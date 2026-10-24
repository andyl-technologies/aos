//! Retains current native container incarnations without reading pack bodies.
//!
//! The executor alone opens and qualifies the actual pack, detached index and
//! protected Committed journal descriptors. The resulting observation retains
//! their names, metadata, parents and actual exclusions through every effect.
//! It grants no mark, grace, retirement, creator or deletion permission.
//!
//! ```text
//! genuine Frame + neutral GcPackRead + protected journals
//! -> actual nofollow descriptors -> bounded index verification -> closed pair
//! ```

use super::{
    CreationJournal, ExactRead, FencePolicy, File, JournalState, MetadataStamp, NamedFence,
    NativeEffectFailure, NativeOpenedDirectory, Path, PathBuf, Plan, Worker, check_opened_name,
    directories_below, journal_path, open_native,
};
use crate::pack::{PackId, PackIndexSnapshot};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{SystemTime, UNIX_EPOCH};
use terrane_format::bucket::PackInventoryEntry;
use terrane_format::gc::ArtifactBinding;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[cfg(all(test, feature = "tokio"))]
use super::{TestGatePhase, wait_test_gate};

/// Fixes one neutral observation for native descriptor verification.
pub(in super::super) struct PairRequest {
    root: PathBuf,
    control: PathBuf,
    pack_path: PathBuf,
    inventory: PackInventoryEntry,
    pack_metadata: Observation,
    index_metadata: Observation,
    index_bytes: Vec<u8>,
    snapshot: PackIndexSnapshot,
    journals: [Vec<u8>; 2],
    owner: u32,
    result: mpsc::Sender<NativeCurrentPair>,
}

impl PairRequest {
    /// Borrows the already fixed name solely for meaningful native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        &self.pack_path
    }
}

/// Takes a current-pair result which only actual native execution can populate.
pub(in super::super) struct PairReceiver {
    result: mpsc::Receiver<NativeCurrentPair>,
}

impl PairReceiver {
    /// Takes the completed retained native observation exactly once.
    ///
    /// # Errors
    /// Refuses unit acknowledgment without actual completed native execution.
    pub(in super::super) fn take(self) -> Result<NativeCurrentPair, NativeEffectFailure> {
        self.result
            .try_recv()
            .map_err(|_| unknown("native current pair unavailable").into())
    }
}

/// Owns a native incarnation observation without exposing descriptors or constructors.
pub(crate) struct NativeCurrentPair {
    hold: Arc<PairHold>,
    root: PathBuf,
    control: PathBuf,
    inventory: PackInventoryEntry,
    snapshot: PackIndexSnapshot,
    pack_modified: SystemTime,
    index_modified: SystemTime,
}

impl NativeCurrentPair {
    /// Borrows the inventory association independently checked by the native worker.
    pub(crate) fn inventory(&self) -> &PackInventoryEntry {
        &self.inventory
    }

    /// Borrows the complete canonical detached-index observation.
    pub(crate) fn snapshot(&self) -> &PackIndexSnapshot {
        &self.snapshot
    }

    /// Returns conservative whole-second backend last-modified time.
    ///
    /// This value comes from the actual retained pack descriptor, not a clock
    /// or Tombstone. It alone grants no grace or elapsed-age qualification.
    ///
    /// # Errors
    /// Refuses pre-Unix time and upward rounding overflow.
    pub(crate) fn pack_modified_unix_seconds(&self) -> Result<u64, NativeEffectFailure> {
        let elapsed = self
            .pack_modified
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unknown("native pack last-modified time precedes Unix epoch"))?;
        elapsed
            .as_secs()
            .checked_add(u64::from(elapsed.subsec_nanos() != 0))
            .ok_or_else(|| unknown("native last-modified conversion overflow").into())
    }

    /// Returns the later independently upward-rounded backend pair modification time.
    ///
    /// Both values come from actual retained descriptors and remain continuously
    /// checked by the pair. This bound grants no Trash creation or deletion age.
    ///
    /// # Errors
    /// Refuses pre-Unix descriptor time or upward rounding overflow.
    pub(crate) fn pair_modified_unix_seconds(&self) -> Result<u64, NativeEffectFailure> {
        let index = self
            .index_modified
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unknown("native index last-modified time precedes Unix epoch"))?;
        let index = index
            .as_secs()
            .checked_add(u64::from(index.subsec_nanos() != 0))
            .ok_or_else(|| unknown("native index last-modified conversion overflow"))?;
        Ok(self.pack_modified_unix_seconds()?.max(index))
    }

    /// Retains the closed pair in an actual subsequent Frame.
    ///
    /// # Errors
    /// Refuses changed native artifacts, journals, controls or exclusions.
    pub(in super::super) fn retention(
        &self,
        root: &Path,
        control: &Path,
        exclusions: &[super::super::NativeExclusion],
    ) -> Result<Arc<PairHold>, NativeEffectFailure> {
        if self.root != root || self.control != control {
            return Err(
                unknown("current pair belongs to a different backend root or control").into(),
            );
        }
        self.hold.recheck()?;
        let state = self
            .hold
            .state
            .lock()
            .map_err(|_| unknown("native pair lock poisoned"))?;
        let current = exclusions
            .iter()
            .map(|retained| MetadataStamp::checked(&retained.file.metadata()?))
            .collect::<Result<Vec<_>, io::Error>>()?;
        for original in state.projection.exclusions.iter() {
            let identity = MetadataStamp::checked(&original.file.metadata()?)?.identity;
            if !current.iter().any(|stamp| stamp.identity == identity) {
                return Err(
                    unknown("current Frame does not retain original pair exclusion").into(),
                );
            }
        }
        Ok(Arc::clone(&self.hold))
    }
}

/// Keeps descriptor state alive in submitted workers after their asynchronous owner drops.
pub(in super::super) struct PairHold {
    state: Mutex<PairState>,
}

impl PairHold {
    /// Rechecks actual descriptors and untouched pair/control preimages.
    ///
    /// # Errors
    /// Refuses poisoned retention, changed identities, metadata, bodies or controls.
    pub(in super::super) fn recheck(&self) -> Result<(), NativeEffectFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| unknown("native pair lock poisoned"))?;
        state.recheck()
    }
}

struct PairState {
    pack: Opened,
    index: Opened,
    journals: [Opened; 2],
    index_bytes: Vec<u8>,
    journal_bytes: [Vec<u8>; 2],
    projection: PhysicalProjection,
    directories: Vec<NativeOpenedDirectory>,
}

// Fixed physical holds contain no old selected-state or session callback. This
// also keeps descriptor retention Send/Sync independently of the caller's
// supported non-Send authority-refresh profile.
struct PhysicalProjection {
    exclusions: Arc<[super::super::NativeExclusion]>,
    names: Vec<NamedFence>,
    preimages: Vec<ExactRead>,
    directories: Option<Arc<[NativeOpenedDirectory]>>,
}

impl PhysicalProjection {
    fn refresh(&self) -> Result<(), NativeEffectFailure> {
        if let Some(directories) = &self.directories {
            for directory in directories.iter() {
                directory.check()?;
            }
        }
        for name in &self.names {
            name.check(&self.exclusions)?;
        }
        for read in &self.preimages {
            read.check()?;
        }
        for name in &self.names {
            name.check(&self.exclusions)?;
        }
        if let Some(directories) = &self.directories {
            for directory in directories.iter() {
                directory.check()?;
            }
        }
        Ok(())
    }
}

impl PairState {
    fn recheck(&mut self) -> Result<(), NativeEffectFailure> {
        self.projection.refresh()?;
        for directory in &self.directories {
            directory.check()?;
        }
        self.pack.check()?;
        self.index.check()?;
        for journal in &self.journals {
            journal.check()?;
        }

        self.index.exact(&self.index_bytes)?;
        for (journal, bytes) in self.journals.iter_mut().zip(&self.journal_bytes) {
            journal.exact(bytes)?;
        }

        // Metadata is checked again after all bounded reads, including pack
        // metadata: an index/journal read cannot hide a concurrent pack change.
        self.pack.check()?;
        self.index.check()?;
        for journal in &self.journals {
            journal.check()?;
        }
        self.projection.refresh()?;
        for directory in &self.directories {
            directory.check()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Observation {
    stamp: MetadataStamp,
    length: u64,
    modified: SystemTime,
    changed: (i64, i64),
}

impl Observation {
    #[cfg(unix)]
    fn checked(metadata: &std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            stamp: MetadataStamp::checked(metadata)?,
            length: metadata.len(),
            modified: metadata.modified()?,
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn checked(_metadata: &std::fs::Metadata) -> io::Result<Self> {
        Err(unknown("native current pair unavailable"))
    }
}

struct Opened {
    file: File,
    path: PathBuf,
    observation: Observation,
    policy: FencePolicy,
}

impl Opened {
    fn open(path: PathBuf, observation: Observation, policy: FencePolicy) -> io::Result<Self> {
        policy.validate(observation.stamp)?;
        let result = Self {
            file: open_native(&path, false)?,
            path,
            observation,
            policy,
        };
        result.check()?;
        Ok(result)
    }

    fn check(&self) -> io::Result<()> {
        check_opened_name(&self.file, &self.path, false)?;
        let opened = Observation::checked(&self.file.metadata()?)?;
        let named = Observation::checked(&std::fs::symlink_metadata(&self.path)?)?;
        self.policy.validate(opened.stamp)?;
        self.policy.validate(named.stamp)?;
        if opened != self.observation || named != self.observation {
            return Err(unknown("native pair descriptor, metadata or name changed"));
        }
        Ok(())
    }

    fn exact(&mut self, expected: &[u8]) -> io::Result<()> {
        self.check()?;
        self.read_expected(expected)?;
        self.check()
    }

    fn read_expected(&mut self, expected: &[u8]) -> io::Result<()> {
        if self
            .path
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            return Err(unknown(
                "native current-pair pack descriptors are metadata-only",
            ));
        }
        if u64::try_from(expected.len()).map_err(io::Error::other)? != self.observation.length {
            return Err(unknown("native pair body length changed"));
        }
        let limit = self
            .observation
            .length
            .checked_add(1)
            .ok_or_else(|| unknown("native pair read bound overflow"))?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut actual = Vec::new();
        (&mut self.file).take(limit).read_to_end(&mut actual)?;
        if actual != expected {
            return Err(unknown("native pair bounded body differs"));
        }
        Ok(())
    }
}

fn unknown(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn binding(inventory: &PackInventoryEntry, index: bool) -> ArtifactBinding {
    if index {
        ArtifactBinding::Index {
            digest: inventory.index_hash,
            size: inventory.index_size,
        }
    } else {
        ArtifactBinding::Pack {
            digest: inventory.pack_hash,
            size: inventory.pack_size,
        }
    }
}

fn committed(bytes: &[u8], key: &str, expected: &ArtifactBinding) -> io::Result<CreationJournal> {
    let record =
        CreationJournal::decode(bytes).map_err(|_| unknown("unknown native creation journal"))?;
    if record.encode().map_err(io::Error::other)? != bytes || record.key != key {
        return Err(unknown(
            "native journal is not exactly canonical or associated",
        ));
    }
    match &record.state {
        JournalState::Committed {
            binding,
            file_identity,
        } if binding == expected && file_identity.len() == 16 => Ok(record),
        _ => Err(unknown(
            "native pair journal is not current Committed evidence",
        )),
    }
}

fn native_identity(observation: Observation) -> [u8; 16] {
    let mut result = [0; 16];
    result[..8].copy_from_slice(&observation.stamp.identity.0.to_be_bytes());
    result[8..].copy_from_slice(&observation.stamp.identity.1.to_be_bytes());
    result
}

fn compare_journal(record: &CreationJournal, observation: Observation) -> io::Result<()> {
    let JournalState::Committed { file_identity, .. } = &record.state else {
        return Err(unknown("native pair has no Committed journal"));
    };
    if file_identity.as_slice() != native_identity(observation).as_slice() {
        return Err(unknown(
            "native pair journal does not match actual descriptor",
        ));
    }
    Ok(())
}

/// Builds an empty channel for a fixed observed container pair.
///
/// These private input observations cannot fill the result or supply descriptors.
/// Only execution under the actual retained Frame creates NativeCurrentPair.
///
/// # Errors
/// Refuses noncanonical paths, incomplete metadata, malformed index or Unknown journals.
pub(in super::super) fn pair_plan(
    root: &Path,
    control: &Path,
    observed: &crate::bucket::publication::receipts::GcPackRead,
    journals: [Vec<u8>; 2],
    owner: u32,
) -> Result<(Plan, PairReceiver), NativeEffectFailure> {
    let inventory = observed.inventory();
    let id = PackId::from_random_bytes(inventory.pack_id);
    if !root.is_absolute()
        || !control.is_absolute()
        || control.starts_with(root)
        || observed.pack_path() != root.join(id.pack_key())
        || observed.index().path() != root.join(id.index_key())
    {
        return Err(unknown("misbound native pair paths").into());
    }
    let pack_metadata = Observation::checked(observed.metadata())?;
    let index_metadata = Observation::checked(
        observed
            .index()
            .metadata()
            .ok_or_else(|| unknown("missing native index metadata"))?,
    )?;
    FencePolicy::Payload { owner }.validate(pack_metadata.stamp)?;
    FencePolicy::Payload { owner }.validate(index_metadata.stamp)?;
    if pack_metadata.length != inventory.pack_size || index_metadata.length != inventory.index_size
    {
        return Err(unknown("native pair differs from inventory sizes").into());
    }
    let index_bytes = observed
        .index()
        .bytes()
        .ok_or_else(|| unknown("missing native index"))?;
    verify_index(inventory, index_bytes, observed.snapshot())?;
    for ((bytes, key), expected) in journals
        .iter()
        .zip([id.pack_key(), id.index_key()])
        .zip([binding(inventory, false), binding(inventory, true)])
    {
        committed(bytes, &key, &expected)?;
    }
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::ObserveCurrentPair(Box::new(PairRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            pack_path: observed.pack_path().to_owned(),
            inventory: inventory.clone(),
            pack_metadata,
            index_metadata,
            index_bytes: index_bytes.to_vec(),
            snapshot: observed.snapshot().clone(),
            journals,
            owner,
            result: sender,
        })),
        PairReceiver { result: receiver },
    ))
}

fn verify_index(
    inventory: &PackInventoryEntry,
    bytes: &[u8],
    expected: &PackIndexSnapshot,
) -> io::Result<()> {
    if u64::try_from(bytes.len()).map_err(io::Error::other)? != inventory.index_size {
        return Err(unknown("native index differs from inventory length"));
    }
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Index, &inventory.index_hash)
        .map_err(io::Error::other)?;
    TERRANE_V1
        .verify(&identity, bytes)
        .map_err(io::Error::other)?;
    let decoded =
        PackIndexSnapshot::decode(bytes, expected.generation()).map_err(io::Error::other)?;
    let body_end = inventory
        .pack_size
        .checked_sub(inventory.index_size)
        .and_then(|size| size.checked_add(terrane_format::pack_format::HEADER_SIZE as u64))
        .and_then(|size| size.checked_sub(terrane_format::pack_format::FOOTER_SIZE as u64))
        .ok_or_else(|| unknown("native container body bound overflow"))?;
    if decoded != *expected
        || decoded.header().id().as_bytes() != &inventory.pack_id
        || decoded.entries().iter().any(|entry| {
            entry
                .offset()
                .checked_add(u64::from(entry.body_len()))
                .is_none_or(|end| end > body_end)
        })
    {
        return Err(unknown("native detached index association differs"));
    }
    Ok(())
}

/// Opens and qualifies fixed native descriptors under the genuine submitted Frame.
///
/// # Errors
/// Refuses changed observations, Unknown journals, unsafe or replaced controls,
/// failed bounded reads and missing actual retained exclusions.
pub(super) fn execute(request: PairRequest, worker: Worker) -> Result<(), NativeEffectFailure> {
    #[cfg(all(test, feature = "tokio"))]
    let mut worker = worker;
    if worker.projection.exclusions.is_empty() {
        return Err(unknown("native pair requires actual retained exclusion").into());
    }
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    let id = PackId::from_random_bytes(request.inventory.pack_id);
    let keys = [id.pack_key(), id.index_key()];
    let index_path = request.root.join(&keys[1]);
    let index_read = worker
        .projection
        .exact(&index_path, Some(&request.index_bytes))?;
    if !matches!(index_read.policy, FencePolicy::Payload { owner } if owner == request.owner)
        || index_read.identity != Some(request.index_metadata.stamp.identity)
        || index_read
            .metadata
            .is_none_or(|stamp| !stamp.same_incarnation(request.index_metadata.stamp))
    {
        return Err(unknown("native pair index lacks its exact payload preimage").into());
    }
    let mut directories = directories_below(index_read, &request.root, request.owner, false)?;
    let mut journal_observations = Vec::new();
    for (key, bytes) in keys.iter().zip(&request.journals) {
        let path = journal_path(&request.control, key);
        let read = worker.projection.exact(&path, Some(bytes))?;
        if !matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
        {
            return Err(unknown("native pair journal lacks protected policy").into());
        }
        directories.extend(directories_below(
            read,
            &request.control,
            request.owner,
            true,
        )?);
        let metadata = std::fs::symlink_metadata(&path)?;
        let observation = Observation::checked(&metadata)?;
        if read
            .metadata
            .is_none_or(|expected| !observation.stamp.same_incarnation(expected))
        {
            return Err(unknown("native pair journal observation changed").into());
        }
        journal_observations.push((path, observation));
    }
    worker.refresh(&[])?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
    let pack = Opened::open(
        request.pack_path,
        request.pack_metadata,
        FencePolicy::Payload {
            owner: request.owner,
        },
    )?;
    let mut index = Opened::open(
        index_path.clone(),
        request.index_metadata,
        FencePolicy::Payload {
            owner: request.owner,
        },
    )?;
    let mut opened_journals = Vec::new();
    for (path, observation) in journal_observations {
        opened_journals.push(Opened::open(
            path,
            observation,
            FencePolicy::ProtectedRecord {
                owner: request.owner,
            },
        )?);
    }
    let mut journals: [Opened; 2] = opened_journals
        .try_into()
        .map_err(|_| unknown("native pair journal inventory incomplete"))?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterOpen)?;
    worker.refresh(&[])?;
    pack.check()?;
    index.check()?;
    index.read_expected(&request.index_bytes)?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterCurrentPairIndexRead)?;
    pack.check()?;
    index.check()?;
    verify_index(&request.inventory, &request.index_bytes, &request.snapshot)?;
    for ((journal, bytes), (key, expected)) in
        journals
            .iter_mut()
            .zip(&request.journals)
            .zip(keys.iter().zip([
                binding(&request.inventory, false),
                binding(&request.inventory, true),
            ]))
    {
        journal.exact(bytes)?;
        let decoded = committed(bytes, key, &expected)?;
        compare_journal(
            &decoded,
            if key == &keys[0] {
                pack.observation
            } else {
                index.observation
            },
        )?;
    }
    pack.check()?;
    index.check()?;
    worker.refresh(&[])?;
    // Keep native controls and all their named fences, but not stale selected
    // mutable payload preimages or an old session check after our own selection.
    // Each subsequent current Frame independently retains its fresh complete
    // projection/final check, while this hold preserves the fixed native pair.
    let final_check = worker.projection.final_check;
    let projection = PhysicalProjection {
        exclusions: Arc::clone(&worker.projection.exclusions),
        names: worker.projection.names,
        preimages: worker
            .projection
            .preimages
            .into_iter()
            .filter(|read| {
                read.path == index_path
                    || keys
                        .iter()
                        .any(|key| read.path == journal_path(&request.control, key))
            })
            .collect(),
        directories: worker.projection.directories,
    };
    let hold = Arc::new(PairHold {
        state: Mutex::new(PairState {
            pack,
            index,
            journals,
            index_bytes: request.index_bytes,
            journal_bytes: request.journals,
            projection,
            directories,
        }),
    });
    hold.recheck()?;
    if let Some(check) = final_check {
        check.recheck()?;
    }
    let result = NativeCurrentPair {
        hold,
        root: request.root,
        control: request.control,
        inventory: request.inventory,
        snapshot: request.snapshot,
        pack_modified: request.pack_metadata.modified,
        index_modified: request.index_metadata.modified,
    };
    let _ = request.result.send(result);
    Ok(())
}
