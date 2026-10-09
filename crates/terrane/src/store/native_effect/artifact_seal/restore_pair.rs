//! Retains actual native maintenance and eligible DATA descriptors without creator authority.
//!
//! The executor alone opens and qualifies the actual pack, detached index and
//! optional protected journal descriptors. Eligible DATA observations require no
//! journal or synthetic Trash name. The resulting observation retains
//! their names, metadata, parents and actual exclusions through every effect.
//! It grants no creator, physical age, retirement or deletion permission.
//!
//! ```text
//! genuine Frame + neutral GcPackRead + optional protected journals
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
use std::time::SystemTime;
use terrane_core::bucket::PackInventoryEntry;
use terrane_core::identity::{IdentityKind, TERRANE_V1};

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
    journals: Vec<JournalInput>,
    owner: u32,
    cancellation: Option<Arc<super::local_deletion::NativeLocalDeletion>>,
    result: mpsc::Sender<NativeRestorePair>,
}

/// Fixes one genuinely relevant protected journal observation for restoration.
struct JournalInput {
    key: String,
    bytes: Option<Vec<u8>>,
}

/// Associates neutral observed bytes with their actual native namespace.
struct PairInputs<'a> {
    root: &'a Path,
    control: &'a Path,
    observed: &'a crate::bucket::publication::receipts::GcPackRead,
    owner: u32,
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
    result: mpsc::Receiver<NativeRestorePair>,
}

impl PairReceiver {
    /// Takes the completed retained native observation exactly once.
    ///
    /// # Errors
    /// Refuses unit acknowledgment without actual completed native execution.
    pub(in super::super) fn take(self) -> Result<NativeRestorePair, NativeEffectFailure> {
        self.result
            .try_recv()
            .map_err(|_| unknown("native current pair unavailable").into())
    }
}

/// Owns a native incarnation observation without exposing descriptors or constructors.
pub(crate) struct NativeRestorePair {
    hold: Arc<PairHold>,
    root: PathBuf,
    control: PathBuf,
    inventory: PackInventoryEntry,
    snapshot: PackIndexSnapshot,
}

impl NativeRestorePair {
    /// Borrows the inventory association independently checked by the native worker.
    pub(crate) fn inventory(&self) -> &PackInventoryEntry {
        &self.inventory
    }

    /// Borrows the complete canonical detached-index observation.
    pub(crate) fn snapshot(&self) -> &PackIndexSnapshot {
        &self.snapshot
    }

    /// Retains the genuinely opened descriptors for subsequent native final checks.
    pub(crate) fn held(&self) -> Arc<PairHold> {
        Arc::clone(&self.hold)
    }

    /// Checks that the observation belongs to this actual namespace.
    ///
    /// # Errors
    /// Refuses another root or changed retained native descriptors and controls.
    pub(crate) fn check_root(&self, root: &Path) -> Result<(), NativeEffectFailure> {
        if self.root != root {
            return Err(unknown("restore pair belongs to another namespace").into());
        }
        self.hold.recheck()
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
pub(crate) struct PairHold {
    state: Mutex<PairState>,
}

impl PairHold {
    /// Adopts only an executor-observed exact invalidation of one owned journal.
    ///
    /// # Errors
    /// Refuses another journal, wrong original body or changed physical descriptor.
    pub(super) fn adopt_cancelled_journal(
        &self,
        replacement: &super::local_deletion::CancelledJournal,
    ) -> Result<(), NativeEffectFailure> {
        let (path, file, bytes) = replacement.replacement()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| unknown("native pair lock poisoned"))?;
        state.pack.check()?;
        state.index.check()?;
        let index = state
            .journals
            .iter()
            .position(|journal| journal.path == path)
            .ok_or_else(|| unknown("cancellation changed an unrelated pair journal"))?;
        if state.journal_bytes[index] != replacement.original() {
            return Err(unknown("cancellation journal original differs").into());
        }
        let old = CreationJournal::decode(replacement.original()).map_err(io::Error::other)?;
        let new = CreationJournal::decode(bytes).map_err(io::Error::other)?;
        if old.key != new.key || old.nonce != new.nonce || new.state != JournalState::Invalidated {
            return Err(unknown("cancellation journal successor differs").into());
        }
        let observation = Observation::checked(&file.metadata()?)?;
        let opened = Opened {
            file,
            path: path.to_owned(),
            observation,
            policy: state.journals[index].policy,
        };
        opened.check()?;
        let read = state
            .projection
            .preimages
            .iter_mut()
            .find(|read| read.path == path)
            .ok_or_else(|| unknown("cancellation lacks its retained journal preimage"))?;
        read.expected = Some(bytes.to_vec());
        read.identity = Some(observation.stamp.identity);
        read.metadata = Some(observation.stamp);
        for name in &mut state.projection.names {
            if name.path == path {
                name.stamp = observation.stamp;
            }
        }
        state.journals[index] = opened;
        state.journal_bytes[index] = bytes.to_vec();
        state.recheck()
    }

    /// Rechecks actual descriptors and untouched pair/control preimages.
    ///
    /// # Errors
    /// Refuses poisoned retention, changed identities, metadata, bodies or controls.
    pub(crate) fn recheck(&self) -> Result<(), NativeEffectFailure> {
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
    journals: Vec<Opened>,
    index_bytes: Vec<u8>,
    journal_bytes: Vec<Vec<u8>>,
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

fn reject_owned(bytes: &[u8]) -> io::Result<()> {
    // Unknown creator bytes never become age or ownership evidence. A genuine
    // represented DeleteOwned needs the separately qualified cancellation lane.
    if CreationJournal::decode(bytes)
        .is_ok_and(|record| matches!(record.state, JournalState::DeleteOwned { .. }))
    {
        return Err(unknown("restore requires native deletion cancellation"));
    }
    Ok(())
}

/// Builds an empty channel for a fixed observed container pair.
///
/// These private input observations cannot fill the result or supply descriptors.
/// Only execution under the actual retained Frame creates NativeRestorePair.
///
/// # Errors
/// Refuses noncanonical paths, incomplete metadata, malformed index or unsafe observations.
pub(in super::super) fn pair_plan(
    root: &Path,
    control: &Path,
    observed: &crate::bucket::publication::receipts::GcPackRead,
    journals: [Option<Vec<u8>>; 3],
    journal_keys: [String; 3],
    owner: u32,
) -> Result<(Plan, PairReceiver), NativeEffectFailure> {
    pair_plan_inner(root, control, observed, journals, journal_keys, owner, None)
}

/// Observes a present pair backed by an actual exact local ownership receipt.
///
/// # Errors
/// Refuses changed ownership, absent containers or another selected association.
pub(in super::super) fn cancellation_pair_plan(
    root: &Path,
    control: &Path,
    observed: &crate::bucket::publication::receipts::GcPackRead,
    journals: [Option<Vec<u8>>; 3],
    journal_keys: [String; 3],
    owner: u32,
    receipt: Arc<super::local_deletion::NativeLocalDeletion>,
) -> Result<(Plan, PairReceiver), NativeEffectFailure> {
    receipt.check_restore_association(
        root,
        control,
        observed.inventory(),
        &journals,
        &journal_keys,
        owner,
    )?;
    pair_plan_inner(
        root,
        control,
        observed,
        journals,
        journal_keys,
        owner,
        Some(receipt),
    )
}

/// Observes eligible DATA without importing creator journals or a Trash identity.
///
/// The result supplies physical continuity only. A genuine DATA producer and its
/// complete current Frame must separately establish eligibility and authority;
/// decoded inventory or unit acknowledgment cannot populate the result channel.
///
/// # Errors
/// Refuses unsafe or misbound paths, sizes, metadata, or detached index bytes.
pub(in super::super) fn eligible_data_pair_plan(
    root: &Path,
    control: &Path,
    observed: &crate::bucket::publication::receipts::GcPackRead,
    owner: u32,
) -> Result<(Plan, PairReceiver), NativeEffectFailure> {
    let inputs = PairInputs {
        root,
        control,
        observed,
        owner,
    };
    let metadata = validate_observation(&inputs)?;
    Ok(observed_plan(inputs, metadata, Vec::new(), None))
}

fn pair_plan_inner(
    root: &Path,
    control: &Path,
    observed: &crate::bucket::publication::receipts::GcPackRead,
    journals: [Option<Vec<u8>>; 3],
    journal_keys: [String; 3],
    owner: u32,
    cancellation: Option<Arc<super::local_deletion::NativeLocalDeletion>>,
) -> Result<(Plan, PairReceiver), NativeEffectFailure> {
    let inputs = PairInputs {
        root,
        control,
        observed,
        owner,
    };
    let metadata = validate_observation(&inputs)?;
    let id = PackId::from_random_bytes(observed.inventory().pack_id);
    if journal_keys[0] != id.pack_key()
        || journal_keys[1] != id.index_key()
        || !journal_keys[2].starts_with("trash/")
        || !journal_keys[2].ends_with(&format!("/{id}"))
        || terrane_core::bucket::BucketKey::parse(&journal_keys[2]).is_err()
    {
        return Err(unknown("restore ownership journal association differs").into());
    }
    if cancellation.is_none() {
        for bytes in journals.iter().flatten() {
            reject_owned(bytes)?;
        }
    }
    let journals = journals
        .into_iter()
        .zip(journal_keys)
        .map(|(bytes, key)| JournalInput { key, bytes })
        .collect();
    Ok(observed_plan(inputs, metadata, journals, cancellation))
}

fn validate_observation(
    inputs: &PairInputs<'_>,
) -> Result<(Observation, Observation, Vec<u8>), NativeEffectFailure> {
    let PairInputs {
        root,
        control,
        observed,
        owner,
    } = *inputs;
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
    Ok((pack_metadata, index_metadata, index_bytes.to_vec()))
}

fn observed_plan(
    inputs: PairInputs<'_>,
    metadata: (Observation, Observation, Vec<u8>),
    journals: Vec<JournalInput>,
    cancellation: Option<Arc<super::local_deletion::NativeLocalDeletion>>,
) -> (Plan, PairReceiver) {
    let PairInputs {
        root,
        control,
        observed,
        owner,
    } = inputs;
    let (pack_metadata, index_metadata, index_bytes) = metadata;
    let (sender, receiver) = mpsc::channel();
    (
        Plan::ObserveRestorePair(Box::new(PairRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            pack_path: observed.pack_path().to_owned(),
            inventory: observed.inventory().clone(),
            pack_metadata,
            index_metadata,
            index_bytes,
            snapshot: observed.snapshot().clone(),
            journals,
            owner,
            cancellation,
            result: sender,
        })),
        PairReceiver { result: receiver },
    )
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
        .and_then(|size| size.checked_add(terrane_core::pack_format::HEADER_SIZE as u64))
        .and_then(|size| size.checked_sub(terrane_core::pack_format::FOOTER_SIZE as u64))
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
/// Refuses changed observations, unsafe observations, unsafe or replaced controls,
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
    for journal in &request.journals {
        let path = journal_path(&request.control, &journal.key);
        let read = worker.projection.exact(&path, journal.bytes.as_deref())?;
        if !matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
        {
            return Err(unknown("native pair journal lacks protected policy").into());
        }
        if journal.bytes.is_none() {
            // The exact missing journal/ancestor remains an original preimage.
            read.check()?;
            continue;
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
    if let Some(receipt) = &request.cancellation {
        receipt.recheck()?;
    }
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
    let mut journals = opened_journals;
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
    for (journal, bytes) in journals.iter_mut().zip(
        request
            .journals
            .iter()
            .filter_map(|journal| journal.bytes.as_deref()),
    ) {
        journal.exact(bytes)?;
        if request.cancellation.is_none() {
            reject_owned(bytes)?;
        }
    }
    if let Some(receipt) = &request.cancellation {
        receipt.recheck()?;
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
                    || request
                        .journals
                        .iter()
                        .any(|journal| read.path == journal_path(&request.control, &journal.key))
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
            journal_bytes: request
                .journals
                .into_iter()
                .filter_map(|journal| journal.bytes)
                .collect(),
            projection,
            directories,
        }),
    });
    hold.recheck()?;
    if let Some(check) = final_check {
        check.recheck()?;
    }
    let result = NativeRestorePair {
        hold,
        root: request.root,
        control: request.control,
        inventory: request.inventory,
        snapshot: request.snapshot,
    };
    let _ = request.result.send(result);
    Ok(())
}
