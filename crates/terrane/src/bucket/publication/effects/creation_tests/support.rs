//! Supplies genuine native buckets and independently predicted journal bytes.
//!
//! ```text
//! Pending = {0:1, 1:logical-key, 2:nonce32, 3:0}
//! Committed = {0:1, 1:logical-key, 2:nonce32, 3:1,
//!              4:[kind,digest32,size], 5:device64be || inode64be}
//! ```

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::super::super::{Plan, TestGate, TestGatePhase};
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::pack::{EntryKind, PackClass, PackId, PackReader, PackWriter, SealedPack};
use crate::store::{
    ByteRange, ContentStore, ContentUpload, ContentValidator, EffectFault, EffectFaultProbe,
    LocalFs, MetaUpload, NativeEffectFailure, NativeExclusion, NativeFsEffect,
    NativePublicationInitialization, NativePublicationInitializationOutcome, StoreErrorKind,
    StoreFailure, TokioClock, TokioFileLock, TokioLocalFs,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use terrane_core::bucket::{BucketCapabilities, GenerationManifest, PackInventoryEntry};
use terrane_core::chunking::ChunkProfile;
use terrane_core::gc::{CreationJournal, JournalState};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_core::refs::Locality;

/// Validates the real canonical metadata used by these storage fixtures.
pub(super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let valid = match upload.kind() {
            IdentityKind::Pack => PackReader::open(upload.bytes()).is_ok(),
            IdentityKind::Node => {
                terrane_core::tree_format::decode_node(upload.bytes(), true, 262144).is_ok()
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(StoreFailure::new(StoreErrorKind::Invalid(
                crate::store::InvalidReason::Upload {
                    rule_id: "STORE-33",
                },
            )))
        }
    }
}

/// Names the genuine native-backed fixture with effect interception only.
pub(super) type Bucket = FileBucket<ProbeFs, TokioClock, Validator>;

/// Identifies real privately fixed native commands without creating authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// Creation of one fixed directory beneath an actual retained root.
    DirectoryCreate(PathBuf),
    /// An actual create-new staging path.
    Write(PathBuf),
    /// An ordinary file synchronization.
    FileSync,
    /// A directory synchronization.
    Directory(PathBuf),
    /// An ordinary atomic destination.
    Rename(PathBuf),
    /// A closed Pending descriptor qualification.
    Pending(PathBuf),
    /// A closed artifact descriptor qualification.
    Seal(PathBuf),
    /// A closed protected commitment.
    Commit(PathBuf),
    /// An exact already-existing CAP range probe.
    Range {
        /// The actual fixed CAP pathname.
        path: PathBuf,
        /// The requested byte offset.
        start: u64,
        /// The complete expected range bytes.
        expected: Vec<u8>,
    },
    /// A fixed immutable catalog cohort, preserving every actual target path.
    ImmutableCatalogCohort(Vec<PathBuf>),
    /// The actual selecting slot undergoing final Raw publication acknowledgment.
    RawPublicationAck(PathBuf),
    /// Another native command.
    Other,
}

/// Selects a real effect by its exact phase/path and one-based occurrence.
#[derive(Clone)]
pub(super) enum Select {
    /// Matches one exact privately fixed command.
    Exact(Kind),
    /// Matches staged writes beneath one actual parent.
    WritesBelow(PathBuf),
    /// Matches the next non-genesis catalog slot destination.
    Catalog(PathBuf),
}

impl Select {
    fn matches(&self, kind: &Kind) -> bool {
        match (self, kind) {
            (Self::Exact(expected), actual) => expected == actual,
            (Self::WritesBelow(parent), Kind::Write(path)) => path.parent() == Some(parent),
            (Self::Catalog(control), Kind::Rename(path)) => {
                path.parent() == Some(control.join("publication/commits").as_path())
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| name.parse::<u64>().ok())
                        .is_some_and(|revision| revision > 0)
            }
            _ => false,
        }
    }
}

/// Fixes one test intervention inside or around the actual native worker.
pub(super) enum Action {
    /// Rejects before submitting the selected effect.
    Stop,
    /// Executes with one actual native fault.
    Fault(EffectFault),
    /// Acknowledges without executing, leaving the private result empty.
    Noop,
    /// Swallows the actual selected native failure after recording it.
    Swallow(EffectFault),
    /// Holds the actual submitted worker at an existing native gate.
    Hold(TestGatePhase, mpsc::Sender<()>, mpsc::Receiver<()>),
}

struct Hook {
    select: Select,
    occurrence: usize,
    seen: usize,
    action: Action,
}

#[derive(Default)]
struct State {
    hooks: Mutex<Vec<Hook>>,
    effects: Mutex<Vec<Kind>>,
    native_errors: Mutex<Vec<String>>,
    entropy32: Mutex<Vec<[u8; 32]>>,
    entropy16: Mutex<Vec<[u8; 16]>>,
    forced_nonce: Mutex<Option<[u8; 32]>>,
    lock_attempt: Mutex<Option<mpsc::Sender<()>>>,
    deny_retention: AtomicBool,
    ordinary_writes: AtomicUsize,
}

/// Forwards genuine native operations while observing exact test boundaries.
#[derive(Clone, Default)]
pub(super) struct ProbeFs(Arc<State>);

impl ProbeFs {
    /// Arms one exact occurrence without consuming unrelated future hooks.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned or occurrence is zero.
    pub(super) fn arm(&self, select: Select, occurrence: usize, action: Action) {
        assert!(occurrence > 0);
        self.0.hooks.lock().unwrap().push(Hook {
            select,
            occurrence,
            seen: 0,
            action,
        });
    }

    /// Requires every registered hook to have reached its selected real effect.
    ///
    /// # Panics
    /// Panics if a hook remains unmatched or fixture synchronization is poisoned.
    pub(super) fn assert_consumed(&self) {
        assert!(self.0.hooks.lock().unwrap().is_empty());
    }

    /// Returns the ordered real native effect inventory, preserving repetitions.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned.
    pub(super) fn effects(&self) -> Vec<Kind> {
        self.0.effects.lock().unwrap().clone()
    }

    /// Returns errors emitted by actual executor calls rather than wrapper selection.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned.
    pub(super) fn native_errors(&self) -> Vec<String> {
        self.0.native_errors.lock().unwrap().clone()
    }

    /// Returns independent entropy observations for exact incarnation expectations.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned.
    pub(super) fn nonces(&self) -> Vec<[u8; 32]> {
        self.0.entropy32.lock().unwrap().clone()
    }

    /// Resets observations after genuine initialization without changing filesystem data.
    ///
    /// # Panics
    /// Panics if a hook remains armed or fixture synchronization is poisoned.
    pub(super) fn clear(&self) {
        self.assert_consumed();
        self.0.effects.lock().unwrap().clear();
        self.0.native_errors.lock().unwrap().clear();
        self.0.entropy32.lock().unwrap().clear();
        self.0.entropy16.lock().unwrap().clear();
        self.0.ordinary_writes.store(0, Ordering::SeqCst);
    }

    /// Makes the next32-byte entropy call deliberately repeat an old nonce.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned.
    pub(super) fn repeat_nonce(&self, nonce: [u8; 32]) {
        *self.0.forced_nonce.lock().unwrap() = Some(nonce);
    }

    /// Signals the next actual existing-lock call before awaiting native exclusion.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned or another signal is armed.
    pub(super) fn observe_next_lock_attempt(&self, signal: mpsc::Sender<()>) {
        let mut pending = self.0.lock_attempt.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(signal);
    }

    /// Refuses actual descriptor retention before the creator can submit effects.
    pub(super) fn deny_retention(&self) {
        self.0.deny_retention.store(true, Ordering::SeqCst);
    }

    /// Counts ordinary filesystem mutations separately from native commands.
    pub(super) fn ordinary_writes(&self) -> usize {
        self.0.ordinary_writes.load(Ordering::SeqCst)
    }
}

fn kind(effect: &NativeFsEffect) -> Kind {
    if let Some(Plan::CreateDirectoryNew { path }) = effect.plan.primitive() {
        return Kind::DirectoryCreate(path.clone());
    }
    if let Some(Plan::ProbeRange {
        path,
        start,
        expected,
    }) = effect.plan.primitive()
    {
        return Kind::Range {
            path: path.clone(),
            start: *start,
            expected: expected.clone(),
        };
    }
    if let Some(targets) = effect.immutable_catalog_cohort_targets() {
        return Kind::ImmutableCatalogCohort(targets);
    }
    match effect.fault_probe() {
        EffectFaultProbe::WriteNew(path) => Kind::Write(path.to_owned()),
        EffectFaultProbe::FileSync => Kind::FileSync,
        EffectFaultProbe::DirectorySync(path) => Kind::Directory(path.to_owned()),
        EffectFaultProbe::Rename(path) | EffectFaultProbe::RenameNoReplace(path) => {
            Kind::Rename(path.to_owned())
        }
        EffectFaultProbe::SealPendingCreation(path) => Kind::Pending(path.to_owned()),
        EffectFaultProbe::SealArtifact(path) => Kind::Seal(path.to_owned()),
        EffectFaultProbe::CommitCreation(path) => Kind::Commit(path.to_owned()),
        EffectFaultProbe::SealRawPublication(path) => Kind::RawPublicationAck(path.to_owned()),
        EffectFaultProbe::SealRetirementBarrier(_)
        | EffectFaultProbe::SealMutationPublication(_)
        | EffectFaultProbe::SealLeasePublication(_)
        | EffectFaultProbe::ObserveCurrentPair(_)
        | EffectFaultProbe::ObserveLocalTriple(_)
        | EffectFaultProbe::LocalFirstOwnership(_, _)
        | EffectFaultProbe::LocalDeletion(_, _)
        | EffectFaultProbe::CopiedPreparation(_)
        | EffectFaultProbe::CopiedBarrier(_)
        | EffectFaultProbe::CopiedOwnership(_)
        | EffectFaultProbe::PermanentLocalObservation(_)
        | EffectFaultProbe::PermanentLocalReclaim(_)
        | EffectFaultProbe::PermanentLocalProgress(_)
        | EffectFaultProbe::Other => Kind::Other,
    }
}

#[async_trait::async_trait]
impl LocalFs for ProbeFs {
    type Lock = TokioFileLock;

    async fn initialize_publication(
        &self,
        request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        TokioLocalFs.initialize_publication(request).await
    }

    fn retain_native_exclusion(&self, held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        if self.0.deny_retention.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "fixture native retention unavailable",
            ));
        }
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        let observed = kind(&effect);
        self.0.effects.lock().unwrap().push(observed.clone());
        let action = {
            let mut hooks = self.0.hooks.lock().unwrap();
            let found = hooks.iter_mut().position(|hook| {
                if hook.select.matches(&observed) {
                    hook.seen += 1;
                    hook.seen == hook.occurrence
                } else {
                    false
                }
            });
            found.map(|index| hooks.remove(index).action)
        };
        let mut swallow = false;
        match action {
            Some(Action::Stop) => {
                return Err(
                    std::io::Error::other("fixture stops exact selected native command").into(),
                );
            }
            Some(Action::Noop) => return Ok(()),
            Some(Action::Fault(fault)) => effect = effect.inject_test_faults(vec![fault]),
            Some(Action::Swallow(fault)) => {
                effect = effect.inject_test_faults(vec![fault]);
                swallow = true;
            }
            Some(Action::Hold(phase, arrived, release)) => effect.gates.push(TestGate {
                phase,
                arrived,
                release,
            }),
            None => {}
        }
        let result = TokioLocalFs.execute_retained_effect(effect).await;
        if let Err(error) = &result {
            self.0.native_errors.lock().unwrap().push(error.to_string());
        }
        if swallow {
            assert!(result.is_err());
            Ok(())
        } else {
            result
        }
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        let bytes = if length == 32 {
            let forced = self.0.forced_nonce.lock().unwrap().take();
            match forced {
                Some(nonce) => nonce.to_vec(),
                None => TokioLocalFs.random_bytes(length).await?,
            }
        } else {
            TokioLocalFs.random_bytes(length).await?
        };
        if length == 16 {
            self.0
                .entropy16
                .lock()
                .unwrap()
                .push(bytes.as_slice().try_into().unwrap());
        }
        if length == 32 {
            self.0
                .entropy32
                .lock()
                .unwrap()
                .push(bytes.as_slice().try_into().unwrap());
        }
        Ok(bytes)
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }
    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        if let Some(signal) = self.0.lock_attempt.lock().unwrap().take() {
            signal.send(()).unwrap();
        }
        TokioLocalFs.lock_existing_exclusive(path).await
    }
    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read(path).await
    }
    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_nofollow(path).await
    }
    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.read_range(path, range).await
    }
    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }
    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }
    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }
    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.0.ordinary_writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.write_new(path, bytes).await
    }
    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.create_dir_all(path).await
    }
    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.ordinary_writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.remove_file(path).await
    }
    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.ordinary_writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename(from, to).await
    }
    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.ordinary_writes.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.rename_no_replace(from, to).await
    }
    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }
    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }
}

/// Owns an actual freshly initialized namespace and independent operator configuration.
pub(super) struct Fixture {
    /// The genuine writable bucket.
    pub(super) bucket: Bucket,
    /// The exact configuration for ordinary reopening or explicit copy.
    pub(super) config: FileBucketConfig,
    /// The existing actual effect/read binding.
    pub(super) fs: ProbeFs,
    /// The actual destination-specific external control location.
    pub(super) control: PathBuf,
}

/// Creates a fresh real native factory fixture without journal backfill.
///
/// # Panics
/// Panics if independent administration setup or native initialization fails.
pub(super) async fn fixture() -> Fixture {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let tag: String = TokioLocalFs
        .random_bytes(16)
        .await
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let root = std::env::temp_dir().join(format!("terrane-creation-{tag}"));
    let administration = root.with_extension("operator");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&administration)
        .unwrap();
    let operator_uid = std::fs::symlink_metadata(&administration).unwrap().uid();
    let config = FileBucketConfig {
        root,
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid,
            control: None,
        }),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: ChunkProfile::cdc_1m([0; 32]),
        locality: Locality::default(),
    };
    let control = control(&config.root);
    let fs = ProbeFs::default();
    let bucket = FileBucket::open(config.clone(), fs.clone(), TokioClock, Validator)
        .await
        .unwrap();
    fs.clear();
    Fixture {
        bucket,
        config,
        fs,
        control,
    }
}

/// Derives the registered default external-control path independently.
pub(super) fn control(root: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let suffix: String = blake3::hash(root.as_os_str().as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    root.with_file_name(format!(".terrane-control:{suffix}"))
}

/// Seals a genuine canonical whole pack with independently named chunk bytes.
///
/// # Panics
/// Panics if entropy, canonical body append or sealing fails.
pub(super) async fn pack() -> SealedPack {
    let mut writer = PackWriter::new(
        PackId::generate(&TokioLocalFs).await.unwrap(),
        PackClass::Data,
        false,
    );
    writer
        .append_raw(EntryKind::Chunk, b"native whole pack body")
        .unwrap();
    writer.seal().unwrap()
}

/// Runs the actual whole-pack ContentStore writer.
///
/// # Errors
/// Preserves native admission, capture, closed acknowledgment and catalog failures.
///
/// # Panics
/// Panics only if the sealed fixture cannot form a metadata upload.
pub(super) async fn put(bucket: &Bucket, pack: &SealedPack) -> Result<Identity, StoreFailure> {
    bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Pack, pack.bytes()).unwrap(),
        ))
        .await
}

/// Derives the exact external journal pathname independently of production helpers.
pub(super) fn journal(control: &Path, key: &str) -> PathBuf {
    let suffix: String = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    control.join(".terrane-creation").join(suffix)
}

/// Returns complete selected inventory from the actual materialized current generation.
///
/// # Panics
/// Panics if current CAPABILITIES or MANIFEST cannot be read and decoded.
pub(super) async fn inventory(root: &Path) -> Vec<PackInventoryEntry> {
    let cap =
        BucketCapabilities::decode(&tokio::fs::read(root.join("CAPABILITIES")).await.unwrap())
            .unwrap();
    let Some(generation) = cap.generation else {
        return Vec::new();
    };
    GenerationManifest::decode(
        &tokio::fs::read(root.join(format!("objects/index/{generation}/MANIFEST")))
            .await
            .unwrap(),
    )
    .unwrap()
    .inventory
    .unwrap()
}

/// Captures exact file names and bytes, including protected controls and staging.
///
/// # Panics
/// Panics if a fixture node cannot be enumerated or read.
pub(super) async fn image(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let mut entries = tokio::fs::read_dir(&path).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if entry.file_type().await.unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    tokio::fs::read(entry.path()).await.unwrap(),
                );
            }
        }
    }
    result
}

fn uint(bytes: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        bytes.push(major | value as u8);
    } else if value <= 255 {
        bytes.extend([major | 24, value as u8]);
    } else if value <= 65535 {
        bytes.push(major | 25);
        bytes.extend((value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        bytes.push(major | 26);
        bytes.extend((value as u32).to_be_bytes());
    } else {
        bytes.push(major | 27);
        bytes.extend(value.to_be_bytes());
    }
}

fn blob(bytes: &mut Vec<u8>, major: u8, body: &[u8]) {
    uint(bytes, major, body.len() as u64);
    bytes.extend(body);
}

/// Encodes predicted Pending independently of the registered production encoder.
pub(super) fn pending_bytes(key: &str, nonce: [u8; 32]) -> Vec<u8> {
    let mut bytes = vec![0xa4, 0, 1, 1];
    blob(&mut bytes, 0x60, key.as_bytes());
    bytes.push(2);
    blob(&mut bytes, 0x40, &nonce);
    bytes.extend([3, 0]);
    bytes
}

/// Predicts native Committed bytes from independent actual metadata and body hashes.
///
/// # Panics
/// Panics if fixture metadata or registered opaque identities cannot be observed.
pub(super) fn committed_bytes(root: &Path, key: &str, body: &[u8], nonce: [u8; 32]) -> Vec<u8> {
    use std::os::unix::fs::MetadataExt;
    let kind = if key.ends_with(".pack") {
        IdentityKind::Pack
    } else {
        IdentityKind::Index
    };
    let digest = TERRANE_V1
        .calculate(kind, body)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let metadata = std::fs::symlink_metadata(root.join(key)).unwrap();
    let mut identity = Vec::new();
    identity.extend(metadata.dev().to_be_bytes());
    identity.extend(metadata.ino().to_be_bytes());
    let mut bytes = vec![0xa6, 0, 1, 1];
    blob(&mut bytes, 0x60, key.as_bytes());
    bytes.push(2);
    blob(&mut bytes, 0x40, &nonce);
    bytes.extend([3, 1, 4, 0x83, u8::from(kind == IdentityKind::Index)]);
    blob(&mut bytes, 0x40, &digest);
    uint(&mut bytes, 0, body.len() as u64);
    bytes.push(5);
    blob(&mut bytes, 0x40, &identity);
    bytes
}

/// Verifies actual journal bytes against independent canonical output expectations.
///
/// # Panics
/// Panics if bytes, nonce, binding or physical incarnation differ from the oracle.
pub(super) async fn assert_committed(fixture: &Fixture, key: &str, body: &[u8]) -> CreationJournal {
    let actual = tokio::fs::read(journal(&fixture.control, key))
        .await
        .unwrap();
    let decoded = CreationJournal::decode(&actual).unwrap();
    assert_eq!(
        actual,
        committed_bytes(fixture.bucket.root(), key, body, decoded.nonce)
    );
    assert!(fixture.fs.nonces().contains(&decoded.nonce));
    assert!(matches!(decoded.state, JournalState::Committed { .. }));
    decoded
}

/// Leaves a real staged pair unselected by failing its actual catalog slot.
///
/// # Panics
/// Panics if staging fails early or membership is published despite the fault.
pub(super) async fn unselected(fixture: &Fixture, pack: &SealedPack) {
    fixture
        .fs
        .arm(Select::Catalog(fixture.control.clone()), 1, Action::Stop);
    assert!(matches!(
        put(&fixture.bucket, pack).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    fixture.fs.assert_consumed();
    assert!(inventory(fixture.bucket.root()).await.is_empty());
    assert_committed(fixture, &pack.header().id().pack_key(), pack.bytes()).await;
    assert_committed(
        fixture,
        &pack.header().id().index_key(),
        pack.index_object(),
    )
    .await;
}

/// Constructs a valid claimed DeleteOwned baseline without conferring authority.
///
/// # Panics
/// Panics if the baseline journal cannot form its canonical registered ownership key.
pub(super) fn owned(record: &CreationJournal) -> Vec<u8> {
    let JournalState::Committed {
        binding,
        file_identity,
    } = &record.state
    else {
        panic!("valid baseline requires Committed");
    };
    let id = record
        .key
        .split('/')
        .next_back()
        .unwrap()
        .split('.')
        .next()
        .unwrap();
    let bytes = CreationJournal {
        key: record.key.clone(),
        nonce: record.nonce,
        state: JournalState::DeleteOwned {
            binding: binding.clone(),
            file_identity: file_identity.clone(),
            operation_key: format!("gc/1/delete/{id}/{}", "11".repeat(32)),
            authorization: [9; 32],
        },
    }
    .encode()
    .unwrap();
    let decoded = CreationJournal::decode(&bytes).unwrap();
    assert!(matches!(decoded.state, JournalState::DeleteOwned { .. }));
    assert_eq!(decoded.key, record.key);
    assert_eq!(decoded.nonce, record.nonce);
    bytes
}

/// Requires the exact nonmutating current-projection repair before a put refusal.
///
/// # Panics
/// Panics if any creator, catalog or unexpected command is submitted.
pub(super) fn assert_current_repair(fixture: &Fixture) {
    assert_eq!(
        fixture.fs.effects(),
        vec![Kind::Directory(fixture.bucket.root().to_owned())]
    );
}

/// Verifies exact current-open probes and only its conditional probe-time publication.
///
/// The real clock may remain within the original second or advance. The latter
/// selects a CAP-only raw successor, preserving all other selected state.
///
/// # Panics
/// Panics on unreadable or inconsistent publication data, unexpected commands,
/// extra entropy, changed state outside probe time, or creator effects.
pub(super) async fn assert_current_open(
    fixture: &Fixture,
    before_cap: &[u8],
    before_pointer: &[u8],
) {
    use terrane_core::gc::publication::{
        LogicalChange, PortableCurrent, PortableSnapshot, ProjectionEntry, PublicationCommit,
        PublicationProof, PublicationTransaction,
    };
    let root = fixture.bucket.root();
    let path = root.join("CAPABILITIES");
    let after_cap = tokio::fs::read(&path).await.unwrap();
    let after_pointer = tokio::fs::read(root.join("publication/PORTABLE"))
        .await
        .unwrap();
    let old_cap = BucketCapabilities::decode(before_cap).unwrap();
    let mut new_cap = BucketCapabilities::decode(&after_cap).unwrap();
    new_cap.probed_at = old_cap.probed_at;
    assert_eq!(new_cap.encode().unwrap(), before_cap);

    let mut expected = vec![
        Kind::Directory(root.to_owned()),
        Kind::Write(path.clone()),
        Kind::Write(fixture.control.join("backend-registration.cbor")),
        Kind::Range {
            path: path.clone(),
            start: 0,
            expected: before_cap[..1].to_vec(),
        },
        Kind::Directory(root.to_owned()),
    ];
    let effects = fixture.fs.effects();
    assert!(effects.len() >= expected.len());
    assert_eq!(&effects[..expected.len()], expected.as_slice());
    assert!(
        !effects
            .iter()
            .any(|kind| matches!(kind, Kind::Pending(_) | Kind::Seal(_) | Kind::Commit(_)))
    );

    if after_cap == before_cap {
        assert_eq!(after_pointer, before_pointer);
        assert!(fixture.fs.nonces().is_empty());
        assert!(fixture.fs.0.entropy16.lock().unwrap().is_empty());
        assert_eq!(effects, expected);
        return;
    }
    let previous = PortableCurrent::decode(before_pointer).unwrap();
    let previous_snapshot =
        PortableSnapshot::decode(&tokio::fs::read(root.join(&previous.key)).await.unwrap())
            .unwrap();
    let revision = previous_snapshot.revision + 1;
    let before_slot_bytes = tokio::fs::read(
        fixture
            .control
            .join(format!("publication/commits/{}", revision - 1)),
    )
    .await
    .unwrap();
    let before_slot = PublicationCommit::decode(&before_slot_bytes).unwrap();
    let before_transaction = PublicationTransaction::decode(
        &tokio::fs::read(fixture.control.join(&before_slot.transaction_key))
            .await
            .unwrap(),
    )
    .unwrap();
    let operation_nonces = fixture.fs.nonces();
    assert_eq!(operation_nonces.len(), 1);
    let operation = hex(&operation_nonces[0]);
    let temporary_nonces = fixture.fs.0.entropy16.lock().unwrap().clone();
    assert_eq!(temporary_nonces.len(), 5);
    let targets = [
        root.join(format!("publication/snapshots/{revision}:{operation}")),
        fixture
            .control
            .join(format!("publication/transactions/{operation}")),
        fixture
            .control
            .join(format!("publication/commits/{revision}")),
        root.join("publication/PORTABLE"),
        path,
    ];
    for (index, (target, nonce)) in targets.iter().zip(&temporary_nonces).enumerate() {
        if index == 2 {
            // Complete staged-payload verification precedes the selecting slot.
            expected.push(Kind::Directory(root.to_owned()));
        }
        expected.push(Kind::Write(
            target
                .parent()
                .unwrap()
                .join(format!(".terrane-tmp:{}", hex(nonce))),
        ));
        expected.push(Kind::FileSync);
        expected.push(Kind::Rename(target.clone()));
    }
    expected.push(Kind::Directory(root.to_owned()));
    expected.push(Kind::RawPublicationAck(
        fixture
            .control
            .join(format!("publication/commits/{revision}")),
    ));
    assert_eq!(effects, expected);
    assert_eq!(fixture.fs.ordinary_writes(), 0);

    let current = PortableCurrent::decode(&after_pointer).unwrap();
    assert_eq!(root.join(&current.key), targets[0]);
    let snapshot_bytes = tokio::fs::read(&targets[0]).await.unwrap();
    assert_eq!(current.digest, *blake3::hash(&snapshot_bytes).as_bytes());
    let snapshot = PortableSnapshot::decode(&snapshot_bytes).unwrap();
    assert_eq!(snapshot.revision, revision);
    assert_eq!(snapshot.origin, previous_snapshot.origin);
    assert_eq!(snapshot.predecessor, Some(previous));
    assert_eq!(
        snapshot.projection,
        vec![ProjectionEntry {
            key: "CAPABILITIES".into(),
            value: Some(after_cap.clone())
        }]
    );
    let transaction_bytes = tokio::fs::read(&targets[1]).await.unwrap();
    let transaction = PublicationTransaction::decode(&transaction_bytes).unwrap();
    transaction.check_snapshot(&snapshot_bytes).unwrap();
    assert_eq!(transaction.nonce, operation_nonces[0]);
    assert_eq!(transaction.proof, PublicationProof::Raw);
    assert_eq!(transaction.snapshot, current);
    assert_eq!(transaction.old, Some(before_transaction.new.clone()));
    assert_eq!(
        transaction.changes,
        vec![LogicalChange {
            key: "CAPABILITIES".into(),
            expected: Some(before_cap.to_vec()),
            new: Some(after_cap)
        }]
    );
    let mut normalized = transaction.new;
    assert_eq!(normalized.revision, revision);
    normalized.revision = before_transaction.new.revision;
    assert_eq!(normalized, before_transaction.new);
    let slot = PublicationCommit::decode(&tokio::fs::read(&targets[2]).await.unwrap()).unwrap();
    assert_eq!(slot.revision, revision);
    assert_eq!(
        slot.predecessor,
        Some(*blake3::hash(&before_slot_bytes).as_bytes())
    );
    assert_eq!(fixture.control.join(slot.transaction_key), targets[1]);
    assert_eq!(
        slot.transaction_digest,
        *blake3::hash(&transaction_bytes).as_bytes()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
