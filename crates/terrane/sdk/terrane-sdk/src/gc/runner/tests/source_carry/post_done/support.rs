//! Observes exact selected sources and completes real ordinary local-v1 deletion.

use super::super::support::{PublicFixture, rounded_modified};
use super::fs::ProbeFs;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig, held::SingleHeld};
use crate::domain::DomainNamespace;
use crate::gc::runner::Collection;
use crate::guard::Guard;
use crate::pack::PackId;
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::native_publication_effects::collection::test_fs::TestClock;
use crate::store::{Clock, ContentStore};
use std::collections::BTreeMap;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::bucket::{BucketCapabilities, BucketKey, GenerationManifest};
use terrane_format::gc::publication::evidence::{CheckedLineage, PhysicalRegistration};
use terrane_format::gc::publication::{PublicationState, PublicationTransaction};
use terrane_format::gc::{CreationJournal, DeleteOperation, DeletePhase, JournalState};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::refs::RefRecord;

/// Names the reopened native repository with the actual metadata validator.
pub(super) type NativeRepository =
    Repository<FileBucket<ProbeFs, TestClock, MetadataValidator>, TestClock, ProbeFs>;

/// Captures a real named file's entire body and physical incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Physical {
    /// Actual recorded path, never reconstructed as publication authority.
    pub(super) path: PathBuf,
    /// Complete bytes independently read from the actual file.
    pub(super) bytes: Vec<u8>,
    /// Actual device and inode of the observed regular file.
    pub(super) identity: (u64, u64),
}

impl Physical {
    /// Captures actual no-symlink regular-file identity and whole bytes.
    ///
    /// # Panics
    /// Panics on missing, replaced or nonregular fixture files.
    pub(super) fn read(path: &Path) -> Self {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file());
        let bytes = std::fs::read(path).unwrap();
        let after = std::fs::symlink_metadata(path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), (after.dev(), after.ino()));
        Self {
            path: path.to_owned(),
            bytes,
            identity: (metadata.dev(), metadata.ino()),
        }
    }

    /// Requires the same whole body and named physical incarnation.
    ///
    /// # Panics
    /// Panics when the real file has changed or disappeared.
    pub(super) fn assert_current(&self) {
        assert_eq!(Self::read(&self.path), *self);
    }
}

/// Captures the physical protection of an actually consumed control directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ControlDirectory {
    /// Actual path containing consumed Original records.
    pub(super) path: PathBuf,
    /// Observed device and inode of the directory.
    pub(super) identity: (u64, u64),
    /// Actual operator ownership and permission bits.
    pub(super) protection: (u32, u32),
}

impl ControlDirectory {
    fn read(path: &Path) -> Self {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_dir());
        Self {
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
            protection: (metadata.uid(), metadata.mode() & 0o777),
        }
    }
}

/// Retains complete independently selected source and consumed physical controls.
#[derive(Clone)]
pub(super) struct Snapshot {
    /// Whole source record actually selected by the authoritative transaction.
    pub(super) record: RefRecord,
    /// Complete decoded selected lineage at the current loss generation.
    pub(super) lineage: CheckedLineage,
    /// Entire selected publication state.
    pub(super) state: PublicationState,
    /// Entire selected logical projection, including source history and catalog.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Complete actual selected generation manifest.
    pub(super) manifest: GenerationManifest,
    /// Actual whole-ref transaction, selected history, Guard and lineage files.
    pub(super) selected_files: Vec<Physical>,
    /// Every actually consumed Original/import control file and incarnation.
    pub(super) controls: Vec<Physical>,
    /// Actual protection and incarnation of each consumed control directory.
    pub(super) control_directories: Vec<ControlDirectory>,
}

/// Reopens real source storage and existing retention using the native adapter.
///
/// # Panics
/// Panics if actual configured storage or independently retained authority fails.
pub(super) async fn reopen(fixture: &PublicFixture, fs: &ProbeFs) -> NativeRepository {
    let old = fixture.repository.coordinator();
    let original = old.guard().configured_original_authority().unwrap();
    let store = old.store();
    let (name, profile) = store.publication_profile();
    let operator = store.publication_operator_uid().unwrap();
    // Release this real namespace exclusion before open reacquires it for the
    // capability probe. The prior whole value comes from selected authority.
    let (before_state, before_logical) = {
        let holder = SingleHeld::acquire(store).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let prior = (observed.state().clone(), observed.logical().clone());
        observed.revalidate().await.unwrap();
        prior
    };
    let before_cap =
        BucketCapabilities::decode(before_logical["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let probe_start = fixture
        .clock
        .now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: store.root().to_owned(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: operator,
                control: None,
            }),
            chunk_profile_name: name.into(),
            chunk_profile: profile.clone(),
            locality: old.guard().config().home.clone(),
        },
        fs.clone(),
        fixture.clock.clone(),
        MetadataValidator::new(profile.clone()),
    )
    .await
    .unwrap();
    let probe_end = fixture
        .clock
        .now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Observe the actual opened bucket before Guard/retention setup. Only the
    // timestamp sampled inside this genuine open can change the whole CAP.
    let probed_capabilities = {
        let holder = SingleHeld::acquire(&bucket).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let after_cap =
            BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap())
                .unwrap();
        assert!(probe_start <= after_cap.probed_at);
        assert!(after_cap.probed_at <= probe_end);
        let mut expected_cap = before_cap;
        expected_cap.probed_at = after_cap.probed_at;
        assert_eq!(after_cap, expected_cap);
        let encoded = expected_cap.encode().unwrap();
        let changed = before_logical["CAPABILITIES"].as_deref() != Some(encoded.as_slice());
        let mut expected_state = before_state;
        expected_state.revision = expected_state
            .revision
            .checked_add(u64::from(changed))
            .unwrap();
        assert_eq!(*observed.state(), expected_state);
        let mut expected_logical = before_logical;
        expected_logical.insert("CAPABILITIES".into(), Some(encoded.clone()));
        assert_eq!(*observed.logical(), expected_logical);
        observed.revalidate().await.unwrap();
        encoded
    };
    let guard = Guard::new(
        bucket,
        fixture.clock.clone(),
        old.guard().keys().to_vec(),
        old.guard().config().clone(),
    );
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        fs.clone(),
    );
    let repository = Repository::reopen_native_retention(
        coordinator,
        &DomainNamespace {
            root: original.root().to_owned(),
            domain: original.domain().into(),
        },
        original.control(),
        operator,
    )
    .await
    .unwrap();
    // Retention setup must not replace the separately proven probe successor.
    {
        let holder = SingleHeld::acquire(repository.coordinator().store())
            .await
            .unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        assert_eq!(
            observed.logical()["CAPABILITIES"].as_deref(),
            Some(probed_capabilities.as_slice())
        );
        observed.revalidate().await.unwrap();
    }
    repository
}

/// Captures current whole source evidence under the real backend exclusion.
///
/// # Panics
/// Panics on incomplete selection, malformed lineage or unavailable controls.
pub(super) async fn snapshot(repository: &NativeRepository, source: &str) -> Snapshot {
    let holder = SingleHeld::acquire(repository.coordinator().store())
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let source_key = BucketKey::ref_record(source).unwrap();
    let record_bytes = observed.logical()[source_key.as_str()].as_deref().unwrap();
    let record = RefRecord::decode(record_bytes).unwrap();
    let lineage_read = held
        .selected_lineage_record(&observed, source)
        .await
        .unwrap()
        .unwrap();
    let lineage = CheckedLineage::decode(lineage_read.bytes().unwrap()).unwrap();
    assert_eq!(lineage.source, record);
    let commit = held
        .get(
            &TERRANE_V1
                .from_digest(IdentityKind::Commit, &record.commit)
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(commit, lineage.commit_bytes);
    assert_eq!(lineage.loss_generation, observed.state().loss_generation);
    assert!(lineage.used.check_supported_view_contexts().unwrap());
    let mut reads = held
        .selected_source_history_records(&observed, source, &record)
        .await
        .unwrap();
    reads.push(lineage_read);
    reads.push(
        held.selected_guard_snapshot_record(&observed)
            .await
            .unwrap()
            .unwrap(),
    );
    // History receipts are committed logs; independently include the immutable
    // transaction selecting the complete source ref's whole bytes.
    reads.push(
        observed
            .physical_reads()
            .iter()
            .rev()
            .find(|read| {
                read.bytes()
                    .and_then(|body| PublicationTransaction::decode(body).ok())
                    .is_some_and(|tx| {
                        tx.changes.iter().any(|change| {
                            change.key == source_key.as_str()
                                && change.new.as_deref() == Some(record_bytes)
                        })
                    })
            })
            .cloned()
            .unwrap(),
    );
    let mut selected_files = Vec::new();
    for read in reads {
        let file = Physical::read(read.path());
        assert_eq!(file.bytes.as_slice(), read.bytes().unwrap());
        let metadata = read.metadata().unwrap();
        assert_eq!(file.identity, (metadata.dev(), metadata.ino()));
        selected_files.push(file);
    }
    let mut controls = Vec::new();
    let mut control_directories = Vec::new();
    for pin in &lineage.controls {
        let PhysicalRegistration::Local(owner) = &pin.owner else {
            panic!("local fixture consumed nonlocal controls");
        };
        let directory = Path::new(std::ffi::OsStr::from_bytes(&owner.control));
        let captured_directory = ControlDirectory::read(directory);
        if !control_directories.contains(&captured_directory) {
            control_directories.push(captured_directory);
        }
        let file = Physical::read(&directory.join(&pin.key));
        pin.check_record(&file.bytes).unwrap();
        controls.push(file);
    }
    assert!(!controls.is_empty());
    // Stable administrative exclusion is an actual protected file too. These
    // observations are preservation oracles; genuine operations acquire it.
    for directory in &control_directories {
        controls.push(Physical::read(&directory.path.join("retention.lock")));
    }
    let cap =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{}/MANIFEST", cap.generation.unwrap())]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let result = Snapshot {
        record,
        lineage,
        state: observed.state().clone(),
        logical: observed.logical().clone(),
        manifest,
        selected_files,
        controls,
        control_directories,
    };
    observed.revalidate().await.unwrap();
    result
}

/// Requires every carried source semantic and physical control to survive Done.
///
/// # Panics
/// Panics on changed source history, lineage, interpretation or physical control.
pub(super) fn assert_preserved(before: &Snapshot, after: &Snapshot, reopened: bool) {
    assert_eq!(after.record, before.record);
    assert_eq!(after.lineage, before.lineage);
    assert!(after.state.revision >= before.state.revision);
    let mut expected = before.state.clone();
    expected.revision = after.state.revision;
    assert_eq!(after.state, expected);
    assert_eq!(after.manifest, before.manifest);
    for (key, body) in &before.logical {
        if key == "gc/lease" {
            continue;
        }
        if reopened && key == "CAPABILITIES" {
            let old = BucketCapabilities::decode(body.as_deref().unwrap()).unwrap();
            let new = BucketCapabilities::decode(after.logical[key].as_deref().unwrap()).unwrap();
            let mut expected = old;
            expected.probed_at = new.probed_at;
            assert_eq!(new, expected);
            continue;
        }
        assert_eq!(after.logical.get(key), Some(body), "selected value {key}");
    }
    assert_eq!(after.selected_files, before.selected_files);
    assert_eq!(after.controls, before.controls);
    assert_eq!(after.control_directories, before.control_directories);
    for directory in &before.control_directories {
        assert_eq!(ControlDirectory::read(&directory.path), *directory);
    }
    for file in before.selected_files.iter().chain(&before.controls) {
        file.assert_current();
    }
}

fn journal(control: &Path, key: &str) -> PathBuf {
    let name: String = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    control.join(".terrane-creation").join(name)
}

/// Retires and physically deletes an actual unrelated pack using fresh current marks.
///
/// # Panics
/// Panics on incomplete current marking, changed carry, abbreviated D or false Done.
pub(super) async fn delete_orphan(
    fixture: &PublicFixture,
    repository: &NativeRepository,
    source: &str,
    pack: PackId,
    modified: u64,
    fs: &ProbeFs,
) -> Snapshot {
    let base = modified.checked_add(61).unwrap();
    fixture.clock.set(base, base.checked_sub(100).unwrap());
    let authority = repository
        .coordinator()
        .guard()
        .configured_original_authority()
        .unwrap();
    let mut collection = Collection::start(
        repository.coordinator().guard(),
        &authority,
        "post-done-source-collector".into(),
        1_000,
        51,
        super::super::super::windows(),
    )
    .await
    .unwrap();
    while !collection.state().pending.is_empty() {
        collection.mark_batch(32).await.unwrap();
    }
    collection.finish_mark().await.unwrap();
    assert_eq!(collection.state().phase, terrane_format::gc::Phase::Sweep);
    let limit = snapshot(repository, source)
        .await
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .len();
    let mut retired = std::collections::BTreeSet::new();
    let selected = loop {
        assert!(retired.len() < limit, "seeded orphan was never retired");
        let before = snapshot(repository, source).await;
        let trash = collection
            .retire_one(repository.coordinator())
            .await
            .unwrap()
            .unwrap();
        assert!(retired.insert(trash.pack));
        let after = snapshot(repository, source).await;
        assert_eq!(
            after.state.loss_generation,
            before.state.loss_generation.checked_add(1).unwrap()
        );
        assert_eq!(after.lineage.source, before.lineage.source);
        assert_eq!(after.lineage.commit_bytes, before.lineage.commit_bytes);
        assert_eq!(after.lineage.original, before.lineage.original);
        assert_eq!(after.lineage.controls, before.lineage.controls);
        assert_eq!(
            after.lineage.used.view_interpretations,
            before.lineage.used.view_interpretations
        );
        assert_eq!(after.controls, before.controls);
        if trash.pack == *pack.as_bytes() {
            break after;
        }
    };
    let exclusion = selected
        .manifest
        .exclusions
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| row.pack_id == *pack.as_bytes())
        .unwrap()
        .clone();
    let root = repository.coordinator().store().root();
    let keys = [
        pack.pack_key(),
        pack.index_key(),
        format!("trash/{}/{pack}", exclusion.cycle),
    ];
    let files = keys.each_ref().map(|key| Physical::read(&root.join(key)));
    let upper = rounded_modified(&files[0].path).max(rounded_modified(&files[1].path));
    assert_eq!(upper, modified);
    // The last selected receipt is the actual complete source transaction.
    let source_transaction = selected.selected_files.last().unwrap();
    assert_eq!(
        source_transaction
            .path
            .parent()
            .unwrap()
            .file_name()
            .unwrap(),
        "transactions"
    );
    let control = source_transaction
        .path
        .ancestors()
        .nth(3)
        .unwrap()
        .to_owned();
    let journals = keys.each_ref().map(|key| {
        CreationJournal::decode(&std::fs::read(journal(&control, key)).unwrap()).unwrap()
    });
    for (index, creator) in journals.iter().enumerate() {
        assert_eq!(creator.key, keys[index]);
        let JournalState::Committed { file_identity, .. } = &creator.state else {
            panic!("genuine creator must be Committed");
        };
        let (device, inode) = files[index].identity;
        assert_eq!(
            file_identity,
            &[device.to_be_bytes(), inode.to_be_bytes()].concat()
        );
    }
    fixture.clock.enable_timer();
    let ownership_started = fixture.clock.monotonic();
    let owned = collection
        .own_local_pack(repository.coordinator(), exclusion)
        .await
        .unwrap();
    let observed_elapsed = fixture
        .clock
        .monotonic()
        .checked_sub(ownership_started)
        .unwrap();
    assert!(observed_elapsed >= Duration::from_secs(super::super::super::windows().deletion()));
    assert_eq!(owned.phase, DeletePhase::Invalidated);
    assert!(
        owned.authorization.elapsed_ns
            >= super::super::super::windows()
                .deletion()
                .checked_mul(1_000_000_000)
                .unwrap()
    );
    assert_eq!(owned.authorization.index_witness, files[1].bytes);
    let key = owned.authorization.operation_key();
    let done = collection
        .resume_local_delete(repository.coordinator(), &key)
        .await
        .unwrap();
    assert_eq!(done.phase, DeletePhase::Done);
    assert_eq!(done.authorization, owned.authorization);
    assert_eq!(
        DeleteOperation::decode(&std::fs::read(control.join(&key)).unwrap(), &key).unwrap(),
        done
    );
    fs.assert_done_effect();
    for (index, file) in files.iter().enumerate() {
        assert_eq!(
            std::fs::symlink_metadata(&file.path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let creator =
            CreationJournal::decode(&std::fs::read(journal(&control, &keys[index])).unwrap())
                .unwrap();
        assert_eq!(creator.nonce, journals[index].nonce);
        let version = &done.authorization.artifacts[index];
        assert_eq!(
            creator.state,
            JournalState::DeleteOwned {
                binding: version.binding.clone(),
                file_identity: version.file_identity.clone(),
                operation_key: key.clone(),
                authorization: done.authorization.digest().unwrap()
            }
        );
    }
    let completed = snapshot(repository, source).await;
    assert_preserved(&selected, &completed, false);
    drop(collection);
    completed
}
