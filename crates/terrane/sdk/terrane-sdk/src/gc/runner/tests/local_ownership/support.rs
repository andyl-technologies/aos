//! Builds genuine signed native history, retired triples and independent owner oracles.

use crate::bucket::{FileBucket, held::SingleHeld};
use crate::domain::DomainNamespace;
use crate::gc::runner::fixture::{Fixture as OriginalFixture, Validator};
use crate::gc::runner::{Collection, CollectionError};
use crate::guard::{Guard, OriginalAuthority};
use crate::pack::{PackId, PackIndexSnapshot};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::Repository;
use crate::store::native_publication_effects::collection_local_ownership::OwnershipFs;
use crate::store::{
    ChunkPosition, ChunkUpload, Clock, ContentStore, ContentUpload, NativeEffectClock,
    StoreErrorKind,
};
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::auth::IssuerKey;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest, PackExclusion};
use terrane_format::gc::publication::PublicationState;
use terrane_format::gc::{CreationJournal, DeleteOperation, DeletePhase, GcLease, JournalState};
use terrane_format::gc::{Phase, Windows};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::refs::Locality;

/// Requires successful real setup or an independently observed record.
pub(super) trait Required<T> {
    /// Returns the asserted success value.
    ///
    /// # Panics
    /// Panics with the original diagnostic when the actual operation fails.
    #[track_caller]
    fn require(self) -> T;
}

impl<T, E: std::fmt::Debug> Required<T> for Result<T, E> {
    #[track_caller]
    fn require(self) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("required native operation failed: {error:?}"),
        }
    }
}

impl<T> Required<T> for Option<T> {
    #[track_caller]
    fn require(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("required native record is absent"),
        }
    }
}

/// Requires a typed actual refusal instead of accepting arbitrary unit success.
pub(super) trait Rejected<E> {
    /// Returns the independently asserted refused result.
    ///
    /// # Panics
    /// Panics when the actual operation unexpectedly succeeds.
    #[track_caller]
    fn require_error(self) -> E;
}

impl<T, E> Rejected<E> for Result<T, E> {
    #[track_caller]
    fn require_error(self) -> E {
        match self {
            Err(error) => error,
            Ok(_) => panic!("native operation unexpectedly succeeded"),
        }
    }
}

/// Names genuine storage with finite ownership observation.
pub(super) type Bucket = FileBucket<OwnershipFs, NativeEffectClock, Validator>;
/// Names its supported genuinely reopened retained repository.
pub(super) type NativeRepository = Repository<Bucket, NativeEffectClock, OwnershipFs>;
/// Names a collector with a real Session and the same injected retained clock.
pub(super) type NativeCollection<'a> =
    Collection<'a, OwnershipFs, NativeEffectClock, Validator, NativeEffectClock>;

/// Retains independently published source history and an ordinary instrumented reopen.
pub(super) struct Fixture {
    /// Actual initial signed publication and original retention setup.
    pub(super) base: OriginalFixture,
    /// Genuine reopened repository supplying all collector factories.
    pub(super) repository: NativeRepository,
    /// Actual original registration resolved by this reopened repository.
    pub(super) authority: OriginalAuthority,
    /// Transparent native executor with finite fault observation.
    pub(super) fs: OwnershipFs,
}

impl Fixture {
    /// Reopens genuine source output without constructing maintenance authority.
    ///
    /// # Panics
    /// Panics if ordinary native reopen or original verification fails.
    pub(super) async fn new() -> Self {
        let base = OriginalFixture::new().await;
        let fs = OwnershipFs::new(base.fs.clone());
        let bucket = FileBucket::open(
            base.config.clone(),
            fs.clone(),
            base.clock.retain_native_clock().require(),
            Validator,
        )
        .await
        .require();
        let public: [u8; 32] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).require(), 16).require())
            .collect::<Vec<_>>()
            .try_into()
            .require();
        let guard = Guard::new(
            bucket,
            base.clock.retain_native_clock().require(),
            vec![IssuerKey {
                issuer: "fixture".into(),
                key_id: "fixture".into(),
                public_key: public,
                retirement: None,
            }],
            base.guard().config().clone(),
        );
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .require(),
            fs.clone(),
        );
        let repository = Repository::reopen_native_retention(
            coordinator,
            &DomainNamespace {
                root: base.config.root.clone(),
                domain: "public".into(),
            },
            &base.parent.join("original"),
            base.config
                .publication_control
                .as_ref()
                .require()
                .operator_uid,
        )
        .await
        .require();
        let authority = repository
            .coordinator()
            .guard()
            .original_commit(&base.head.commit)
            .require()
            .baseline()
            .authority()
            .clone();
        assert_eq!(
            repository.coordinator().guard().config().home,
            Locality::default()
        );
        Self {
            base,
            repository,
            authority,
            fs,
        }
    }

    /// Borrows the genuine configured Guard that owns current source contexts.
    pub(super) fn guard(&self) -> &Guard<Bucket, NativeEffectClock> {
        self.repository.coordinator().guard()
    }

    /// Reads the actual selected lease under genuine exclusion after an operation ends.
    ///
    /// # Panics
    /// Panics if held current selection or canonical lease decoding fails.
    pub(super) async fn selected_lease(&self) -> GcLease {
        let holder = SingleHeld::acquire(self.guard().store()).await.require();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.require();
        GcLease::decode(observed.logical()["gc/lease"].as_deref().require()).require()
    }

    /// Removes this finite private fixture after all retained operations finish.
    ///
    /// # Panics
    /// Panics if genuine fixture cleanup fails.
    pub(super) fn cleanup(self) {
        drop(self.repository);
        self.base.cleanup();
    }
}

impl std::ops::Deref for Fixture {
    type Target = OriginalFixture;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

/// Captures actual whole selected semantics for independent successor assertions.
pub(super) struct Image {
    /// Actual complete selected state.
    pub(super) state: PublicationState,
    /// Actual selected logical projection.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Actual decoded selected capabilities.
    pub(super) cap: BucketCapabilities,
    /// Actual decoded selected generation manifest.
    pub(super) manifest: GenerationManifest,
}

/// Reads complete authoritative selected semantics under actual backend exclusion.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) async fn image(fixture: &Fixture) -> Image {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.require();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.require();
    let cap = BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().require())
        .require();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{}/MANIFEST", cap.generation.require())]
            .as_deref()
            .require(),
    )
    .require();
    Image {
        state: observed.state().clone(),
        logical: observed.logical().clone(),
        cap,
        manifest,
    }
}

/// Resolves the protected canonical creation-journal path for one physical key.
pub(super) fn journal(fixture: &Fixture, key: &str) -> std::path::PathBuf {
    let suffix = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    fixture
        .parent
        .join("publication/.terrane-creation")
        .join(suffix)
}

/// Rounds an actual descriptor modification time conservatively upward.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) fn rounded_modified(path: &std::path::Path) -> u64 {
    let elapsed = std::fs::symlink_metadata(path)
        .require()
        .modified()
        .require()
        .duration_since(UNIX_EPOCH)
        .require();
    elapsed
        .as_secs()
        .checked_add(u64::from(elapsed.subsec_nanos() != 0))
        .require()
}

/// Creates one unrooted chunk through actual production container admission.
///
/// # Panics
/// Panics when the genuine fixture operation or independent expected record fails.
pub(super) async fn orphan(fixture: &Fixture) -> (PackId, u64) {
    let plaintext = b"unreferenced genuine retirement candidate";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .require();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    let uploaded = fixture
        .guard()
        .store()
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &fixture.config.chunk_profile,
        }))
        .await
        .require();
    assert_eq!(uploaded, identity);
    let before = image(fixture).await;
    let digest = identity.terrane_v1_digest().require();
    let mut candidate = None;
    let mut data = Vec::new();
    for row in before.manifest.inventory.as_ref().require() {
        let id = PackId::from_random_bytes(row.pack_id);
        let bytes = tokio::fs::read(fixture.config.root.join(id.index_key()))
            .await
            .require();
        assert_eq!(&bytes[..6], b"TRPK\x01\x00");
        let index = PackIndexSnapshot::decode(&bytes, before.cap.generation.require()).require();
        if bytes[6] & 2 == 0 {
            data.push(fixture.config.root.join(id.pack_key()));
        }
        if index.entries().iter().any(|row| row.hash() == &digest) {
            assert_eq!(bytes[6] & 2, 0);
            candidate = Some(id);
        }
    }
    let id = candidate.require();
    let upper = rounded_modified(&fixture.config.root.join(id.pack_key()))
        .max(rounded_modified(&fixture.config.root.join(id.index_key())));
    // Establish the injected wall base from actual backend metadata BEFORE
    // acquiring the collector. No file or commit timestamp is rewritten.
    fixture.fs.forbid_data_body_reads(&data).require();
    (id, upper)
}

/// Uses the same unchanged C/G/D/H windows as the existing native runner profile.
pub(super) fn windows() -> Windows {
    Windows::new(30, 60, 60, 90).require()
}

/// Completes genuine marking and retirement with a lease horizon shorter than D.
///
/// # Panics
/// Panics if genuine creation, whole-lease acquisition, marking or retirement fails.
pub(super) async fn retired(fixture: &Fixture) -> (NativeCollection<'_>, PackExclusion) {
    let (pack, upper) = orphan(fixture).await;
    let base = upper
        .checked_add(windows().grace())
        .require()
        .checked_add(1)
        .require();
    fixture.clock.set(base, base.checked_sub(100).require());
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "ownership-collector".into(),
        10,
        51,
        windows(),
    )
    .await
    .require();
    collection.mark_batch(32).await.require();
    collection.finish_mark().await.require();
    assert_eq!(collection.state().phase, Phase::Sweep);
    let trash = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .require()
        .require();
    assert_eq!(trash.pack, *pack.as_bytes());
    let requested = PackExclusion {
        pack_id: trash.pack,
        cycle: trash.cycle,
        epoch: trash.epoch,
    };
    assert!(collection.lease().expiry - base < windows().deletion());
    (collection, requested)
}

/// Captures actual artifact bytes, inode identities and original creator versions.
pub(super) struct TripleImage {
    /// Exact ordered pack/index/Trash physical paths.
    pub(super) paths: [PathBuf; 3],
    /// Exact original bytes independently read before data-body reads are fenced.
    pub(super) bodies: [Vec<u8>; 3],
    /// Exact actual device/inode identities of these three artifacts.
    pub(super) identities: [(u64, u64); 3],
    /// Actual original canonical Committed creator records.
    pub(super) journals: [CreationJournal; 3],
    /// Whole selected semantics apart from the permitted lease-only transitions.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Whole original selected state, allowing only advancing transaction revision.
    pub(super) selected: PublicationState,
}

/// Reads independent original bytes and versions without manufacturing authority.
///
/// # Panics
/// Panics if actual protected creator records or native artifacts are absent.
pub(super) async fn before(fixture: &Fixture, requested: &PackExclusion) -> TripleImage {
    let pack = PackId::from_random_bytes(requested.pack_id);
    let keys = [
        pack.pack_key(),
        pack.index_key(),
        format!("trash/{}/{}", requested.cycle, pack),
    ];
    let paths = keys.each_ref().map(|key| fixture.config.root.join(key));
    let bodies = paths.each_ref().map(|path| std::fs::read(path).require());
    let identities = paths.each_ref().map(|path| {
        let metadata = std::fs::symlink_metadata(path).require();
        (metadata.dev(), metadata.ino())
    });
    let journals = keys.each_ref().map(|key| {
        CreationJournal::decode(&std::fs::read(journal(fixture, key)).require()).require()
    });
    for (index, creator) in journals.iter().enumerate() {
        assert_eq!(creator.key, keys[index]);
        let JournalState::Committed { file_identity, .. } = &creator.state else {
            panic!("genuine creator is not Committed")
        };
        let (device, inode) = identities[index];
        assert_eq!(
            file_identity,
            &[device.to_be_bytes(), inode.to_be_bytes()].concat()
        );
    }
    let selected = image(fixture).await;
    let mut logical = selected.logical;
    logical.remove("gc/lease");
    TripleImage {
        paths,
        bodies,
        identities,
        journals,
        logical,
        selected: selected.state,
    }
}

/// Checks the exact durable operation phase and owner prefix from actual files.
///
/// # Panics
/// Panics for any unrelated changed bytes, identity, creator state or authorization.
pub(super) async fn assert_prefix(
    fixture: &Fixture,
    before: &TripleImage,
    phase: Option<DeletePhase>,
    prefix: usize,
) -> Option<DeleteOperation> {
    // The executor's requested pack must match the independently captured retired tuple.
    assert_eq!(fixture.fs.triple_paths(), vec![before.paths[0].clone()]);
    let observed = fixture.fs.ownership();
    let operation_path = observed
        .iter()
        .find(|(boundary, _)| *boundary == 0)
        .map(|(_, path)| path.clone());
    let operation = match phase {
        Some(expected) => {
            let path = operation_path.require();
            let key = path
                .strip_prefix(fixture.parent.join("publication"))
                .require()
                .to_str()
                .require();
            let metadata = std::fs::symlink_metadata(&path).require();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            let decoded = DeleteOperation::decode(&std::fs::read(&path).require(), key).require();
            assert_eq!(decoded.phase, expected);
            assert_eq!(
                decoded.revision,
                u64::from(expected == DeletePhase::Invalidated)
            );
            assert_eq!(decoded.authorization.deletion_seconds, windows().deletion());
            assert!(decoded.authorization.elapsed_ns >= windows().deletion() * 1_000_000_000);
            assert_eq!(decoded.authorization.index_witness, before.bodies[1]);
            assert_eq!(decoded.authorization.artifacts.len(), 3);
            Some(decoded)
        }
        None => {
            if let Some(path) = operation_path {
                assert!(!path.exists());
            }
            None
        }
    };
    for index in 0..3 {
        assert_eq!(
            std::fs::read(&before.paths[index]).require(),
            before.bodies[index]
        );
        let metadata = std::fs::symlink_metadata(&before.paths[index]).require();
        assert_eq!((metadata.dev(), metadata.ino()), before.identities[index]);
        let original = &before.journals[index];
        let actual =
            CreationJournal::decode(&std::fs::read(journal(fixture, &original.key)).require())
                .require();
        assert_eq!(actual.key, original.key);
        assert_eq!(actual.nonce, original.nonce);
        let JournalState::Committed {
            binding,
            file_identity,
        } = &original.state
        else {
            panic!("original creator is not Committed")
        };
        if let Some(operation) = &operation {
            let version = &operation.authorization.artifacts[index];
            assert_eq!(version.key, original.key);
            assert_eq!(version.nonce, original.nonce);
            assert_eq!(&version.binding, binding);
            assert_eq!(&version.file_identity, file_identity);
        }
        if index < prefix {
            let operation = operation.as_ref().require();
            assert_eq!(
                actual.state,
                JournalState::DeleteOwned {
                    binding: binding.clone(),
                    file_identity: file_identity.clone(),
                    operation_key: operation.authorization.operation_key(),
                    authorization: operation.authorization.digest().require(),
                }
            );
        } else {
            assert_eq!(actual, *original);
        }
    }
    let mut selected = image(fixture).await;
    selected.logical.remove("gc/lease");
    assert_eq!(selected.logical, before.logical);
    assert!(selected.state.revision >= before.selected.revision);
    selected.state.revision = before.selected.revision;
    assert_eq!(selected.state, before.selected);
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    operation
}

/// Requires the exact permanent Session refusal shared by expiry and cancellation.
///
/// # Panics
/// Panics if the result differs from the configured collector Session denial.
pub(super) fn assert_session_denied(error: &CollectionError) {
    let CollectionError::Store(error) = error else {
        panic!("expected Session store denial: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Denied {
            verb: "gc-checkpoint",
            pattern: "current configured collector session".into()
        }
    );
}

/// Advances the same injected clock beyond all finite fixture renewals.
///
/// This is negative-test expiry injection, never an elapsed permission source.
///
/// # Panics
/// Panics if actual clock samples or bounded arithmetic are unavailable.
pub(super) fn expire(fixture: &Fixture) {
    let wall = fixture
        .clock
        .now()
        .duration_since(UNIX_EPOCH)
        .require()
        .as_secs();
    let ticks = fixture.clock.monotonic().as_secs();
    fixture.clock.set(
        wall.checked_add(10_000).require(),
        ticks.checked_add(10_000).require(),
    );
}

/// Replaces one actual retained Original record while preserving its canonical bytes.
///
/// # Panics
/// Panics if real protected registration replacement or identity verification fails.
pub(super) fn replace_control(fixture: &Fixture) {
    let path = fixture.authority.control().join("registration.cbor");
    let bytes = std::fs::read(&path).require();
    let old = std::fs::symlink_metadata(&path).require();
    let temporary = path.with_extension("ownership-replacement");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .require();
    std::io::Write::write_all(&mut file, &bytes).require();
    file.sync_all().require();
    std::fs::rename(&temporary, &path).require();
    assert_ne!(std::fs::symlink_metadata(&path).require().ino(), old.ino());
}

/// Awaits one actual handoff within the finite qualification deadline.
///
/// # Panics
/// Panics if the precise native handoff is not reached.
pub(super) async fn arrival(receiver: mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(90)))
        .await
        .require()
        .require();
}

/// Awaits two real held renewals separated by the genuine timer wait.
///
/// # Panics
/// Panics if the wait never reaches its actual retained renewal producer.
pub(super) async fn waiting(fixture: &Fixture, previous: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while fixture.fs.completed_renewals() < previous + 3 || fixture.fs.triples() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .require();
}

/// Replaces one actual pack incarnation with equal bytes through ordinary filesystem I/O.
///
/// # Panics
/// Panics if the controlled replacement does not create a different native inode.
pub(super) fn replace_pack(before: &mut TripleImage) {
    let path = &before.paths[0];
    let temporary = path.with_extension("ownership-replacement");
    let metadata = std::fs::symlink_metadata(path).require();
    let mut replacement = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(metadata.mode() & 0o777)
        .open(&temporary)
        .require();
    std::io::Write::write_all(&mut replacement, &before.bodies[0]).require();
    replacement.sync_all().require();
    std::fs::rename(&temporary, path).require();
    let actual = std::fs::symlink_metadata(path).require();
    assert_ne!(actual.ino(), metadata.ino());
    before.identities[0] = (actual.dev(), actual.ino());
}
