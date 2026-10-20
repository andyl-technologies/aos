//! Builds genuine retired triples and independent physical deletion oracles.

use crate::bucket::{FileBucket, held::SingleHeld};
use crate::domain::DomainNamespace;
use crate::gc::runner::Collection;
use crate::gc::runner::fixture::{Fixture as OriginalFixture, Validator};
use crate::guard::{Guard, OriginalAuthority, StagedUpload};
use crate::pack::{PackId, PackIndexSnapshot};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::Repository;
use crate::store::native_publication_effects::collection_local_deletion::DeletionFs;
use crate::store::{
    ChunkPosition, ChunkUpload, Clock, ContentStore, ContentUpload, NativeEffectClock,
};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::auth::{Authority, Grant, IssuerKey, Token, Verbs};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest, PackExclusion};
use terrane_format::chunking::ChunkProfile;
use terrane_format::gc::publication::PublicationState;
use terrane_format::gc::{CreationJournal, DeleteOperation, DeletePhase, GcLease, JournalState};
use terrane_format::gc::{Phase, Windows};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::refs::{
    Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance,
};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

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
pub(super) type Bucket = FileBucket<DeletionFs, NativeEffectClock, Validator>;

/// Names its supported genuinely reopened retained repository.
pub(super) type NativeRepository = Repository<Bucket, NativeEffectClock, DeletionFs>;

/// Names a collector with a real Session and the same injected retained clock.
pub(super) type NativeCollection<'a> =
    Collection<'a, DeletionFs, NativeEffectClock, Validator, NativeEffectClock>;

/// Retains independently published source history and an ordinary instrumented reopen.
pub(super) struct Fixture {
    /// Actual initial signed publication and original retention setup.
    pub(super) base: OriginalFixture,
    /// Genuine reopened repository supplying all collector factories.
    pub(super) repository: NativeRepository,
    /// Actual original registration resolved by this reopened repository.
    pub(super) authority: OriginalAuthority,
    /// Transparent native executor with finite fault observation.
    pub(super) fs: DeletionFs,
    /// Exact capabilities bytes independently verified at the last real reopen.
    pub(super) reopened_capabilities: Option<Vec<u8>>,
}

impl Fixture {
    /// Reopens genuine source output without constructing maintenance authority.
    ///
    /// # Panics
    /// Panics if ordinary native reopen or original verification fails.
    pub(super) async fn new() -> Self {
        let base = OriginalFixture::new().await;
        let fs = DeletionFs::new(base.fs.clone());
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
            reopened_capabilities: None,
        }
    }

    /// Reopens ordinary native history with a new Guard before fresh recovery.
    ///
    /// # Panics
    /// Panics if genuine opening or retained-history verification fails, or the
    /// probe successor violates its clock bounds or exact record expectations.
    pub(super) async fn reopen(&mut self) {
        let before_probe = image(self).await;
        let probe_start = self
            .base
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .require()
            .as_secs();
        let bucket = FileBucket::open(
            self.base.config.clone(),
            self.fs.clone(),
            self.base.clock.retain_native_clock().require(),
            Validator,
        )
        .await
        .require();
        let probe_end = self
            .base
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .require()
            .as_secs();
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
            self.base.clock.retain_native_clock().require(),
            vec![IssuerKey {
                issuer: "fixture".into(),
                key_id: "fixture".into(),
                public_key: public,
                retirement: None,
            }],
            self.base.guard().config().clone(),
        );
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .require(),
            self.fs.clone(),
        );
        let repository = Repository::reopen_native_retention(
            coordinator,
            &DomainNamespace {
                root: self.base.config.root.clone(),
                domain: "public".into(),
            },
            &self.base.parent.join("original"),
            self.base
                .config
                .publication_control
                .as_ref()
                .require()
                .operator_uid,
        )
        .await
        .require();
        self.authority = repository
            .coordinator()
            .guard()
            .original_commit(&self.base.head.commit)
            .require()
            .baseline()
            .authority()
            .clone();
        self.repository = repository;

        // Opening republishes only the capability probe timestamp. Capture and
        // prove that whole-record boundary before later reclamation comparisons.
        let after_probe = image(self).await;
        assert!(probe_start <= after_probe.cap.probed_at);
        assert!(after_probe.cap.probed_at <= probe_end);
        let mut expected_cap = before_probe.cap.clone();
        expected_cap.probed_at = after_probe.cap.probed_at;
        assert_eq!(after_probe.cap, expected_cap);
        let capabilities = expected_cap.encode().require();
        let changed =
            before_probe.logical["CAPABILITIES"].as_deref() != Some(capabilities.as_slice());
        let mut expected_state = before_probe.state.clone();
        expected_state.revision = expected_state
            .revision
            .checked_add(u64::from(changed))
            .require();
        assert_eq!(after_probe.state, expected_state);
        assert_eq!(after_probe.manifest, before_probe.manifest);
        let mut expected_logical = before_probe.logical;
        expected_logical.insert("CAPABILITIES".into(), Some(capabilities.clone()));
        assert_eq!(after_probe.logical, expected_logical);
        self.reopened_capabilities = Some(capabilities);
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
    fixture.base.fs.forbid_data_body_reads(&data).require();
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

/// Reads the protected actual operation using its canonical registered key.
///
/// # Panics
/// Panics if the real operation bytes are absent or malformed.
pub(super) fn operation(fixture: &Fixture, key: &str) -> DeleteOperation {
    DeleteOperation::decode(
        &std::fs::read(fixture.parent.join("publication").join(key)).require(),
        key,
    )
    .require()
}

/// Proves Done independently from physical absence and exact retained authorization.
///
/// # Panics
/// Panics if any artifact survives, authorization changes or ownership association differs.
pub(super) async fn assert_done(
    fixture: &Fixture,
    before: &TripleImage,
    original: &DeleteOperation,
    done: &DeleteOperation,
) {
    assert_eq!(done.phase, DeletePhase::Done);
    assert_eq!(done.authorization, original.authorization);
    assert_eq!(done.authorization.index_witness, before.bodies[1]);
    for (index, version) in done.authorization.artifacts.iter().enumerate() {
        let (device, inode) = before.identities[index];
        assert_eq!(
            version.file_identity,
            [device.to_be_bytes(), inode.to_be_bytes()].concat()
        );
    }
    let submitted = fixture.fs.submitted();
    assert!(submitted.iter().any(|(_, path)| {
        path == &fixture
            .parent
            .join("publication")
            .join(done.authorization.operation_key())
    }));
    assert!(
        fixture
            .fs
            .completed()
            .iter()
            .any(|phase| matches!(phase, DeletePhase::ContainersConfirmed | DeletePhase::Done))
    );
    assert_eq!(
        operation(fixture, &done.authorization.operation_key()),
        *done
    );
    for (index, path) in before.paths.iter().enumerate() {
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let creator = CreationJournal::decode(
            &std::fs::read(journal(fixture, &before.journals[index].key)).require(),
        )
        .require();
        assert_eq!(creator.key, before.journals[index].key);
        assert_eq!(creator.nonce, before.journals[index].nonce);
        let version = &done.authorization.artifacts[index];
        assert_eq!(
            creator.state,
            JournalState::DeleteOwned {
                binding: version.binding.clone(),
                file_identity: version.file_identity.clone(),
                operation_key: done.authorization.operation_key(),
                authorization: done.authorization.digest().require(),
            }
        );
    }
    let after = image(fixture).await;
    assert!(after.cap.generation.require() >= 1);
    assert!(after.state.revision >= before.selected.revision);
    let mut logical = after.logical;
    logical.remove("gc/lease");
    // Reopening proves its exact capability-probe successor separately. Physical
    // reclamation preserves that whole record and every other original semantic.
    for (key, body) in &before.logical {
        if key == "CAPABILITIES"
            && let Some(capabilities) = &fixture.reopened_capabilities
        {
            assert_eq!(logical.get(key), Some(&Some(capabilities.clone())));
            continue;
        }
        assert_eq!(logical.get(key), Some(body));
    }
}

/// Completes a genuinely new collector cycle after the previous whole lease ends.
///
/// # Panics
/// Panics if fresh higher-epoch acquisition or complete current marking fails.
pub(super) async fn fresh_collection(fixture: &Fixture, cycle: u64) -> NativeCollection<'_> {
    let previous = fixture.selected_lease().await;
    let ticks = fixture.clock.monotonic().as_secs().checked_add(1).require();
    fixture
        .clock
        .set(previous.expiry.checked_add(1).require(), ticks);
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "ownership-collector".into(),
        10,
        cycle,
        windows(),
    )
    .await
    .require();
    assert!(collection.lease().epoch > previous.epoch);
    collection.mark_batch(32).await.require();
    collection.finish_mark().await.require();
    assert_eq!(collection.state().phase, Phase::Sweep);
    collection
}

/// Waits only for an actual native handoff signal at its original finite bound.
///
/// # Panics
/// Panics if the actual worker never reaches its selected handoff.
pub(super) async fn arrival(receiver: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(90)).require())
        .await
        .require();
}

/// Publishes a genuinely signed current root using the freshly admitted identity.
///
/// # Panics
/// Panics if actual authorized staging, source retention or publication fails.
pub(super) async fn root_readmission(fixture: &Fixture) -> terrane_format::refs::RefRecord {
    let mut writer = fixture
        .repository
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .require();
    fixture
        .repository
        .commit_request(
            &mut writer,
            request(
                vec![fixture.base.head.commit],
                b"unreferenced genuine retirement candidate",
                None,
            ),
        )
        .await
        .require()
}

fn key(hex: &str) -> [u8; 32] {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn secret() -> [u8; 32] {
    key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
}

fn public() -> [u8; 32] {
    key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
}

fn token() -> Vec<u8> {
    Token::issue(
        Authority {
            issuer: "fixture".into(),
            key_id: "fixture".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [1; 16],
            grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
            workload: None,
        },
        &secret(),
        public(),
    )
    .unwrap()
    .encode()
}

fn request(parents: Vec<[u8; 32]>, plaintext: &[u8], count: Option<u64>) -> CommitRequest {
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let mut count_bytes = Vec::new();
    terrane_format::cbor::write_array(&mut count_bytes, 2);
    terrane_format::cbor::write_text(&mut count_bytes, "count");
    terrane_format::cbor::write_uint(&mut count_bytes, count.unwrap_or(0));
    let mut properties = vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
    ];
    if count.is_some() {
        properties.push(Property {
            name: "reflog_retain",
            value: &count_bytes,
        });
    }
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(chunk.terrane_v1_digest().unwrap()),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(properties),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect::<Vec<_>>();
    uploads.push(StagedUpload::Chunk {
        encoded: terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
            codec: terrane_format::codec::Codec::Raw,
            body: plaintext,
        }),
        identity: chunk,
        declared_plaintext_len: plaintext.len(),
        position: crate::store::ChunkPosition::Final,
        profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
    });
    CommitRequest {
        commit: Commit {
            tree: tree.root_identity(),
            parents,
            provenance: Provenance {
                issuer: String::new(),
                token_id: [0; 16],
                subject: String::new(),
                kind: PrincipalKind::Human,
                workload_identity: None,
                process: "fixture".into(),
                observed_at: 0,
                writer_epoch: 0,
                source: CommitSource::Built,
                embedded_token: None,
            },
            timestamp: 0,
            message: "Publish collector source".into(),
            profile_pair: ProfilePair {
                tree_format: 1,
                chunk_profile: "cdc-1m".into(),
                recipe: None,
                conflicted: None,
                lease: None,
                required_properties: None,
                entry_receipts: None,
                commit_context: None,
            },
            packs: None,
            signature: None,
        },
        uploads,
        token: token(),
        terminal_secret: secret(),
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    }
}

/// Requires the precise genuine I/O taxonomy and source at the actual fault.
///
/// # Panics
/// Panics if the operation returns another error class or unrelated source.
#[track_caller]
pub(super) fn assert_io(error: &crate::gc::runner::CollectionError, source: &str) {
    let crate::gc::runner::CollectionError::Store(error) = error else {
        panic!("expected actual native Store I/O refusal: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &crate::store::StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(error).require().to_string(),
        source
    );
}
