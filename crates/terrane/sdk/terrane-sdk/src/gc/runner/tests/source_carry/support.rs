//! Builds genuine signed sources, native unrooted containers and current collectors.

use super::*;
use crate::pack::{PackId, PackIndexSnapshot};
use crate::store::{ChunkPosition, ChunkUpload, ContentUpload};
use std::time::UNIX_EPOCH;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::Phase;
use terrane_format::gc::publication::PublicationState;

/// Retains the whole selected state and exact catalog manifest independently.
pub(super) struct Image {
    /// Whole state selected by genuine protected publication.
    pub(super) state: PublicationState,
    /// Exact current catalog inventory, exclusion and burn data.
    pub(super) manifest: GenerationManifest,
}

/// Observes whole selected state and canonical manifest under a real holder.
///
/// # Panics
/// Panics on unavailable native selection or malformed actual capabilities/manifest.
pub(super) async fn image(fixture: &Fixture) -> Image {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let cap =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{}/MANIFEST", cap.generation.unwrap())]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    Image {
        state: observed.state().clone(),
        manifest,
    }
}

/// Derives the registered creator journal key for an independently chosen artifact.
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

/// Bounds actual native artifact modification time upward to whole seconds.
///
/// # Panics
/// Panics on unavailable metadata, pre-Unix time or arithmetic overflow.
pub(super) fn rounded_modified(path: &std::path::Path) -> u64 {
    let elapsed = std::fs::symlink_metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    elapsed
        .as_secs()
        .checked_add(u64::from(elapsed.subsec_nanos() != 0))
        .unwrap()
}

/// Creates one unrooted chunk through actual production container admission.
///
/// # Panics
/// Panics on failed canonical upload, absent actual index association or invalid metadata.
pub(super) async fn orphan(fixture: &Fixture) -> (PackId, u64) {
    let plaintext = b"unreferenced genuine retirement candidate";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
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
        .unwrap();
    assert_eq!(uploaded, identity);
    let before = image(fixture).await;
    let digest = identity.terrane_v1_digest().unwrap();
    let mut candidate = None;
    let mut data = Vec::new();
    for row in before.manifest.inventory.as_ref().unwrap() {
        let id = PackId::from_random_bytes(row.pack_id);
        let bytes = tokio::fs::read(fixture.config.root.join(id.index_key()))
            .await
            .unwrap();
        assert_eq!(&bytes[..6], b"TRPK\x01\x00");
        let index = PackIndexSnapshot::decode(&bytes, before.manifest.generation).unwrap();
        if bytes[6] & 2 == 0 {
            data.push(fixture.config.root.join(id.pack_key()));
        }
        if index.entries().iter().any(|row| row.hash() == &digest) {
            assert_eq!(bytes[6] & 2, 0);
            candidate = Some(id);
        }
    }
    let id = candidate.unwrap();
    let upper = rounded_modified(&fixture.config.root.join(id.pack_key()))
        .max(rounded_modified(&fixture.config.root.join(id.index_key())));
    // Establish the injected wall base from actual backend metadata BEFORE
    // acquiring the collector. No file or commit timestamp is rewritten.
    fixture.fs.forbid_data_body_reads(&data).unwrap();
    (id, upper)
}

type NativeCollection<'a> = Collection<
    'a,
    crate::store::native_publication_effects::collection::test_fs::TestFs,
    crate::store::NativeEffectClock,
    super::super::fixture::Validator,
    crate::store::NativeEffectClock,
>;

/// Completes genuine root selection and marking before any candidate is chosen.
///
/// # Panics
/// Panics on invalid clock arithmetic, failed whole lease or real mark publication.
pub(super) async fn completed(
    fixture: &Fixture,
    base: u64,
    configured: Windows,
) -> NativeCollection<'_> {
    fixture.clock.set(base, base.checked_sub(100).unwrap());
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "retirement-collector".into(),
        1_000,
        51,
        configured,
    )
    .await
    .unwrap();
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    assert_eq!(collection.state().phase, Phase::Sweep);
    collection
}

/// Derives an ordinary signed actor request from the genuinely selected commit.
///
/// # Panics
/// Panics on missing actual Commit, invalid fixture key or failed token issuance.
pub(super) async fn request(fixture: &Fixture) -> crate::ref_advance::CommitRequest {
    use terrane_format::auth::{Authority, Grant, Token, Verbs};
    use terrane_format::refs::{Commit, PrincipalKind};
    let secret: [u8; 32] =
        hex_key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public: [u8; 32] =
        hex_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let current = fixture
        .guard()
        .store()
        .ref_get(SOURCE)
        .await
        .unwrap()
        .unwrap();
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Commit, &current.commit)
        .unwrap();
    let bytes = fixture.guard().store().get(&identity, None).await.unwrap();
    let mut commit = Commit::decode(&bytes).unwrap();
    commit.signature = None;
    commit.profile_pair.commit_context = None;
    let token = Token::issue(
        Authority {
            issuer: "fixture".into(),
            key_id: "fixture".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [2; 16],
            grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
            workload: None,
        },
        &secret,
        public,
    )
    .unwrap()
    .encode();
    crate::ref_advance::CommitRequest {
        commit,
        uploads: Vec::new(),
        token,
        terminal_secret: secret,
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    }
}

fn hex_key(text: &str) -> [u8; 32] {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Publishes an empty source with genuine root retention through the signed writer.
///
/// # Panics
/// Panics on canonical tree preparation or failed authorized native publication.
pub(super) async fn retained_source(
    fixture: &Fixture,
    retention: &[u8],
    reflog: Option<&[u8]>,
) -> terrane_format::refs::RefRecord {
    use crate::guard::StagedUpload;
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{Property, TreeUse};
    let mut properties = vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
        Property {
            name: "retain",
            value: retention,
        },
    ];
    if let Some(value) = reflog {
        properties.push(Property {
            name: "reflog_retain",
            value,
        });
    }
    properties.sort_by_key(|property| property.name);
    let tree = Tree::build(Vec::new(), Some(properties), 262144, TreeUse::Ordinary).unwrap();
    let mut request = request(fixture).await;
    let mut writer = fixture
        .repository
        .begin(SOURCE, &request.token, "sdk")
        .await
        .unwrap();
    request.commit.parents = vec![fixture.head.commit];
    request.commit.tree = tree.root_identity();
    request.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    fixture
        .repository
        .commit_request(&mut writer, request)
        .await
        .unwrap()
}

/// Publishes an expired lease head without changing its actual lease policy.
///
/// # Panics
/// Panics when genuine signed source publication fails.
pub(super) async fn witness_source(fixture: &Fixture) -> terrane_format::refs::RefRecord {
    retained_source(fixture, b"\x65lease", None).await
}

/// Derives collection time from every actual pair's backend modification bound.
///
/// # Panics
/// Panics on missing actual containers or arithmetic overflow.
pub(super) async fn pair_age_base(fixture: &Fixture) -> u64 {
    image(fixture)
        .await
        .manifest
        .inventory
        .as_ref()
        .unwrap()
        .iter()
        .map(|row| {
            let pack = crate::pack::PackId::from_random_bytes(row.pack_id);
            rounded_modified(&fixture.config.root.join(pack.pack_key())).max(rounded_modified(
                &fixture.config.root.join(pack.index_key()),
            ))
        })
        .max()
        .unwrap()
        .checked_add(61)
        .unwrap()
}

/// Reopens with the actual local metadata validator used by the cold oracle.
///
/// # Panics
/// Panics on genuine opening, persisted Original retention or configuration failure.
pub(super) async fn reopen_for_cold(
    fixture: &Fixture,
) -> crate::repository::Repository<
    crate::bucket::FileBucket<
        crate::store::native_publication_effects::collection::test_fs::TestFs,
        crate::store::NativeEffectClock,
        crate::repository::MetadataValidator,
    >,
    crate::store::NativeEffectClock,
    crate::store::native_publication_effects::collection::test_fs::TestFs,
> {
    let clock = fixture.clock.retain_native_clock().unwrap();
    let bucket = crate::bucket::FileBucket::open(
        fixture.config.clone(),
        fixture.fs.clone(),
        clock.retain_native_clock().unwrap(),
        crate::repository::MetadataValidator::new(fixture.config.chunk_profile.clone()),
    )
    .await
    .unwrap();
    let guard = crate::guard::Guard::new(
        bucket,
        clock,
        fixture.guard().keys().to_vec(),
        fixture.guard().config().clone(),
    );
    let coordinator = crate::ref_advance::Coordinator::new(
        guard,
        crate::ref_advance::CommitTiming::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )
        .unwrap(),
        fixture.fs.clone(),
    );
    crate::repository::Repository::reopen_native_retention(
        coordinator,
        &crate::domain::DomainNamespace {
            root: fixture.config.root.clone(),
            domain: fixture.guard().config().storage_domain.clone(),
        },
        &fixture.parent.join("original"),
        fixture
            .config
            .publication_control
            .as_ref()
            .unwrap()
            .operator_uid,
    )
    .await
    .unwrap()
}

/// Names the native public producer with the actual metadata validator.
pub(super) type PublicRepository = crate::repository::Repository<
    crate::bucket::FileBucket<
        crate::store::native_publication_effects::collection::test_fs::TestFs,
        crate::store::native_publication_effects::collection::test_fs::TestClock,
        crate::repository::MetadataValidator,
    >,
    crate::store::native_publication_effects::collection::test_fs::TestClock,
    crate::store::native_publication_effects::collection::test_fs::TestFs,
>;

/// Retains a genuinely initialized public producer and its same injected clock.
pub(super) struct PublicFixture {
    /// Actual repository initialized through the public local producer.
    pub(super) repository: PublicRepository,
    /// Actual public signing authority bound to this repository.
    pub(super) authority: crate::repository::LocalAuthority,
    /// Independently configured private parent of bucket and authority.
    pub(super) parent: std::path::PathBuf,
    /// Whole signed source record from the successful public producer.
    pub(super) record: terrane_format::refs::RefRecord,
    /// Same real injected clock retained by repository and collector workers.
    pub(super) clock: crate::store::native_publication_effects::collection::test_fs::TestClock,
}

impl PublicFixture {
    /// Initializes an ordinary public source with complete native retention.
    ///
    /// # Panics
    /// Panics on genuine initialization, entropy, metadata or source-ref failure.
    pub(super) async fn open() -> Self {
        use crate::repository::{
            LocalAuthorityParameters, LocalRepositoryLocation, LocalRepositoryPolicy, Repository,
        };
        use crate::store::native_publication_effects::collection::test_fs::{TestClock, TestFs};
        use std::os::unix::fs::MetadataExt;
        use terrane_format::auth::{Authority, Grant, Verbs};
        use terrane_format::refs::{Locality, PrincipalKind};

        let fs = TestFs::default();
        let clock = TestClock::new(1000);
        let entropy = fs.random_bytes(16).await.unwrap();
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-gc-foreign-view-{suffix}"));
        fs.create_dir_new(&parent).await.unwrap();
        let owner_uid = fs.metadata(&parent).await.unwrap().uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let policy = LocalRepositoryPolicy {
            store_name: "local".into(),
            domain: "public".into(),
            default_private_domain: "private:owner".into(),
            acl: vec![("owner".into(), 31)],
            locality: Locality::default(),
            timing: crate::ref_advance::CommitTiming::new(
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(10),
            )
            .unwrap(),
            policy_authority: None,
            bootstrap_properties: vec![("retain".into(), b"\x67forever".to_vec())],
        };
        let (repository, authority) = Repository::initialize_local(
            &location,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "owner".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: u64::MAX,
                    not_before: None,
                    token_id: entropy.try_into().unwrap(),
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
                    workload: None,
                },
            },
            policy,
            SOURCE,
            fs,
            clock.clone(),
        )
        .await
        .unwrap();
        let record = repository
            .coordinator()
            .store()
            .ref_get(SOURCE)
            .await
            .unwrap()
            .unwrap();
        Self {
            repository,
            authority,
            parent,
            record,
            clock,
        }
    }

    /// Publishes real public file attributes through signed directory import.
    ///
    /// # Panics
    /// Panics on failed filesystem, public signing or attribute observation.
    pub(super) async fn open_file() -> Self {
        let mut fixture = Self::open().await;
        let directory = fixture.parent.join("source");
        let fs = fixture.repository.coordinator().fs();
        fs.create_dir_new(&directory).await.unwrap();
        fs.write_new(
            &directory.join("file"),
            b"independently public attributed content",
        )
        .await
        .unwrap();
        let mut writer = fixture
            .repository
            .begin(SOURCE, fixture.authority.token(), "sdk")
            .await
            .unwrap();
        fixture.record = fixture
            .repository
            .commit_directory(
                &mut writer,
                &directory,
                &fixture.authority,
                public_metadata("Import independently public source"),
            )
            .await
            .unwrap();
        fixture
    }
}

impl Drop for PublicFixture {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.parent) {
            eprintln!("Failed to remove private GC foreign-view fixture: {error}");
        }
    }
}

/// Creates ordinary claims for the real public signer to bind and publish.
pub(super) fn public_metadata(message: &str) -> crate::repository::CommitMetadata {
    crate::repository::CommitMetadata {
        message: message.into(),
        process: "gc-source-carry-qualification".into(),
        source: terrane_format::refs::CommitSource::Built,
    }
}

/// Observes the exact selected lineage under the actual physical holder.
///
/// # Panics
/// Panics on unavailable selection or malformed protected lineage bytes.
pub(super) async fn public_lineage(repository: &PublicRepository, name: &str) -> CheckedLineage {
    let holder = SingleHeld::acquire(repository.coordinator().store())
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let read = held
        .selected_lineage_record(&observed, name)
        .await
        .unwrap()
        .unwrap();
    CheckedLineage::decode(read.bytes().unwrap()).unwrap()
}

/// Observes complete actual selected state and catalog under exclusion.
///
/// # Panics
/// Panics on unavailable native state or malformed actual catalog records.
pub(super) async fn public_image(repository: &PublicRepository) -> Image {
    let holder = SingleHeld::acquire(repository.coordinator().store())
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let cap =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{}/MANIFEST", cap.generation.unwrap())]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    Image {
        state: observed.state().clone(),
        manifest,
    }
}

/// Discloses real public content while preserving its public attribute producers.
///
/// # Panics
/// Panics on lost signed source, changed attribute producers or failed disclosure.
pub(super) async fn disclose_public_file(
    source: &PublicFixture,
    destination: &PublicFixture,
    target: &str,
) -> terrane_format::refs::RefRecord {
    use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{LeafItem, Property, TreeUse};

    let snapshot = source
        .repository
        .coordinator()
        .guard()
        .read_snapshot(SOURCE, source.authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot
        .history
        .locate(source.record.commit, b"file")
        .unwrap();
    let mut entry = snapshot.history.entry(&location).unwrap().clone();
    assert!(!entry.attrs.is_empty());
    for attribute in &entry.attrs {
        assert_eq!(
            snapshot
                .history
                .attribute_producer(&location, attribute.name)
                .unwrap(),
            source.record.commit
        );
    }
    // Public attribute producers are genuine foreign used views, not optional
    // data stripped away to make imported history look destination-local.
    entry.provenance = None;
    let (root, uploads) = {
        let tree = Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry,
            }],
            Some(vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x65owner\x18\x1f",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "retain",
                    value: b"\x67forever",
                },
            ]),
            destination.repository.chunk_profile().minimum() as u64,
            TreeUse::Ordinary,
        )
        .unwrap();
        let uploads = tree
            .nodes()
            .map(|node| crate::guard::StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        (tree.root_identity(), uploads)
    };
    let mut writer = destination
        .repository
        .begin(target, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let mut proposal = destination.repository.source_request(
        &destination.authority,
        public_metadata("Retain public foreign used view"),
    );
    proposal.commit.tree = root;
    proposal.commit.parents = writer
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    proposal.uploads = uploads;
    destination
        .repository
        .commit_disclosure(
            &source.repository,
            &mut writer,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: SOURCE.into(),
                    source_commit: source.record.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap()
}

/// Uploads a genuinely unrooted container and observes its real age bound.
///
/// # Panics
/// Panics on upload, absent exact native index membership or invalid metadata.
pub(super) async fn public_orphan(fixture: &PublicFixture) -> (PackId, u64) {
    let plaintext = b"unreferenced public foreign-view retirement candidate";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let encoded = terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
        codec: terrane_format::codec::Codec::Raw,
        body: plaintext,
    });
    let uploaded = fixture
        .repository
        .coordinator()
        .store()
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: fixture.repository.chunk_profile(),
        }))
        .await
        .unwrap();
    assert_eq!(uploaded, identity);
    let image = public_image(&fixture.repository).await;
    let digest = identity.terrane_v1_digest().unwrap();
    let mut candidate = None;
    let mut data = Vec::new();
    for row in image.manifest.inventory.as_ref().unwrap() {
        let id = PackId::from_random_bytes(row.pack_id);
        let root = fixture.repository.coordinator().store().root();
        let bytes = tokio::fs::read(root.join(id.index_key())).await.unwrap();
        let index = PackIndexSnapshot::decode(&bytes, image.manifest.generation).unwrap();
        if bytes[6] & 2 == 0 {
            data.push(root.join(id.pack_key()));
        }
        if index.entries().iter().any(|entry| entry.hash() == &digest) {
            assert_eq!(bytes[6] & 2, 0);
            assert!(candidate.replace(id).is_none());
        }
    }
    let id = candidate.unwrap();
    let root = fixture.repository.coordinator().store().root();
    let upper = rounded_modified(&root.join(id.pack_key()))
        .max(rounded_modified(&root.join(id.index_key())));
    fixture
        .repository
        .coordinator()
        .fs()
        .forbid_data_body_reads(&data)
        .unwrap();
    (id, upper)
}
