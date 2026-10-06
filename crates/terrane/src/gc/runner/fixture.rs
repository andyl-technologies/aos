//! Publishes real signed source history through the production retained repository.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::{FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{GuardConfig, StagedUpload};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::Repository;
use crate::store::native_publication_effects::collection::test_fs::{TestClock, TestFs};
use crate::store::{ContentValidator, MetaUpload, NativeEffectClock};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::time::Duration;
use terrane_core::auth::{Authority, Grant, IssuerKey, Token, Verbs};
use terrane_core::bucket::{BucketCapabilities, BucketKey};
use terrane_core::chunking::ChunkProfile;
use terrane_core::gc::publication::LogicalChange;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::refs::{
    Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance, RefClass, RefName,
    RefRecord,
};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

/// Checks the same bounded canonical metadata admitted by the real fixture writer.
pub(crate) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        match upload.kind() {
            IdentityKind::Node => {
                terrane_core::tree_format::decode_node(upload.bytes(), true, 262144)
                    .map(|_| ())
                    .map_err(|_| denied())
            }
            IdentityKind::Commit => Commit::decode(upload.bytes())
                .map(|_| ())
                .map_err(|_| denied()),
            _ => Err(denied()),
        }
    }
}

/// Names the real filesystem and actual injected clock used by the native cases.
pub(crate) type Bucket = FileBucket<TestFs, NativeEffectClock, Validator>;
/// Names the production repository with protected original retention enabled.
pub(crate) type NativeRepository = Repository<Bucket, NativeEffectClock, TestFs>;

/// Owns real configured storage, signed source history and its injected clock.
pub(crate) struct Fixture {
    /// Private directory containing the real bucket and sibling controls.
    pub(super) parent: PathBuf,
    /// Actual opened native layout and independently configured operator.
    pub(crate) config: FileBucketConfig,
    /// Production retained repository that publishes the signed source history.
    pub(super) repository: NativeRepository,
    /// Opaque registration obtained from the genuinely published original context.
    pub(crate) authority: OriginalAuthority,
    /// Exact selected first source record.
    pub(super) head: RefRecord,
    /// Same injected clock state retained by all native effects.
    pub(crate) clock: TestClock,
    /// Actual native executor with bounded test queue observation.
    pub(crate) fs: TestFs,
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

impl Fixture {
    /// Initializes protected storage and publishes a genuinely signed source.
    ///
    /// # Panics
    /// Panics when private native setup, original retention or signed publication fails.
    pub(crate) async fn new() -> Self {
        let fs = TestFs::default();
        let entropy = fs.random_bytes(16).await.unwrap();
        let suffix = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let parent = std::env::temp_dir().join(format!("terrane-gc-checkpoint-{suffix}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let owner = std::fs::symlink_metadata(&parent).unwrap().uid();
        let config = FileBucketConfig {
            root: parent.join("bucket"),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: Some(parent.join("publication")),
            }),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m([0; 32]),
            locality: Locality::default(),
        };
        let clock = TestClock::new(100);
        let bucket = FileBucket::open(
            config.clone(),
            fs.clone(),
            clock.retain_native_clock().unwrap(),
            Validator,
        )
        .await
        .unwrap();
        let guard = Guard::new(
            bucket,
            clock.retain_native_clock().unwrap(),
            vec![IssuerKey {
                issuer: "fixture".into(),
                key_id: "fixture".into(),
                public_key: public(),
                retirement: None,
            }],
            GuardConfig {
                store_name: "local".into(),
                private_domain: "private:fixture".into(),
                home: Locality::default(),
                initial_acl: vec![("writer".into(), 31)],
                min_chunk_size: 262144,
                storage_domain: "public".into(),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
                policy_authority: None,
            },
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
        let control = parent.join("original");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&control)
            .unwrap();
        let repository = Repository::initialize_native_retention(
            coordinator,
            &DomainNamespace {
                root: config.root.clone(),
                domain: "public".into(),
            },
            &control,
            owner,
        )
        .await
        .unwrap();
        let mut writer = repository
            .begin("refs/heads/_/main", &token(), "sdk")
            .await
            .unwrap();
        let head = repository
            .commit_request(&mut writer, request(Vec::new(), b"published source", None))
            .await
            .unwrap();
        let authority = repository
            .coordinator()
            .guard()
            .original_commit(&head.commit)
            .unwrap()
            .baseline()
            .authority()
            .clone();
        Self {
            parent,
            config,
            repository,
            authority,
            head,
            clock,
            fs,
        }
    }

    /// Borrows the actual configured historical Guard from the retained repository.
    pub(crate) fn guard(&self) -> &Guard<Bucket, NativeEffectClock> {
        self.repository.coordinator().guard()
    }

    /// Selects opaque Notes and their canonical inventory under genuine exclusion.
    ///
    /// The existing backend-only raw lane grants no collector or actor authority.
    /// Subsequent collection uses the actual configured retained producer.
    ///
    /// # Panics
    /// Panics on invalid Note names or failed canonical inventory/native publication.
    pub(super) async fn publish_notes(&self, notes: &[(&str, &[u8])]) -> u64 {
        let holder = crate::bucket::held::SingleHeld::acquire(self.guard().store())
            .await
            .unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let previous = observed
            .logical()
            .get("CAPABILITIES")
            .unwrap()
            .as_deref()
            .unwrap();
        let mut capabilities = BucketCapabilities::decode(previous).unwrap();
        let names = capabilities.ref_names.as_mut().unwrap();
        let mut changes = Vec::new();
        for (name, bytes) in notes {
            assert_eq!(RefName::parse(name).unwrap().class(), RefClass::Notes);
            let key = BucketKey::ref_record(name).unwrap().as_str().to_owned();
            if let Err(position) = names.binary_search_by(|row| row.as_bytes().cmp(name.as_bytes()))
            {
                names.insert(position, (*name).into());
            }
            changes.push(LogicalChange {
                expected: observed.logical().get(&key).cloned().flatten(),
                key,
                new: Some(bytes.to_vec()),
            });
        }
        let next_capabilities = capabilities.encode().unwrap();
        if next_capabilities != previous {
            changes.push(LogicalChange {
                key: "CAPABILITIES".into(),
                expected: Some(previous.to_vec()),
                new: Some(next_capabilities),
            });
        }
        let selected = held.publish_raw(&observed, changes).await.unwrap();
        let after = held.observe_publication_unrepaired().await.unwrap();
        assert_eq!(after.stamp(), selected.stamp);
        assert_eq!(after.state(), &selected.state);
        for (name, bytes) in notes {
            let key = BucketKey::ref_record(name).unwrap();
            assert_eq!(
                after.logical().get(key.as_str()).unwrap().as_deref(),
                Some(*bytes),
            );
        }
        selected.stamp.0
    }

    /// Publishes a commit-bearing Derived ref through the real retained writer.
    ///
    /// # Panics
    /// Panics when canonical source verification or authorized native commit fails.
    pub(super) async fn publish_derived(&self) -> RefRecord {
        let mut writer = self
            .repository
            .begin("refs/derived/_/collection", &token(), "sdk")
            .await
            .unwrap();
        self.repository
            .commit_request(&mut writer, request(Vec::new(), b"derived source", None))
            .await
            .unwrap()
    }

    /// Independently reopens the actual bucket and its existing protected history.
    ///
    /// The new Guard receives trusted setup configuration and freshly checks
    /// persisted registration, baselines and associations through the native factory.
    ///
    /// # Panics
    /// Panics when actual bucket opening or existing retained history verification fails.
    pub(super) async fn reopen_repository(&self) -> NativeRepository {
        let clock = self.clock.retain_native_clock().unwrap();
        let bucket = FileBucket::open(
            self.config.clone(),
            self.fs.clone(),
            clock.retain_native_clock().unwrap(),
            Validator,
        )
        .await
        .unwrap();
        let guard = Guard::new(
            bucket,
            clock,
            vec![IssuerKey {
                issuer: "fixture".into(),
                key_id: "fixture".into(),
                public_key: public(),
                retirement: None,
            }],
            self.guard().config().clone(),
        );
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .unwrap(),
            self.fs.clone(),
        );
        Repository::reopen_native_retention(
            coordinator,
            &DomainNamespace {
                root: self.config.root.clone(),
                domain: self.guard().config().storage_domain.clone(),
            },
            &self.parent.join("original"),
            self.config
                .publication_control
                .as_ref()
                .unwrap()
                .operator_uid,
        )
        .await
        .unwrap()
    }

    /// Publishes a real successor with count-zero ordinary history retention.
    ///
    /// # Panics
    /// Panics when the real writer cannot select its authorized canonical successor.
    pub(super) async fn publish_count_zero(&self) -> RefRecord {
        let mut writer = self
            .repository
            .begin("refs/heads/_/main", &token(), "sdk")
            .await
            .unwrap();
        self.repository
            .commit_request(
                &mut writer,
                request(vec![self.head.commit], b"current source", Some(0)),
            )
            .await
            .unwrap()
    }

    /// Independently reopens and resolves the actual selected whole state.
    ///
    /// # Panics
    /// Panics when durable reopen, complete selection or canonical state decoding fails.
    pub(super) async fn selected_state(&self, cycle: u64) -> GcState {
        let reopened = FileBucket::open(
            self.config.clone(),
            self.fs.clone(),
            self.clock.retain_native_clock().unwrap(),
            Validator,
        )
        .await
        .unwrap();
        let holder = crate::bucket::held::SingleHeld::acquire(&reopened)
            .await
            .unwrap();
        let held = holder.destination();
        let observation = held.observe_publication_unrepaired().await.unwrap();
        GcState::decode(
            observation
                .logical()
                .get(&format!("gc/{cycle}/state"))
                .unwrap()
                .as_deref()
                .unwrap(),
        )
        .unwrap()
    }

    /// Observes the actual selected whole lease and publication revision.
    ///
    /// # Panics
    /// Panics when genuine held selection or canonical lease decoding fails.
    pub(super) async fn selected_lease(&self) -> (GcLease, u64) {
        let holder = crate::bucket::held::SingleHeld::acquire(self.guard().store())
            .await
            .unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let lease = GcLease::decode(
            observed
                .logical()
                .get("gc/lease")
                .unwrap()
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        (lease, observed.state().revision)
    }

    /// Derives the real checkpoint slot following this operation's lease renewal.
    ///
    /// # Panics
    /// Panics when actual held selection fails or the bounded fixture exhausts revisions.
    pub(super) async fn next_checkpoint_slot(&self) -> PathBuf {
        let holder = crate::bucket::held::SingleHeld::acquire(self.guard().store())
            .await
            .unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        self.parent
            .join("publication/publication/commits")
            .join((observed.state().revision + 2).to_string())
    }

    /// Removes this fixture's private native storage after every worker completes.
    ///
    /// # Panics
    /// Panics when the completed fixture's private storage cannot be removed.
    pub(crate) fn cleanup(self) {
        std::fs::remove_dir_all(self.parent).unwrap();
    }
}

fn request(parents: Vec<[u8; 32]>, plaintext: &[u8], count: Option<u64>) -> CommitRequest {
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let mut count_bytes = Vec::new();
    terrane_core::cbor::write_array(&mut count_bytes, 2);
    terrane_core::cbor::write_text(&mut count_bytes, "count");
    terrane_core::cbor::write_uint(&mut count_bytes, count.unwrap_or(0));
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
        encoded: terrane_core::codec::encode_envelope(terrane_core::codec::EncodedChunk {
            codec: terrane_core::codec::Codec::Raw,
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
