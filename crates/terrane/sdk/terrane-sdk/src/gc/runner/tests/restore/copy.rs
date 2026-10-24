//! Creates portable payload copies with genuinely independent native activation.
//!
//! The destination's own Original factory publishes a Signed empty root. The
//! paired public disclosure producer separately checks and retains source signing
//! history; no source control bytes or creator receipts are copied. Disclosure
//! setup uses a separate native observer from the permanently armed restore trap.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::pack::PackId;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};

fn fixture_key(hex: &str) -> [u8; 32] {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn fixture_token() -> Vec<u8> {
    use terrane_format::auth::{Authority, Grant, Token, Verbs};
    Token::issue(
        Authority {
            issuer: "fixture".into(),
            key_id: "fixture".into(),
            subject: "writer".into(),
            kind: terrane_format::refs::PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [1; 16],
            grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
            workload: None,
        },
        &fixture_key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        fixture_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    )
    .unwrap()
    .encode()
}

/// Supplies an actual empty-tree Original publication in the independent destination.
fn bootstrap_request() -> crate::ref_advance::CommitRequest {
    use terrane_format::refs::{Commit, CommitSource, PrincipalKind, ProfilePair, Provenance};
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{Property, TreeUse};

    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    crate::ref_advance::CommitRequest {
        commit: Commit {
            tree: tree.root_identity(),
            parents: Vec::new(),
            provenance: Provenance {
                issuer: String::new(),
                token_id: [0; 16],
                subject: String::new(),
                kind: PrincipalKind::Human,
                workload_identity: None,
                process: "restore destination".into(),
                observed_at: 0,
                writer_epoch: 0,
                source: CommitSource::Built,
                embedded_token: None,
            },
            timestamp: 0,
            message: "Publish independent restore context".into(),
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
        uploads: tree
            .nodes()
            .map(|node| crate::guard::StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect(),
        token: fixture_token(),
        terminal_secret: fixture_key(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ),
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    }
}

/// Copies the exact portable payload and initializes genuinely independent native control.
///
/// The complete source refs and logs remain retained. A real new Signed root
/// establishes destination Original context, and genuine paired disclosure
/// supplies source history independently. Optional burn input exercises copied
/// visibility only, never a native permanent-delete ownership receipt.
///
/// # Panics
/// Panics if actual source publication, byte copy, native activation or Original
/// factory/bootstrap fails, or if any copied creator journal is invented.
pub(super) async fn copied(fixture: &Fixture, id: PackId, burned: bool) -> Fixture {
    use crate::bucket::FileBucketPublicationConfig;
    use crate::domain::DomainNamespace;
    use crate::ref_advance::{CommitTiming, Coordinator};
    use crate::repository::Repository;
    use crate::store::native_publication_effects::collection::test_fs::TestFs;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use terrane_format::gc::publication::{
        PortableCurrent, PortableSnapshot, ProjectionEntry, SelectedHistory,
    };
    let source = {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        held.observe_publication_unrepaired()
            .await
            .unwrap()
            .logical()
            .clone()
    };
    let entropy = fixture.fs.random_bytes(16).await.unwrap();
    let tag: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = fixture.parent.join(format!("copy-{tag}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let mut config = fixture.config.clone();
    config.root = parent.join("bucket");
    config.publication_control = Some(FileBucketPublicationConfig {
        operator_uid: std::fs::symlink_metadata(&parent).unwrap().uid(),
        control: Some(parent.join("publication")),
    });
    let mut directories = vec![(fixture.config.root.clone(), config.root.clone())];
    while let Some((source, destination)) = directories.pop() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&destination)
            .unwrap();
        let mut entries = tokio::fs::read_dir(source).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let output = destination.join(entry.file_name());
            if entry.file_type().await.unwrap().is_dir() {
                directories.push((entry.path(), output));
            } else {
                tokio::fs::copy(entry.path(), output).await.unwrap();
            }
        }
    }
    let mut logical = source;
    logical.retain(|key, _| {
        matches!(
            key.as_str(),
            "CAPABILITIES" | "publication/SELECTED-HISTORY" | "gc/lease"
        ) || key.starts_with("objects/index/")
            || key.starts_with("refs/")
    });
    logical.insert("gc/lease".into(), None);
    if burned {
        let capabilities =
            BucketCapabilities::decode(logical["CAPABILITIES"].as_deref().unwrap()).unwrap();
        let key = format!(
            "objects/index/{}/MANIFEST",
            capabilities.generation.unwrap()
        );
        let mut manifest = GenerationManifest::decode(logical[&key].as_deref().unwrap()).unwrap();
        manifest.burns = Some(vec![*id.as_bytes()]);
        let bytes = manifest.encode().unwrap();
        assert_eq!(GenerationManifest::decode(&bytes).unwrap(), manifest);
        tokio::fs::write(config.root.join(&key), &bytes)
            .await
            .unwrap();
        logical.insert(key, Some(bytes));
    }
    // This canonical portable input is ordinary data. Destination activation
    // still comes exclusively from the real explicit initializer and its receipt.
    let origin =
        SelectedHistory::decode(logical["publication/SELECTED-HISTORY"].as_deref().unwrap())
            .unwrap()
            .origin;
    let snapshot = PortableSnapshot {
        revision: 0,
        origin: origin.clone(),
        predecessor: None,
        projection: logical
            .iter()
            .map(|(key, value)| ProjectionEntry {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    };
    let bytes = snapshot.encode().unwrap();
    let nonce = fixture.fs.random_bytes(32).await.unwrap();
    let operation: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let pointer = PortableCurrent {
        key: format!("publication/snapshots/0:{operation}"),
        digest: *blake3::hash(&bytes).as_bytes(),
    };
    tokio::fs::write(config.root.join(&pointer.key), bytes)
        .await
        .unwrap();
    tokio::fs::write(
        config.root.join("publication/PORTABLE"),
        pointer.encode().unwrap(),
    )
    .await
    .unwrap();
    let fs = TestFs::default();
    let clock = fixture.clock.clone();
    let bucket = FileBucket::initialize_portable_copy(
        config.clone(),
        fs.clone(),
        clock.retain_native_clock().unwrap(),
        super::super::super::fixture::Validator,
    )
    .await
    .unwrap();
    let guard = Guard::new(
        bucket,
        clock.retain_native_clock().unwrap(),
        vec![terrane_format::auth::IssuerKey {
            issuer: "fixture".into(),
            key_id: "fixture".into(),
            retirement: None,
            public_key: fixture_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
        }],
        fixture.guard().config().clone(),
    );
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )
        .unwrap(),
        fs.clone(),
    );
    let original = parent.join("original");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&original)
        .unwrap();
    let owner = std::fs::symlink_metadata(&parent).unwrap().uid();
    let repository = Repository::initialize_native_retention(
        coordinator,
        &DomainNamespace {
            root: config.root.clone(),
            domain: "public".into(),
        },
        &original,
        owner,
    )
    .await
    .unwrap();
    assert!(!parent.join("publication/.terrane-creation").exists());
    let mut writer = repository
        .begin("refs/heads/_/restore-bootstrap", &fixture_token(), "sdk")
        .await
        .unwrap();
    let proposal = bootstrap_request();
    let proposal_template = proposal.commit.clone();
    let head = repository
        .commit_request(&mut writer, proposal)
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
    drop(writer);
    if !burned {
        import_source_history(fixture, &repository).await;
    }
    let imported = GenerationManifest::decode(
        logical[&format!(
            "objects/index/{}/MANIFEST",
            BucketCapabilities::decode(logical["CAPABILITIES"].as_deref().unwrap())
                .unwrap()
                .generation
                .unwrap()
        )]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let exclusion = imported
        .exclusions
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| row.pack_id == *id.as_bytes())
        .unwrap();
    for key in [
        id.pack_key(),
        id.index_key(),
        format!("trash/{}/{id}", exclusion.cycle),
    ] {
        let suffix = blake3::hash(key.as_bytes())
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            !parent
                .join("publication/.terrane-creation")
                .join(suffix)
                .exists()
        );
    }
    assert_ne!(authority.id(), fixture.authority.id());
    assert_eq!(authority.root(), config.root);
    assert_ne!(
        authority.physical_identity(),
        fixture.authority.physical_identity()
    );
    let registration = terrane_format::gc::publication::BackendRegistration::decode(
        &tokio::fs::read(parent.join("publication/backend-registration.cbor"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        registration.activation,
        terrane_format::gc::publication::Activation::Active
    );
    assert!(registration.genesis.is_some());
    assert_ne!(registration.binding, origin);
    {
        let holder = SingleHeld::acquire(repository.coordinator().guard().store())
            .await
            .unwrap();
        let held = holder.destination();
        let selected = held.observe_publication_unrepaired().await.unwrap();
        assert_eq!(selected.state().binding, registration.binding);
        assert_eq!(
            SelectedHistory::decode(
                selected.logical()["publication/SELECTED-HISTORY"]
                    .as_deref()
                    .unwrap()
            )
            .unwrap()
            .origin,
            registration.binding
        );
        assert_eq!(selected.logical()["gc/lease"], None);
    }
    Fixture {
        parent,
        config,
        repository,
        authority,
        head,
        proposal_template,
        clock,
        fs,
        authoring: None,
    }
}

/// Imports real source Original/trust through independently checked public disclosure.
async fn import_source_history(
    fixture: &Fixture,
    destination: &super::super::super::fixture::NativeRepository,
) {
    use crate::domain::DomainNamespace;
    use crate::ref_advance::{
        CommitTiming, Coordinator, DisclosureCommitRequest, DisclosureCommitSelection,
    };
    use crate::repository::Repository;
    use crate::store::native_publication_effects::collection::test_fs::TestFs;
    use std::os::unix::fs::MetadataExt;

    // This observer serves actor setup, so ordinary verified source reads are
    // permitted. The original collector executor's body trap stays armed.
    let fs = TestFs::default();
    let bucket = FileBucket::open(
        fixture.config.clone(),
        fs.clone(),
        fixture.clock.retain_native_clock().unwrap(),
        super::super::super::fixture::Validator,
    )
    .await
    .unwrap();
    let guard = Guard::new(
        bucket,
        fixture.clock.retain_native_clock().unwrap(),
        vec![terrane_format::auth::IssuerKey {
            issuer: "fixture".into(),
            key_id: "fixture".into(),
            retirement: None,
            public_key: fixture_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
        }],
        fixture.guard().config().clone(),
    );
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )
        .unwrap(),
        fs,
    );
    let source = Repository::reopen_native_retention(
        coordinator,
        &DomainNamespace {
            root: fixture.config.root.clone(),
            domain: "public".into(),
        },
        fixture.authority.control(),
        std::fs::symlink_metadata(&fixture.parent).unwrap().uid(),
    )
    .await
    .unwrap();
    let verified = source
        .coordinator()
        .guard()
        .verified_tree(fixture.head.commit)
        .await
        .unwrap();
    let tree = verified
        .evidence
        .tree(verified.evidence.root, 262144)
        .unwrap();
    let mut proposal = bootstrap_request();
    proposal.commit.tree = tree.root_identity();
    proposal.uploads = tree
        .nodes()
        .map(|node| crate::guard::StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    let mut writer = destination
        .begin("refs/heads/_/restore-import", &fixture_token(), "sdk")
        .await
        .unwrap();
    destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut writer,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: "refs/heads/_/main".into(),
                    source_commit: fixture.head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: fixture_token(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}
