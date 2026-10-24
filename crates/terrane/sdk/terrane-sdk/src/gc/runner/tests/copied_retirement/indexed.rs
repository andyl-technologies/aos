//! Publishes a genuine indexed source before constructing a copied destination.
//!
//! The initial Active profile and historical selections come from the existing
//! native fixture and its owning Guards. An unused canonical Memo shares the
//! actual Index result; its unused recipe claim cannot invent a tree-use context.

use crate::bucket::FileBucket;
use crate::domain::DomainNamespace;
use crate::gc::runner::fixture::{self, Fixture};
use crate::guard::{StagedUpload, ViewSelection};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{Clock, ContentStore, ContentUpload, MetaUpload};
use std::collections::BTreeMap;
use std::time::Duration;
use terrane_format::auth::{Authority, Grant, Token, Verbs};
use terrane_format::derived::AttributeValue;
use terrane_format::identity::{Digest, Identity, IdentityKind, TERRANE_V1};
use terrane_format::indexing::carrier::SemanticContext;
use terrane_format::indexing::{IndexEvaluationRecipe, completion, evaluation, maintenance};
use terrane_format::refs::PrincipalKind;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{
    Attribute, ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse,
};

/// Retains independent observations of actual indexed source metadata.
pub(super) struct Observation {
    /// Actual canonical unused Memo identity admitted by the production store.
    pub(super) memo: Identity,
    /// Actual independently live Index result digest.
    pub(super) index: Digest,
    /// Canonical Memo bytes, preserved without consuming their unused recipe claim.
    pub(super) bytes: Vec<u8>,
}

/// Carries a signed native fixture and its genuinely selected historical inputs.
pub(super) struct Setup {
    /// Actual source fixture with its newly published indexed head.
    pub(super) fixture: Fixture,
    /// Exact owning Guard exports for the signed head and its parents.
    pub(super) selections: Vec<ViewSelection>,
    /// Independent metadata observations used by the copied regression.
    pub(super) observation: Observation,
}

fn seed() -> [u8; 32] {
    let hex = b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    std::array::from_fn(|index| {
        u8::from_str_radix(
            std::str::from_utf8(&hex[index * 2..index * 2 + 2]).unwrap(),
            16,
        )
        .unwrap()
    })
}

fn entry(bytes: &[u8]) -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: bytes.len() as u64,
            content: ContentRef::Inline(
                TERRANE_V1
                    .calculate(IdentityKind::Chunk, bytes)
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
            ),
            link_id: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Builds and publishes indexed DATA using actual independently configured authority.
///
/// # Panics
/// Panics on genuine native setup, signature, indexed publication or metadata failure.
pub(super) async fn source() -> Setup {
    // This existing constructor chooses property3/attribute2 before first Guard
    // installation. Candidate fields never select the authoring configuration.
    let mut fixture = Fixture::new_indexed().await;
    let initial = fixture::capture_view_selections(fixture.guard(), &[fixture.head.commit]).await;
    let clock = fixture.clock.retain_native_clock().unwrap();
    let bucket = FileBucket::open(
        fixture.config.clone(),
        fixture.fs.clone(),
        clock.retain_native_clock().unwrap(),
        MetadataValidator::new(fixture.config.chunk_profile.clone()),
    )
    .await
    .unwrap();
    let guard = fixture::configured_guard(
        bucket,
        clock,
        fixture.guard().keys().to_vec(),
        fixture.guard().config().clone(),
        fixture.authoring.as_ref(),
    )
    .with_view_selections(initial)
    .unwrap();
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        fixture.fs.clone(),
    );
    let repository = Repository::reopen_native_retention(
        coordinator,
        &DomainNamespace {
            root: fixture.config.root.clone(),
            domain: "public".into(),
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
    .unwrap();

    let value = AttributeValue::Sha256([11; 32]).encode().unwrap();
    let present_bytes = b"present index object";
    let missing_bytes = b"missing value remains reachable";
    let mut present = entry(present_bytes);
    present.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &value,
    }];
    present.attrs_present = true;
    let source = Tree::build(
        vec![
            LeafItem {
                key: b"missing".to_vec(),
                entry: entry(missing_bytes),
            },
            LeafItem {
                key: b"present".to_vec(),
                entry: present,
            },
        ],
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
    let graph = BTreeMap::from([(source.root_identity(), source.clone())]);
    let recipe = IndexEvaluationRecipe::new(source.root_identity(), "hash.sha256").unwrap();
    // These are the independently chosen fixture evaluation revisions, matching
    // its preinstalled authoring inputs; they do not authorize publication.
    let context = SemanticContext::new(3, 2, 1).unwrap();
    let data = evaluation::construct(&recipe, &graph, 262144, context).unwrap();
    let arena = maintenance::ByteArena::new(1 << 20).unwrap();
    let completed = completion::complete(
        source.root_identity(),
        &graph,
        &[completion::Selection {
            attribute: "hash.sha256",
            data: &data,
        }],
        &arena,
        262144,
        context,
        completion::MemoPolicy::Omit,
    )
    .unwrap();

    let guard = repository.coordinator().guard();
    let mut commit = guard
        .verified_tree(fixture.head.commit)
        .await
        .unwrap()
        .commit
        .commit()
        .clone();
    commit.tree = completed.owner.tree.root_identity();
    commit.parents = vec![fixture.head.commit];
    commit.signature = None;
    commit.timestamp = 0;
    commit.message = "Publish genuine indexed copied DATA".into();
    let mut uploads = completed
        .owner
        .tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect::<Vec<_>>();
    uploads.extend(data.nodes.values().map(|bytes| StagedUpload::Meta {
        kind: IdentityKind::Node,
        bytes: bytes.clone(),
    }));
    for plaintext in [present_bytes.as_slice(), missing_bytes.as_slice()] {
        uploads.push(StagedUpload::Chunk {
            encoded: terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
                codec: terrane_format::codec::Codec::Raw,
                body: plaintext,
            }),
            identity: TERRANE_V1
                .calculate(IdentityKind::Chunk, plaintext)
                .unwrap(),
            declared_plaintext_len: plaintext.len(),
            position: crate::store::ChunkPosition::Final,
            profile: Box::new(fixture.config.chunk_profile.clone()),
        });
    }
    let token = Token::issue(
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
        &seed(),
        fixture.guard().keys()[0].public_key,
    )
    .unwrap()
    .encode();
    let request = CommitRequest {
        commit,
        uploads,
        token: token.clone(),
        terminal_secret: seed(),
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    };
    let mut writer = repository
        .begin("refs/heads/_/main", &token, "sdk")
        .await
        .unwrap();
    let head = repository
        .commit_request(&mut writer, request)
        .await
        .unwrap();
    let selections =
        fixture::capture_view_selections(repository.coordinator().guard(), &[head.commit]).await;
    let index = data.root;
    let mut bytes = vec![0xa2, 1];
    terrane_format::cbor::write_bytes(&mut bytes, &[0xa4; 32]);
    bytes.push(2);
    terrane_format::cbor::write_bytes(&mut bytes, &index);
    let memo = repository
        .coordinator()
        .guard()
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Memo, &bytes).unwrap(),
        ))
        .await
        .unwrap();
    fixture.head = head;
    drop(writer);
    drop(repository);
    Setup {
        fixture,
        selections,
        observation: Observation { memo, index, bytes },
    }
}
