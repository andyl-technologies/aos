//! Checks scoped graph audit through genuine repositories without content reads.

#![cfg(all(feature = "tokio", unix))]

#[allow(dead_code, reason = "Other targets share this repository fixture.")]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, OLD, TestResult};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use terrane_format::{
    auth::{self, Attenuation, Caveat, Grant, Token, Verbs},
    identity::{Identity, IdentityKind},
    surface::{View, ViewTarget},
    tree_builder::Tree,
    tree_format::{self, Entry, EntryKind, LeafItem, NodeItems, TreeUse},
};
use terrane_sdk::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    StoreErrorKind, StoreFailure,
};
use terrane_sdk::{
    ref_advance::StagedUpload,
    repository::{PreparedTree, RootNodeLimits},
};

fn attenuated(
    fixture: &Fixture,
    attenuation: Attenuation,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret: [u8; 32] = std::fs::read(fixture.location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "invalid terminal fixture seed")?;
    Ok(Token::decode(fixture.authority.token())?
        .attenuate(attenuation, &secret, auth::public_key_from_secret(&secret))?
        .encode())
}

#[tokio::test]
async fn blame_requires_only_selected_root_read_and_refuses_other_scopes() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let current = publish_unrelated_graft(&fixture).await?;
    let view = View::parse(MAIN)?;
    let scoped = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            caveats: vec![Caveat::Root("/".into())],
            ..Default::default()
        },
    )?;

    let blame = fixture
        .repository
        .blame(&view, b"file", &scoped, "sdk")
        .await?;
    assert_eq!(blame.view_commit, current);
    assert_eq!(blame.introduction.commit, commit);
    assert_eq!(blame.introduction.subject, "owner");
    assert!(blame.fold_chain.is_empty());
    let pinned = fixture
        .repository
        .blame(
            &View {
                target: ViewTarget::Commit(commit),
                subtree: Vec::new(),
                policy: None,
            },
            b"file",
            &scoped,
            "sdk",
        )
        .await?;
    assert_eq!(pinned.view_commit, commit);
    assert_eq!(pinned.introduction, blame.introduction);
    assert!(pinned.fold_chain.is_empty());

    let secret_path = fixture
        .repository
        .blame(&view, b"graft/leaf", &scoped, "sdk")
        .await;
    assert!(
        matches!(secret_path, Err(terrane_sdk::repository::Error::Store(error))
        if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    );
    for attenuation in [
        Attenuation {
            not_after: Some(1),
            ..Default::default()
        },
        Attenuation {
            caveats: vec![Caveat::Surface("other".into())],
            ..Default::default()
        },
        Attenuation {
            grants: Some(vec![Grant::new(
                "refs/heads/_/other".into(),
                Verbs::new(1)?,
            )?]),
            ..Default::default()
        },
        Attenuation {
            caveats: vec![Caveat::Root("/sibling".into())],
            ..Default::default()
        },
    ] {
        let token = attenuated(&fixture, attenuation)?;
        assert!(
            matches!(fixture.repository.blame(&view, b"file", &token, "sdk").await,
            Err(terrane_sdk::repository::Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn blame_uses_signed_metadata_without_requesting_object_bodies() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let bodies = Arc::new(AtomicUsize::new(0));
    let repository = fixture
        .repository
        .with_read_driver(|original| MetadataOnly {
            original: original.clone(),
            bodies: Arc::clone(&bodies),
        });

    let blame = repository
        .blame(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;

    assert_eq!(blame.introduction.commit, commit);
    assert_eq!(bodies.load(Ordering::Relaxed), 0);
    Ok(())
}

/// Adds a real sibling authorization root while preserving the original file.
async fn publish_unrelated_graft(
    fixture: &Fixture,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let target = ViewTarget::Ref(MAIN.parse()?);
    let limits = RootNodeLimits {
        max_entries: 64,
        max_metadata_bytes: 65536,
        max_path_bytes: 4096,
    };
    let baseline = fixture
        .repository
        .read_root_nodes(&target, fixture.authority.token(), "sdk", limits)
        .await?;
    let (prepared, uploads) = {
        let original_root = tree_format::decode_node(
            &baseline.nodes()[&baseline.root()],
            true,
            baseline.minimum_chunk_size(),
        )?;
        let entry = |kind| Entry {
            kind,
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        // Publish newly authored metadata through the real admission path.
        // Moving a previously attributed entry without source proof is refused.
        let child = Tree::build(
            vec![LeafItem {
                key: b"leaf".to_vec(),
                entry: entry(EntryKind::Directory { mode: 0o555 }),
            }],
            original_root.props.clone(),
            baseline.minimum_chunk_size(),
            TreeUse::Ordinary,
        )?;
        let uploads = child
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect::<Vec<_>>();
        let NodeItems::Leaf(mut entries) = original_root.items else {
            return Err("expected published original leaf root".into());
        };
        // Keep the original file at its exact attributed path. Only the new
        // unrelated graft requires fresh metadata admission and provenance.
        entries.push(LeafItem {
            key: b"graft".to_vec(),
            entry: entry(EntryKind::Tree {
                root: child.root_identity(),
                props: None,
            }),
        });
        let tree = Tree::build(
            entries,
            original_root.props,
            baseline.minimum_chunk_size(),
            TreeUse::Ordinary,
        )?;
        (PreparedTree::from_tree(&tree)?, uploads)
    };
    let mut session = fixture
        .repository
        .begin(MAIN, fixture.authority.token(), "sdk")
        .await?;
    let mut request = fixture.repository.source_request(
        &fixture.authority,
        fixture::metadata("Publish genuine nested root"),
    );
    request.commit.tree = prepared.root();
    request.commit.parents = vec![baseline.commit()];
    request.uploads.extend(uploads);
    Ok(fixture
        .repository
        .commit(&mut session, prepared, request)
        .await?
        .commit)
}

struct MetadataOnly<S> {
    original: S,
    bodies: Arc<AtomicUsize>,
}

impl<S: CapabilityReport> CapabilityReport for MetadataOnly<S> {
    fn capabilities(&self) -> &Capabilities {
        self.original.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: ContentStore + Sync> ContentStore for MetadataOnly<S> {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("metadata disclosure attempted a content write")
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if matches!(
            identity.kind(),
            IdentityKind::Chunk | IdentityKind::Manifest
        ) {
            self.bodies.fetch_add(1, Ordering::Relaxed);
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        self.original.get(identity, range).await
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("metadata disclosure attempted content presence reads")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("metadata disclosure attempted advisory content enumeration")
    }
}
