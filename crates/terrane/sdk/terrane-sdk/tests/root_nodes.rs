//! Exercises complete root disclosure through genuine signed native repositories.

#![cfg(all(feature = "tokio", unix))]
#![allow(
    dead_code,
    reason = "The shared native fixture also supports other targets."
)]

#[path = "local_sdk/fixture.rs"]
mod fixture;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use fixture::{Fixture, MAIN, NEW, OLD, TestResult};
use terrane_format::{
    auth::{self, Attenuation, Caveat, Grant, Token, Verbs},
    identity::{Identity, IdentityKind, TERRANE_V1},
    surface::{View, ViewTarget},
    tree_format::{self, EntryKind, NodeItems},
};
use terrane_sdk::{
    repository::{Error, RootNodeLimits},
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
        StoreErrorKind, StoreFailure,
    },
};

fn limits() -> RootNodeLimits {
    RootNodeLimits {
        max_entries: 128,
        max_metadata_bytes: 1024 * 1024,
        max_path_bytes: 65536,
    }
}

fn target() -> Result<ViewTarget, Box<dyn std::error::Error>> {
    Ok(ViewTarget::Ref(MAIN.parse()?))
}

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
async fn canonical_nodes_preserve_the_signed_target_without_any_content_read() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let bodies = Arc::new(AtomicUsize::new(0));
    let repository = fixture
        .repository
        .with_read_driver(|original| MetadataOnly {
            original: original.clone(),
            bodies: Arc::clone(&bodies),
        });

    let metadata = repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;

    assert_eq!(metadata.commit(), commit);
    assert_eq!(bodies.load(Ordering::Relaxed), 0);
    assert!(metadata.nodes().contains_key(&metadata.root()));
    for (identity, bytes) in metadata.nodes() {
        assert_eq!(
            TERRANE_V1.calculate(IdentityKind::Node, bytes)?.digest(),
            *identity
        );
        tree_format::decode_node(
            bytes,
            *identity == metadata.root(),
            metadata.minimum_chunk_size(),
        )?;
    }

    assert!(
        repository
            .read_file(
                &View::parse(MAIN)?,
                b"file",
                fixture.authority.token(),
                "sdk"
            )
            .await
            .is_err()
    );
    assert!(bodies.load(Ordering::Relaxed) > 0);
    Ok(())
}

#[tokio::test]
async fn reopened_and_pinned_reads_preserve_the_selected_immutable_root() -> TestResult {
    let fixture = Fixture::new().await?;
    let old_commit = fixture.commit_bytes(OLD).await?;
    let old = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;
    let new_commit = fixture.commit_bytes(NEW).await?;
    let fixture = fixture.reopen().await?;

    let pinned = fixture
        .repository
        .read_root_nodes(
            &ViewTarget::Commit(old_commit),
            fixture.authority.token(),
            "sdk",
            limits(),
        )
        .await?;
    let current = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;

    assert_eq!(pinned.commit(), old_commit);
    assert_eq!(pinned.root(), old.root());
    assert_eq!(pinned.nodes(), old.nodes());
    assert_eq!(current.commit(), new_commit);
    assert_ne!(current.root(), old.root());
    Ok(())
}

#[tokio::test]
async fn exact_inventory_entry_and_path_limits_pass_and_each_underflow_refuses() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let metadata = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;
    let exact = RootNodeLimits {
        max_entries: 2,
        max_metadata_bytes: metadata
            .nodes()
            .values()
            .map(|bytes| 32 + bytes.len())
            .sum(),
        max_path_bytes: b"/".len() + b"/file".len(),
    };
    let repeated = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", exact)
        .await?;
    assert_eq!(repeated.nodes(), metadata.nodes());

    for bounded in [
        RootNodeLimits {
            max_entries: 1,
            ..exact
        },
        RootNodeLimits {
            max_metadata_bytes: exact.max_metadata_bytes - 1,
            ..exact
        },
        RootNodeLimits {
            max_path_bytes: exact.max_path_bytes - 1,
            ..exact
        },
    ] {
        assert!(matches!(
            fixture
                .repository
                .read_root_nodes(&target()?, fixture.authority.token(), "sdk", bounded)
                .await,
            Err(Error::Tree(tree_format::Error::Limit))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn empty_roots_still_require_read_and_current_credentials() -> TestResult {
    let fixture = Fixture::new().await?;
    let metadata = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;
    let node = tree_format::decode_node(
        &metadata.nodes()[&metadata.root()],
        true,
        metadata.minimum_chunk_size(),
    )?;
    assert!(matches!(node.items, NodeItems::Leaf(items) if items.is_empty()));
    let expired = attenuated(
        &fixture,
        Attenuation {
            not_after: Some(1),
            ..Default::default()
        },
    )?;
    let other_reference = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(
                "refs/heads/_/other".into(),
                Verbs::new(1)?,
            )?]),
            ..Default::default()
        },
    )?;

    for token in [
        b"invalid".as_slice(),
        expired.as_slice(),
        other_reference.as_slice(),
    ] {
        assert!(
            matches!(fixture.repository.read_root_nodes(&target()?, token, "sdk", limits()).await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn surface_and_named_root_caveats_cannot_disclose_a_full_root() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    for caveat in [
        Caveat::Surface("different-surface".into()),
        Caveat::Root("/private".into()),
    ] {
        let token = attenuated(
            &fixture,
            Attenuation {
                caveats: vec![caveat],
                ..Default::default()
            },
        )?;
        assert!(
            matches!(fixture.repository.read_root_nodes(&target()?, &token, "sdk", limits()).await,
            Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
        );
    }
    Ok(())
}

#[tokio::test]
async fn raw_symlink_targets_survive_without_checkout_resolution() -> TestResult {
    let fixture = Fixture::new().await?;
    let source = fixture.parent.join("source");
    std::fs::create_dir(&source)?;
    std::os::unix::fs::symlink("../../outside//untouched", source.join("link"))?;
    fixture.commit_directory(&source).await?;

    let metadata = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;
    let node = tree_format::decode_node(
        &metadata.nodes()[&metadata.root()],
        true,
        metadata.minimum_chunk_size(),
    )?;
    let NodeItems::Leaf(items) = node.items else {
        return Err("expected leaf root".into());
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].key, b"link");
    assert!(matches!(
        items[0].entry.kind,
        EntryKind::Symlink {
            target: b"../../outside//untouched"
        }
    ));
    Ok(())
}

#[tokio::test]
async fn a_denied_graft_descendant_refuses_the_entire_node_inventory() -> TestResult {
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{Entry, LeafItem, TreeUse};
    use terrane_sdk::{ref_advance::StagedUpload, repository::PreparedTree};

    let fixture = Fixture::new().await?;
    let baseline = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
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
        let tree = Tree::build(
            vec![LeafItem {
                key: b"graft".to_vec(),
                entry: entry(EntryKind::Tree {
                    root: child.root_identity(),
                    props: None,
                }),
            }],
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
    fixture
        .repository
        .commit(&mut session, prepared, request)
        .await?;
    let full = fixture
        .repository
        .read_root_nodes(&target()?, fixture.authority.token(), "sdk", limits())
        .await?;
    let root =
        tree_format::decode_node(&full.nodes()[&full.root()], true, full.minimum_chunk_size())?;
    let NodeItems::Leaf(entries) = root.items else {
        return Err("expected published leaf root".into());
    };
    let graft = entries
        .iter()
        .find(|entry| entry.key == b"graft")
        .ok_or("published graft missing")?;
    let EntryKind::Tree {
        root: graft_root, ..
    } = &graft.entry.kind
    else {
        return Err("published graft changed kind".into());
    };
    assert!(full.nodes().contains_key(graft_root));
    let root_only = attenuated(
        &fixture,
        Attenuation {
            caveats: vec![Caveat::Root("/".into())],
            ..Default::default()
        },
    )?;

    assert!(matches!(
        fixture.repository.read_root_nodes(&target()?, &root_only, "sdk", limits()).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. })
    ));
    Ok(())
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
