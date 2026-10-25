//! Exercises scoped file preparations against actual signed native repositories.

#![cfg(all(feature = "tokio", unix))]
#![allow(
    dead_code,
    reason = "The shared native fixture also supports other targets."
)]

#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, NEW, OLD, TestResult};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use terrane_format::{
    auth::{self, Attenuation, Caveat, Token},
    identity::{Identity, IdentityKind, TERRANE_V1},
    surface::{View, ViewTarget},
    tree_format::ContentRef,
};
use terrane_sdk::{
    repository::{Error, RootNodeLimits},
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
        StoreErrorKind, StoreFailure,
    },
};

#[tokio::test]
async fn file_preparation_selects_exact_signed_metadata_without_content_reads() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let bodies = Arc::new(AtomicUsize::new(0));
    let repository = fixture
        .repository
        .with_read_driver(|original| MetadataOnly {
            original: original.clone(),
            bodies: Arc::clone(&bodies),
        });

    let prepared = repository
        .prepare_file_read(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    let expected = TERRANE_V1
        .calculate(IdentityKind::Chunk, OLD)?
        .terrane_v1_digest()?;
    assert_eq!(prepared.commit(), commit);
    assert_eq!(prepared.path(), b"/file");
    assert_eq!(prepared.content(), ContentRef::Inline(expected));
    assert_eq!(prepared.size(), OLD.len() as u64);
    assert!(!prepared.storage_domain().is_empty());
    assert_ne!(prepared.root(), [0; 32]);
    prepared.finish().await?;
    assert_eq!(bodies.load(Ordering::Relaxed), 0);

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
async fn closing_refuses_a_real_policy_advance_and_a_fresh_historical_read_succeeds() -> TestResult
{
    let fixture = Fixture::new().await?;
    let first = fixture.commit_bytes(OLD).await?;
    let prepared = fixture
        .repository
        .prepare_file_read(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    fixture.commit_bytes(NEW).await?;

    assert!(matches!(prepared.finish().await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. })));

    let view = View {
        target: ViewTarget::Commit(first),
        subtree: Vec::new(),
        policy: None,
    };
    let historical = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(historical.commit(), first);
    assert_eq!(historical.size(), OLD.len() as u64);
    historical.finish().await?;
    Ok(())
}

#[tokio::test]
async fn a_root_scoped_token_prepares_a_file_without_disclosing_an_unrelated_graft() -> TestResult {
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{self, Entry, EntryKind, LeafItem, NodeItems, TreeUse};
    use terrane_sdk::{ref_advance::StagedUpload, repository::PreparedTree};

    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
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
    fixture
        .repository
        .commit(&mut session, prepared, request)
        .await?;
    let secret: [u8; 32] = std::fs::read(fixture.location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "invalid terminal fixture seed")?;
    let token = Token::decode(fixture.authority.token())?
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Root("/".into())],
                ..Default::default()
            },
            &secret,
            auth::public_key_from_secret(&secret),
        )?
        .encode();

    let file = fixture
        .repository
        .prepare_file_read(&View::parse(MAIN)?, b"file", &token, "sdk")
        .await?;
    assert_eq!(file.path(), b"/file");
    file.finish().await?;
    assert!(
        matches!(fixture.repository.read_root_nodes(&target, &token, "sdk", limits).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    );
    Ok(())
}

#[tokio::test]
async fn manifest_file_preparation_requires_no_manifest_or_chunk_body_read() -> TestResult {
    let fixture = Fixture::new().await?;
    let plaintext = vec![0x5a; terrane_format::chunking::CDC_1M_MIN + 1];
    let commit = fixture.commit_bytes(&plaintext).await?;
    let bodies = Arc::new(AtomicUsize::new(0));
    let repository = fixture
        .repository
        .with_read_driver(|original| MetadataOnly {
            original: original.clone(),
            bodies: Arc::clone(&bodies),
        });

    let prepared = repository
        .prepare_file_read(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    assert_eq!(prepared.commit(), commit);
    assert!(matches!(prepared.content(), ContentRef::Manifest(_)));
    assert_eq!(prepared.size(), plaintext.len() as u64);
    prepared.finish().await?;
    assert_eq!(bodies.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn non_files_invalid_paths_and_wrong_surfaces_never_prepare_a_handle() -> TestResult {
    let fixture = Fixture::new().await?;
    let source = fixture.parent.join("source");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(source.join("directory"))?;
    std::fs::write(source.join("directory/file"), OLD)?;
    std::os::unix::fs::symlink("../outside", source.join("link"))?;
    std::fs::write(source.join("file"), OLD)?;
    fixture.commit_directory(&source).await?;

    for path in [
        b"directory".as_slice(),
        b"link",
        b"missing",
        b"../file",
        b"/file",
        b"",
    ] {
        assert!(
            fixture
                .repository
                .prepare_file_read(&View::parse(MAIN)?, path, fixture.authority.token(), "sdk")
                .await
                .is_err()
        );
    }
    let mut subtree = View::parse(MAIN)?;
    subtree.subtree = b"directory".to_vec();
    let nested = fixture
        .repository
        .prepare_file_read(&subtree, b"file", fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(nested.path(), b"/directory/file");
    nested.finish().await?;

    let secret: [u8; 32] = std::fs::read(fixture.location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "invalid terminal fixture seed")?;
    let token = Token::decode(fixture.authority.token())?
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Surface("different-surface".into())],
                ..Default::default()
            },
            &secret,
            auth::public_key_from_secret(&secret),
        )?
        .encode();
    assert!(
        matches!(fixture.repository.prepare_file_read(&View::parse(MAIN)?, b"file", &token, "sdk").await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    );
    Ok(())
}

#[tokio::test]
async fn file_storage_constraint_checks_signed_private_policy_without_content_reads() -> TestResult
{
    use terrane_format::properties::{EffectiveProperties, PropertyName, Value};
    use terrane_sdk::guard::ReadStoragePolicy;

    struct StoragePolicy {
        refuse: bool,
        checks: AtomicUsize,
    }

    impl ReadStoragePolicy for StoragePolicy {
        fn validate(&self, properties: &EffectiveProperties<'_>) -> Result<(), StoreFailure> {
            self.checks.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                properties.get(PropertyName::Wipe),
                Some(&Value::Text("zero"))
            );
            if self.refuse {
                Err(StoreFailure::new(StoreErrorKind::Unavailable {
                    retry_after: None,
                }))
            } else {
                Ok(())
            }
        }
    }

    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let bodies = Arc::new(AtomicUsize::new(0));
    let repository = fixture
        .repository
        .with_read_driver(|original| MetadataOnly {
            original: original.clone(),
            bodies: Arc::clone(&bodies),
        });
    let prepared = repository
        .prepare_file_read(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    let refusing = StoragePolicy {
        refuse: true,
        checks: AtomicUsize::new(0),
    };
    let accepting = StoragePolicy {
        refuse: false,
        checks: AtomicUsize::new(0),
    };

    assert!(matches!(prepared.validate_storage_policy(&refusing),
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Unavailable { .. })));
    prepared.validate_storage_policy(&accepting)?;
    assert_eq!(refusing.checks.load(Ordering::Relaxed), 1);
    assert_eq!(accepting.checks.load(Ordering::Relaxed), 1);
    assert_eq!(bodies.load(Ordering::Relaxed), 0);

    // A storage refusal grants no alternative authority and does not replace
    // the ordinary closing check of this still-private preparation.
    prepared.finish().await?;
    assert_eq!(bodies.load(Ordering::Relaxed), 0);
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
