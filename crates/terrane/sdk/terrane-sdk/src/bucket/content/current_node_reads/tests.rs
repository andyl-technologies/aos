//! Refuses real physical and selected mutations after reusable Node data reads.
//!
//! Fixtures publish through the production native repository before acquiring
//! the tested scope. Adversarial writes mutate only that isolated real backend;
//! no test constructs a completed history, physical recipe or publication ACK.

#![allow(
    clippy::unwrap_used,
    reason = "Isolated fixture assertions intentionally panic."
)]

use super::*;
use crate::bucket::held::SingleHeld;
use crate::guard::StagedUpload;
use crate::ref_advance::native_fixture::NativeFixture;
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::{Clock, RefStore, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use terrane_format::auth::Verb;
use terrane_format::refs::RefRecord;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem, TreeUse};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type NodeData = (Identity, Vec<u8>);
const REFERENCE: &str = "refs/heads/_/main";

struct Fixture {
    repository: NativeFixture<TokioLocalFs>,
    head: RefRecord,
    nodes: Vec<NodeData>,
    current_check: crate::guard::PendingCurrentReadCheck,
}

impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let repository = fixture().await;
        let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
        let mut request = request_file(Vec::new(), b"actual held Node read scope");
        let empty = Tree::build(Vec::new(), None, 262144, TreeUse::Ordinary)?;
        request
            .uploads
            .extend(empty.nodes().map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            }));
        let chunk = TERRANE_V1
            .calculate(IdentityKind::Chunk, b"actual held Node read scope")?
            .terrane_v1_digest()?;
        // The initial empty Node already exists. These distinct ordinary Nodes
        // enter one later native Meta run after the shared chunk is durable.
        for key in [b"unused-a", b"unused-b"] {
            let unused = Tree::build(
                vec![LeafItem {
                    key: key.to_vec(),
                    entry: Entry {
                        kind: EntryKind::File {
                            mode: 0o644,
                            size: b"actual held Node read scope".len() as u64,
                            content: ContentRef::Inline(chunk),
                            link_id: None,
                        },
                        attrs: Vec::new(),
                        attrs_present: false,
                        xattrs: Vec::new(),
                        xattrs_present: false,
                        provenance: None,
                    },
                }],
                None,
                262144,
                TreeUse::Ordinary,
            )?;
            request
                .uploads
                .extend(unused.nodes().map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                }));
        }
        let nodes = request
            .uploads
            .iter()
            .filter_map(|upload| match upload {
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                } => Some(bytes),
                _ => None,
            })
            .map(|bytes| {
                Ok((
                    TERRANE_V1.calculate(IdentityKind::Node, bytes)?,
                    bytes.clone(),
                ))
            })
            .collect::<Result<Vec<_>, terrane_format::identity::IdentityError>>()?;
        let head = repository.advance(&mut writer, request).await?;
        let current_check = crate::guard::PendingCurrentReadCheck::for_guard(
            repository.guard(),
            REFERENCE,
            &token(),
            Verb::Read,
        )?;
        Ok(Self {
            repository,
            head,
            nodes,
            current_check,
        })
    }

    fn same_pack_nodes<F, C, V>(
        &self,
        reads: &HeldCurrentNodeReads<'_, '_, F, C, V>,
    ) -> Result<(&NodeData, &NodeData), Box<dyn std::error::Error>>
    where
        F: LocalFs + BucketBinding,
        C: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        for (index, first) in self.nodes.iter().enumerate() {
            for second in &self.nodes[index + 1..] {
                if first.0 != second.0
                    && pack_path(reads, &first.0)? == pack_path(reads, &second.0)?
                {
                    return Ok((first, second));
                }
            }
        }
        Err("actual native batch has no distinct same-pack Node pair".into())
    }
}

fn pack_path<F, C, V>(
    reads: &HeldCurrentNodeReads<'_, '_, F, C, V>,
    node: &Identity,
) -> Result<PathBuf, StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    Ok(reads.bucket.root().join(
        reads
            .bucket
            .location(&reads.catalog, node)?
            .pack()
            .pack_key(),
    ))
}

async fn replace_equal(path: &Path) -> TestResult {
    let before = std::fs::symlink_metadata(path)?;
    let bytes = TokioLocalFs.read_nofollow(path).await?;
    let permissions = TokioLocalFs.symlink_metadata(path).await?.permissions();
    let temporary = path.with_extension("replacement");
    TokioLocalFs.write_new(&temporary, &bytes).await?;
    TokioLocalFs
        .set_permissions_and_sync(&temporary, permissions)
        .await?;
    TokioLocalFs.rename(&temporary, path).await?;
    let after = std::fs::symlink_metadata(path)?;
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(TokioLocalFs.read_nofollow(path).await?, bytes);
    Ok(())
}

#[tokio::test]
async fn current_node_reads_share_pack_data_and_refuse_repeated_closing() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let (first, second) = fixture.same_pack_nodes(&reads)?;

    let (left, right) = tokio::join!(reads.get(&first.0, None), reads.get(&second.0, None));
    assert_eq!(left?, first.1);
    assert_eq!(right?, second.1);
    let consumed = reads.begin_closing()?;
    let pack = pack_path(&reads, &first.0)?;
    assert_eq!(
        consumed.iter().filter(|read| read.path() == pack).count(),
        1
    );
    for read in &consumed {
        read.revalidate_retained(held.fs()).await?;
    }
    assert!(reads.begin_closing().is_err());
    assert!(reads.get(&first.0, None).await.is_err());
    assert!(reads.completed_reads().is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn current_closing_refuses_in_flight_cached_hit_and_releases_cancelled_consumer() -> TestResult
{
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let (first, second) = fixture.same_pack_nodes(&reads)?;
    assert_eq!(reads.get(&first.0, None).await?, first.1);
    let (entered, arrival) = tokio::sync::oneshot::channel();
    let (_resume, waiting) = tokio::sync::oneshot::channel();
    *reads.consumer_pause.lock().unwrap() = Some(ConsumerPause {
        entered,
        resume: waiting,
    });

    let mut consumer = Box::pin(reads.get(&second.0, None));
    tokio::select! {
        result = &mut consumer => panic!("paused cache-hit consumer completed: {result:?}"),
        result = arrival => result?,
    }
    assert_eq!(reads.cache.lock().unwrap().active_consumers, 1);
    assert!(reads.begin_closing().is_err());
    drop(consumer);
    assert_eq!(reads.cache.lock().unwrap().active_consumers, 0);
    assert!(reads.begin_closing().is_ok());
    assert!(reads.completed_reads().is_err());
    Ok(())
}

#[tokio::test]
async fn current_node_original_pack_receipt_refuses_same_byte_replacement() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let (first, _) = fixture.same_pack_nodes(&reads)?;
    assert_eq!(reads.get(&first.0, None).await?, first.1);
    let pack = pack_path(&reads, &first.0)?;
    replace_equal(&pack).await?;

    let consumed = reads.begin_closing()?;
    let original = consumed
        .iter()
        .find(|read| read.path() == pack)
        .ok_or("pack receipt absent")?;
    assert!(original.revalidate_retained(held.fs()).await.is_err());
    assert!(reads.completed_reads().is_err());
    Ok(())
}

#[tokio::test]
async fn current_node_reader_refuses_recaptured_selection_and_foreign_holder() -> TestResult {
    let fixture = Fixture::new().await?;
    let foreign = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let recaptured = held.observe_publication_retained().await?;
    let foreign_holder = SingleHeld::acquire_read_only(foreign.repository.store()).await?;

    assert!(reads.check_selection(&selected).is_ok());
    assert!(reads.check_selection(&recaptured).is_err());
    assert!(
        reads
            .check_holder(&foreign_holder.source().identity_proof())
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn current_history_commit_read_joins_the_same_consumed_data_ledger() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = TERRANE_V1.from_digest(IdentityKind::Commit, &fixture.head.commit)?;
    let expected = fixture.repository.store().get(&commit, None).await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;

    assert_eq!(reads.get(&commit, None).await?, expected);
    let pack = pack_path(&reads, &commit)?;
    let consumed = reads.begin_closing()?;
    assert_eq!(
        consumed.iter().filter(|read| read.path() == pack).count(),
        1
    );
    assert!(
        consumed
            .iter()
            .find(|read| read.path() == pack)
            .ok_or("commit pack receipt absent")?
            .is_ordinary_retained()
    );
    assert!(reads.completed_reads().is_err());
    Ok(())
}

#[tokio::test]
async fn current_node_reader_refuses_corrupt_pack_and_failed_scope_closing() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let (first, _) = fixture.same_pack_nodes(&reads)?;
    let path = pack_path(&reads, &first.0)?;
    let mut corrupt = TokioLocalFs.read_nofollow(&path).await?;
    corrupt[24] ^= 1;
    tokio::fs::write(&path, corrupt).await?;

    assert!(reads.get(&first.0, None).await.is_err());
    assert!(reads.begin_closing().is_err());
    assert!(reads.completed_reads().is_err());
    Ok(())
}

#[tokio::test]
async fn current_reader_refuses_another_authentication_capture_on_same_selection() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let foreign = crate::guard::PendingCurrentReadCheck::for_guard(
        fixture.repository.guard(),
        REFERENCE,
        &token(),
        Verb::Read,
    )?;

    assert!(reads.check_current(&fixture.current_check.clone()).is_ok());
    assert!(reads.check_current(&foreign).is_err());
    assert!(reads.completed_reads().is_err());
    Ok(())
}

#[tokio::test]
async fn current_original_receipts_refuses_detached_index_and_catalog_reincarnation() -> TestResult
{
    for detached in [false, true] {
        let fixture = Fixture::new().await?;
        let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
        let held = holder.source();
        let selected = held.observe_publication_retained().await?;
        let reads = held
            .current_node_reads(&selected, &fixture.current_check)
            .await?;
        reads.get(&fixture.nodes[0].0, None).await?;
        let path = if detached {
            let id = reads
                .bucket
                .location(&reads.catalog, &fixture.nodes[0].0)?
                .pack();
            reads.bucket.root().join(id.index_key())
        } else {
            reads
                .artifacts
                .reads
                .lock()
                .unwrap()
                .iter()
                .find(|read| {
                    read.bytes().is_some()
                        && read
                            .path()
                            .starts_with(reads.bucket.root().join("objects/index"))
                        && read
                            .path()
                            .extension()
                            .is_some_and(|extension| extension == "idx")
                })
                .ok_or("actual selected catalog shard was not retained")?
                .path()
                .to_owned()
        };
        if !detached {
            assert!(path.starts_with(reads.bucket.root().join("objects/index")));
        }
        replace_equal(&path).await?;

        let consumed = reads.begin_closing()?;
        let original = consumed
            .iter()
            .find(|read| read.path() == path)
            .ok_or("actual replaced DATA receipt absent")?;
        assert!(
            original.revalidate_retained(held.fs()).await.is_err(),
            "detached index: {detached}"
        );
        assert!(reads.completed_reads().is_err());
        assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    }
    Ok(())
}

#[tokio::test]
async fn current_original_receipts_refuses_equal_child_bytes_under_reincarnated_parent()
-> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    reads.get(&fixture.nodes[0].0, None).await?;
    let path = pack_path(&reads, &fixture.nodes[0].0)?;
    let parent = path.parent().ok_or("actual pack parent absent")?;
    let before = TokioLocalFs.symlink_metadata(&path).await?;
    let parent_before = TokioLocalFs.symlink_metadata(parent).await?;
    let displaced = parent.with_extension("original-parent");

    // Move the actual children without replacing their inodes. Only the
    // directory selected by the original ancestor receipt is reincarnated.
    TokioLocalFs.rename(parent, &displaced).await?;
    TokioLocalFs.create_dir_new(parent).await?;
    TokioLocalFs
        .set_permissions_and_sync(parent, parent_before.permissions())
        .await?;
    let mut children = tokio::fs::read_dir(&displaced).await?;
    while let Some(child) = children.next_entry().await? {
        TokioLocalFs
            .rename(&child.path(), &parent.join(child.file_name()))
            .await?;
    }
    let after = TokioLocalFs.symlink_metadata(&path).await?;
    let parent_after = TokioLocalFs.symlink_metadata(parent).await?;
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_ne!(
        (parent_before.dev(), parent_before.ino()),
        (parent_after.dev(), parent_after.ino())
    );

    let consumed = reads.begin_closing()?;
    let original = consumed
        .iter()
        .find(|read| read.path() == path)
        .ok_or("actual pack DATA receipt absent")?;
    assert!(original.revalidate_retained(held.fs()).await.is_err());
    assert!(reads.completed_reads().is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn current_node_reader_keeps_public_hardlinked_pack_data_readable() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .current_node_reads(&selected, &fixture.current_check)
        .await?;
    let (first, _) = fixture.same_pack_nodes(&reads)?;
    let pack = pack_path(&reads, &first.0)?;
    let alias = pack.with_extension("ordinary-alias");
    tokio::fs::hard_link(&pack, &alias).await?;
    TokioLocalFs
        .set_permissions_and_sync(&pack, std::fs::Permissions::from_mode(0o644))
        .await?;
    assert!(std::fs::symlink_metadata(&pack)?.nlink() > 1);

    assert_eq!(reads.get(&first.0, None).await?, first.1);
    let consumed = reads.begin_closing()?;
    let original = consumed
        .iter()
        .find(|read| read.path() == pack)
        .ok_or("ordinary pack recipe absent")?;
    assert!(original.is_ordinary_retained());
    original.revalidate_retained(held.fs()).await?;
    assert!(reads.completed_reads().is_err());
    Ok(())
}
