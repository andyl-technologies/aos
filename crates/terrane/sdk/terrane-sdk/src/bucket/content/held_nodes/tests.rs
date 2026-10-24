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
use crate::bucket::tests::Selected as _;
use crate::guard::StagedUpload;
use crate::ref_advance::native_fixture::NativeFixture;
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::{Clock, RefStore, TokioClock, TokioLocalFs};
use std::future::Future as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use terrane_format::auth::Verb;
use terrane_format::cbor;
use terrane_format::refs::RefRecord;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type NodeData = (Identity, Vec<u8>);
const REFERENCE: &str = "refs/heads/_/main";

struct Fixture {
    repository: NativeFixture<TokioLocalFs>,
    head: RefRecord,
    nodes: Vec<NodeData>,
    role_target: Option<terrane_format::identity::Digest>,
    final_check: crate::selected_bridge::OwnedFinalCheck,
}

impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_role_mismatch(false).await
    }

    async fn with_role_mismatch(role_mismatch: bool) -> Result<Self, Box<dyn std::error::Error>> {
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
        let mut role_target = None;
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
            role_target.get_or_insert(unused.root_identity());
            request
                .uploads
                .extend(unused.nodes().map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                }));
        }
        if role_mismatch {
            let mut binding = Vec::new();
            cbor::write_map(&mut binding, 2);
            cbor::write_text(&mut binding, "value");
            cbor::write_map(&mut binding, 1);
            cbor::write_text(&mut binding, "uid");
            let suffix: String = role_target
                .ok_or("actual ordinary role target absent")?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            cbor::write_text(&mut binding, &suffix);
            cbor::write_text(&mut binding, "inherit");
            binding.push(0xf4);
            let unused = Tree::build(
                Vec::new(),
                Some(vec![Property {
                    name: "index-roots",
                    value: &binding,
                }]),
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
        let started = TokioClock.monotonic();
        let authorized = repository
            .guard()
            .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
            .await?;
        let timing = crate::ref_advance::CommitTiming::new(
            repository.maximum_commit_duration(),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )?;
        let final_check = crate::selected_bridge::native_guard::retain_final_check(
            repository.guard(),
            &[authorized],
            started,
            timing,
        )?;
        Ok(Self {
            repository,
            head,
            nodes,
            role_target: if role_mismatch { role_target } else { None },
            final_check,
        })
    }

    fn same_pack_nodes<F, C, V>(
        &self,
        reads: &HeldNodeReads<'_, '_, F, C, V>,
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
    reads: &HeldNodeReads<'_, '_, F, C, V>,
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

fn run_serial_native_io(future: impl std::future::Future<Output = TestResult>) -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?
        .block_on(future)
}

/// Holds the real runtime worker so queued native filesystem reads stay pending.
struct BlockingPause {
    release: Option<std::sync::mpsc::Sender<()>>,
    _worker: tokio::task::JoinHandle<()>,
}

impl BlockingPause {
    async fn acquire() -> Result<Self, Box<dyn std::error::Error>> {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (release, waiting) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = arrived.send(());
            let _ = waiting.recv();
        });
        arrival.await?;
        Ok(Self {
            release: Some(release),
            _worker: worker,
        })
    }
}

impl Drop for BlockingPause {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn held_node_reads_share_same_pack_data_and_require_once_only_fresh_close() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    let (first, second) = fixture.same_pack_nodes(&reads)?;
    assert_eq!(pack_path(&reads, &first.0)?, pack_path(&reads, &second.0)?);

    let (left, right) = tokio::join!(reads.get(&first.0, None), reads.get(&second.0, None));
    assert_eq!(left?, first.1);
    assert_eq!(right?, second.1);
    assert!(reads.completed_reads().is_err());
    reads.finish().await?;
    let consumed = reads.completed_reads()?;
    let pack = pack_path(&reads, &first.0)?;
    assert_eq!(
        consumed.iter().filter(|read| read.path() == pack).count(),
        1
    );
    assert!(reads.finish().await.is_err());
    assert!(reads.get(&first.0, None).await.is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn held_node_reads_refuse_recaptured_selection_and_repeated_closing() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    reads.get(&fixture.nodes[0].0, None).await?;
    let recaptured = held.observe_publication_retained().await?;
    let pack = pack_path(&reads, &fixture.nodes[0].0)?;

    assert_eq!(selected.stamp(), recaptured.stamp());
    reads.check_selection(&selected)?;
    assert!(reads.check_selection(&recaptured).is_err());
    let originals = reads.begin_closing()?;
    assert!(
        originals
            .iter()
            .any(|read| { read.path() == pack && read.retained_payload().is_some() })
    );
    assert!(reads.completed_reads().is_err());
    assert!(reads.get(&fixture.nodes[0].0, None).await.is_err());
    assert!(reads.begin_closing().is_err());
    assert!(reads.finish().await.is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn held_node_data_survives_pack_removal_but_cannot_complete_its_read_scope() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    assert_eq!(
        reads.get(&fixture.nodes[0].0, None).await?,
        fixture.nodes[0].1
    );
    TokioLocalFs
        .remove_file(&pack_path(&reads, &fixture.nodes[0].0)?)
        .await?;

    // Cached immutable data is usable by the private parser, never as authority.
    assert_eq!(
        reads.get(&fixture.nodes[1].0, None).await?,
        fixture.nodes[1].1
    );
    assert!(reads.finish().await.is_err());
    assert!(reads.completed_reads().is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn held_node_close_refuses_pack_overwrite_and_equal_byte_reincarnation() -> TestResult {
    for equal_bytes in [false, true] {
        let fixture = Fixture::new().await?;
        let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
        let held = holder.source();
        let selected = held.observe_publication_retained().await?;
        let reads = held
            .held_node_reads(&selected, fixture.final_check.clone())
            .await?;
        reads.get(&fixture.nodes[0].0, None).await?;
        let path = pack_path(&reads, &fixture.nodes[0].0)?;
        if equal_bytes {
            replace_equal(&path).await?;
        } else {
            let mut bytes = TokioLocalFs.read_nofollow(&path).await?;
            bytes[24] ^= 1;
            tokio::fs::write(&path, bytes).await?;
        }

        assert!(reads.finish().await.is_err(), "equal bytes: {equal_bytes}");
        assert!(reads.completed_reads().is_err());
        assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    }
    Ok(())
}

#[tokio::test]
async fn held_node_close_refuses_detached_index_and_catalog_reincarnation() -> TestResult {
    for detached in [false, true] {
        let fixture = Fixture::new().await?;
        let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
        let held = holder.source();
        let selected = held.observe_publication_retained().await?;
        let reads = held
            .held_node_reads(&selected, fixture.final_check.clone())
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
                    read.path()
                        .extension()
                        .is_some_and(|extension| extension == "idx")
                })
                .ok_or("actual selected catalog shard was not retained")?
                .path()
                .to_owned()
        };
        replace_equal(&path).await?;

        assert!(reads.finish().await.is_err(), "detached index: {detached}");
        assert!(reads.completed_reads().is_err());
        assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    }
    Ok(())
}

#[tokio::test]
async fn held_node_close_refuses_changed_original_pack_ancestry() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    reads.get(&fixture.nodes[0].0, None).await?;
    let path = pack_path(&reads, &fixture.nodes[0].0)?;
    let parent = path.parent().ok_or("actual pack parent absent")?;
    let permissions = TokioLocalFs.symlink_metadata(parent).await?.permissions();
    TokioLocalFs
        .set_permissions_and_sync(parent, std::fs::Permissions::from_mode(0o775))
        .await?;

    assert!(reads.finish().await.is_err());
    assert!(reads.completed_reads().is_err());
    TokioLocalFs
        .set_permissions_and_sync(parent, permissions)
        .await?;
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn held_node_close_refuses_equal_child_bytes_under_reincarnated_parent() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
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

    assert!(reads.finish().await.is_err());
    assert!(reads.completed_reads().is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn held_node_close_refuses_actual_selected_revision_change() -> TestResult {
    let fixture = Fixture::new().await?;
    let holder = SingleHeld::acquire(fixture.repository.store()).await?;
    let held = holder.destination();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    reads.get(&fixture.nodes[0].0, None).await?;
    let next = fixture
        .head
        .advance(fixture.head.commit, fixture.head.writer_epoch)?
        .selected();
    let proposal = crate::bucket::tests::log(next.clone(), Some(fixture.head.clone()));
    assert!(matches!(
        held.ref_log_append(REFERENCE, next.seq, &proposal).await?,
        crate::store::RefLogAppendOutcome::Appended
    ));
    let result = held.ref_cas(REFERENCE, Some(&fixture.head), &next).await?;
    assert!(matches!(result, crate::store::RefCasOutcome::Applied));

    assert!(reads.finish().await.is_err());
    assert!(reads.completed_reads().is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(next));
    Ok(())
}

#[tokio::test]
async fn held_node_close_refuses_selected_slot_and_guard_reincarnation() -> TestResult {
    for guard in [false, true] {
        let fixture = Fixture::new().await?;
        let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
        let held = holder.source();
        let selected = held.observe_publication_retained().await?;
        let reads = held
            .held_node_reads(&selected, fixture.final_check.clone())
            .await?;
        reads.get(&fixture.nodes[0].0, None).await?;
        let control = crate::bucket::tests::control_path(held.root());
        let path = if guard {
            let digest = selected
                .state()
                .guard
                .ok_or("actual selected Guard absent")?;
            let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            control.join(format!("publication/guards/{suffix}"))
        } else {
            control.join(format!("publication/commits/{}", selected.stamp().0))
        };
        replace_equal(&path).await?;

        assert!(reads.finish().await.is_err(), "selected Guard: {guard}");
        assert!(reads.completed_reads().is_err());
    }
    Ok(())
}

#[test]
fn cancelled_native_pack_read_wakes_waiters_without_publishing_incomplete_data() -> TestResult {
    run_serial_native_io(async {
        let fixture = Fixture::new().await?;
        let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
        let held = holder.source();
        let selected = held.observe_publication_retained().await?;
        let reads = held
            .held_node_reads(&selected, fixture.final_check.clone())
            .await?;
        let (leader, follower) = fixture.same_pack_nodes(&reads)?;
        let path = pack_path(&reads, &leader.0)?;
        assert_eq!(path, pack_path(&reads, &follower.0)?);

        let pause = BlockingPause::acquire().await?;
        let mut first = Box::pin(reads.get(&leader.0, None));
        let first_pending =
            poll_fn(|context| Poll::Ready(matches!(first.as_mut().poll(context), Poll::Pending)))
                .await;
        assert!(first_pending, "actual native read did not reach its await");
        let mut second = Box::pin(reads.get(&follower.0, None));
        let wakes = Arc::new(WakeCount::default());
        let follower_waker = Waker::from(Arc::clone(&wakes));
        let mut follower_context = std::task::Context::from_waker(&follower_waker);
        let second_pending = matches!(second.as_mut().poll(&mut follower_context), Poll::Pending);
        assert!(
            second_pending,
            "same-pack follower did not wait for actual data"
        );
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        std::fs::remove_file(&path)?;
        drop(pause);

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), second).await?;
        assert!(outcome.is_err());
        assert!(reads.finish().await.is_err());
        assert!(reads.completed_reads().is_err());
        assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
        Ok(())
    })
}

#[test]
fn cancelling_actual_closing_reads_cannot_complete_the_scope() -> TestResult {
    run_serial_native_io(async {
        let fixture = Fixture::new().await?;
        let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
        let held = holder.source();
        let selected = held.observe_publication_retained().await?;
        let reads = held
            .held_node_reads(&selected, fixture.final_check.clone())
            .await?;
        reads.get(&fixture.nodes[0].0, None).await?;

        let pause = BlockingPause::acquire().await?;
        let mut closing = Box::pin(reads.finish());
        let pending =
            poll_fn(|context| Poll::Ready(matches!(closing.as_mut().poll(context), Poll::Pending)))
                .await;
        assert!(pending, "actual physical closure did not reach its await");
        drop(closing);
        drop(pause);

        assert!(reads.completed_reads().is_err());
        assert!(reads.finish().await.is_err());
        assert!(reads.get(&fixture.nodes[0].0, None).await.is_err());
        assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
        Ok(())
    })
}

#[tokio::test]
async fn actual_unchanged_native_deadline_expiry_refuses_node_scope_completion() -> TestResult {
    let fixture = Fixture::new().await?;
    assert_eq!(
        fixture.repository.maximum_commit_duration(),
        std::time::Duration::from_secs(30)
    );
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    reads.get(&fixture.nodes[0].0, None).await?;

    // Observe real elapsed expiry; neither the injected clock nor C is changed.
    tokio::time::sleep(std::time::Duration::from_secs(31)).await;

    assert!(reads.finish().await.is_err());
    assert!(reads.completed_reads().is_err());
    assert!(reads.get(&fixture.nodes[1].0, None).await.is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}

#[tokio::test]
async fn shared_actual_node_bytes_cannot_supply_an_incompatible_auxiliary_role() -> TestResult {
    let fixture = Fixture::with_role_mismatch(true).await?;
    let holder = SingleHeld::acquire_read_only(fixture.repository.store()).await?;
    let held = holder.source();
    let selected = held.observe_publication_retained().await?;
    let reads = held
        .held_node_reads(&selected, fixture.final_check.clone())
        .await?;
    let target = fixture
        .role_target
        .ok_or("actual ordinary role target absent")?;
    let ordinary = fixture
        .nodes
        .iter()
        .find(|(identity, _)| identity.terrane_v1_digest().ok() == Some(target))
        .ok_or("actual ordinary Node bytes absent")?;
    let incompatible_owner = fixture.nodes.last().ok_or("unused role fixture absent")?;
    assert_eq!(
        pack_path(&reads, &ordinary.0)?,
        pack_path(&reads, &incompatible_owner.0)?
    );
    assert_eq!(reads.get(&ordinary.0, None).await?, ordinary.1);

    let outcome = crate::indexing::load(
        &reads,
        incompatible_owner.0.terrane_v1_digest()?,
        "uid",
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        262144,
    )
    .await;

    match outcome {
        Err(error) => assert_eq!(error.kind(), crate::indexing::ErrorKind::Invalid),
        Ok(_) => panic!("ordinary cached data acquired an incompatible auxiliary role"),
    }
    assert!(reads.completed_reads().is_err());
    assert_eq!(held.ref_get(REFERENCE).await?, Some(fixture.head));
    Ok(())
}
