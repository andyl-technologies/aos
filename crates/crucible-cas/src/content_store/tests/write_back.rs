//! Write back content-store behavior tests.

use super::*;

#[test]
fn durable_write_back_survives_restart_and_exposes_exact_retention_roots() {
    let temp = TempDir::new().expect("temporary directory");
    let graph = write_back_graph(temp.path(), 8, 1_024).expect("write-back graph");
    assert!(
        graph
            .describe()
            .iter()
            .any(|node| node.kind == StoreNodeKind::WriteBack)
    );

    let bytes = b"durable deferred transfer";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    let opens = Arc::new(AtomicUsize::new(0));
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let source = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::from(bytes.as_slice()),
        opens: Arc::clone(&opens),
        bytes_read: Arc::clone(&bytes_read),
    }));
    let receipt = graph
        .put_if_absent(id, &source)
        .expect("stage write-back object");
    assert!(receipt.is_durable());
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    assert_eq!(bytes_read.load(Ordering::SeqCst), bytes.len());
    assert!(matches!(
        write_back_graph(temp.path(), 9, 1_024),
        Err(StoreError::Incompatible)
    ));

    let destination = DirectoryBlobBackend::new("destination-check", temp.path().join("archive"));
    assert!(!destination.contains(id).expect("destination absence"));
    let mut fence = graph
        .acquire_write_back_retention_fence()
        .expect("write-back retention fence");
    let mut roots = Vec::new();
    let summary = fence
        .visit_roots(&mut |root| {
            roots.push(root);
            Ok(())
        })
        .expect("pending roots");
    assert_eq!(summary.roots(), 1);
    assert_eq!(summary.logical_bytes(), bytes.len() as u64);
    assert_eq!(roots[0].node(), "write-back");
    assert_eq!(roots[0].id(), id);
    drop(fence);

    let restarted = write_back_graph(temp.path(), 8, 1_024).expect("restart write-back graph");
    let flush = restarted
        .flush_write_back(1)
        .expect("flush pending transfer");
    assert_eq!(flush.completed(), 1);
    assert_eq!(flush.pending(), 0);
    assert_eq!(
        read_bytes(&destination, id, None).expect("destination object"),
        bytes
    );

    let reopened = write_back_graph(temp.path(), 8, 1_024).expect("reopen completed journal");
    assert_eq!(
        reopened
            .flush_write_back(1)
            .expect("idempotent empty flush")
            .completed(),
        0
    );
}

#[test]
fn write_back_retention_fence_excludes_children_before_journal_publication() {
    let temp = TempDir::new().expect("temporary directory");
    let graph = write_back_graph(temp.path(), 8, 1_024).expect("write-back graph");
    let fence = graph
        .acquire_write_back_retention_fence()
        .expect("exclusive transfer fence");
    let bytes = b"fenced transfer";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    let started = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let worker_graph = write_back_graph(temp.path(), 8, 1_024).expect("second graph instance");
    let worker_started = Arc::clone(&started);
    let worker_finished = Arc::clone(&finished);
    let worker = thread::spawn(move || {
        worker_started.store(true, Ordering::Release);
        put_bytes(&worker_graph, id, bytes).expect("fenced write-back put");
        worker_finished.store(true, Ordering::Release);
    });
    while !started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(Duration::from_millis(25));
    assert!(!finished.load(Ordering::Acquire));
    drop(fence);
    worker.join().expect("fenced writer");
    assert!(finished.load(Ordering::Acquire));
}

#[test]
fn write_back_journal_recovers_torn_tail_and_rejects_corruption() {
    let temp = TempDir::new().expect("temporary directory");
    let bytes = b"journal recovery";
    let id = ContentId::for_bytes(ObjectKind::Finding, 1, bytes);
    {
        let graph = write_back_graph(temp.path(), 8, 1_024).expect("write-back graph");
        put_bytes(&graph, id, bytes).expect("pending transfer");
    }

    let journal = temp.path().join("journal/transfers-v1.log");
    let original = fs::read(&journal).expect("journal bytes");
    let mut torn = original.clone();
    torn.extend_from_slice(&[0, 0]);
    fs::write(&journal, torn).expect("write torn tail");
    let recovered = write_back_graph(temp.path(), 8, 1_024).expect("recover torn tail");
    let mut fence = recovered
        .acquire_write_back_retention_fence()
        .expect("retention fence");
    assert_eq!(
        fence
            .visit_roots(&mut |_root| Ok(()))
            .expect("recovered roots")
            .roots(),
        1
    );
    drop(fence);
    assert_eq!(fs::read(&journal).expect("truncated journal"), original);

    fs::write(&journal, &original[..8]).expect("write truncated journal header");
    assert!(matches!(
        write_back_graph(temp.path(), 8, 1_024),
        Err(StoreError::Incompatible)
    ));

    fs::write(&journal, &original).expect("restore complete journal");
    let mut corrupt = original;
    let last = corrupt.last_mut().expect("journal record checksum");
    *last ^= 0x80;
    fs::write(&journal, corrupt).expect("corrupt journal");
    assert!(matches!(
        write_back_graph(temp.path(), 8, 1_024),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn write_back_bounds_and_durable_child_requirements_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let graph = write_back_graph(temp.path(), 8, 4).expect("bounded write-back graph");
    let first = ContentId::for_bytes(ObjectKind::Finding, 1, b"four");
    put_bytes(&graph, first, b"four").expect("first bounded transfer");
    let overflow = ContentId::for_bytes(ObjectKind::Finding, 1, b"five!");
    assert!(matches!(
        put_bytes(&graph, overflow, b"five!"),
        Err(StoreError::Quota)
    ));
    let staging_check = DirectoryBlobBackend::new("staging-check", temp.path().join("staging"));
    assert!(
        !staging_check
            .contains(overflow)
            .expect("quota rejection leaves staging unchanged")
    );

    let root = node_id("write-back");
    let staging = node_id("memory-staging");
    let destination = node_id("destination");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    root,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: temp.path().join("invalid-journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Memory {
                        max_logical_bytes: 1_024,
                    },
                ),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("invalid-destination"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidComposition { .. })
    ));

    let outer = node_id("outer-write-back");
    let inner = node_id("inner-write-back");
    let inner_staging = node_id("inner-staging");
    let inner_destination = node_id("inner-destination");
    let outer_destination = node_id("outer-destination");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: outer.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    outer,
                    StoreNodeSpec::WriteBack {
                        staging: inner.clone(),
                        destination: outer_destination.clone(),
                        journal_root: temp.path().join("outer-journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    inner,
                    StoreNodeSpec::WriteBack {
                        staging: inner_staging.clone(),
                        destination: inner_destination.clone(),
                        journal_root: temp.path().join("inner-journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (
                    inner_staging,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("inner-staging"),
                    },
                ),
                (
                    inner_destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("inner-destination"),
                    },
                ),
                (
                    outer_destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("outer-destination"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn write_back_journal_paths_cannot_overlap_blob_or_other_journal_roots() {
    let temp = TempDir::new().expect("temporary directory");
    let write_back = node_id("write-back");
    let staging = node_id("staging");
    let destination = node_id("destination");
    let staging_root = temp.path().join("staging");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: write_back.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: destination.clone(),
                        journal_root: staging_root.join("journal"),
                        maximum_pending_objects: 8,
                        maximum_pending_bytes: 1_024,
                    },
                ),
                (staging, StoreNodeSpec::Directory { root: staging_root },),
                (
                    destination,
                    StoreNodeSpec::Directory {
                        root: temp.path().join("destination"),
                    },
                ),
            ]),
        }),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::OverlappingAdministrativePath,
            ..
        })
    ));
}
