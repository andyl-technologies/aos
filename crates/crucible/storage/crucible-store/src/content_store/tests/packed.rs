//! Packed content-store behavior tests.

use super::*;

#[test]
fn packed_backend_restarts_repackages_and_keeps_old_reader_inodes_valid() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let first_bytes = vec![0x31; 8 * 1024];
    let second_bytes = vec![0x72; 12 * 1024];
    let first = ContentId::for_bytes(ObjectKind::RamExtent, 1, &first_bytes);
    let second = ContentId::for_bytes(ObjectKind::DiskExtent, 1, &second_bytes);
    put_bytes(&store, first, &first_bytes).expect("first packed put");
    put_bytes(&store, second, &second_bytes).expect("second packed put");

    let pinned_before_repack = store.read(first, None).expect("pinned old pack reader");
    let release_old_reader = Arc::new(Barrier::new(2));
    let old_reader_release = Arc::clone(&release_old_reader);
    let old_reader = thread::spawn(move || {
        old_reader_release.wait();
        pinned_before_repack.read_all(TEST_READ_LIMIT)
    });
    assert_eq!(
        read_bytes(
            &store,
            second,
            Some(ByteRange::new(4_096, 2_048).expect("packed range")),
        )
        .expect("authenticated packed range"),
        vec![0x72; 2_048]
    );
    let before = store.accounting().expect("packed accounting");
    assert_eq!(before.logical_objects(), 2);
    assert_eq!(before.logical_bytes(), 20 * 1024);
    assert_eq!(before.packs(), 2);

    let plan = store.plan_repack().expect("exact-generation repack plan");
    let canonical_plan = plan.canonical_bytes();
    let decoded_plan =
        PackedRepackPlan::from_canonical_bytes(&canonical_plan).expect("canonical repack plan");
    assert_eq!(decoded_plan, plan);
    assert_eq!(plan.before(), before);
    let report = store
        .apply_repack(&decoded_plan)
        .expect("deterministic repack");
    assert_eq!(report.plan(), plan.id());
    assert!(!report.replayed());
    assert_eq!(report.before(), before);
    assert_eq!(report.after().logical_objects(), 2);
    assert_eq!(report.after().packs(), 1);
    assert_eq!(report.removed_packs(), 2);
    release_old_reader.wait();
    assert_eq!(
        old_reader
            .join()
            .expect("old reader thread")
            .expect("old inode remains readable"),
        first_bytes
    );

    let restarted =
        PackedBlobBackend::open("packed", &root, 64 * 1024).expect("restart packed backend");
    let replay = restarted
        .apply_repack(&plan)
        .expect("restart replay of committed plan");
    assert!(replay.replayed());
    assert_eq!(replay.plan(), plan.id());
    assert_eq!(replay.removed_packs(), 0);
    assert_eq!(replay.after(), report.after());
    assert_eq!(
        read_bytes(&restarted, second, None).expect("restart packed read"),
        second_bytes
    );
    assert!(matches!(
        PackedBlobBackend::open("packed", &root, 128 * 1024),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn incomplete_pack_cleanup_authenticates_retained_generation_and_retries_idempotently() {
    let temporary = TempDir::new().expect("packed cleanup fixture root");
    let root = temporary.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let unreferenced = root.join(format!("packs/{}.pack", "00".repeat(32)));
    let staging = root.join("packs/.pack.tmp-999-1");
    fs::write(&unreferenced, b"unindexed complete pack").expect("write unreferenced pack");
    fs::write(&staging, b"abandoned staging pack").expect("write staging pack");

    let report = store
        .cleanup_incomplete_packs()
        .expect("clean incomplete pack material");
    assert_eq!(report.index_generation(), 0);
    assert_eq!(report.removed_unreferenced_packs(), 1);
    assert_eq!(report.removed_staging_packs(), 1);
    assert!(!unreferenced.exists());
    assert!(!staging.exists());

    let repeated_cleanup = store
        .cleanup_incomplete_packs()
        .expect("repeat completed cleanup");
    assert_eq!(
        repeated_cleanup.index_generation(),
        report.index_generation()
    );
    assert_eq!(repeated_cleanup.removed_unreferenced_packs(), 0);
    assert_eq!(repeated_cleanup.removed_staging_packs(), 0);

    let bytes = b"retained pack must authenticate before cleanup";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    put_bytes(&store, id, bytes).expect("seed retained pack");
    let retained_pack = fs::read_dir(root.join("packs"))
        .expect("list retained packs")
        .map(|entry| entry.expect("retained pack entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pack")
        })
        .expect("retained pack path");
    let rejected_staging = root.join("packs/.pack.tmp-999-2");
    fs::write(&rejected_staging, b"must survive rejected cleanup")
        .expect("write rejected staging pack");
    fs::write(&retained_pack, b"corrupt retained pack").expect("corrupt retained pack");

    assert!(store.cleanup_incomplete_packs().is_err());
    assert!(rejected_staging.exists());
}

#[test]
fn packed_initialization_waits_for_in_flight_staging() {
    let temporary = TempDir::new().expect("packed staging fixture root");
    let root = temporary.path().join("packed");
    let writer_store =
        PackedBlobBackend::open("packed", &root, 64 * 1024).expect("writer packed backend");
    let bytes = Arc::<[u8]>::from(&b"blocked packed staging body"[..]);
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    let (opened_sender, opened_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let source = BlobHandle::new(Arc::new(BlockingSource {
        bytes: Arc::clone(&bytes),
        opened: opened_sender,
        release: Mutex::new(Some(release_receiver)),
    }));
    let writer = thread::spawn(move || writer_store.put_if_absent(id, &source));

    opened_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("writer reached packed staging stream");
    assert_eq!(pack_staging_file_count(&root), 1);
    let lifecycle_probe = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".packed-admin/lifecycle.lock"))
        .expect("open lifecycle lock probe");
    let lock_error = rustix::fs::flock(
        &lifecycle_probe,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .expect_err("in-flight staging retains shared lifecycle lock");
    assert_eq!(
        std::io::Error::from_raw_os_error(lock_error.raw_os_error()).kind(),
        std::io::ErrorKind::WouldBlock
    );

    let unrelated = root.join("packs/.operator-note");
    fs::write(&unrelated, b"operator-owned hidden file").expect("write unrelated hidden file");
    let (initialization_started_sender, initialization_started_receiver) = mpsc::channel();
    let (initialized_sender, initialized_receiver) = mpsc::channel();
    let initializer_root = root.clone();
    let initializer = thread::spawn(move || {
        initialization_started_sender
            .send(())
            .expect("signal initialization attempt");
        let backend = PackedBlobBackend::open("packed", initializer_root, 64 * 1024)
            .expect("initialize after staged put");
        initialized_sender
            .send(())
            .expect("signal completed initialization");
        backend
    });

    initialization_started_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("initializer started");
    assert!(matches!(
        initialized_receiver.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(pack_staging_file_count(&root), 1);

    release_sender.send(()).expect("release staged source");
    writer
        .join()
        .expect("join packed writer")
        .expect("complete packed put");
    initialized_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("initializer completed after staged put");
    let restarted = initializer.join().expect("join packed initializer");

    assert_eq!(pack_staging_file_count(&root), 0);
    assert!(unrelated.exists());
    assert_eq!(
        read_bytes(&restarted, id, None).expect("read staged object after initialization"),
        bytes.as_ref()
    );

    drop(restarted);
    let non_regular = root.join("packs/.pack.tmp-1-1");
    fs::create_dir(&non_regular).expect("create non-regular owned staging name");
    let reopened = PackedBlobBackend::open("packed", &root, 64 * 1024)
        .expect("reopen before explicit maintenance cleanup");
    assert!(matches!(
        reopened.cleanup_incomplete_packs(),
        Err(StoreError::InvalidComposition {
            reason: "packed staging path is not a regular file"
        })
    ));
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn pack_index_interruption_recovers_old_generation_and_retries() {
    if std::env::var_os(PACK_INDEX_INTERRUPTION_CHILD_ENVIRONMENT).is_some() {
        run_pack_index_interruption_child();
        panic!("pack-index child returned without reaching the injected interruption");
    }

    let temporary = TempDir::new().expect("pack-index interruption fixture root");
    let root = temporary.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let first_bytes = vec![0x31; 8 * 1024];
    let second_bytes = vec![0x72; 12 * 1024];
    let first = ContentId::for_bytes(ObjectKind::RamExtent, 1, &first_bytes);
    let second = ContentId::for_bytes(ObjectKind::DiskExtent, 1, &second_bytes);
    put_bytes(&store, first, &first_bytes).expect("first packed put");
    put_bytes(&store, second, &second_bytes).expect("second packed put");

    let before = store.accounting().expect("old index accounting");
    let plan = store.plan_repack().expect("interrupted repack plan");
    assert_eq!(before.generation(), 2);
    assert_eq!(before.packs(), 2);
    drop(store);

    let child = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg(PACK_INDEX_INTERRUPTION_TEST_NAME)
        .arg("--nocapture")
        .env(PACK_INDEX_INTERRUPTION_CHILD_ENVIRONMENT, "1")
        .env(PACK_INDEX_INTERRUPTION_ROOT_ENVIRONMENT, &root)
        .env(
            DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
            PACK_INDEX_INTERRUPTION_TRIGGER,
        )
        .output()
        .expect("run pack-index interruption child");
    assert_eq!(
        child.status.code(),
        Some(PACK_INDEX_INTERRUPTION_CHILD_EXIT_CODE),
        "pack-index child did not preserve the expected state:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
    assert_eq!(pack_file_count(&root), 3);
    assert_eq!(pack_staging_file_count(&root), 1);

    let restarted =
        PackedBlobBackend::open("packed", &root, 64 * 1024).expect("restart old generation");
    assert_eq!(pack_file_count(&root), 3);
    assert_eq!(pack_staging_file_count(&root), 1);
    let cleanup = restarted
        .cleanup_incomplete_packs()
        .expect("clean interrupted replacement material");
    assert_eq!(cleanup.index_generation(), before.generation());
    assert_eq!(cleanup.removed_unreferenced_packs(), 1);
    assert_eq!(cleanup.removed_staging_packs(), 1);
    assert_eq!(pack_file_count(&root), 2);
    assert_eq!(pack_staging_file_count(&root), 0);
    assert_eq!(
        restarted.accounting().expect("recovered accounting"),
        before
    );
    assert_eq!(
        read_bytes(&restarted, first, None).expect("first old-generation object"),
        first_bytes
    );
    assert_eq!(
        read_bytes(&restarted, second, None).expect("second old-generation object"),
        second_bytes
    );

    let report = restarted
        .apply_repack(&plan)
        .expect("resume exact interrupted plan");
    assert!(!report.replayed());
    assert_eq!(report.plan(), plan.id());
    assert_eq!(report.before(), before);
    assert_eq!(report.after().generation(), before.generation() + 1);
    assert_eq!(report.after().packs(), 1);
    assert_eq!(pack_file_count(&root), 1);
    assert_eq!(
        read_bytes(&restarted, first, None).expect("first object after resume"),
        first_bytes
    );
    assert_eq!(
        read_bytes(&restarted, second, None).expect("second object after resume"),
        second_bytes
    );
}

#[cfg(feature = "destructive-recovery-faults")]
fn run_pack_index_interruption_child() {
    let root = std::env::var_os(PACK_INDEX_INTERRUPTION_ROOT_ENVIRONMENT)
        .map(PathBuf::from)
        .expect("pack-index fixture root");
    let store = PackedBlobBackend::open("packed", root, 64 * 1024).expect("child packed backend");
    let plan = store.plan_repack().expect("child repack plan");

    store
        .apply_repack(&plan)
        .expect("fault hook must interrupt before repack returns");
}

#[test]
fn packed_inventory_deletes_logical_entries_without_removing_live_pack_bytes() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let first = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"first packed page");
    let second = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"second packed page");
    put_bytes(&store, first, b"first packed page").expect("first packed object");
    put_bytes(&store, second, b"second packed page").expect("second packed object");
    let plan = store.plan_repack().expect("coalescing plan");
    store.apply_repack(&plan).expect("coalesce physical pack");
    assert_eq!(pack_file_count(&root), 1);

    let mut fence = store
        .acquire_inventory_fence()
        .expect("packed inventory fence");
    let before = fence
        .visit_inventory(&mut |_record| Ok(()))
        .expect("packed inventory");
    assert_eq!(before.objects(), 2);
    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete first logical candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(pack_file_count(&root), 1);
    assert_eq!(
        fence
            .delete_candidate(second)
            .expect("delete last logical candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(pack_file_count(&root), 0);
    drop(fence);
    assert!(!store.contains(first).expect("first logical absence"));
    assert!(!store.contains(second).expect("second logical absence"));
}

#[test]
fn packed_repack_rejects_stale_or_corrupt_plans_and_preserves_empty_objects() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let empty = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"");
    put_bytes(&store, empty, b"").expect("empty packed object");
    assert_eq!(
        read_bytes(&store, empty, None).expect("read empty object"),
        b""
    );

    let stale = store.plan_repack().expect("stale plan basis");
    let second_bytes = b"intervening logical mutation";
    let second = ContentId::for_bytes(ObjectKind::DiskExtent, 1, second_bytes);
    put_bytes(&store, second, second_bytes).expect("intervening packed put");
    assert!(matches!(
        store.apply_repack(&stale),
        Err(StoreError::Incompatible)
    ));
    assert!(store.contains(empty).expect("empty object retained"));
    assert!(store.contains(second).expect("second object retained"));

    let current = store.plan_repack().expect("current plan");
    let mut corrupt = current.canonical_bytes();
    *corrupt.last_mut().expect("plan checksum byte") ^= 0x01;
    assert!(matches!(
        PackedRepackPlan::from_canonical_bytes(&corrupt),
        Err(StoreError::Incompatible)
    ));
    let report = store.apply_repack(&current).expect("current plan apply");
    assert_eq!(report.after().logical_objects(), 2);
    assert_eq!(report.after().logical_bytes(), second_bytes.len() as u64);
    assert_eq!(
        read_bytes(&store, empty, None).expect("empty after repack"),
        b""
    );
}

#[test]
fn packed_backend_rejects_corruption_and_cleans_unindexed_complete_packs() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("packed");
    let store = PackedBlobBackend::open("packed", &root, 64 * 1024).expect("packed backend");
    let bytes = b"authenticated packed body";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    put_bytes(&store, id, bytes).expect("packed put");
    let pack = only_pack_path(&root);
    let mut corrupt = fs::read(&pack).expect("pack bytes");
    *corrupt.last_mut().expect("pack body byte") ^= 0x80;
    fs::write(&pack, corrupt).expect("corrupt pack body");
    assert!(matches!(
        store
            .read(id, Some(ByteRange::new(0, 1).expect("corrupt range")))
            .and_then(|handle| handle.read_all(TEST_READ_LIMIT)),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(matches!(
        put_bytes(&store, id, bytes),
        Err(StoreError::Corrupt { .. })
    ));

    let second_root = temp.path().join("recovery");
    let recovery =
        PackedBlobBackend::open("recovery", &second_root, 64 * 1024).expect("recovery backend");
    put_bytes(&recovery, id, bytes).expect("recovery packed put");
    let referenced = only_pack_path(&second_root);
    let orphan = second_root
        .join("packs")
        .join(format!("{}{}", "0".repeat(64), ".pack"));
    fs::copy(&referenced, &orphan).expect("simulate pack-before-index interruption");
    assert_eq!(pack_file_count(&second_root), 2);
    let reopened =
        PackedBlobBackend::open("recovery", &second_root, 64 * 1024).expect("recover orphan pack");
    assert_eq!(pack_file_count(&second_root), 2);
    let cleanup = reopened
        .cleanup_incomplete_packs()
        .expect("remove unindexed complete pack");
    assert_eq!(cleanup.removed_unreferenced_packs(), 1);
    assert_eq!(cleanup.removed_staging_packs(), 0);
    assert_eq!(pack_file_count(&second_root), 1);
    assert_eq!(
        read_bytes(&reopened, id, None).expect("recovered logical object"),
        bytes
    );

    fs::write(second_root.join(".packed-admin/index-v1"), b"truncated")
        .expect("truncate packed index");
    assert!(matches!(
        PackedBlobBackend::open("recovery", &second_root, 64 * 1024),
        Err(StoreError::Incompatible)
    ));

    let missing_root = temp.path().join("missing-pack");
    let missing =
        PackedBlobBackend::open("missing", &missing_root, 64 * 1024).expect("missing-pack backend");
    put_bytes(&missing, id, bytes).expect("missing-pack put");
    fs::remove_file(only_pack_path(&missing_root)).expect("remove referenced pack");
    assert!(matches!(
        PackedBlobBackend::open("missing", &missing_root, 64 * 1024),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn packed_store_graph_is_admitted_and_requires_an_isolated_persistent_root() {
    let temp = TempDir::new().expect("temporary directory");
    let packed = node_id("packed");
    let (graph, admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: packed.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
        nodes: BTreeMap::from([(
            packed.clone(),
            StoreNodeSpec::Packed {
                root: temp.path().join("packed"),
                target_pack_bytes: 64 * 1024,
            },
        )]),
    })
    .expect("packed store graph");
    assert_eq!(graph.describe()[0].kind, StoreNodeKind::Packed);
    let physical = admin.physical();
    assert_eq!(physical.len(), 1);
    assert_eq!(physical[0].node(), &packed);
    let repack = admin.packed_repack();
    assert_eq!(repack.len(), 1);
    assert_eq!(repack[0].node(), &packed);
    let repack_plan = repack[0].plan().expect("packed graph repack plan");
    let repack_report = repack[0]
        .apply(&repack_plan)
        .expect("packed graph repack apply");
    assert_eq!(repack_report.plan(), repack_plan.id());
    assert_eq!(repack_report.after().generation(), 1);
    let mut fence = physical[0]
        .admin()
        .acquire_inventory_fence()
        .expect("packed graph maintenance fence");
    let empty = fence
        .visit_inventory(&mut |_record| Ok(()))
        .expect("empty packed graph inventory");
    assert_eq!(empty.backend(), packed.as_str());
    assert_eq!(empty.objects(), 0);
    drop(fence);
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"graph packed page");
    put_bytes(&graph, id, b"graph packed page").expect("graph packed put");

    let mirror = node_id("mirror");
    let directory = node_id("directory");
    let shared = temp.path().join("overlap");
    assert!(matches!(
        StoreGraph::build(StoreGraphConfig {
            root: mirror.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::RamExtent]),
            nodes: BTreeMap::from([
                (
                    mirror,
                    StoreNodeSpec::WriteThrough {
                        children: vec![packed.clone(), directory.clone()],
                    },
                ),
                (
                    packed,
                    StoreNodeSpec::Packed {
                        root: shared.clone(),
                        target_pack_bytes: 64 * 1024,
                    },
                ),
                (
                    directory,
                    StoreNodeSpec::Directory {
                        root: shared.join("loose"),
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
