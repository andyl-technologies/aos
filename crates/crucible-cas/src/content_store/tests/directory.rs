//! Persistent directory backend conformance and restart tests.

use super::*;

#[test]
fn compressed_directory_streams_plaintext_identity_ranges_and_inventory_across_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed");
    let store = CompressedDirectoryBlobBackend::new("compressed", &root, 4 * 1024 * 1024)
        .expect("compressed directory");
    let bytes = vec![0x5a; 2 * 1024 * 1024];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);

    let receipt = put_bytes(&store, id, &bytes).expect("compressed put");
    assert!(receipt.is_durable());
    assert_eq!(receipt.id, id);
    let physical = object_path(&root, id);
    assert!(
        fs::metadata(&physical)
            .expect("compressed object metadata")
            .len()
            < bytes.len() as u64 / 8
    );
    assert_eq!(
        put_bytes(&store, id, &bytes).expect("idempotent compressed put"),
        receipt
    );

    let reopened = CompressedDirectoryBlobBackend::new("compressed", &root, 4 * 1024 * 1024)
        .expect("reopened compressed directory");
    assert_eq!(
        read_bytes(
            &reopened,
            id,
            Some(ByteRange::new(1_048_571, 17).expect("valid compressed range")),
        )
        .expect("authenticated compressed range"),
        vec![0x5a; 17]
    );
    assert_eq!(
        reopened
            .read(id, None)
            .expect("restart handle")
            .read_all(4 * 1024 * 1024)
            .expect("restart read"),
        bytes
    );
    let concurrent_handle = reopened.read(id, None).expect("concurrent restart handle");
    let first_handle = concurrent_handle.clone();
    let first_reader = thread::spawn(move || first_handle.read_all(4 * 1024 * 1024));
    let second_reader = thread::spawn(move || concurrent_handle.read_all(4 * 1024 * 1024));
    assert_eq!(
        first_reader
            .join()
            .expect("join first compressed reader")
            .expect("first compressed reader"),
        bytes
    );
    assert_eq!(
        second_reader
            .join()
            .expect("join second compressed reader")
            .expect("second compressed reader"),
        bytes
    );

    let mut fence = reopened
        .acquire_inventory_fence()
        .expect("compressed inventory fence");
    let mut records = Vec::new();
    let summary = fence
        .visit_inventory(&mut |record| {
            records.push(record);
            Ok(())
        })
        .expect("compressed inventory");
    assert_eq!(summary.objects(), 1);
    assert_eq!(summary.logical_bytes(), bytes.len() as u64);
    assert_eq!(
        records,
        vec![BlobInventoryRecord::new(id, bytes.len() as u64)]
    );
    assert_eq!(
        fence
            .delete_candidate(id)
            .expect("planned compressed delete"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(id)
            .expect("repeated compressed delete"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    drop(fence);
    assert!(!reopened.contains(id).expect("deleted compressed object"));
}

#[test]
fn compressed_directory_rejects_oversized_sources_and_corrupt_physical_records() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed");
    let store =
        CompressedDirectoryBlobBackend::new("compressed", &root, 64).expect("compressed directory");
    let oversized_bytes = Arc::<[u8]>::from(vec![0x44; 65]);
    let oversized_id = ContentId::for_bytes(ObjectKind::Trace, 1, &oversized_bytes);
    let opens = Arc::new(AtomicUsize::new(0));
    let oversized = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::clone(&oversized_bytes),
        opens: Arc::clone(&opens),
        bytes_read: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(matches!(
        store.put_if_absent(oversized_id, &oversized),
        Err(StoreError::Quota)
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);

    let wrong_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"expected");
    assert!(matches!(
        put_bytes(&store, wrong_id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    let wrong_path = object_path(&root, wrong_id);
    assert!(!wrong_path.exists());
    assert!(
        fs::read_dir(wrong_path.parent().expect("wrong-ID parent"))
            .expect("read wrong-ID parent")
            .all(|entry| !entry
                .expect("wrong-ID directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-"))
    );

    let bytes = vec![0x31; 64];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    put_bytes(&store, id, &bytes).expect("bounded compressed put");
    let physical = object_path(&root, id);
    let physical_length = fs::metadata(&physical)
        .expect("compressed physical metadata")
        .len();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&physical)
        .expect("open compressed physical record");
    file.set_len(physical_length - 1)
        .expect("truncate compressed physical record");
    assert!(matches!(
        store.read(id, None),
        Err(StoreError::Corrupt { .. })
    ));

    let symlink_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"symlink");
    let symlink_path = object_path(&root, symlink_id);
    fs::create_dir_all(symlink_path.parent().expect("symlink object parent"))
        .expect("create symlink parent");
    std::os::unix::fs::symlink(&physical, &symlink_path).expect("create compressed symlink");
    assert!(matches!(
        store.read(symlink_id, None),
        Err(StoreError::Io { .. })
    ));

    let oversized_frame_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"x");
    let oversized_frame_path = object_path(&root, oversized_frame_id);
    fs::create_dir_all(
        oversized_frame_path
            .parent()
            .expect("oversized frame parent"),
    )
    .expect("create oversized frame parent");
    let oversized_frame_length = zstd::zstd_safe::compress_bound(1) + 1;
    let mut oversized_frame_record = Vec::with_capacity(24 + oversized_frame_length);
    oversized_frame_record.extend_from_slice(b"CRUCZ001");
    oversized_frame_record.extend_from_slice(&1_u64.to_be_bytes());
    oversized_frame_record.extend_from_slice(&(oversized_frame_length as u64).to_be_bytes());
    oversized_frame_record.resize(24 + oversized_frame_length, 0);
    fs::write(&oversized_frame_path, oversized_frame_record).expect("write oversized frame");
    assert!(matches!(
        store.read(oversized_frame_id, None),
        Err(StoreError::Corrupt { .. })
    ));

    let range_root = temp.path().join("compressed-range");
    let range_store =
        CompressedDirectoryBlobBackend::new("compressed-range", &range_root, 128 * 1024)
            .expect("compressed range directory");
    let range_bytes = (0_u32..64 * 1024)
        .map(|value| value.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) as u8)
        .collect::<Vec<_>>();
    let range_id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &range_bytes);
    put_bytes(&range_store, range_id, &range_bytes).expect("compressed range put");
    let range_path = object_path(&range_root, range_id);
    let mut changed_plaintext = range_bytes.clone();
    *changed_plaintext.last_mut().expect("plaintext tail") ^= 0x80;
    let changed_frame = zstd::stream::encode_all(Cursor::new(&changed_plaintext), 3)
        .expect("encode changed compressed frame");
    let mut changed_record = Vec::with_capacity(24 + changed_frame.len());
    changed_record.extend_from_slice(b"CRUCZ001");
    changed_record.extend_from_slice(&(changed_plaintext.len() as u64).to_be_bytes());
    changed_record.extend_from_slice(&(changed_frame.len() as u64).to_be_bytes());
    changed_record.extend_from_slice(&changed_frame);
    fs::write(&range_path, changed_record).expect("replace compressed frame plaintext");
    let range = range_store
        .read(
            range_id,
            Some(ByteRange::new(0, 16).expect("valid leading range")),
        )
        .expect("open compressed range with changed plaintext");
    assert!(matches!(
        range.read_all(1024),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn encrypted_directory_authenticates_ranges_and_inventory_across_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("encrypted");
    let key_id = StoreEncryptionKeyId::new("campaign-key-7").expect("key ID");
    let key_bytes = [0xa5; 32];
    let store = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        4 * 1024 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new(key_bytes).expect("key"),
    )
    .expect("encrypted directory");

    let mut expected = BTreeMap::new();
    let mut largest = None;
    for length in [0_usize, 65_535, 65_536, 65_537, 2 * 65_536 + 17] {
        let bytes = (0..length)
            .map(|index| (index as u32).wrapping_mul(17).wrapping_add(91) as u8)
            .collect::<Vec<_>>();
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let receipt = put_bytes(&store, id, &bytes).expect("encrypted put");
        assert!(receipt.is_durable());
        assert_eq!(receipt.id, id);
        assert_eq!(
            put_bytes(&store, id, &bytes).expect("idempotent encrypted put"),
            receipt
        );
        expected.insert(id, bytes);
        largest = Some(id);
    }

    let largest = largest.expect("largest object ID");
    let largest_bytes = &expected[&largest];
    let physical = fs::read(object_path(&root, largest)).expect("encrypted physical record");
    assert!(
        !physical
            .windows(key_bytes.len())
            .any(|window| window == key_bytes)
    );
    let key_state = fs::read(root.join(".inventory-admin/encryption-key-v1"))
        .expect("encrypted key-generation state");
    assert!(
        !key_state
            .windows(key_bytes.len())
            .any(|window| window == key_bytes)
    );
    assert!(
        !physical
            .windows(largest_bytes.len())
            .any(|window| window == largest_bytes)
    );

    let reopened = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        4 * 1024 * 1024,
        key_id,
        StoreEncryptionKey::new(key_bytes).expect("restart key"),
    )
    .expect("reopened encrypted directory");
    for (id, bytes) in &expected {
        assert_eq!(
            read_bytes(&reopened, *id, None).expect("restart encrypted read"),
            *bytes
        );
    }
    assert_eq!(
        read_bytes(
            &reopened,
            largest,
            Some(ByteRange::new(65_530, 19).expect("cross-chunk range")),
        )
        .expect("authenticated encrypted range"),
        largest_bytes[65_530..65_549]
    );

    let mut fence = reopened
        .acquire_inventory_fence()
        .expect("encrypted inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("encrypted inventory");
    assert_eq!(summary.objects(), expected.len() as u64);
    assert_eq!(
        summary.logical_bytes(),
        expected.values().map(|bytes| bytes.len() as u64).sum()
    );
    assert_eq!(
        fence
            .delete_candidate(largest)
            .expect("planned encrypted delete"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence
            .delete_candidate(largest)
            .expect("repeated encrypted delete"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
}

#[test]
fn compressed_encrypted_directory_streams_round_trip_and_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed-encrypted");
    let key_id = StoreEncryptionKeyId::new("compressed-key-1").expect("key ID");
    let key_bytes = [0x6d; 32];
    let store = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted",
        &root,
        4 * 1024 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new(key_bytes).expect("key"),
    )
    .expect("compressed encrypted directory");

    let mut expected = BTreeMap::new();
    for length in [0_usize, 1, 65_535, 65_536, 65_537, 256 * 1024] {
        let bytes = (0..length)
            .map(|index| ((index / 257) as u32).wrapping_mul(13) as u8)
            .collect::<Vec<_>>();
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
        let receipt = put_bytes(&store, id, &bytes).expect("compressed encrypted put");
        assert!(receipt.is_durable());
        assert_eq!(receipt.id, id);
        assert_eq!(
            put_bytes(&store, id, &bytes).expect("idempotent compressed encrypted put"),
            receipt
        );
        let physical = fs::read(object_path(&root, id)).expect("physical record");
        assert_eq!(&physical[..8], b"CRUCC001");
        if bytes.len() >= 64 {
            assert!(!physical.windows(bytes.len()).any(|window| window == bytes));
        }
        expected.insert(id, bytes);
    }

    let largest = *expected
        .iter()
        .max_by_key(|(_, bytes)| bytes.len())
        .map(|(id, _)| id)
        .expect("largest ID");
    let largest_bytes = &expected[&largest];
    let alternate_root = temp.path().join("compressed-encrypted-alternate-key-id");
    let alternate = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted-alternate-key-id",
        &alternate_root,
        4 * 1024 * 1024,
        StoreEncryptionKeyId::new("compressed-key-1b").expect("alternate key ID"),
        StoreEncryptionKey::new(key_bytes).expect("reused master key"),
    )
    .expect("alternate compressed encrypted directory");
    put_bytes(&alternate, largest, largest_bytes).expect("alternate-key-ID put");
    let physical = fs::read(object_path(&root, largest)).expect("primary physical record");
    let alternate_physical =
        fs::read(object_path(&alternate_root, largest)).expect("alternate physical record");
    assert_ne!(physical[92..108], alternate_physical[92..108]);

    let reopened = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted",
        &root,
        4 * 1024 * 1024,
        key_id,
        StoreEncryptionKey::new(key_bytes).expect("restart key"),
    )
    .expect("reopened compressed encrypted directory");
    for (id, bytes) in &expected {
        assert_eq!(
            read_bytes(&reopened, *id, None).expect("restart read"),
            *bytes
        );
    }
    if largest_bytes.len() >= 65_549 {
        assert_eq!(
            read_bytes(
                &reopened,
                largest,
                Some(ByteRange::new(65_530, 19).expect("cross-chunk range")),
            )
            .expect("authenticated compressed encrypted range"),
            largest_bytes[65_530..65_549]
        );
    }

    let mut fence = reopened
        .acquire_inventory_fence()
        .expect("compressed encrypted inventory fence");
    let summary = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("compressed encrypted inventory");
    assert_eq!(summary.objects(), expected.len() as u64);
    assert_eq!(
        summary.logical_bytes(),
        expected.values().map(|bytes| bytes.len() as u64).sum()
    );
}

#[test]
fn compressed_encrypted_directory_rejects_format_substitution_and_corruption() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("compressed-encrypted");
    let key_id = StoreEncryptionKeyId::new("compressed-key-2").expect("key ID");
    let key_bytes = [0x7e; 32];
    let store = EncryptedDirectoryBlobBackend::new_compressed(
        "compressed-encrypted",
        &root,
        512 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new(key_bytes).expect("key"),
    )
    .expect("compressed encrypted directory");
    let bytes = vec![0x41; 192 * 1024];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    put_bytes(&store, id, &bytes).expect("compressed encrypted put");

    let plain = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        512 * 1024,
        key_id,
        StoreEncryptionKey::new(key_bytes).expect("same key"),
    )
    .expect("plain encrypted directory view");
    assert!(matches!(
        plain.read(id, None),
        Err(StoreError::Corrupt { .. })
    ));

    let physical_path = object_path(&root, id);
    let mut physical = fs::read(&physical_path).expect("physical record");
    let original = physical.clone();
    physical[8..16].copy_from_slice(&1_u64.to_be_bytes());
    fs::write(&physical_path, &physical).expect("forge logical length");
    let mut fence = store
        .acquire_inventory_fence()
        .expect("inventory fence with forged header");
    assert!(matches!(
        fence.visit_inventory(&mut |_| Ok(())),
        Err(StoreError::Corrupt { .. })
    ));
    drop(fence);

    physical = original;
    *physical.last_mut().expect("ciphertext tail") ^= 0x80;
    fs::write(&physical_path, physical).expect("corrupt ciphertext tail");
    let leading = store
        .read(id, Some(ByteRange::new(0, 16).expect("leading range")))
        .expect("open corrupted range");
    assert!(matches!(
        leading.read_all(1024),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn encrypted_directory_fails_closed_on_limits_wrong_keys_and_corruption() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("encrypted");
    for invalid in ["", "bad/key", "bad:key", "space key"] {
        assert!(matches!(
            StoreEncryptionKeyId::new(invalid),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    assert!(matches!(
        StoreEncryptionKey::new([0; 32]),
        Err(StoreError::InvalidComposition { .. })
    ));
    let key_id = StoreEncryptionKeyId::new("campaign-key-8").expect("key ID");
    let store = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        128 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new([0x18; 32]).expect("key"),
    )
    .expect("encrypted directory");

    let oversized_bytes = Arc::<[u8]>::from(vec![0x44; 128 * 1024 + 1]);
    let oversized_id = ContentId::for_bytes(ObjectKind::Trace, 1, &oversized_bytes);
    let opens = Arc::new(AtomicUsize::new(0));
    let oversized = BlobHandle::new(Arc::new(CountingSource {
        bytes: Arc::clone(&oversized_bytes),
        opens: Arc::clone(&opens),
        bytes_read: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(matches!(
        store.put_if_absent(oversized_id, &oversized),
        Err(StoreError::Quota)
    ));
    assert_eq!(opens.load(Ordering::SeqCst), 0);

    let wrong_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"expected");
    assert!(matches!(
        put_bytes(&store, wrong_id, b"different"),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(!object_path(&root, wrong_id).exists());

    let bytes = (0_u32..96 * 1024)
        .map(|value| value.wrapping_mul(1_103_515_245).wrapping_add(12_345) as u8)
        .collect::<Vec<_>>();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    put_bytes(&store, id, &bytes).expect("encrypted put");

    let wrong_key = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        128 * 1024,
        key_id.clone(),
        StoreEncryptionKey::new([0x19; 32]).expect("wrong key"),
    )
    .expect("wrong-key store");
    assert!(matches!(
        read_bytes(&wrong_key, id, None),
        Err(StoreError::Unauthorized)
    ));
    let wrong_key_bytes = b"wrong-key-new-object";
    let wrong_key_new_id = ContentId::for_bytes(ObjectKind::Trace, 1, wrong_key_bytes);
    assert!(matches!(
        put_bytes(&wrong_key, wrong_key_new_id, wrong_key_bytes),
        Err(StoreError::Unauthorized)
    ));
    assert!(!object_path(&root, wrong_key_new_id).exists());
    let wrong_key_id = EncryptedDirectoryBlobBackend::new(
        "encrypted",
        &root,
        128 * 1024,
        StoreEncryptionKeyId::new("campaign-key-9").expect("wrong key ID"),
        StoreEncryptionKey::new([0x18; 32]).expect("right key"),
    )
    .expect("wrong-key-ID store");
    assert!(matches!(
        wrong_key_id.read(id, None),
        Err(StoreError::InvalidComposition { .. })
    ));

    let physical_path = object_path(&root, id);
    let mut physical = fs::read(&physical_path).expect("encrypted physical record");
    *physical.last_mut().expect("ciphertext tail") ^= 0x80;
    fs::write(&physical_path, &physical).expect("corrupt ciphertext tail");
    let leading = store
        .read(id, Some(ByteRange::new(0, 16).expect("leading range")))
        .expect("open corrupted encrypted range");
    assert!(matches!(
        leading.read_all(1024),
        Err(StoreError::Corrupt { .. })
    ));

    let symlink_id = ContentId::for_bytes(ObjectKind::Trace, 1, b"symlink");
    let symlink_path = object_path(&root, symlink_id);
    fs::create_dir_all(symlink_path.parent().expect("symlink parent"))
        .expect("create symlink parent");
    std::os::unix::fs::symlink(&physical_path, &symlink_path).expect("create encrypted symlink");
    assert!(matches!(
        store.read(symlink_id, None),
        Err(StoreError::Io { .. })
    ));

    let key_state_path = root.join(".inventory-admin/encryption-key-v1");
    let mut key_state = fs::read(&key_state_path).expect("read key state");
    *key_state.last_mut().expect("key-state checksum") ^= 0x01;
    fs::write(&key_state_path, key_state).expect("corrupt key state");
    assert!(matches!(
        store.read(id, None),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn encrypted_directory_serializes_first_key_generation_across_instances() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("encrypted");
    let key_id = StoreEncryptionKeyId::new("campaign-key-race").expect("key ID");
    let first = Arc::new(
        EncryptedDirectoryBlobBackend::new(
            "first",
            &root,
            1024,
            key_id.clone(),
            StoreEncryptionKey::new([0x31; 32]).expect("first key"),
        )
        .expect("first encrypted directory"),
    );
    let second = Arc::new(
        EncryptedDirectoryBlobBackend::new(
            "second",
            &root,
            1024,
            key_id,
            StoreEncryptionKey::new([0x32; 32]).expect("second key"),
        )
        .expect("second encrypted directory"),
    );
    let first_bytes = b"first-generation-object";
    let second_bytes = b"second-generation-object";
    let first_id = ContentId::for_bytes(ObjectKind::Trace, 1, first_bytes);
    let second_id = ContentId::for_bytes(ObjectKind::Trace, 1, second_bytes);
    let barrier = Arc::new(Barrier::new(3));

    let first_worker = {
        let store = Arc::clone(&first);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            put_bytes(store.as_ref(), first_id, first_bytes)
        })
    };
    let second_worker = {
        let store = Arc::clone(&second);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            put_bytes(store.as_ref(), second_id, second_bytes)
        })
    };
    barrier.wait();
    let first_result = first_worker.join().expect("join first key writer");
    let second_result = second_worker.join().expect("join second key writer");

    match (&first_result, &second_result) {
        (Ok(_), Err(StoreError::Unauthorized)) => {
            assert_eq!(
                read_bytes(first.as_ref(), first_id, None).expect("first read"),
                first_bytes
            );
            assert!(!object_path(&root, second_id).exists());
        }
        (Err(StoreError::Unauthorized), Ok(_)) => {
            assert_eq!(
                read_bytes(second.as_ref(), second_id, None).expect("second read"),
                second_bytes
            );
            assert!(!object_path(&root, first_id).exists());
        }
        results => panic!("exactly one key generation must win: {results:?}"),
    }
}

#[test]
fn directory_ref_inventory_is_persistent_fenced_and_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("authority");
    let refs = Arc::new(DirectoryRefBackend::new(&root));
    let first_name = RefName::new("campaigns/first").expect("first ref name");
    let staging_prefix_name =
        RefName::new(".ref-staging-user").expect("valid staging-prefix ref name");
    let third_name = RefName::new("campaigns/third").expect("third ref name");
    let first = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"first");
    let second = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"second");
    let third = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"third");
    refs.compare_exchange(&first_name, None, first)
        .expect("create first directory ref");
    refs.compare_exchange(&staging_prefix_name, None, second)
        .expect("create staging-prefix directory ref");

    let mut fence = refs
        .acquire_ref_inventory_fence()
        .expect("acquire directory ref fence");
    let mut inventory = BTreeMap::new();
    let before = fence
        .visit_refs(&mut |record| {
            inventory.insert(record.name().clone(), record.target());
            Ok(())
        })
        .expect("visit directory refs");
    assert_eq!(before.refs(), 2);
    assert_eq!(
        inventory,
        BTreeMap::from([(first_name.clone(), first), (staging_prefix_name, second),])
    );

    let writer_refs = Arc::clone(&refs);
    let (writer_started, writer_started_receiver) = mpsc::channel();
    let (writer_finished, writer_finished_receiver) = mpsc::channel();
    let writer = thread::spawn(move || {
        writer_started.send(()).expect("signal ref writer start");
        let result = writer_refs.compare_exchange(&third_name, None, third);
        writer_finished
            .send(result)
            .expect("report ref writer completion");
    });
    writer_started_receiver
        .recv_timeout(FILESYSTEM_FENCE_COMPLETION_TIMEOUT)
        .expect("ref writer reached fenced operation");
    assert!(matches!(
        writer_finished_receiver.recv_timeout(Duration::from_millis(10)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(fence);
    writer_finished_receiver
        .recv_timeout(FILESYSTEM_FENCE_COMPLETION_TIMEOUT)
        .expect("ref writer completed after fence release")
        .expect("create fenced directory ref");
    writer.join().expect("join directory ref writer");

    refs.compare_exchange(&first_name, Some(first), second)
        .expect("advance directory ref away from original");
    refs.compare_exchange(&first_name, Some(second), first)
        .expect("restore directory ref after ABA");
    let reopened = DirectoryRefBackend::new(&root);
    let mut reopened_fence = reopened
        .acquire_ref_inventory_fence()
        .expect("reopen directory ref fence");
    let reopened_summary = reopened_fence
        .visit_refs(&mut |_| Ok(()))
        .expect("visit reopened refs");
    assert_ne!(reopened_summary.generation(), before.generation());
    assert_eq!(reopened_summary.refs(), 3);
    drop(reopened_fence);

    fs::write(root.join("refs/campaigns/first"), [0_u8; 257]).expect("inject oversized ref record");
    let mut malformed_fence = reopened
        .acquire_ref_inventory_fence()
        .expect("acquire malformed directory ref fence");
    assert!(matches!(
        malformed_fence.visit_refs(&mut |_| Ok(())),
        Err(StoreError::InvalidId)
    ));
    drop(malformed_fence);

    fs::write(root.join(".ref-admin/state-v1"), [0_u8; 257])
        .expect("inject oversized ref inventory state");
    assert!(matches!(
        reopened.acquire_ref_inventory_fence(),
        Err(StoreError::InvalidComposition {
            reason: "directory ref inventory state exceeds its byte limit"
        })
    ));
}

#[test]
fn directory_ref_inventory_waits_for_cross_instance_publication() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("authority");
    let publisher = DirectoryRefBackend::new(&root);
    let publication = publisher
        .acquire_publication_guard()
        .expect("acquire directory publication guard");
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let inventor = DirectoryRefBackend::new(root);
        started_tx.send(()).expect("signal inventory attempt");
        let _fence = inventor
            .acquire_ref_inventory_fence()
            .expect("acquire directory inventory fence");
        acquired_tx.send(()).expect("signal acquired inventory");
    });

    started_rx
        .recv_timeout(FILESYSTEM_FENCE_COMPLETION_TIMEOUT)
        .expect("inventory worker started");
    assert!(matches!(
        acquired_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    drop(publication);
    acquired_rx
        .recv_timeout(FILESYSTEM_FENCE_COMPLETION_TIMEOUT)
        .expect("inventory acquired after publication completed");
    worker.join().expect("join directory inventory worker");
}

#[test]
fn directory_exact_replay_does_not_advance_physical_inventory_generation() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("blobs");
    let blobs = DirectoryBlobBackend::new("directory-replay", &root);
    let bytes = b"durable campaign metadata";
    let id = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, bytes);

    put_bytes(&blobs, id, bytes).expect("put durable object");
    let inventory_state = root.join(".inventory-admin/state-v1");
    let before = fs::read(&inventory_state).expect("initial inventory state");
    put_bytes(&blobs, id, bytes).expect("replay exact durable object");
    let after_replay = fs::read(&inventory_state).expect("replayed inventory state");
    assert_eq!(after_replay, before);

    // A fresh owner authenticates the object and may replay it after the
    // earlier owner exits without any additional inventory transition.
    let reopened = DirectoryBlobBackend::new("directory-replay", &root);
    assert!(reopened.contains(id).expect("cold contains"));
    assert_eq!(read_bytes(&reopened, id, None).expect("cold read"), bytes);
    put_bytes(&reopened, id, bytes).expect("retry after cold reopen");
    assert_eq!(
        fs::read(&inventory_state).expect("retried inventory state"),
        before
    );

    let other_bytes = b"second durable campaign object";
    let other_id = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, other_bytes);
    put_bytes(&reopened, other_id, other_bytes).expect("put new durable object");
    let after_new_object = fs::read(&inventory_state).expect("advanced inventory state");
    assert_ne!(after_new_object, before);

    fs::write(object_path(&root, id), b"corrupt").expect("inject corrupt existing object");
    assert!(matches!(
        put_bytes(&reopened, id, bytes),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == id
    ));
    assert_eq!(
        fs::read(&inventory_state).expect("inventory after rejected replay"),
        after_new_object
    );
}

#[test]
fn directory_replay_completes_interrupted_object_publication() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("blobs");
    let blobs = DirectoryBlobBackend::new("directory-interrupted", &root);
    let bytes = b"published before directory sync";
    let id = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, bytes);

    // Model a writer that persisted its inventory generation and linked the
    // complete staged object, then exited before syncing the containing dir.
    let lock = blobs.acquire_inventory_lock().expect("inventory lock");
    let mut state = blobs
        .load_or_create_inventory_state()
        .expect("initial inventory state");
    blobs
        .advance_inventory_state(&mut state)
        .expect("persist publication generation");
    let path = object_path(&root, id);
    let parent = path.parent().expect("object directory");
    fs::create_dir_all(parent).expect("create object directory");
    let staging = parent.join(".interrupted-staging");
    fs::write(&staging, bytes).expect("write staged bytes");
    fs::hard_link(&staging, &path).expect("publish staged object");
    fs::remove_file(&staging).expect("remove staging name");
    drop(lock);

    let inventory_state = root.join(".inventory-admin/state-v1");
    let before = fs::read(&inventory_state).expect("precommitted inventory state");
    let reopened = DirectoryBlobBackend::new("directory-interrupted", &root);
    put_bytes(&reopened, id, bytes).expect("retry interrupted publication");
    assert_eq!(
        fs::read(&inventory_state).expect("inventory after retry"),
        before
    );
    assert!(reopened.contains(id).expect("cold contains after retry"));
    assert_eq!(read_bytes(&reopened, id, None).expect("cold read"), bytes);
}

#[test]
fn directory_administration_is_persistent_fenced_and_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("blobs");
    let blobs = Arc::new(DirectoryBlobBackend::new("directory-admin", &root));
    let first_bytes = b"first durable object";
    let second_bytes = b"second durable object";
    let first = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, first_bytes);
    let second = ContentId::for_bytes(ObjectKind::Observation, 1, second_bytes);
    put_bytes(blobs.as_ref(), first, first_bytes).expect("put first object");
    put_bytes(blobs.as_ref(), second, second_bytes).expect("put second object");

    let mut fence = blobs
        .acquire_inventory_fence()
        .expect("acquire directory inventory fence");
    let mut records = BTreeSet::new();
    let before = fence
        .visit_inventory(&mut |record| {
            records.insert(record.id());
            Ok(())
        })
        .expect("visit directory inventory");
    assert_eq!(before.backend(), "directory-admin");
    assert_eq!(before.objects(), 2);
    assert_eq!(records, BTreeSet::from([first, second]));

    let writer_store = Arc::clone(&blobs);
    let (writer_started, writer_started_receiver) = mpsc::channel();
    let (writer_completed, writer_completed_receiver) = mpsc::channel();
    let third_bytes = b"third durable object";
    let third = ContentId::for_bytes(ObjectKind::CampaignFact, 1, third_bytes);
    let writer = thread::spawn(move || {
        writer_started.send(()).expect("signal blob writer start");
        let result = put_bytes(writer_store.as_ref(), third, third_bytes);
        writer_completed
            .send(result)
            .expect("report blob writer completion");
    });
    writer_started_receiver
        .recv_timeout(FILESYSTEM_FENCE_COMPLETION_TIMEOUT)
        .expect("blob writer reached fenced operation");
    assert!(matches!(
        writer_completed_receiver.recv_timeout(Duration::from_millis(10)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    assert_eq!(
        fence
            .delete_candidate(first)
            .expect("delete durable candidate"),
        PlannedDeleteDisposition::Deleted
    );
    let after_delete = fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("visit after deletion");
    assert_ne!(after_delete.generation(), before.generation());
    drop(fence);
    writer_completed_receiver
        .recv_timeout(FILESYSTEM_FENCE_COMPLETION_TIMEOUT)
        .expect("blob writer completed after fence release")
        .expect("fenced writer put");
    writer.join().expect("join fenced writer");
    put_bytes(blobs.as_ref(), first, first_bytes).expect("reinsert deleted durable object");

    let reopened = DirectoryBlobBackend::new("directory-admin", &root);
    let mut reopened_fence = reopened
        .acquire_inventory_fence()
        .expect("reopen directory inventory fence");
    let reopened_summary = reopened_fence
        .visit_inventory(&mut |_| Ok(()))
        .expect("visit reopened inventory");
    assert_ne!(reopened_summary.generation(), after_delete.generation());
    assert_ne!(reopened_summary.generation(), before.generation());
    assert_eq!(reopened_summary.objects(), 3);
    drop(reopened_fence);

    fs::write(root.join("unexpected-physical-entry"), b"unowned")
        .expect("inject malformed physical entry");
    let mut malformed_fence = reopened
        .acquire_inventory_fence()
        .expect("acquire malformed inventory fence");
    assert!(matches!(
        malformed_fence.visit_inventory(&mut |_| Ok(())),
        Err(StoreError::InvalidComposition {
            reason: "inventory contains an unknown object-kind directory"
        })
    ));
    drop(malformed_fence);

    fs::remove_file(root.join("unexpected-physical-entry"))
        .expect("remove malformed physical entry");
    fs::write(root.join(".inventory-admin/state-v1"), [0_u8; 257])
        .expect("inject oversized inventory state");
    assert!(matches!(
        reopened.acquire_inventory_fence(),
        Err(StoreError::InvalidComposition {
            reason: "directory inventory state exceeds its byte limit"
        })
    ));
}
