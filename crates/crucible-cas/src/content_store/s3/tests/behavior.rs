//! S3 backend conformance, recovery, and graph-composition tests.

use super::*;

#[test]
fn s3_blob_leaf_passes_the_shared_persistent_conformance_suite() {
    let endpoint = StoreS3EndpointId::new("minio/blob-conformance").assert_value("endpoint");
    let ordinary = Arc::new(FakeS3Client::new(endpoint));
    let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
    let backend = administrative_backend(ordinary, administration);
    conformance::assert_blob_leaf_conformance(&backend);
}

#[test]
fn committed_inventory_is_restart_stable_aba_safe_and_deletable() {
    let endpoint = StoreS3EndpointId::new("minio/administration").assert_value("endpoint");
    let ordinary = Arc::new(FakeS3Client::new(endpoint));
    let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
    let backend = administrative_backend(ordinary.clone(), administration.clone());
    let first_bytes = b"first object".to_vec();
    let second_bytes = b"second object".to_vec();
    let first = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &first_bytes);
    let second = ContentId::for_bytes(ObjectKind::Observation, 1, &second_bytes);
    backend
        .put_if_absent(first, &BlobHandle::from_bytes(first_bytes.clone()))
        .assert_value("put first object");

    let mut initial_records = Vec::new();
    let initial = backend
        .acquire_inventory_fence()
        .assert_value("initial inventory fence")
        .visit_inventory(&mut |record| {
            initial_records.push(record);
            Ok(())
        })
        .assert_value("initial inventory");
    assert_eq!(initial.objects(), 1);
    assert_eq!(initial.logical_bytes(), first_bytes.len() as u64);
    assert_eq!(initial_records[0].id(), first);

    backend
        .put_if_absent(first, &BlobHandle::from_bytes(first_bytes.clone()))
        .assert_value("exact replay");
    let after_replay = backend
        .acquire_inventory_fence()
        .assert_value("replay inventory fence")
        .visit_inventory(&mut |_record| Ok(()))
        .assert_value("replay inventory");
    assert_eq!(after_replay, initial);

    let restarted = administrative_backend(ordinary, administration);
    let after_restart = restarted
        .acquire_inventory_fence()
        .assert_value("restart inventory fence")
        .visit_inventory(&mut |_record| Ok(()))
        .assert_value("restart inventory");
    assert_eq!(after_restart, initial);

    let mut deletion = restarted
        .acquire_inventory_fence()
        .assert_value("deletion fence");
    assert_eq!(
        deletion
            .delete_candidate(first)
            .assert_value("delete first"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        deletion
            .delete_candidate(first)
            .assert_value("retry deletion"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    drop(deletion);

    restarted
        .put_if_absent(first, &BlobHandle::from_bytes(first_bytes))
        .assert_value("restore first object after ABA");
    restarted
        .put_if_absent(second, &BlobHandle::from_bytes(second_bytes))
        .assert_value("put second object");
    let restored = restarted
        .acquire_inventory_fence()
        .assert_value("restored inventory fence")
        .visit_inventory(&mut |_record| Ok(()))
        .assert_value("restored inventory");
    assert_ne!(restored.generation(), initial.generation());
    assert_eq!(restored.objects(), 2);
}

#[test]
fn committed_inventory_fails_closed_on_stale_delete_and_bad_listing() {
    let endpoint = StoreS3EndpointId::new("minio/admin-fail-closed").assert_value("endpoint");
    let ordinary = Arc::new(FakeS3Client::new(endpoint));
    let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
    let backend = administrative_backend(ordinary, administration.clone());
    let bytes = b"retained object";
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .assert_value("put object");

    administration
        .force_delete_conflict
        .store(true, Ordering::SeqCst);
    let mut fence = backend
        .acquire_inventory_fence()
        .assert_value("stale-delete fence");
    assert!(matches!(
        fence.delete_candidate(id),
        Err(StoreError::Incompatible)
    ));
    drop(fence);
    assert!(backend.contains(id).assert_value("object retained"));

    administration
        .force_delete_conflict
        .store(false, Ordering::SeqCst);
    administration.malformed_scan.store(true, Ordering::SeqCst);
    let mut malformed = backend
        .acquire_inventory_fence()
        .assert_value("malformed inventory fence");
    assert!(matches!(
        malformed.visit_inventory(&mut |_record| Ok(())),
        Err(StoreError::Incompatible)
    ));
    drop(malformed);

    administration.malformed_scan.store(false, Ordering::SeqCst);
    administration
        .ordinary
        .authorized
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        backend.acquire_inventory_fence(),
        Err(StoreError::Unauthorized)
    ));
}

#[test]
fn committed_inventory_excludes_cross_instance_publication() {
    let endpoint = StoreS3EndpointId::new("minio/admin-publication").assert_value("endpoint");
    let ordinary = Arc::new(FakeS3Client::new(endpoint));
    let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
    let inventor = administrative_backend(ordinary.clone(), administration.clone());
    let publisher = administrative_backend(ordinary, administration);
    let fence = inventor
        .acquire_inventory_fence()
        .assert_value("inventory fence");
    let bytes = b"blocked publication".to_vec();
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let (finished_sender, finished_receiver) = mpsc::sync_channel(1);
    let publisher_thread = thread::spawn(move || {
        started_sender.send(()).assert_value("announce publication");
        let result = publisher.put_if_absent(id, &BlobHandle::from_bytes(bytes));
        finished_sender
            .send(result)
            .assert_value("return publication result");
    });
    started_receiver.recv().assert_value("publication started");
    assert!(
        finished_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err()
    );
    drop(fence);
    finished_receiver
        .recv_timeout(Duration::from_secs(1))
        .assert_value("publication unblocked")
        .assert_value("publication result");
    publisher_thread.join().assert_value("publisher thread");
}

#[test]
fn multipart_round_trip_ranges_replay_and_corruption_are_authenticated() {
    let endpoint = StoreS3EndpointId::new("minio/archive").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint));
    let backend = backend(client.clone());
    let mut bytes = vec![0x31; 5 * 1024 * 1024 + 137];
    bytes[5 * 1024 * 1024 + 1] = 0x92;
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);

    let receipt = backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .assert_value("multipart put");
    assert!(receipt.is_durable());
    assert_eq!(client.upload_parts.load(Ordering::SeqCst), 2);
    assert_eq!(
        backend
            .read(
                id,
                Some(ByteRange::new(5 * 1024 * 1024 - 2, 8).assert_value("range"))
            )
            .assert_value("range handle")
            .read_all(8)
            .assert_value("authenticated range"),
        bytes[5 * 1024 * 1024 - 2..5 * 1024 * 1024 + 6]
    );

    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .assert_value("exact replay");
    assert_eq!(client.upload_parts.load(Ordering::SeqCst), 2);

    client.corrupt_only_object();
    assert!(matches!(
        backend
            .read(id, None)
            .assert_value("deferred corrupt handle")
            .copy_to(&mut io::sink()),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn interrupted_upload_aborts_and_failed_abort_is_explicit() {
    let endpoint = StoreS3EndpointId::new("minio/interruption").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint));
    let backend = backend(client.clone());
    let bytes = vec![0x44; 5 * 1024 * 1024 + 1];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    client.fail_part.store(true, Ordering::SeqCst);

    assert!(matches!(
        backend.put_if_absent(id, &BlobHandle::from_bytes(bytes.clone())),
        Err(StoreError::Unavailable)
    ));
    assert_eq!(client.aborts.load(Ordering::SeqCst), 1);
    assert!(
        !backend
            .contains(id)
            .assert_value("absent interrupted object")
    );

    client.fail_abort.store(true, Ordering::SeqCst);
    assert!(matches!(
        backend.put_if_absent(id, &BlobHandle::from_bytes(bytes)),
        Err(StoreError::MultipartCleanupRequired)
    ));
    assert_eq!(client.aborts.load(Ordering::SeqCst), 2);

    client.fail_abort.store(false, Ordering::SeqCst);
    let cleanup = backend
        .multipart_cleanup_admin()
        .cleanup_page(None, 1)
        .assert_value("reclaim retained upload");
    assert_eq!(cleanup.aborted(), 1);
    assert!(cleanup.next().is_none());
    assert!(client.uploads.lock().assert_value("upload lock").is_empty());
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn multipart_remove_leaf_aborts_before_completion_and_retries() {
    if std::env::var_os(MULTIPART_REMOVE_LEAF_CHILD_ENVIRONMENT).is_some() {
        run_multipart_remove_leaf_child();
        panic!("multipart remove-leaf child returned without recording recovery");
    }

    let child =
        std::process::Command::new(std::env::current_exe().assert_value("current test binary"))
            .arg("--exact")
            .arg(MULTIPART_REMOVE_LEAF_TEST_NAME)
            .arg("--nocapture")
            .env(MULTIPART_REMOVE_LEAF_CHILD_ENVIRONMENT, "1")
            .env(
                DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
                MULTIPART_REMOVE_LEAF_TRIGGER,
            )
            .output()
            .assert_value("run multipart remove-leaf child");
    assert_eq!(
        child.status.code(),
        Some(MULTIPART_REMOVE_LEAF_CHILD_EXIT_CODE),
        "multipart remove-leaf child did not recover:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
}

#[cfg(feature = "destructive-recovery-faults")]
fn run_multipart_remove_leaf_child() {
    let endpoint = StoreS3EndpointId::new("minio/multipart-remove-leaf").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint));
    let backend = backend(client.clone());
    let mut bytes = vec![0x5a; 5 * 1024 * 1024 + 37];
    bytes[5 * 1024 * 1024 + 11] = 0xa5;
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);

    assert!(matches!(
        backend.put_if_absent(id, &BlobHandle::from_bytes(bytes.clone())),
        Err(StoreError::NotFound { id: missing }) if missing == id
    ));
    assert_eq!(client.upload_parts.load(Ordering::SeqCst), 1);
    assert_eq!(client.aborts.load(Ordering::SeqCst), 1);
    assert!(client.uploads.lock().assert_value("upload lock").is_empty());
    assert!(
        !backend
            .contains(id)
            .assert_value("incomplete object absent")
    );

    let receipt = backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .assert_value("retry selected leaf transfer");
    assert_eq!(receipt.id, id);
    assert!(receipt.is_durable());
    assert_eq!(client.upload_parts.load(Ordering::SeqCst), 3);
    assert_eq!(client.aborts.load(Ordering::SeqCst), 1);
    assert!(client.uploads.lock().assert_value("upload lock").is_empty());
    let restored = backend
        .read(id, None)
        .assert_value("read retried leaf")
        .read_all(bytes.len() as u64)
        .assert_value("authenticate retried leaf");
    assert_eq!(restored, bytes);

    std::process::exit(MULTIPART_REMOVE_LEAF_CHILD_EXIT_CODE);
}

#[test]
fn multipart_cleanup_is_bounded_resumable_and_namespace_scoped() {
    let endpoint = StoreS3EndpointId::new("minio/cleanup").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint));
    let backend = backend(client.clone());
    let ids = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
        .map(|bytes| ContentId::for_bytes(ObjectKind::Trace, 1, bytes));
    let mut keys = ids
        .map(|id| format!("tenant-a/objects/{id}"))
        .into_iter()
        .collect::<Vec<_>>();
    keys.push(format!("tenant-b/objects/{}", ids[0]));
    for key in &keys {
        client
            .begin_multipart("campaign-archive", key)
            .assert_value("unfinished upload");
    }

    let admin = backend.multipart_cleanup_admin();
    client.malformed_listing.store(true, Ordering::SeqCst);
    assert!(matches!(
        admin.cleanup_page(None, 2),
        Err(StoreError::Incompatible)
    ));
    assert_eq!(client.aborts.load(Ordering::SeqCst), 0);
    client.malformed_listing.store(false, Ordering::SeqCst);

    let first = admin
        .cleanup_page(None, 2)
        .assert_value("first cleanup page");
    assert_eq!(first.aborted(), 2);
    let second = admin
        .cleanup_page(first.next(), 2)
        .assert_value("second cleanup page");
    assert_eq!(second.aborted(), 1);
    assert!(second.next().is_none());
    let uploads = client.uploads.lock().assert_value("upload lock");
    assert_eq!(uploads.len(), 1);
    assert_eq!(
        uploads.values().next().assert_value("foreign upload").key,
        keys[3]
    );
}

#[test]
fn credential_expiry_and_configuration_bounds_fail_closed() {
    let endpoint = StoreS3EndpointId::new("minio/credentials").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint.clone()));
    let backend = backend(client.clone());
    let bytes = b"credential-bound object";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    client.authorized.store(false, Ordering::SeqCst);
    assert!(matches!(
        backend.contains(id),
        Err(StoreError::Unauthorized)
    ));
    assert!(matches!(
        S3BlobBackend::new(
            S3BlobBackendConfig::new("invalid", endpoint.clone(), "ab", "bad//prefix", 1, 1,),
            client.clone(),
        ),
        Err(StoreError::InvalidComposition { .. })
    ));
    let maximum_prefix = format!(
        "{}/{}/{}/{}",
        "a".repeat(255),
        "b".repeat(255),
        "c".repeat(255),
        "d".repeat(154)
    );
    assert_eq!(maximum_prefix.len(), MAX_PREFIX_BYTES);
    let longest_id = ContentId::for_bytes(ObjectKind::CampaignSnapshot, u32::MAX, b"");
    assert_eq!(longest_id.encode().len(), MAX_CONTENT_ID_TEXT_BYTES);
    assert_eq!(
        format!("{maximum_prefix}/objects/{longest_id}").len(),
        MAX_OBJECT_KEY_BYTES
    );
    assert!(
        S3BlobBackend::new(
            S3BlobBackendConfig::new(
                "maximum-prefix",
                endpoint.clone(),
                "valid-bucket",
                maximum_prefix.clone(),
                5 * 1024 * 1024,
                5 * 1024 * 1024,
            ),
            client.clone(),
        )
        .is_ok()
    );
    let oversized_prefix = format!("{maximum_prefix}e");
    assert!(matches!(
        S3BlobBackend::new(
            S3BlobBackendConfig::new(
                "oversized-prefix",
                endpoint,
                "valid-bucket",
                oversized_prefix,
                5 * 1024 * 1024,
                5 * 1024 * 1024,
            ),
            client,
        ),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[cfg(feature = "destructive-recovery-faults")]
#[test]
fn credential_expiry_preserves_identity_and_authenticated_retry() {
    if std::env::var_os(STORE_CREDENTIAL_EXPIRY_CHILD_ENVIRONMENT).is_some() {
        run_store_credential_expiry_child();
        panic!("credential-expiry child returned without recording recovery");
    }

    let child =
        std::process::Command::new(std::env::current_exe().assert_value("current test binary"))
            .arg("--exact")
            .arg(STORE_CREDENTIAL_EXPIRY_TEST_NAME)
            .arg("--nocapture")
            .env(STORE_CREDENTIAL_EXPIRY_CHILD_ENVIRONMENT, "1")
            .env(
                DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
                STORE_CREDENTIAL_EXPIRY_TRIGGER,
            )
            .output()
            .assert_value("run credential-expiry child");
    assert_eq!(
        child.status.code(),
        Some(STORE_CREDENTIAL_EXPIRY_CHILD_EXIT_CODE),
        "credential-expiry child did not recover:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
}

#[cfg(feature = "destructive-recovery-faults")]
fn run_store_credential_expiry_child() {
    let endpoint = StoreS3EndpointId::new("minio/credential-expiry").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint.clone()));
    let backend = backend(client.clone());
    let bytes = b"credential-expiry-authenticated-object".to_vec();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let location = ("campaign-archive".to_string(), backend.key(id));
    client
        .objects
        .lock()
        .assert_value("object lock")
        .insert(location.clone(), Arc::from(bytes.clone()));

    assert!(matches!(
        backend.read(id, None),
        Err(StoreError::Unauthorized)
    ));
    let retained = client
        .objects
        .lock()
        .assert_value("object lock")
        .get(&location)
        .cloned()
        .assert_value("retained authenticated object");
    assert_eq!(retained.as_ref(), bytes.as_slice());
    assert_eq!(backend.endpoint_id(), &endpoint);

    let restored = backend
        .read(id, None)
        .assert_value("retry read after credential recovery")
        .read_all(bytes.len() as u64)
        .assert_value("authenticate retry bytes");
    assert_eq!(restored, bytes);
    let receipt = backend
        .put_if_absent(id, &BlobHandle::from_bytes(restored))
        .assert_value("retry existing-object write after credential recovery");
    assert_eq!(receipt.id, id);
    assert!(receipt.is_durable());
    assert_eq!(client.upload_parts.load(Ordering::SeqCst), 0);

    std::process::exit(STORE_CREDENTIAL_EXPIRY_CHILD_EXIT_CODE);
}

#[test]
fn graph_binds_exact_endpoint_capability_and_canonical_configuration() {
    let endpoint = StoreS3EndpointId::new("minio/graph").assert_value("endpoint");
    let client = Arc::new(FakeS3Client::new(endpoint.clone()));
    let administration = Arc::new(FakeBlobAdminClient::new(client.clone()));
    let mut clients = StoreGraphS3Clients::new();
    clients
        .insert(endpoint.clone(), client)
        .assert_value("S3 capability");
    let root = StoreNodeId::new("archive").assert_value("node");
    let config = StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: std::collections::BTreeSet::from([ObjectKind::Finding]),
        nodes: BTreeMap::from([(
            root,
            StoreNodeSpec::S3 {
                endpoint,
                bucket: "campaign-archive".to_string(),
                prefix: "tenant-a".to_string(),
                maximum_logical_object_bytes: 12 * 1024 * 1024,
                multipart_part_bytes: 5 * 1024 * 1024,
            },
        )]),
    };
    assert!(matches!(
        StoreGraph::build(config.clone()),
        Err(StoreError::Unauthorized)
    ));
    let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
        config.clone(),
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &StoreGraphPhysicalQuotaBinders::new(),
        &clients,
    )
    .assert_value("S3 graph");
    assert_eq!(graph.describe()[0].kind, StoreNodeKind::S3);
    assert!(admin.physical().is_empty());
    assert_eq!(admin.s3_multipart_cleanup().len(), 1);
    assert_eq!(admin.s3_multipart_cleanup()[0].node().as_str(), "archive");
    assert_eq!(
        encode_hex(&graph.configuration_id().as_bytes()),
        "92c25a713c145ececbeadfbba56dc54fc667410dbe14d7ad075d86dba745c777"
    );

    clients
        .insert_administration(
            StoreS3EndpointId::new("minio/graph").assert_value("admin endpoint"),
            administration,
        )
        .assert_value("S3 administration capability");
    assert!(matches!(
        StoreGraph::build_with_admin_and_all_capabilities(
            config.clone(),
            &StoreGraphKeyring::new(),
            &StoreGraphNamespaceAuthorizers::new(),
            &StoreGraphObjectProfilers::new(),
            &StoreGraphPhysicalQuotaBinders::new(),
            &clients,
        ),
        Err(StoreError::InvalidComposition { .. })
    ));
    drop(graph);
    drop(admin);
    let (_graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
        config,
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &StoreGraphPhysicalQuotaBinders::new(),
        &clients,
    )
    .assert_value("administrable S3 graph");
    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node().as_str(), "archive");
    assert_eq!(admin.s3_multipart_cleanup().len(), 1);
}
