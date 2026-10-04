//! Exercises content-only completion against a reopened mixed-phase journal.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;

use aos_net::direct_upload::DirectCheckpointStore as _;

use super::*;

async fn retain_completion(
    coordinator: &DirectUploadCoordinator,
    profile: &DirectProviderProfile,
    session_id: &str,
    object_id: u64,
    path: &str,
    phase: DirectDependencyPhase,
) -> (DirectCompleteRequest, DirectSessionStatus) {
    let target = DirectUploadTarget::PublicationObject {
        publication_id: "publication-1".into(),
        surface_object_id: WireInteger::new(object_id),
        path: path.into(),
    };
    let target_bytes = encode_direct_control(&target).unwrap();
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: commitment(
            "object-operation",
            &[coordinator.store.run_id().as_bytes(), &target_bytes],
        ),
        target: target.clone(),
        expected_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        byte_size: WireInteger::new(3),
        part_size: WireInteger::new(coordinator.part_size()),
        dependency_phase: phase,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let placement = DirectPlacementRef {
        placement_id: profile.placement_id,
        placement_fingerprint: "ab".repeat(32),
        placement_resource_version: profile.placement_resource_version,
        write_spec_version: profile.write_spec_version,
        binding_id: profile.binding_id,
        binding_resource_version: profile.binding_resource_version,
        binding_write_revision: profile.binding_write_revision,
        profile_fingerprint: profile.profile_fingerprint.clone(),
        private_policy_digest: profile.private_policy_digest.clone(),
        checksum_algorithm: profile.checksum_algorithm,
    };
    let session = DirectSessionRef {
        session_id: session_id.into(),
        logical_fingerprint: intent.fingerprint().unwrap(),
    };
    let original_status = DirectSessionStatus {
        session: session.clone(),
        resource_version: WireInteger::new(1),
        intent: intent.clone(),
        placements: vec![placement.clone()],
        state: DirectSessionState::Active,
        parts: Vec::new(),
        next_cursor: None,
        outstanding_grants: false,
    };
    coordinator.store.admit_intent(&intent).await.unwrap();
    coordinator
        .store
        .admit_session(&original_status)
        .await
        .unwrap();
    let observed = DirectManifestPart {
        part: DirectPart {
            part_number: 1,
            offset: WireInteger::new(0),
            byte_size: WireInteger::new(3),
            sha256: intent.expected_sha256.clone(),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Sha256,
                value: "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=".into(),
            },
        },
        etag: "\"original-etag\"".into(),
    };
    coordinator
        .store
        .record_server_part(&session, &placement, &observed)
        .await
        .unwrap();
    let manifest_digest = canonical_manifest_digest(&intent, &placement, &[observed]).unwrap();
    let manifests = vec![DirectManifestCommitment {
        placement,
        manifest_digest,
        part_count: 1,
    }];
    let manifest_bytes = encode_direct_control(&manifests).unwrap();
    let manifest_commitment = hex::encode(Sha256::digest(&manifest_bytes));
    let original_complete = DirectCompleteRequest {
        session: session.clone(),
        operation_id: commitment(
            "complete",
            &[
                session.session_id.as_bytes(),
                session.logical_fingerprint.as_bytes(),
                manifest_commitment.as_bytes(),
            ],
        ),
        expected_resource_version: WireInteger::new(1),
        manifests,
    };

    coordinator
        .store
        .admit_complete(&original_complete)
        .await
        .unwrap();
    (original_complete, original_status)
}

fn request(listener: &TcpListener) -> (TcpStream, DirectBatch<DirectCompleteRequest>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "expected completion request"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("local completion listener: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() <= MAX_DIRECT_CONTROL_BYTES + 8192);
        let Some(end) = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&bytes[..end]);
        assert!(headers.starts_with("POST /aos.hub.v1.DirectUploadService/CompleteBatch "));
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap();
        if bytes.len() == end + 4 + length {
            return (stream, decode_direct_control(&bytes[end + 4..]).unwrap());
        }
    }
}

fn reply(
    stream: &mut TcpStream,
    batch: &DirectBatch<DirectCompleteRequest>,
    status: DirectSessionStatus,
) {
    let bytes = encode_direct_control(&DirectUploadResponse {
        operation_id: batch.operation_id.clone(),
        sessions: vec![status],
        grants: Vec::new(),
        errors: Vec::new(),
    })
    .unwrap();
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
    stream.write_all(&bytes).unwrap();
}

#[tokio::test]
async fn reopened_content_barrier_preserves_visibility_for_normal_finish() {
    let directory =
        std::env::temp_dir().join(format!("aos-content-barrier-{}", rand::random::<u64>()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let checkpoint = directory.join("direct.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hub = HubClient::connect_with_token(&origin, "original-owned-bearer").unwrap();
    let profile = DirectProviderProfile {
        placement_id: WireInteger::new(1),
        placement_resource_version: WireInteger::new(1),
        write_spec_version: WireInteger::new(1),
        binding_id: WireInteger::new(1),
        binding_resource_version: WireInteger::new(1),
        binding_write_revision: WireInteger::new(1),
        checksum_algorithm: DirectChecksumAlgorithm::Sha256,
        provider_origin: "https://provider.invalid".into(),
        profile_fingerprint: "af".repeat(32),
        private_policy_digest: "fe".repeat(32),
    };
    let capabilities = DirectUploadCapabilities {
        target: DirectCapabilitiesTarget::Publication {
            publication_id: "publication-1".into(),
        },
        requested_delivery_url: None,
        deployment_id: "deployment".into(),
        principal_id: "de".repeat(32),
        version: 1,
        capability: DIRECT_UPLOAD_CAPABILITY.into(),
        transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
        config_generation: WireInteger::new(1),
        valid_until: WireInteger::new(now().unwrap() + 600),
        maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
        maximum_batch_items: 1,
        maximum_batch_parts: 64,
        maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
        minimum_object_bytes: WireInteger::new(0),
        minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
        maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
        profiles: vec![profile.clone()],
    };

    let first = DirectUploadCoordinator::open(
        &hub,
        capabilities.clone(),
        &checkpoint,
        ProviderOptions::default(),
    )
    .await
    .unwrap();
    // Visibility sorts first and occupies an entire page. The content barrier
    // must traverse that page without dispatching or changing its original.
    let visibility = retain_completion(
        &first,
        &profile,
        "a-visibility",
        1,
        "HEAD",
        DirectDependencyPhase::Visibility,
    )
    .await;
    let content = retain_completion(
        &first,
        &profile,
        "b-content",
        2,
        "releases/1.0.0/release.json",
        DirectDependencyPhase::Content,
    )
    .await;
    drop(first);

    let reopened = DirectUploadCoordinator::open(
        &hub,
        capabilities.clone(),
        &checkpoint,
        ProviderOptions::default(),
    )
    .await
    .unwrap();
    let content_original = content.0.clone();
    let visibility_original = visibility.0.clone();
    let worker = std::thread::spawn(move || {
        let mut captured = Vec::new();
        // Stage-only requires two exact Content replays across pending state.
        // Ordinary finish then replays the untouched Visibility and Content.
        for (original, status, state) in [
            (
                &content.0,
                &content.1,
                DirectSessionState::CompletingStaging,
            ),
            (&content.0, &content.1, DirectSessionState::Committed),
            (&visibility.0, &visibility.1, DirectSessionState::Committed),
            (&content.0, &content.1, DirectSessionState::Committed),
        ] {
            let (mut stream, batch) = request(&listener);
            assert_eq!(batch.items, vec![original.clone()]);
            reply(
                &mut stream,
                &batch,
                DirectSessionStatus {
                    state,
                    resource_version: WireInteger::new(2),
                    ..status.clone()
                },
            );
            captured.push(batch);
        }
        captured
    });

    reopened
        .finish_staged_content(Duration::from_secs(5))
        .await
        .unwrap();
    drop(reopened);
    let normal =
        DirectUploadCoordinator::open(&hub, capabilities, &checkpoint, ProviderOptions::default())
            .await
            .unwrap();
    normal.finish(Duration::from_secs(5)).await.unwrap();
    let captured = worker.join().unwrap();
    assert_eq!(captured.len(), 4);
    assert_eq!(captured[0], captured[1]);
    assert_eq!(captured[0].items, vec![content_original.clone()]);
    assert_eq!(captured[2].items, vec![visibility_original]);
    assert_eq!(captured[3].items, vec![content_original]);
    drop(normal);
    std::fs::remove_dir_all(directory).unwrap();
}
