//! Tests admitted immutable completion and closed options against durable pointers.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use aos_net::direct_upload::{
    DirectCheckpointStore as _, ProviderOptions, SqliteDirectCheckpoints,
};
use aos_remote::hub_types::direct_upload::*;
use aos_remote::{DirectUploadCoordinator, checkpoint_namespace};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::*;

fn commitment(domain: &str, members: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aos.direct.adapter-operation.v1\0");
    for member in std::iter::once(domain.as_bytes()).chain(members.iter().copied()) {
        hash.update((member.len() as u64).to_be_bytes());
        hash.update(member);
    }
    hex::encode(hash.finalize())
}

async fn retain_completion(
    store: &SqliteDirectCheckpoints,
    profile: &DirectProviderProfile,
    object: &hub_types::RegistryPublicationObject,
    source: &[u8],
    part_size: u64,
) -> (DirectCompleteRequest, DirectSessionStatus) {
    let target = DirectUploadTarget::PublicationObject {
        publication_id: "publication-1".into(),
        surface_object_id: WireInteger::new(object.object_id as u64),
        path: object.path.clone(),
    };
    let target_bytes = encode_direct_control(&target).unwrap();
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: commitment(
            "object-operation",
            &[store.run_id().as_bytes(), &target_bytes],
        ),
        target: target.clone(),
        expected_sha256: object.sha256.clone(),
        byte_size: WireInteger::new(source.len() as u64),
        part_size: WireInteger::new(part_size),
        dependency_phase: if object.kind == "immutable" {
            DirectDependencyPhase::Content
        } else {
            DirectDependencyPhase::Visibility
        },
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
        session_id: format!("session-{:02}", object.object_id),
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
    store.admit_intent(&intent).await.unwrap();
    store.admit_session(&original_status).await.unwrap();
    let observed = DirectManifestPart {
        part: DirectPart {
            part_number: 1,
            offset: WireInteger::new(0),
            byte_size: WireInteger::new(source.len() as u64),
            sha256: intent.expected_sha256.clone(),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Sha256,
                value: base64::engine::general_purpose::STANDARD.encode(Sha256::digest(source)),
            },
        },
        etag: "\"original-etag\"".into(),
    };
    store
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

    store.admit_complete(&original_complete).await.unwrap();
    (original_complete, original_status)
}

fn request(listener: &TcpListener) -> (TcpStream, String, Vec<u8>) {
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
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap();
        if bytes.len() == end + 4 + length {
            return (
                stream,
                headers.lines().next().unwrap().to_owned(),
                bytes[end + 4..].to_vec(),
            );
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
async fn immutable_only_adapter_does_not_complete_prior_pointer_sessions() {
    exercise_retained_completions(Invocation::AdmittedAdapter).await;
}

#[tokio::test]
async fn closed_options_refuse_retained_completions_before_transfer() {
    exercise_retained_completions(Invocation::ClosedOptions).await;
}

#[derive(Clone, Copy)]
enum Invocation {
    AdmittedAdapter,
    ClosedOptions,
}

async fn exercise_retained_completions(invocation: Invocation) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().join("source");
    std::fs::create_dir_all(root.join("info")).unwrap();
    std::fs::create_dir_all(root.join("releases/1.0.0")).unwrap();
    std::fs::write(root.join("HEAD"), "ref: refs/heads/stable\n").unwrap();
    std::fs::write(
        root.join("info/refs"),
        format!("{}\trefs/heads/stable\n", "a".repeat(64)),
    )
    .unwrap();
    std::fs::write(root.join("releases/1.0.0/release.json"), b"{}").unwrap();
    let pinned = super::super::inventory::publication_from_root(&root, "example/main").unwrap();
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
        valid_until: WireInteger::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600,
        ),
        maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
        maximum_batch_items: 1,
        maximum_batch_parts: 64,
        maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
        minimum_object_bytes: WireInteger::new(0),
        minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
        maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
        profiles: vec![profile.clone()],
    };

    let publication = hub_types::RegistryPublication {
        publication_id: "publication-1".into(),
        generation: pinned.request.generation.clone(),
        manifest_digest: aos_remote::publication_inventory_digest(&pinned.request.objects).unwrap(),
        objects: pinned
            .request
            .objects
            .iter()
            .enumerate()
            .map(|(index, object)| hub_types::RegistryPublicationObject {
                object_id: index as i64 + 1,
                path: object.path.clone(),
                sha256: object.sha256.clone(),
                byte_size: object.byte_size,
                kind: object.kind.clone(),
                media_type: object.media_type.clone(),
                verified: false,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let checkpoint = directory.path().join("direct.sqlite");
    let first = DirectUploadCoordinator::open(
        &hub,
        capabilities.clone(),
        &checkpoint,
        ProviderOptions::default(),
    )
    .await
    .unwrap();
    let part_size = first.part_size();
    drop(first);
    let store = SqliteDirectCheckpoints::open(
        &checkpoint,
        &checkpoint_namespace(&hub, &capabilities).unwrap(),
        false,
    )
    .await
    .unwrap();
    let mut originals = Vec::new();
    for object in &publication.objects {
        originals.push((
            object.kind.clone(),
            retain_completion(
                &store,
                &profile,
                object,
                &std::fs::read(root.join(&object.path)).unwrap(),
                part_size,
            )
            .await,
        ));
    }
    drop(store);
    assert!(originals.iter().any(|(kind, _)| kind == "mutable_pointer"));
    let (_, (content_original, content_status)) = originals
        .iter()
        .find(|(kind, _)| kind == "immutable")
        .unwrap()
        .clone();
    let expected_original = content_original.clone();
    let original_capabilities = capabilities.clone();
    let worker = std::thread::spawn(move || {
        if matches!(invocation, Invocation::ClosedOptions) {
            let (mut stream, route, _) = request(&listener);
            assert!(route.starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities "));
            let bytes = encode_direct_control(&capabilities).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
            stream.write_all(&bytes).unwrap();
            return (listener, None);
        }

        let (mut stream, route, bytes) = request(&listener);
        assert!(route.starts_with("POST /aos.hub.v1.DirectUploadService/CompleteBatch "));
        let batch: DirectBatch<DirectCompleteRequest> = decode_direct_control(&bytes).unwrap();
        assert_eq!(batch.items, vec![content_original]);
        reply(
            &mut stream,
            &batch,
            DirectSessionStatus {
                state: DirectSessionState::Committed,
                resource_version: WireInteger::new(2),
                ..content_status
            },
        );
        (listener, Some(batch))
    });
    let prepared = aos_remote::PreparedDirectPublication {
        publication,
        deployment_id: "deployment".into(),
        principal_id: "de".repeat(32),
    };
    let objects = prepared.publication.objects.iter().collect::<Vec<_>>();

    match invocation {
        Invocation::AdmittedAdapter => {
            // Absolute ancestor admission intentionally refuses foreign sandbox
            // roots. Exercise the adapter with real reopened final-file custody;
            // the production entry still performs full options admission first.
            prepared
                .validate_capabilities(&original_capabilities)
                .unwrap();
            let coordinator = DirectUploadCoordinator::open(
                &hub,
                original_capabilities,
                &checkpoint,
                ProviderOptions::default(),
            )
            .await
            .unwrap();
            assert!(
                upload_with_coordinator(
                    coordinator,
                    &prepared,
                    &pinned.root,
                    &pinned.request.objects,
                    &objects,
                    true
                )
                .await
                .unwrap()
            );
            let (_, batch) = worker.join().unwrap();
            assert_eq!(batch.unwrap().items, vec![expected_original]);
        }
        Invocation::ClosedOptions => {
            // A relative journal refuses after genuine target discovery but
            // before any retained completion can reach the transport.
            let options = DirectUploadOptions {
                journal: Some(std::path::PathBuf::from("relative-checkpoint.sqlite")),
                ..Default::default()
            };
            let error = upload_if_required(
                &options,
                &hub,
                &prepared,
                &pinned.root,
                &pinned.request.objects,
                &objects,
                true,
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .downcast_ref::<aos_net::direct_upload::DirectClientError>()
                    .is_some_and(|error| matches!(
                        error,
                        aos_net::direct_upload::DirectClientError::Checkpoint
                    ))
            );
            let (listener, batch) = worker.join().unwrap();
            assert!(batch.is_none());
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    assert_eq!(
        prepared.publication.objects.len(),
        pinned.request.objects.len()
    );
    assert!(
        prepared
            .publication
            .objects
            .iter()
            .filter(|object| object.kind == "mutable_pointer")
            .all(|object| !object.verified)
    );
}
