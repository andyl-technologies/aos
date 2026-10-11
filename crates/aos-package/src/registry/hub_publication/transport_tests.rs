//! Actual shared entry-point refusal before any legacy upload after Direct discovery.

use std::io::{Read as _, Write as _};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use aos_registry_surface::staging::{
    STAGE_SCHEMA, StageObject, StagePointer, StageRevision, inventory_digest,
};

fn source() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("info")).unwrap();
    std::fs::create_dir_all(root.path().join("releases/1.0.0")).unwrap();
    std::fs::write(root.path().join("HEAD"), "ref: refs/heads/stable\n").unwrap();
    std::fs::write(
        root.path().join("info/refs"),
        format!("{}\trefs/heads/stable\n", "a".repeat(64)),
    )
    .unwrap();
    std::fs::write(root.path().join("releases/1.0.0/release.json"), b"{}").unwrap();
    root
}

fn revision(root: &std::path::Path) -> StageRevision {
    let pinned = inventory::publication_from_root(root, "example/main").unwrap();
    let inventory = pinned
        .request
        .objects
        .iter()
        .filter(|object| object.kind == "immutable")
        .map(|object| StageObject {
            path: object.path.clone(),
            sha256: format!("sha256:{}", object.sha256),
            byte_size: object.byte_size as u64,
            kind: "immutable".into(),
            media_type: object.media_type.clone(),
        })
        .collect::<Vec<_>>();
    let publication = pinned
        .request
        .objects
        .iter()
        .filter(|object| object.kind == "mutable_pointer")
        .map(|object| StagePointer {
            path: object.path.clone(),
            bytes: std::fs::read(root.join(&object.path)).unwrap(),
            expected_sha256: None,
        })
        .collect();
    StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "candidate".into(),
        registry: "example/main".into(),
        revision: 1,
        release_id: "1.0.0".into(),
        source_branch: "dplecki/candidate".into(),
        commit: "a".repeat(64),
        inventory_digest: inventory_digest(&inventory).unwrap(),
        inventory,
        container: None,
        publication,
        store_roots: Vec::new(),
    }
}

fn proof(principal: &str) -> Vec<u8> {
    serde_json::to_vec(&hub_types::WhoAmIResponse {
        deployment_id: "deployment".into(),
        principal_id: principal.into(),
        transfer_mode: "direct_required".into(),
        ..Default::default()
    })
    .unwrap()
}

fn server(replies: Vec<Vec<u8>>) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (send, requests) = mpsc::channel();
    let worker = thread::spawn(move || {
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "expected bounded control request"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("control listener: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let count = socket.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                assert!(bytes.len() <= 256 * 1024 + 8192);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if bytes.len() == end + 4 + length {
                        break;
                    }
                }
            }
            send.send(
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned(),
            )
            .unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
            socket.write_all(&reply).unwrap();
        }
    });
    (origin, requests, worker)
}

#[tokio::test]
async fn upload_and_prepare_use_direct_discovery_without_legacy_body_fallback() {
    for commit in [false, true] {
        let root = source();
        let (origin, requests, worker) =
            server(vec![proof(&"aa".repeat(32)), proof(&"bb".repeat(32))]);
        let access = PublicationAccess {
            hub: Some(origin),
            token: Some("fixture-token".into()),
        };
        let printer = Printer::new(0, true, false);

        let result = if commit {
            upload_registry_publication(&access, "example/main", None, root.path(), &printer).await
        } else {
            prepare_registry_publication(&access, "example/main", None, root.path(), &printer).await
        };

        assert!(result.is_err());
        worker.join().unwrap();
        let requests = requests.into_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.starts_with("POST /aos.hub.v1.IdentityService/WhoAmI "))
        );
    }
}

#[tokio::test]
async fn staged_candidate_retains_registration_then_refuses_changed_direct_actor() {
    let root = source();
    let revision = revision(root.path());
    revision.validate().unwrap();
    let response = hub_types::StagedRelease {
        registry: revision.registry.clone(),
        stage_id: revision.id.clone(),
        revision: revision.revision,
        release_id: revision.release_id.clone(),
        source_branch: revision.source_branch.clone(),
        commit: revision.commit.clone(),
        inventory_digest: revision.inventory_digest.clone(),
        state: "draft".into(),
        revision_gzip: aos_registry_surface::staging::wire::encode_revision(&revision).unwrap(),
        object_count: revision.inventory.len() as u64,
        missing_object_count: revision.inventory.len() as u64,
        missing_paths: revision
            .inventory
            .iter()
            .map(|object| object.path.clone())
            .collect(),
        total_bytes: revision
            .inventory
            .iter()
            .map(|object| object.byte_size)
            .sum(),
        ..Default::default()
    };
    let (origin, requests, worker) = server(vec![
        serde_json::to_vec(&response).unwrap(),
        proof(&"aa".repeat(32)),
        proof(&"bb".repeat(32)),
    ]);
    let access = PublicationAccess {
        hub: Some(origin),
        token: Some("fixture-token".into()),
    };

    let result = stage_registry_candidate(
        &access,
        &revision,
        0,
        root.path(),
        &Printer::new(0, true, false),
    )
    .await;

    assert!(result.is_err());
    worker.join().unwrap();
    let requests = requests.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("POST /aos.hub.v1.PublishService/UpsertStagedRelease "));
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.starts_with("POST /aos.hub.v1.IdentityService/WhoAmI "))
    );
}

fn stage_reply(revision: &StageRevision, publication: Option<&str>) -> hub_types::StagedRelease {
    let ready = publication.is_some();
    let missing_paths = if ready {
        Vec::new()
    } else {
        revision
            .inventory
            .iter()
            .map(|object| object.path.clone())
            .collect()
    };
    let total_bytes = revision
        .inventory
        .iter()
        .map(|object| object.byte_size)
        .sum();
    hub_types::StagedRelease {
        registry: revision.registry.clone(),
        stage_id: revision.id.clone(),
        revision: revision.revision,
        release_id: revision.release_id.clone(),
        source_branch: revision.source_branch.clone(),
        commit: revision.commit.clone(),
        inventory_digest: revision.inventory_digest.clone(),
        revision_gzip: aos_registry_surface::staging::wire::encode_revision(revision).unwrap(),
        state: if ready { "ready" } else { "draft" }.into(),
        publication_id: publication.unwrap_or_default().into(),
        object_count: revision.inventory.len() as u64,
        missing_object_count: missing_paths.len() as u64,
        missing_paths,
        total_bytes,
        uploaded_bytes: if ready { total_bytes } else { 0 },
        ..Default::default()
    }
}

#[tokio::test]
async fn staged_reuse_withholds_pointers_and_rejects_foreign_prepared_readback() {
    for changed_readback in [false, true] {
        let root = source();
        let revision = revision(root.path());
        let pinned = inventory::publication_from_root(root.path(), &revision.registry).unwrap();
        let publication = hub_types::RegistryPublication {
            publication_id: "original-publication".into(),
            registry: pinned.request.registry.clone(),
            generation: pinned.request.generation.clone(),
            manifest_digest: publication_manifest_digest(&pinned.request.objects).unwrap(),
            refs_digest: pinned.request.refs_digest.clone(),
            default_commit: pinned.request.default_commit.clone(),
            state: "preparing".into(),
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
                    verified: object.kind == "immutable",
                    upload_url: "/must-not-upload".into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let admission = hub_types::RegistryPublicationManifestSession {
            publication_id: publication.publication_id.clone(),
            lease_token: "original-lease".into(),
            manifest_digest: publication.manifest_digest.clone(),
            object_count: publication.objects.len() as u32,
            admitted_object_count: publication.objects.len() as u32,
            state: "ready".into(),
            ..Default::default()
        };
        let mut readback = publication.clone();
        if changed_readback {
            readback.generation = "foreign-generation".into();
        }
        let ready = stage_reply(&revision, Some(&publication.publication_id));
        let mut replies = vec![
            serde_json::to_vec(&stage_reply(&revision, None)).unwrap(),
            serde_json::to_vec(&hub_types::WhoAmIResponse {
                transfer_mode: "legacy".into(),
                ..Default::default()
            })
            .unwrap(),
            serde_json::to_vec(&hub_types::ListRegistryPublicationsResponse::default()).unwrap(),
            serde_json::to_vec(&admission).unwrap(),
            serde_json::to_vec(&publication).unwrap(),
            serde_json::to_vec(&ready).unwrap(),
            serde_json::to_vec(&readback).unwrap(),
        ];
        if !changed_readback {
            replies.push(serde_json::to_vec(&ready).unwrap());
        }
        let (origin, requests, worker) = server(replies);
        let access = PublicationAccess {
            hub: Some(origin),
            token: Some("fixture-token".into()),
        };

        let result = stage_registry_candidate(
            &access,
            &revision,
            0,
            root.path(),
            &Printer::new(0, true, false),
        )
        .await;

        if changed_readback {
            assert!(format!("{:#}", result.unwrap_err()).contains("original prepared publication"));
        } else {
            let result = result.unwrap();
            assert_eq!(result.publication_id, publication.publication_id);
            assert!(
                result
                    .objects
                    .iter()
                    .filter(|object| object.kind == "mutable_pointer")
                    .all(|object| !object.verified)
            );
        }
        worker.join().unwrap();
        let requests = requests.into_iter().collect::<Vec<_>>();
        let expected = [
            "UpsertStagedRelease",
            "WhoAmI",
            "ListRegistryPublications",
            "BeginRegistryPublicationManifest",
            "SealRegistryPublicationManifest",
            "UpsertStagedRelease",
            "GetRegistryPublication",
            "UpsertStagedRelease",
        ];
        assert_eq!(requests.len(), if changed_readback { 7 } else { 8 });
        for (request, method) in requests.iter().zip(expected) {
            assert!(request.starts_with("POST /aos.hub.v1."));
            assert!(
                request.ends_with(&format!("/{method} HTTP/1.1")),
                "{request}"
            );
        }
    }
}
