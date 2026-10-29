//! Lost read responses across expiry and current SQL placement fences.

use super::*;
use aos_hub_db::db::NewSurfacePlacementSpec;
use aos_hub_db::db::SurfaceTarget;
use aos_hub_db::db::UpdateSurfacePlacementSpec;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

const WORK_KEY: &[u8] = b"read-retry-test-key-with-thirty-two-bytes";

async fn receive_plan(stream: TcpStream) -> (TcpStream, StorageWorkPlan) {
    let mut reader = BufReader::new(stream);
    let mut length = None;
    let mut signature = None;

    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).await.unwrap() > 0);
        assert!(line.len() < 8192);
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse::<usize>().unwrap());
            } else if name.eq_ignore_ascii_case(STORAGE_WORK_SIGNATURE_HEADER) {
                signature = Some(value.trim().to_owned());
            }
        }
    }

    let length = length.unwrap();
    assert!(length < 65536);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    let plan = StorageWorkKey::new(WORK_KEY)
        .unwrap()
        .verify_plan(
            &signature.unwrap(),
            &body,
            "deployment-1",
            aos_hub_model::clock::now_unix_secs(),
        )
        .unwrap();
    (reader.into_inner(), plan)
}

async fn lost_response_case(change_placement: bool, mutation: bool) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let registry = db
        .register_registry("retry-registry", &[], false)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("retry-bucket"))
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "registry".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(
            placement.id,
            "ready",
            "complete",
            placement.resource_version,
        )
        .await
        .unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_db = Arc::clone(&db);
    let server_received = Arc::clone(&received);
    let placement_id = placement.id;
    let placement_version = placement.resource_version;

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (stream, first) = receive_plan(stream).await;
        server_received.lock().await.push(first);

        // The request was authenticated while fresh. Its connection disappears
        // after its original window, as a delayed or lost Worker reply can do.
        tokio::time::sleep(Duration::from_secs(3)).await;
        if change_placement {
            server_db
                .update_surface_placement(
                    placement_id,
                    &UpdateSurfacePlacementSpec {
                        expected_version: placement_version,
                        desired_state: "active".into(),
                        desired_read_enabled: true,
                        read_order: 1,
                    },
                )
                .await
                .unwrap();
        }
        drop(stream);

        let (stream, _) = listener.accept().await.unwrap();
        let (mut stream, plan) = receive_plan(stream).await;
        server_received.lock().await.push(plan.clone());
        let body = serde_json::to_vec(&StorageWorkResult {
            plan_id: plan.plan_id,
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 0,
            versioned_sources: Vec::new(),
            outcome: StorageWorkOutcome::NotFound,
        })
        .unwrap();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    });

    let mut work =
        RemoteStorageWorkClient::new("https://worker.example", "deployment-1".into(), WORK_KEY)
            .unwrap();
    work.endpoint = format!("http://{address}/");
    let fetch = HybridSurfaceFetch {
        db,
        placement,
        binding,
        work: Arc::new(work),
    };
    let operation = if mutation {
        StorageWorkOperation::CreateMultipart {
            path: "object".into(),
        }
    } else {
        StorageWorkOperation::InspectSha256 {
            path: "object".into(),
            expected_sha256: None,
            max_source_bytes: 1024,
        }
    };
    let mut original = fetch
        .work
        .plan_for_placement(
            &fetch.placement,
            &fetch.binding,
            operation,
            aos_hub_model::clock::now_unix_secs(),
        )
        .unwrap();
    original.issued_at -= 28;
    original.expires_at = original.issued_at + 30;
    let unchanged = original.clone();

    let result = fetch.execute(&original).await;
    server.abort();
    if let Err(error) = server.await {
        assert!(error.is_cancelled(), "mock Worker failed: {error}");
    }

    assert_eq!(original, unchanged);
    let received = received.lock().await;
    if change_placement || mutation {
        assert!(result.is_err());
        assert_eq!(received.len(), 1);
    } else {
        let result = result.unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0], original);
        assert_ne!(received[1].plan_id, original.plan_id);
        assert!(received[1].issued_at > original.expires_at);
        assert_eq!(received[1].expires_at - received[1].issued_at, 30);
        assert_eq!(received[1].placement_id, original.placement_id);
        assert_eq!(
            received[1].placement_resource_version,
            original.placement_resource_version
        );
        assert_eq!(received[1].binding_id, original.binding_id);
        assert_eq!(
            received[1].binding_resource_version,
            original.binding_resource_version
        );
        assert_eq!(received[1].placement_prefix, original.placement_prefix);
        assert_eq!(received[1].operation, original.operation);
        assert_eq!(result.plan_id, received[1].plan_id);
    }
}

#[tokio::test]
async fn lost_managed_read_reply_obtains_a_fresh_sql_fenced_plan() {
    lost_response_case(false, false).await;
}

#[tokio::test]
async fn changed_placement_prevents_reissuing_an_expired_read() {
    lost_response_case(true, false).await;
}

#[tokio::test]
async fn lost_mutation_reply_is_never_reissued() {
    lost_response_case(false, true).await;
}
