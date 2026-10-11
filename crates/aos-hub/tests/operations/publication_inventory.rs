//! Measures actual metadata inventory bodies through the Native local-file
//! publication flow. Provider bulk traffic and direct acceptance are measured
//! separately by the fleet qualification.

use super::*;
use aos_proto_types::RegistryPublicationObjectInput;
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};

/// Captures encoded bodies without substituting a reconstructed projection.
async fn measured_rpc(
    app: &axum::Router,
    auth: &str,
    method: &str,
    body: Value,
    observations: &mut Vec<Value>,
) -> Value {
    let encoded = serde_json::to_vec(&body).unwrap();
    let request_bytes = encoded.len();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/aos.hub.v1.PublishService/{method}"))
                .header(header::HOST, "127.0.0.1:8420")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {auth}"))
                .header("connect-protocol-version", "1")
                .body(Body::from(encoded))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    // The observer must retain an oversized Worker reply before reporting its
    // failed 8 MiB gate. This is the existing client inventory collection cap.
    let bytes = axum::body::to_bytes(response.into_body(), 64 << 20)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let mut fields = value
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, field)| (name.clone(), serde_json::to_vec(field).unwrap().len()))
        .collect::<Vec<_>>();
    fields.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    observations.push(json!({
        "route": format!("/aos.hub.v1.PublishService/{method}"),
        "status": status.as_u16(),
        "requestBodyBytes": request_bytes,
        "responseBodyBytes": bytes.len(),
        "largestResponseFields": fields.into_iter().take(4).map(|(name, size)|
            json!({"field": name, "encodedValueBytes": size})).collect::<Vec<_>>(),
    }));
    assert_eq!(status, StatusCode::OK, "{method}: {value}");
    value
}

#[tokio::test]
#[ignore = "opt-in 12,535-object transport measurement before fleet qualification"]
async fn actual_metadata_publication_inventory_transport() {
    const OBJECT_COUNT: usize = 12_535;
    const CHUNK_ITEMS: usize = 64;
    let (db, surface, _, _) = empty_managed().await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        &db,
        Principal::service_account(1),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        &[Permission::Publish],
    )
    .await;

    let corpus = (0..OBJECT_COUNT)
        .map(|number| {
            let path = format!("web/packages/direct-qualification-{number:05}.json");
            let mut bytes = serde_json::to_vec(&json!({
                "name": format!("direct-qualification-{number:05}"),
                "qualificationSequence": number,
                "version": "1.0.0",
            }))
            .unwrap();
            bytes.push(b'\n');
            let input = RegistryPublicationObjectInput {
                media_type: aos_hub_core::keymap::content_type(&path).into(),
                path,
                sha256: hex::encode(Sha256::digest(&bytes)),
                byte_size: bytes.len() as i64,
                kind: "mutable_pointer".into(),
            };
            (input, bytes)
        })
        .collect::<Vec<_>>();
    let inputs = corpus
        .iter()
        .map(|(input, _)| input.clone())
        .collect::<Vec<_>>();
    let manifest_digest = aos_remote::publication_inventory_digest(&inputs).unwrap();
    let mut observations = Vec::new();
    let session = measured_rpc(
        &app,
        &token,
        "BeginRegistryPublicationManifest",
        json!({
            "registry": "acme/infra/prod/cdn",
            "generation": "metadata-transport-measurement",
            "refsDigest": hex::encode(Sha256::digest(b"")),
            "manifestDigest": manifest_digest,
            "objectCount": OBJECT_COUNT,
        }),
        &mut observations,
    )
    .await;
    let publication_id = session["publicationId"].as_str().unwrap().to_owned();
    let lease = session["leaseToken"].as_str().unwrap();

    for (index, chunk) in inputs.chunks(CHUNK_ITEMS).enumerate() {
        let appended = measured_rpc(
            &app,
            &token,
            "AppendRegistryPublicationManifest",
            json!({
                "publicationId": publication_id,
                "leaseToken": lease,
                "chunkIndex": index,
                "chunkDigest": aos_remote::publication_inventory_digest(chunk).unwrap(),
                "objects": chunk,
            }),
            &mut observations,
        )
        .await;
        let count = ((index + 1) * CHUNK_ITEMS).min(OBJECT_COUNT);
        assert_eq!(
            appended["admittedObjectCount"].as_u64().unwrap(),
            count as u64
        );
    }
    let sealed = measured_rpc(
        &app,
        &token,
        "SealRegistryPublicationManifest",
        json!({"publicationId": publication_id, "leaseToken": lease}),
        &mut observations,
    )
    .await;
    let objects = sealed["objects"].as_array().unwrap();
    assert_eq!(objects.len(), OBJECT_COUNT);

    // Write every real admitted body through the production router. The final
    // verified projection comes from storage checks, never edited response JSON.
    stream::iter(corpus.iter().zip(objects.iter()))
        .for_each_concurrent(8, |((input, bytes), object)| {
            let app = &app;
            let token = &token;
            async move {
                assert_eq!(object["path"], input.path);
                let (status, _) = upload_publication_object(
                    app,
                    object["uploadUrl"].as_str().unwrap(),
                    token,
                    bytes.clone(),
                )
                .await;
                assert!(status.is_success(), "{}: {status}", input.path);
            }
        })
        .await;
    let committed = measured_rpc(
        &app,
        &token,
        "CommitRegistryPublication",
        json!({"publicationId": publication_id}),
        &mut observations,
    )
    .await;
    assert_eq!(committed["state"], "ready");
    assert_eq!(committed["objects"].as_array().unwrap().len(), OBJECT_COUNT);
    assert!(committed["objects"]
        .as_array()
        .unwrap()
        .iter()
        .all(|object| object["verified"] == true));
    for (input, bytes) in &corpus {
        assert_eq!(std::fs::read(surface.join(&input.path)).unwrap(), *bytes);
    }

    let report = json!({
        "version": 1,
        "scope": "Native router local_fs metadata publication; no Worker/provider/VM acceptance",
        "metadataObjectCount": OBJECT_COUNT,
        "verifiedObjectCount": OBJECT_COUNT,
        "metadataBodyBytes": corpus.iter().map(|(_, bytes)| bytes.len()).sum::<usize>(),
        "manifestDigest": manifest_digest,
        "appendCalls": inputs.chunks(CHUNK_ITEMS).len(),
        "observations": observations,
    });
    eprintln!("Native metadata inventory observation: {report}");
    assert!(observations
        .iter()
        .all(|observation| observation["requestBodyBytes"].as_u64().unwrap() < 65_536));
    assert!(
        observations.iter().all(|observation|
            observation["responseBodyBytes"].as_u64().unwrap() <= 8 * 1024 * 1024),
        "actual inventory reply exceeds the Worker 8 MiB cap"
    );
}
