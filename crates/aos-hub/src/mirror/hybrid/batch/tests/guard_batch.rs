//! Actual signed TLS batching through the production final commit scheduler.
//!
//! The controlled peer reports test positives; it qualifies control transport
//! and actual SQL publication, while provider receipts have a separate runtime
//! gate. Every request and reply passes the ordinary canonical MAC verifier.

use aos_hub_core::mirror_guard::batch::*;
use aos_hub_core::mirror_guard::MIRROR_GUARD_SIGNATURE_HEADER;
use sha2::Digest as _;

use super::*;

pub(super) async fn execute(State(state): State<Arc<Mutex<Peer>>>, request: Request) -> Response {
    let signature = request.headers()[MIRROR_GUARD_SIGNATURE_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let body = axum::body::to_bytes(request.into_body(), MAX_PLAN_BYTES)
        .await
        .unwrap();
    let key = StorageWorkKey::new(GUARD_KEY).unwrap();
    let now = aos_hub_core::clock::now_unix_secs() as u64 + 1;
    let lookup =
        verify_mirror_guard_batch_lookup(&key, &signature, &body, DEPLOYMENT, now).unwrap();
    let mut peer = state.lock().unwrap();
    peer.guard_request_bytes.push(body.len());
    peer.guard_requests.push(lookup.clone());
    let results = lookup
        .items
        .iter()
        .map(|item| {
            let original_digest = digest(&item.original).unwrap();
            if peer.refuse_guard_path.as_deref() == Some(&item.original.path) {
                MirrorGuardBatchResult::Refused {
                    original_digest,
                    refusal: MirrorGuardBatchRefusal::Unavailable,
                }
            } else {
                assert_eq!(peer.progress[&item.original.job_id], item.expected);
                MirrorGuardBatchResult::Positive {
                    original_digest,
                    progress: item.expected.clone(),
                    observed_at: now,
                }
            }
        })
        .collect();
    let reply = MirrorGuardBatchReply {
        version: 1,
        request_digest: hex::encode(sha2::Sha256::digest(&body)),
        request_nonce: lookup.request_nonce.clone(),
        issuer: lookup.issuer.clone(),
        results,
        observed_at: now,
    };
    let signed = sign_mirror_guard_batch_reply(&key, &reply, &lookup).unwrap();
    peer.guard_reply_bytes.push(signed.body.len());
    if peer.lose_guard_reply {
        peer.lose_guard_reply = false;
        return Response::builder().status(502).body(Body::empty()).unwrap();
    }
    Response::builder()
        .header(MIRROR_GUARD_SIGNATURE_HEADER, signed.signature)
        .body(Body::from(signed.body))
        .unwrap()
}

async fn positives(
    db: &Database,
    client: &RemoteStorageWorkClient,
    registry: &aos_hub_core::db::RegistryRecord,
    peer: &Arc<Mutex<Peer>>,
) -> (String, Vec<(MirrorOriginal, MirrorProgress)>) {
    let prepared = prepare(db, client, registry, selected()).await.unwrap();
    let publication = crate::mirror::hybrid::publication::admit(
        db,
        registry.id,
        &"5".repeat(64),
        &"6".repeat(64),
        &prepared,
    )
    .await
    .unwrap();
    let mut positive = Vec::new();
    for item in prepared {
        let original = item.original;
        let mut progress = db
            .mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .progress
            .unwrap();
        progress.destination_upload_id = Some(format!("final-{}", original.job_id));
        progress.destination_parts = progress.stage_parts.clone();
        progress.destination = Some(MirrorVerifiedObject {
            object: StorageObjectIdentity {
                key: aos_hub_core::keymap::r2_key(&original.placement_prefix, &original.path),
                size: original.verification.size(),
                etag: "\"final\"".into(),
                provider_version: Some("controlled-final-incarnation".into()),
            },
            sha256: "1".repeat(64),
            nar_sha256: None,
            nar_size: None,
        });
        progress.validate(&original).unwrap();
        peer.lock()
            .unwrap()
            .progress
            .insert(original.job_id.clone(), progress.clone());
        positive.push((original, progress));
    }
    (publication.publication_id, positive)
}

#[tokio::test]
async fn sixty_four_final_positives_use_one_guard_tls_request_with_local_refusals() {
    let (_directory, db, registry, client, peer, task) = fixture().await;
    let (publication, positive) = positives(&db, &client, &registry, &peer).await;
    peer.lock().unwrap().refuse_guard_path = Some(positive[0].0.path.clone());
    let results = super::super::commit::commit(&db, &client, positive.clone(), &publication).await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 63);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    for (index, (original, progress)) in positive.iter().enumerate() {
        let retained = db.mirror_import(&original.job_id).await.unwrap().unwrap();
        assert_eq!(retained.original, *original);
        assert_eq!(retained.progress.as_ref(), Some(progress));
        assert_eq!(
            retained.publication_commit_version,
            (index != 0).then_some(7)
        );
    }
    let observed = peer.lock().unwrap();
    assert_eq!(observed.guard_requests.len(), 1);
    assert_eq!(observed.guard_requests[0].items.len(), 64);
    assert_eq!(observed.requests.len(), 5);
    assert!(observed
        .guard_request_bytes
        .iter()
        .chain(&observed.guard_reply_bytes)
        .all(|bytes| *bytes <= MAX_PLAN_BYTES));
    eprintln!(
        "controlled mirror final guard requests=1 request_bytes={} reply_bytes={}",
        observed.guard_request_bytes[0], observed.guard_reply_bytes[0]
    );
    task.abort();
}

#[tokio::test]
async fn lost_guard_reply_keeps_positive_originals_and_cold_retry_uses_one_new_batch() {
    let (directory, db, registry, client, peer, task) = fixture().await;
    let (publication, positive) = positives(&db, &client, &registry, &peer).await;
    peer.lock().unwrap().lose_guard_reply = true;
    let refused = super::super::commit::commit(&db, &client, positive.clone(), &publication).await;
    assert_eq!(refused.len(), 64);
    assert!(refused.iter().all(Result::is_err));
    for (original, progress) in &positive {
        let retained = db.mirror_import(&original.job_id).await.unwrap().unwrap();
        assert_eq!(retained.original, *original);
        assert_eq!(retained.progress.as_ref(), Some(progress));
        assert_eq!(retained.publication_commit_version, None);
    }
    drop(db);
    let db = Database::open(&directory.path().join("controller.db"))
        .await
        .unwrap();
    let acknowledged = super::super::commit::commit(&db, &client, positive, &publication).await;
    assert_eq!(acknowledged.len(), 64);
    assert!(acknowledged.iter().all(Result::is_ok));
    let observed = peer.lock().unwrap();
    assert_eq!(observed.guard_requests.len(), 2);
    assert_ne!(
        observed.guard_requests[0].request_nonce,
        observed.guard_requests[1].request_nonce
    );
    assert_eq!(
        observed.guard_requests[0].items,
        observed.guard_requests[1].items
    );
    assert_eq!(observed.requests.len(), 5);
    task.abort();
}
