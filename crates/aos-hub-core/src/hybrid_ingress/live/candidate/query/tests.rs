//! Controlled query protocol checks, not runtime measurements or acceptance.

use super::*;

fn request() -> MirrorLiveQueryCandidateRequest {
    let mut target = crate::hybrid_ingress::live::tests::target();
    let run = "ab".repeat(16);
    target.upstream_base = format!("https://upstream.example.com/.aos-mirror-qualification/{run}");
    target.placement_prefix = format!(".aos-mirror-qualification/{run}/final");
    MirrorLiveQueryCandidateRequest {
        version: 1,
        nonce: "ef".repeat(16),
        candidate: MirrorLiveCandidateRequest {
            version: 1,
            run_id: run.clone(),
            compiled_source_sha256: "cd".repeat(32),
            script_version: "controlled-script-1".into(),
            request: crate::hybrid_ingress::HybridIngressAssertion {
                version: 1,
                deployment_id: "deployment-1".into(),
                issued_at: 100,
                expires_at: 130,
                request_id: "query-original-1".into(),
                scheme: "https".into(),
                authority: "hub.example.com".into(),
                method: "GET".into(),
                path_and_query: format!("/.aos-mirror-qualification/{run}/HEAD"),
                body_sha256: crate::hybrid_ingress::body_sha256(&[]),
                upload_phase: None,
                client_ip: "192.0.2.1".into(),
            },
            target,
        },
    }
}

fn reply(request: &MirrorLiveQueryCandidateRequest) -> MirrorLiveQueryCandidateReply {
    let bytes = b"ref: refs/heads/main\n";
    MirrorLiveQueryCandidateReply {
        version: 1,
        nonce: request.nonce.clone(),
        request_sha256: crate::mirror_work::digest(request).unwrap(),
        observed_at: 101,
        outcome: StorageWorkOutcome::MirrorLiveMetadata {
            sha256: crate::hybrid_ingress::body_sha256(bytes),
            size: bytes.len() as u64,
            content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        },
        source_bytes: bytes.len() as u64,
    }
}

#[test]
fn query_purpose_and_reply_bind_actual_output_and_fresh_original() {
    let key = StorageWorkKey::new([31; 32]).unwrap();
    let request = request();
    let body = serde_json::to_vec(&request).unwrap();
    let signature = sign_mirror_live_query_candidate(&key, &request).unwrap();
    assert!(
        verify_mirror_live_query_candidate(&key, &signature, &body, "deployment-1", 101).is_ok()
    );
    assert!(key.verify_body(&signature, &body).is_err());
    assert!(
        verify_mirror_live_query_candidate(&key, &signature, &body, "deployment-1", 130).is_err()
    );
    let stream_signature =
        super::super::sign_mirror_live_candidate(&key, &request.candidate).unwrap();
    assert!(verify_mirror_live_query_candidate(
        &key,
        &stream_signature,
        &body,
        "deployment-1",
        101
    )
    .is_err());

    let reply = reply(&request);
    let body = serde_json::to_vec(&reply).unwrap();
    let signature = sign_mirror_live_query_candidate_reply(&key, &request, &reply).unwrap();
    assert!(body.len() > 0 && body.len() <= LIVE_QUERY_CANDIDATE_REPLY_BYTES);
    assert!(
        verify_mirror_live_query_candidate_reply(&key, &signature, &body, &request, 102).is_ok()
    );
    assert!(
        verify_mirror_live_query_candidate_reply(&key, &signature, &body, &request, 130).is_err()
    );
    assert!(
        verify_mirror_live_query_candidate_reply(&key, &signature, &body, &request, 100).is_err()
    );
    let mut foreign = request.clone();
    foreign.nonce = "fe".repeat(16);
    assert!(
        verify_mirror_live_query_candidate_reply(&key, &signature, &body, &foreign, 102).is_err()
    );
    let mut foreign = request;
    foreign.candidate.request.request_id.push('x');
    assert!(
        verify_mirror_live_query_candidate_reply(&key, &signature, &body, &foreign, 102).is_err()
    );
}

#[test]
fn query_refuses_bulk_head_oversize_foreign_outcome_and_wrong_bytes() {
    let original = request();
    for change in 0..4 {
        let mut bad = original.clone();
        match change {
            0 => bad.candidate.request.method = "HEAD".into(),
            1 => bad.candidate.target.maximum_bytes = 128 * 1024 + 1,
            2 => bad.candidate.target.class = HybridLiveDeliveryClass::Pack,
            _ => bad.candidate.target.placement_prefix = "public/final".into(),
        }
        assert!(bad.validate("deployment-1", 101).is_err());
    }

    for change in 0..5 {
        let mut bad = reply(&original);
        match change {
            0 => bad.source_bytes += 1,
            1 => bad.outcome = StorageWorkOutcome::NotFound,
            2 => bad.request_sha256 = "aa".repeat(32),
            3 => {
                if let StorageWorkOutcome::MirrorLiveMetadata { sha256, .. } = &mut bad.outcome {
                    *sha256 = "aa".repeat(32);
                }
            }
            _ => {
                if let StorageWorkOutcome::MirrorLiveMetadata { content_base64, .. } =
                    &mut bad.outcome
                {
                    *content_base64 = "A".repeat(256 * 1024);
                }
            }
        }
        assert!(bad.validate_for(&original, 102).is_err());
    }
}
