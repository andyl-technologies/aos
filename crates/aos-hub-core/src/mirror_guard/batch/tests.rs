//! Outer MAC, exact selected originals, partial refusals and bounded phase tests.

use super::*;
use crate::{
    mirror_work::{MirrorVerification, MirrorVerifiedObject},
    storage_work::StorageObjectIdentity,
};

fn item(index: usize) -> MirrorGuardBatchItem {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("11".repeat(16)),
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        upstream_base: "https://mirror.example.org/".into(),
        path: format!("metadata-{index}.json"),
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 6,
        binding_id: 7,
        binding_resource_version: 8,
        placement_prefix: "managed".into(),
        protected_profile_digest: "22".repeat(32),
        verification: MirrorVerification::Sha256 {
            sha256: "33".repeat(32),
            size: 0,
        },
    };
    original.job_id = original.identity().unwrap();
    let source = StorageObjectIdentity {
        key: original.stage_key(),
        size: 0,
        etag: "\"stage-etag\"".into(),
        provider_version: Some("stage-incarnation".into()),
    };
    let verified = MirrorVerifiedObject {
        object: source.clone(),
        sha256: "33".repeat(32),
        nar_sha256: None,
        nar_size: None,
    };
    let mut destination = verified.clone();
    destination.object.key = crate::keymap::r2_key(&original.placement_prefix, &original.path);
    destination.object.etag = "\"final-etag\"".into();
    destination.object.provider_version = Some("final-incarnation".into());
    let expected = MirrorProgress {
        original_digest: digest(&original).unwrap(),
        stage_object: Some(source),
        verified: Some(verified),
        destination: Some(destination),
        ..Default::default()
    };
    MirrorGuardBatchItem { original, expected }
}

fn request(count: usize) -> MirrorGuardBatchLookup {
    MirrorGuardBatchLookup {
        version: 1,
        deployment_id: "fixture-deployment".into(),
        execution: MirrorGuardExecution::Hosted,
        issuer: MirrorGuardIssuer {
            source_digest: "44".repeat(32),
            script_version: "fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        items: (0..count).map(item).collect(),
        request_nonce: "55".repeat(32),
        issued_at: 100,
        expires_at: 130,
    }
}

fn positive(item: &MirrorGuardBatchItem, observed_at: u64) -> MirrorGuardBatchResult {
    MirrorGuardBatchResult::Positive {
        original_digest: digest(&item.original).unwrap(),
        progress: item.expected.clone(),
        observed_at,
    }
}

fn reply(request: &MirrorGuardBatchLookup) -> MirrorGuardBatchReply {
    MirrorGuardBatchReply {
        version: 1,
        request_digest: digest(request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        issuer: request.issuer.clone(),
        results: request
            .items
            .iter()
            .map(|item| positive(item, 105))
            .collect(),
        observed_at: 107,
    }
}

fn key() -> StorageWorkKey {
    StorageWorkKey::new("independent-guard-role-secret-0001").unwrap()
}

#[test]
fn retained_batch_observations_preserve_order_without_renewing_proofs() {
    let request = request(2);
    let mut reply = reply(&request);
    reply.results[1] = MirrorGuardBatchResult::Refused {
        original_digest: digest(&request.items[1].original).unwrap(),
        refusal: MirrorGuardBatchRefusal::Unavailable,
    };
    let signed = sign_mirror_guard_batch_reply(&key(), &reply, &request).unwrap();

    assert!(verify_mirror_guard_batch_reply(
        &key(),
        &signed.signature,
        &signed.body,
        &request,
        200,
    )
    .is_err());
    assert!(validate_mirror_guard_batch_reply_observation(&request, &reply).is_ok());

    reply.results.swap(0, 1);
    assert!(validate_mirror_guard_batch_reply_observation(&request, &reply).is_err());
    reply.results.swap(0, 1);
    if let MirrorGuardBatchResult::Positive { observed_at, .. } = &mut reply.results[0] {
        *observed_at = reply.observed_at + 1;
    }
    assert!(validate_mirror_guard_batch_reply_observation(&request, &reply).is_err());
}

#[test]
fn full_phase_batch_preserves_positive_times_and_explicit_refusals() {
    let request = request(64);
    let signed = sign_mirror_guard_batch_lookup(&key(), &request).unwrap();
    let checked = verify_mirror_guard_batch_lookup(
        &key(),
        &signed.signature,
        &signed.body,
        "fixture-deployment",
        105,
    )
    .unwrap();
    assert_eq!(checked, request);
    let mut reply = reply(&request);
    reply.results[15] = MirrorGuardBatchResult::Refused {
        original_digest: digest(&request.items[15].original).unwrap(),
        refusal: MirrorGuardBatchRefusal::Unavailable,
    };
    let signed = sign_mirror_guard_batch_reply(&key(), &reply, &request).unwrap();
    let results =
        verify_mirror_guard_batch_reply(&key(), &signed.signature, &signed.body, &request, 108)
            .unwrap();

    assert_eq!(results.len(), 64);
    for (index, result) in results.into_iter().enumerate() {
        match result {
            VerifiedMirrorGuardBatchItem::Positive(proof) => {
                assert_ne!(index, 15);
                assert_eq!(proof.observed_at(), 105);
                proof
                    .validate_for(
                        &request.items[index].original,
                        &request.items[index].expected,
                        108,
                    )
                    .unwrap();
                assert_eq!(proof.remaining_validity_seconds(108).unwrap(), 21);
                assert!(proof
                    .validate_for(
                        &request.items[(index + 1) % 64].original,
                        &request.items[index].expected,
                        108
                    )
                    .is_err());
                assert!(proof.remaining_validity_seconds(129).is_err());
            }
            VerifiedMirrorGuardBatchItem::Refused {
                original_digest,
                refusal,
            } => {
                assert_eq!(index, 15);
                assert_eq!(
                    original_digest,
                    digest(&request.items[15].original).unwrap()
                );
                assert_eq!(refusal, MirrorGuardBatchRefusal::Unavailable);
            }
        }
    }
    assert!(signed.body.len() <= MIRROR_GUARD_MAX_BYTES);
}

#[test]
fn physical_observation_binds_entire_outer_body_and_selected_index() {
    let request = request(2);
    let observation = MirrorGuardBatchObservation {
        version: 1,
        request_digest: digest(&request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        issuer: request.issuer.clone(),
        item_index: 0,
        result: positive(&request.items[0], 105),
        observed_at: 105,
    };
    let signed = sign_mirror_guard_batch_observation(&key(), &observation, &request).unwrap();
    assert_eq!(
        verify_mirror_guard_batch_observation(
            &key(),
            &signed.signature,
            &signed.body,
            &request,
            0,
            106
        )
        .unwrap(),
        observation
    );
    assert!(verify_mirror_guard_batch_observation(
        &key(),
        &signed.signature,
        &signed.body,
        &request,
        1,
        106
    )
    .is_err());
    let mut other = request.clone();
    other.items[1] = item(3);
    assert!(verify_mirror_guard_batch_observation(
        &key(),
        &signed.signature,
        &signed.body,
        &other,
        0,
        106
    )
    .is_err());
    assert!(verify_mirror_guard_batch_reply(
        &key(),
        &signed.signature,
        &signed.body,
        &request,
        106
    )
    .is_err());
    let producer = StorageWorkKey::new("producer-role-secret-00000000001").unwrap();
    assert!(verify_mirror_guard_batch_observation(
        &producer,
        &signed.signature,
        &signed.body,
        &request,
        0,
        106
    )
    .is_err());
}

#[test]
fn changed_nonce_order_incarnation_and_authenticated_noncanonical_body_refuse() {
    let request = request(2);
    let reply = reply(&request);
    let signed = sign_mirror_guard_batch_reply(&key(), &reply, &request).unwrap();
    for changed in 0..4 {
        let mut other = request.clone();
        match changed {
            0 => other.request_nonce = "66".repeat(32),
            1 => other.items.swap(0, 1),
            2 => other.expires_at = 129,
            _ => other.clock_uncertainty_seconds = 2,
        }
        assert!(verify_mirror_guard_batch_reply(
            &key(),
            &signed.signature,
            &signed.body,
            &other,
            108
        )
        .is_err());
    }
    let mut changed = reply.clone();
    let MirrorGuardBatchResult::Positive { progress, .. } = &mut changed.results[0] else {
        panic!("expected positive");
    };
    progress
        .destination
        .as_mut()
        .unwrap()
        .object
        .provider_version = Some("changed-incarnation".into());
    assert!(sign_mirror_guard_batch_reply(&key(), &changed, &request).is_err());
    changed = reply.clone();
    changed.results.pop();
    assert!(sign_mirror_guard_batch_reply(&key(), &changed, &request).is_err());
    changed = reply.clone();
    changed.observed_at = 104;
    assert!(sign_mirror_guard_batch_reply(&key(), &changed, &request).is_err());
    let mut noncanonical = signed.body.clone();
    noncanonical.push(b' ');
    let mac = key()
        .sign_body(&domain_body(REPLY_DOMAIN, &noncanonical))
        .unwrap();
    assert!(verify_mirror_guard_batch_reply(&key(), &mac, &noncanonical, &request, 108).is_err());
    assert!(verify_mirror_guard_batch_reply(
        &key(),
        &signed.signature,
        &signed.body,
        &request,
        130
    )
    .is_err());
    assert!(verify_mirror_guard_reply(
        &key(),
        &signed.signature,
        &signed.body,
        &request.item_lookup(0).unwrap(),
        108
    )
    .is_err());
}

#[test]
fn duplicate_empty_excessive_and_candidate_namespace_batches_refuse() {
    assert!(sign_mirror_guard_batch_lookup(&key(), &request(0)).is_err());
    assert!(sign_mirror_guard_batch_lookup(&key(), &request(65)).is_err());
    let mut repeated = request(2);
    repeated.items[1] = repeated.items[0].clone();
    assert!(sign_mirror_guard_batch_lookup(&key(), &repeated).is_err());
    let mut candidate = request(1);
    candidate.execution = MirrorGuardExecution::ControlledCandidate;
    candidate.issuer.script_version = format!("emulated-{}", candidate.issuer.source_digest);
    assert!(sign_mirror_guard_batch_lookup(&key(), &candidate).is_err());
    let oversized = vec![b' '; MIRROR_GUARD_MAX_BYTES + 1];
    assert!(
        verify_mirror_guard_batch_lookup(&key(), "", &oversized, "fixture-deployment", 105)
            .is_err()
    );
}
