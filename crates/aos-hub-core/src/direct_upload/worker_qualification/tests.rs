//! Independent acceptance signature and measured binding refusal tests.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn resign(artifact: &mut DirectWorkerQualificationArtifact) {
    artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
    let key = SigningKey::from_bytes(&[0x19; 32]);
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
}

#[test]
fn expired_guard_history_verifies_original_facts_without_qualifying_dispatch() {
    let (original, reviewer) = fixtures::direct_worker_qualification_fixture();
    let expiry = original.evidence.valid_until.get();
    original
        .verify_expired_guard_history(
            "deployment-1",
            "https://hub.example.test",
            &reviewer,
            expiry,
        )
        .unwrap();
    assert!(original
        .verify(
            "deployment-1",
            "https://hub.example.test",
            &reviewer,
            expiry
        )
        .is_err());
    assert!(original
        .verify_expired_guard_history("deployment-1", "https://hub.example.test", &reviewer, 100)
        .is_err());
    let mut invalid = original.clone();
    invalid.signature.replace_range(..2, "00");
    assert!(invalid
        .verify_expired_guard_history(
            "deployment-1",
            "https://hub.example.test",
            &reviewer,
            expiry
        )
        .is_err());
    let mut future = original.clone();
    future.evidence.issued_at = WireInteger::new(expiry + 10);
    resign(&mut future);
    assert!(future
        .verify_expired_guard_history(
            "deployment-1",
            "https://hub.example.test",
            &reviewer,
            expiry
        )
        .is_err());
    let mut changed_policy = original.clone();
    changed_policy.evidence.clock_policy.uncertainty_seconds = WireInteger::new(3);
    resign(&mut changed_policy);
    assert!(changed_policy
        .verify_expired_guard_history(
            "deployment-1",
            "https://hub.example.test",
            &reviewer,
            expiry
        )
        .is_err());
}

#[test]
fn metadata_qualification_uses_the_actual_narinfo_parser_size_bound() {
    let parser_limit = crate::fetch::MAX_CACHE_NARINFO_BYTES as u64;
    for runtime_limit in [parser_limit / 2, 1024 * 1024] {
        let required = runtime_limit.min(parser_limit);
        for observed in [required - 1, required] {
            let (mut artifact, key) = fixtures::direct_worker_qualification_fixture();
            artifact.evidence.runtime.maximum_object_bytes = WireInteger::new(runtime_limit);
            if let Some(limits) = &mut artifact.evidence.qualification_limits {
                limits.maximum_object_bytes = WireInteger::new(runtime_limit);
            }
            artifact
                .evidence
                .metadata_queue
                .maximum_verified_object_bytes = WireInteger::new(observed);
            resign(&mut artifact);

            assert_eq!(
                artifact
                    .verify("deployment-1", "https://hub.example.test", &key, 100)
                    .is_ok(),
                observed == required,
            );
        }
    }
}

#[test]
fn actual_public_refusal_classifications_bind_the_exact_managed_policy_readback() {
    for status in [401, 403, 404] {
        let (mut artifact, key) = fixtures::direct_worker_qualification_fixture();
        artifact
            .evidence
            .privacy
            .as_mut()
            .unwrap()
            .public_read_rejection_status = status;
        resign(&mut artifact);
        artifact
            .verify("deployment-1", "https://hub.example.test", &key, 100)
            .unwrap();
    }

    for mutation in 0..3 {
        let (mut artifact, key) = fixtures::direct_worker_qualification_fixture();
        let privacy = artifact.evidence.privacy.as_mut().unwrap();
        match mutation {
            0 => privacy.public_read_rejection_status = 400,
            1 => privacy.provider_bucket_name = "different-bucket".into(),
            2 => privacy.provider_policy_readback_sha256.clear(),
            _ => unreachable!(),
        }
        resign(&mut artifact);
        assert!(artifact
            .verify("deployment-1", "https://hub.example.test", &key, 100)
            .is_err());
    }
}

#[test]
fn unsigned_review_and_emulated_identity_never_supply_acceptance_authority() {
    let (mut artifact, key) = fixtures::direct_worker_qualification_fixture();
    artifact.signature.clear();
    artifact
        .validate_unsigned("deployment-1", "https://hub.example.test", 100)
        .unwrap();
    assert!(artifact
        .verify("deployment-1", "https://hub.example.test", &key, 100)
        .is_err());

    assert_eq!(
        direct_worker_emulated_script_id(&artifact.source_digest).unwrap(),
        format!("emulated-{}", artifact.source_digest),
    );
    assert!(direct_worker_emulated_script_id(&"AB".repeat(32)).is_err());
    assert!(direct_worker_emulated_script_id("configured-script").is_err());
    artifact.script_version = direct_worker_emulated_script_id(&artifact.source_digest).unwrap();
    resign(&mut artifact);
    assert!(artifact
        .verify("deployment-1", "https://hub.example.test", &key, 100)
        .is_err());
    assert!(emulated_dns_host("storage.example.test"));
    assert!(emulated_dns_host("localhost"));
    assert!(!emulated_dns_host("storage.example.com"));
    assert!(!emulated_dns_host("test"));
}

#[test]
fn verifies_independently_signed_exact_measured_profile_and_current_version() {
    let (artifact, key) = fixtures::direct_worker_qualification_fixture();

    artifact
        .verify("deployment-1", "https://hub.example.test", &key, 100)
        .unwrap();
    artifact
        .verify_runtime_identity(&artifact.source_digest, "script-1")
        .unwrap();

    assert!(artifact
        .verify_runtime_identity(&artifact.source_digest, "script-2")
        .is_err());
    assert!(artifact
        .verify_runtime_identity(&"ab".repeat(32), "script-1")
        .is_err());
    assert!(artifact
        .verify("deployment-2", "https://hub.example.test", &key, 100)
        .is_err());
    assert!(artifact
        .verify("deployment-1", "https://other.example.test", &key, 100)
        .is_err());
    assert!(artifact
        .verify(
            "deployment-1",
            "https://hub.example.test",
            &key,
            4_000_000_000
        )
        .is_err());
    assert!(artifact
        .verify(
            "deployment-1",
            "https://hub.example.test",
            &key,
            artifact.evidence.valid_until.get() - 1,
        )
        .is_err());
}

#[test]
fn changed_measurement_digest_and_self_selected_reviewer_cannot_enable_dispatch() {
    let (mut artifact, key) = fixtures::direct_worker_qualification_fixture();
    artifact.evidence.runtime.maximum_parallel_objects = WireInteger::new(8);
    artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();

    assert!(artifact
        .verify("deployment-1", "https://hub.example.test", &key, 100)
        .is_err());

    let attacker = SigningKey::from_bytes(&[0x42; 32]);
    artifact.signature = hex::encode(attacker.sign(&artifact.signing_bytes().unwrap()).to_bytes());
    assert!(artifact
        .verify("deployment-1", "https://hub.example.test", &key, 100)
        .is_err());
}

#[test]
fn even_trusted_signature_refuses_unknown_sdk_effects_or_inadequate_queue_capacity() {
    for mutation in 0..13 {
        let (mut artifact, key) = fixtures::direct_worker_qualification_fixture();
        match mutation {
            0 => {
                artifact
                    .evidence
                    .sdk_probe
                    .as_mut()
                    .unwrap()
                    .late_part_after_abort = "unknown_sdk_rejection".into()
            }
            1 => {
                artifact
                    .evidence
                    .sdk_probe
                    .as_mut()
                    .unwrap()
                    .ordinary_get_streamed_sha_size = "unsupported".into()
            }
            2 => artifact.evidence.bulk_queue.peak_parallel_objects = WireInteger::new(1),
            3 => {
                artifact.evidence.metadata_queue.queue_name =
                    artifact.evidence.bulk_queue.queue_name.clone()
            }
            4 => artifact.evidence.clock.expired_mutation_dispatches = WireInteger::new(1),
            5 => {
                artifact
                    .evidence
                    .privacy
                    .as_mut()
                    .unwrap()
                    .independent_writer_count = WireInteger::new(1)
            }
            6 => {
                artifact
                    .evidence
                    .managed_profile
                    .as_mut()
                    .unwrap()
                    .bucket_name = "different-bucket".into()
            }
            7 => artifact.execution_kind = DirectWorkerExecutionKind::EmulatedExternal,
            8 => artifact.evidence.runtime.maximum_parallel_provider_requests = WireInteger::new(1),
            9 => artifact.evidence.metadata_queue.peak_parallel_objects = WireInteger::new(1),
            10 => {
                artifact
                    .evidence
                    .metadata_queue
                    .metadata_progress_during_bulk = WireInteger::new(0)
            }
            11 => {
                artifact
                    .evidence
                    .metadata_queue
                    .delivery_policy
                    .maximum_batch_size = WireInteger::new(5)
            }
            12 => artifact
                .evidence
                .metadata_queue
                .configuration_readback_sha256
                .clear(),
            _ => unreachable!(),
        }
        resign(&mut artifact);

        assert!(
            artifact
                .verify("deployment-1", "https://hub.example.test", &key, 100)
                .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn closed_json_refuses_secret_fields_and_ambiguous_registry_coordinates() {
    let (artifact, _) = fixtures::direct_worker_qualification_fixture();
    let mut value = serde_json::to_value(artifact).unwrap();
    value["secretAccessKey"] = "private-marker".into();

    assert!(serde_json::from_value::<DirectWorkerQualificationArtifact>(value).is_err());
    assert!(
        direct_worker_acceptance_key("deployment/other", &"ab".repeat(32), "script-1").is_err()
    );
    assert_eq!(
        direct_worker_acceptance_key("deployment-1", &"ab".repeat(32), "script-1").unwrap(),
        format!(
            "aos.direct-upload.acceptance.v1/deployment-1/{}/script-1",
            "ab".repeat(32)
        )
    );
}
