//! Independent acceptance signature and measured binding refusal tests.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn resign(artifact: &mut DirectWorkerQualificationArtifact) {
    artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
    let key = SigningKey::from_bytes(&[0x19; 32]);
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
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
    for mutation in 0..9 {
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
