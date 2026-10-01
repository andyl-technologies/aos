//! Explicit test-only signed Worker acceptance fixtures.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

/// Builds a deterministic signed managed fixture for acceptance contract tests.
///
/// The signature uses a public test key and is not production evidence.
#[must_use]
pub fn direct_worker_qualification_fixture() -> (DirectWorkerQualificationArtifact, String) {
    let clock_policy = DirectClockPolicy {
        version: 1,
        mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: WireInteger::new(1),
    };
    let clock = DirectClockMeasurement {
        observation_sha256: "11".repeat(32),
        samples: WireInteger::new(16),
        maximum_observed_skew_millis: WireInteger::new(500),
        uncertainty_seconds: WireInteger::new(1),
        expired_mutation_dispatches: WireInteger::new(0),
    };
    let measurement = DirectRuntimeMeasurement {
        observation_sha256: "22".repeat(32),
        samples: WireInteger::new(16),
        maximum_verified_object_bytes: WireInteger::new(1024 * 1024),
        peak_parallel_objects: WireInteger::new(4),
        peak_parallel_provider_requests: WireInteger::new(8),
        maximum_verification_millis: WireInteger::new(1000),
        maximum_settlement_millis: WireInteger::new(500),
    };
    let runtime = DirectRuntimeQualification {
        version: 1,
        qualification_digest: direct_qualification_digest(&measurement).unwrap(),
        maximum_object_bytes: WireInteger::new(1024 * 1024),
        maximum_verification_seconds: WireInteger::new(2),
        settlement_reserve_seconds: WireInteger::new(1),
        maximum_parallel_objects: WireInteger::new(4),
        maximum_parallel_provider_requests: WireInteger::new(8),
        cache_destination_policy: DirectCacheDestinationPolicy::RetainedOriginalBaseline,
    };
    let privacy = DirectPrivacyMeasurement {
        observation_sha256: "33".repeat(32),
        namespace: "private-objects".into(),
        policy_id: "private-stage".into(),
        provider_account_id: "0123456789abcdef0123456789abcdef".into(),
        provider_bucket_name: "hub-private-objects".into(),
        public_endpoint: "https://disabled-public.example.test".into(),
        provider_policy_readback_sha256: "3a".repeat(32),
        public_read_rejection_status: 403,
        worker_namespace_rejection_status: 404,
        independent_writer_count: WireInteger::new(0),
    };
    let policy = DirectPrivateStagePolicyRef {
        policy_id: privacy.policy_id.clone(),
        namespace: privacy.namespace.clone(),
        policy_digest: direct_private_stage_policy_commitment(
            &privacy.policy_id,
            &privacy.namespace,
        )
        .unwrap(),
    };
    let mut profile = DirectManagedR2Profile {
        deployment_id: "deployment-1".into(),
        bucket_namespace: privacy.namespace.clone(),
        account_id: "0123456789abcdef0123456789abcdef".into(),
        bucket_name: "hub-private-objects".into(),
        credential_id: "persistent-direct".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "persistent-direct/v1".into(),
        credential_fingerprint: String::new(),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: clock_policy.commitment().unwrap(),
        clock_uncertainty_seconds: clock.uncertainty_seconds,
    };
    profile.credential_fingerprint = profile
        .fingerprint_with_credentials("test-access", "test-secret")
        .unwrap();
    let source_digest = "44".repeat(32);
    let script_version = "script-1".to_string();
    let queue = |phase: &str| DirectQueueMeasurement {
        delivery_policy: DirectQueueDeliveryPolicy {
            maximum_batch_size: WireInteger::new(if phase == "content" { 3 } else { 4 }),
            maximum_concurrent_invocations: Some(WireInteger::new(2)),
        },
        configuration_readback_sha256: "9a".repeat(32),
        observation_sha256: "55".repeat(32),
        queue_name: format!("direct-{phase}"),
        dependency_phase: phase.into(),
        completed_jobs: WireInteger::new(16),
        peak_parallel_objects: WireInteger::new(if phase == "content" { 3 } else { 4 }),
        maximum_verified_object_bytes: WireInteger::new(1024 * 1024),
        source_digest: source_digest.clone(),
        script_version: script_version.clone(),
        metadata_progress_during_bulk: WireInteger::new(if phase == "metadata" { 1 } else { 0 }),
        mixed_load_observation_sha256: (phase == "metadata").then(|| "9b".repeat(32)),
    };
    let sdk = DirectHostedSdkProbeDocument {
        version: 1,
        source_kind: "hosted_ordinary_r2_binding".into(),
        workers_rs_version: "0.8.5".into(),
        source_digest: source_digest.clone(),
        original: DirectHostedSdkProbeOriginal {
            run_id: "66".repeat(32),
            account_id: profile.account_id.clone(),
            bucket_name: profile.bucket_name.clone(),
            script_version: script_version.clone(),
            colo: "SJC".into(),
        },
        expected_sha256: "77".repeat(32),
        expected_byte_size: WireInteger::new(32768),
        upload_part_checksum_algorithm: DirectChecksumAlgorithm::Md5,
        source: DirectHostedSdkObjectReceipt {
            version: "object-1".into(),
            etag: "opaque-etag-1".into(),
            byte_size: WireInteger::new(32768),
        },
        destination: DirectHostedSdkObjectReceipt {
            version: "object-2".into(),
            etag: "opaque-etag-2".into(),
            byte_size: WireInteger::new(32768),
        },
        ordinary_create: "positive".into(),
        ordinary_complete: "positive".into(),
        ordinary_head: "positive".into(),
        ordinary_get_streamed_sha_size: "positive".into(),
        ordinary_range_streamed_sha_size: "positive".into(),
        ordinary_upload_part_streamed_copy: "positive".into(),
        ordinary_abort: "positive".into(),
        late_part_after_complete: "negative".into(),
        late_part_after_abort: "negative".into(),
        direct_s3_checksum_rejection_sha256: "88".repeat(32),
        cleanup_state: "retained_known_objects".into(),
    };
    let evidence = DirectWorkerQualificationEvidence {
        installation: None,
        clock_policy,
        qualification_limits: None,
        clock,
        runtime,
        runtime_measurement: measurement,
        managed_profile: Some(profile),
        private_stage_policy: Some(policy),
        external_profiles: Vec::new(),
        sdk_probe: Some(sdk),
        privacy: Some(privacy),
        bulk_queue: queue("content"),
        metadata_queue: queue("metadata"),
        issued_at: WireInteger::new(1),
        valid_until: WireInteger::new(4_000_000_000),
    };
    let mut artifact = DirectWorkerQualificationArtifact {
        version: 1,
        execution_kind: DirectWorkerExecutionKind::Hosted,
        deployment_id: "deployment-1".into(),
        reviewer_key_id: "qualification-reviewer-1".into(),
        public_origin: "https://hub.example.test".into(),
        workers_rs_version: "0.8.5".into(),
        source_digest,
        script_version,
        evidence_sha256: direct_qualification_digest(&evidence).unwrap(),
        evidence,
        signature: String::new(),
    };
    let key = SigningKey::from_bytes(&[0x19; 32]);
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
    (artifact, hex::encode(key.verifying_key().to_bytes()))
}
