//! Test-only reviewer signatures and measured-envelope contract regressions.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::direct_upload::{
    DirectCacheDestinationPolicy, DirectChecksumAlgorithm, DirectRuntimeQualification, WireInteger,
};
use crate::mirror_work::{
    digest, MirrorOriginal, MirrorPart, MirrorProgress, MirrorVerification, MirrorVerifiedObject,
};
use crate::storage_work::StorageObjectIdentity;

fn profile() -> DirectProtectedProfile {
    let raw = DirectManagedR2Profile {
        deployment_id: "deployment-1".into(),
        account_id: "0123456789abcdef0123456789abcdef".into(),
        bucket_name: "mirror-test-bucket".into(),
        bucket_namespace: "mirror-test-namespace".into(),
        credential_id: "mirror-test-material".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "mirror-test-material/v1".into(),
        credential_fingerprint: "11".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: "22".repeat(32),
        clock_uncertainty_seconds: WireInteger::new(1),
    };
    DirectProtectedProfile::managed(
        raw,
        DirectPrivateStagePolicyRef {
            policy_id: "mirror-test-policy".into(),
            policy_digest: "33".repeat(32),
            namespace: "mirror-test-namespace".into(),
        },
        DirectRuntimeQualification {
            version: 1,
            qualification_digest: "44".repeat(32),
            maximum_object_bytes: WireInteger::new(MIRROR_MAX_OBJECT_BYTES),
            maximum_verification_seconds: WireInteger::new(2),
            settlement_reserve_seconds: WireInteger::new(1),
            maximum_parallel_objects: WireInteger::new(4),
            maximum_parallel_provider_requests: WireInteger::new(8),
            cache_destination_policy: DirectCacheDestinationPolicy::RetainedOriginalBaseline,
        },
    )
    .unwrap()
}

pub(super) fn roundtrip(
    kind: &str,
    profile_digest: &str,
    prefix: &str,
) -> MirrorRoundtripMeasurement {
    let sha = "55".repeat(32);
    let verification = if kind == "metadata" {
        MirrorVerification::Sha256 {
            sha256: sha.clone(),
            size: 8,
        }
    } else {
        MirrorVerification::Nar {
            file_sha256: Some(sha.clone()),
            file_size: 8,
            compression: kind.into(),
            nar_sha256: sha.clone(),
            nar_size: 8,
        }
    };
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: None,
        registry_id: 1,
        registry_resource_version: 1,
        mirror_resource_version: 1,
        upstream_base: "https://mirror.example.org/".into(),
        path: format!("{kind}.nar"),
        placement_id: 1,
        placement_resource_version: 1,
        write_spec_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        placement_prefix: prefix.into(),
        protected_profile_digest: profile_digest.into(),
        verification,
    };
    original.job_id = original.identity().unwrap();
    let identity = |key: String, version: &str| StorageObjectIdentity {
        key,
        size: 8,
        etag: "\"test-etag\"".into(),
        provider_version: Some(version.into()),
    };
    let object = identity(original.stage_key(), "stage-version");
    let verified = MirrorVerifiedObject {
        object: object.clone(),
        sha256: sha.clone(),
        nar_sha256: (kind != "metadata").then(|| sha.clone()),
        nar_size: (kind != "metadata").then_some(8),
    };
    let mut destination = verified.clone();
    destination.object = identity(
        crate::keymap::r2_key(prefix, &original.path),
        "final-version",
    );
    let part = MirrorPart {
        part_number: 1,
        size: 8,
        sha256: sha.clone(),
        etag: "\"part-etag\"".into(),
    };
    let progress = MirrorProgress {
        original_digest: digest(&original).unwrap(),
        upstream_etag: None,
        stage_upload_id: Some("stage-upload".into()),
        stage_parts: vec![part.clone()],
        stage_object: Some(object),
        verified: Some(verified),
        destination_upload_id: Some("final-upload".into()),
        destination_parts: vec![part],
        destination: Some(destination),
    };
    MirrorRoundtripMeasurement {
        commit_digest: progress.commit_digest(&original).unwrap(),
        original,
        progress,
        readback_sha256: sha,
        readback_bytes: 8,
        observation_sha256: "66".repeat(32),
    }
}

pub(super) fn artifact() -> MirrorAcceptanceArtifact {
    use MirrorSafetyCase::*;
    let profile = profile();
    let pin = profile.digest().unwrap();
    let hash = "77".repeat(32);
    let cases = [
        UnknownCreate,
        UnknownPart,
        UnknownClose,
        UnknownPromotion,
        UnknownCleanup,
        PositivePrefixReplay,
        LostNativeAcknowledgement,
        ArchivedAcknowledgement,
        Restart,
        ChangedBinding,
        ChangedSource,
        NativeRevocation,
        ExpiredPlan,
        PrivateNamespace,
        MetadataDuringBulk,
    ];
    MirrorAcceptanceArtifact {
        version: 1,
        purpose: MirrorAcceptancePurpose::ManagedR2MirrorV1,
        execution: MirrorAcceptanceExecution::Hosted,
        reviewer_key_id: "mirror-reviewer".into(),
        deployment_id: "deployment-1".into(),
        public_origin: "https://hub.example.org".into(),
        workers_rs_version: "0.8.5".into(),
        source_digest: "88".repeat(32),
        script_version: "script-version-1".into(),
        protected_profile: Some(profile),
        candidate_profile: None,
        direct_evidence_sha256: Some("99".repeat(32)),
        geometry: MirrorProducerGeometry::current(),
        maximum_object_bytes: MIRROR_MAX_OBJECT_BYTES,
        issued_at: 100,
        valid_until: 200,
        signature: String::new(),
        evidence: MirrorAcceptanceEvidence {
            report_sha256: hash.clone(),
            roundtrips: ["none", "zstd", "metadata"]
                .into_iter()
                .map(|kind| roundtrip(kind, &pin, "final"))
                .collect(),
            workload: MirrorWorkloadMeasurement {
                observation_sha256: hash.clone(),
                large_objects: 3,
                metadata_objects: 1000,
                maximum_encoded_bytes: MIRROR_MAX_OBJECT_BYTES,
                maximum_plain_bytes: MIRROR_MAX_OBJECT_BYTES,
                peak_provider_requests: 8,
                metadata_completed_during_bulk: 1,
                native_bulk_bytes: 0,
                maximum_native_control_bytes: 4096,
                maximum_control_millis: 10,
                maximum_step_wall_millis: 100,
                maximum_step_cpu_millis: 10,
                installed_cpu_limit_millis: 1000,
            },
            safety: cases
                .into_iter()
                .map(|case| MirrorSafetyMeasurement {
                    case,
                    observation_sha256: hash.clone(),
                    samples: 1,
                    violations: 0,
                })
                .collect(),
            memory: MirrorMemoryMeasurement {
                observation_sha256: hash.clone(),
                samples: 4,
                peak_worker_bytes: 64 * 1024 * 1024,
                peak_bulk_buffered_producers: 1,
                peak_metadata_buffered_producers_during_bulk: 2,
                peak_rust_part_bytes: MIRROR_PART_BYTES,
                peak_js_sdk_bytes: 16 * 1024 * 1024,
                peak_decoder_window_bytes: 8 * 1024 * 1024,
            },
            release: MirrorReleaseMeasurement {
                release_pack_sha256: hash.clone(),
                wasm_sha256: hash.clone(),
                script_sha256: hash.clone(),
                compressed_script_sha256: hash.clone(),
                script_bytes: 1024 * 1024,
                compressed_script_bytes: 128 * 1024,
                observation_sha256: hash,
                cold_start_samples: 4,
                maximum_startup_millis: 100,
            },
        },
    }
}

fn sign(artifact: &mut MirrorAcceptanceArtifact) -> String {
    let key = SigningKey::from_bytes(&[0xa1; 32]);
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
    hex::encode(key.verifying_key().to_bytes())
}

fn production(artifact: &MirrorAcceptanceArtifact, key: &str) -> Result<()> {
    artifact.require_production(
        "deployment-1",
        "https://hub.example.org",
        &"88".repeat(32),
        "script-version-1",
        &profile(),
        &"99".repeat(32),
        key,
        150,
    )
}

#[test]
fn unsigned_foreign_purpose_and_direct_domain_do_not_authorize_mirror() {
    let mut value = artifact();
    value.validate_unsigned(150).unwrap();
    let key = sign(&mut value);
    production(&value, &key).unwrap();

    value.signature.clear();
    assert!(production(&value, &key).is_err());
    let mut json = serde_json::to_value(&value).unwrap();
    json["purpose"] = serde_json::json!("direct_upload");
    assert!(serde_json::from_value::<MirrorAcceptanceArtifact>(json).is_err());

    let signer = SigningKey::from_bytes(&[0xa1; 32]);
    let direct_bytes = [
        b"aos.direct-upload.accepted-worker-qualification.v1\0".as_slice(),
        &value.signing_bytes().unwrap(),
    ]
    .concat();
    value.signature = hex::encode(signer.sign(&direct_bytes).to_bytes());
    assert!(production(&value, &key).is_err());
}

#[test]
fn every_current_pin_is_independently_compared_after_valid_review_signature() {
    for change in 0..7 {
        let mut value = artifact();
        match change {
            0 => value.source_digest = "aa".repeat(32),
            1 => value.script_version = "new-script".into(),
            2 => value.direct_evidence_sha256 = Some("aa".repeat(32)),
            3 => value.public_origin = "https://other.example.org".into(),
            4 => value.reviewer_key_id.clear(),
            5 => value.valid_until = 150,
            _ => {
                if let Some(DirectProtectedProfile::Managed {
                    runtime_qualification,
                    ..
                }) = &mut value.protected_profile
                {
                    runtime_qualification.qualification_digest = "aa".repeat(32);
                }
            }
        }
        let key = sign(&mut value);
        assert!(production(&value, &key).is_err(), "changed pin {change}");
    }
}

#[test]
fn hosted_acceptance_requires_full_workload_memory_release_and_all_safety_cases() {
    for change in 0..14 {
        let mut value = artifact();
        match change {
            0 => value.evidence.workload.large_objects = 2,
            1 => value.evidence.workload.metadata_objects = 999,
            2 => value.evidence.safety.pop().map(|_| ()).unwrap(),
            3 => value.evidence.safety[0].violations = 1,
            4 => value.evidence.memory.peak_worker_bytes = 128 * 1024 * 1024,
            5 => value.evidence.memory.peak_bulk_buffered_producers = 4,
            6 => value.evidence.memory.peak_js_sdk_bytes = 0,
            7 => value.evidence.release.maximum_startup_millis = 1001,
            8 => value.evidence.release.script_bytes = 64 * 1024 * 1024 + 1,
            9 => value.evidence.workload.native_bulk_bytes = 1,
            10 => value.evidence.workload.peak_provider_requests = 7,
            11 => {
                value
                    .evidence
                    .memory
                    .peak_metadata_buffered_producers_during_bulk = 1
            }
            12 => value.evidence.workload.maximum_step_wall_millis = 600_001,
            _ => value.evidence.workload.maximum_step_cpu_millis = 1001,
        }
        let key = sign(&mut value);
        assert!(
            production(&value, &key).is_err(),
            "missing observed gate {change}"
        );
    }
}

#[test]
fn controlled_raw_profile_can_be_reviewed_but_never_grants_production() {
    let mut value = artifact();
    let DirectProtectedProfile::Managed {
        profile: raw,
        private_stage_policy,
        ..
    } = value.protected_profile.take().unwrap()
    else {
        panic!("managed fixture");
    };
    let pin = mirror_candidate_profile_digest(&raw, &private_stage_policy).unwrap();
    assert_ne!(pin, profile().digest().unwrap());
    value.candidate_profile = Some(MirrorCandidateProfile {
        profile: raw,
        private_stage_policy,
    });
    value.direct_evidence_sha256 = None;
    value.execution = MirrorAcceptanceExecution::Controlled;
    value.script_version = direct_worker_emulated_script_id(&value.source_digest).unwrap();
    value.evidence.roundtrips = ["none", "zstd", "metadata"]
        .into_iter()
        .map(|kind| roundtrip(kind, &pin, ".aos-mirror-qualification/test-run/final"))
        .collect();
    let key = sign(&mut value);
    value.verify(&key, 150).unwrap();
    assert!(production(&value, &key).is_err());

    value.evidence.roundtrips[0] = roundtrip("none", &pin, "public-final");
    sign(&mut value);
    assert!(value.verify(&key, 150).is_err());
}

#[test]
fn positive_final_readback_and_ack_are_bound_to_canonical_originals() {
    for change in 0..4 {
        let mut value = artifact();
        let sample = &mut value.evidence.roundtrips[0];
        match change {
            0 => sample.readback_sha256 = "aa".repeat(32),
            1 => sample.commit_digest = "aa".repeat(32),
            2 => {
                sample
                    .progress
                    .destination
                    .as_mut()
                    .unwrap()
                    .object
                    .provider_version = None
            }
            _ => sample.original.binding_resource_version += 1,
        }
        let key = sign(&mut value);
        assert!(production(&value, &key).is_err());
    }
}

#[test]
fn review_cutoff_is_rechecked_after_capacity_wait_without_renewal() {
    let mut value = artifact();
    let key = sign(&mut value);
    production(&value, &key).unwrap();

    value.validate_dispatch_time(199).unwrap();
    assert!(value.validate_dispatch_time(200).is_err());
    assert!(value.validate_dispatch_time(99).is_err());
    assert_eq!(value.valid_until, 200);
}
