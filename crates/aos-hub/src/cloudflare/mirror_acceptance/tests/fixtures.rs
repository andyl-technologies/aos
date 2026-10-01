//! Synthetic closed measurement envelopes for installer contract tests.
//! These public test-key signatures are not provider or hosted evidence.

use aos_hub_core::mirror_acceptance::pack::*;
use ed25519_dalek::{Signer as _, SigningKey};

use aos_hub_core::direct_upload::{
    DirectCacheDestinationPolicy, DirectChecksumAlgorithm, DirectRuntimeQualification, WireInteger,
};
use aos_hub_core::direct_upload::{
    DirectManagedR2Profile, DirectPrivateStagePolicyRef, DirectProtectedProfile,
};
use aos_hub_core::mirror_acceptance::*;
use aos_hub_core::mirror_work::{
    digest, MirrorOriginal, MirrorPart, MirrorProgress, MirrorVerification, MirrorVerifiedObject,
    MIRROR_MAX_OBJECT_BYTES, MIRROR_PART_BYTES,
};
use aos_hub_core::storage_work::StorageObjectIdentity;

pub(super) fn profile() -> DirectProtectedProfile {
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
        aos_hub_core::keymap::r2_key(prefix, &original.path),
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

pub(super) fn pack_artifact(
    mirror: &MirrorAcceptanceArtifact,
    key: &SigningKey,
) -> MirrorPackAcceptanceArtifact {
    use aos_hub_core::mirror_acceptance::pack::MirrorPackSafetyCase::*;
    let geometry = MirrorPackGeometry::current();
    let cases = [
        BaseSelection,
        OffsetDeltaSelection,
        ReferenceDeltaSelection,
        EncodedChecksumRefusal,
        IndexCrcRefusal,
        SelectedOidRefusal,
        EncodedLimitRefusal,
        DecodedLimitRefusal,
        ExpiredReadRefusal,
        MetadataDuringInspection,
    ];
    let mut result = MirrorPackAcceptanceArtifact {
        version: 1,
        purpose: MirrorPackAcceptancePurpose::ManagedR2PackInspectionV1,
        execution: mirror.execution,
        mirror_artifact_sha256: digest(mirror).unwrap(),
        source_digest: mirror.source_digest.clone(),
        script_version: mirror.script_version.clone(),
        report_sha256: "aa".repeat(32),
        pairs: cases[..3]
            .iter()
            .map(|case| MirrorPackPairMeasurement {
                case: *case,
                observation_sha256: "bb".repeat(32),
                pack_sha256: "cc".repeat(32),
                index_sha256: "dd".repeat(32),
                pack_trailer_sha256: "ee".repeat(32),
                pack_bytes: geometry.pack_bytes,
                index_bytes: 2 * 1024 * 1024,
                peak_decoded_graph_bytes: geometry.decoded_graph_bytes,
                maximum_object_bytes: geometry.object_bytes,
                selected_oids: vec!["ff".repeat(32)],
                selected_result_sha256: "11".repeat(32),
                selected_bytes: 128 * 1024,
            })
            .collect(),
        safety: cases
            .iter()
            .map(|case| MirrorPackSafetyMeasurement {
                case: *case,
                observation_sha256: "22".repeat(32),
                query_sha256: "33".repeat(32),
                result_sha256: "44".repeat(32),
                samples: 1,
                violations: 0,
                provider_dispatches: if *case == ExpiredReadRefusal { 0 } else { 2 },
            })
            .collect(),
        geometry,
        memory_observation_sha256: "55".repeat(32),
        peak_worker_bytes: 64 * 1024 * 1024,
        memory_samples: 3,
        peak_wasm_bytes: 32 * 1024 * 1024,
        peak_js_sdk_bytes: 16 * 1024 * 1024,
        metadata_completed_during_inspection: 2,
        maximum_provider_requests: 3,
        native_bulk_bytes: 0,
        maximum_cpu_millis: 500,
        maximum_wall_millis: 1500,
        cpu_limit_millis: 1000,
        release_pack_sha256: mirror.evidence.release.release_pack_sha256.clone(),
        issued_at: 100,
        valid_until: 200,
        signature: String::new(),
    };
    sign(&mut result, key);
    result
}

fn sign(artifact: &mut MirrorPackAcceptanceArtifact, key: &SigningKey) {
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
}
