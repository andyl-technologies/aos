//! Test-only original identities shared by native SQLite and Worker fixtures.

use aos_hub_core::direct_upload::*;
use sha2::{Digest as _, Sha256};

use super::state::{Reservation, Source};

pub(crate) fn reservation(deployment: &str, final_key: &str) -> Reservation {
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "fixture-credential".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "fixture:1".into(),
        credential_fingerprint: "11".repeat(32),
    };
    let placement = DirectPlacement {
        placement_id: WireInteger::new(1),
        placement_resource_version: WireInteger::new(2),
        write_spec_version: WireInteger::new(3),
        binding_id: WireInteger::new(4),
        binding_resource_version: WireInteger::new(5),
        binding_write_revision: WireInteger::new(6),
        final_key: final_key.into(),
        staging_prefix: ".aos-direct-upload/fixture".into(),
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "fixture-private".into(),
            policy_digest: "22".repeat(32),
            namespace: "fixture-namespace".into(),
        },
        protected_profile_digest: "33".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        physical: DirectPhysicalContext::DeploymentR2 {
            deployment_id: deployment.into(),
            bucket_namespace: "fixture-namespace".into(),
        },
        write_credential: credential("write"),
        read_credential: credential("read"),
        presign_credential: credential("presign"),
    };
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(1),
        incarnation: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "fixture-session".into(),
        principal_id: actor_slot.principal_id(deployment).unwrap(),
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "44".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "fixture-cache".into(),
                path: "fixture-object".into(),
            },
            expected_sha256: hex::encode(Sha256::digest(b"x")),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(1_900_000_000),
        placements: vec![placement.clone()],
    };
    admission.logical_fingerprint = admission.fingerprint(deployment).unwrap();
    let session = DirectSessionRef {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
    };
    let manifest = DirectManifestCommitment {
        placement: placement.public_ref(deployment).unwrap(),
        manifest_digest: "66".repeat(32),
        part_count: 1,
    };
    let complete = DirectCompleteRequest {
        session: session.clone(),
        operation_id: "77".repeat(32),
        expected_resource_version: WireInteger::new(7),
        manifests: vec![manifest.clone()],
    };
    let selected = DirectSelectedCompleteCommitment {
        version: 1,
        session: session.clone(),
        operation_id: complete.operation_id.clone(),
        expected_resource_version: complete.expected_resource_version,
        complete_intent_digest: complete.fingerprint().unwrap(),
        manifest,
        protected_profile_digest: placement.protected_profile_digest.clone(),
    };
    let binding = DirectDestinationBaselineBinding {
        deployment_id: deployment.into(),
        session,
        admission_expires_at: admission.expires_at,
        complete_operation_id: complete.operation_id.clone(),
        complete_intent_digest: complete.fingerprint().unwrap(),
        placement: selected.manifest.placement.clone(),
        protected_profile_digest: selected.protected_profile_digest.clone(),
        final_key_digest: direct_destination_key_digest(final_key).unwrap(),
        scope: DirectDestinationReservationScope::Managed {
            bucket_namespace: "fixture-namespace".into(),
        },
        reservation_operation_id: direct_destination_promotion_operation_id(
            &complete.session,
            placement.placement_id,
            &complete.operation_id,
        )
        .unwrap(),
        reservation_nonce: "88".repeat(32),
        reservation_revision: WireInteger::new(1),
    };
    let source = Source {
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        incarnation: DirectObjectIncarnation::ProviderVersion {
            version: "fixture-source-version".into(),
        },
    };
    let baseline = DirectDestinationBaselineEvidence {
        binding: binding.clone(),
        observation_operation_id: "99".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
        state: DirectDestinationBaselineState::Missing {},
    };
    Reservation {
        admission,
        complete,
        selected,
        binding,
        source,
        baseline: Some(baseline),
        final_record: None,
        native_committed: false,
    }
}

pub(crate) fn final_record(owner: &Reservation) -> DirectFinalGuardRecord {
    DirectFinalGuardRecord {
        version: 1,
        reservation: owner.binding.clone(),
        selected: owner.selected.clone(),
        sha256: owner.source.sha256.clone(),
        byte_size: owner.source.byte_size,
        source_incarnation: owner.source.incarnation.clone(),
        final_incarnation: DirectObjectIncarnation::ProviderVersion {
            version: "fixture-final-version".into(),
        },
        final_etag: "\"fixture-final-etag\"".into(),
    }
}

pub(super) fn changed_complete(owner: &Reservation) -> Reservation {
    let mut changed = owner.clone();
    changed.complete.expected_resource_version = WireInteger::new(8);
    changed.selected.expected_resource_version = changed.complete.expected_resource_version;
    let digest = changed.complete.fingerprint().unwrap();
    changed.selected.complete_intent_digest = digest.clone();
    changed.binding.complete_intent_digest = digest;
    if let Some(baseline) = &mut changed.baseline {
        baseline.binding = changed.binding.clone();
    }
    changed.validate().unwrap();
    changed
}
