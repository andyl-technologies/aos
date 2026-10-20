//! Original required-set, whole-profile and closed compact-wire binding tests.

use super::*;
use crate::direct_upload::capabilities_wire::tests::runtime_reference;

fn fixture() -> (
    DirectUploadAdmission,
    DirectCompleteRequest,
    DirectProtectedProfile,
) {
    let profile = DirectManagedR2Profile {
        deployment_id: "deployment".into(),
        account_id: "account".into(),
        bucket_name: "bucket".into(),
        bucket_namespace: "namespace".into(),
        credential_id: "credential".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "protected:1".into(),
        credential_fingerprint: "11".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: "22".repeat(32),
        clock_uncertainty_seconds: WireInteger::new(2),
    };
    let policy = DirectPrivateStagePolicyRef {
        policy_id: "private-policy".into(),
        policy_digest: "33".repeat(32),
        namespace: profile.bucket_namespace.clone(),
    };
    let protected =
        DirectProtectedProfile::managed(profile.clone(), policy.clone(), runtime_reference())
            .unwrap();
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: profile.credential_id.clone(),
        generation: profile.credential_generation,
        secret_version_ref: profile.secret_version_ref.clone(),
        credential_fingerprint: profile.credential_fingerprint.clone(),
    };
    let placements = (1..=2)
        .map(|id| DirectPlacement {
            placement_id: WireInteger::new(id),
            placement_resource_version: WireInteger::new(2),
            write_spec_version: WireInteger::new(3),
            binding_id: WireInteger::new(id),
            binding_resource_version: WireInteger::new(5),
            binding_write_revision: WireInteger::new(6),
            final_key: format!("cache/object/{id}"),
            staging_prefix: ".aos-direct-upload".into(),
            private_stage_policy: policy.clone(),
            protected_profile_digest: protected.digest().unwrap(),
            checksum_algorithm: profile.checksum_algorithm,
            physical: DirectPhysicalContext::DeploymentR2 {
                deployment_id: profile.deployment_id.clone(),
                bucket_namespace: profile.bucket_namespace.clone(),
            },
            write_credential: credential("write"),
            read_credential: credential("read"),
            presign_credential: credential("presign"),
        })
        .collect();
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(1),
        incarnation: "01234567-89ab-4def-8123-456789abcdef".into(),
    };
    let mut admission = DirectUploadAdmission {
        session_id: "session".into(),
        principal_id: actor_slot.principal_id("deployment").unwrap(),
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "44".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache".into(),
                path: "object".into(),
            },
            expected_sha256: "55".repeat(32),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(1000),
        placements,
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        },
        operation_id: "66".repeat(32),
        expected_resource_version: WireInteger::new(7),
        manifests: admission
            .placements
            .iter()
            .map(|placement| DirectManifestCommitment {
                placement: placement.public_ref("deployment").unwrap(),
                manifest_digest: "77".repeat(32),
                part_count: 1,
            })
            .collect(),
    };
    (admission, complete, protected)
}

fn selected(
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    protected: &DirectProtectedProfile,
) -> Result<DirectSelectedCompleteCommitment> {
    DirectSelectedCompleteCommitment::new(
        admission,
        complete,
        WireInteger::new(1),
        "deployment",
        protected,
    )
}

#[test]
fn selection_round_trips_and_binds_the_full_complete_and_whole_profile() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();

    assert_eq!(commitment.version, 1);
    assert_eq!(commitment.session, complete.session);
    assert_eq!(commitment.operation_id, complete.operation_id);
    assert_eq!(
        commitment.expected_resource_version,
        complete.expected_resource_version
    );
    assert_eq!(
        commitment.complete_intent_digest,
        complete.fingerprint().unwrap()
    );
    assert_eq!(commitment.manifest, complete.manifests[0]);
    assert_eq!(
        commitment.protected_profile_digest,
        protected.digest().unwrap()
    );
    assert_ne!(
        commitment.protected_profile_digest,
        commitment.manifest.placement.profile_fingerprint
    );

    let bytes = commitment.encode().unwrap();
    assert!(bytes.len() < MAX_DIRECT_SELECTED_COMPLETE_BYTES);
    let decoded = DirectSelectedCompleteCommitment::decode(&bytes).unwrap();
    assert_eq!(decoded, commitment);
    decoded
        .validate_for(&admission, &complete, "deployment", &protected)
        .unwrap();
}

#[test]
fn construction_and_validation_reject_incomplete_duplicate_unordered_and_foreign_required_sets() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();

    for case in ["missing", "duplicate", "unordered", "foreign", "geometry"] {
        let mut changed = complete.clone();
        match case {
            "missing" => {
                changed.manifests.pop();
            }
            "duplicate" => changed.manifests[1] = changed.manifests[0].clone(),
            "unordered" => changed.manifests.swap(0, 1),
            "foreign" => changed.manifests[1].placement.binding_id = WireInteger::new(99),
            "geometry" => changed.manifests[1].part_count = 2,
            _ => unreachable!(),
        }

        assert!(
            selected(&admission, &changed, &protected).is_err(),
            "{case}"
        );
        assert!(
            commitment
                .validate_for(&admission, &changed, "deployment", &protected)
                .is_err(),
            "{case}"
        );
    }

    assert!(DirectSelectedCompleteCommitment::new(
        &admission,
        &complete,
        WireInteger::new(3),
        "deployment",
        &protected
    )
    .is_err());
}

#[test]
fn retained_binding_rejects_changed_unselected_manifest_operation_cas_and_session() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();

    for case in [
        "unselected manifest",
        "operation",
        "CAS",
        "session",
        "admission fingerprint",
    ] {
        let mut changed = complete.clone();
        match case {
            "unselected manifest" => changed.manifests[1].manifest_digest = "88".repeat(32),
            "operation" => changed.operation_id = "99".repeat(32),
            "CAS" => changed.expected_resource_version = WireInteger::new(8),
            "session" => changed.session.session_id = "other-session".into(),
            "admission fingerprint" => changed.session.logical_fingerprint = "aa".repeat(32),
            _ => unreachable!(),
        }

        assert!(
            commitment
                .validate_for(&admission, &changed, "deployment", &protected)
                .is_err(),
            "{case}"
        );
    }
}

#[test]
fn selection_rejects_changed_admission_and_whole_profile_even_with_same_material_pin() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();
    let mut changed_admission = admission.clone();
    changed_admission.placements[1].final_key = "cache/other-object".into();

    assert!(selected(&changed_admission, &complete, &protected).is_err());
    assert!(commitment
        .validate_for(&changed_admission, &complete, "deployment", &protected)
        .is_err());
    changed_admission.logical_fingerprint = changed_admission.fingerprint("deployment").unwrap();
    assert!(selected(&changed_admission, &complete, &protected).is_err());

    let mut changed_profile = protected.clone();
    if let DirectProtectedProfile::Managed {
        runtime_qualification,
        ..
    } = &mut changed_profile
    {
        runtime_qualification.qualification_digest = "bb".repeat(32);
    }
    assert!(selected(&admission, &complete, &changed_profile).is_err());
    assert!(commitment
        .validate_for(&admission, &complete, "deployment", &changed_profile)
        .is_err());
}

#[test]
fn compact_wire_rejects_missing_unknown_duplicate_and_malformed_fields() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();
    let value = serde_json::to_value(&commitment).unwrap();

    for field in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            DirectSelectedCompleteCommitment::decode(&serde_json::to_vec(&missing).unwrap())
                .is_err(),
            "missing {field}"
        );
    }
    for field in ["sessionId", "logicalFingerprint"] {
        let mut missing = value.clone();
        missing["session"].as_object_mut().unwrap().remove(field);
        assert!(
            DirectSelectedCompleteCommitment::decode(&serde_json::to_vec(&missing).unwrap())
                .is_err(),
            "missing session {field}"
        );
    }
    for field in ["placement", "manifestDigest", "partCount"] {
        let mut missing = value.clone();
        missing["manifest"].as_object_mut().unwrap().remove(field);
        assert!(
            DirectSelectedCompleteCommitment::decode(&serde_json::to_vec(&missing).unwrap())
                .is_err(),
            "missing manifest {field}"
        );
    }

    for pointer in ["", "/session", "/manifest", "/manifest/placement"] {
        let mut unknown = value.clone();
        unknown
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        assert!(
            DirectSelectedCompleteCommitment::decode(&serde_json::to_vec(&unknown).unwrap())
                .is_err(),
            "unknown at {pointer}"
        );
    }
    for (old, duplicate) in [
        ("\"version\":1", "\"version\":1,\"version\":1"),
        ("\"partCount\":1", "\"partCount\":1,\"partCount\":1"),
        (
            "\"sessionId\":\"session\"",
            "\"sessionId\":\"session\",\"sessionId\":\"session\"",
        ),
    ] {
        let bytes = String::from_utf8(commitment.encode().unwrap()).unwrap();
        let changed = bytes.replacen(old, duplicate, 1);
        assert_ne!(bytes, changed);
        assert!(DirectSelectedCompleteCommitment::decode(changed.as_bytes()).is_err());
    }

    for (field, invalid) in [
        ("version", serde_json::json!(2)),
        ("operationId", serde_json::json!("invalid")),
        ("expectedResourceVersion", serde_json::json!("0")),
        ("completeIntentDigest", serde_json::json!("invalid")),
        ("protectedProfileDigest", serde_json::json!("invalid")),
    ] {
        let mut changed = value.clone();
        changed[field] = invalid;
        assert!(
            DirectSelectedCompleteCommitment::decode(&serde_json::to_vec(&changed).unwrap())
                .is_err(),
            "invalid {field}"
        );
    }
}

#[test]
fn compact_binding_rejects_each_changed_identity_field_against_the_originals() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();

    for case in [
        "session",
        "operation",
        "CAS",
        "intent digest",
        "manifest",
        "profile pin",
    ] {
        let mut changed = commitment.clone();
        match case {
            "session" => changed.session.session_id = "other-session".into(),
            "operation" => changed.operation_id = "88".repeat(32),
            "CAS" => changed.expected_resource_version = WireInteger::new(8),
            "intent digest" => changed.complete_intent_digest = "99".repeat(32),
            "manifest" => changed.manifest.manifest_digest = "aa".repeat(32),
            "profile pin" => changed.protected_profile_digest = "bb".repeat(32),
            _ => unreachable!(),
        }

        changed.validate().unwrap();
        assert!(
            changed
                .validate_for(&admission, &complete, "deployment", &protected)
                .is_err(),
            "{case}"
        );
    }
}

#[test]
fn maximum_required_fanout_still_encodes_only_one_manifest() {
    let (mut admission, mut complete, protected) = fixture();
    for id in 3..=MAX_DIRECT_PLACEMENTS as u64 {
        let mut placement = admission.placements[0].clone();
        placement.placement_id = WireInteger::new(id);
        placement.final_key = format!("cache/object/{id}");
        admission.placements.push(placement);
    }
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    complete.session.logical_fingerprint = admission.logical_fingerprint.clone();
    complete.manifests = admission
        .placements
        .iter()
        .map(|placement| DirectManifestCommitment {
            placement: placement.public_ref("deployment").unwrap(),
            manifest_digest: "77".repeat(32),
            part_count: 1,
        })
        .collect();

    let commitment = selected(&admission, &complete, &protected).unwrap();
    let bytes = commitment.encode().unwrap();

    assert!(bytes.len() < MAX_DIRECT_SELECTED_COMPLETE_BYTES);
    assert_eq!(
        commitment.complete_intent_digest,
        complete.fingerprint().unwrap()
    );
    assert_eq!(commitment.manifest, complete.manifests[0]);
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes)
        .unwrap()
        .get("manifests")
        .is_none());
}

#[test]
fn compact_wire_checks_raw_size_before_parsing() {
    let (admission, complete, protected) = fixture();
    let commitment = selected(&admission, &complete, &protected).unwrap();
    let mut padded = commitment.encode().unwrap();
    padded.resize(MAX_DIRECT_SELECTED_COMPLETE_BYTES, b' ');

    assert_eq!(
        DirectSelectedCompleteCommitment::decode(&padded).unwrap(),
        commitment
    );
    padded.push(b' ');
    assert!(DirectSelectedCompleteCommitment::decode(&padded).is_err());
}
