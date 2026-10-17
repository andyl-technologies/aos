//! Baseline commitment, exact reservation correlation and current witness gates.

mod observation;

use super::*;
use crate::storage_work::StorageWorkKey;

fn fixture() -> (
    DirectUploadAdmission,
    DirectCompleteRequest,
    DirectDestinationBaselineEvidence,
    DirectRequestContext,
) {
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: "profile".into(),
        generation: WireInteger::new(1),
        secret_version_ref: "protected:1".into(),
        credential_fingerprint: "11".repeat(32),
    };
    let placement = DirectPlacement {
        placement_id: WireInteger::new(1),
        placement_resource_version: WireInteger::new(2),
        write_spec_version: WireInteger::new(3),
        binding_id: WireInteger::new(4),
        binding_resource_version: WireInteger::new(5),
        binding_write_revision: WireInteger::new(6),
        final_key: "cache/object".into(),
        staging_prefix: ".aos-direct-upload".into(),
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "reviewed".into(),
            policy_digest: "22".repeat(32),
            namespace: "private".into(),
        },
        protected_profile_digest: "12".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        physical: DirectPhysicalContext::DeploymentR2 {
            deployment_id: "deployment".into(),
            bucket_namespace: "permanent-bucket".into(),
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
        session_id: "session".into(),
        principal_id: actor_slot.principal_id("deployment").unwrap(),
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "33".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache".into(),
                path: "object".into(),
            },
            expected_sha256: "44".repeat(32),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: WireInteger::new(1000),
        placements: vec![placement.clone()],
    };
    admission.logical_fingerprint = admission.fingerprint("deployment").unwrap();
    let complete = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        },
        operation_id: "55".repeat(32),
        expected_resource_version: WireInteger::new(7),
        manifests: vec![DirectManifestCommitment {
            placement: placement.public_ref("deployment").unwrap(),
            manifest_digest: "66".repeat(32),
            part_count: 1,
        }],
    };
    let baseline = DirectDestinationBaselineEvidence {
        binding: DirectDestinationBaselineBinding {
            deployment_id: "deployment".into(),
            session: complete.session.clone(),
            admission_expires_at: admission.expires_at,
            complete_operation_id: complete.operation_id.clone(),
            complete_intent_digest: complete.fingerprint().unwrap(),
            placement: complete.manifests[0].placement.clone(),
            protected_profile_digest: "12".repeat(32),
            final_key_digest: direct_destination_key_digest(&placement.final_key).unwrap(),
            scope: DirectDestinationReservationScope::Managed {
                bucket_namespace: "permanent-bucket".into(),
            },
            reservation_operation_id: direct_destination_promotion_operation_id(
                &complete.session,
                complete.manifests[0].placement.placement_id,
                &complete.operation_id,
            )
            .unwrap(),
            reservation_nonce: "88".repeat(32),
            reservation_revision: WireInteger::new(1),
        },
        observation_operation_id: "99".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(120),
        state: DirectDestinationBaselineState::Missing {},
    };
    let context = DirectRequestContext {
        deployment_id: "deployment".into(),
        executor_public_origin: "https://executor.test".into(),
        foreground: super::super::DirectForegroundBudget {
            invocation_id: "aa".repeat(32),
            issued_at: WireInteger::new(200),
            expires_at: WireInteger::new(230),
        },
        public_authority: "executor.test".into(),
        request_nonce: "aa".repeat(32),
        request_body_sha256: "bb".repeat(32),
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
        issued_at: WireInteger::new(200),
        expires_at: WireInteger::new(230),
    };
    (admission, complete, baseline, context)
}

fn witness(baseline: &DirectDestinationBaselineEvidence) -> DirectDestinationBaselineWitness {
    DirectDestinationBaselineWitness {
        binding: baseline.binding.clone(),
        baseline_digest: baseline.fingerprint().unwrap(),
        observation_operation_id: "cc".repeat(32),
        issued_at: WireInteger::new(201),
        expires_at: WireInteger::new(220),
    }
}

#[test]
fn immutable_missing_and_held_legacy_present_do_not_mint_stamps() {
    let (admission, complete, mut baseline, _) = fixture();
    baseline
        .validate_for(&admission, &complete, "deployment", &"12".repeat(32))
        .unwrap();
    let missing = baseline.fingerprint().unwrap();
    assert!(
        !String::from_utf8(encode_direct_control(&baseline).unwrap())
            .unwrap()
            .contains("guardStamp")
    );

    baseline.state = DirectDestinationBaselineState::Present {
        byte_size: WireInteger::new(5),
        sha256: "dd".repeat(32),
        etag: "\"strong\"".into(),
        provider_version: None,
        guard_stamp: None,
    };
    baseline
        .validate_for(&admission, &complete, "deployment", &"12".repeat(32))
        .unwrap();
    assert_ne!(baseline.fingerprint().unwrap(), missing);
    if let DirectDestinationBaselineState::Present { sha256, .. } = &mut baseline.state {
        sha256.clear();
    }
    assert!(baseline.validate().is_err());

    assert_eq!(
        serde_json::to_string(&DirectDestinationBaselineState::Missing {}).unwrap(),
        r#"{"kind":"missing"}"#
    );

    let raw = br#"{"kind":"missing","sha256":"invented"}"#;
    assert!(serde_json::from_slice::<DirectDestinationBaselineState>(raw).is_err());
    let raw = br#"{"kind":"missing","guardStamp":null}"#;
    assert!(serde_json::from_slice::<DirectDestinationBaselineState>(raw).is_err());
}

#[test]
fn original_baseline_is_not_renewed_by_a_fresh_witness() {
    let (_, _, baseline, context) = fixture();
    let original = encode_direct_control(&baseline).unwrap();
    let witness = witness(&baseline);
    // The first document is historical here; only this distinct live witness has a fresh interval.
    witness.validate_for(&baseline, &context, 202).unwrap();
    assert_eq!(encode_direct_control(&baseline).unwrap(), original);
    assert!(witness.validate_for(&baseline, &context, 220).is_err());
    assert!(witness.validate_for(&baseline, &context, 200).is_err());
    let mut shortened = baseline.clone();
    shortened.binding.admission_expires_at = WireInteger::new(219);
    let outside_original = DirectDestinationBaselineWitness {
        binding: shortened.binding.clone(),
        baseline_digest: shortened.fingerprint().unwrap(),
        ..witness.clone()
    };
    assert!(outside_original.validate().is_err());
    assert!(outside_original
        .validate_for(&shortened, &context, 202)
        .is_err());

    let mut changed = witness.clone();
    changed.expires_at = WireInteger::new(231);
    assert!(changed.validate_for(&baseline, &context, 202).is_err());
    changed = witness.clone();
    changed.observation_operation_id = baseline.observation_operation_id.clone();
    assert!(changed.validate_for(&baseline, &context, 202).is_err());
    changed = witness.clone();
    changed.observation_operation_id = baseline.binding.reservation_operation_id.clone();
    assert!(changed.validate().is_err());
    assert!(changed.validate_for(&baseline, &context, 202).is_err());
    changed = witness.clone();
    changed.binding.reservation_nonce = "ee".repeat(32);
    assert!(changed.validate_for(&baseline, &context, 202).is_err());
    changed = witness;
    changed.binding.reservation_revision = WireInteger::new(2);
    assert!(changed.validate_for(&baseline, &context, 202).is_err());
}

#[test]
fn baseline_commits_original_cas_manifest_final_key_and_physical_domain() {
    let (admission, complete, baseline, _) = fixture();
    for mutate in [0, 1, 2, 3, 4] {
        let mut changed = baseline.clone();
        match mutate {
            0 => changed.binding.final_key_digest = "ee".repeat(32),
            1 => changed.binding.complete_intent_digest = "ee".repeat(32),
            2 => changed.binding.placement.binding_write_revision = WireInteger::new(7),
            3 => {
                changed.binding.scope = DirectDestinationReservationScope::Managed {
                    bucket_namespace: "rebound".into(),
                }
            }
            _ => changed.binding.session.logical_fingerprint = "ee".repeat(32),
        }
        assert!(changed
            .validate_for(&admission, &complete, "deployment", &"12".repeat(32))
            .is_err());
        if let Ok(changed_digest) = changed.fingerprint() {
            assert_ne!(changed_digest, baseline.fingerprint().unwrap());
        }
    }
    let mut changed = baseline.clone();
    changed.binding.reservation_revision = WireInteger::new(0);
    assert!(changed.validate().is_err());
    changed = baseline;
    changed.expires_at = WireInteger::new(1001);
    assert!(changed
        .validate_for(&admission, &complete, "deployment", &"12".repeat(32))
        .is_err());
    assert!(direct_destination_key_digest("cache/../object").is_err());
    assert_ne!(
        direct_destination_key_digest("cache/object").unwrap(),
        direct_destination_key_digest("cache/objects").unwrap()
    );
}

#[test]
fn original_admission_retains_whole_profile_without_default_or_replay_adoption() {
    let (admission, complete, baseline, _) = fixture();
    let original = admission.fingerprint("deployment").unwrap();
    let public_material = admission.placements[0]
        .public_ref("deployment")
        .unwrap()
        .profile_fingerprint;
    let mut changed = admission.clone();
    changed.placements[0].protected_profile_digest = "ee".repeat(32);
    assert_ne!(changed.fingerprint("deployment").unwrap(), original);
    assert_eq!(
        changed.placements[0]
            .public_ref("deployment")
            .unwrap()
            .profile_fingerprint,
        public_material
    );
    assert!(changed.validate("deployment").is_err());
    assert!(baseline
        .validate_for(&admission, &complete, "deployment", &"ee".repeat(32))
        .is_err());

    let mut raw = serde_json::to_value(&admission).unwrap();
    raw["placements"][0]
        .as_object_mut()
        .unwrap()
        .remove("protectedProfileDigest");
    assert!(serde_json::from_value::<DirectUploadAdmission>(raw).is_err());
}

#[test]
fn present_incarnation_and_hash_are_checked_as_distinct_fields() {
    let (_, _, mut baseline, _) = fixture();
    baseline.state = DirectDestinationBaselineState::Present {
        byte_size: WireInteger::new(1),
        sha256: "dd".repeat(32),
        etag: "\"strong\"".into(),
        provider_version: Some("real-provider-version".into()),
        guard_stamp: None,
    };
    baseline.validate().unwrap();
    let original = baseline.fingerprint().unwrap();
    if let DirectDestinationBaselineState::Present {
        provider_version, ..
    } = &mut baseline.state
    {
        *provider_version = Some("replacement-version".into());
    }
    assert_ne!(original, baseline.fingerprint().unwrap());
    if let DirectDestinationBaselineState::Present { etag, .. } = &mut baseline.state {
        *etag = "W/\"weak\"".into();
    }
    assert!(baseline.validate().is_err());
    if let DirectDestinationBaselineState::Present {
        etag, guard_stamp, ..
    } = &mut baseline.state
    {
        *etag = "\"strong\"".into();
        *guard_stamp = Some(StorageGuardStamp {
            physical_authority_id: PhysicalStorageAuthorityId::parse(
                "00000000-0000-4000-8000-000000000001",
            )
            .unwrap(),
            incarnation: crate::storage_authority::GuardIncarnation::parse("1").unwrap(),
        });
    }
    assert!(baseline.validate().is_err());
}

#[test]
fn fresh_permission_binds_witness_nonce_and_exclusive_deadline() {
    let (_, _, baseline, context) = fixture();
    let witness = witness(&baseline);
    let permission = DirectDestinationBaselinePermission {
        binding: baseline.binding.clone(),
        baseline_digest: baseline.fingerprint().unwrap(),
        witness_digest: witness.fingerprint().unwrap(),
        request_nonce: context.request_nonce.clone(),
        expires_at: witness.expires_at,
    };
    permission
        .validate_for(&baseline, &witness, &context, 202)
        .unwrap();
    assert!(permission
        .validate_for(&baseline, &witness, &context, 220)
        .is_err());
    let mut changed = permission.clone();
    changed.request_nonce = "ee".repeat(32);
    assert!(changed
        .validate_for(&baseline, &witness, &context, 202)
        .is_err());
    changed = permission;
    changed.witness_digest = baseline.fingerprint().unwrap();
    assert!(changed
        .validate_for(&baseline, &witness, &context, 202)
        .is_err());
}

#[test]
fn private_phase_requires_staging_and_correlates_current_baseline() {
    let (admission, complete, baseline, context) = fixture();
    let stage = DirectVerifiedStageEvidence {
        session_id: admission.session_id,
        logical_fingerprint: admission.logical_fingerprint,
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: admission.intent.expected_sha256,
        byte_size: WireInteger::new(1),
        placements: vec![DirectStagePlacementEvidence {
            placement: complete.manifests[0].placement.clone(),
            manifest: complete.manifests[0].clone(),
            verification_operation_id: "ff".repeat(32),
            staging_incarnation: DirectObjectIncarnation::ProviderVersion {
                version: "real-stage-version".into(),
            },
        }],
        projection: None,
    };
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let mut envelope = DirectLogicalRequestEnvelope {
        context: context.clone(),
        request: DirectUploadLogicalRequest::Authorize {
            action: DirectLogicalAction::Complete,
            complete_step: Some(DirectCompleteStep::Baseline),
            stage_evidence: vec![stage],
            retained_stage_digests: Vec::new(),
            baseline_evidence: vec![],
            baseline_witnesses: vec![],
            baseline_witness_refs: Vec::new(),
            settled_placements: vec![],
            sessions: vec![DirectSessionAuthorization {
                session: complete.session.clone(),
                expected_resource_version: Some(complete.expected_resource_version),
                operation_id: complete.operation_id.clone(),
                complete_intent: Some(complete),
            }],
        },
    };
    sign_direct_logical_request(&key, &envelope).unwrap();
    let witness = witness(&baseline);
    if let DirectUploadLogicalRequest::Authorize {
        complete_step,
        stage_evidence,
        retained_stage_digests,
        baseline_evidence,
        baseline_witness_refs,
        ..
    } = &mut envelope.request
    {
        *complete_step = Some(DirectCompleteStep::Promote);
        retained_stage_digests
            .push(DirectRetainedStageDigest::from_evidence(&stage_evidence[0]).unwrap());
        let reference = &retained_stage_digests[0];
        assert_eq!(
            reference.expand(&stage_evidence[0]).unwrap(),
            stage_evidence[0]
        );
        let mut changed_source = stage_evidence[0].clone();
        changed_source.sha256 = "f".repeat(64);
        assert!(reference.expand(&changed_source).is_err());
        stage_evidence.clear();
        baseline_evidence.push(baseline.clone());
        baseline_witness_refs.push(DirectBaselineWitnessRef::from_witness(&witness).unwrap());
        assert_eq!(baseline_witness_refs[0].expand(&baseline).unwrap(), witness);
        let mut substituted_binding = baseline.clone();
        substituted_binding.binding.final_key_digest = "f".repeat(64);
        assert!(baseline_witness_refs[0]
            .expand(&substituted_binding)
            .is_err());
    }
    // An authenticated producer cannot smuggle object facts into Missing.
    for forbidden in ["sha256", "guardStamp", "providerVersion"] {
        let mut raw = serde_json::to_value(&envelope).unwrap();
        raw["request"]["baselineEvidence"][0]["state"]
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::Value::Null);
        let body = serde_json::to_vec(&raw).unwrap();
        let mut authenticated = b"aos.direct-upload.logical-request.v3\0".to_vec();
        authenticated.extend_from_slice(&body);
        let signature = key.sign_body(&authenticated).unwrap();
        assert!(verify_direct_logical_request(
            &key,
            &signature,
            &body,
            "deployment",
            "https://executor.test",
            202
        )
        .is_err());
    }

    let signed = sign_direct_logical_request(&key, &envelope).unwrap();
    verify_direct_logical_request(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        202,
    )
    .unwrap();
    assert!(verify_direct_logical_request(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        "https://executor.test",
        220
    )
    .is_err());
    let mut aliased = envelope.clone();
    if let DirectUploadLogicalRequest::Authorize {
        baseline_witness_refs,
        ..
    } = &mut aliased.request
    {
        baseline_witness_refs[0].observation_operation_id =
            baseline.binding.reservation_operation_id.clone();
    }
    assert!(sign_direct_logical_request(&key, &aliased).is_err());
    if let DirectUploadLogicalRequest::Authorize {
        baseline_evidence,
        baseline_witness_refs,
        ..
    } = &mut envelope.request
    {
        baseline_evidence.push(baseline);
        baseline_witness_refs.push(baseline_witness_refs[0].clone());
    }
    assert!(sign_direct_logical_request(&key, &envelope).is_err());
}

#[test]
fn signed_permission_requires_exact_native_authorization_and_request_nonce() {
    let (_, complete, baseline, context) = fixture();
    let witness = witness(&baseline);
    let permission = DirectDestinationBaselinePermission {
        binding: baseline.binding.clone(),
        baseline_digest: baseline.fingerprint().unwrap(),
        witness_digest: witness.fingerprint().unwrap(),
        request_nonce: context.request_nonce.clone(),
        expires_at: witness.expires_at,
    };
    let authorization = DirectSessionAuthorization {
        session: complete.session.clone(),
        expected_resource_version: Some(complete.expected_resource_version),
        operation_id: complete.operation_id.clone(),
        complete_intent: Some(complete),
    };
    let mut envelope = DirectLogicalReplyEnvelope {
        context: context.clone(),
        reply: DirectUploadLogicalReply {
            admissions: vec![],
            sessions: vec![],
            session_summaries: Vec::new(),
            authorizations: vec![authorization],
            baseline_permissions: vec![permission],
            errors: vec![],
        },
    };
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let signed = sign_direct_logical_reply(&key, &envelope).unwrap();
    verify_direct_logical_reply(&key, &signed.signature, &signed.body, &context, 202).unwrap();
    assert!(
        verify_direct_logical_reply(&key, &signed.signature, &signed.body, &context, 220).is_err()
    );

    envelope.reply.baseline_permissions[0].request_nonce = "ee".repeat(32);
    assert!(sign_direct_logical_reply(&key, &envelope).is_err());
    envelope.reply.baseline_permissions[0].request_nonce = context.request_nonce;
    envelope.reply.authorizations.clear();
    assert!(sign_direct_logical_reply(&key, &envelope).is_err());
}

#[test]
fn logical_owner_preserves_existing_managed_wire_vector_and_exact_original_tuple() {
    let session = DirectSessionRef {
        session_id: "session".into(),
        logical_fingerprint: "11".repeat(32),
    };
    let original =
        direct_destination_promotion_operation_id(&session, WireInteger::new(7), &"22".repeat(32))
            .unwrap();
    // Independently evaluated with pinned Node's SHA256 and JSON.stringify of this exact tuple.
    assert_eq!(
        original,
        "e22b92f1600c55f703229b0bf64f47edaea49b610aee860783bd585a6686cd3b"
    );
    assert_ne!(
        original,
        direct_destination_promotion_operation_id(&session, WireInteger::new(8), &"22".repeat(32))
            .unwrap()
    );
    assert_ne!(
        original,
        direct_destination_promotion_operation_id(&session, WireInteger::new(7), &"33".repeat(32))
            .unwrap()
    );
    let mut changed = session.clone();
    changed.logical_fingerprint = "44".repeat(32);
    assert_ne!(
        original,
        direct_destination_promotion_operation_id(&changed, WireInteger::new(7), &"22".repeat(32))
            .unwrap()
    );
    assert!(direct_destination_promotion_operation_id(
        &session,
        WireInteger::new(0),
        &"22".repeat(32)
    )
    .is_err());
}

#[test]
fn fresh_lookup_challenge_can_follow_the_original_current_witness() {
    let (admission, complete, baseline, _) = fixture();
    let witness = witness(&baseline);
    let request = crate::direct_upload::DirectAuthorityLookup {
        deployment_id: "deployment".into(),
        request_nonce: "de".repeat(32),
        issued_at: WireInteger::new(205),
        expires_at: WireInteger::new(215),
        operation: crate::direct_upload::DirectAuthorityLookupOperation::Baseline {
            admission,
            complete,
            evidence: baseline,
            witness,
        },
    };
    let key = StorageWorkKey::new([17; 32]).unwrap();
    let signed = crate::direct_upload::sign_direct_authority_lookup(&key, &request).unwrap();
    let verified = crate::direct_upload::verify_direct_authority_lookup(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        206,
    )
    .unwrap();
    assert_eq!(verified, request);
    assert!(crate::direct_upload::verify_direct_authority_lookup(
        &key,
        &signed.signature,
        &signed.body,
        "deployment",
        215,
    )
    .is_err());
    let mut future = request;
    if let crate::direct_upload::DirectAuthorityLookupOperation::Baseline { witness, .. } =
        &mut future.operation
    {
        witness.issued_at = WireInteger::new(207);
    }
    assert!(future.validate("deployment", 206).is_err());
}
