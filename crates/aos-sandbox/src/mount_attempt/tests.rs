//! Durable Mount-attempt codec and fail-closed validation regressions.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_proto::aos::sandbox::local::v1::{
    ApplyMountRequest, AssignmentFence, Descriptor, MountAttributes, MountResult, MountState,
    RequestHeader,
};
use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
use aos_sandbox_core::model::{
    KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerGrant, DesiredGeneration, IncarnationId,
    LeaseAssignment, NodeId, OperationId, OwnershipLease, RevocationScopeId, SandboxId,
    TrustScopeId, sign_statement,
};
use aos_sandbox_protocol::AuthorizationArtifactBytes;
use buffa::Message as _;
use ed25519_dalek::SigningKey;

use crate::{
    BrokerPlanPreparation, EffectFailure, EffectObservation, EffectPlan, EffectReceipt,
    JournalLimits, Reconciler, ReturnedSignature, SigningAuthority, SingleNodeEffectExecutor,
};

use super::*;

struct NoEffects;

impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("Mount-attempt validation must run before effect observation")
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("Mount-attempt validation must run before effect dispatch")
    }
}

fn key_reference(name: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(name.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    )
}

fn signing_authority(key: &SigningKey) -> SigningAuthority {
    let signer = key_reference("controller", KeyUsage::BrokerAuthorization, key);
    let scope = TrustScopeId::from_bytes([21; 16]);
    let policy = TrustPolicy::new(
        scope,
        SignaturePurpose::BrokerAuthorization,
        vec![signer.clone()],
        Vec::new(),
    )
    .unwrap();
    let canonical_policy = encode_trust_policy(&policy);
    let descriptor =
        artifact_descriptor(PortableMediaType::TrustPolicy, &canonical_policy).unwrap();
    SigningAuthority::new(
        canonical_policy,
        descriptor,
        scope,
        signer,
        key.verifying_key().to_bytes(),
        SignaturePurpose::BrokerAuthorization,
        DecodeLimits::default(),
    )
    .unwrap()
}

fn request(assignment: BrokerAssignment, deadline: u64) -> ApplyMountRequest {
    ApplyMountRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 2,
            request_id: vec![10; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: assignment.sandbox().as_bytes().to_vec(),
            incarnation_id: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: assignment.digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
        attachment_id: vec![3; 16],
        destination_slot_id: vec![4; 16],
        view_revision: Some(Descriptor {
            media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
            sha256: vec![5; 32],
            encoded_size: 64,
            ..Default::default()
        })
        .into(),
        attributes: Some(MountAttributes {
            read_only: true,
            no_exec: true,
            no_suid: true,
            no_device: true,
            no_atime: true,
            ..Default::default()
        })
        .into(),
        source_generation: 7,
        namespace_generation: 9,
        ..Default::default()
    }
}

fn record() -> Record {
    let broker_key = SigningKey::from_bytes(&[42; 32]);
    let lease_key = SigningKey::from_bytes(&[43; 32]);
    let lease_authority =
        key_reference("ownership-authority", KeyUsage::OwnershipLease, &lease_key);
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes([2; 16]),
        AssignmentEpoch::new(3),
        DesiredGeneration::new(4),
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    let deadline = 2_000;
    let catalog = ObjectDigest::from_bytes([12; 32]);

    let template_body = request(assignment, 0).encode_to_vec();
    let body = crate::dispatch::durable_attempt_body(&template_body, deadline).unwrap();
    assert!(validate_durable_attempt_body(
        &template_body,
        deadline,
        &body
    ));
    let decoded = decode_attempt_body(&body, deadline).unwrap();
    let canonical = canonical_mount_semantics_v1(
        &decoded,
        Some(MountCatalogBindingV1::from_verified_digest(catalog).unwrap()),
        &[],
    )
    .unwrap();
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        canonical.verb(),
        canonical.target(),
        canonical.commitment(),
    );
    let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
        BrokerAudience::Mount,
        ProtocolId::MountBroker,
        AUTHORITY_VERSION,
        assignment,
        NodeId::from_bytes([6; 16]),
        lease_authority.clone(),
        vec![
            BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.argument_commitment(),
                u32::try_from(body.len()).unwrap(),
                0,
            )
            .unwrap(),
        ],
        ObjectDigest::from_bytes([8; 32]),
        RevocationScopeId::from_bytes([9; 16]),
        100,
        200,
        Vec::new(),
    )
    .unwrap();
    let preparation = BrokerPlanPreparation::new(plan, signing_authority(&broker_key)).unwrap();
    let signature = sign_statement(
        preparation.signing_request().statement().clone(),
        &broker_key,
    )
    .unwrap();
    let signed_plan = preparation
        .complete(ReturnedSignature::Bytes(signature.signature()), 150)
        .unwrap();

    let lease_assignment = LeaseAssignment::new(
        assignment.sandbox(),
        assignment.incarnation(),
        assignment.epoch(),
        assignment.digest(),
    )
    .unwrap();
    let lease = OwnershipLease::new(
        lease_assignment,
        NodeId::from_bytes([6; 16]),
        11,
        110,
        190,
        5,
        [13; 16],
    )
    .unwrap();
    let lease_bytes = encode_ownership_lease(&lease);
    let lease_descriptor =
        artifact_descriptor(PortableMediaType::OwnershipLease, &lease_bytes).unwrap();
    let lease_scope = TrustScopeId::from_bytes([31; 16]);
    let lease_policy = TrustPolicy::new(
        lease_scope,
        SignaturePurpose::OwnershipLease,
        vec![lease_authority.clone()],
        Vec::new(),
    )
    .unwrap();
    let lease_policy_bytes = encode_trust_policy(&lease_policy);
    let lease_policy_descriptor =
        artifact_descriptor(PortableMediaType::TrustPolicy, &lease_policy_bytes).unwrap();
    let lease_statement = SignatureStatement::new(
        lease_descriptor.clone(),
        lease_scope,
        lease_authority,
        SignaturePurpose::OwnershipLease,
        110,
        Some(190),
        lease_policy_descriptor,
    )
    .unwrap();
    let lease_signature = sign_statement(lease_statement, &lease_key).unwrap();
    let lease_signature_bytes = encode_signature(&lease_signature);
    let packet = aos_sandbox_protocol::encode_authorized_request_envelope(
        ProtocolId::MountBroker,
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        &body,
        &[],
        AuthorizationArtifactBytes {
            broker_plan: signed_plan.canonical_plan(),
            broker_plan_signature: signed_plan.canonical_signature(),
            ownership_lease: &lease_bytes,
            ownership_lease_signature: &lease_signature_bytes,
        },
    )
    .unwrap();

    let mut record = Record {
        request_id: [10; 16],
        namespace_target: DurableNamespaceTargetReferenceV1::from_parts(
            assignment.sandbox(),
            assignment.incarnation(),
            7,
            [13; 32],
            9,
            [14; 32],
        ),
        assignment_epoch: assignment.epoch().get(),
        desired_generation: assignment.desired_generation().get(),
        assignment_digest: *assignment.digest().as_bytes(),
        catalog_commitment: *catalog.as_bytes(),
        semantic_digest: *semantic_identity_digest(semantics).as_bytes(),
        plan_digest: *signed_plan.digest().as_bytes(),
        template_digest: *template_digest_from_parts(
            signed_plan.digest(),
            signed_plan.canonical_signature(),
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            &template_body,
            &[],
            semantics,
        )
        .as_bytes(),
        lease_digest: *lease_descriptor.digest().as_bytes(),
        lease_generation: lease.lease_generation(),
        deadline_boottime_nanoseconds: deadline,
        template_body,
        body,
        packet,
        digest: [0; 32],
    };
    record.digest = record.compute_digest();
    record
}

fn journal() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open_protected_at_uid(
        directory.path(),
        "controller.journal",
        JournalLimits::default(),
        std::fs::metadata(directory.path()).unwrap().uid(),
    )
    .unwrap()
    .0;
    (directory, journal)
}

fn successful_receipt(record: &Record) -> Vec<u8> {
    let request = decode_attempt_body(&record.body, record.deadline_boottime_nanoseconds).unwrap();
    let request_digest = Sha256::digest(&record.body);
    let detached_handle = aos_sandbox_protocol::detached_mount_handle_v1(request_digest.into());
    let view_revision = request.view_revision().map(|descriptor| Descriptor {
        media_type: descriptor.media_type().as_str().to_owned(),
        sha256: descriptor.digest().as_bytes().to_vec(),
        encoded_size: descriptor.encoded_size(),
        ..Default::default()
    });
    MountResult {
        attachment_id: request.attachment_id().to_vec(),
        detached_mount_handle: detached_handle.to_vec(),
        view_revision: view_revision.into(),
        source_generation: request.source_generation(),
        state: MountState::MOUNT_STATE_DETACHED.into(),
        ..Default::default()
    }
    .encode_to_vec()
}

#[test]
fn codec_preserves_one_exact_self_consistent_attempt() {
    let record = record();
    record.validate_contents().unwrap();
    let encoded = record.encode();

    assert_eq!(encoded.len(), record.encoded_len());
    assert_eq!(Record::decode(&encoded).unwrap(), record);
    assert_eq!(record.key(), [vec![b'a'], vec![10; 16]].concat());
}

#[test]
fn codec_rejects_every_changed_or_truncated_byte() {
    let encoded = record().encode();
    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(Record::decode(&changed).is_err(), "changed byte {index}");
        assert!(Record::decode(&encoded[..index]).is_err(), "length {index}");
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert!(Record::decode(&trailing).is_err());
}

#[test]
fn recomputed_record_digest_cannot_hide_cross_field_substitution() {
    for substitution in 0..10 {
        let mut changed = record();
        match substitution {
            0 => changed.assignment_epoch += 1,
            1 => changed.desired_generation += 1,
            2 => changed.assignment_digest[0] ^= 1,
            3 => changed.catalog_commitment[0] ^= 1,
            4 => changed.semantic_digest[0] ^= 1,
            5 => changed.plan_digest[0] ^= 1,
            6 => changed.template_digest[0] ^= 1,
            7 => changed.lease_digest[0] ^= 1,
            8 => changed.lease_generation += 1,
            _ => {
                changed.namespace_target = DurableNamespaceTargetReferenceV1::from_parts(
                    SandboxId::from_bytes([1; 16]),
                    IncarnationId::from_bytes([2; 16]),
                    7,
                    [13; 32],
                    10,
                    [14; 32],
                )
            }
        }
        changed.digest = changed.compute_digest();

        assert!(
            changed.validate_contents().is_err(),
            "substitution {substitution}"
        );
    }
}

#[test]
fn request_identity_replays_only_byte_exact_attempts() {
    let record = record();
    let history = History {
        records: BTreeMap::from([(record.request_id, record.clone())]),
        retained_bytes: record.encoded_len() + record.key().len(),
    };
    assert_eq!(
        history.admission_outcome(&record).unwrap(),
        Some(MountAttemptAdmissionOutcomeV1::Replay)
    );

    let mut conflicting = record;
    conflicting.catalog_commitment[0] ^= 1;
    conflicting.digest = conflicting.compute_digest();
    assert!(matches!(
        history.admission_outcome(&conflicting),
        Err(MountAttemptError::Conflict)
    ));

    let mut fresh = conflicting;
    fresh.request_id = [11; 16];
    fresh.digest = fresh.compute_digest();
    assert_eq!(history.admission_outcome(&fresh).unwrap(), None);
}

#[test]
fn fixed_count_and_byte_capacity_fail_closed() {
    let record = record();
    let full_records = (0..MAXIMUM_ATTEMPTS)
        .map(|index| {
            let mut request_id = [0; 16];
            request_id[8..].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
            (request_id, record.clone())
        })
        .collect();
    let full = History {
        records: full_records,
        retained_bytes: 0,
    };
    assert!(matches!(
        full.ensure_capacity(&record),
        Err(MountAttemptError::Capacity)
    ));

    let bytes_full = History {
        records: BTreeMap::new(),
        retained_bytes: MAXIMUM_NAMESPACE_BYTES,
    };
    assert!(matches!(
        bytes_full.ensure_capacity(&record),
        Err(MountAttemptError::Capacity)
    ));
}

#[test]
fn missing_namespace_audit_reference_fails_replay() {
    let (_directory, mut journal) = journal();
    let record = record();
    journal.commit(&record.transaction().unwrap()).unwrap();

    let result = validate_namespace(&mut journal);
    assert!(
        matches!(
            &result,
            Err(MountAttemptError::NamespaceTarget(
                NamespaceTargetError::CorruptState
            ))
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
fn durable_key_must_equal_the_embedded_request_identity() {
    let (_directory, mut journal) = journal();
    let record = record();
    journal
        .commit(
            &JournalTransaction::new(
                [98; 16],
                vec![JournalRecord::put(
                    NAMESPACE,
                    [vec![b'a'], vec![11; 16]].concat(),
                    record.encode(),
                )],
            )
            .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        validate_namespace(&mut journal),
        Err(MountAttemptError::CorruptState)
    ));
}

#[test]
fn corrupt_attempt_blocks_reconciliation_before_executor_access() {
    let (_directory, mut journal) = journal();
    journal
        .commit(
            &JournalTransaction::new(
                [99; 16],
                vec![JournalRecord::put(NAMESPACE, vec![b'a'; 17], vec![1])],
            )
            .unwrap(),
        )
        .unwrap();
    let mut reconciler = Reconciler::new(journal, NoEffects);

    assert!(matches!(
        reconciler.reconcile_next(),
        Err(crate::ReconcilerError::MountAttempt(error))
            if matches!(*error, MountAttemptError::CorruptState)
    ));
}

#[test]
fn completion_codec_binds_one_exact_success_receipt() {
    let attempt = record();
    let receipt = successful_receipt(&attempt);
    let (completion, result) =
        completion::CompletionRecord::from_attempt(&attempt, receipt).unwrap();
    let encoded = completion.encode();

    assert_eq!(result.state(), MountState::MOUNT_STATE_DETACHED);
    assert_eq!(encoded.len(), completion.encoded_len());
    assert_eq!(
        completion::CompletionRecord::decode(&encoded).unwrap(),
        completion
    );
    assert_eq!(completion.key(), [vec![b'c'], vec![10; 16]].concat());
}

#[test]
fn completion_codec_rejects_every_changed_or_truncated_byte() {
    let attempt = record();
    let (completion, _) =
        completion::CompletionRecord::from_attempt(&attempt, successful_receipt(&attempt)).unwrap();
    let encoded = completion.encode();

    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(
            completion::CompletionRecord::decode(&changed).is_err(),
            "changed byte {index}"
        );
        assert!(
            completion::CompletionRecord::decode(&encoded[..index]).is_err(),
            "length {index}"
        );
    }
}

#[test]
fn completion_replay_conflicts_on_any_different_success_bytes() {
    let attempt = record();
    let (completion, _) =
        completion::CompletionRecord::from_attempt(&attempt, successful_receipt(&attempt)).unwrap();
    let history = completion::CompletionHistory {
        records: BTreeMap::from([(completion.request_id, completion.clone())]),
        retained_bytes: completion.encoded_len() + completion.key().len(),
    };
    assert_eq!(
        history.outcome(&completion).unwrap(),
        Some(MountCompletionOutcomeV1::Replay)
    );

    let mut conflicting = completion;
    conflicting.receipt.push(0);
    conflicting.digest = conflicting.compute_digest();
    assert!(matches!(
        history.outcome(&conflicting),
        Err(MountAttemptError::Conflict)
    ));
}

#[test]
fn orphaned_completion_blocks_reconciliation_before_executor_access() {
    let (_directory, mut journal) = journal();
    let attempt = record();
    let (completion, _) =
        completion::CompletionRecord::from_attempt(&attempt, successful_receipt(&attempt)).unwrap();
    journal.commit(&completion.transaction().unwrap()).unwrap();
    let mut reconciler = Reconciler::new(journal, NoEffects);

    assert!(matches!(
        reconciler.reconcile_next(),
        Err(crate::ReconcilerError::MountAttempt(error))
            if matches!(*error, MountAttemptError::CorruptState)
    ));
}
