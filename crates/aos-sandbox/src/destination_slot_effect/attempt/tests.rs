//! Durable destination-slot attempt and completion regressions.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, DestinationSlotAction, DestinationSlotInventoryRecord,
    DestinationSlotLifecycle, DestinationSlotReapCorrelation, MountAssignmentBinding,
    MountOperationCorrelation, RequestHeader,
};
use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
use aos_sandbox_core::model::{
    IdentityProfile, KeyReference, KeyUsage, NetworkKind, NetworkProfile, ResourceProfile,
    SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy, UnmappableIdentityPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, AttachmentSlotId, BrokerAssignment, BrokerAudience, BrokerGrant, DecodeLimits,
    DesiredGeneration, FeatureRef, IncarnationId, LeaseAssignment, MediaType, NodeId, ObjectDigest,
    OperationId, OwnershipLease, PortableMediaType, ProtocolId, RevocationScopeId, SandboxId,
    TrustScopeId, descriptor_for_bytes, encode_sandbox_spec, sign_statement,
};
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, encode_authorized_request_envelope,
    encode_destination_slot_response,
};
use buffa::Message as _;
use ed25519_dalek::SigningKey;
use sha2::Digest as _;

use super::*;
use crate::destination_slot_effect::completion::CompletionRecord;
use crate::destination_slot_effect::{
    METHOD, ReadyResourceExpectation, decode_request, proto_descriptor, proto_fence,
};
use crate::dispatch::{
    BrokerDispatchSemanticIdentityV1, semantic_identity_digest, template_digest_from_parts,
};
use crate::{
    BrokerPlanPreparation, EffectFailure, EffectObservation, EffectPlan, EffectReceipt,
    JournalLimits, Reconciler, ReturnedSignature, SigningAuthority, SingleNodeEffectExecutor,
};

const SANDBOX_ID: [u8; 16] = [1; 16];
const INCARNATION_ID: [u8; 16] = [2; 16];
const SLOT_ID: [u8; 16] = [3; 16];
const CREATE_OPERATION: [u8; 16] = [10; 16];
const RELEASE_OPERATION: [u8; 16] = [11; 16];
const NAMESPACE_GENERATION: u64 = 9;
const DEADLINE: u64 = 2_000;
const ORIGINAL_ASSIGNMENT_DIGEST: [u8; 32] = [5; 32];
const CURRENT_ASSIGNMENT_DIGEST: [u8; 32] = [6; 32];
const RESOURCE_BOOT_ID: [u8; 16] = [24; 16];
const READY_RESOURCE_DIGEST: [u8; 32] = [30; 32];
const SLOT_DEVICE: u64 = 25;
const SLOT_INODE: u64 = 26;
const ANCHOR_MOUNT_ID: u64 = 27;

struct NoEffects;

impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("destination-slot validation must run before effect observation")
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("destination-slot validation must run before effect dispatch")
    }
}

fn descriptor(kind: PortableMediaType, byte: u8) -> aos_sandbox_core::ObjectDescriptor {
    aos_sandbox_core::ObjectDescriptor::new(
        MediaType::new(kind.as_str().to_owned()).unwrap(),
        ObjectDigest::from_bytes([byte; 32]),
        1,
    )
}

fn sandbox_specification() -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
    let specification = aos_sandbox_core::model::SandboxSpec::new(
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
        IdentityProfile::PrivateUserns {
            id_range_size: NonZeroU32::new(65_536).unwrap(),
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        },
        ResourceProfile::new(Vec::new()).unwrap(),
        descriptor(PortableMediaType::Environment, 40),
        descriptor(PortableMediaType::View, 41),
        vec![AttachmentSlotId::from_bytes(SLOT_ID)],
        NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    let bytes = encode_sandbox_spec(&specification);
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
        &bytes,
    );
    (bytes, descriptor)
}

fn assignment(action: DestinationSlotAction) -> BrokerAssignment {
    let (epoch, generation, digest) = match action {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => {
            (3, 4, ORIGINAL_ASSIGNMENT_DIGEST)
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => (4, 5, CURRENT_ASSIGNMENT_DIGEST),
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            unreachable!("fixtures use a concrete action")
        }
    };
    BrokerAssignment::new(
        SandboxId::from_bytes(SANDBOX_ID),
        IncarnationId::from_bytes(INCARNATION_ID),
        AssignmentEpoch::new(epoch),
        DesiredGeneration::new(generation),
        ObjectDigest::from_bytes(digest),
    )
    .unwrap()
}

fn wire_fence(assignment: BrokerAssignment) -> AssignmentFence {
    AssignmentFence {
        sandbox_id: assignment.sandbox().as_bytes().to_vec(),
        incarnation_id: assignment.incarnation().as_bytes().to_vec(),
        assignment_epoch: assignment.epoch().get(),
        desired_generation: assignment.desired_generation().get(),
        assignment_digest: assignment.digest().as_bytes().to_vec(),
        ..Default::default()
    }
}

fn operation_id(action: DestinationSlotAction) -> [u8; 16] {
    match action {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => CREATE_OPERATION,
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => RELEASE_OPERATION,
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            unreachable!("fixtures use a concrete action")
        }
    }
}

fn request(action: DestinationSlotAction, deadline: u64) -> Vec<u8> {
    let (specification, descriptor) = sandbox_specification();
    let reap = action == DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP;
    aos_proto::aos::sandbox::local::v1::ApplyDestinationSlotRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 3,
            request_id: operation_id(action).to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes: RESPONSE_BYTES,
            ..Default::default()
        })
        .into(),
        fence: Some(wire_fence(assignment(action))).into(),
        resource_fence: reap
            .then(|| {
                wire_fence(assignment(
                    DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE,
                ))
            })
            .into(),
        action: action.into(),
        namespace_generation: NAMESPACE_GENERATION,
        destination_slot_id: SLOT_ID.to_vec(),
        sandbox_spec: Some(proto_descriptor(&descriptor)).into(),
        sandbox_spec_bytes: specification,
        expected_resource_digest: if reap {
            READY_RESOURCE_DIGEST.to_vec()
        } else {
            Vec::new()
        },
        ..Default::default()
    }
    .encode_to_vec()
}

fn attempt_body(action: DestinationSlotAction) -> Vec<u8> {
    crate::dispatch::durable_attempt_body(&request(action, 0), DEADLINE).unwrap()
}

fn key_reference(name: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(name.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(sha2::Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    )
}

fn signing_authority(key: &SigningKey) -> SigningAuthority {
    let signer = key_reference("controller", KeyUsage::BrokerAuthorization, key);
    let scope = TrustScopeId::from_bytes([50; 16]);
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

fn ready_expectation() -> ReadyResourceExpectation {
    ReadyResourceExpectation {
        materialization_operation_id: CREATE_OPERATION,
        materialization_request_digest: sha2::Sha256::digest(attempt_body(
            DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE,
        ))
        .into(),
        resource_kernel_boot_id: RESOURCE_BOOT_ID,
        slot_device: SLOT_DEVICE,
        slot_inode: SLOT_INODE,
        anchor_unique_mount_id: ANCHOR_MOUNT_ID,
        ready_resource_digest: READY_RESOURCE_DIGEST,
    }
}

fn record(action: DestinationSlotAction) -> Record {
    let broker_key = SigningKey::from_bytes(&[51; 32]);
    let lease_key = SigningKey::from_bytes(&[52; 32]);
    let lease_authority =
        key_reference("ownership-authority", KeyUsage::OwnershipLease, &lease_key);
    let assignment = assignment(action);
    let template_body = request(action, 0);
    let body = attempt_body(action);
    let decoded = decode_request(&body, DEADLINE).unwrap();
    let canonical = canonical_destination_slot_semantics_v1(&decoded).unwrap();
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        canonical.verb(),
        canonical.target(),
        canonical.commitment(),
    );
    let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
        BrokerAudience::Mount,
        ProtocolId::MountBroker,
        CARRIER_VERSION,
        assignment,
        NodeId::from_bytes([53; 16]),
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
        ObjectDigest::from_bytes([54; 32]),
        RevocationScopeId::from_bytes([55; 16]),
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
        NodeId::from_bytes([53; 16]),
        11,
        110,
        190,
        5,
        [56; 16],
    )
    .unwrap();
    let lease_bytes = encode_ownership_lease(&lease);
    let lease_descriptor =
        artifact_descriptor(PortableMediaType::OwnershipLease, &lease_bytes).unwrap();
    let lease_scope = TrustScopeId::from_bytes([57; 16]);
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
    let packet = encode_authorized_request_envelope(
        ProtocolId::MountBroker,
        METHOD,
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
    let (_, sandbox_spec) = sandbox_specification();
    let mut record = Record {
        request_id: operation_id(action),
        assignment_target: DurableRuntimeAuthorityReferenceV1::from_parts(
            assignment.sandbox(),
            7,
            ObjectDigest::from_bytes([59; 32]),
        ),
        slot_id: SLOT_ID,
        sandbox_spec_digest: *sandbox_spec.digest().as_bytes(),
        sandbox_spec_size: sandbox_spec.encoded_size(),
        assignment_epoch: assignment.epoch().get(),
        desired_generation: assignment.desired_generation().get(),
        assignment_digest: *assignment.digest().as_bytes(),
        semantic_digest: *semantic_identity_digest(semantics).as_bytes(),
        plan_digest: *signed_plan.digest().as_bytes(),
        template_digest: *template_digest_from_parts(
            signed_plan.digest(),
            signed_plan.canonical_signature(),
            METHOD,
            &template_body,
            &[],
            semantics,
        )
        .as_bytes(),
        lease_digest: *lease_descriptor.digest().as_bytes(),
        lease_generation: lease.lease_generation(),
        deadline_boottime_nanoseconds: DEADLINE,
        action,
        ready: (action == DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP)
            .then(ready_expectation),
        template_body,
        body,
        packet,
        digest: [0; 32],
    };
    record.digest = record.compute_digest();
    record.validate_contents().unwrap();
    record
}

fn response_record(attempt: &Record) -> DestinationSlotInventoryRecord {
    let request = decode_request(&attempt.body, attempt.deadline_boottime_nanoseconds).unwrap();
    let request_digest: [u8; 32] = sha2::Sha256::digest(&attempt.body).into();
    let (fence, materialization, reap, lifecycle, resource_digest) = match request.action() {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => (
            proto_fence(request.binding_fence()),
            MountOperationCorrelation {
                operation_id: request.header().request_id().to_vec(),
                request_digest: request_digest.to_vec(),
                ..Default::default()
            },
            None,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
            READY_RESOURCE_DIGEST,
        ),
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => {
            let ready = attempt.ready.unwrap();
            (
                proto_fence(request.resource_fence().unwrap()),
                MountOperationCorrelation {
                    operation_id: ready.materialization_operation_id.to_vec(),
                    request_digest: ready.materialization_request_digest.to_vec(),
                    ..Default::default()
                },
                Some(DestinationSlotReapCorrelation {
                    operation: Some(MountOperationCorrelation {
                        operation_id: request.header().request_id().to_vec(),
                        request_digest: request_digest.to_vec(),
                        ..Default::default()
                    })
                    .into(),
                    expected_resource_digest: ready.ready_resource_digest.to_vec(),
                    ..Default::default()
                }),
                DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
                [31; 32],
            )
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            unreachable!("validated request has a concrete action")
        }
    };
    DestinationSlotInventoryRecord {
        binding: Some(MountAssignmentBinding {
            fence: Some(fence).into(),
            namespace_generation: request.namespace_generation(),
            ..Default::default()
        })
        .into(),
        destination_slot_id: request.destination_slot_id().to_vec(),
        sandbox_spec: Some(proto_descriptor(request.sandbox_spec())).into(),
        lifecycle: lifecycle.into(),
        resource_kernel_boot_id: RESOURCE_BOOT_ID.to_vec(),
        materialization: Some(materialization).into(),
        reap: reap.into(),
        slot_device: Some(SLOT_DEVICE),
        slot_inode: Some(SLOT_INODE),
        anchor_unique_mount_id: Some(ANCHOR_MOUNT_ID),
        resource_digest: resource_digest.to_vec(),
        ..Default::default()
    }
}

fn receipt(attempt: &Record) -> Vec<u8> {
    encode_destination_slot_response(response_record(attempt)).unwrap()
}

fn test_journal() -> (tempfile::TempDir, Journal) {
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

#[test]
fn attempt_codec_is_exact_and_checks_every_byte() {
    let record = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP);
    let encoded = record.encode();

    assert_eq!(encoded.len(), record.encoded_len());
    assert_eq!(
        encoded.len() - record.template_body.len() - record.body.len() - record.packet.len(),
        FIXED_RECORD_BYTES
    );
    assert_eq!(Record::decode(&encoded).unwrap(), record);
    assert_eq!(
        record.key(),
        [vec![b'a'], RELEASE_OPERATION.to_vec()].concat()
    );

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
fn recomputed_digest_cannot_hide_attempt_field_substitution() {
    for substitution in 0..14 {
        let mut changed = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP);
        match substitution {
            0 => changed.request_id[0] ^= 1,
            1 => {
                changed.assignment_target = DurableRuntimeAuthorityReferenceV1::from_parts(
                    SandboxId::from_bytes([60; 16]),
                    7,
                    ObjectDigest::from_bytes([59; 32]),
                )
            }
            2 => changed.slot_id[0] ^= 1,
            3 => changed.sandbox_spec_digest[0] ^= 1,
            4 => changed.sandbox_spec_size += 1,
            5 => changed.assignment_epoch += 1,
            6 => changed.desired_generation += 1,
            7 => changed.assignment_digest[0] ^= 1,
            8 => changed.semantic_digest[0] ^= 1,
            9 => changed.plan_digest[0] ^= 1,
            10 => changed.template_digest[0] ^= 1,
            11 => changed.deadline_boottime_nanoseconds += 1,
            12 => changed.ready.as_mut().unwrap().ready_resource_digest[0] ^= 1,
            _ => changed.ready.as_mut().unwrap().slot_inode = 0,
        }
        changed.digest = changed.compute_digest();

        assert!(
            changed.validate_contents().is_err(),
            "substitution {substitution}"
        );
    }
}

#[test]
fn pending_resume_preserves_every_immutable_field() {
    let original = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP);
    let mut refreshed = original.clone();
    refreshed.lease_digest = [61; 32];
    refreshed.lease_generation += 1;
    refreshed.packet = vec![62; refreshed.packet.len()];
    refreshed.digest = [63; 32];
    assert!(original.matches_resumed_record(&refreshed));

    let mut replayed = original.clone();
    replayed.packet = vec![64; replayed.packet.len()];
    replayed.digest = [65; 32];
    assert!(original.matches_resumed_record(&replayed));

    let mut substitutions = Vec::new();
    let mut changed = refreshed.clone();
    changed.request_id[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.slot_id[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.sandbox_spec_digest[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.assignment_epoch += 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.assignment_digest[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.semantic_digest[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.plan_digest[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.template_digest[0] ^= 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.deadline_boottime_nanoseconds += 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.ready.as_mut().unwrap().slot_inode += 1;
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.template_body.push(1);
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.body.push(1);
    substitutions.push(changed);
    let mut changed = refreshed.clone();
    changed.lease_generation = original.lease_generation - 1;
    substitutions.push(changed);
    let mut changed = refreshed;
    changed.lease_generation = original.lease_generation;
    substitutions.push(changed);

    for (index, changed) in substitutions.iter().enumerate() {
        assert!(
            !original.matches_resumed_record(changed),
            "substitution {index}"
        );
    }
}

#[test]
fn retained_reap_crosslinks_an_exact_local_materialization() {
    let materialization = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE);
    let reap = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP);
    let records = BTreeMap::from([
        (materialization.request_id, materialization.clone()),
        (reap.request_id, reap.clone()),
    ]);
    validate_materialization_links(&records).unwrap();

    let mut changed_reap = reap.clone();
    changed_reap
        .ready
        .as_mut()
        .unwrap()
        .materialization_request_digest[0] ^= 1;
    let changed = BTreeMap::from([
        (materialization.request_id, materialization.clone()),
        (changed_reap.request_id, changed_reap),
    ]);
    assert!(validate_materialization_links(&changed).is_err());

    let mut changed_materialization = materialization;
    changed_materialization.action = DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP;
    let changed = BTreeMap::from([
        (changed_materialization.request_id, changed_materialization),
        (reap.request_id, reap),
    ]);
    assert!(validate_materialization_links(&changed).is_err());
}

#[test]
fn pending_actions_reproduce_only_the_original_effect() {
    let materialization = decode_request(
        &attempt_body(DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE),
        DEADLINE,
    )
    .unwrap();
    let creation = OperationId::from_bytes(CREATE_OPERATION);
    let release = OperationId::from_bytes(RELEASE_OPERATION);
    assert!(crate::destination_slot_effect::request_matches_action(
        &materialization,
        crate::DestinationSlotReconciliationActionV1::ResumeMaterialize {
            operation_id: creation,
        },
        None,
    ));
    assert!(crate::destination_slot_effect::request_matches_action(
        &materialization,
        crate::DestinationSlotReconciliationActionV1::ResumeMaterializeForReap {
            operation_id: creation,
            reap_operation_id: release,
        },
        None,
    ));

    let reap = decode_request(
        &attempt_body(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP),
        DEADLINE,
    )
    .unwrap();
    assert!(crate::destination_slot_effect::request_matches_action(
        &reap,
        crate::DestinationSlotReconciliationActionV1::ResumeReap {
            operation_id: release,
        },
        Some(ready_expectation()),
    ));
    assert!(!crate::destination_slot_effect::request_matches_action(
        &reap,
        crate::DestinationSlotReconciliationActionV1::ResumeMaterialize {
            operation_id: release,
        },
        Some(ready_expectation()),
    ));
}

#[test]
fn materialize_and_reap_receipts_bind_the_exact_resource() {
    let materialization = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE);
    let (materialization_completion, ready) =
        CompletionRecord::from_attempt(&materialization, receipt(&materialization)).unwrap();
    assert_eq!(
        ready.lifecycle(),
        DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY
    );
    assert_eq!(
        ready.fence().assignment_digest(),
        &ORIGINAL_ASSIGNMENT_DIGEST
    );
    materialization_completion
        .validate(&materialization)
        .unwrap();

    let reap = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP);
    let (reap_completion, released) =
        CompletionRecord::from_attempt(&reap, receipt(&reap)).unwrap();
    assert_eq!(
        released.lifecycle(),
        DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
    );
    assert_eq!(
        released.fence().assignment_digest(),
        &ORIGINAL_ASSIGNMENT_DIGEST
    );
    assert_ne!(
        released.fence().assignment_digest(),
        &CURRENT_ASSIGNMENT_DIGEST
    );
    reap_completion.validate(&reap).unwrap();

    let request = decode_request(&reap.body, reap.deadline_boottime_nanoseconds).unwrap();
    let mut substituted = response_record(&reap);
    substituted.binding.get_or_insert_default().fence = Some(proto_fence(request.fence())).into();
    let substituted = encode_destination_slot_response(substituted).unwrap();
    assert!(CompletionRecord::from_attempt(&reap, substituted).is_err());
}

#[test]
fn completion_codec_is_exact_and_checks_every_byte() {
    let attempt = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP);
    let (completion, _) = CompletionRecord::from_attempt(&attempt, receipt(&attempt)).unwrap();
    let encoded = completion.encode();

    assert_eq!(encoded.len(), completion.encoded_len());
    assert_eq!(
        encoded.len() - completion.receipt.len(),
        crate::destination_slot_effect::completion::FIXED_RECORD_BYTES
    );
    assert_eq!(CompletionRecord::decode(&encoded).unwrap(), completion);
    assert_eq!(
        completion.key(),
        [vec![b'c'], RELEASE_OPERATION.to_vec()].concat()
    );

    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(
            CompletionRecord::decode(&changed)
                .and_then(|record| record.validate(&attempt))
                .is_err(),
            "changed byte {index}"
        );
        assert!(
            CompletionRecord::decode(&encoded[..index]).is_err(),
            "length {index}"
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert!(CompletionRecord::decode(&trailing).is_err());
}

#[test]
fn capacity_and_conflicting_completion_fail_closed() {
    let attempt = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE);
    let (completion, _) = CompletionRecord::from_attempt(&attempt, receipt(&attempt)).unwrap();
    let history = History {
        records: BTreeMap::new(),
        retained_bytes: MAXIMUM_NAMESPACE_BYTES,
    };
    assert!(matches!(
        history.ensure_capacity(&attempt),
        Err(DestinationSlotEffectError::Capacity)
    ));

    let mut conflicting = completion.clone();
    conflicting.receipt.push(0);
    conflicting.digest = conflicting.compute_digest();
    assert_ne!(conflicting, completion);
    assert!(conflicting.validate(&attempt).is_err());
}

#[test]
fn corrupt_attempt_blocks_reconciliation_before_executor_access() {
    let (_directory, mut journal) = test_journal();
    journal
        .commit(
            &JournalTransaction::new(
                [90; 16],
                vec![JournalRecord::put(
                    NAMESPACE,
                    [vec![b'a'], CREATE_OPERATION.to_vec()].concat(),
                    b"corrupt".to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    let mut reconciler = Reconciler::new(journal, NoEffects);

    assert!(matches!(
        reconciler.reconcile_next(),
        Err(crate::ReconcilerError::DestinationSlotEffect(error))
            if matches!(*error, DestinationSlotEffectError::CorruptState)
    ));
}

#[test]
fn request_identity_cannot_cross_mount_attempt_domains() {
    let (_directory, mut journal) = test_journal();
    let attempt = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE);
    journal
        .commit(
            &JournalTransaction::new(
                [91; 16],
                vec![
                    JournalRecord::put(NAMESPACE, attempt.key(), attempt.encode()),
                    JournalRecord::put(
                        RecordNamespace::MountAttempt,
                        attempt.key(),
                        b"foreign".to_vec(),
                    ),
                ],
            )
            .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        validate_namespace(&mut journal),
        Err(DestinationSlotEffectError::CorruptState)
    ));
}

#[test]
fn orphaned_completion_blocks_reconciliation_before_executor_access() {
    let (_directory, mut journal) = test_journal();
    let attempt = record(DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE);
    let (completion, _) = CompletionRecord::from_attempt(&attempt, receipt(&attempt)).unwrap();
    journal.commit(&completion.transaction().unwrap()).unwrap();
    let mut reconciler = Reconciler::new(journal, NoEffects);

    assert!(matches!(
        reconciler.reconcile_next(),
        Err(crate::ReconcilerError::DestinationSlotEffect(error))
            if matches!(*error, DestinationSlotEffectError::CorruptState)
    ));
}
