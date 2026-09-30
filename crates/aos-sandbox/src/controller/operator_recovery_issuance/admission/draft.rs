//! Derives only original Repair request DATA and an independent ordinary plan.
//!
//! The actual public peer, authenticated Inventory, protected predecessor and
//! publication select the sole workspace. No intent is signed or operation
//! admitted here; the existing admission owner later verifies the signed plan
//! and atomically commits the original request and dedicated intent together.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, RepairStorageWorkspacePinRequest, RequestHeader,
};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, CapabilityId, NodeId,
    OperationId, ProtocolId, ProtocolVersion, ResourceId, ResourceKind,
    RevocationScopeId, SandboxId, Selector,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use buffa::Message as _;

use super::*;
use crate::lifecycle::{LifecycleResourceV1, LifecycleStorageInventoryKindV1};

/// Distinguishes authorized original replay from unsigned new admission DATA.
pub enum StorageRepairAdmissionPreparationV1 {
    /// Returns the original admitted identity without another effect or grant.
    Replay(OperationId),
    /// Requires independent ordinary signing and atomic original admission.
    Draft(StorageRepairAdmissionDraftV1),
}

/// Keeps an original request and exact current lease alongside unsigned plan DATA.
pub struct StorageRepairAdmissionDraftV1 {
    plan: BrokerAuthorizationPlan,
    body: Vec<u8>,
    lease: Vec<u8>,
    lease_signature: Vec<u8>,
}

impl StorageRepairAdmissionDraftV1 {
    /// Moves the exact plan and original request into independent signing.
    #[must_use]
    pub fn into_parts(self) -> (BrokerAuthorizationPlan, Vec<u8>, Vec<u8>, Vec<u8>) {
        (self.plan, self.body, self.lease, self.lease_signature)
    }
}

impl<C: ActivatedOperationCompiler, E: SingleNodeEffectExecutor> NodeController<C, E> {
    /// Reauthorizes an exact Repair replay before any fresh Storage request.
    ///
    /// # Errors
    ///
    /// Rejects malformed input, conflicting idempotency, stale public peer or
    /// capability scope, and changed original public admission. Vacant input
    /// returns `None` without admitting or allocating an operation.
    pub fn replay_operator_storage_repair_admission_v1(
        &mut self,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        canonical: &[u8],
    ) -> Result<Option<AcceptOutcome>, ControllerServiceError> {
        let digest = self.checked_public_request_digest(peer, canonical)?;
        let (_, request) = decode_repair_public_request(canonical)?;
        let idempotency = crate::IdempotencyKey::new(request.idempotency_key().to_vec())
            .map_err(|_| OperationCompilationError::Malformed)?;

        let journal = self.reconciler.journal_mut();
        match journal.check_idempotency(&idempotency, digest) {
            crate::IdempotencyOutcome::Vacant => Ok(None),
            crate::IdempotencyOutcome::Conflict => Err(OperationCompilationError::Rejected.into()),
            crate::IdempotencyOutcome::Replay(operation) => {
                let plan = crate::production_operation_compiler::compile_replayed_storage_repair_v1(
                    journal, peer, capability, canonical, digest, operation,
                )?;
                peer.recheck().map_err(|_| OperationCompilationError::Rejected)?;
                self.accept_compiled_plan(plan, digest).map(Some)
            }
        }
    }

    /// Prepares one exact Repair draft or reauthorizes its original replay.
    ///
    /// Fresh IDs and deadline are created only for vacant idempotency. Existing
    /// attempts never regenerate an envelope or require a reconstructed peer.
    ///
    /// # Errors
    ///
    /// Rejects malformed public input, changed peer/capability/project/current
    /// head, ambiguous Inventory, absent current publication/lease/template,
    /// unsupported role policy or an expired/unrepresentable paired interval.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_operator_storage_repair_admission_v1(
        &mut self,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        canonical: &[u8],
        inventory_outcome: &AuthenticatedBrokerMethodOutcomeV1,
        node: NodeId,
        revocation_scope: RevocationScopeId,
        now_wall: i64,
        now_boot: u64,
    ) -> Result<StorageRepairAdmissionPreparationV1, ControllerServiceError> {
        let digest = self.checked_public_request_digest(peer, canonical)?;
        let (envelope, request) = decode_repair_public_request(canonical)?;
        let idempotency = crate::IdempotencyKey::new(request.idempotency_key().to_vec())
            .map_err(|_| OperationCompilationError::Malformed)?;

        let journal = self.reconciler.journal_mut();
        match journal.check_idempotency(&idempotency, digest) {
            crate::IdempotencyOutcome::Replay(operation) => {
                let plan = crate::production_operation_compiler::compile_replayed_storage_repair_v1(
                    journal, peer, capability, canonical, digest, operation,
                )?;
                peer.recheck().map_err(|_| OperationCompilationError::Rejected)?;
                self.accept_compiled_plan(plan, digest)?;
                return Ok(StorageRepairAdmissionPreparationV1::Replay(operation));
            }
            crate::IdempotencyOutcome::Conflict => {
                return Err(OperationCompilationError::Rejected.into());
            }
            crate::IdempotencyOutcome::Vacant => {}
        }

        let current_key = super::super::super::recovery_current_key(request.resource_id());
        let current_bytes = journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(OperationCompilationError::Rejected)?
            .to_vec();
        super::super::super::validate_recovery_current(&request, &current_bytes)
            .map_err(|_| OperationCompilationError::Rejected)?;
        let current_head = super::super::super::decode_recovery_current(&current_bytes)
            .map_err(|_| OperationCompilationError::Rejected)?;
        if current_head.kind != 1 {
            return Err(OperationCompilationError::Rejected.into());
        }
        super::super::super::authorize_public_operator_recovery_v1(
            journal,
            peer,
            capability,
            ResourceKind::Sandbox,
            Selector::Resource {
                resource: ResourceId::from_bytes(request.resource_id()),
            },
            envelope.protobuf_body(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;

        let inventory =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(inventory_outcome)
                .map_err(|_| OperationCompilationError::Rejected)?;
        let resource = LifecycleResourceV1::Sandbox(SandboxId::from_bytes(request.resource_id()));
        let mut matching = inventory.entries().iter().filter(|entry| {
            entry.kind() == LifecycleStorageInventoryKindV1::Dataset && entry.resource() == resource
        });
        let workspace = matching.next().ok_or(OperationCompilationError::Rejected)?;
        if matching.next().is_some() || inventory.source_version() != 3 {
            return Err(OperationCompilationError::Rejected.into());
        }

        let publication = crate::AuthorityPublicationStore::new(journal)
            .current(SandboxId::from_bytes(request.resource_id()))
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        let assignment = publication
            .manifest()
            .broker_assignment()
            .map_err(|_| OperationCompilationError::Rejected)?;
        let lease = publication.lease().lease();
        let template = publication
            .templates()
            .iter()
            .find(|template| template.audience() == BrokerAudience::Storage)
            .ok_or(OperationCompilationError::Rejected)?;
        let parent = template.plan();
        if publication.manifest().manifest().project() != peer.project()
            || publication.manifest().manifest().node() != node
            || assignment.desired_generation().get() != current_head.desired_generation
            || parent.assignment() != assignment
            || parent.node() != node
            || parent.protocol() != ProtocolId::StorageBroker
            || parent.protocol_version() != ProtocolVersion::new(1, 0)
            || parent.revocation_scope() != revocation_scope
            || lease.assignment().sandbox() != assignment.sandbox()
            || lease.assignment().incarnation() != assignment.incarnation()
            || lease.assignment().epoch() != assignment.epoch()
            || lease.assignment().digest() != assignment.digest()
            || lease.node() != node
            || now_wall < lease.authority_issued_seconds()
        {
            return Err(OperationCompilationError::Rejected.into());
        }

        let (expires, deadline) = original_admission_interval(
            now_wall,
            now_boot,
            lease.authority_expires_seconds(),
        )?;
        let operation = OperationId::new();
        let body = RepairStorageWorkspacePinRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: operation.as_bytes().to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: deadline,
                maximum_response_bytes: aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES,
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
            operation_id: operation.as_bytes().to_vec(),
            storage_handle: workspace.effect_subject().as_bytes().to_vec(),
            ..Default::default()
        }
        .encode_to_vec();

        let semantics = CanonicalStorageRepairSemanticsV1::decode(
            &body,
            inventory_outcome.request().peer(),
            inventory_outcome.request().peer_policy(),
            now_boot,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        super::super::ProtectedStorageRepairSelectionV1::from_authenticated_inventory(
            &inventory,
            operation,
            request.resource_id(),
            current_head.desired_generation,
            &semantics,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let grant = BrokerGrant::new(
            semantics.broker_verb(),
            semantics.grant_target(),
            semantics.argument_commitment(),
            u32::try_from(body.len()).map_err(|_| OperationCompilationError::Rejected)?,
            0,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            node,
            parent.ownership_authority().clone(),
            vec![grant],
            parent.policy_commitment(),
            revocation_scope,
            now_wall,
            expires,
            Vec::new(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        peer.recheck().map_err(|_| OperationCompilationError::Rejected)?;

        Ok(StorageRepairAdmissionPreparationV1::Draft(
            StorageRepairAdmissionDraftV1 {
                plan,
                body,
                lease: publication.lease().canonical_lease().to_vec(),
                lease_signature: publication.lease().canonical_signature().to_vec(),
            },
        ))
    }
}

fn decode_repair_public_request(
    canonical: &[u8],
) -> Result<
    (PublicMutationRequestV1, super::super::super::OperatorRecoveryRequestV1),
    OperationCompilationError,
> {
    let envelope = PublicMutationRequestV1::decode(canonical)
        .map_err(|_| OperationCompilationError::Malformed)?;
    let crate::cli_model::DormantSandboxRequestKindV1::OperatorRecover(decoded) = envelope
        .decode_validated_kind()
        .map_err(|_| OperationCompilationError::Malformed)?
    else {
        return Err(OperationCompilationError::Malformed);
    };
    let request = super::super::decode_public_request(envelope.protobuf_body())
        .map_err(|_| OperationCompilationError::Malformed)?;
    if envelope.method() != crate::cli_model::PublicApiAuditMethodV1::OperatorRecover
        || request != super::super::super::OperatorRecoveryRequestV1::try_from(decoded)
            .map_err(|_| OperationCompilationError::Malformed)?
        || request.action()
            != aos_proto::aos::sandbox::v1::OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
    {
        return Err(OperationCompilationError::Rejected);
    }
    Ok((envelope, request))
}

// This is arithmetic DATA, not clock/lease validation. The caller must hold
// actual public authorization and exact current publication/lease first.
fn original_admission_interval(
    now_wall: i64,
    now_boot: u64,
    lease_expires: i64,
) -> Result<(i64, u64), OperationCompilationError> {
    let expires = now_wall
        .checked_add(30)
        .ok_or(OperationCompilationError::Rejected)?
        .min(lease_expires);
    let remaining = expires
        .checked_sub(now_wall)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .ok_or(OperationCompilationError::Rejected)?;
    let deadline = remaining
        .checked_mul(1_000_000_000)
        .and_then(|interval| now_boot.checked_add(interval))
        .ok_or(OperationCompilationError::Rejected)?;
    Ok((expires, deadline))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_interval_is_clamped_to_actual_lease_without_renewal() {
        assert_eq!(original_admission_interval(100, 5, 102).unwrap(), (102, 2_000_000_005));
        assert_eq!(original_admission_interval(100, 5, 500).unwrap(), (130, 30_000_000_005));
    }

    #[test]
    fn expired_or_unrepresentable_original_interval_rejects() {
        assert!(original_admission_interval(100, 5, 100).is_err());
        assert!(original_admission_interval(100, 5, 99).is_err());
        assert!(original_admission_interval(i64::MAX, 5, i64::MAX).is_err());
        assert!(original_admission_interval(100, u64::MAX, 102).is_err());
    }
}
