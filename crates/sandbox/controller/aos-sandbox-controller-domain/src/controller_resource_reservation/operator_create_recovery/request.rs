//! Retains the paid exact Recover request and protected authorization prefix.

use super::*;
use aos_sandbox_model::{CapabilityId, OperationId, ResourceId, ResourceKind, Selector};
use aos_sandbox_protocol::public_api::mutation::PublicMutationEnvelopeDataV1;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use crate::cli_model::{OperatorRecoveryRequestV1, PublicApiAuditMethodV1, PublicMutationRequestV1};
use crate::{JournalError, OperationCompilationError};
use crate::public_api_session::PublicApiPeer;

pub(crate) struct RequestModelsV1 {
    envelope: PublicMutationRequestV1,
    request: OperatorRecoveryRequestV1,
    target: OperationId,
    canonical: Vec<u8>,
    target_kind: RecoveryTargetKindV2,
}

pub(super) enum RecoveryTargetKindV2 {
    CreateFinality,
    StopCleanup(crate::production_operation_compiler::StopRecoveryTargetDataV1),
    ExecutionNoApply(crate::production_operation_compiler::ExecutionNoApplyRecoveryTargetDataV1),
}

impl RequestModelsV1 {
    fn decode_once_v1(controller: &Journal, peer: &PublicApiPeer, encoded: &[u8], node: NodeId)
        -> Result<Self, OperationCompilationError> {
        Self::decode_for_current_target_v2(controller, peer.project(), node, encoded, None)
    }

    fn decode_for_current_target_v2(controller: &Journal, project: aos_sandbox_model::ProjectId,
        node: NodeId, encoded: &[u8], expected: Option<aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1>,
    ) -> Result<Self, OperationCompilationError> {
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 as Kind;
        let (envelope, request) = decode_recover_request_v1(encoded)?;
        let operation = OperationId::from_bytes(request.resource_id());
        let raw = controller.get(crate::RecordNamespace::Operation, operation.as_bytes())
            .ok_or(OperationCompilationError::Rejected)?;
        let operation = aos_sandbox_protocol::domain_ledger::operation::decode_operation(raw)
            .map_err(|_| OperationCompilationError::Rejected)?;
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1 as Method;
        let (target, target_kind) = match operation.public_operation().map(|public| public.method()) {
            Some(Method::CreateSandbox) if expected.is_none_or(|kind| kind == Kind::MetadataComplete) => (
                crate::production_operation_compiler::require_create_recovery_target_v1(
                    controller, project, &request)?, RecoveryTargetKindV2::CreateFinality),
            Some(Method::StopSandbox) if expected.is_none_or(|kind| kind == Kind::StopCleanup) => {
                let target = crate::production_operation_compiler::require_stop_recovery_target_v1(
                    controller, project, node, &request)?;
                (target.operation_v1(), RecoveryTargetKindV2::StopCleanup(target))
            }
            Some(Method::CreateExecution) if expected.is_none_or(|kind| kind == Kind::ExecutionNoApply) => {
                let target = crate::production_operation_compiler::require_execution_no_apply_recovery_target_v1(
                    controller, project, node, &request)?;
                (target.operation_v1(), RecoveryTargetKindV2::ExecutionNoApply(target))
            }
            _ => return Err(OperationCompilationError::Rejected),
        };
        Ok(Self { envelope, request, target, canonical: encoded.to_vec(), target_kind })
    }

    /// Replays only canonical request/target DATA under independently paid C.
    pub(crate) fn decode_for_project_v1(controller: &Journal,
        project: aos_sandbox_model::ProjectId, encoded: &[u8],
    ) -> Result<Self, OperationCompilationError> {
        let (envelope, request) = decode_recover_request_v1(encoded)?;
        let target = crate::production_operation_compiler::require_create_recovery_target_v1(
            controller, project, &request)?;
        Ok(Self { envelope, request, target, canonical: encoded.to_vec(),
            target_kind: RecoveryTargetKindV2::CreateFinality })
    }

    /// Parses only the protected Stop cleanup purpose for Root's current reader.
    pub(crate) fn decode_stop_cleanup_for_project_v1(controller: &Journal,
        project: aos_sandbox_model::ProjectId, node: NodeId, encoded: &[u8],
    ) -> Result<Self, OperationCompilationError> {
        Self::decode_for_current_target_v2(controller, project, node, encoded,
            Some(aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::StopCleanup))
    }

    /// Parses only the protected NoApply purpose for Root's current reader.
    pub(crate) fn decode_execution_no_apply_for_project_v1(controller: &Journal,
        project: aos_sandbox_model::ProjectId, node: NodeId, encoded: &[u8],
    ) -> Result<Self, OperationCompilationError> {
        Self::decode_for_current_target_v2(controller, project, node, encoded,
            Some(aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::ExecutionNoApply))
    }

    /// Measures the same canonical request and protected authorization models.
    ///
    /// Native raw replay, named indexes, peers and clock/append carriers remain
    /// separate obligations. This cost-only helper performs no decode or IO.
    pub(crate) fn receiving_bytes_v1(controller: &Journal, encoded: &[u8])
        -> Result<usize, ResourceReservationErrorV1> {
        let mut bytes = 0_usize;
        let mut rows = 0_usize;
        for (_, key, value) in controller.all_records() {
            bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(value.len()))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            rows = rows.checked_add(1).ok_or(ResourceReservationErrorV1::Conflict)?;
        }
        let models = crate::public_mutation_compiler::delete_admission::geometry::authorization_model_bytes_v1(bytes, rows)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let request_node = std::mem::size_of::<buffa::UnknownField>()
            .checked_add(std::mem::size_of::<Vec<u8>>())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let request = encoded.len().checked_mul(request_node)
            .and_then(|n| n.checked_mul(6))
            .and_then(|n| n.checked_add(encoded.len().checked_mul(32)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryRequest>().checked_mul(4)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<RequestModelsV1>().checked_mul(4)?))
            .and_then(|n| n.checked_add(models))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        request.checked_add(crate::production_operation_compiler::ExecutionNoApplyRecoveryTargetDataV1::
            receiving_bytes_v1(controller).ok_or(ResourceReservationErrorV1::Conflict)?)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn observation_input_v1(&self) -> (&[u8], &OperatorRecoveryRequestV1, OperationId) {
        (&self.canonical, &self.request, self.target)
    }

    pub(crate) fn stop_cleanup_target_v1(&self)
        -> Option<&crate::production_operation_compiler::StopRecoveryTargetDataV1> {
        match &self.target_kind {
            RecoveryTargetKindV2::StopCleanup(target) => Some(target),
            RecoveryTargetKindV2::CreateFinality | RecoveryTargetKindV2::ExecutionNoApply(_) => None,
        }
    }

    pub(crate) fn execution_no_apply_target_v1(&self)
        -> Option<&crate::production_operation_compiler::ExecutionNoApplyRecoveryTargetDataV1> {
        match &self.target_kind {
            RecoveryTargetKindV2::ExecutionNoApply(target) => Some(target),
            RecoveryTargetKindV2::CreateFinality | RecoveryTargetKindV2::StopCleanup(_) => None,
        }
    }

    pub(crate) const fn public_recovery_kind_v1(&self)
        -> aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 {
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 as Kind;
        match &self.target_kind {
            RecoveryTargetKindV2::CreateFinality => Kind::MetadataComplete,
            RecoveryTargetKindV2::StopCleanup(_) => Kind::StopCleanup,
            RecoveryTargetKindV2::ExecutionNoApply(_) => Kind::ExecutionNoApply,
        }
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Computes the actual reached input/authority containers before entry.
    ///
    /// The envelope check borrows input bytes and allocates no request model.
    pub(crate) fn request_receiving_demand_v1(controller: &Journal, peer: &PublicApiPeer,
        encoded: &[u8],
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let envelope = PublicMutationEnvelopeDataV1::decode_v1(encoded)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if envelope.method_v1() != PublicApiAuditMethodV1::OperatorRecover {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let request = RequestModelsV1::receiving_bytes_v1(controller, encoded)?
            .checked_add(Journal::operator_recover_append_carrier_bytes_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?)
            .and_then(|n| n.checked_add(
                aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let peer = peer.retained_recheck_demand_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let clock = crate::policy_compiler::provisioning_current::RootContinuationClockGateV1::controller_authorization_receiving_demand_v1()
            .map_err(ResourceReservationErrorV1::Journal)?
            .checked_add(crate::controller::RetainedControllerProtectedClockAttemptV1::receiving_demand_v1()
                .map_err(ResourceReservationErrorV1::Journal)?)?;
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let controller_models = crate::cold_launch_publication::completion::
            create_stopped_controller_receiving_demand_v1(state)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let controller_indices = crate::cold_launch_publication::completion::
            controller_selector_namespace_entries_v1(state)
            .and_then(|entries| entries.checked_add(
                crate::publisher_admin::authorization_namespace_entries_v1(controller)?))
            .and_then(|entries| u64::try_from(entries).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let projection = crate::controller_service::public_projection::
            sandbox_source_receiving_bytes_v1(controller)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // The finite target selector may reach the existing full accepted Stop
        // and current assignment decoders. Pay their actual retained models
        // before the public target kind or any protected graph is interpreted.
        let target_graph = crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(controller)?;
        let target_graph = u64::try_from(target_graph).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let runtime = crate::runtime_authority::current_publication_receiving_demand_v2(controller)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(clock.checked_add(controller_models)?
            .checked_add(runtime)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, target_graph))?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, projection)
                .with(D::MetadataEntries, controller_indices))?
            .checked_add(peer)?.checked_add(peer)?.checked_add(peer)?.checked_add(peer)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, request)
                .with(D::OpenFiles, 1).with(D::MetadataEntries, 1))?)
    }
}

impl Journal {
    pub(crate) fn authorize_operator_create_recovery_once_v1(&mut self,
        peer: &PublicApiPeer, capability: CapabilityId, handle: &[u8], encoded: &[u8],
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        let mut original = self.take_operator_recover_v1().ok_or(OperatorCreateRecoveryClosedV1)?;
        let prepared = (|| {
            original.require_native_current_v1(self).map_err(|_| OperatorCreateRecoveryClosedV1)?;
            if original.request.is_some() || original.authorization.is_some() {
                return Err(OperatorCreateRecoveryClosedV1);
            }
            let node = original.bank.lock().map_err(|_| OperatorCreateRecoveryClosedV1)?
                .operator_recover_node_v1(self, &original.profile)
                .map_err(|_| OperatorCreateRecoveryClosedV1)?;
            original.request = Some(RequestModelsV1::decode_once_v1(self, peer, encoded, node));
            let request = original.request.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(OperatorCreateRecoveryClosedV1)?;
            original.target = Some(request.target);
            Ok(())
        })();
        original.latch_primary_failure_v1();
        if let Err(original) = self.install_operator_recover_v1(original) {
            let _retained_original = original;
            std::process::abort();
        }
        prepared?;

        // The actual floor scope stays installed while its independent retained
        // authorization-native destination is lent to the sole grant engine.
        let mut native = self.operator_recover_original_mut_v1()
            .and_then(|original| original.authorization_native.take())
            .ok_or(OperatorCreateRecoveryClosedV1)?;
        let entered = (|| {
            let handle_result = crate::controller::resolve_delete_capability_handle_retaining_v1(
                self, peer, capability, handle, &mut native.handle_peers,
            );
            let resolved = handle_result.as_ref().ok().copied();
            self.operator_recover_original_mut_v1().ok_or(OperatorCreateRecoveryClosedV1)?.handle = Some(handle_result);
            let authorization = match resolved {
                Some(capability) => {
                    let original = self.operator_recover_original_mut_v1().ok_or(OperatorCreateRecoveryClosedV1)?;
                    let models = original.request.as_mut().and_then(|value| value.as_mut().ok())
                        .ok_or(OperatorCreateRecoveryClosedV1)?;
                    // Move the retained model out for the one crossing, then restore
                    // it before any after/post or externally visible projection.
                    let target = models.target;
                    let models = original.request.take().ok_or(OperatorCreateRecoveryClosedV1)?;
                    let result = match models.as_ref() {
                        Ok(models) => crate::controller::authorize_public_operator_recovery_retaining_v1(
                            self, peer, capability, ResourceKind::Operation,
                            Selector::Resource { resource: ResourceId::from_bytes(target.into_bytes()) },
                            models.envelope.protobuf_body(), &mut native,
                        ),
                        Err(_) => Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
                    };
                    self.operator_recover_original_mut_v1().ok_or(OperatorCreateRecoveryClosedV1)?.request = Some(models);
                    result
                }
                None => Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
            };
            let original = self.operator_recover_original_mut_v1().ok_or(OperatorCreateRecoveryClosedV1)?;
            original.authorization = Some(match authorization {
                Ok((authorization, decision)) => {
                    let sample = decision.clock();
                    let expiry = decision.capability().claims().expires_at.min(decision.policy().expires_at());
                    original.horizon = Some(RecoverHorizonV1::from_current_authorization_v1(sample, expiry));
                    if let Some(Ok(horizon)) = &original.horizon {
                        if let Ok(bound) = crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1::from_original_data_v1(
                            horizon.original, horizon.cutoff,
                        ) {
                            original.clock = Some(crate::policy_compiler::provisioning_current::RootContinuationClockGateV1::new_controller_authorization_v1(
                                bound.with_wall_expiry_data_v1(horizon.expires_wall_seconds),
                            ));
                        } else {
                            original.horizon = Some(Err(OperatorCreateRecoveryClosedV1));
                        }
                    }
                    native.decision = Some(decision);
                    Ok(authorization)
                }
                Err(cause) => Err(cause),
            });
            if !matches!(original.authorization, Some(Ok(_))) || !matches!(original.horizon, Some(Ok(_))) {
                return Err(OperatorCreateRecoveryClosedV1);
            }
            Ok(())
        })();

        // A refused handle, floor or horizon still owns the same native prefix.
        // Restore it before selecting a cause or running independent afters.
        let original = self.operator_recover_original_mut_v1()
            .ok_or(OperatorCreateRecoveryClosedV1)?;
        original.authorization_native = Some(native);
        original.latch_primary_failure_v1();
        entered?;

        let mut original = self.take_operator_recover_v1()
            .ok_or(OperatorCreateRecoveryClosedV1)?;
        original.authorization_readback = Some((|| {
            let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
            let decision = original.authorization_native.as_ref()
                .and_then(|native| native.decision.as_ref()).ok_or_else(refused)?;
            let models = original.request.as_ref()
                .and_then(|models| models.as_ref().ok()).ok_or_else(refused)?;
            let claims = decision.capability().claims();
            let revision = crate::cli_model::authorization_adapter::
                recompute_create_recovery_authorization_from_records_v1(
                    crate::publisher_admin::PublisherReadDataV2::from_journal_v2(self),
                    &models.request, peer.project(), peer.principal(), claims.id,
                    claims.channel_binding, decision.clock(),
                )?;
            if revision != decision.revision_data_v1() { return Err(refused()); }
            Ok(revision)
        })());
        original.latch_primary_failure_v1();
        let complete = matches!(original.authorization_readback, Some(Ok(_)));
        if let Err(original) = self.install_operator_recover_v1(original) {
            let _retained_original = original;
            std::process::abort();
        }
        if complete { Ok(()) } else { Err(OperatorCreateRecoveryClosedV1) }
    }
}

fn decode_recover_request_v1(
    encoded: &[u8],
) -> Result<(PublicMutationRequestV1, OperatorRecoveryRequestV1), OperationCompilationError> {
        let envelope = PublicMutationRequestV1::decode(encoded)
            .map_err(|_| OperationCompilationError::Malformed)?;
        if envelope.method() != PublicApiAuditMethodV1::OperatorRecover {
            return Err(OperationCompilationError::Malformed);
        }
        let DormantSandboxRequestKindV1::OperatorRecover(request) = envelope.decode_validated_kind()
            .map_err(|_| OperationCompilationError::Malformed)? else {
                return Err(OperationCompilationError::Malformed);
            };
        let request = OperatorRecoveryRequestV1::try_from(request)
            .map_err(|_| OperationCompilationError::Malformed)?;
    Ok((envelope, request))
}

impl RequestModelsV1 {
    pub(super) fn decode_completed_retry_v1(
        controller: &Journal,
        peer: &PublicApiPeer,
        encoded: &[u8],
        request_scope: crate::controller::ControllerRequestScopeV1,
        expected_operation: OperationId,
    ) -> Result<Self, OperationCompilationError> {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::{
            CreateFinalityObservationAdmissionDataV1 as Data,
            public_operation::require_metadata_complete_completed_operation_v1,
        };
        let rejected = || OperationCompilationError::Rejected;
        let (envelope, request) = decode_recover_request_v1(encoded)?;
        if request.action() != aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryAction::
            OPERATOR_RECOVERY_ACTION_RETRY as i32 {
            return Err(rejected());
        }
        let holder = *peer.principal().as_bytes();
        let idempotency = Data::idempotency_digest_v1(holder, request.idempotency_key());
        let key = Data::key_from_original_v1(holder, idempotency);
        let raw = controller.get(crate::RecordNamespace::OperatorRecovery, &key).ok_or_else(rejected)?;
        let data = Data::decode_v1(raw).map_err(|_| rejected())?;
        require_completed_replay_binding_v1(data, holder, *peer.project().as_bytes(),
            *request_scope.digest().as_bytes(), *expected_operation.as_bytes(),
            request.resource_id(), encoded)?;
        if data.key_v1() != key { return Err(rejected()); }
        let idempotency = crate::IdempotencyKey::new(request.idempotency_key().to_vec())
            .map_err(|_| rejected())?;
        if controller.check_idempotency(&idempotency, data.request_digest_v1())
            != crate::IdempotencyOutcome::Replay(expected_operation)
        {
            return Err(rejected());
        }
        require_metadata_complete_completed_operation_v1(data,
            controller.get(crate::RecordNamespace::Operation, expected_operation.as_bytes())
                .ok_or_else(rejected)?).map_err(|_| rejected())?;
        Ok(Self { envelope, request, target: OperationId::from_bytes(data.target),
            canonical: encoded.to_vec(), target_kind: RecoveryTargetKindV2::CreateFinality })
    }
}

// This compares historical identity DATA only. Fresh current read authority
// comes exclusively from the retained operation-read authorization engine.
fn require_completed_replay_binding_v1(
    data: aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::CreateFinalityObservationAdmissionDataV1<'_>,
    holder: [u8; 16], project: [u8; 16], scope: [u8; 32], operation: [u8; 16],
    target: [u8; 16], canonical: &[u8],
) -> Result<(), OperationCompilationError> {
    if data.holder != holder || data.project != project || data.request_scope != scope
        || data.operation != operation || data.target != target || data.canonical_request != canonical {
        return Err(OperationCompilationError::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod completed_replay_binding_tests {
    use super::*;
    use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
    use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::CreateFinalityObservationAdmissionDataV1 as Data;

    fn historical<'a>(canonical: &'a [u8]) -> Data<'a> {
        let original = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [8; 16], 100, 10_000_000_000,
        ).unwrap();
        Data { operation: [1; 16], request_scope: [2; 32], target: [3; 16],
            node: [4; 16], holder: [5; 16], project: [6; 16], capability: [7; 16],
            channel: [9; 32], authorization_revision: [10; 32], idempotency_digest: [11; 32],
            original, cutoff: 11_000_000_000, wall_expiry: 101, canonical_request: canonical }
    }

    #[test]
    fn same_completed_result_binds_all_original_request_identities() {
        let data = historical(b"the original canonical request");
        assert!(require_completed_replay_binding_v1(data, [5; 16], [6; 16], [2; 32],
            [1; 16], [3; 16], data.canonical_request).is_ok());
        for (holder, project, scope, operation, target) in [
            ([12; 16], [6; 16], [2; 32], [1; 16], [3; 16]),
            ([5; 16], [12; 16], [2; 32], [1; 16], [3; 16]),
            ([5; 16], [6; 16], [12; 32], [1; 16], [3; 16]),
            ([5; 16], [6; 16], [2; 32], [12; 16], [3; 16]),
            ([5; 16], [6; 16], [2; 32], [1; 16], [12; 16]),
        ] {
            assert!(require_completed_replay_binding_v1(data, holder, project, scope,
                operation, target, data.canonical_request).is_err());
        }
    }

    #[test]
    fn replaced_request_cannot_reuse_a_completed_idempotency_lookup() {
        let data = historical(b"the original canonical request");
        assert!(require_completed_replay_binding_v1(data, [5; 16], [6; 16], [2; 32],
            [1; 16], [3; 16], b"a substituted canonical request").is_err());
    }
}
