//! Atomically admits this genuine Recover observation and its pending public operation.
//!
//! The rows preserve the authenticated caller and original new horizon for an
//! independent Root read. It admits no old effect or public success. Every
//! entered model, exact transaction, returned append and readback stays here.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::{
    metadata_complete_admission_transaction_v1,
    require_metadata_complete_admission_transaction_v1,
    stop_cleanup_admission_transaction_v1,
    require_stop_cleanup_admission_transaction_v1,
    execution_no_apply_admission_transaction_v1,
    require_execution_no_apply_admission_transaction_v1,
};
use crate::journal::{
    CommitResult, JournalError, JournalTransaction, RecordNamespace,
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::{
    CreateFinalityObservationAdmissionDataV1 as Data,
};

#[derive(Clone, Copy)]
enum First {
    Facts,
    Geometry,
    Funding,
    Transaction,
    NativeGeometry,
    NativeFunding,
    Append,
    Readback,
}

#[derive(Default)]
pub(super) struct ObservationAdmissionOriginalV1 {
    facts: Option<Result<FactsV1, ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    native_geometry: Option<Result<ResourceVector, JournalError>>,
    native_funding: Option<Result<(), ResourceReservationErrorV1>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), JournalError>>,
    first: Option<First>,
}

struct FactsV1 {
    operation: [u8; 16],
    request_scope: [u8; 32],
    target: [u8; 16],
    node: [u8; 16],
    holder: [u8; 16],
    project: [u8; 16],
    capability: [u8; 16],
    channel: [u8; 32],
    revision: [u8; 32],
    idempotency: [u8; 32],
    original: RawPairedClockSample,
    cutoff: u64,
    expiry: i64,
}

impl ObservationAdmissionOriginalV1 {
    fn current_failure_v1(&self) -> Option<First> {
        if matches!(self.facts, Some(Err(_))) {
            return Some(First::Facts);
        }
        if matches!(self.geometry, Some(Err(_))) {
            return Some(First::Geometry);
        }
        if matches!(self.funding, Some(Err(_))) {
            return Some(First::Funding);
        }
        if matches!(self.transaction, Some(Err(_))) {
            return Some(First::Transaction);
        }
        if matches!(self.native_geometry, Some(Err(_))) {
            return Some(First::NativeGeometry);
        }
        if matches!(self.native_funding, Some(Err(_))) {
            return Some(First::NativeFunding);
        }
        if matches!(self.append, Some(Err(_))) {
            return Some(First::Append);
        }
        if matches!(self.readback, Some(Err(_))) {
            return Some(First::Readback);
        }
        None
    }

    fn latch_v1(&mut self) {
        if self.first.is_none() {
            self.first = self.current_failure_v1();
        }
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self.first.or_else(|| self.current_failure_v1())? {
            First::Facts => cause(&self.facts),
            First::Geometry => cause(&self.geometry),
            First::Funding => cause(&self.funding),
            First::Transaction => cause(&self.transaction),
            First::NativeGeometry => cause(&self.native_geometry),
            First::NativeFunding => cause(&self.native_funding),
            First::Append => cause(&self.append),
            First::Readback => cause(&self.readback),
        }
    }

    fn require_completed_v1(&self) -> Result<(), JournalError> {
        if matches!(self.append, Some(Ok(_)))
            && matches!(self.readback, Some(Ok(())))
            && self.failure_v1().is_none()
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    // This checks the response only. The new purpose-specific native owner
    // must have completed its real cleanup and exact C append before returning.
    // The fixed original quote pays this pure projection's retained carriers.
    pub(crate) fn require_completed_cleanup_response_data_v2(&self,
        controller: &Journal,
        purpose: aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1,
        response: &aos_sandbox_api::aos::sandbox::v1::Operation,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        use aos_sandbox_protocol::domain_ledger::{
            operation::decode_operation,
            public_operation::{OperationState, PublicRecoveryKindV1},
            provisioning_root::finality_recover::public_operation::{
                stop_cleanup_operation_v1, execution_no_apply_operation_v1,
            },
        };
        let closed = OperatorCreateRecoveryClosedV1;
        let data = self.observation_data_v1().map_err(|_| closed)?;
        let admitted = match purpose {
            PublicRecoveryKindV1::StopCleanup => stop_cleanup_operation_v1(data),
            PublicRecoveryKindV1::ExecutionNoApply => execution_no_apply_operation_v1(data),
            PublicRecoveryKindV1::Ordinary | PublicRecoveryKindV1::MetadataComplete => return Err(closed),
        }.map_err(|_| closed)?;
        let request = self.request.as_ref().and_then(|value| value.as_ref().ok()).ok_or(closed)?;
        if request.public_recovery_kind_v1() != purpose {
            return Err(closed);
        }
        self.admission.require_completed_v1().map_err(|_| closed)?;
        let raw = controller.get(RecordNamespace::Operation, &data.operation).ok_or(closed)?;
        let actual = decode_operation(raw).map_err(|_| closed)?;
        let public = actual.public_operation().ok_or(closed)?;
        let wall = public.completed_wall_seconds_v1().ok_or(closed)?;
        let expected_public = admitted.public_operation().ok_or(closed)?
            .advance(OperationState::Succeeded, wall).map_err(|_| closed)?;
        let expected = admitted.with_state_and_public_operation(OperationState::Succeeded,
            Some(expected_public));
        if actual != expected {
            return Err(closed);
        }
        let transaction = self.admission.transaction.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(closed)?;
        // Only this one Operation successor may change. All three immutable
        // admission members stay byte-exact through the new cleanup interval.
        for row in transaction.records() {
            if row.namespace() == RecordNamespace::Operation {
                if row.key() != data.operation.as_slice() { return Err(closed); }
            } else if controller.get(row.namespace(), row.key()) != row.value() {
                return Err(closed);
            }
        }
        let projected = public.project(aos_sandbox_model::OperationId::from_bytes(data.operation),
            OperationState::Succeeded, 0, 0, false, false, raw, &[]);
        if &projected != response { return Err(closed); }
        Ok(())
    }

    fn observation_data_v1(&self) -> Result<Data<'_>, JournalError> {
        let facts = self
            .admission
            .facts
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let (canonical_request, _, _) = self
            .request
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?
            .observation_input_v1();
        Ok(Data {
            operation: facts.operation,
            request_scope: facts.request_scope,
            target: facts.target,
            node: facts.node,
            holder: facts.holder,
            project: facts.project,
            capability: facts.capability,
            channel: facts.channel,
            authorization_revision: facts.revision,
            idempotency_digest: facts.idempotency,
            original: facts.original,
            cutoff: facts.cutoff,
            wall_expiry: facts.expiry,
            canonical_request,
        })
    }

    fn observation_facts_v1(
        &self,
        controller: &Journal,
        request_scope: crate::controller::ControllerRequestScopeV1,
    ) -> Result<FactsV1, ResourceReservationErrorV1> {
        self.require_native_current_v1(controller)?;
        if !matches!(self.authorization, Some(Ok(_)))
            || !matches!(self.authorization_readback, Some(Ok(_)))
            || self.failure_v1().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let decision = self
            .authorization_native
            .as_ref()
            .and_then(|native| native.decision.as_ref())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let claims = decision.capability().claims();
        let (_, request, target) = self
            .request
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .observation_input_v1();
        let horizon = self
            .horizon
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let node = self
            .bank
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .operator_recover_node_v1(controller, &self.profile)?;
        let holder = claims.holder.into_bytes();
        let idempotency = Data::idempotency_digest_v1(holder, request.idempotency_key());
        let operation = Data::operation_id_v1(&Data::key_from_original_v1(holder, idempotency));
        Ok(FactsV1 {
            operation,
            request_scope: *request_scope.digest().as_bytes(),
            target: target.into_bytes(),
            node: node.into_bytes(),
            holder: claims.holder.into_bytes(),
            project: claims.project.into_bytes(),
            capability: claims.id.into_bytes(),
            channel: *claims.channel_binding.as_bytes(),
            revision: *decision.revision_data_v1().digest().as_bytes(),
            idempotency,
            original: horizon.original,
            cutoff: horizon.cutoff,
            expiry: horizon.expires_wall_seconds,
        })
    }

    pub(crate) fn append_observation_admission_once_v1(
        &mut self,
        controller: &mut Journal,
        request_scope: crate::controller::ControllerRequestScopeV1,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        if self.admission.facts.is_some() {
            return Err(OperatorCreateRecoveryClosedV1);
        }
        let result = (|| {
            self.admission.facts = Some(self.observation_facts_v1(controller, request_scope));
            self.admission.geometry = Some((|| {
                let width = self
                    .observation_data_v1()?
                    .encoded_bytes_v1()
                    .map_err(|cause| JournalError::MetadataComplete(cause.into()))?;
                // Exact row/value/native candidate copies and constructors are
                // paid before the first encoded Vec or transaction grows.
                let (_, request, _) = self.request.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?.observation_input_v1();
                let bytes = aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::
                    metadata_complete_admission_receiving_bytes_v1(width, request.idempotency_key().len())
                    .and_then(|bytes| {
                        bytes.checked_add(Journal::operator_recover_append_carrier_bytes_v1()?)
                    })
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(JournalError::JournalTooLarge)?;
                Ok(ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::MetadataEntries, 4))
            })());
            let geometry = self
                .admission
                .geometry
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied();
            self.admission.funding = Some(match geometry {
                Some(geometry) => self
                    .reached
                    .checked_add(geometry)
                    .map_err(ResourceReservationErrorV1::from)
                    .and_then(|complete| self.require_complete_v1(controller, complete)),
                None => Err(ResourceReservationErrorV1::Conflict),
            });
            if !matches!(self.admission.funding, Some(Ok(()))) {
                return Err(OperatorCreateRecoveryClosedV1);
            }
            self.admission.transaction = Some((|| {
                let data = self.observation_data_v1()?;
                let (_, request, _) = self.request.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?.observation_input_v1();
                use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 as Kind;
                let kind = self.request.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?.public_recovery_kind_v1();
                let transaction = match kind {
                    Kind::MetadataComplete => metadata_complete_admission_transaction_v1(data, request.idempotency_key())?,
                    Kind::StopCleanup => stop_cleanup_admission_transaction_v1(data, request.idempotency_key())?,
                    Kind::ExecutionNoApply => execution_no_apply_admission_transaction_v1(data, request.idempotency_key())?,
                    Kind::Ordinary => return Err(JournalError::ProtectedBoundary),
                };
                for record in transaction.records() {
                    if controller.get(record.namespace(), record.key()).is_some() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                Ok(transaction)
            })());
            self.admission.native_geometry = Some((|| {
                let tx = self
                    .admission
                    .transaction
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                let native = controller
                    .append_receiving_demand_v1(tx.records().iter().map(|record| {
                        aos_sandbox_journal::geometry::RecordShape {
                            key_bytes: record.key().len(),
                            value_bytes: record.value().map(<[u8]>::len),
                        }
                    }))
                    .map_err(|cause| match cause {
                        crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => {
                            cause
                        }
                        crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => {
                            JournalError::ReceivingAccounting(cause)
                        }
                    })?;
                native
                    .checked_add(controller.create_storage_semantic_append_demand_v1()?)
                    .map_err(JournalError::ReceivingAccounting)
            })());
            let geometry = self
                .admission
                .native_geometry
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied();
            self.admission.native_funding = Some(match geometry {
                Some(geometry) => self
                    .reached
                    .checked_add(geometry)
                    .map_err(ResourceReservationErrorV1::from)
                    .and_then(|complete| self.require_complete_v1(controller, complete)),
                None => Err(ResourceReservationErrorV1::Conflict),
            });
            if !matches!(self.admission.native_funding, Some(Ok(()))) {
                return Err(OperatorCreateRecoveryClosedV1);
            }
            self.clock
                .as_mut()
                .ok_or(OperatorCreateRecoveryClosedV1)?
                .check_next_once_v1()
                .map_err(|_| OperatorCreateRecoveryClosedV1)?;
            // Move the whole exact transaction into this lexical crossing,
            // then restore it before any later post or coarse refusal returns.
            let transaction = self.admission.transaction.take();
            let appended = match transaction.as_ref().and_then(|result| result.as_ref().ok()) {
                Some(tx) => controller.commit_operator_recover_observation_v1(self, tx),
                None => Err(JournalError::ProtectedBoundary),
            };
            self.admission.transaction = transaction;
            self.admission.append = Some(appended);
            if !matches!(self.admission.append, Some(Ok(_))) {
                return Err(OperatorCreateRecoveryClosedV1);
            }
            self.admission.readback = Some(self.require_observation_row_v1(controller));
            if !matches!(self.admission.readback, Some(Ok(()))) {
                return Err(OperatorCreateRecoveryClosedV1);
            }
            Ok(())
        })();
        self.admission.latch_v1();
        self.latch_primary_failure_v1();
        result
    }

    pub(crate) fn require_observation_transition_v1(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.require_native_current_v1(controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if !matches!(self.admission.funding, Some(Ok(())))
            || !matches!(self.admission.native_funding, Some(Ok(())))
            || self.admission.append.is_some()
            || self.failure_v1().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let data = self.observation_data_v1()?;
        let (_, request, _) = self.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.observation_input_v1();
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 as Kind;
        match self.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.public_recovery_kind_v1() {
            Kind::MetadataComplete => require_metadata_complete_admission_transaction_v1(data, request.idempotency_key(), transaction)?,
            Kind::StopCleanup => require_stop_cleanup_admission_transaction_v1(data, request.idempotency_key(), transaction)?,
            Kind::ExecutionNoApply => require_execution_no_apply_admission_transaction_v1(data, request.idempotency_key(), transaction)?,
            Kind::Ordinary => return Err(JournalError::ProtectedBoundary),
        }
        for record in transaction.records() {
            if controller.get(record.namespace(), record.key()).is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    /// Rechecks the unchanged new horizon after shared native-before work.
    ///
    /// The same paid gate retires each positive clock prefix before the next
    /// frontier. A failed sampler/comparison stays owned and is never rearmed.
    pub(crate) fn final_observation_crossing_v1(
        &mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.require_observation_transition_v1(controller, transaction)?;
        let result = require_observation_write_clock_v1(&mut self.clock)
            .and_then(|()| self.require_observation_transition_v1(controller, transaction));
        self.latch_primary_failure_v1();
        result
    }

    fn require_observation_bytes_v1(&self, encoded: &[u8]) -> Result<(), JournalError> {
        let expected = self.observation_data_v1()?;
        let actual = Data::decode_v1(encoded)
            .map_err(|cause| JournalError::MetadataComplete(cause.into()))?;
        if actual.operation != expected.operation
            || actual.request_scope != expected.request_scope
            || actual.target != expected.target
            || actual.node != expected.node
            || actual.holder != expected.holder
            || actual.project != expected.project
            || actual.capability != expected.capability
            || actual.channel != expected.channel
            || actual.authorization_revision != expected.authorization_revision
            || actual.idempotency_digest != expected.idempotency_digest
            || actual.original != expected.original
            || actual.cutoff != expected.cutoff
            || actual.wall_expiry != expected.wall_expiry
            || actual.canonical_request != expected.canonical_request
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_observation_row_v1(&self, controller: &Journal) -> Result<(), JournalError> {
        let key = self.observation_data_v1()?.key_v1();
        self.require_observation_bytes_v1(controller.get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(JournalError::ProtectedBoundary)?)?;
        let transaction = self.admission.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::
            require_metadata_complete_admission_rows_v1(transaction,
                controller.historical_read_view_v1().materialized_state_v1())?;
        Ok(())
    }

    pub(crate) fn current_observation_data_v1(&self, controller: &Journal)
        -> Result<Data<'_>, JournalError> {
        self.require_observation_current_v1(controller)?;
        self.observation_data_v1()
    }

    pub(super) fn require_observation_current_v1(
        &self,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        self.admission.require_completed_v1()?;
        self.require_observation_row_v1(controller)
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

// The append loan invokes this only at the actual final write frontier. The
// earlier preparation sample cannot substitute for this later observation.
fn require_observation_write_clock_v1(
    clock: &mut Option<crate::policy_compiler::provisioning_current::RootContinuationClockGateV1>,
) -> Result<(), JournalError> {
    clock.as_mut().ok_or(JournalError::ProtectedBoundary)?
        .check_next_once_v1().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::RetainedControllerProtectedClockAttemptV1;
    use crate::policy_compiler::provisioning_current::{
        RootContinuationClockGateV1, RootContinuationHorizonDataV1,
    };

    #[test]
    fn final_write_rejects_expiry_after_an_earlier_positive_frontier() {
        let mut original = RetainedControllerProtectedClockAttemptV1::default();
        let first = original.observe_once_v1().unwrap();
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            first, first.boottime_nanoseconds().checked_add(65_000_000_000).unwrap(),
        ).unwrap();
        let mut gate = RootContinuationClockGateV1::new_controller_authorization_v1(horizon);
        let prepared = gate.check_next_once_v1().unwrap();
        let narrowed = RootContinuationHorizonDataV1::from_original_data_v1(
            first, prepared.boottime_nanoseconds().checked_add(1).unwrap(),
        ).unwrap();
        gate.narrow_horizon_data_v1(narrowed).unwrap();
        let mut clock = Some(gate);

        assert!(require_observation_write_clock_v1(&mut clock).is_err());
        let retained = clock.as_ref().unwrap().failure().unwrap().to_string();
        assert!(require_observation_write_clock_v1(&mut clock).is_err());
        assert_eq!(clock.as_ref().unwrap().failure().unwrap().to_string(), retained);
    }
}
