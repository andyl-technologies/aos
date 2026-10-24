//! Borrows the genuine Source receiver for the shared native Controller append.
//!
//! Each crossing retains its forecast metadata, exact transaction, writer
//! identity, native before/final/after clocks and independent name posts. A
//! durable append followed by failed readback or posts never issues ACK DATA.

use aos_sandbox_model::RawPairedClockSample;


use super::*;

pub(super) use crate::closed_controller_append::ClosedControllerAppendOriginalV2 as AppendOriginalV2;
use crate::closed_controller_append::{ClosedControllerAppendFirstV2 as First, require_clock};
pub(in crate::controller_execution_operation::no_apply_client) use crate::closed_controller_append::require_current_map;

/// Borrows the exact actual Source/C18 receiver and one paid native crossing.
pub(crate) struct ControllerExecutionNoApplyAppendLoanV2<'append, 'source, 'original> {
    recovery_metadata_operation: Option<OperationId>,
    source: &'append ControllerExecutionReadReceivingLoanV1<'source, 'original>,
    stage: &'append mut AppendOriginalV2,
    expected: Cut,
    boot: [u8; 16],
    cutoff: u64,
}

impl ControllerExecutionNoApplyAppendLoanV2<'_, '_, '_> {
    pub(crate) fn require_transition(
        &mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self.stage.transition.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.stage.transition = Some((|| {
            positive(&self.stage.before)?;
            positive(&self.stage.forecast)?;
            positive(&self.stage.funding)?;
            if Some(transaction) != self.stage.transaction.as_ref() {
                return Err(JournalError::ProtectedBoundary);
            }
            if transaction.records().iter().any(|row| {
                row.namespace() == RecordNamespace::ControllerCreateFailurePrepare
                    && row.key() != self.source.operation_v1().as_bytes()
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
            let records = transaction.records();
            let prepare = records.len() == 1
                && records[0].namespace() == RecordNamespace::ControllerCreateFailurePrepare;
            let terminal = records.len() == 3
                && records[0].namespace() == RecordNamespace::Effect
                && records[1].namespace() == RecordNamespace::Operation
                && records[2].namespace() == RecordNamespace::DesiredState
                && records[1].key() == self.source.operation_v1().as_bytes();
            let recovery_metadata = self.recovery_metadata_operation.is_some_and(|operation|
                records.len() == 1 && records[0].namespace() == RecordNamespace::Operation
                    && records[0].key() == operation.as_bytes());
            if !prepare && !terminal && !recovery_metadata {
                return Err(JournalError::ProtectedBoundary);
            }
            require_current_map(controller, self.expected)
        })());
        positive(&self.stage.transition).map(|_| ())
    }

    pub(crate) fn require_prechecked_transaction_v2(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        positive(&self.stage.transition)?;
        if Some(transaction) != self.stage.transaction.as_ref() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_crossing(&mut self, controller: &Journal) -> Result<(), JournalError> {
        self.stage.final_crossing_once(controller, self.expected, self.boot, self.cutoff)
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    pub(in crate::controller_execution_operation::no_apply_client) fn run_recovery_metadata_append_once_v2(
        &mut self,
        root: &crate::normal_root::RootExecutionNoApplyClientOriginalV2,
    ) -> Result<ControllerExecutionNoApplyRecoveredMetadataV2, ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::{operation::{decode_operation, OPERATION_RECORD_V2_BYTES},
            provisioning_root::finality_recover::{CreateFinalityObservationAdmissionDataV1 as Admission,
                finality_admission_commitment_v1, public_operation::closed_cleanup_terminal_transaction_data_v2}};
        self.native()?;
        let cleanup = self.native.cleanup.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.native.active != 5 || !self.native.retirement_issued {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let reference = cleanup.admission;
        let boot = cleanup.first.host_boot_id();
        let cutoff = self.no_apply_cutoff_data_v2()?;
        let horizon = self.cleanup_clock_horizon_v2()?;
        let ack = self.controller_acknowledgement_data_v2()?;
        root.require_completed_controller_acknowledgement_v2(&ack)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if self.native.settlement.as_ref().is_none_or(|original| original.recovery_metadata.is_some()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bytes = aos_sandbox_protocol::domain_ledger::public_operation::metadata_complete_projection_receiving_bytes_v1()
            .and_then(|n| n.checked_add(OPERATION_RECORD_V2_BYTES.checked_mul(4)?))
            .and_then(|n| n.checked_add(size_of::<JournalTransaction>().checked_mul(3)?))
            .and_then(|n| n.checked_add(size_of::<ControllerExecutionNoApplyRecoveredMetadataV2>().checked_mul(3)?))
            .and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, bytes);
        let complete = self.complete_transport_base_v2(demand)?;
        let funded = self.require_transport_complete_v2(complete);
        self.native.settlement.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?.recovery_funding = Some(funded);
        if !matches!(self.native.settlement.as_ref().and_then(|original| original.recovery_funding.as_ref()), Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.base = self.base.checked_add(demand)?;
        let original = self.native.settlement.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        original.stages[2].cleanup_horizon = horizon;
        original.stages[2].begin(self.controller, ack.controller_cut, boot, cutoff);
        let body = (|| -> Result<(), JournalError> {
            let original = self.native.settlement.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            positive(&original.stages[2].before)?;
            let sample = *positive(&original.stages[2].samples[0])?;
            let raw = self.controller.get(RecordNamespace::OperatorRecovery, &reference.key)
                .ok_or(JournalError::ProtectedBoundary)?;
            if finality_admission_commitment_v1(raw) != reference.commitment {
                return Err(JournalError::ProtectedBoundary);
            }
            let data = Admission::decode_v1(raw).map_err(|_| JournalError::ProtectedBoundary)?;
            if data.original != reference.original || data.cutoff != reference.cutoff
                || data.wall_expiry != reference.wall_expiry || data.target != *self.source.operation_v1().as_bytes() {
                return Err(JournalError::ProtectedBoundary);
            }
            let operation = OperationId::from_bytes(data.operation);
            let admitted = decode_operation(self.controller.get(RecordNamespace::Operation, &data.operation)
                .ok_or(JournalError::ProtectedBoundary)?).map_err(|_| JournalError::ProtectedBoundary)?;
            original.recovery_operation = Some(operation);
            original.recovery_model = Some(closed_cleanup_terminal_transaction_data_v2(
                aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::ExecutionNoApply,
                data, admitted, sample));
            let transaction = positive(&original.recovery_model)?.clone();
            self.run_controller_append(2, transaction, ack.controller_cut)
        })();
        let original = self.native.settlement.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        if original.stages[2].transaction.is_none() {
            // Model/row refusal still owes the paid names and paired-clock
            // after. No fresh Source debit or healthy-body gate intervenes.
            original.stages[2].finish(self.controller, ack.controller_cut, boot, cutoff);
        }
        original.recovery_metadata = Some(body);
        positive(&original.recovery_metadata).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let cut = original.stages[2].after_cut().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if cut.next() != ack.controller_cut.next().checked_add(3).ok_or(ResourceReservationErrorV1::Conflict)? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        crate::reconciler::require_closed_no_apply_terminal_ack_data_v2(self.controller, ack)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let operation = original.recovery_operation.ok_or(ResourceReservationErrorV1::Conflict)?;
        let raw = self.controller.get(RecordNamespace::Operation, operation.as_bytes())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let record = decode_operation(raw).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let public = record.public_operation().ok_or(ResourceReservationErrorV1::Conflict)?;
        let response = public.project(operation,
            aos_sandbox_protocol::domain_ledger::public_operation::OperationState::Succeeded,
            0, 0, false, false, raw, &[]);
        Ok(ControllerExecutionNoApplyRecoveredMetadataV2::from_native_v2(
            self.controller.execution_observation_identity_v4(), self.source.operation_v1(), operation, ack, cut, response))
    }

    pub(super) fn run_controller_terminal_replay_once_v2(
        &mut self, expected: Cut, prepare: Prepare,
    ) -> Result<(), JournalError> {
        let boot = self.native.cleanup.as_deref().ok_or(JournalError::ProtectedBoundary)?
            .first.host_boot_id();
        let cutoff = self.no_apply_cutoff_data_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let horizon = self.cleanup_clock_horizon_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let original = self.native.settlement.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let stage = &mut original.stages[1];
        stage.cleanup_horizon = horizon;
        if stage.before.is_some() || stage.replay.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        // Settled cleanup runs actual paid names/clock before/final/after, but
        // never manufactures an append result or rewrites the terminal rows.
        if stage.before.is_none() {
            stage.begin(self.controller, expected, boot, cutoff);
        }
        if stage.first.is_none() {
            stage.samples[1] = Some(stage.clocks[1].sample_v1());
            stage.crossing = Some((|| {
                require_clock(&stage.samples[1], boot, cutoff, stage.cleanup_horizon)?;
                require_current_map(self.controller, expected)
            })());
            stage.replay = Some((|| {
                positive(&stage.crossing)?;
                crate::reconciler::require_closed_no_apply_terminal_ack_data_v2(self.controller, Ack {
                    operation: prepare.operation, root_floor: prepare.root_floor,
                    root_sequence: prepare.root_sequence, controller_prepare: prepare.digest(),
                    settled_cas: prepare.settled_cas_digest(), phase: AckPhase::RecoverySettled,
                    controller_cut: expected,
                }).map_err(|_| JournalError::ProtectedBoundary)
            })());
            if !matches!(stage.replay, Some(Ok(()))) { stage.first.get_or_insert(First::Append); }
        }
        // This independent post is owed even after exact terminal validation
        // or final paired-clock failure, with no fresh financial gate.
        stage.finish(self.controller, expected, boot, cutoff);
        stage.readback = Some((|| {
            positive(&stage.replay)?;
            let actual = stage.physical_cut(self.controller, 1)?;
            if actual != expected { return Err(JournalError::StaleAuthoritySnapshot); }
            require_current_map(self.controller, expected)?;
            Ok(actual)
        })());
        if !matches!(stage.readback, Some(Ok(_))) { stage.first.get_or_insert(First::Readback); }
        stage.complete()
    }

    pub(super) fn run_controller_append(
        &mut self,
        index: usize,
        transaction: JournalTransaction,
        expected: Cut,
    ) -> Result<(), JournalError> {
        let boot = self.native.cleanup.as_deref().map(|cleanup| cleanup.first.host_boot_id())
            .unwrap_or(self.native.source.fields().host_boot);
        let cutoff = self.no_apply_cutoff_data_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let horizon = self.cleanup_clock_horizon_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        let stage = &mut original.stages[index];
        stage.cleanup_horizon = horizon;
        if stage.transaction.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        stage.transaction = Some(transaction);
        if stage.before.is_none() {
            stage.begin(self.controller, expected, boot, cutoff);
        }

        // This same forecast and native readback engine is shared by the
        // distinct closed cleanup payers; financial admission stays here.
        stage.forecast_once(self.controller)?;
        let demand = stage
            .forecast
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied();
        if let Some(demand) = demand {
            let funding = (|| {
                let complete = self.complete_transport_base_v2(demand)?;
                self.require_transport_complete_v2(complete)?;
                self.base = self.base.checked_add(demand)?;
                Ok(())
            })();
            let stage = &mut self
                .native
                .settlement
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .stages[index];
            stage.funding = Some(funding);
            if !matches!(stage.funding, Some(Ok(()))) {
                stage.first.get_or_insert(First::Funding);
            }
        }
        let original = self
            .native
            .settlement
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        let stage = &mut original.stages[index];
        if stage.first.is_none() {
            // Duplicate the transaction within its prepaid representation to
            // avoid aliasing the mutable stage. The loan compares the literal via
            // the separately paid duplicate, never caller-selected rows.
            let transaction = stage
                .transaction
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .clone();
            let mut loan = ControllerExecutionNoApplyAppendLoanV2 {
                recovery_metadata_operation: if index == 2 { original.recovery_operation } else { None },
                source: &mut self.source,
                stage: &mut *stage,
                expected,
                boot,
                cutoff,
            };
            let appended = self
                .controller
                .commit_execution_no_apply_controller_original_v2(&transaction, &mut loan);
            loan.stage.append = Some(appended);
            if !matches!(loan.stage.append, Some(Ok(_))) {
                loan.stage.first.get_or_insert(First::Append);
            }
        }
        stage.finish_append_once(self.controller, expected, boot, cutoff)
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    fn cleanup_clock_horizon_v2(&self) -> Result<Option<(RawPairedClockSample, i64)>, ResourceReservationErrorV1> {
        let Some(cleanup) = self.native()?.cleanup.as_deref() else { return Ok(None) };
        let acquisition = cleanup.acquisition_fields.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(Some((cleanup.first, cleanup.admission.wall_expiry.min(acquisition.policy_expires_at))))
    }
}
