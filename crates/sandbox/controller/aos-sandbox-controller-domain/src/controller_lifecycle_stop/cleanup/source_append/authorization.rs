//! Borrows the actual funded Source22/native writer for one literal A8 pair.

use super::*;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::protected_journal::LifecycleProtectedJournalProjectionV1;
use crate::lifecycle::{LifecycleHistoricalReadOriginalV1, LifecycleJournalVerifierV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1 as Pair;
use crate::{JournalError, JournalTransaction};
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use std::cell::RefCell;

pub(super) struct AppendNativeOriginalV1 {
    expected_operation: Option<
        std::result::Result<
            Vec<u8>,
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError,
        >,
    >,
    transaction: Option<JournalTransaction>,
    validation: Option<std::result::Result<(), JournalError>>,
    current: Option<Result<()>>,
    binding: Option<Result<()>>,
    binding_entered: bool,
    before: Pair,
    before_result: Option<std::result::Result<RawPairedClockSample, JournalError>>,
    publication: Option<std::result::Result<(), JournalError>>,
    after: Pair,
    after_result: Option<std::result::Result<RawPairedClockSample, JournalError>>,
    crossed: bool,
    pub(super) successor: Option<SourceProvisioningIdentityV1>,
    existing: bool,
    readonly_before: Option<Result<()>>,
    readonly_after: Option<Result<()>>,
}

impl AppendNativeOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            expected_operation: None,
            transaction: None,
            validation: None,
            current: None,
            binding: None,
            binding_entered: false,
            before: Default::default(),
            before_result: None,
            publication: None,
            after: Default::default(),
            after_result: None,
            crossed: false,
            successor: None,
            existing: false,
            readonly_before: None,
            readonly_after: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.body_failure()
            .or_else(|| error(&self.readonly_after))
            .or_else(|| self.after.failure())
            .or_else(|| {
                self.after_result.as_ref()?.as_ref().err().map(|cause| cause as _)
            })
    }

    // Owed posts remain resident but cannot replace a selected body cause.
    pub(super) fn body_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.expected_operation
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| error(&self.current))
            .or_else(|| {
                self.validation
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| error(&self.binding))
            .or_else(|| error(&self.readonly_before))
            .or_else(|| self.before.failure())
            .or_else(|| {
                self.before_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.publication
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    pub(super) fn completed(&self) -> bool {
        self.failure().is_none()
            && self.crossed
            && matches!(self.after_result, Some(Ok(_)))
            && if self.existing {
                self.binding.is_none()
                    && self.publication.is_none()
                    && matches!(self.readonly_before, Some(Ok(())))
                    && matches!(self.readonly_after, Some(Ok(())))
            } else {
                matches!(self.binding, Some(Ok(()))) && matches!(self.publication, Some(Ok(())))
            }
    }
}

/// Borrows genuine Source22 originals for the existing shared append engine.
///
/// Its constructor is private to the paid Source22 driver. Neither a digest
/// nor a canonical A8 row constructs this view or selects its Cache gate.
pub(crate) struct StopCleanupSourceAppendAuthorizationV1<'held> {
    read: &'held LifecycleHistoricalReadOriginalV1,
    identity: &'held SourceProvisioningIdentityV1,
    state: &'held RefCell<AppendNativeOriginalV1>,
    bank: &'held Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &'held ProductionControllerNormalRootProfileV1,
    controller_native: &'held ControllerCreateProvisioningReceivingV1,
    controller: &'held Journal,
    original: &'held StopCleanupOriginalV1,
    proof: &'held StopCleanupCompletionOriginalV1<'held>,
}

impl<'held> StopCleanupSourceAppendAuthorizationV1<'held> {
    pub(super) fn new(
        read: &'held LifecycleHistoricalReadOriginalV1,
        identity: &'held SourceProvisioningIdentityV1,
        state: &'held RefCell<AppendNativeOriginalV1>,
        bank: &'held Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &'held ProductionControllerNormalRootProfileV1,
        controller_native: &'held ControllerCreateProvisioningReceivingV1,
        controller: &'held Journal,
        original: &'held StopCleanupOriginalV1,
        proof: &'held StopCleanupCompletionOriginalV1<'held>,
    ) -> Self {
        Self {
            read,
            identity,
            state,
            bank,
            profile,
            controller_native,
            controller,
            original,
            proof,
        }
    }

    pub(crate) fn require_current_v1(&self) -> std::result::Result<(), JournalError> {
        if self.original.failure().is_some()
            || self.original.posts.is_some()
            || !self
                .original
                .controller
                .is_same_original_v4(&self.controller.execution_observation_identity_v4())
            || self.original.subject != self.proof.subject
            || self.original.dispatch_record != self.proof.data.binding_v1().dispatch_record
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if self
            .state
            .borrow()
            .current
            .as_ref()
            .is_some_and(std::result::Result::is_err)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let result = (|| {
            self.bank
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_lifecycle_stop_native_current_v4(
                    self.controller_native,
                    self.controller,
                    self.profile,
                )
        })();
        self.state.borrow_mut().current = Some(result);
        if matches!(self.state.borrow().current, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn require_source_prefix_v1(
        &self,
        source: &Journal,
    ) -> std::result::Result<(), JournalError> {
        self.require_current_v1()?;
        source.require_current_source_provisioning_identity_v1(self.identity)?;
        self.proof
            .require_current_v1(source, &self.original.subject)
            .map(|_| ())
    }

    pub(crate) fn completion_data_v1(&self) -> &LifecycleStopCompletionDataV1 {
        &self.proof.data
    }

    pub(crate) fn read_v1(&self) -> &'held LifecycleHistoricalReadOriginalV1 {
        self.read
    }

    pub(crate) fn projection_v1(
        &self,
    ) -> std::result::Result<
        (
            &'held LifecycleProtectedJournalProjectionV1,
            &'held LifecycleJournalVerifierV1,
        ),
        JournalError,
    > {
        self.read_v1().projection_ready_v1()
    }

    pub(crate) fn transaction_id_v1(&self) -> [u8; 16] {
        let binding = self.proof.data.binding_v1();
        let prefix = b"stop-cleanup-completion";
        let mut purpose = [0; b"stop-cleanup-completion".len() + 16];
        purpose[..prefix.len()].copy_from_slice(prefix);
        purpose[prefix.len()..].copy_from_slice(binding.recovery.as_bytes());
        crate::lifecycle::lifecycle_progress_transaction_id_v1(
            binding.operation,
            binding.operation_record,
            &purpose,
        )
    }

    pub(crate) fn lineage_v1(&self, operation_member: bool) -> aos_sandbox_model::ResourceId {
        crate::lifecycle::lifecycle_plan_resource_id_v5(
            OperationId::from_bytes(self.transaction_id_v1()),
            if operation_member {
                b"stop-cleanup-operation"
            } else {
                b"stop-cleanup-evidence"
            },
        )
    }

    // Planning prepares the exact literal transaction before the common
    // semantic preflight. Later calls must borrow that same immutable literal.
    pub(crate) fn precheck_transaction_once_v1(
        &self,
        source: &Journal,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        self.require_source_prefix_v1(source)?;
        if self.state.borrow().validation.is_some() {
            return self.require_prechecked_transaction_v1(transaction);
        }
        let result = self.check_candidate(transaction);
        let mut state = self.state.borrow_mut();
        state.validation = Some(result);
        if matches!(state.validation, Some(Ok(()))) {
            state.transaction = Some(transaction.clone());
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn check_candidate(
        &self,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
            LifecycleAuxiliaryEnvelopeFormatV1, borrow_lifecycle_auxiliary_member_data_v1,
        };
        self.require_current_v1()?;
        if *transaction.id() != self.transaction_id_v1() || transaction.records().len() != 2 {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut state = self.state.borrow_mut();
        state.expected_operation = Some(crate::lifecycle::encode_lifecycle_auxiliary_payload_v1(
            &crate::lifecycle::LifecycleAuxiliaryPayloadV1::Operation(
                self.read_v1().operation_v1()?.0.clone(),
            ),
        ));
        let expected_operation = state
            .expected_operation
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let mut kinds = 0_u16;
        for record in transaction.records() {
            if record.namespace() != crate::RecordNamespace::DesiredState {
                return Err(JournalError::ProtectedBoundary);
            }
            let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
            let frame =
                borrow_lifecycle_auxiliary_member_data_v1(record.key(), value, transaction.id())
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            if frame.format != LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion
                || frame.operation != self.proof.data.operation()
                || frame.operation_record != self.proof.historical.digest()
                || frame.atomic_join.as_bytes() != transaction.id()
                || frame.declared_members != 0x101
                || frame.declared_count != 2
                || !matches!(frame.kind, 0 | 8)
                || frame.lineage != self.lineage_v1(frame.kind == 0)
                || kinds & (1 << frame.kind) != 0
            {
                return Err(JournalError::ProtectedBoundary);
            }
            if frame.kind == 0 {
                if frame.payload != expected_operation {
                    return Err(JournalError::ProtectedBoundary);
                }
            } else if LifecycleStopCompletionDataV1::from_bytes(frame.payload)
                .map_err(|_| JournalError::ProtectedBoundary)?
                != self.proof.data
            {
                return Err(JournalError::ProtectedBoundary);
            }
            kinds |= 1 << frame.kind;
        }
        if kinds != 0x101 {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_prechecked_transaction_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        self.require_current_v1()?;
        let state = self.state.borrow();
        if !matches!(state.validation, Some(Ok(())))
            || state.transaction.as_ref() != Some(transaction)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn bind_prepared_source_once_v1(
        &self,
        source: &mut Journal,
        native: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        self.require_source_prefix_v1(source)?;
        self.require_prechecked_transaction_v1(transaction)?;
        if self.state.borrow().binding_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.state.borrow_mut().binding_entered = true;
        let result = (|| {
            let bank = self.bank.lock().map_err(|_| CLOSED)?;
            bank.bind_provisioning_source_native_v1(
                native,
                self.controller_native,
                self.controller,
                source,
                self.profile,
                transaction,
            )
        })();
        self.state.borrow_mut().binding = Some(result);
        if matches!(self.state.borrow().binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn begin_existing_read_once_v1(
        &self,
        source: &Journal,
        native: &mut SourceProvisioningCurrentnessOriginalV1,
    ) -> std::result::Result<(), JournalError> {
        self.require_source_prefix_v1(source)?;
        {
            let state = self.state.borrow();
            if state.binding_entered
                || state.readonly_before.is_some()
                || state.before_result.is_some()
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        // The existing A8 remains settlement history. The native read is paid
        // by the fresh Source22 and completed Root/index1 proof, never old48.
        self.state.borrow_mut().existing = true;
        let result = self.observe_readonly_native(source, native);
        self.state.borrow_mut().readonly_before = Some(result);
        if !matches!(self.state.borrow().readonly_before, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut state = self.state.borrow_mut();
        let result = self.observe_clock(&mut state.before);
        state.before_result = Some(result);
        if matches!(state.before_result, Some(Ok(_))) {
            state.crossed = true;
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn observe_readonly_native(
        &self,
        source: &Journal,
        native: &mut SourceProvisioningCurrentnessOriginalV1,
    ) -> Result<()> {
        self.bank
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_provisioning_source_readonly_current_v1(
                native,
                self.controller_native,
                self.controller,
                source,
                self.profile,
            )
    }

    pub(crate) fn final_append_gate_once_v1(
        &self,
        source: &Journal,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        self.require_source_prefix_v1(source)?;
        self.require_prechecked_transaction_v1(transaction)?;
        let mut state = self.state.borrow_mut();
        if !matches!(state.binding, Some(Ok(()))) || state.before_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let result = self.observe_clock(&mut state.before);
        state.before_result = Some(result);
        if matches!(state.before_result, Some(Ok(_))) {
            state.crossed = true;
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn observe_clock(
        &self,
        clock: &mut Pair,
    ) -> std::result::Result<RawPairedClockSample, JournalError> {
        let sample = clock
            .observe_once(None)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        require_cleanup_clock(
            sample,
            *positive(&self.original.first).map_err(|_| JournalError::ProtectedBoundary)?,
            (*positive(&self.original.cutoff).map_err(|_| JournalError::ProtectedBoundary)?)
                .min(self.proof.cutoff),
            self.original.admission.wall_expiry.min(self.proof.expiry),
        )
        .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok(sample)
    }

    pub(crate) fn require_published_source_successor_once_v1(
        &self,
        source: &Journal,
        native: &mut SourceProvisioningCurrentnessOriginalV1,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        self.require_prechecked_transaction_v1(transaction)?;
        if self.state.borrow().publication.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let result = (|| {
            let successor = source.stop_cleanup_completion_source_successor_v1(
                native,
                self.identity,
                transaction,
            )?;
            self.state.borrow_mut().successor = Some(successor);
            Ok(())
        })();
        self.state.borrow_mut().publication = Some(result);
        if matches!(self.state.borrow().publication, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn observe_existing_source_owed_after_v1(
        &self,
        source: &Journal,
        native: &mut SourceProvisioningCurrentnessOriginalV1,
    ) -> std::result::Result<(), JournalError> {
        if self.state.borrow().existing {
            if self.state.borrow().readonly_after.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            // A refused read still owes its independent original native post.
            let result = self.observe_readonly_native(source, native);
            self.state.borrow_mut().readonly_after = Some(result);
        }
        if self
            .state
            .borrow()
            .readonly_after
            .as_ref()
            .is_some_and(std::result::Result::is_err)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn observe_source_append_owed_after_v1(
        &self,
    ) -> std::result::Result<(), JournalError> {
        let mut state = self.state.borrow_mut();
        if !state.binding_entered && !state.existing {
            return Ok(());
        }
        if state.after_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        // No healthy-body gate or financial reentry precedes this owed post.
        let result = self.observe_clock(&mut state.after);
        state.after_result = Some(result);
        if matches!(state.after_result, Some(Ok(_))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }
}
