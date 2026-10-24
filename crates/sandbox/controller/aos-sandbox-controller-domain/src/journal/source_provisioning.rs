//! Restricts one actual Source provisioning crossing to its canonical plan.
//!
//! The planner and append both use the ordinary schema/CAS engines. This loan
//! only selects the retained Q04 boundary for that exact transaction; the
//! ordinary Cache mutation interlock remains active on both paths.

use std::sync::Arc;

use super::*;
use crate::controller_resource_reservation::SourceAppendBoundaryV1;

pub(crate) struct SourceProvisioningIdentityV1 {
    instance: Arc<JournalAuthorityInstance>,
    sequence: u64,
}

#[derive(Clone, Copy)]
enum StopSourcePublicationV1 { Dispatch, Completion }

#[derive(Clone, Copy)]
pub(crate) struct SourceProvisioningAppendLoanV1<'loan> {
    authorization: SourceAppendBoundaryV1<'loan>,
    transaction: &'loan JournalTransaction,
}

impl SourceProvisioningAppendLoanV1<'_> {
    pub(crate) fn require_transition(&self, journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.authorization.require_current_v1()?;
        let identity = self.authorization.source_identity_v1();
        if !Arc::ptr_eq(&identity.instance, &journal.authority_instance)
            || identity.sequence != journal.snapshot_sequence()
            || transaction != self.transaction || transaction.records().len() != 1 {
            return Err(JournalError::ProtectedBoundary);
        }
        // The closed lifecycle planner has already validated and encoded this
        // exact first Intent. No other namespace, key, deletion or sibling
        // operation can acquire this Source boundary exception.
        let expected = self.authorization.expected_key_v1()?;
        require_exact_source_provisioning_record_v1(
            transaction, &expected, self.authorization.transaction_id_v1()?,
        )?;
        self.require_retained_source_cut_v1(journal.native.state())
    }

    pub(crate) fn require_retained_source_cut_v1(&self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), JournalError> {
        let cut = self.authorization.q04_v1();
        let current = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)
            .map_err(JournalError::from)?;
        let pending = current.q04_pending.ok_or(JournalError::ProtectedBoundary)?;
        let hold = current.hold.ok_or(JournalError::ProtectedBoundary)?;
        if current.delete_pending.is_some() || current.v8_pending.is_some()
            || pending.is_held() || hold.is_held() || hold.operation() != cut.operation()
            || hold.sandbox() != cut.sandbox() {
            return Err(JournalError::ProtectedBoundary);
        }
        pending.require_identity(cut).map_err(JournalError::from)
    }

    pub(crate) fn final_crossing(&self, journal: &Journal) -> Result<(), JournalError> {
        self.require_transition(journal, self.transaction)?;
        self.authorization.final_native_cut_v2()
    }
}

impl Journal {
    pub(crate) fn source_provisioning_identity_v1(&self)
        -> Result<SourceProvisioningIdentityV1, JournalError> {
        self.ensure_healthy()?;
        if !matches!(&self.native, super::native_backing::JournalNativeBackingV1::Source(_)) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(SourceProvisioningIdentityV1 {
            instance: Arc::clone(&self.authority_instance), sequence: self.snapshot_sequence(),
        })
    }

    pub(crate) fn source_provisioning_loan_v1<'loan>(
        &self, authorization: SourceAppendBoundaryV1<'loan>,
        transaction: &'loan JournalTransaction,
    ) -> Result<SourceProvisioningAppendLoanV1<'loan>, JournalError> {
        let loan = SourceProvisioningAppendLoanV1 { authorization, transaction };
        loan.require_transition(self, transaction)?;
        Ok(loan)
    }

    pub(crate) fn preflight_source_provisioning_v1(&self,
        transactions: &[JournalTransaction], loan: &SourceProvisioningAppendLoanV1<'_>,
    ) -> Result<(), JournalError> {
        if transactions.len() != 1 {
            return Err(JournalError::ProtectedBoundary);
        }
        loan.require_transition(self, &transactions[0])?;
        self.preflight_with_source_provisioning_v1(transactions, loan)
    }

    pub(crate) fn commit_source_provisioning_v1(&mut self,
        transaction: &JournalTransaction, loan: &mut SourceProvisioningAppendLoanV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_create_storage_original_v1(transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::SourceProvisioning(loan))
    }
}

impl Journal {
    pub(crate) fn begin_source_provisioning_native_v1<C>(&mut self,
        original: &mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .begin_provisioning_currentness_once_v1(original, controller, launch, profile, complete)
                .map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn bind_source_provisioning_native_v1<C>(&mut self,
        source_original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .bind_provisioning_transaction_once_v1(source_original, original, controller,
                    launch, profile, transaction).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn finish_source_provisioning_native_v1(&self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
    ) -> Result<(), JournalError> {
        match &self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .finish_provisioning_currentness_once_v1(original).map_err(JournalError::SourceNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn dispose_source_provisioning_native_v1<C>(&mut self,
        source_original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .dispose_provisioning_currentness_after_posts_v1(source_original, original,
                    controller, launch, profile).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }
}


impl Journal {
    pub(crate) fn prearm_source_completion_native_v1<C>(&mut self,
        original: &mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .prearm_completion_source_currentness_once_v1(original, controller, launch, profile, complete).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn enter_source_completion_native_v1<C>(&self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        destination: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1,
        completed: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match & self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .enter_completion_source_currentness_once_v1(original, destination, completed, controller, launch, profile).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn bind_source_completion_native_v1<C>(&mut self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        destination: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1,
        completed: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .bind_completion_source_transaction_once_v1(original, destination, completed, controller, launch, profile, transaction).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }

    pub(crate) fn dispose_source_completion_native_v1<C>(&mut self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        destination: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1,
        completed: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &mut self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .dispose_completion_source_currentness_once_v1(original, destination, completed, controller, launch, profile).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }
}

// This is an association with the existing writer instance, never a journal
// constructor or mutation grant. It remains comparable after native poison.
pub(crate) struct CreateStoppedControllerIdentityV1 { instance: Arc<JournalAuthorityInstance> }

impl Journal {
    pub(crate) fn create_stopped_controller_identity_v1(&self) -> Result<CreateStoppedControllerIdentityV1,JournalError> {
        self.controller_coordinator_for_bank_read_v1()?;
        Ok(CreateStoppedControllerIdentityV1 {instance:Arc::clone(&self.authority_instance)})
    }

    pub(crate) fn fence_create_stopped_completion_v1(&mut self, identity:&CreateStoppedControllerIdentityV1)
        -> Result<(),JournalError> {
        if !Arc::ptr_eq(&self.authority_instance,&identity.instance) {return Err(JournalError::ProtectedBoundary);}
        self.native.poison();
        Ok(())
    }
}


// The same closed Source loan follows the canonical phase-selected key. Intent
// is DesiredState, effect progress is Effect, and terminal is Operation; the
// namespace must come from that actual typed key rather than the first phase.
fn require_exact_source_provisioning_record_v1(
    transaction: &JournalTransaction,
    expected: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
    transaction_id: [u8; 16],
) -> Result<(), JournalError> {
    use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaV1;
    use crate::lifecycle::protected_journal::LifecycleProtectedJournalSchemaV1;

    let [record] = transaction.records() else {
        return Err(JournalError::ProtectedBoundary);
    };
    if record.namespace() != LifecycleProtectedJournalSchemaV1::namespace(expected.kind())
        || record.key() != expected.as_bytes()
        || record.value().is_none()
        || transaction.id() != &transaction_id
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod keylaw_tests {
    use super::*;
    use aos_sandbox_model::{OperationId, ProjectId, ResourceId};
    use crate::lifecycle::{LifecyclePhaseV1, LifecycleProtectedRecordKindV1,
        lifecycle_protected_key_v1, provisioning_operation_record_kind_v1};

    #[test]
    fn closed_source_append_uses_each_actual_phase_selected_namespace() {
        let project = ProjectId::from_bytes([1; 16]);
        let sandbox = ResourceId::from_bytes([2; 16]);
        let parent = OperationId::from_bytes([3; 16]);
        let transaction_id = [4; 16];
        let phases = [
            (LifecyclePhaseV1::Accepted, RecordNamespace::DesiredState),
            (LifecyclePhaseV1::Prepared, RecordNamespace::Effect),
            (LifecyclePhaseV1::ReadyToCommit, RecordNamespace::Operation),
            (LifecyclePhaseV1::Committed, RecordNamespace::Operation),
            (LifecyclePhaseV1::Completing, RecordNamespace::Effect),
            (LifecyclePhaseV1::Terminal, RecordNamespace::Operation),
        ];

        for (phase, namespace) in phases {
            let kind = provisioning_operation_record_kind_v1(phase);
            let key = lifecycle_protected_key_v1(kind, project, sandbox, parent).unwrap();
            let transaction = JournalTransaction::new(transaction_id, vec![JournalRecord::put(
                namespace, key.as_bytes().to_vec(), vec![1],
            )]).unwrap();
            assert!(require_exact_source_provisioning_record_v1(&transaction, &key, transaction_id).is_ok());

            for (_, other_namespace) in phases {
                if other_namespace == namespace { continue; }
                let wrong = JournalTransaction::new(transaction_id, vec![JournalRecord::put(
                    other_namespace, key.as_bytes().to_vec(), vec![1],
                )]).unwrap();
                assert!(require_exact_source_provisioning_record_v1(&wrong, &key, transaction_id).is_err());
            }
        }
    }

    #[test]
    fn phase_selection_never_widens_parent_key_or_transaction_scope() {
        let key = lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Operation,
            ProjectId::from_bytes([1; 16]), ResourceId::from_bytes([2; 16]),
            OperationId::from_bytes([3; 16]),
        ).unwrap();
        let transaction_id = [4; 16];
        let record = || JournalRecord::put(RecordNamespace::Operation, key.as_bytes().to_vec(), vec![1]);
        let wrong_id = JournalTransaction::new([5; 16], vec![record()]).unwrap();
        assert!(require_exact_source_provisioning_record_v1(&wrong_id, &key, transaction_id).is_err());

        let sibling = lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Operation,
            ProjectId::from_bytes([1; 16]), ResourceId::from_bytes([2; 16]),
            OperationId::from_bytes([6; 16]),
        ).unwrap();
        let wrong_parent = JournalTransaction::new(transaction_id, vec![JournalRecord::put(
            RecordNamespace::Operation, sibling.as_bytes().to_vec(), vec![1],
        )]).unwrap();
        assert!(require_exact_source_provisioning_record_v1(&wrong_parent, &key, transaction_id).is_err());

        let extra = JournalTransaction::new(transaction_id, vec![record(), JournalRecord::put(
            RecordNamespace::DesiredState, b"another resource".to_vec(), vec![1],
        )]).unwrap();
        assert!(require_exact_source_provisioning_record_v1(&extra, &key, transaction_id).is_err());
    }
}


impl Journal {
    // Association only for the next paid native entry. This performs no path
    // observation, model replay or mutation and cannot issue a Source lease.
    pub(crate) fn require_completed_source_instance_v1(
        &self, identity: &SourceProvisioningIdentityV1,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if !matches!(&self.native, super::native_backing::JournalNativeBackingV1::Source(_))
            || !Arc::ptr_eq(&self.authority_instance, &identity.instance)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_completed_create_controller_instance_v1(
        &self, identity: &CreateStoppedControllerIdentityV1,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        self.controller_coordinator_for_bank_read_v1()?;
        if !Arc::ptr_eq(&self.authority_instance, &identity.instance) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl Journal {
    pub(crate) fn require_source_provisioning_readonly_current_v1<C>(&self,
        source_original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        original: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1,
        controller: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<C>,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        match &self.native {
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .require_provisioning_readonly_current_v1(source_original, original, controller,
                    launch, profile).map_err(Into::into),
            _ => Err(crate::controller_resource_reservation::ResourceReservationErrorV1::Conflict),
        }
    }
}

impl Journal {
    /// Accepts only this Source interval's literal A7 append and actual readback.
    pub(crate) fn stop_dispatch_source_successor_v1(
        &self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        predecessor: &SourceProvisioningIdentityV1,
        transaction: &JournalTransaction,
    ) -> Result<SourceProvisioningIdentityV1, JournalError> {
        self.stop_auxiliary_source_successor_v1(original, predecessor, transaction, StopSourcePublicationV1::Dispatch)
    }

    /// Accepts only this Source interval's actual independently settled A8 pair.
    pub(crate) fn stop_cleanup_completion_source_successor_v1(
        &self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        predecessor: &SourceProvisioningIdentityV1,
        transaction: &JournalTransaction,
    ) -> Result<SourceProvisioningIdentityV1, JournalError> {
        self.stop_auxiliary_source_successor_v1(original, predecessor, transaction, StopSourcePublicationV1::Completion)
    }

    // This closed readback choice issues no append permission. Both entries
    // require the same genuine original, publication and exact native values.
    fn stop_auxiliary_source_successor_v1(
        &self,
        original: &mut aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1,
        predecessor: &SourceProvisioningIdentityV1,
        transaction: &JournalTransaction,
        purpose: StopSourcePublicationV1,
    ) -> Result<SourceProvisioningIdentityV1, JournalError> {
        self.ensure_healthy()?;
        if !Arc::ptr_eq(&predecessor.instance, &self.authority_instance) {
            return Err(JournalError::ProtectedBoundary);
        }
        match &self.native {
            super::native_backing::JournalNativeBackingV1::Source(source)
                if matches!(purpose, StopSourcePublicationV1::Completion) => source
                .require_stop_cleanup_completion_successor_once_v1(original, transaction, predecessor.sequence)
                .map_err(JournalError::SourceNative)?,
            super::native_backing::JournalNativeBackingV1::Source(source) => source
                .require_stop_dispatch_successor_once_v1(original, transaction, predecessor.sequence)
                .map_err(JournalError::SourceNative)?,
            _ => return Err(JournalError::ProtectedBoundary),
        }
        // Both the selected canonical append and every exact protected member
        // have been read back from this same genuine native writer above.
        Ok(SourceProvisioningIdentityV1 {
            instance: Arc::clone(&self.authority_instance), sequence: self.snapshot_sequence(),
        })
    }

    pub(crate) fn require_current_source_provisioning_identity_v1(&self,identity:&SourceProvisioningIdentityV1)
        ->Result<(),JournalError> {
        self.ensure_healthy()?;
        if !matches!(&self.native,super::native_backing::JournalNativeBackingV1::Source(_))
            || !Arc::ptr_eq(&identity.instance,&self.authority_instance)
            || identity.sequence!=self.snapshot_sequence() {return Err(JournalError::ProtectedBoundary);}
        Ok(())
    }
}
