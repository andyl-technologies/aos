//! Associates one genuinely completed Recover interval with fresh NoApply finance.
//!
//! Public Recover remains pending. The old interval has finished every Source,
//! Controller and clock post; no old loan, Source cursor or Root stream is
//! reactivated. A fresh actual cleanup owner must pay all later native work.

use super::*;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_model::{OperationId, ProjectId};
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::
    OBSERVATION_ADMISSION_KEY_BYTES_V1;
use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub(super) struct CompletedHandoffStateV2 {
    entered: bool,
    result: Option<Result<(), ResourceReservationErrorV1>>,
    reentry: Option<OperatorCreateRecoveryClosedV1>,
    claimed: AtomicBool,
}

impl CompletedHandoffStateV2 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.result.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

/// Borrows genuine completed finance and the still-pending admitted kind-3 scope.
///
/// Private construction and a once-only entry claim bind the next real cleanup
/// receiver to this same payer and target. This token supplies no effect,
/// current capability decision, Source loan, Root signature or public success.
#[doc(hidden)]
#[must_use = "retain this association beside its actual new cleanup original"]
pub struct OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'completed> {
    owner: &'completed OperatorCreateRecoveryOriginalV1,
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Associates the actual disposed interval with one fresh cleanup entrance.
    ///
    /// The original's fixed receiving quote includes this retained state; no
    /// Root connection or uncharged native prefix crosses this boundary.
    ///
    /// # Errors
    /// Retains reentry, unfinished native/Source/clock posts, changed admission,
    /// target, profile or protected Source identity on this same owner.
    #[doc(hidden)]
    pub fn completed_execution_no_apply_handoff_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'_>, ResourceReservationErrorV1> {
        if self.cleanup_handoff.entered {
            self.cleanup_handoff.reentry.get_or_insert(OperatorCreateRecoveryClosedV1);
            self.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.cleanup_handoff.entered = true;
        self.cleanup_handoff.result = Some((|| {
            self.require_completed_cleanup_scope_v2(bank, controller, &self.profile,
                PublicRecoveryKindV1::ExecutionNoApply)?;
            self.source.require_current_identity_v2(source)?;
            Ok(())
        })());
        self.latch_primary_failure_v1();
        if !matches!(self.cleanup_handoff.result, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(OperatorExecutionNoApplyRecoveryCompletedHandoffV2 { owner: self })
    }

    fn require_completed_cleanup_scope_v2(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        purpose: PublicRecoveryKindV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(profile, self.profile.as_ref())
            || self.failure_v1().is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || !matches!(self.final_clock, Some(Ok(_)))
            || !matches!(self.final_clock_comparison, Some(Ok(())))
            || !matches!(self.authorization, Some(Ok(_)))
            || !matches!(self.authorization_readback, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_source_disposed_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        bank.require_operator_recover_disposed_v1(native, controller, profile)?;
        self.require_completed_cleanup_target_for_v2(controller, purpose)
    }

    fn require_completed_cleanup_target_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.require_completed_cleanup_target_for_v2(controller, PublicRecoveryKindV1::ExecutionNoApply)
    }

    fn require_completed_cleanup_target_for_v2(&self, controller: &Journal,
        purpose: PublicRecoveryKindV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let request = self.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if request.public_recovery_kind_v1() != purpose {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let data = self.current_observation_data_v1(controller)?;
        let (_, recovery, target) = request.observation_input_v1();
        if target.as_bytes() != &data.target || self.target != Some(target) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let project = ProjectId::from_bytes(data.project);
        let node = NodeId::from_bytes(data.node);
        match purpose {
            PublicRecoveryKindV1::ExecutionNoApply => request.execution_no_apply_target_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .require_current_v1(
                    crate::journal::historical_observation::HistoricalObservationV1::
                        from_journal_v1(controller),
                    project, node, recovery,
                ),
            PublicRecoveryKindV1::StopCleanup => request.stop_cleanup_target_v1()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .require_current_v1(
                    crate::journal::historical_observation::HistoricalObservationV1::
                        from_journal_v1(controller),
                    project, node, recovery,
                ),
            PublicRecoveryKindV1::Ordinary | PublicRecoveryKindV1::MetadataComplete =>
                return Err(ResourceReservationErrorV1::Conflict),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'_> {
    /// Returns the exact current protected target as comparison DATA.
    ///
    /// Runtime uses this selector to enter the actual fresh cleanup financial
    /// owner. It grants no capability, native work, phase proof or effect.
    ///
    /// # Errors
    /// Refuses failed handoff, changed target or altered pending admission.
    #[doc(hidden)]
    pub fn target_operation_data_v2(&self, controller: &Journal)
        -> Result<OperationId, ResourceReservationErrorV1>
    {
        self.require_issued_v2()?;
        self.owner.require_completed_cleanup_target_v2(controller)?;
        self.owner.target.ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Consumes the single association before the actual new native entrance.
    ///
    /// # Errors
    /// Refuses another bank/C/profile/target, unfinished original disposal,
    /// changed exact accepted scope or a repeated fresh cleanup entrance.
    #[doc(hidden)]
    pub(crate) fn require_fresh_execution_cleanup_v2(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        target: OperationId,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_completed_cleanup_scope_v2(bank, controller, profile,
            PublicRecoveryKindV1::ExecutionNoApply)?;
        if self.owner.target != Some(target)
            || !matches!(self.owner.cleanup_handoff.result, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.cleanup_handoff.claimed.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Rejoins the original protected Source identity before a fresh read loan.
    ///
    /// # Errors
    /// Refuses an unconsumed association, substituted or advanced Source.
    #[doc(hidden)]
    pub(crate) fn require_fresh_execution_cleanup_source_v2(
        &self,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_issued_v2()?;
        if !self.owner.cleanup_handoff.claimed.load(Ordering::Acquire) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.source.require_current_identity_v2(source)
    }

    /// Returns only the unchanged admitted capability cutoff and wall expiry.
    ///
    /// The new cleanup samples its own actual paired clock and narrows this
    /// ceiling again. These values renew neither old Execution nor Recover D.
    ///
    /// # Errors
    /// Refuses failed original custody, incomplete handoff or missing horizon.
    #[doc(hidden)]
    pub(crate) fn cleanup_authorization_horizon_data_v2(&self)
        -> Result<(u64, i64), ResourceReservationErrorV1>
    {
        self.require_issued_v2()?;
        self.owner.horizon.as_ref().and_then(|value| value.as_ref().ok())
            .map(|horizon| (horizon.cutoff, horizon.expires_wall_seconds))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the canonical current admission key and actual protected bytes.
    ///
    /// Root independently verifies the accepted four rows/current capability;
    /// this projection grants no signature, native currentness or success.
    ///
    /// # Errors
    /// Refuses failed handoff, changed target/admission or a missing exact row.
    #[doc(hidden)]
    pub(crate) fn admission_record_data_v2<'controller>(
        &self,
        controller: &'controller Journal,
    ) -> Result<([u8; OBSERVATION_ADMISSION_KEY_BYTES_V1], &'controller [u8]), ResourceReservationErrorV1> {
        self.require_issued_v2()?;
        self.owner.require_completed_cleanup_target_v2(controller)?;
        let key = self.owner.current_observation_data_v1(controller)?.key_v1();
        let raw = controller.get(crate::RecordNamespace::OperatorRecovery, &key)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((key, raw))
    }

    fn require_issued_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.owner.cleanup_handoff.result, Some(Ok(()))) || self.owner.failure_v1().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}


/// Binds completed kind-2 Recover finance to one fresh Stop cleanup payer.
///
/// This private association retains the actual original and its immutable
/// comparison models. It grants no Host request, Root signature, capability,
/// old Stop outcome or renewed deadline.
#[doc(hidden)]
#[must_use = "retain this association beside its actual fresh Stop original"]
pub struct OperatorStopCleanupRecoveryCompletedHandoffV1<'completed> {
    owner: &'completed OperatorCreateRecoveryOriginalV1,
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Associates the disposed observation with a single fresh cleanup entrance.
    ///
    /// The complete cold capture and Session must physically drop before this
    /// method: their genuine retained identity is checked by the native owner.
    /// The accepted public Recover remains pending throughout this handoff.
    ///
    /// # Errors
    /// Retains reentry, incomplete posts/disposal, live cold owners, changed
    /// capability admission, protected Stop target or actual Source A7 binding.
    #[doc(hidden)]
    pub fn completed_stop_cleanup_handoff_v1(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<OperatorStopCleanupRecoveryCompletedHandoffV1<'_>, ResourceReservationErrorV1> {
        if self.cleanup_handoff.entered {
            self.cleanup_handoff.reentry.get_or_insert(OperatorCreateRecoveryClosedV1);
            self.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.cleanup_handoff.entered = true;
        self.cleanup_handoff.result = Some((|| {
            self.require_completed_stop_cleanup_scope_v1(bank, controller, &self.profile, source)?;
            Ok(())
        })());
        self.latch_primary_failure_v1();
        if !matches!(self.cleanup_handoff.result, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(OperatorStopCleanupRecoveryCompletedHandoffV1 { owner: self })
    }

    fn require_completed_stop_cleanup_scope_v1(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_cleanup_scope_v2(bank, controller, profile,
            PublicRecoveryKindV1::StopCleanup)?;
        let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        native.require_cold_session_retired_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.stop_cleanup_observation.selected()?;
        self.stop_dispatch_binding_data_v1(controller, source)?;
        Ok(())
    }
}

impl OperatorStopCleanupRecoveryCompletedHandoffV1<'_> {
    /// Borrows the exact A7 auxiliary commitment from its actual held decoder.
    ///
    /// This is comparison DATA after the same current Source/target binding;
    /// it cannot reconstruct an old result or native cleanup permission.
    pub(crate) fn stop_dispatch_auxiliary_digest_data_v1(
        &self, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<aos_sandbox_model::ObjectDigest, ResourceReservationErrorV1> {
        self.require_issued_v1()?;
        self.owner.stop_dispatch_binding_data_v1(controller, source)?;
        self.owner.source.stop_dispatch_record_digest_data_v1()
    }

    /// Returns the actual completed passive Host3 coordinates as comparison DATA.
    ///
    /// # Errors
    /// Refuses an incomplete handoff or missing actual native/model receipt.
    #[doc(hidden)]
    pub fn host_observation_reference_data_v1(&self)
        -> Result<([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]), ResourceReservationErrorV1>
    {
        self.require_issued_v1()?;
        let selected = self.owner.stop_cleanup_observation.selected()?;
        Ok((selected.request, selected.session, selected.signed_request, selected.answer, selected.body))
    }

    /// Builds strict456 DATA from the actual Host comparison and Source A7.
    ///
    /// This is not a signed plan. Root must independently authenticate the
    /// actual Source/Host rows, current capability, policy and fresh deadline.
    ///
    /// # Errors
    /// Refuses changed current admission, Source/target, old SDK/Launch identity,
    /// namespace, missing actual Host3 observation or reused cleanup nonce.
    #[doc(hidden)]
    pub fn cleanup_subject_data_v1(
        &self,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1,
        ResourceReservationErrorV1>
    {
        use super::stop_cleanup::StopCleanupHostComparisonDataV1 as Comparison;
        use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1 as Subject;

        self.require_issued_v1()?;
        self.owner.require_completed_cleanup_target_for_v2(controller, PublicRecoveryKindV1::StopCleanup)?;
        let (dispatch, _) = self.owner.stop_dispatch_binding_data_v1(controller, source)?;
        let data = self.owner.current_observation_data_v1(controller)?;
        let cleanup = self.cleanup_request_data_v1()?;
        let selected = self.owner.stop_cleanup_observation.selected()?;
        let request = self.owner.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let target = request.stop_cleanup_target_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let original = target.binding_v1().manifest().broker_assignment()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let (historical, boot, dispatched) = match &selected.comparison {
            Comparison::Pending(row) => (*row.historical_scope_v1(), *row.current_boot_v1(), false),
            Comparison::Dispatched(row) => {
                let subject = Subject::from_dispatched_data_v2(*row.launch_scope_v1(),
                    dispatch.sdk_request_data_v1(), data.operation, cleanup, data.request_digest_v1(),
                    *row.current_boot_v1(), data.authorization_revision, data.cutoff)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                (*subject.historical_scope_v1(), *row.current_boot_v1(), true)
            }
            Comparison::Recovered(row) => (*row.historical_scope_v7(), *row.observation_v7().boot_v5(), false),
            Comparison::Lineage(row) => (*row.subject_v1().historical_scope_v1(), *row.observation_v1().boot_v5(),
                row.subject_v1().origin_v1() == aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::DispatchedBeforeHost),
        };
        let fence = historical.fence_v4();
        if boot != data.original.host_boot_id()
            || historical.stop_v4() != dispatch.sdk_request_data_v1()
            || fence.sandbox_id() != original.sandbox().as_bytes()
            || fence.incarnation_id() != original.incarnation().as_bytes()
            || fence.assignment_epoch() != original.epoch().get()
            || fence.assignment_digest() != original.digest().as_bytes()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if dispatched {
            Subject::from_dispatched_data_v2(historical.launch_scope_v1(), dispatch.sdk_request_data_v1(),
                data.operation, cleanup, data.request_digest_v1(), boot, data.authorization_revision, data.cutoff)
        } else {
            Subject::from_data_v1(historical, data.operation, cleanup, data.request_digest_v1(),
                boot, data.authorization_revision, data.cutoff)
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Returns the genuinely sampled fresh cleanup identifier as DATA.
    ///
    /// # Errors
    /// Refuses an incomplete handoff or failed/absent actual kernel nonce.
    #[doc(hidden)]
    pub fn cleanup_request_data_v1(&self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.require_issued_v1()?;
        self.owner.stop_cleanup_nonce.value().copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Returns the exact still-pending protected Stop selector as DATA.
    ///
    /// # Errors
    /// Refuses a failed handoff or a changed current target/admission.
    #[doc(hidden)]
    pub fn target_operation_data_v1(&self, controller: &Journal)
        -> Result<OperationId, ResourceReservationErrorV1>
    {
        self.require_issued_v1()?;
        self.owner.require_completed_cleanup_target_for_v2(controller, PublicRecoveryKindV1::StopCleanup)?;
        self.owner.target.ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Returns the unchanged admitted Recover cutoff and capability wall expiry.
    ///
    /// The fresh owner must sample its own actual paired clock and narrow this
    /// ceiling again. These values supply neither native work nor authority.
    ///
    /// # Errors
    /// Refuses an incomplete association or absent original horizon.
    #[doc(hidden)]
    pub(crate) fn cleanup_authorization_horizon_data_v1(&self)
        -> Result<(u64, i64), ResourceReservationErrorV1>
    {
        self.require_issued_v1()?;
        self.owner.horizon.as_ref().and_then(|value| value.as_ref().ok())
            .map(|horizon| (horizon.cutoff, horizon.expires_wall_seconds))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the exact canonical current admission key and protected bytes.
    ///
    /// # Errors
    /// Refuses a substituted target, changed admission or missing actual row.
    #[doc(hidden)]
    pub(crate) fn admission_record_data_v1<'controller>(
        &self,
        controller: &'controller Journal,
    ) -> Result<([u8; OBSERVATION_ADMISSION_KEY_BYTES_V1], &'controller [u8]), ResourceReservationErrorV1> {
        self.target_operation_data_v1(controller)?;
        let key = self.owner.current_observation_data_v1(controller)?.key_v1();
        let raw = controller.get(crate::RecordNamespace::OperatorRecovery, &key)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((key, raw))
    }

    /// Borrows only the same selected A7 packet after its original disposition.
    ///
    /// # Errors
    /// Refuses changed C/Source, target, dispatch provenance or completed finance.
    #[doc(hidden)]
    pub(crate) fn stop_dispatch_data_v1(
        &self,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(&aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
        crate::lifecycle::LifecycleRecordDigestV1), ResourceReservationErrorV1> {
        self.require_issued_v1()?;
        self.owner.require_completed_cleanup_target_for_v2(controller, PublicRecoveryKindV1::StopCleanup)?;
        self.owner.stop_dispatch_binding_data_v1(controller, source)
    }

    /// Projects the exact current cleanup funding association as comparison DATA.
    ///
    /// The fresh Stop owner independently rejoins these fields to this same
    /// completed handoff before its one-shot native entry. This projection
    /// neither claims that entrance nor supplies a Source loan or effect grant.
    ///
    /// # Errors
    /// Refuses changed admission, pending target, selected A7 ancestry, Source
    /// identity or the canonical cleanup subject on the completed original.
    #[doc(hidden)]
    pub fn cleanup_association_data_v1(
        &self,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
        ResourceReservationErrorV1> {
        self.target_operation_data_v1(controller)?;
        let data = self.owner.current_observation_data_v1(controller)?;
        let request = self.owner.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let target = request.stop_cleanup_target_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let (_, parent) = self.owner.stop_dispatch_binding_data_v1(controller, source)?;
        let subject = self.cleanup_subject_data_v1(controller, source)?;
        let association = aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1 {
            recovery_operation: data.operation,
            cleanup_operation: self.cleanup_request_data_v1()?,
            target_stop_operation: data.target,
            expected_resource_version: *target.version_v1(),
            public_request_digest: data.request_digest_v1(),
            source_parent_digest: *parent.digest().as_bytes(),
            cleanup_subject_digest: subject.digest_data_v1(),
        };
        association.encode_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(association)
    }

    /// Claims this exact completed association before a genuine fresh entrance.
    ///
    /// This comparison funds no work itself. The bank must use the actual
    /// completed native original below to debit the shared Stop slot, and
    /// independently verify the strict456 subject's digest and all effect gates.
    ///
    /// # Errors
    /// Refuses a foreign bank/profile/Source, changed current protected target,
    /// substituted association or repeated fresh entrance.
    #[doc(hidden)]
    pub(crate) fn require_fresh_stop_cleanup_v1(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        source: &ProtectedSourceDomainJournalOwnerV1,
        association: &aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_issued_v1()?;
        self.owner.require_completed_stop_cleanup_scope_v1(bank, controller, profile, source)?;
        association.encode_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let data = self.owner.current_observation_data_v1(controller)?;
        let request = self.owner.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let target = request.stop_cleanup_target_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
        let (dispatch, parent) = self.owner.stop_dispatch_binding_data_v1(controller, source)?;
        let subject = self.cleanup_subject_data_v1(controller, source)?;
        if association.recovery_operation != data.operation
            || association.cleanup_operation != self.cleanup_request_data_v1()?
            || association.target_stop_operation != data.target
            || association.expected_resource_version != *target.version_v1()
            || association.public_request_digest != data.request_digest_v1()
            || association.source_parent_digest != *parent.digest().as_bytes()
            || association.cleanup_subject_digest != subject.digest_data_v1()
            || association.cleanup_operation == dispatch.sdk_request_data_v1().0
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.cleanup_handoff.claimed.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the genuine completed native financial original after the claim.
    ///
    /// This crate-private port exists solely for the same bank's finite
    /// purpose22 seed issuer. It exposes no ordinary operation authority.
    ///
    /// # Errors
    /// Refuses an unclaimed, failed or absent actual completed native original.
    #[doc(hidden)]
    pub(crate) fn completed_native_original_v1(&self)
        -> Result<&ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1>
    {
        self.require_issued_v1()?;
        if !self.owner.cleanup_handoff.claimed.load(Ordering::Acquire) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    fn require_issued_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.owner.cleanup_handoff.result, Some(Ok(()))) || self.owner.failure_v1().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}
