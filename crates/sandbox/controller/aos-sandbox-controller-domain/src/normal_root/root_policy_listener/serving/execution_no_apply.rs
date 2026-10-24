//! Certifies the genuine Execution ACK against the same held Root pair.
//!
//! The floor legitimately changed Authority after the original Root6. Only the
//! actual final native verifier can certify that successor; a stale identity
//! comparison before it would reject the genuine append. Custody is restored
//! before any result is projected, including failures with owed native posts.

use crate::journal::JournalError;
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::continuation_policy::RootExecutionNoApplyPolicyOriginalV2;
use crate::policy_compiler::execution_no_apply_root::{
    RootExecutionNoApplyAckOriginalV2, RootExecutionNoApplyFloorOriginalV2,
    RootExecutionNoApplyHostTrustOriginalV2,
};
use crate::policy_compiler::provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn certify_execution_no_apply_ack_once_v2(
        &mut self,
        acknowledged: &mut RootExecutionNoApplyAckOriginalV2,
        stream: &RetainedUnixStream,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        floor: &RootExecutionNoApplyFloorOriginalV2,
        acquisition: Option<&mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyAcquisitionOriginalV2>,
    ) -> Result<(), JournalError> {
        self.execution_no_apply_cut_startup_v2()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let mut custody = self
            .listener
            .serving
            .take()
            .ok_or(JournalError::ProtectedBoundary)?;
        let returned = (|| {
            if !custody.ready_for_delete || custody.validation.is_err() {
                return Err(JournalError::ProtectedBoundary);
            }
            match acquisition {
                Some(acquisition) => acknowledged.observe_recovery_once_v2(
                    self,
                    stream,
                    &custody.writers,
                    &custody.pins,
                    &custody.terminal,
                    policy,
                    floor,
                    readonly,
                    trust,
                    acquisition,
                )?,
                None => {
                    acknowledged.observe_active_once_v2(
                        self,
                        stream,
                        &custody.writers,
                        &custody.pins,
                        &custody.terminal,
                        policy,
                        floor,
                        readonly,
                        trust,
                    )?;
                }
            }
            custody
                .terminal
                .certify_execution_no_apply_successor_once_v2(
                    &custody.writers,
                    &custody.pins,
                    floor,
                    acknowledged,
                )?;
            custody.validation = custody.require_same_completed_pair();
            custody
                .validation
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            Ok(())
        })();
        self.listener.serving = Some(custody);
        returned
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn observe_execution_no_apply_acquisition_once_v2(
        &mut self,
        acquisition: &mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyAcquisitionOriginalV2,
        stream: &RetainedUnixStream,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        clock: &mut crate::policy_compiler::provisioning_current::RootContinuationClockGateV1,
        selection: crate::policy_compiler::execution_no_apply_root::RootNoApplyAcquisitionSelectionDataV2,
    ) -> Result<(), JournalError> {
        self.execution_no_apply_cut_startup_v2()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let custody = self
            .listener
            .serving
            .take()
            .ok_or(JournalError::ProtectedBoundary)?;
        let result = (|| {
            if !custody.ready_for_delete || custody.validation.is_err() {
                return Err(JournalError::ProtectedBoundary);
            }
            custody
                .require_same_completed_pair()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            acquisition.observe_once_v2(
                self,
                stream,
                &custody.writers,
                &custody.pins,
                policy,
                clock,
                selection,
            )
        })();
        self.listener.serving = Some(custody);
        result
    }
}
