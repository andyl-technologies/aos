//! Completes admitted kind3 recovery under its fresh Source/C18 and cold Session.
//!
//! The old Recover interval has already disposed its financial originals. Its
//! opaque association admits one fresh cleanup interval; it never renews the
//! old deadline or supplies an effect grant. Root acquisition, four actual
//! Host turns, native C settlement and the causal Root confirmation precede
//! the sole Recover metadata append and final Source disposal.

use super::*;
use aos_sandbox_controller_domain::ControllerResourceBankOpeningV1;
use aos_sandbox_controller_domain::controller_execution_operation::{
    ControllerExecutionCleanupReceivingLoanV2, ControllerExecutionCleanupSourceLoanV2,
    ControllerExecutionNoApplyCompletionV2, ControllerExecutionNoApplyOriginalV2,
    ControllerExecutionNoApplyRecoveredMetadataV2,
};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1 as Demand;
use aos_sandbox_broker_session_security::{
    ExecutionNoApplySessionOpenV2, HostExecutionNoApplySessionIoOriginalV2,
};
use aos_sandbox_model::{ResourceDimension, ResourceVector};

// Owns the actual Source loan so its prepaid posts run before the lower
// nonpositive Source Drop, including body unwind. It never resumes a failed
// body or replaces a retained native cause with a cleanup result.
struct CleanupSourcePostsV2<'scope, 'owner, 'native> {
    source: ControllerExecutionCleanupSourceLoanV2<'scope, 'owner>,
    bank: &'native ControllerResourceBankOpeningV1,
    controller: &'native mut Journal,
    profile: &'native aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    finished: bool,
}

impl CleanupSourcePostsV2<'_, '_, '_> {
    fn finish_once(&mut self) {
        if !self.finished {
            // Mark before crossing; disposal resets the lower post slot. Drop
            // must not interpret that later reset as a newly owed interval.
            self.finished = true;
            self.source
                .finish_native_once_v2(self.bank, self.controller, self.profile);
        }
    }
}

impl Drop for CleanupSourcePostsV2<'_, '_, '_> {
    fn drop(&mut self) {
        self.finish_once();
    }
}

#[derive(Default)]
pub(super) struct ExecutionNoApplyRecoveryOriginalV2 {
    entered: bool,
    image: Option<Result<Pid1LaunchImageV1, Closed>>,
    cold: Box<ExecutionNoApplySessionOpenV2>,
    opened: Option<Result<(), BrokerSessionSecurityError>>,
    session: Option<Box<DormantAuthenticatedBrokerSessionV1>>,
    sdk: Box<HostExecutionNoApplySessionIoOriginalV2>,
    native: Box<ControllerExecutionNoApplyOriginalV2>,
    body: Option<Result<(), Closed>>,
    metadata: Option<ControllerExecutionNoApplyRecoveredMetadataV2>,
}

impl ExecutionNoApplyRecoveryOriginalV2 {
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<ExecutionNoApplySessionOpenV2>(),
            boxed_bytes::<HostExecutionNoApplySessionIoOriginalV2>(),
            boxed_bytes::<ControllerExecutionNoApplyOriginalV2>(),
            boxed_bytes::<DormantAuthenticatedBrokerSessionV1>(),
        ])
    }

    fn resident_demand() -> Result<Demand, Closed> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<CleanupSourcePostsV2<'_, '_, '_>>().checked_mul(2)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<aos_sandbox_controller_domain::OperatorCleanupRecoveryCompletionV2>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(Closed)?;
        Ok(Demand::from_demand_v1(
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes),
        ))
    }

    fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.image
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.cold.failure_v2())
            .or_else(|| {
                self.opened
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                if self.sdk.original_failure_selected_v2() {
                    self.native.failure_v2().or_else(|| self.sdk.failure_v2())
                } else {
                    self.sdk.failure_v2().or_else(|| self.native.failure_v2())
                }
            })
            .or_else(|| {
                self.body
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    fn run_source_once_v2(
        &mut self,
        receiving: &mut ControllerExecutionCleanupReceivingLoanV2<'_>,
        source_domain: &mut aos_sandbox_controller_domain::source_domain::ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        bank: &ControllerResourceBankOpeningV1,
        profile: &Arc<aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>,
        completed: &aos_sandbox_controller_domain::OperatorExecutionNoApplyRecoveryCompletedHandoffV2<'_>,
    ) -> Result<
        (
            aos_sandbox_api::aos::sandbox::v1::Operation,
            ControllerExecutionNoApplyCompletionV2,
        ),
        Closed,
    > {
        let source = receiving
            .prepare_source_once_v2(bank, source_domain, controller, profile, completed)
            .map_err(|_| Closed)?;
        let mut posts = CleanupSourcePostsV2 {
            source,
            bank,
            controller,
            profile,
            finished: false,
        };
        self.body = Some((|| {
            let source = &mut posts.source;
            let controller = &mut *posts.controller;
            let image = self
                .image
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .cloned()
                .ok_or(Closed)?;
            self.opened = Some(
                self.cold
                    .open_once_v2(source, bank, controller, profile, image),
            );
            if !matches!(self.opened, Some(Ok(()))) {
                return Err(Closed);
            }
            self.session = self.cold.take_completed_once_v2().map(Box::new);
            let session = self.session.as_mut().ok_or(Closed)?;
            // The public cold owner rejoins this exact initial receiver and
            // fresh Source before lending paid schema/history reception.
            let mut borrower = self
                .cold
                .borrow_cleanup_execution_no_apply_client_once_v2(
                    session,
                    source,
                    &mut self.sdk,
                    &mut self.native,
                    controller,
                    bank,
                    profile,
                )
                .map_err(|_| Closed)?;
            borrower.acquire_root_once_v2().map_err(|_| Closed)?;
            borrower.preliminary_once_v2().map_err(|_| Closed)?;
            borrower
                .prepare_controller_cut_once_v2()
                .map_err(|_| Closed)?;
            borrower.begin_root_exchange_once_v2().map_err(|_| Closed)?;
            borrower.query_root_nonce_once_v2().map_err(|_| Closed)?;
            borrower.receive_root_floor_once_v2().map_err(|_| Closed)?;
            borrower.prepare_controller_once_v2().map_err(|_| Closed)?;
            borrower.floor_seal_once_v2().map_err(|_| Closed)?;
            borrower
                .commit_controller_cas_once_v2()
                .map_err(|_| Closed)?;
            borrower.acknowledge_once_v2().map_err(|_| Closed)?;
            borrower
                .finish_root_exchange_once_v2()
                .map_err(|_| Closed)?;
            self.metadata = Some(
                borrower
                    .complete_recovery_metadata_once_v2()
                    .map_err(|_| Closed)?,
            );
            Ok(())
        })());

        // The borrower has ended, including every failed body. This original
        // owes both Source/C posts independently of the transport result.
        posts.finish_once();
        if !matches!(self.body, Some(Ok(()))) {
            if let Some(cause) = self.failure_v2() {
                eprintln!("aos-sandboxd: Execution NoApply recovery body: {cause}");
            }
            if let Some(cause) = posts.source.failure_v2() {
                eprintln!("aos-sandboxd: Execution NoApply recovery Source/C: {cause}");
            }
            return Err(Closed);
        }
        if let Some(cause) = posts.source.failure_v2() {
            eprintln!("aos-sandboxd: Execution NoApply recovery Source/C: {cause}");
            return Err(Closed);
        }
        let disposal = posts
            .source
            .prepare_positive_disposal_v2(bank, posts.controller, profile)
            .map_err(|_| Closed)?;
        let disposed = self
            .sdk
            .retire_no_apply_before_native_disposal_v2(&mut self.native, &disposal)
            .map_err(|_| Closed)?;

        // The lower D-positive gate independently requires the final cold
        // financial owner to be unique. Drop the real Session graph and cold
        // capture, after the whole SDK/Core retirement and before that gate.
        drop(self.session.take());
        drop(std::mem::take(&mut *self.cold));
        self.opened = None;
        self.image = None;
        self.body = None;
        let metadata = self.metadata.take().ok_or(Closed)?;
        disposal
            .complete_recovery_after_disposal_v2(posts.controller, disposed, metadata)
            .map_err(|_| Closed)
    }
}

impl ProductionEffectExecutor {
    pub(super) fn complete_execution_no_apply_recovery_v2(
        &mut self,
        controller: &mut Journal,
        original: &mut OperatorCreateRecoveryOriginalV1,
    ) -> Result<aos_sandbox_controller_domain::OperatorCleanupRecoveryCompletionV2, Closed> {
        let bank = self.resource_bank.as_ref().ok_or(Closed)?;
        let bank = bank.lock().map_err(|_| Closed)?;
        let profile = self.execution_profile.as_ref().ok_or(Closed)?;
        let runtime = ExecutionNoApplyRecoveryOriginalV2::resident_demand()?;
        let state = &mut self.operator_recover.execution_no_apply;
        if state.entered {
            return Err(Closed);
        }
        state.entered = true;
        state.image = Some((|| {
            let sessions = self.sessions.lock().map_err(|_| Closed)?;
            sessions.launch_image.clone().ok_or(Closed)
        })());
        if !matches!(state.image, Some(Ok(_))) {
            return Err(Closed);
        }

        let completed = original
            .completed_execution_no_apply_handoff_v2(&bank, controller, &self.source_domains)
            .map_err(|_| Closed)?;
        let target = completed
            .target_operation_data_v2(controller)
            .map_err(|_| Closed)?;
        // Existing initialization can already have installed the actual C18.
        // Only its absent case uses the existing sole declaration claim.
        if self.execution_original.is_none() {
            self.execution_original = Some(
                execution_output_effect::ControllerExecutionOriginalV1::claim_once_v1(
                    &bank, controller, profile,
                )
                .map_err(|_| Closed)?,
            );
        }
        let financial = self
            .execution_original
            .as_mut()
            .ok_or(Closed)?
            .borrow_cleanup_financial_v2()
            .map_err(|_| Closed)?;
        let mut receiving = match financial
            .begin_no_apply_cleanup_once_v2(&bank, controller, profile, &completed, target, runtime)
        {
            Ok(receiving) => receiving,
            Err(_) => std::process::abort(),
        };
        let result = state.run_source_once_v2(
            &mut receiving,
            &mut self.source_domains,
            controller,
            &bank,
            profile,
            &completed,
        );
        match result {
            Ok((response, completion)) => {
                Ok(aos_sandbox_controller_domain::OperatorCleanupRecoveryCompletionV2::Execution { response, completion })
            }
            Err(_) => {
                // If Source entry refused, the native C18 after remains owed.
                // For an entered Source this is already posted and inert. An
                // uncertain terminal C fact must never resume ordinary Apply.
                receiving.finish_without_source_once_v2(&bank, controller, profile);
                std::process::abort()
            }
        }
    }
}
