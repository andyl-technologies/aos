//! Consumes one genuine authorized Source pair through real Planned readback.
//!
//! This owns the same exclusive Source/C17 scope and checked plan. Pending is
//! not acceptance: the original scope cannot release while its durable pending
//! obligation remains. Root, initial ACK, fresh six and effects remain separate.

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1;
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchV1;

use super::*;
use crate::journal::JournalError;
use crate::lifecycle::delete_pending::SourceDeletePendingPlanV1;
use crate::lifecycle::protected_journal::LifecycleProtectedJournalErrorV1;
use crate::public_mutation_compiler::delete_admission::planning_nonce::PlanningClockError;

mod readiness;
pub use readiness::{OriginalDeleteStoragePreparationLoanV3, OriginalDeleteStorageApplyLoanV3, OriginalDeleteNetworkApplyLoanV4, OriginalDeleteMountReapLoanV4};
use readiness::ControllerDeleteSourceReadinessOriginalV3;

type Clock = RetainedKernelPairedClockAttemptV1<PlanningClockError>;

/// Retains one actual durable Planned fence and its original authorization.
///
/// Fields and construction are private. A batch, position, decoded record or
/// supplied result cannot construct this continuation. It cannot grant Root
/// approval, Controller acceptance, native destruction or outer C17 disposal.
#[doc(hidden)]
#[must_use = "retain the same pending Source/C17 obligation until real terminal completion"]
pub struct ControllerDeletePendingOriginalV2<'scope, 'original> {
    source: SourceDeleteSemanticScopeV1<'scope, 'original>,
    plan: Option<Result<SourceDeletePendingPlanV1<'scope>, LifecycleProtectedJournalErrorV1>>,
    original_clock: RawPairedClockSample,
    expires: i64,
    clocks: [Clock; 3],
    samples: [Option<Result<RawPairedClockSample, PlanningClockError>>; 3],
    horizons: [Option<Result<(), JournalError>>; 3],
    entry: Option<Result<(), JournalError>>,
    run: Option<Result<(), JournalError>>,
    readback: Option<Result<(), JournalError>>,
    outer_after: Option<Result<(), JournalError>>,
    complete: bool,
    readiness: ControllerDeleteSourceReadinessOriginalV3,
}

impl<'scope, 'original> ControllerDeletePendingOriginalV2<'scope, 'original> {
    /// Returns the same canonical planner's operation identity as passive DATA.
    ///
    /// # Errors
    /// Refuses missing original Planned native readback or a consumed plan.
    #[doc(hidden)]
    pub fn operation_id_data_v4(&self) -> Result<aos_sandbox_model::OperationId, JournalError> {
        if !self.complete || !matches!(self.readback, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.plan.as_ref().and_then(|value| value.as_ref().ok())
            .map(|plan| plan.coordinates().1).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn fixed_demand_v2() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(Clock::dominant_requested_bytes_v1()?.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
                (ResourceVector, ResourceVector, ResourceVector), JournalError>>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Delete pending continuation"))?;
        let files = u64::try_from(Clock::MAXIMUM_RETAINED_FILES_V1).ok()
            .and_then(|files| files.checked_mul(3))
            .ok_or(JournalError::LimitExceeded("Delete pending clock files"))?;
        let names = Clock::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(3)).and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::LimitExceeded("Delete pending clock names"))?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files)
            .with(D::MetadataEntries, names))
    }

    fn sample_once_v2(&mut self, index: usize) {
        observe_clock_once_v2(
            &mut self.clocks, &mut self.samples, &mut self.horizons,
            index, self.original_clock, self.expires,
        );
    }

    fn fail_while_held_v2(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> ! {
        if self.samples[2].is_none() {
            self.sample_once_v2(2);
        }
        self.outer_after = Some(self.source.finish_native_once_v1(controller, launch, profile));
        std::process::abort();
    }

    /// Borrows the actual pending batch retained by the completed native plan.
    #[must_use]
    pub fn batch_bytes_v2(&self) -> Option<&[u8]> {
        if !self.complete || self.outer_after.is_some() {
            return None;
        }
        self.plan.as_ref()?.as_ref().ok()?.batch_bytes().ok()
    }

    /// Borrows the first reached local error while its original owners live.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.clocks[0].failure()
            .or_else(|| self.horizons[0].as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.plan.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.clocks[1].failure())
            .or_else(|| self.horizons[1].as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.entry.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.run.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.clocks[2].failure())
            .or_else(|| self.horizons[2].as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.readback.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.outer_after.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.readiness.selected_failure_v3(&self.source))
            .or_else(|| self.source.failure())
    }

    /// Runs the already owed joint Source/C17 post after an upper refusal.
    ///
    /// The caller keeps the whole failed Root/Collection originals resident.
    /// This terminal negative route never clears the pending obligation or
    /// runs on a successful initial comparison before later fresh queries.
    pub(crate) fn finish_outer_failure_once_v2(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        if self.outer_after.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.outer_after = Some(self.source.finish_native_once_v1(controller, launch, profile));
        if matches!(self.outer_after, Some(Ok(()))) {
            Ok(())
        } else {
            // The owned native cause stays on outer_after and the same Source.
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn intake_failure_view_v2<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.source.pending_root_intake_failure_view_v2(profile)
    }

    pub(crate) fn borrow_fence_v2<'fence>(
        &'fence mut self,
    )
        -> Result<crate::journal::SourceDeletePendingFenceV1<'fence, 'scope, 'original, 'scope>, JournalError>
    {
        if !self.complete || self.outer_after.is_some() || self.readiness.started {
            return Err(JournalError::ProtectedBoundary);
        }
        let plan = self.plan.as_ref().and_then(|plan| plan.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.source.borrow_pending_fence_v1(plan)
    }
}

impl<'scope, 'original> ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original> {
    pub(crate) fn commit_pending_inner_v2(
        mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        request_scope: crate::ControllerRequestScopeV1,
        operation: crate::lifecycle::LifecycleOperationV1,
        batch: LifecycleDeleteBatchV1,
    ) -> ControllerDeletePendingOriginalV2<'scope, 'original> {
        let admission = (|| {
            self.source.reserve_pending_consumer_v2(controller, launch, profile,
                &operation, &batch, ControllerDeletePendingOriginalV2::fixed_demand_v2()?)
        })();
        let complete = match admission {
            Ok(complete) => complete,
            Err(cause) => {
                let _primary = cause;
                let _after = self.source.finish_native_once_v1(controller, launch, profile);
                std::process::abort();
            }
        };
        let (original_clock, expires) = self.authorization.authorization_horizon_v1();
        let Self { authorization, source } = self;
        let mut owner = ControllerDeletePendingOriginalV2 {
            source,
            plan: None,
            original_clock,
            expires,
            clocks: std::array::from_fn(|_| Clock::default()),
            samples: std::array::from_fn(|_| None), horizons: std::array::from_fn(|_| None),
            entry: None,
            run: None,
            readback: None,
            outer_after: None,
            complete: false,
            readiness: Default::default(),
        };

        owner.sample_once_v2(0);
        if !matches!(owner.horizons[0], Some(Ok(()))) {
            owner.fail_while_held_v2(controller, launch, profile);
        }
        owner.plan = Some(owner.source.prepare_pending_plan_v1(
            controller, launch, profile, request_scope,
            authorization, operation, batch, complete,
        ));
        if !matches!(owner.plan, Some(Ok(_))) {
            owner.fail_while_held_v2(controller, launch, profile);
        }

        // Pure graph/planning may take time. Recheck the ORIGINAL lease again
        // immediately before native append, without minting a new horizon.
        owner.sample_once_v2(1);
        if !matches!(owner.horizons[1], Some(Ok(()))) {
            owner.fail_while_held_v2(controller, launch, profile);
        }
        // End every temporary plan/native borrow before moving the SAME
        // completed pending owner. The append is positively disposed first;
        // failed branches still run owed posts and abort with it resident.
        {
            let plan = match owner.plan.as_ref().and_then(|plan| plan.as_ref().ok()) {
                Some(plan) => plan,
                None => std::process::abort(),
            };
            let native_complete = owner.source.reserve_pending_append_v2(controller, launch, profile, plan);
            let complete = match native_complete {
                Ok(complete) => complete,
                Err(cause) => {
                    owner.entry = Some(Err(cause));
                    observe_clock_once_v2(&mut owner.clocks, &mut owner.samples, &mut owner.horizons,
                        2, owner.original_clock, owner.expires);
                    owner.outer_after = Some(owner.source.finish_native_once_v1(controller, launch, profile));
                    std::process::abort();
                }
            };
            let entered = owner.source.enter_pending_append_v1(controller, launch, profile, plan, complete);
            if entered.is_err() {
                // Consume the failed entry Result before reborrowing the same
                // Source for its already owed outer post. No append owner exists
                // on this branch, and no live borrowed Result is discarded.
                let cause = match entered.err() {
                    Some(cause) => cause,
                    None => std::process::abort(),
                };
                owner.entry = Some(Err(cause));
                observe_clock_once_v2(
                    &mut owner.clocks, &mut owner.samples, &mut owner.horizons,
                    2, owner.original_clock, owner.expires,
                );
                owner.outer_after = Some(owner.source.finish_native_once_v1(controller, launch, profile));
                std::process::abort();
            }
            let mut append = match entered {
                Ok(append) => {
                    owner.entry = Some(Ok(()));
                    append
                }
                Err(_) => std::process::abort(),
            };

            owner.run = Some(append.run_once_v1());
            // Independently owed even after an earlier native/semantic refusal.
            observe_clock_once_v2(&mut owner.clocks, &mut owner.samples, &mut owner.horizons,
                2, owner.original_clock, owner.expires);
            if !matches!(owner.run, Some(Ok(()))) || !matches!(owner.horizons[2], Some(Ok(()))) {
                owner.outer_after = Some(append.finish_outer_scope_once_v1(controller, launch, profile));
                std::process::abort();
            }
            owner.readback = Some(append.complete_pending_readback_v1().map(|_| ()));
            if !matches!(owner.readback, Some(Ok(()))) {
                owner.outer_after = Some(append.finish_outer_scope_once_v1(controller, launch, profile));
                std::process::abort();
            }

            drop(append);
        }
        owner.complete = true;
        owner
    }
}

fn observe_clock_once_v2(
    clocks: &mut [Clock; 3],
    samples: &mut [Option<Result<RawPairedClockSample, PlanningClockError>>; 3],
    horizons: &mut [Option<Result<(), JournalError>>; 3],
    index: usize,
    original: RawPairedClockSample,
    expires: i64,
) {
    samples[index] = Some(clocks[index].observe_once(None));
    horizons[index] = Some((|| {
        let sample = *samples[index].as_ref().and_then(|sample| sample.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        original.validate_later_sample(sample)
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        let cutoff = original.conservative_expiry_deadline_data_v1(expires)
            .ok_or(JournalError::StaleAuthoritySnapshot)?;
        if sample.boottime_nanoseconds() >= cutoff {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        if index > 0 {
            let before = *samples[index - 1].as_ref().and_then(|sample| sample.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            before.validate_later_sample(sample)
                .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        }
        Ok(())
    })());
}
