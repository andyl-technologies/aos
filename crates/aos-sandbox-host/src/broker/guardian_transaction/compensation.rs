//! Selects the same cleanup worker without exposing its healthy capabilities.

use super::*;
use crate::worker::launch::{HostLaunchCompensationLoanV1, HostLaunchWorkerReceivingV2};

pub(super) enum GuardianCleanupReceivingV1<'borrow, 'call, 'original> {
    Selected(&'borrow mut HostLaunchWorkerReceivingV2<'call, 'original>),
    Negative(HostLaunchCompensationLoanV1<'borrow, 'call, 'original>),
}

pub(super) enum GuardianCompensationOutcomeV1 {
    Completed(Vec<u8>),
    RetainedNegative,
}

impl GuardianCleanupReceivingV1<'_, '_, '_> {
    pub(super) async fn observe_v1(
        &mut self,
        worker: &crate::worker::RetainedPayloadWorkerV1<'_>,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
        post_unref: bool,
    ) -> Result<crate::worker::GuardianObservation> {
        match self {
            Self::Negative(loan) => loan.observe_v1(worker, identity, role, post_unref).await,
            Self::Selected(receiving) if post_unref => {
                receiving
                    .observe_post_unref_v3(worker, identity, role)
                    .await
            }
            Self::Selected(receiving) => receiving.observe_role_v2(worker, identity, role).await,
        }
    }

    pub(super) async fn stop_v1(
        &mut self,
        worker: &crate::worker::RetainedPayloadWorkerV1<'_>,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
        binding: [u8; 32],
        invocation: [u8; 16],
    ) -> Result<ExactWorkerStopOutcome> {
        match self {
            Self::Negative(loan) => {
                loan.stop_v1(worker, identity, role, binding, invocation)
                    .await
            }
            Self::Selected(receiving) => {
                receiving
                    .stop_exact_unit_v3(worker, identity, role, binding, invocation)
                    .await
            }
        }
    }
}

// This selection is constructed only at the real failed verification frontier
// and rejoined to its resident worker before any external diagnostic uses it.
pub(super) struct SelectedVerificationFailureOriginalV1 {
    affinity: crate::worker::launch::HostLaunchVerificationAffinityV1,
    domain: VerificationFailureDomainV1,
}

enum VerificationFailureDomainV1 {
    Source,
    Clock,
    Readback,
}

/// Borrows a cause only after the concrete same-original affinity joined.
#[derive(Clone, Copy)]
pub(in crate::broker) enum SelectedVerificationFailureBorrowV1<'cause> {
    Source,
    Clock,
    Readback(&'cause dyn std::error::Error),
}

impl SelectedVerificationFailureBorrowV1<'_> {
    pub(in crate::broker) fn cause_v1<'sample>(
        &'sample self,
        source: &'sample dyn std::error::Error,
        clock: Option<&'sample dyn std::error::Error>,
    ) -> Option<&'sample dyn std::error::Error> {
        match self {
            Self::Source => Some(source),
            Self::Clock => clock,
            Self::Readback(cause) => Some(*cause),
        }
    }
}

impl SelectedVerificationFailureOriginalV1 {
    pub(super) fn capture_v1(
        affinity: crate::worker::launch::HostLaunchVerificationAffinityV1,
        stage: &super::super::launch_handoff::HostLaunchOriginalV2,
    ) -> Result<Self> {
        if !stage
            .worker
            .as_ref()
            .is_some_and(|worker| affinity.matches_worker_v1(worker, stage.request))
        {
            return Err(HostError::Fence(
                "verification diagnostic differs from actual Stage",
            ));
        }
        let domain = if affinity.original_failure_selected_v1() {
            VerificationFailureDomainV1::Source
        } else if stage
            .clock
            .as_ref()
            .and_then(super::super::argument_handoff::ArgumentClockV2::failure)
            .is_some()
        {
            VerificationFailureDomainV1::Clock
        } else {
            VerificationFailureDomainV1::Readback
        };
        Ok(Self { affinity, domain })
    }

    pub(super) fn borrow_v1<'cause>(
        &self,
        stage: &super::super::launch_handoff::HostLaunchOriginalV2,
        cause: &'cause dyn std::error::Error,
    ) -> Option<SelectedVerificationFailureBorrowV1<'cause>> {
        if !stage
            .worker
            .as_ref()
            .is_some_and(|worker| self.affinity.matches_worker_v1(worker, stage.request))
        {
            return None;
        }
        Some(match self.domain {
            VerificationFailureDomainV1::Source => SelectedVerificationFailureBorrowV1::Source,
            VerificationFailureDomainV1::Clock => SelectedVerificationFailureBorrowV1::Clock,
            VerificationFailureDomainV1::Readback => {
                SelectedVerificationFailureBorrowV1::Readback(cause)
            }
        })
    }
}

