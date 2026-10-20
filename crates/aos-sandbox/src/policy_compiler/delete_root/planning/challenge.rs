//! Holds the paid planning nonce, original horizon and independent Root clock.

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1, fresh_root_nonce};
use aos_sandbox_core::{RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::planning::{
    DeleteRootPlanningChallengeDataV3, DeleteRootPlanningDataErrorV3, DeleteRootPlanningOpenDataV3,
};
use std::error::Error;

#[derive(Default)]
pub(crate) struct RootDeletePlanningChallengeOriginalV1 {
    entered: bool,
    open: Option<DeleteRootPlanningOpenDataV3>,
    permit: Option<Result<(), ResourceReservationErrorV1>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    nonce: Option<std::io::Result<[u8; 16]>>,
    challenge: Option<Result<DeleteRootPlanningChallengeDataV3, DeleteRootPlanningDataErrorV3>>,
    returned: Option<Result<(), NormalRootStartupErrorV1>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    closed: Option<NormalRootStartupErrorV1>,
}

impl RootDeletePlanningChallengeOriginalV1 {
    pub(super) fn prepare_once_v1(
        &mut self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        open: DeleteRootPlanningOpenDataV3,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.entered {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.entered = true;
        self.open = Some(open);
        self.permit = Some(flight.admit_delete_planning_challenge_once_v1(self));
        self.returned = Some((|| {
            positive(&self.permit)?;
            self.before = Some(self.before_original.observe_once(None));
            let before = *positive(&self.before)?;
            self.nonce = Some(fresh_root_nonce());
            let nonce = *positive(&self.nonce)?;
            self.challenge = Some((|| {
                let challenge = DeleteRootPlanningChallengeDataV3 {
                    open: open.digest_v3()?,
                    clock: before,
                    nonce,
                    cutoff: open.cutoff_for_root_sample_v1(before)?,
                };
                challenge.require_open_v3(open)?;
                challenge.encode_v3()?;
                Ok(challenge)
            })());
            positive(&self.challenge).map(|_| ())
        })());
        if matches!(self.returned, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.permit.is_some() || self.open.is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        super::RootDeletePlanningReceivingV1::fixed_receiving_demand_v1()
    }

    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.permit, Some(Ok(())))
            || !matches!(self.returned, Some(Ok(())))
            || !matches!(self.challenge, Some(Ok(_)))
            || self.failure().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, NormalRootStartupErrorV1> {
        self.require_paid_chunk_peak_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        self.data_v1().map(|challenge| challenge.cutoff)
    }

    pub(super) fn data_v1(
        &self,
    ) -> Result<DeleteRootPlanningChallengeDataV3, NormalRootStartupErrorV1> {
        positive(&self.challenge).copied()
    }

    pub(super) fn require_current_clock_v1(
        &self,
        clock: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        let invalid = || JournalError::ProtectedBoundary;
        let open = self.open.ok_or_else(invalid)?;
        let challenge = self.data_v1().map_err(|_| invalid())?;
        challenge
            .clock
            .validate_later_sample(clock)
            .map_err(|_| invalid())?;
        open.authorization_clock
            .validate_later_sample(clock)
            .map_err(|_| invalid())?;
        if clock.boottime_nanoseconds() >= challenge.cutoff
            || clock.wall_seconds() >= open.authorization_expires
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn finish_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.after.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        if !matches!(self.permit, Some(Ok(()))) {
            return Ok(());
        }
        // This actual prepaid clock remains owed after every reached failure.
        self.after = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            let clock = *self
                .after
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.require_current_clock_v1(clock)
        })());
        if matches!(self.after_binding, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    pub(super) fn final_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        if !matches!(self.after_binding, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.after
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.permit, Some(Err(_)))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.permit)
            .or_else(|| self.before_original.failure())
            .or_else(|| error(&self.before))
            .or_else(|| error(&self.nonce))
            .or_else(|| error(&self.challenge))
            .or_else(|| error(&self.returned))
            .or_else(|| self.after_original.failure())
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.after_binding))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, NormalRootStartupErrorV1> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(NormalRootStartupErrorV1::Service)
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
