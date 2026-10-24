//! Retains the paid mechanical cutoff of one catalog maintenance interval.
//!
//! The fixed transport ceiling bounds this local work only. It grants no
//! ownership, lease, accepted effect or publication authority. Current C,
//! Source, profile, signed inventories and Session owners remain separate
//! predicates on the genuine maintenance borrower.

use std::error::Error;

use crate::controller::RetainedControllerProtectedClockAttemptV1;
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1, RootContinuationHorizonDataV1,
};
use crate::{JournalError, ResourceReservationErrorV1};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2;
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};

const TRANSPORT_NANOSECONDS: u64 = 10_000_000_000;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Reentry,
    Before,
    Horizon,
    Frontier,
    After,
    AfterComparison,
}

/// Owns both independently paid paired observations and every failed prefix.
#[derive(Default)]
pub(super) struct CatalogMaintenanceClockV2 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    before: RetainedControllerProtectedClockAttemptV1,
    before_result: Option<Result<RawPairedClockSample, JournalError>>,
    horizon: Option<Result<RootContinuationHorizonDataV1, JournalError>>,
    cutoff: Option<u64>,
    gate: Option<RootContinuationClockGateV1>,
    after: RetainedControllerProtectedClockAttemptV1,
    after_result: Option<Result<RawPairedClockSample, JournalError>>,
    after_comparison: Option<Result<(), JournalError>>,
    first: Option<First>,
    reentry: Option<JournalError>,
}

impl CatalogMaintenanceClockV2 {
    pub(super) fn receiving_demand_v2() -> Result<ResourceVector, JournalError> {
        let paired = RetainedControllerProtectedClockAttemptV1::receiving_demand_v1()?;
        let frontiers =
            RootContinuationClockGateV1::controller_authorization_receiving_demand_v1()?;
        paired
            .checked_add(paired)
            .and_then(|demand| demand.checked_add(frontiers))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn begin_once_v2(
        &mut self,
        native: &ControllerCatalogMaintenanceReceivingV2,
    ) -> Result<(), JournalError> {
        if self.entry.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.entry = Some(
            native
                .require_prepaid_owed_observation_v2()
                .map_err(Into::into),
        );
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.before_result = Some(self.before.observe_once_v1());
        let Some(sample) = self
            .before_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            self.first = Some(First::Before);
            return Err(JournalError::ProtectedBoundary);
        };
        self.horizon = Some(
            sample
                .boottime_nanoseconds()
                .checked_add(TRANSPORT_NANOSECONDS)
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|cutoff| {
                    self.cutoff = Some(cutoff);
                    RootContinuationHorizonDataV1::from_original_data_v1(sample, cutoff)
                }),
        );
        let Some(horizon) = self
            .horizon
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            self.first = Some(First::Horizon);
            return Err(JournalError::ProtectedBoundary);
        };
        self.gate = Some(RootContinuationClockGateV1::new_controller_authorization_v1(horizon));
        Ok(())
    }

    pub(super) fn check_frontier_v2(&mut self) -> Result<RawPairedClockSample, JournalError> {
        if self.first.is_some() || self.after_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let returned = self
            .gate
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .check_next_once_v1();
        if returned.is_err() {
            self.first = Some(First::Frontier);
        }
        returned
    }

    pub(super) fn narrow_authority_expiry_v2(&mut self, expires: i64) -> Result<(), JournalError> {
        if self.first.is_some() || self.after_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.gate
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .narrow_wall_expiry_data_v1(expires);
        Ok(())
    }

    pub(super) fn original_sample_data_v2(&self) -> Result<RawPairedClockSample, JournalError> {
        self.before_result
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn cutoff_data_v2(&self) -> Result<u64, JournalError> {
        if self.first.is_some() || self.after_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cutoff.ok_or(JournalError::ProtectedBoundary)
    }

    // An entered primary failure never suppresses this independent sampler.
    // Its result is parked before comparison and cannot replace an earlier cause.
    pub(super) fn finish_once_v2(&mut self, native: &ControllerCatalogMaintenanceReceivingV2) {
        if self.after_result.is_some() {
            return;
        }
        if native.require_prepaid_owed_observation_v2().is_err() {
            return;
        }
        self.after_result = Some(self.after.observe_once_v1());
        let Some(sample) = self
            .after_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            self.first.get_or_insert(First::After);
            return;
        };
        self.after_comparison = Some(
            self.gate
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|gate| gate.require_final_sample_v1(sample)),
        );
        if !matches!(self.after_comparison, Some(Ok(()))) {
            self.first.get_or_insert(First::AfterComparison);
        }
    }

    pub(super) fn require_completed_v2(&self) -> Result<(), JournalError> {
        if self.first.is_some()
            || !matches!(self.before_result, Some(Ok(_)))
            || !matches!(self.after_result, Some(Ok(_)))
            || !matches!(self.after_comparison, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Before => self.before.failure().or_else(|| {
                self.before_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::Horizon => self
                .horizon
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Frontier => self.gate.as_ref()?.failure(),
            First::After => self.after.failure().or_else(|| {
                self.after_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::AfterComparison => self
                .after_comparison
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
        }
    }
}
