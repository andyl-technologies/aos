//! Adds paid recurring destinations to the one existing Host observer.
//!
//! Initial slots retain their original inline layout and indices. A genuine
//! purpose must admit each additional pair before its allocation. The same
//! fragment/process/PID1/pair/boot recipe indexes both kinds of destination;
//! this module neither observes a process nor constructs a receiving permit.

use std::ops::{Index, IndexMut};

use super::*;

type ManagerResult = std::result::Result<(), aos_systemd_client::Error>;
const FIXED_ATTEMPTS: usize = MAXIMUM_ATTEMPTS + EXECUTION_ATTEMPTS;
const FIXED_MANAGERS: usize = 5;

#[derive(Clone, Copy)]
enum ObservationDispositionV4 {
    Ordinary,
    StopContainment,
}

struct RecurringPairV4 {
    attempts: [OriginAttemptV2; 2],
    first: [Option<FirstCauseV2>; 2],
    manager: Option<ManagerResult>,
    maximum_materialized_bytes: usize,
}

pub(super) struct OriginAttemptsV4 {
    fixed: [OriginAttemptV2; FIXED_ATTEMPTS],
    recurring: Vec<RecurringPairV4>,
    allocation: Option<std::result::Result<(), std::collections::TryReserveError>>,
}

// These are only indices into the same retained original. The private genuine
// purpose factory owns admission and must retain its separately typed identity.
pub(super) struct RecurringObservationDestinationsV4 {
    pub(super) round_start: usize,
    pub(super) manager_slot: usize,
}

impl OriginAttemptsV4 {
    pub(super) fn get(&self, round: usize) -> Option<&OriginAttemptV2> {
        if round < FIXED_ATTEMPTS {
            self.fixed.get(round)
        } else {
            let offset = round.checked_sub(FIXED_ATTEMPTS)?;
            self.recurring.get(offset / 2)?.attempts.get(offset % 2)
        }
    }

    pub(super) fn new() -> Self {
        Self {
            fixed: std::array::from_fn(|_| OriginAttemptV2::new()),
            recurring: Vec::new(),
            allocation: None,
        }
    }

    pub(super) fn allocation_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.allocation.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    // Two full vector planes cover retained backing and construction/reallocation
    // while the old backing is still live. Existing nested native suppliers
    // separately cover each pair's actual Files, bytes and semantic models.
    fn next_pair_receiving_bytes_v4(&self) -> Option<usize> {
        self.recurring.len().checked_add(1)?
            .checked_mul(std::mem::size_of::<RecurringPairV4>())?
            .checked_mul(2)
    }

    fn append_pair_v4(&mut self, maximum: usize) -> Result<RecurringObservationDestinationsV4> {
        if self.allocation.as_ref().is_some_and(|result| result.is_err()) {
            return Err(HostError::Fence("Host recurring destination allocation already failed"));
        }
        let index = self.recurring.len();
        let round_start = index.checked_mul(2)
            .and_then(|offset| FIXED_ATTEMPTS.checked_add(offset))
            .ok_or(HostError::ResourceExhausted)?;
        let manager_slot = FIXED_MANAGERS.checked_add(index)
            .ok_or(HostError::ResourceExhausted)?;

        self.allocation = Some(self.recurring.try_reserve_exact(1));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(HostError::Fence("Host recurring destination allocation failed; cause retained"));
        }
        self.recurring.push(RecurringPairV4 {
            attempts: std::array::from_fn(|_| OriginAttemptV2::new()),
            first: [None; 2],
            manager: None,
            maximum_materialized_bytes: maximum,
        });
        Ok(RecurringObservationDestinationsV4 { round_start, manager_slot })
    }
}

impl Index<usize> for OriginAttemptsV4 {
    type Output = OriginAttemptV2;

    fn index(&self, round: usize) -> &Self::Output {
        if round < FIXED_ATTEMPTS {
            &self.fixed[round]
        } else {
            let offset = round - FIXED_ATTEMPTS;
            &self.recurring[offset / 2].attempts[offset % 2]
        }
    }
}

impl IndexMut<usize> for OriginAttemptsV4 {
    fn index_mut(&mut self, round: usize) -> &mut Self::Output {
        if round < FIXED_ATTEMPTS {
            &mut self.fixed[round]
        } else {
            let offset = round - FIXED_ATTEMPTS;
            &mut self.recurring[offset / 2].attempts[offset % 2]
        }
    }
}

impl HostComponentControlStartupV2 {
    pub(super) fn record_origin_failure_v4(&mut self, round: usize, cause: FirstCauseV2) {
        self.first.get_or_insert(cause);
        if let Some(offset) = round.checked_sub(FIXED_ATTEMPTS) {
            if let Some(pair) = self.attempts.recurring.get_mut(offset / 2) {
                pair.first[offset % 2].get_or_insert(cause);
            }
        }
    }

    // Borrowing this new row never selects a later failure from the same
    // component over its earlier native cause. The owning pair is retained.
    pub(super) fn recurring_leaf_failure_v4(&self, round: usize) -> Option<&dyn Error> {
        let offset = round.checked_sub(FIXED_ATTEMPTS)?;
        let first = self.attempts.recurring.get(offset / 2)?.first[offset % 2]?;
        Some(self.failure_for_first_v4(Some(first)))
    }

    // The existing execution loan and the closed recurring purpose factories
    // call this sole native recipe after admission. The independent post may
    // still call it after an earlier failure; healthy admission is not retried.
    pub(super) async fn observe_execution_slot_v4(&mut self, round: usize) -> Result<()> {
        self.observe_execution_slot_with_disposition_v4(round, ObservationDispositionV4::Ordinary).await
    }

    // Only the fresh signed Stop lender may enter this sibling. Earlier failed
    // execution flags stay sticky; the new paid leaf must independently pass
    // every original native check. This never resumes positive execution.
    pub(super) async fn observe_capture_stop_slot_v4(&mut self, round: usize) -> Result<()> {
        self.observe_execution_slot_with_disposition_v4(round, ObservationDispositionV4::StopContainment).await
    }

    async fn observe_execution_slot_with_disposition_v4(
        &mut self,
        round: usize,
        disposition: ObservationDispositionV4,
    ) -> Result<()> {
        if self.attempts[round].action.is_some() {
            return Err(HostError::Fence("Host execution native observation was already entered"));
        }
        self.armed = true;
        self.attempts[round].action = Some(self.require_fragment());
        if self.attempts[round].action.as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Action(round));
        }
        let manager = self.manager_original.as_ref().and_then(|original| original.client_v2())
            .cloned().ok_or(HostError::Fence("Host execution same manager is absent"))?;
        self.post_available(&manager, round).await;
        match disposition {
            ObservationDispositionV4::Ordinary => {
                if self.first.is_some() {
                    if let Some(owner) = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok()) {
                        owner.close();
                    }
                    return Err(HostError::Fence("Host execution original native observation failed"));
                }
                self.armed = false;
                Ok(())
            }
            ObservationDispositionV4::StopContainment => {
                // Keep the whole old failed original armed. Its failure neither
                // excuses a missing new post nor becomes this Stop's success.
                self.attempts[round].require_positive_leaf_v2()
            }
        }
    }

    pub(super) fn manager_growth_v4(&self, slot: usize) -> Option<&ManagerResult> {
        if slot < FIXED_MANAGERS {
            self.execution_manager_growth[slot].as_ref()
        } else {
            self.attempts.recurring[slot - FIXED_MANAGERS].manager.as_ref()
        }
    }

    pub(super) fn record_manager_growth_v4(&mut self, slot: usize, result: ManagerResult) {
        if slot < FIXED_MANAGERS {
            self.execution_manager_growth[slot] = Some(result);
        } else {
            self.attempts.recurring[slot - FIXED_MANAGERS].manager = Some(result);
        }
    }

    pub(super) fn recurring_materialized_maximum_v4(&self, slot: usize) -> Option<usize> {
        self.attempts.recurring.get(slot.checked_sub(FIXED_MANAGERS)?)
            .map(|pair| pair.maximum_materialized_bytes)
    }

    // The actual upper Stop/Capture purpose compares this complete DATA term
    // on its same consumed operation before invoking the allocator below.
    pub(crate) fn recurring_observation_demand_v4(&self) -> Result<(ResourceVector, usize)> {
        self.require_admitted_original()?;
        self.recurring_observation_geometry_v4()
    }

    pub(super) fn recurring_observation_geometry_v4(&self) -> Result<(ResourceVector, usize)> {
        use aos_sandbox_model::ResourceDimension as D;

        let schedule = self.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host recurring observation has no original schedule"))?;
        let manager = self.manager_original.as_ref()
            .ok_or(HostError::Fence("Host recurring observation has no original manager"))?;
        let maximum = manager.materialization_extent_v2().1
            .checked_add(schedule.phase_materialized_bytes)
            .ok_or(HostError::ResourceExhausted)?;
        let storage = self.attempts.next_pair_receiving_bytes_v4()
            .ok_or(HostError::ResourceExhausted)?;
        let demand = self.execution_observation_demand_for_maximum_v4(maximum, 1)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(storage).map_err(|_| HostError::ResourceExhausted)?))
            .map_err(|_| HostError::ResourceExhausted)?;
        Ok((demand, maximum))
    }

    pub(super) fn append_capture_stop_destinations_v4(
        &mut self,
        launch: super::execution_receiving::Request,
        request: super::execution_receiving::Request,
        maximum: usize,
    ) -> Result<RecurringObservationDestinationsV4> {
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("fresh Stop intrinsic original is absent"))?
            .require_capture_stop_owed_v4(launch, request)
            .map_err(|_| HostError::Fence("fresh Stop native destinations were not prepaid"))?;
        let result = self.attempts.append_pair_v4(maximum);
        if result.is_err() {
            self.first.get_or_insert(FirstCauseV2::RecurringAllocation);
            if let Some(Ok(receiving)) = self.execution_receiving.as_mut() {
                let _ = receiving.record_capture_stop_allocation_refusal_v4(launch, request);
            }
        }
        result
    }

    pub(super) fn append_stop_admission_destinations_v4(
        &mut self, request: super::execution_receiving::Request, maximum: usize,
    ) -> Result<RecurringObservationDestinationsV4> {
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Stop admission has no consumed receiving original"))?
            .require_stop_admission_owed_v4(request)
            .map_err(|_| HostError::Fence("Stop admission native destinations were not paid"))?;
        let result = self.attempts.append_pair_v4(maximum);
        if result.is_err() {
            self.first.get_or_insert(FirstCauseV2::RecurringAllocation);
            if let Some(Ok(owner)) = self.execution_receiving.as_mut() {
                owner.record_stop_admission_allocation_refusal_v4(request);
            }
        }
        result
    }

    pub(super) fn append_recurring_observation_destinations_v4(
        &mut self,
        maximum: usize,
    ) -> Result<RecurringObservationDestinationsV4> {
        self.require_admitted_original()?;
        let result = self.attempts.append_pair_v4(maximum);
        if result.is_err() {
            self.first.get_or_insert(FirstCauseV2::RecurringAllocation);
        }
        result
    }
}
