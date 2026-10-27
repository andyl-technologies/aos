//! Funds the one installed Phase0 capture on the original Control ledger.
//!
//! The finite readonly interval shares the existing native pair observer and
//! independent post. Neither its returned programs nor its manager association
//! create backend readiness or a per-workload receiving grant.

use std::os::fd::AsFd;

use super::terminal_inventory::{ControlPreparationPurposeV5, HostControlPreparationReceivingV5};
use super::*;

impl HostComponentControlStartupV2 {
    pub(in crate::plan::deployment) fn require_component_phase0_manager_v2(
        &self,
        actual: &std::sync::Arc<SystemdClient>,
    ) -> Result<()> {
        self.require_admitted_original()?;
        let same = self.manager_original.as_ref().is_some_and(|original| {
            !original.has_ended_v2()
                && original.client_v2().is_some_and(|client| std::sync::Arc::ptr_eq(client, actual))
        });
        if !same {
            return Err(HostError::Fence("component Phase0 must use the same prepaid readonly manager"));
        }
        Ok(())
    }

    pub(in crate::plan::deployment) fn component_phase0_manager_original_v2(
        &self,
    ) -> Result<&std::sync::Arc<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>> {
        self.require_admitted_original()?;
        self.manager_original.as_ref()
            .ok_or(HostError::Fence("component Phase0 readonly manager original is absent"))
    }

    // Negative diagnostics require the same privately held manager identity,
    // but never reenter healthy admission after the actual original refused.
    pub(in crate::plan::deployment) fn component_phase0_failure_for_origin_v2(
        &self,
        actual: &std::sync::Arc<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>,
    ) -> Option<&dyn std::error::Error> {
        if self.first.is_none()
            || !self.manager_original.as_ref().is_some_and(|held| std::sync::Arc::ptr_eq(held, actual))
        {
            return None;
        }
        Some(self.failure())
    }

    pub(in crate::plan::deployment) fn require_component_phase0_origin_v2(
        &self,
        actual: &std::sync::Arc<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>,
    ) -> Result<()> {
        self.require_admitted_original()?;
        if !self.manager_original.as_ref().is_some_and(|held| std::sync::Arc::ptr_eq(held, actual))
            || actual.has_ended_v2()
        {
            return Err(HostError::Fence("component Phase0 belongs to another readonly manager original"));
        }
        Ok(())
    }

    pub(in crate::plan::deployment) fn component_host_executable_path_v2(&self) -> Result<&Path> {
        self.require_admitted_original()?;
        self.profile.as_ref().map(|profile| Path::new(&profile.host_path))
            .ok_or(HostError::Fence("component Host executable profile is absent"))
    }

    pub(in crate::plan::deployment) fn component_programs_v2(&self) -> Result<&[u8]> {
        self.require_admitted_original()?;
        if self.files[8].is_none() || self.identities[8].is_none() || self.bytes[2].is_empty() {
            return Err(HostError::Fence("component program original is absent"));
        }
        Ok(&self.bytes[2])
    }

    // Only the actual retained Phase0 constructor supplies this source-owned
    // demand. The full amount is added to already-spent Control before either
    // the new observer backing or any Phase0 native/model destination grows.
    pub(in crate::plan::deployment) fn begin_component_phase0_once_v2(
        &mut self,
        actual: &std::sync::Arc<SystemdClient>,
        phase0_source_demand: ResourceVector,
        selected_failure: &mut bool,
    ) -> Result<HostControlPreparationReceivingV5<'_>> {
        *selected_failure = false;
        self.require_component_phase0_manager_v2(actual)?;
        if self.component_phase0_funding.is_some() {
            return Err(HostError::Fence("component Phase0 preparation is already entered"));
        }
        let (observer, maximum) = self.recurring_observation_demand_v4()?;
        let loan_bytes = std::mem::size_of::<HostControlPreparationReceivingV5<'_>>()
            .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HostError::ResourceExhausted)?;
        let complete = phase0_source_demand.checked_add(observer)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes, loan_bytes)))
            .map_err(|_| HostError::ResourceExhausted)?;
        self.component_phase0_funding = Some(self.execution_receiving.as_mut()
            .and_then(|result| result.as_mut().ok()).ok_or(execution_receiving::Closed)
            .and_then(|owner| {
                owner.arm_component_physical_fit_once_v2()?;
                owner.extend_control_representation_v2(complete)
            }));
        if !matches!(self.component_phase0_funding, Some(Ok(()))) {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            *selected_failure = true;
            return Err(HostError::Fence("component Phase0 exceeds its same consumed Control"));
        }
        let destinations = match self.append_recurring_observation_destinations_v4(maximum) {
            Ok(destinations) => destinations,
            Err(cause) => {
                *selected_failure = matches!(self.first, Some(FirstCauseV2::RecurringAllocation));
                return Err(cause);
            }
        };
        Ok(HostControlPreparationReceivingV5 {
            original: self,
            purpose: ControlPreparationPurposeV5::ComponentPhase0,
            destinations,
            before: false,
            after: false,
            completed: false,
            extension: false,
            cleanup: None,
        })
    }
}

impl HostControlPreparationReceivingV5<'_> {
    fn require_component_phase0_v2(&self) -> Result<()> {
        if !matches!(self.purpose, ControlPreparationPurposeV5::ComponentPhase0) {
            return Err(HostError::Fence("readonly preparation has another purpose"));
        }
        self.original.require_admitted_original()
    }

    // This is sampled only at this same interval's failed boundary, before
    // independent later posts can enter a different original first cause.
    pub(in crate::plan::deployment) fn component_phase0_control_failure_selected_v2(&self) -> bool {
        matches!(self.purpose, ControlPreparationPurposeV5::ComponentPhase0)
            && self.original.first.is_some()
    }

    pub(in crate::plan::deployment) fn component_host_executable_path_v2(&self) -> Result<&Path> {
        self.require_component_phase0_v2()?;
        self.original.component_host_executable_path_v2()
    }

    pub(in crate::plan::deployment) fn component_programs_v2(&self) -> Result<&[u8]> {
        self.require_component_phase0_v2()?;
        self.original.component_programs_v2()
    }

    pub(in crate::plan::deployment) fn component_pid1_original_v2(&self) -> Result<BorrowedFd<'_>> {
        self.require_component_phase0_v2()?;
        // The admitted startup already verified this exact inherited PID1 pin.
        self.original.files[0].as_ref().map(AsFd::as_fd)
            .ok_or(HostError::Fence("component PID1 original is absent"))
    }

    pub(in crate::plan::deployment) fn component_manager_original_v2(
        &self,
    ) -> Result<&std::sync::Arc<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>> {
        self.require_component_phase0_v2()?;
        self.original.manager_original.as_ref()
            .ok_or(HostError::Fence("component readonly manager original is absent"))
    }
}
