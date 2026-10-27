//! Shares finite Inventory and next-execution preparation observations.
//!
//! Both destinations debit the same consumed control operation. Stopped
//! Inventory uses its actual read header and opens its own readonly interval.
//! A next-execution transition keeps the old Accept interval occupied; only its
//! separate genuine method58 admission can authorize reservation State writes.
//! The observer supplies no role, deadline, new account or execution permission.

use super::*;
use super::recurring_observation::RecurringObservationDestinationsV4;
use aos_sandbox_protocol::ValidatedHeader;

#[derive(Clone, Copy)]
pub(super) enum ControlPreparationPurposeV5 {
    RuntimeInventory,
    LiveRuntimeInventory {
        launch: execution_receiving::Request,
        capture: Option<(execution_receiving::Request, execution_receiving::Request)>,
    },
    CatalogPublication,
    ComponentPhase0,
    StopAdmission,
    UnsentStopDisposal,
    ExecutionTransition,
    StopCleanup,
    NoApplyCleanup,
}

pub(crate) struct HostControlPreparationReceivingV5<'original> {
    pub(super) original: &'original mut HostComponentControlStartupV2,
    pub(super) purpose: ControlPreparationPurposeV5,
    pub(super) destinations: RecurringObservationDestinationsV4,
    pub(super) before: bool,
    pub(super) after: bool,
    pub(super) completed: bool,
    pub(super) extension: bool,
    pub(super) cleanup: Option<super::cleanup_preparation::CleanupPreparationV1>,
}

impl HostComponentControlStartupV2 {
    pub(crate) fn begin_unsent_stop_disposal_v1<'original>(
        &'original mut self,
        launch: execution_receiving::Request,
        proof: &crate::broker::HostResidentStopNativeCompletedV4,
        complete: ResourceVector,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        self.require_admitted_original()?;
        let (native, maximum) = self.recurring_observation_demand_v4()?;
        let loan = inventory_loan_demand_v5()?;
        let complete = complete.checked_add(native)
            .and_then(|demand| demand.checked_add(loan))
            .map_err(|_| HostError::ResourceExhausted)?;
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::Fence("unsent Stop has no actual Control owner"))?
            .admit_unsent_stop_disposal_v1(launch, proof, complete);
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("unsent Stop disposal exceeds its same Control"));
        }
        let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
        Ok(HostControlPreparationReceivingV5 {
            original: self,
            purpose: ControlPreparationPurposeV5::UnsentStopDisposal,
            destinations,
            before: false,
            after: false,
            completed: false,
            extension: false,
            cleanup: None,
        })
    }

    pub(crate) fn begin_terminal_inventory_v4<'original>(
        &'original mut self,
        header: &ValidatedHeader,
        proof: &crate::broker::HostStoppedNamespaceOriginalV4,
        shape: &crate::broker::HostTerminalInventoryShapeV4,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        self.require_argument_boot_v2(*proof.scope_v4().boot_v4())?;
        if header.request_id() == &[0; 16] || header.maximum_response_bytes() == 0 {
            return Err(HostError::Fence(
                "Host terminal Inventory has no validated read header",
            ));
        }
        self.begin_native_inventory_engine_v5(shape.receiving_demand_v4()?, None, None)
    }

    pub(crate) fn native_inventory_coordinates_v5(&self) -> Result<([u8; 16], [u8; 16])> {
        self.require_admitted_original()?;
        let boot = self.original_boot.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host native inventory original boot is absent"))?;
        Ok((boot.into_bytes(), self.recipient.ok_or(HostError::Fence(
            "Host native inventory recipient is absent"))?))
    }

    pub(crate) fn begin_native_inventory_entry_v5<'original>(&'original mut self,
        complete: ResourceVector, selected_failure: &mut bool)
        -> Result<HostControlPreparationReceivingV5<'original>>
    {
        *selected_failure = false;
        self.require_admitted_original()?;
        // This admits only the fixed readonly comparison prefix. Fresh Header
        // acceptance follows its actual paid native pair before discovery.
        self.begin_native_inventory_engine_v5(complete, Some(selected_failure), None)
    }

    /// Lends the same paid read engine alongside its genuine resident parent.
    ///
    /// # Errors
    /// Refuses mismatched original bindings, closed Control or insufficient funds.
    pub(crate) fn begin_live_native_inventory_entry_v1<'original>(
        &'original mut self,
        complete: ResourceVector,
        selected_failure: &mut bool,
        parent: &crate::broker::HostLiveCleanupParentV1<'_>,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        *selected_failure = false;
        self.require_admitted_original()?;
        self.begin_native_inventory_engine_v5(complete, Some(selected_failure), Some(parent))
    }

    fn begin_native_inventory_engine_v5<'original>(
        &'original mut self,
        complete: ResourceVector,
        mut selected_failure: Option<&mut bool>,
        parent: Option<&crate::broker::HostLiveCleanupParentV1<'_>>,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        let (native, maximum) = self.recurring_observation_demand_v4()?;
        let loan = inventory_loan_demand_v5()?;
        let complete = complete
            .checked_add(native)
            .and_then(|demand| demand.checked_add(loan))
            .map_err(|_| HostError::ResourceExhausted)?;
        let live = parent.map(|parent| parent.original_bindings_v1());
        let admitted = self
            .execution_receiving
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| match live {
                Some((launch, capture)) => owner.admit_live_inventory_v1(launch, capture, complete),
                None => owner.admit_terminal_inventory_v4(complete),
            });
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            if let Some(selected) = selected_failure.as_mut() {
                **selected = true;
            }
            return Err(HostError::Fence(
                "Host terminal Inventory exceeds its consumed control original",
            ));
        }
        let destinations = match self.append_recurring_observation_destinations_v4(maximum) {
            Ok(destinations) => destinations,
            Err(cause) => {
                if let Some(selected) = selected_failure.as_mut() { **selected = self.first.is_some(); }
                return Err(cause);
            }
        };
        Ok(HostControlPreparationReceivingV5 {
            original: self,
            purpose: match live {
                Some((launch, capture)) => {
                    ControlPreparationPurposeV5::LiveRuntimeInventory { launch, capture }
                }
                None => ControlPreparationPurposeV5::RuntimeInventory,
            },
            destinations,
            before: false,
            after: false,
            completed: false,
            extension: false,
            cleanup: None,
        })
    }
}

impl HostComponentControlStartupV2 {
    pub(crate) fn control_preparation_failure_v5(&self) -> Option<&(dyn std::error::Error + '_)> {
        self.first.map(|_| self.failure())
    }

    pub(crate) fn begin_execution_transition_preparation_v5<'original>(
        &'original mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        shape: &crate::broker::HostExecutionTransitionShapeV5,
        parent: &crate::broker::HostExecutionTransitionParentV5<'_>,
        selected_failure: &mut bool,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        *selected_failure = false;
        let preparation = (|| -> Result<RecurringObservationDestinationsV4> {
            use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
            use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;
            if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
                || request.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                || request.authorization().is_none() || self.armed || self.first.is_some()
            {
                return Err(HostError::Fence("execution transition requires actual authenticated method58"));
            }
            let (native, maximum) = self.recurring_observation_demand_v4()?;
            let loan_bytes = std::mem::size_of::<HostControlPreparationReceivingV5<'_>>()
                .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(HostError::ResourceExhausted)?;
            let complete = shape.receiving_demand_v5()?.checked_add(native)
                .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(
                    aos_sandbox_model::ResourceDimension::MemoryBytes, loan_bytes)))
                .map_err(|_| HostError::ResourceExhausted)?;
            let (launch, accept, observe) = parent.original_bindings_v5();
            let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(execution_receiving::Closed)
                .and_then(|owner| owner.admit_execution_transition_preparation_v5(launch, accept, observe, complete));
            if admitted.is_err() {
                self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
                return Err(HostError::Fence("execution transition exceeds its consumed control original"));
            }
            let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
            Ok(destinations)
        })();
        if preparation.is_err() {
            *selected_failure = self.control_preparation_failure_v5().is_some();
        }
        let destinations = preparation?;
        Ok(HostControlPreparationReceivingV5 { original: self,
            purpose: ControlPreparationPurposeV5::ExecutionTransition, destinations,
            before: false, after: false, completed: false, extension: false, cleanup: None })
    }
}

impl HostControlPreparationReceivingV5<'_> {
    pub(crate) fn native_inventory_extension_available_v5(&self) -> Result<ResourceVector> {
        if !matches!(
            self.purpose,
            ControlPreparationPurposeV5::RuntimeInventory
                | ControlPreparationPurposeV5::LiveRuntimeInventory { .. }
        ) || self.before
            || self.extension
        {
            return Err(HostError::Fence(
                "Host native inventory extension is occupied",
            ));
        }
        let owner = self
            .original
            .execution_receiving
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or(HostError::Fence(
                "Host native inventory control original is absent",
            ))?;
        match self.purpose {
            ControlPreparationPurposeV5::LiveRuntimeInventory { launch, capture } => {
                owner.live_inventory_available_v1(launch, capture)
            }
            _ => owner.native_inventory_available_v5(),
        }
        .map_err(|_| HostError::Fence("Host native inventory control original is occupied"))
    }

    pub(crate) fn extend_native_inventory_once_v5(
        &mut self,
        additional: ResourceVector,
    ) -> Result<()> {
        if !matches!(
            self.purpose,
            ControlPreparationPurposeV5::RuntimeInventory
                | ControlPreparationPurposeV5::LiveRuntimeInventory { .. }
        ) || self.before
            || self.extension
        {
            return Err(HostError::Fence(
                "Host native inventory extension is occupied",
            ));
        }
        self.extension = true;
        let admitted = self
            .original
            .execution_receiving
            .as_mut()
            .and_then(|r| r.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| match self.purpose {
                ControlPreparationPurposeV5::LiveRuntimeInventory { launch, capture } => {
                    owner.admit_live_inventory_v1(launch, capture, additional)
                }
                _ => owner.admit_terminal_inventory_v4(additional),
            });
        if admitted.is_err() {
            self.original
                .first
                .get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence(
                "Host native inventory exceeds its same consumed control",
            ));
        }
        Ok(())
    }

    pub(crate) fn original_failure_entered_v5(&self) -> bool {
        self.original.first.is_some()
    }

    pub(crate) fn extend_execution_transition_v5(
        &mut self, shape: &crate::broker::HostExecutionTransitionShapeV5,
    ) -> Result<()> {
        if !matches!(self.purpose, ControlPreparationPurposeV5::ExecutionTransition)
            || self.before || self.extension
        { return Err(HostError::Fence("Host transition extension is occupied")); }
        self.extension = true;
        let additional = shape.claim_demand_v5()?;
        let admitted = self.original.execution_receiving.as_mut()
            .and_then(|result| result.as_mut().ok()).ok_or(execution_receiving::Closed)
            .and_then(|owner| owner.extend_execution_transition_preparation_v5(additional));
        if admitted.is_err() {
            self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Host transition claim exceeds its control original"));
        }
        Ok(())
    }

    pub(crate) async fn observe_before_once_v5(&mut self) -> Result<()> {
        if self.before { return Err(HostError::Fence("Host terminal Inventory before is occupied")); }
        self.before = true;
        self.cleanup_before_entered_v1()?;
        // Prearm the independent destination before entering any manager work.
        self.original
            .prepare_owed_process_once_v2(self.destinations.round_start + 1)
            .map_err(|_| HostError::Fence(
                "Host terminal Inventory independent process post could not be prearmed",
            ))?;
        let maximum = self.original.recurring_materialized_maximum_v4(self.destinations.manager_slot)
            .ok_or(HostError::ResourceExhausted)?;
        let manager = self.original.manager_original.as_ref()
            .ok_or(HostError::Fence("Host terminal Inventory manager is absent"))?;
        let growth = manager
            .raise_materialization_limit_v2(maximum)
            .and_then(|()| match self.purpose {
                ControlPreparationPurposeV5::RuntimeInventory
                | ControlPreparationPurposeV5::LiveRuntimeInventory { capture: None, .. }
                | ControlPreparationPurposeV5::CatalogPublication
                | ControlPreparationPurposeV5::ComponentPhase0 => {
                    manager.begin_readonly_interval_v2()
                }
                ControlPreparationPurposeV5::StopCleanup
                | ControlPreparationPurposeV5::NoApplyCleanup => {
                    if self.cleanup.as_ref().is_some_and(|cleanup| cleanup.resumed) {
                        Ok(())
                    } else {
                        manager.begin_readonly_interval_v2()
                    }
                }
                // The original Accept interval remains occupied throughout the
                // transition; its later genuine terminal disposer ends it.
                ControlPreparationPurposeV5::ExecutionTransition
                | ControlPreparationPurposeV5::UnsentStopDisposal
                | ControlPreparationPurposeV5::LiveRuntimeInventory {
                    capture: Some(_), ..
                }
                | ControlPreparationPurposeV5::StopAdmission => Ok(()),
            });
        self.original
            .record_manager_growth_v4(self.destinations.manager_slot, growth);
        if self
            .original
            .manager_growth_v4(self.destinations.manager_slot)
            .is_some_and(|result| result.is_err())
        {
            self.original.record_origin_failure_v4(
                self.destinations.round_start,
                FirstCauseV2::ExecutionManager(self.destinations.manager_slot),
            );
            return Err(HostError::Fence(
                "Host terminal Inventory manager interval failed",
            ));
        }
        match self.purpose {
            ControlPreparationPurposeV5::StopAdmission => self.original
                .observe_capture_stop_slot_v4(self.destinations.round_start).await,
            _ => self.original.observe_execution_slot_v4(self.destinations.round_start).await,
        }
    }

    pub(crate) async fn observe_after_once_v5(&mut self) -> Result<()> {
        if !self.before || self.after {
            return Err(HostError::Fence("Host terminal Inventory has no independently owed after"));
        }
        self.after = true;
        self.cleanup_after_entered_v1()?;
        // This is the already-paid negative destination, including after an
        // earlier body/native/financial refusal. It does not reenter health.
        match self.purpose {
            ControlPreparationPurposeV5::StopAdmission => self.original
                .observe_capture_stop_slot_v4(self.destinations.round_start + 1).await,
            _ => self.original.observe_execution_slot_v4(self.destinations.round_start + 1).await,
        }
    }

    pub(crate) fn dispose_positive_once_v5(&mut self) -> Result<()> {
        if self.cleanup.is_some() {
            return Err(HostError::Fence("cleanup native ownership requires its typed final disposer"));
        }
        if !self.before || !self.after {
            return Err(HostError::Fence("Host terminal Inventory posts are incomplete"));
        }
        match self.purpose {
            ControlPreparationPurposeV5::RuntimeInventory
            | ControlPreparationPurposeV5::LiveRuntimeInventory { capture: None, .. }
            | ControlPreparationPurposeV5::CatalogPublication
            | ControlPreparationPurposeV5::ComponentPhase0 => {
                self.original.retire_execution_samples_v2(
                    self.destinations.round_start,
                    2,
                    self.destinations.manager_slot,
                )?
            }
            ControlPreparationPurposeV5::ExecutionTransition
            | ControlPreparationPurposeV5::UnsentStopDisposal
            | ControlPreparationPurposeV5::LiveRuntimeInventory {
                capture: Some(_), ..
            }
            | ControlPreparationPurposeV5::StopAdmission => {
                for round in self.destinations.round_start..self.destinations.round_start + 2 {
                    self.original.attempts[round].require_positive_leaf_v2()?;
                }
                for round in self.destinations.round_start .. self.destinations.round_start + 2 {
                    self.original.attempts[round].dispose_positive_leaf_v2()?;
                }
            }
            ControlPreparationPurposeV5::StopCleanup | ControlPreparationPurposeV5::NoApplyCleanup => {
                return Err(HostError::Fence("cleanup preparation lost its retained flight"));
            }
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for HostControlPreparationReceivingV5<'_> {
    fn drop(&mut self) {
        if self.completed { return; }
        // An unpolled/cancelled/failed entered interval never becomes a fresh
        // control budget or healthy read. All native slots stay on the original.
        self.original.armed = true;
        self.original.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
        if let Some(Ok(owner)) = self.original.execution_receiving.as_mut() { owner.close(); }
    }
}

fn inventory_loan_demand_v5() -> Result<ResourceVector> {
    let bytes = std::mem::size_of::<HostControlPreparationReceivingV5<'_>>()
        .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(HostError::ResourceExhausted)?;
    Ok(ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes))
}
