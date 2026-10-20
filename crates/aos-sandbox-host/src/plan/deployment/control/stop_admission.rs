//! Pays one failed-Capture Stop verification before its signed effect exists.
//!
//! This finite read interval uses the consumed control capacity and the actual
//! old Launch/Accept identities. It keeps their readonly window and sticky
//! failures occupied. Only the separately verified Stop may authorize effects.

use super::*;
use super::execution_receiving::Request;
use super::terminal_inventory::{ControlPreparationPurposeV5, HostControlPreparationReceivingV5};

impl HostComponentControlStartupV2 {
    pub(crate) fn begin_capture_stop_admission_v4<'original>(
        &'original mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        parent: &crate::broker::HostCaptureStopAdmissionParentV4<'_>,
        shape: &crate::broker::HostCaptureStopAdmissionShapeV4,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        use aos_proto::aos::sandbox::local::v1::BrokerMethod;
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;

        parent.require_failed_v4()?;
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || request.authorization().is_none() || !self.admitted
        {
            return Err(HostError::Fence("Capture Stop verification requires its actual authenticated receiver"));
        }
        let (native, maximum) = self.recurring_observation_geometry_v4()?;
        let headers = std::mem::size_of::<HostControlPreparationReceivingV5<'_>>()
            .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HostError::ResourceExhausted)?;
        let complete = shape.receiving_demand_v4().checked_add(native)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(
                aos_sandbox_core::ResourceDimension::MemoryBytes, headers)))
            .map_err(|_| HostError::ResourceExhausted)?;
        let request = Request { id: request.request_id(), session: request.session_binding(),
            signed: request.signed_request_digest() };
        let (launch, accept) = parent.bindings_v4();
        let admitted = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| owner.begin_stop_admission_preparation_v4(launch, accept, request, complete));
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("Capture Stop verification exceeds its consumed control capacity"));
        }
        let destinations = self.append_stop_admission_destinations_v4(request, maximum)?;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::AgentLaunchQuarantined)?
            .park_stop_admission_destinations_v4(request, destinations.round_start, destinations.manager_slot)
            .map_err(|_| HostError::Fence("Stop admission lost its prepaid destinations"))?;
        Ok(HostControlPreparationReceivingV5 {
            original: self, purpose: ControlPreparationPurposeV5::StopAdmission,
            destinations, before: false, after: false, completed: false, extension: false, cleanup: None,
        })
    }

    pub(crate) fn capture_stop_admission_failure_v4(
        &self, request: HostExecutionRequestBindingV2, after: bool,
    ) -> Option<&(dyn std::error::Error + '_)> {
        let owner = self.execution_receiving.as_ref()?.as_ref().ok()?;
        if let Some(cause) = owner.stop_admission_financial_failure_v4(request) {
            return Some(cause);
        }
        if owner.stop_admission_allocation_refused_v4(request) {
            return self.attempts.allocation_failure_v4();
        }
        // The broker snapshots the row's returned error before later posts.
        // The original global failure remains owned but is not this selector.
        let destinations = owner.stop_admission_destinations_v4(request)?;
        self.recurring_leaf_failure_v4(destinations.0 + usize::from(after))
    }
}

impl HostControlPreparationReceivingV5<'_> {
    pub(crate) fn extend_capture_stop_admission_v4(
        &mut self,
        request: HostExecutionRequestBindingV2,
        shape: &crate::broker::HostCaptureStopAdmissionShapeV4,
    ) -> Result<()> {
        if !matches!(self.purpose, ControlPreparationPurposeV5::StopAdmission)
            || self.before || self.extension
        {
            return Err(HostError::Fence("Capture Stop admission extension is occupied"));
        }
        self.extension = true;
        let additional = shape.claim_demand_v4()?;
        self.original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostError::AgentLaunchQuarantined)?
            .extend_stop_admission_preparation_v4(request, additional)
            .map_err(|_| HostError::Fence("Capture Stop protected claim exceeds its consumed control capacity"))
    }
}
