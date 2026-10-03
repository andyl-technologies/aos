//! Original-ticket dispatch from existing authenticated Host admission proofs.
//!
//! Only these opaque query/reservation owners can reach the crate-private route
//! producer. Selectors, lease, correlation and deadlines come from the same
//! admitted statement; scalar data cannot construct a consume authorization.

use super::{
    HostAttachReadOnlyProofV1, HostAttachReadOnlyRequestV1, HostExecutionGrantRequestV1,
    HostExecutionGrantReservationV1, execution_assignment,
};
use crate::attach_route::{
    HostOpenSshAttachRouteErrorV1 as Error, HostOpenSshAttachRouteEvidenceV1,
    HostOpenSshAttachRouteOwnerV1,
};
use crate::live_agent::HostAgentLiveSessionV1;
use aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1;
use aos_sandbox_core::BrokerVerb;

impl HostAttachReadOnlyProofV1 {
    /// Polls an original ticket through this exact authenticated read-only plan.
    ///
    /// # Errors
    /// Rejects a foreign query, changed runtime/session, expiry or invalid readback.
    pub fn poll_original_attach_v3(
        &self,
        routes: &mut HostOpenSshAttachRouteOwnerV1,
        current: &DormantRuntimeExecutionClaimV1<'_>,
        agent: &mut HostAgentLiveSessionV1,
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, Error> {
        let HostAttachReadOnlyRequestV1::Route(request) = self.request() else {
            return Err(Error::Stale);
        };
        if self.intersection.verb() != BrokerVerb::HostQueryAttachGateRoute
            || !self.matches_claim(current)
        {
            return Err(Error::Stale);
        }
        agent
            .validate_claim(current)
            .map_err(|_| Error::GateMismatch)?;
        let control = routes.original_control_on_held_session_v5(
            current,
            self.verified_lease(),
            self.authority_expires_at(),
            self.effect_deadline_boottime_nanoseconds(),
            request.operation_id(),
            request.execution_id(),
            None,
            *agent.session_binding().digest().as_bytes(),
            agent,
        )?;
        let (observation, _) =
            aos_sandbox_agent::openssh_control_channel::decode_original_control_response_shape_v5(
                &control.original_session_observation_v5,
            )?;
        if observation.transfer_attempted
            || observation.phase
                == aos_sandbox_agent::openssh_control_channel::OriginalControlPhaseV5::Queued
        {
            agent
                .validate_claim(current)
                .map_err(|_| Error::GateMismatch)?;
            if !self.matches_claim(current) {
                return Err(Error::Stale);
            }
            return Ok(control);
        }
        let evidence = routes.original_attach_on_held_session_v3(
            current,
            self.verified_lease(),
            self.authority_expires_at(),
            self.effect_deadline_boottime_nanoseconds(),
            request.operation_id(),
            request.execution_id(),
            None,
            *agent.session_binding().digest().as_bytes(),
            agent,
        )?;
        agent
            .validate_claim(current)
            .map_err(|_| Error::GateMismatch)?;
        if !self.matches_claim(current) {
            return Err(Error::Stale);
        }
        Ok(evidence)
    }
}

impl HostExecutionGrantReservationV1 {
    /// Applies the exact admitted original-monitor control through held owners.
    ///
    /// # Errors
    /// Rejects foreign request/assignment, expired or substituted original ticket,
    /// replay, lost live custody or ambiguous Guest effects/acknowledgements.
    pub fn apply_original_control_v5(
        &self,
        routes: &mut HostOpenSshAttachRouteOwnerV1,
        current: &DormantRuntimeExecutionClaimV1<'_>,
        agent: &mut HostAgentLiveSessionV1,
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, Error> {
        let HostExecutionGrantRequestV1::AttachGate(request) = self.request() else {
            return Err(Error::Stale);
        };
        let (binding, challenge, control) =
            request.original_session_control_v5().ok_or(Error::Stale)?;
        let ticket = request.original_ticket_binding_v2().ok_or(Error::Stale)?;
        if self.intersection.verb() != BrokerVerb::HostInstallAttachGate
            || self.intersection.request_id() != &self.request_id
            || self.effect.request_id() != &self.request_id
            || execution_assignment(current).map_err(|_| Error::Stale)? != self.assignment
            || current.currentness().runtime().handle() != self.runtime_handle
        {
            return Err(Error::Stale);
        }
        agent
            .validate_claim(current)
            .map_err(|_| Error::GateMismatch)?;
        let evidence = routes.original_control_on_held_session_v5(
            current,
            self.verified_lease(),
            self.authority_expires_at(),
            self.effect_deadline_boottime_nanoseconds(),
            request.operation_id(),
            request.execution_id(),
            Some((ticket, binding, challenge, control)),
            *agent.session_binding().digest().as_bytes(),
            agent,
        )?;
        current.revalidate()?;
        agent
            .validate_claim(current)
            .map_err(|_| Error::GateMismatch)?;
        Ok(evidence)
    }

    /// Consumes this durably admitted exact original-ticket ATTACH request.
    ///
    /// The caller retains its runtime claim; this method never drops it to
    /// reconstruct currentness or accepts externally chosen grants/deadlines.
    ///
    /// # Errors
    /// Rejects another verb/request, changed runtime/session, missing original
    /// custody, expiry, reused reservation or an ambiguous descriptor transfer.
    pub fn consume_original_attach_v3(
        &self,
        routes: &mut HostOpenSshAttachRouteOwnerV1,
        current: &DormantRuntimeExecutionClaimV1<'_>,
        agent: &mut HostAgentLiveSessionV1,
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, Error> {
        let HostExecutionGrantRequestV1::AttachGate(request) = self.request() else {
            return Err(Error::Stale);
        };
        let (binding, challenge) = request.original_ticket_consume_v3().ok_or(Error::Stale)?;
        let ticket = request.original_ticket_binding_v2().ok_or(Error::Stale)?;
        if self.intersection.verb() != BrokerVerb::HostInstallAttachGate
            || self.intersection.request_id() != &self.request_id
            || self.effect.request_id() != &self.request_id
            || execution_assignment(current).map_err(|_| Error::Stale)? != self.assignment
            || current.currentness().runtime().handle() != self.runtime_handle
        {
            return Err(Error::Stale);
        }
        agent
            .validate_claim(current)
            .map_err(|_| Error::GateMismatch)?;
        let evidence = routes.original_attach_on_held_session_v3(
            current,
            self.verified_lease(),
            self.authority_expires_at(),
            self.effect_deadline_boottime_nanoseconds(),
            request.operation_id(),
            request.execution_id(),
            Some((ticket, binding, challenge)),
            *agent.session_binding().digest().as_bytes(),
            agent,
        )?;
        current.revalidate()?;
        agent
            .validate_claim(current)
            .map_err(|_| Error::GateMismatch)?;
        Ok(evidence)
    }
}
