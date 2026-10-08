//! Schedules retained controller, RootMount, and Storage Host sessions fairly.
//!
//! The application owns three private session slots, guest-launch retention,
//! and the volatile fairness cursor. Session security retains fixed listener
//! custody, authenticated acceptance, and Storage peer currentness checks.
//! Request execution and response completion use existing sealed method ports.

use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionOwnerV1,
};
use aos_sandbox_broker_session_security::{
    DormantAuthenticatedBrokerSessionV1, ProductionBrokerServiceErrorV1,
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    ProductionHostActivationV1, ProductionHostRoleV1,
};
use aos_sandbox_host::live_agent::HostAgentLiveErrorV1;

const STORAGE_ROLE: usize = 2;
const HOST_ROLES: [ProductionHostRoleV1; 3] = [
    ProductionHostRoleV1::Controller,
    ProductionHostRoleV1::RootMount,
    ProductionHostRoleV1::Storage,
];

/// Owns three fixed Host listeners and one retained session per peer role.
pub struct ProductionHostBrokerServiceV1 {
    // Preserve the original activation, session, and guest custody drop order.
    activation: ProductionHostActivationV1,
    sessions: [Option<DormantAuthenticatedBrokerSessionV1>; 3],
    agent: Option<aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
    next_role: usize,
}

/// Reports admission failure or a consumed Host request-cycle failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionHostBrokerServiceErrorV1 {
    /// Activation, readiness polling, or protected session admission failed.
    #[error(transparent)]
    Activation(#[from] ProductionBrokerSessionActivationErrorV1),
    /// A selected request failed and its session custody was consumed.
    #[error(transparent)]
    Request(#[from] ProductionBrokerServiceErrorV1),
    /// The protected runtime generation could not be claimed for a guest launch.
    #[error("guest-agent launch currentness is unavailable: {0}")]
    GuestRuntime(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// The private launch channel did not authenticate its exact guest peer.
    #[error("guest-agent launch session is invalid: {0}")]
    GuestSession(#[from] HostAgentLiveErrorV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedAgentStateV1 {
    Current,
    Stale,
}

fn retained_agent_state(
    validation: Result<(), HostAgentLiveErrorV1>,
) -> Result<RetainedAgentStateV1, ProductionHostBrokerServiceErrorV1> {
    match validation {
        Ok(()) => Ok(RetainedAgentStateV1::Current),
        Err(HostAgentLiveErrorV1::Binding) => Ok(RetainedAgentStateV1::Stale),
        Err(error) => Err(error.into()),
    }
}

impl ProductionHostBrokerServiceV1 {
    /// Retains the complete fixed Host activation profile and empty role slots.
    ///
    /// # Errors
    ///
    /// Rejects any activation profile other than the three ordered Host listeners.
    pub fn new(
        activation: ProductionBrokerSessionActivationV1,
    ) -> Result<Self, ProductionBrokerSessionActivationErrorV1> {
        Ok(Self {
            activation: activation.into_host_activation()?,
            sessions: [None, None, None],
            agent: None,
            next_role: 0,
        })
    }

    fn retain_authenticated_agent_launch(
        &mut self,
        session: aos_sandbox_host::live_agent::HostAgentLiveSessionV1,
    ) -> Result<(), ProductionHostBrokerServiceErrorV1> {
        // The sealed Host callsite releases this channel only after the
        // Guardian-first transaction durably reaches Complete. There is no
        // standalone pending-session installer that can skip that transition.
        let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
        let claim = owner.claim()?;
        session.validate_claim(&claim)?;
        if let Some(retained) = self.agent.as_ref() {
            if retained_agent_state(retained.validate_claim(&claim))?
                == RetainedAgentStateV1::Current
            {
                return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                    "current guest agent session already retained",
                )
                .into());
            }
        }
        self.agent = Some(session);
        Ok(())
    }

    /// Serves at most one bounded request from the next ready Host peer role.
    ///
    /// An idle deadline preserves retained sessions. A request failure consumes
    /// only the selected session; its protected journal is never cleared.
    /// Admission failures remain fatal to the service owner.
    ///
    /// # Errors
    ///
    /// Returns an activation error on timeout, invalid listener or session
    /// custody, or failed handshake. Returns a request error if selected
    /// request admission, execution, commit, or response delivery fails.
    /// Guest runtime-claim and launch-authentication failures are fatal to this owner.
    pub async fn serve_next(
        &mut self,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(), ProductionHostBrokerServiceErrorV1> {
        self.retire_stale_agent_session()?;
        let role = self.wait_for_ready_role(deadline_boottime_nanoseconds)?;
        self.next_role = (role + 1) % self.sessions.len();

        let mut session = match self.sessions[role].take() {
            Some(session) => session,
            None => match self
                .activation
                .try_accept(HOST_ROLES[role], deadline_boottime_nanoseconds)?
            {
                Some(session) => session,
                None => return Ok(()),
            },
        };

        if role == STORAGE_ROLE {
            self.activation.recheck_storage_peer(&mut session)?;
        }

        let served = serve_host_request(
            session,
            host,
            publisher,
            self.agent.as_mut(),
            deadline_boottime_nanoseconds,
        )
        .await;
        if let Some(agent) = host.take_authenticated_agent_launch() {
            self.retain_authenticated_agent_launch(agent)?;
        }
        let mut retained = served?;
        if role == STORAGE_ROLE {
            self.activation.recheck_storage_peer(&mut retained)?;
        }
        self.sessions[role] = Some(retained);
        Ok(())
    }

    fn retire_stale_agent_session(&mut self) -> Result<(), ProductionHostBrokerServiceErrorV1> {
        let Some(agent) = self.agent.as_ref() else {
            return Ok(());
        };
        let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
        let claim = owner.claim()?;
        match retained_agent_state(agent.validate_claim(&claim))? {
            RetainedAgentStateV1::Current => Ok(()),
            RetainedAgentStateV1::Stale => {
                // A private socket cannot cross an assignment or boot change.
                // Recovery must launch and authenticate a new guest channel.
                self.agent = None;
                Ok(())
            }
        }
    }

    fn wait_for_ready_role(
        &self,
        deadline: u64,
    ) -> Result<usize, ProductionBrokerSessionActivationErrorV1> {
        loop {
            let Some(readiness) = self.activation.poll_readiness(&self.sessions, deadline)? else {
                continue;
            };
            let ready = HOST_ROLES.map(|role| readiness.contains(role));
            if let Some(role) = select_ready_role(ready, self.next_role) {
                return Ok(role);
            }
        }
    }
}

/// Composes existing sealed receive and completion ports without opening authority.
async fn serve_host_request(
    session: DormantAuthenticatedBrokerSessionV1,
    host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
    publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
    deadline: u64,
) -> Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerServiceErrorV1> {
    let (session, event) = session.receive_production_host_request(deadline)?;
    session
        .complete_host_request_event(event, host, publisher, agent, deadline)
        .await
        .map_err(Into::into)
}

fn select_ready_role(ready: [bool; 3], next_role: usize) -> Option<usize> {
    (0..ready.len())
        .map(|offset| (next_role + offset) % ready.len())
        .find(|role| ready[*role])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_identity_mismatch_allows_guest_channel_replacement() {
        assert_eq!(
            retained_agent_state(Ok(())).unwrap(),
            RetainedAgentStateV1::Current
        );
        assert_eq!(
            retained_agent_state(Err(HostAgentLiveErrorV1::Binding)).unwrap(),
            RetainedAgentStateV1::Stale
        );
        assert!(matches!(
            retained_agent_state(Err(HostAgentLiveErrorV1::Unauthenticated)),
            Err(ProductionHostBrokerServiceErrorV1::GuestSession(
                HostAgentLiveErrorV1::Unauthenticated
            ))
        ));
    }

    #[test]
    fn continuously_ready_roles_alternate() {
        let mut next_role = 0;
        for cycle in 0..100 {
            let role = select_ready_role([true, true, true], next_role).unwrap();
            assert_eq!(role, cycle % 3);
            next_role = (role + 1) % 3;
        }
    }

    #[test]
    fn scheduler_restart_does_not_inherit_a_previous_role_cursor() {
        let mut prior_next_role = 0;
        for _ in 0..8 {
            let selected = select_ready_role([true, true, true], prior_next_role).unwrap();
            prior_next_role = (selected + 1) % 3;
        }
        assert_ne!(prior_next_role, 0);

        // Session sequence and role custody are reopened from their journals;
        // the volatile fairness cursor starts at the first fixed listener.
        let restarted_next_role = 0;
        assert_eq!(
            select_ready_role([true, true, true], restarted_next_role),
            Some(0)
        );
        assert_eq!(
            select_ready_role([false, false, true], restarted_next_role),
            Some(2)
        );
    }

    #[test]
    fn idle_role_does_not_block_the_other_role() {
        for next_role in 0..3 {
            assert_eq!(select_ready_role([true, false, false], next_role), Some(0));
            assert_eq!(select_ready_role([false, true, false], next_role), Some(1));
            assert_eq!(select_ready_role([false, false, true], next_role), Some(2));
            assert_eq!(select_ready_role([false, false, false], next_role), None);
        }
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification;
