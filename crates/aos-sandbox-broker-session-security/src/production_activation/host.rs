//! Schedules retained controller, RootMount, and Storage Host sessions fairly.
//!
//! Each role owns at most one authenticated session. Idle sessions retain their
//! sequence custody without blocking another listener. Ready roles rotate
//! after each bounded handshake/request cycle; effects still execute serially.

use std::fs::File;
use std::path::Path;

use aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerV1;
use aos_sandbox_host::peer::ControllerPeerVerifier;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;

use super::*;
use crate::ProductionBrokerServiceErrorV1;

const STORAGE_ROLE: usize = 2;
const STORAGE_SERVICE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";

/// Owns three fixed Host listeners and one retained session per peer role.
pub struct ProductionHostBrokerServiceV1 {
    activation: ProductionBrokerSessionActivationV1,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedAgentStateV1 {
    Current,
    Stale,
}

fn retained_agent_state(
    validation: Result<(), HostAgentLiveErrorV1>,
) -> Result<RetainedAgentStateV1, ProductionBrokerSessionActivationErrorV1> {
    match validation {
        Ok(()) => Ok(RetainedAgentStateV1::Current),
        Err(HostAgentLiveErrorV1::Binding) => Ok(RetainedAgentStateV1::Stale),
        Err(error) => Err(error.into()),
    }
}

impl ProductionBrokerSessionActivationV1 {
    /// Retains all Host role listeners in a bounded round-robin service owner.
    ///
    /// # Errors
    ///
    /// Rejects an activation profile other than the fixed three-listener Host profile.
    pub fn into_host_service(
        self,
    ) -> Result<ProductionHostBrokerServiceV1, ProductionBrokerSessionActivationErrorV1> {
        if self.listeners.len() != 3
            || !matches!(
                self.listeners[0].endpoint,
                ProtectedBrokerSessionFixedEndpointV1::HostBroker
            )
            || !matches!(
                self.listeners[1].endpoint,
                ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker
            )
            || !matches!(
                self.listeners[2].endpoint,
                ProtectedBrokerSessionFixedEndpointV1::StorageHostBroker
            )
        {
            return Err(ProductionBrokerSessionActivationErrorV1::Activation(
                "Host scheduling requires all three fixed role listeners",
            ));
        }
        Ok(ProductionHostBrokerServiceV1 {
            activation: self,
            sessions: [None, None, None],
            agent: None,
            next_role: 0,
        })
    }
}

impl ProductionHostBrokerServiceV1 {
    fn retain_authenticated_agent_launch(
        &mut self,
        session: aos_sandbox_host::live_agent::HostAgentLiveSessionV1,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
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
                ));
            }
        }
        self.agent = Some(session);
        Ok(())
    }

    /// Serves at most one bounded request from the next ready Host peer role.
    ///
    /// An idle deadline preserves both sessions. A request failure consumes
    /// only the selected session; its protected journal is never cleared.
    /// Admission failures remain fatal to the service owner.
    ///
    /// # Errors
    ///
    /// Returns an activation error on timeout, invalid listener or session
    /// custody, or failed handshake. Returns a request error if selected
    /// request admission, execution, commit, or response delivery fails.
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
            None => {
                let fixed = &mut self.activation.listeners[role];
                fixed
                    .listener
                    .validate_current()
                    .map_err(ProductionBrokerSessionActivationErrorV1::from)?;
                let socket = match fixed.listener.accept() {
                    Ok(socket) => socket,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => return Ok(()),
                    Err(error) => {
                        return Err(ProductionBrokerSessionActivationErrorV1::from(error).into());
                    }
                };
                if role == STORAGE_ROLE {
                    verify_storage_connection_peer(socket.peer())?;
                }
                let custody =
                    ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(fixed.endpoint)
                        .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)
                        .map_err(ProductionBrokerSessionActivationErrorV1::from)?;
                custody
                    .complete_production_broker_handshake(socket, deadline_boottime_nanoseconds)
                    .map_err(ProductionBrokerSessionActivationErrorV1::from)?
            }
        };

        if role == STORAGE_ROLE {
            verify_storage_session_peer(&mut session)?;
        }

        let served = session
            .serve_production_host_request(
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
            verify_storage_session_peer(&mut retained)?;
        }
        self.sessions[role] = Some(retained);
        Ok(())
    }

    fn retire_stale_agent_session(
        &mut self,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
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
            let mut descriptors = [
                self.poll_descriptor(0)?,
                self.poll_descriptor(1)?,
                self.poll_descriptor(2)?,
            ];
            if let Some(role) = poll_ready_role(&mut descriptors, self.next_role, deadline)? {
                return Ok(role);
            }
        }
    }

    fn poll_descriptor(
        &self,
        role: usize,
    ) -> Result<PollFd<'_>, ProductionBrokerSessionActivationErrorV1> {
        let fd = match &self.sessions[role] {
            Some(session) => session.as_fd()?,
            None => {
                let listener = &self.activation.listeners[role].listener;
                listener.validate_current()?;
                listener.as_fd()
            }
        };
        Ok(PollFd::from_borrowed_fd(fd, PollFlags::IN))
    }
}

fn storage_cgroup_root() -> Result<CgroupV2Root, ProductionBrokerSessionActivationErrorV1> {
    let root = File::open("/sys/fs/cgroup").map_err(|_| {
        ProductionBrokerSessionActivationErrorV1::Activation("cgroup root unavailable")
    })?;
    CgroupV2Root::from_owned(root.into()).map_err(|_| {
        ProductionBrokerSessionActivationErrorV1::Activation("cgroup-v2 root unavailable")
    })
}

fn verify_storage_connection_peer(
    peer: &ConnectionPeerIdentity,
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    ControllerPeerVerifier::new(storage_cgroup_root()?)
        .verify_storage_broker(peer)
        .map_err(|_| {
            ProductionBrokerSessionActivationErrorV1::Activation("Storage Host peer is not current")
        })?;
    Ok(())
}

fn verify_storage_session_peer(
    session: &mut DormantAuthenticatedBrokerSessionV1,
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    let descriptor = session
        .retain_authenticated_peer_pidfd()
        .map_err(ProductionBrokerSessionActivationErrorV1::Handshake)?;
    let peer = PidFd::from_owned(descriptor).map_err(|_| {
        ProductionBrokerSessionActivationErrorV1::Activation("Storage Host pidfd is invalid")
    })?;
    let cgroup = storage_cgroup_root()?
        .resolve(Path::new(STORAGE_SERVICE_CGROUP))
        .map_err(|_| {
            ProductionBrokerSessionActivationErrorV1::Activation(
                "Storage service cgroup is unavailable",
            )
        })?;
    let info = cgroup.verify_exact_membership(&peer).map_err(|_| {
        ProductionBrokerSessionActivationErrorV1::Activation(
            "Storage Host peer left its service cgroup",
        )
    })?;
    let credentials =
        info.credentials()
            .ok_or(ProductionBrokerSessionActivationErrorV1::Activation(
                "Storage Host peer credentials are unavailable",
            ))?;
    if info.pid() != info.thread_group_id()
        || credentials.real_user_id() != 0
        || credentials.real_group_id() != 0
        || credentials.effective_user_id() != 0
        || credentials.effective_group_id() != 0
        || credentials.saved_user_id() != 0
        || credentials.saved_group_id() != 0
        || credentials.filesystem_user_id() != 0
        || credentials.filesystem_group_id() != 0
    {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "Storage Host peer identity changed",
        ));
    }
    Ok(())
}

fn poll_ready_role(
    descriptors: &mut [PollFd<'_>; 3],
    next_role: usize,
    deadline: u64,
) -> Result<Option<usize>, ProductionBrokerSessionActivationErrorV1> {
    let remaining = remaining_duration(deadline)?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
    };
    match poll(descriptors, Some(&timeout)) {
        Ok(0) => return Err(ProductionBrokerSessionActivationErrorV1::Deadline),
        Err(rustix::io::Errno::INTR) => return Ok(None),
        Err(_) => return Err(ProductionBrokerSessionActivationErrorV1::Kernel),
        Ok(_) => {}
    }
    remaining_duration(deadline)?;
    // HUP/ERR also select a session so its consuming request path can retire
    // it. An idle session must never suppress the other role.
    let ready = std::array::from_fn(|index| !descriptors[index].revents().is_empty());
    Ok(select_ready_role(ready, next_role))
}

fn select_ready_role(ready: [bool; 3], next_role: usize) -> Option<usize> {
    (0..ready.len())
        .map(|offset| (next_role + offset) % ready.len())
        .find(|role| ready[*role])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

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
            Err(ProductionBrokerSessionActivationErrorV1::GuestSession(
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

    #[test]
    fn poll_selects_ready_peer_without_waiting_on_idle_peer() {
        let (controller, mut controller_peer) = UnixStream::pair().unwrap();
        let (root_mount, mut root_mount_peer) = UnixStream::pair().unwrap();
        let (storage, mut storage_peer) = UnixStream::pair().unwrap();
        let mut descriptors = [
            PollFd::new(&controller, PollFlags::IN),
            PollFd::new(&root_mount, PollFlags::IN),
            PollFd::new(&storage, PollFlags::IN),
        ];
        let deadline = crate::production_deadline_after(Duration::from_secs(5)).unwrap();

        root_mount_peer.write_all(&[1]).unwrap();
        assert_eq!(
            poll_ready_role(&mut descriptors, 0, deadline).unwrap(),
            Some(1)
        );

        controller_peer.write_all(&[1]).unwrap();
        assert_eq!(
            poll_ready_role(&mut descriptors, 0, deadline).unwrap(),
            Some(0)
        );
        assert_eq!(
            poll_ready_role(&mut descriptors, 1, deadline).unwrap(),
            Some(1)
        );
        storage_peer.write_all(&[1]).unwrap();
        assert_eq!(
            poll_ready_role(&mut descriptors, 2, deadline).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn expired_deadline_does_not_admit_ready_traffic() {
        let (controller, mut peer) = UnixStream::pair().unwrap();
        let (root_mount, _peer) = UnixStream::pair().unwrap();
        let (storage, _peer) = UnixStream::pair().unwrap();
        let mut descriptors = [
            PollFd::new(&controller, PollFlags::IN),
            PollFd::new(&root_mount, PollFlags::IN),
            PollFd::new(&storage, PollFlags::IN),
        ];
        peer.write_all(&[1]).unwrap();

        assert!(matches!(
            poll_ready_role(&mut descriptors, 0, 0),
            Err(ProductionBrokerSessionActivationErrorV1::Deadline)
        ));
    }
}
