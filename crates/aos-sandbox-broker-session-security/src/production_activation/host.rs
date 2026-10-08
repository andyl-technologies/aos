//! Owns fixed Host listener admission and protected Storage peer bookends.
//!
//! Role readiness is only a descriptor observation, not verified authority.
//! The application chooses its next ready role and retains authenticated
//! sessions; listener sockets, handshake custody, and peer pidfds stay private.

use std::fs::File;
use std::path::Path;

use aos_sandbox_host::peer::ControllerPeerVerifier;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;

use super::*;

const STORAGE_SERVICE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";

/// Selects one of the three fixed Host listener audiences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionHostRoleV1 {
    /// Selects the Controller-to-Host listener.
    Controller,
    /// Selects the RootMount-to-Host listener.
    RootMount,
    /// Selects the Storage-to-Host listener.
    Storage,
}

impl ProductionHostRoleV1 {
    const fn index(self) -> usize {
        match self {
            Self::Controller => 0,
            Self::RootMount => 1,
            Self::Storage => 2,
        }
    }
}

/// Reports readiness of fixed Host roles without attesting peer authority.
pub struct ProductionHostReadinessV1([bool; 3]);

impl ProductionHostReadinessV1 {
    /// Reports whether the selected role had an input, hangup, or error event.
    #[must_use]
    pub fn contains(&self, role: ProductionHostRoleV1) -> bool {
        self.0[role.index()]
    }
}

/// Retains the exact three-listener Host activation profile.
#[must_use = "retain the fixed listeners while serving Host sessions"]
pub struct ProductionHostActivationV1(ProductionBrokerSessionActivationV1);

impl ProductionBrokerSessionActivationV1 {
    /// Retains all three ordered Host listeners behind fixed admission ports.
    ///
    /// # Errors
    ///
    /// Rejects an activation profile other than the fixed three-listener Host profile.
    pub fn into_host_activation(
        self,
    ) -> Result<ProductionHostActivationV1, ProductionBrokerSessionActivationErrorV1> {
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
        Ok(ProductionHostActivationV1(self))
    }
}

impl ProductionHostActivationV1 {
    /// Polls retained sessions or their corresponding fixed listeners once.
    ///
    /// Session references are borrowed only for polling. Descriptor readiness
    /// neither verifies a peer nor permits an effect; authenticated receive and
    /// completion remain the independent sealed request owners' responsibility.
    /// An interrupted poll returns `None` so the application can retry.
    ///
    /// # Errors
    ///
    /// Returns an error on invalid listener/session custody, deadline expiry,
    /// or a failed kernel poll. No descriptor or accepted socket escapes.
    pub fn poll_readiness(
        &self,
        sessions: &[Option<DormantAuthenticatedBrokerSessionV1>; 3],
        deadline: u64,
    ) -> Result<Option<ProductionHostReadinessV1>, ProductionBrokerSessionActivationErrorV1> {
        let mut descriptors = [
            self.poll_descriptor(sessions, ProductionHostRoleV1::Controller)?,
            self.poll_descriptor(sessions, ProductionHostRoleV1::RootMount)?,
            self.poll_descriptor(sessions, ProductionHostRoleV1::Storage)?,
        ];
        poll_host_readiness(&mut descriptors, deadline)
    }

    /// Accepts at most one peer from the selected fixed Host listener.
    ///
    /// The Storage peer is checked before the handshake. Every admitted socket
    /// completes the exact selected audience's protected handshake before its
    /// authenticated session is returned. Transient acceptance returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if listener currentness, peer identity, protected custody,
    /// or the bounded authenticated handshake fails.
    pub fn try_accept(
        &mut self,
        role: ProductionHostRoleV1,
        deadline: u64,
    ) -> Result<Option<DormantAuthenticatedBrokerSessionV1>, ProductionBrokerSessionActivationErrorV1>
    {
        let fixed = &mut self.0.listeners[role.index()];
        fixed.listener.validate_current()?;
        let socket = match fixed.listener.accept() {
            Ok(socket) => socket,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if role == ProductionHostRoleV1::Storage {
            verify_storage_connection_peer(socket.peer())?;
        }
        let custody = ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(fixed.endpoint)
            .map_err(DormantBrokerSessionHandshakeErrorV1::Protected)?;
        let session = custody.complete_production_broker_handshake(socket, deadline)?;
        Ok(Some(session))
    }

    /// Rejects a Storage Host session whose exact protected peer is no longer current.
    ///
    /// This negative-only bookend checks the retained peer pidfd, fixed service
    /// cgroup, thread-group identity, and all root credential identities. It
    /// returns no grant, verification token, or raw peer descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when protected peer custody or exact current membership
    /// and credentials cannot be established.
    pub fn recheck_storage_peer(
        &self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
        verify_storage_session_peer(session)
    }

    fn poll_descriptor<'a>(
        &'a self,
        sessions: &'a [Option<DormantAuthenticatedBrokerSessionV1>; 3],
        role: ProductionHostRoleV1,
    ) -> Result<PollFd<'a>, ProductionBrokerSessionActivationErrorV1> {
        let fd = match &sessions[role.index()] {
            Some(session) => session.as_fd()?,
            None => {
                let listener = &self.0.listeners[role.index()].listener;
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

pub(crate) fn verify_storage_session_peer(
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

fn poll_host_readiness(
    descriptors: &mut [PollFd<'_>; 3],
    deadline: u64,
) -> Result<Option<ProductionHostReadinessV1>, ProductionBrokerSessionActivationErrorV1> {
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
    Ok(Some(ProductionHostReadinessV1(ready)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn poll_observes_ready_peers_without_waiting_on_idle_peers() {
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
            poll_host_readiness(&mut descriptors, deadline)
                .unwrap()
                .map(|ready| ready.0),
            Some([false, true, false])
        );

        controller_peer.write_all(&[1]).unwrap();
        assert_eq!(
            poll_host_readiness(&mut descriptors, deadline)
                .unwrap()
                .map(|ready| ready.0),
            Some([true, true, false])
        );

        storage_peer.write_all(&[1]).unwrap();
        assert_eq!(
            poll_host_readiness(&mut descriptors, deadline)
                .unwrap()
                .map(|ready| ready.0),
            Some([true, true, true])
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
            poll_host_readiness(&mut descriptors, 0),
            Err(ProductionBrokerSessionActivationErrorV1::Deadline)
        ));
    }
}
