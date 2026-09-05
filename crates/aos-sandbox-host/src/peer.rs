//! Pidfd-pinned node-controller service identity verification.
//!
//! Unix credentials identify a local account, but do not prove which service
//! is speaking. The host broker therefore pins the peer process and compares
//! its kernel-reported cgroup ID with the pre-opened, fixed controller service
//! cgroup before reading a request. This verifies the connection establisher;
//! the legacy broker channel can be delegated and does not identify each writer.

use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::PeerCredentials;

use crate::{HostError, Result};

const NODE_CONTROLLER_CGROUP: &str = "aos-control.slice/aos-sandboxd.service";

/// Retains proof that one accepted peer belongs to `aos-sandboxd.service`.
///
/// The proof cannot outlive its pinned socket identity.
///
/// ```compile_fail
/// use aos_sandbox_host::peer::{ControllerPeerVerifier, VerifiedControllerPeer};
/// use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
/// fn escape(verifier: &ControllerPeerVerifier, identity: ConnectionPeerIdentity)
///     -> VerifiedControllerPeer<'static>
/// {
///     verifier.verify(&identity).unwrap()
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedControllerPeer<'a> {
    credentials: PeerCredentials,
    _identity: &'a ConnectionPeerIdentity,
}

impl VerifiedControllerPeer<'_> {
    /// Returns the kernel socket credentials bound to this live proof.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }
}

/// Verifies peers against the exact node-controller cgroup under cgroup v2.
#[derive(Debug)]
pub struct ControllerPeerVerifier {
    cgroup_root: BeneathRoot,
}

impl ControllerPeerVerifier {
    /// Constructs a verifier around a pre-opened cgroup-v2 mount root.
    #[must_use]
    pub const fn new(cgroup_root: BeneathRoot) -> Self {
        Self { cgroup_root }
    }

    /// Pins and verifies the service identity of one accepted socket peer.
    ///
    /// Borrows the kernel-supplied socket peer pidfd throughout the proof's
    /// lifetime. It never reopens a numeric PID, including before verification.
    /// This is connection-establisher authority, not per-record writer identity.
    ///
    /// ```compile_fail
    /// use aos_sandbox_host::peer::ControllerPeerVerifier;
    /// use aos_sandbox_protocol::PeerCredentials;
    /// fn fabricated(verifier: &ControllerPeerVerifier, claims: PeerCredentials) {
    ///     let _ = verifier.verify(claims);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the kernel omitted a PID or cgroup identity, the
    /// PID cannot be pinned, the peer is not a process leader in the exact
    /// controller service cgroup, or the process exits during verification.
    pub fn verify<'a>(
        &self,
        identity: &'a ConnectionPeerIdentity,
    ) -> Result<VerifiedControllerPeer<'a>> {
        self.verify_in_cgroup(identity, Path::new(NODE_CONTROLLER_CGROUP))
    }

    fn verify_in_cgroup<'a>(
        &self,
        identity: &'a ConnectionPeerIdentity,
        expected_relative_cgroup: &Path,
    ) -> Result<VerifiedControllerPeer<'a>> {
        let observed = identity.credentials();
        let pid = observed.pid();
        let expected = self
            .cgroup_root
            .resolve(expected_relative_cgroup, ResolveOptions::directory())
            .map_err(|_| HostError::Protocol(peer_mismatch()))?;
        let pidfd = identity.pidfd();
        let info = pidfd
            .info()
            .map_err(|_| HostError::Protocol(peer_mismatch()))?;
        if info.pid() != pid.get()
            || info.thread_group_id() != pid.get()
            || info.cgroup_id() != Some(expected.identity().inode)
            || !pidfd
                .is_alive()
                .map_err(|_| HostError::Protocol(peer_mismatch()))?
        {
            return Err(HostError::Protocol(peer_mismatch()));
        }
        Ok(VerifiedControllerPeer {
            credentials: PeerCredentials {
                uid: observed.uid(),
                gid: observed.gid(),
                pid: Some(pid.get()),
            },
            _identity: identity,
        })
    }
}

fn peer_mismatch() -> aos_sandbox_protocol::ProtocolValidationError {
    aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::os::fd::OwnedFd;

    use super::*;

    #[test]
    fn unregistered_controller_path_rejects_a_live_socket_peer() {
        let directory = tempfile::tempdir().unwrap();
        let root: OwnedFd = File::open(directory.path()).unwrap().into();
        let verifier = ControllerPeerVerifier::new(BeneathRoot::from_owned(root).unwrap());
        let (socket, _other) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let identity =
            ConnectionPeerIdentity::from_socket(std::os::fd::AsFd::as_fd(&socket)).unwrap();
        let error = verifier.verify(&identity).unwrap_err();
        assert!(matches!(
            error,
            HostError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch
            )
        ));
    }
}
