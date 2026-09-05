//! Pidfd-pinned node-controller service identity verification.
//!
//! Unix credentials identify a local account, but do not prove which service
//! is speaking. The host broker therefore pins the peer process and compares
//! its kernel-reported cgroup ID with the pre-opened, fixed controller service
//! cgroup before reading a request. This verifies the connection establisher;
//! the legacy broker channel can be delegated and does not identify each writer.

use std::path::Path;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::PeerCredentials;

use crate::{HostError, Result};

const NODE_CONTROLLER_CGROUP: &str = "aos-control.slice/aos-sandboxd.service";
const ROOT_MOUNT_CGROUP: &str = "aos-control.slice/aos-sandbox-mountd.service";

/// Retains a root-account proof for the fixed Mount broker service only.
#[derive(Debug)]
pub struct VerifiedMountBrokerPeer<'a> {
    credentials: PeerCredentials,
    _identity: &'a ConnectionPeerIdentity,
    _cgroup: RetainedCgroupAnchor,
}

impl VerifiedMountBrokerPeer<'_> {
    /// Returns kernel credentials bound to this live RootMount proof.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }
}

/// Retains proof that one accepted peer belongs to `aos-sandboxd.service`.
///
/// The proof cannot outlive its pinned socket identity.
/// It retains the observed cgroup too, but does not stop later migration or exit.
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
    _cgroup: RetainedCgroupAnchor,
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
    cgroup_root: CgroupV2Root,
}

impl ControllerPeerVerifier {
    /// Constructs a verifier around a pre-opened cgroup-v2 mount root.
    #[must_use]
    pub const fn new(cgroup_root: CgroupV2Root) -> Self {
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

    /// Verifies a root peer in the exact fixed Mount broker service cgroup.
    ///
    /// This distinct proof never authorizes controller methods. Like controller
    /// verification, it authenticates the connection establisher, not individual
    /// packet writers on a subsequently delegated connection.
    ///
    /// # Errors
    ///
    /// Rejects non-root credentials, a missing or substituted service cgroup,
    /// non-leader peers, and failed live pidfd membership verification.
    pub fn verify_mount_broker<'a>(
        &self,
        identity: &'a ConnectionPeerIdentity,
    ) -> Result<VerifiedMountBrokerPeer<'a>> {
        if identity.credentials().uid() != 0 || identity.credentials().gid() != 0 {
            return Err(HostError::Protocol(peer_mismatch()));
        }

        let (credentials, cgroup) = self.verify_service(identity, Path::new(ROOT_MOUNT_CGROUP))?;

        Ok(VerifiedMountBrokerPeer {
            credentials,
            _identity: identity,
            _cgroup: cgroup,
        })
    }

    fn verify_in_cgroup<'a>(
        &self,
        identity: &'a ConnectionPeerIdentity,
        expected_relative_cgroup: &Path,
    ) -> Result<VerifiedControllerPeer<'a>> {
        let (credentials, cgroup) = self.verify_service(identity, expected_relative_cgroup)?;

        Ok(VerifiedControllerPeer {
            credentials,
            _identity: identity,
            _cgroup: cgroup,
        })
    }

    fn verify_service(
        &self,
        identity: &ConnectionPeerIdentity,
        expected_relative_cgroup: &Path,
    ) -> Result<(PeerCredentials, RetainedCgroupAnchor)> {
        let observed = identity.credentials();
        let pid = observed.pid();
        let expected = self
            .cgroup_root
            .resolve(expected_relative_cgroup)
            .map_err(|_| HostError::Protocol(peer_mismatch()))?;
        let info = expected
            .verify_exact_membership(identity.pidfd())
            .map_err(|_| HostError::Protocol(peer_mismatch()))?;
        if info.pid() != pid.get() || info.thread_group_id() != pid.get() {
            return Err(HostError::Protocol(peer_mismatch()));
        }

        Ok((
            PeerCredentials {
                uid: observed.uid(),
                gid: observed.gid(),
                pid: Some(pid.get()),
            },
            expected,
        ))
    }
}

fn peer_mismatch() -> aos_sandbox_protocol::ProtocolValidationError {
    aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch
}

#[cfg(all(test, feature = "kernel-tests"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::os::fd::OwnedFd;

    use super::*;

    #[test]
    fn registered_root_mount_path_accepts_only_the_distinct_peer_profile() {
        // The VM harness places only this fixture in the exact RootMount
        // service cgroup. No test mutates the host's cgroup hierarchy.
        let root: OwnedFd = File::open("/sys/fs/cgroup").unwrap().into();
        let verifier = ControllerPeerVerifier::new(CgroupV2Root::from_owned(root).unwrap());
        let (socket, _other) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let identity =
            ConnectionPeerIdentity::from_socket(std::os::fd::AsFd::as_fd(&socket)).unwrap();

        let mount_peer = verifier.verify_mount_broker(&identity).unwrap();

        assert_eq!(mount_peer.credentials().uid, 0);
        assert_eq!(mount_peer.credentials().gid, 0);
        assert!(verifier.verify(&identity).is_err());
    }

    #[test]
    fn unregistered_controller_path_rejects_a_live_socket_peer() {
        let directory = tempfile::tempdir().unwrap();
        let root: OwnedFd = File::open("/sys/fs/cgroup").unwrap().into();
        let verifier = ControllerPeerVerifier::new(CgroupV2Root::from_owned(root).unwrap());
        let (socket, _other) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let identity =
            ConnectionPeerIdentity::from_socket(std::os::fd::AsFd::as_fd(&socket)).unwrap();
        let missing = Path::new(directory.path().file_name().unwrap());
        let error = verifier.verify_in_cgroup(&identity, missing).unwrap_err();
        assert!(matches!(
            error,
            HostError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch
            )
        ));
    }
}
