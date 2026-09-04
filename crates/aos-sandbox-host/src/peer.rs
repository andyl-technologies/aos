//! Pidfd-pinned node-controller service identity verification.
//!
//! Unix credentials identify a local account, but do not prove which service
//! is speaking. The host broker therefore pins the peer process and compares
//! its kernel-reported cgroup ID with the pre-opened, fixed controller service
//! cgroup before reading a request.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::PeerCredentials;

use crate::{HostError, Result};

const NODE_CONTROLLER_CGROUP: &str = "aos-control.slice/aos-sandboxd.service";

/// Retains proof that one accepted peer belongs to `aos-sandboxd.service`.
#[derive(Debug)]
pub struct VerifiedControllerPeer {
    credentials: PeerCredentials,
    _pidfd: PidFd,
}

impl VerifiedControllerPeer {
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
    /// The returned proof retains the pidfd until request processing ends, so
    /// PID reuse cannot substitute another process after verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the kernel omitted a PID or cgroup identity, the
    /// PID cannot be pinned, the peer is not a process leader in the exact
    /// controller service cgroup, or the process exits during verification.
    pub fn verify(&self, credentials: PeerCredentials) -> Result<VerifiedControllerPeer> {
        self.verify_in_cgroup(credentials, Path::new(NODE_CONTROLLER_CGROUP))
    }

    fn verify_in_cgroup(
        &self,
        credentials: PeerCredentials,
        expected_relative_cgroup: &Path,
    ) -> Result<VerifiedControllerPeer> {
        let pid = credentials
            .pid
            .and_then(NonZeroU32::new)
            .ok_or_else(|| HostError::Protocol(peer_mismatch()))?;
        let expected = self
            .cgroup_root
            .resolve(expected_relative_cgroup, ResolveOptions::directory())
            .map_err(|_| HostError::Protocol(peer_mismatch()))?;
        let pidfd = PidFd::open(pid).map_err(|_| HostError::Protocol(peer_mismatch()))?;
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
            credentials,
            _pidfd: pidfd,
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
    fn missing_peer_pid_fails_before_cgroup_lookup() {
        let directory = tempfile::tempdir().unwrap();
        let root: OwnedFd = File::open(directory.path()).unwrap().into();
        let verifier = ControllerPeerVerifier::new(BeneathRoot::from_owned(root).unwrap());
        let error = verifier
            .verify(PeerCredentials {
                uid: 0,
                gid: 0,
                pid: None,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            HostError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch
            )
        ));
    }
}
