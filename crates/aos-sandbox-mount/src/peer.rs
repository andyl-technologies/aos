//! Pidfd-pinned node-controller service identity verification.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::{PeerCredentials, ProtocolValidationError};

use crate::{MountError, Result};

const NODE_CONTROLLER_CGROUP: &str = "aos-control.slice/aos-sandboxd.service";

/// Retains proof that one accepted peer belongs to `aos-sandboxd.service`.
#[derive(Debug)]
pub struct VerifiedControllerPeer {
    credentials: PeerCredentials,
    _pidfd: PidFd,
}

impl VerifiedControllerPeer {
    /// Returns kernel socket credentials bound to the retained pidfd proof.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }
}

/// Verifies peers against the exact controller cgroup under cgroup v2.
#[derive(Debug)]
pub struct ControllerPeerVerifier {
    cgroup_root: BeneathRoot,
}

impl ControllerPeerVerifier {
    /// Constructs a verifier around a pre-opened cgroup-v2 root.
    #[must_use]
    pub const fn new(cgroup_root: BeneathRoot) -> Self {
        Self { cgroup_root }
    }

    /// Pins and verifies one peer process before request bytes are read.
    ///
    /// # Errors
    ///
    /// Returns a uniform authentication error for missing PID/cgroup data,
    /// identity mismatch, non-leader peers, or process exit during validation.
    pub fn verify(&self, credentials: PeerCredentials) -> Result<VerifiedControllerPeer> {
        let mismatch = || MountError::Protocol(ProtocolValidationError::PeerCredentialMismatch);
        let pid = credentials
            .pid
            .and_then(NonZeroU32::new)
            .ok_or_else(mismatch)?;
        let expected = self
            .cgroup_root
            .resolve(
                Path::new(NODE_CONTROLLER_CGROUP),
                ResolveOptions::directory(),
            )
            .map_err(|_| mismatch())?;
        let pidfd = PidFd::open(pid).map_err(|_| mismatch())?;
        let info = pidfd.info().map_err(|_| mismatch())?;
        if info.pid() != pid.get()
            || info.thread_group_id() != pid.get()
            || info.cgroup_id() != Some(expected.identity().inode)
            || !pidfd.is_alive().map_err(|_| mismatch())?
        {
            return Err(mismatch());
        }
        Ok(VerifiedControllerPeer {
            credentials,
            _pidfd: pidfd,
        })
    }
}
