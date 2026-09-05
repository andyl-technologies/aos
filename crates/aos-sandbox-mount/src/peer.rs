//! Pidfd-pinned node-controller service identity verification.
//!
//! The legacy broker authorizes the connection establisher and its delegated
//! channel, not each later writer. Kernel socket pidfds prevent numeric PID
//! reuse from substituting a different establisher during verification.

use std::path::Path;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::{PeerCredentials, ProtocolValidationError};

use crate::{MountError, Result};

const NODE_CONTROLLER_CGROUP: &str = "aos-control.slice/aos-sandboxd.service";

/// Retains proof that one accepted peer belongs to `aos-sandboxd.service`.
///
/// The proof cannot outlive its pinned socket identity.
/// It retains the observed cgroup too, but does not stop later migration or exit.
///
/// ```compile_fail
/// use aos_sandbox_mount::peer::{ControllerPeerVerifier, VerifiedControllerPeer};
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
    /// Returns kernel socket credentials bound to the retained pidfd proof.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }
}

/// Verifies peers against the exact controller cgroup under cgroup v2.
#[derive(Debug)]
pub struct ControllerPeerVerifier {
    cgroup_root: CgroupV2Root,
}

impl ControllerPeerVerifier {
    /// Constructs a verifier around a pre-opened cgroup-v2 root.
    #[must_use]
    pub const fn new(cgroup_root: CgroupV2Root) -> Self {
        Self { cgroup_root }
    }

    /// Pins and verifies one peer process before request bytes are read.
    ///
    /// Borrows the socket's kernel-supplied peer pidfd instead of reopening a
    /// numeric PID. The returned proof cannot outlive that pinned identity.
    ///
    /// ```compile_fail
    /// use aos_sandbox_mount::peer::ControllerPeerVerifier;
    /// use aos_sandbox_protocol::PeerCredentials;
    /// fn fabricated(verifier: &ControllerPeerVerifier, claims: PeerCredentials) {
    ///     let _ = verifier.verify(claims);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a uniform authentication error for missing PID/cgroup data,
    /// identity mismatch, non-leader peers, or process exit during validation.
    pub fn verify<'a>(
        &self,
        identity: &'a ConnectionPeerIdentity,
    ) -> Result<VerifiedControllerPeer<'a>> {
        let mismatch = || MountError::Protocol(ProtocolValidationError::PeerCredentialMismatch);
        let observed = identity.credentials();
        let pid = observed.pid();
        let expected = self
            .cgroup_root
            .resolve(Path::new(NODE_CONTROLLER_CGROUP))
            .map_err(|_| mismatch())?;
        let info = expected
            .verify_exact_membership(identity.pidfd())
            .map_err(|_| mismatch())?;
        if info.pid() != pid.get() || info.thread_group_id() != pid.get() {
            return Err(mismatch());
        }
        Ok(VerifiedControllerPeer {
            credentials: PeerCredentials {
                uid: observed.uid(),
                gid: observed.gid(),
                pid: Some(pid.get()),
            },
            _identity: identity,
            _cgroup: expected,
        })
    }
}
