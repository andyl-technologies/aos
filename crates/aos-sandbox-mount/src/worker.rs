//! Closed mount-effect interface implemented by the namespace helper.

use aos_proto::aos::sandbox::local::v1::{MountAction, MountState};
use aos_sandbox_protocol::ValidatedMountRequest;

use crate::Result;

/// Supplies broker-minted handles for one admitted mount effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectHandles {
    /// Handle naming the prepared detached mount, when one exists.
    pub detached: Option<[u8; 32]>,
    /// Handle naming the published mount generation, when one exists.
    pub installed: Option<[u8; 32]>,
}

/// Reports the kernel-verified result of one fixed mount effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerObservation {
    /// Closed protocol state observed after the effect.
    pub state: MountState,
    /// Broker handles whose resources remain live after the effect.
    pub handles: EffectHandles,
}

/// Applies one idempotent, descriptor-only mount transaction.
pub trait MountWorker {
    /// Applies or reconciles the validated action and verifies its result.
    ///
    /// The worker must resolve all resources through its trusted catalog. It
    /// must never interpret a caller path, mount option, descriptor number, or
    /// namespace PID. Repeating the exact request after a crash must return the
    /// same semantic observation.
    ///
    /// # Errors
    ///
    /// Returns an error when catalog resolution, helper execution, the mount
    /// mutation, or post-effect kernel observation fails.
    fn execute(
        &mut self,
        request: &ValidatedMountRequest,
        handles: EffectHandles,
    ) -> Result<WorkerObservation>;
}

pub(crate) fn expected_handles(
    action: MountAction,
    request_digest: [u8; 32],
    _supplied_detached: Option<[u8; 32]>,
) -> EffectHandles {
    match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => EffectHandles {
            detached: Some(derive_handle(b"detached", request_digest)),
            installed: None,
        },
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => EffectHandles {
            detached: None,
            installed: Some(derive_handle(b"installed", request_digest)),
        },
        MountAction::MOUNT_ACTION_DETACH
        | MountAction::MOUNT_ACTION_RELEASE
        | MountAction::MOUNT_ACTION_UNSPECIFIED => EffectHandles {
            detached: None,
            installed: None,
        },
    }
}

fn derive_handle(label: &[u8], request_digest: [u8; 32]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.handle.v1\0");
    digest.update(label);
    digest.update(request_digest);
    digest.finalize().into()
}
