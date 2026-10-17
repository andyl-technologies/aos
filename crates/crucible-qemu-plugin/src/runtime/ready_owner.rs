//! Installed resource custody from the original committed READY lifecycle.
//!
//! Registration seals the native resource manifest; successful transmission
//! and commitment of the original READY acknowledgement establish the retained
//! setup owner. This receipt does not grant a runnable phase, authenticate a
//! closed control boundary, or authorize a restored process.

use crucible_protocol::{
    ControlLifecycleError, ControlLifecycleEvent, ControlLifecycleIoError, ControlLifecycleState,
    ControlLifecycleStream, SETUP_ACK_STATUS_READY,
};

use crate::{PluginReadySetupAck, QemuPluginResourceManifest};

/// Resources observed immediately after the original registration succeeds.
pub(super) struct SealedRuntimeResources {
    manifest: QemuPluginResourceManifest,
}

impl SealedRuntimeResources {
    /// Retains the manifest after its one original native registration.
    pub(super) const fn observe_registered(manifest: QemuPluginResourceManifest) -> Self {
        Self { manifest }
    }

    /// Joins resource registration to the original successfully committed READY.
    ///
    /// # Errors
    ///
    /// Refuses a lifecycle that has not committed the sent acknowledgement.
    pub(super) fn observe_ready_commit<S>(
        self,
        stream: &ControlLifecycleStream<S>,
        _sent: &PluginReadySetupAck,
    ) -> Result<CommittedRuntimeReady, ControlLifecycleIoError> {
        if stream.state() != ControlLifecycleState::SetupAcknowledged {
            return Err(ControlLifecycleError::UnexpectedEvent {
                state: stream.state(),
                event: ControlLifecycleEvent::PluginSetupAck {
                    status: SETUP_ACK_STATUS_READY,
                },
            }
            .into());
        }
        Ok(CommittedRuntimeReady {
            manifest: self.manifest,
        })
    }
}

/// Noncloneable original setup custody retained beside its pinned mapping.
pub(super) struct CommittedRuntimeReady {
    manifest: QemuPluginResourceManifest,
}

impl CommittedRuntimeReady {
    /// Borrows the original physical resource manifest for a native join.
    pub(super) const fn manifest(&self) -> &QemuPluginResourceManifest {
        &self.manifest
    }
}
