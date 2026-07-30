//! Backend-route consistency and production execution evidence.

use super::*;

impl BackendSelectionPlan {
    pub(crate) fn has_consistent_route(&self) -> bool {
        self.local_remote_equivalence_contract
            && match self.target {
                BackendExecutionTarget::RemoteDaemon => {
                    self.daemon
                        .as_deref()
                        .is_some_and(|daemon| !daemon.is_empty())
                        && self.resolved_backend.is_none()
                        && self.remote_uses_control_api
                        && !self.local_uses_simulation_backend
                        && self.reason == BackendSelectionReason::RemoteDaemon
                }
                BackendExecutionTarget::Local => {
                    self.daemon.is_none()
                        && self.resolved_backend.is_some()
                        && !self.remote_uses_control_api
                        && self.local_uses_simulation_backend
                        && match (self.requested_backend, &self.resolved_backend, self.reason) {
                            (
                                Backend::Auto,
                                Some(ResolvedLocalBackend::Qemu { qemu, plugin, .. }),
                                BackendSelectionReason::AutoQemuArtifactsSupplied,
                            ) => !qemu.as_os_str().is_empty() && !plugin.as_os_str().is_empty(),
                            #[cfg(any(test, feature = "test-double"))]
                            (
                                Backend::Auto,
                                Some(ResolvedLocalBackend::Double),
                                BackendSelectionReason::AutoFallbackDouble,
                            )
                            | (
                                Backend::Double,
                                Some(ResolvedLocalBackend::Double),
                                BackendSelectionReason::ExplicitDouble,
                            ) => true,
                            (
                                Backend::Qemu,
                                Some(ResolvedLocalBackend::Qemu { qemu, plugin, .. }),
                                BackendSelectionReason::ExplicitQemu,
                            ) => !qemu.as_os_str().is_empty() && !plugin.as_os_str().is_empty(),
                            _ => false,
                        }
                }
            }
    }

    pub(crate) fn expected_execution_evidence(&self) -> Option<BackendExecutionEvidence> {
        match (&self.target, &self.resolved_backend, &self.daemon) {
            #[cfg(any(test, feature = "test-double"))]
            (BackendExecutionTarget::Local, Some(ResolvedLocalBackend::Double), None) => {
                Some(BackendExecutionEvidence::LocalDouble)
            }
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu {
                    qemu_build_id,
                    plugin_abi,
                    ..
                }),
                None,
            ) => Some(BackendExecutionEvidence::LocalProduction {
                build_id: qemu_build_id.clone(),
                plugin_abi: plugin_abi.clone(),
            }),
            (BackendExecutionTarget::RemoteDaemon, None, Some(daemon)) => {
                Some(BackendExecutionEvidence::RemoteDaemon {
                    daemon: daemon.clone(),
                })
            }
            _ => None,
        }
    }
}
