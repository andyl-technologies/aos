//! Launch materialization and bounded host-liveness waits for the install gate.

use std::path::Path;
use std::thread;
use std::time::Instant;

use crucible::{
    NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};

use super::*;

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds QEMU liveness only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_exact_boundary(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    config: &LivePluginInstallGateConfig,
) -> Result<(), LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        let current = QemuShmemHotPathChannel::current_icount(hot_path)
            .map_err(|source| channel_error("poll completed icount", source))?
            .retired;
        if current >= config.horizon_icount {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginInstallGateError::ChildWait { source })?
        {
            return Err(LivePluginInstallGateError::ChildExitBeforeBoundary {
                horizon_icount: config.horizon_icount,
                status: status.to_string(),
            });
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LivePluginInstallGateError::CompletionTimeout {
                horizon_icount: config.horizon_icount,
                last_icount: current,
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds digest-worker liveness only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_execution_fingerprint(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    config: &LivePluginInstallGateConfig,
) -> Result<ExecutionFingerprint, LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        match QemuShmemHotPathChannel::execution_fingerprint(hot_path) {
            Ok(fingerprint) => return Ok(fingerprint),
            Err(source) if source.is_retryable() => {
                if let Some(status) = child
                    .try_wait_natural_exit()
                    .map_err(|source| LivePluginInstallGateError::ChildWait { source })?
                {
                    return Err(LivePluginInstallGateError::ChildExitBeforeFingerprint {
                        icount: config.horizon_icount,
                        status: status.to_string(),
                    });
                }
                if started.elapsed() >= config.completion_timeout {
                    return Err(LivePluginInstallGateError::FingerprintTimeout {
                        icount: config.horizon_icount,
                        timeout: config.completion_timeout,
                        last_error: source.to_string(),
                    });
                }
            }
            Err(source) => {
                return Err(channel_error("read execution fingerprint", source));
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds plugin teardown only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_plugin_teardown(
    hot_path: &QemuMappedQuantumShmemHotPath,
    config: &LivePluginInstallGateConfig,
) -> Result<(), LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        if hot_path
            .plugin_teardown_done()
            .map_err(|source| LivePluginInstallGateError::MappedHotPath { source })?
        {
            return Ok(());
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LivePluginInstallGateError::PluginQuitTimeout {
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- install-gate host timeout bounds child reap only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_natural_child_exit(
    child: &mut crate::QemuNodeChild,
    config: &LivePluginInstallGateConfig,
) -> Result<std::process::ExitStatus, LivePluginInstallGateError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginInstallGateError::ChildWait { source })?
        {
            return Ok(status);
        }
        if started.elapsed() >= config.completion_timeout {
            return Err(LivePluginInstallGateError::ChildExitTimeout {
                timeout: config.completion_timeout,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

pub(super) fn vm_launch_config(config: &LivePluginInstallGateConfig) -> QemuVmLaunchConfig {
    let vm = QemuVmLaunchConfig::new(
        GATE_NODE,
        launch_artifact("kernel", &config.kernel),
        launch_artifact("root-image", &config.root_image),
    )
    .with_root_image_format(config.root_image_format);
    match &config.initrd {
        Some(initrd) => vm.with_initrd(launch_artifact("initrd", initrd)),
        None => vm,
    }
}

fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path_text(path);
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

pub(super) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(super) fn channel_error(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> LivePluginInstallGateError {
    LivePluginInstallGateError::Channel { operation, source }
}

/// Send authorizer for the single-node install run.
///
/// The install gate has one VM and one router slot and never routes a real
/// cross-node frame, so authorization is unconditional.
pub(super) struct GateSendAuthorizer;

impl SchedulerSendAuthorizer for GateSendAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}
