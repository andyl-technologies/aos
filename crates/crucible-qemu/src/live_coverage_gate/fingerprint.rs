//! Exact-boundary fingerprint publication for the loaded-QEMU coverage gate.
//!
//! Coverage equivalence compares the production execution fingerprint only
//! after a tokenized control boundary has caused the plugin to publish its
//! current digest. This module owns that bounded publication/read handshake so
//! the main gate remains focused on launch, event-log, and teardown policy.

use std::time::Instant;

use crucible::ExecutionFingerprint;

use crate::{
    QemuHostIoRuntime, QemuHostPluginSetup, QemuLiveHostIoRuntime, QemuMappedQuantumShmemHotPath,
    QemuNodeChannelError, QemuNodeChild, QemuShmemHotPathChannel,
};

use super::{
    GATE_SLOT, LoadedQemuCoverageGateConfig, LoadedQemuCoverageGateError, channel_error,
    wait_for_poll_interval,
};

/// Publishes and reads the fingerprint for one acknowledged exact boundary.
///
/// # Errors
///
/// Returns an error when the production control-boundary request fails, QEMU
/// exits before publishing the digest, the shared-memory read fails, or the
/// configured host-side timeout expires.
// crucible-lint: allow clippy-disallowed-method -- host timeout bounds diagnostic publication only.
#[allow(clippy::disallowed_methods)]
pub(super) fn publish_and_wait_for_execution_fingerprint(
    setup: &QemuHostPluginSetup,
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut QemuNodeChild,
    config: &LoadedQemuCoverageGateConfig,
    mode: &'static str,
    icount: u64,
) -> Result<ExecutionFingerprint, LoadedQemuCoverageGateError> {
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.wake_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| {
        channel_error(
            mode,
            "construct production fingerprint runtime",
            QemuNodeChannelError::new("map production host runtime", source.to_string()),
        )
    })?;
    runtime
        .publish_current_execution_fingerprint(config.completion_timeout)
        .map_err(|source| {
            channel_error(
                mode,
                "publish execution fingerprint boundary",
                QemuNodeChannelError::new("execution fingerprint boundary", source.to_string()),
            )
        })?;

    let started = Instant::now();
    loop {
        match QemuShmemHotPathChannel::execution_fingerprint(hot_path) {
            Ok(fingerprint) => return Ok(fingerprint),
            Err(source) if source.is_retryable() => {
                if let Some(status) = child
                    .try_wait_natural_exit()
                    .map_err(|source| LoadedQemuCoverageGateError::ChildWait { mode, source })?
                {
                    return Err(channel_error(
                        mode,
                        "wait for execution fingerprint",
                        QemuNodeChannelError::new(
                            "execution fingerprint publication",
                            format!(
                                "QEMU exited before publishing the icount {icount} fingerprint: {status}"
                            ),
                        ),
                    ));
                }
                if started.elapsed() >= config.completion_timeout {
                    return Err(channel_error(
                        mode,
                        "wait for execution fingerprint",
                        QemuNodeChannelError::new(
                            "execution fingerprint publication",
                            format!(
                                "icount {icount} fingerprint was not published within {:?}; last error was {source}",
                                config.completion_timeout
                            ),
                        ),
                    ));
                }
            }
            Err(source) => {
                return Err(channel_error(mode, "read execution fingerprint", source));
            }
        }
        wait_for_poll_interval();
    }
}
