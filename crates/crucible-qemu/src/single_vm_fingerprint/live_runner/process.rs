//! Fresh QEMU spawning and bounded process cleanup.

use std::fs::{self, File};
use std::io;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::QemuNodeChild;

use super::{
    LiveRunnerArtifacts, LiveRunnerConfig, LiveRunnerConfigError, LiveRunnerLaunchKind,
    LiveRunnerQmpConnector, LiveRunnerQmpObservation, LiveRunnerQmpPollError, LiveRunnerQmpPoller,
    LiveRunnerQmpSession, LiveRunnerSleeper,
};

/// Owned fresh QEMU observation process.
#[derive(Debug)]
pub struct LiveObservationProcess {
    child: QemuNodeChild,
    artifacts: LiveRunnerArtifacts,
    launch_kind: LiveRunnerLaunchKind,
    expected_vcpus: u16,
}

impl LiveObservationProcess {
    /// Returns whether the child has already been reaped.
    #[must_use]
    pub const fn reaped(&self) -> bool {
        self.child.reaped()
    }

    /// Observes this process's exact QMP boundary and binds its session to the child.
    ///
    /// Consuming `self` prevents a QMP session from one attempt from being paired
    /// with another attempt's child. A failed observation drops the owned child
    /// through [`QemuNodeChild`]'s kill-and-wait fallback.
    ///
    /// # Errors
    ///
    /// Returns [`LiveObservationProcessError`] when bounded typed QMP observation
    /// or topology validation fails.
    pub fn observe<C, S>(
        self,
        poller: &mut LiveRunnerQmpPoller<C, S>,
    ) -> Result<LiveObservationAttempt<C::Session>, LiveObservationProcessError>
    where
        C: LiveRunnerQmpConnector,
        S: LiveRunnerSleeper,
    {
        let connection = poller
            .observe_stopped(
                self.artifacts.qmp_socket(),
                self.expected_vcpus,
                self.launch_kind.expected_stopped_state(),
            )
            .map_err(LiveObservationProcessError::Qmp)?;
        Ok(LiveObservationAttempt {
            process: self,
            session: connection.session,
            observation: connection.observation,
        })
    }

    fn shutdown<S: LiveRunnerQmpSession>(
        mut self,
        session: &mut S,
        policy: LiveObservationShutdownPolicy,
    ) -> Result<LiveObservationShutdown, LiveObservationProcessError> {
        let policy = policy.validate()?;
        session.quit().map_err(LiveObservationProcessError::Qmp)?;
        for attempt in 0..policy.poll_attempts {
            match self.child.try_wait_natural_exit() {
                Ok(Some(status)) => {
                    return Ok(LiveObservationShutdown::NaturalExit {
                        success: status.success(),
                    });
                }
                Ok(None) => {}
                Err(source) => {
                    return Err(LiveObservationProcessError::Child {
                        operation: "poll natural QEMU exit",
                        detail: source.to_string(),
                    });
                }
            }
            if attempt + 1 < policy.poll_attempts {
                thread::sleep(policy.interval);
            }
        }
        Ok(LiveObservationShutdown::ForcedByOwnerDrop)
    }
}

/// One observed attempt whose child and typed QMP session cannot be separated.
#[derive(Debug)]
pub struct LiveObservationAttempt<S> {
    process: LiveObservationProcess,
    session: S,
    observation: LiveRunnerQmpObservation,
}

impl<S: LiveRunnerQmpSession> LiveObservationAttempt<S> {
    /// Returns the accepted exact run-state and vCPU-topology observation.
    #[must_use]
    pub const fn observation(&self) -> &LiveRunnerQmpObservation {
        &self.observation
    }

    /// Returns the fresh artifact paths owned by this attempt.
    #[must_use]
    pub fn artifacts(&self) -> &LiveRunnerArtifacts {
        &self.process.artifacts
    }

    /// Requests typed QMP quit and performs bounded child cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`LiveObservationProcessError`] when QMP quit fails, natural-exit
    /// polling fails, or the finite shutdown policy is invalid. On every error,
    /// the owned child still receives kill-and-wait cleanup during drop.
    pub fn shutdown(
        mut self,
        policy: LiveObservationShutdownPolicy,
    ) -> Result<LiveObservationShutdown, LiveObservationProcessError> {
        self.process.shutdown(&mut self.session, policy)
    }
}

/// Explicit finite bounds for graceful QEMU process shutdown polling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveObservationShutdownPolicy {
    /// Maximum child-status polls after typed QMP quit.
    pub poll_attempts: u32,
    /// Delay between child-status polls.
    pub interval: Duration,
}

impl LiveObservationShutdownPolicy {
    /// Validates finite nonzero polling bounds.
    ///
    /// # Errors
    ///
    /// Returns [`LiveObservationProcessError`] when either bound is zero.
    pub fn validate(self) -> Result<Self, LiveObservationProcessError> {
        if self.poll_attempts == 0 {
            return Err(LiveObservationProcessError::InvalidShutdownPolicy {
                field: "poll_attempts",
            });
        }
        if self.interval.is_zero() {
            return Err(LiveObservationProcessError::InvalidShutdownPolicy { field: "interval" });
        }
        Ok(self)
    }
}

impl Default for LiveObservationShutdownPolicy {
    fn default() -> Self {
        Self {
            poll_attempts: 500,
            interval: Duration::from_millis(20),
        }
    }
}

/// Result of bounded observation-process teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveObservationShutdown {
    /// QEMU exited after typed QMP quit.
    NaturalExit {
        /// Whether QEMU returned success.
        success: bool,
    },
    /// The graceful bound expired and `QemuNodeChild` performed owner-drop cleanup.
    ForcedByOwnerDrop,
}

/// Spawns one fresh observation-only QEMU process with an empty environment.
///
/// # Errors
///
/// Returns [`LiveObservationProcessError`] when argv construction, log creation,
/// metadata sync, or process spawning fails.
pub fn spawn_live_observation_process(
    config: &LiveRunnerConfig,
    kind: LiveRunnerLaunchKind,
    artifacts: &LiveRunnerArtifacts,
) -> Result<LiveObservationProcess, LiveObservationProcessError> {
    let spec = config
        .launch_spec(kind, artifacts)
        .map_err(LiveObservationProcessError::Config)?;
    let stdout = create_new_log(artifacts.stdout_log())?;
    let stderr = create_new_log(artifacts.stderr_log())?;
    fs::File::open(artifacts.directory())
        .and_then(|directory| directory.sync_all())
        .map_err(|source| LiveObservationProcessError::Io {
            operation: "sync fresh attempt directory",
            source,
        })?;
    let mut command = Command::new(spec.executable());
    command
        .args(spec.argv())
        .current_dir(artifacts.directory())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let child = command
        .spawn()
        .map_err(|source| LiveObservationProcessError::Io {
            operation: "spawn fresh observation-only QEMU",
            source,
        })?;
    Ok(LiveObservationProcess {
        child: QemuNodeChild::new(child),
        artifacts: artifacts.clone(),
        launch_kind: kind,
        expected_vcpus: config.vcpus(),
    })
}

fn create_new_log(path: &std::path::Path) -> Result<File, LiveObservationProcessError> {
    File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| LiveObservationProcessError::Io {
            operation: "create fresh QEMU process log",
            source,
        })
}

/// Failures while spawning or cleaning up an observation process.
#[derive(Debug, Error)]
pub enum LiveObservationProcessError {
    /// Launch configuration could not produce argv.
    #[error("live-run launch configuration failed: {0}")]
    Config(LiveRunnerConfigError),
    /// Typed QMP cleanup failed.
    #[error("live-run QMP cleanup failed: {0}")]
    Qmp(LiveRunnerQmpPollError),
    /// Shutdown polling policy had a zero bound.
    #[error("live-run shutdown policy field {field} must be non-zero")]
    InvalidShutdownPolicy {
        /// Invalid policy field.
        field: &'static str,
    },
    /// Child ownership operation failed.
    #[error("{operation} failed: {detail}")]
    Child {
        /// Operation being attempted.
        operation: &'static str,
        /// Error detail.
        detail: String,
    },
    /// Filesystem or process operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying error.
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_shutdown_bounds_are_rejected() {
        let attempts = LiveObservationShutdownPolicy {
            poll_attempts: 0,
            ..LiveObservationShutdownPolicy::default()
        };
        assert!(matches!(
            attempts.validate(),
            Err(LiveObservationProcessError::InvalidShutdownPolicy {
                field: "poll_attempts"
            })
        ));

        let interval = LiveObservationShutdownPolicy {
            interval: Duration::ZERO,
            ..LiveObservationShutdownPolicy::default()
        };
        assert!(matches!(
            interval.validate(),
            Err(LiveObservationProcessError::InvalidShutdownPolicy { field: "interval" })
        ));
    }
}
