//! Bounded typed QMP connection, status, and topology polling.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::{QmpClient, QmpCpuTopology, QmpRunState, QmpRunStateKind};

/// One established typed QMP session used by the live runner.
pub trait LiveRunnerQmpSession {
    /// Queries QEMU's typed run state.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when QMP cannot return a valid status.
    fn query_status(&mut self) -> Result<QmpRunState, LiveRunnerQmpPollError>;

    /// Queries QEMU's exact contiguous vCPU topology.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when QMP cannot return a valid topology.
    fn query_topology(&mut self) -> Result<QmpCpuTopology, LiveRunnerQmpPollError>;

    /// Requests graceful process termination.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when the typed QMP quit fails.
    fn quit(&mut self) -> Result<(), LiveRunnerQmpPollError>;
}

impl LiveRunnerQmpSession for QmpClient<UnixStream> {
    fn query_status(&mut self) -> Result<QmpRunState, LiveRunnerQmpPollError> {
        QmpClient::query_status(self).map_err(|source| LiveRunnerQmpPollError::Qmp {
            operation: "query QMP status",
            detail: source.to_string(),
        })
    }

    fn query_topology(&mut self) -> Result<QmpCpuTopology, LiveRunnerQmpPollError> {
        QmpClient::query_cpus_fast(self).map_err(|source| LiveRunnerQmpPollError::Qmp {
            operation: "query QMP topology",
            detail: source.to_string(),
        })
    }

    fn quit(&mut self) -> Result<(), LiveRunnerQmpPollError> {
        QmpClient::quit(self)
            .map(|_| ())
            .map_err(|source| LiveRunnerQmpPollError::Qmp {
                operation: "request QMP quit",
                detail: source.to_string(),
            })
    }
}

/// Factory for an established typed QMP session.
pub trait LiveRunnerQmpConnector {
    /// Session returned after capability negotiation.
    type Session: LiveRunnerQmpSession;

    /// Connects to `socket` and negotiates QMP capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when connection or negotiation fails.
    fn connect(&mut self, socket: &Path) -> Result<Self::Session, LiveRunnerQmpPollError>;
}

/// Production connector backed by the crate's bounded typed QMP client.
#[derive(Clone, Copy, Debug, Default)]
pub struct TypedLiveRunnerQmpConnector;

impl LiveRunnerQmpConnector for TypedLiveRunnerQmpConnector {
    type Session = QmpClient<UnixStream>;

    fn connect(&mut self, socket: &Path) -> Result<Self::Session, LiveRunnerQmpPollError> {
        QmpClient::connect_unix_socket(socket).map_err(|source| LiveRunnerQmpPollError::Qmp {
            operation: "connect QMP Unix socket",
            detail: source.to_string(),
        })
    }
}

/// Sleep hook separating bounded polling policy from host timing in tests.
pub trait LiveRunnerSleeper {
    /// Delays the next bounded poll.
    fn sleep(&mut self, duration: Duration);
}

/// Production polling sleeper.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadLiveRunnerSleeper;

impl LiveRunnerSleeper for ThreadLiveRunnerSleeper {
    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// Explicit finite QMP polling bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveRunnerQmpPollPolicy {
    /// Maximum socket connection attempts.
    pub connect_attempts: u32,
    /// Maximum status queries after connection.
    pub status_attempts: u32,
    /// Delay between attempts.
    pub interval: Duration,
}

impl LiveRunnerQmpPollPolicy {
    /// Validates nonzero finite polling bounds.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when any bound is zero.
    pub fn validate(self) -> Result<Self, LiveRunnerQmpPollError> {
        if self.connect_attempts == 0 {
            return Err(LiveRunnerQmpPollError::UnboundedPolicy {
                field: "connect_attempts",
            });
        }
        if self.status_attempts == 0 {
            return Err(LiveRunnerQmpPollError::UnboundedPolicy {
                field: "status_attempts",
            });
        }
        if self.interval.is_zero() {
            return Err(LiveRunnerQmpPollError::UnboundedPolicy { field: "interval" });
        }
        Ok(self)
    }
}

impl Default for LiveRunnerQmpPollPolicy {
    fn default() -> Self {
        Self {
            connect_attempts: 600,
            status_attempts: 24_000,
            interval: Duration::from_millis(100),
        }
    }
}

/// Typed observation made after QEMU reaches a non-running boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRunnerQmpObservation {
    /// Exact run state returned by QMP.
    pub run_state: QmpRunState,
    /// Exact contiguous vCPU indexes.
    pub cpu_indexes: Vec<u64>,
}

/// Established typed QMP session paired with its accepted boundary observation.
#[derive(Debug)]
pub(super) struct LiveRunnerQmpConnection<S> {
    pub(super) session: S,
    pub(super) observation: LiveRunnerQmpObservation,
}

/// Bounded typed QMP observer with injectable connection and sleep hooks.
#[derive(Debug)]
pub struct LiveRunnerQmpPoller<C, S> {
    connector: C,
    sleeper: S,
    policy: LiveRunnerQmpPollPolicy,
}

impl<C, S> LiveRunnerQmpPoller<C, S>
where
    C: LiveRunnerQmpConnector,
    S: LiveRunnerSleeper,
{
    /// Creates a bounded poller.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when `policy` contains a zero bound.
    pub fn new(
        connector: C,
        sleeper: S,
        policy: LiveRunnerQmpPollPolicy,
    ) -> Result<Self, LiveRunnerQmpPollError> {
        Ok(Self {
            connector,
            sleeper,
            policy: policy.validate()?,
        })
    }

    /// Waits for QMP, an exact non-running status, and the expected topology.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerQmpPollError`] when connection remains unavailable,
    /// QEMU never reaches `expected_state`, reports another non-running state, a
    /// typed query fails, or topology differs. `Running` is not an admissible
    /// observation boundary.
    pub(super) fn observe_stopped(
        &mut self,
        socket: &Path,
        expected_vcpus: u16,
        expected_state: QmpRunStateKind,
    ) -> Result<LiveRunnerQmpConnection<C::Session>, LiveRunnerQmpPollError> {
        if expected_vcpus == 0 {
            return Err(LiveRunnerQmpPollError::ExpectedVcpusZero);
        }
        if expected_state == QmpRunStateKind::Running {
            return Err(LiveRunnerQmpPollError::ExpectedStateRunning);
        }
        let mut session = None;
        let mut last_connect_error = String::from("QMP socket was not ready");
        for attempt in 0..self.policy.connect_attempts {
            match self.connector.connect(socket) {
                Ok(connected) => {
                    session = Some(connected);
                    break;
                }
                Err(error) => last_connect_error = error.to_string(),
            }
            if attempt + 1 < self.policy.connect_attempts {
                self.sleeper.sleep(self.policy.interval);
            }
        }
        let mut session = session.ok_or_else(|| LiveRunnerQmpPollError::ConnectExhausted {
            socket: socket.to_owned(),
            attempts: self.policy.connect_attempts,
            last_error: last_connect_error,
        })?;

        for attempt in 0..self.policy.status_attempts {
            let status = session.query_status()?;
            if status.running != (status.status == QmpRunStateKind::Running) {
                return Err(LiveRunnerQmpPollError::InconsistentRunState {
                    running: status.running,
                    status: status.status,
                });
            }
            if !status.running && status.status == expected_state {
                let topology = session.query_topology()?;
                let expected: Vec<u64> = (0..u64::from(expected_vcpus)).collect();
                if topology.cpu_indexes() != expected {
                    return Err(LiveRunnerQmpPollError::TopologyMismatch {
                        expected,
                        observed: topology.cpu_indexes().to_vec(),
                    });
                }
                return Ok(LiveRunnerQmpConnection {
                    session,
                    observation: LiveRunnerQmpObservation {
                        run_state: status,
                        cpu_indexes: topology.cpu_indexes().to_vec(),
                    },
                });
            }
            if !status.running {
                return Err(LiveRunnerQmpPollError::UnexpectedRunState {
                    expected: expected_state,
                    observed: status.status,
                });
            }
            if attempt + 1 < self.policy.status_attempts {
                self.sleeper.sleep(self.policy.interval);
            }
        }
        Err(LiveRunnerQmpPollError::StatusExhausted {
            attempts: self.policy.status_attempts,
        })
    }

    /// Reuses the finite status-poll budget for a post-pause publication barrier.
    pub(super) fn poll_publication<T, E, F>(&mut self, mut inspect: F) -> Result<Option<T>, E>
    where
        F: FnMut() -> Result<Option<T>, E>,
    {
        for attempt in 0..self.policy.status_attempts {
            if let Some(value) = inspect()? {
                return Ok(Some(value));
            }
            if attempt + 1 < self.policy.status_attempts {
                self.sleeper.sleep(self.policy.interval);
            }
        }
        Ok(None)
    }
}

/// Failures from bounded typed QMP observation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LiveRunnerQmpPollError {
    /// Poll policy has a zero bound.
    #[error("QMP poll policy field {field} must be non-zero")]
    UnboundedPolicy {
        /// Invalid field.
        field: &'static str,
    },
    /// Launch contract requested no vCPUs.
    #[error("expected QMP topology vCPU count must be non-zero")]
    ExpectedVcpusZero,
    /// Caller requested running state as a stopped boundary.
    #[error("expected stopped QMP state cannot be running")]
    ExpectedStateRunning,
    /// QMP's boolean and symbolic run-state fields contradicted each other.
    #[error(
        "QEMU reported internally inconsistent run state: running={running}, status={status:?}"
    )]
    InconsistentRunState {
        /// Boolean running field returned by QMP.
        running: bool,
        /// Symbolic status returned by QMP.
        status: QmpRunStateKind,
    },
    /// Connection attempts were exhausted.
    #[error("QMP connection to {socket} failed after {attempts} attempts: {last_error}", socket = socket.display())]
    ConnectExhausted {
        /// Socket path.
        socket: PathBuf,
        /// Attempt count.
        attempts: u32,
        /// Last connection error.
        last_error: String,
    },
    /// QEMU did not stop within the finite status polls.
    #[error("QEMU remained running after {attempts} typed status polls")]
    StatusExhausted {
        /// Attempt count.
        attempts: u32,
    },
    /// QEMU stopped in a state other than the exact expected boundary.
    #[error("QEMU stopped in {observed:?}, expected {expected:?}")]
    UnexpectedRunState {
        /// Required stopped state.
        expected: QmpRunStateKind,
        /// Observed stopped state.
        observed: QmpRunStateKind,
    },
    /// Typed topology differed from the launch contract.
    #[error("QMP topology mismatch: expected {expected:?}, observed {observed:?}")]
    TopologyMismatch {
        /// Expected indexes.
        expected: Vec<u64>,
        /// Observed indexes.
        observed: Vec<u64>,
    },
    /// Typed QMP operation failed.
    #[error("{operation} failed: {detail}")]
    Qmp {
        /// Operation being attempted.
        operation: &'static str,
        /// Error detail.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct ScriptedSession {
        status: QmpRunState,
        topology: Option<QmpCpuTopology>,
    }

    impl LiveRunnerQmpSession for ScriptedSession {
        fn query_status(&mut self) -> Result<QmpRunState, LiveRunnerQmpPollError> {
            Ok(self.status.clone())
        }

        fn query_topology(&mut self) -> Result<QmpCpuTopology, LiveRunnerQmpPollError> {
            self.topology
                .take()
                .ok_or_else(|| LiveRunnerQmpPollError::Qmp {
                    operation: "unexpected topology query",
                    detail: "test did not provide a topology".into(),
                })
        }

        fn quit(&mut self) -> Result<(), LiveRunnerQmpPollError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ScriptedConnector {
        status: QmpRunState,
        topology: Option<QmpCpuTopology>,
        connections: u32,
    }

    impl LiveRunnerQmpConnector for ScriptedConnector {
        type Session = ScriptedSession;

        fn connect(&mut self, _socket: &Path) -> Result<Self::Session, LiveRunnerQmpPollError> {
            self.connections += 1;
            Ok(ScriptedSession {
                status: self.status.clone(),
                topology: self.topology.take(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct NoSleep;

    impl LiveRunnerSleeper for NoSleep {
        fn sleep(&mut self, _duration: Duration) {}
    }

    #[test]
    fn zero_poll_bounds_are_rejected() {
        let policy = LiveRunnerQmpPollPolicy {
            connect_attempts: 0,
            ..LiveRunnerQmpPollPolicy::default()
        };
        assert_eq!(
            policy.validate(),
            Err(LiveRunnerQmpPollError::UnboundedPolicy {
                field: "connect_attempts"
            })
        );
    }

    #[test]
    fn running_boundary_is_rejected_before_connecting() -> Result<(), LiveRunnerQmpPollError> {
        let connector = ScriptedConnector {
            status: QmpRunState {
                running: true,
                status: QmpRunStateKind::Running,
            },
            topology: None,
            connections: 0,
        };
        let mut poller =
            LiveRunnerQmpPoller::new(connector, NoSleep, LiveRunnerQmpPollPolicy::default())?;
        let result = poller.observe_stopped(
            Path::new("/tmp/unused-qmp.sock"),
            1,
            QmpRunStateKind::Running,
        );
        assert!(matches!(
            result,
            Err(LiveRunnerQmpPollError::ExpectedStateRunning)
        ));
        assert_eq!(poller.connector.connections, 0);
        Ok(())
    }

    #[test]
    fn wrong_stopped_state_is_rejected_before_topology() -> Result<(), LiveRunnerQmpPollError> {
        let connector = ScriptedConnector {
            status: QmpRunState {
                running: false,
                status: QmpRunStateKind::Shutdown,
            },
            topology: None,
            connections: 0,
        };
        let mut poller =
            LiveRunnerQmpPoller::new(connector, NoSleep, LiveRunnerQmpPollPolicy::default())?;
        let result = poller.observe_stopped(
            Path::new("/tmp/unused-qmp.sock"),
            4,
            QmpRunStateKind::Paused,
        );
        assert!(matches!(
            result,
            Err(LiveRunnerQmpPollError::UnexpectedRunState {
                expected: QmpRunStateKind::Paused,
                observed: QmpRunStateKind::Shutdown,
            })
        ));
        assert_eq!(poller.connector.connections, 1);
        Ok(())
    }

    #[test]
    fn internally_inconsistent_running_shape_is_rejected() -> Result<(), LiveRunnerQmpPollError> {
        let connector = ScriptedConnector {
            status: QmpRunState {
                running: true,
                status: QmpRunStateKind::Paused,
            },
            topology: None,
            connections: 0,
        };
        let mut poller =
            LiveRunnerQmpPoller::new(connector, NoSleep, LiveRunnerQmpPollPolicy::default())?;
        let result = poller.observe_stopped(
            Path::new("/tmp/unused-qmp.sock"),
            4,
            QmpRunStateKind::Paused,
        );
        assert!(matches!(
            result,
            Err(LiveRunnerQmpPollError::InconsistentRunState {
                running: true,
                status: QmpRunStateKind::Paused,
            })
        ));
        Ok(())
    }

    #[test]
    fn internally_inconsistent_stopped_shape_is_rejected() -> Result<(), LiveRunnerQmpPollError> {
        let connector = ScriptedConnector {
            status: QmpRunState {
                running: false,
                status: QmpRunStateKind::Running,
            },
            topology: None,
            connections: 0,
        };
        let mut poller =
            LiveRunnerQmpPoller::new(connector, NoSleep, LiveRunnerQmpPollPolicy::default())?;
        let result = poller.observe_stopped(
            Path::new("/tmp/unused-qmp.sock"),
            4,
            QmpRunStateKind::Paused,
        );
        assert!(matches!(
            result,
            Err(LiveRunnerQmpPollError::InconsistentRunState {
                running: false,
                status: QmpRunStateKind::Running,
            })
        ));
        Ok(())
    }

    #[test]
    fn exact_boundary_retains_the_negotiated_session() -> Result<(), LiveRunnerQmpPollError> {
        let connector = ScriptedConnector {
            status: QmpRunState {
                running: false,
                status: QmpRunStateKind::Paused,
            },
            topology: Some(QmpCpuTopology::from_test_cpu_indexes(vec![0, 1, 2, 3])),
            connections: 0,
        };
        let mut poller =
            LiveRunnerQmpPoller::new(connector, NoSleep, LiveRunnerQmpPollPolicy::default())?;
        let connection = poller.observe_stopped(
            Path::new("/tmp/unused-qmp.sock"),
            4,
            QmpRunStateKind::Paused,
        )?;
        assert_eq!(connection.observation.cpu_indexes, vec![0, 1, 2, 3]);
        assert_eq!(
            connection.observation.run_state.status,
            QmpRunStateKind::Paused
        );
        assert_eq!(connection.session.status.status, QmpRunStateKind::Paused);
        Ok(())
    }
}
