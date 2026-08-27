//! Minimal typed QMP client.
//!
//! RFC-0010 QEMU-19 limits QMP use to capability negotiation, typed VM
//! status/topology, hot-fork-readiness observation, and the bounded QEMU-owned
//! thread inventory, plus VM snapshot save/load/delete, snapshot job polling,
//! and graceful quit. The client parses JSON-line QMP responses internally,
//! skips asynchronous event objects while waiting for a command response, and
//! exposes no public arbitrary-command execution path.

use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use thiserror::Error;

use crate::{QemuLoadvmCommandAuthorization, QemuNodeChannelError};

mod hot_fork;
mod snapshot_tag;
#[cfg(target_os = "linux")]
mod unix_socket;
mod vmstate_control;

pub use hot_fork::{
    QMP_HOT_FORK_AIO_HANDLER_INVENTORY_MAX, QMP_HOT_FORK_AIO_HANDLER_INVENTORY_SCHEMA_VERSION,
    QMP_HOT_FORK_AIO_INVENTORY_MAX, QMP_HOT_FORK_AIO_INVENTORY_SCHEMA_VERSION,
    QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX, QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_SCHEMA_VERSION,
    QMP_HOT_FORK_BLOCK_BACKEND_NAME_MAX_BYTES, QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX,
    QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_SCHEMA_VERSION, QMP_HOT_FORK_BOTTOM_HALF_NAME_MAX_BYTES,
    QMP_HOT_FORK_MUTEX_INVENTORY_MAX, QMP_HOT_FORK_MUTEX_INVENTORY_SCHEMA_VERSION,
    QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION, QMP_HOT_FORK_RCU_INVENTORY_MAX,
    QMP_HOT_FORK_RCU_INVENTORY_SCHEMA_VERSION, QMP_HOT_FORK_READINESS_SCHEMA_VERSION,
    QMP_HOT_FORK_REQUIRED_PROOFS, QMP_HOT_FORK_THREAD_INVENTORY_MAX,
    QMP_HOT_FORK_THREAD_INVENTORY_SCHEMA_VERSION, QMP_HOT_FORK_THREAD_NAME_MAX_BYTES,
    QMP_HOT_FORK_TIMER_INVENTORY_MAX, QMP_HOT_FORK_TIMER_INVENTORY_SCHEMA_VERSION,
    QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_READINESS_COMMAND, QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND, QmpHotForkAioContext, QmpHotForkAioHandler,
    QmpHotForkAioHandlerInventory, QmpHotForkAioInventory, QmpHotForkBlockBackend,
    QmpHotForkBlockBackendInventory, QmpHotForkBottomHalf, QmpHotForkBottomHalfInventory,
    QmpHotForkMutex, QmpHotForkMutexInventory, QmpHotForkPluginResourceInventory, QmpHotForkProof,
    QmpHotForkRcuInventory, QmpHotForkRcuReader, QmpHotForkReadiness, QmpHotForkThread,
    QmpHotForkThreadDisposition, QmpHotForkThreadInventory, QmpHotForkTimer, QmpHotForkTimerClock,
    QmpHotForkTimerInventory,
};
use hot_fork::{
    parse_hot_fork_aio_handler_inventory, parse_hot_fork_aio_inventory,
    parse_hot_fork_block_backend_inventory, parse_hot_fork_bottom_half_inventory,
    parse_hot_fork_mutex_inventory, parse_hot_fork_plugin_resource_inventory,
    parse_hot_fork_rcu_inventory, parse_hot_fork_readiness, parse_hot_fork_thread_inventory,
    parse_hot_fork_timer_inventory,
};
pub use snapshot_tag::QmpSnapshotTag;
pub use vmstate_control::QemuQmpVmStateControlChannel;

/// QMP command name used for capability negotiation.
pub const QMP_CAPABILITIES_COMMAND: &str = "qmp_capabilities";
/// QMP command name used for saving the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_SAVE_COMMAND: &str = "snapshot-save";
/// QMP command name used for loading the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_LOAD_COMMAND: &str = "snapshot-load";
/// QMP command name used for deleting the QEMU VMState half of a checkpoint.
pub const QMP_SNAPSHOT_DELETE_COMMAND: &str = "snapshot-delete";
/// QMP command name used for polling snapshot job completion.
pub const QMP_QUERY_JOBS_COMMAND: &str = "query-jobs";
/// QMP command name used to release one concluded snapshot job.
pub const QMP_JOB_DISMISS_COMMAND: &str = "job-dismiss";
/// QMP command name used for reading the VM run state.
pub const QMP_QUERY_STATUS_COMMAND: &str = "query-status";
/// QMP command used to stop guest execution at a lifecycle boundary.
pub const QMP_STOP_COMMAND: &str = "stop";
/// QMP command used to resume guest execution after a lifecycle boundary.
pub const QMP_CONT_COMMAND: &str = "cont";
/// QMP command that authorizes one authenticated terminal lifecycle exit.
pub const QMP_COMPLETE_TERMINAL_LIFECYCLE_COMMAND: &str = "crucible-complete-terminal-lifecycle";
/// QMP command name used for reading configured vCPU indexes.
pub const QMP_QUERY_CPUS_FAST_COMMAND: &str = "query-cpus-fast";
/// QMP command name used for graceful QEMU termination.
pub const QMP_QUIT_COMMAND_NAME: &str = "quit";
/// Versioned token consumed by the dormant fixture-side debugger bootstrap.
pub const QMP_DEBUG_GUEST_ACTIVATION_TOKEN: &str = "CRUCIBLE_DEBUG_AGENT_V1\n";
/// QMP snapshot device name used for diskless VMState snapshots.
pub const QMP_SNAPSHOT_VMSTATE_DEVICE: &str = "vmstate";
/// Default maximum number of `query-jobs` polls for a snapshot operation.
pub const QMP_JOB_QUERY_LIMIT: usize = 1200;
/// Default delay between `query-jobs` polls for a snapshot operation.
pub const QMP_JOB_QUERY_INTERVAL: Duration = Duration::from_millis(250);
/// Default timeout for the initial QMP greeting.
pub const QMP_GREETING_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for one QMP command read or write.
pub const QMP_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum bytes in one QMP JSON line.
pub const QMP_MAX_LINE_BYTES: usize = 1024 * 1024;
/// Default maximum asynchronous QMP event objects skipped while awaiting a command.
pub const QMP_MAX_ASYNC_EVENTS_PER_COMMAND: usize = 1024;

/// Stream contract required by the bounded QMP client.
pub trait QmpTimeoutStream: Read + Write + Send {
    /// Installs the read timeout used by the next QMP receive operation.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the stream cannot install the timeout.
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()>;

    /// Installs the write timeout used by the next QMP send operation.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the stream cannot install the timeout.
    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()>;
}

impl QmpTimeoutStream for TcpStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}

#[cfg(unix)]
impl QmpTimeoutStream for UnixStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}

/// Typed minimal QMP client over an established stream.
#[derive(Debug)]
pub struct QmpClient<S> {
    stream: BufReader<S>,
    greeting: QmpGreeting,
    job_poll_policy: QmpJobPollPolicy,
    io_timeout_policy: QmpIoTimeoutPolicy,
    predeclared_debug_guest_endpoint: bool,
}

impl<S> QmpClient<S>
where
    S: QmpTimeoutStream,
{
    /// Connects a client to an established QMP stream and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the greeting cannot be read or decoded, when the
    /// greeting is not a QMP greeting, when the capabilities request cannot be
    /// written, or when QMP reports an error response.
    pub fn connect(stream: S) -> Result<Self, QmpError> {
        Self::connect_with_policies(
            stream,
            QmpJobPollPolicy::default(),
            QmpIoTimeoutPolicy::default(),
        )
    }

    /// Connects a client with an explicit snapshot-job polling policy.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the greeting cannot be read or decoded, when the
    /// greeting is not a QMP greeting, when the capabilities request cannot be
    /// written, or when QMP reports an error response.
    pub fn connect_with_job_poll_policy(
        stream: S,
        job_poll_policy: QmpJobPollPolicy,
    ) -> Result<Self, QmpError> {
        Self::connect_with_policies(stream, job_poll_policy, QmpIoTimeoutPolicy::default())
    }

    /// Connects a client with explicit snapshot-job and stream timeout policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when either timeout is zero, when the greeting cannot
    /// be read or decoded, when the greeting is not a QMP greeting, when the
    /// capabilities request cannot be written, or when QMP cannot enable the
    /// required OOB capability or reports another error response.
    pub fn connect_with_policies(
        stream: S,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        io_timeout_policy.validate()?;
        let mut client = Self {
            stream: BufReader::new(stream),
            greeting: QmpGreeting {
                version_present: false,
                capabilities_present: false,
            },
            job_poll_policy,
            io_timeout_policy,
            predeclared_debug_guest_endpoint: false,
        };
        client.greeting = client.read_greeting()?;
        client.send_command(QmpCommand::Capabilities)?;
        Ok(client)
    }

    /// Returns the QMP greeting fields observed during connection setup.
    #[must_use]
    pub const fn greeting(&self) -> QmpGreeting {
        self.greeting
    }

    /// Returns a client whose launch already contains the fixed inert endpoint.
    #[must_use]
    pub const fn with_predeclared_debug_guest_endpoint(mut self) -> Self {
        self.predeclared_debug_guest_endpoint = true;
        self
    }

    /// Saves the VMState snapshot under a tag derived from a checkpoint address.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be read or decoded, when QMP returns an error response, or when
    /// the snapshot job reports failure or does not conclude within
    /// [`QMP_JOB_QUERY_LIMIT`] polls.
    pub fn savevm(&mut self, tag: &QmpSnapshotTag) -> Result<QmpCommandComplete, QmpError> {
        let job_id = snapshot_job_id("save", tag);
        self.send_command(QmpCommand::SaveVm {
            tag,
            job_id: &job_id,
        })?;
        self.wait_for_job(QmpCommandKind::SaveVm, &job_id)
    }

    /// Loads the VMState snapshot named by a checkpoint-derived tag.
    ///
    /// This only performs the low-level QMP command. Runtime admission remains a
    /// separate replay-oracle-validated policy decision.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be read or decoded, when QMP returns an error response, or when
    /// the snapshot job reports failure or does not conclude within
    /// [`QMP_JOB_QUERY_LIMIT`] polls.
    pub fn loadvm(
        &mut self,
        tag: &QmpSnapshotTag,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<QmpCommandComplete, QmpError> {
        if authorization.purpose() != crate::QemuLoadvmCommandPurpose::ReplayOracleProbe {
            return Err(QmpError::UnauthorizedLoadvmPurpose {
                purpose: authorization.purpose(),
            });
        }
        self.loadvm_authorized(tag)
    }

    pub(crate) fn loadvm_authorized(
        &mut self,
        tag: &QmpSnapshotTag,
    ) -> Result<QmpCommandComplete, QmpError> {
        let job_id = snapshot_job_id("load", tag);
        self.send_command(QmpCommand::LoadVm {
            tag,
            job_id: &job_id,
        })?;
        self.wait_for_job(QmpCommandKind::LoadVm, &job_id)
    }

    /// Deletes the VMState snapshot named by a checkpoint-derived tag.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be decoded, or when the delete job fails or exceeds its poll bound.
    pub fn delete_snapshot(
        &mut self,
        tag: &QmpSnapshotTag,
    ) -> Result<QmpCommandComplete, QmpError> {
        let job_id = snapshot_job_id("delete", tag);
        self.send_command(QmpCommand::DeleteSnapshot {
            tag,
            job_id: &job_id,
        })?;
        self.wait_for_job(QmpCommandKind::DeleteSnapshot, &job_id)
    }

    /// Requests graceful QEMU termination over QMP.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request cannot be written, when the response
    /// cannot be read or decoded, or when QMP returns an error response.
    pub fn quit(&mut self) -> Result<QmpCommandComplete, QmpError> {
        self.send_command(QmpCommand::Quit)
    }

    /// Confirms that launch predeclared the fixed guest-introspection channel.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::DebugGuestEndpointNotPredeclared`] when the launch
    /// omitted the endpoint. Runtime QMP mutation is never attempted.
    pub const fn confirm_predeclared_debug_guest_endpoint(&self) -> Result<(), QmpError> {
        if self.predeclared_debug_guest_endpoint {
            Ok(())
        } else {
            Err(QmpError::DebugGuestEndpointNotPredeclared)
        }
    }

    /// Returns the current VM run state.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, when QEMU omits
    /// a required field, reports an unknown QEMU 10.0 run state, or contradicts
    /// the typed relationship between `running` and `status`.
    pub fn query_status(&mut self) -> Result<QmpRunState, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryStatus)?;
        let running = response.value.get("running").and_then(Value::as_bool);
        let status = response
            .value
            .get("status")
            .and_then(Value::as_str)
            .and_then(QmpRunStateKind::from_wire);
        match (running, status) {
            (Some(running), Some(status)) if running == (status == QmpRunStateKind::Running) => {
                Ok(QmpRunState { running, status })
            }
            _ => Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryStatus,
                response: response.value.to_string(),
            }),
        }
    }

    /// Stops guest execution while leaving the QMP main loop responsive.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the command fails or QEMU does not report the
    /// typed paused state after acknowledging it.
    pub fn stop(&mut self) -> Result<QmpCommandComplete, QmpError> {
        let complete = self.send_command(QmpCommand::Stop)?;
        let state = self.query_status()?;
        if state.running || state.status != QmpRunStateKind::Paused {
            return Err(QmpError::UnexpectedRunState {
                command: QmpCommandKind::Stop,
                status: state.status,
                running: state.running,
            });
        }
        Ok(complete)
    }

    /// Resumes guest execution after a lifecycle boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the command fails or QEMU does not report the
    /// typed running state after acknowledging it.
    pub fn cont(&mut self) -> Result<QmpCommandComplete, QmpError> {
        let complete = self.send_command(QmpCommand::Cont)?;
        let state = self.query_status()?;
        if !state.running || state.status != QmpRunStateKind::Running {
            return Err(QmpError::UnexpectedRunState {
                command: QmpCommandKind::Cont,
                status: state.status,
                running: state.running,
            });
        }
        Ok(complete)
    }

    /// Resumes guest execution and returns after QEMU acknowledges `cont`.
    ///
    /// This narrower operation is for an exact restore whose simulator may
    /// immediately park on the plugin barrier. A follow-up QMP query would then
    /// create an ordering cycle: the query cannot run until the scheduler
    /// receives the restored node and publishes its next ceiling. The `cont`
    /// reply itself is emitted only after QEMU accepts the run-state change;
    /// the first bounded node step provides the subsequent execution proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the command cannot be written, its response
    /// cannot be decoded, or QEMU rejects the run-state transition.
    pub(crate) fn cont_acknowledged(&mut self) -> Result<QmpCommandComplete, QmpError> {
        self.send_command(QmpCommand::Cont)
    }

    /// Completes an authenticated terminal lifecycle transition.
    ///
    /// This dedicated command never resumes guest execution. Patched QEMU
    /// validates the action, evidence, and process generation before scheduling
    /// the transition-specific exit. Repeating the same request is idempotent.
    /// The owning process supervisor must independently reap and verify that
    /// exact child after this method returns.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU does not acknowledge the command.
    pub fn complete_terminal_lifecycle_exit(
        &mut self,
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    ) -> Result<QmpCommandComplete, QmpError> {
        self.send_command(QmpCommand::CompleteTerminalLifecycle {
            action,
            evidence,
            process_generation,
        })
    }

    /// Returns the exact sorted set of configured vCPU indexes.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, when QEMU does
    /// not return an array, or when a CPU index is missing, negative, duplicate,
    /// outside the unsigned 64-bit range, nonzero-start, or noncontiguous.
    pub fn query_cpus_fast(&mut self) -> Result<QmpCpuTopology, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryCpusFast)?;
        let Some(cpus) = response.value.as_array() else {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryCpusFast,
                response: response.value.to_string(),
            });
        };
        let mut cpu_indexes = cpus
            .iter()
            .map(|cpu| cpu.get("cpu-index").and_then(Value::as_u64))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryCpusFast,
                response: response.value.to_string(),
            })?;
        cpu_indexes.sort_unstable();
        if cpu_indexes.is_empty()
            || cpu_indexes
                .iter()
                .enumerate()
                .any(|(expected, actual)| *actual != expected as u64)
        {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryCpusFast,
                response: response.value.to_string(),
            });
        }
        Ok(QmpCpuTopology { cpu_indexes })
    }

    /// Returns QEMU's exact versioned hot-fork readiness proof bitmap.
    ///
    /// This query is observational. It does not pause, prepare, or fork QEMU.
    /// A caller may treat hot fork as available only when
    /// [`QmpHotForkReadiness::ready`] is true; ordinary paused state is
    /// deliberately insufficient.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when QEMU
    /// reports an unknown schema, changes the required proof set, acknowledges
    /// an unknown proof, or contradicts the relationship between its bitmap and
    /// readiness flag.
    pub fn query_hot_fork_readiness(&mut self) -> Result<QmpHotForkReadiness, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkReadiness)?;
        parse_hot_fork_readiness(&response.value)
    }

    /// Returns QEMU's exact bounded active-thread registry.
    ///
    /// The query is audit-only. A structurally complete registry may still
    /// contain unclassified threads and cannot authorize a fork.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, count/name bounds, sorted unique
    /// thread IDs, disposition vocabulary, or derived completeness fields.
    pub fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<QmpHotForkThreadInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkThreadInventory)?;
        parse_hot_fork_thread_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational RCU inventory.
    ///
    /// This query does not drain callbacks, hold readers quiescent, or
    /// acknowledge the RCU hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, reader bound, sorted unique
    /// identifiers, declared counts, or derived completeness relationship.
    pub fn query_hot_fork_rcu_inventory(&mut self) -> Result<QmpHotForkRcuInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkRcuInventory)?;
        parse_hot_fork_rcu_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational AioContext inventory.
    ///
    /// This query does not drain or park AIO, bottom halves, handlers, or
    /// timers and does not acknowledge the AIO hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, context bound, sorted unique
    /// identifiers, home-thread profile, declared aggregates, or derived
    /// completeness relationship.
    pub fn query_hot_fork_aio_inventory(&mut self) -> Result<QmpHotForkAioInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkAioInventory)?;
        parse_hot_fork_aio_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded inventory of every allocated AIO handler.
    ///
    /// The query includes handlers awaiting deferred deletion, their exact
    /// AioContext and descriptor binding, installed callback classes, and
    /// active callback count. It does not drain or park callbacks and cannot
    /// acknowledge hot-fork proof bit 3.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, bound, identifier ordering,
    /// descriptor profile, declared aggregates, or completeness rule.
    pub fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<QmpHotForkAioHandlerInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkAioHandlerInventory)?;
        parse_hot_fork_aio_handler_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded inventory of every allocated block backend.
    ///
    /// The OOB query observes stable backend/AioContext identities, monitor
    /// visibility, root/device attachment, permissions, quiesce depth, queue
    /// policy, and in-flight I/O. It neither traverses nor drains the block
    /// graph and cannot acknowledge hot-fork proof bit 5.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, bound, identifier ordering,
    /// monitor-name profile, declared aggregates, or completeness rule.
    pub fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<QmpHotForkBlockBackendInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkBlockBackendInventory)?;
        parse_hot_fork_block_backend_inventory(&response.value)
    }

    /// Returns QEMU's exact sealed inventory of Crucible plugin resources.
    ///
    /// The OOB query binds the plugin/process identity, shared-memory backing,
    /// descriptors, feature resources, and plugin/QEMU callback masks. It is
    /// observational and cannot acknowledge hot-fork proof bit 6.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, masks, identities, descriptor
    /// relationships, feature derivations, or completeness rule.
    pub fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<QmpHotForkPluginResourceInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkPluginResourceInventory)?;
        parse_hot_fork_plugin_resource_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded inventory of every allocated bottom half.
    ///
    /// This query observes inert, pending, active, canceled, and deferred-free
    /// bottom halves. It does not drain or park them and cannot acknowledge
    /// hot-fork proof bit 3.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, bounds, identifier ordering,
    /// state relationships, declared aggregates, or completeness rule.
    pub fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<QmpHotForkBottomHalfInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkBottomHalfInventory)?;
        parse_hot_fork_bottom_half_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational mutex ownership inventory.
    ///
    /// This query does not hold a lock barrier across another operation and
    /// does not acknowledge the child-reinitialization hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, mutex bound, sorted identifiers,
    /// owner/depth relationship, declared aggregates, or completeness rule.
    pub fn query_hot_fork_mutex_inventory(&mut self) -> Result<QmpHotForkMutexInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkMutexInventory)?;
        parse_hot_fork_mutex_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational live-timer inventory.
    ///
    /// Initialized but inert timers are absent. This query does not drain or
    /// park pending timers or callbacks and cannot acknowledge hot-fork proof
    /// bit 3.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, timer bound, sorted identifiers,
    /// pending/expiry relationship, declared aggregates, or completeness rule.
    pub fn query_hot_fork_timer_inventory(&mut self) -> Result<QmpHotForkTimerInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkTimerInventory)?;
        parse_hot_fork_timer_inventory(&response.value)
    }

    fn read_greeting(&mut self) -> Result<QmpGreeting, QmpError> {
        let deadline = QmpOperationDeadline::new(self.io_timeout_policy.greeting_timeout);
        let response = self.read_json_line("read QMP greeting", &deadline)?;
        let Some(qmp) = response.get("QMP") else {
            return Err(QmpError::UnexpectedGreeting {
                response: response.to_string(),
            });
        };
        let Some(qmp) = qmp.as_object() else {
            return Err(QmpError::UnexpectedGreeting {
                response: response.to_string(),
            });
        };

        let greeting = QmpGreeting {
            version_present: qmp.contains_key("version"),
            capabilities_present: qmp.contains_key("capabilities"),
        };
        if !greeting.version_present || !greeting.capabilities_present {
            return Err(QmpError::UnexpectedGreeting {
                response: response.to_string(),
            });
        }

        Ok(greeting)
    }

    fn send_command(&mut self, command: QmpCommand<'_>) -> Result<QmpCommandComplete, QmpError> {
        let command = self.send_command_return(command)?;
        Ok(QmpCommandComplete {
            command: command.command,
        })
    }

    fn send_command_return(
        &mut self,
        command: QmpCommand<'_>,
    ) -> Result<QmpCommandReturn, QmpError> {
        let kind = command.kind();
        let deadline = QmpOperationDeadline::new(self.io_timeout_policy.command_timeout);
        self.write_json_line(kind.wire_name(), command.request(), &deadline)?;
        self.read_command_response(kind, &deadline)
    }

    fn read_command_response(
        &mut self,
        command: QmpCommandKind,
        deadline: &QmpOperationDeadline,
    ) -> Result<QmpCommandReturn, QmpError> {
        let mut skipped_events = 0usize;
        loop {
            let response = self.read_json_line(command.wire_name(), deadline)?;
            if response.get("event").is_some() {
                skipped_events = skipped_events.saturating_add(1);
                if skipped_events > self.io_timeout_policy.max_async_events_per_command {
                    return Err(QmpError::AsyncEventLimitExceeded {
                        command,
                        limit: self.io_timeout_policy.max_async_events_per_command,
                    });
                }
                continue;
            }
            if let Some(value) = response.get("return") {
                return Ok(QmpCommandReturn {
                    command,
                    value: value.clone(),
                });
            }
            if let Some(error) = response.get("error") {
                return Err(command_error(command, error));
            }
            return Err(QmpError::UnexpectedResponse {
                command,
                response: response.to_string(),
            });
        }
    }

    fn wait_for_job(
        &mut self,
        command: QmpCommandKind,
        job_id: &str,
    ) -> Result<QmpCommandComplete, QmpError> {
        for attempt in 0..self.job_poll_policy.max_polls {
            let jobs = self.send_command_return(QmpCommand::QueryJobs)?;
            let Some(jobs) = jobs.value.as_array() else {
                return Err(QmpError::UnexpectedJobList {
                    command,
                    response: jobs.value.to_string(),
                });
            };
            for job in jobs {
                if job.get("id").and_then(Value::as_str) != Some(job_id) {
                    continue;
                }
                if let Some(error) = job.get("error") {
                    self.send_command(QmpCommand::JobDismiss { job_id })?;
                    return Err(QmpError::JobFailed {
                        command,
                        job_id: job_id.to_owned(),
                        detail: error.to_string(),
                    });
                }
                if job.get("status").and_then(Value::as_str) == Some("concluded") {
                    self.send_command(QmpCommand::JobDismiss { job_id })?;
                    return Ok(QmpCommandComplete { command });
                }
            }

            if attempt + 1 < self.job_poll_policy.max_polls {
                thread::sleep(self.job_poll_policy.poll_interval);
            }
        }

        Err(QmpError::JobNotConcluded {
            command,
            job_id: job_id.to_owned(),
            polls: self.job_poll_policy.max_polls,
        })
    }

    fn read_json_line(
        &mut self,
        operation: &'static str,
        deadline: &QmpOperationDeadline,
    ) -> Result<Value, QmpError> {
        let mut line = Vec::new();
        loop {
            if line.len() == self.io_timeout_policy.max_line_bytes {
                return Err(QmpError::LineTooLong {
                    operation,
                    max_bytes: self.io_timeout_policy.max_line_bytes,
                });
            }
            let remaining = deadline.remaining(operation)?;
            self.stream
                .get_mut()
                .set_qmp_read_timeout(remaining)
                .map_err(|error| QmpError::from_io("set QMP read timeout", error))?;
            let mut byte = [0u8; 1];
            let read = self.stream.read(&mut byte).map_err(|error| {
                QmpError::from_io_with_timeout(operation, deadline.timeout, error)
            })?;
            if read == 0 {
                return Err(QmpError::Io {
                    operation,
                    kind: ErrorKind::UnexpectedEof,
                });
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        serde_json::from_slice(&line).map_err(|error| QmpError::Json {
            operation,
            message: error.to_string(),
        })
    }

    fn write_json_line(
        &mut self,
        operation: &'static str,
        request: Value,
        deadline: &QmpOperationDeadline,
    ) -> Result<(), QmpError> {
        let mut line = serde_json::to_vec(&request).map_err(|error| QmpError::Json {
            operation,
            message: error.to_string(),
        })?;
        line.extend_from_slice(b"\r\n");
        let mut written = 0usize;
        while written < line.len() {
            let remaining = deadline.remaining(operation)?;
            self.stream
                .get_mut()
                .set_qmp_write_timeout(remaining)
                .map_err(|error| QmpError::from_io("set QMP write timeout", error))?;
            let count = self
                .stream
                .get_mut()
                .write(&line[written..])
                .map_err(|error| {
                    QmpError::from_io_with_timeout("write QMP request", deadline.timeout, error)
                })?;
            if count == 0 {
                return Err(QmpError::Io {
                    operation: "write QMP request",
                    kind: ErrorKind::WriteZero,
                });
            }
            written = written.saturating_add(count);
        }
        self.stream.get_mut().flush().map_err(|error| {
            QmpError::from_io_with_timeout("flush QMP request", deadline.timeout, error)
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct QmpOperationDeadline {
    started_at: Instant,
    timeout: Duration,
}

impl QmpOperationDeadline {
    // crucible-lint: allow clippy-disallowed-method -- QMP host deadlines bound child I/O only.
    #[allow(clippy::disallowed_methods)]
    fn new(timeout: Duration) -> Self {
        // QMP lifecycle I/O uses host realtime only to bound child liveness; the
        // resulting timestamp is never folded into virtual-time ordering state.
        Self {
            started_at: Instant::now(),
            timeout,
        }
    }

    // crucible-lint: allow clippy-disallowed-method -- elapsed host time only gates QMP timeout reporting.
    #[allow(clippy::disallowed_methods)]
    fn remaining(&self, operation: &'static str) -> Result<Duration, QmpError> {
        // See `new`: this deadline gates a host control-plane wait, not guest
        // ordering or replay-visible state.
        let elapsed = self.started_at.elapsed();
        let Some(remaining) = self.timeout.checked_sub(elapsed) else {
            return Err(QmpError::Timeout {
                operation,
                timeout: self.timeout,
            });
        };
        if remaining.is_zero() {
            Err(QmpError::Timeout {
                operation,
                timeout: self.timeout,
            })
        } else {
            Ok(remaining)
        }
    }
}

/// Polling policy for QMP snapshot jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpJobPollPolicy {
    /// Maximum number of `query-jobs` polls before reporting a non-concluded job.
    pub max_polls: usize,
    /// Delay between polls.
    pub poll_interval: Duration,
}

impl QmpJobPollPolicy {
    /// Returns a zero-delay policy for deterministic unit tests.
    #[must_use]
    pub const fn fast_test(max_polls: usize) -> Self {
        Self {
            max_polls,
            poll_interval: Duration::ZERO,
        }
    }
}

impl Default for QmpJobPollPolicy {
    fn default() -> Self {
        Self {
            max_polls: QMP_JOB_QUERY_LIMIT,
            poll_interval: QMP_JOB_QUERY_INTERVAL,
        }
    }
}

/// Timeout policy for blocking QMP stream operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpIoTimeoutPolicy {
    /// Timeout for the initial QMP greeting read.
    pub greeting_timeout: Duration,
    /// Timeout for each command write and response read.
    pub command_timeout: Duration,
    /// Maximum bytes accepted before a QMP newline.
    pub max_line_bytes: usize,
    /// Maximum asynchronous event objects skipped while awaiting one command.
    pub max_async_events_per_command: usize,
}

impl QmpIoTimeoutPolicy {
    /// Builds a QMP I/O timeout policy from explicit budgets.
    #[must_use]
    pub const fn new(greeting_timeout: Duration, command_timeout: Duration) -> Self {
        Self {
            greeting_timeout,
            command_timeout,
            max_line_bytes: QMP_MAX_LINE_BYTES,
            max_async_events_per_command: QMP_MAX_ASYNC_EVENTS_PER_COMMAND,
        }
    }

    /// Uses one QMP command budget for both greeting and command I/O.
    #[must_use]
    pub const fn from_command_timeout(command_timeout: Duration) -> Self {
        Self::new(command_timeout, command_timeout)
    }

    /// Returns this policy with a custom QMP line-size bound.
    #[must_use]
    pub const fn with_max_line_bytes(mut self, max_line_bytes: usize) -> Self {
        self.max_line_bytes = max_line_bytes;
        self
    }

    /// Returns this policy with a custom asynchronous event bound.
    #[must_use]
    pub const fn with_max_async_events_per_command(
        mut self,
        max_async_events_per_command: usize,
    ) -> Self {
        self.max_async_events_per_command = max_async_events_per_command;
        self
    }

    /// Validates that all QMP stream operations have nonzero timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::UnboundedTimeout`] when either timeout is zero.
    pub fn validate(self) -> Result<(), QmpError> {
        if self.greeting_timeout.is_zero() {
            return Err(QmpError::UnboundedTimeout {
                operation: "read QMP greeting",
            });
        }
        if self.command_timeout.is_zero() {
            return Err(QmpError::UnboundedTimeout {
                operation: "QMP command",
            });
        }
        if self.max_line_bytes == 0 {
            return Err(QmpError::InvalidBound {
                operation: "QMP line bytes",
            });
        }
        if self.max_async_events_per_command == 0 {
            return Err(QmpError::InvalidBound {
                operation: "QMP async events",
            });
        }
        Ok(())
    }
}

impl Default for QmpIoTimeoutPolicy {
    fn default() -> Self {
        Self {
            greeting_timeout: QMP_GREETING_TIMEOUT,
            command_timeout: QMP_COMMAND_TIMEOUT,
            max_line_bytes: QMP_MAX_LINE_BYTES,
            max_async_events_per_command: QMP_MAX_ASYNC_EVENTS_PER_COMMAND,
        }
    }
}

/// Fields observed in the QMP greeting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpGreeting {
    /// Whether the greeting carried a `version` object.
    pub version_present: bool,
    /// Whether the greeting carried a `capabilities` array.
    pub capabilities_present: bool,
}

/// Current VM run state returned by typed `query-status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpRunState {
    /// Whether the VM is in QEMU's running state.
    pub running: bool,
    /// Exact typed QEMU run state.
    pub status: QmpRunStateKind,
}

/// QEMU 10.0 run-state values admitted by typed `query-status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpRunStateKind {
    /// Execution stopped for debugger control.
    Debug,
    /// Execution stopped to finish migration.
    FinishMigrate,
    /// Waiting for incoming migration.
    InMigrate,
    /// Execution stopped by an internal error.
    InternalError,
    /// Execution stopped by a configured I/O error action.
    IoError,
    /// Execution explicitly paused.
    Paused,
    /// Execution stopped after migration.
    PostMigrate,
    /// VM started with `-S` and has not executed.
    Prelaunch,
    /// Restoring VM state.
    RestoreVm,
    /// Guest execution is running.
    Running,
    /// Saving VM state.
    SaveVm,
    /// Guest shut down under `-no-shutdown`.
    Shutdown,
    /// Guest entered hardware suspend.
    Suspended,
    /// Watchdog action paused execution.
    Watchdog,
    /// Guest panic paused execution.
    GuestPanicked,
    /// COLO checkpoint save or restore state.
    Colo,
}

impl QmpRunStateKind {
    fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "debug" => Self::Debug,
            "finish-migrate" => Self::FinishMigrate,
            "inmigrate" => Self::InMigrate,
            "internal-error" => Self::InternalError,
            "io-error" => Self::IoError,
            "paused" => Self::Paused,
            "postmigrate" => Self::PostMigrate,
            "prelaunch" => Self::Prelaunch,
            "restore-vm" => Self::RestoreVm,
            "running" => Self::Running,
            "save-vm" => Self::SaveVm,
            "shutdown" => Self::Shutdown,
            "suspended" => Self::Suspended,
            "watchdog" => Self::Watchdog,
            "guest-panicked" => Self::GuestPanicked,
            "colo" => Self::Colo,
            _ => return None,
        })
    }
}

/// Exact contiguous `0..N` vCPU indexes returned by typed `query-cpus-fast`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpCpuTopology {
    cpu_indexes: Vec<u64>,
}

impl QmpCpuTopology {
    /// Returns the sorted configured vCPU indexes, exactly contiguous from zero.
    #[must_use]
    pub fn cpu_indexes(&self) -> &[u64] {
        &self.cpu_indexes
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn from_test_cpu_indexes(cpu_indexes: Vec<u64>) -> Self {
        Self { cpu_indexes }
    }
}

/// Supported QMP command kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpCommandKind {
    /// QMP capability negotiation.
    Capabilities,
    /// VMState snapshot save.
    SaveVm,
    /// VMState snapshot load.
    LoadVm,
    /// VMState snapshot deletion.
    DeleteSnapshot,
    /// Snapshot job status query.
    QueryJobs,
    /// Release a concluded snapshot job.
    JobDismiss,
    /// VM run-state query.
    QueryStatus,
    /// Stop guest execution.
    Stop,
    /// Resume guest execution.
    Cont,
    /// Authenticated terminal lifecycle completion.
    CompleteTerminalLifecycle,
    /// Configured vCPU topology query.
    QueryCpusFast,
    /// QEMU-owned hot-fork readiness query.
    QueryHotForkReadiness,
    /// QEMU-owned hot-fork active-thread inventory query.
    QueryHotForkThreadInventory,
    /// QEMU-owned hot-fork RCU-state inventory query.
    QueryHotForkRcuInventory,
    /// QEMU-owned hot-fork AioContext activity inventory query.
    QueryHotForkAioInventory,
    /// QEMU-owned hot-fork allocated-AIO-handler inventory query.
    QueryHotForkAioHandlerInventory,
    /// QEMU-owned hot-fork allocated-block-backend inventory query.
    QueryHotForkBlockBackendInventory,
    /// QEMU-owned sealed plugin-resource inventory query.
    QueryHotForkPluginResourceInventory,
    /// QEMU-owned hot-fork allocated-bottom-half inventory query.
    QueryHotForkBottomHalfInventory,
    /// QEMU-owned hot-fork mutex ownership inventory query.
    QueryHotForkMutexInventory,
    /// QEMU-owned hot-fork live-timer inventory query.
    QueryHotForkTimerInventory,
    /// Graceful QEMU quit.
    Quit,
}

impl QmpCommandKind {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Capabilities => QMP_CAPABILITIES_COMMAND,
            Self::SaveVm => QMP_SNAPSHOT_SAVE_COMMAND,
            Self::LoadVm => QMP_SNAPSHOT_LOAD_COMMAND,
            Self::DeleteSnapshot => QMP_SNAPSHOT_DELETE_COMMAND,
            Self::QueryJobs => QMP_QUERY_JOBS_COMMAND,
            Self::JobDismiss => QMP_JOB_DISMISS_COMMAND,
            Self::QueryStatus => QMP_QUERY_STATUS_COMMAND,
            Self::Stop => QMP_STOP_COMMAND,
            Self::Cont => QMP_CONT_COMMAND,
            Self::CompleteTerminalLifecycle => QMP_COMPLETE_TERMINAL_LIFECYCLE_COMMAND,
            Self::QueryCpusFast => QMP_QUERY_CPUS_FAST_COMMAND,
            Self::QueryHotForkReadiness => QMP_QUERY_HOT_FORK_READINESS_COMMAND,
            Self::QueryHotForkThreadInventory => QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND,
            Self::QueryHotForkRcuInventory => QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND,
            Self::QueryHotForkAioInventory => QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND,
            Self::QueryHotForkAioHandlerInventory => {
                QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND
            }
            Self::QueryHotForkBlockBackendInventory => {
                QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND
            }
            Self::QueryHotForkPluginResourceInventory => {
                QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND
            }
            Self::QueryHotForkBottomHalfInventory => {
                QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND
            }
            Self::QueryHotForkMutexInventory => QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND,
            Self::QueryHotForkTimerInventory => QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND,
            Self::Quit => QMP_QUIT_COMMAND_NAME,
        }
    }
}

/// Successful response for a typed QMP command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpCommandComplete {
    /// Command that completed successfully.
    pub command: QmpCommandKind,
}

#[derive(Clone, Debug, PartialEq)]
struct QmpCommandReturn {
    command: QmpCommandKind,
    value: Value,
}

#[path = "qmp/error.rs"]
mod error;

pub use error::QmpError;

enum QmpCommand<'a> {
    Capabilities,
    SaveVm {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    LoadVm {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    DeleteSnapshot {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    QueryJobs,
    JobDismiss {
        job_id: &'a str,
    },
    QueryStatus,
    Stop,
    Cont,
    CompleteTerminalLifecycle {
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    },
    QueryCpusFast,
    QueryHotForkReadiness,
    QueryHotForkThreadInventory,
    QueryHotForkRcuInventory,
    QueryHotForkAioInventory,
    QueryHotForkAioHandlerInventory,
    QueryHotForkBlockBackendInventory,
    QueryHotForkPluginResourceInventory,
    QueryHotForkBottomHalfInventory,
    QueryHotForkMutexInventory,
    QueryHotForkTimerInventory,
    Quit,
}

impl QmpCommand<'_> {
    const fn kind(&self) -> QmpCommandKind {
        match self {
            Self::Capabilities => QmpCommandKind::Capabilities,
            Self::SaveVm { .. } => QmpCommandKind::SaveVm,
            Self::LoadVm { .. } => QmpCommandKind::LoadVm,
            Self::DeleteSnapshot { .. } => QmpCommandKind::DeleteSnapshot,
            Self::QueryJobs => QmpCommandKind::QueryJobs,
            Self::JobDismiss { .. } => QmpCommandKind::JobDismiss,
            Self::QueryStatus => QmpCommandKind::QueryStatus,
            Self::Stop => QmpCommandKind::Stop,
            Self::Cont => QmpCommandKind::Cont,
            Self::CompleteTerminalLifecycle { .. } => QmpCommandKind::CompleteTerminalLifecycle,
            Self::QueryCpusFast => QmpCommandKind::QueryCpusFast,
            Self::QueryHotForkReadiness => QmpCommandKind::QueryHotForkReadiness,
            Self::QueryHotForkThreadInventory => QmpCommandKind::QueryHotForkThreadInventory,
            Self::QueryHotForkRcuInventory => QmpCommandKind::QueryHotForkRcuInventory,
            Self::QueryHotForkAioInventory => QmpCommandKind::QueryHotForkAioInventory,
            Self::QueryHotForkAioHandlerInventory => {
                QmpCommandKind::QueryHotForkAioHandlerInventory
            }
            Self::QueryHotForkBlockBackendInventory => {
                QmpCommandKind::QueryHotForkBlockBackendInventory
            }
            Self::QueryHotForkPluginResourceInventory => {
                QmpCommandKind::QueryHotForkPluginResourceInventory
            }
            Self::QueryHotForkBottomHalfInventory => {
                QmpCommandKind::QueryHotForkBottomHalfInventory
            }
            Self::QueryHotForkMutexInventory => QmpCommandKind::QueryHotForkMutexInventory,
            Self::QueryHotForkTimerInventory => QmpCommandKind::QueryHotForkTimerInventory,
            Self::Quit => QmpCommandKind::Quit,
        }
    }

    fn request(&self) -> Value {
        match self {
            Self::Capabilities => json!({
                "execute": QMP_CAPABILITIES_COMMAND,
                "arguments": {
                    "enable": ["oob"],
                },
            }),
            Self::SaveVm { tag, job_id } => {
                snapshot_request(QMP_SNAPSHOT_SAVE_COMMAND, job_id, tag)
            }
            Self::LoadVm { tag, job_id } => {
                snapshot_request(QMP_SNAPSHOT_LOAD_COMMAND, job_id, tag)
            }
            Self::DeleteSnapshot { tag, job_id } => json!({
                "execute": QMP_SNAPSHOT_DELETE_COMMAND,
                "arguments": {
                    "job-id": job_id,
                    "tag": tag.as_str(),
                    "devices": [QMP_SNAPSHOT_VMSTATE_DEVICE],
                },
            }),
            Self::QueryJobs => json!({
                "execute": QMP_QUERY_JOBS_COMMAND,
            }),
            Self::JobDismiss { job_id } => json!({
                "execute": QMP_JOB_DISMISS_COMMAND,
                "arguments": { "id": job_id },
            }),
            Self::QueryStatus => json!({
                "execute": QMP_QUERY_STATUS_COMMAND,
            }),
            Self::Stop => json!({
                "execute": QMP_STOP_COMMAND,
            }),
            Self::Cont => json!({
                "execute": QMP_CONT_COMMAND,
            }),
            Self::CompleteTerminalLifecycle {
                action,
                evidence,
                process_generation,
            } => json!({
                "execute": QMP_COMPLETE_TERMINAL_LIFECYCLE_COMMAND,
                "arguments": {
                    "action-sha256": action.to_hex(),
                    "evidence-sha256": evidence.to_hex(),
                    "process-generation": process_generation,
                },
            }),
            Self::QueryCpusFast => json!({
                "execute": QMP_QUERY_CPUS_FAST_COMMAND,
            }),
            Self::QueryHotForkReadiness => json!({
                "execute": QMP_QUERY_HOT_FORK_READINESS_COMMAND,
            }),
            Self::QueryHotForkThreadInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkRcuInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkAioInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkAioHandlerInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkBlockBackendInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkPluginResourceInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkBottomHalfInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkMutexInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkTimerInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND,
            }),
            Self::Quit => json!({
                "execute": QMP_QUIT_COMMAND_NAME,
            }),
        }
    }
}

fn snapshot_request(command: &'static str, job_id: &str, tag: &QmpSnapshotTag) -> Value {
    json!({
        "execute": command,
        "arguments": {
            "job-id": job_id,
            "tag": tag.as_str(),
            "vmstate": QMP_SNAPSHOT_VMSTATE_DEVICE,
            "devices": [QMP_SNAPSHOT_VMSTATE_DEVICE],
        },
    })
}

fn snapshot_job_id(job_action: &'static str, tag: &QmpSnapshotTag) -> String {
    format!("crucible-{job_action}-{}", tag.as_str())
}

fn command_error(command: QmpCommandKind, error: &Value) -> QmpError {
    let class = error
        .get("class")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_owned();
    let description = error
        .get("desc")
        .and_then(Value::as_str)
        .unwrap_or("QMP command failed")
        .to_owned();
    QmpError::Command {
        command,
        class,
        description,
    }
}
