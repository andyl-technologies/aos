//! Concrete Guest-owned execution trees, PTYs, and durable terminal effects.

use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Instant;

use aos_sandbox_guest_protocol::openssh_gate::{OpenSshGateObserveRequestV1, OpenSshGateReadbackV1};
use crate::protected_entry::{GuestOperationEffectsV1, ProtectedGuestAgentErrorV1};
use aos_sandbox_guest_protocol::{
    AgentExecutionOperationV1, AgentExecutionPhaseV1, AgentFeatureV1, AgentOperationRequestV1,
    AgentRuntimeBindingV1,
};
use aos_sandbox_model::{
    DecodeLimits, ExecutionId, ExecutionOutputModeV1, ExecutionTerminalModeV1, ObjectDigest,
    decode_execution_spec_v1, execution_spec_digest_v1,
};
use rustix::fs::{Mode, OFlags, fchown, open};
use rustix::io;
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::bridge::AttachBridge;
use crate::gate::GuestOpenSshGate;
use crate::ledger::{
    AttachIoShapeV3, Ledger, ProcessRecord, Reservation, StoredOutcome, runtime_identity,
};

const MAX_SPECIFICATION_BYTES: usize = 15 * 1_048_576;

/// Reports a failed concrete guest-local process or ledger operation.
#[derive(Debug, thiserror::Error)]
pub enum GuestProcessEffectErrorV1 {
    /// A kernel or filesystem operation failed.
    #[error("guest process I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A rustix operation failed.
    #[error("guest process syscall failed: {0}")]
    Syscall(#[from] io::Errno),
    /// A protected Unix sequenced-packet operation failed.
    #[error("guest attach bridge failed: {0}")]
    Bridge(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// A retained original monitor socket returned an uncertain native poll state.
    #[error("original monitor socket liveness is ambiguous: {0:?}")]
    MonitorPoll(rustix::event::PollFlags),
    /// The retained owner-created SSH gate failed its physical terminal boundary.
    #[error("original SSH gate retirement failed: {0}")]
    OpenSshPhysical(#[from] crate::openssh_gate_linux::OpenSshGatePhysicalErrorV1),
    /// Enforcing Guest ownership or retained kernel custody failed.
    #[error("guest execution confinement failed: {0}")]
    Confinement(#[from] aos_linux_descriptors::Error),
    /// The protected state directory or one of its records is unsafe.
    #[error("guest effect ledger is not root-protected")]
    UnprotectedLedger,
    /// Durable records conflict or are malformed.
    #[error("guest effect ledger identity conflict")]
    LedgerConflict,
    /// A prior effect was reserved but its outcome was not durably observed.
    #[error("guest effect outcome is ambiguous; effect will not be replayed")]
    AmbiguousEffect,
    /// The request does not match the provisioned execution target.
    #[error("guest execution request does not match the provisioned runtime")]
    InvalidRequest,
    /// The requested operation is not supported by the current local state.
    #[error("guest execution effect is unavailable: {0}")]
    Unavailable(&'static str),
}

mod timeout;
mod startup;
mod ssh_lifetime;

/// Retains actual startup custody and its first failure until whole Guest death.
///
/// This stays on the startup thread. Execution and monitor errors use their
/// separate shareable error type and cannot carry a failed native mapping.
pub struct GuestProcessStartupErrorV1 {
    topology: Option<Box<aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1>>,
    ledger: Option<Ledger>,
    bridge: Option<AttachBridge>,
    cause: Option<Box<GuestProcessEffectErrorV1>>,
}

/// Identifies an actual execution whose native and IO owners physically retired.
///
/// Only the original process owner's completed retirement constructs this
/// non-clone token. It permits no execution, signal, cancellation or renewal;
/// the Agent uses it solely to restore its original receive-rights mode after
/// that same execution has no native residency left.
pub struct OriginalExecutionTransportRetirementV2 {
    execution: ExecutionId,
    runtime: [u8; 32],
}

impl OriginalExecutionTransportRetirementV2 {
    pub(crate) fn matches(&self, execution: ExecutionId, runtime: &AgentRuntimeBindingV1) -> bool {
        self.execution == execution && self.runtime == runtime_identity(runtime)
    }
}

pub(crate) use timeout::{LiveProcess, LiveProcessRegistryV1};
use timeout::{PendingExecutionChildLoanV1, PendingExecutionChildV1, StartupInputLoanV1};
pub(super) use timeout::{poll_original_execution_timeouts_v1, publish_original_execution_timeout_v1,
    settle_original_execution_timeout_v1};

/// Owns durable guest execution records and the currently attached children.
pub struct GuestProcessEffectsV1 {
    ledger: Ledger,
    bridge: AttachBridge,
    execution_root: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    _payload_cgroup: aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1,
    _runtime_topology: Box<aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1>,
    gate: Option<GuestOpenSshGate>,
    gate_installation: Option<crate::gate::GuestOpenSshInstallOriginalV1>,
    transport_retirement: Option<OriginalExecutionTransportRetirementV2>,
    quiesced: bool,
}

impl GuestProcessEffectsV1 {
    /// Opens the fixed root-owned guest-local effect ledger.
    ///
    /// # Errors
    ///
    /// Returns the owning startup error when native topology or the fixed
    /// ledger/Bridge cannot complete. Every failed startup prefix stays owned.
    pub fn open() -> Result<Self, Box<GuestProcessStartupErrorV1>> {
        GuestProcessStartupErrorV1::open()
    }

    fn apply_effect(
        &mut self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        deadline: Instant,
        mut capture: Option<&mut crate::capture::GuestCaptureAuthorizeOriginalV2>,
        ssh_plan: Option<&aos_sandbox_guest_protocol::openssh_receiving::OpenSshDescendantPlanDataV1>,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        check_deadline(deadline)?;
        match request.operation() {
            AgentExecutionOperationV1::Authorize {
                execution,
                specification_bytes,
                specification_digest,
                admission_commitment,
                principal,
                audit,
            } => {
                self.transport_retirement = None;
                if self.quiesced || admission_commitment.as_bytes() == &[0; 32] {
                    return Err(GuestProcessEffectErrorV1::InvalidRequest);
                }
                let specification = decode_execution_spec_v1(
                    specification_bytes,
                    DecodeLimits {
                        maximum_bytes: MAX_SPECIFICATION_BYTES,
                        maximum_collection_items: 65_536,
                        maximum_total_items: 262_144,
                        maximum_byte_string_bytes: MAX_SPECIFICATION_BYTES,
                        maximum_text_bytes: 1_048_576,
                        maximum_depth: 128,
                    },
                )
                .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
                if specification.execution() != *execution
                    || execution_spec_digest_v1(&specification) != *specification_digest
                    || specification.principal() != *principal
                    || specification.audit() != *audit
                    || specification.target().sandbox() != runtime.sandbox()
                    || specification.target().incarnation() != runtime.incarnation()
                    || specification.target().assignment_epoch() != runtime.assignment_epoch()
                    || specification.target().assignment_digest() != runtime.assignment_digest()
                    || specification.target().namespace_generation()
                        != runtime.namespace_generation()
                    || specification.target().payload_boot_id().as_bytes()
                        != runtime.payload_boot_id()
                {
                    return Err(GuestProcessEffectErrorV1::InvalidRequest);
                }

                crate::capture::require_capture_shape(
                    specification.io().output_mode(), specification.io().terminal_mode(),
                    capture.is_some(),
                )?;
                if let Some(plan) = ssh_plan {
                    plan.require_request_data_v1(runtime, request)
                        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
                    if capture.is_some()
                        || !matches!(specification.io().output_mode(), ExecutionOutputModeV1::Stream)
                        || !matches!(specification.io().access_route(),
                            aos_sandbox_model::ExecutionAccessRouteV1::OpenSsh(_))
                    {
                        return Err(GuestProcessEffectErrorV1::InvalidRequest);
                    }
                }
                if let Some(original) = capture.as_deref_mut() {
                    original.validate_pipes_once(request)?;
                }

                let credentials = specification.command().credentials();
                check_deadline(deadline)?;
                self.start_process(
                    *execution,
                    specification_bytes,
                    credentials.user_id(),
                    credentials.primary_group_id(),
                    specification.io().terminal_mode() == ExecutionTerminalModeV1::Pty,
                    match (
                        specification.io().output_mode(),
                        specification.io().access_route(),
                    ) {
                        (
                            ExecutionOutputModeV1::Stream,
                            aos_sandbox_model::ExecutionAccessRouteV1::OpenSsh(_),
                        ) => Some(
                            if specification.io().terminal_mode() == ExecutionTerminalModeV1::Pty {
                                AttachIoShapeV3::Pty
                            } else {
                                AttachIoShapeV3::Stream
                            },
                        ),
                        _ => None,
                    },
                    runtime,
                    *request.operation_id().as_bytes(),
                    *principal.as_bytes(),
                    *audit.as_bytes(),
                    specification.io().disconnect_policy()
                        == aos_sandbox_model::ExecutionDisconnectPolicyV1::Cancel,
                    deadline,
                    specification.timeout().nanoseconds(),
                    *specification_digest,
                    capture,
                    ssh_plan.copied(),
                )
            }
            AgentExecutionOperationV1::ResizeTerminal {
                execution,
                rows,
                columns,
            } => self.resize(*execution, *rows, *columns, runtime),
            AgentExecutionOperationV1::Signal {
                execution,
                signal_code,
            } => self.signal(*execution, *signal_code, runtime, deadline),
            AgentExecutionOperationV1::Cancel { execution } => {
                self.cancel(*execution, runtime, deadline)
            }
            AgentExecutionOperationV1::Observe { execution } => self.observe(*execution, runtime),
            AgentExecutionOperationV1::BeginQuiesce => {
                if self.ledger.has_ambiguous_operation(request)? {
                    return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
                }
                for record in self.ledger.processes()? {
                    if record.terminal.is_none() {
                        let live = self
                            .ledger
                            .live()
                            .lock()
                            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
                        let process = live
                            .get(&record.execution)
                            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
                        if !process.tree.empty_and_exited()? {
                            return Err(GuestProcessEffectErrorV1::Unavailable(
                                "active execution trees prevent the local quiesce barrier",
                            ));
                        }
                    }
                }
                self.ledger.write_quiesced(true)?;
                self.quiesced = true;
                Ok(outcome(AgentExecutionPhaseV1::Quiesced, 9, b"quiesced"))
            }
            AgentExecutionOperationV1::EndQuiesce => {
                self.ledger.write_quiesced(false)?;
                self.quiesced = false;
                Ok(outcome(AgentExecutionPhaseV1::Ready, 10, b"ready"))
            }
        }
    }

    fn start_process(
        &mut self,
        execution: ExecutionId,
        specification: &[u8],
        uid: u32,
        gid: u32,
        pty: bool,
        attach_io: Option<AttachIoShapeV3>,
        runtime: &AgentRuntimeBindingV1,
        operation: [u8; 16],
        principal: [u8; 16],
        audit: [u8; 16],
        cancel_on_disconnect: bool,
        deadline: Instant,
        timeout_nanoseconds: u64,
        specification_digest: ObjectDigest,
        mut capture: Option<&mut crate::capture::GuestCaptureAuthorizeOriginalV2>,
        ssh_plan: Option<aos_sandbox_guest_protocol::openssh_receiving::OpenSshDescendantPlanDataV1>,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let helper = std::env::current_exe()?.with_file_name("aos-sandbox-guest-exec");
        let mut command = Command::new(helper);
        // This exact measured Owner helper remains root and cannot consume the
        // spec until its proper-descendant membership and durable row exist.
        command.env_clear();
        command.stdin(Stdio::piped());
        if let Some(original) = capture.as_deref_mut() {
            original.configure_command(&mut command)?;
        } else if pty {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        } else {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }

        // Receive all startup Files before a later native operation can fail.
        let mut pending_loan = PendingExecutionChildLoanV1::enter(self.ledger.live())?;
        let pending = pending_loan.original.as_mut()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        pending.pty_result = Some((|| {
            if pty {
                pending.pty_master = Some(openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?);
                let master = pending.pty_master.as_ref().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
                grantpt(master)?;
                unlockpt(master)?;
                pending.pty_name = Some(ptsname(master, Vec::new())?);
                let path = pending.pty_name.as_ref().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
                pending.pty_slave = Some(open(path.as_c_str(), OFlags::RDWR | OFlags::NOCTTY, Mode::empty())?);
                fchown(pending.pty_slave.as_ref().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?,
                    Some(rustix::process::Uid::from_raw(uid)), Some(rustix::process::Gid::from_raw(gid)))?;
                command.arg(path.to_string_lossy().as_ref());
                // Only this completed chown-only temporary has no further debt.
                drop(pending.pty_slave.take());
            } else { command.process_group(0); }
            Ok(())
        })());
        if !pending.pty_result.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        pending.lifetime.start_once(timeout_nanoseconds)
            .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if pending.lifetime.is_expired().map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)? {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }

        let (origin, timeout, lifetime_deadline) = pending.lifetime.origin_data_v1()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        // The helper learns the SAME immutable origin before it can block on
        // parent admission. These private arguments confer no Tenant authority;
        // the later exact authenticated specification must match all three.
        command.arg("--lifetime-v1").arg(origin.to_string())
            .arg(timeout.to_string()).arg(lifetime_deadline.to_string());

        // Capture's same command remains in its entered protocol original.
        // The actual returned Child moves before any later fallible admission.
        if let Some(original) = capture.as_deref_mut() {
            original.command = Some(command);
            original.spawned = Some(original.command.as_mut()
                .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?.spawn());
            match original.spawned.as_ref() {
                Some(Ok(_)) => pending.spawned = original.spawned.take(),
                _ => return Err(GuestProcessEffectErrorV1::AmbiguousEffect),
            }
        } else {
            pending.command = Some(command);
            pending.spawned = Some(pending.command.as_mut()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?.spawn());
        }
        let child = pending.spawned.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        pending.input = child.stdin.take();
        pending.lifetime.bind_child_once(child)
            .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let (origin, timeout, lifetime_deadline) = pending.lifetime.origin_data_v1()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let lifetime_record = crate::ledger::ExecutionLifetimeRecordV1 {
            version: 1, origin_boottime_nanoseconds: origin, timeout_nanoseconds: timeout,
            deadline_boottime_nanoseconds: lifetime_deadline,
            specification_digest: *specification_digest.as_bytes(),
        };
        let pid = child.id();
        pending.tree = Some(pending.tree_native.capture_once(
            &self.execution_root, execution.as_bytes(), pid));
        let tree = pending.tree.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let start_ticks = tree.leader_start_ticks_retaining_v1(&mut pending.start_ticks_native)?;
        let record = ProcessRecord {
            version: 3,
            runtime: runtime_identity(runtime), operation, execution: *execution.as_bytes(),
            incarnation: *runtime.incarnation().as_bytes(),
            assignment_epoch: runtime.assignment_epoch().get(), principal, audit, uid, pid, start_ticks,
            pty: pending.pty_name.is_some(), attach_io, cgroup: Some(tree.kernel_id()),
            cancel_on_disconnect: Some(cancel_on_disconnect),
            lifetime: Some(lifetime_record.clone()), timed_out: false,
            canceled: false, terminal: None, terminal_waitstatus: None,
        };
        pending.record = Some(record.clone());
        pending.record_result = Some(self.ledger.write_process_retaining_v1(execution, &record,
            &mut pending.record_native));
        if !pending.record_result.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        pending.membership = Some(tree.require_leader_retaining_v1(&mut pending.membership_native));
        if !pending.membership.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        let mut live = self.ledger.live().lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let mut completed = pending_loan.original.take()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let (child, tree, input) = match (completed.spawned.take(), completed.tree.take(), completed.input.take()) {
            (Some(Ok(child)), Some(Ok(tree)), Some(input)) => (child, tree, input),
            (spawned, tree, input) => {
                completed.spawned = spawned; completed.tree = tree; completed.input = input;
                pending_loan.original = Some(completed);
                return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
            }
        };
        let lifetime = std::mem::take(&mut completed.lifetime);
        live.insert(*execution.as_bytes(), Box::new(LiveProcess {
            child, lifetime, lifetime_record, record: record.clone(), startup_input: None, startup_write: None, io_registration: None,
            timeout_record: None, timeout_native: None, timeout_terminal: None, timeout_finish: None,
            normal_terminal: None, normal_finish: None,
            terminal_native: crate::ledger::RetainedProcessRecordWriteV1::new(),
            pty_master: completed.pty_master.take().map(std::sync::Arc::new), tree: std::sync::Arc::new(tree),
            ssh_plan, ssh_standing: None,
        }));
        drop(live);
        drop(pending_loan);
        let mut ordinary_input = StartupInputLoanV1::new(self.ledger.live(), *execution.as_bytes());
        let input = if let Some(original) = capture.as_deref_mut() {
            original.input = Some(input);
            original.input.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
        } else {
            ordinary_input.set(input);
            ordinary_input.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
        };
        let written = write_specification(input, specification, deadline, &record);
        let positive_write = written.is_ok();
        self.ledger.live().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(execution.as_bytes()).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
            .startup_write = Some(written);
        if !positive_write { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        let mut live = self
            .ledger
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let process = live
            .get_mut(execution.as_bytes())
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let master = process.pty_master.as_ref().map(std::sync::Arc::clone);
        let original = if capture.is_some() {
            None
        } else if master.is_some() {
            Some(crate::bridge::AttachIoRegistrationOriginalV1::new(None, None, None))
        } else {
            Some(crate::bridge::AttachIoRegistrationOriginalV1::new(ordinary_input.take(),
                process.child.stdout.take(), process.child.stderr.take()))
        };
        let mut registration = timeout::IoRegistrationLoanV1 {
            registry: self.ledger.live(), execution: *execution.as_bytes(), original,
        };
        drop(live);
        if let Some(original) = registration.original.as_mut() {
            self.bridge.register_original_once(*execution.as_bytes(),
                master.as_ref().map(|master| master.as_ref()), original)?;
        }
        drop(registration);
        loop {
            check_deadline(deadline)?;
            let mut live = self
                .ledger
                .live()
                .lock()
                .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
            let process = live
                .get_mut(execution.as_bytes())
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            if process.lifetime.is_expired().map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)? {
                return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
            }
            let initialized = process.tree.matches(&record)? || process.child.try_wait()?.is_some();
            drop(live);
            if initialized {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        drop(ordinary_input);
        self.observe(execution, runtime)
    }

    fn bound_process(
        &self,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<ProcessRecord, GuestProcessEffectErrorV1> {
        let record = self.ledger.read_process(execution)?;
        if record.runtime != runtime_identity(runtime) {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        Ok(record)
    }

    fn resize(
        &mut self,
        execution: ExecutionId,
        rows: u16,
        columns: u16,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let record = self.bound_process(execution, runtime)?;
        // Public Resize applies to the original admitted PTY, independently of
        // whether that execution was eligible for an OpenSSH attach route.
        if !record.pty {
            return Err(GuestProcessEffectErrorV1::Unavailable("PTY is not live"));
        }
        let live = self
            .ledger
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let process = live
            .get(execution.as_bytes())
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        process.tree.require_original_scope(&record)?;
        if process.tree.empty_and_exited()? {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "PTY execution has exited",
            ));
        }
        let master = process
            .pty_master
            .as_ref()
            .ok_or(GuestProcessEffectErrorV1::Unavailable(
                "PTY master cannot be reattached after agent restart",
            ))?;
        tcsetwinsize(
            master,
            Winsize {
                ws_row: rows,
                ws_col: columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?;
        let mut geometry = [0_u8; 4];
        geometry[..2].copy_from_slice(&rows.to_be_bytes());
        geometry[2..].copy_from_slice(&columns.to_be_bytes());
        Ok(outcome(AgentExecutionPhaseV1::Running, 2, &geometry))
    }

    fn signal(
        &mut self,
        execution: ExecutionId,
        code: u8,
        runtime: &AgentRuntimeBindingV1,
        deadline: Instant,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let record = self.bound_process(execution, runtime)?;
        let live = self
            .ledger
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let process = live
            .get(execution.as_bytes())
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let tree = std::sync::Arc::clone(&process.tree);
        drop(live);
        tree.require_original_scope(&record)?;
        tree.signal_with_lifetime_cut_v1(code, deadline, || tree.require_original_scope(&record),
            || tree.require_original_scope(&record))?;
        // The surrounding operation reservation stays indeterminate if any
        // signal or freezer restoration failed; no partial send is replayed.
        Ok(outcome(AgentExecutionPhaseV1::Running, 3, &[code]))
    }

    fn cancel(
        &mut self,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
        deadline: Instant,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let record = self.bound_process(execution, runtime)?;
        let result = cancel_owned_execution(&self.ledger, execution, deadline)?;
        match self.finish_execution(execution)? {
            crate::bridge::OriginalIoDispositionV1::Disposed => Ok(result),
            crate::bridge::OriginalIoDispositionV1::Pending => Ok(outcome(
                AgentExecutionPhaseV1::Running, 5, &record.pid.to_be_bytes(),
            )),
        }
    }

    fn finish_execution(
        &mut self,
        execution: ExecutionId,
    ) -> Result<crate::bridge::OriginalIoDispositionV1, GuestProcessEffectErrorV1> {
        let original_runtime = {
            let live = self.ledger.live().lock()
                .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
            live.get(execution.as_bytes()).map(|process| process.record.runtime)
        };
        let result = self.finish_execution_inner_v2(execution);
        if matches!(result, Ok(crate::bridge::OriginalIoDispositionV1::Disposed)) {
            let live = self.ledger.live().lock()
                .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
            if !live.contains_key(execution.as_bytes()) {
                if let Some(runtime) = original_runtime {
                    // Only this actual owner crossed all native/monitor/gate
                    // afters and was physically removed. Historical absence
                    // or a terminal DATA row cannot construct this token.
                    self.transport_retirement = Some(OriginalExecutionTransportRetirementV2 {
                        execution, runtime,
                    });
                }
            }
        }
        result
    }

    fn finish_execution_inner_v2(
        &mut self,
        execution: ExecutionId,
    ) -> Result<crate::bridge::OriginalIoDispositionV1, GuestProcessEffectErrorV1> {
        let result = (|| {
            if self.gate_installation.as_ref().is_some_and(|original| original.failure().is_some()) {
                if let Some(original) = self.gate_installation.as_mut() {
                    let _ = original.poll_failed_retirement_v1(&self.ledger);
                }
                // A failed install can own a child/file prefix even without a
                // published Gate. It cannot counterfeit terminal disposition.
                return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
            }
            // Close the I/O factory immediately, but retain an already consumed
            // original monitor long enough to report the actual terminal status.
            let disposition = self.bridge.finish_execution(*execution.as_bytes())?;
            if disposition == crate::bridge::OriginalIoDispositionV1::Disposed
                && self
                    .gate
                    .as_ref()
                    .is_some_and(|gate| gate.execution() == *execution.as_bytes())
            {
                if !self.gate.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
                    .poll_original_retirement_v1(&self.ledger)?
                {
                    return Ok(crate::bridge::OriginalIoDispositionV1::Pending);
                }
                self.gate = None;
            }
            Ok(disposition)
        })();
        let mut live = self.ledger.live().lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let Some(process) = live.get_mut(execution.as_bytes()) else { return result; };
        if process.timeout_terminal.is_some() {
            drop(live);
            return settle_original_execution_timeout_v1(&self.ledger, *execution.as_bytes(), result);
        }
        if process.normal_terminal.is_none() { return result; }
        if process.normal_finish.is_some() {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        if matches!(result, Ok(crate::bridge::OriginalIoDispositionV1::Pending)) {
            if process.normal_terminal.as_ref().is_some_and(Result::is_err)
                || process.startup_write.as_ref().is_some_and(Result::is_err)
                || process.io_registration.as_ref().is_some_and(|original| original.failure().is_some())
            { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
            return Ok(crate::bridge::OriginalIoDispositionV1::Pending);
        }
        process.normal_finish = Some(result.map(|_| ()));
        if process.normal_terminal.as_ref().is_some_and(Result::is_err)
            || !process.normal_finish.as_ref().is_some_and(Result::is_ok)
            || process.startup_write.as_ref().is_some_and(Result::is_err)
            || process.io_registration.as_ref().is_some_and(|original| original.failure().is_some())
        { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        // This exact owner was recursively empty and reaped before its native
        // terminal write. Its independently owed bridge posts now also passed.
        live.remove(execution.as_bytes());
        Ok(crate::bridge::OriginalIoDispositionV1::Disposed)
    }

    fn observe(
        &mut self,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let record = self.bound_process(execution, runtime)?;
        if let Some(result) = observe_owned_terminal(&self.ledger, execution)? {
            if self.finish_execution(execution)? == crate::bridge::OriginalIoDispositionV1::Disposed {
                return Ok(result);
            }
        }
        // A live descendant or retained consumed monitor keeps the same
        // execution occupied. Pending disposal is not a sticky failure.
        Ok(outcome(
            AgentExecutionPhaseV1::Running,
            5,
            &record.pid.to_be_bytes(),
        ))
    }
}

impl GuestProcessEffectsV1 {
    fn service_original_timeouts(&mut self) {
        // Failed startup still owns the actual native child/receipt prefix.
        // The main keeper advances its negative reap independently of the
        // healthy effect barrier; its standing slot already owns containment.
        if let Some(original) = self.gate_installation.as_mut()
            .filter(|original| original.failure().is_some())
        {
            let _ = original.poll_failed_retirement_v1(&self.ledger);
        }
        let barrier = self.ledger.effect_barrier();
        let Ok(_current) = barrier.lock() else { return; };
        if let Ok(Some(execution)) = poll_original_execution_timeouts_v1(&self.ledger) {
            if publish_original_execution_timeout_v1(&self.ledger, execution).is_ok() {
                let _ = self.finish_execution(ExecutionId::from_bytes(execution));
            }
        }
        // The ordinary disconnect law is unchanged: only the original true
        // cancel_on_disconnect can cancel, while Continue remains live until D.
        if let Ok(Some(execution)) = self.bridge.prune_original_disconnects_v1(&self.ledger) {
            let _ = self.finish_execution(ExecutionId::from_bytes(execution));
        }
        // The one actually owned gate can finish a nonblocking daemon reap
        // without waiting for another Agent request. This is an inspection of
        // the same resident owner, never a reconstructed PID or process list.
        if let Some(execution) = self.gate.as_ref().map(GuestOpenSshGate::execution) {
            let terminal = self.ledger.live().lock().is_ok_and(|live|
                live.get(&execution).is_some_and(|process|
                    process.normal_terminal.as_ref().is_some_and(Result::is_ok)
                        || process.timeout_terminal.as_ref().is_some_and(Result::is_ok)));
            if terminal {
                let _ = self.finish_execution(ExecutionId::from_bytes(execution));
            }
        }
    }

    fn apply_operation(
        &mut self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
        mut capture: Option<&mut crate::capture::GuestCaptureAuthorizeOriginalV2>,
        ssh_plan: Option<&aos_sandbox_guest_protocol::openssh_receiving::OpenSshDescendantPlanDataV1>,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        let barrier = self.ledger.effect_barrier();
        let _current = project_effect_result_v2(
            barrier.lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict),
            capture.as_deref_mut(),
        )?;
        project_effect_result_v2(check_deadline(deadline), capture.as_deref_mut())?;
        let reservation = project_effect_result_v2(
            self.ledger.reserve(request, runtime, channel), capture.as_deref_mut(),
        )?;
        let stored = match reservation {
            Reservation::Fresh => {
                project_effect_result_v2(check_deadline(deadline), capture.as_deref_mut())?;
                let attempted = self.apply_effect(request, runtime, deadline, capture.as_deref_mut(), ssh_plan);
                let result = match attempted {
                    Ok(result) => result,
                    Err(cause) => {
                        if let Some(original) = capture.as_deref_mut() {
                            original.effect = Some(Err(cause));
                            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                        }
                        return Err(effect_error(cause));
                    }
                };
                let committed = self.ledger.complete(request, runtime, channel, result.clone());
                if let Err(cause) = committed {
                    if let Some(original) = capture.as_deref_mut() {
                        original.effect = Some(Err(cause));
                        return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
                    }
                    return Err(effect_error(cause));
                }
                result
            }
            Reservation::Replayed(result) => {
                if capture.is_some() || ssh_plan.is_some() {
                    return project_effect_result_v2(
                        Err(GuestProcessEffectErrorV1::AmbiguousEffect), capture.as_deref_mut(),
                    );
                }
                let expected_quiesced = match request.operation() {
                    AgentExecutionOperationV1::BeginQuiesce => Some(true),
                    AgentExecutionOperationV1::EndQuiesce => Some(false),
                    _ => None,
                };
                if expected_quiesced.is_some_and(|expected| expected != self.quiesced) {
                    return Err(effect_error(GuestProcessEffectErrorV1::LedgerConflict));
                }
                result
            }
        };
        project_effect_result_v2(check_deadline(deadline), capture.as_deref_mut())?;
        let phase = AgentExecutionPhaseV1::from_code(stored.phase).ok_or_else(|| {
            ProtectedGuestAgentErrorV1::EffectFailed("invalid durable phase".into())
        })?;
        if let Some(original) = capture {
            original.effect = Some(Ok(()));
        }
        Ok((phase, stored.result))
    }

}

impl GuestProcessEffectsV1 {
    fn observe_openssh_gate_engine_v1(
        &mut self,
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
        startup_deadline: Option<u64>,
    ) -> Result<OpenSshGateReadbackV1, ProtectedGuestAgentErrorV1> {
        let barrier = self.ledger.effect_barrier();
        let _current = barrier
            .lock()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        check_deadline(deadline).map_err(effect_error)?;
        request
            .validate()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::InvalidRequest))?;
        if self.quiesced {
            return Err(effect_error(GuestProcessEffectErrorV1::Unavailable(
                "guest is quiesced",
            )));
        }
        if self.gate.is_none() {
            if self.gate_installation.is_some() {
                return Err(effect_error(GuestProcessEffectErrorV1::AmbiguousEffect));
            }
            if !self
                .ledger
                .require_live_process(
                    &self
                        .ledger
                        .read_process_bytes(request.binding.execution_id)
                        .map_err(effect_error)?,
                )
                .map_err(effect_error)?
            {
                return Err(effect_error(GuestProcessEffectErrorV1::Unavailable(
                    "admitted process is not held by this agent",
                )));
            }
            self.gate_installation = Some(Default::default());
            self.gate = Some(
                GuestOpenSshGate::install_retaining_once(request, runtime, &self.ledger, deadline, startup_deadline,
                    &self._runtime_topology, &self._payload_cgroup, &self.execution_root,
                    self.gate_installation.as_mut().ok_or_else(|| effect_error(GuestProcessEffectErrorV1::AmbiguousEffect))?)
                    .map_err(effect_error)?,
            );
            // Every install native phase and owning daemon handoff succeeded.
            // Only this actual positive owner can retire the temporary prefix.
            self.gate_installation.take();
        }
        self.gate
            .as_mut()
            .ok_or_else(|| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?
            .observe(request, runtime, channel, &self.ledger, deadline)
            .map_err(effect_error)
    }

}

impl GuestOperationEffectsV1 for GuestProcessEffectsV1 {
    fn selected_openssh_startup_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.gate_installation.as_ref().and_then(|original| original.failure())
    }
    fn original_transport_retirement_v2(&self) -> Option<&OriginalExecutionTransportRetirementV2> {
        self.transport_retirement.as_ref()
    }
    fn require_original_start_reply_current_v1(&mut self, request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1) -> Result<(), ProtectedGuestAgentErrorV1>
    {
        let AgentExecutionOperationV1::Authorize { execution, specification_digest, .. } = request.operation()
            else { return Ok(()); };
        let mut live = self.ledger.live().lock()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        let process = live.get_mut(execution.as_bytes())
            .ok_or_else(|| effect_error(GuestProcessEffectErrorV1::AmbiguousEffect))?;
        if process.record.runtime != runtime_identity(runtime)
            || process.record.operation != *request.operation_id().as_bytes()
            || process.lifetime_record.specification_digest != *specification_digest.as_bytes()
            || process.timeout_record.is_some() || process.record.terminal.is_some()
            || process.lifetime.is_expired().map_err(|_| effect_error(GuestProcessEffectErrorV1::AmbiguousEffect))?
        {
            return Err(effect_error(GuestProcessEffectErrorV1::AmbiguousEffect));
        }
        Ok(())
    }

    fn has_original_execution_custody_v1(&self) -> bool {
        let live = self.ledger.live().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        !live.is_empty() || live.pending.is_some() || live.pending_lent || live.has_failed_input_v1()
    }

    fn service_original_deadlines_v1(&mut self) {
        self.service_original_timeouts();
    }

    fn supports(&self, feature: AgentFeatureV1) -> bool {
        matches!(
            feature,
            AgentFeatureV1::Readiness
                | AgentFeatureV1::ExecutionHandoff
                | AgentFeatureV1::ExecutionObservation
                | AgentFeatureV1::TerminalResize
                | AgentFeatureV1::ExecutionSignal
                | AgentFeatureV1::Quiesce
                | AgentFeatureV1::CapturePipeHandoffV2
        )
    }

    fn apply(
        &mut self, request: &AgentOperationRequestV1, runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest, deadline: Instant,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        self.apply_operation(request, runtime, channel, deadline, None, None)
    }

    fn apply_capture_v2(
        &mut self, request: &AgentOperationRequestV1, runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest, deadline: Instant,
        capture: &mut crate::capture::GuestCaptureAuthorizeOriginalV2,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        if !capture.matches_request(request) {
            return project_effect_result_v2(
                Err(GuestProcessEffectErrorV1::InvalidRequest), Some(capture),
            );
        }
        self.apply_operation(request, runtime, channel, deadline, Some(capture), None)
    }

    fn apply_ssh_authorize_v1(
        &mut self, request: &AgentOperationRequestV1, runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest, deadline: Instant,
        plan: &aos_sandbox_guest_protocol::openssh_receiving::OpenSshDescendantPlanDataV1,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        plan.require_request_data_v1(runtime, request)
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::InvalidRequest))?;
        self.apply_operation(request, runtime, channel, deadline, None, Some(plan))
    }

    fn observe_openssh_gate(
        &mut self, request: &OpenSshGateObserveRequestV1, runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest, deadline: Instant,
    ) -> Result<OpenSshGateReadbackV1, ProtectedGuestAgentErrorV1> {
        self.observe_openssh_gate_engine_v1(request, runtime, channel, deadline, None)
    }

    fn observe_openssh_gate_original_v1(
        &mut self, request: &OpenSshGateObserveRequestV1, runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest, deadline: Instant,
        original: &crate::protected_entry::GuestOperationDeadlineOriginalV1,
    ) -> Result<OpenSshGateReadbackV1, ProtectedGuestAgentErrorV1> {
        self.observe_openssh_gate_engine_v1(request, runtime, channel, deadline,
            Some(original.cutoff_data_v1()?))
    }

    fn bind_openssh_ticket_v2(
        &mut self,
        request: &OpenSshGateObserveRequestV1,
        ticket: &[u8],
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
    ) -> Result<(OpenSshGateReadbackV1, [u8; 32]), ProtectedGuestAgentErrorV1> {
        let barrier = self.ledger.effect_barrier();
        let _current = barrier
            .lock()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        if self.quiesced
            || !self
                .ledger
                .require_live_process(
                    &self
                        .ledger
                        .read_process_bytes(request.binding.execution_id)
                        .map_err(effect_error)?,
                )
                .map_err(effect_error)?
        {
            return Err(effect_error(GuestProcessEffectErrorV1::InvalidRequest));
        }
        // Binding never installs/reconstructs a process or base route.
        let gate = self
            .gate
            .as_mut()
            .ok_or_else(|| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        let result = gate
            .bind_ticket_v2(request, ticket, runtime, channel, &self.ledger, deadline)
            .map_err(effect_error)?;
        self.bridge
            .bind_monitor_v2(gate.monitor_runtime_v2().map_err(effect_error)?, ticket)
            .map_err(effect_error)?;
        check_deadline(deadline).map_err(effect_error)?;
        Ok(result)
    }

    fn original_control_v5(
        &mut self,
        action: aos_sandbox_guest_protocol::openssh_control_channel::OriginalControlActionV5,
        binding: [u8; 32],
        control: &[u8],
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        request: &OpenSshGateObserveRequestV1,
        ticket: &[u8],
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
    ) -> Result<
        (
            OpenSshGateReadbackV1,
            aos_sandbox_guest_protocol::openssh_control_channel::OriginalControlObservationV5,
        ),
        ProtectedGuestAgentErrorV1,
    > {
        let barrier = self.ledger.effect_barrier();
        let _current = barrier
            .lock()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        check_deadline(deadline).map_err(effect_error)?;
        if self.quiesced {
            return Err(effect_error(GuestProcessEffectErrorV1::InvalidRequest));
        }
        let gate = self
            .gate
            .as_mut()
            .ok_or_else(|| effect_error(GuestProcessEffectErrorV1::InvalidRequest))?;
        let readback = gate
            .observe_active_original_tree_v5(request, runtime, channel, &self.ledger, deadline)
            .map_err(effect_error)?;
        let observation = self
            .bridge
            .original_control_v5(
                action,
                binding,
                control,
                authority_expires_at,
                effect_deadline_boottime_nanoseconds,
                ticket,
                &self.ledger,
                deadline,
            )
            .map_err(effect_error)?;
        // The effect owner has physically rechecked installation before/after
        // its effect and ACK. KILL may empty the original tree; that is not a
        // fresh active-tree permission for another control or consume.
        check_deadline(deadline).map_err(effect_error)?;
        Ok((readback, observation))
    }

    fn original_attach_v3(
        &mut self,
        action: aos_sandbox_guest_protocol::openssh_consume::OriginalAttachActionV3,
        binding: [u8; 32],
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        request: &OpenSshGateObserveRequestV1,
        ticket: &[u8],
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
    ) -> Result<
        (
            OpenSshGateReadbackV1,
            aos_sandbox_guest_protocol::openssh_consume::OriginalAttachObservationV3,
        ),
        ProtectedGuestAgentErrorV1,
    > {
        let barrier = self.ledger.effect_barrier();
        let _current = barrier
            .lock()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        check_deadline(deadline).map_err(effect_error)?;
        if self.quiesced {
            return Err(effect_error(GuestProcessEffectErrorV1::InvalidRequest));
        }
        // Installation and binding are earlier effects. Consume cannot rebuild
        // either, nor infer attach eligibility from historical Observe evidence.
        let gate = self
            .gate
            .as_mut()
            .ok_or_else(|| effect_error(GuestProcessEffectErrorV1::InvalidRequest))?;
        let readback = gate
            .observe_active_original_tree_v5(request, runtime, channel, &self.ledger, deadline)
            .map_err(effect_error)?;
        let observation = self
            .bridge
            .original_attach_v3(
                action,
                binding,
                authority_expires_at,
                effect_deadline_boottime_nanoseconds,
                ticket,
                &self.ledger,
                deadline,
            )
            .map_err(effect_error)?;
        check_deadline(deadline).map_err(effect_error)?;
        Ok((readback, observation))
    }
}

pub(super) fn require_owned_gate_lifetime_v1(ledger: &Ledger, record: &ProcessRecord)
    -> Result<(), GuestProcessEffectErrorV1>
{
    let mut live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process = live.get_mut(&record.execution).ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    // This is the actual private native owner, not reconstruction of a child
    // from the supplied row. The actor's effect barrier excludes replacement;
    // the standing timeout worker may only terminate this same original.
    if process.record.execution != record.execution || process.record.pid != record.pid
        || process.record.start_ticks != record.start_ticks || process.record.runtime != record.runtime
        || process.normal_terminal.is_some() || process.timeout_terminal.is_some()
        || process.timeout_record.is_some()
        || process.lifetime.is_expired().map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn check_deadline(deadline: Instant) -> Result<(), GuestProcessEffectErrorV1> {
    if Instant::now() >= deadline {
        return Err(GuestProcessEffectErrorV1::Unavailable(
            "guest operation deadline expired",
        ));
    }
    Ok(())
}

fn project_effect_result_v2<T>(
    result: Result<T, GuestProcessEffectErrorV1>,
    capture: Option<&mut crate::capture::GuestCaptureAuthorizeOriginalV2>,
) -> Result<T, ProtectedGuestAgentErrorV1> {
    match result {
        Ok(value) => Ok(value),
        Err(cause) => match capture {
            Some(original) => {
                if original.effect.is_none() { original.effect = Some(Err(cause)); }
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
            None => Err(effect_error(cause)),
        },
    }
}

fn effect_error(error: GuestProcessEffectErrorV1) -> ProtectedGuestAgentErrorV1 {
    ProtectedGuestAgentErrorV1::EffectFailed(error.to_string())
}

fn outcome(phase: AgentExecutionPhaseV1, kind: u8, payload: &[u8]) -> StoredOutcome {
    let capacity = aos_sandbox_guest_protocol::protocol::guest_result_encoded_bytes_v5(payload.len())
        .unwrap_or(0);
    let mut result = Vec::with_capacity(capacity);
    result.extend_from_slice(b"AOSGER01");
    result.push(kind);
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    result.extend_from_slice(payload);
    StoredOutcome {
        phase: phase.code(),
        result,
    }
}

pub(super) fn terminal_outcome(
    status: aos_sandbox_guest_protocol::openssh_session::OriginalExecutionWaitStatusV4,
    canceled: bool,
) -> StoredOutcome {
    let mut result = outcome(
        if canceled {
            AgentExecutionPhaseV1::Canceled
        } else {
            AgentExecutionPhaseV1::Exited
        },
        if canceled { 7 } else { 6 },
        &status.raw().to_be_bytes(),
    );
    // V1's signed -1 sentinel never identifies a terminating signal. V2
    // preserves the exact original Linux waitstatus, including its core bit.
    result.result[..8].copy_from_slice(b"AOSGER02");
    result
}

/// Distinguishes actual duration exhaustion from a successful leader exit.
/// A dead zero-status leader can still leave descendants that time out.
pub(super) fn timeout_terminal_outcome_v1(
    status: aos_sandbox_guest_protocol::openssh_session::OriginalExecutionWaitStatusV4,
) -> StoredOutcome {
    let mut result = outcome(AgentExecutionPhaseV1::Failed, 8, &status.raw().to_be_bytes());
    result.result[..8].copy_from_slice(b"AOSGER03");
    result
}

/// Retains genuine terminal data while the caller holds the shared barrier.
///
/// An absent live tree is never reconstructed from a cold row or missing PID.
///
/// # Errors
/// Rejects foreign original tree custody, missing live process ownership,
/// ambiguous leader status, or failed protected terminal publication.
pub(super) fn observe_owned_terminal(
    ledger: &Ledger,
    execution: ExecutionId,
) -> Result<Option<StoredOutcome>, GuestProcessEffectErrorV1> {
    let mut record = ledger.read_process(execution)?;
    if let Some(terminal) = &record.terminal {
        let live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if live.get(execution.as_bytes()).is_some_and(|process|
            process.normal_terminal.as_ref().is_some_and(Result::is_err)
                || process.normal_finish.as_ref().is_some_and(Result::is_err))
        { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        return Ok(Some(terminal.clone()));
    }
    let mut live = ledger
        .live()
        .lock()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process = live
        .get_mut(execution.as_bytes())
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    process.tree.require_original_identity(&record)?;
    if process.io_registration.as_ref().is_some_and(|original| original.failure().is_some()) {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }
    if process.timeout_record.is_some()
        || process.lifetime.is_expired().map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?
    {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }
    if !process.tree.empty_and_exited()? {
        return Ok(None);
    }
    let status = process
        .child
        .try_wait()?
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let status = aos_sandbox_guest_protocol::openssh_session::OriginalExecutionWaitStatusV4::new(
        u32::try_from(status.into_raw()).map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?,
    )
    .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
    if process.lifetime.is_expired().map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)? {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }
    let result = terminal_outcome(status, record.canceled);
    record.terminal_waitstatus = Some(status.raw());
    record.terminal = Some(result.clone());
    let original = live.remove(execution.as_bytes()).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    drop(live);
    let mut loan = timeout::QuiescentExecutionLoanV1 {
        registry: ledger.live(), execution: *execution.as_bytes(), original: Some(original),
    };
    let original = loan.original.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    original.record = record;
    original.normal_terminal = Some(ledger.replace_process_retaining_v1(execution, &original.record,
        &mut original.terminal_native));
    if !original.normal_terminal.as_ref().is_some_and(Result::is_ok) {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }
    // Parking restores the SAME quiescent native owner before the upper bridge
    // posts. Only finish_execution may retire it after those posts succeed.
    drop(loan);
    Ok(Some(result))
}

/// Applies only a queued original-session control while all owner cuts stay held.
///
/// The monitor owner supplies the already matched immutable ticket/session and
/// root-owned request; it retains the shared barrier and custody through this
/// call. This private method cannot select another process, create a PTY or
/// infer authority from the parsed action. Every actual effect follows its
/// durable exact sequence reservation, and a failure never permits redispatch.
///
/// # Errors
/// Rejects absent/foreign original tree or PTY ownership, closed process state,
/// unsupported topology, lost currentness, ambiguous reservation or effect.
pub(super) fn apply_owned_original_control_v5(
    ledger: &Ledger,
    execution: ExecutionId,
    ticket: [u8; 32],
    session: [u8; 32],
    request: &aos_sandbox_guest_protocol::openssh_control::OpenSshControlRequestV5,
    deadline: Instant,
    mut current_deadline: impl FnMut() -> Result<(), GuestProcessEffectErrorV1>,
    mut recheck: impl FnMut() -> Result<(), GuestProcessEffectErrorV1>,
) -> Result<(), GuestProcessEffectErrorV1> {
    use std::os::fd::AsFd as _;

    use aos_sandbox_guest_protocol::openssh_control::OpenSshControlActionV5;

    recheck()?;
    current_deadline()?;
    check_deadline(deadline)?;
    let record = ledger.read_process(execution)?;
    let live = ledger
        .live()
        .lock()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process = live
        .get(execution.as_bytes())
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let tree = std::sync::Arc::clone(&process.tree);
    let master = process.pty_master.as_ref().map(std::sync::Arc::clone);
    drop(live);
    tree.require_original_scope(&record)?;
    if tree.empty_and_exited()? {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }

    // Preflight every mode and the actual retained descriptor before reserving.
    // The client terminal label is committed data, never an environment update.
    let prepared_pty = match &request.action {
        OpenSshControlActionV5::Signal(_) => None,
        OpenSshControlActionV5::Resize(geometry) | OpenSshControlActionV5::Pty { geometry, .. } => {
            if record.attach_io != Some(AttachIoShapeV3::Pty) || !record.pty {
                return Err(GuestProcessEffectErrorV1::InvalidRequest);
            }
            let master = master.as_ref()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            use crate::openssh_pty::PreparedOriginalPtySettings;

            Some(match &request.action {
                OpenSshControlActionV5::Resize(_) => {
                    PreparedOriginalPtySettings::prepare_resize(master.as_fd(), *geometry)?
                }
                OpenSshControlActionV5::Pty { modes, .. } => {
                    PreparedOriginalPtySettings::prepare_initial(master.as_fd(), *geometry, modes)?
                }
                _ => return Err(GuestProcessEffectErrorV1::InvalidRequest),
            })
        }
    };
    ledger.reserve_original_control_v5(&record, ticket, session, request)?;
    recheck()?;
    current_deadline()?;
    check_deadline(deadline)?;
    tree.require_original_scope(&record)?;
    match (&request.action, prepared_pty) {
        (OpenSshControlActionV5::Signal(signal), None) => {
            tree.signal_with_lifetime_cut_v1(*signal, deadline, || {
                    recheck()?;
                    tree.require_original_scope(&record)?;
                    current_deadline()
                }, || tree.require_original_scope(&record))?;
        }
        (_, Some(settings)) => {
            let master = master.as_ref()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            settings.apply(master.as_fd(), || {
                recheck()?;
                tree.require_original_scope(&record)?;
                if tree.empty_and_exited()? {
                    return Err(GuestProcessEffectErrorV1::InvalidRequest);
                }
                // Physical and tree reads precede the final time fence; the
                // retained PTY syscall follows without intervening owner I/O.
                current_deadline()?;
                check_deadline(deadline)
            })?;
        }
        _ => return Err(GuestProcessEffectErrorV1::InvalidRequest),
    }
    // The effect has already been attempted. Any final custody or deadline
    // failure is ambiguous rather than permission to try the sequence again.
    (|| {
        recheck()?;
        tree.require_original_scope(&record)?;
        current_deadline()?;
        check_deadline(deadline)
    })()
    .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)
}

pub(super) fn write_specification(
    input: &mut ChildStdin,
    specification: &[u8],
    deadline: Instant,
    process: &ProcessRecord,
) -> Result<(), GuestProcessEffectErrorV1> {
    let lifetime = process.lifetime.as_ref().ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    aos_sandbox_linux::process::require_child_lifetime_data_v1(
        lifetime.origin_boottime_nanoseconds, lifetime.timeout_nanoseconds,
        lifetime.deadline_boottime_nanoseconds)?;
    let length = u32::try_from(specification.len())
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let flags = rustix::fs::fcntl_getfl(&*input)?;
    rustix::fs::fcntl_setfl(&*input, flags | OFlags::NONBLOCK)?;
    let mut header = [0_u8; 36];
    header[..8].copy_from_slice(b"AOSGEX02");
    header[8..16].copy_from_slice(&lifetime.origin_boottime_nanoseconds.to_be_bytes());
    header[16..24].copy_from_slice(&lifetime.timeout_nanoseconds.to_be_bytes());
    header[24..32].copy_from_slice(&lifetime.deadline_boottime_nanoseconds.to_be_bytes());
    header[32..].copy_from_slice(&length.to_be_bytes());
    for mut bytes in [&header[..], specification] {
        while !bytes.is_empty() {
            check_deadline(deadline)?;
            aos_sandbox_linux::process::require_child_lifetime_data_v1(
                lifetime.origin_boottime_nanoseconds, lifetime.timeout_nanoseconds,
                lifetime.deadline_boottime_nanoseconds)?;
            match rustix::io::write(&*input, bytes) {
                Ok(0) => return Err(GuestProcessEffectErrorV1::AmbiguousEffect),
                Ok(written) => bytes = &bytes[written..],
                Err(io::Errno::INTR) => {}
                Err(io::Errno::AGAIN) => std::thread::sleep(std::time::Duration::from_millis(2)),
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

/// Cancels the actual original execution tree while its caller retains the
/// shared terminal/reservation/SCM barrier. No cold scalar state is adopted.
pub(super) fn cancel_owned_execution(
    ledger: &Ledger,
    execution: ExecutionId,
    deadline: Instant,
) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
    let mut record = ledger.read_process(execution)?;
    if let Some(terminal) = &record.terminal {
        let live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if live.get(execution.as_bytes()).is_some_and(|process|
            process.normal_terminal.as_ref().is_some_and(Result::is_err)
                || process.normal_finish.as_ref().is_some_and(Result::is_err))
        { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        return Ok(terminal.clone());
    }
    let mut live = ledger
        .live()
        .lock()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process = live
        .get_mut(execution.as_bytes())
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    process.tree.require_original_identity(&record)?;
    if process.timeout_record.is_some() {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }

    let tree = std::sync::Arc::clone(&process.tree);
    drop(live);

    // Foreclose attach before kill. A failed/ambiguous wait leaves the durable
    // row canceled but nonterminal, never a false success or another IO slot.
    record.canceled = true;
    ledger.replace_process(execution, &record)?;
    {
        let mut live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        live.get_mut(execution.as_bytes()).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
            .record = record.clone();
    }
    tree.kill_and_wait(deadline)?;
    let mut live = ledger.live().lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process = live.get_mut(execution.as_bytes()).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let status = process
        .child
        .try_wait()?
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let status = aos_sandbox_guest_protocol::openssh_session::OriginalExecutionWaitStatusV4::new(
        u32::try_from(status.into_raw()).map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?,
    )
    .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let result = terminal_outcome(status, true);
    record.terminal_waitstatus = Some(status.raw());
    record.terminal = Some(result.clone());
    let original = live.remove(execution.as_bytes()).ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    drop(live);
    let mut loan = timeout::QuiescentExecutionLoanV1 {
        registry: ledger.live(), execution: *execution.as_bytes(), original: Some(original),
    };
    let original = loan.original.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    original.record = record;
    original.normal_terminal = Some(ledger.replace_process_retaining_v1(execution, &original.record,
        &mut original.terminal_native));
    if !original.normal_terminal.as_ref().is_some_and(Result::is_ok) {
        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
    }
    drop(loan);
    Ok(result)
}
