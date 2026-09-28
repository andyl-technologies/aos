//! Concrete Guest-owned execution trees, PTYs, and durable terminal effects.

use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Instant;

use aos_sandbox_agent::openssh_gate::{OpenSshGateObserveRequestV1, OpenSshGateReadbackV1};
use aos_sandbox_agent::protected_entry::{GuestOperationEffectsV1, ProtectedGuestAgentErrorV1};
use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionPhaseV1, AgentFeatureV1, AgentOperationRequestV1,
    AgentRuntimeBindingV1,
};
use aos_sandbox_core::{
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
    /// Enforcing Guest ownership or retained kernel custody failed.
    #[error("guest execution confinement failed: {0}")]
    Confinement(#[from] aos_sandbox_linux::Error),
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

pub(crate) struct LiveProcess {
    child: Child,
    pty_master: Option<OwnedFd>,
    pub(crate) tree: crate::execution_tree::ExecutionTree,
}

/// Owns durable guest execution records and the currently attached children.
pub struct GuestProcessEffectsV1 {
    ledger: Ledger,
    bridge: AttachBridge,
    execution_root: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    _payload_cgroup: aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1,
    gate: Option<GuestOpenSshGate>,
    quiesced: bool,
}

impl GuestProcessEffectsV1 {
    /// Opens the fixed root-owned guest-local effect ledger.
    ///
    /// # Errors
    ///
    /// Returns [`GuestProcessEffectErrorV1`] when the fixed ledger cannot be
    /// created or authenticated as root-owned private state.
    pub fn open() -> Result<Self, GuestProcessEffectErrorV1> {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        let payload_cgroup =
            aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1::from_inherited()?;
        let execution_root = payload_cgroup.execution_root()?;
        for descriptor in [6, 7] {
            aos_sandbox_linux::inherited_fd::mark_inherited_descriptor_close_on_exec(descriptor)?;
            // SAFETY: fixed bootstrap startup gives this Agent sole numeric
            // custody of the originals. Typed owners represent only clones.
            drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) });
        }
        let ledger = Ledger::open()?;
        let quiesced = ledger.read_quiesced()?;
        let bridge = AttachBridge::start(ledger.clone())?;
        Ok(Self {
            ledger,
            bridge,
            execution_root,
            _payload_cgroup: payload_cgroup,
            gate: None,
            quiesced,
        })
    }

    fn apply_effect(
        &mut self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        deadline: Instant,
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
                            aos_sandbox_core::ExecutionAccessRouteV1::OpenSsh(_),
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
                        == aos_sandbox_core::ExecutionDisconnectPolicyV1::Cancel,
                    deadline,
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
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let helper = std::env::current_exe()?.with_file_name("aos-sandbox-guest-exec");
        let mut command = Command::new(helper);
        // This exact measured Owner helper remains root and cannot consume the
        // spec until its proper-descendant membership and durable row exist.
        command.env_clear();
        command.stdin(Stdio::piped());
        if pty {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        } else {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }

        let (master, slave_path) = if pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
            grantpt(&master)?;
            unlockpt(&master)?;
            let slave_path = ptsname(&master, Vec::new())?;
            let slave = open(
                slave_path.as_c_str(),
                OFlags::RDWR | OFlags::NOCTTY,
                Mode::empty(),
            )?;
            fchown(
                &slave,
                Some(rustix::process::Uid::from_raw(uid)),
                Some(rustix::process::Gid::from_raw(gid)),
            )?;
            command.arg(slave_path.to_string_lossy().as_ref());
            (Some(master), Some(slave_path))
        } else {
            command.process_group(0);
            (None, None)
        };

        let mut child = command.spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let pid = child.id();
        let tree = crate::execution_tree::ExecutionTree::create(
            &self.execution_root,
            execution.as_bytes(),
            pid,
        )?;
        let start_ticks = tree.leader_start_ticks()?;
        let record = ProcessRecord {
            version: 2,
            runtime: runtime_identity(runtime),
            operation,
            execution: *execution.as_bytes(),
            incarnation: *runtime.incarnation().as_bytes(),
            assignment_epoch: runtime.assignment_epoch().get(),
            principal,
            audit,
            uid,
            pid,
            start_ticks,
            pty: slave_path.is_some(),
            attach_io,
            cgroup: Some(tree.kernel_id()),
            cancel_on_disconnect: Some(cancel_on_disconnect),
            canceled: false,
            terminal: None,
            terminal_waitstatus: None,
        };
        self.ledger.write_process(execution, &record)?;
        tree.require_leader()?;
        self.ledger
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?
            .insert(
                *execution.as_bytes(),
                LiveProcess {
                    child,
                    pty_master: master,
                    tree,
                },
            );
        write_specification(&mut input, specification, deadline)?;
        let mut live = self
            .ledger
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let process = live
            .get_mut(execution.as_bytes())
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if let Some(master) = process.pty_master.as_ref() {
            self.bridge.register_pty(*execution.as_bytes(), master)?;
        } else {
            let stdout = process
                .child
                .stdout
                .take()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            let stderr = process
                .child
                .stderr
                .take()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            self.bridge
                .register_stream(*execution.as_bytes(), input, stdout, stderr)?;
        }
        drop(live);
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
            let initialized = process.tree.matches(&record)? || process.child.try_wait()?.is_some();
            drop(live);
            if initialized {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
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
        process.tree.require_original_scope(&record)?;
        process.tree.signal(code, deadline)?;
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
        self.bound_process(execution, runtime)?;
        let result = cancel_owned_execution(&self.ledger, execution, deadline)?;
        self.finish_execution(execution)?;
        Ok(result)
    }

    fn finish_execution(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        // Close the I/O factory immediately, but retain an already consumed
        // original monitor long enough to report the actual terminal status.
        self.bridge.finish_execution(*execution.as_bytes())?;
        if !self.bridge.has_original_session(*execution.as_bytes())?
            && self
                .gate
                .as_ref()
                .is_some_and(|gate| gate.execution() == *execution.as_bytes())
        {
            self.gate = None;
        }
        Ok(())
    }

    fn observe(
        &mut self,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let record = self.bound_process(execution, runtime)?;
        if let Some(result) = observe_owned_terminal(&self.ledger, execution)? {
            self.finish_execution(execution)?;
            return Ok(result);
        }
        // A dead leader with live descendants is not a terminal execution.
        Ok(outcome(
            AgentExecutionPhaseV1::Running,
            5,
            &record.pid.to_be_bytes(),
        ))
    }
}

impl GuestOperationEffectsV1 for GuestProcessEffectsV1 {
    fn supports(&self, feature: AgentFeatureV1) -> bool {
        matches!(
            feature,
            AgentFeatureV1::Readiness
                | AgentFeatureV1::ExecutionHandoff
                | AgentFeatureV1::ExecutionObservation
                | AgentFeatureV1::TerminalResize
                | AgentFeatureV1::ExecutionSignal
                | AgentFeatureV1::Quiesce
        )
    }

    fn apply(
        &mut self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        let barrier = self.ledger.effect_barrier();
        let _current = barrier
            .lock()
            .map_err(|_| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?;
        check_deadline(deadline).map_err(effect_error)?;
        let reservation = self
            .ledger
            .reserve(request, runtime, channel)
            .map_err(effect_error)?;
        let stored = match reservation {
            Reservation::Fresh => {
                check_deadline(deadline).map_err(effect_error)?;
                let result = self
                    .apply_effect(request, runtime, deadline)
                    .map_err(effect_error)?;
                self.ledger
                    .complete(request, runtime, channel, result.clone())
                    .map_err(effect_error)?;
                result
            }
            Reservation::Replayed(result) => {
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
        check_deadline(deadline).map_err(effect_error)?;
        let phase = AgentExecutionPhaseV1::from_code(stored.phase).ok_or_else(|| {
            ProtectedGuestAgentErrorV1::EffectFailed("invalid durable phase".into())
        })?;
        Ok((phase, stored.result))
    }

    fn observe_openssh_gate(
        &mut self,
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        deadline: Instant,
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
            self.gate = Some(
                GuestOpenSshGate::install(request, runtime, &self.ledger, deadline)
                    .map_err(effect_error)?,
            );
        }
        self.gate
            .as_mut()
            .ok_or_else(|| effect_error(GuestProcessEffectErrorV1::LedgerConflict))?
            .observe(request, runtime, channel, &self.ledger, deadline)
            .map_err(effect_error)
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
        action: aos_sandbox_agent::openssh_control_channel::OriginalControlActionV5,
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
            aos_sandbox_agent::openssh_control_channel::OriginalControlObservationV5,
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
        action: aos_sandbox_agent::openssh_consume::OriginalAttachActionV3,
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
            aos_sandbox_agent::openssh_consume::OriginalAttachObservationV3,
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

pub(crate) fn check_deadline(deadline: Instant) -> Result<(), GuestProcessEffectErrorV1> {
    if Instant::now() >= deadline {
        return Err(GuestProcessEffectErrorV1::Unavailable(
            "guest operation deadline expired",
        ));
    }
    Ok(())
}

fn effect_error(error: GuestProcessEffectErrorV1) -> ProtectedGuestAgentErrorV1 {
    ProtectedGuestAgentErrorV1::EffectFailed(error.to_string())
}

fn outcome(phase: AgentExecutionPhaseV1, kind: u8, payload: &[u8]) -> StoredOutcome {
    let mut result = Vec::with_capacity(13 + payload.len());
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
    status: aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4,
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
    if !process.tree.empty_and_exited()? {
        return Ok(None);
    }
    let status = process
        .child
        .try_wait()?
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(
        u32::try_from(status.into_raw()).map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?,
    )
    .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let result = terminal_outcome(status, record.canceled);
    record.terminal_waitstatus = Some(status.raw());
    record.terminal = Some(result.clone());
    ledger.replace_process(execution, &record)?;
    live.remove(execution.as_bytes());
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
    request: &aos_sandbox_agent::openssh_control::OpenSshControlRequestV5,
    deadline: Instant,
    mut current_deadline: impl FnMut() -> Result<(), GuestProcessEffectErrorV1>,
    mut recheck: impl FnMut() -> Result<(), GuestProcessEffectErrorV1>,
) -> Result<(), GuestProcessEffectErrorV1> {
    use std::os::fd::AsFd as _;

    use aos_sandbox_agent::openssh_control::OpenSshControlActionV5;

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
    process.tree.require_original_scope(&record)?;
    if process.tree.empty_and_exited()? {
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
            let master = process
                .pty_master
                .as_ref()
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
    process.tree.require_original_scope(&record)?;
    match (&request.action, prepared_pty) {
        (OpenSshControlActionV5::Signal(signal), None) => {
            process
                .tree
                .signal_with_current_cut(*signal, deadline, || {
                    recheck()?;
                    current_deadline()
                })?;
        }
        (_, Some(settings)) => {
            let master = process
                .pty_master
                .as_ref()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            settings.apply(master.as_fd(), || {
                recheck()?;
                process.tree.require_original_scope(&record)?;
                if process.tree.empty_and_exited()? {
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
        process.tree.require_original_scope(&record)?;
        current_deadline()?;
        check_deadline(deadline)
    })()
    .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)
}

fn write_specification(
    input: &mut ChildStdin,
    specification: &[u8],
    deadline: Instant,
) -> Result<(), GuestProcessEffectErrorV1> {
    let length = u32::try_from(specification.len())
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let flags = rustix::fs::fcntl_getfl(&*input)?;
    rustix::fs::fcntl_setfl(&*input, flags | OFlags::NONBLOCK)?;
    let header = length.to_be_bytes();
    for mut bytes in [&header[..], specification] {
        while !bytes.is_empty() {
            check_deadline(deadline)?;
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

    // Foreclose attach before kill. A failed/ambiguous wait leaves the durable
    // row canceled but nonterminal, never a false success or another IO slot.
    record.canceled = true;
    ledger.replace_process(execution, &record)?;
    process.tree.kill_and_wait(deadline)?;
    let status = process
        .child
        .try_wait()?
        .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(
        u32::try_from(status.into_raw()).map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?,
    )
    .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
    let result = terminal_outcome(status, true);
    record.terminal_waitstatus = Some(status.raw());
    record.terminal = Some(result.clone());
    ledger.replace_process(execution, &record)?;
    live.remove(execution.as_bytes());
    Ok(result)
}
