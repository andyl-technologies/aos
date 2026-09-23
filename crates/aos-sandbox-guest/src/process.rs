//! Concrete, guest-local process, PTY, and process-group effects.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ChildStdin, Command, Stdio};

use aos_sandbox_agent::protected_entry::{GuestOperationEffectsV1, ProtectedGuestAgentErrorV1};
use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionPhaseV1, AgentFeatureV1, AgentOperationRequestV1,
    AgentRuntimeBindingV1,
};
use aos_sandbox_core::{
    DecodeLimits, ExecutionId, ExecutionTerminalModeV1, ObjectDigest, decode_execution_spec_v1,
    execution_spec_digest_v1,
};
use rustix::fs::{Mode, OFlags, fchown, open};
use rustix::io;
use rustix::process::{Pid, Signal, kill_process_group};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::bridge::AttachBridge;
use crate::ledger::{Ledger, ProcessRecord, Reservation, StoredOutcome, runtime_identity};

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

struct LiveProcess {
    child: Child,
    pty_master: Option<OwnedFd>,
}

/// Owns durable guest execution records and the currently attached children.
pub struct GuestProcessEffectsV1 {
    ledger: Ledger,
    bridge: AttachBridge,
    live: BTreeMap<[u8; 16], LiveProcess>,
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
        let ledger = Ledger::open()?;
        let quiesced = ledger.read_quiesced()?;
        let bridge = AttachBridge::start(ledger.clone())?;
        Ok(Self {
            ledger,
            bridge,
            live: BTreeMap::new(),
            quiesced,
        })
    }

    fn apply_effect(
        &mut self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
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
                // CommandExt::uid clears supplementary groups in the child.
                // Nonempty groups need a separate audited credential launcher.
                if !credentials.supplementary_group_ids().is_empty() {
                    return Err(GuestProcessEffectErrorV1::Unavailable(
                        "supplementary groups are not supported by this launcher",
                    ));
                }
                self.start_process(
                    *execution,
                    specification_bytes,
                    credentials.user_id(),
                    credentials.primary_group_id(),
                    specification.io().terminal_mode() == ExecutionTerminalModeV1::Pty,
                    runtime,
                    *request.operation_id().as_bytes(),
                    *principal.as_bytes(),
                    *audit.as_bytes(),
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
            } => self.signal(*execution, *signal_code, runtime),
            AgentExecutionOperationV1::Cancel { execution } => self.cancel(*execution, runtime),
            AgentExecutionOperationV1::Observe { execution } => self.observe(*execution, runtime),
            AgentExecutionOperationV1::BeginQuiesce => {
                if self.ledger.has_ambiguous_operation(request)? {
                    return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
                }
                for record in self.ledger.processes()? {
                    if record.terminal.is_none() && process_matches(&record)? {
                        return Err(GuestProcessEffectErrorV1::Unavailable(
                            "active children prevent the local quiesce barrier",
                        ));
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
        runtime: &AgentRuntimeBindingV1,
        operation: [u8; 16],
        principal: [u8; 16],
        audit: [u8; 16],
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let helper = std::env::current_exe()?.with_file_name("aos-sandbox-guest-exec");
        let mut command = Command::new(helper);
        command.uid(uid).gid(gid);
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
        write_specification(&mut input, specification)?;
        let pid = child.id();
        let start_ticks = process_identity(pid)?
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
            .start_ticks;
        self.ledger.write_process(
            execution,
            &ProcessRecord {
                version: 1,
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
                canceled: false,
                terminal: None,
            },
        )?;
        if let Some(master) = master.as_ref() {
            self.bridge.register_pty(*execution.as_bytes(), master)?;
        } else {
            let stdout = child
                .stdout
                .take()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            let stderr = child
                .stderr
                .take()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            self.bridge
                .register_stream(*execution.as_bytes(), input, stdout, stderr)?;
        }
        self.live.insert(
            *execution.as_bytes(),
            LiveProcess {
                child,
                pty_master: master,
            },
        );
        Ok(outcome(
            AgentExecutionPhaseV1::Running,
            1,
            &pid.to_be_bytes(),
        ))
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
        if !record.pty || !process_matches(&record)? {
            return Err(GuestProcessEffectErrorV1::Unavailable("PTY is not live"));
        }
        let master = self
            .live
            .get(execution.as_bytes())
            .and_then(|process| process.pty_master.as_ref())
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
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let record = self.bound_process(execution, runtime)?;
        if !process_matches(&record)? {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "process is not live",
            ));
        }
        let signal = portable_signal(code).ok_or(GuestProcessEffectErrorV1::Unavailable(
            "unsupported signal code",
        ))?;
        let pid =
            Pid::from_raw(record.pid as i32).ok_or(GuestProcessEffectErrorV1::LedgerConflict)?;
        kill_process_group(pid, signal)?;
        Ok(outcome(AgentExecutionPhaseV1::Running, 3, &[code]))
    }

    fn cancel(
        &mut self,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let mut record = self.bound_process(execution, runtime)?;
        if !process_matches(&record)? {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "process is not live",
            ));
        }
        let pid =
            Pid::from_raw(record.pid as i32).ok_or(GuestProcessEffectErrorV1::LedgerConflict)?;
        self.bridge.remove(*execution.as_bytes())?;
        kill_process_group(pid, Signal::KILL)?;
        record.canceled = true;
        self.ledger.replace_process(execution, &record)?;
        Ok(outcome(
            AgentExecutionPhaseV1::Canceled,
            4,
            execution.as_bytes(),
        ))
    }

    fn observe(
        &mut self,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<StoredOutcome, GuestProcessEffectErrorV1> {
        let mut record = self.bound_process(execution, runtime)?;
        if let Some(terminal) = &record.terminal {
            return Ok(terminal.clone());
        }
        if let Some(process) = self.live.get_mut(execution.as_bytes()) {
            if let Some(status) = process.child.try_wait()? {
                let result = if record.canceled {
                    outcome(AgentExecutionPhaseV1::Canceled, 7, b"canceled")
                } else {
                    outcome(
                        AgentExecutionPhaseV1::Exited,
                        6,
                        &status.code().unwrap_or(-1).to_be_bytes(),
                    )
                };
                record.terminal = Some(result.clone());
                self.ledger.replace_process(execution, &record)?;
                self.bridge.remove(*execution.as_bytes())?;
                self.live.remove(execution.as_bytes());
                return Ok(result);
            }
        }
        if process_matches(&record)? {
            Ok(outcome(
                AgentExecutionPhaseV1::Running,
                5,
                &record.pid.to_be_bytes(),
            ))
        } else {
            let result = outcome(AgentExecutionPhaseV1::Lost, 8, b"lost");
            record.terminal = Some(result.clone());
            self.ledger.replace_process(execution, &record)?;
            self.bridge.remove(*execution.as_bytes())?;
            Ok(result)
        }
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
    ) -> Result<(AgentExecutionPhaseV1, Vec<u8>), ProtectedGuestAgentErrorV1> {
        let reservation = self
            .ledger
            .reserve(request, runtime, channel)
            .map_err(effect_error)?;
        let stored = match reservation {
            Reservation::Fresh => {
                let result = self.apply_effect(request, runtime).map_err(effect_error)?;
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
        let phase = decode_phase(stored.phase).ok_or_else(|| {
            ProtectedGuestAgentErrorV1::EffectFailed("invalid durable phase".into())
        })?;
        Ok((phase, stored.result))
    }
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
        phase: encode_phase(phase),
        result,
    }
}

fn encode_phase(phase: AgentExecutionPhaseV1) -> u8 {
    match phase {
        AgentExecutionPhaseV1::Authorized => 1,
        AgentExecutionPhaseV1::Starting => 2,
        AgentExecutionPhaseV1::Running => 3,
        AgentExecutionPhaseV1::Exited => 4,
        AgentExecutionPhaseV1::Canceled => 5,
        AgentExecutionPhaseV1::Failed => 6,
        AgentExecutionPhaseV1::Lost => 7,
        AgentExecutionPhaseV1::Quiesced => 8,
        AgentExecutionPhaseV1::Ready => 9,
    }
}

fn decode_phase(phase: u8) -> Option<AgentExecutionPhaseV1> {
    match phase {
        1 => Some(AgentExecutionPhaseV1::Authorized),
        2 => Some(AgentExecutionPhaseV1::Starting),
        3 => Some(AgentExecutionPhaseV1::Running),
        4 => Some(AgentExecutionPhaseV1::Exited),
        5 => Some(AgentExecutionPhaseV1::Canceled),
        6 => Some(AgentExecutionPhaseV1::Failed),
        7 => Some(AgentExecutionPhaseV1::Lost),
        8 => Some(AgentExecutionPhaseV1::Quiesced),
        9 => Some(AgentExecutionPhaseV1::Ready),
        _ => None,
    }
}

fn write_specification(
    input: &mut ChildStdin,
    specification: &[u8],
) -> Result<(), GuestProcessEffectErrorV1> {
    let length = u32::try_from(specification.len())
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    input.write_all(&length.to_be_bytes())?;
    input.write_all(specification)?;
    Ok(())
}

pub(crate) struct ProcIdentity {
    pub(crate) start_ticks: u64,
    pub(crate) process_group: u32,
    pub(crate) parent: u32,
}

pub(crate) fn process_identity(
    pid: u32,
) -> Result<Option<ProcIdentity>, GuestProcessEffectErrorV1> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let fields = stat
        .rsplit_once(") ")
        .ok_or(GuestProcessEffectErrorV1::LedgerConflict)?
        .1
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let parent = fields
        .get(1)
        .ok_or(GuestProcessEffectErrorV1::LedgerConflict)?
        .parse()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let process_group = fields
        .get(2)
        .ok_or(GuestProcessEffectErrorV1::LedgerConflict)?
        .parse()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let start = fields
        .get(19)
        .ok_or(GuestProcessEffectErrorV1::LedgerConflict)?
        .parse()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    Ok(Some(ProcIdentity {
        start_ticks: start,
        process_group,
        parent,
    }))
}

pub(crate) fn process_matches(record: &ProcessRecord) -> Result<bool, GuestProcessEffectErrorV1> {
    Ok(matches!(
        process_identity(record.pid)?,
        Some(identity)
            if identity.start_ticks == record.start_ticks
                && identity.process_group == record.pid
    ))
}

fn portable_signal(code: u8) -> Option<Signal> {
    match code {
        1 => Some(Signal::HUP),
        2 => Some(Signal::INT),
        3 => Some(Signal::QUIT),
        6 => Some(Signal::ABORT),
        9 => Some(Signal::KILL),
        10 => Some(Signal::USR1),
        12 => Some(Signal::USR2),
        13 => Some(Signal::PIPE),
        14 => Some(Signal::ALARM),
        15 => Some(Signal::TERM),
        17 => Some(Signal::CHILD),
        18 => Some(Signal::CONT),
        19 => Some(Signal::STOP),
        20 => Some(Signal::TSTP),
        21 => Some(Signal::TTIN),
        22 => Some(Signal::TTOU),
        28 => Some(Signal::WINCH),
        _ => None,
    }
}
