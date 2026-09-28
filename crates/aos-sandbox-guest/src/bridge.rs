//! Fixed guest-local process I/O handoff for the authenticated SSH gate.
//!
//! The root-owned process ledger owns the PTY master or stream pipe ends. This
//! socket hands them to the exact monitor-owned private relay only through the
//! held original-ticket V3 consume. Legacy gate ancestry never releases IO.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
    PermissionsExt as _,
};
use std::path::Path;
use std::process::{ChildStderr, ChildStdin, ChildStdout};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aos_sandbox_agent::openssh_gate::{OpenSshGateBridgeRequestV1, OpenSshGateClaimV1};
use aos_sandbox_linux::Error as LinuxError;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError, SeqpacketSocket};

use crate::GuestProcessEffectErrorV1;
use crate::ledger::Ledger;

const SOCKET_DIRECTORY: &str = "/run/aos-sandbox-agent";
const SOCKET_PATH: &str = "/run/aos-sandbox-agent/exec-gate.sock";
const GATE_RECORD: &str = "/etc/aos/sandbox-attach/gate-record.json";
const MAX_GATE_RECORD_BYTES: u64 = 16 * 1024;
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;

enum AttachedIo {
    Pty(OwnedFd),
    Stream {
        input: OwnedFd,
        output: OwnedFd,
        error: OwnedFd,
    },
}

type PtyRegistry = Arc<Mutex<BTreeMap<[u8; 16], AttachedIo>>>;

pub(super) struct AttachBridge {
    masters: PtyRegistry,
    monitors: crate::monitor::MonitorRegistry,
    server: JoinHandle<()>,
}

impl AttachBridge {
    /// Applies only existing original-monitor controls under the caller's barrier.
    ///
    /// # Errors
    /// Rejects a closed bridge, expired/nonnarrowed deadline, absent custody,
    /// replay, unsupported original topology or ambiguous effects/ACK.
    pub(super) fn original_control_v5(
        &self,
        action: aos_sandbox_agent::openssh_control_channel::OriginalControlActionV5,
        binding: [u8; 32],
        request: &[u8],
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        ticket: &[u8],
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<
        aos_sandbox_agent::openssh_control_channel::OriginalControlObservationV5,
        GuestProcessEffectErrorV1,
    > {
        if self.server.is_finished() {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "attach bridge stopped",
            ));
        }
        let deadline = original_authority_deadline(
            authority_expires_at,
            effect_deadline_boottime_nanoseconds,
        )?
        .min(deadline);
        self.monitors.original_control_v5(
            action,
            binding,
            request,
            ticket,
            ledger,
            deadline,
            authority_expires_at,
            effect_deadline_boottime_nanoseconds,
        )
    }

    pub(super) fn original_attach_v3(
        &self,
        action: aos_sandbox_agent::openssh_consume::OriginalAttachActionV3,
        expected_binding: [u8; 32],
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        ticket: &[u8],
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<
        aos_sandbox_agent::openssh_consume::OriginalAttachObservationV3,
        GuestProcessEffectErrorV1,
    > {
        if self.server.is_finished() {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "attach bridge stopped",
            ));
        }
        let deadline = original_authority_deadline(
            authority_expires_at,
            effect_deadline_boottime_nanoseconds,
        )?
        .min(deadline);
        self.monitors.with_original_attach_v3(
            action,
            expected_binding,
            ticket,
            ledger,
            |pending, claim, recheck| {
                transfer_original_io_v3(
                    &self.masters,
                    ledger,
                    pending,
                    claim,
                    recheck,
                    ticket,
                    expected_binding,
                    authority_expires_at,
                    effect_deadline_boottime_nanoseconds,
                    deadline,
                )
            },
        )
    }

    pub(super) fn start(ledger: Ledger) -> Result<Self, GuestProcessEffectErrorV1> {
        verify_socket_directory()?;
        let path = Path::new(SOCKET_PATH);
        let listener = bind_listener(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
        }

        let masters = Arc::new(Mutex::new(BTreeMap::new()));
        let registry = Arc::clone(&masters);
        let monitors = crate::monitor::MonitorRegistry::default();
        let monitor_registry = monitors.clone();
        let server = thread::Builder::new()
            .name("aos-guest-attach".into())
            .spawn(move || serve(listener, ledger, registry, monitor_registry))?;
        Ok(Self {
            masters,
            monitors,
            server,
        })
    }

    pub(super) fn bind_monitor_v2(
        &self,
        runtime: aos_sandbox_agent::openssh_gate_linux::OpenSshMonitorRuntimeV2,
        ticket: &[u8],
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if self.server.is_finished() {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "attach bridge stopped",
            ));
        }
        self.monitors.install(runtime, ticket)
    }

    pub(super) fn register_pty(
        &self,
        execution: [u8; 16],
        master: &OwnedFd,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if self.server.is_finished() {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "attach bridge stopped",
            ));
        }
        let duplicate = rustix::io::dup(master)?;
        let mut masters = self.masters.lock().map_err(|_| {
            GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned")
        })?;
        if masters.contains_key(&execution) {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        masters.insert(execution, AttachedIo::Pty(duplicate));
        Ok(())
    }

    pub(super) fn register_stream(
        &self,
        execution: [u8; 16],
        input: ChildStdin,
        output: ChildStdout,
        error: ChildStderr,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if self.server.is_finished() {
            return Err(GuestProcessEffectErrorV1::Unavailable(
                "attach bridge stopped",
            ));
        }
        let descriptors = AttachedIo::Stream {
            input: input.into(),
            output: output.into(),
            error: error.into(),
        };
        let mut masters = self.masters.lock().map_err(|_| {
            GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned")
        })?;
        if masters.contains_key(&execution) {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        masters.insert(execution, descriptors);
        Ok(())
    }

    /// Closes the I/O factory without discarding consumed terminal-data custody.
    ///
    /// # Errors
    /// Rejects poisoned monitor or I/O ownership locks.
    pub(super) fn finish_execution(
        &self,
        execution: [u8; 16],
    ) -> Result<(), GuestProcessEffectErrorV1> {
        // Owner effects already retain the shared barrier. Preserve lock order
        // for the later held consume: barrier, monitor custody, I/O registry.
        self.monitors.finish_execution(execution)?;
        let mut masters = self.masters.lock().map_err(|_| {
            GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned")
        })?;
        masters.remove(&execution);
        Ok(())
    }

    /// Reports retained consumed-session data ownership, not attach permission.
    ///
    /// # Errors
    /// Rejects a poisoned monitor ownership lock.
    pub(super) fn has_original_session(
        &self,
        execution: [u8; 16],
    ) -> Result<bool, GuestProcessEffectErrorV1> {
        self.monitors.has_original_session(execution)
    }
}

/// Narrows a local wait by current wall-clock expiry and the admitted BOOTTIME cut.
///
/// Repeating this nonauthorizing check detects suspension and forward wall-clock
/// changes during an effect; it does not refresh either original deadline.
///
/// # Errors
/// Rejects expired, negative, overflowing or unrepresentable deadlines.
pub(super) fn original_authority_deadline(
    expires_at: i64,
    effect_deadline_boottime_nanoseconds: u64,
) -> Result<Instant, GuestProcessEffectErrorV1> {
    let expiry = u64::try_from(expires_at)
        .map(Duration::from_secs)
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let remaining = expiry
        .checked_sub(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(boot.tv_sec).map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let nanoseconds =
        u64::try_from(boot.tv_nsec).map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let boot = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    let remaining_boot = effect_deadline_boottime_nanoseconds
        .checked_sub(boot)
        .filter(|value| *value > 0)
        .map(Duration::from_nanos)
        .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    Instant::now()
        .checked_add(remaining.min(remaining_boot))
        .ok_or(GuestProcessEffectErrorV1::InvalidRequest)
}

#[allow(clippy::too_many_arguments)]
fn transfer_original_io_v3(
    masters: &PtyRegistry,
    ledger: &Ledger,
    pending: &mut crate::monitor::RelayConnection,
    claim: &OpenSshGateClaimV1,
    recheck_custody: &mut dyn FnMut(
        &crate::monitor::RelayConnection,
    ) -> Result<(), GuestProcessEffectErrorV1>,
    ticket: &[u8],
    expected_binding: [u8; 32],
    authority_expires_at: i64,
    effect_deadline_boottime_nanoseconds: u64,
    deadline: Instant,
) -> Result<(), GuestProcessEffectErrorV1> {
    crate::process::check_deadline(deadline)?;
    let process = ledger.read_process_bytes(claim.binding.execution_id)?;
    if read_gate_claim()? != *claim || process.canceled || process.terminal.is_some() {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    // The barrier and monitor registry are already held by the caller. Keep
    // this actual original tree borrowed through SCM and its final receipt;
    // the root/relay callback below must never recursively lock ledger.live.
    let result = ledger.with_active_original_tree_v5(&process, |tree| {
        let mut masters = masters
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let io = masters
            .get(&process.execution)
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        let shape = process
            .attach_io
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        match (shape, io, claim.pty) {
            (crate::ledger::AttachIoShapeV3::Pty, AttachedIo::Pty(_), true)
            | (crate::ledger::AttachIoShapeV3::Stream, AttachedIo::Stream { .. }, false) => {}
            _ => return Err(GuestProcessEffectErrorV1::LedgerConflict),
        }

        // Every rejection above is effect-free. Even an ambiguous SCM send after
        // this exact durable reservation permanently consumes the logical slot.
        ledger.reserve_original_attach_v3(
            &process,
            aos_sandbox_agent::openssh_ticket::ticket_digest_v2(ticket),
            expected_binding,
        )?;
        crate::process::check_deadline(deadline)?;
        original_authority_deadline(authority_expires_at, effect_deadline_boottime_nanoseconds)?;
        recheck_custody(pending)?;
        if read_gate_claim()? != *claim {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        tree.require_active_original_scope(&process)?;
        crate::process::check_deadline(deadline)?;
        original_authority_deadline(authority_expires_at, effect_deadline_boottime_nanoseconds)?;
        pending.io_attempted = true;
        match io {
            AttachedIo::Pty(master) => pending
                .socket
                .send_with_descriptors(b"AOSGOK03", &[master.as_fd()])?,
            AttachedIo::Stream {
                input,
                output,
                error,
            } => pending.socket.send_with_descriptors(
                b"AOSGOS03",
                &[input.as_fd(), output.as_fd(), error.as_fd()],
            )?,
        }

        // Keep the same barrier and registry custody through kernel-identified
        // receipt. Neither reflected bytes nor an ACK can nominate another child.
        let reply = loop {
            crate::process::check_deadline(deadline)?;
            original_authority_deadline(
                authority_expires_at,
                effect_deadline_boottime_nanoseconds,
            )?;
            match pending.socket.receive(8) {
                Ok(record) => break record,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        };
        let reply = pending
            .socket
            .bind_received(reply)
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        let sender = reply.subject().credentials();
        let connector = reply.peer().credentials();
        if reply.payload() != b"AOSRID03"
            || sender.pid() != connector.pid()
            || sender.uid() != connector.uid()
            || sender.gid() != connector.gid()
            || !reply
                .subject()
                .is_alive()
                .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?
        {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        drop(reply);
        crate::process::check_deadline(deadline)?;
        original_authority_deadline(authority_expires_at, effect_deadline_boottime_nanoseconds)?;
        recheck_custody(pending)?;
        tree.require_active_original_scope(&process)?;
        masters.remove(&process.execution);
        Ok(())
    });
    if pending.io_attempted {
        // SCM may already have exposed the original descriptors. Expiry,
        // tree exit, changed custody or lost receipt cannot become a retry.
        result.map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)
    } else {
        result
    }
}

fn bind_listener(path: &Path) -> Result<RecordSubjectListener, GuestProcessEffectErrorV1> {
    match RecordSubjectListener::bind(path, 16) {
        Ok(listener) => Ok(listener),
        Err(SeqpacketError::Kernel(LinuxError::Syscall { source, .. }))
            if source.kind() == std::io::ErrorKind::AddrInUse =>
        {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.file_type().is_socket() || metadata.uid() != 0 {
                return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
            }
            match SeqpacketSocket::connect(path) {
                Err(SeqpacketError::Kernel(LinuxError::Syscall { source, .. }))
                    if source.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    fs::remove_file(path)?;
                    Ok(RecordSubjectListener::bind(path, 16)?)
                }
                Ok(_) | Err(_) => Err(GuestProcessEffectErrorV1::Unavailable(
                    "attach socket is owned by another process",
                )),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_socket_directory() -> Result<(), GuestProcessEffectErrorV1> {
    let run = fs::symlink_metadata("/run")?;
    if !run.is_dir() || run.uid() != 0 || run.mode() & 0o022 != 0 {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    let path = Path::new(SOCKET_DIRECTORY);
    if !path.exists() {
        fs::DirBuilder::new().mode(0o755).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    Ok(())
}

fn serve(
    mut listener: RecordSubjectListener,
    ledger: Ledger,
    masters: PtyRegistry,
    monitors: crate::monitor::MonitorRegistry,
) {
    loop {
        // One held barrier covers the real disconnect sample, subtree kill,
        // recursive-empty/leader-exit evidence and durable terminal record.
        let barrier = ledger.effect_barrier();
        if let Ok(_current) = barrier.lock() {
            match monitors.prune_closed(&ledger) {
                Ok(Some(execution)) => {
                    if let Ok(mut masters) = masters.lock() {
                        masters.remove(&execution);
                    }
                }
                Ok(None) => {}
                Err(_) => {} // The canceled durable row already forecloses IO.
            }
        } else {
            break;
        }
        if listener.validate_current().is_err() {
            break;
        }
        match listener.accept() {
            Ok(socket) => {
                if socket.peer().credentials().uid() == 0 {
                    // Only the measured live monitor can retain a binding.
                    // Registration exposes no I/O and never reaches reserve.
                    let barrier = ledger.effect_barrier();
                    if let Ok(_current) = barrier.lock() {
                        let _ = monitors.register(socket, &ledger);
                    }
                    continue;
                }
                if std::fs::symlink_metadata(
                    aos_sandbox_agent::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2,
                )
                .is_ok()
                {
                    // The empty internal-relay request can only join the exact
                    // pidfd received from the measured root monitor. It never
                    // transfers descriptors or accepts reflected claim bytes.
                    let _ = monitors.queue_relay(socket, &ledger);
                    continue;
                }
                // Every accepted socket carries a pinned peer and a per-record
                // subject. A denied request closes without an FD or success byte.
                // Ticket absence is not a legacy ancestry/byte1 shortcut.
                // Only the typed original-monitor V3 owner consume sends IO.
                drop(socket);
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
    monitors.close();
}

fn read_gate_claim() -> Result<OpenSshGateClaimV1, GuestProcessEffectErrorV1> {
    for parent in ["/etc", "/etc/aos", "/etc/aos/sandbox-attach"] {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(GATE_RECORD)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_GATE_RECORD_BYTES
    {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    let mut bytes = Vec::new();
    file.take(MAX_GATE_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_GATE_RECORD_BYTES {
        return Err(GuestProcessEffectErrorV1::LedgerConflict);
    }
    let claim: OpenSshGateClaimV1 =
        serde_json::from_slice(&bytes).map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    claim
        .validate()
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let canonical =
        serde_json::to_vec(&claim).map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let now =
        i64::try_from(now.as_secs()).map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    if canonical != bytes || claim.binding.expires_at <= now {
        return Err(GuestProcessEffectErrorV1::LedgerConflict);
    }
    Ok(claim)
}

pub(super) fn request_matches(
    request: &OpenSshGateBridgeRequestV1,
    claim: &OpenSshGateClaimV1,
    process: &crate::ledger::ProcessRecord,
) -> bool {
    let binding = &claim.binding;
    request.operation == binding.attach_operation_id
        && request.execution == binding.execution_id
        && request.execution == process.execution
        && request.incarnation == binding.incarnation_id
        && request.incarnation == process.incarnation
        && request.assignment_epoch == binding.assignment_epoch
        && request.assignment_epoch == process.assignment_epoch
        && request.principal == binding.principal_id
        && request.principal == process.principal
        && request.audit == binding.audit_id
        && request.audit == process.audit
        && request.route_digest == claim.route_digest
        && request.runtime_identity == claim.runtime_identity
        && request.runtime_identity == process.runtime
        && request.process_pid == claim.process_pid
        && request.process_pid == process.pid
        && request.process_start_ticks == claim.process_start_ticks
        && request.process_start_ticks == process.start_ticks
        && claim.pty == process.pty
}
