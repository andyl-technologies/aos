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

use aos_sandbox_guest_protocol::openssh_gate::{OpenSshGateBridgeRequestV1, OpenSshGateClaimV1};
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

/// Retains the exact startup descriptors until the existing registry accepts them.
pub(super) struct AttachIoRegistrationOriginalV1 {
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    error: Option<ChildStderr>,
    duplicate: Option<rustix::io::Result<OwnedFd>>,
    result: Option<Result<(), GuestProcessEffectErrorV1>>,
    entered: bool,
}

impl AttachIoRegistrationOriginalV1 {
    pub(super) fn new(input: Option<ChildStdin>, output: Option<ChildStdout>,
        error: Option<ChildStderr>) -> Self
    {
        Self { input, output, error, duplicate: None, result: None, entered: false }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.duplicate.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
    }
}

type PtyRegistry = Arc<Mutex<BTreeMap<[u8; 16], AttachedIo>>>;

/// Distinguishes retained original terminal channels from physical retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OriginalIoDispositionV1 {
    Pending,
    Disposed,
}

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
        action: aos_sandbox_guest_protocol::openssh_control_channel::OriginalControlActionV5,
        binding: [u8; 32],
        request: &[u8],
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        ticket: &[u8],
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<
        aos_sandbox_guest_protocol::openssh_control_channel::OriginalControlObservationV5,
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
        action: aos_sandbox_guest_protocol::openssh_consume::OriginalAttachActionV3,
        expected_binding: [u8; 32],
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        ticket: &[u8],
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<
        aos_sandbox_guest_protocol::openssh_consume::OriginalAttachObservationV3,
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

    pub(super) fn prune_original_disconnects_v1(&self, ledger: &Ledger)
        -> Result<Option<[u8; 16]>, GuestProcessEffectErrorV1>
    {
        self.monitors.prune_closed(ledger)
    }

    pub(super) fn bind_monitor_v2(
        &self,
        runtime: crate::openssh_gate_linux::OpenSshMonitorRuntimeV2,
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
        let mut original = AttachIoRegistrationOriginalV1::new(None, None, None);
        let _ = self.register_original_once(execution, Some(master), &mut original);
        original.result.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
    }

    pub(super) fn register_stream(
        &self,
        execution: [u8; 16],
        input: ChildStdin,
        output: ChildStdout,
        error: ChildStderr,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        let mut original = AttachIoRegistrationOriginalV1::new(Some(input), Some(output), Some(error));
        let _ = self.register_original_once(execution, None, &mut original);
        original.result.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
    }

    pub(super) fn register_original_once(
        &self,
        execution: [u8; 16],
        master: Option<&OwnedFd>,
        original: &mut AttachIoRegistrationOriginalV1,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if original.entered {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        original.entered = true;
        let result = (|| {
            if self.server.is_finished() {
                return Err(GuestProcessEffectErrorV1::Unavailable("attach bridge stopped"));
            }
            if let Some(master) = master {
                original.duplicate = Some(rustix::io::dup(master));
                if let Some(Err(cause)) = original.duplicate.as_ref() {
                    return Err((*cause).into());
                }
            } else if original.input.is_none() || original.output.is_none() || original.error.is_none() {
                return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
            }
            let mut masters = self.masters.lock().map_err(|_| {
                GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned")
            })?;
            if masters.contains_key(&execution) {
                return Err(GuestProcessEffectErrorV1::LedgerConflict);
            }
            // No fallible native work follows these moves. The SAME owners
            // enter the existing registry only after its complete acceptance.
            let descriptors = if master.is_some() {
                match original.duplicate.take() {
                    Some(Ok(duplicate)) => AttachedIo::Pty(duplicate),
                    _ => return Err(GuestProcessEffectErrorV1::AmbiguousEffect),
                }
            } else {
                match (original.input.take(), original.output.take(), original.error.take()) {
                    (Some(input), Some(output), Some(error)) => AttachedIo::Stream {
                        input: input.into(), output: output.into(), error: error.into(),
                    },
                    (input, output, error) => {
                        original.input = input;
                        original.output = output;
                        original.error = error;
                        return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
                    }
                }
            };
            masters.insert(execution, descriptors);
            Ok(())
        })();
        let positive = result.is_ok();
        original.result = Some(result);
        if positive { Ok(()) } else { Err(GuestProcessEffectErrorV1::AmbiguousEffect) }
    }

    /// Closes the I/O factory without discarding consumed terminal-data custody.
    ///
    /// # Errors
    /// Rejects poisoned monitor or I/O ownership locks.
    pub(super) fn finish_execution(
        &self,
        execution: [u8; 16],
    ) -> Result<OriginalIoDispositionV1, GuestProcessEffectErrorV1> {
        // Owner effects already retain the shared barrier. Preserve lock order
        // for the later held consume: barrier, monitor custody, I/O registry.
        let monitors_disposed = self.monitors.finish_execution(execution)?;
        let mut masters = self.masters.lock().map_err(|_| {
            GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned")
        })?;
        masters.remove(&execution);
        drop(masters);
        // The consumed original channel learns durable waitstatus through
        // MonitorRegistry's terminal-data path before the signed Agent reply.
        // Keep its Process/gate charged until that exact channel is pruned.
        if monitors_disposed {
            Ok(OriginalIoDispositionV1::Disposed)
        } else {
            Ok(OriginalIoDispositionV1::Pending)
        }
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
            aos_sandbox_guest_protocol::openssh_ticket::ticket_digest_v2(ticket),
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
            let _ = crate::process::poll_original_execution_timeouts_v1(ledger);
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
    let mut listener_current = None;
    loop {
        // A standing execution timeout is independent of fresh Host/monitor
        // traffic and its global effect barrier. This step only advances fixed
        // native kill/population/reap destinations; the actor publishes later.
        let _ = crate::process::poll_original_execution_timeouts_v1(&ledger);
        if monitors.registration_refused() {
            // Keep the entered failed registration and listener in this sole
            // actor. Do not accept a replacement or accumulate failed sockets.
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        if !listener_current.as_ref().is_some_and(Result::is_err) {
            listener_current = Some(listener.validate_current());
        }
        if listener_current.as_ref().is_some_and(Result::is_err) {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        match listener.accept() {
            Ok(socket) => {
                if socket.peer().credentials().uid() == 0 {
                    // Only the measured live monitor can retain a binding.
                    // Registration exposes no I/O and never reaches reserve.
                    let barrier = ledger.effect_barrier();
                    if let Ok(_current) = lock_effect_barrier_with_deadlines(&barrier, &ledger) {
                        let _ = monitors.register(socket, &ledger);
                    }
                    continue;
                }
                if std::fs::symlink_metadata(
                    aos_sandbox_guest_protocol::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2,
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
}

pub(super) fn lock_effect_barrier_with_deadlines<'barrier>(
    barrier: &'barrier Mutex<()>, ledger: &Ledger,
) -> Result<std::sync::MutexGuard<'barrier, ()>, GuestProcessEffectErrorV1> {
    loop {
        match barrier.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) =>
                return Err(GuestProcessEffectErrorV1::LedgerConflict),
            Err(std::sync::TryLockError::WouldBlock) => {
                let _ = crate::process::poll_original_execution_timeouts_v1(ledger);
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
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

#[cfg(test)]
mod startup_registration_tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn refused_registry_retains_actual_duplicate_until_original_is_disposed() {
        let master: OwnedFd = std::fs::File::open(std::env::current_exe().unwrap()).unwrap().into();
        let execution = [7; 16];
        let mut entries = BTreeMap::new();
        entries.insert(execution, AttachedIo::Pty(rustix::io::dup(&master).unwrap()));
        let (release, wait) = std::sync::mpsc::channel();
        let bridge = AttachBridge {
            masters: Arc::new(Mutex::new(entries)),
            monitors: crate::monitor::MonitorRegistry::default(),
            server: std::thread::spawn(move || { let _ = wait.recv(); }),
        };
        let mut original = AttachIoRegistrationOriginalV1::new(None, None, None);

        assert!(bridge.register_original_once(execution, Some(&master), &mut original).is_err());
        assert!(matches!(original.result, Some(Err(GuestProcessEffectErrorV1::LedgerConflict))));
        let duplicate = original.duplicate.as_ref().unwrap().as_ref().unwrap();
        assert!(rustix::io::fcntl_getfd(duplicate).is_ok());
        let native_path = format!("/proc/self/fd/{}", duplicate.as_raw_fd());
        assert!(std::fs::read_link(&native_path).is_ok());
        assert!(original.failure().is_some());

        drop(original);
        assert!(std::fs::read_link(native_path).is_err());
        release.send(()).unwrap();
        bridge.server.join().unwrap();
    }

    #[test]
    fn no_session_disposition_closes_the_actual_io_master_before_completing() {
        let descriptor: OwnedFd = std::fs::File::open(std::env::current_exe().unwrap()).unwrap().into();
        let path = format!("/proc/self/fd/{}", descriptor.as_raw_fd());
        let execution = [8; 16];
        let mut entries = BTreeMap::new();
        entries.insert(execution, AttachedIo::Pty(descriptor));
        let (release, wait) = std::sync::mpsc::channel();
        let bridge = AttachBridge {
            masters: Arc::new(Mutex::new(entries)),
            monitors: crate::monitor::MonitorRegistry::default(),
            server: std::thread::spawn(move || { let _ = wait.recv(); }),
        };

        assert!(std::fs::read_link(&path).is_ok());
        assert_eq!(bridge.finish_execution(execution).unwrap(), OriginalIoDispositionV1::Disposed);
        assert!(std::fs::read_link(path).is_err());
        assert!(bridge.masters.lock().unwrap().is_empty());

        release.send(()).unwrap();
        bridge.server.join().unwrap();
    }
}
