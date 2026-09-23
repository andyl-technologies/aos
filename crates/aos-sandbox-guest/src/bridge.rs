//! Fixed guest-local PTY descriptor handoff for the authenticated SSH gate.
//!
//! The root-owned process ledger owns the PTY master. This socket hands one
//! duplicate to one kernel-identified forced-command gate only after reading
//! back the installed route claim and the current process identity.

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

use aos_sandbox_linux::Error as LinuxError;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError, SeqpacketSocket};
use serde::{Deserialize, Serialize};

use crate::GuestProcessEffectErrorV1;
use crate::ledger::Ledger;
use crate::process::{process_identity, process_matches};

const SOCKET_DIRECTORY: &str = "/run/aos-sandbox-agent";
const SOCKET_PATH: &str = "/run/aos-sandbox-agent/exec-gate.sock";
const GATE_EXECUTABLE: &str = "/usr/libexec/aos-sandbox-exec-gate";
const SSHD_SESSION_EXECUTABLE: &str = "/usr/libexec/sshd-session";
const GATE_RECORD: &str = "/etc/aos/sandbox-attach/gate-record.json";
const REQUEST_BYTES: usize = 172;
const MAX_GATE_RECORD_BYTES: u64 = 16 * 1024;
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;
const PEER_DEADLINE: Duration = Duration::from_secs(5);

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
    server: JoinHandle<()>,
}

impl AttachBridge {
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
        let server = thread::Builder::new()
            .name("aos-guest-attach".into())
            .spawn(move || serve(listener, ledger, registry))?;
        Ok(Self { masters, server })
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

    pub(super) fn remove(&self, execution: [u8; 16]) -> Result<(), GuestProcessEffectErrorV1> {
        let mut masters = self.masters.lock().map_err(|_| {
            GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned")
        })?;
        masters.remove(&execution);
        Ok(())
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

fn serve(mut listener: RecordSubjectListener, ledger: Ledger, masters: PtyRegistry) {
    loop {
        if listener.validate_current().is_err() {
            return;
        }
        match listener.accept() {
            Ok(mut socket) => {
                // Every accepted socket carries a pinned peer and a per-record
                // subject. A denied request closes without an FD or success byte.
                let _ = serve_one(&mut socket, &ledger, &masters);
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn serve_one(
    socket: &mut SeqpacketSocket,
    ledger: &Ledger,
    masters: &PtyRegistry,
) -> Result<(), GuestProcessEffectErrorV1> {
    verify_executable(socket.peer().credentials().pid().get(), GATE_EXECUTABLE)?;
    let deadline = Instant::now() + PEER_DEADLINE;
    let received = loop {
        match socket.receive(REQUEST_BYTES) {
            Ok(record) => break record,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    let request = decode_request(received.payload())?;
    let peer = socket.peer();
    let connector = peer.credentials();
    let subject = received.subject();
    let nominated = subject.credentials();
    if connector.pid() != nominated.pid()
        || connector.uid() != nominated.uid()
        || connector.gid() != nominated.gid()
        || !peer
            .is_alive()
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?
        || !subject
            .is_alive()
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }

    let claim = read_gate_claim()?;
    let process = ledger.read_process_bytes(request.execution)?;
    if !request.matches(&claim, &process)
        || connector.uid() != process.uid
        || !process.pty
        || process.canceled
        || process.terminal.is_some()
        || !process_matches(&process)?
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    verify_gate_peer(
        connector.pid().get(),
        claim.sshd_pid,
        claim.sshd_start_ticks,
    )?;

    let mut masters = masters
        .lock()
        .map_err(|_| GuestProcessEffectErrorV1::Unavailable("attach bridge registry poisoned"))?;
    let descriptors =
        masters
            .get(&request.execution)
            .ok_or(GuestProcessEffectErrorV1::Unavailable(
                "execution I/O is not held",
            ))?;
    if !peer
        .is_alive()
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?
        || !subject
            .is_alive()
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }

    // The durable reservation precedes SCM_RIGHTS. A crash or short send may
    // consume the attach right, but cannot permit duplicate terminal holders.
    ledger.reserve_attach(request.execution)?;
    match descriptors {
        AttachedIo::Pty(master) if claim.pty => {
            socket.send_with_descriptors(b"AOSGOK01", &[master.as_fd()])?;
        }
        AttachedIo::Stream {
            input,
            output,
            error,
        } if !claim.pty => {
            socket.send_with_descriptors(
                b"AOSGOS01",
                &[input.as_fd(), output.as_fd(), error.as_fd()],
            )?;
        }
        _ => return Err(GuestProcessEffectErrorV1::LedgerConflict),
    }
    masters.remove(&request.execution);
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GateClaim {
    binding: GateBinding,
    route_digest: [u8; 32],
    runtime_identity: [u8; 32],
    process_pid: u32,
    process_start_ticks: u64,
    pty: bool,
    sshd_pid: u32,
    sshd_start_ticks: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GateBinding {
    attach_operation_id: [u8; 16],
    execution_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    principal_id: [u8; 16],
    audit_id: [u8; 16],
    user: String,
    port: u16,
    host_public_key: String,
    trusted_user_ca_public_key: String,
    expires_at: i64,
    gate_config_digest: [u8; 32],
}

fn read_gate_claim() -> Result<GateClaim, GuestProcessEffectErrorV1> {
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
    let claim: GateClaim =
        serde_json::from_slice(&bytes).map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let canonical =
        serde_json::to_vec(&claim).map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    let now =
        i64::try_from(now.as_secs()).map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
    if canonical != bytes
        || claim.sshd_pid == 0
        || claim.sshd_start_ticks == 0
        || claim.binding.expires_at <= now
        || claim.binding.user.is_empty()
        || claim.binding.port == 0
        || claim.binding.host_public_key.is_empty()
        || claim.binding.trusted_user_ca_public_key.is_empty()
        || claim.binding.gate_config_digest == [0; 32]
        || claim.route_digest == [0; 32]
    {
        return Err(GuestProcessEffectErrorV1::LedgerConflict);
    }
    Ok(claim)
}

struct BridgeRequest {
    operation: [u8; 16],
    execution: [u8; 16],
    incarnation: [u8; 16],
    assignment_epoch: u64,
    principal: [u8; 16],
    audit: [u8; 16],
    route_digest: [u8; 32],
    runtime_identity: [u8; 32],
    process_pid: u32,
    process_start_ticks: u64,
}

impl BridgeRequest {
    fn matches(&self, claim: &GateClaim, process: &crate::ledger::ProcessRecord) -> bool {
        let binding = &claim.binding;
        self.operation == binding.attach_operation_id
            && self.execution == binding.execution_id
            && self.execution == process.execution
            && self.incarnation == binding.incarnation_id
            && self.incarnation == process.incarnation
            && self.assignment_epoch == binding.assignment_epoch
            && self.assignment_epoch == process.assignment_epoch
            && self.principal == binding.principal_id
            && self.principal == process.principal
            && self.audit == binding.audit_id
            && self.audit == process.audit
            && self.route_digest == claim.route_digest
            && self.runtime_identity == claim.runtime_identity
            && self.runtime_identity == process.runtime
            && self.process_pid == claim.process_pid
            && self.process_pid == process.pid
            && self.process_start_ticks == claim.process_start_ticks
            && self.process_start_ticks == process.start_ticks
            && claim.pty == process.pty
    }
}

fn decode_request(bytes: &[u8]) -> Result<BridgeRequest, GuestProcessEffectErrorV1> {
    if bytes.len() != REQUEST_BYTES || bytes.get(..8) != Some(b"AOSGAB01".as_slice()) {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    let mut offset = 8;
    let operation = take::<16>(bytes, &mut offset)?;
    let execution = take::<16>(bytes, &mut offset)?;
    let incarnation = take::<16>(bytes, &mut offset)?;
    let assignment_epoch = u64::from_be_bytes(take(bytes, &mut offset)?);
    let principal = take::<16>(bytes, &mut offset)?;
    let audit = take::<16>(bytes, &mut offset)?;
    let route_digest = take::<32>(bytes, &mut offset)?;
    let runtime_identity = take::<32>(bytes, &mut offset)?;
    let process_pid = u32::from_be_bytes(take(bytes, &mut offset)?);
    let process_start_ticks = u64::from_be_bytes(take(bytes, &mut offset)?);
    if offset != REQUEST_BYTES {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    Ok(BridgeRequest {
        operation,
        execution,
        incarnation,
        assignment_epoch,
        principal,
        audit,
        route_digest,
        runtime_identity,
        process_pid,
        process_start_ticks,
    })
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], GuestProcessEffectErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    let mut result = [0_u8; N];
    result.copy_from_slice(slice);
    *offset = end;
    Ok(result)
}

fn verify_gate_peer(
    pid: u32,
    sshd_pid: u32,
    sshd_start_ticks: u64,
) -> Result<(), GuestProcessEffectErrorV1> {
    verify_executable(pid, GATE_EXECUTABLE)?;
    let gate = process_identity(pid)?.ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
    verify_executable(gate.parent, SSHD_SESSION_EXECUTABLE)?;

    let mut ancestor = gate.parent;
    for _ in 0..16 {
        let identity =
            process_identity(ancestor)?.ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        if ancestor == sshd_pid {
            if identity.start_ticks == sshd_start_ticks {
                return Ok(());
            }
            break;
        }
        if identity.parent == 0 || identity.parent == ancestor {
            break;
        }
        ancestor = identity.parent;
    }
    Err(GuestProcessEffectErrorV1::InvalidRequest)
}

fn verify_executable(pid: u32, expected: &str) -> Result<(), GuestProcessEffectErrorV1> {
    let installed = fs::metadata(expected)?;
    let observed = fs::metadata(format!("/proc/{pid}/exe"))?;
    if !installed.is_file()
        || installed.uid() != 0
        || installed.mode() & 0o022 != 0
        || installed.dev() != observed.dev()
        || installed.ino() != observed.ino()
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    Ok(())
}
