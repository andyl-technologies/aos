//! Fixed guest PID 1 bootstrap for inherited agent and attach-trust descriptors.
//!
//! Nspawn delivers one connected channel at FD 3 and fully sealed launch
//! records at FD 4 and FD 5. FD 6 pins the existing mounted payload cgroup;
//! sealed FD 7 joins its inode to the original provisioning inode without
//! copying a key or creating a grant. This bootstrap adopts the whole table
//! before duplicates, checks runtime binding, installs the OpenSSH trust at
//! fixed protected paths, starts the only agent, and execs AOS systemd.
//! No request or environment variable can select a path or executable.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use aos_sandbox_guest_protocol::guest_attach_trust::{
    GuestAttachTrustRecordV1, MAX_GUEST_ATTACH_TRUST_BYTES,
};
use aos_sandbox_guest_protocol::launch::GUEST_AGENT_PROVISIONING_BYTES_V1;
use aos_sandbox_guest::protected_entry::{
    validated_guest_agent_runtime_prefix_v1,
};
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::inherited_fd::{
    duplicate_inherited_descriptor,
    mark_inherited_descriptor_close_on_exec,
};
use aos_sandbox_linux::seqpacket::{
    SeqpacketSocket,
};
use sha2::{Digest as _, Sha256};
use aos_sandbox_linux::guest_startup_report::{GuestStartupReportOriginalV1, HostStartupReportKindV1};

const CHANNEL_FD: i32 = 3;
const PROVISIONING_FD: i32 = 4;
const ATTACH_TRUST_FD: i32 = 5;
const AGENT_PATH: &str = "/usr/libexec/aos-sandbox-guest-agent";
const SYSTEMD_PATH: &str = "/usr/lib/systemd/systemd";
const TRUST_DIRECTORY: &str = "/etc/aos/sandbox-attach";
const HOST_KEY_PATH: &str = "/etc/aos/sandbox-attach/host_key";
const HOST_PUBLIC_PATH: &str = "/etc/aos/sandbox-attach/host_key.pub";
const CA_PUBLIC_PATH: &str = "/etc/aos/sandbox-attach/trusted_user_ca.pub";
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::process::id() != 1 || rustix::process::geteuid().as_raw() != 0 {
        return Err("guest bootstrap must be root PID 1".into());
    }
    if std::env::args_os().len() != 1 {
        return Err("guest bootstrap accepts no arguments".into());
    }
    let mut report = GuestStartupReportOriginalV1::new();
    if report.capture_original()? {
        let (runtime, channel) = report.with_launch_bytes_v1(|bytes| {
            let runtime = validated_guest_agent_runtime_prefix_v1(bytes)?;
            let channel = bytes[112..144].try_into()
                .map_err(|_| aos_sandbox_guest::protected_entry::ProtectedGuestAgentErrorV1::InvalidProvisioning)?;
            Ok::<_, aos_sandbox_guest::protected_entry::ProtectedGuestAgentErrorV1>((runtime, channel))
        })??;
        report.bind_launch_once_v1(&runtime, channel)?;
    }
    let canary_selected = report.kind_data_v1() == Some(HostStartupReportKindV1::Canary);
    aos_sandbox_linux::guest_confinement::prepare_guest_runtime_anchors()?;
    aos_sandbox_guest_root_realization::guest_root_label::label_fresh_guest_manager_before_v1()?;

    let mut normal = (!canary_selected).then(|| Box::new(GuestPid1NormalOriginalV1::new()));
    let body = launch_actual_agent_and_systemd(&mut report, canary_selected, normal.as_deref_mut());
    match body {
        Ok(()) => Ok(()),
        Err(cause) => {
            if let Some(mut original) = normal {
                original.cause = Some(cause);
                if original.topology.requires_original_guardian_hold_v1() {
                    eprintln!("Guest PID1 startup remains occupied: {original}");
                    loop { std::hint::black_box(&original); std::thread::park(); }
                }
                return Err(original);
            }
            Err(cause)
        }
    }
}

fn launch_actual_agent_and_systemd(report: &mut GuestStartupReportOriginalV1, canary_selected: bool,
    normal: Option<&mut GuestPid1NormalOriginalV1>) -> Result<(), Box<dyn std::error::Error>>
{
    let (topology, mut spawn) = match normal {
        Some(original) => (Some(&mut original.topology), Some(&mut original.spawn)),
        None => (None, None),
    };
    let mut topology = topology;

    // Adopt original slots 6/7 before any startup duplicate can reuse them.
    // Their fixed originals remain live only through the one Agent spawn.
    let ordinary = if let Some(topology) = topology.as_mut() {
        topology.capture_initial_pid1_once_v1()?;
        None
    } else {
        let cgroup = aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1::from_inherited()?;
        let root = cgroup.execution_root()?;
        Some((cgroup, root))
    };
    let (cgroup, execution_root) = match ordinary.as_ref() {
        Some((cgroup, root)) => (cgroup, root),
        None => topology.as_ref().and_then(|original| original.borrow_pid1_parts_v1())
            .ok_or("completed PID1 topology has no original native roots")?,
    };
    // Both report kinds already retain and compare the actual ancestor-Host
    // FD3/FD8 pins. The ordinary peer decoder cannot name namespace-local
    // PID0; preserve that old route only when no startup report is selected.
    let channel = if report.kind_data_v1().is_none() {
        Some(duplicate_inherited_descriptor(CHANNEL_FD)?)
    } else {
        None
    };
    let provisioning = cgroup.original_provisioning()?;
    let trust = duplicate_inherited_descriptor(ATTACH_TRUST_FD)?;
    let socket = if let Some(channel) = channel {
        let socket = SeqpacketSocket::from_owned(channel)?;
        if !socket.peer().pidfd().is_alive()?
            || socket.peer().credentials().pid().get() == std::process::id()
        {
            return Err("guest agent channel peer is unavailable".into());
        }
        Some(socket)
    } else {
        None
    };

    let (runtime, report_channel) = SealedMemfdMapping::run(
        provisioning,
        GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
        GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
        |bytes, _identity| {
            let runtime = validated_guest_agent_runtime_prefix_v1(bytes)?;
            let channel = if report.kind_data_v1().is_some() {
                let mut channel = [0; 32];
                channel.copy_from_slice(&bytes[112..144]);
                Some(channel)
            } else {
                None
            };
            Ok::<_, aos_sandbox_guest::protected_entry::ProtectedGuestAgentErrorV1>(
                (runtime, channel),
            )
        },
    )??;
    let trust_file = File::from(trust);
    let trust_length = trust_file.metadata()?.len();
    if trust_length == 0 || trust_length > MAX_GUEST_ATTACH_TRUST_BYTES as u64 {
        return Err("guest attach-trust credential size is invalid".into());
    }
    let trust = SealedMemfdMapping::run(
        trust_file.into(),
        trust_length,
        MAX_GUEST_ATTACH_TRUST_BYTES as u64,
        |bytes, _identity| GuestAttachTrustRecordV1::decode(bytes),
    )??;
    if trust.runtime_bytes() != &runtime {
        return Err("guest attach-trust runtime differs from provisioning".into());
    }

    install_trust(&trust)?;
    drop(trust);
    mark_inherited_descriptor_close_on_exec(ATTACH_TRUST_FD)?;
    // SAFETY: fixed nspawn startup gives PID 1 sole ownership of FD 5; no
    // Rust owner represents the original descriptor, only its closed clone.
    drop(unsafe { OwnedFd::from_raw_fd(ATTACH_TRUST_FD) });

    verify_executable(AGENT_PATH)?;
    verify_executable(SYSTEMD_PATH)?;
    if let Some(channel) = report_channel {
        report.report_original(&runtime, channel)?;
    }
    if canary_selected {
        report.spawn_agent_original()?;
    } else {
        let mut agent = Command::new(AGENT_PATH);
        agent.env_clear();
        agent.stdin(Stdio::null());
        agent.stdout(Stdio::null());
        agent.stderr(Stdio::null());
        let actual = spawn.as_deref_mut().ok_or("normal Agent spawn original is absent")?;
        actual.capture_once(&mut agent)?;
        if report.kind_data_v1() == Some(HostStartupReportKindV1::Component) {
            let child = actual.spawned.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or("normal Agent Child original is absent")?;
            report.report_component_agent_once_v1(child)?;
        }
    }

    for descriptor in [6, 7] {
        mark_inherited_descriptor_close_on_exec(descriptor)?;
        // SAFETY: fixed nspawn startup retains these numeric originals solely
        // for this Agent spawn. Rust owns only separate CLOEXEC duplicates.
        drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
    }
    let _ = (cgroup, execution_root);
    drop(ordinary);
    drop(socket);

    if let Some(topology) = topology.as_mut() {
        let child = spawn.as_ref().and_then(|original| original.process.as_ref())
            .ok_or("actual Agent child pidfd is absent before completion")?;
        topology.wait_actual_agent_topology_once_v1(child)?;
        topology.prepare_systemd_exec_once_v1()?;
    }

    mark_inherited_descriptor_close_on_exec(CHANNEL_FD)?;
    mark_inherited_descriptor_close_on_exec(PROVISIONING_FD)?;
    if report.kind_data_v1().is_some() {
        report.prepare_systemd_exec()?;
    }
    let mut systemd = Command::new(SYSTEMD_PATH);
    match report.kind_data_v1() {
        Some(HostStartupReportKindV1::Canary) => { systemd.arg("--aos-host-readiness-report"); }
        Some(HostStartupReportKindV1::Component) => { systemd.arg("--aos-host-component-readiness-report"); }
        None => {}
    }
    systemd.env_clear();
    Err(systemd.exec().into())
}

struct GuestPid1AgentSpawnOriginalV1 {
    spawned: Option<std::io::Result<Child>>,
    pidfd: aos_sandbox_linux::pidfd::PidFdOpenAttemptV1,
    process: Option<aos_linux_descriptors::pidfd::PidFd>,
    identity: Option<Box<aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1>>,
}

impl GuestPid1AgentSpawnOriginalV1 {
    fn new() -> Self {
        Self { spawned: None, pidfd: aos_sandbox_linux::pidfd::PidFdOpenAttemptV1::new(),
            process: None, identity: None }
    }

    fn capture_once(&mut self, agent: &mut Command) -> Result<(), Box<dyn std::error::Error>> {
        if self.spawned.is_some() { return Err("original Agent child spawn already entered".into()); }
        self.spawned = Some(agent.spawn());
        let child = self.spawned.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or("actual Agent child spawn refused")?;
        let pid = std::num::NonZeroU32::new(child.id()).ok_or("actual Agent child PID is zero")?;
        self.pidfd.capture_once(pid)?;
        self.process = self.pidfd.take_validated();
        self.identity = Some(Box::new(aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1::new()));
        let original = self.identity.as_mut().ok_or("Agent identity original is absent")?;
        original.capture_once(self.process.as_ref().ok_or("Agent original pidfd is absent")?)?;
        let identity = original.identity().ok_or("Agent original identity is absent")?;
        // The same unreaped Child reserves this PID throughout pidfd capture.
        // Its own fixed startup may already have moved it to the Agent leaf.
        if identity.pid() != child.id() || identity.thread_group_id() != child.id()
            || identity.parent_pid() != 1
        { return Err("actual Agent child parent/identity changed".into()); }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.spawned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.pidfd.failure().map(|cause| cause as _))
            .or_else(|| self.identity.as_ref().and_then(|original| original.failure()).map(|cause| cause as _))
    }
}

struct GuestPid1NormalOriginalV1 {
    topology: Box<aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1>,
    spawn: GuestPid1AgentSpawnOriginalV1,
    cause: Option<Box<dyn std::error::Error>>,
}

impl GuestPid1NormalOriginalV1 {
    fn new() -> Self {
        Self { topology: Box::new(aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1::new()),
            spawn: GuestPid1AgentSpawnOriginalV1::new(), cause: None }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.topology.failure().or_else(|| self.spawn.failure()).or(self.cause.as_deref())
    }
}

impl std::fmt::Debug for GuestPid1NormalOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("GuestPid1NormalOriginalV1").field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for GuestPid1NormalOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() { Some(cause) => write!(formatter, "{cause}"),
            None => formatter.write_str("actual Guest PID1 startup remains occupied") }
    }
}

impl std::error::Error for GuestPid1NormalOriginalV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}

const _: () = {
    let header = 2 * std::mem::size_of::<GuestPid1NormalOriginalV1>()
        + 2 * std::mem::size_of::<Command>() + 4 * AGENT_PATH.len() + 4 * SYSTEMD_PATH.len();
    assert!(header <= aos_sandbox_linux::guest_cgroup::GUEST_PID1_STARTUP_CONTROL_BYTES_V1);
};


fn install_trust(record: &GuestAttachTrustRecordV1) -> Result<(), Box<dyn std::error::Error>> {
    for directory in ["/etc", "/etc/aos", TRUST_DIRECTORY] {
        if !Path::new(directory).exists() {
            fs::create_dir(directory)?;
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("guest trust directory is unprotected".into());
        }
    }

    write_new_protected(HOST_KEY_PATH, record.private_key_bytes(), 0o600)?;
    let mut host_public = record.host_public_key_bytes().to_vec();
    host_public.push(b'\n');
    write_new_protected(HOST_PUBLIC_PATH, &host_public, 0o644)?;
    let mut ca_public = record.trusted_ca_public_key_bytes().to_vec();
    ca_public.push(b'\n');
    write_new_protected(CA_PUBLIC_PATH, &ca_public, 0o644)?;
    File::open(TRUST_DIRECTORY)?.sync_all()?;
    Ok(())
}

fn write_new_protected(
    path: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn verify_executable(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    for directory in ["/usr", "/usr/lib", "/usr/libexec", "/usr/lib/systemd"] {
        if !Path::new(path).starts_with(directory) {
            continue;
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("guest bootstrap executable directory is unprotected".into());
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err("guest bootstrap executable is unprotected".into());
    }
    Ok(())
}
