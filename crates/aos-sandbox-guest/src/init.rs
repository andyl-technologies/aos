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

use aos_sandbox_agent::guest_attach_trust::{
    GuestAttachTrustRecordV1, MAX_GUEST_ATTACH_TRUST_BYTES,
};
use aos_sandbox_agent::protected_entry::{
    GUEST_AGENT_PROVISIONING_BYTES_V1, validated_guest_agent_runtime_prefix_v1,
    require_host_canary_challenge_v1,
};
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::pidfd::HostCanaryLocalChildOriginalsV1;
use aos_sandbox_linux::inherited_fd::{
    GuestCanaryReportOriginalV1, duplicate_inherited_descriptor,
    mark_inherited_descriptor_close_on_exec,
};
use aos_sandbox_linux::seqpacket::{
    GuestAncestorHostChannelV1, GuestAncestorHostRecordV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketError, SeqpacketSocket,
};
use sha2::{Digest as _, Sha256};

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
    let mut canary = GuestCanaryReportV1::new();
    let canary_selected = canary.capture_original()?;
    aos_sandbox_linux::guest_confinement::prepare_guest_runtime_anchors()?;
    aos_sandbox_agent::guest_root_label::label_fresh_guest_manager_before_v1()?;

    // Adopt original slots 6/7 before any startup duplicate can reuse them.
    // Their fixed originals remain live only through the one Agent spawn.
    let cgroup = aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1::from_inherited()?;
    let execution_root = cgroup.execution_root()?;
    let channel = if !canary_selected {
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

    let (runtime, canary_channel) = SealedMemfdMapping::run(
        provisioning,
        GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
        GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
        |bytes, _identity| {
            let runtime = validated_guest_agent_runtime_prefix_v1(bytes)?;
            let channel = if canary_selected {
                let mut channel = [0; 32];
                channel.copy_from_slice(&bytes[112..144]);
                Some(channel)
            } else {
                None
            };
            Ok::<_, aos_sandbox_agent::protected_entry::ProtectedGuestAgentErrorV1>(
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
    if let Some(channel) = canary_channel {
        canary.report_original(&runtime, channel)?;
    }
    let mut agent = Command::new(AGENT_PATH);
    agent.env_clear();
    agent.stdin(Stdio::null());
    agent.stdout(Stdio::null());
    agent.stderr(Stdio::null());
    if canary_selected {
        agent.arg("--host-canary-readiness-v1");
    }
    if canary_selected {
        canary.spawn_agent_original(&mut agent)?;
    } else {
        agent.spawn()?;
    }

    for descriptor in [6, 7] {
        mark_inherited_descriptor_close_on_exec(descriptor)?;
        // SAFETY: fixed nspawn startup retains these numeric originals solely
        // for this Agent spawn. Rust owns only separate CLOEXEC duplicates.
        drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
    }
    drop(cgroup);
    drop(execution_root);
    drop(socket);

    mark_inherited_descriptor_close_on_exec(CHANNEL_FD)?;
    mark_inherited_descriptor_close_on_exec(PROVISIONING_FD)?;
    if canary_selected {
        canary.prepare_systemd_exec()?;
    }
    let mut systemd = Command::new(SYSTEMD_PATH);
    if canary_selected {
        systemd.arg("--aos-host-readiness-report");
    }
    systemd.env_clear();
    Err(systemd.exec().into())
}

const CANARY_CHALLENGE_BYTES: usize = 200;
const CANARY_HEADER_BYTES: usize = 176;
const CANARY_WAIT_NANOSECONDS: u64 = 30_000_000_000;
const CANARY_OWN_PATHS: [&str; 11] = [
    "/",
    "/proc/thread-self/ns/user",
    "/proc/thread-self/ns/mnt",
    "/proc/thread-self/ns/net",
    "/proc/thread-self/ns/pid",
    "/proc/thread-self/stat",
    "/proc/thread-self/status",
    "/proc/thread-self/attr/current",
    "/proc/thread-self/uid_map",
    "/proc/thread-self/gid_map",
    "/proc/thread-self/exe",
];

// Selected originals remain resident through the only Agent spawn and the
// immediate PID1 exec. An error or unwind terminates before these fields drop;
// this is not a claim that remote processes or effects have drained.
struct GuestCanaryReportV1 {
    original: GuestCanaryReportOriginalV1,
    socket: GuestAncestorHostChannelV1,
    agent: GuestAncestorHostChannelV1,
    challenge: Option<GuestAncestorHostRecordV1>,
    receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    originals: [Option<File>; 11],
    spawned_agent: Option<Child>,
    child_originals: HostCanaryLocalChildOriginalsV1,
    header: [u8; CANARY_HEADER_BYTES],
    deadline: u64,
    selected: bool,
    attempted: bool,
    armed: bool,
    first_failure: Option<Box<dyn std::error::Error>>,
}

impl GuestCanaryReportV1 {
    fn new() -> Self {
        Self {
            original: GuestCanaryReportOriginalV1::new(),
            socket: GuestAncestorHostChannelV1::new(),
            agent: GuestAncestorHostChannelV1::new(),
            challenge: None,
            receive_failure: None,
            originals: std::array::from_fn(|_| None),
            spawned_agent: None,
            child_originals: HostCanaryLocalChildOriginalsV1::new(),
            header: [0; CANARY_HEADER_BYTES],
            deadline: 0,
            selected: false,
            attempted: false,
            armed: false,
            first_failure: None,
        }
    }

    fn capture_original(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        self.armed = true;
        self.selected = self.original.capture_original()
            .map_err(|_| "Guest canary report capture failed; original cause remains resident")?;
        if !self.selected {
            self.armed = false;
        } else {
            self.agent.capture_agent_original()
                .map_err(|_| "Guest original Agent channel failed; cause remains resident")?;
            self.socket.capture_report_original(&self.original)
                .map_err(|_| "Guest original report channel failed; cause remains resident")?;
            self.socket.require_same_host_original(&mut self.agent)?;
        }
        Ok(self.selected)
    }

    fn report_original(
        &mut self,
        runtime: &[u8; 104],
        channel: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.selected || self.attempted || self.first_failure.is_some() {
            return Err("Guest canary report observation is closed".into());
        }
        self.attempted = true;
        match self.report_inner(runtime, channel) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.first_failure = Some(cause);
                Err("Guest canary report failed; original cause remains resident".into())
            }
        }
    }

    fn report_inner(
        &mut self,
        runtime: &[u8; 104],
        channel: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.require_same_host_original(&mut self.agent)?;

        let first_deadline = aos_sandbox_linux::seqpacket::bounded::boottime()?
            .checked_add(CANARY_WAIT_NANOSECONDS)
            .ok_or("Guest canary challenge deadline overflowed")?;
        loop {
            self.require_before(first_deadline)?;
            let received = self.socket.receive_retaining(CANARY_CHALLENGE_BYTES);
            match received {
                Ok(record) => {
                    self.challenge = Some(record);
                    break;
                }
                Err(error) if error.is_nonconsuming_would_block()
                    || error.is_nonconsuming_interrupted() => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => {
                    self.receive_failure = Some(error);
                    return Err("Guest canary challenge receive failed; originals remain resident".into());
                }
            }
        }
        self.require_before(first_deadline)?;
        let record = self.challenge.as_ref().ok_or("Guest canary challenge is absent")?;
        self.socket.require_record_original(record)?;
        self.socket.require_same_host_original(&mut self.agent)?;
        self.deadline = require_host_canary_challenge_v1(record.payload(), runtime, channel)?;
        self.require_before(self.deadline)?;
        self.header.copy_from_slice(&record.payload()[..CANARY_HEADER_BYTES]);

        for (slot, path) in CANARY_OWN_PATHS.iter().enumerate() {
            self.originals[slot] = Some(OpenOptions::new()
                .read(true)
                .custom_flags(O_CLOEXEC)
                .open(path)?);
            self.require_before(self.deadline)?;
        }
        self.send_originals(3, 0, 0..5)?;
        self.send_originals(4, 1, 5..10)?;
        self.send_originals(5, 2, 10..11)?;
        Ok(())
    }

    fn send_originals(
        &mut self,
        kind: u16,
        sequence: u64,
        slots: std::ops::Range<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.header[10..12].copy_from_slice(&kind.to_be_bytes());
        self.header[12..16].copy_from_slice(&(CANARY_HEADER_BYTES as u32).to_be_bytes());
        self.header[168..176].copy_from_slice(&sequence.to_be_bytes());
        let count = slots.len();
        let first = self.originals[slots.start].as_ref()
            .ok_or("Guest canary original descriptor is absent")?.as_fd();
        let mut descriptors: [BorrowedFd<'_>; 5] = [first; 5];
        for (target, slot) in slots.enumerate() {
            descriptors[target] = self.originals[slot].as_ref()
                .ok_or("Guest canary original descriptor is absent")?.as_fd();
        }
        loop {
            self.require_before(self.deadline)?;
            match self.socket.send_with_descriptors(&self.header, &descriptors[..count])
            {
                Ok(()) => return self.require_before(self.deadline),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(cause) => return Err(cause.into()),
            }
        }
    }

    fn spawn_agent_original(&mut self, command: &mut Command)
        -> Result<(), Box<dyn std::error::Error>>
    {
        if !self.selected || !self.attempted || self.spawned_agent.is_some()
            || self.first_failure.is_some()
        {
            return Err("Guest original Agent spawn is closed".into());
        }
        match self.spawn_agent_inner(command) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.first_failure = Some(cause);
                Err("Guest original Agent observation failed; cause remains resident".into())
            }
        }
    }

    fn spawn_agent_inner(&mut self, command: &mut Command)
        -> Result<(), Box<dyn std::error::Error>>
    {
        self.require_before(self.deadline)?;
        self.socket.require_same_host_original(&mut self.agent)?;
        self.spawned_agent = Some(command.spawn()?);
        self.child_originals.capture_original(
            self.spawned_agent.as_ref().ok_or("actual Agent child is absent")?,
        )?;
        self.require_before(self.deadline)?;

        for stage in 0..2 {
            loop {
                self.require_before(self.deadline)?;
                let result = if stage == 0 {
                    self.socket.send_host_canary_child_first_v1(
                        &mut self.child_originals, &self.header,
                    )
                } else {
                    self.socket.send_host_canary_child_second_v1(
                        &mut self.child_originals, &self.header,
                    )
                };
                match result {
                    Ok(()) => break,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(cause) => return Err(cause.into()),
                }
            }
            self.require_before(self.deadline)?;
        }
        self.socket.require_same_host_original(&mut self.agent)?;
        self.child_originals.recheck_original()?;
        self.require_before(self.deadline)
    }

    fn require_before(&self, deadline: u64) -> Result<(), Box<dyn std::error::Error>> {
        if aos_sandbox_linux::seqpacket::bounded::boottime()? >= deadline {
            return Err("Guest canary original deadline expired".into());
        }
        Ok(())
    }

    fn prepare_systemd_exec(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.require_before(self.deadline)?;
        self.original.prepare_systemd_exec()
            .map_err(|_| "Guest canary exec disposition failed; original cause remains resident")?;
        // Successful exec retains original FD8. If exec fails or unwinds this
        // still-armed owner terminates rather than silently dropping prefixes.
        Ok(())
    }
}

impl Drop for GuestCanaryReportV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

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
