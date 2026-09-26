//! Fixed guest PID 1 bootstrap for inherited agent and attach-trust descriptors.
//!
//! Nspawn delivers one connected channel at FD 3 and fully sealed launch
//! records at FD 4 and FD 5. This bootstrap checks the carrier and exact
//! runtime binding, installs the OpenSSH trust material at fixed root-owned
//! paths, starts the only guest agent, and replaces PID 1 with AOS systemd.
//! No request or environment variable can select a path or executable.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use aos_sandbox_agent::guest_attach_trust::{
    GuestAttachTrustRecordV1, MAX_GUEST_ATTACH_TRUST_BYTES,
};
use aos_sandbox_agent::protected_entry::{
    GUEST_AGENT_PROVISIONING_BYTES_V1, validated_guest_agent_runtime_prefix_v1,
};
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::inherited_fd::{
    duplicate_inherited_descriptor, mark_inherited_descriptor_close_on_exec,
};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

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

    let channel = duplicate_inherited_descriptor(CHANNEL_FD)?;
    let provisioning = duplicate_inherited_descriptor(PROVISIONING_FD)?;
    let trust = duplicate_inherited_descriptor(ATTACH_TRUST_FD)?;
    let socket = SeqpacketSocket::from_owned(channel)?;
    if !socket.peer().pidfd().is_alive()?
        || socket.peer().credentials().pid().get() == std::process::id()
    {
        return Err("guest agent channel peer is unavailable".into());
    }

    let runtime = SealedMemfdMapping::run(
        provisioning,
        GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
        GUEST_AGENT_PROVISIONING_BYTES_V1 as u64,
        |bytes, _identity| validated_guest_agent_runtime_prefix_v1(bytes),
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
    let mut agent = Command::new(AGENT_PATH);
    agent.env_clear();
    agent.stdin(Stdio::null());
    agent.stdout(Stdio::null());
    agent.stderr(Stdio::null());
    agent.spawn()?;

    mark_inherited_descriptor_close_on_exec(CHANNEL_FD)?;
    mark_inherited_descriptor_close_on_exec(PROVISIONING_FD)?;
    let mut systemd = Command::new(SYSTEMD_PATH);
    systemd.env_clear();
    Err(systemd.exec().into())
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
