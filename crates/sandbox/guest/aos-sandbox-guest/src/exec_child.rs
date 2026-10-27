//! Fixed child launcher for a previously authenticated guest execution spec.
//!
//! The helper remains in the enforcing Owner subject and UID zero while its
//! parent pins its cgroup and accepts the durable original process record. Only
//! then is the canonical spec released on its private pipe. It installs the
//! exact admitted groups/GID/UID, closes private descriptors, and explicitly
//! selects the Tenant exec SID without changing the inherited NNP profile.

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aos_sandbox_model::{DecodeLimits, ExecutionSpecV1, RelativePath, decode_execution_spec_v1};
use aos_sandbox_linux::guest_confinement::{
    close_guest_private_descriptors, require_guest_owner, require_guest_stdio,
    select_guest_tenant_exec,
};
use aos_sandbox_linux::pidfd::SingleThreadedProcess;

const MAX_SPECIFICATION_BYTES: usize = 15 * 1_048_576;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let worker = SingleThreadedProcess::verify()?;
    require_guest_owner()?;
    worker.disable_core_dumps()?;
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("guest helper requires fixed trusted startup".into());
    }
    let mut arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|argument| argument == "--openssh-bootstrap-v1") {
        return run_openssh_bootstrap(&worker, &arguments);
    }
    if !(arguments.len() == 4 || arguments.len() == 5) {
        return Err("guest helper requires the original lifetime arguments".into());
    }
    let lifetime_offset = arguments.len() - 4;
    if arguments[lifetime_offset] != "--lifetime-v1" {
        return Err("guest helper requires the versioned original lifetime".into());
    }
    let number = |offset: usize| -> Result<u64, Box<dyn std::error::Error>> {
        Ok(arguments[lifetime_offset + offset].to_str()
            .ok_or("noncanonical helper lifetime")?.parse()?)
    };
    let original_lifetime = (number(1)?, number(2)?, number(3)?);
    aos_sandbox_linux::process::require_child_lifetime_data_v1(
        original_lifetime.0, original_lifetime.1, original_lifetime.2)?;
    let pty_path = if lifetime_offset == 1 { Some(arguments.remove(0)) } else { None };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut header = [0_u8; 36];
    let original_flags = rustix::fs::fcntl_getfl(&stdin)?;
    rustix::fs::fcntl_setfl(&stdin, original_flags | rustix::fs::OFlags::NONBLOCK)?;
    read_original_input(&mut input, &mut header, original_lifetime)?;
    if &header[..8] != b"AOSGEX02" {
        return Err("guest helper requires the original versioned lifetime".into());
    }
    let origin = u64::from_be_bytes(header[8..16].try_into()?);
    let timeout = u64::from_be_bytes(header[16..24].try_into()?);
    let deadline = u64::from_be_bytes(header[24..32].try_into()?);
    if (origin, timeout, deadline) != original_lifetime {
        return Err("guest helper input changed the original lifetime".into());
    }
    aos_sandbox_linux::process::require_child_lifetime_data_v1(origin, timeout, deadline)?;
    let specification_length = u32::from_be_bytes(header[32..].try_into()?) as usize;
    if specification_length > MAX_SPECIFICATION_BYTES {
        return Err("guest command specification is oversized".into());
    }
    let mut specification_bytes = vec![0_u8; specification_length];
    read_original_input(&mut input, &mut specification_bytes, original_lifetime)?;
    let specification = decode_execution_spec_v1(
        &specification_bytes,
        DecodeLimits {
            maximum_bytes: MAX_SPECIFICATION_BYTES,
            maximum_collection_items: 65_536,
            maximum_total_items: 262_144,
            maximum_byte_string_bytes: MAX_SPECIFICATION_BYTES,
            maximum_text_bytes: 1_048_576,
            maximum_depth: 128,
        },
    )?;
    if specification.timeout().nanoseconds() != timeout {
        return Err("guest helper timeout differs from accepted specification".into());
    }
    aos_sandbox_linux::process::require_child_lifetime_data_v1(origin, timeout, deadline)?;
    drop(input);
    rustix::fs::fcntl_setfl(&stdin, original_flags)?;
    run_command(&worker, &specification, pty_path.as_deref(), (origin, timeout, deadline))
}

/// Installs the admitted SSH allocation limit on this same single-threaded
/// child before the fixed daemon can allocate descriptors or fork. The cgroup
/// memory/tasks limits already apply from the parent's atomic spawn; argv is
/// comparison DATA from that private parent, never a new execution grant.
fn run_openssh_bootstrap(
    worker: &SingleThreadedProcess,
    arguments: &[OsString],
) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 4 {
        return Err("SSH helper requires its fixed original bounds".into());
    }
    let number = |index: usize| -> Result<u64, Box<dyn std::error::Error>> {
        let text = arguments[index].to_str().ok_or("SSH helper bound is not text")?;
        let value = text.parse::<u64>()?;
        if value == 0 || text != value.to_string() {
            return Err("SSH helper bound is not canonical".into());
        }
        Ok(value)
    };
    let nofile = number(1)?;
    let deadline = number(2)?;
    let wall = i64::try_from(number(3)?)?;
    if nofile < 3 || nofile > u64::from(u32::MAX) {
        return Err("SSH helper nofile bound is outside the fixed plan".into());
    }
    let require_current = || -> Result<(), Box<dyn std::error::Error>> {
        let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let now = u64::try_from(boot.tv_sec)?.checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(u64::try_from(boot.tv_nsec).ok()?))
            .ok_or("SSH helper BOOTTIME overflow")?;
        let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        if now >= deadline || realtime.tv_sec >= wall {
            return Err("SSH helper original horizon expired".into());
        }
        Ok(())
    };
    require_current()?;
    let mut command = Command::new(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_PROGRAM_V1);
    command.args(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_ARGUMENTS_V1);
    command.arg(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_BOOTSTRAP_ARGUMENT_V1);
    command.current_dir("/");
    command.env_clear();
    command.envs(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_ENVIRONMENT_V1);
    command.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    // SAFETY: this existing helper is single-threaded, all Rust-owned private
    // descriptors have been dropped, and only the parent's private bootstrap
    // socket on stdin plus /dev/null stdout/stderr survive the immediate exec.
    unsafe { close_guest_private_descriptors(worker)?; }
    require_current()?;
    let expected = rustix::process::Rlimit { current: Some(nofile), maximum: Some(nofile) };
    rustix::process::setrlimit(rustix::process::Resource::Nofile, expected)?;
    if rustix::process::getrlimit(rustix::process::Resource::Nofile) != expected {
        return Err("SSH helper hard nofile limit differs after installation".into());
    }
    require_current()?;
    Err(command.exec().into())
}

/// Uses the existing private pipe without ever renewing its pre-spawn deadline.
fn read_original_input(input: &mut impl std::io::Read, mut bytes: &mut [u8],
    lifetime: (u64, u64, u64)) -> Result<(), Box<dyn std::error::Error>>
{
    while !bytes.is_empty() {
        aos_sandbox_linux::process::require_child_lifetime_data_v1(lifetime.0, lifetime.1, lifetime.2)?;
        match input.read(bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock =>
                std::thread::sleep(std::time::Duration::from_millis(2)),
            Err(error) => return Err(error.into()),
        }
    }
    aos_sandbox_linux::process::require_child_lifetime_data_v1(lifetime.0, lifetime.1, lifetime.2)?;
    Ok(())
}

fn run_command(
    worker: &SingleThreadedProcess,
    specification: &ExecutionSpecV1,
    pty_path: Option<&OsStr>,
    lifetime: (u64, u64, u64),
) -> Result<(), Box<dyn std::error::Error>> {
    let command_spec = specification.command();
    let executable = resolve_executable(specification)?;
    let mut command = Command::new(executable);
    command.args(
        command_spec
            .arguments()
            .iter()
            .skip(1)
            .map(|argument| OsString::from_vec(argument.clone())),
    );
    command.current_dir(rooted_path(command_spec.working_directory()));
    command.env_clear();
    for entry in specification.base_environment().variables() {
        command.env(entry.name(), entry.value());
    }
    for entry in command_spec.environment_overlay() {
        command.env(entry.name(), OsStr::from_bytes(entry.value()));
    }

    if let Some(pty_path) = pty_path {
        let path = Path::new(pty_path);
        if !path.starts_with("/dev/pts/") || path.components().count() != 4 {
            return Err("invalid guest PTY path".into());
        }
        rustix::process::setsid()?;
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        rustix::process::ioctl_tiocsctty(&slave)?;
        rustix::stdio::dup2_stdin(&slave)?;
        rustix::stdio::dup2_stdout(&slave)?;
        rustix::stdio::dup2_stderr(&slave)?;
        drop(slave);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    require_guest_stdio(pty_path.is_some())?;

    let credentials = command_spec.credentials();
    let groups = credentials
        .supplementary_group_ids()
        .iter()
        .map(|group| rustix::process::Gid::from_raw(*group))
        .collect::<Vec<_>>();
    rustix::thread::set_thread_groups(&groups)?;
    let gid = rustix::process::Gid::from_raw(credentials.primary_group_id());
    rustix::thread::set_thread_res_gid(gid, gid, gid)?;
    let uid = rustix::process::Uid::from_raw(credentials.user_id());
    rustix::thread::set_thread_res_uid(uid, uid, uid)?;
    if rustix::process::getuid() != uid
        || rustix::process::geteuid() != uid
        || rustix::process::getgid() != gid
        || rustix::process::getegid() != gid
        || rustix::process::getgroups()? != groups
    {
        return Err("guest original credentials differ after installation".into());
    }

    select_guest_tenant_exec(worker)?;
    // SAFETY: this fixed single-threaded helper has dropped every nonstdio
    // descriptor owner, uses only inherited stdio in Command, and immediately
    // execs or exits on failure. No private FD can survive the Tenant transition.
    unsafe {
        close_guest_private_descriptors(worker)?;
    }

    // Helper setup, credentials and suspend consume the original duration.
    // No Tenant image enters exec with a fresh window or an expired origin.
    aos_sandbox_linux::process::require_child_lifetime_data_v1(lifetime.0, lifetime.1, lifetime.2)?;
    Err(command.exec().into())
}

fn resolve_executable(specification: &ExecutionSpecV1) -> Result<PathBuf, &'static str> {
    let first = specification
        .command()
        .arguments()
        .first()
        .ok_or("missing command executable")?;
    let executable = Path::new(OsStr::from_bytes(first));
    if executable.is_absolute() {
        return Ok(executable.to_path_buf());
    }
    if first.contains(&b'/') {
        return Ok(rooted_path(specification.command().working_directory()).join(executable));
    }
    for directory in specification.base_environment().command_search_path() {
        let candidate = rooted_path(directory).join(executable);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("command executable is absent from the admitted search path")
}

fn rooted_path(path: &RelativePath) -> PathBuf {
    let mut absolute = PathBuf::from("/");
    for component in path.components() {
        absolute.push(OsStr::from_bytes(component.as_bytes()));
    }
    absolute
}
