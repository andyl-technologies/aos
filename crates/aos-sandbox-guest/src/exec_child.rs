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

use aos_sandbox_core::{DecodeLimits, ExecutionSpecV1, RelativePath, decode_execution_spec_v1};
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
    if rustix::process::geteuid().as_raw() != 0 || std::env::args_os().len() > 2 {
        return Err("guest helper requires fixed trusted startup".into());
    }
    let pty_path = std::env::args_os().nth(1);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut length = [0_u8; 4];
    input.read_exact(&mut length)?;
    let specification_length = u32::from_be_bytes(length) as usize;
    if specification_length > MAX_SPECIFICATION_BYTES {
        return Err("guest command specification is oversized".into());
    }
    let mut specification_bytes = vec![0_u8; specification_length];
    input.read_exact(&mut specification_bytes)?;
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
    drop(input);
    run_command(&worker, &specification, pty_path.as_deref())
}

fn run_command(
    worker: &SingleThreadedProcess,
    specification: &ExecutionSpecV1,
    pty_path: Option<&OsStr>,
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
