//! Fixed child launcher for a previously authenticated guest execution spec.
//!
//! The parent agent drops UID and GID before launching this helper. The helper
//! reads the canonical spec from an inherited pipe and uses safe kernel wrappers
//! to establish a controlling PTY before replacing itself with the command.

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aos_sandbox_core::{DecodeLimits, ExecutionSpecV1, RelativePath, decode_execution_spec_v1};

const MAX_SPECIFICATION_BYTES: usize = 15 * 1_048_576;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    run_command(&specification, pty_path.as_deref())
}

fn run_command(
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
        command.stdin(Stdio::from(slave.try_clone()?));
        command.stdout(Stdio::from(slave.try_clone()?));
        command.stderr(Stdio::from(slave));
    } else {
        command.stdin(Stdio::inherit());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
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
