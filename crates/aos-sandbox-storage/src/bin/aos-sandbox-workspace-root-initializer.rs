//! Runs one authenticated Create root initializer in a separate service unit.

use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_storage::{ZfsWorkerError, run_inherited_workspace_root_initializer};

fn main() -> ExitCode {
    if let Err(error) = aos_sandbox_linux::no_setid::require_guarded_startup() {
        eprintln!("aos-sandbox-workspace-root-initializer: {error}");
        return ExitCode::FAILURE;
    }

    match configured_paths().and_then(|(zfs, authority, replay)| {
        run_inherited_workspace_root_initializer(zfs, &authority, &replay)
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-workspace-root-initializer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn configured_paths() -> Result<(PathBuf, PathBuf, PathBuf), ZfsWorkerError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let zfs = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured ZFS executable is absent",
    ))?;
    let authority = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured Storage authority directory is absent",
    ))?;
    let replay = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured workspace pin replay directory is absent",
    ))?;
    if arguments.next().is_some() {
        return Err(ZfsWorkerError::Protocol(
            "workspace root initializer accepts exactly three configured paths",
        ));
    }
    Ok((zfs.into(), authority.into(), replay.into()))
}
