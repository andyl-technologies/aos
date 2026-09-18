//! Runs one authenticated, descriptor-backed workspace root-pin observation.

use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_storage::{ZfsWorkerError, run_inherited_workspace_pin_observer};

fn main() -> ExitCode {
    match configured_paths()
        .and_then(|(zfs, authority)| run_inherited_workspace_pin_observer(zfs, &authority))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-workspace-pin-observer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn configured_paths() -> Result<(PathBuf, PathBuf), ZfsWorkerError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let zfs = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured ZFS executable is absent",
    ))?;
    let authority = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured Storage authority directory is absent",
    ))?;
    if arguments.next().is_some() {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin observer accepts exactly two configured paths",
        ));
    }
    Ok((zfs.into(), authority.into()))
}
