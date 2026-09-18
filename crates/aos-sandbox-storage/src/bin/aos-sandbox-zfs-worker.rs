//! Runs one systemd-contained, typed OpenZFS transaction.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match configured_executable().and_then(aos_sandbox_storage::run_inherited_worker) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-zfs-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

fn configured_executable() -> Result<PathBuf, aos_sandbox_storage::ZfsWorkerError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let executable = arguments
        .next()
        .ok_or(aos_sandbox_storage::ZfsWorkerError::Protocol(
            "configured ZFS executable is absent",
        ))?;
    if arguments.next().is_some() {
        return Err(aos_sandbox_storage::ZfsWorkerError::Protocol(
            "worker accepts exactly one configured ZFS executable",
        ));
    }
    Ok(executable.into())
}
