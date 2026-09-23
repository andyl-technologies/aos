//! Executes one fixed, protected guest-root publication effect.

use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_storage::ZfsWorkerError;
use aos_sandbox_storage::guest_root_worker::run_inherited_guest_root_publisher;

fn main() -> ExitCode {
    match configured_paths().and_then(|(template, authority, replay)| {
        run_inherited_guest_root_publisher(&template, &authority, &replay)
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-guest-root-publisher: {error}");
            ExitCode::FAILURE
        }
    }
}

fn configured_paths() -> Result<(PathBuf, PathBuf, PathBuf), ZfsWorkerError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let template = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured guest-root template is absent",
    ))?;
    let authority = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured Storage authority directory is absent",
    ))?;
    let replay = arguments.next().ok_or(ZfsWorkerError::Protocol(
        "configured guest-root replay directory is absent",
    ))?;
    if arguments.next().is_some() {
        return Err(ZfsWorkerError::Protocol(
            "guest-root publisher accepts exactly three configured paths",
        ));
    }
    Ok((template.into(), authority.into(), replay.into()))
}
