//! Runs the fixed systemd-activated Network lifecycle admission worker.
//!
//! PID 1 supplies a connected sequenced-packet socket and a fresh private
//! Network namespace. This entrypoint accepts no authority, journal, helper, or
//! artifact paths and exits after one descriptor-correlation acknowledgement.

use std::process::ExitCode;

use aos_sandbox_network::{
    NetworkLifecycleWorkerRuntimeError, run_inherited_network_lifecycle_admission_worker,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-network-lifecycle-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    validate_arguments(std::env::args_os())?;
    run_inherited_network_lifecycle_admission_worker()
}

fn validate_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), NetworkLifecycleWorkerRuntimeError> {
    drop(arguments.next());
    if arguments.next().is_some() {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle admission worker accepts no arguments",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn fixed_entrypoint_has_no_configuration_arguments() {
        assert!(validate_arguments([OsString::from("worker")].into_iter()).is_ok());
        assert!(
            validate_arguments([OsString::from("worker"), OsString::from("/secret")].into_iter())
                .is_err()
        );
    }
}
