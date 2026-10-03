//! Runs the fixed systemd-activated Network postcondition observer.
//!
//! PID 1 provides one connected sequenced-packet socket. All immutable reader
//! paths come from the fixed unit, while the authenticated broker transfers the
//! exact host and target namespace descriptors with one canonical plan.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_linux::no_setid::require_guarded_startup;
use aos_sandbox_network::{
    NetworkObservationWorkerConfiguration, NetworkObservationWorkerError,
    run_inherited_network_observation_worker,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-network-observation-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), NetworkObservationWorkerError> {
    require_guarded_startup()
        .map_err(|_| NetworkObservationWorkerError::Protocol("Network startup guard failed"))?;

    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(NetworkObservationWorkerError::Protocol(
            "observation worker requires root identity",
        ));
    }

    let mut arguments = env::args_os();
    drop(arguments.next());
    let configuration = NetworkObservationWorkerConfiguration {
        ip: required_path(&mut arguments)?,
        nft: required_path(&mut arguments)?,
        enforcement_loader: required_path(&mut arguments)?,
        bpf_observer: required_path(&mut arguments)?,
        lease_gate_object: required_path(&mut arguments)?,
    };
    if arguments.next().is_some() {
        return Err(NetworkObservationWorkerError::Protocol(
            "observation worker requires exactly five fixed path arguments",
        ));
    }

    run_inherited_network_observation_worker(configuration)
}

fn required_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, NetworkObservationWorkerError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or(NetworkObservationWorkerError::Protocol(
            "observation worker requires exactly five fixed path arguments",
        ))
}
