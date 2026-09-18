//! Runs the fixed systemd-activated Network lifecycle effect worker.
//!
//! PID 1 supplies a connected sequenced-packet socket and a fresh private
//! Network namespace. Authority, replay, helper, and BPF artifact paths come
//! only from the fixed service unit.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_network::{
    NetworkLifecycleWorkerConfiguration, NetworkLifecycleWorkerRuntimeError,
    run_inherited_network_lifecycle_worker,
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
    let mut arguments = env::args_os();
    drop(arguments.next());
    let configuration = NetworkLifecycleWorkerConfiguration {
        authority_directory: required_path(&mut arguments)?,
        replay_directory: required_path(&mut arguments)?,
        ip: required_path(&mut arguments)?,
        nft: required_path(&mut arguments)?,
        enforcement_artifact: required_path(&mut arguments)?,
        lease_gate_loader: required_path(&mut arguments)?,
        lease_gate_object: required_path(&mut arguments)?,
    };
    if arguments.next().is_some() {
        return Err(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle worker requires exactly seven fixed path arguments",
        ));
    }
    run_inherited_network_lifecycle_worker(configuration)
}

fn required_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, NetworkLifecycleWorkerRuntimeError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or(NetworkLifecycleWorkerRuntimeError::Protocol(
            "lifecycle worker requires exactly seven fixed path arguments",
        ))
}
