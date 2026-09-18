//! Runs the fixed systemd-activated Network preparation worker.
//!
//! PID 1 provides a connected sequenced-packet socket on standard input and a
//! fresh private Network namespace. All authority, replay, helper, and BPF
//! artifact paths come only from the fixed service unit.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_network::{
    NetworkWorkerConfiguration, NetworkWorkerRuntimeError, run_inherited_network_prepare_worker,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-network-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), NetworkWorkerRuntimeError> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(NetworkWorkerRuntimeError::Authority);
    }
    let mut arguments = env::args_os();
    drop(arguments.next());
    let configuration = NetworkWorkerConfiguration {
        authority_directory: required_path(&mut arguments)?,
        replay_directory: required_path(&mut arguments)?,
        ip: required_path(&mut arguments)?,
        nft: required_path(&mut arguments)?,
        enforcement_artifact: required_path(&mut arguments)?,
        lease_gate_loader: required_path(&mut arguments)?,
        lease_gate_object: required_path(&mut arguments)?,
    };
    if arguments.next().is_some() {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "worker requires exactly seven fixed path arguments",
        ));
    }
    run_inherited_network_prepare_worker(configuration)
}

fn required_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, NetworkWorkerRuntimeError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "worker requires exactly seven fixed path arguments",
        ))
}
