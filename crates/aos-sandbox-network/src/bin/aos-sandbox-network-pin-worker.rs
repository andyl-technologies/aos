//! Entrypoint for one host-visible Network namespace-pin teardown.

use std::process::ExitCode;

use aos_sandbox_network::run_inherited_network_namespace_pin_worker;

fn main() -> ExitCode {
    match run_inherited_network_namespace_pin_worker() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-network-pin-worker: {error}");
            ExitCode::FAILURE
        }
    }
}
