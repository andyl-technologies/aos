//! Runs the dedicated, transport-only Git Gateway's fixed PID1 entry point.
//!
//! The transport requires an explicit service-memcg/advisory-memory profile.
//! Observed memory is not reserved capacity. Neither process startup nor
//! transport READY authorizes Git effects.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match aos_sandbox::git::run_git_gateway_transport_from_environment_v1() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-git-gateway: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("aos-sandbox-git-gateway: Linux service custody is required");
    ExitCode::FAILURE
}
