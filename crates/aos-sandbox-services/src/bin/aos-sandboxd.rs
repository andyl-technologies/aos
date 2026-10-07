//! Runs the production unprivileged AOS sandbox node controller.
//!
//! [`aos_sandbox_services::controller`] selects the fixed listener and HTTP
//! assembly. Protected startup, readiness, capability reporting, and authority
//! gates remain in the session-security runtime and its domain owners.

use std::process::ExitCode;

fn main() -> ExitCode {
    match aos_sandbox_services::controller::run_from_environment() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandboxd: {error}");
            ExitCode::FAILURE
        }
    }
}
