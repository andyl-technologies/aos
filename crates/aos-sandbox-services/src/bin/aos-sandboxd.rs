//! Runs the production unprivileged AOS sandbox node controller.
//!
//! The implementation lives in [`aos_sandbox_services::controller`] so startup,
//! readiness, capability reporting, and unavailable-authority gates remain
//! directly testable without a child process.

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
