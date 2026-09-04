//! Executes one sealed descriptor-only mount-helper transaction.

use std::process::ExitCode;

fn main() -> ExitCode {
    match aos_sandbox_mount::helper::run_inherited() {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("aos-sandbox-mount-helper: {error}");
            ExitCode::FAILURE
        }
    }
}
