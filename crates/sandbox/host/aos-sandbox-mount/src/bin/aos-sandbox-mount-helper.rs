//! Executes one sealed descriptor-only mount-helper transaction.

use std::process::ExitCode;

fn main() -> ExitCode {
    // SAFETY: the fixed launcher starts this single-threaded helper with only
    // the exact descriptor roles 3 through 9 and no preconstructed Rust owner.
    // No code runs before this call that can mutate the descriptor table.
    match unsafe { aos_sandbox_mount::helper::run_inherited() } {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("aos-sandbox-mount-helper: {error}");
            ExitCode::FAILURE
        }
    }
}
