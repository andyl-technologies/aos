//! Measures one Storage-selected held snapshot in a private mount namespace.

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(error) = aos_sandbox_linux::no_setid::require_guarded_startup() {
        eprintln!("aos-sandbox-held-snapshot-reader: {error}");
        return ExitCode::FAILURE;
    }

    match aos_sandbox_storage::process::run_inherited_held_snapshot_reader() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-held-snapshot-reader: {error}");
            ExitCode::FAILURE
        }
    }
}
