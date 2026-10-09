//! Runs the fixed selected Host055 publisher after exclusive original capture.
//!
//! It performs one protected association attempt; it neither provisions missing
//! state nor opens public runtime/Create gates. The original startup parts stay
//! local through the operation's terminal observations and negative fence.
//! Returning releases originals under ordinary Drop, not all-owner Drain.

use std::process::ExitCode;

use aos_sandbox::ProductionRuntimeDeploymentStartupCaptureV1;
use aos_sandbox_broker_session_security::run_runtime_deployment_canary_once_v2;

fn main() -> ExitCode {
    // This must precede argument collection, threads, runtimes, credentials and
    // journal opens. Later role names cannot reconstruct the original table.
    let captured = match ProductionRuntimeDeploymentStartupCaptureV1::capture() {
        Ok(captured) => captured,
        Err(error) => {
            eprintln!("runtime publisher original capture refused: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--canary-association-v2"))
        || arguments.next().is_some()
    {
        eprintln!("runtime publisher requires the fixed --canary-association-v2 mode");
        return ExitCode::FAILURE;
    }

    let mut parts = match captured.admit_canary_v2() {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("runtime publisher selected startup refused: {error}");
            return ExitCode::FAILURE;
        }
    };
    match run_runtime_deployment_canary_once_v2(&mut parts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The called operation has already parked the authentic first
            // cause and performed its terminal posts/fence, without retry.
            eprintln!("runtime publisher selected attempt refused: {error}");
            ExitCode::FAILURE
        }
    }
}
