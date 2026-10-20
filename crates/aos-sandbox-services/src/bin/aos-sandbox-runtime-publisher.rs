//! Runs the build-selected Host055 publisher after exclusive original capture.
//!
//! The normal feature performs one completed boot preparation and exits while
//! its actual Source and reached originals remain resident through owed posts.
//! The Canary feature preserves its existing association attempt and ordinary
//! return. Neither recipe provisions missing state or opens a public runtime.

#[cfg(not(feature = "runtime-boot-preparation"))]
use std::process::ExitCode;

#[cfg(not(feature = "runtime-boot-preparation"))]
use aos_sandbox::ProductionRuntimeDeploymentStartupCaptureV1;
#[cfg(not(feature = "runtime-boot-preparation"))]
use aos_sandbox_broker_session_security::run_runtime_deployment_canary_once_v2;

#[cfg(feature = "runtime-boot-preparation")]
fn main() -> ! {
    // The build-selected normal recipe captures the real initial four-entry
    // Source before argv, credentials, runtime/thread or journal operations.
    // The actual PID1 Source gate already fixes argc2 and the normal flag.
    let mut startup = aos_sandbox::RuntimeBootPreparationStartupOriginalV1::new();
    let admitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        startup.capture_before_arguments_once_v1()?;
        startup.admit_once_v1()?;
        startup.require_arguments_once_v1()?;
        Ok::<(), aos_sandbox::RuntimeBootPreparationStartupClosedV1>(())
    }));
    if !matches!(admitted, Ok(Ok(()))) {
        let _after = startup.finish_source_after_owed_once_v1(Err(
            aos_sandbox::RuntimeBootPreparationStartupClosedV1,
        ));
        std::process::exit(1);
    }
    aos_sandbox_broker_session_security::run_runtime_boot_preparation_once_v1(&startup)
}

#[cfg(not(feature = "runtime-boot-preparation"))]
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
