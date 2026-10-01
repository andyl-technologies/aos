//! Manual prepare-keys-only entrypoint with resident negative custody.
//!
//! The selected service is disabled by default and has no boot activation.
//! Explicit process exit retains originals through the terminal boundary; it
//! deliberately avoids returning an ExitCode that would drop failed custody.

use std::panic::{AssertUnwindSafe, catch_unwind};

use aos_sandbox::normal_root::OfflineNixPrepareStartupV3;
use aos_sandbox_broker_session_security::nix_floor_provisioning::NixPrepareKeysAttemptV3;

fn main() {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("prepare-keys"))
        || arguments.next().is_some()
    {
        std::process::exit(2);
    }

    // Empty resident slots precede the complete original activation observation.
    let mut startup = OfflineNixPrepareStartupV3::new();
    let admission = catch_unwind(AssertUnwindSafe(|| startup.capture_and_admit().is_ok()));
    if !matches!(admission, Ok(true)) {
        let _original_unwind = admission.err();
        std::process::exit(1);
    }
    let original = &mut startup;
    let borrowed = catch_unwind(AssertUnwindSafe(move || {
        // Move the external borrow into this single invocation, not a reusable
        // closure that could let a mutable loan escape between calls.
        let original = original;
        original.borrow_original()
    }));
    let origin = match borrowed {
        Ok(Ok(origin)) => origin,
        Ok(Err(_)) => std::process::exit(1),
        Err(payload) => {
            let _original_unwind = payload;
            std::process::exit(1);
        }
    };
    let mut attempt = NixPrepareKeysAttemptV3::new(origin);
    let prepared = catch_unwind(AssertUnwindSafe(|| attempt.prepare_keys().is_ok()));
    let success = matches!(prepared, Ok(true));
    let _original_unwind = prepared.err();

    // Both success and failure wipe parked secret allocations without deleting
    // files or dropping original startup, file, directory and lock descriptors.
    attempt.wipe_secrets();
    std::process::exit(if success { 0 } else { 1 });
}
