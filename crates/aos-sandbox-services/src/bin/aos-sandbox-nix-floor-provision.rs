//! Manual Nix preparation, static inspection and approved offline hardware job.
//!
//! The selected service is disabled by default and has no boot activation.
//! Explicit process exit retains originals through the terminal boundary; it
//! deliberately avoids returning an ExitCode that would drop failed custody.

use std::panic::{AssertUnwindSafe, catch_unwind};

use aos_sandbox::normal_root::OfflineNixPrepareStartupV3;
use aos_sandbox_broker_session_security::nix_floor_provisioning::{
    NixApprovedJobInspectionAttemptV3, NixPrepareKeysAttemptV3,
    NixOfflineHardwareAttemptV5, NixOfflineHardwareResourcesV5,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    PrepareKeys,
    InspectApprovedJob,
    Initialize,
    Recover,
}

fn command(value: Option<&std::ffi::OsStr>) -> Option<Command> {
    match value {
        Some(value) if value == "prepare-keys" => Some(Command::PrepareKeys),
        Some(value) if value == "inspect-approved-job" => Some(Command::InspectApprovedJob),
        Some(value) if value == "initialize" => Some(Command::Initialize),
        Some(value) if value == "recover" => Some(Command::Recover),
        _ => None,
    }
}

fn main() {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    let selected = match command(arguments.next().as_deref()) {
        Some(selected) => selected,
        None => std::process::exit(2),
    };
    if arguments.next().is_some() {
        std::process::exit(2);
    }

    if matches!(selected, Command::Initialize | Command::Recover) {
        hardware_main(selected);
    }

    // Empty resident slots precede the complete original activation observation.
    let mut startup = OfflineNixPrepareStartupV3::new();
    let admission = catch_unwind(AssertUnwindSafe(|| {
        match selected {
            Command::PrepareKeys => startup.capture_and_admit(),
            Command::InspectApprovedJob => startup.capture_and_admit_inspection(),
            Command::Initialize | Command::Recover => std::process::exit(2),
        }
        .is_ok()
    }));
    if !matches!(admission, Ok(true)) {
        let _original_unwind = admission.err();
        std::process::exit(1);
    }
    let original = &mut startup;
    let borrowed = catch_unwind(AssertUnwindSafe(move || {
        // Move the external borrow into this single invocation, not a reusable
        // closure that could let a mutable loan escape between calls.
        let original = original;
        match selected {
            Command::PrepareKeys => original.borrow_original(),
            Command::InspectApprovedJob => original.borrow_inspection(),
            Command::Initialize | Command::Recover => std::process::exit(2),
        }
    }));
    let origin = match borrowed {
        Ok(Ok(origin)) => origin,
        Ok(Err(_)) => std::process::exit(1),
        Err(payload) => {
            let _original_unwind = payload;
            std::process::exit(1);
        }
    };
    match selected {
        Command::PrepareKeys => {
            let mut attempt = NixPrepareKeysAttemptV3::new(origin);
            let prepared = catch_unwind(AssertUnwindSafe(|| attempt.prepare_keys().is_ok()));
            let success = matches!(prepared, Ok(true));
            let _original_unwind = prepared.err();

            // Both success and failure wipe parked secret allocations without deleting
            // files or dropping original startup, file, directory and lock descriptors.
            attempt.wipe_secrets();
            std::process::exit(if success { 0 } else { 1 });
        }
        Command::InspectApprovedJob => {
            let mut attempt = NixApprovedJobInspectionAttemptV3::new(origin);
            let inspected = catch_unwind(AssertUnwindSafe(|| attempt.inspect_once().is_ok()));
            let success = matches!(inspected, Ok(true));
            let _original_unwind = inspected.err();

            // Static success has no receipt or effect consumer. Keep the same
            // resident originals through exit, including on a caught unwind.
            attempt.wipe_secrets();
            std::process::exit(if success { 0 } else { 1 });
        }
        Command::Initialize | Command::Recover => std::process::exit(2),
    }
}

fn hardware_main(selected: Command) -> ! {
    // The same fixed phase reservoirs outlive all borrowing runs, including
    // negative results and caught unwind. No failed owner returns through Drop.
    let mut resources = NixOfflineHardwareResourcesV5::new();
    let mut startup = OfflineNixPrepareStartupV3::new();
    let admission = catch_unwind(AssertUnwindSafe(|| {
        match selected {
            Command::Initialize => startup.capture_and_admit_initialize(),
            Command::Recover => startup.capture_and_admit_recovery(),
            _ => std::process::exit(2),
        }.is_ok()
    }));
    if !matches!(admission, Ok(true)) {
        let _original_unwind = admission.err();
        std::process::exit(1);
    }
    let original = &mut startup;
    let borrowed = catch_unwind(AssertUnwindSafe(move || {
        match selected {
            Command::Initialize => original.borrow_initialize(),
            Command::Recover => original.borrow_recovery(),
            _ => std::process::exit(2),
        }
    }));
    let origin = match borrowed {
        Ok(Ok(origin)) => origin,
        Ok(Err(_)) => std::process::exit(1),
        Err(payload) => {
            let _original_unwind = payload;
            std::process::exit(1);
        }
    };
    let mut attempt = NixOfflineHardwareAttemptV5::new(origin, &mut resources);
    let execution = catch_unwind(AssertUnwindSafe(|| attempt.execute_once().is_ok()));
    let success = matches!(execution, Ok(true));
    let _original_unwind = execution.err();
    // These owners remain resident through explicit exit. A successful offline
    // job does not install runtime public/secret credentials or claim a floor.
    std::process::exit(if success { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parser_accepts_only_the_four_literal_manual_commands() {
        assert_eq!(
            command(Some(std::ffi::OsStr::new("prepare-keys"))),
            Some(Command::PrepareKeys),
        );
        assert_eq!(
            command(Some(std::ffi::OsStr::new("inspect-approved-job"))),
            Some(Command::InspectApprovedJob),
        );
        assert_eq!(command(Some(std::ffi::OsStr::new("initialize"))), Some(Command::Initialize));
        assert_eq!(command(Some(std::ffi::OsStr::new("recover"))), Some(Command::Recover));
        for value in [
            "",
            "initialize extra",
            "--recover",
            "--inspect-approved-job",
            "prepare-keys extra",
        ] {
            assert_eq!(command(Some(std::ffi::OsStr::new(value))), None);
        }
        assert_eq!(command(None), None);
    }
}
