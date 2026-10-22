//! Manual Nix preparation, static inspection and approved offline hardware job.
//!
//! The selected service is disabled by default and has no boot activation.
//! Explicit process exit retains originals through the terminal boundary; it
//! deliberately avoids returning an ExitCode that would drop failed custody.

use std::io::{self, Write as _};
use std::panic::{AssertUnwindSafe, catch_unwind};

use sha2::{Digest as _, Sha256};

use aos_sandbox_controller_domain::normal_root::{OfflineNixPrepareStartupV3, OfflineNixApprovalDeliveryStartupV6};
use aos_sandbox_controller_domain::journal::NixOfflineApprovalDeliveryNativeV6;
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
    ImportInitializeV6,
    ImportRecoveryV6,
}

fn command(value: Option<&std::ffi::OsStr>) -> Option<Command> {
    match value {
        Some(value) if value == "prepare-keys" => Some(Command::PrepareKeys),
        Some(value) if value == "inspect-approved-job" => Some(Command::InspectApprovedJob),
        Some(value) if value == "initialize" => Some(Command::Initialize),
        Some(value) if value == "recover" => Some(Command::Recover),
        Some(value) if value == "import-initialize-v6" => Some(Command::ImportInitializeV6),
        Some(value) if value == "import-recovery-v6" => Some(Command::ImportRecoveryV6),
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

    if matches!(selected, Command::ImportInitializeV6 | Command::ImportRecoveryV6) {
        approval_delivery_main(selected);
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
            Command::Initialize | Command::Recover | Command::ImportInitializeV6 | Command::ImportRecoveryV6 => std::process::exit(2),
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
            Command::Initialize | Command::Recover | Command::ImportInitializeV6 | Command::ImportRecoveryV6 => std::process::exit(2),
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
            let prepared = catch_unwind(AssertUnwindSafe(|| {
                if attempt.prepare_keys().is_err() {
                    return false;
                }

                // Operators receive only the verified public candidate through
                // the selected unit's output, without opening its private tree.
                let Some(public) = attempt.public_candidates_data() else {
                    return false;
                };
                write_public_candidate(public).is_ok()
            }));
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
        Command::Initialize | Command::Recover | Command::ImportInitializeV6 | Command::ImportRecoveryV6 => std::process::exit(2),
    }
}

fn approval_delivery_main(selected: Command) -> ! {
    let mut startup = OfflineNixApprovalDeliveryStartupV6::new();
    let admission = catch_unwind(AssertUnwindSafe(|| {
        match selected {
            Command::ImportInitializeV6 => startup.capture_initialize_approval(),
            Command::ImportRecoveryV6 => startup.capture_recovery_approval(),
            _ => std::process::exit(2),
        }
        .is_ok()
    }));
    if !matches!(admission, Ok(true)) {
        let _original_unwind = admission.err();
        std::process::exit(1);
    }
    let original = &mut startup;
    let borrowed = catch_unwind(AssertUnwindSafe(move || {
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
    let mut attempt = NixOfflineApprovalDeliveryNativeV6::new(origin);
    let delivery = catch_unwind(AssertUnwindSafe(|| attempt.deliver_once().is_ok()));
    let success = matches!(delivery, Ok(true));
    let _original_unwind = delivery.err();
    attempt.wipe_secrets();
    std::process::exit(if success { 0 } else { 1 });
}

fn write_public_candidate(public: &[u8; 268]) -> io::Result<()> {
    const PREFIX: &[u8] = b"AOS_NIX_OFFLINE_PUBLIC_V3=";
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut line = [0; PREFIX.len() + 536 + 1];
    line[..PREFIX.len()].copy_from_slice(PREFIX);
    for (index, byte) in public.iter().copied().enumerate() {
        line[PREFIX.len() + index * 2] = HEX[usize::from(byte >> 4)];
        line[PREFIX.len() + index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    line[PREFIX.len() + 536] = b'\n';

    let mut output = io::stdout().lock();
    output.write_all(&line)?;
    output.flush()
}

fn write_public_history(output: &mut impl io::Write, history: &[u8]) -> io::Result<()> {
    if history.is_empty() || history.len() > 4 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid public history extent",
        ));
    }

    // Each record stays below the journal's line limit. The explicit extent,
    // contiguous offsets and terminal digest let the operator reject partial
    // delivery without reading the protected journal as generic root.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0; 2048];
    for (index, chunk) in history.chunks(1024).enumerate() {
        for (offset, byte) in chunk.iter().copied().enumerate() {
            encoded[offset * 2] = HEX[usize::from(byte >> 4)];
            encoded[offset * 2 + 1] = HEX[usize::from(byte & 15)];
        }

        write!(
            output,
            "AOS_NIX_OFFLINE_HISTORY_V5={}:{}:",
            history.len(),
            index * 1024,
        )?;
        output.write_all(&encoded[..chunk.len() * 2])?;
        output.write_all(b"\n")?;
    }

    let digest = Sha256::digest(history);
    for (index, byte) in digest.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    output.write_all(b"AOS_NIX_OFFLINE_HISTORY_V5_END=")?;
    output.write_all(&encoded[..64])?;
    output.write_all(b"\n")?;
    output.flush()
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
        // Move this loan into the single invocation, as in the preparation path.
        let original = original;
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
    let execution = catch_unwind(AssertUnwindSafe(|| {
        if attempt.execute_once().is_err() {
            return false;
        }

        let Some(history) = attempt.public_completed_history_data() else {
            return false;
        };
        write_public_history(&mut io::stdout().lock(), history).is_ok()
    }));
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
    fn history_output_preserves_exact_bytes_across_bounded_records() {
        for size in [1, 1024, 1025, 2065] {
            let history: Vec<_> = (0_u8..=255).cycle().take(size).collect();
            let mut output = Vec::new();
            write_public_history(&mut output, &history).unwrap();

            let text = std::str::from_utf8(&output).unwrap();
            let mut lines: Vec<_> = text.lines().collect();
            let terminal = lines.pop().unwrap();
            assert_eq!(
                terminal,
                format!(
                    "AOS_NIX_OFFLINE_HISTORY_V5_END={:x}",
                    Sha256::digest(&history)
                ),
            );

            let mut decoded = Vec::new();
            for line in lines {
                assert!(line.len() < 2200);
                let mut fields = line
                    .strip_prefix("AOS_NIX_OFFLINE_HISTORY_V5=")
                    .unwrap()
                    .split(':');
                assert_eq!(fields.next().unwrap().parse::<usize>().unwrap(), size);
                assert_eq!(
                    fields.next().unwrap().parse::<usize>().unwrap(),
                    decoded.len()
                );
                let payload = fields.next().unwrap();
                assert!(fields.next().is_none());
                assert_eq!(payload.len() % 2, 0);
                for index in (0..payload.len()).step_by(2) {
                    decoded.push(u8::from_str_radix(&payload[index..index + 2], 16).unwrap());
                }
            }
            assert_eq!(decoded, history);
        }
    }

    #[test]
    fn history_output_rejects_invalid_extents_before_writing() {
        let mut output = Vec::new();
        assert!(write_public_history(&mut output, &[]).is_err());
        assert!(output.is_empty());

        let oversized = vec![0; 4 * 1024 * 1024 + 1];
        assert!(write_public_history(&mut output, &oversized).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn command_parser_accepts_only_the_six_literal_manual_commands() {
        assert_eq!(
            command(Some(std::ffi::OsStr::new("prepare-keys"))),
            Some(Command::PrepareKeys),
        );
        assert_eq!(
            command(Some(std::ffi::OsStr::new("inspect-approved-job"))),
            Some(Command::InspectApprovedJob),
        );
        assert_eq!(
            command(Some(std::ffi::OsStr::new("initialize"))),
            Some(Command::Initialize)
        );
        assert_eq!(
            command(Some(std::ffi::OsStr::new("recover"))),
            Some(Command::Recover)
        );
        assert_eq!(
            command(Some(std::ffi::OsStr::new("import-initialize-v6"))),
            Some(Command::ImportInitializeV6)
        );
        assert_eq!(
            command(Some(std::ffi::OsStr::new("import-recovery-v6"))),
            Some(Command::ImportRecoveryV6)
        );
        for value in [
            "",
            "initialize extra",
            "--recover",
            "import-initialize",
            "import-recovery-v5",
            "import-recovery-v6 extra",
            "--inspect-approved-job",
            "prepare-keys extra",
        ] {
            assert_eq!(command(Some(std::ffi::OsStr::new(value))), None);
        }
        assert_eq!(command(None), None);
    }


}
