//! Implements the bounded local interface for the AOS recovery initrd.
//!
//! The recovery application validates the exact recovery boot identity before
//! presenting operations. Its unauthenticated operation set is represented by
//! [`Operation`] rather than caller-supplied commands or paths. [`RecoverySession`]
//! retains successful slot verification in memory so a one-shot boot can only
//! target a slot verified during the same recovery process.
//!
//! [`verify`] owns the offline normal-UKI, release identity, authenticated
//! manifest, and dm-verity checks. It never mounts a normal root filesystem.

pub mod device;
pub mod maintenance;
pub mod restore;
pub mod status;
pub mod verify;

use std::error::Error;
use std::fmt;

use aos_boot_identity::BootSlot;
use verify::{VerificationError, VerifiedSlot, verify_slot};

/// Identifies an operation available before recovery-key authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Displays the bounded recovery status summary.
    Status,
    /// Verifies immutable slot A without mounting it.
    VerifyA,
    /// Verifies immutable slot B without mounting it.
    VerifyB,
    /// Boots slot A once after same-session verification.
    BootA,
    /// Boots slot B once after same-session verification.
    BootB,
    /// Verifies removable media and restores only the opposite inactive slot.
    RestoreInactive,
    /// Authenticates with the exact LUKS recovery token and mounts `/var`.
    UnlockState,
    /// Starts the bounded-environment shell after recovery-key authentication.
    MaintenanceShell,
    /// Unmounts and closes authenticated persistent state.
    LockState,
    /// Powers the machine off without changing persistent boot state.
    PowerOff,
}

/// Reports why a menu selection cannot be resolved to a bounded operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionError;

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("selection is not an available recovery operation")
    }
}

impl Error for SelectionError {}

/// Retains the verified-slot capability for one recovery process.
#[derive(Debug, Default)]
pub struct RecoverySession {
    verified_a: Option<VerifiedSlot>,
    verified_b: Option<VerifiedSlot>,
}

impl RecoverySession {
    /// Creates an unauthenticated session with no verified slot capability.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies a slot and retains the result for one-shot selection.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError`] when the manifest, UKI, embedded identity,
    /// slot pairing, or dm-verity tree fails validation.
    pub fn verify(&mut self, slot: BootSlot) -> Result<&VerifiedSlot, VerificationError> {
        let verified = verify_slot(slot)?;
        let destination = match slot {
            BootSlot::A => &mut self.verified_a,
            BootSlot::B => &mut self.verified_b,
        };
        *destination = Some(verified);

        destination
            .as_ref()
            .ok_or_else(|| VerificationError::Internal("verified result was not retained".into()))
    }

    /// Returns the same-session verified capability for a slot.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::NotVerified`] when the selected slot has
    /// not passed verification during this process.
    pub fn verified(&self, slot: BootSlot) -> Result<&VerifiedSlot, VerificationError> {
        let verified = match slot {
            BootSlot::A => self.verified_a.as_ref(),
            BootSlot::B => self.verified_b.as_ref(),
        };
        verified.ok_or(VerificationError::NotVerified(slot))
    }
}

/// Resolves one line of console input to a bounded recovery operation.
///
/// Whitespace around the selection is ignored. No selection is interpreted as
/// a path, device, executable, or shell fragment.
///
/// # Errors
///
/// Returns [`SelectionError`] when the input is not one of the exact menu
/// choices.
pub fn parse_selection(selection: &str) -> Result<Operation, SelectionError> {
    match selection.trim() {
        "1" | "status" => Ok(Operation::Status),
        "2" | "verify-a" => Ok(Operation::VerifyA),
        "3" | "verify-b" => Ok(Operation::VerifyB),
        "4" | "boot-a" => Ok(Operation::BootA),
        "5" | "boot-b" => Ok(Operation::BootB),
        "6" | "restore" => Ok(Operation::RestoreInactive),
        "7" | "unlock" => Ok(Operation::UnlockState),
        "8" | "shell" => Ok(Operation::MaintenanceShell),
        "9" | "lock" => Ok(Operation::LockState),
        "p" | "poweroff" => Ok(Operation::PowerOff),
        _ => Err(SelectionError),
    }
}

#[cfg(test)]
mod tests {
    use super::{Operation, parse_selection};

    #[test]
    fn resolves_only_fixed_operations() {
        assert_eq!(parse_selection("1"), Ok(Operation::Status));
        assert_eq!(parse_selection(" status\n"), Ok(Operation::Status));
        assert_eq!(parse_selection("2"), Ok(Operation::VerifyA));
        assert_eq!(parse_selection("verify-b"), Ok(Operation::VerifyB));
        assert_eq!(parse_selection("boot-a"), Ok(Operation::BootA));
        assert_eq!(parse_selection("5"), Ok(Operation::BootB));
        assert_eq!(parse_selection("restore"), Ok(Operation::RestoreInactive));
        assert_eq!(parse_selection("unlock"), Ok(Operation::UnlockState));
        assert_eq!(parse_selection("8"), Ok(Operation::MaintenanceShell));
        assert_eq!(parse_selection("lock"), Ok(Operation::LockState));
        assert_eq!(parse_selection("p"), Ok(Operation::PowerOff));
        assert_eq!(parse_selection("poweroff"), Ok(Operation::PowerOff));
    }

    #[test]
    fn rejects_commands_paths_and_arguments() {
        for selection in [
            "",
            "sh",
            "/bin/sh",
            "status /dev/vda",
            "boot-a --force",
            "poweroff --force",
            "$(id)",
        ] {
            assert!(parse_selection(selection).is_err());
        }
    }
}
