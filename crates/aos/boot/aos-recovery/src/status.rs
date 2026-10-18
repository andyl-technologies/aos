//! Produces the bounded status document shown before operator authentication.
//!
//! Status is assembled only from fixed firmware and signed-UKI paths. It does
//! not accept caller-provided paths and never returns raw file contents.

use std::fs;
use std::io;

use crate::RecoverySession;
use aos_boot_identity::BootSlot;

const OS_RELEASE: &str = "/etc/os-release";
const SECURE_BOOT: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const SETUP_MODE: &str = "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Names the independently installed recovery copy that is currently running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCopy {
    /// Recovery copy paired with normal slot A.
    A,
    /// Recovery copy paired with normal slot B.
    B,
}

/// Summarizes firmware verification without exposing variable bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwarePosture {
    /// Secure Boot is enabled and firmware is outside setup mode.
    Enforcing,
    /// Firmware variables explicitly report a non-enforcing posture.
    NotEnforcing,
    /// Required fixed firmware variables could not be read canonically.
    Unavailable,
}

/// Summarizes one normal slot using only same-session verification evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlotPosture {
    /// The slot has not been verified during this recovery process.
    Unverified,
    /// The slot passed signed-identity and dm-verity verification.
    Verified {
        /// Signed release identity carried by the normal UKI.
        release: String,
        /// Whether the installed normal entry currently has a tries suffix.
        counted: bool,
    },
}

/// Contains the complete unauthenticated status surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryStatus {
    /// Signed recovery copy selected by firmware.
    pub copy: RecoveryCopy,
    /// Current firmware Secure Boot posture.
    pub firmware: FirmwarePosture,
    /// Same-session status for normal slot A.
    pub slot_a: SlotPosture,
    /// Same-session status for normal slot B.
    pub slot_b: SlotPosture,
}

/// Reports malformed signed recovery metadata.
#[derive(Debug)]
pub enum StatusError {
    /// A required fixed-path read failed.
    Io(io::Error),
    /// The signed recovery copy field was missing, duplicated, or malformed.
    RecoveryCopy,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "status read failed: {error}"),
            Self::RecoveryCopy => formatter.write_str("signed recovery copy identity is invalid"),
        }
    }
}

impl std::error::Error for StatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::RecoveryCopy => None,
        }
    }
}

impl From<io::Error> for StatusError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl RecoveryStatus {
    /// Collects normalized status from fixed signed and firmware inputs.
    ///
    /// # Errors
    ///
    /// Returns [`StatusError`] when the signed recovery os-release cannot be
    /// read or does not carry exactly one canonical `AOS_RECOVERY_COPY` field.
    pub fn collect(session: &RecoverySession) -> Result<Self, StatusError> {
        let os_release = fs::read_to_string(OS_RELEASE)?;
        let copy = recovery_copy(&os_release)?;
        let firmware = match (efi_boolean(SECURE_BOOT), efi_boolean(SETUP_MODE)) {
            (Some(true), Some(false)) => FirmwarePosture::Enforcing,
            (Some(_), Some(_)) => FirmwarePosture::NotEnforcing,
            _ => FirmwarePosture::Unavailable,
        };

        Ok(Self {
            copy,
            firmware,
            slot_a: slot_posture(session, BootSlot::A),
            slot_b: slot_posture(session, BootSlot::B),
        })
    }
}

fn slot_posture(session: &RecoverySession, slot: BootSlot) -> SlotPosture {
    match session.verified(slot) {
        Ok(verified) => SlotPosture::Verified {
            release: verified.release.clone(),
            counted: verified.counted,
        },
        Err(_) => SlotPosture::Unverified,
    }
}

fn efi_boolean(path: &str) -> Option<bool> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() != 5 {
        return None;
    }
    match bytes[4] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn recovery_copy(os_release: &str) -> Result<RecoveryCopy, StatusError> {
    let mut copy = None;
    for line in os_release.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key != "AOS_RECOVERY_COPY" {
            continue;
        }
        if copy.is_some() {
            return Err(StatusError::RecoveryCopy);
        }
        copy = match value {
            "A" => Some(RecoveryCopy::A),
            "B" => Some(RecoveryCopy::B),
            _ => return Err(StatusError::RecoveryCopy),
        };
    }
    copy.ok_or(StatusError::RecoveryCopy)
}

#[cfg(test)]
mod tests {
    use super::{RecoveryCopy, recovery_copy};

    #[test]
    fn accepts_only_one_canonical_copy_field() {
        assert_eq!(
            recovery_copy("ID=aos-recovery\nAOS_RECOVERY_COPY=A\n").ok(),
            Some(RecoveryCopy::A)
        );
        assert_eq!(
            recovery_copy("AOS_RECOVERY_COPY=B\n").ok(),
            Some(RecoveryCopy::B)
        );
        assert!(recovery_copy("ID=aos-recovery\n").is_err());
        assert!(recovery_copy("AOS_RECOVERY_COPY=C\n").is_err());
        assert!(recovery_copy("AOS_RECOVERY_COPY=A\nAOS_RECOVERY_COPY=A\n").is_err());
    }
}
