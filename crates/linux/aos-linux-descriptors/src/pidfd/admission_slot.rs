//! In-place raw pidfd validation and infallible same-slot transfer.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use super::PidFd;
use crate::{Error, Result};

/// Owns one raw descriptor through validation and later typed transfer.
///
/// Native errors and unwinding leave the descriptor resident. Validation is
/// mechanical kernel evidence and grants no process identity or service role.
#[derive(Debug)]
pub struct PidFdAdmissionSlotV1 {
    fd: OwnedFd,
    state: AdmissionStateV1,
}

#[derive(Debug, Eq, PartialEq)]
enum AdmissionStateV1 {
    Raw,
    Validated,
    Refused,
}

impl PidFdAdmissionSlotV1 {
    /// Parks one actual descriptor without validation, IO or duplication.
    #[must_use]
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd, state: AdmissionStateV1::Raw }
    }

    /// Validates this resident original with the sole CLOEXEC/pidfs checker.
    ///
    /// # Errors
    /// Retains the descriptor on native or kind failure. Repeated or interrupted
    /// validation is refused without another kernel observation.
    pub fn validate_once(&mut self) -> Result<()> {
        if self.state != AdmissionStateV1::Raw {
            return Err(Error::invalid("pidfd admission", "already entered"));
        }
        self.state = AdmissionStateV1::Refused;
        PidFd::validate_owned_kind(self.fd.as_fd())?;
        self.state = AdmissionStateV1::Validated;
        Ok(())
    }

    /// Transfers the same validated pin without native work or duplication.
    ///
    /// # Errors
    /// Returns this whole slot unchanged if validation has not succeeded.
    pub fn into_validated(self) -> std::result::Result<PidFd, Self> {
        if self.state != AdmissionStateV1::Validated {
            return Err(self);
        }
        Ok(PidFd { fd: self.fd })
    }

    /// Transfers raw custody to its actual disposal or capture owner.
    #[must_use]
    pub fn into_owned(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for PidFdAdmissionSlotV1 {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for PidFdAdmissionSlotV1 {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
