//! Bounded physical checkpoint disposition observations on the RAM channel.
//!
//! ```text
//! Request tag 10: ARM digest[32], request generation:u64, connection epoch:u64
//! Reply tag 130: same selectors[48], physical state:u8, first:i32, post:i32
//! Common header[158]; all integers big endian; request206/reply215 body bytes.
//! ```
//!
//! These records select existing custody. Only the registered native owner can
//! publish its actual terminal journal after candidate I/O, root acknowledgments,
//! observer returns, and provider return. Wire syntax never establishes that cut.

use super::RamControlError;

/// Selects a retained ARM request and its actual Monitor connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlCheckpointBinding {
    /// Digest of the exact original ARM request, rather than this observation.
    pub arm_request_digest: [u8; 32],
    /// Actual nonzero generation of the retained native request.
    pub request_generation: u64,
    /// Actual Monitor connection epoch, or zero before any QMP binding exists.
    pub connection_epoch: u64,
}

impl RamControlCheckpointBinding {
    /// Checks bounded selector syntax without creating a request owner.
    ///
    /// # Errors
    /// Refuses a zero request generation. A connection epoch of zero makes no
    /// assertion that a root or stop owner exists or has been released.
    pub fn validate(self) -> Result<(), RamControlError> {
        if self.request_generation == 0 {
            return Err(RamControlError::InvalidFrame);
        }
        Ok(())
    }
}

/// Names the physical custody reported by an actual native terminal journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamControlCheckpointPhysicalState {
    /// The request or its physical borrowers remain retained.
    Pending = 0,
    /// Actual candidate I/O, root, observers, provider, and alias have returned.
    Retired = 1,
    /// Actual no-root/no-effects cleanup returned every retained borrower.
    NoRootAbandoned = 2,
    /// Independent physical disposition remains indeterminate.
    Uncertain = 3,
}

/// Keeps physical completion distinct from the initiating semantic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlCheckpointDispositionReceipt {
    /// Physical custody state, independent of the initiating semantic result.
    pub physical_state: RamControlCheckpointPhysicalState,
    /// Raw initiating status; a semantic failure can survive physical retirement.
    pub first_status: i32,
    /// Independent postcut status; uncertain custody cannot report completion.
    pub post_status: i32,
}

impl RamControlCheckpointDispositionReceipt {
    /// Checks canonical state/status relationships without certifying retirement.
    ///
    /// # Errors
    /// Refuses positive statuses, completed physical custody with a failed
    /// postcut, or retirement without a retained Monitor connection. Abandonment
    /// may follow a bound connection if no root or checkpoint effects occurred.
    pub fn validate(self, connection_epoch: u64) -> Result<(), RamControlError> {
        let complete = matches!(
            self.physical_state,
            RamControlCheckpointPhysicalState::Retired
                | RamControlCheckpointPhysicalState::NoRootAbandoned
        );
        if self.first_status > 0
            || self.post_status > 0
            || (complete && self.post_status != 0)
            || (self.physical_state == RamControlCheckpointPhysicalState::Retired
                && connection_epoch == 0)
        {
            return Err(RamControlError::InvalidFrame);
        }
        Ok(())
    }
}
