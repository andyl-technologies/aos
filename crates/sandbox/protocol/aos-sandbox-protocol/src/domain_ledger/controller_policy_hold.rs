//! Owns the canonical passive Controller policy-hold identity.
//!
//! The value carries comparison DATA only. Its native historical codec, typed
//! errors and currentness operations remain with the existing Ledger owner.

use aos_sandbox_model::{ObjectDigest, OperationId, SandboxId};

/// Identifies one exact, nonauthorizing Controller policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyHoldV1 {
    /// Names the associated public Create operation.
    pub operation: OperationId,
    /// Names the associated sandbox.
    pub sandbox: SandboxId,
    /// Commits the Controller-selected Create source.
    pub source: ObjectDigest,
    /// Commits the proposed policy binding.
    pub binding: ObjectDigest,
    /// Names the policy handoff epoch.
    pub epoch: u64,
    /// Distinguishes the held row from its released form.
    pub held: bool,
}

impl ControllerPolicyHoldV1 {

    /// Returns the accepted Create operation fixed by this hold.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the accepted Create sandbox fixed by this hold.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the query-time Controller source commitment.
    #[must_use]
    pub const fn source(self) -> ObjectDigest {
        self.source
    }

    /// Returns the root binding digest fixed before submission.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root handoff epoch fixed before submission.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether this historical hold row is held.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }
}
