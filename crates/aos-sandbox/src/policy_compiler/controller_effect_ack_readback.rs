//! Shared Root challenges and Native errors for Controller V8 readbacks.

use aos_sandbox_core::ObjectDigest;

use crate::journal::JournalError;

/// Names a fresh Root writer session and its expected effect cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerEffectAckChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
}

impl ControllerEffectAckChallengeV1 {
    /// Constructs a nonzero Root challenge.
    ///
    /// # Errors
    ///
    /// Rejects an empty nonce or cut.
    pub fn new(
        nonce: [u8; 16],
        cut: ObjectDigest,
    ) -> Result<Self, ControllerEffectAckReadbackErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(ControllerEffectAckReadbackErrorV1::Stale);
        }
        Ok(Self { nonce, cut })
    }

    /// Returns the Root-generated nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the Root-owned cut commitment.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }
}

/// Rejects an invalid or stale Controller effect-ACK receipt.
#[derive(Debug, thiserror::Error)]
pub enum ControllerEffectAckReadbackErrorV1 {
    /// The receipt, challenge, generation, or Controller state is stale.
    #[error("stale Controller effect acknowledgment")]
    Stale,
    /// The packet signature is invalid for the pinned Controller key.
    #[error("invalid Controller effect acknowledgment signature")]
    Signature,
    /// Protected Controller custody failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}
