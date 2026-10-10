//! Runtime, replay, capability, and checkpoint failures.

use std::error::Error;
use std::fmt;

use super::*;

/// Runtime, replay, capability, or checkpoint failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultRuntimeError {
    /// A capability manifest names a different adapter family.
    AdapterManifestMismatch,
    /// An action crossed adapter, target, phase, or lifetime contracts.
    AdapterActionMismatch,
    /// The adapter already owns one uncommitted transaction.
    AdapterTransactionPending,
    /// A commit or abort named no prepared transaction.
    UnknownAdapterTransaction,
    /// One atomic batch repeated an exact action identity.
    DuplicateAdapterAction,
    /// Rolling back a partially prepared cross-adapter batch failed.
    AdapterTransactionRollback,
    /// A collection count could not fit the canonical counter.
    CountOverflow(&'static str),
    /// A scenario-owned resource reservation failed.
    ResourceLimit(FaultResourceLimitError),
    /// Canonical evaluator checkpoint failed version, identity, or content validation.
    InvalidEvaluatorCheckpoint,
    /// Checkpoint omitted, duplicated, or added binding state.
    IncompleteBindingState,
    /// Checkpoint omitted or added production-adapter state.
    IncompleteAdapterState,
    /// Adapter payload digest does not authenticate its bytes.
    AdapterCheckpointDigest,
    /// Adapter checkpoint bytes are not the exact supported canonical schema.
    AdapterCheckpointCodec,
    /// The complete runtime checkpoint could not be encoded canonically.
    CheckpointEncoding,
    /// A monotone runtime sequence overflowed.
    SequenceOverflow(&'static str),
    /// A non-persistent effect entered the active table.
    NonPersistentActivation,
    /// Active key contradicts the effect registry.
    InvalidContributionKey,
    /// Active contribution has no active owning binding state.
    OrphanActiveContribution,
    /// A nested target or record contract failed.
    Contract(FaultContractError),
    /// Live backend omitted a required capability.
    MissingCapability(FaultCapabilityId),
    /// Replay trace or cursor is malformed.
    InvalidReplayTrace,
    /// Replay consumed every expected effect.
    ReplayExhausted,
    /// Encountered opportunity differs from the locked record.
    ReplayMismatch {
        /// Record index.
        index: usize,
        /// Expected opportunity identity.
        expected: Option<ContentHash>,
        /// Observed opportunity identity.
        observed: ContentHash,
    },
    /// Locked replay encountered a different live before-state digest.
    ReplayPreconditionMismatch {
        /// Exact resolved action identity.
        action: ContentHash,
        /// Digest retained by the replay record.
        expected: ContentHash,
        /// Digest observed by the live backend before mutation.
        observed: ContentHash,
    },
    /// Runtime semantic version or program identity differs.
    VersionOrIdentityMismatch,
}

impl fmt::Display for FaultRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid fault runtime state: {self:?}")
    }
}

impl Error for FaultRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ResourceLimit(error) => Some(error),
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}
