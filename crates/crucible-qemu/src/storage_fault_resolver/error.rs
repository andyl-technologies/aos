//! Typed failures from production storage-fault resolution.
//!
//! The resolver keeps semantic translation in its parent module while this
//! module owns the stable, user-visible rejection vocabulary shared by every
//! resolution phase.

use crucible::model::{FaultObjectId, MappedEffectParameter};

/// Deterministic failure to resolve a production block directive.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageFaultResolutionError {
    /// The supplied opportunity does not describe this target and operation.
    #[error("storage opportunity does not match this block request")]
    OpportunityMismatch,
    /// Independently sampled phase contributions overflowed during composition.
    #[error("storage phase composition overflowed `{field}`")]
    PhaseMergeOverflow {
        /// Overflowed directive field.
        field: &'static str,
    },
    /// Independently sampled phases selected mutually exclusive request behavior.
    #[error("storage phase composition conflicts on `{field}`")]
    PhaseMergeConflict {
        /// Conflicting directive field.
        field: &'static str,
    },
    /// An action is not bound to the supplied opportunity and phase.
    #[error("storage binding `{binding}` is not bound to this request opportunity")]
    ActionIdentity {
        /// Binding carrying invalid action identity.
        binding: FaultObjectId,
    },
    /// An action selected a different concrete target.
    #[error("storage binding `{binding}` does not target this block request")]
    TargetMismatch {
        /// Mismatched binding.
        binding: FaultObjectId,
    },
    /// Removal actions must be applied to host state before request resolution.
    #[error("storage binding `{binding}` supplied a removal action at request resolution")]
    RemovalAction {
        /// Invalid binding.
        binding: FaultObjectId,
    },
    /// A non-storage action crossed the storage adapter boundary.
    #[error("binding `{binding}` supplied a non-storage effect to the block resolver")]
    NonStorageAction {
        /// Invalid binding.
        binding: FaultObjectId,
    },
    /// A referenced policy artifact was missing or wrong-shaped.
    #[error("storage binding `{binding}` reference `{reference}` is not {expected}")]
    PolicyReference {
        /// Binding containing the reference.
        binding: FaultObjectId,
        /// Referenced artifact.
        reference: FaultObjectId,
        /// Required artifact shape.
        expected: &'static str,
    },
    /// Checked directive composition overflowed.
    #[error("storage binding `{binding}` overflowed `{field}`")]
    Overflow {
        /// Binding whose contribution overflowed.
        binding: FaultObjectId,
        /// Overflowed field.
        field: &'static str,
    },
    /// A dynamic mapping named the wrong effect field or carried the wrong value type.
    #[error("storage binding `{binding}` did not map a valid {expected:?} value")]
    MappingOutput {
        /// Binding carrying the invalid mapping.
        binding: FaultObjectId,
        /// Effect field required by this resolver branch.
        expected: MappedEffectParameter,
    },
    /// The composed device directive violates an exact live invariant.
    #[error("storage binding `{binding}` produced an invalid block directive: {reason}")]
    InvalidDirective {
        /// Binding that produced the invalid contribution.
        binding: FaultObjectId,
        /// Stable failure detail.
        reason: String,
    },
    /// Locked replay observed a different pre-loss cache entry set.
    #[error(
        "storage binding `{binding}` cache-loss replay digest mismatch: expected {expected:?}, actual {actual:?}"
    )]
    ReplayEntrySetMismatch {
        /// Binding whose recorded transition is being replayed.
        binding: FaultObjectId,
        /// Digest recorded by the original execution.
        expected: [u8; 32],
        /// Digest computed from the live state before mutation.
        actual: [u8; 32],
    },
    /// The live adapter does not yet implement the complete selected semantics.
    #[error("storage binding `{binding}` selects unavailable live semantics: {parameter}")]
    UnsupportedEffect {
        /// Binding selecting the effect.
        binding: FaultObjectId,
        /// Unsupported semantic component.
        parameter: &'static str,
    },
    /// The selected target is not a declared live block device.
    #[error("storage action target is not a declared live block device")]
    UnsupportedTarget,
}
