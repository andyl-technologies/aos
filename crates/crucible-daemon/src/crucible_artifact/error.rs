//! Typed failures for campaign artifact preparation and decoding.

use crucible_campaign::{CampaignCodecError, CampaignRepositoryError};

/// Required replay stage in signature-preserving finding preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingRequiredReproductionStage {
    /// The original reproduction failed at the start of the minimization pass.
    MinimizationOriginal,
    /// The original reproduction failed at the start of the independent verification pass.
    VerificationOriginal,
    /// The independently selected minimized reproduction disagreed with the first pass.
    SelectedVerification,
}

impl std::fmt::Display for FindingRequiredReproductionStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::MinimizationOriginal => "minimization-original replay",
            Self::VerificationOriginal => "verification-original replay",
            Self::SelectedVerification => "selected-reproduction verification",
        };
        formatter.write_str(name)
    }
}

/// Failure to translate a campaign artifact into the Crucible execution model.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleArtifactError {
    /// A private production replay could not be converted to portable capture evidence.
    #[error(transparent)]
    ProductionReplay(#[from] crate::FindingProductionReplayCaptureError),
    /// A required original or selected replay did not preserve the finding signature.
    #[error("required finding reproduction failed during {stage}")]
    FindingRequiredReproductionMismatch {
        /// Exact preparation stage that failed to reproduce the target signature.
        stage: FindingRequiredReproductionStage,
    },
    /// The artifact names a payload schema this adapter cannot execute.
    #[error("unsupported {artifact} payload schema {actual}; expected {expected}")]
    UnsupportedPayloadSchema {
        /// Stable artifact class used for diagnostics.
        artifact: &'static str,
        /// Unsupported schema supplied by the artifact.
        actual: u32,
        /// Exact schema implemented by this adapter.
        expected: u32,
    },
    /// Configuration payload bytes do not carry the required Schedule version.
    #[error("Crucible configuration payload requires Schedule compact binary V2")]
    UnsupportedScheduleEncoding,
    /// Compact Crucible bytes were malformed or semantically invalid.
    #[error("invalid Crucible {artifact} payload: {source}")]
    InvalidPayload {
        /// Stable artifact class used for diagnostics.
        artifact: &'static str,
        /// Crucible compact-codec validation failure.
        #[source]
        source: Box<crucible::EngineError>,
    },
    /// The decoded semantic identity differs from the campaign binding.
    #[error("Crucible {artifact} payload semantic identity does not match its campaign artifact")]
    SemanticIdentityMismatch {
        /// Stable artifact class used for diagnostics.
        artifact: &'static str,
    },
    /// A configuration names a different exact scenario artifact.
    #[error("Crucible configuration artifact names a different exact scenario artifact")]
    ScenarioArtifactMismatch,
    /// A structurally valid schedule contains selections that were not resolved.
    #[error("Crucible configuration contains an unresolved campaign selection decision")]
    UnresolvedSelectionDecision,
    /// Authenticated campaign selection closure could not be resolved.
    #[error(transparent)]
    SelectionRepository(#[from] CampaignRepositoryError),
    /// Immutable artifact publication failed after semantic verification.
    #[error(transparent)]
    RepositoryPublication(CampaignRepositoryError),
    /// A model-sampled value has no pure model verifier in this executor.
    #[error("Crucible configuration contains a model selection without a registered verifier")]
    UnverifiedModelSelection,
    /// A configuration exceeds the bounded selection-resolution contract.
    #[error("Crucible configuration exceeds the campaign selection resolution limit")]
    SelectionResolutionLimit,
    /// Selected-continuation decoding exceeds its admitted logical memory budget.
    #[error("Crucible selected-continuation decoding exceeds `{resource}`")]
    ResourceLimit {
        /// Stable resource category that refused the decoded representation.
        resource: &'static str,
    },
    /// A derived schedule prefix was inconsistent with its source schedule.
    #[error(transparent)]
    SelectionPrefix(#[from] crucible::ScheduleError),
    /// Campaign envelope construction rejected a newly encoded artifact.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// A promoted signal-fault selection did not match its standardized records.
    #[error(transparent)]
    SignalFaultSelection(#[from] crucible::SignalFaultSelectableError),
    /// A scenario-owned network fault selection failed exact producer replay.
    #[error(transparent)]
    NetworkFaultSelection(Box<crucible::NetworkFaultSelectableError>),
    /// A standardized signal-fault selection was not followed by its exact prefix.
    #[error("Crucible configuration signal-fault branch differs from its authenticated prefix")]
    SignalFaultScheduleMismatch,
    /// A raw signal-fault override was not certified by a standardized selection.
    #[error("Crucible configuration contains an unbound signal-fault override")]
    UnboundSignalFaultOverride,
}

impl From<crucible::NetworkFaultSelectableError> for CrucibleArtifactError {
    fn from(error: crucible::NetworkFaultSelectableError) -> Self {
        Self::NetworkFaultSelection(Box::new(error))
    }
}
