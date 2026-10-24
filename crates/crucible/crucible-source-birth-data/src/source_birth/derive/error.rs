//! Preserves typed stage failures, actual error owners and written byte prefixes.

use crate::errors::ProviderError;
use crate::errors::RuntimeError;
use crucible_node_format::ContractError;
use std::{collections::TryReserveError, fmt};

/// Identifies the actual original algorithm boundary that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationStage {
    /// Performs complete launch credit, validation and nested policy decodes.
    LaunchValidation,
    /// Performs the original distinct prebirth coordinator decode.
    CoordinatorDecode,
    /// Compares the decoded candidate against the independent original.
    WorldComparison,
    /// Materializes the unchanged SourceBirth serializer.
    SourceMaterialization,
    /// Materializes the unchanged registration serializer.
    RegistrationMaterialization,
    /// Builds the actual selected Hello declaration.
    HelloDeclaration,
    /// Authenticates the actual planned registration data.
    ProspectiveRegistration,
    /// Quotes the original source serializer geometry.
    SourceGeometry,
    /// Quotes the original registration serializer geometry.
    RegistrationGeometry,
    /// Checks output-only bounds and reserves both banks in order.
    OutputReservation,
    /// Writes the source canonical bank.
    SourceEncoding,
    /// Writes the registration canonical bank.
    RegistrationEncoding,
}

/// Carries a closed original guard disposition without claiming Source authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorldRefusal {
    /// Preserves the original complete Source process guard.
    ForeignCreatorProcess,
    /// Preserves the original complete Source thread guard.
    ForeignCreatorThread,
    /// Preserves an absent complete producer world.
    ProducerWorldAbsent,
    /// Preserves a changed or non-complete producer installation.
    ProducerCoordinatorChanged,
    /// Preserves the original reactive source owner guard.
    ReactiveForeignOwner,
    /// Preserves a changed or non-edition-five reactive installation.
    ReactiveCoordinatorChanged,
    /// Preserves the ordinary view's sole-binding prerequisite.
    AmbiguousBinding,
}

impl fmt::Display for WorldRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ForeignCreatorProcess => "complete source belongs to another creator process",
            Self::ForeignCreatorThread => "complete source belongs to another creator thread",
            Self::ProducerWorldAbsent => "complete producer world absent",
            Self::ProducerCoordinatorChanged => "packet complete original coordinator changed",
            Self::ReactiveForeignOwner => "connected packet foreign original source process/thread",
            Self::ReactiveCoordinatorChanged => "complete packet original coordinator changed",
            Self::AmbiguousBinding => "foreign or stale authority",
        })
    }
}

/// Owns the actual failing error or a closed operational output refusal.
#[derive(Debug)]
pub enum DerivationCause {
    /// Retains the original Transport error and its owned nested diagnostic.
    Provider(ProviderError),
    /// Retains the original canonical writer error.
    Contract(ContractError),
    /// Retains the original DOM materialization error.
    Json(serde_json::Error),
    /// Retains the original serializer geometry refusal.
    Runtime(RuntimeError),
    /// Retains the closed deferred guard or independent comparison refusal.
    World(WorldRefusal),
    /// Retains the actual output-bank reservation failure.
    Reservation(TryReserveError),
    /// Refuses overflow of the two actual requested bank extents.
    OutputOverflow,
    /// Refuses the explicit operational output-storage limit.
    OutputLimit,
    /// Preserves the original constructor's observed over-allocation refusal.
    OutputCapacity,
}

impl fmt::Display for DerivationCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
            Self::Runtime(error) => error.fmt(formatter),
            Self::World(reason) => reason.fmt(formatter),
            Self::Reservation(error) => error.fmt(formatter),
            Self::OutputOverflow => formatter.write_str("candidate bank extent overflow"),
            Self::OutputLimit => formatter.write_str("candidate bank output limit"),
            Self::OutputCapacity => formatter.write_str("candidate bank reservation capacity"),
        }
    }
}

/// Retains a failure and both actual bank prefixes without returning deep DOMs.
#[derive(Debug)]
pub struct DerivationFailure {
    pub(super) stage: DerivationStage,
    pub(super) cause: DerivationCause,
    pub(super) source_bank: Vec<u8>,
    pub(super) registration_bank: Vec<u8>,
}

impl DerivationFailure {
    /// Returns the actual failing boundary.
    pub fn stage(&self) -> DerivationStage {
        self.stage
    }

    /// Borrows the original owned error or closed operational refusal.
    pub fn cause(&self) -> &DerivationCause {
        &self.cause
    }

    /// Borrows any source bytes written before refusal.
    pub fn source_prefix(&self) -> &[u8] {
        &self.source_bank
    }

    /// Borrows any registration bytes written before refusal.
    pub fn registration_prefix(&self) -> &[u8] {
        &self.registration_bank
    }

    /// Returns the ordinary parent's unchanged semantic error category.
    ///
    /// Operational reservation/output failures are separate and return `None`.
    /// This mapping grants neither original-world authentication nor funding.
    pub fn original_runtime_error(&self) -> Option<RuntimeError> {
        use DerivationStage::*;
        match self.stage {
            LaunchValidation | CoordinatorDecode | HelloDeclaration => {
                Some(RuntimeError::UnsupportedFacet)
            }
            WorldComparison | ProspectiveRegistration => Some(RuntimeError::ForeignAuthority),
            SourceMaterialization | RegistrationMaterialization => {
                if matches!(self.cause, DerivationCause::World(_)) {
                    Some(RuntimeError::ForeignAuthority)
                } else {
                    Some(RuntimeError::ResourceLimit)
                }
            }
            SourceGeometry | RegistrationGeometry | SourceEncoding | RegistrationEncoding => {
                Some(RuntimeError::ResourceLimit)
            }
            OutputReservation => None,
        }
    }
}

impl fmt::Display for DerivationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.stage, self.cause)
    }
}

impl std::error::Error for DerivationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            DerivationCause::Provider(error) => Some(error),
            DerivationCause::Contract(error) => Some(error),
            DerivationCause::Json(error) => Some(error),
            DerivationCause::Runtime(error) => Some(error),
            DerivationCause::Reservation(error) => Some(error),
            _ => None,
        }
    }
}
