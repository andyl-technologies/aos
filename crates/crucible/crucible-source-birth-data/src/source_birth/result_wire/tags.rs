//! Maps actual owned derivation errors to closed wire tags and real serde metadata.

use super::super::derive::{DerivationCause, DerivationFailure, DerivationStage, WorldRefusal};
use super::{TagField, WireError};
use crate::errors::ProviderError;
use crucible_node_format::ContractError;

/// Selects the closed result shape; numeric tags belong to codec version one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Carries two complete candidate byte banks.
    Success = 0,
    /// Carries an original semantic derivation failure.
    DerivationFailure = 1,
    /// Carries an explicit child input, allocation or output failure.
    OperationalFailure = 2,
}

impl Status {
    pub(super) fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::DerivationFailure),
            2 => Ok(Self::OperationalFailure),
            value => Err(WireError::UnknownTag(TagField::Status, value)),
        }
    }
}

/// Identifies an original pure stage, with zero reserved for operations outside derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    /// Names the absence of an entered derivation stage.
    None = 0,
    /// Names the original LaunchValidation boundary.
    LaunchValidation = 1,
    /// Names the original CoordinatorDecode boundary.
    CoordinatorDecode = 2,
    /// Names the original WorldComparison boundary.
    WorldComparison = 3,
    /// Names the original SourceMaterialization boundary.
    SourceMaterialization = 4,
    /// Names the original RegistrationMaterialization boundary.
    RegistrationMaterialization = 5,
    /// Names the original HelloDeclaration boundary.
    HelloDeclaration = 6,
    /// Names the original ProspectiveRegistration boundary.
    ProspectiveRegistration = 7,
    /// Names the original SourceGeometry boundary.
    SourceGeometry = 8,
    /// Names the original RegistrationGeometry boundary.
    RegistrationGeometry = 9,
    /// Names the original OutputReservation boundary.
    OutputReservation = 10,
    /// Names the original SourceEncoding boundary.
    SourceEncoding = 11,
    /// Names the original RegistrationEncoding boundary.
    RegistrationEncoding = 12,
}

impl Stage {
    pub(super) fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::LaunchValidation),
            2 => Ok(Self::CoordinatorDecode),
            3 => Ok(Self::WorldComparison),
            4 => Ok(Self::SourceMaterialization),
            5 => Ok(Self::RegistrationMaterialization),
            6 => Ok(Self::HelloDeclaration),
            7 => Ok(Self::ProspectiveRegistration),
            8 => Ok(Self::SourceGeometry),
            9 => Ok(Self::RegistrationGeometry),
            10 => Ok(Self::OutputReservation),
            11 => Ok(Self::SourceEncoding),
            12 => Ok(Self::RegistrationEncoding),
            value => Err(WireError::UnknownTag(TagField::Stage, value)),
        }
    }
}

/// Identifies the actual owned error family or a closed operational refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cause {
    /// Carries no failure cause on success.
    None = 0,
    /// Names the ProviderIo error category.
    ProviderIo = 1,
    /// Names the ProviderContractInvalid error category.
    ProviderContractInvalid = 2,
    /// Names the ProviderContractOverflow error category.
    ProviderContractOverflow = 3,
    /// Names the ProviderContractJson error category.
    ProviderContractJson = 4,
    /// Names the ProviderFrame error category.
    ProviderFrame = 5,
    /// Names the ProviderCorrelation error category.
    ProviderCorrelation = 6,
    /// Names the ProviderResourceExhausted error category.
    ProviderResourceExhausted = 7,
    /// Names the ProviderConflict error category.
    ProviderConflict = 8,
    /// Names the ContractInvalid error category.
    ContractInvalid = 9,
    /// Names the ContractOverflow error category.
    ContractOverflow = 10,
    /// Names the ContractJson error category.
    ContractJson = 11,
    /// Names the Json error category.
    Json = 12,
    /// Names the Runtime error category.
    Runtime = 13,
    /// Names the WorldCreatorProcess error category.
    WorldCreatorProcess = 14,
    /// Names the WorldCreatorThread error category.
    WorldCreatorThread = 15,
    /// Names the WorldProducerAbsent error category.
    WorldProducerAbsent = 16,
    /// Names the WorldProducerChanged error category.
    WorldProducerChanged = 17,
    /// Names the WorldReactiveOwner error category.
    WorldReactiveOwner = 18,
    /// Names the WorldReactiveChanged error category.
    WorldReactiveChanged = 19,
    /// Names the WorldBinding error category.
    WorldBinding = 20,
    /// Names the Reservation error category.
    Reservation = 21,
    /// Names the OutputOverflow error category.
    OutputOverflow = 22,
    /// Names the OutputLimit error category.
    OutputLimit = 23,
    /// Names the OutputCapacity error category.
    OutputCapacity = 24,
    /// Names the RequestMalformed error category.
    RequestMalformed = 25,
    /// Names the RequestLimit error category.
    RequestLimit = 26,
    /// Names the InputIo error category.
    InputIo = 27,
    /// Names the DiagnosticLimit error category.
    DiagnosticLimit = 28,
}

impl Cause {
    pub(super) fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ProviderIo),
            2 => Ok(Self::ProviderContractInvalid),
            3 => Ok(Self::ProviderContractOverflow),
            4 => Ok(Self::ProviderContractJson),
            5 => Ok(Self::ProviderFrame),
            6 => Ok(Self::ProviderCorrelation),
            7 => Ok(Self::ProviderResourceExhausted),
            8 => Ok(Self::ProviderConflict),
            9 => Ok(Self::ContractInvalid),
            10 => Ok(Self::ContractOverflow),
            11 => Ok(Self::ContractJson),
            12 => Ok(Self::Json),
            13 => Ok(Self::Runtime),
            14 => Ok(Self::WorldCreatorProcess),
            15 => Ok(Self::WorldCreatorThread),
            16 => Ok(Self::WorldProducerAbsent),
            17 => Ok(Self::WorldProducerChanged),
            18 => Ok(Self::WorldReactiveOwner),
            19 => Ok(Self::WorldReactiveChanged),
            20 => Ok(Self::WorldBinding),
            21 => Ok(Self::Reservation),
            22 => Ok(Self::OutputOverflow),
            23 => Ok(Self::OutputLimit),
            24 => Ok(Self::OutputCapacity),
            25 => Ok(Self::RequestMalformed),
            26 => Ok(Self::RequestLimit),
            27 => Ok(Self::InputIo),
            28 => Ok(Self::DiagnosticLimit),
            value => Err(WireError::UnknownTag(TagField::Cause, value)),
        }
    }
}

/// Preserves the actual original serde error classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SerdeCategory {
    /// Preserves serde Io classification.
    Io = 1,
    /// Preserves serde Syntax classification.
    Syntax = 2,
    /// Preserves serde Data classification.
    Data = 3,
    /// Preserves serde Eof classification.
    Eof = 4,
}

impl SerdeCategory {
    pub(super) fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Io),
            2 => Ok(Self::Syntax),
            3 => Ok(Self::Data),
            4 => Ok(Self::Eof),
            value => Err(WireError::UnknownTag(TagField::SerdeCategory, value)),
        }
    }
}

/// Preserves actual serde coordinates with an explicitly unspecified original input.
///
/// Presence corresponds to coordinate-basis tag `1`. These are the unchanged
/// line/column returned by the actual nested error, including real zero values.
/// They are not offsets in a whole request, candidate buffer or inferred token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SerdeMetadata {
    /// Preserves the original serde classifier.
    pub category: SerdeCategory,
    /// Preserves the actual original line number, without rebasing.
    pub line: u64,
    /// Preserves the actual original column number, without rebasing.
    pub column: u64,
}

/// Selects explicit operational failures that can occur before derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationalReason {
    /// The private request is malformed.
    RequestMalformed,
    /// The private request exceeds its explicit limit.
    RequestLimit,
    /// Reading the actual input stream fails.
    InputIo,
    /// Reserving actual input/clone storage fails.
    Reservation,
    /// The complete original diagnostic cannot fit its explicit limit.
    DiagnosticLimit,
}

/// Carries a closed, status-compatible diagnostic classification as ordinary data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureInfo {
    pub(super) status: Status,
    pub(super) stage: Stage,
    pub(super) cause: Cause,
    pub(super) metadata: Option<SerdeMetadata>,
}

impl FailureInfo {
    /// Classifies the actual owned facade error without parsing its Display text.
    ///
    /// # Errors
    /// Refuses an actual serde coordinate not representable as a wire u64.
    pub fn from_derivation(failure: &DerivationFailure) -> Result<Self, WireError> {
        let stage = match failure.stage() {
            DerivationStage::LaunchValidation => Stage::LaunchValidation,
            DerivationStage::CoordinatorDecode => Stage::CoordinatorDecode,
            DerivationStage::WorldComparison => Stage::WorldComparison,
            DerivationStage::SourceMaterialization => Stage::SourceMaterialization,
            DerivationStage::RegistrationMaterialization => Stage::RegistrationMaterialization,
            DerivationStage::HelloDeclaration => Stage::HelloDeclaration,
            DerivationStage::ProspectiveRegistration => Stage::ProspectiveRegistration,
            DerivationStage::SourceGeometry => Stage::SourceGeometry,
            DerivationStage::RegistrationGeometry => Stage::RegistrationGeometry,
            DerivationStage::OutputReservation => Stage::OutputReservation,
            DerivationStage::SourceEncoding => Stage::SourceEncoding,
            DerivationStage::RegistrationEncoding => Stage::RegistrationEncoding,
        };
        let (cause, metadata) = classify_cause(failure.cause())?;
        let status = if matches!(
            cause,
            Cause::Reservation | Cause::OutputOverflow | Cause::OutputLimit | Cause::OutputCapacity
        ) {
            Status::OperationalFailure
        } else {
            Status::DerivationFailure
        };
        Ok(Self {
            status,
            stage,
            cause,
            metadata,
        })
    }

    /// Classifies a concrete operational refusal outside derivation.
    pub fn operational(reason: OperationalReason) -> Self {
        let cause = match reason {
            OperationalReason::RequestMalformed => Cause::RequestMalformed,
            OperationalReason::RequestLimit => Cause::RequestLimit,
            OperationalReason::InputIo => Cause::InputIo,
            OperationalReason::Reservation => Cause::Reservation,
            OperationalReason::DiagnosticLimit => Cause::DiagnosticLimit,
        };
        Self {
            status: Status::OperationalFailure,
            stage: Stage::None,
            cause,
            metadata: None,
        }
    }

    /// Returns the explicit operational or semantic status.
    pub fn status(&self) -> Status {
        self.status
    }

    /// Returns the actual entered derivation stage, or none before derivation.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Returns the actual underlying closed category.
    pub fn cause(&self) -> Cause {
        self.cause
    }

    /// Returns only actual original serde metadata when that error exists.
    pub fn serde_metadata(&self) -> Option<SerdeMetadata> {
        self.metadata
    }
}

impl Cause {
    pub(super) fn is_serde(self) -> bool {
        matches!(
            self,
            Self::ProviderContractJson | Self::ContractJson | Self::Json
        )
    }
}

pub(super) fn valid_failure(status: Status, stage: Stage, cause: Cause) -> bool {
    use Cause as C;
    use Stage as S;
    match status {
        Status::Success => false,
        Status::OperationalFailure => match cause {
            C::Reservation => matches!(stage, S::None | S::OutputReservation),
            C::OutputOverflow | C::OutputLimit | C::OutputCapacity => stage == S::OutputReservation,
            C::RequestMalformed | C::RequestLimit | C::InputIo | C::DiagnosticLimit => {
                stage == S::None
            }
            _ => false,
        },
        Status::DerivationFailure => match cause {
            C::ProviderIo
            | C::ProviderContractInvalid
            | C::ProviderContractOverflow
            | C::ProviderContractJson
            | C::ProviderFrame
            | C::ProviderCorrelation
            | C::ProviderResourceExhausted
            | C::ProviderConflict => matches!(
                stage,
                S::LaunchValidation
                    | S::CoordinatorDecode
                    | S::HelloDeclaration
                    | S::ProspectiveRegistration
            ),
            C::ContractInvalid | C::ContractOverflow | C::ContractJson => {
                matches!(stage, S::SourceEncoding | S::RegistrationEncoding)
            }
            C::Json => matches!(
                stage,
                S::SourceMaterialization | S::RegistrationMaterialization
            ),
            C::Runtime => matches!(stage, S::SourceGeometry | S::RegistrationGeometry),
            C::WorldCreatorProcess
            | C::WorldCreatorThread
            | C::WorldProducerAbsent
            | C::WorldProducerChanged
            | C::WorldReactiveOwner
            | C::WorldReactiveChanged => stage == S::WorldComparison,
            C::WorldBinding => matches!(
                stage,
                S::WorldComparison | S::SourceMaterialization | S::RegistrationMaterialization
            ),
            _ => false,
        },
    }
}

fn serde_metadata(error: &serde_json::Error) -> Result<SerdeMetadata, WireError> {
    let category = match error.classify() {
        serde_json::error::Category::Io => SerdeCategory::Io,
        serde_json::error::Category::Syntax => SerdeCategory::Syntax,
        serde_json::error::Category::Data => SerdeCategory::Data,
        serde_json::error::Category::Eof => SerdeCategory::Eof,
    };
    Ok(SerdeMetadata {
        category,
        line: u64::try_from(error.line()).map_err(|_| WireError::LengthOverflow)?,
        column: u64::try_from(error.column()).map_err(|_| WireError::LengthOverflow)?,
    })
}

fn classify_cause(cause: &DerivationCause) -> Result<(Cause, Option<SerdeMetadata>), WireError> {
    Ok(match cause {
        DerivationCause::Provider(error) => match error {
            ProviderError::Io(_) => (Cause::ProviderIo, None),
            ProviderError::Contract(error) => match error {
                ContractError::Invalid { .. } => (Cause::ProviderContractInvalid, None),
                ContractError::Overflow => (Cause::ProviderContractOverflow, None),
                ContractError::Json(error) => {
                    (Cause::ProviderContractJson, Some(serde_metadata(error)?))
                }
            },
            ProviderError::Frame(_) => (Cause::ProviderFrame, None),
            ProviderError::Correlation(_) => (Cause::ProviderCorrelation, None),
            ProviderError::ResourceExhausted(_) => (Cause::ProviderResourceExhausted, None),
            ProviderError::Conflict(_) => (Cause::ProviderConflict, None),
        },
        DerivationCause::Contract(error) => match error {
            ContractError::Invalid { .. } => (Cause::ContractInvalid, None),
            ContractError::Overflow => (Cause::ContractOverflow, None),
            ContractError::Json(error) => (Cause::ContractJson, Some(serde_metadata(error)?)),
        },
        DerivationCause::Json(error) => (Cause::Json, Some(serde_metadata(error)?)),
        DerivationCause::Runtime(_) => (Cause::Runtime, None),
        DerivationCause::World(reason) => (
            match reason {
                WorldRefusal::ForeignCreatorProcess => Cause::WorldCreatorProcess,
                WorldRefusal::ForeignCreatorThread => Cause::WorldCreatorThread,
                WorldRefusal::ProducerWorldAbsent => Cause::WorldProducerAbsent,
                WorldRefusal::ProducerCoordinatorChanged => Cause::WorldProducerChanged,
                WorldRefusal::ReactiveForeignOwner => Cause::WorldReactiveOwner,
                WorldRefusal::ReactiveCoordinatorChanged => Cause::WorldReactiveChanged,
                WorldRefusal::AmbiguousBinding => Cause::WorldBinding,
            },
            None,
        ),
        DerivationCause::Reservation(_) => (Cause::Reservation, None),
        DerivationCause::OutputOverflow => (Cause::OutputOverflow, None),
        DerivationCause::OutputLimit => (Cause::OutputLimit, None),
        DerivationCause::OutputCapacity => (Cause::OutputCapacity, None),
    })
}

#[cfg(test)]
#[path = "tags/tests.rs"]
mod tests;
