//! Errors raised by the strict public fault-signal authoring projection.

use std::error::Error;
use std::fmt;

use super::super::*;

/// Failure to project or admit the public fault-signal authoring grammar.
#[derive(Debug)]
pub(crate) enum FaultSignalAuthoringError {
    /// Public TOML cannot encode multiple independently bounded graphs.
    MultiplePrograms {
        /// Submitted program count.
        actual: usize,
    },
    /// The fault-signal semantic version is not implemented.
    Version {
        /// Exact implemented version.
        expected: u16,
        /// Authored version.
        actual: u16,
    },
    /// Bindings were authored without a signal graph.
    BindingsWithoutSignals,
    /// A required field was omitted.
    MissingField(&'static str),
    /// A field had the wrong TOML representation.
    InvalidField(&'static str),
    /// A field is not legal in this selected variant.
    UnexpectedField(&'static str),
    /// A selected table contains an unknown field.
    UnknownField {
        /// Owning table.
        context: &'static str,
        /// Unknown field name.
        field: String,
    },
    /// A closed variant name is unknown.
    UnknownKind(String),
    /// A value-type spelling is unknown or malformed.
    InvalidValueType(String),
    /// A tagged value was not a table.
    ExpectedTable(&'static str),
    /// Flattening would overwrite a common field.
    DuplicateProjectedField(String),
    /// `signal` and `signals` were both supplied.
    ConflictingSignalFields,
    /// A selector did not reconstruct a valid homogeneous target set.
    InvalidSelector,
    /// A closed enum did not serialize as its canonical string.
    InvalidEnum,
    /// A byte or event payload was not canonical lowercase even-length hex.
    InvalidHex,
    /// A source coordinate does not belong to its node's declared domain.
    CoordinateDomainMismatch,
    /// A public authoring collection exceeds its configured or hard ceiling.
    CollectionLimit {
        /// Field containing the collection.
        field: &'static str,
        /// Submitted element count.
        actual: usize,
        /// Effective ceiling.
        limit: usize,
    },
    /// An authored selector does not resolve to a declared world target.
    UnknownWorldTarget {
        /// Authored selector kind.
        kind: String,
        /// Authored target identity.
        id: String,
    },
    /// A mobile endpoint names no exported trajectory signal.
    MissingTrajectorySignal {
        /// Mobile endpoint declaration.
        endpoint: String,
        /// Missing exported signal.
        signal: String,
    },
    /// A mobile trajectory is not virtual-time `vector3:i64` millimetres.
    InvalidTrajectorySignal {
        /// Mobile endpoint declaration.
        endpoint: String,
        /// Invalid exported signal.
        signal: String,
    },
    /// A time-driven binding requests a boundary not representable by World icount.
    RuntimeWakeupAlignment {
        /// Binding whose cadence or residence is invalid.
        binding: String,
        /// Authored virtual-time interval.
        nanos: u64,
        /// Largest fixed icount shift used by a World VM.
        icount_shift: u8,
    },
    /// A network effect refers to an absent or wrong-typed policy declaration.
    InvalidNetworkPolicyReference {
        /// Binding containing the reference.
        binding: String,
        /// Rejected policy identity.
        reference: String,
        /// Effect parameter containing the reference.
        field: &'static str,
        /// Accepted policy class or classes.
        expected: String,
        /// Actual class, or none when the declaration is absent.
        actual: Option<&'static str>,
    },
    /// A storage or 9p effect refers to an absent or wrong-typed policy declaration.
    InvalidStoragePolicyReference {
        /// Binding containing the reference.
        binding: String,
        /// Rejected policy identity.
        reference: String,
        /// Effect parameter containing the reference.
        field: &'static str,
        /// Accepted policy class or classes.
        expected: String,
        /// Actual class, or none when the declaration is absent.
        actual: Option<&'static str>,
    },
    /// A shared-medium binding disagrees with its World medium contract.
    InvalidNetworkMediumContract {
        /// Binding containing the shared-medium effect.
        binding: String,
        /// Stable diagnostic for the mismatched contract component.
        field: &'static str,
    },
    /// A network service effect was not bound to its exact physical input schema.
    InvalidNetworkServiceInputs {
        /// Binding containing the service mapping.
        binding: String,
        /// Network effect requiring the inputs.
        effect: &'static str,
        /// Required ordered named physical inputs.
        expected: Vec<ServiceProfileInput>,
        /// Admitted inputs, or none for a non-service mapping.
        actual: Option<Vec<ServiceProfileInput>>,
    },
    /// A telemetry or coordinate adapter is outside the executable registry.
    UnsupportedAdapter(String),
    /// A telemetry field is absent from the selected adapter registry.
    UnknownTelemetryField {
        /// Executable adapter name.
        adapter: String,
        /// Rejected field name.
        field: String,
    },
    /// Two authored signal rows reuse one graph identity.
    DuplicateSignalId(String),
    /// An operator or binding references an absent signal row.
    UnknownSignal(String),
    /// JSON/TOML exact-integer conversion failed.
    Toml(FaultSignalTomlWireError),
    /// Plan-owned resource validation failed.
    ResourceLimit(FaultResourceLimitError),
    /// An identity failed its closed grammar.
    Contract(FaultContractError),
    /// Signal graph admission failed.
    Program(SignalProgramError),
    /// Binding wire admission failed.
    Wire(FaultSignalWireError),
    /// Complete fault plan admission failed.
    Plan(FaultSignalPlanError),
}

impl fmt::Display for FaultSignalAuthoringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fault signal authoring admission failed: ")?;
        match self {
            Self::MultiplePrograms { actual } => write!(
                formatter,
                "public TOML requires one flat signal graph, found {actual} programs"
            ),
            Self::Version { expected, actual } => write!(
                formatter,
                "semantic version {actual} does not match implemented version {expected}"
            ),
            Self::BindingsWithoutSignals => formatter.write_str("bindings require signals"),
            Self::MissingField(field) => write!(formatter, "missing required field `{field}`"),
            Self::InvalidField(field) => write!(formatter, "invalid field `{field}`"),
            Self::UnexpectedField(field) => write!(formatter, "unexpected field `{field}`"),
            Self::UnknownField { context, field } => {
                write!(formatter, "unknown {context} field `{field}`")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown closed kind `{kind}`"),
            Self::InvalidValueType(value) => write!(formatter, "invalid value type `{value}`"),
            Self::ExpectedTable(context) => write!(formatter, "{context} must be a table"),
            Self::DuplicateProjectedField(field) => {
                write!(
                    formatter,
                    "projected field `{field}` conflicts with a common field"
                )
            }
            Self::ConflictingSignalFields => {
                formatter.write_str("`signal` and `signals` are mutually exclusive")
            }
            Self::InvalidSelector => formatter.write_str("selector target set is invalid"),
            Self::InvalidEnum => formatter.write_str("closed enum is not a canonical string"),
            Self::InvalidHex => formatter.write_str("payload is not canonical lowercase hex"),
            Self::CoordinateDomainMismatch => {
                formatter.write_str("source coordinate does not match the signal domain")
            }
            Self::CollectionLimit {
                field,
                actual,
                limit,
            } => write!(
                formatter,
                "collection `{field}` contains {actual} items, limit is {limit}"
            ),
            Self::UnknownWorldTarget { kind, id } => {
                write!(
                    formatter,
                    "{kind} selector target `{id}` is absent from the world"
                )
            }
            Self::MissingTrajectorySignal { endpoint, signal } => write!(
                formatter,
                "mobile endpoint `{endpoint}` names absent exported trajectory `{signal}`"
            ),
            Self::InvalidTrajectorySignal { endpoint, signal } => write!(
                formatter,
                "mobile endpoint `{endpoint}` trajectory `{signal}` must be virtual-time vector3:i64 millimetres at scale zero"
            ),
            Self::RuntimeWakeupAlignment {
                binding,
                nanos,
                icount_shift,
            } => write!(
                formatter,
                "binding `{binding}` interval {nanos}ns is not representable at World icount shift {icount_shift}"
            ),
            Self::InvalidNetworkPolicyReference {
                binding,
                reference,
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "binding `{binding}` field `{field}` references network policy `{reference}` with class {}, expected {expected}",
                actual.unwrap_or("absent")
            ),
            Self::InvalidStoragePolicyReference {
                binding,
                reference,
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "binding `{binding}` field `{field}` references storage policy `{reference}` with class {}, expected {expected}",
                actual.unwrap_or("absent")
            ),
            Self::InvalidNetworkMediumContract { binding, field } => write!(
                formatter,
                "binding `{binding}` disagrees with its World shared-medium `{field}` contract"
            ),
            Self::InvalidNetworkServiceInputs {
                binding,
                effect,
                expected,
                actual,
            } => write!(
                formatter,
                "binding `{binding}` maps `{effect}` with physical inputs {actual:?}, expected {expected:?}"
            ),
            Self::UnsupportedAdapter(adapter) => {
                write!(
                    formatter,
                    "adapter `{adapter}` is not executable in schema v2"
                )
            }
            Self::UnknownTelemetryField { adapter, field } => {
                write!(
                    formatter,
                    "telemetry field `{field}` is unknown for `{adapter}`"
                )
            }
            Self::DuplicateSignalId(id) => write!(formatter, "duplicate signal ID `{id}`"),
            Self::UnknownSignal(id) => write!(formatter, "unknown signal ID `{id}`"),
            Self::Toml(error) => error.fmt(formatter),
            Self::ResourceLimit(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Program(error) => error.fmt(formatter),
            Self::Wire(error) => error.fmt(formatter),
            Self::Plan(error) => error.fmt(formatter),
        }
    }
}

impl Error for FaultSignalAuthoringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::ResourceLimit(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Program(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Plan(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FaultSignalTomlWireError> for FaultSignalAuthoringError {
    fn from(value: FaultSignalTomlWireError) -> Self {
        Self::Toml(value)
    }
}

impl From<FaultContractError> for FaultSignalAuthoringError {
    fn from(value: FaultContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<SignalProgramError> for FaultSignalAuthoringError {
    fn from(value: SignalProgramError) -> Self {
        Self::Program(value)
    }
}
