//! Protected operator-only controller observations.
//!
//! These types intentionally implement neither `Serialize` nor revealing
//! `Debug`. Node-local names and kernel identifiers remain available only
//! through explicit accessors on the operator projection.

use std::fmt;

/// Maximum protected diagnostic rows carried by one resource.
pub const MAXIMUM_OPERATOR_DIAGNOSTICS: usize = 256;
/// Maximum UTF-8 bytes in one protected node-local name.
pub const MAXIMUM_OPERATOR_LOCAL_NAME_BYTES: usize = 4 * 1024;

/// Reports invalid protected diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidOperatorDiagnostics {
    /// A local name is empty, oversized, or contains an ASCII control byte.
    #[error("operator diagnostic local name is invalid")]
    InvalidLocalName,
    /// A numeric or opaque identifier uses its zero sentinel.
    #[error("operator diagnostic identifier is unspecified")]
    Unspecified,
    /// The diagnostic value is not valid for its closed diagnostic family.
    #[error("operator diagnostic value has the wrong type")]
    TypeMismatch,
    /// Diagnostic rows are oversized, unordered, or duplicated.
    #[error("operator diagnostics must be a bounded canonical set")]
    NotCanonical,
}

/// Identifies one protected node-local diagnostic family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperatorDiagnosticKindV1 {
    /// A transient service-manager unit name.
    TransientUnit,
    /// A service-manager invocation identity.
    Invocation,
    /// A node-local cgroup path.
    Cgroup,
    /// A payload process identifier.
    PayloadProcess,
    /// A namespace inode identifier.
    Namespace,
    /// A mount unique identifier.
    Mount,
    /// A FUSE connection identifier.
    FuseConnection,
    /// A node-local dataset name.
    Dataset,
    /// A backend storage-snapshot name.
    StorageSnapshot,
    /// A storage transaction identity.
    StorageTransaction,
    /// A worker process identifier.
    WorkerProcess,
    /// A backend-local step name.
    BackendStep,
}

/// Stores a bounded protected node-local textual identifier.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperatorLocalIdentifierV1(String);

impl OperatorLocalIdentifierV1 {
    /// Constructs a protected node-local identifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOperatorDiagnostics::InvalidLocalName`] for empty,
    /// oversized, NUL-containing, or control-containing text.
    pub fn new(value: String) -> Result<Self, InvalidOperatorDiagnostics> {
        let valid = !value.is_empty()
            && value.len() <= MAXIMUM_OPERATOR_LOCAL_NAME_BYTES
            && !value.bytes().any(|byte| byte.is_ascii_control());
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidOperatorDiagnostics::InvalidLocalName)
        }
    }

    /// Returns the protected local value to an already authorized operator path.
    #[must_use]
    pub fn expose_to_operator(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperatorLocalIdentifierV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorLocalIdentifierV1")
            .field("redacted_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Stores one typed protected diagnostic value.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperatorDiagnosticValueV1 {
    /// A protected node-local textual identifier.
    LocalName(OperatorLocalIdentifierV1),
    /// A protected nonzero numeric identifier.
    Numeric(u64),
    /// A protected nonzero 128-bit identifier.
    Opaque128([u8; 16]),
}

impl fmt::Debug for OperatorDiagnosticValueV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalName(value) => value.fmt(formatter),
            Self::Numeric(_) => formatter.write_str("Numeric(<redacted>)"),
            Self::Opaque128(_) => formatter.write_str("Opaque128(<redacted>)"),
        }
    }
}

/// Stores one protected diagnostic with a closed kind/value pairing.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperatorDiagnosticV1 {
    kind: OperatorDiagnosticKindV1,
    value: OperatorDiagnosticValueV1,
}

impl OperatorDiagnosticV1 {
    /// Constructs one protected diagnostic observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOperatorDiagnostics`] for zero sentinels or a value
    /// representation not allowed by the diagnostic kind.
    pub fn new(
        kind: OperatorDiagnosticKindV1,
        value: OperatorDiagnosticValueV1,
    ) -> Result<Self, InvalidOperatorDiagnostics> {
        use OperatorDiagnosticKindV1 as K;
        use OperatorDiagnosticValueV1 as V;

        if matches!(&value, V::Numeric(0))
            || matches!(&value, V::Opaque128(identity) if *identity == [0; 16])
        {
            return Err(InvalidOperatorDiagnostics::Unspecified);
        }
        let valid = match (&kind, &value) {
            (
                K::TransientUnit | K::Cgroup | K::Dataset | K::StorageSnapshot | K::BackendStep,
                V::LocalName(_),
            ) => true,
            (
                K::PayloadProcess | K::Namespace | K::Mount | K::FuseConnection | K::WorkerProcess,
                V::Numeric(_),
            ) => true,
            (K::Invocation | K::StorageTransaction, V::Opaque128(_)) => true,
            _ => false,
        };
        if valid {
            Ok(Self { kind, value })
        } else {
            Err(InvalidOperatorDiagnostics::TypeMismatch)
        }
    }

    /// Returns the closed diagnostic family.
    #[must_use]
    pub const fn kind(&self) -> OperatorDiagnosticKindV1 {
        self.kind
    }

    /// Returns the protected value to an already authorized operator path.
    #[must_use]
    pub const fn expose_to_operator(&self) -> &OperatorDiagnosticValueV1 {
        &self.value
    }
}

impl fmt::Debug for OperatorDiagnosticV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorDiagnosticV1")
            .field("kind", &self.kind)
            .field("value", &self.value)
            .finish()
    }
}

/// Stores a bounded canonical protected diagnostic set.
#[derive(Clone, Eq, PartialEq)]
pub struct OperatorDiagnosticsV1(Vec<OperatorDiagnosticV1>);

impl OperatorDiagnosticsV1 {
    /// Constructs a protected diagnostic set.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOperatorDiagnostics::NotCanonical`] for oversized,
    /// unordered, or duplicate rows.
    pub fn new(values: Vec<OperatorDiagnosticV1>) -> Result<Self, InvalidOperatorDiagnostics> {
        if values.len() > MAXIMUM_OPERATOR_DIAGNOSTICS
            || !values.windows(2).all(|pair| pair[0] < pair[1])
        {
            Err(InvalidOperatorDiagnostics::NotCanonical)
        } else {
            Ok(Self(values))
        }
    }

    /// Returns protected rows to an already authorized operator path.
    #[must_use]
    pub fn expose_to_operator(&self) -> &[OperatorDiagnosticV1] {
        &self.0
    }
}

impl fmt::Debug for OperatorDiagnosticsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorDiagnosticsV1")
            .field("redacted_rows", &self.0.len())
            .finish_non_exhaustive()
    }
}
