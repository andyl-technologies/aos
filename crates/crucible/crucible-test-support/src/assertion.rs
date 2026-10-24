//! Declarative determinism gate assertions and their stable report identifiers.
//!
//! Runtime guest assertions remain engine-owned; these values describe test
//! expectations and preserve the historical `crucible-assert.v1` report domain.

/// Version tag included in layer-0 assertion identifiers.
pub const ASSERTION_VOCABULARY_VERSION: &str = "crucible-assert.v1";

/// A deterministic assertion kind represented as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssertionKind {
    /// Two canonical digests must be byte-identical.
    DigestEquality,
    /// A collection's total order must be stable.
    TotalOrderStability,
    /// A named decision stream must be stable when unrelated entities are added.
    DecisionStreamStability,
}

impl AssertionKind {
    /// Returns the stable lowercase tag for this assertion kind.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::DigestEquality => "digest-equality",
            Self::TotalOrderStability => "total-order-stability",
            Self::DecisionStreamStability => "decision-stream-stability",
        }
    }
}

/// A declarative assertion identified by kind and subject.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssertionSpec {
    /// The property being asserted.
    pub kind: AssertionKind,
    /// The stable subject path the assertion applies to.
    pub subject: String,
}

impl AssertionSpec {
    /// Builds an assertion spec.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionSpecError::EmptySubject`] when `subject` is empty,
    /// and [`AssertionSpecError::AmbiguousSubject`] when it contains the
    /// canonical identifier delimiter.
    pub fn new(
        kind: AssertionKind,
        subject: impl Into<String>,
    ) -> Result<Self, AssertionSpecError> {
        let subject = subject.into();
        match subject.as_str() {
            "" => Err(AssertionSpecError::EmptySubject),
            subject if subject.contains(':') => Err(AssertionSpecError::AmbiguousSubject),
            _ => Ok(Self { kind, subject }),
        }
    }

    /// Returns the stable identifier used by layer-0 gate reports.
    #[must_use]
    pub fn canonical_id(&self) -> String {
        format!(
            "{}:{}:{}",
            ASSERTION_VOCABULARY_VERSION,
            self.kind.tag(),
            self.subject
        )
    }
}

/// A validation error for [`AssertionSpec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssertionSpecError {
    /// Assertion subjects must be stable, non-empty paths.
    EmptySubject,
    /// Assertion subjects must not contain the canonical identifier delimiter.
    AmbiguousSubject,
}

impl std::fmt::Display for AssertionSpecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySubject => formatter.write_str("assertion subject must be non-empty"),
            Self::AmbiguousSubject => formatter.write_str("assertion subject must not contain ':'"),
        }
    }
}

impl std::error::Error for AssertionSpecError {}
