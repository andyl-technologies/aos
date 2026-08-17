//! Errors and representation checks for reviewed native-call boundaries.

use std::{error::Error, fmt};

use ratchet_value::value::{
    Value, ValueError,
    compressed::{CompressedValueError, CompressedValueKind},
    tag::{TaggedValueKind, TaggedValueWordError},
};

use super::JitCraneliftModuleSetupError;
use crate::{
    artifact::{JitClifArtifactKind, JitValueAbi},
    module::JitModuleArtifactMetadata,
};

/// A failure while calling finalized native thunk code.
#[derive(Debug)]
pub enum JitCraneliftNativeCallError {
    /// The current host does not have a reviewed native `Value` calling convention.
    UnsupportedNativeValueAbi {
        /// Human-readable reason this host is not enabled for native thunk calls.
        message: &'static str,
    },
    /// The artifact could not be lowered, finalized, or installed into callable code metadata.
    FinalizeArtifact {
        /// The underlying Cranelift setup error.
        source: JitCraneliftModuleSetupError,
    },
    /// The finalized artifact is not a compiled thunk body.
    UnsupportedArtifactKind {
        /// The lowered artifact kind carried by finalization metadata.
        kind: JitClifArtifactKind,
    },
    /// The artifact's by-value representation does not match the call boundary.
    UnsupportedArtifactValueAbi {
        /// The representation required by the selected native entry type.
        expected: JitValueAbi,
        /// The representation recorded when the artifact was lowered.
        actual: JitValueAbi,
    },
    /// A Candidate-B call returned a malformed tagged word.
    InvalidCandidateBReturnValue {
        /// The stable module symbol that was called.
        symbol_name: String,
        /// The malformed raw one-word return.
        word: u64,
        /// The underlying tagged-value layout error.
        source: TaggedValueWordError,
    },
    /// The receiving evaluator could not decode a Candidate-B return word.
    UnsupportedCandidateBReturnKind {
        /// The tagged kind that failed context-owned decoding.
        kind: TaggedValueKind,
    },
    /// The native call returned valid-tag bits that violate the runtime value payload layout.
    InvalidReturnValue {
        /// The stable module symbol that was called.
        symbol_name: String,
        /// The valid-tag value whose payload failed validation.
        value: Value,
        /// The underlying value-layout error.
        source: ValueError,
    },
    /// A Candidate-C call returned a malformed compressed word.
    InvalidCandidateCReturnValue {
        /// The stable module symbol that was called.
        symbol_name: String,
        /// The malformed raw one-word return.
        word: u64,
        /// The underlying compressed-value layout error.
        source: CompressedValueError,
    },
    /// The receiving evaluator could not decode a Candidate-C return word.
    UnsupportedCandidateCReturnKind {
        /// The compressed kind that failed context-owned decoding.
        kind: CompressedValueKind,
    },
}

impl fmt::Display for JitCraneliftNativeCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedNativeValueAbi { message } => write!(formatter, "{message}"),
            Self::FinalizeArtifact { source } => write!(formatter, "{source}"),
            Self::UnsupportedArtifactKind { kind } => write!(
                formatter,
                "artifact kind {kind:?} is not callable as a thunk body"
            ),
            Self::UnsupportedArtifactValueAbi { expected, actual } => write!(
                formatter,
                "artifact value ABI {actual:?} is not callable through the {expected:?} boundary"
            ),
            Self::InvalidCandidateBReturnValue {
                symbol_name,
                source,
                ..
            } => write!(
                formatter,
                "native Candidate-B thunk {symbol_name:?} returned an invalid tagged value: {source}"
            ),
            Self::UnsupportedCandidateBReturnKind { kind } => write!(
                formatter,
                "Candidate-B return kind {kind:?} is not owned by the receiving evaluator"
            ),
            Self::InvalidReturnValue {
                symbol_name,
                source,
                ..
            } => write!(
                formatter,
                "native thunk {symbol_name:?} returned an invalid runtime value: {source}"
            ),
            Self::InvalidCandidateCReturnValue {
                symbol_name,
                source,
                ..
            } => write!(
                formatter,
                "native Candidate-C thunk {symbol_name:?} returned an invalid compressed value: {source}"
            ),
            Self::UnsupportedCandidateCReturnKind { kind } => write!(
                formatter,
                "Candidate-C return kind {kind:?} is not owned by the receiving evaluator"
            ),
        }
    }
}

impl Error for JitCraneliftNativeCallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnsupportedNativeValueAbi { .. }
            | Self::UnsupportedArtifactKind { .. }
            | Self::UnsupportedArtifactValueAbi { .. }
            | Self::UnsupportedCandidateBReturnKind { .. }
            | Self::UnsupportedCandidateCReturnKind { .. } => None,
            Self::FinalizeArtifact { source } => Some(source),
            Self::InvalidCandidateBReturnValue { source, .. } => Some(source),
            Self::InvalidReturnValue { source, .. } => Some(source),
            Self::InvalidCandidateCReturnValue { source, .. } => Some(source),
        }
    }
}

pub(super) fn require_artifact_value_abi(
    artifact: &JitModuleArtifactMetadata,
    expected: JitValueAbi,
) -> Result<(), JitCraneliftNativeCallError> {
    let actual = artifact.value_abi();
    if actual != expected {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactValueAbi { expected, actual });
    }
    Ok(())
}
