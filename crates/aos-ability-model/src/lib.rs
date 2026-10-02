//! Portable module types and realized artifact-consumption evidence.
//!
//! This crate contains only closed versioned, serializable data and
//! invariant-bearing identifiers. It performs no package lookup, Nix
//! evaluation, resource acquisition, or runtime effects.
//!
//! [`option`] and [`schema`] define the native module type vocabulary;
//! [`value`] and [`identity`] preserve bounded literals and immutable artifact
//! identities. [`artifact_consumption`] uses the independent canonical evidence
//! codec in [`document`]. [`transaction_blob`] defines bounded durable content
//! references, while [`limits`] and [`diagnostic`] carry shared admission rules.

#![forbid(unsafe_code)]

pub mod artifact_consumption;
pub mod diagnostic;
pub mod document;
pub mod identity;
pub mod limits;
pub mod option;
pub mod schema;
pub mod transaction_blob;
pub mod value;

pub use artifact_consumption::{
    ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA, ArtifactConsumptionContract,
    ArtifactConsumptionEvidenceDocument, ArtifactConsumptionMechanism,
    ArtifactConsumptionObservation, ArtifactConsumptionPlatforms, ArtifactFileEvidence,
    ArtifactRetentionRequirement, BUILD_TOOL_EXECUTION_FEATURE, ELF_STARTUP_LINKAGE_FEATURE,
    ElfSearchPathKind, ElfStartupLinkageContract, ElfStartupLinkageObservation, ElfSymbolVersion,
    HELPER_EXECUTION_FEATURE, IMMUTABLE_DATA_INPUT_FEATURE, ObservedPathConsumptionContract,
    ObservedPathConsumptionObservation, RUNTIME_PLUGIN_LOAD_FEATURE,
};
pub use diagnostic::DiagnosticCode;
pub use document::{RequiredFeature, VersionedDocument, decode_canonical, encode_canonical};
pub use identity::{LocalKey, RelativePath, TransactionId};
pub use limits::{ABILITY_LIMITS_V1, LimitProfile, MAX_SAFE_INTEGER};
pub use option::{OptionEnumValue, OptionType, OptionVisibility};
pub use schema::*;
pub use transaction_blob::*;
pub use value::*;
