//! Portable data contracts for AOS abilities and structured effects.
//!
//! This crate contains only closed versioned, serializable data and
//! invariant-bearing identifiers. It performs no package lookup, Nix
//! evaluation, resource acquisition, or runtime effects.
//!
//! # Module map
//!
//! - [`document`] owns the closed versioned document envelopes.
//! - [`identity`] defines stable logical identities and scoped references.
//! - [`interface`] defines public interfaces and provider implementations.
//! - [`plan`] defines bindings, resources, and finite operation graphs.
//! - [`schema`] defines the portable value-schema vocabulary.
//! - [`value`] defines typed values carried by plans.

#![forbid(unsafe_code)]

pub mod diagnostic;
pub mod document;
pub mod identity;
pub mod interface;
pub mod limits;
pub mod plan;
pub mod schema;
pub mod value;

pub use diagnostic::{Diagnostic, DiagnosticClass, DiagnosticCode, DiagnosticPhase};
pub use document::{
    AbilityActivationMode, AggregateOutput, BindingPlanDocument, BranchSelection,
    DesiredStateDocument, EffectPlanDocument, EnvironmentDocument, ExecutionDocument,
    InterfaceDocument, MergeRecord, PackageDocument, RequiredFeature, SkippedOperationRecord,
    VersionedDocument, decode_canonical, encode_canonical,
};
pub use identity::{
    AggregateId, EnvironmentId, ExecutionStage, IncarnationId, InstanceId, InterfaceKey,
    InterfaceName, LocalKey, OperationId, PlanId, RequestId, ResourceId, RevisionId, ScopePath,
    ScopedOperationKey, TransactionId,
};
pub use interface::*;
pub use limits::{ABILITY_LIMITS_V1, LimitProfile};
pub use plan::*;
pub use schema::*;
pub use value::*;
