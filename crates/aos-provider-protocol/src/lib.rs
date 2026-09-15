//! Bounded wire protocol for authenticated package-owned ability handlers.
//!
//! Generic AOS dispatch launches the exact terminal executable authenticated by
//! a selected package implementation. The executable receives one canonical
//! JSON document on standard input and emits one canonical JSON document on
//! standard output. This crate owns those shared schemas; provider crates own
//! all interpretation of desired values, realizations, and native state.

use std::collections::BTreeMap;

use aos_ability_model::{
    AbilityValue, IncarnationId, LocalKey, MethodReference, MethodSemantics, ResourceId,
    ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Selects the version-1 command-handler ABI on an authenticated executable.
pub const HANDLER_ABI_ARGUMENT: &str = "--aos-primitive-v1";
/// Identifies one durable command request.
pub const REQUEST_SCHEMA: &str = "aos.primitive.command-handler-request/v1";
/// Identifies one effect, reconciliation, or cancellation invocation.
pub const INVOCATION_SCHEMA: &str = "aos.primitive.command-handler-invocation/v1";
/// Identifies one effect-free native resource admission request.
pub const ADMISSION_REQUEST_SCHEMA: &str = "aos.primitive.command-handler-admission-request/v1";
/// Identifies one native resource admission response.
pub const ADMISSION_SCHEMA: &str = "aos.primitive.command-handler-admission/v1";
/// Identifies one command invocation response.
pub const RESULT_SCHEMA: &str = "aos.primitive.command-handler-result/v1";
/// Identifies runtime-bound desired, realized, and provider-native context.
pub const RESOURCE_CONTEXT_SCHEMA: &str = "aos.primitive.command-handler-resource-context/v1";
/// Bounds one handler result independently of the child process implementation.
pub const MAX_HANDLER_RESULT_BYTES: usize = 256 * 1024;

/// Carries the exact fixed-point resource specification authenticated for use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    /// Identifies the provider-owned logical resource.
    pub resource: ResourceId,
    /// Carries the provider-neutral desired value.
    pub value: AbilityValue,
    /// Carries the selected provider's checked backend realization.
    pub realization: AbilityValue,
    /// Identifies the semantic desired content.
    pub revision: RevisionId,
}

/// Carries one admitted resource and its complete checked authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContext {
    /// Retains the full checked reference and its operation/lifetime authority.
    pub reference: ResourceReference,
    /// Identifies the desired semantic resource content.
    pub revision: RevisionId,
    /// Carries fresh method-typed admission observation evidence.
    pub observation: AbilityValue,
    /// Carries runtime-bound resource specification and provider context.
    pub native_context: AbilityValue,
    /// Authenticates the exact native-context value.
    pub native_context_digest: Sha256Digest,
}

/// Binds a fixed-point resource specification to provider-native observations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundNativeContext {
    /// Carries [`RESOURCE_CONTEXT_SCHEMA`].
    pub schema: String,
    /// Retains the exact checked desired and realized resource.
    pub resource_spec: ResourceSpec,
    /// Carries the provider-owned, effect-free native observation context.
    pub provider_context: AbilityValue,
}

/// Carries one effect-free admission probe and all referenced resource context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    /// Carries [`ADMISSION_REQUEST_SCHEMA`].
    pub schema: String,
    /// Identifies the exact selected interface method.
    pub method: MethodReference,
    /// Carries its retained provider-neutral authority semantics.
    pub semantics: MethodSemantics,
    /// Retains the full target resource authority.
    pub target: ResourceReference,
    /// Carries the exact resource being admitted.
    pub resource_spec: ResourceSpec,
    /// Carries every transitively referenced resource context in canonical order.
    pub resources: Vec<ResourceContext>,
    /// Bounds the effect-free probe.
    pub control: InvocationControl,
}

/// Carries the durable checked request persisted before an external effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRequest {
    /// Carries [`REQUEST_SCHEMA`].
    pub schema: String,
    /// Identifies the exact selected interface method.
    pub method: MethodReference,
    /// Carries its retained provider-neutral authority semantics.
    pub semantics: MethodSemantics,
    /// Retains the full target resource authority.
    pub target: ResourceReference,
    /// Carries resolved, method-typed inputs.
    pub inputs: AbilityValue,
    /// Carries every acquired referenced resource in canonical order.
    pub resources: Vec<ResourceContext>,
    /// Authenticates the complete ordered resource-context set.
    pub native_context_digest: Sha256Digest,
}

/// Carries one bounded handler effect, reconciliation, or cancellation call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    /// Carries [`INVOCATION_SCHEMA`].
    pub schema: String,
    /// Selects effect, reconciliation, or cancellation behavior.
    pub purpose: InvocationPurpose,
    /// Carries the exact durable request.
    pub request: DurableRequest,
    /// Carries live bounded execution control.
    pub control: InvocationControl,
}

/// Supplies live deadlines and cancellation state to one handler call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationControl {
    /// Bounds the current call.
    pub attempt_remaining_millis: u64,
    /// Bounds all remaining recovery work.
    pub recovery_remaining_millis: u64,
    /// Reports whether cancellation has already been requested.
    pub cancelled: bool,
}

/// Selects the externally visible purpose of one command-handler invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvocationPurpose {
    /// Performs the declared effect.
    Effect,
    /// Observes and resolves an ambiguous effect.
    Reconcile,
    /// Requests bounded cancellation without creating a missing effect.
    Cancel,
}

/// Reports an effect-free native resource admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionResult {
    /// Carries [`ADMISSION_SCHEMA`].
    pub schema: String,
    /// Reports whether the provider accepted the resource.
    pub disposition: AdmissionDisposition,
    /// Reports the fresh semantic native revision.
    pub revision: AdmissionRevision,
    /// Pins the current native provider or resource incarnation when present.
    pub incarnation: Option<IncarnationId>,
    /// Carries fresh method-typed observation evidence.
    pub observation: AbilityValue,
    /// Carries provider-owned native identity and drift context.
    pub native_context: AbilityValue,
}

/// Reports whether an admission probe accepted a resource.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionDisposition {
    /// Admits the exact checked resource and context.
    Admitted,
    /// Rejects the resource before any effect.
    Rejected,
}

/// Reports the fresh semantic revision observed during admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum AdmissionRevision {
    /// Reports that the resource is absent.
    Absent,
    /// Reports the exact present semantic revision.
    Present {
        /// Identifies the observed semantic content.
        revision: RevisionId,
    },
    /// Reports that bounded observation could not establish a revision.
    Unknown,
}

/// Reports one command-handler effect, reconciliation, or cancellation call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResult {
    /// Carries [`RESULT_SCHEMA`].
    pub schema: String,
    /// Reports the runtime disposition.
    pub disposition: InvocationDisposition,
    /// Carries method-typed completion or observation evidence.
    pub evidence: AbilityValue,
    /// Carries successful named method outputs.
    pub outputs: BTreeMap<LocalKey, AbilityValue>,
    /// Echoes the complete checked resource-context digest.
    pub native_context_digest: Sha256Digest,
}

/// Reports the legal command-handler disposition vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvocationDisposition {
    /// Establishes the declared completion condition.
    Completed,
    /// Establishes that no external effect occurred.
    RejectedBeforeEffect,
    /// Reports that an effect may have occurred.
    Indeterminate,
    /// Proves that a new effect attempt is safe.
    SafeToRetry,
    /// Reports that bounded reconciliation remains inconclusive.
    StillIndeterminate,
    /// Requires explicit operator intervention.
    InterventionRequired,
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionDisposition, AdmissionRevision, InvocationDisposition, InvocationPurpose,
    };

    #[test]
    fn command_vocabulary_has_stable_wire_names() {
        let purposes = [
            (InvocationPurpose::Effect, r#""effect""#),
            (InvocationPurpose::Reconcile, r#""reconcile""#),
            (InvocationPurpose::Cancel, r#""cancel""#),
        ];
        let dispositions = [
            (InvocationDisposition::Completed, r#""completed""#),
            (
                InvocationDisposition::RejectedBeforeEffect,
                r#""rejected-before-effect""#,
            ),
            (InvocationDisposition::Indeterminate, r#""indeterminate""#),
            (InvocationDisposition::SafeToRetry, r#""safe-to-retry""#),
            (
                InvocationDisposition::StillIndeterminate,
                r#""still-indeterminate""#,
            ),
            (
                InvocationDisposition::InterventionRequired,
                r#""intervention-required""#,
            ),
        ];

        for (purpose, expected) in purposes {
            assert_eq!(serde_json::to_string(&purpose).unwrap(), expected);
        }
        for (disposition, expected) in dispositions {
            assert_eq!(serde_json::to_string(&disposition).unwrap(), expected);
        }
    }

    #[test]
    fn admission_vocabulary_has_stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&AdmissionDisposition::Admitted).unwrap(),
            r#""admitted""#
        );
        assert_eq!(
            serde_json::to_string(&AdmissionDisposition::Rejected).unwrap(),
            r#""rejected""#
        );
        assert_eq!(
            serde_json::to_string(&AdmissionRevision::Absent).unwrap(),
            r#"{"state":"absent"}"#
        );
        assert_eq!(
            serde_json::to_string(&AdmissionRevision::Unknown).unwrap(),
            r#"{"state":"unknown"}"#
        );
    }
}
