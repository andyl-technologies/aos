//! Bounded wire protocol for authenticated package-owned ability handlers.
//!
//! Generic AOS dispatch launches the exact terminal executable authenticated by
//! a selected package implementation. The executable receives one canonical
//! JSON document on standard input and emits one canonical JSON document on
//! standard output. This crate owns those shared schemas; provider crates own
//! all interpretation of desired values, realizations, and native state.

use std::collections::BTreeMap;

use aos_ability_model::{
    AbilityValue, IncarnationId, InterfaceName, LocalKey, MethodReference, MethodSemantics,
    ResourceId, ResourceLifetime, ResourceReference, RevisionId,
};
pub use aos_ability_model::{
    MAX_TRANSACTION_BLOB_BYTES, TRANSACTION_BLOB_REFERENCE_TYPE, TransactionBlobReference,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Selects the version-1 command-handler ABI on an authenticated executable.
pub const HANDLER_ABI_ARGUMENT: &str = "--aos-primitive-v1";
/// Identifies one durable command request.
pub const REQUEST_SCHEMA: &str = "aos.primitive.command-handler-request/v1";
/// Identifies one effect, reconciliation, cancellation, or compensation invocation.
pub const INVOCATION_SCHEMA: &str = "aos.primitive.command-handler-invocation/v1";
/// Identifies one effect-free native resource admission request.
pub const ADMISSION_REQUEST_SCHEMA: &str = "aos.primitive.command-handler-admission-request/v1";
/// Identifies one native resource admission response.
pub const ADMISSION_SCHEMA: &str = "aos.primitive.command-handler-admission/v1";
/// Identifies one command invocation response.
pub const RESULT_SCHEMA: &str = "aos.primitive.command-handler-result/v1";
/// Identifies runtime-bound desired, realized, and provider-native context.
pub const RESOURCE_CONTEXT_SCHEMA: &str = "aos.primitive.command-handler-resource-context/v1";
/// Domain-separates one provider-native context digest.
pub const NATIVE_CONTEXT_DIGEST_DOMAIN: &str = "aos.primitive.command-handler-context/v1";
/// Domain-separates one ordered resource-context set digest.
pub const RESOURCE_SET_DIGEST_DOMAIN: &str = "aos.primitive.command-handler-resource-set/v1";
/// Bounds one handler result independently of the child process implementation.
pub const MAX_HANDLER_RESULT_BYTES: usize = 256 * 1024;
/// Environment variable naming the invocation's authorized blob inputs.
pub const TRANSACTION_BLOB_INPUT_DIRECTORY_ENV: &str = "AOS_ABILITY_TRANSACTION_BLOB_INPUTS";
/// Environment variable naming the invocation's private blob output slots.
pub const TRANSACTION_BLOB_OUTPUT_DIRECTORY_ENV: &str = "AOS_ABILITY_TRANSACTION_BLOB_OUTPUTS";
/// Marker returned by a handler after writing one blob output slot.
pub const TRANSACTION_BLOB_OUTPUT_TYPE: &str = "aos-transaction-blob-output";

/// Computes the canonical digest of one provider-native context.
///
/// # Errors
///
/// Returns an error when the context cannot be encoded in canonical AOS JSON.
pub fn native_context_digest(context: &AbilityValue) -> anyhow::Result<Sha256Digest> {
    Sha256Digest::of_canonical(NATIVE_CONTEXT_DIGEST_DOMAIN, context)
}

/// Computes the canonical digest of one ordered resource-context set.
///
/// # Errors
///
/// Returns an error when a context is invalid, the set is not in strict
/// resource-identity order, or canonical AOS JSON encoding fails.
pub fn resource_set_digest(resources: &[ResourceContext]) -> anyhow::Result<Sha256Digest> {
    validate_resource_contexts(resources)?;
    Sha256Digest::of_canonical(RESOURCE_SET_DIGEST_DOMAIN, &resources)
}

/// Validates one admitted resource against its checked reference and bound context.
///
/// # Errors
///
/// Returns an error when the resource reference, semantic revision, or bound
/// native context disagree. The assignment identifies the terminal callable;
/// the reference identifies the controller-owned resource and may therefore
/// name a different provider and interface.
pub fn validate_resource_context(context: &ResourceContext) -> anyhow::Result<BoundNativeContext> {
    anyhow::ensure!(
        !context.reference.operations.is_empty()
            && context
                .reference
                .operations
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        "resource context operations are empty or noncanonical"
    );
    anyhow::ensure!(
        native_context_digest(&context.native_context)? == context.native_context_digest,
        "resource native-context digest does not match"
    );

    let bound: BoundNativeContext =
        serde_json::from_value(context.native_context.as_json().clone())?;
    anyhow::ensure!(
        bound.schema == RESOURCE_CONTEXT_SCHEMA,
        "unsupported bound native-context schema"
    );
    anyhow::ensure!(
        bound.resource_spec.resource == context.reference.resource
            && bound.resource_spec.kind == context.reference.interface.name
            && bound.resource_spec.lifetime == context.reference.lifetime
            && bound.resource_spec.revision == context.revision,
        "bound native context differs from the checked resource authority"
    );
    Ok(bound)
}

/// Validates a canonical, duplicate-free admitted resource set.
///
/// # Errors
///
/// Returns an error when any context is invalid or resource identities are not
/// in strict canonical order.
pub fn validate_resource_contexts(resources: &[ResourceContext]) -> anyhow::Result<()> {
    anyhow::ensure!(
        resources
            .windows(2)
            .all(|pair| pair[0].reference.resource < pair[1].reference.resource),
        "resource contexts are not in strict resource identity order"
    );
    for context in resources {
        validate_resource_context(context)?;
    }
    Ok(())
}

/// Validates the exact resource authority carried by an admission request.
///
/// # Errors
///
/// Returns an error when the selected method, target reference, or resolved
/// resource specification disagree on resource, interface, operation, or
/// lifetime identity.
pub fn validate_admission_resource(request: &AdmissionRequest) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.assignment.interface == request.method.interface,
        "admission provider assignment differs from the callable method interface"
    );
    anyhow::ensure!(
        request.target.resource == request.resource_spec.resource,
        "admission target differs from the resolved resource"
    );
    anyhow::ensure!(
        request.target.interface.name == request.resource_spec.kind,
        "admission target differs from the resolved resource kind"
    );
    anyhow::ensure!(
        request.target.lifetime == request.resource_spec.lifetime,
        "admission target differs from the resolved resource lifetime"
    );
    anyhow::ensure!(
        request
            .target
            .operations
            .binary_search(&request.method.method)
            .is_ok(),
        "admission method is outside the target reference authority"
    );
    Ok(())
}

/// Carries the exact fixed-point resource specification authenticated for use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    /// Identifies the provider-owned logical resource.
    pub resource: ResourceId,
    /// Identifies the canonical interface that owns the resource value.
    pub kind: InterfaceName,
    /// Declares the resource retention boundary.
    pub lifetime: ResourceLifetime,
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
    /// Pins the exact selected implementation and live provider incarnation.
    pub assignment: aos_ability_model::ProviderAssignment,
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
    /// Pins the exact provider implementation and live incarnation selected by
    /// the checked plan or its authenticated recovery inventory.
    pub assignment: aos_ability_model::ProviderAssignment,
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
    /// Retains every explicitly declared recovery method.
    pub recovery: RecoveryMethods,
    /// Retains the full target resource authority.
    pub target: ResourceReference,
    /// Carries resolved, method-typed inputs.
    pub inputs: AbilityValue,
    /// Carries every acquired referenced resource in canonical order.
    pub resources: Vec<ResourceContext>,
    /// Authenticates the complete ordered resource-context set.
    pub native_context_digest: Sha256Digest,
}

impl DurableRequest {
    /// Returns the exact method authorized for one invocation purpose.
    #[must_use]
    pub const fn method_for(&self, purpose: InvocationPurpose) -> Option<&MethodReference> {
        self.recovery.method_for(&self.method, purpose)
    }
}

/// Carries one bounded handler effect, recovery, or compensation call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    /// Carries [`INVOCATION_SCHEMA`].
    pub schema: String,
    /// Selects effect, recovery, or compensation behavior.
    pub purpose: InvocationPurpose,
    /// Identifies the exact method selected for this purpose.
    pub method: MethodReference,
    /// Carries the selected method's retained authority semantics.
    pub semantics: MethodSemantics,
    /// Carries the exact durable request.
    pub request: DurableRequest,
    /// Carries live bounded execution control.
    pub control: InvocationControl,
}

impl Invocation {
    /// Reports whether the selected method is bound to the durable recovery contract.
    #[must_use]
    pub fn method_is_bound(&self) -> bool {
        self.request.method_for(self.purpose) == Some(&self.method)
    }
}

/// Retains the methods authorized for operation recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMethods {
    /// Names the observation method used after an ambiguous effect.
    pub reconcile: Option<MethodReference>,
    /// Names the explicitly supported cancellation method.
    pub cancel: Option<MethodReference>,
    /// Names the explicitly supported compensation method.
    pub compensate: Option<MethodReference>,
}

impl RecoveryMethods {
    /// Returns the method authorized for one purpose around the primary effect.
    #[must_use]
    pub const fn method_for<'a>(
        &'a self,
        effect: &'a MethodReference,
        purpose: InvocationPurpose,
    ) -> Option<&'a MethodReference> {
        match purpose {
            InvocationPurpose::Effect => Some(effect),
            InvocationPurpose::Reconcile | InvocationPurpose::ReconcileCompensation => {
                self.reconcile.as_ref()
            }
            InvocationPurpose::Cancel => self.cancel.as_ref(),
            InvocationPurpose::Compensate => self.compensate.as_ref(),
        }
    }
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvocationPurpose {
    /// Performs the declared effect.
    Effect,
    /// Observes and resolves an ambiguous effect.
    Reconcile,
    /// Requests bounded cancellation without creating a missing effect.
    Cancel,
    /// Executes the method declared to compensate the primary effect.
    Compensate,
    /// Observes and resolves an ambiguous compensation effect.
    ReconcileCompensation,
}

/// Holds a bounded, strictly ordered set of supported invocation purposes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SupportedPurposes(Vec<InvocationPurpose>);

impl SupportedPurposes {
    /// Constructs a set only from strict canonical enum order.
    #[must_use]
    pub fn from_ordered(purposes: Vec<InvocationPurpose>) -> Option<Self> {
        let canonical = purposes.len() <= 5 && purposes.windows(2).all(|pair| pair[0] < pair[1]);
        canonical.then_some(Self(purposes))
    }

    /// Reports whether admission explicitly supports one invocation purpose.
    #[must_use]
    pub fn contains(&self, purpose: InvocationPurpose) -> bool {
        self.0.binary_search(&purpose).is_ok()
    }

    /// Iterates over purposes in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = InvocationPurpose> + '_ {
        self.0.iter().copied()
    }
}

impl<'de> Deserialize<'de> for SupportedPurposes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let purposes = Vec::<InvocationPurpose>::deserialize(deserializer)?;
        Self::from_ordered(purposes).ok_or_else(|| {
            serde::de::Error::custom("supported purposes are not in strict canonical order")
        })
    }
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
    /// Lists every invocation purpose this admission can execute safely.
    pub supported_purposes: SupportedPurposes,
}

impl AdmissionResult {
    /// Reports whether admission explicitly supports one invocation purpose.
    #[must_use]
    pub fn supports(&self, purpose: InvocationPurpose) -> bool {
        self.supported_purposes.contains(purpose)
    }
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

/// Reports one command-handler effect, recovery, or compensation call.
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

/// Names one private output slot written through the runtime blob transport.
///
/// Handlers may return this marker as a method output. The command adapter
/// replaces it with a [`TransactionBlobReference`] only after durably copying,
/// sizing, and hashing the slot bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionBlobOutput {
    /// Carries [`TRANSACTION_BLOB_OUTPUT_TYPE`].
    #[serde(rename = "_type")]
    pub kind: String,
    /// Selects one bounded file name inside the invocation output directory.
    pub slot: LocalKey,
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
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AbilityValue, AccessMode, InterfaceKey, InterfaceName, LocalKey, MethodReference,
        MethodSemantics, ResourceId, ResourceLifetime, RevisionId,
    };
    use aos_contract::Sha256Digest;

    use super::{
        ADMISSION_REQUEST_SCHEMA, AdmissionDisposition, AdmissionRequest, AdmissionRevision,
        BoundNativeContext, InvocationControl, InvocationDisposition, InvocationPurpose,
        NATIVE_CONTEXT_DIGEST_DOMAIN, RecoveryMethods, ResourceContext, ResourceSpec,
        SupportedPurposes, native_context_digest, validate_admission_resource,
        validate_resource_contexts,
    };

    #[test]
    fn command_vocabulary_has_stable_wire_names() {
        let purposes = [
            (InvocationPurpose::Effect, r#""effect""#),
            (InvocationPurpose::Reconcile, r#""reconcile""#),
            (InvocationPurpose::Cancel, r#""cancel""#),
            (InvocationPurpose::Compensate, r#""compensate""#),
            (
                InvocationPurpose::ReconcileCompensation,
                r#""reconcile-compensation""#,
            ),
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
    fn compensation_selects_only_declared_recovery_methods() {
        let method = |name: &str| MethodReference {
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test.handler").expect("interface is valid"),
                abi: NonZeroU32::MIN,
                descriptor: Sha256Digest::of_bytes(b"test-handler-interface"),
            },
            method: LocalKey::new(name).expect("method is valid"),
        };
        let effect = method("apply");
        let reconcile = method("observe");
        let compensate = method("remove");
        let recovery = RecoveryMethods {
            reconcile: Some(reconcile.clone()),
            cancel: None,
            compensate: Some(compensate.clone()),
        };

        assert_eq!(
            recovery.method_for(&effect, InvocationPurpose::Effect),
            Some(&effect)
        );
        assert_eq!(
            recovery.method_for(&effect, InvocationPurpose::Compensate),
            Some(&compensate)
        );
        assert_eq!(
            recovery.method_for(&effect, InvocationPurpose::ReconcileCompensation),
            Some(&reconcile)
        );
        assert_eq!(
            recovery.method_for(&effect, InvocationPurpose::Cancel),
            None
        );
    }

    #[test]
    fn admission_resource_validation_binds_kind_lifetime_and_method_authority() {
        let resource_interface = InterfaceKey {
            name: InterfaceName::new("aos.test.resource").expect("interface is valid"),
            abi: NonZeroU32::MIN,
            descriptor: Sha256Digest::of_bytes(b"test-resource-interface"),
        };
        let handler_interface = InterfaceKey {
            name: InterfaceName::new("aos.test.handler").expect("interface is valid"),
            abi: NonZeroU32::MIN,
            descriptor: Sha256Digest::of_bytes(b"test-handler-interface"),
        };
        let resource: ResourceId = serde_json::from_value(serde_json::json!({
            "provider": {
                "environment": {"authority":"test","key":"host","stage":"host"},
                "key":"provider"
            },
            "key":"resource"
        }))
        .expect("resource identity is valid");
        let assignment = serde_json::from_value(serde_json::json!({
            "provider": {
                "environment": resource.provider.environment.clone(),
                "key": "terminal-provider"
            },
            "interface": handler_interface.clone(),
            "implementation": {
                "descriptor": format!("sha256:{}", "3".repeat(64)),
                "artifact": {
                    "content": format!("sha256:{}", "4".repeat(64)),
                    "store_path": "/nix/store/00000000000000000000000000000000-provider",
                    "nar_hash": format!("sha256:{}", "5".repeat(64)),
                    "closure": format!("sha256:{}", "6".repeat(64)),
                },
                "handler": "test",
            },
            "incarnation": "test-incarnation",
        }))
        .expect("provider assignment is valid");
        let request = AdmissionRequest {
            schema: ADMISSION_REQUEST_SCHEMA.into(),
            method: MethodReference {
                interface: handler_interface,
                method: LocalKey::new("apply").expect("method is valid"),
            },
            semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
            target: aos_ability_model::ResourceReference {
                interface: resource_interface.clone(),
                resource: resource.clone(),
                operations: vec![LocalKey::new("apply").expect("operation is valid")],
                lifetime: ResourceLifetime::Instance,
            },
            assignment,
            resource_spec: ResourceSpec {
                resource,
                kind: InterfaceName::new("aos.test.resource").expect("kind is valid"),
                lifetime: ResourceLifetime::Instance,
                value: AbilityValue::new(serde_json::json!({"enabled":true}))
                    .expect("value is valid"),
                realization: AbilityValue::new(serde_json::json!({"native":"resource"}))
                    .expect("realization is valid"),
                revision: RevisionId(Sha256Digest::of_bytes(b"resource-revision")),
            },
            resources: Vec::new(),
            control: InvocationControl {
                attempt_remaining_millis: 1_000,
                recovery_remaining_millis: 1_000,
                cancelled: false,
            },
        };

        validate_admission_resource(&request)
            .expect("a terminal callable may target a controller-owned resource");

        let mut wrong_callable = request.clone();
        wrong_callable.assignment.interface = resource_interface.clone();
        assert!(validate_admission_resource(&wrong_callable).is_err());

        let mut wrong_lifetime = request.clone();
        wrong_lifetime.resource_spec.lifetime = ResourceLifetime::Persistent;
        assert!(validate_admission_resource(&wrong_lifetime).is_err());

        let mut wrong_interface = request.clone();
        wrong_interface.method.interface.name =
            InterfaceName::new("aos.test.other").expect("interface is valid");
        assert!(validate_admission_resource(&wrong_interface).is_err());

        let mut wrong_assignment = request.clone();
        wrong_assignment.assignment.interface.name =
            InterfaceName::new("aos.test.other").expect("interface is valid");
        assert!(validate_admission_resource(&wrong_assignment).is_err());

        let mut missing_method = request;
        missing_method.target.operations.clear();
        assert!(validate_admission_resource(&missing_method).is_err());
    }

    fn resource_context(key: &str) -> ResourceContext {
        let reference: aos_ability_model::ResourceReference =
            serde_json::from_value(serde_json::json!({
                "interface": {
                    "name": "aos.test.resource",
                    "abi": 1,
                    "descriptor": format!("sha256:{}", "1".repeat(64)),
                },
                "resource": {
                    "provider": {
                        "environment": {"authority":"test","key":"host","stage":"host"},
                        "key":"provider",
                    },
                    "key": key,
                },
                "operations": ["observe"],
                "lifetime": "instance",
            }))
            .expect("resource reference is valid");
        let revision = RevisionId(Sha256Digest::of_bytes(format!("revision-{key}")));
        let native_context = AbilityValue::new(
            serde_json::to_value(BoundNativeContext {
                schema: super::RESOURCE_CONTEXT_SCHEMA.into(),
                resource_spec: ResourceSpec {
                    resource: reference.resource.clone(),
                    kind: reference.interface.name.clone(),
                    lifetime: reference.lifetime,
                    value: AbilityValue::new(serde_json::json!({"enabled":true}))
                        .expect("value is valid"),
                    realization: AbilityValue::new(serde_json::json!({"path":"/run/test"}))
                        .expect("realization is valid"),
                    revision,
                },
                provider_context: AbilityValue::new(serde_json::json!({"present":true}))
                    .expect("provider context is valid"),
            })
            .expect("bound context serializes"),
        )
        .expect("bound context is valid");
        ResourceContext {
            assignment: serde_json::from_value(serde_json::json!({
                "provider": {
                    "environment": reference.resource.provider.environment,
                    "key": "terminal-provider"
                },
                "interface": {
                    "name": "aos.test.handler",
                    "abi": 1,
                    "descriptor": format!("sha256:{}", "2".repeat(64)),
                },
                "implementation": {
                    "descriptor": format!("sha256:{}", "3".repeat(64)),
                    "artifact": {
                        "content": format!("sha256:{}", "4".repeat(64)),
                        "store_path": "/nix/store/00000000000000000000000000000000-provider",
                        "nar_hash": format!("sha256:{}", "5".repeat(64)),
                        "closure": format!("sha256:{}", "6".repeat(64)),
                    },
                    "handler": "test",
                },
                "incarnation": "test-incarnation",
            }))
            .expect("assignment is valid"),
            reference,
            revision,
            observation: AbilityValue::new(serde_json::json!({"state":"ready"}))
                .expect("observation is valid"),
            native_context_digest: native_context_digest(&native_context)
                .expect("context digest computes"),
            native_context,
        }
    }

    #[test]
    fn resource_context_validation_rejects_drift_and_noncanonical_sets() {
        let first = resource_context("first");
        let second = resource_context("second");
        validate_resource_contexts(&[first.clone(), second.clone()])
            .expect("matching canonical contexts are accepted");

        let mut wrong_revision = first.clone();
        wrong_revision.revision = RevisionId(Sha256Digest::of_bytes(b"wrong-revision"));
        assert!(validate_resource_contexts(&[wrong_revision]).is_err());

        let mut wrong_resource = first.clone();
        wrong_resource.reference.resource.key =
            LocalKey::new("other-resource").expect("resource key is valid");
        assert!(validate_resource_contexts(&[wrong_resource]).is_err());

        assert!(validate_resource_contexts(&[first.clone(), first.clone()]).is_err());
        assert!(validate_resource_contexts(&[second, first]).is_err());
    }

    #[test]
    fn supported_purposes_reject_duplicates_and_noncanonical_order() {
        assert!(serde_json::from_str::<SupportedPurposes>(r#"["effect","effect"]"#).is_err());
        assert!(serde_json::from_str::<SupportedPurposes>(r#"["cancel","effect"]"#).is_err());

        let purposes = SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
            InvocationPurpose::Compensate,
            InvocationPurpose::ReconcileCompensation,
        ])
        .expect("canonical purpose order is accepted");
        assert_eq!(
            serde_json::to_string(&purposes).expect("purpose set serializes"),
            r#"["effect","reconcile","cancel","compensate","reconcile-compensation"]"#
        );
    }

    #[test]
    fn native_context_digest_uses_the_shared_domain() {
        let context = aos_ability_model::AbilityValue::new(serde_json::json!({
            "schema": "aos.test.native-context/v1",
            "identity": "resource",
        }))
        .expect("context is canonical");

        assert_eq!(
            native_context_digest(&context).expect("context digest computes"),
            Sha256Digest::of_canonical(NATIVE_CONTEXT_DIGEST_DOMAIN, &context)
                .expect("reference digest computes")
        );
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
