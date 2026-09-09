//! Closed versioned canonical documents for the RFC-0022 format families.
//!
//! Each document uses the integer-only canonical JSON dialect from
//! `aos-contract`, carries an exact schema discriminator, and declares every
//! required semantic feature explicitly.
//!
//! An interface envelope uses this closed shape:
//!
//! ```json
//! {"interface":{"abi":1,"guarantees":[],"lifecycle":{"persistent_delete_method":null,"releases_ephemeral_on_disable":true,"retains_persistent_by_default":true,"stable_resource_identity":true},"methods":{},"name":"test.echo","outputs":{},"request":{"kind":"boolean"}},"required_features":[],"schema":"aos.ability.interface/v1"}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::num::NonZeroU32;

use aos_contract::Sha256Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::identity::{
    AggregateId, EnvironmentId, IncarnationId, InstanceId, InterfaceKey, LocalKey, RequestId,
    ResourceId, RevisionId, ScopePath, ScopedOperationKey, TransactionId,
};
use crate::interface::{
    ExportDeclaration, GuaranteeKey, InterfaceDescriptor, PackageImplementation,
    ProviderImplementationReference, RequirementDeclaration,
};
use crate::limits::{ABILITY_LIMITS_V1, LimitProfile};
use crate::plan::{
    Binding, BindingRequest, ControllerAssignment, DecisionNode, DependencyEdge,
    DeploymentObligation, MergeNode, Operation, ResourceRevision,
};
use crate::value::{AbilityValue, ArtifactReference, ValueExpression};

/// Identifies one required format semantic understood by a consumer.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequiredFeature(LocalKey);

impl RequiredFeature {
    /// Constructs a required feature using the version-1 local-key grammar.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not a valid local key.
    pub fn new(value: impl Into<String>) -> Result<Self, crate::identity::IdentityError> {
        LocalKey::new(value).map(Self)
    }

    /// Returns the serialized required-feature name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for RequiredFeature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RequiredFeature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LocalKey::deserialize(deserializer).map(Self)
    }
}

/// Reports a canonical envelope decoding or feature-negotiation failure.
#[derive(Debug, Error)]
pub enum DocumentError {
    /// The document exceeded an effective input bound.
    #[error("{label} exceeds the effective {limit} limit")]
    Limit {
        /// Names the document being processed.
        label: String,
        /// Names the exceeded limit.
        limit: &'static str,
    },
    /// The bytes were not exact canonical JSON for the closed schema.
    #[error("invalid canonical {label}")]
    Decode {
        /// Names the document being processed.
        label: String,
        /// Retains the parser or schema error chain.
        #[source]
        source: anyhow::Error,
    },
    /// The document carried another format discriminator.
    #[error("unsupported schema '{actual}', expected '{expected}'")]
    Schema {
        /// Gives the required exact discriminator.
        expected: &'static str,
        /// Gives the received discriminator.
        actual: String,
    },
    /// A required-feature set was duplicated or out of canonical order.
    #[error("required_features must be strictly sorted without duplicates")]
    RequiredFeatureOrder,
    /// The consumer does not implement a required semantic feature.
    #[error("unsupported required feature '{feature}'")]
    UnsupportedFeature {
        /// Names the unsupported semantic feature.
        feature: String,
    },
    /// The document's embedded limit profile is invalid.
    #[error("the document limit profile exceeds the version-1 ceiling or contains a zero bound")]
    InvalidLimitProfile,
}

/// Defines behavior shared by every versioned ability document envelope.
pub trait VersionedDocument: Serialize + DeserializeOwned {
    /// Gives the exact versioned schema discriminator and digest domain.
    const SCHEMA: &'static str;

    /// Returns the schema discriminator carried by this document.
    fn schema(&self) -> &str;

    /// Returns required semantics in canonical order.
    fn required_features(&self) -> &[RequiredFeature];

    /// Returns the document's effective embedded limit profile, when present.
    fn limit_profile(&self) -> Option<&LimitProfile> {
        None
    }

    /// Checks recursive in-memory structures before serde traverses them.
    ///
    /// # Errors
    ///
    /// Returns an error when a recursive schema or expression exceeds the
    /// effective structural-depth limit.
    fn validate_structure(&self, _limits: &LimitProfile) -> Result<(), DocumentError> {
        Ok(())
    }

    /// Computes the exact domain-separated identity of the canonical document.
    ///
    /// # Errors
    ///
    /// Returns an error when the document violates the canonical JSON dialect.
    fn content_digest(&self) -> Result<Sha256Digest, DocumentError> {
        Ok(Sha256Digest::separated(
            Self::SCHEMA,
            encode_canonical(self)?,
        ))
    }
}

/// Decodes one exact canonical document under explicit feature support.
///
/// # Errors
///
/// Returns an error for a size or structural bound violation, noncanonical or
/// ambiguous JSON, a closed-schema violation, a discriminator mismatch, a
/// noncanonical required-feature set, or an unsupported required feature.
pub fn decode_canonical<T>(
    bytes: &[u8],
    limits: LimitProfile,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<T, DocumentError>
where
    T: VersionedDocument,
{
    let label = T::SCHEMA;
    if !limits.is_admissible_v1() {
        return Err(DocumentError::InvalidLimitProfile);
    }
    if bytes.len() as u64 > limits.max_document_bytes {
        return Err(DocumentError::Limit {
            label: label.to_string(),
            limit: "document byte",
        });
    }

    let json_limits = aos_contract::limits::JsonLimits {
        max_bytes: bounded_usize(limits.max_document_bytes),
        max_depth: limits.max_structural_depth as usize,
        max_items: bounded_usize(limits.max_collection_items),
        max_string_bytes: bounded_usize(limits.max_string_bytes),
    };
    let document =
        json_limits
            .decode::<T>(bytes, label)
            .map_err(|source| DocumentError::Decode {
                label: label.to_string(),
                source,
            })?;

    validate_envelope(&document, supported_features)?;
    let canonical = encode_canonical(&document)?;
    if canonical != bytes {
        return Err(DocumentError::Decode {
            label: label.to_string(),
            source: anyhow::anyhow!(
                "document is not the exact canonical encoding of its closed schema"
            ),
        });
    }
    Ok(document)
}

/// Encodes one document into the exact canonical JSON dialect.
///
/// # Errors
///
/// Returns an error for a discriminator mismatch, a noncanonical feature set,
/// an invalid embedded limit profile, or a canonical encoding failure.
pub fn encode_canonical<T>(document: &T) -> Result<Vec<u8>, DocumentError>
where
    T: VersionedDocument,
{
    validate_envelope(
        document,
        &document.required_features().iter().cloned().collect(),
    )?;
    let limits = document.limit_profile().unwrap_or(&ABILITY_LIMITS_V1);
    document.validate_structure(limits)?;

    let max_bytes = limits.max_document_bytes;
    preflight_serialized_size(document, max_bytes)?;

    let bytes =
        aos_contract::canonical::to_vec(document).map_err(|source| DocumentError::Decode {
            label: T::SCHEMA.to_string(),
            source,
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(DocumentError::Limit {
            label: T::SCHEMA.to_string(),
            limit: "document byte",
        });
    }

    let json_limits = aos_contract::limits::JsonLimits {
        max_bytes: bounded_usize(limits.max_document_bytes),
        max_depth: limits.max_structural_depth as usize,
        max_items: bounded_usize(limits.max_collection_items),
        max_string_bytes: bounded_usize(limits.max_string_bytes),
    };
    json_limits
        .decode::<serde_json::Value>(&bytes, T::SCHEMA)
        .map_err(|source| DocumentError::Decode {
            label: T::SCHEMA.to_string(),
            source,
        })?;
    Ok(bytes)
}

fn preflight_serialized_size<T>(value: &T, max_bytes: u64) -> Result<(), DocumentError>
where
    T: VersionedDocument,
{
    let mut writer = BoundedWriter::new(max_bytes);
    serde_json::to_writer(&mut writer, value).map_err(|source| {
        if writer.exceeded {
            DocumentError::Limit {
                label: T::SCHEMA.to_string(),
                limit: "document byte",
            }
        } else {
            DocumentError::Decode {
                label: T::SCHEMA.to_string(),
                source: source.into(),
            }
        }
    })
}

struct BoundedWriter {
    remaining: u64,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(max_bytes: u64) -> Self {
        Self {
            remaining: max_bytes,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized document exceeds its byte limit",
            ));
        }

        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wraps one exact public interface descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceDocument {
    /// Carries `aos.ability.interface/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Contains only caller-visible interface semantics.
    pub interface: InterfaceDescriptor,
}

impl InterfaceDocument {
    /// Computes the exact key used by package and plan references.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding of this document fails.
    pub fn interface_key(&self) -> Result<InterfaceKey, DocumentError> {
        Ok(InterfaceKey {
            name: self.interface.name.clone(),
            abi: self.interface.abi,
            descriptor: self.content_digest()?,
        })
    }
}

/// Wraps one authenticated package ability manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDocument {
    /// Carries `aos.ability.package/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies the package subject without referring to its enclosing signature.
    pub package: PackageSubject,
    /// Lists retained companion artifacts in canonical digest order.
    pub artifacts: Vec<ArtifactReference>,
    /// Lists public exports in canonical name order.
    pub exports: Vec<ExportDeclaration>,
    /// Lists declarative imports in canonical alias order.
    pub requirements: Vec<RequirementDeclaration>,
    /// Maps module entry names to exact authenticated artifacts.
    pub module_entry_points: BTreeMap<LocalKey, ArtifactReference>,
    /// Contains provider-specific implementations and handler declarations.
    pub implementation: PackageImplementation,
    /// Names configuration/resource ownership roots in canonical order.
    pub ownership: Vec<ScopePath>,
}

/// Identifies the package artifacts authenticated by an enclosing release.
///
/// The enclosing signed release authenticates its association with this
/// manifest, payload, and source. The manifest does not contain the release's
/// own content digest, which would create a hash cycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSubject {
    /// Names the package.
    pub name: LocalKey,
    /// Preserves the authored package version.
    pub version: String,
    /// Identifies the exact payload artifact.
    pub payload: ArtifactReference,
    /// Identifies the exact source artifact used for the package build.
    pub source: ArtifactReference,
}

/// Identifies a target platform without consulting the evaluator host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformIdentity {
    /// Names the operating-system family.
    pub system: LocalKey,
    /// Names the target machine architecture.
    pub architecture: LocalKey,
}

/// Classifies a provider inventory entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderState {
    /// Implementation metadata is authenticated but no bootstrap is selected.
    Declared,
    /// A validated bootstrap path will establish the provider.
    Planned,
    /// A fresh assignment currently supplies the provider.
    Available,
    /// Required resources or evidence are absent.
    Unavailable,
    /// A previous assignment exists but is no longer fresh.
    Stale,
}

/// Describes one provider in an authenticated environment snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInventory {
    /// Identifies the provider instance.
    pub provider: InstanceId,
    /// Identifies its exact public interface.
    pub interface: InterfaceKey,
    /// Pins the exact implementation and executable artifact.
    pub implementation: ProviderImplementationReference,
    /// States declared, planned, available, unavailable, or stale status.
    pub state: ProviderState,
    /// Identifies the live provider assignment, when available.
    pub incarnation: Option<IncarnationId>,
    /// Names exact supplied guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
}

/// Bounds the validity of one environment observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessCondition {
    /// Identifies the provider-defined observation generation.
    pub generation: RevisionId,
    /// Gives the maximum accepted age without embedding a wall-clock reading.
    pub max_age_millis: u64,
}

/// Wraps one authenticated environment and trusted-root inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDocument {
    /// Carries `aos.ability.environment/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies the environment and execution stage.
    pub environment: EnvironmentId,
    /// Identifies the target platform.
    pub platform: PlatformIdentity,
    /// Identifies the policy revision governing admission.
    pub policy_revision: RevisionId,
    /// Lists trusted provider inventory in canonical provider order.
    pub providers: Vec<ProviderInventory>,
    /// Names environment-wide supplied guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Bounds the inventory observation's validity.
    pub freshness: FreshnessCondition,
}

/// Describes one desired deployment instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredInstance {
    /// Identifies the stable deployment-owned instance.
    pub instance: InstanceId,
    /// Identifies the exact package ability manifest.
    pub package: Sha256Digest,
    /// States explicit operator-owned enablement.
    pub enabled: bool,
}

/// Records one admitted contribution without erasing provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    /// Identifies the original consumer request.
    pub request: RequestId,
    /// Identifies the provider aggregation group.
    pub aggregate: AggregateId,
    /// Names the authorized contribution slot.
    pub slot: LocalKey,
    /// Identifies the grant that admitted this contribution.
    pub grant: LocalKey,
    /// Carries the checked contribution value.
    pub value: AbilityValue,
}

/// Wraps normalized desired state before transition planning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredStateDocument {
    /// Carries `aos.ability.desired/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies the exact target environment contract.
    pub environment: Sha256Digest,
    /// Lists desired instances in canonical identity order.
    pub instances: Vec<DesiredInstance>,
    /// Lists admitted contributions in the explicit contribution order.
    pub contributions: Vec<Contribution>,
    /// Lists expanded child requests in canonical request order.
    pub child_requests: Vec<BindingRequest>,
    /// Lists desired logical resources in canonical resource order.
    pub resources: Vec<ResourceRevision>,
    /// Maps typed aggregate outputs in canonical name order.
    pub outputs: BTreeMap<LocalKey, ValueExpression>,
    /// Assigns one controller to every desired mutable resource.
    pub controllers: Vec<ControllerAssignment>,
}

/// Wraps exact provider choices, grants, resources, and obligations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingPlanDocument {
    /// Carries `aos.ability.binding-plan/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies the normalized desired-state input.
    pub desired_state: Sha256Digest,
    /// Identifies the target environment input.
    pub environment: Sha256Digest,
    /// Identifies the exact policy revision used for every grant.
    pub policy_revision: RevisionId,
    /// Lists original and expanded requests in canonical order.
    pub requests: Vec<BindingRequest>,
    /// Lists exact provider choices and grants in canonical binding order.
    pub bindings: Vec<Binding>,
    /// Lists logical resources in canonical identity order.
    pub resources: Vec<ResourceRevision>,
    /// Lists unresolved deployment inputs in canonical key order.
    pub obligations: Vec<DeploymentObligation>,
}

/// Wraps a finite typed effect graph for one exact binding plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPlanDocument {
    /// Carries `aos.ability.effect-plan/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Publishes the effective bounded plan profile.
    pub limits: LimitProfile,
    /// Identifies the exact binding plan input.
    pub binding_plan: Sha256Digest,
    /// Lists admitted current resource revisions in canonical resource order.
    pub current_revisions: Vec<ResourceRevision>,
    /// Lists desired resource revisions in canonical resource order.
    pub desired_revisions: Vec<ResourceRevision>,
    /// Lists operations in canonical scoped-key order.
    pub operations: Vec<Operation>,
    /// Lists conditional selector decisions in canonical scoped-key order.
    pub decisions: Vec<DecisionNode>,
    /// Lists conditional result merges in canonical scoped-key order.
    pub merges: Vec<MergeNode>,
    /// Lists typed graph edges in canonical endpoint and kind order.
    pub edges: Vec<DependencyEdge>,
    /// Assigns one lifecycle controller to each mutable resource.
    pub controllers: Vec<ControllerAssignment>,
    /// Carries unresolved deployment inputs that prohibit execution.
    pub obligations: Vec<DeploymentObligation>,
}

/// Classifies one durable operation attempt outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptOutcome {
    /// Completion evidence established the promised target.
    Completed,
    /// The provider proved rejection occurred before any external effect.
    RejectedBeforeEffect,
    /// A live effect may have occurred and requires reconciliation.
    Indeterminate,
}

/// Records one operation attempt without rewriting prior history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    /// Names the operation inside the exact plan.
    pub operation: ScopedOperationKey,
    /// Gives the positive attempt index for the stable operation identity.
    pub attempt: NonZeroU32,
    /// Records completed, rejected-before-effect, or indeterminate status.
    pub outcome: AttemptOutcome,
    /// Retains typed provider evidence without parsing human output.
    pub evidence: AbilityValue,
}

/// Records one durable conditional selection and its selector evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BranchSelection {
    /// Names the decision that selected an alternative.
    pub decision: ScopedOperationKey,
    /// Names the selected alternative.
    pub alternative: LocalKey,
    /// Retains the selector value used for the durable choice.
    pub selector_evidence: AbilityValue,
}

/// Records an operation omitted because an enclosing branch was not selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedOperationRecord {
    /// Names the operation that did not run.
    pub operation: ScopedOperationKey,
    /// Names the decision that excluded the operation.
    pub decision: ScopedOperationKey,
    /// Names the alternative selected instead.
    pub selected_alternative: LocalKey,
}

/// Records the typed outputs exposed by one completed conditional merge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeRecord {
    /// Names the completed merge node.
    pub merge: ScopedOperationKey,
    /// Names the decision whose selection was merged.
    pub decision: ScopedOperationKey,
    /// Names the selected alternative.
    pub alternative: LocalKey,
    /// Retains the selected typed output values in canonical port order.
    pub outputs: BTreeMap<LocalKey, AbilityValue>,
}

/// Records an authoritative live publication outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Names the publishing operation.
    pub operation: ScopedOperationKey,
    /// Identifies the published resource.
    pub resource: ResourceId,
    /// Identifies the expected previous revision, when one existed.
    pub previous_revision: Option<RevisionId>,
    /// Identifies the authoritative selected revision.
    pub selected_revision: RevisionId,
    /// Retains provider-specific typed evidence.
    pub evidence: AbilityValue,
}

/// Records one admitted observation about actual resource state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecord {
    /// Gives the observation a stable local name.
    pub key: LocalKey,
    /// Identifies the observed resource.
    pub resource: ResourceId,
    /// Identifies the observed revision, when established.
    pub revision: Option<RevisionId>,
    /// Retains bounded typed observation evidence.
    pub evidence: AbilityValue,
}

/// Classifies the durable terminal result of a transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalResult {
    /// The command's declared target condition was established.
    Succeeded,
    /// The transaction settled without reaching its declared target.
    SettledFailure,
    /// An unresolved indeterminate effect requires operator intervention.
    InterventionRequired,
}

/// Wraps durable attempts, publication receipts, observations, and outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDocument {
    /// Carries `aos.ability.execution/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies this distinct durable execution.
    pub transaction: TransactionId,
    /// Identifies the exact effect plan.
    pub effect_plan: Sha256Digest,
    /// Lists exact retained artifacts in canonical digest order.
    pub artifacts: Vec<ArtifactReference>,
    /// Retains operation attempts in durable sequence order.
    pub attempts: Vec<AttemptRecord>,
    /// Retains conditional choices in durable sequence order.
    pub branch_selections: Vec<BranchSelection>,
    /// Retains operations excluded by durable conditional choices.
    pub skipped_operations: Vec<SkippedOperationRecord>,
    /// Retains completed conditional merge outputs in durable sequence order.
    pub merges: Vec<MergeRecord>,
    /// Retains authoritative publication receipts in durable sequence order.
    pub publications: Vec<PublicationReceipt>,
    /// Retains admitted observations in durable sequence order.
    pub observations: Vec<ObservationRecord>,
    /// Records the terminal result once the transaction settles.
    pub terminal: Option<TerminalResult>,
}

macro_rules! versioned_document {
    ($type:ty, $schema:literal) => {
        impl VersionedDocument for $type {
            const SCHEMA: &'static str = $schema;

            fn schema(&self) -> &str {
                &self.schema
            }

            fn required_features(&self) -> &[RequiredFeature] {
                &self.required_features
            }
        }
    };
}

versioned_document!(EnvironmentDocument, "aos.ability.environment/v1");
versioned_document!(BindingPlanDocument, "aos.ability.binding-plan/v1");
versioned_document!(ExecutionDocument, "aos.ability.execution/v1");

impl VersionedDocument for InterfaceDocument {
    const SCHEMA: &'static str = "aos.ability.interface/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        validate_interface_depth(&self.interface, limits)
    }
}

impl VersionedDocument for PackageDocument {
    const SCHEMA: &'static str = "aos.ability.package/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        for requirement in &self.requirements {
            if let Some(fallback) = &requirement.fallback {
                ensure_schema_depth(fallback, limits)?;
            }
        }
        for provider in &self.implementation.providers {
            for requirement in &provider.requirements {
                if let Some(fallback) = &requirement.fallback {
                    ensure_schema_depth(fallback, limits)?;
                }
            }
        }
        for handler in self.implementation.handlers.values() {
            ensure_schema_depth(&handler.arguments, limits)?;
            ensure_schema_depth(&handler.result, limits)?;
        }
        Ok(())
    }
}

impl VersionedDocument for DesiredStateDocument {
    const SCHEMA: &'static str = "aos.ability.desired/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        for expression in self.outputs.values() {
            ensure_expression_depth(expression, limits)?;
        }
        Ok(())
    }
}

impl VersionedDocument for EffectPlanDocument {
    const SCHEMA: &'static str = "aos.ability.effect-plan/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn limit_profile(&self) -> Option<&LimitProfile> {
        Some(&self.limits)
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        for operation in &self.operations {
            ensure_expression_depth(&operation.inputs, limits)?;
        }
        for merge in &self.merges {
            for output in merge.outputs.values() {
                ensure_schema_depth(&output.descriptor.schema, limits)?;
            }
        }
        Ok(())
    }
}

fn validate_interface_depth(
    interface: &InterfaceDescriptor,
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    ensure_schema_depth(&interface.request, limits)?;
    for output in interface.outputs.values() {
        ensure_schema_depth(&output.schema, limits)?;
    }
    for method in interface.methods.values() {
        ensure_schema_depth(&method.parameters, limits)?;
        ensure_schema_depth(&method.outcome.completion_evidence, limits)?;
        for output in method.outputs.values() {
            ensure_schema_depth(&output.schema, limits)?;
        }
    }
    Ok(())
}

fn ensure_schema_depth(
    schema: &crate::schema::ValueSchema,
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    if !schema.is_within_limits(limits.max_structural_depth, limits.max_collection_items) {
        return Err(DocumentError::Limit {
            label: "ability document".to_string(),
            limit: "structural depth",
        });
    }
    Ok(())
}

fn ensure_expression_depth(
    expression: &ValueExpression,
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    if !expression.is_within_limits(limits.max_structural_depth, limits.max_collection_items) {
        return Err(DocumentError::Limit {
            label: "ability document".to_string(),
            limit: "structural depth",
        });
    }
    Ok(())
}

fn validate_envelope<T>(
    document: &T,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<(), DocumentError>
where
    T: VersionedDocument,
{
    if document.schema() != T::SCHEMA {
        return Err(DocumentError::Schema {
            expected: T::SCHEMA,
            actual: document.schema().to_string(),
        });
    }
    if !strictly_sorted(document.required_features()) {
        return Err(DocumentError::RequiredFeatureOrder);
    }
    for feature in document.required_features() {
        if !supported_features.contains(feature) {
            return Err(DocumentError::UnsupportedFeature {
                feature: feature.as_str().to_string(),
            });
        }
    }
    if document
        .limit_profile()
        .is_some_and(|limits| !limits.is_admissible_v1())
    {
        return Err(DocumentError::InvalidLimitProfile);
    }
    Ok(())
}

fn strictly_sorted<T>(values: &[T]) -> bool
where
    T: Ord,
{
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn bounded_usize(value: u64) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::interface::{LifecycleSemantics, ValueVisibility};
    use crate::schema::ValueSchema;
    use crate::value::ResourceLifetime;

    fn interface_document() -> InterfaceDocument {
        InterfaceDocument {
            schema: InterfaceDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            interface: InterfaceDescriptor {
                name: crate::identity::InterfaceName::new("test.echo")
                    .expect("valid test interface name"),
                abi: NonZeroU32::new(1).expect("positive test ABI"),
                request: ValueSchema::Boolean,
                outputs: BTreeMap::from([(
                    LocalKey::new("accepted").expect("valid test output name"),
                    crate::interface::OutputDescriptor {
                        schema: ValueSchema::Boolean,
                        phase: crate::interface::ValuePhase::Evaluation,
                        visibility: ValueVisibility::Public,
                        lifetime: ResourceLifetime::Instance,
                    },
                )]),
                methods: BTreeMap::new(),
                lifecycle: LifecycleSemantics {
                    stable_resource_identity: true,
                    releases_ephemeral_on_disable: true,
                    retains_persistent_by_default: true,
                    persistent_delete_method: None,
                },
                guarantees: Vec::new(),
            },
        }
    }

    #[test]
    fn canonical_round_trip_preserves_interface_identity() -> Result<(), DocumentError> {
        let original = interface_document();
        let bytes = encode_canonical(&original)?;
        let decoded =
            decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, &BTreeSet::new())?;

        assert_eq!(decoded, original);
        assert_eq!(decoded.interface_key()?, original.interface_key()?);
        Ok(())
    }

    #[test]
    fn equivalent_but_noncanonical_json_is_rejected() {
        let bytes = br#"{"schema":"aos.ability.interface/v1","required_features":[],"interface":{"name":"test.echo","abi":1,"request":{"kind":"boolean"},"outputs":{},"methods":{},"lifecycle":{"stable_resource_identity":true,"releases_ephemeral_on_disable":true,"retains_persistent_by_default":true,"persistent_delete_method":null},"guarantees":[]}}"#;

        assert!(
            decode_canonical::<InterfaceDocument>(bytes, ABILITY_LIMITS_V1, &BTreeSet::new())
                .is_err()
        );
    }

    #[test]
    fn unknown_required_semantics_fail_closed() {
        let mut document = interface_document();
        document.required_features =
            vec![RequiredFeature::new("future-semantics").expect("valid test feature")];
        let bytes = encode_canonical(&document).expect("canonical test document");

        assert!(matches!(
            decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, &BTreeSet::new()),
            Err(DocumentError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn canonical_schema_rejects_an_absent_optional_member() {
        let document = interface_document();
        let bytes = encode_canonical(&document).expect("canonical test document");
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid test JSON");
        value["interface"]["lifecycle"]
            .as_object_mut()
            .expect("test lifecycle object")
            .remove("persistent_delete_method");
        let without_null =
            aos_contract::canonical::canonical_json(&value).expect("canonical test JSON");

        assert!(
            decode_canonical::<InterfaceDocument>(
                &without_null,
                ABILITY_LIMITS_V1,
                &BTreeSet::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn decoding_applies_the_caller_document_bound_first() {
        let bytes = encode_canonical(&interface_document()).expect("canonical test document");
        let limits = LimitProfile {
            max_document_bytes: (bytes.len() - 1) as u64,
            ..ABILITY_LIMITS_V1
        };

        assert!(matches!(
            decode_canonical::<InterfaceDocument>(&bytes, limits, &BTreeSet::new()),
            Err(DocumentError::Limit { .. })
        ));
    }

    #[test]
    fn encoding_rejects_programmatic_schema_depth_before_serialization() {
        let mut document = interface_document();
        let mut schema = ValueSchema::Boolean;
        for _ in 0..=ABILITY_LIMITS_V1.max_structural_depth {
            schema = ValueSchema::Optional {
                value: Box::new(schema),
            };
        }
        document.interface.request = schema;

        assert!(matches!(
            encode_canonical(&document),
            Err(DocumentError::Limit {
                limit: "structural depth",
                ..
            })
        ));
    }

    #[test]
    fn shared_nix_fixture_has_the_same_bytes_and_identity() -> Result<(), DocumentError> {
        let bytes = include_bytes!("../../../tests/abilities/fixtures/interface.json");
        let supported_features =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid test feature")]);
        let document =
            decode_canonical::<InterfaceDocument>(bytes, ABILITY_LIMITS_V1, &supported_features)?;

        assert_eq!(encode_canonical(&document)?, bytes);
        assert_eq!(
            document.interface_key()?.descriptor,
            Sha256Digest::parse(
                "sha256:ed3b07a958b2384c213605c20a3eb7dd5d8489906bc0c79fbe9d75395883e8c7",
            )
            .expect("valid test digest"),
        );
        Ok(())
    }
}
