//! Closed versioned canonical documents for the RFC-0022 format families.
//!
//! Each document uses the integer-only canonical JSON dialect from
//! `aos-contract`, carries an exact schema discriminator, and declares every
//! required semantic feature explicitly.
//!
//! An interface envelope uses this closed shape:
//!
//! ```json
//! {"interface":{"abi":1,"guarantees":[],"lifecycle":{"persistent_delete_method":null},"methods":{},"name":"test.echo","outputs":{},"request":{"kind":"boolean"}},"required_features":[],"schema":"aos.ability.interface/v1"}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use aos_contract::Sha256Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::identity::{
    AggregateId, DeclarationAuthority, EnvironmentId, IncarnationId, InstanceId, InterfaceKey,
    InterfaceName, LocalKey, RelativePath, RequestId, ResourceId, RevisionId, ScopedOperationKey,
    TransactionId,
};
use crate::interface::{
    ExportDeclaration, GuaranteeDeclaration, GuaranteeKey, InterfaceDescriptor,
    PackageImplementation, PackageQualification, ProviderImplementationReference,
    RequirementDeclaration,
};
use crate::limits::{ABILITY_LIMITS_V1, LimitProfile};
use crate::option::{PackageOptionDeclaration, validate_package_option_declarations};
use crate::plan::{
    Binding, BindingId, BindingRequest, ControllerAssignment, DecisionNode, DependencyEdge,
    DeploymentObligation, MergeNode, Operation, ResourceRevision,
};
use crate::schema::ValueSchema;
use crate::value::{AbilityValue, ArtifactReference, ValueExpression};
use aos_contract::limits::BoundedWriter;

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

impl DocumentError {
    /// Returns the stable diagnostic code for this decoding or envelope failure.
    #[must_use]
    pub const fn diagnostic_code(&self) -> crate::DiagnosticCode {
        match self {
            Self::Limit { .. } | Self::InvalidLimitProfile => crate::DiagnosticCode::LimitExceeded,
            Self::Decode { .. } => crate::DiagnosticCode::ValueTypeMismatch,
            Self::Schema { .. } => crate::DiagnosticCode::UnsupportedSchema,
            Self::RequiredFeatureOrder => crate::DiagnosticCode::NonCanonicalOrder,
            Self::UnsupportedFeature { .. } => crate::DiagnosticCode::UnsupportedRequiredFeature,
        }
    }
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
    let mut writer = BoundedWriter::new(max_bytes, "serialized document exceeds its byte limit");
    serde_json::to_writer(&mut writer, value).map_err(|source| {
        if writer.exceeded() {
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

/// Names the package-reader feature for authenticated ability contracts.
pub const FEATURE_ABILITIES_V1: &str = "abilities-v1";

/// Names the package-reader feature for package-owned effect implementations.
pub const FEATURE_ABILITY_EFFECTS_V1: &str = "ability-effects-v1";

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
    /// Maps package-local interface declaration aliases to exact public identities.
    pub interfaces: BTreeMap<LocalKey, InterfaceKey>,
    /// Maps package-local guarantee aliases to their semantic declarations and prose.
    pub guarantees: BTreeMap<LocalKey, GuaranteeDeclaration>,
    /// Locates the package's executable ability/configuration module.
    pub package_module: Option<ModuleLocator>,
    /// Retains the mechanically derived package-owned module option declarations.
    pub option_declarations: Vec<PackageOptionDeclaration>,
    /// Lists public exports in canonical name order.
    pub exports: Vec<ExportDeclaration>,
    /// Lists declarative imports in canonical alias order.
    pub requirements: Vec<RequirementDeclaration>,
    /// Contains provider-specific implementations and handler declarations.
    pub implementation: PackageImplementation,
    /// Contains the package's signed qualification declarations.
    pub qualification: PackageQualification,
}

/// Locates one Nix provider module below an authenticated artifact root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLocator {
    /// Authenticates and retains the artifact containing the module.
    pub artifact: ArtifactReference,
    /// Selects the normalized module file below the artifact root.
    pub path: RelativePath,
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
    /// Identifies the release-recorded build source without retaining its build closure.
    pub source: crate::ArtifactIdentity,
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
    /// Lists exact immutable artifacts retained by this environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactReference>,
    /// Lists authenticated current resource revisions in canonical resource order.
    pub resources: Vec<ResourceRevision>,
    /// Lists authenticated current lifecycle controllers in canonical resource order.
    pub controllers: Vec<ControllerAssignment>,
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
    /// Identifies the authenticated configuration authority that authored the instance.
    pub authority: DeclarationAuthority,
    /// Identifies the exact package ability manifest when the instance uses one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<Sha256Digest>,
    /// States explicit operator-owned enablement.
    pub enabled: bool,
    /// Carries configuration owned by the operator for this exact instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<AbilityValue>,
}

/// Records one admitted aggregate input without erasing provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateInput {
    /// Identifies the original consumer request.
    pub request: RequestId,
    /// Identifies the provider aggregation group.
    pub aggregate: AggregateId,
    /// Names the authorized aggregate input slot.
    pub slot: LocalKey,
    /// Identifies the exact binding whose caller grant admitted this aggregate input.
    pub grant: BindingId,
    /// Carries the checked aggregate input value.
    pub value: AbilityValue,
}

/// Names one aggregate output without collapsing provider or interface identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateOutput {
    /// Identifies the provider-owned aggregate producing the value.
    pub aggregate: AggregateId,
    /// Identifies the exact public interface declaring the output port.
    pub interface: InterfaceKey,
    /// Names the interface-local output port.
    pub port: LocalKey,
    /// Carries the typed literal or symbolic desired value.
    pub value: ValueExpression,
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
    /// Lists admitted aggregate inputs in the explicit aggregate input order.
    pub aggregate_inputs: Vec<AggregateInput>,
    /// Lists expanded child requests in canonical request order.
    pub child_requests: Vec<BindingRequest>,
    /// Lists desired logical resources in canonical resource order.
    pub resources: Vec<ResourceRevision>,
    /// Lists provider-qualified typed aggregate outputs in canonical order.
    pub outputs: Vec<AggregateOutput>,
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
    /// Lists authenticated artifacts retained for every possible branch.
    pub artifacts: Vec<ArtifactReference>,
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
    /// Declares exact assignment evidence for every planned provider binding.
    pub provider_readiness: Vec<crate::plan::ProviderReadiness>,
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

#[path = "document_validation.rs"]
mod validation;

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
        ensure_schema_depth(&method.outcome.observation_evidence, limits)?;
        for output in method.outputs.values() {
            ensure_schema_depth(&output.schema, limits)?;
        }
    }
    Ok(())
}

fn validate_interface_prose(
    interface: &InterfaceDescriptor,
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    validate_documentation_text("interface description", &interface.description, limits)?;
    for output in interface.outputs.values() {
        validate_documentation_text("interface output description", &output.description, limits)?;
    }
    for method in interface.methods.values() {
        validate_documentation_text("interface method description", &method.description, limits)?;
        for output in method.outputs.values() {
            validate_documentation_text(
                "interface method output description",
                &output.description,
                limits,
            )?;
        }
    }
    Ok(())
}

fn validate_documentation_text(
    label: &'static str,
    value: &str,
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    if value.is_empty()
        || value.len() as u64 > limits.max_string_bytes
        || value.chars().any(char::is_control)
    {
        return Err(DocumentError::Decode {
            label: "ability document".to_string(),
            source: anyhow::anyhow!(
                "{label} must be nonempty, control-free, and within the string limit"
            ),
        });
    }
    Ok(())
}

fn validate_package_probe(
    probe: &crate::PackageProbe,
    retained_artifacts: &[ArtifactReference],
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    fn validate_template(
        template: &crate::PackageProbeTemplate,
        retained_artifacts: &[ArtifactReference],
        limits: &LimitProfile,
    ) -> Result<(), DocumentError> {
        if template.fragments.is_empty() || template.fragments.len() > 64 {
            return Err(DocumentError::Decode {
                label: PackageDocument::SCHEMA.to_string(),
                source: anyhow::anyhow!("package probe template has an invalid fragment count"),
            });
        }
        for fragment in &template.fragments {
            match fragment {
                crate::PackageProbeTemplateFragment::Literal { text } => {
                    if text.len() as u64 > limits.max_string_bytes {
                        return Err(DocumentError::Decode {
                            label: PackageDocument::SCHEMA.to_string(),
                            source: anyhow::anyhow!("package probe literal exceeds its size bound"),
                        });
                    }
                }
                crate::PackageProbeTemplateFragment::ArtifactRoot { artifact }
                | crate::PackageProbeTemplateFragment::ArtifactPath { artifact, .. } => {
                    if !retained_artifacts.contains(artifact) {
                        return Err(DocumentError::Decode {
                            label: PackageDocument::SCHEMA.to_string(),
                            source: anyhow::anyhow!(
                                "package probe references an artifact outside the retained package set"
                            ),
                        });
                    }
                }
                crate::PackageProbeTemplateFragment::WorkPath { .. }
                | crate::PackageProbeTemplateFragment::Harness { .. } => {}
            }
        }
        Ok(())
    }

    for (name, operation) in [("primary", &probe.primary), ("bad input", &probe.bad_input)] {
        validate_documentation_text("package probe input", &operation.input, limits)?;
        validate_documentation_text("package probe operation", &operation.operation, limits)?;
        validate_documentation_text("package probe expectation", &operation.expected, limits)?;
        if operation.files.len() > 32
            || operation.steps.is_empty()
            || operation.steps.len() > 16
            || operation.artifacts.len() > 32
        {
            return Err(DocumentError::Decode {
                label: PackageDocument::SCHEMA.to_string(),
                source: anyhow::anyhow!(
                    "package probe {name} operation exceeds its collection bounds"
                ),
            });
        }
        for template in operation.files.values() {
            validate_template(template, retained_artifacts, limits)?;
        }
        for step in &operation.steps {
            if step.argv.is_empty()
                || step.argv.len() > 64
                || step
                    .timeout_seconds
                    .is_some_and(|seconds| !(1..=300).contains(&seconds))
            {
                return Err(DocumentError::Decode {
                    label: PackageDocument::SCHEMA.to_string(),
                    source: anyhow::anyhow!(
                        "package probe {name} step has invalid execution bounds"
                    ),
                });
            }
            for template in &step.argv {
                validate_template(template, retained_artifacts, limits)?;
            }
            for template in [&step.stdin, &step.stdout, &step.stderr]
                .into_iter()
                .flatten()
            {
                validate_template(template, retained_artifacts, limits)?;
            }
        }
    }
    if probe.primary.steps.iter().any(|step| step.exit_code != 0) {
        return Err(DocumentError::Decode {
            label: PackageDocument::SCHEMA.to_string(),
            source: anyhow::anyhow!("package probe primary operation expects a failing status"),
        });
    }
    if !probe
        .bad_input
        .steps
        .iter()
        .any(|step| step.observes_rejection || step.exit_code != 0)
    {
        return Err(DocumentError::Decode {
            label: PackageDocument::SCHEMA.to_string(),
            source: anyhow::anyhow!("package probe bad input has no observable rejection"),
        });
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
#[path = "document_tests.rs"]
mod tests;
