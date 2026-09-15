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
    AggregateId, EnvironmentId, IncarnationId, InstanceId, InterfaceKey, InterfaceName, LocalKey,
    RelativePath, RequestId, ResourceId, RevisionId, ScopedOperationKey, TransactionId,
};
use crate::interface::{
    ExportDeclaration, GuaranteeDeclaration, GuaranteeKey, InterfaceDescriptor,
    PackageImplementation, ProviderImplementationReference, RequirementDeclaration,
};
use crate::limits::{ABILITY_LIMITS_V1, LimitProfile};
use crate::option::{PackageOptionDeclaration, validate_package_option_declarations};
use crate::plan::{
    Binding, BindingId, BindingRequest, ControllerAssignment, DecisionNode, DependencyEdge,
    DeploymentObligation, MergeNode, Operation, ResourceRevision,
};
use crate::schema::ValueSchema;
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

/// Selects whether a signed package may author structured activation effects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbilityActivationMode {
    /// Publishes interfaces and pure planning contracts without resource effects.
    ContractsOnly,
    /// Authorizes declared resource ownership and structured effect construction.
    StructuredEffects,
}

/// Wraps one authenticated package ability manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDocument {
    /// Carries `aos.ability.package/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Selects the signed package activation and effect-authoring capability.
    pub activation_mode: AbilityActivationMode,
    /// Identifies the package subject without referring to its enclosing signature.
    pub package: PackageSubject,
    /// Lists retained companion artifacts in canonical digest order.
    pub artifacts: Vec<ArtifactReference>,
    /// Maps package-local interface declaration aliases to exact public identities.
    pub interfaces: BTreeMap<LocalKey, InterfaceKey>,
    /// Maps package-local guarantee aliases to their semantic declarations and prose.
    pub guarantees: BTreeMap<LocalKey, GuaranteeDeclaration>,
    /// Locates the package's executable ability/configuration module.
    pub package_module: ModuleLocator,
    /// Retains the mechanically derived package-owned module option declarations.
    pub option_declarations: Vec<PackageOptionDeclaration>,
    /// Lists public exports in canonical name order.
    pub exports: Vec<ExportDeclaration>,
    /// Lists declarative imports in canonical alias order.
    pub requirements: Vec<RequirementDeclaration>,
    /// Contains provider-specific implementations and handler declarations.
    pub implementation: PackageImplementation,
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
    /// Identifies the exact release-recorded build-source artifact.
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
    /// Identifies the exact package ability manifest.
    pub package: Sha256Digest,
    /// States explicit operator-owned enablement.
    pub enabled: bool,
    /// Carries configuration owned by the operator for this exact instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<AbilityValue>,
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
    /// Identifies the exact binding whose caller grant admitted this contribution.
    pub grant: BindingId,
    /// Carries the checked contribution value.
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
    /// Lists admitted contributions in the explicit contribution order.
    pub contributions: Vec<Contribution>,
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

impl VersionedDocument for InterfaceDocument {
    const SCHEMA: &'static str = "aos.ability.interface/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        validate_interface_depth(&self.interface, limits)?;
        validate_interface_prose(&self.interface, limits)
    }

    fn content_digest(&self) -> Result<Sha256Digest, DocumentError> {
        #[derive(Serialize)]
        struct SemanticOutput<'a> {
            schema: &'a ValueSchema,
            phase: crate::interface::ValuePhase,
            visibility: crate::interface::ValueVisibility,
            lifetime: crate::ResourceLifetime,
        }

        #[derive(Serialize)]
        struct SemanticMethod<'a> {
            semantics: &'a crate::interface::MethodSemantics,
            parameters: &'a ValueSchema,
            target_resource: &'a InterfaceName,
            outputs: BTreeMap<&'a LocalKey, SemanticOutput<'a>>,
            permitted_operations: &'a [LocalKey],
            guarantees: &'a [GuaranteeKey],
            outcome: &'a crate::interface::OutcomeSemantics,
        }

        #[derive(Serialize)]
        struct SemanticInterface<'a> {
            name: &'a InterfaceName,
            abi: NonZeroU32,
            request: &'a ValueSchema,
            configuration: &'a Option<ValueSchema>,
            outputs: BTreeMap<&'a LocalKey, SemanticOutput<'a>>,
            methods: BTreeMap<&'a LocalKey, SemanticMethod<'a>>,
            lifecycle: &'a crate::interface::LifecycleSemantics,
            aggregation: &'a crate::interface::AggregationContract,
            guarantees: &'a [GuaranteeKey],
        }

        #[derive(Serialize)]
        struct SemanticInterfaceDocument<'a> {
            schema: &'a str,
            required_features: &'a [RequiredFeature],
            interface: SemanticInterface<'a>,
        }

        #[derive(Serialize)]
        struct DescriptorEnvelope<'a> {
            domain: &'static str,
            document: SemanticInterfaceDocument<'a>,
        }

        fn semantic_output(descriptor: &crate::interface::OutputDescriptor) -> SemanticOutput<'_> {
            SemanticOutput {
                schema: &descriptor.schema,
                phase: descriptor.phase,
                visibility: descriptor.visibility,
                lifetime: descriptor.lifetime,
            }
        }

        let outputs = self
            .interface
            .outputs
            .iter()
            .map(|(name, descriptor)| (name, semantic_output(descriptor)))
            .collect();
        let methods = self
            .interface
            .methods
            .iter()
            .map(|(name, method)| {
                (
                    name,
                    SemanticMethod {
                        semantics: &method.semantics,
                        parameters: &method.parameters,
                        target_resource: &method.target_resource,
                        outputs: method
                            .outputs
                            .iter()
                            .map(|(name, descriptor)| (name, semantic_output(descriptor)))
                            .collect(),
                        permitted_operations: &method.permitted_operations,
                        guarantees: &method.guarantees,
                        outcome: &method.outcome,
                    },
                )
            })
            .collect();

        let envelope = DescriptorEnvelope {
            domain: Self::SCHEMA,
            document: SemanticInterfaceDocument {
                schema: &self.schema,
                required_features: &self.required_features,
                interface: SemanticInterface {
                    name: &self.interface.name,
                    abi: self.interface.abi,
                    request: &self.interface.request,
                    configuration: &self.interface.configuration,
                    outputs,
                    methods,
                    lifecycle: &self.interface.lifecycle,
                    aggregation: &self.interface.aggregation,
                    guarantees: &self.interface.guarantees,
                },
            },
        };
        let bytes =
            aos_contract::canonical::to_vec(&envelope).map_err(|source| DocumentError::Decode {
                label: Self::SCHEMA.to_string(),
                source,
            })?;

        Ok(Sha256Digest::of_bytes(bytes))
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
        validate_package_option_declarations(&self.option_declarations, limits)?;
        for provider in &self.implementation.providers {
            validate_documentation_text(
                "provider implementation description",
                &provider.description,
                limits,
            )?;
            if let Some(schema) = &provider.desired_schema {
                ensure_schema_depth(schema, limits)?;
            }
            for requirement in &provider.requirements {
                validate_documentation_text(
                    "provider requirement description",
                    &requirement.description,
                    limits,
                )?;
            }
        }
        for requirement in &self.requirements {
            validate_documentation_text(
                "package requirement description",
                &requirement.description,
                limits,
            )?;
        }
        for guarantee in self.guarantees.values() {
            if guarantee.semantics.is_empty()
                || guarantee.semantics.chars().any(char::is_control)
                || guarantee.semantics.len() as u64 > limits.max_string_bytes
                || guarantee.description.is_empty()
                || guarantee.description.chars().any(char::is_control)
                || guarantee.description.len() as u64 > limits.max_string_bytes
            {
                return Err(DocumentError::Decode {
                    label: Self::SCHEMA.to_string(),
                    source: anyhow::anyhow!(
                        "package guarantee semantics and description must be non-empty and control-free"
                    ),
                });
            }
        }
        for handler in self.implementation.handlers.values() {
            ensure_schema_depth(&handler.arguments, limits)?;
            ensure_schema_depth(&handler.result, limits)?;
        }
        for qualification in self.implementation.qualification.values() {
            if qualification.conformance_families.is_empty()
                || qualification
                    .conformance_families
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(DocumentError::Decode {
                    label: Self::SCHEMA.to_string(),
                    source: anyhow::anyhow!(
                        "package qualification families must be non-empty and strictly ordered"
                    ),
                });
            }
            ensure_schema_depth(&qualification.observer.arguments, limits)?;
            ensure_schema_depth(&qualification.observer.result, limits)?;
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<Sha256Digest, DocumentError> {
        #[derive(Serialize)]
        struct SemanticGuarantee<'a> {
            name: &'a InterfaceName,
            version: std::num::NonZeroU32,
            semantics: &'a str,
        }

        #[derive(Serialize)]
        struct SemanticPackageSubject<'a> {
            name: &'a LocalKey,
            version: &'a str,
            payload: crate::ArtifactIdentity,
            source: crate::ArtifactIdentity,
        }

        #[derive(Serialize)]
        struct SemanticModuleLocator<'a> {
            artifact: crate::ArtifactIdentity,
            path: &'a RelativePath,
        }

        #[derive(Serialize)]
        struct SemanticHandler<'a> {
            artifact: crate::ArtifactIdentity,
            entry_point: &'a str,
            arguments: &'a ValueSchema,
            result: &'a ValueSchema,
        }

        #[derive(Serialize)]
        struct SemanticPackageImplementation<'a> {
            providers: Vec<Sha256Digest>,
            handlers: BTreeMap<&'a LocalKey, SemanticHandler<'a>>,
            qualification: BTreeMap<&'a Sha256Digest, SemanticQualification<'a>>,
        }

        #[derive(Serialize)]
        struct SemanticExport<'a> {
            name: &'a LocalKey,
            interface: &'a InterfaceKey,
            implementation: Sha256Digest,
        }

        #[derive(Serialize)]
        struct SemanticOptionDeclaration<'a> {
            path: &'a [String],
            structured_type: &'a crate::OptionType,
            default: Option<&'a AbilityValue>,
            visibility: crate::OptionVisibility,
            read_only: bool,
            contributable: bool,
        }

        #[derive(Serialize)]
        struct SemanticQualification<'a> {
            conformance_families: &'a [LocalKey],
            observer: SemanticHandler<'a>,
        }

        #[derive(Serialize)]
        struct SemanticRequirement<'a> {
            alias: &'a LocalKey,
            accepted_interfaces: &'a [crate::InterfaceSelector],
            methods: &'a [LocalKey],
            guarantees: &'a [GuaranteeKey],
            strength: crate::interface::RequirementStrength,
            fallback: &'a Option<crate::interface::RequirementFallback>,
        }

        #[derive(Serialize)]
        struct SemanticPackage<'a> {
            schema: &'a str,
            required_features: &'a [RequiredFeature],
            activation_mode: AbilityActivationMode,
            package: SemanticPackageSubject<'a>,
            artifacts: Vec<crate::ArtifactIdentity>,
            interfaces: &'a BTreeMap<LocalKey, InterfaceKey>,
            guarantees: BTreeMap<LocalKey, SemanticGuarantee<'a>>,
            package_module: SemanticModuleLocator<'a>,
            option_declarations: Vec<SemanticOptionDeclaration<'a>>,
            exports: Vec<SemanticExport<'a>>,
            requirements: Vec<SemanticRequirement<'a>>,
            implementation: SemanticPackageImplementation<'a>,
        }

        let guarantees = self
            .guarantees
            .iter()
            .map(|(alias, guarantee)| {
                (
                    alias.clone(),
                    SemanticGuarantee {
                        name: &guarantee.name,
                        version: guarantee.version,
                        semantics: &guarantee.semantics,
                    },
                )
            })
            .collect();
        let providers = self
            .implementation
            .providers
            .iter()
            .map(|provider| provider.descriptor_digest())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| DocumentError::Decode {
                label: Self::SCHEMA.to_string(),
                source,
            })?;
        let handlers = self
            .implementation
            .handlers
            .iter()
            .map(|(name, handler)| {
                (
                    name,
                    SemanticHandler {
                        artifact: handler.artifact.identity(),
                        entry_point: &handler.entry_point,
                        arguments: &handler.arguments,
                        result: &handler.result,
                    },
                )
            })
            .collect();
        let qualification = self
            .implementation
            .qualification
            .iter()
            .map(|(implementation, qualification)| {
                (
                    implementation,
                    SemanticQualification {
                        conformance_families: &qualification.conformance_families,
                        observer: SemanticHandler {
                            artifact: qualification.observer.artifact.identity(),
                            entry_point: &qualification.observer.entry_point,
                            arguments: &qualification.observer.arguments,
                            result: &qualification.observer.result,
                        },
                    },
                )
            })
            .collect();
        let semantic = SemanticPackage {
            schema: &self.schema,
            required_features: &self.required_features,
            activation_mode: self.activation_mode,
            package: SemanticPackageSubject {
                name: &self.package.name,
                version: &self.package.version,
                payload: self.package.payload.identity(),
                source: self.package.source.identity(),
            },
            artifacts: self
                .artifacts
                .iter()
                .map(ArtifactReference::identity)
                .collect(),
            interfaces: &self.interfaces,
            guarantees,
            package_module: SemanticModuleLocator {
                artifact: self.package_module.artifact.identity(),
                path: &self.package_module.path,
            },
            option_declarations: self
                .option_declarations
                .iter()
                .map(|declaration| SemanticOptionDeclaration {
                    path: &declaration.path,
                    structured_type: &declaration.structured_type,
                    default: match &declaration.default {
                        Some(crate::DocumentedValue::Literal { value }) => Some(value),
                        Some(crate::DocumentedValue::Text { .. }) | None => None,
                    },
                    visibility: declaration.visibility,
                    read_only: declaration.read_only,
                    contributable: declaration.contributable,
                })
                .collect(),
            exports: self
                .exports
                .iter()
                .map(|export| SemanticExport {
                    name: &export.name,
                    interface: &export.interface,
                    implementation: export.implementation,
                })
                .collect(),
            requirements: self
                .requirements
                .iter()
                .map(|requirement| SemanticRequirement {
                    alias: &requirement.alias,
                    accepted_interfaces: &requirement.accepted_interfaces,
                    methods: &requirement.methods,
                    guarantees: &requirement.guarantees,
                    strength: requirement.strength,
                    fallback: &requirement.fallback,
                })
                .collect(),
            implementation: SemanticPackageImplementation {
                providers,
                handlers,
                qualification,
            },
        };

        let bytes =
            aos_contract::canonical::to_vec(&semantic).map_err(|source| DocumentError::Decode {
                label: Self::SCHEMA.to_string(),
                source,
            })?;

        Ok(Sha256Digest::separated(Self::SCHEMA, bytes))
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
        for output in &self.outputs {
            ensure_expression_depth(&output.value, limits)?;
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
    use crate::interface::{
        AggregationContract, AggregationScope, LifecycleSemantics, ValueVisibility,
    };
    use crate::schema::ValueSchema;
    use crate::value::ResourceLifetime;
    use crate::{DocumentedValue, OptionSource, OptionType, OptionVisibility};

    fn interface_document() -> InterfaceDocument {
        InterfaceDocument {
            schema: InterfaceDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            interface: InterfaceDescriptor {
                description: "Describes this declaration.".to_string(),
                name: crate::identity::InterfaceName::new("test.echo")
                    .expect("valid test interface name"),
                abi: NonZeroU32::new(1).expect("positive test ABI"),
                request: ValueSchema::Boolean,
                configuration: None,
                outputs: BTreeMap::from([(
                    LocalKey::new("accepted").expect("valid test output name"),
                    crate::interface::OutputDescriptor {
                        description: "Describes this declaration.".to_string(),
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
                aggregation: AggregationContract {
                    scope: AggregationScope::ProviderInstance,
                    key: LocalKey::new("slot").expect("valid aggregation key"),
                    controller_group: LocalKey::new("test").expect("valid controller group"),
                    reject_slot_collisions: true,
                    merge_contract: None,
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
        assert!(
            serde_json::to_value(&decoded)
                .expect("interface must serialize")
                .get("interface")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|interface| !interface.contains_key("configuration"))
        );
        Ok(())
    }

    #[test]
    fn interface_prose_changes_signed_bytes_without_changing_identity() -> Result<(), DocumentError>
    {
        let mut original = interface_document();
        original.interface.methods.insert(
            LocalKey::new("observe").expect("valid method name"),
            crate::interface::MethodDescriptor {
                description: "Observes the test resource.".to_string(),
                semantics: crate::interface::MethodSemantics::ordinary(
                    crate::plan::AccessMode::Read,
                ),
                parameters: ValueSchema::Boolean,
                target_resource: original.interface.name.clone(),
                outputs: BTreeMap::from([(
                    LocalKey::new("observed").expect("valid output name"),
                    crate::interface::OutputDescriptor {
                        description: "Reports the observed value.".to_string(),
                        schema: ValueSchema::Boolean,
                        phase: crate::interface::ValuePhase::Observation,
                        visibility: ValueVisibility::Public,
                        lifetime: ResourceLifetime::Instance,
                    },
                )]),
                permitted_operations: Vec::new(),
                guarantees: Vec::new(),
                outcome: crate::interface::OutcomeSemantics {
                    completion_evidence: ValueSchema::Boolean,
                    observation_evidence: ValueSchema::Boolean,
                    supports_rejected_before_effect: true,
                    indeterminate: crate::interface::IndeterminateSemantics::Reconcile,
                },
            },
        );
        let mut edited = original.clone();
        edited.interface.description = "Reworded interface documentation.".to_string();
        edited
            .interface
            .outputs
            .get_mut(&LocalKey::new("accepted").expect("valid output name"))
            .expect("interface output")
            .description = "Reworded aggregate output documentation.".to_string();
        let method = edited
            .interface
            .methods
            .get_mut(&LocalKey::new("observe").expect("valid method name"))
            .expect("interface method");
        method.description = "Reworded method documentation.".to_string();
        method
            .outputs
            .get_mut(&LocalKey::new("observed").expect("valid output name"))
            .expect("method output")
            .description = "Reworded method output documentation.".to_string();

        assert_eq!(original.interface_key()?, edited.interface_key()?);
        assert_ne!(encode_canonical(&original)?, encode_canonical(&edited)?);
        Ok(())
    }

    #[test]
    fn desired_instance_without_optional_configuration_round_trips_unchanged() {
        let unconfigured = serde_json::json!({
            "instance": {
                "environment": {
                    "authority": "test",
                    "key": "web",
                    "stage": "host",
                },
                "key": "nginx",
            },
            "package": format!("sha256:{}", "0".repeat(64)),
            "enabled": true,
        });

        let decoded: DesiredInstance =
            serde_json::from_value(unconfigured.clone()).expect("unconfigured instance decodes");

        assert_eq!(decoded.configuration, None);
        assert_eq!(
            serde_json::to_value(decoded).expect("unconfigured instance serializes"),
            unconfigured
        );
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

    fn package_option(path: &str, option_type: OptionType) -> PackageOptionDeclaration {
        PackageOptionDeclaration {
            path: vec![path.to_string()],
            type_signature: "test option".to_string(),
            structured_type: option_type,
            description: "Test option declaration.".to_string(),
            default: None,
            example: None,
            visibility: OptionVisibility::Public,
            read_only: false,
            contributable: false,
            deprecated: None,
            replacement: None,
            source: OptionSource {
                path: RelativePath::new("module.nix").expect("valid option source path"),
            },
        }
    }

    #[test]
    fn package_option_declarations_reject_opaque_public_types() {
        let declaration = package_option(
            "opaque",
            OptionType::Opaque {
                signature: "unstructured".to_string(),
            },
        );

        assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
    }

    #[test]
    fn package_option_declarations_reject_open_public_submodules() {
        let declaration = package_option(
            "open",
            OptionType::Submodule {
                fields: BTreeMap::new(),
                open: true,
            },
        );

        assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
    }

    #[test]
    fn package_option_declarations_check_literal_defaults_against_the_type() {
        let mut declaration = package_option("enabled", OptionType::Bool);
        declaration.default = Some(DocumentedValue::Literal {
            value: AbilityValue::new(serde_json::json!("yes")).expect("canonical test literal"),
        });

        assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
    }

    #[test]
    fn package_option_declarations_require_strict_path_order() {
        let first = package_option("same", OptionType::Bool);
        let second = first.clone();

        assert!(
            validate_package_option_declarations(&[first, second], &ABILITY_LIMITS_V1).is_err()
        );
    }

    #[test]
    fn shared_nix_fixture_round_trips_canonically() -> Result<(), DocumentError> {
        let bytes = include_bytes!("../../../tests/abilities/fixtures/interface.json");
        let supported_features =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid test feature")]);
        let document =
            decode_canonical::<InterfaceDocument>(bytes, ABILITY_LIMITS_V1, &supported_features)?;

        assert_eq!(encode_canonical(&document)?, bytes);
        document.interface_key()?;
        Ok(())
    }
}
