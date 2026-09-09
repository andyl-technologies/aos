//! Public ability interfaces and provider-owned implementation declarations.
//!
//! Public descriptors contain caller-visible semantics. Provider lower
//! requirements, constructors, handlers, and implementation authority remain
//! in separate implementation records so they do not alter the public API by
//! accident.

use std::collections::BTreeMap;

use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::identity::{InterfaceKey, InterfaceName, LocalKey};
use crate::plan::OperationFamily;
use crate::schema::ValueSchema;
use crate::value::{ArtifactReference, ResourceLifetime};

/// Identifies one exact immutable guarantee semantic.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeKey {
    /// Names the guarantee within its namespace.
    pub name: InterfaceName,
    /// Identifies the guarantee contract version.
    pub version: std::num::NonZeroU32,
    /// Identifies the exact authenticated semantic descriptor.
    pub descriptor: Sha256Digest,
}

/// Identifies when a value becomes available to a consumer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValuePhase {
    /// Exists during pure configuration evaluation.
    Evaluation,
    /// Exists after immutable artifact construction.
    Artifact,
    /// Exists after provider selection and pure plan construction.
    Planning,
    /// Exists after runtime admission and handle acquisition.
    Admission,
    /// Exists after an admitted effect settles successfully.
    Runtime,
    /// Exists only after an explicit observation establishes it.
    Observation,
}

/// Defines who may inspect a method result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueVisibility {
    /// May appear in public package and interface views.
    Public,
    /// May appear only in authorized deployment views.
    Protected,
    /// Remains restricted to its producing provider and runtime controller.
    Private,
}

/// Describes one typed output port of a public interface or method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDescriptor {
    /// Defines the exact output value shape.
    pub schema: ValueSchema,
    /// States when the output becomes available.
    pub phase: ValuePhase,
    /// Defines who may inspect the output.
    pub visibility: ValueVisibility,
    /// Bounds the output by the lifetime of its underlying resource.
    pub lifetime: ResourceLifetime,
}

/// Defines how an indeterminate method outcome can be resolved.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndeterminateSemantics {
    /// A named provider observation can establish the actual outcome.
    Reconcile,
    /// Automatic recovery is unavailable and operator intervention is needed.
    InterventionRequired,
}

/// Defines caller-visible completion and failure semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeSemantics {
    /// Defines evidence returned after successful completion.
    pub completion_evidence: ValueSchema,
    /// States whether the provider can prove some rejections precede effects.
    pub supports_rejected_before_effect: bool,
    /// Defines the public handling promised after an ambiguous effect.
    pub indeterminate: IndeterminateSemantics,
}

/// Describes lifecycle properties shared by an interface's resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSemantics {
    /// States whether resources retain logical identity across revisions.
    pub stable_resource_identity: bool,
    /// States whether disabling an instance releases ephemeral resources.
    pub releases_ephemeral_on_disable: bool,
    /// States whether persistent state is retained by default.
    pub retains_persistent_by_default: bool,
    /// Names a separately authorized deletion operation, when supported.
    pub persistent_delete_method: Option<LocalKey>,
}

/// Describes one caller-visible interface method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MethodDescriptor {
    /// Retains the method's high-level semantic operation family.
    pub operation_family: OperationFamily,
    /// Defines the closed parameter record.
    pub parameters: ValueSchema,
    /// Names the resource interface targeted by the method.
    pub target_resource: InterfaceName,
    /// Defines output ports in canonical name order.
    pub outputs: BTreeMap<LocalKey, OutputDescriptor>,
    /// Names resource operations the method may request in canonical order.
    pub permitted_operations: Vec<LocalKey>,
    /// Names exact guarantees callers may require in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Defines caller-visible completion and ambiguous-outcome behavior.
    pub outcome: OutcomeSemantics,
}

/// Defines one exact public ability interface without provider internals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceDescriptor {
    /// Names the public interface.
    pub name: InterfaceName,
    /// Identifies the caller-visible ABI family.
    pub abi: std::num::NonZeroU32,
    /// Defines one contribution or request value.
    pub request: ValueSchema,
    /// Defines aggregate caller-visible outputs.
    pub outputs: BTreeMap<LocalKey, OutputDescriptor>,
    /// Defines callable methods in canonical name order.
    pub methods: BTreeMap<LocalKey, MethodDescriptor>,
    /// Defines interface-wide resource lifecycle behavior.
    pub lifecycle: LifecycleSemantics,
    /// Names interface-wide exact guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
}

/// Defines the ownership scope of one contribution aggregate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggregationScope {
    /// Aggregates independently for every provider instance.
    ProviderInstance,
}

/// Defines how a provider combines authorized contributions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationContract {
    /// Selects the ownership scope of the aggregate.
    pub scope: AggregationScope,
    /// Names the contribution-key convention.
    pub key: LocalKey,
    /// Rejects two contributors claiming one exclusive slot.
    pub reject_slot_collisions: bool,
    /// Names an explicit field-level merge contract, when one is supported.
    pub merge_contract: Option<Sha256Digest>,
}

/// Classifies a lower-interface requirement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementStrength {
    /// Must bind or become a discharged deployment obligation.
    Required,
    /// May be omitted only with its declared fallback behavior.
    Advisory,
}

/// Defines a provider implementation's named lower-interface requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementDeclaration {
    /// Names the requirement inside the provider implementation.
    pub alias: LocalKey,
    /// Lists exact accepted interface descriptors in canonical order.
    pub accepted_interfaces: Vec<InterfaceKey>,
    /// Names required methods in canonical order.
    pub methods: Vec<LocalKey>,
    /// Names required guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Defines whether omission is allowed.
    pub strength: RequirementStrength,
    /// Defines an explicit fallback result for an advisory requirement.
    pub fallback: Option<ValueSchema>,
}

/// Identifies how a provider realizes one exported interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ImplementationKind {
    /// Uses authenticated Nix entry points to construct finite child graphs.
    PureComposition {
        /// Names the pure composition entry point.
        compose_entry: LocalKey,
        /// Names the pure transition entry point.
        transition_entry: LocalKey,
    },
    /// Terminates composition at an exact trusted adapter or cataloged helper.
    TerminalHandler {
        /// Names the handler in the package's handler catalog.
        handler: LocalKey,
    },
}

/// Declares one provider's implementation separately from its public interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderImplementation {
    /// Identifies the exact public interface implemented.
    pub interface: InterfaceKey,
    /// Identifies the authenticated implementation artifact.
    pub artifact: ArtifactReference,
    /// Lists the bounded lower-interface discovery vocabulary.
    pub requirements: Vec<RequirementDeclaration>,
    /// Defines how recursive composition terminates or expands.
    pub implementation: ImplementationKind,
    /// Names provider-owned resource kinds in canonical order.
    pub owns_resource_kinds: Vec<InterfaceName>,
}

/// Pins one exact provider implementation used by a binding or environment root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderImplementationReference {
    /// Identifies the canonical provider implementation descriptor.
    pub descriptor: Sha256Digest,
    /// Identifies the retained executable implementation artifact.
    pub artifact: ArtifactReference,
    /// Names a terminal handler within that artifact, when applicable.
    pub handler: Option<LocalKey>,
}

/// Declares one package export and its aggregation boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDeclaration {
    /// Names the export within the package.
    pub name: LocalKey,
    /// Identifies the exact public interface contract.
    pub interface: InterfaceKey,
    /// Defines contribution aggregation, when the export accepts contributions.
    pub aggregation: Option<AggregationContract>,
    /// Identifies the separate provider implementation.
    pub implementation: Sha256Digest,
}

/// Collects a package's provider implementations and handler catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImplementation {
    /// Lists provider implementations in canonical interface order.
    pub providers: Vec<ProviderImplementation>,
    /// Maps handler names to exact constrained handler artifacts.
    pub handlers: BTreeMap<LocalKey, HandlerDescriptor>,
}

/// Describes one constrained terminal handler artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerDescriptor {
    /// Identifies the exact executable artifact and retained closure.
    pub artifact: ArtifactReference,
    /// Names the entry point relative to that artifact.
    pub entry_point: String,
    /// Defines the handler's closed argument schema.
    pub arguments: ValueSchema,
    /// Defines the handler's closed result schema.
    pub result: ValueSchema,
}
