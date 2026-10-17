//! Closed authored capability demands and their identity-bearing selection root.
//!
//! A requirement is a predicate over one complete installed contract; it never
//! creates support or combines facets from different implementations.
//!
//! The independently versioned selection root has this closed layout:
//!
//! ```text
//! capability-selection.v1+json
//!   format, schema_version: 1
//!   base_scenario_ref: ContentRef
//!   requirements_ref: ContentRef (capability-requirements.v1+json)
//!   bindings: [{ node: Id, compatibility_hash: HashRef }]
//! ```
//!
//! A requirements document contains sorted node demands; optional compute and
//! timing-grid values are required nullable fields. An absent document keeps
//! legacy scenario-root interpretation and serialization unchanged.

use crucible_node_contract::{
    CaptureScope, ContentRef, Continuation, ExtensionSelection, FacetSelection, HashRef, Id,
    OperatingMode, Repeatability, U64,
};
use serde::{Deserialize, Serialize};

/// Defines mandatory per-node capabilities independently of realization identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirements {
    /// Selects this closed document format.
    pub format: String,
    /// Selects edition one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Enumerates every demanded node in strictly increasing identity order.
    pub nodes: Vec<NodeCapabilityRequirement>,
}

/// Requires conjunctive capabilities from one actual selected node profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilityRequirement {
    /// Names the logical node whose complete binding must satisfy the demands.
    pub node: Id,
    /// Requires these actual advertised roles, in strictly increasing order.
    pub roles: Vec<Id>,
    /// Requires this explicitly selected timing mode and grid.
    pub timing: TimingRequirement,
    /// Requires exact selected operation facets and installed semantic support.
    pub operations: Vec<OperationRequirement>,
    /// Requires independent guarantee axes; no axis implies another.
    pub guarantees: GuaranteeRequirement,
    /// Requires explicit architecture and device interpretation when non-null.
    #[serde(deserialize_with = "required_nullable")]
    pub compute: Option<ComputeRequirement>,
    /// Requires exact directly selected semantic extensions, sorted by identifier.
    pub extensions: Vec<ExtensionSelection>,
}

/// Requires an exact mode, resolution, phase and native timing-policy identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingRequirement {
    /// Requires the actual selected operating mode.
    pub mode: OperatingMode,
    /// Requires the actual resolution, including explicit absence.
    #[serde(deserialize_with = "required_nullable")]
    pub resolution_ps: Option<U64>,
    /// Requires the actual phase, including explicit absence.
    #[serde(deserialize_with = "required_nullable")]
    pub phase_ps: Option<U64>,
    /// Binds the complete timing contract rather than a nominal mode label.
    pub policy_ref: ContentRef,
}

/// Requires one source-qualified operation with an exact selected facet edition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequirement {
    /// Names the operation whose actual implementation must be qualified.
    pub operation: Id,
    /// Requires the complete facet version, configuration, guarantees and extensions.
    pub facet: FacetSelection,
}

/// Requires independently specified preservation and repeatability guarantees.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeRequirement {
    /// Requires this exact repeatability contract.
    pub repeatability: Repeatability,
    /// Requires this exact modeled-state scope.
    pub capture_scope: CaptureScope,
    /// Requires this exact continuation contract.
    pub continuation: Continuation,
    /// Requires durable restart when true.
    pub durable_restart: bool,
    /// Requires isolated fork when true.
    pub isolated_fork: bool,
    /// Requires conditional replay when true.
    pub conditional_replay: bool,
}

/// Requires installed architectural/device semantics, independently of model names.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeRequirement {
    /// Names the exact architecture interpretation accepted by installed policy.
    pub architecture: Id,
    /// Binds the complete actual machine configuration.
    pub machine_ref: ContentRef,
    /// Binds the complete actual device map, including ABI versions and features.
    pub devices_ref: ContentRef,
}

/// Binds the authored demands and one complete resolution into scenario identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySelection {
    /// Selects the identity-bearing capability-selection root.
    pub format: String,
    /// Selects edition one.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Retains the original scenario root without replacing its semantics.
    pub base_scenario_ref: ContentRef,
    /// Commits to the exact authored capability-requirements document.
    pub requirements_ref: ContentRef,
    /// Binds every selected durable compatibility contract, in node order.
    pub bindings: Vec<CapabilityBinding>,
}

/// Commits one selected node's complete compatibility rather than individual claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBinding {
    /// Names the exact logical node.
    pub node: Id,
    /// Commits to its complete selected implementation/mode/configuration contract.
    pub compatibility_hash: HashRef,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
