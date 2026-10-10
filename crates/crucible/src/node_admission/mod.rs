//! Whole-graph admission for immutable RFC-0025 node contracts.
//!
//! [`admit_graph`] checks bounded core records, verifies referenced bytes,
//! authenticates installed and live identities through [`AdmissionEvidence`],
//! validates every node and edge, and seals complete ownership, capture, and
//! causal guarantees. [`AdmittedGraph`] is a validation seal, not native custody
//! or permission to activate. Preparation, all-owner readiness, durable world
//! publication, and execution grants remain separate host transactions.

mod capabilities;
mod error;
mod evidence;
mod extensions;
mod graph;
mod nodes;
mod policy;
mod ports;

#[cfg(any(test, feature = "test-double"))]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{
    GuaranteeProfile, HashRef, Id, NodeBinding, NodeDescriptor, OwnerBinding, Repeatability,
    WorldBinding,
};

pub use capabilities::{
    AdmittedCapabilitySelection, CAPABILITY_REQUIREMENTS_FORMAT,
    CAPABILITY_REQUIREMENTS_MEDIA_TYPE, CAPABILITY_SELECTION_FORMAT,
    CAPABILITY_SELECTION_MEDIA_TYPE, CapabilityBinding, CapabilityRequirements,
    CapabilitySelection, ComputeRequirement, GuaranteeRequirement, MAX_CAPABILITY_REQUIREMENTS,
    NodeCapabilityRequirement, OperationRequirement, TimingRequirement,
};

pub use error::{AdmissionCode, AdmissionError, AdmissionStage, AdmissionSubject, EffectCertainty};
pub use evidence::{AdmissionEvidence, AdmissionLimits, EvidenceError, QualificationClaim};
pub use extensions::{
    AdmittedExtensionApplication, AdmittedExtensionDefinition, AdmittedExtensionSet,
    ExtensionApplication, ExtensionApplicationScope, ExtensionImpact,
    ExtensionInstallationAuthority, ExtensionQualificationAuthority, ExtensionRecordKind,
    ExtensionRecordPath, ExtensionRegistration, ExtensionRegistryLimits, ExtensionSemanticContract,
    ExtensionSemanticHandler, InstalledExtensionPeerPolicy, InstalledExtensionRegistry,
};
pub use policy::{
    ConnectionDelivery, ConnectionPolicy, CoordinatorPolicy, FlowControl, InternalDependency,
    LanePolicy, LaneVisibility, ObjectState, OwnerCapturePolicy, OwnershipPolicy, PortPolicy,
    SameTimeClosure, ScenarioRequirements, StateDomain, StateObject, VisibilityConversion,
};

/// Borrows a complete resolved graph and its explicitly selected scenario contract.
#[derive(Clone, Copy)]
pub struct AdmissionRequest<'a> {
    /// Contains the complete immutable world binding selected during resolution.
    pub world: &'a WorldBinding,
    /// Contains every actual immutable node descriptor, sorted by node identity.
    pub descriptors: &'a [NodeDescriptor],
    /// Contains every actual selected node binding, sorted by node identity.
    pub bindings: &'a [NodeBinding],
    /// Contains every execution and capture owner, sorted by owner identity.
    pub owners: &'a [OwnerBinding],
    /// Specifies required guarantees and explicit weaker-contract acceptance.
    pub requirements: &'a ScenarioRequirements,
}

/// Seals a validated immutable graph without granting execution or native authority.
///
/// Instances can only be constructed by [`admit_graph`]. The seal records the
/// exact descriptors, compatibility, live admission claims, and ownership that
/// were verified; a changed realization must undergo fresh admission.
#[derive(Debug)]
pub struct AdmittedGraph {
    world: WorldBinding,
    world_hash: HashRef,
    descriptors: BTreeMap<Id, NodeDescriptor>,
    bindings: BTreeMap<Id, NodeBinding>,
    owners: BTreeMap<Id, OwnerBinding>,
    guarantees: BTreeMap<Id, GuaranteeProfile>,
    effective_repeatability: BTreeMap<Id, Repeatability>,
    world_repeatability: Repeatability,
    ownership: OwnershipPolicy,
    coordinator: CoordinatorPolicy,
    port_policies: ports::PortPolicies,
    connection_policies: BTreeMap<Id, ConnectionPolicy>,
    operating_policies: BTreeMap<Id, crate::node_scheduling::ExecutionPolicy>,
    requirements: ScenarioRequirements,
    owner_conflicts: BTreeMap<Id, BTreeSet<Id>>,
    selected_extensions: AdmittedExtensionSet,
    capability_requirements: Option<AdmittedCapabilitySelection>,
}

impl AdmittedGraph {
    /// Borrows explicit mandatory capabilities bound into the selected scenario root.
    pub fn capability_requirements(&self) -> Option<&CapabilityRequirements> {
        self.capability_requirements
            .as_ref()
            .map(AdmittedCapabilitySelection::requirements)
    }

    /// Borrows the complete original authored selection inventory sealed at admission.
    pub fn capability_selection(&self) -> Option<&AdmittedCapabilitySelection> {
        self.capability_requirements.as_ref()
    }

    /// Borrows the exact qualified extensions and their selected immutable closure.
    ///
    /// Installed but unselected definitions do not contribute to this inventory.
    /// Native capture/restore codecs must independently support and preserve this
    /// closure rather than consulting current registry defaults.
    pub fn selected_extensions(&self) -> &AdmittedExtensionSet {
        &self.selected_extensions
    }

    /// Returns the immutable complete world whose graph was admitted.
    pub fn world(&self) -> &WorldBinding {
        &self.world
    }

    /// Returns the sealed durable world identity.
    pub fn world_binding_hash(&self) -> &HashRef {
        &self.world_hash
    }

    /// Returns an admitted node descriptor by logical identity.
    pub fn descriptor(&self, id: &Id) -> Option<&NodeDescriptor> {
        self.descriptors.get(id)
    }

    /// Returns an admitted selected binding by logical identity.
    pub fn binding(&self, id: &Id) -> Option<&NodeBinding> {
        self.bindings.get(id)
    }

    /// Returns a complete admitted owner binding by owner identity.
    pub fn owner(&self, id: &Id) -> Option<&OwnerBinding> {
        self.owners.get(id)
    }

    /// Enumerates every execution and capture owner in canonical identity order.
    pub fn owners(&self) -> impl Iterator<Item = &OwnerBinding> {
        self.owners.values()
    }

    /// Enumerates all public logical nodes in canonical identity order.
    pub fn node_ids(&self) -> impl Iterator<Item = &Id> {
        self.bindings.keys()
    }

    /// Returns a node's actual selected guarantee profile before graph propagation.
    pub fn guarantees(&self, id: &Id) -> Option<&GuaranteeProfile> {
        self.guarantees.get(id)
    }

    /// Returns repeatability after all declared causal and shared-state influence.
    pub fn effective_repeatability(&self, id: &Id) -> Option<Repeatability> {
        self.effective_repeatability.get(id).copied()
    }

    /// Returns the conservative guarantee of the complete world.
    pub fn world_repeatability(&self) -> Repeatability {
        self.world_repeatability
    }

    /// Returns the verified complete domain and internal causal-path inventory.
    pub fn ownership_policy(&self) -> &OwnershipPolicy {
        &self.ownership
    }

    /// Returns the verified coordinator progress, closure, and containment policy.
    pub fn coordinator_policy(&self) -> &CoordinatorPolicy {
        &self.coordinator
    }

    /// Returns a verified port's selected lane semantics and state ownership.
    pub fn port_policy(&self, node: &Id, port: &Id) -> Option<&PortPolicy> {
        self.port_policies.get(&(node.clone(), port.clone()))
    }

    /// Returns the verified execution ceiling or complete quantized window policy.
    pub fn operating_policy(&self, node: &Id) -> Option<&crate::node_scheduling::ExecutionPolicy> {
        self.operating_policies.get(node)
    }

    /// Returns the scenario requirements and explicit acceptance bound at admission.
    pub fn requirements(&self) -> &ScenarioRequirements {
        &self.requirements
    }

    /// Returns the verified actual delivery, visibility, and custody policy.
    pub fn connection_policy(&self, connection: &Id) -> Option<&ConnectionPolicy> {
        self.connection_policies.get(connection)
    }

    /// Returns other owners sharing mutation or capture custody of any domain.
    ///
    /// These conflicts apply even when public-node execution/capture routes are
    /// disjoint. Runtime reservations must exclude conflicting owners before
    /// mutation or capture begins; distinct nonconflicting owners may progress.
    pub fn owner_conflicts(&self, owner: &Id) -> Option<&BTreeSet<Id>> {
        self.owner_conflicts.get(owner)
    }
}

/// Authenticates, validates, and seals a complete resolved node graph.
///
/// # Errors
/// Refuses malformed or oversized records, unavailable/corrupt content,
/// unauthenticated installed/live identities, unsupported selected claims,
/// incompatible edges, incomplete or conflicting ownership, unsupported exact
/// capture, unaccepted weaker modes, and unqualified zero-lookahead cycles.
/// Validation performs no modeled execution, resource preparation, or external
/// publication; its errors retain [`EffectCertainty::Absent`].
pub fn admit_graph(
    request: AdmissionRequest<'_>,
    evidence: &dyn AdmissionEvidence,
    limits: AdmissionLimits,
) -> Result<AdmittedGraph, AdmissionError> {
    let mut content = evidence::VerifiedContent::new(evidence, limits);
    nodes::check_core(&request, limits)?;
    let world_hash = request.world.identity().map_err(nodes::schema_error)?;
    content.configure_extensions(request, world_hash.clone());
    evidence::bounded_core(request.requirements, limits.maximum_core_object_bytes)?;
    let requirements_hash = crucible_node_contract::canonical::json_hash(
        "cnp.admission-requirements.v1",
        request.requirements,
    )
    .map_err(nodes::schema_error)?;
    content.qualify(
        AdmissionSubject::World,
        QualificationClaim::Scenario {
            world_binding_hash: &world_hash,
            scenario_ref: &request.world.scenario_ref,
            requirements_hash: &requirements_hash,
        },
    )?;
    let nodes::NodeSelections {
        scenario_bytes,
        guarantees,
        operating_policies,
    } = nodes::validate_nodes(&request, &mut content)?;
    let ownership: OwnershipPolicy = content.policy(&request.world.ownership_ref)?;
    let coordinator: CoordinatorPolicy = content.policy(&request.world.coordinator_contract_ref)?;
    graph::check_policy_bounds(&ownership, &coordinator, limits)?;
    let port_policies =
        ports::validate_ports(&request, &ownership, &operating_policies, &mut content)?;
    let ports::ConnectionSelections {
        edges,
        policies: connection_policies,
    } = ports::validate_connections(
        &request,
        &ownership,
        &port_policies,
        &world_hash,
        &mut content,
    )?;
    let graph::GraphGuarantees {
        effective_repeatability,
        world_repeatability,
    } = graph::validate_graph(
        &request,
        graph::GraphClaims {
            ownership: &ownership,
            coordinator: &coordinator,
            guarantees: &guarantees,
            ports: &port_policies,
            world_hash: &world_hash,
        },
        edges,
        &mut content,
    )?;

    let owner_conflicts = graph::owner_conflicts(&request, &ownership, limits)?;
    let selected_extensions = content.take_extensions();
    let capability_requirements = capabilities::check_selection(
        &request,
        &guarantees,
        &selected_extensions,
        scenario_bytes,
        &mut content,
    )?;

    Ok(AdmittedGraph {
        world: request.world.clone(),
        world_hash,
        descriptors: request
            .descriptors
            .iter()
            .map(|node| (node.id.clone(), node.clone()))
            .collect(),
        bindings: request
            .bindings
            .iter()
            .map(|binding| (binding.compatibility.node_id.clone(), binding.clone()))
            .collect(),
        owners: request
            .owners
            .iter()
            .map(|owner| (owner.owner.id.clone(), owner.clone()))
            .collect(),
        guarantees,
        effective_repeatability,
        world_repeatability,
        ownership,
        coordinator,
        port_policies,
        connection_policies,
        operating_policies,
        requirements: request.requirements.clone(),
        owner_conflicts,
        selected_extensions,
        capability_requirements,
    })
}

#[cfg(test)]
pub(crate) fn test_fixture_with_content() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::admitted_fixture_with_content()
}

#[cfg(test)]
pub(crate) fn test_model_graph_with_extension() -> AdmittedGraph {
    extensions::test_model_graph_with_extension()
}

#[cfg(test)]
pub(crate) fn test_nondeterministic_fixture_with_content()
-> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::nondeterministic_fixture_with_content()
}

#[cfg(test)]
pub(crate) fn test_restore_fixture_with_content(
    nondeterministic: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::restore_fixture_with_content(nondeterministic)
}

#[cfg(test)]
pub(crate) fn test_fixture_with_execution(
    shared_writers: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::execution_fixture_with_content(shared_writers)
}

#[cfg(test)]
pub(crate) fn test_fixture_isolated_execution(
    shared_writers: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::isolated_execution_fixture_with_content(shared_writers)
}

/// Constructs a synthetic sealed graph solely for cross-crate model tests.
///
/// Available only under the explicit `test-double` feature. The in-memory
/// qualification source authenticates fixture objects; it provides no installed
/// implementation, native authority, or operational provider qualification.
#[cfg(feature = "test-double")]
pub fn test_double_graph(nondeterministic: bool) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    if nondeterministic {
        tests::nondeterministic_fixture_with_content()
    } else {
        tests::admitted_fixture_with_content()
    }
}

#[cfg(test)]
pub(crate) fn test_fixture_host_clocks() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::host_clock_fixture_with_content()
}

#[cfg(test)]
pub(crate) fn test_fixture_host_clock_execution() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::host_clock_execution_fixture_with_content()
}

#[cfg(test)]
pub(crate) fn test_restore_fixture_host_clock_execution()
-> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::host_clock_restore_fixture_with_content()
}

#[cfg(test)]
pub(crate) fn test_fixture_host_model(
    role: &str,
    initialization: Vec<u8>,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::host_model_fixture_with_content(role, initialization)
}

#[cfg(test)]
pub(crate) fn test_fixture_host_initial_queue(
    role: &str,
    initialization: Vec<u8>,
    generation: u64,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::host_initial_queue_fixture_with_content(role, initialization, generation)
}

#[cfg(test)]
pub(crate) fn test_restore_fixture_host_model(
    role: &str,
    initialization: Vec<u8>,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::host_model_restore_fixture_with_content(role, initialization)
}

#[cfg(test)]
pub(crate) fn test_fixture_reference_device(
    executable: Vec<u8>,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    tests::reference_device_fixture_with_content(executable)
}
