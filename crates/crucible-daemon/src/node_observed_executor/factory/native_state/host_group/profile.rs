//! Regenerates a complete independent native CPU and finite storage-group profile.
//!
//! Source metadata alone supplies no native custody or readiness. The distinct
//! enrollment policy must measure every original inactive model and the actual
//! parked CPU capsule before this complete graph can be sealed.

use std::{collections::BTreeMap, rc::Rc};

use crucible::node_admission::{CoordinatorPolicy, ObjectState, OwnershipPolicy, StateObject};
use crucible_node_contract::{
    CapabilityProfile, CaptureScope, ContentRef, Continuation, Extensions, GuaranteeProfile,
    WorldBinding, canonical,
};

use super::super::super::{
    InstalledGem5ClosedProfile, InstalledNodeCatalog, InstalledNodeSelection, NodeObservedError,
    profile as host_profile, refused,
};
use super::super::profile::MixedProfile;
use super::selection::IndependentGroupSelection;
use crate::node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeScenario, ScenarioContent};

/// Holds independently regenerated source definitions for one complete mixed world.
pub(in crate::node_observed_executor::factory::native_state) struct IndependentGroupProfile {
    pub(in crate::node_observed_executor::factory::native_state) scenario: NodeScenario,
    pub(in crate::node_observed_executor::factory::native_state) native: MixedProfile,
    pub(in crate::node_observed_executor::factory::native_state) group: NodeScenario,
    pub(in crate::node_observed_executor::factory::native_state) qualification: ContentRef,
}

impl IndependentGroupProfile {
    pub(in crate::node_observed_executor::factory::native_state) fn with_capabilities(
        mut self,
        resolved: &super::super::super::ResolvedCapabilityWorld,
    ) -> Result<Self, NodeObservedError> {
        self.scenario = resolved.gem5_scenario(&self.scenario)?;
        Ok(self)
    }

    /// Regenerates all source definitions without accepting portable profile bodies.
    ///
    /// # Errors
    /// Refuses unsupported source selections, unenrolled immutable inputs,
    /// incompatible coordinate grammar, aliased ownership or excessive content.
    pub(in crate::node_observed_executor::factory::native_state) fn build(
        installed: Rc<InstalledGem5ClosedProfile>,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
    ) -> Result<Self, NodeObservedError> {
        let selected = IndependentGroupSelection::new(selections)?;
        let native = MixedProfile::build_public(installed, &catalog.host_identity, "x86_64")?;
        let group = host_profile::build_world(
            selected.selections,
            &catalog.host_identity,
            &catalog.device_identity,
            &catalog.artifacts,
        )?
        .scenario;
        if group.world.connections[0].producer.node_id != selected.source.node
            || group.world.connections[0].consumer.node_id != selected.block.node
        {
            return Err(refused(
                "regenerated group connection differs from original source and Block selection",
            ));
        }
        let (scenario, qualification) = compose(&native.scenario, &group)?;

        Ok(Self {
            scenario,
            native,
            group,
            qualification,
        })
    }
}

fn original_policy<T: serde::de::DeserializeOwned>(
    scenario: &NodeScenario,
    reference: &ContentRef,
) -> Result<T, NodeObservedError> {
    let object = scenario
        .content
        .iter()
        .find(|object| &object.reference == reference)
        .ok_or_else(|| refused("regenerated source policy body is absent"))?;
    reference.verify(&object.bytes)?;
    Ok(serde_json::from_value(canonical::parse_json(
        &object.bytes,
        MAX_NODE_SCENARIO_BYTES,
    )?)?)
}

fn compose(
    native: &NodeScenario,
    group: &NodeScenario,
) -> Result<(NodeScenario, ContentRef), NodeObservedError> {
    if native.descriptors.len() != 2
        || group.descriptors.len() != 2
        || !native.world.connections.is_empty()
        || group.world.connections.len() != 1
        || native.world.ordering_profile != "superdense-v1"
        || group.world.ordering_profile != native.world.ordering_profile
        || !native.world.extensions.is_empty()
        || !group.world.extensions.is_empty()
    {
        return Err(refused("independent group source topology is unsupported"));
    }
    for descriptor in &group.descriptors {
        if native
            .descriptors
            .iter()
            .any(|original| original.id == descriptor.id)
        {
            return Err(refused(
                "independent source node aliases the original CPU world",
            ));
        }
    }
    for owner in &group.owners {
        if native
            .owners
            .iter()
            .any(|original| original.owner.id == owner.owner.id)
        {
            return Err(refused(
                "independent source owner aliases the original CPU world",
            ));
        }
    }

    // The source roster is bounded before copying any immutable bodies. Repeated
    // definitions are charged conservatively here, then exact duplicates dedup.
    let mut total_bytes = 0usize;
    let mut entries = 0usize;
    for object in native.content.iter().chain(&group.content) {
        entries = entries
            .checked_add(1)
            .ok_or_else(|| refused("source object count overflow"))?;
        total_bytes = total_bytes
            .checked_add(object.bytes.len())
            .ok_or_else(|| refused("source content credit overflow"))?;
        if entries > 16_384
            || object.bytes.len() > 4 * 1024 * 1024
            || total_bytes > MAX_NODE_SCENARIO_BYTES
        {
            return Err(refused(
                "independent group exceeds original source content credit",
            ));
        }
        object.reference.verify(&object.bytes)?;
    }
    let mut content: BTreeMap<String, ScenarioContent> = BTreeMap::new();
    for object in native.content.iter().chain(&group.content) {
        match content.get(&object.reference.hash.digest) {
            Some(original)
                if original.reference != object.reference || original.bytes != object.bytes =>
            {
                return Err(refused(
                    "independent source content has a foreign full reference or body",
                ));
            }
            Some(_) => {}
            None => {
                content.insert(object.reference.hash.digest.clone(), object.clone());
            }
        }
    }
    let qualification = host_profile::put_json(
        &mut content,
        &serde_json::json!({
            "schema":"crucible.installed-independent-host-group-qualification.v1",
            "native_source_world":native.world.identity()?,
            "group_source_world":group.world.identity()?,
            "native_scope":"unchanged source-installed closed x86 CPU and portless integer Clock",
            "group_scope":"independently installed finite Script/Block model bodies, input/port/connection policy and original immutable artifacts",
            "complete_world":"actual original inactive resource enrollment and one all-owner barrier required",
            "whole_world_capture":false,"whole_world_continuation":false,"whole_world_durable_restart":false,"isolated_fork":false,
            "individual_model_contracts":"original source models and immutable inputs remain exact; the new public preparation facade selects live-only guarantees and refuses old capture codecs",
            "cpu_input_connections":false,"external_inputs":false,
            "common_microstep_credit":"exact unchanged installed native authority ceiling; the disconnected finite Host source introduces no same-time cycle",
            "original_group_preparation":crucible::node_adapters::HOST_PUBLIC_OWNED_MODEL_PREPARATION_SPECIFICATION,
        }),
    )?;

    let mut ownership: OwnershipPolicy = original_policy(native, &native.world.ownership_ref)?;
    let group_ownership: OwnershipPolicy = original_policy(group, &group.world.ownership_ref)?;
    ownership.domains.extend(group_ownership.domains);
    ownership.objects.extend(group_ownership.objects);
    ownership
        .internal_dependencies
        .extend(group_ownership.internal_dependencies);
    ownership
        .capture_owners
        .extend(group_ownership.capture_owners);
    // Public initial preparation adds original session/readiness custody that
    // the old model codec cannot preserve. Declare it in the complete realized
    // inventory while explicitly excluding capture of this selected facade.
    for node in &group.descriptors {
        ownership.objects.push(StateObject {
            id: crucible_node_contract::Id::new(format!("object/{}/public-preparation", node.id))?,
            node_ids: vec![node.id.clone()],
            future_affecting: true,
            state: ObjectState::OutsideScope,
        });
    }
    ownership
        .domains
        .sort_by(|left, right| left.id.cmp(&right.id));
    ownership
        .objects
        .sort_by(|left, right| left.id.cmp(&right.id));
    ownership
        .capture_owners
        .sort_by(|left, right| left.owner_id.cmp(&right.owner_id));
    if ownership
        .domains
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
        || ownership
            .objects
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        || ownership
            .capture_owners
            .windows(2)
            .any(|pair| pair[0].owner_id == pair[1].owner_id)
        || !ownership.internal_dependencies.is_empty()
    {
        return Err(refused(
            "independent group state inventory aliases another source or declares coupled ownership",
        ));
    }
    ownership.inventory_proof_ref = qualification.clone();
    for owner in &mut ownership.capture_owners {
        if group
            .owners
            .iter()
            .any(|original| original.owner.id == owner.owner_id)
        {
            owner.complete_model = false;
            owner.unchanged_cut = false;
            owner.exact_continuation = false;
            owner.durable_restart = false;
            owner.isolated_fork = false;
            owner.cut_procedure_ref = qualification.clone();
        }
    }
    let ownership_ref = host_profile::put_json(&mut content, &ownership)?;
    let native_coordinator: CoordinatorPolicy =
        original_policy(native, &native.world.coordinator_contract_ref)?;
    let group_coordinator: CoordinatorPolicy =
        original_policy(group, &group.world.coordinator_contract_ref)?;
    if !native_coordinator.external_inputs.is_empty()
        || !group_coordinator.external_inputs.is_empty()
        || !native_coordinator.same_time_closure.is_empty()
        || !group_coordinator.same_time_closure.is_empty()
    {
        return Err(refused(
            "independent source declares an unsupported input or same-time cycle",
        ));
    }
    let coordinator_ref = host_profile::put_json(
        &mut content,
        &CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: qualification.clone(),
            // The actual native certificate authenticates this exact ceiling.
            // The independent finite source has no coupled same-time cycle;
            // its addition cannot change the original native authority budget.
            maximum_microsteps_per_instant: native_coordinator.maximum_microsteps_per_instant,
            same_time_closure: Vec::new(),
            operational_policy_ref: qualification.clone(),
            external_inputs: Vec::new(),
        },
    )?;
    let mut descriptors = native.descriptors.clone();
    descriptors.extend(group.descriptors.clone());
    descriptors.sort_by(|left, right| left.id.cmp(&right.id));
    let mut compatibility = native.compatibility.clone();
    for original in &group.compatibility {
        let mut selected = original.clone();
        let mut capabilities: CapabilityProfile =
            original_policy(group, &original.capabilities_ref)?;
        capabilities
            .facets
            .retain(|facet| facet.id.as_str() == "host/exact-v1");
        if capabilities.facets.len() != 1 {
            return Err(refused(
                "original group lacks its unique qualified exact facade",
            ));
        }
        let mut guarantees: GuaranteeProfile = original_policy(group, &original.guarantees_ref)?;
        guarantees.capture_scope = CaptureScope::None;
        guarantees.continuation = Continuation::Unsupported;
        guarantees.durable_restart = false;
        guarantees.isolated_fork = false;
        guarantees.conditional_replay = false;
        guarantees.limitations_ref = qualification.clone();
        selected.guarantees_ref = host_profile::put_json(&mut content, &guarantees)?;
        for facet in &mut capabilities.facets {
            facet.guarantees_ref = selected.guarantees_ref.clone();
        }
        capabilities.requirements_ref = qualification.clone();
        selected.operating_contract.facets = capabilities.facets.clone();
        selected.capabilities_ref = host_profile::put_json(&mut content, &capabilities)?;
        selected.qualification_refs.push(qualification.clone());
        selected.qualification_refs.sort();
        selected.qualification_refs.dedup();
        let descriptor = group
            .descriptors
            .iter()
            .find(|descriptor| descriptor.id == selected.node_id)
            .ok_or_else(|| refused("original selected model descriptor is absent"))?;
        selected.profile_ref = host_profile::put_json(
            &mut content,
            &serde_json::json!({
                "schema_version":1,"descriptor":descriptor,
                "implementation":selected.implementation,
                "operating_contract":selected.operating_contract,
                "capabilities":capabilities,"guarantees":guarantees,
            }),
        )?;
        compatibility.push(selected);
    }
    compatibility.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let mut owners = native.owners.clone();
    owners.extend(group.owners.clone());
    // Owner participants commit to the narrowed selected facade, while the
    // separately retained source owner records continue to bind its old tuple.
    for owner in &mut owners {
        for participant in &mut owner.node_bindings {
            let selected = compatibility
                .iter()
                .find(|binding| binding.node_id == participant.node_id)
                .ok_or_else(|| refused("selected actual owner participant is absent"))?;
            participant.binding_hash = selected.identity()?;
        }
    }
    owners.sort_by(|left, right| left.owner.id.cmp(&right.owner.id));
    let initialization_ref = host_profile::put_json(
        &mut content,
        &descriptors
            .iter()
            .map(|node| (&node.id, &node.initialization_ref))
            .collect::<Vec<_>>(),
    )?;
    let scenario_ref = host_profile::put_json(
        &mut content,
        &serde_json::json!({
            "schema":"crucible.installed-independent-host-group-scenario.v1",
            "native":native.world.scenario_ref,"group":group.world.scenario_ref,
            "qualification":qualification,"cross_group_connections":[],"external_inputs":[],
        }),
    )?;
    let mut requirements = group.requirements.clone();
    requirements.exact_capture = false;
    requirements.exact_continuation = false;
    requirements.durable_restart = false;
    requirements
        .accepted_limited_state_nodes
        .extend(native.requirements.accepted_limited_state_nodes.clone());
    requirements
        .accepted_limited_state_nodes
        .extend(group.descriptors.iter().map(|node| node.id.clone()));
    requirements.accepted_limited_state_nodes.sort();
    requirements.accepted_limited_state_nodes.dedup();
    let scenario = NodeScenario {
        format: "crucible.node-scenario".into(),
        version: 1,
        world: WorldBinding {
            schema_version: 1,
            scenario_ref,
            node_bindings: compatibility
                .iter()
                .map(|binding| {
                    Ok(crucible_node_contract::NodeBindingRef {
                        node_id: binding.node_id.clone(),
                        binding_hash: binding.identity()?,
                        extensions: Extensions::new(),
                    })
                })
                .collect::<Result<_, crucible_node_contract::ContractError>>()?,
            connections: group.world.connections.clone(),
            ownership_ref,
            coordinator_contract_ref: coordinator_ref,
            ordering_profile: "superdense-v1".into(),
            initialization_ref,
            extensions: Extensions::new(),
        },
        descriptors,
        compatibility,
        owners,
        requirements,
        content: content.into_values().collect(),
    };
    scenario.canonical_bytes()?;
    Ok((scenario, qualification))
}
