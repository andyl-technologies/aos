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
    pub(in crate::node_observed_executor::factory::native_state) native: Rc<MixedProfile>,
    pub(in crate::node_observed_executor::factory::native_state) group: NodeScenario,
    pub(in crate::node_observed_executor::factory::native_state) qualification: ContentRef,
    pub(in crate::node_observed_executor::factory::native_state) preserving: bool,
    pub(super) metadata: Option<super::metadata::MetadataClosure>,
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
        let (scenario, qualification) = compose(&native.scenario, &group, false)?;

        Ok(Self {
            scenario,
            native: Rc::new(native),
            group,
            qualification,
            preserving: false,
            metadata: None,
        })
    }

    /// Regenerates a distinct complete native and Host preparation-bearing source.
    ///
    /// # Errors
    /// Refuses another selected family, missing immutable inputs or unsupported
    /// complete codec, ownership or original source capability geometry.
    pub(in crate::node_observed_executor::factory::native_state) fn build_preserving(
        installed: Rc<InstalledGem5ClosedProfile>,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
    ) -> Result<Self, NodeObservedError> {
        Self::build_preserving_scoped(installed, catalog, selections, &catalog.artifacts)
    }

    /// Regenerates the same selected source using independently enrolled archive inputs.
    pub(in crate::node_observed_executor::factory::native_state) fn build_preserving_scoped(
        installed: Rc<InstalledGem5ClosedProfile>,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        artifacts: &BTreeMap<String, super::super::super::InstalledIoArtifact>,
    ) -> Result<Self, NodeObservedError> {
        let selected = IndependentGroupSelection::new_preserving(selections)?;
        let native =
            MixedProfile::build_public_preserving(installed, &catalog.host_identity, "x86_64")?;
        let group = host_profile::build_world(
            selected.selections,
            &catalog.host_identity,
            &catalog.device_identity,
            artifacts,
        )?
        .scenario;
        if group.world.connections.len() != 1
            || group.world.connections[0].producer.node_id != selected.source.node
            || group.world.connections[0].consumer.node_id != selected.block.node
        {
            return Err(refused("preserving original storage connection differs"));
        }
        let (mut scenario, qualification) = compose(&native.scenario, &group, true)?;
        let metadata = super::metadata::MetadataClosure::install(&mut scenario, &native, catalog)?;
        Ok(Self {
            scenario,
            native: Rc::new(native),
            group,
            qualification,
            preserving: true,
            metadata: Some(metadata),
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
    preserving: bool,
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
    let mut qualification_body = serde_json::json!({
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
    });
    if preserving {
        qualification_body["schema"] =
            "crucible.installed-independent-host-group-preservation-qualification.v1".into();
        qualification_body["whole_world_capture"] = true.into();
        qualification_body["whole_world_continuation"] = true.into();
        qualification_body["whole_world_durable_restart"] = true.into();
        qualification_body["individual_model_contracts"] = "unchanged source-installed native CPU/Clock preservation and finite Host model state, plus actual complete original public preparation and fresh restoring ownership under selected Host9; complete signed original input/ACK/payload/FIFO/coordinator closure required".into();
        qualification_body["owned_model_continuation"] =
            crucible::node_adapters::HOST_PUBLIC_OWNED_MODEL_CONTINUATION_SPECIFICATION.into();
        qualification_body["consistent_cut"] = "the original transfer FIFO capture owner includes both original endpoint capture owners; native9 model histories, full runtime staged input/ACK and complete coordinator pending delivery remain jointly authenticated".into();
    }
    let qualification = host_profile::put_json(&mut content, &qualification_body)?;

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
    if preserving {
        qualify_transfer_cut(group, &mut ownership)?;
    }
    // Public initial preparation adds original session/readiness custody that
    // the old model codec cannot preserve. Declare it in the complete realized
    // inventory while explicitly excluding capture of this selected facade.
    for node in &group.descriptors {
        ownership.objects.push(StateObject {
            id: crucible_node_contract::Id::new(format!("object/{}/public-preparation", node.id))?,
            node_ids: vec![node.id.clone()],
            future_affecting: true,
            state: if preserving {
                let binding = group
                    .compatibility
                    .iter()
                    .find(|binding| binding.node_id == node.id)
                    .ok_or_else(|| refused("preserving public model binding is absent"))?;
                ownership
                    .capture_owners
                    .iter()
                    .find(|owner| owner.owner_id == binding.capture_owner.id)
                    .ok_or_else(|| refused("preserving public model capture owner is absent"))?;
                // Native model custody and the original transfer FIFO are distinct
                // domains of the same capture owner. Preparation belongs to the
                // exact original model object, while the FIFO stays unchanged.
                ObjectState::Mutable {
                    domain_id: model_preparation_domain(
                        &ownership,
                        &node.id,
                        &binding.capture_owner.id,
                        &binding.capture_owner.state_domain_ids,
                    )?,
                }
            } else {
                ObjectState::OutsideScope
            },
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
            owner.complete_model = preserving;
            owner.unchanged_cut = preserving;
            owner.exact_continuation = preserving;
            owner.durable_restart = preserving;
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
        capabilities.facets.retain(|facet| {
            facet.id.as_str() == "host/exact-v1"
                || preserving && facet.id.as_str() == "host/preservation-v1"
        });
        if capabilities.facets.len() != if preserving { 2 } else { 1 } {
            return Err(refused(
                "original group lacks its unique qualified exact facade",
            ));
        }
        let mut guarantees: GuaranteeProfile = original_policy(group, &original.guarantees_ref)?;
        guarantees.capture_scope = if preserving {
            CaptureScope::CompleteModel
        } else {
            CaptureScope::None
        };
        guarantees.continuation = if preserving {
            Continuation::Exact
        } else {
            Continuation::Unsupported
        };
        guarantees.durable_restart = preserving;
        guarantees.isolated_fork = false;
        guarantees.conditional_replay = false;
        guarantees.limitations_ref = qualification.clone();
        selected.guarantees_ref = host_profile::put_json(&mut content, &guarantees)?;
        for facet in &mut capabilities.facets {
            facet.guarantees_ref = selected.guarantees_ref.clone();
            if preserving && facet.id.as_str() == "host/preservation-v1" {
                facet.id = crucible_node_contract::Id::new(
                    crucible::node_adapters::HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE,
                )?;
            }
        }
        if preserving {
            let schema = crucible::node_adapters::host_public_owned_model_continuation_schema()
                .map_err(|error| refused(&error.reason))?;
            if host_profile::put(
                &mut content,
                crucible::node_adapters::HOST_PUBLIC_OWNED_MODEL_CONTINUATION_SPECIFICATION
                    .as_bytes()
                    .to_vec(),
                "text/plain",
            )? != schema.definition
            {
                return Err(refused("preserving public model schema body differs"));
            }
            selected.implementation.formats.push(schema);
            selected
                .implementation
                .formats
                .sort_by(|left, right| left.id.cmp(&right.id));
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
    let mut scenario_body = serde_json::json!({
            "schema":"crucible.installed-independent-host-group-scenario.v1",
            "native":native.world.scenario_ref,"group":group.world.scenario_ref,
            "qualification":qualification,"cross_group_connections":[],"external_inputs":[],
    });
    if preserving {
        scenario_body["schema"] =
            "crucible.installed-independent-host-group-preservation-scenario.v1".into();
    }
    let scenario_ref = host_profile::put_json(&mut content, &scenario_body)?;
    let mut requirements = group.requirements.clone();
    requirements.exact_capture = preserving;
    requirements.exact_continuation = preserving;
    requirements.durable_restart = preserving;
    requirements
        .accepted_limited_state_nodes
        .extend(native.requirements.accepted_limited_state_nodes.clone());
    if !preserving {
        requirements
            .accepted_limited_state_nodes
            .extend(group.descriptors.iter().map(|node| node.id.clone()));
    }
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

fn model_preparation_domain(
    ownership: &OwnershipPolicy,
    node: &crucible_node_contract::Id,
    capture_owner: &crucible_node_contract::Id,
    captured_domains: &[crucible_node_contract::Id],
) -> Result<crucible_node_contract::Id, NodeObservedError> {
    let mut originals = ownership.objects.iter().filter(|object| &object.id == node);
    let original = originals
        .next()
        .ok_or_else(|| refused("preserving public model original state object is absent"))?;
    let ObjectState::Mutable { domain_id } = &original.state else {
        return Err(refused(
            "preserving public model original object is not mutable",
        ));
    };
    if originals.next().is_some()
        || original.node_ids.as_slice() != std::slice::from_ref(node)
        || !original.future_affecting
        || !captured_domains.contains(domain_id)
        || ownership
            .domains
            .iter()
            .filter(|domain| &domain.id == domain_id)
            .count()
            != 1
        || !ownership.domains.iter().any(|domain| {
            &domain.id == domain_id
                && &domain.capture_owner_id == capture_owner
                && domain.future_affecting
        })
    {
        return Err(refused(
            "preserving public model original domain or ownership differs",
        ));
    }
    Ok(domain_id.clone())
}

fn qualify_transfer_cut(
    group: &NodeScenario,
    ownership: &mut OwnershipPolicy,
) -> Result<(), NodeObservedError> {
    let [connection] = group.world.connections.as_slice() else {
        return Err(refused(
            "preserving group requires its original single transfer",
        ));
    };
    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(2)
        .map_err(|_| refused("preserving original transfer dependency credit is unavailable"))?;
    for endpoint in [&connection.producer, &connection.consumer] {
        let mut bindings = group
            .compatibility
            .iter()
            .filter(|binding| binding.node_id == endpoint.node_id);
        let binding = bindings
            .next()
            .ok_or_else(|| refused("preserving original transfer endpoint binding is absent"))?;
        if bindings.next().is_some()
            || !group.owners.iter().any(|owner| {
                owner.owner == binding.capture_owner
                    && owner.owner.participant_ids.as_slice()
                        == std::slice::from_ref(&endpoint.node_id)
            })
            || ownership
                .capture_owners
                .iter()
                .filter(|owner| owner.owner_id == binding.capture_owner.id)
                .count()
                != 1
        {
            return Err(refused(
                "preserving original transfer endpoint owner differs",
            ));
        }
        if binding.capture_owner.id != connection.capture_owner_id {
            dependencies.push(binding.capture_owner.id.clone());
        }
    }
    let mut policies = ownership
        .capture_owners
        .iter_mut()
        .filter(|owner| owner.owner_id == connection.capture_owner_id);
    let policy = policies
        .next()
        .ok_or_else(|| refused("preserving original transfer capture owner is absent"))?;
    if policies.next().is_some() {
        return Err(refused(
            "preserving original transfer capture owner is ambiguous",
        ));
    }
    policy
        .dependencies
        .try_reserve_exact(dependencies.len())
        .map_err(|_| refused("preserving original transfer cut credit is unavailable"))?;
    policy.dependencies.extend(dependencies);
    policy.dependencies.sort();
    policy.dependencies.dedup();
    Ok(())
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
