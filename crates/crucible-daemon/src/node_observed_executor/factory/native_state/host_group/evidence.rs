//! Conjoins original source-installed native and storage evidence in one full world.
//!
//! The old clock-only native policy remains unchanged. This distinct policy
//! admits only the regenerated disconnected Script/Block connection and all
//! four originally enrolled inactive resources. Source metadata never supplies
//! the native certificate, host model, binding or readiness token.

use std::rc::Rc;

use crucible::{
    node_adapters::{HostModel, HostModelQualification, gem5::Gem5PreparationQualification},
    node_admission::{AdmissionEvidence, AdmittedGraph, EvidenceError, QualificationClaim},
    node_contract::{EffectKnowledge, OperationFailure},
};
use crucible_node_contract::{
    ContentRef, HashRef, Id, ImplementationIdentity, NodeBinding, NodeDescriptor, SchemaRef,
    canonical,
};
use crucible_node_provider::gem5::{Gem5ExactAuthority, Gem5NativeProcess};

use super::super::super::{NodeObservedError, refused, trust::InstalledEvidence};
use super::super::evidence::{MixedEvidence, MixedPreparedQualification};
use super::profile::IndependentGroupProfile;

pub(in crate::node_observed_executor::factory::native_state) struct IndependentGroupEvidence {
    profile: Rc<IndependentGroupProfile>,
    bindings: Vec<NodeBinding>,
    native: Rc<MixedEvidence>,
    host: InstalledEvidence,
    original_host_bindings: Vec<NodeBinding>,
    original_native_graph: Rc<AdmittedGraph>,
}

impl IndependentGroupEvidence {
    pub(super) fn metadata(&self) -> Result<&super::metadata::MetadataClosure, EvidenceError> {
        self.authenticate_all()?;
        self.profile
            .metadata
            .as_ref()
            .ok_or_else(|| error("live group has no selected preserving metadata codec"))
    }

    pub(super) fn authenticate_continuation_scope(
        &self,
        graph: &AdmittedGraph,
        source: &crucible::node_state::AuthenticatedNativeSource<'_>,
        target: &crucible::node_contract::ActivationRecord,
    ) -> Result<(), crucible::node_state::StateError> {
        let runtime = source.runtime();
        if !self.profile.preserving
            || target.world_binding_hash != *graph.world_binding_hash()
            || target.boundary != runtime.capture_cut
            || target.owners.len() != 4
            || target.generation.get()
                != runtime
                    .source_activation
                    .generation
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| super::source::error("group world generation exhausted"))?
            || target.activation_id == runtime.source_activation.activation_id
            || target
                .owners
                .windows(2)
                .any(|pair| pair[0].owner >= pair[1].owner)
            || target.owners.iter().any(|fresh| {
                !runtime.source_activation.owners.iter().any(|original| {
                    fresh.owner == original.owner
                        && fresh.incarnation != original.incarnation
                        && original.generation.get().checked_add(1) == Some(fresh.generation.get())
                })
            })
            || target.owners.iter().any(|fresh| {
                !self.bindings.iter().any(|binding| {
                    binding.compatibility.execution_owner.id == fresh.owner
                        && binding.authority.incarnation_id == fresh.incarnation
                        && binding.authority.owner_generation == fresh.generation
                        && graph.binding(&binding.compatibility.node_id) == Some(binding)
                })
            })
        {
            return Err(super::source::error(
                "installed group continuation has no complete fresh owner mapping",
            ));
        }
        self.authenticate_all().map_err(super::source::error)?;
        super::source::authenticate(
            &self.profile,
            graph,
            runtime,
            &source.archive().scheduling_snapshot()?,
            source.content(),
        )
    }

    /// Retains actual original enrollment predicates and both independently built scopes.
    pub(in crate::node_observed_executor::factory::native_state) fn new(
        profile: Rc<IndependentGroupProfile>,
        bindings: Vec<NodeBinding>,
        native: Rc<MixedEvidence>,
        host: InstalledEvidence,
        original_host_bindings: Vec<NodeBinding>,
        original_native_graph: Rc<AdmittedGraph>,
    ) -> Result<Self, NodeObservedError> {
        if bindings.len() != 4
            || original_host_bindings.len() != 2
            || original_host_bindings
                .iter()
                .map(|binding| &binding.compatibility)
                .ne(profile.group.compatibility.iter())
            || bindings
                .iter()
                .map(|binding| &binding.compatibility)
                .ne(profile.scenario.compatibility.iter())
            || original_native_graph.world_binding_hash()
                != &profile.native.scenario.world.identity()?
        {
            return Err(refused(
                "complete group enrollment differs from original source scopes",
            ));
        }
        let result = Self {
            profile,
            bindings,
            native,
            host,
            original_host_bindings,
            original_native_graph,
        };
        result
            .authenticate_all()
            .map_err(|error| refused(&error.message))?;
        Ok(result)
    }

    pub(in crate::node_observed_executor::factory::native_state) fn bindings(
        &self,
    ) -> &[NodeBinding] {
        &self.bindings
    }

    fn is_native(&self, node: &Id) -> bool {
        self.profile
            .native
            .scenario
            .descriptors
            .iter()
            .any(|descriptor| &descriptor.id == node)
    }

    pub(super) fn known_immutable_reference(&self, reference: &ContentRef) -> bool {
        self.profile
            .scenario
            .content
            .iter()
            .any(|object| &object.reference == reference)
            || self.native.known_immutable_reference(reference)
            || self.host.known_immutable_reference(reference)
    }

    fn original_host_binding(&self, selected: &NodeBinding) -> Result<&NodeBinding, EvidenceError> {
        if !self.bindings.contains(selected) {
            return Err(error("model facade was never actually enrolled"));
        }
        let original = self
            .original_host_bindings
            .iter()
            .find(|binding| binding.compatibility.node_id == selected.compatibility.node_id)
            .ok_or_else(|| error("original installed model binding is absent"))?;
        if original.authority != selected.authority || original.extensions != selected.extensions {
            return Err(error(
                "selected model lost its original actual authority tuple",
            ));
        }
        Ok(original)
    }

    fn check_world(&self, world: &HashRef) -> Result<(), EvidenceError> {
        if &self.profile.scenario.world.identity().map_err(error)? != world {
            return Err(error(
                "independent group claim names another complete world",
            ));
        }
        self.authenticate_all()
    }

    fn authenticate_all(&self) -> Result<(), EvidenceError> {
        for binding in &self.bindings {
            self.authenticate_authority(binding)?;
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory::native_state) fn qualify_prepared(
        &self,
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
        graph: Rc<AdmittedGraph>,
    ) -> Result<IndependentPreparedQualification, NodeObservedError> {
        if graph.world_binding_hash() != &self.profile.scenario.world.identity()? {
            return Err(refused(
                "native group preparation names another complete graph",
            ));
        }
        let node = Id::new("cpu")?;
        if graph.binding(&node) != self.original_native_graph.binding(&node)
            || graph.descriptor(&node) != self.original_native_graph.descriptor(&node)
        {
            return Err(refused(
                "whole-world CPU differs from its genuine original source tuple",
            ));
        }
        self.authenticate_all()
            .map_err(|error| refused(&error.message))?;
        Ok(IndependentPreparedQualification {
            original: self.native.qualify_prepared(native, authority)?,
            original_graph: self.original_native_graph.clone(),
            complete_graph: graph,
        })
    }
}

impl AdmissionEvidence for IndependentGroupEvidence {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        if reference.length.get() > maximum_bytes as u64 {
            return Err(error("independent group content exceeds caller credit"));
        }
        if let Some(object) = self
            .profile
            .scenario
            .content
            .iter()
            .find(|body| &body.reference == reference)
        {
            reference.verify(&object.bytes).map_err(error)?;
            return Ok(object.bytes.clone());
        }
        self.native
            .content(reference, maximum_bytes)
            .or_else(|_| self.host.content(reference, maximum_bytes))
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.authenticate_all()?;
        if self
            .profile
            .native
            .scenario
            .compatibility
            .iter()
            .any(|binding| &binding.implementation == implementation)
        {
            self.native.authenticate_implementation(implementation)
        } else {
            let selected = self
                .bindings
                .iter()
                .find(|binding| &binding.compatibility.implementation == implementation)
                .ok_or_else(|| {
                    error("selected public model implementation is not source regenerated")
                })?;
            self.host.authenticate_implementation(
                &self
                    .original_host_binding(selected)?
                    .compatibility
                    .implementation,
            )
        }
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        if !self.bindings.contains(binding) {
            return Err(error(
                "independent group binding was never actually enrolled",
            ));
        }
        if self.is_native(&binding.compatibility.node_id) {
            self.native.authenticate_authority(binding)
        } else {
            self.host
                .authenticate_authority(self.original_host_binding(binding)?)
        }
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.authenticate_all()?;
        let native = self
            .profile
            .native
            .scenario
            .compatibility
            .iter()
            .any(|binding| binding.implementation.formats.contains(schema))
            || self
                .profile
                .native
                .scenario
                .descriptors
                .iter()
                .flat_map(|node| &node.ports)
                .flat_map(|port| &port.lanes)
                .any(|lane| &lane.payload_schema == schema);
        if native {
            self.native.authenticate_schema(schema)
        } else {
            if self.profile.preserving
                && schema == &crucible::node_adapters::host_public_owned_model_continuation_schema()
                    .map_err(|failure| error(failure.reason))?
                && self.profile.scenario.content.iter().any(|body| body.reference == schema.definition
                    && body.bytes == crucible::node_adapters::HOST_PUBLIC_OWNED_MODEL_CONTINUATION_SPECIFICATION.as_bytes())
            {
                return Ok(());
            }
            self.host.authenticate_schema(schema)
        }
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        let scenario = &self.profile.scenario;
        match claim {
            QualificationClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } => {
                self.check_world(world_binding_hash)?;
                if scenario_ref != &scenario.world.scenario_ref
                    || requirements_hash
                        != &canonical::json_hash(
                            "cnp.admission-requirements.v1",
                            &scenario.requirements,
                        )
                        .map_err(error)?
                {
                    return Err(error(
                        "complete group demands differ from regenerated source",
                    ));
                }
            }
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                self.authenticate_all()?;
                if self.is_native(&binding.node_id) {
                    self.native.qualify(claim)?;
                } else {
                    let selected = self
                        .bindings
                        .iter()
                        .find(|selected| &selected.compatibility == binding)
                        .ok_or_else(|| {
                            error("model claim differs from selected live-only facade")
                        })?;
                    if binding_hash != &binding.identity().map_err(error)?
                        || qualification_refs != binding.qualification_refs.as_slice()
                    {
                        return Err(error(
                            "model claim omitted exact source-selected contract or proof",
                        ));
                    }
                    let original = self.original_host_binding(selected)?;
                    self.host.qualify(QualificationClaim::Node {
                        binding: &original.compatibility,
                        binding_hash: &original.compatibility.identity().map_err(error)?,
                        qualification_refs: &original.compatibility.qualification_refs,
                    })?;
                }
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => {
                self.authenticate_all()?;
                if self.is_native(node_id) {
                    self.native.qualify(claim)?;
                } else {
                    let selected = self
                        .bindings
                        .iter()
                        .find(|binding| &binding.compatibility.node_id == node_id)
                        .ok_or_else(|| error("selected model port has no actual binding"))?;
                    if binding_hash != &selected.compatibility.identity().map_err(error)? {
                        return Err(error("model port belongs to another selected facade"));
                    }
                    let original = self.original_host_binding(selected)?;
                    self.host.qualify(QualificationClaim::Port {
                        node_id,
                        binding_hash: &original.compatibility.identity().map_err(error)?,
                        port_id,
                        policy_ref,
                    })?;
                }
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if ownership_ref != &scenario.world.ownership_ref
                    || proof_ref != &self.profile.qualification
                {
                    return Err(error(
                        "complete group inventory differs from source-installed owner closure",
                    ));
                }
                // Both unchanged source inventories must still authenticate their
                // original resource tuples; the new closure only adds their exact
                // disjoint union and the independently installed connection.
                for (original, evidence) in [
                    (
                        &self.profile.native.scenario,
                        self.native.as_ref() as &dyn AdmissionEvidence,
                    ),
                    (&self.profile.group, &self.host as &dyn AdmissionEvidence),
                ] {
                    let ownership: crucible::node_admission::OwnershipPolicy =
                        serde_json::from_slice(
                            &evidence.content(&original.world.ownership_ref, 4 * 1024 * 1024)?,
                        )
                        .map_err(error)?;
                    evidence.qualify(QualificationClaim::CompleteInventory {
                        world_binding_hash: &original.world.identity().map_err(error)?,
                        ownership_ref: &original.world.ownership_ref,
                        proof_ref: &ownership.inventory_proof_ref,
                    })?;
                }
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if policy_ref != &scenario.world.coordinator_contract_ref {
                    return Err(error(
                        "complete group coordinator differs from source-installed bounded policy",
                    ));
                }
            }
            QualificationClaim::Connection {
                world_binding_hash,
                connection_id,
                proof_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if !scenario
                    .world
                    .connections
                    .iter()
                    .any(|connection| &connection.id == connection_id)
                    || scenario.world.connections != self.profile.group.world.connections
                {
                    return Err(error(
                        "group connection is not the original disconnected storage route",
                    ));
                }
                self.host.qualify(QualificationClaim::Connection {
                    world_binding_hash: &self.profile.group.world.identity().map_err(error)?,
                    connection_id,
                    proof_ref,
                })?;
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                self.check_world(world_binding_hash)?;
                if self
                    .profile
                    .group
                    .owners
                    .iter()
                    .any(|owner| &owner.owner.id == capture_owner_id)
                {
                    if procedure_ref != &self.profile.qualification {
                        return Err(error(
                            "live-only model capture refusal differs from source policy",
                        ));
                    }
                    if self.profile.preserving {
                        let ownership: crucible::node_admission::OwnershipPolicy =
                            serde_json::from_slice(&self.host.content(
                                &self.profile.group.world.ownership_ref,
                                4 * 1024 * 1024,
                            )?)
                            .map_err(error)?;
                        let original = ownership
                            .capture_owners
                            .iter()
                            .find(|owner| &owner.owner_id == capture_owner_id)
                            .ok_or_else(|| {
                                error("original complete Host capture owner is absent")
                            })?;
                        if !original.complete_model
                            || !original.unchanged_cut
                            || !original.exact_continuation
                            || !original.durable_restart
                        {
                            return Err(error(
                                "original Host model lacks complete continuation qualification",
                            ));
                        }
                        self.host.qualify(QualificationClaim::Capture {
                            world_binding_hash: &self
                                .profile
                                .group
                                .world
                                .identity()
                                .map_err(error)?,
                            capture_owner_id,
                            procedure_ref: &original.cut_procedure_ref,
                        })?;
                    }
                    // The live path authenticates its unsupported procedure;
                    // the selected preserving path also requires the unchanged
                    // original model procedure and preparation-bearing codec.
                    return Ok(());
                }
                let (original, evidence): (_, &dyn AdmissionEvidence) = if self
                    .profile
                    .native
                    .scenario
                    .owners
                    .iter()
                    .any(|binding| &binding.owner.id == capture_owner_id)
                {
                    (&self.profile.native.scenario, self.native.as_ref())
                } else if self
                    .profile
                    .group
                    .owners
                    .iter()
                    .any(|binding| &binding.owner.id == capture_owner_id)
                {
                    (&self.profile.group, &self.host)
                } else {
                    return Err(error(
                        "individual model procedure names a foreign actual owner",
                    ));
                };
                evidence.qualify(QualificationClaim::Capture {
                    world_binding_hash: &original.world.identity().map_err(error)?,
                    capture_owner_id,
                    procedure_ref,
                })?;
            }
            QualificationClaim::SameTimeClosure { .. } => {
                return Err(error(
                    "coupled cycles are not qualified by the independent storage group",
                ));
            }
        }
        Ok(())
    }
}

impl HostModelQualification for IndependentGroupEvidence {
    fn authenticate_initial_owned_model(
        &self,
        model: &HostModel,
        graph: &AdmittedGraph,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if self.is_native(&descriptor.id)
            || graph.world_binding_hash()
                != &self
                    .profile
                    .scenario
                    .world
                    .identity()
                    .map_err(|failure| no_effect(error(failure)))?
            || graph.binding(&descriptor.id) != Some(binding)
            || graph.descriptor(&descriptor.id) != Some(descriptor)
        {
            return Err(no_effect(error(
                "original model preparation names another complete source scope",
            )));
        }
        self.authenticate_all().map_err(no_effect)?;
        self.authenticate_model(model, descriptor, binding)
    }

    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.authenticate_all().map_err(no_effect)?;
        if self.is_native(&descriptor.id) {
            self.native.authenticate_model(model, descriptor, binding)
        } else {
            self.host.authenticate_model(
                model,
                descriptor,
                self.original_host_binding(binding).map_err(no_effect)?,
            )
        }
    }
}

/// Keeps original native qualification conjunct with the exact complete world.
pub(in crate::node_observed_executor::factory::native_state) struct IndependentPreparedQualification
{
    original: MixedPreparedQualification,
    original_graph: Rc<AdmittedGraph>,
    complete_graph: Rc<AdmittedGraph>,
}

impl Gem5PreparationQualification for IndependentPreparedQualification {
    fn authenticate_preparation(
        &self,
        native: &Gem5NativeProcess,
        graph: &AdmittedGraph,
        node: &Id,
    ) -> Result<(), OperationFailure> {
        if graph.world_binding_hash() != self.complete_graph.world_binding_hash()
            || graph.binding(node) != self.complete_graph.binding(node)
            || graph.descriptor(node) != self.complete_graph.descriptor(node)
            || node.as_str() != "cpu"
        {
            return Err(no_effect(error(
                "native preparation names another complete group tuple",
            )));
        }
        self.original
            .authenticate_preparation(native, &self.original_graph, node)
    }
}

fn error(failure: impl std::fmt::Display) -> EvidenceError {
    EvidenceError {
        message: failure.to_string(),
    }
}

fn no_effect(failure: EvidenceError) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: failure.message,
    }
}
