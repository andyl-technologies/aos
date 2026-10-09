//! Installed clock state qualification, immutable archive content and cold native prepare.
//!
//! This edition accepts isolated local integer clocks only. The regenerated
//! profile and current executable are measured independently of the source
//! archive. The source-qualified restore wrapper additionally requires the
//! archive driver's opaque authenticated original-custody seal.

use std::{collections::BTreeMap, fs::File, io::Read, rc::Rc};

use crucible::{
    node_adapters::{
        HostModel, HostModelNode, HostModelQualification, HostModelResources,
        host_clock_initial_bytes, validate_host_continuation,
    },
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, EffectKnowledge, NativeRuntimeContinuationEvidence, OperationFailure,
        RuntimeSnapshot,
    },
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedHostSource, CaptureEvidence, HostWorldFactory, NativeCoordinatorCaptureProof,
        NativeOwnerCaptureProof, RestoreReservations, StateError, StateErrorCode,
        StateRequirements, VerifiedStateContent,
    },
};
use crucible_device::clock::VirtualClock;
use crucible_node_contract::{
    CaptureManifest, CapturedOwner, ContentRef, Id, NodeBinding, NodeDescriptor, SchemaRef,
};

use super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, NodeObservedError,
    measure_executable, profile, refused,
};
use crate::node_scenario::NodeScenario;

/// Authenticates actual installed isolated clocks and their complete source archives.
///
/// Construction is restricted to the installed catalog. It regenerates the
/// entire clock scenario and remeasures the running host executable. Public
/// scenario bytes or matching backend labels cannot create an instance.
pub struct InstalledHostStateFactory {
    scenario: NodeScenario,
    host_identity: ContentRef,
    host_executable: std::path::PathBuf,
    objects: BTreeMap<String, (ContentRef, Vec<u8>)>,
}

impl InstalledNodeCatalog {
    /// Resolves installed clock state support and an immutable content source.
    ///
    /// The returned owner implements both native host qualification and archive
    /// immutable-content retrieval. The caller still needs genuine admitted live
    /// resources or a separately admitted fresh target before capture/restore.
    ///
    /// # Errors
    /// Refuses unsupported reference/coupled models, changed authored profiles,
    /// unavailable installed artifacts or an unsupported complete native codec.
    pub fn host_state_factory(
        &self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
    ) -> Result<Rc<InstalledHostStateFactory>, NodeObservedError> {
        if selections
            .iter()
            .any(|selection| !matches!(selection.kind, InstalledNodeKind::HostClock))
        {
            return Err(refused(
                "installed archive edition supports isolated host clocks only",
            ));
        }
        let expected =
            profile::build_world(selections, &self.host_identity, &self.device_identity)?.scenario;
        if scenario.canonical_bytes()? != expected.canonical_bytes()?
            || measure_executable(&self.host_executable)? != self.host_identity
        {
            return Err(refused(
                "clock archive profile or actual installed executable differs",
            ));
        }
        if expected
            .compatibility
            .iter()
            .any(|binding| binding.implementation.formats.len() != 1)
        {
            return Err(refused(
                "installed clock archive lacks its unique complete continuation edition",
            ));
        }
        let objects = expected
            .content
            .iter()
            .map(|object| {
                (
                    object.reference.hash.digest.clone(),
                    (object.reference.clone(), object.bytes.clone()),
                )
            })
            .collect();
        Ok(Rc::new(InstalledHostStateFactory {
            scenario: expected,
            host_identity: self.host_identity.clone(),
            host_executable: self.host_executable.clone(),
            objects,
        }))
    }
}

impl InstalledHostStateFactory {
    fn check_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        if measure_executable(&self.host_executable).map_err(state_error)? != self.host_identity
            || graph.world() != &self.scenario.world
            || graph.node_ids().count() != self.scenario.descriptors.len()
            || !graph.world().connections.is_empty()
            || !graph.coordinator_policy().same_time_closure.is_empty()
            || !graph.coordinator_policy().external_inputs.is_empty()
            || !graph.ownership_policy().internal_dependencies.is_empty()
        {
            return Err(refusal(
                "actual isolated installed clock world or executable differs",
            ));
        }
        for expected in &self.scenario.descriptors {
            let selected = self
                .scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == expected.id)
                .ok_or_else(|| refusal("installed clock binding missing"))?;
            if graph.descriptor(&expected.id) != Some(expected)
                || graph
                    .binding(&expected.id)
                    .is_none_or(|binding| &binding.compatibility != selected)
                || expected.roles.as_slice() != [Id::new("clock").map_err(state_error)?]
                || !expected.ports.is_empty()
            {
                return Err(refusal(
                    "actual installed clock descriptor or native profile differs",
                ));
            }
        }
        Ok(())
    }

    fn check_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        let expected = self
            .scenario
            .descriptors
            .iter()
            .find(|node| node.id == descriptor.id);
        let selected = self
            .scenario
            .compatibility
            .iter()
            .find(|selected| selected.node_id == descriptor.id);
        if measure_executable(&self.host_executable).map_err(no_effect)? != self.host_identity
            || expected != Some(descriptor)
            || selected != Some(&binding.compatibility)
            || !matches!(model, HostModel::Clock(_))
            || model.initialization_bytes(1024)? != host_clock_initial_bytes(0)
        {
            return Err(no_effect(
                "actual clock or measured installed implementation differs",
            ));
        }
        Ok(())
    }

    fn immutable(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        if reference.length.get() > maximum as u64 {
            return Err(refusal(
                "installed immutable content exceeds allocation ceiling",
            ));
        }
        if let Some((expected, bytes)) = self.objects.get(&reference.hash.digest) {
            if expected != reference {
                return Err(refusal("installed immutable object metadata differs"));
            }
            return Ok(bytes.clone());
        }
        if reference != &self.host_identity {
            return Err(refusal(
                "immutable object is not in the installed clock registry",
            ));
        }
        let file = File::open(&self.host_executable).map_err(state_error)?;
        if file.metadata().map_err(state_error)?.len() != reference.length.get() {
            return Err(refusal("installed executable changed before bounded fetch"));
        }
        let length = usize::try_from(reference.length.get()).map_err(state_error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(state_error)?;
        file.take(reference.length.get().saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(state_error)?;
        reference.verify(&bytes).map_err(state_error)?;
        Ok(bytes)
    }
}

impl HostWorldFactory for InstalledHostStateFactory {
    fn reservation(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &[u8],
        limits: HostModelResources,
    ) -> Result<RestoreReservations, StateError> {
        self.check_graph(graph)?;
        if graph.descriptor(node).is_none()
            || native.len() > limits.maximum_capture_bytes
            || limits.maximum_operations > 65_536
        {
            return Err(refusal(
                "installed clock source or operation reservation exceeds finite limits",
            ));
        }
        // The selected synchronous clock has no external handles. This enforced
        // upper reservation includes parsed envelopes, original cached receipts,
        // staged metadata and runtime/native copies rather than only the u64.
        let memory_bytes = (native.len() as u64)
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(|| refusal("installed clock peak memory reservation exhausted"))?;
        Ok(RestoreReservations {
            memory_bytes,
            ..Default::default()
        })
    }

    fn state_schema(&self, graph: &AdmittedGraph, node: &Id) -> Result<SchemaRef, StateError> {
        self.check_graph(graph)?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| refusal("installed clock binding absent"))?;
        if binding.compatibility.implementation.formats.len() != 1 {
            return Err(refusal("installed clock continuation edition differs"));
        }
        Ok(binding.compatibility.implementation.formats[0].clone())
    }

    fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        let policy = graph.ownership_policy();
        if runtime.schema_version != 1
            || scheduler.schema_version != 1
            || runtime.source_activation.world_binding_hash != *graph.world_binding_hash()
            || scheduler.world_binding_hash != *graph.world_binding_hash()
            || runtime.capture_cut != scheduler.capture_cut
            || runtime.capture_ordinal != scheduler.capture_ordinal
            || policy.objects.len() != self.scenario.descriptors.len()
            || policy.domains.len() != self.scenario.descriptors.len()
            || policy.capture_owners.iter().any(|owner| {
                !owner.complete_model
                    || !owner.unchanged_cut
                    || !owner.exact_continuation
                    || !owner.durable_restart
                    || !owner.dependencies.is_empty()
            })
            || !scheduler.external_closed_prefixes.is_empty()
            || !scheduler.pending_deliveries.is_empty()
            || !scheduler.input_batches.is_empty()
            || !runtime.inputs.is_empty()
        {
            return Err(refusal(
                "clock-only coordinator inventory contains unsupported shared, input, fault or external state",
            ));
        }
        for expected in &self.scenario.content {
            // Scenario-owned objects include the complete selected fault-free
            // coordinator and native model definitions. All referenced objects
            // must remain in the authenticated immutable closure.
            if content.get(&expected.reference).is_none()
                && self.scenario.world.initialization_ref == expected.reference
            {
                return Err(refusal(
                    "installed clock initialization inventory is incomplete",
                ));
            }
        }
        Ok(())
    }

    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &[u8],
        source: &RuntimeSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| refusal("installed clock descriptor absent"))?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| refusal("installed clock binding absent"))?;
        let inventory = validate_host_continuation(
            native,
            source,
            descriptor,
            binding,
            HostModelResources {
                maximum_capture_bytes: 64 * 1024 * 1024,
                maximum_operations: 65_536,
            },
        )
        .map_err(|error| refusal(error.reason))?;
        if inventory.native_model.bytes
            != host_clock_initial_bytes(source.capture_cut.time_ps.get())
            || content.get(&descriptor.initialization_ref)
                != Some(host_clock_initial_bytes(0).as_slice())
            || source.inputs.iter().any(|input| &input.node == node)
        {
            return Err(refusal(
                "complete actual clock codec, initialization or no-input state differs",
            ));
        }
        for definition in &binding.compatibility.implementation.model_definitions {
            if content.get(definition).is_none() {
                return Err(refusal(
                    "installed clock model definition absent from source",
                ));
            }
        }
        Ok(())
    }

    fn prepare_node(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        source: &AuthenticatedHostSource<'_>,
        target: &ActivationRecord,
        limits: HostModelResources,
    ) -> Result<(HostModelNode, NativeRuntimeContinuationEvidence), StateError> {
        if source.node() != node {
            return Err(refusal("authenticated original clock identity differs"));
        }
        self.authenticate_source(
            graph,
            node,
            source.native(),
            source.runtime(),
            source.content(),
        )?;
        let qualification = SourceQualification {
            installed: self,
            source,
            target,
        };
        let mut actual = HostModelNode::new(
            graph,
            node,
            HostModel::Clock(VirtualClock::new()),
            &qualification,
            limits,
        )
        .map_err(|error| refusal(error.reason))?;
        let proof = actual
            .prepare_continuation(source.native(), source.runtime(), target, &qualification)
            .map_err(|error| refusal(error.reason))?;
        Ok((actual, proof))
    }
}

struct SourceQualification<'a> {
    installed: &'a InstalledHostStateFactory,
    source: &'a AuthenticatedHostSource<'a>,
    target: &'a ActivationRecord,
}

impl HostModelQualification for SourceQualification<'_> {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.installed.check_model(model, descriptor, binding)
    }

    fn authenticate_continuation(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
        native: &[u8],
        source: &RuntimeSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        self.installed.check_model(model, descriptor, binding)?;
        if self.source.node() != &descriptor.id
            || self.source.native() != native
            || self.source.runtime() != source
            || self.target != target
            || target.world_binding_hash != source.source_activation.world_binding_hash
            || target.boundary != source.capture_cut
            || target.generation <= source.source_activation.generation
        {
            return Err(no_effect(
                "original authenticated source, cut or fresh clock target differs",
            ));
        }
        Ok(())
    }
}

impl CaptureEvidence for InstalledHostStateFactory {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.immutable(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        if reference == &self.host_identity {
            reference.verify(bytes).map_err(state_error)?;
            return Ok(vec![]);
        }
        let (expected, original) = self
            .objects
            .get(&reference.hash.digest)
            .ok_or_else(|| refusal("unsupported installed immutable object"))?;
        if expected != reference || original != bytes {
            return Err(refusal("installed immutable object changed"));
        }
        if reference.media_type != "application/json" {
            return Ok(vec![]);
        }
        // Only locally regenerated closed core records use this enumerator.
        // Native receipt bodies and opaque provider formats never enter here.
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(state_error)?;
        let mut stack = vec![&value];
        let mut references = Vec::new();
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::Object(object)
                    if object.contains_key("hash")
                        && object.contains_key("length")
                        && object.contains_key("media_type") =>
                {
                    if references.len() >= maximum {
                        return Err(refusal(
                            "installed dependency inventory exceeds preallocation ceiling",
                        ));
                    }
                    let reference: ContentRef =
                        serde_json::from_value(value.clone()).map_err(state_error)?;
                    if reference != self.host_identity
                        && self
                            .objects
                            .get(&reference.hash.digest)
                            .is_none_or(|(expected, _)| expected != &reference)
                    {
                        return Err(refusal(
                            "installed core dependency has no measured immutable source",
                        ));
                    }
                    references.push(reference);
                }
                serde_json::Value::Object(object) => stack.extend(object.values()),
                serde_json::Value::Array(array) => stack.extend(array),
                _ => {}
            }
        }
        references.sort();
        references.dedup();
        Ok(references)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(refusal(
            "immutable installed registry cannot issue original native capture provenance",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(refusal(
            "immutable installed registry cannot issue original coordinator capture provenance",
        ))
    }
}

fn refusal(reason: impl Into<String>) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed clock archive",
        reason,
    )
}

fn state_error(error: impl std::fmt::Display) -> StateError {
    refusal(error.to_string())
}

fn no_effect(error: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: error.to_string(),
    }
}
