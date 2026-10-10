//! Installed host state qualification, immutable archive content and cold native prepare.
//!
//! This edition accepts local integer clocks and finite scripted storage worlds. The regenerated
//! profile and current executable are measured independently of the source
//! archive. The source-qualified restore wrapper additionally requires the
//! archive driver's opaque authenticated original-custody seal.

#[cfg(test)]
#[path = "host_state_transfer_tests.rs"]
mod transfer_tests;

#[path = "host_state_fault.rs"]
mod fault;

use std::{collections::BTreeMap, fs::File, io::Read, rc::Rc};

use crucible::{
    node_adapters::{
        HostModel, HostModelNode, HostModelQualification, HostModelResources, ScriptedSource,
        host_clock_initial_bytes, validate_host_continuation,
    },
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, EffectKnowledge, NativeRuntimeContinuationEvidence, OperationFailure,
        RuntimeSnapshot,
    },
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedHostSource, CaptureEvidence, HostArchiveRecord, HostWorldFactory,
        NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, RestoreReservations, StateError,
        StateErrorCode, StateRequirements, VerifiedStateContent,
    },
};
use crucible_device::clock::VirtualClock;
use crucible_node_contract::{
    CaptureManifest, CapturedOwner, ContentRef, Id, NodeBinding, NodeDescriptor, Phase, Position,
    SchemaRef, canonical,
};

use super::{
    InstalledIoArtifact, InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection,
    NodeObservedError, archive_artifacts, io, measure_executable, profile, refused,
};
use crate::node_scenario::NodeScenario;

/// Authenticates actual installed host models and their complete source archives.
///
/// Construction is restricted to the installed catalog. It regenerates the
/// entire native scenario and remeasures the running host executable. Public
/// scenario bytes or matching backend labels cannot create an instance.
pub struct InstalledHostStateFactory {
    scenario: NodeScenario,
    host_identity: ContentRef,
    host_executable: std::path::PathBuf,
    objects: BTreeMap<String, (ContentRef, Vec<u8>)>,
    selections: BTreeMap<Id, InstalledNodeSelection>,
}

impl InstalledNodeCatalog {
    /// Resolves installed host state support and an immutable content source.
    ///
    /// The returned owner implements both native host qualification and archive
    /// immutable-content retrieval. The caller still needs genuine admitted live
    /// resources or a separately admitted fresh target before capture/restore.
    ///
    /// # Errors
    /// Refuses unsupported reference/link models, changed authored profiles,
    /// unavailable installed artifacts or an unsupported complete native codec.
    pub fn host_state_factory(
        &self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
    ) -> Result<Rc<InstalledHostStateFactory>, NodeObservedError> {
        self.host_state_factory_with_artifacts(selections, scenario, &self.artifacts)
    }

    /// Resolves installed state support using authenticated original immutable inputs.
    ///
    /// References must already be enrolled by independent operator policy. The
    /// signed source supplies complete bytes to scoped native constructors; it
    /// cannot enroll a new implementation, change a profile, or grant execution.
    /// Original artifact pathnames are not reopened by this regeneration.
    ///
    /// # Errors
    /// Refuses unsupported native families, unenrolled references, incomplete
    /// archive content, changed authored profiles or actual installed artifacts,
    /// and excessive immutable source geometry.
    pub fn host_state_factory_from_archive(
        &self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
        record: &HostArchiveRecord,
    ) -> Result<Rc<InstalledHostStateFactory>, NodeObservedError> {
        let artifacts = archive_artifacts::materialize(&self.artifacts, selections, record)?;
        self.host_state_factory_with_artifacts(selections, scenario, artifacts.registry())
    }

    // The registry is either the independent operator enrollment or a scoped
    // copy authenticated against that enrollment and the original archive.
    pub(super) fn host_state_factory_with_artifacts(
        &self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
    ) -> Result<Rc<InstalledHostStateFactory>, NodeObservedError> {
        if selections.iter().any(|selection| {
            !matches!(
                selection.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostIo { .. }
                    | InstalledNodeKind::HostRecordedBlockPreserving { .. }
                    | InstalledNodeKind::HostScripted { .. }
                    | InstalledNodeKind::HostSeededLink { .. }
                    | InstalledNodeKind::HostFaultedLink { .. }
                    | InstalledNodeKind::HostControlledFaultLink { .. }
                    | InstalledNodeKind::HostPacketReceiver { .. }
                    | InstalledNodeKind::HostSemantics { .. }
            )
        }) {
            return Err(refused(
                "installed archive edition supports clocks and finite scripted storage worlds",
            ));
        }
        let expected = profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            artifacts,
        )?
        .scenario;
        if scenario.canonical_bytes()? != expected.canonical_bytes()?
            || measure_executable(&self.host_executable)? != self.host_identity
        {
            return Err(refused(
                "native archive profile or actual installed executable differs",
            ));
        }
        if expected.compatibility.iter().any(|binding| {
            binding
                .implementation
                .formats
                .iter()
                .filter(|schema| {
                    ((schema.id.as_str() == "host/native-continuation-v1"
                        || schema.id.as_str() == "host/native-recorded-block-v1"
                        || schema.id.as_str() == "host/native-seeded-link-v1"
                        || schema.id.as_str() == "host/native-faulted-link-v1"
                        || schema.id.as_str() == "host/native-controlled-fault-link-v1"
                        || schema.id.as_str() == "host/native-packet-receiver-v1")
                        && schema.version == 1)
                        || (schema.id.as_str() == "host/native-semantic-continuation-v2"
                            && schema.version == 2)
                })
                .count()
                != 1
        }) {
            return Err(refused(
                "installed native archive lacks its unique complete continuation edition",
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
            selections: selections
                .iter()
                .cloned()
                .map(|selection| (selection.node.clone(), selection))
                .collect(),
        }))
    }
}

#[path = "host_state_recorded.rs"]
mod recorded;

#[path = "host_state_native.rs"]
mod native;

impl InstalledHostStateFactory {
    fn recorded_world(&self) -> bool {
        self.selections.len() == 1
            && self.selections.values().all(|selection| {
                matches!(
                    &selection.kind,
                    InstalledNodeKind::HostRecordedBlockPreserving { .. }
                )
            })
    }

    fn check_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        if measure_executable(&self.host_executable).map_err(state_error)? != self.host_identity
            || graph.world() != &self.scenario.world
            || graph.node_ids().count() != self.scenario.descriptors.len()
            || !graph.coordinator_policy().same_time_closure.is_empty()
            || (!graph.coordinator_policy().external_inputs.is_empty() && !self.recorded_world())
            || !graph.ownership_policy().internal_dependencies.is_empty()
        {
            return Err(refusal(
                "actual installed native world or executable differs",
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
            {
                return Err(refusal(
                    "actual installed descriptor or native profile differs",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory) fn check_model(
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
        {
            return Err(no_effect(
                "actual native model or measured installed implementation differs",
            ));
        }
        let selection = self
            .selections
            .get(&descriptor.id)
            .ok_or_else(|| no_effect("installed native selection absent"))?;
        let (_, initial) = self
            .objects
            .get(&descriptor.initialization_ref.hash.digest)
            .ok_or_else(|| no_effect("installed initial native inventory absent"))?;
        if model.initialization_bytes(4 * 1024 * 1024)? != *initial {
            return Err(no_effect("actual complete native initialization differs"));
        }
        match (&selection.kind, model) {
            (InstalledNodeKind::HostClock, HostModel::Clock(_)) => {}
            (InstalledNodeKind::HostPacketReceiver { .. }, HostModel::PacketReceiver(_)) => {}
            (InstalledNodeKind::HostRecordedBlockPreserving { profile }, HostModel::Io(actual)) => {
                let block = actual
                    .block_device()
                    .ok_or_else(|| no_effect("recorded preservation requires Block"))?;
                profile
                    .storage
                    .artifact()
                    .verify(block.base().bytes())
                    .map_err(no_effect)?;
            }
            (
                InstalledNodeKind::HostSeededLink { profile },
                HostModel::SeededLink { definition, .. },
            ) => {
                let bytes = canonical::canonical_json(
                    &serde_json::to_value(definition).map_err(no_effect)?,
                )
                .map_err(no_effect)?;
                profile.program.verify(&bytes).map_err(no_effect)?;
            }
            (
                InstalledNodeKind::HostFaultedLink { profile },
                HostModel::FaultedLink { definition, .. },
            ) => {
                let bytes = canonical::canonical_json(
                    &serde_json::to_value(definition).map_err(no_effect)?,
                )
                .map_err(no_effect)?;
                profile.program.verify(&bytes).map_err(no_effect)?;
            }
            (
                InstalledNodeKind::HostControlledFaultLink { profile },
                HostModel::ControlledFaultLink(actual),
            ) => {
                let bytes = canonical::canonical_json(
                    &serde_json::to_value(actual.program()).map_err(no_effect)?,
                )
                .map_err(no_effect)?;
                profile.program.verify(&bytes).map_err(no_effect)?;
            }
            (InstalledNodeKind::HostIo { profile }, HostModel::Io(actual)) => {
                if let Some(block) = actual.block_device() {
                    profile
                        .artifact()
                        .verify(block.base().bytes())
                        .map_err(no_effect)?;
                } else if let Some(filesystem) = actual.ninep_device() {
                    profile
                        .artifact()
                        .verify(&filesystem.server().tree().canonical_bytes())
                        .map_err(no_effect)?;
                } else {
                    return Err(no_effect("actual storage immutable input absent"));
                }
            }
            (InstalledNodeKind::HostScripted { profile }, HostModel::ScriptedSource(actual)) => {
                profile
                    .script
                    .verify(&actual.script_bytes()?)
                    .map_err(no_effect)?;
            }
            (InstalledNodeKind::HostSemantics { profile }, HostModel::Semantics(actual)) => {
                let definition = canonical::canonical_json(
                    &serde_json::to_value(actual.definition()).map_err(no_effect)?,
                )
                .map_err(no_effect)?;
                profile.program.verify(&definition).map_err(no_effect)?;
            }
            _ => return Err(no_effect("actual installed native family differs")),
        }
        Ok(())
    }

    fn selection(&self, node: &Id) -> Result<&InstalledNodeSelection, StateError> {
        self.selections
            .get(node)
            .ok_or_else(|| refusal("installed native selection absent"))
    }

    fn immutable_input<'a>(
        &self,
        node: &Id,
        content: &'a VerifiedStateContent,
    ) -> Result<Option<&'a [u8]>, StateError> {
        let reference = match &self.selection(node)?.kind {
            InstalledNodeKind::HostClock | InstalledNodeKind::HostPacketReceiver { .. } => {
                return Ok(None);
            }
            InstalledNodeKind::HostSeededLink { profile } => &profile.program,
            InstalledNodeKind::HostFaultedLink { profile } => &profile.program,
            InstalledNodeKind::HostControlledFaultLink { profile } => &profile.program,
            InstalledNodeKind::HostIo { profile } => profile.artifact(),
            InstalledNodeKind::HostRecordedBlockPreserving { profile } => {
                profile.storage.artifact()
            }
            InstalledNodeKind::HostScripted { profile } => &profile.script,
            InstalledNodeKind::HostSemantics { profile } => &profile.program,
            _ => return Err(refusal("unsupported installed native archive family")),
        };
        let bytes = content.get(reference).ok_or_else(|| {
            refusal("complete immutable native input is absent from signed closure")
        })?;
        reference.verify(bytes).map_err(state_error)?;
        Ok(Some(bytes))
    }

    fn model(&self, node: &Id, content: &VerifiedStateContent) -> Result<HostModel, StateError> {
        let selected = self.selection(node)?;
        match &selected.kind {
            InstalledNodeKind::HostClock => Ok(HostModel::Clock(VirtualClock::new())),
            InstalledNodeKind::HostPacketReceiver {
                source_node,
                latency_ps,
            } => Ok(HostModel::PacketReceiver(Box::new(
                crucible::node_adapters::PacketReceiver::new(*source_node, latency_ps.get())
                    .map_err(|error| refusal(error.reason))?,
            ))),
            InstalledNodeKind::HostSeededLink { .. } => {
                let definition: crucible::node_adapters::SeededLinkDefinition =
                    serde_json::from_slice(
                        self.immutable_input(node, content)?
                            .ok_or_else(|| refusal("seeded original program absent"))?,
                    )
                    .map_err(state_error)?;
                Ok(HostModel::SeededLink {
                    link: Box::new(
                        definition
                            .instantiate()
                            .map_err(|error| refusal(error.reason))?,
                    ),
                    definition,
                })
            }
            InstalledNodeKind::HostFaultedLink { .. } => {
                let definition: crucible::node_adapters::FaultedLinkDefinition =
                    serde_json::from_slice(
                        self.immutable_input(node, content)?
                            .ok_or_else(|| refusal("seeded original program absent"))?,
                    )
                    .map_err(state_error)?;
                Ok(HostModel::FaultedLink {
                    link: Box::new(
                        definition
                            .instantiate()
                            .map_err(|error| refusal(error.reason))?,
                    ),
                    definition,
                    decisions: Vec::new(),
                })
            }
            InstalledNodeKind::HostControlledFaultLink { .. } => {
                let program = serde_json::from_slice(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("complete controller program absent"))?,
                )
                .map_err(state_error)?;
                Ok(HostModel::ControlledFaultLink(Box::new(
                    crucible::node_adapters::ControlledFaultLink::new(program)
                        .map_err(|error| refusal(error.reason))?,
                )))
            }
            InstalledNodeKind::HostRecordedBlockPreserving { profile } => {
                io::build_model_from_bytes(
                    selected,
                    &profile.storage,
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("recorded base absent"))?
                        .to_vec(),
                )
                .map_err(state_error)
            }
            InstalledNodeKind::HostIo { profile } => io::build_model_from_bytes(
                selected,
                profile,
                self.immutable_input(node, content)?
                    .ok_or_else(|| refusal("storage input absent"))?
                    .to_vec(),
            )
            .map_err(state_error),
            InstalledNodeKind::HostScripted { .. } => Ok(HostModel::ScriptedSource(Box::new(
                ScriptedSource::from_script_bytes(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("script input absent"))?,
                )
                .map_err(|error| refusal(error.reason))?,
            ))),
            InstalledNodeKind::HostSemantics { .. } => {
                let definition = serde_json::from_slice(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("semantic immutable program absent"))?,
                )
                .map_err(state_error)?;
                let model = crucible::node_adapters::HostSemanticModel::new(
                    definition,
                    super::semantics::MAXIMUM_SEMANTIC_STATE_BYTES,
                    super::semantics::MAXIMUM_SEMANTIC_EVENTS,
                )
                .map_err(|error| refusal(error.reason))?;
                Ok(HostModel::Semantics(Box::new(model)))
            }
            _ => Err(refusal("unsupported installed native archive family")),
        }
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

struct SourceQualification<'a> {
    installed: &'a InstalledHostStateFactory,
    source: &'a AuthenticatedHostSource<'a>,
    target: &'a ActivationRecord,
}

impl HostModelQualification for SourceQualification<'_> {
    fn authenticate_recorded_preservation(
        &self,
        definition: &crucible::node_adapters::RecordedIngressDefinition,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.authenticate_recorded_ingress(definition, descriptor, binding)
    }

    fn authenticate_recorded_ingress(
        &self,
        definition: &crucible::node_adapters::RecordedIngressDefinition,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if !self.installed.recorded_world()
            || self
                .installed
                .scenario
                .descriptors
                .iter()
                .find(|node| node.id == descriptor.id)
                != Some(descriptor)
            || self
                .installed
                .scenario
                .compatibility
                .iter()
                .find(|expected| expected.node_id == descriptor.id)
                != Some(&binding.compatibility)
        {
            return Err(no_effect(
                "recorded continuation has no independent source policy",
            ));
        }
        let expected = super::recorded_ingress::from_content(descriptor, &self.installed.objects)
            .map_err(no_effect)?;
        if &expected != definition {
            return Err(no_effect(
                "recorded restored source differs from installed closure",
            ));
        }
        Ok(())
    }

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
