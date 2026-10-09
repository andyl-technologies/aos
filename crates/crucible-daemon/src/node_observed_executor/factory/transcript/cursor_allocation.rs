//! Original-source cursor custody before fresh conditional replay admission.
//!
//! These host-owned allocations are distinct from the physical source. They own
//! the accepted signed bodies and initial cursor roster under finite credit;
//! public profile records and enrollment hashes cannot instantiate them.

use crucible::{
    node_adapters::transcript::{AuthenticatedTranscript, TranscriptReplayNode},
    node_admission::{AdmissionLimits, AdmissionRequest, AdmittedGraph, admit_graph},
    node_contract::NodeRoute,
};

use super::*;
use std::rc::Rc;

const MAXIMUM_SOURCE_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct CursorAllocation {
    source: source_enrollment::VerifiedRecordedWorld,
    profile: replay_profile::ReplayProfile,
    host_executable: PathBuf,
    host_identity: ContentRef,
    device_executable: PathBuf,
    device_identity: ContentRef,
    thread: std::thread::ThreadId,
}

pub(super) struct PreparedReplayPair {
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) record: ActivationRecord,
    pub(super) scenario: NodeScenario,
    pub(super) configuration: NodeRunConfiguration,
    pub(super) nodes: Vec<Box<dyn SimulationNode>>,
}

impl CursorAllocation {
    #[cfg(test)]
    pub(super) fn allocate(
        catalog: &InstalledNodeCatalog,
        source: source_enrollment::VerifiedRecordedWorld,
        execution: ExecutionId,
    ) -> Result<Self, NodeObservedError> {
        Self::allocate_contract(
            catalog,
            source,
            execution,
            replay_profile::ReplayContract::OriginalExecution,
        )
    }

    pub(super) fn allocate_preserving(
        catalog: &InstalledNodeCatalog,
        source: source_enrollment::VerifiedRecordedWorld,
        execution: ExecutionId,
    ) -> Result<Self, NodeObservedError> {
        Self::allocate_contract(
            catalog,
            source,
            execution,
            replay_profile::ReplayContract::CompleteReplayModel,
        )
    }

    fn allocate_contract(
        catalog: &InstalledNodeCatalog,
        source: source_enrollment::VerifiedRecordedWorld,
        execution: ExecutionId,
        contract: replay_profile::ReplayContract,
    ) -> Result<Self, NodeObservedError> {
        // Bound all signed source documents before the source-owning allocation
        // can create cursor copies or a fresh compatibility graph.
        let total = source
            .sources
            .values()
            .try_fold(0usize, |total, transcript| {
                total.checked_add(transcript.bytes().len())
            })
            .ok_or_else(|| refused("accepted replay source extent overflow"))?;
        if total > MAXIMUM_SOURCE_BYTES
            || source.sources.len() != 2
            || measure_executable(&catalog.host_executable)? != catalog.host_identity
        {
            return Err(refused(
                "accepted replay source exceeds installed cursor custody",
            ));
        }
        let profile = replay_profile::build(catalog, &source, execution, contract)?;
        Ok(Self {
            source,
            profile,
            host_executable: catalog.host_executable.clone(),
            host_identity: catalog.host_identity.clone(),
            device_executable: catalog.device_executable.clone(),
            device_identity: catalog.device_identity.clone(),
            thread: std::thread::current().id(),
        })
    }

    pub(super) fn prepare(&self) -> Result<PreparedReplayPair, NodeObservedError> {
        self.check_scope()?;
        let graph = Rc::new(
            admit_graph(
                AdmissionRequest {
                    world: &self.profile.scenario.world,
                    descriptors: &self.profile.scenario.descriptors,
                    bindings: &self.profile.bindings,
                    owners: &self.profile.scenario.owners,
                    requirements: &self.profile.scenario.requirements,
                },
                self,
                AdmissionLimits {
                    maximum_content_bytes: 512 * 1024 * 1024,
                    maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
                    ..AdmissionLimits::default()
                },
            )
            .map_err(native)?,
        );
        let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
        nodes
            .try_reserve_exact(self.source.sources.len())
            .map_err(native)?;
        for (node, source) in &self.source.sources {
            let binding = graph
                .binding(node)
                .ok_or_else(|| refused("allocated replay binding absent"))?;
            let owner = self
                .profile
                .record
                .owners
                .iter()
                .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .cloned()
                .ok_or_else(|| refused("allocated replay owner absent"))?;
            let route = NodeRoute {
                node: node.clone(),
                owners: vec![owner],
            };
            let replay = TranscriptReplayNode::prepare(
                source.clone(),
                &graph,
                route,
                &source.transcript().origin.context,
                self,
            )
            .map_err(native)?;
            nodes.push(Box::new(replay));
        }
        Ok(PreparedReplayPair {
            graph,
            record: self.profile.record.clone(),
            scenario: self.profile.scenario.clone(),
            configuration: self.source.configuration.clone(),
            nodes,
        })
    }

    #[cfg(test)]
    pub(super) fn admit_graph(&self) -> Result<Rc<AdmittedGraph>, NodeObservedError> {
        self.check_scope()?;
        Ok(Rc::new(
            admit_graph(
                AdmissionRequest {
                    world: &self.profile.scenario.world,
                    descriptors: &self.profile.scenario.descriptors,
                    bindings: &self.profile.bindings,
                    owners: &self.profile.scenario.owners,
                    requirements: &self.profile.scenario.requirements,
                },
                self,
                AdmissionLimits {
                    maximum_content_bytes: 512 * 1024 * 1024,
                    maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
                    ..AdmissionLimits::default()
                },
            )
            .map_err(native)?,
        ))
    }

    pub(super) fn installed_asset(&self, reference: &ContentRef) -> Option<&Path> {
        if reference == &self.host_identity {
            Some(&self.host_executable)
        } else if reference == &self.device_identity {
            Some(&self.device_executable)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(super) fn fresh_branch(
        &self,
        source: &crucible::node_state::NativeArchiveRecord,
        execution: ExecutionId,
    ) -> Result<Self, NodeObservedError> {
        self.check_scope()?;
        if source.manifest().world_binding_hash != self.profile.scenario.world.identity()? {
            return Err(refused(
                "authenticated replay continuation belongs to another world",
            ));
        }
        let original = source.source_activation().map_err(native)?;
        let mut profile = self.profile.clone();
        profile.record.generation = original.generation.checked_add(U64::new(1))?;
        profile.record.activation_id = Id::new(format!(
            "activation/replay-restored/{}",
            execution_text(execution)
        ))?;
        profile.record.boundary = source.manifest().cut;
        profile.record.owners.clear();
        for binding in &mut profile.bindings {
            let old = original
                .owners
                .iter()
                .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .ok_or_else(|| refused("authenticated replay source owner absent"))?;
            let incarnation = Id::new(format!(
                "incarnation/replay-restored/{}/{}",
                execution_text(execution),
                binding.compatibility.node_id
            ))?;
            let owner = OwnerIdentity {
                owner: old.owner.clone(),
                incarnation: incarnation.clone(),
                generation: old.generation.checked_add(U64::new(1))?,
            };
            let bytes = canonical::canonical_json(&serde_json::json!({
                "schema":"crucible.installed-replay-restored-cursor-enrollment.v1",
                "source":source.artifact(),"target_owner":owner,"host":self.host_identity,
            }))?;
            let receipt = canonical::content_ref(&bytes, "application/json")?;
            profile.enrolled.insert(
                binding.compatibility.node_id.clone(),
                InputPayload {
                    reference: receipt.clone(),
                    bytes,
                },
            );
            binding.authority.session_id = Id::new(format!(
                "session/replay-restored/{}",
                execution_text(execution)
            ))?;
            binding.authority.incarnation_id = incarnation;
            binding.authority.realization_id = Id::new(format!(
                "realization/replay-restored/{}/{}",
                execution_text(execution),
                binding.compatibility.node_id
            ))?;
            binding.authority.input_epoch = Id::new(format!(
                "input/replay-restored/{}/{}",
                execution_text(execution),
                binding.compatibility.node_id
            ))?;
            binding.authority.owner_generation = owner.generation;
            binding.authority.host_receipt = receipt;
            profile.record.owners.push(owner);
        }
        profile
            .scenario
            .content
            .sort_by(|a, b| a.reference.cmp(&b.reference));
        profile.record.owners.sort();
        Ok(Self {
            source: self.source.clone(),
            profile,
            host_executable: self.host_executable.clone(),
            host_identity: self.host_identity.clone(),
            device_executable: self.device_executable.clone(),
            device_identity: self.device_identity.clone(),
            thread: self.thread,
        })
    }

    pub(super) fn check_thread(&self) -> Result<(), NodeObservedError> {
        if std::thread::current().id() != self.thread
            || self.profile.bindings.len() != self.source.sources.len()
            || self.source.selections.len() != self.source.sources.len()
            || self
                .source
                .selections
                .iter()
                .any(|selection| !self.source.sources.contains_key(&selection.node))
        {
            return Err(refused(
                "original allocated replay cursor roster or thread differs",
            ));
        }
        Ok(())
    }

    pub(super) fn check_scope(&self) -> Result<(), NodeObservedError> {
        self.check_thread()?;
        if measure_executable(&self.host_executable)? != self.host_identity {
            return Err(refused(
                "installed replay host image differs from allocated source scope",
            ));
        }
        Ok(())
    }

    pub(super) fn profile(&self) -> &replay_profile::ReplayProfile {
        &self.profile
    }
    pub(super) fn source(&self) -> &source_enrollment::VerifiedRecordedWorld {
        &self.source
    }
    pub(super) fn host_identity(&self) -> &ContentRef {
        &self.host_identity
    }
    pub(super) fn source_for(&self, node: &Id) -> Option<&AuthenticatedTranscript> {
        self.source.sources.get(node)
    }
}
