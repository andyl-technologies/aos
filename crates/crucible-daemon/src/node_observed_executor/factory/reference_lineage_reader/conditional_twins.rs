//! Owns both fresh complete Runtime7 branches through publication and continuation.
//!
//! Complete pins are retained before reference-counted sharing or fresh model
//! construction. Refusal leaves this capsule with every pin, model and original
//! pending token. The caller must keep it beside the retired source factory.

#![cfg(test)]

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use super::{
    conditional_admission,
    conditional_capture_factory::ConditionalCaptureFactory,
    conditional_policy::ConditionalPolicy,
    conditional_profile::ConditionalProfile,
    conditional_source::InspectionError,
    conditional_twins_publication::TwinsPublisher,
    conditional_twins_suffix,
    conditional_twins_verifier::{ModelEvidence, TwinsVerifier},
};
use crate::node_observed_executor::StoredWorldActivationPublisher;
use crucible::{
    node_adapters::transcript::{
        PinnedTape2Continuation, Tape2PreparationFailure, TranscriptReplayNode,
        authenticate_pinned_tape2_continuation,
    },
    node_admission::AdmittedGraph,
    node_contract::{
        NodeRoute, NodeRuntime, OperationToken, OriginalInputLineageLimits,
        OriginalLineageRestorationLimits, RuntimeCustodyQueue, RuntimeCustodySlot,
        RuntimeCustodySupervisor, RuntimeLimits, RuntimePreparationFailure, SavedRuntimeResult,
        SimulationNode, WorldActivation,
    },
    node_scheduling::{InputPayload, NativePublication, PreparedSchedulingRestore},
    node_state::PinnedOriginalLineageSource,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend, RefName};

/// Owns the original pin transfer even when sharing or fresh preparation refuses.
pub(super) struct ConditionalTwins<'a> {
    source: Rc<ConditionalProfile>,
    source_graph: &'a AdmittedGraph,
    factory: &'a ConditionalCaptureFactory,
    original_pins: Vec<PinnedOriginalLineageSource>,
    pins: Vec<Rc<PinnedOriginalLineageSource>>,
    branches: Vec<Branch>,
    attempted: bool,
}

impl<'a> ConditionalTwins<'a> {
    /// Takes the entire original vector before any allocation or source callback.
    pub(super) fn new(
        source: Rc<ConditionalProfile>,
        source_graph: &'a AdmittedGraph,
        factory: &'a ConditionalCaptureFactory,
        pins: Vec<PinnedOriginalLineageSource>,
    ) -> Self {
        Self {
            source,
            source_graph,
            factory,
            original_pins: pins,
            pins: Vec::new(),
            branches: Vec::new(),
            attempted: false,
        }
    }

    /// Prepares and publishes both fresh worlds from the same owned source cut.
    pub(super) fn restore(&mut self) -> Result<(), InspectionError> {
        if self.attempted || self.original_pins.len() != 3 {
            return Err("twins restoration repeated or original pin roster differs".into());
        }
        self.attempted = true;
        self.pins.try_reserve_exact(3).map_err(text)?;
        self.branches.try_reserve_exact(2).map_err(text)?;
        let first = self.original_pins.first().ok_or("original pin absent")?;
        for pin in &self.original_pins {
            if pin.source_artifact() != first.source_artifact()
                || pin.runtime_reference() != first.runtime_reference()
                || pin.runtime() != first.runtime()
                || pin.scheduling() != first.scheduling()
                || pin.content().object_count() > 4096
                || pin.content().total_bytes() > 384 * 1024 * 1024
                || pin.original_objects().any(|(reference, bytes)| {
                    reference.length.get() > 256 * 1024 * 1024 || bytes.len() > 256 * 1024 * 1024
                })
            {
                return Err(
                    "twins complete original source roster or archive credit differs".into(),
                );
            }
            self.factory
                .verify_pinned_source(self.source_graph, pin)
                .map_err(text)?;
        }
        // The capsule owns both vectors during conversion. Each moved pin is
        // installed into its reserved destination immediately, before callbacks.
        while let Some(pin) = self.original_pins.pop() {
            self.pins.push(Rc::new(pin));
        }
        let first = self.pins.first().ok_or("shared original pin absent")?;
        for name in ["fresh-left", "fresh-right"] {
            let profile = Rc::new(self.source.fresh_target(first, name)?);
            self.branches.push(Branch::new(profile, name)?);
            let branch = self.branches.last_mut().ok_or("owned branch absent")?;
            branch.prepare_models(&self.pins)?;
            branch.publish_and_install(
                &self.source,
                self.source_graph,
                self.factory,
                &self.pins,
            )?;
        }
        Ok(())
    }

    /// Finishes each original pending suffix once and compares both exact outputs.
    pub(super) fn complete_suffixes(&mut self) -> Result<(), InspectionError> {
        if self.branches.len() != 2 {
            return Err("both complete fresh branches are required".into());
        }
        for branch in &mut self.branches {
            branch.complete_suffix(&self.source)?;
        }
        if self.branches[0].publications != self.branches[1].publications {
            return Err("fresh original suffix publications differ".into());
        }
        Ok(())
    }

    /// Borrows actual published targets and their retained original suffix outputs.
    pub(super) fn results(
        &self,
    ) -> impl Iterator<
        Item = (
            &crucible::node_contract::ActivationRecord,
            &[NativePublication],
        ),
    > {
        self.branches.iter().filter_map(|branch| {
            branch
                .activation
                .as_ref()
                .map(|activation| (activation.record(), branch.publications.as_slice()))
        })
    }

    /// Retains actual fresh suffix journals before serialization or reclamation.
    pub(super) fn retain_suffix_witnesses(&mut self) -> Result<(), InspectionError> {
        if self.branches.len() != 2 {
            return Err("both fresh suffixes are required for journal retention".into());
        }
        for branch in &mut self.branches {
            branch.retain_suffix_witness()?;
        }
        Ok(())
    }

    /// Borrows original owning snapshots without granting another capture seal.
    pub(super) fn suffix_witnesses(
        &self,
    ) -> impl Iterator<
        Item = (
            &crucible::node_contract::ActivationRecord,
            &crucible::node_contract::OriginalLineageRuntimeRecord,
            &crucible::node_scheduling::SchedulingSnapshot,
        ),
    > {
        self.branches.iter().filter_map(|branch| {
            Some((
                branch.activation.as_ref()?.record(),
                branch.suffix_runtime.as_ref()?,
                branch.suffix_scheduler.as_ref()?,
            ))
        })
    }

    /// Reclaims both actual runtime rosters while keeping every source pin owned.
    pub(super) fn retire(&mut self) -> Result<(), InspectionError> {
        if self.branches.len() != 2 {
            return Err("both complete fresh branches are required for retirement".into());
        }
        for branch in &mut self.branches {
            branch.retire()?;
        }
        Ok(())
    }
}

impl Drop for ConditionalTwins<'_> {
    fn drop(&mut self) {
        // Declaration order cannot release pins before guarded branch teardown.
        // A parked branch therefore retains the complete source capsule too.
        self.branches.clear();
    }
}

struct Branch {
    profile: Rc<ConditionalProfile>,
    graph: AdmittedGraph,
    queue: RuntimeCustodyQueue,
    slot: Option<Box<dyn RuntimeCustodySlot>>,
    directory: Option<tempfile::TempDir>,
    models: Vec<Box<dyn SimulationNode>>,
    preparing: Option<PinnedTape2Continuation>,
    model: Option<TranscriptReplayNode>,
    model_failure: Option<Tape2PreparationFailure>,
    runtime_failure: Option<Box<RuntimePreparationFailure>>,
    runtime: Option<NodeRuntime>,
    evidence: Vec<ModelEvidence>,
    proof_custody: Vec<InputPayload>,
    scheduling: Option<PreparedSchedulingRestore>,
    publisher: Option<TwinsPublisher>,
    activation: Option<WorldActivation>,
    pending: Vec<OperationToken>,
    publications: Vec<NativePublication>,
    suffix_attempted: bool,
    retirement_attempted: bool,
    retired: bool,
    witness_attempted: bool,
    suffix_runtime: Option<crucible::node_contract::OriginalLineageRuntimeRecord>,
    suffix_scheduler: Option<crucible::node_scheduling::SchedulingSnapshot>,
}

impl Branch {
    fn new(profile: Rc<ConditionalProfile>, name: &str) -> Result<Self, InspectionError> {
        use std::os::unix::fs::PermissionsExt;
        let graph = conditional_admission::admit(&profile)?;
        let queue = RuntimeCustodyQueue::new(1).map_err(text)?;
        let slot = queue
            .reserve_world(&profile.activation, RuntimeLimits::default())
            .map_err(text)?;
        let mut branch = Self {
            profile,
            graph,
            queue,
            slot: Some(slot),
            directory: None,
            models: Vec::new(),
            preparing: None,
            model: None,
            model_failure: None,
            runtime_failure: None,
            runtime: None,
            evidence: Vec::new(),
            proof_custody: Vec::new(),
            scheduling: None,
            publisher: None,
            activation: None,
            pending: Vec::new(),
            publications: Vec::new(),
            suffix_attempted: false,
            retirement_attempted: false,
            retired: false,
            witness_attempted: false,
            suffix_runtime: None,
            suffix_scheduler: None,
        };
        branch.models.try_reserve_exact(3).map_err(text)?;
        branch.evidence.try_reserve_exact(3).map_err(text)?;
        branch.proof_custody.try_reserve_exact(3).map_err(text)?;
        branch.pending.try_reserve_exact(3).map_err(text)?;
        branch.publications.try_reserve_exact(3).map_err(text)?;
        branch.directory = Some(
            tempfile::Builder::new()
                .prefix(&format!("reader-tape2-{name}-"))
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")
                .map_err(text)?,
        );
        Ok(branch)
    }

    fn prepare_models(
        &mut self,
        pins: &[Rc<PinnedOriginalLineageSource>],
    ) -> Result<(), InspectionError> {
        let policy = ConditionalPolicy::install(Rc::clone(&self.profile))?;
        for node in self.graph.node_ids() {
            let binding = self.graph.binding(node).ok_or("fresh binding absent")?;
            let mut selected = pins.iter().filter(|pin| {
                pin.source().owner().owner == binding.compatibility.execution_owner.id
            });
            let pin = selected.next().ok_or("fresh original owner pin absent")?;
            if selected.next().is_some() {
                return Err("fresh original owner pin is ambiguous".into());
            }
            let owner = self
                .profile
                .activation
                .owners
                .iter()
                .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .ok_or("fresh actual owner absent")?;
            let mut owners = Vec::new();
            owners.try_reserve_exact(1).map_err(text)?;
            owners.push(owner.clone());
            self.preparing =
                Some(authenticate_pinned_tape2_continuation(Rc::clone(pin), node).map_err(text)?);
            let original = self
                .profile
                .history
                .originals
                .get(node)
                .ok_or("original MAC transcript absent")?;
            let source = self.preparing.take().ok_or("owned continuation absent")?;
            match TranscriptReplayNode::prepare_restored_original_lineage(
                source,
                &self.graph,
                NodeRoute {
                    node: node.clone(),
                    owners,
                },
                &original.transcript().origin.context,
                &policy,
            ) {
                Ok(model) => self.model = Some(model),
                Err(failure) => {
                    self.model_failure = Some(failure);
                    return Err(text(
                        self.model_failure
                            .as_ref()
                            .ok_or("owned failure absent")?
                            .error(),
                    ));
                }
            }
            // Evidence comes only from this retained actual inactive model.
            let native = self
                .model
                .as_ref()
                .ok_or("held fresh model absent")?
                .original_lineage_restoration_evidence(&self.profile.activation)
                .map_err(text)?;
            self.evidence.push(ModelEvidence {
                node: node.clone(),
                native,
            });
            self.models
                .push(Box::new(self.model.take().ok_or("held model disappeared")?));
        }
        let slot = self.slot.take().ok_or("fresh world reservation absent")?;
        match NodeRuntime::new(
            &self.graph,
            std::mem::take(&mut self.models),
            self.profile.activation.clone(),
            RuntimeLimits::default(),
            slot,
        ) {
            Ok(runtime) => self.runtime = Some(runtime),
            Err(failure) => {
                self.runtime_failure = Some(failure);
                return Err(text(
                    &self
                        .runtime_failure
                        .as_ref()
                        .ok_or("owned runtime failure absent")?
                        .error,
                ));
            }
        }
        Ok(())
    }

    fn publish_and_install(
        &mut self,
        source_profile: &ConditionalProfile,
        source_graph: &AdmittedGraph,
        factory: &ConditionalCaptureFactory,
        pins: &[Rc<PinnedOriginalLineageSource>],
    ) -> Result<(), InspectionError> {
        let first = pins.first().ok_or("complete original source absent")?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or("inactive fresh runtime absent")?;
        let mut verifier = TwinsVerifier {
            source_graph,
            source_profile,
            factory,
            pins,
            target_profile: &self.profile,
            target_graph: &self.graph,
            evidence: &self.evidence,
            proof_custody: &mut self.proof_custody,
        };
        let context = runtime
            .prepare_original_lineage_restoration(
                first.runtime_reference(),
                first.content(),
                first.scheduling(),
                &self.profile.activation,
                &mut verifier,
                OriginalLineageRestorationLimits {
                    lineage: OriginalInputLineageLimits::default(),
                    maximum_record_bytes: 8 * 1024 * 1024,
                },
            )
            .map_err(text)?;
        self.scheduling = Some(
            runtime
                .prepare_original_lineage_scheduler(
                    &self.graph,
                    &context,
                    first.scheduling().clone(),
                )
                .map_err(text)?,
        );
        runtime
            .arm_original_lineage_restoration(&context)
            .map_err(text)?;
        let root = self
            .directory
            .as_ref()
            .ok_or("fresh publication directory absent")?
            .path();
        let stored = StoredWorldActivationPublisher::new(
            Arc::new(DirectoryBlobBackend::new(
                "reader-tape2-fresh",
                root.join("blobs"),
            )),
            Arc::new(DirectoryRefBackend::new(root.join("refs"))),
            RefName::new("node-world-activations/reader-tape2-fresh").map_err(text)?,
        )
        .map_err(text)?;
        self.publisher = Some(TwinsPublisher::new(
            stored,
            Rc::clone(first),
            self.profile.activation.clone(),
        ));
        self.activation = Some(
            runtime
                .activate(self.publisher.as_mut().ok_or("owned publisher absent")?)
                .map_err(text)?,
        );
        let activation = self
            .activation
            .as_ref()
            .ok_or("actual fresh publication absent")?;
        runtime
            .install_complete_original_lineage_restoration(
                &self.graph,
                &context,
                activation,
                self.scheduling
                    .take()
                    .ok_or("owned original scheduler absent")?,
            )
            .map_err(text)?;
        for saved in &first.runtime().operations {
            if matches!(saved.result, SavedRuntimeResult::Pending) {
                self.pending
                    .push(runtime.recover(&saved.operation).map_err(text)?);
            }
        }
        if self.pending.len() != 3 {
            return Err("fresh original pending roster differs".into());
        }
        Ok(())
    }

    fn complete_suffix(&mut self, source: &ConditionalProfile) -> Result<(), InspectionError> {
        if self.suffix_attempted || self.pending.len() != 3 {
            return Err("fresh original suffix repeated or pending roster differs".into());
        }
        self.suffix_attempted = true;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or("published fresh runtime absent")?;
        for token in &self.pending {
            let publication = conditional_twins_suffix::complete(runtime, token, source)?;
            self.publications.push(publication);
        }
        self.publications
            .sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
        Ok(())
    }
}

impl Branch {
    fn retain_suffix_witness(&mut self) -> Result<(), InspectionError> {
        use crucible_node_contract::{Phase, Position, U64};

        if self.witness_attempted || self.retirement_attempted || self.publications.len() != 3 {
            return Err("fresh suffix witness repeated or actual suffix incomplete".into());
        }
        self.witness_attempted = true;
        let runtime = self.runtime.as_mut().ok_or("fresh suffix runtime absent")?;
        let activation = self
            .activation
            .as_ref()
            .ok_or("fresh suffix activation absent")?;
        if activation.record() != &self.profile.activation {
            return Err("fresh suffix activation changed".into());
        }
        let cut = Position::new(U64::new(3000), U64::new(0), Phase::BoundaryControl);
        let ordinal = U64::new(9);

        // Each actual owning result is retained before the next export/callback.
        // These reference-only views do not sign or qualify another archive.
        self.suffix_runtime = Some(
            runtime
                .original_lineage_runtime_snapshot(
                    cut,
                    ordinal,
                    OriginalInputLineageLimits::default(),
                    8 * 1024 * 1024,
                )
                .map_err(text)?,
        );
        self.suffix_scheduler = Some(
            runtime
                .original_lineage_scheduler_snapshot(activation, cut, ordinal)
                .map_err(text)?,
        );
        let saved = self
            .suffix_runtime
            .as_ref()
            .ok_or("retained fresh Runtime7 absent")?;
        let scheduling = self
            .suffix_scheduler
            .as_ref()
            .ok_or("retained fresh Scheduler1 absent")?;
        if saved.source_activation
            != crucible::node_contract::SavedRuntimeActivation::from(activation.record())
            || saved.capture_cut != cut
            || saved.capture_ordinal != ordinal
            || saved.operations.len() != 9
            || saved
                .operations
                .iter()
                .any(|operation| !matches!(operation.result, SavedRuntimeResult::Acknowledged(_)))
            || saved.inputs.len() != 9
            || saved
                .inputs
                .iter()
                .any(|input| input.acknowledgement.is_none())
            || scheduling.capture_cut != cut
            || scheduling.capture_ordinal != ordinal
            || scheduling.source_activation_id != activation.record().activation_id
            || scheduling.source_generation != activation.record().generation
            || !scheduling.reservations.is_empty()
        {
            return Err("actual fresh suffix journal/cursor/acknowledgement roster differs".into());
        }
        Ok(())
    }

    fn retire(&mut self) -> Result<(), InspectionError> {
        if self.retired {
            return Ok(());
        }
        if self.retirement_attempted {
            return Err("fresh runtime retirement already crossed owning callbacks".into());
        }
        self.retirement_attempted = true;
        // The pins remain in the outer capsule while every actual model is
        // transferred to the reserved whole-world quarantine and reclaimed.
        let settled = catch_unwind(AssertUnwindSafe(|| {
            drop(self.runtime.take());
            drop(self.runtime_failure.take());
            if let Some(model) = self.model.take() {
                self.models.push(Box::new(model));
            }
            if !self.models.is_empty() {
                if let Some(slot) = self.slot.take() {
                    drop(NodeRuntime::new(
                        &self.graph,
                        std::mem::take(&mut self.models),
                        self.profile.activation.clone(),
                        RuntimeLimits::default(),
                        slot,
                    ));
                } else {
                    return false;
                }
            }
            drop(self.slot.take());
            let mut context = Context::from_waker(Waker::noop());
            for _ in 0..32 {
                if matches!(
                    self.queue.poll_reclamation(&mut context),
                    Poll::Ready(Err(_))
                ) {
                    return false;
                }
                if self.queue.reserved_worlds() == 0 {
                    return true;
                }
            }
            false
        }))
        .unwrap_or(false);
        if !settled {
            return Err("fresh runtime remains under complete owning quarantine".into());
        }
        self.retired = true;
        Ok(())
    }
}

impl Drop for Branch {
    fn drop(&mut self) {
        if self.retire().is_err() {
            // Callback refusal retains this complete branch and outer pins.
            loop {
                std::thread::park();
            }
        }
        if let Some(directory) = self.directory.take() {
            let _ = directory.keep();
        }
    }
}

fn text(error: impl std::fmt::Debug) -> InspectionError {
    format!("{error:?}").into()
}
