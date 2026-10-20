//! Retains an original complete-source preparation plan without effect permission.
//!
//! The same concrete roster, genuine Host2 source, measured graph and private
//! launches remain owned throughout preparation. Every normative obligation is
//! explicit and unexecuted. Capture and operation callbacks inherit refusal.

mod report_startup;
mod retained;
pub use report_startup::{
    PacketCompleteFreshRestorationInputs, PacketCompleteNativeLaunchInputs,
    PacketCompleteOriginalSceneInputs, PacketCompleteOriginalSceneSupervisor,
    PacketCompletePreparationConnection, PacketCompleteReportStartupHolder,
};

use super::super::scope;
use super::{
    InstalledPacketCompleteGraphPolicy, PacketCompletePopulationRequest, PacketCompleteRoster,
    PacketCompleteWitnessPopulation, QualificationError, refused,
};
use crate::node_qualification::{PlannedFixtureAudit, QualificationLimits, WitnessPlan};
use crucible_engine::{
    node_adapters::cnp::{CnpSemanticInstallation, CnpSemanticSource},
    node_admission::{
        ConformancePlanEvidence, EvidenceError, InstalledConformancePlan, ScenarioRequirements,
    },
    node_contract::{HostSchedulingSource, OperationFailure},
};
use crucible_node_format::{ContentRef, HashRef, WorldBinding, canonical};
use crucible_node_transport::reference_packet::{
    coordinator::PacketNative5CoordinatorInstallation,
    service::{PacketConnectedSourceProgram, PacketNative5SourceLaunch},
};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    rc::Rc,
};

mod admission;
mod unit;

/// Borrows one exact complete-source scene before native process birth.
pub struct PacketCompleteCollectionRequest<'a> {
    /// Retains the original producer, relay and sink source allocations.
    pub roster: PacketCompleteRoster,
    /// Retains the genuine complete Host2 factory source.
    pub host: Rc<HostSchedulingSource>,
    /// Retains the independently measured structural graph issuer.
    pub graph_policy: Rc<InstalledPacketCompleteGraphPolicy>,
    /// Borrows the complete four-owner world.
    pub world: &'a WorldBinding,
    /// Borrows the unchanged preparation-only scenario requirements.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows all exact source-authored bodies.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows the complete initial coordinator, without predicted readiness.
    pub coordinator: &'a PacketNative5CoordinatorInstallation,
    /// Owns all three full source-selected native launch declarations.
    pub launches: [PacketNative5SourceLaunch; 3],
    /// Owns the exact private session directories selected before Child.
    pub directories: [PathBuf; 3],
    /// Bounds the full original witness and audit population.
    pub limits: QualificationLimits,
    /// Bounds complete canonical Refused audit bytes before retention.
    pub maximum_audit_bytes: usize,
}

type OriginalAckHelloSlot =
    Rc<RefCell<Option<crucible_node_transport::client::OriginalHelloJournal>>>;

/// Retains the exact original preparation scope and full Refused witness plan.
///
/// This authority grants no operation, Arm, Capture, restore or class acceptance.
/// An independently installed complete factory must supply those later gates.
pub struct InstalledPacketCompleteCollectionAuthority {
    roster: PacketCompleteRoster,
    host: Rc<HostSchedulingSource>,
    graph_policy: Rc<InstalledPacketCompleteGraphPolicy>,
    world: WorldBinding,
    requirements: HashRef,
    kernel: String,
    population: PacketCompleteWitnessPopulation,
    audit: PlannedFixtureAudit,
    refused_reference: ContentRef,
    refused_bytes: Vec<u8>,
    roots: Vec<ContentRef>,
    private_launches: [Vec<u8>; 3],
    original_launches: [PacketNative5SourceLaunch; 3],
    report_startup_holder:
        OnceCell<std::rc::Weak<RefCell<report_startup::PacketCompleteReportStartupHolder>>>,
    directories: [PathBuf; 3],
    original_ack_hello: RefCell<[Option<OriginalAckHelloSlot>; 3]>,
    original_ack_callback_started: Cell<bool>,
    // Only an issued initial-lifecycle window selects the bounded callback path.
    original_initial_callback_active: Cell<bool>,
    original_runtime_callback_active: Cell<bool>,
    capture_factory: OnceCell<std::rc::Weak<super::capture_factory::PacketCompleteCaptureFactory>>,
    execution_scene: OnceCell<std::rc::Weak<super::execution::PacketCompleteExecutionScene>>,
}

impl InstalledPacketCompleteCollectionAuthority {
    /// Reconstructs the complete measured unit and its unexecuted population.
    ///
    /// # Errors
    /// Refuses changed source/host/file custody, foreign launch declarations,
    /// incomplete original obligations or exhausted pre-effect storage ceilings.
    pub fn install(
        request: PacketCompleteCollectionRequest<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        if request.maximum_audit_bytes == 0 || request.maximum_audit_bytes > 8 * 1024 * 1024 {
            return Err(refused());
        }
        let requirements =
            canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
        request.graph_policy.authenticate_scope(
            &request.roster,
            &request.host,
            request.world,
            &requirements,
        )?;
        request.graph_policy.authenticate_content(request.content)?;
        scope::encoded_size(
            &(&request.launches, request.world, request.requirements),
            8 * 1024 * 1024,
        )?;
        if request.coordinator != &request.roster.coordinator {
            return Err(refused());
        }
        let coordinator = encoded(request.coordinator)?;
        for member in 0..3 {
            let source = &request.roster.sources[member];
            let selected = source.installation();
            let launch = &request.launches[member];
            launch
                .validate()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
            let program = match &launch.program {
                PacketConnectedSourceProgram::Producer { program } => encoded(program),
                PacketConnectedSourceProgram::Reactive { program } => encoded(program),
            }?;
            if launch.initial_coordinator.bytes.as_slice() != coordinator
                || canonical::content_ref(&program, "application/json")?
                    != selected.descriptor.model_ref
                || request.content.get(&selected.descriptor.model_ref) != Some(&program)
                || launch.selection != request.coordinator.participants[member]
                || request.directories[member].file_name().is_none()
                || request.directories[..member].contains(&request.directories[member])
            {
                return Err(refused());
            }
            authenticate_expected_launch_selections(source, launch)?;
            let expected = source
                .selected_storage_selection()
                .map_err(operation_qualification)?;
            let expected_profile = source
                .selected_capture_profile()
                .map_err(operation_qualification)?;
            if launch.storage != expected.storage
                || launch.limits != expected.limits
                || &launch.capture_profile != expected_profile
            {
                return Err(refused());
            }
        }
        let unit::InterpretedUnit {
            unit,
            content,
            kernel,
        } = unit::interpret(&request)?;
        let population = PacketCompleteWitnessPopulation::build(PacketCompletePopulationRequest {
            unit,
            content: &content,
        })?;
        let audit = PlannedFixtureAudit::prepare(
            &population.plan,
            &population.reference,
            request.limits,
            request.maximum_audit_bytes,
        )?;
        let refused_bytes = encoded(audit.record())?;
        let refused_reference = canonical::content_ref(&refused_bytes, "application/json")?;
        let unit = &population.plan.unit;
        let mut roots = vec![
            population.reference.clone(),
            unit.implementation.clone(),
            unit.realization.clone(),
            unit.descriptors.clone(),
            unit.contracts.clone(),
            unit.port_profiles.clone(),
            unit.environment.clone(),
            unit.harness.clone(),
            unit.fixtures.clone(),
            unit.specification.clone(),
            population.plan.limitations.clone(),
        ];
        roots.sort();
        roots.dedup();
        let private_launches = request.launches.each_ref().map(encoded);
        let [first, second, third] = private_launches;
        let original = Rc::new(Self {
            original_ack_hello: RefCell::new(std::array::from_fn(|_| None)),
            original_ack_callback_started: Cell::new(false),
            original_initial_callback_active: Cell::new(false),
            original_runtime_callback_active: Cell::new(false),
            capture_factory: OnceCell::new(),
            execution_scene: OnceCell::new(),
            report_startup_holder: OnceCell::new(),
            roster: request.roster,
            host: request.host,
            graph_policy: request.graph_policy,
            world: request.world.clone(),
            requirements,
            kernel,
            population,
            audit,
            refused_reference,
            refused_bytes,
            roots,
            private_launches: [first?, second?, third?],
            original_launches: request.launches,
            directories: request.directories,
        });
        original.current()?;
        Ok(original)
    }

    /// Reauthenticates original source, Host2 and measured file custody.
    ///
    /// # Errors
    /// Refuses changed source allocations, revocation, foreign origin or kernel.
    pub fn current(&self) -> Result<(), QualificationError> {
        if self.original_runtime_callback_active.get() {
            // Only a retained opaque Core construction member enables this
            // same-body bounded file/kernel/Source callback phase.
            return self.current_for_original_initial_callback();
        }
        self.graph_policy.authenticate_scope(
            &self.roster,
            &self.host,
            &self.world,
            &self.requirements,
        )?;
        if super::super::fixture::world_fixture_kernel()? != self.kernel {
            return Err(refused());
        }
        self.population.reference.verify(&self.population.bytes)?;
        if !matches!(
            self.audit.record().decision,
            crate::node_qualification::AcceptanceDecision::Refused { .. }
        ) {
            return Err(refused());
        }

        self.graph_policy.authenticate_scope(
            &self.roster,
            &self.host,
            &self.world,
            &self.requirements,
        )
    }

    /// Retains this same original authority beneath the opaque collecting plan.
    ///
    /// # Errors
    /// Refuses a stale original plan, changed file/source custody or credit excess.
    pub fn collection_plan(self: &Rc<Self>) -> Result<InstalledConformancePlan, EvidenceError> {
        self.current().map_err(evidence_error)?;
        InstalledConformancePlan::install(self.plan_evidence(), self.clone())
    }

    pub(super) fn capture_graph_policy(&self) -> &InstalledPacketCompleteGraphPolicy {
        &self.graph_policy
    }

    pub(super) fn bind_capture_factory(
        &self,
        factory: &Rc<super::capture_factory::PacketCompleteCaptureFactory>,
    ) -> Result<(), crucible_engine::node_state::StateError> {
        self.current().map_err(super::capture_records::error)?;
        factory.authenticate_authority_object(self)?;
        self.capture_factory
            .set(Rc::downgrade(factory))
            .map_err(|_| {
                super::capture_records::refused("original complete factory was already installed")
            })
    }

    pub(super) fn original_capture_factory(
        &self,
    ) -> Result<Rc<super::capture_factory::PacketCompleteCaptureFactory>, EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.capture_factory
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(|| evidence_error(refused()))
    }

    pub(super) fn requirements_identity(&self) -> &HashRef {
        &self.requirements
    }

    pub(super) fn bind_execution_scene(
        &self,
        scene: &Rc<super::execution::PacketCompleteExecutionScene>,
    ) -> Result<(), QualificationError> {
        self.current()?;
        if !scene.has_authority(self) {
            return Err(refused());
        }
        self.execution_scene
            .set(Rc::downgrade(scene))
            .map_err(|_| refused())
    }

    pub(super) fn original_execution_scene(
        &self,
    ) -> Result<Rc<super::execution::PacketCompleteExecutionScene>, QualificationError> {
        self.current()?;
        self.execution_scene
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(refused)
    }

    /// Borrows the complete original unit and all unexecuted normative cases.
    pub fn witness_plan(&self) -> &WitnessPlan {
        &self.population.plan
    }

    /// Borrows the original complete world declaration.
    pub fn world(&self) -> &WorldBinding {
        &self.world
    }

    /// Borrows the same genuine Host2 factory source.
    pub fn host_source(&self) -> &Rc<HostSchedulingSource> {
        &self.host
    }

    /// Borrows the three original concrete source handles.
    pub fn roster(&self) -> &PacketCompleteRoster {
        &self.roster
    }

    /// Borrows the exact original complete coordinator declaration.
    pub fn coordinator(&self) -> &PacketNative5CoordinatorInstallation {
        &self.roster.coordinator
    }

    /// Retains the original recorded-Hello slot before the first realization callback.
    ///
    /// The slot starts empty and later receives the same SDK-recorded journal.
    /// Source authentication compares its actual literal bank and controller;
    /// merely installing a sidecar grants no preparation or operation authority.
    ///
    /// # Errors
    /// Refuses a foreign source origin, an unselected or invalid member, a late
    /// or repeated slot, a borrowed journal, or a slot that already owns a journal.
    pub fn bind_original_ack_hello_slot(
        &self,
        member: usize,
        slot: Rc<RefCell<Option<crucible_node_transport::client::OriginalHelloJournal>>>,
    ) -> Result<(), QualificationError> {
        let source = self.roster.sources.get(member).ok_or_else(refused)?;
        if source
            .selected_ack_emitter_selection()
            .map_err(|_| refused())?
            .is_none()
        {
            return Err(refused());
        }
        self.current()?;
        if self.original_ack_callback_started.get()
            || slot.try_borrow().map_err(|_| refused())?.is_some()
        {
            return Err(refused());
        }
        let mut originals = self
            .original_ack_hello
            .try_borrow_mut()
            .map_err(|_| refused())?;
        if originals[member].is_some() {
            return Err(refused());
        }
        originals[member] = Some(slot);
        Ok(())
    }

    /// Borrows one original source without replacing its concrete allocation.
    ///
    /// # Errors
    /// Refuses a foreign index, revoked scope or changed measured file custody.
    pub fn semantic_source(
        &self,
        member: usize,
    ) -> Result<Rc<dyn CnpSemanticSource>, QualificationError> {
        self.current()?;
        let source = self.roster.sources.get(member).ok_or_else(refused)?;
        let answer: Rc<dyn CnpSemanticSource> = source.clone();
        self.current()?;
        Ok(answer)
    }

    /// Authenticates the complete private launch against its original measured slot.
    ///
    /// # Errors
    /// Refuses changed launch bytes, executable path, directory or current source.
    pub fn authenticate_private_peer(
        &self,
        launch: &PacketNative5SourceLaunch,
        executable: &Path,
        directory: &Path,
    ) -> Result<(), QualificationError> {
        self.current()?;
        let index = self
            .roster
            .coordinator
            .participants
            .iter()
            .position(|one| one == &launch.selection)
            .ok_or_else(refused)?;
        let measured = &self.graph_policy.measurements()[index];
        if executable != measured.peer.path
            || directory != self.directories[index]
            || encoded(launch)? != self.private_launches[index]
        {
            return Err(refused());
        }
        self.current()
    }

    // Pointer equality precedes callbacks: equal portable data cannot enroll a
    // different source allocation into this original collection authority.
    fn index(&self, selected: &CnpSemanticInstallation) -> Result<usize, QualificationError> {
        self.roster
            .sources
            .iter()
            .position(|source| std::ptr::eq(source.installation(), selected))
            .ok_or_else(refused)
    }

    fn plan_evidence(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: &self.population.reference,
            plan_bytes: &self.population.bytes,
            refused_ref: &self.refused_reference,
            refused_bytes: &self.refused_bytes,
            world: &self.roster.sources[0].installation().world_binding_hash,
            sources: &self.roots,
        }
    }

    fn authenticate_plan_view(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        if self.original_initial_callback_active.get() {
            return self.authenticate_original_plan_view_interval_data(plan);
        }

        self.current_for_original_initial_callback()
            .map_err(evidence_error)?;
        let original = self.plan_evidence();
        if plan.plan_ref != original.plan_ref
            || plan.plan_bytes != original.plan_bytes
            || plan.refused_ref != original.refused_ref
            || plan.refused_bytes != original.refused_bytes
            || plan.world != original.world
            || plan.sources != original.sources
        {
            return Err(evidence_error(refused()));
        }
        self.current_for_original_initial_callback()
            .map_err(evidence_error)
    }
}

fn encoded(value: &impl serde::Serialize) -> Result<Vec<u8>, QualificationError> {
    scope::encoded_size(value, 8 * 1024 * 1024)?;
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?,
    )?)
}

// This matches QualificationError's public Display text. A closed refusal
// writes into one exact requested bank instead of hidden formatter growth;
// other error families preserve their original formatting behavior.
const QUALIFICATION_REFUSAL_PREFIX: &str = "qualification refused: ";

fn qualification_reason(error: QualificationError) -> String {
    match error {
        QualificationError::Refused(message) => {
            let mut reason =
                String::with_capacity(QUALIFICATION_REFUSAL_PREFIX.len() + message.len());
            reason.push_str(QUALIFICATION_REFUSAL_PREFIX);
            reason.push_str(message);
            reason
        }
        error => error.to_string(),
    }
}

fn evidence_error(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: qualification_reason(error),
    }
}

fn operation_error(error: QualificationError) -> OperationFailure {
    OperationFailure {
        effects: crucible_engine::node_contract::EffectKnowledge::None,
        reason: qualification_reason(error),
    }
}

fn operation_qualification(error: OperationFailure) -> QualificationError {
    QualificationError::Evidence(error.reason)
}

/// Compares independently bound Source choices before actual launch effects.
pub(super) fn authenticate_expected_launch_selections(
    source: &crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), QualificationError> {
    if launch.confirmation_selection
        != source
            .selected_confirmation_selection()
            .map_err(operation_qualification)?
        || launch.ack_emitter_selection
            != source
                .selected_ack_emitter_selection()
                .map_err(operation_qualification)?
        || launch.complete_restore_selection
            != source
                .selected_complete_restore_selection()
                .map_err(operation_qualification)?
        || launch.protocol_metadata_limits
            != source
                .selected_protocol_metadata_limits()
                .map_err(operation_qualification)?
        || launch.capture_allocation_selection
            != source
                .selected_capture_allocation_selection()
                .map_err(operation_qualification)?
        || launch.fresh_restore_allocation_selection
            != source
                .selected_fresh_restore_allocation_selection()
                .map_err(operation_qualification)?
        || launch.restore_input_emitter_selection
            != source
                .selected_restore_input_emitter_selection()
                .map_err(operation_qualification)?
        || launch.native_codec_metadata_extent
            != source
                .selected_native_ack_codec_metadata_extent()
                .map_err(operation_qualification)?
    {
        return Err(refused());
    }
    Ok(())
}
