//! Retains a distinct complete-world packet source for original live collection.
//!
//! This concrete adapter selects edition five without translating its installation
//! into edition four. Underlying model records and input journals keep their
//! original dialects. Capture and fresh restoration remain unsupported until the
//! complete source-owned protocol and settlement mechanism is installed.

use super::packet_connected_source::*;
use super::*;
use crate::{node_contract::*, node_scheduling::*};
use crucible_node_contract::*;
use crucible_node_provider::{
    bodies::*,
    reference_packet::{
        connected::PacketConnectedDefinition, control::PacketNative5StorageSelection,
        coordinator::PacketNative5CoordinatorInstallation, service::PacketNative5CaptureProfile,
    },
};

#[path = "packet_complete_source/witness.rs"]
mod witness;

#[path = "packet_complete_source/native_objects.rs"]
mod native_objects;

#[path = "packet_complete_source/ancestry.rs"]
mod ancestry;

#[path = "packet_complete_source/capture_banks.rs"]
mod capture_banks;
pub use capture_banks::{PacketCompleteCaptureBankFacts, PacketCompleteCaptureBankLimits};

pub use witness::{PacketCompleteNativeRecord, PacketCompleteNativeWitness};

#[path = "packet_complete_source/preconstruction.rs"]
mod preconstruction;

#[path = "packet_complete_source/effects.rs"]
mod effects;
pub use effects::{PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader};

/// Identifies the original model retained by a complete collecting source.
///
/// This is immutable declaration data. It grants no native currentness,
/// execution, capture or restoration permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketCompleteSourceRole {
    /// Retains the unchanged output-only producer model.
    Producer,
    /// Retains the unchanged input-bearing reactive model.
    Reactive,
}

/// Retains an original edition-five packet source and its complete coordinator.
///
/// Construction checks the selected declaration only. The registry, current
/// original child, installed transport, realization and collection authority
/// remain independent guards. This object grants no capture or restart permission.
pub struct PacketCompleteSemanticSource {
    original: CompletePacketOriginal,
    process: u32,
    thread: std::thread::ThreadId,
    capture_banks: std::cell::RefCell<Option<capture_banks::PacketCompleteCaptureBanks>>,
    preconstruction: std::cell::RefCell<Option<preconstruction::OriginalCompletePreconstruction>>,
    effect_receiver: Option<effects::OriginalCompleteEffectReceiver>,
}

impl PacketCompleteSemanticSource {
    /// Retains a complete reactive selection for independently authorized collection.
    ///
    /// # Errors
    /// Refuses a changed native definition, whole coordinator, selected contract,
    /// owner roster, schema or finite source budget.
    pub fn new_reactive_for_collecting_world(
        installation: CnpSemanticInstallation,
        definition: PacketConnectedDefinition,
        coordinator: PacketNative5CoordinatorInstallation,
        storage_selection: PacketNative5StorageSelection,
    ) -> Result<Self, OperationFailure> {
        let reactive = PacketConnectedSemanticSource::new_complete_collecting(
            installation,
            definition,
            coordinator,
            storage_selection,
        )?;
        Ok(Self {
            original: CompletePacketOriginal::Reactive(Box::new(reactive)),
            process: std::process::id(),
            thread: std::thread::current().id(),
            capture_banks: std::cell::RefCell::new(None),
            preconstruction: std::cell::RefCell::new(None),
            effect_receiver: None,
        })
    }

    /// Retains a complete output-only source for independently authorized collection.
    ///
    /// # Errors
    /// Refuses a changed original producer program, whole coordinator, selected
    /// contract, owner roster, schema or finite source budget.
    pub fn new_producer_for_collecting_world(
        installation: CnpSemanticInstallation,
        program: crucible_node_provider::reference_packet::PacketProgramDefinition,
        coordinator: PacketNative5CoordinatorInstallation,
        storage_selection: PacketNative5StorageSelection,
    ) -> Result<Self, OperationFailure> {
        let source = PacketSemanticSource::new_complete_collecting(
            installation,
            program,
            coordinator,
            storage_selection,
        )?;
        Ok(Self {
            original: CompletePacketOriginal::Producer(Box::new(source)),
            process: std::process::id(),
            thread: std::thread::current().id(),
            capture_banks: std::cell::RefCell::new(None),
            preconstruction: std::cell::RefCell::new(None),
            effect_receiver: None,
        })
    }

    /// Binds the expected original capture profile before native association.
    ///
    /// This selection is immutable correlation data. It does not install an
    /// encoder, allocate protocol banks, or qualify capture and restoration.
    /// Existing constructors retain the original array profile by default.
    ///
    /// # Errors
    /// Refuses a foreign creator, an already associated native owner, a previous
    /// profile binding or reservation, or nonpositive/oversized compact bounds.
    pub fn bind_original_capture_profile(
        &mut self,
        profile: PacketNative5CaptureProfile,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        profile.validate().map_err(unknown)?;
        if self.capture_banks.get_mut().is_some() {
            return Err(refused("complete source profile follows bank reservation"));
        }

        let slot = match &mut self.original {
            CompletePacketOriginal::Producer(source) => {
                if !source.complete_preparation_unbound()? {
                    return Err(refused(
                        "complete source profile follows native association",
                    ));
                }
                &mut source.complete_capture_profile
            }
            CompletePacketOriginal::Reactive(source) => {
                if !source.complete_preparation_unbound()? {
                    return Err(refused(
                        "complete source profile follows native association",
                    ));
                }
                &mut source.complete_capture_profile
            }
        };
        if slot.is_some() {
            return Err(refused("complete source profile is already bound"));
        }
        *slot = Some(profile);
        Ok(())
    }

    /// Borrows the expected codec profile retained before native association.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread.
    pub fn selected_capture_profile(
        &self,
    ) -> Result<&PacketNative5CaptureProfile, OperationFailure> {
        self.ensure_origin()?;
        let profile = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_capture_profile.as_ref(),
            CompletePacketOriginal::Reactive(source) => source.complete_capture_profile.as_ref(),
        };
        Ok(profile.unwrap_or(&PacketNative5CaptureProfile::OriginalArrays6))
    }

    /// Returns the model role selected by the original concrete constructor.
    ///
    /// The role describes retained ownership; current native authority still
    /// requires the original source and process guards.
    pub fn role(&self) -> PacketCompleteSourceRole {
        match &self.original {
            CompletePacketOriginal::Producer(_) => PacketCompleteSourceRole::Producer,
            CompletePacketOriginal::Reactive(_) => PacketCompleteSourceRole::Reactive,
        }
    }

    // Raw origin precedes the original source's cells, controller and SDK reads.
    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() {
            return Err(refused(
                "complete source belongs to another creator process",
            ));
        }
        if self.thread != std::thread::current().id() {
            return Err(refused("complete source belongs to another creator thread"));
        }
        Ok(())
    }

    fn source(&self) -> &dyn CnpSemanticSource {
        match &self.original {
            CompletePacketOriginal::Producer(source) => source.as_ref(),
            CompletePacketOriginal::Reactive(source) => source.as_ref(),
        }
    }

    /// Authenticates the exact native custody attached to this original source.
    ///
    /// Equal installation metadata and another live child cannot satisfy this
    /// association. The source must already retain its genuine preparation read.
    ///
    /// # Errors
    /// Refuses a foreign creator, absent original preparation, changed original
    /// allocation, revoked registrar or no longer current native process.
    pub fn authenticate_original_native_owner(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.authenticate_complete_native_owner(native)
            }
            CompletePacketOriginal::Reactive(source) => {
                source.authenticate_complete_native_owner(native)
            }
        }
    }

    /// Borrows the immutable storage tuple retained by the original constructor.
    ///
    /// These declarations grant no physical allocation or capture permission.
    ///
    /// # Errors
    /// Refuses foreign origin or absent original complete storage selection.
    pub fn selected_storage_selection(
        &self,
    ) -> Result<&PacketNative5StorageSelection, OperationFailure> {
        self.ensure_origin()?;
        let selected = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_selected_storage(),
            CompletePacketOriginal::Reactive(source) => source.complete_selected_storage(),
        };
        selected.ok_or_else(|| refused("original complete storage selection is absent"))
    }

    /// Checks the same complete coordinator retained at original construction.
    ///
    /// # Errors
    /// Refuses a changed complete coordinator, native roster or host declaration.
    pub fn authenticate_collecting_world_scope(
        &self,
        coordinator: &PacketNative5CoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.authenticate_complete_world_scope(coordinator)
            }
            CompletePacketOriginal::Reactive(source) => {
                source.authenticate_complete_world_scope(coordinator)
            }
        }
    }

    /// Authenticates the original collecting declaration without native effects.
    ///
    /// # Errors
    /// Refuses a foreign creator or changed complete source-owned installation.
    pub fn authenticate_registration(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        super::preparation::validate_complete_installation(self.installation())
    }

    /// Checks the retained original native source without replacing its capsule.
    ///
    /// # Errors
    /// Refuses an absent, released, busy, foreign-process or changed original source.
    pub fn authenticate_current_native(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        match &self.original {
            CompletePacketOriginal::Producer(source) => source.authenticate_current_native(),
            CompletePacketOriginal::Reactive(source) => source.authenticate_current_native(),
        }
    }
}

impl CnpSemanticSource for PacketCompleteSemanticSource {
    fn preflight_complete_original_lineage_capture(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: crate::node_state::NativeArchiveLimits,
    ) -> Result<crate::node_state::CompleteOriginalOwnerCapturePreflight, OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_witness_scope(&scope)?;
        let runtime = scope
            .native
            .runtime
            .as_ref()
            .ok_or_else(|| refused("complete preflight has no owning semantic custody"))?;
        let active = runtime
            .active
            .as_ref()
            .filter(|active| active.same_authority(activation))
            .ok_or_else(|| refused("complete preflight has another original activation"))?;
        let saved = &record.source_activation;
        let original = active.record();
        if saved.generation != original.generation
            || saved.activation_id != original.activation_id
            || saved.world_binding_hash != original.world_binding_hash
            || saved.owners != original.owners
            || saved.boundary != original.boundary
        {
            return Err(refused("complete preflight Runtime7 activation differs"));
        }
        runtime_object
            .reference
            .verify(&runtime_object.bytes)
            .map_err(unknown)?;

        // Both reads borrow the SAME controller. Neither comes from the
        // registrar reader, a mirrored count or the launch declaration alone.
        let storage = scope
            .controller
            .original_native5_storage_facts()
            .map_err(unknown)?;
        let custody = scope
            .controller
            .original_native5_custody_facts()
            .map_err(unknown)?;
        let selected = self.selected_storage_selection()?;
        if !storage.all_io_complete
            || storage.maximum_frame_bytes as u64 != selected.limits.frame_bytes.get()
            || storage.maximum_history_bytes as u64 != selected.storage.frame_bank_bytes.get()
            || storage.maximum_frames_per_direction as u64
                != selected.storage.frames_per_direction.get()
            || custody.negotiated_journal_entries != selected.limits.journal_entries.get()
        {
            return Err(refused(
                "complete preflight actual bank or lifetime selection differs",
            ));
        }
        let maximum = usize::try_from(selected.storage.settlement_bytes.get())
            .map_err(|_| refused("complete semantic bank limit is not representable"))?
            .min(limits.native.maximum_record_bytes);
        super::semantic_snapshot::complete_size(runtime, maximum)?;
        self.authenticate_witness_scope(&scope)?;
        self.original_capture_bank_facts()?;
        self.original_ancestry_size(&scope)?;
        let chunk = usize::try_from(selected.limits.blob_chunk_bytes.get())
            .ok()
            .filter(|chunk| *chunk != 0)
            .ok_or_else(|| refused("complete prefix chunk bound is unavailable"))?;
        let objects = [
            selected.storage.snapshot_bytes.get(),
            selected.storage.control_snapshot_bytes.get(),
            8192,
        ];
        let mut provider_requests = 0usize;
        let mut content_bytes = 0usize;
        for object in objects {
            let bytes = usize::try_from(object)
                .map_err(|_| refused("complete prefix object is not representable"))?;
            let frames = bytes
                .checked_add(chunk - 1)
                .map(|n| n / chunk)
                .and_then(|chunks| chunks.checked_add(2))
                .ok_or_else(|| refused("complete prefix frame demand overflow"))?;
            provider_requests = provider_requests
                .checked_add(frames)
                .ok_or_else(|| refused("complete prefix request demand overflow"))?;
            content_bytes = content_bytes
                .checked_add(bytes)
                .ok_or_else(|| refused("complete prefix content demand overflow"))?;
        }
        let journal_bytes = provider_requests
            .checked_add(1)
            .and_then(|frames| frames.checked_mul(2))
            .and_then(|frames| frames.checked_mul(storage.maximum_frame_bytes))
            .ok_or_else(|| refused("complete prefix journal demand overflow"))?;
        scope
            .controller
            .preflight_source_reply(1, provider_requests, journal_bytes, 3, content_bytes)
            .map_err(unknown)?;
        let needed = provider_requests
            .checked_add(1)
            .ok_or_else(|| refused("complete prefix lifetime-frame demand overflow"))?;
        if storage
            .incoming_frames
            .checked_add(needed)
            .is_none_or(|frames| frames > storage.maximum_frames_per_direction)
            || storage
                .outgoing_frames
                .checked_add(needed)
                .is_none_or(|frames| frames > storage.maximum_frames_per_direction)
            || storage
                .retained_bytes
                .checked_add(journal_bytes)
                .is_none_or(|bytes| bytes > storage.maximum_history_bytes)
        {
            return Err(refused(
                "complete prefix exceeds original lifetime literal banks",
            ));
        }
        self.authenticate_witness_scope(&scope)?;

        // Current protocol facts and a complete semantic count are necessary,
        // but do not stand for allocated local settlement/ancestry banks or the
        // authenticated native suffix. No geometry row is issued before those
        // source-owned components are installed and fully charged.
        Err(refused(
            "complete local settlement and ancestry codecs are not installed",
        ))
    }

    fn requires_original_input_lineage(&self, _batch: &RuntimeInputBatch) -> bool {
        if self.process != std::process::id() {
            return true;
        }
        self.source().requires_original_input_lineage(_batch)
    }

    fn validate_original_input_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_original_input_lineage(scope, batch, provenance, lineage)
    }

    fn read_original_input_evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalInputEvidence, OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .read_original_input_evidence(scope, original, staged, limits)
    }

    fn validate_original_input_evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        evidence: &OriginalInputEvidence,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_original_input_evidence(scope, original, staged, evidence)
    }

    fn original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .original_publication_lineage(scope, original, outcome, publication, limits)
    }

    fn validate_original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().validate_original_publication_lineage(
            scope,
            original,
            outcome,
            publication,
            claim,
        )
    }

    fn validate_exact_original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().validate_exact_original_publication_lineage(
            scope,
            original,
            outcome,
            publication,
            claim,
        )
    }

    fn validate_deferred_original_publication(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        prior: &OperationAdmission,
        prior_outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().validate_deferred_original_publication(
            scope,
            original,
            outcome,
            publication,
            prior,
            prior_outcome,
        )
    }

    fn installation(&self) -> &CnpSemanticInstallation {
        self.source().installation()
    }

    fn authenticate_provider(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().authenticate_provider(native)
    }

    fn preflight_transition(
        &self,
        native: &CnpSemanticProcessCustody,
        transition: CnpSemanticTransition,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().preflight_transition(native, transition)
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().authenticate_realization(scope)
    }

    fn preflight_operation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().preflight_operation(scope, original)
    }

    fn status(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<NodeStatus, OperationFailure> {
        self.ensure_origin()?;
        self.source().status(scope)
    }

    fn prepared_owner(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<PreparedOwner, OperationFailure> {
        self.ensure_origin()?;
        self.source().prepared_owner(scope, record, ready)
    }

    fn validate_initial_preparation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_initial_preparation(scope, record, ready)
    }

    fn readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        response: &ActivateResult,
    ) -> Result<ReadyAttestation, OperationFailure> {
        self.ensure_origin()?;
        self.source().readiness(scope, record, response)
    }

    fn validate_readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().validate_readiness(scope, record, ready)
    }

    fn preflight_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().preflight_world_activation(scope, activation)
    }

    fn validate_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &WorldActivateResult,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_world_activation(scope, activation, response)
    }

    fn outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        response: &ResponseBody,
    ) -> Result<OperationOutcome, OperationFailure> {
        self.ensure_origin()?;
        self.source().outcome(scope, original, response)
    }

    fn validate_outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().validate_outcome(scope, original, outcome)
    }

    fn scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &ObserveResult,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.ensure_origin()?;
        self.source().scheduling(scope, activation, response)
    }

    fn validate_scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_scheduling(scope, activation, observation)
    }

    fn evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        original: Option<&OperationAdmission>,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .evidence(scope, activation, original, references, maximum_bytes)
    }

    fn consumption(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        outputs: &[Id],
    ) -> Result<InputPayload, OperationFailure> {
        self.ensure_origin()?;
        self.source().consumption(scope, original, outcome, outputs)
    }

    fn validate_retirement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        consumption: &InputPayload,
        response: &RetireResult,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_retirement(scope, original, consumption, response)
    }

    fn reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        owner: &OwnerIdentity,
    ) -> Result<NativeReclamationReceipt, OperationFailure> {
        self.ensure_origin()?;
        self.source().reclamation(native, owner)
    }

    fn validate_reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source().validate_reclamation(native, receipt)
    }

    fn input_batch(
        &self,
        batch: &RuntimeInputBatch,
        sequence: U64,
    ) -> Result<InputBatch, OperationFailure> {
        self.ensure_origin()?;
        self.source().input_batch(batch, sequence)
    }

    fn input_acknowledgement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        response: &InputResult,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.ensure_origin()?;
        self.source().input_acknowledgement(scope, batch, response)
    }

    fn input_staging_context(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        request: &InputRequest,
    ) -> Result<(Extensions, Vec<InputPayload>), OperationFailure> {
        self.ensure_origin()?;
        self.source().input_staging_context(scope, batch, request)
    }

    fn input_commit_context(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
        request: &InputRequest,
        staging: &InputResult,
    ) -> Result<(Extensions, Vec<InputPayload>), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .input_commit_context(scope, batch, commit, request, staging)
    }

    fn validate_input_commit(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
        request: &InputRequest,
        staging: &InputResult,
        response: &InputResult,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .validate_input_commit(scope, batch, commit, request, staging, response)
    }

    fn boundary_policy(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<BoundaryPolicy, OperationFailure> {
        self.ensure_origin()?;
        self.source().boundary_policy(scope, original)
    }

    fn input_authorization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        watermark: U64,
    ) -> Result<InputPayload, OperationFailure> {
        self.ensure_origin()?;
        self.source()
            .input_authorization(scope, original, watermark)
    }
}

// A public profile string cannot replace either concrete original.
enum CompletePacketOriginal {
    Producer(Box<PacketSemanticSource>),
    Reactive(Box<PacketConnectedSemanticSource>),
}

#[cfg(test)]
mod tests;
