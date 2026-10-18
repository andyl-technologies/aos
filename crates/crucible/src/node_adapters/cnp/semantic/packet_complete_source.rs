//! Retains a distinct complete-world packet source for original live collection.
//!
//! This concrete adapter selects edition five without translating its installation
//! into edition four. Underlying model records and input journals keep their
//! original dialects. Capture and fresh restoration remain unsupported until the
//! complete source-owned protocol and settlement mechanism is installed.

use super::packet_connected_source::*;
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crate::{node_contract::*, node_scheduling::*};
use crucible_node_contract::*;
use crucible_node_provider::{
    bodies::*,
    client::CnpController,
    reference_packet::{
        connected::PacketConnectedDefinition, control::PacketNative5StorageSelection,
        coordinator::PacketNative5CoordinatorInstallation, service::PacketNative5CaptureProfile,
    },
};

#[path = "packet_complete_source/archive_semantics.rs"]
mod archive_semantics;
pub use archive_semantics::PacketCompleteArchivedSemantics;

#[path = "packet_complete_source/metadata_storage.rs"]
mod metadata_storage;

#[path = "packet_complete_source/archive_native_input.rs"]
mod archive_native_input;

#[path = "packet_complete_source/witness.rs"]
mod witness;

#[path = "packet_complete_source/native_objects.rs"]
mod native_objects;

#[path = "packet_complete_source/ancestry.rs"]
mod ancestry;

#[path = "packet_complete_source/capture_allocation_selection.rs"]
mod capture_allocation_selection;

#[path = "packet_complete_source/fresh_restore_allocation_selection.rs"]
mod fresh_restore_allocation_selection;

#[path = "packet_complete_source/capture_banks.rs"]
mod capture_banks;
#[path = "packet_complete_source/execution.rs"]
mod execution;
pub use execution::dependency_credit::{
    PacketCompleteCaptureDependencyLookupData, PacketCompleteCaptureDependencyStorageData,
};
#[path = "packet_complete_source/capture_transcript.rs"]
mod capture_transcript;

#[path = "packet_complete_source/protocol_metadata.rs"]
mod protocol_metadata;
pub use capture_banks::{PacketCompleteCaptureBankFacts, PacketCompleteCaptureBankLimits};

pub use witness::{PacketCompleteNativeRecord, PacketCompleteNativeWitness};

#[path = "packet_complete_source/preconstruction.rs"]
mod preconstruction;

#[path = "packet_complete_source/effects.rs"]
mod effects;
pub use effects::{PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader};

#[path = "packet_complete_source/ack_peer.rs"]
mod ack_peer;

#[path = "packet_complete_source/world_admission.rs"]
mod world_admission;
pub use ack_peer::{
    PacketCompleteAckHostRegistrationPlan, PacketCompleteAckPeerBootFrame,
    PacketCompleteAckPeerBootMaterial, PacketCompleteNativeRestoredSuffixStartupWire,
    PacketCompleteNativeStartupWire, PacketCompleteOriginalHostSdk,
    PacketCompleteRestorePreparation,
};
pub(super) use world_admission::OriginalCompletedCanonicalAckWorldAdmission;

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
    capture_execution: std::cell::RefCell<Option<execution::OriginalCompleteCaptureExecution>>,
    preconstruction: std::cell::RefCell<Option<preconstruction::OriginalCompletePreconstruction>>,
    effect_receiver: Option<effects::OriginalCompleteEffectReceiver>,
    ack_emitter_selection: Option<Option<crucible_node_provider::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>>,
    ack_peer_birth: std::cell::RefCell<Option<ack_peer::OriginalAckPeerBirth>>,
    ack_birth_attempted: bool,
    ack_peer_association: std::cell::RefCell<Option<ack_peer::OriginalAckPeerAssociation>>,
    // Source-local once fence precedes every suffix custody/evidence loan.
    restored_suffix_attempted: std::cell::Cell<bool>,
    ack_codec_metadata_extent: Option<crucible_node_provider::client::CanonicalAckCodecMetadataExtent>,
    native_ack_codec_metadata_extent: Option<crucible_node_provider::client::CanonicalAckCodecMetadataExtent>,
    ack_birth_input_banks: Option<(Vec<u8>, Vec<u8>)>,
    complete_restore_selection: Option<Option<crucible_node_provider::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>>,
    restore_input_emitter_selection: Option<Option<crucible_node_provider::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>>,
    protocol_metadata_limits: Option<crucible_node_provider::reference_packet::service::PacketNative5ProtocolMetadataLimits>,
    capture_allocation_selection: Option<Option<crucible_node_provider::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>>,
    fresh_restore_allocation_selection: Option<Option<crucible_node_provider::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>>,
    original_extension_registry: std::cell::RefCell<Option<crucible_node_provider::handshake::OriginalExtensionRegistryOwner>>,
    registry_capture: std::cell::RefCell<Option<registry_capture::OriginalCompleteRegistryCapture>>,
    registry_retention_attempted: std::cell::Cell<bool>,
    registry_retention_failed: std::cell::Cell<bool>,
    complete_bytes_launch_reserved: std::cell::Cell<bool>,
    invocation_snapshot_declaration: Option<invocation_snapshot::Declaration>,
    original_coordinator_policy17: Option<invocation_snapshot::CoordinatorPolicy17>,
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
            capture_execution: std::cell::RefCell::new(None),
            preconstruction: std::cell::RefCell::new(None),
            effect_receiver: None,
            ack_emitter_selection: None,
            ack_peer_birth: std::cell::RefCell::new(None),
            ack_birth_attempted: false,
            ack_peer_association: std::cell::RefCell::new(None),
            restored_suffix_attempted: std::cell::Cell::new(false),
            ack_codec_metadata_extent: None,
            native_ack_codec_metadata_extent: None,
            ack_birth_input_banks: None,
            protocol_metadata_limits: None,
            capture_allocation_selection: None,
            fresh_restore_allocation_selection: None,
            original_extension_registry: std::cell::RefCell::new(None),
            registry_capture: std::cell::RefCell::new(None),
            registry_retention_attempted: std::cell::Cell::new(false),
            registry_retention_failed: std::cell::Cell::new(false),
            complete_bytes_launch_reserved: std::cell::Cell::new(false),
            invocation_snapshot_declaration: None,
            original_coordinator_policy17: None,
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
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
            capture_execution: std::cell::RefCell::new(None),
            preconstruction: std::cell::RefCell::new(None),
            effect_receiver: None,
            ack_emitter_selection: None,
            ack_peer_birth: std::cell::RefCell::new(None),
            ack_birth_attempted: false,
            ack_peer_association: std::cell::RefCell::new(None),
            restored_suffix_attempted: std::cell::Cell::new(false),
            ack_codec_metadata_extent: None,
            native_ack_codec_metadata_extent: None,
            ack_birth_input_banks: None,
            protocol_metadata_limits: None,
            capture_allocation_selection: None,
            fresh_restore_allocation_selection: None,
            original_extension_registry: std::cell::RefCell::new(None),
            registry_capture: std::cell::RefCell::new(None),
            registry_retention_attempted: std::cell::Cell::new(false),
            registry_retention_failed: std::cell::Cell::new(false),
            complete_bytes_launch_reserved: std::cell::Cell::new(false),
            invocation_snapshot_declaration: None,
            original_coordinator_policy17: None,
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
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
    /// Quotes fixed Source/read component observation layouts before a walk.
    ///
    /// This conservative sum includes actual metadata/scanner view layouts and
    /// the nested read counter separately from an enclosing preparation counter.
    /// It certifies no compiler/recursive frames, allocator or kernel resources.
    pub fn retained_requested_storage_precredit_scratch_data() -> usize {
        Self::original_report_startup_observer_scratch_data()
            + ack_peer::OriginalAckPeerAssociation::reserved_suffix_counter_scratch_data()
            + NodeRuntime::capture_opaque_owner_observer_scratch_data()
            + CnpSemanticSourceRead::retained_requested_storage_precredit_scratch_data()
            + std::mem::size_of::<[Option<super::retained_storage::CnpRetainedStorageReport>; 2]>()
            + 3 * std::mem::size_of::<retained_storage::PacketCompleteSourceRetainedStorage>()
            + std::mem::size_of::<[usize; 9]>()
    }

    pub(super) fn storage_origin_with_error<E: StorageError>(&self) -> Result<(), E> {
        if self.process != std::process::id() {
            return Err(E::origin(
                "complete source belongs to another creator process",
            ));
        }
        if self.thread != std::thread::current().id() {
            return Err(E::origin(
                "complete source belongs to another creator thread",
            ));
        }
        Ok(())
    }

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
    fn requires_restored_capture17_scope_data(&self) -> Result<bool, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        match self.invocation_snapshot_declaration {
            Some(invocation_snapshot::Declaration::Attempted) => {
                Err(RuntimeError::OutstandingObligations)
            }
            Some(invocation_snapshot::Declaration::RestoredSettledRecapture17) => Ok(true),
            _ => Ok(false),
        }
    }

    fn call_original_installed_restoration_observation_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        claim: crate::node_admission::OriginalInstalledRestorationObservationClaim,
        admitted: &OriginalSourceRestorationObservationConstructionData,
        completed: &mut Option<crucible_node_provider::bodies::ResponseBody>,
    ) -> Result<
        OriginalSourceRestorationObservationVerifiedPhase<'a>,
        crate::node_contract::RuntimeError,
    > {
        PacketCompleteSemanticSource::call_original_installed_restoration_observation_into(
            self, controller, claim, admitted, completed,
        )
    }

    fn call_original_installed_restoration_activation_into<'a>(
        &'a self,
        controller: &'a mut CnpController,
        claim: crate::node_admission::OriginalInstalledRestorationActivationClaim,
        command: crucible_node_provider::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand,
        admitted: &OriginalSourceRestorationActivationConstructionData,
        completed: &mut Option<crucible_node_provider::bodies::ResponseBody>,
    ) -> Result<
        OriginalSourceRestorationActivationVerifiedPhase<'a>,
        crate::node_contract::RuntimeError,
    > {
        PacketCompleteSemanticSource::call_original_installed_restoration_activation_into(
            self, controller, claim, command, admitted, completed,
        )
    }

    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        self.original_complete_retained_nested_precredit_data(maximum)
            .map(Some)
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        self.original_complete_retained_nested_storage_data(maximum)?
            .complete_requested_bytes()
            .map(Some)
    }

    fn preflight_complete_original_lineage_capture(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: crate::node_state::NativeArchiveLimits,
    ) -> Result<crate::node_state::CompleteOriginalOwnerCapturePreflight, OperationFailure> {
        self.ensure_origin()?;
        // The legacy preflight initializes old banks before its owning-report
        // refusal. A selected current codec must never create those old Some
        // owners while its distinct complete native quote remains unavailable.
        if self
            .requires_restored_capture17_scope_data()
            .map_err(unknown)?
        {
            return Err(refused(
                "complete native owning Capture17 quote is unavailable",
            ));
        }
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
        if matches!(
            self.selected_capture_profile()?,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            scope
                .native
                .retain_original_complete_protocol_supervisor()
                .map_err(unknown)?;
            self.authenticate_witness_scope(&scope)?;
            let call =
                super::process::ReadCall::begin(std::rc::Rc::clone(&scope.native.read_owner))
                    .map_err(unknown)?;
            let quoted = (|| {
                let witness = scope
                    .native
                    .protocol_supervisor
                    .try_borrow()
                    .map_err(|_| refused("complete quote supervisor is borrowed"))?;
                let witness = witness
                    .as_ref()
                    .ok_or_else(|| refused("complete quote supervisor is absent"))?;
                let mut banks = self
                    .capture_banks
                    .try_borrow_mut()
                    .map_err(|_| refused("complete quote banks are borrowed"))?;
                let banks = banks
                    .as_mut()
                    .ok_or_else(|| refused("complete quote banks are absent"))?;
                let reservation = banks.protocol.as_mut().ok_or_else(|| {
                    refused("complete quote original protocol reservation is absent")
                })?;
                // The SDK walks and counts the SAME current complete tuple used
                // by capture into these actual banks. This is no prediction of
                // the later three-body/fourth-Poll suffix or native state.
                scope
                    .controller
                    .quote_original_owned11_state_with_supervisor(reservation, witness)
                    .map_err(unknown)
            })();
            call.finish(quoted.is_ok());
            let quote = quoted?;
            self.authenticate_witness_scope(&scope)?;
            if quote.encoded_extent > quote.snapshot_allocation.encoded_capacity
                || quote.required_record_rows > quote.metadata_allocation.capacity_rows
                || quote.required_alias_rows > quote.alias_allocation.row_capacity
                || quote.required_alias_rows > quote.alias_allocation.lookup_capacity
            {
                return Err(refused(
                    "complete current host view exceeds its actual banks",
                ));
            }
        }
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
        self.prepare_original_complete_capture_execution(
            &scope,
            runtime_object,
            limits
                .native
                .maximum_total_record_bytes
                .min(limits.state.maximum_total_content_bytes),
        )?;
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

        // Local banks, the current host quote and semantic counts are actual,
        // but the remote native model/Control/service retained and transient
        // owners still need their authentic current Observe allocation report.
        // Its selection or P capacity cannot supply that owning row. Until the
        // same whole aggregation includes it, no geometry or ticket is issued.
        Err(refused(
            "complete native owning allocation report and whole peak are unavailable",
        ))
    }

    fn capture_original_lineage_continuation_with_ticket_into(
        &self,
        scope: CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        self.dispatch_original_complete_capture_into(
            scope,
            ticket,
            activation,
            record,
            runtime_object,
            limits,
            completed,
        )
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
        if self.selected_capture_allocation_selection()?.is_some() {
            if !response.complete || response.observations.len() != 1 {
                return Err(refused("selected allocation observation is incomplete"));
            }
            return self.selected_allocation_observation(
                &scope,
                activation,
                &response.observations[0].measurement_ref,
            );
        }
        self.source().scheduling(scope, activation, response)
    }

    fn validate_scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.selected_capture_allocation_selection()?.is_some() {
            let actual =
                self.selected_allocation_observation(&scope, activation, &observation.proof_ref)?;
            return if &actual == observation {
                Ok(())
            } else {
                Err(refused("selected original scheduling data changed"))
            };
        }
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

impl PacketCompleteSemanticSource {
    /// Binds expected confirmation data before native association and bank selection.
    ///
    /// This does not install a native/SDK mechanism. A selected source later
    /// authenticates the actual same-child receipt, installed codec and negotiated
    /// feature in its original realization scope. None preserves the old route.
    ///
    /// # Errors
    /// Refuses foreign origin, prior bank/native association, repeated binding or
    /// a selected schema absent from the exact source declaration.
    pub fn bind_original_confirmation_selection(
        &mut self,
        selected: Option<
            crucible_node_provider::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.capture_banks.get_mut().is_some() {
            return Err(refused(
                "confirmation selection follows source bank reservation",
            ));
        }
        if selected.is_some() {
            let schema = crucible_node_provider::reference_packet::service::confirmation::native_after_confirmation_schema().map_err(unknown)?;
            if !self.installation().binding.compatibility.implementation.formats.contains(&schema)
                || !self.installation().provider.extensions_supported.iter().any(|feature| {
                    feature.as_str() == crucible_node_provider::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE
                })
            {
                return Err(refused("selected confirmation lacks exact source declaration"));
            }
        }
        let slot = match &mut self.original {
            CompletePacketOriginal::Producer(source) => {
                if !source.complete_preparation_unbound()? {
                    return Err(refused("confirmation selection follows native association"));
                }
                &mut source.complete_confirmation_selection
            }
            CompletePacketOriginal::Reactive(source) => {
                if !source.complete_preparation_unbound()? {
                    return Err(refused("confirmation selection follows native association"));
                }
                &mut source.complete_confirmation_selection
            }
        };
        if slot.is_some() {
            return Err(refused("original confirmation selection was already bound"));
        }
        *slot = Some(selected);
        Ok(())
    }

    /// Returns expected confirmation data retained before sharing the source.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread. Matching data confers no
    /// capture, source-ticket or restoration permission.
    pub fn selected_confirmation_selection(
        &self,
    ) -> Result<
        Option<
            crucible_node_provider::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
        OperationFailure,
    > {
        self.ensure_origin()?;
        let selected = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_confirmation_selection,
            CompletePacketOriginal::Reactive(source) => source.complete_confirmation_selection,
        };
        Ok(selected.flatten())
    }
}

#[cfg(test)]
mod tests;

#[path = "packet_complete_source/complete_restore_selection.rs"]
mod complete_restore_selection;

#[path = "packet_complete_source/archive_journal.rs"]
mod archive_journal;
pub use archive_journal::{
    PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA, PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA,
    PacketCompleteSettledJournal,
};

#[path = "packet_complete_source/archive_owner.rs"]
mod archive_owner;
pub use archive_owner::CompleteHistoricalArchiveFamily;
pub use archive_owner::PacketCompleteArchivedOwnerData;
pub(crate) use archive_owner::{
    OriginalCompleteHistoricalColdGroup, OriginalRestoredSettledColdGroup,
    OriginalRestoredSettledColdOwnerView,
};
pub(crate) use archive_owner::{OriginalRestorationColdGroup, OriginalRestorationColdOwnerView};

impl PacketCompleteSemanticSource {
    /// Borrows the original typed reactive model used by this complete source.
    ///
    /// A producer returns None. The factory separately compares the actual
    /// installed configuration/model reference and complete canonical bytes;
    /// this loan avoids reparsing that known definition into another JSON tree.
    /// It grants no execution, archive or capture permission.
    ///
    /// # Errors
    /// Refuses a foreign creator or a source without its exact complete world.
    pub fn complete_reactive_definition_data(
        &self,
    ) -> Result<Option<&PacketConnectedDefinition>, OperationFailure> {
        self.ensure_origin()?;
        match &self.original {
            CompletePacketOriginal::Producer(_) => Ok(None),
            CompletePacketOriginal::Reactive(source) => {
                source.complete_original_definition_data().map(Some)
            }
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Retains original graph-authenticated full static input rows before Stage.
    ///
    /// The installed graph supplies exact full bodies and explicit direct rows;
    /// a producer accepts an empty roster. This data operation grants no graph,
    /// input, Capture or archive authority. Every full measured leaf is retained,
    /// including executables; a too-small selected bank refuses before copying.
    ///
    /// # Errors
    /// Refuses changed origin, late/repeated differing rows, missing selected
    /// policy/proof bodies or insufficient actual retained backing allowance.
    pub fn retain_original_complete_input_static_rows(
        &self,
        rows: &[(InputPayload, Vec<ContentRef>)],
        maximum_retained_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        match &self.original {
            CompletePacketOriginal::Producer(_) => {
                if !rows.is_empty() {
                    return Err(refused("complete producer has no input static rows"));
                }
                Ok(())
            }
            CompletePacketOriginal::Reactive(source) => {
                source.retain_complete_input_static_rows(rows, maximum_retained_bytes)
            }
        }
    }

    /// Reports actual retained complete-only static input body/row storage.
    ///
    /// The source/factory must include this distinct backing in whole admission;
    /// it is not covered by encoded protocol or ancestry bank capacities.
    ///
    /// # Errors
    /// Refuses foreign custody or an unbound/incomplete reactive static bank.
    pub fn original_complete_input_static_storage(&self) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        match &self.original {
            CompletePacketOriginal::Producer(_) => Ok(0),
            CompletePacketOriginal::Reactive(source) => source.complete_input_static_storage(),
        }
    }
}

#[path = "packet_complete_source/restore_input_emitter_selection.rs"]
mod restore_input_emitter_selection;

#[path = "packet_complete_source/retained_installation.rs"]
mod retained_installation;

#[path = "packet_complete_source/retained_values.rs"]
mod retained_values;

impl PacketCompleteSemanticSource {
    /// Counts actual static and first-sealed lineage banks retained by this Source.
    ///
    /// Complete producers have no source input-lineage bank. Reactive Sources
    /// count their original full byte/row/dependency static closure and lineage
    /// Vec plus actual Core-owned lineage data/batch backing. Only identical
    /// pairs of original Rc addresses share credit; equal hashes do not.
    /// Shared Core activation authority and publication owners excluded by the
    /// Core observer remain separate actual Core owning-row terms.
    ///
    /// # Errors
    /// Refuses foreign origin, busy/missing static custody, unsupported lineage
    /// population or a combined actual requested-storage overrun.
    pub fn original_complete_static_lineage_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_complete_static_lineage_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_static_lineage_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        match &self.original {
            CompletePacketOriginal::Producer(_) => Ok(0),
            CompletePacketOriginal::Reactive(source) => retained_values::sum_with_error::<E, _>(
                [
                    source.complete_input_static_storage_with_error::<E>()?,
                    source.complete_retained_lineage_storage_with_error::<E>(maximum)?,
                ],
                maximum,
            ),
        }
    }
}

#[path = "packet_complete_source/retained_holders.rs"]
mod retained_holders;

#[path = "packet_complete_source/registry_capture.rs"]
mod registry_capture;

#[path = "packet_complete_source/retained_registry.rs"]
mod retained_registry;

#[path = "packet_complete_source/retained_storage.rs"]
mod retained_storage;

#[path = "packet_complete_source/storage_error.rs"]
pub(in crate::node_adapters::cnp::semantic) mod storage_error;
pub use retained_storage::PacketCompleteSourceRetainedStorage;

#[path = "packet_complete_source/complete_launch.rs"]
mod complete_launch;

pub(in crate::node_adapters::cnp::semantic) mod capture_allocation_receipt;

pub use capture_allocation_receipt::{
    OriginalCaptureAllocationData, original_capture_allocation_witness_counter_scratch_data,
};

pub(crate) use ack_peer::{PacketCompleteInitialLifecycleIdentity, PacketCompleteInitialLifecycleQuote};

#[path = "packet_complete_source/invocation_snapshot.rs"]
mod invocation_snapshot;

pub(crate) use ack_peer::{
    OriginalSourceRestoreSignerConstructionData, OriginalSourceRestoreVerifiedPhase,
    OriginalSourceRestoreVerifiedPhaseKind,
};

// Selected node partial Values use the same defining raw-capacity walk. This
// grants no Source permission and constructs no substitute serialized owner.
pub(in crate::node_adapters::cnp::semantic) use retained_values::value_storage_with_error as original_retained_value_storage_with_error;

pub use ack_peer::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestorationActivationVerifiedPhase,
    OriginalSourceRestorationObservationConstructionData,
    OriginalSourceRestorationObservationVerifiedPhase,
};

pub(crate) use ack_peer::OriginalSourceRestoredObservationCompletion;

#[path = "packet_complete_source/restored_producer_outcome.rs"]
mod restored_producer_outcome;
pub use restored_producer_outcome::{
    OriginalRestoredProducerOutcomeConstructionData, OriginalRestoredProducerOutcomeProjection,
};

pub(crate) use ack_peer::OriginalSourceRestoredProducerPhaseCompletion;

pub use ack_peer::PacketCompleteNativeRestoredSettledStartupWire;

#[path = "packet_complete_source/header17.rs"]
mod header17;

pub(crate) use ack_peer::{
    OriginalSourceRestoredFirstObservationHistory17Read, OriginalSourceRestoredInstallation17,
    OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17,
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Prelude, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs,
};

pub(crate) use restored_producer_outcome::{
    OriginalRestoredProducerHistoricalAdmissionData,
    OriginalRestoredProducerHistoricalInstallationData,
};

pub(crate) use ack_peer::{
    OriginalSourceRestoredCaptureCompletion, OriginalSourceRestoredCaptureQuoteInputs,
};

pub(crate) use ack_peer::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use ack_peer::OriginalSourceRestoredCaptureCountingBanksData;

pub(crate) use archive_owner::{OriginalInitial15ArchivedGroup, OriginalInitial15ArchivedOwnerRead};

pub use ack_peer::OriginalSourceRestoredCaptureConstructionData;

pub(super) use retained_values::value_storage_with_error;

impl PacketCompleteSemanticSource {
    /// Names fixed origin and cached-declaration controls for native preflight.
    ///
    /// No schema, Window, kernel or mutable-owner callback is performed by the
    /// discriminator. This counter conveys no currentness or selected support.
    pub(crate) fn original_restored_capture_scope_selection_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<Option<invocation_snapshot::Declaration>>()
            + std::mem::size_of::<std::thread::ThreadId>()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<Result<bool, RuntimeError>>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
    }
}
