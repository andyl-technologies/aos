//! Composes the retained prebirth Source field roster into one capacity census.
//!
//! Each component observes actual owners into the same optional physical bank.
//! The supported phase retains its original deployment obligation separately;
//! native association, completed Initial and runtime handoff need their own
//! later proofs. Numeric capacity facts issue no Source action or phase grant.

use super::retained_storage::PrebirthStoragePurpose;
use super::*;
use crate::node_adapters::cnp::source_birth_derivation::installation::VerifiedSourceBirthMechanism;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_host_resources::DeploymentResourceReadContext;
use crucible_node_transport::{
    client::CanonicalAckCodecMetadataExtent,
    handshake::OriginalExtensionRegistryOwner,
    reference_packet::service::{
        PacketNative5ProtocolMetadataLimits,
        ack_emitter::PacketNative5AckEmitterSelection,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    },
    retained_metadata::{RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank},
};
use std::{
    cell::{BorrowError, Cell, Ref, RefCell},
    mem::size_of,
    rc::Rc,
    thread::ThreadId,
};

type SourceFieldRoster<'a> = (
    &'a CompletePacketOriginal,
    &'a u32,
    &'a ThreadId,
    &'a RefCell<Option<capture_banks::PacketCompleteCaptureBanks>>,
    &'a RefCell<Option<execution::OriginalCompleteCaptureExecution>>,
    &'a RefCell<Option<preconstruction::OriginalCompletePreconstruction>>,
    &'a Option<effects::OriginalCompleteEffectReceiver>,
    &'a Option<Option<PacketNative5AckEmitterSelection>>,
    &'a RefCell<Option<ack_peer::OriginalAckPeerBirth>>,
    &'a bool,
    &'a Option<Box<ack_peer::NativeImport18BirthConstruction>>,
    &'a Option<ack_peer::NativeImport18DerivationState>,
    &'a Option<Rc<VerifiedSourceBirthMechanism>>,
    &'a RefCell<Option<ack_peer::OriginalAckPeerAssociation>>,
    &'a Cell<bool>,
    &'a Option<CanonicalAckCodecMetadataExtent>,
    &'a Option<CanonicalAckCodecMetadataExtent>,
    &'a Option<(Vec<u8>, Vec<u8>)>,
    &'a Option<Option<PacketNative5CompleteRestoreSelection>>,
    &'a Option<Option<PacketNative5RestoreInputEmitterSelection>>,
    &'a Option<PacketNative5ProtocolMetadataLimits>,
    &'a Option<Option<PacketNative5CaptureAllocationSelection>>,
    &'a Option<Option<PacketNative5FreshRestoreAllocationSelection>>,
    &'a RefCell<Option<OriginalExtensionRegistryOwner>>,
    &'a RefCell<Option<registry_capture::OriginalCompleteRegistryCapture>>,
    &'a Cell<bool>,
    &'a Cell<bool>,
    &'a Cell<bool>,
    &'a Option<ack_peer::Import18Declaration>,
    &'a Cell<bool>,
    &'a RefCell<Option<Box<import18_phase_bank::NativeImport18SourcePhaseBank>>>,
    &'a Cell<bool>,
    &'a RefCell<Option<Box<capture_banks::Import18CaptureBankReservation>>>,
    &'a RefCell<ack_peer::Import18RecipeOwner>,
    &'a Option<invocation_snapshot::Declaration>,
    &'a Option<invocation_snapshot::CoordinatorPolicy17>,
    &'a Option<invocation_snapshot::CoordinatorPolicy18>,
);

type ComponentObserver = fn(
    &PacketCompleteSemanticSource,
    Option<&mut PacketRuntimeMetadataRecordBank>,
) -> Result<RetainedProtocolMetadataFacts, RuntimeError>;

impl PacketCompleteSemanticSource {
    /// Observes the actual unlaunched Code Source and its retained capacities.
    ///
    /// The original pre-Child guards must hold before and after the walk. Shared
    /// views retain each occurrence without alias discounts. The caller admits
    /// the bank and [`Self::prebirth_source_capacity_counter_scratch_data`] first.
    /// These DATA do not authorize native work, Initial or future SDK storage.
    ///
    /// # Errors
    /// Refuses foreign creation, a spent or native/associated Source, busy owners,
    /// exhausted rows, unavailable physical backing or checked geometry/work overflow.
    pub fn original_prechild_capacity_data(
        self: &Rc<Self>,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.prebirth_capacity_data(PrebirthStoragePurpose::Code, maximum_rows, bank)
    }

    /// Observes an isolated template's known Source capacities under its lease.
    ///
    /// The actual deployment is authenticated before and after observation.
    /// Opaque native and receiver resources retain that separate original
    /// obligation. The result is neither a whole-native footprint nor completed
    /// Initial ownership, a Recipe producer or a runtime allocation grant.
    ///
    /// # Errors
    /// Refuses foreign deployment/creation, an unsupported phase, busy owners,
    /// exhausted rows, unavailable backing or checked geometry/work overflow.
    pub fn original_isolated_template_capacity_data(
        self: &Rc<Self>,
        context: &DeploymentResourceReadContext<'_>,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.prebirth_capacity_data(
            PrebirthStoragePurpose::IsolatedTemplate(context),
            maximum_rows,
            bank,
        )
    }

    fn prebirth_capacity_data(
        self: &Rc<Self>,
        purpose: PrebirthStoragePurpose<'_>,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.authenticate_prebirth_storage_phase_with_error::<RuntimeError>(purpose)?;
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);
        self.record_prebirth_fields(&mut census)?;
        census.observe_component_capacity_data(|_, bank| {
            self.original_complete_holder_capacity_data(bank)
        })?;
        // Capture banks already include the independent Import18 reservation.
        // Holder rows already include the Source's separate mechanism view.
        for observe in [
            Self::original_complete_installation_capacity_data as ComponentObserver,
            Self::original_complete_static_lineage_capacity_data,
            Self::original_complete_capture_banks_capacity_data,
            Self::original_complete_capture_execution_capacity_data,
            Self::original_complete_registry_capacity_data,
            Self::original_complete_birth_capacity_data,
            Self::native_import18_birth_construction_capacity_data,
            Self::native_import18_phase_bank_capacity_data,
        ] {
            census.observe_component_capacity_data(|_, bank| observe(self, bank))?;
        }
        census.observe_component_capacity_data(|remaining, bank| {
            self.native_import18_derivation_known_capacity_data(remaining, bank)
        })?;
        self.authenticate_prebirth_storage_phase_with_error::<RuntimeError>(purpose)?;
        Ok(census.finish())
    }

    fn record_prebirth_fields(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            original: _,
            process,
            thread,
            capture_banks,
            capture_execution,
            preconstruction,
            effect_receiver,
            ack_emitter_selection,
            ack_peer_birth,
            ack_birth_attempted,
            native_import18_birth_construction,
            native_import18_derivation,
            native_import18_derivation_mechanism,
            ack_peer_association,
            restored_suffix_attempted,
            ack_codec_metadata_extent,
            native_ack_codec_metadata_extent,
            ack_birth_input_banks,
            complete_restore_selection,
            restore_input_emitter_selection,
            protocol_metadata_limits,
            capture_allocation_selection,
            fresh_restore_allocation_selection,
            original_extension_registry,
            registry_capture,
            registry_retention_attempted,
            registry_retention_failed,
            complete_bytes_launch_reserved,
            native_import18_declaration,
            native_import18_phase_bank_attempted,
            native_import18_phase_bank,
            native_import18_bank_attempted,
            native_import18_bank_reservation,
            native_import18_recipe,
            invocation_snapshot_declaration,
            original_coordinator_policy17,
            original_coordinator_policy18,
        } = self;
        let busy = |_| RuntimeError::OwnerBusy;
        // The original enum's actual Box and nested owners are walked below.
        census.observe_work_data(1)?;
        for present in [
            capture_banks.try_borrow().map_err(busy)?.is_some(),
            capture_execution.try_borrow().map_err(busy)?.is_some(),
            preconstruction.try_borrow().map_err(busy)?.is_some(),
            effect_receiver.is_some(),
            ack_peer_birth.try_borrow().map_err(busy)?.is_some(),
            native_import18_birth_construction.is_some(),
            native_import18_derivation.is_some(),
            native_import18_derivation_mechanism.is_some(),
            ack_peer_association.try_borrow().map_err(busy)?.is_some(),
            ack_birth_input_banks.is_some(),
            original_extension_registry
                .try_borrow()
                .map_err(busy)?
                .is_some(),
            registry_capture.try_borrow().map_err(busy)?.is_some(),
            native_import18_phase_bank
                .try_borrow()
                .map_err(busy)?
                .is_some(),
            native_import18_bank_reservation
                .try_borrow()
                .map_err(busy)?
                .is_some(),
        ] {
            census.observe_inline_data(&present)?;
        }
        census.observe_inline_data(process)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(ack_emitter_selection)?;
        census.observe_inline_data(ack_birth_attempted)?;
        census.observe_inline_data(ack_codec_metadata_extent)?;
        census.observe_inline_data(native_ack_codec_metadata_extent)?;
        census.observe_inline_data(complete_restore_selection)?;
        census.observe_inline_data(restore_input_emitter_selection)?;
        census.observe_inline_data(protocol_metadata_limits)?;
        census.observe_inline_data(capture_allocation_selection)?;
        census.observe_inline_data(fresh_restore_allocation_selection)?;
        census.observe_inline_data(native_import18_declaration)?;
        census.observe_inline_data(invocation_snapshot_declaration)?;
        census.observe_inline_data(original_coordinator_policy17)?;
        census.observe_inline_data(original_coordinator_policy18)?;
        census.observe_inline_cell_data(restored_suffix_attempted)?;
        census.observe_inline_cell_data(registry_retention_attempted)?;
        census.observe_inline_cell_data(registry_retention_failed)?;
        census.observe_inline_cell_data(complete_bytes_launch_reserved)?;
        census.observe_inline_cell_data(native_import18_phase_bank_attempted)?;
        census.observe_inline_cell_data(native_import18_bank_attempted)?;
        census.observe_work_data(1)?;
        native_import18_recipe
            .try_borrow()
            .map_err(busy)?
            .record_retained_capacity_data(census)?;
        if let Some((source, registration)) = ack_birth_input_banks {
            census.observe(source)?;
            census.observe(registration)?;
        }
        Ok(())
    }

    /// Names the actual field roster, child visitors, bank loans and controls.
    ///
    /// Opaque deployment/runtime work remains with its separate original owner.
    pub fn prebirth_source_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + Self::retained_requested_storage_precredit_scratch_data()
            + Self::isolated_derivation_counter_scratch_data()
            + Self::original_complete_holder_capacity_counter_scratch_data()
            + Self::original_complete_installation_capacity_counter_scratch_data()
            + Self::original_complete_static_lineage_capacity_counter_scratch_data()
            + Self::original_complete_capture_banks_capacity_counter_scratch_data()
            + Self::original_complete_capture_execution_capacity_counter_scratch_data()
            + Self::original_complete_registry_capacity_counter_scratch_data()
            + Self::original_complete_birth_capacity_counter_scratch_data()
            + Self::native_import18_birth_construction_counter_scratch_data()
            + Self::native_import18_phase_bank_counter_scratch_data()
            + Self::retained_metadata_conversion_counter_scratch_data()
            + ack_peer::Import18RecipeOwner::retained_capacity_counter_scratch_data()
            + size_of::<SourceFieldRoster<'static>>()
            + size_of::<(&Self, &Rc<Self>, PrebirthStoragePurpose<'static>)>()
            + size_of::<[bool; 14]>()
            + size_of::<std::array::IntoIter<bool, 14>>()
            + size_of::<[ComponentObserver; 8]>()
            + size_of::<std::array::IntoIter<ComponentObserver, 8>>()
            + size_of::<ComponentObserver>()
            + size_of::<Ref<'static, ack_peer::Import18RecipeOwner>>()
            + size_of::<Result<Ref<'static, ack_peer::Import18RecipeOwner>, BorrowError>>()
            + size_of::<(&Vec<u8>, &Vec<u8>)>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>() * 2
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>() * 2
    }
}

#[cfg(test)]
#[path = "source_capacity/tests.rs"]
mod tests;
