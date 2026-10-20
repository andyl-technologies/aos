//! Constructs ordinary complete packet Sources with empty live-state slots.
//!
//! Both constructors retain the original producer/reactive declaration and
//! coordinator. They initialize no selected derivation mechanism and grant no
//! native, capture or restoration authority.

use super::*;

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
            native_import18_birth_construction: None,
            native_import18_derivation_mechanism: None,
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
            native_import18_declaration: None,
            native_import18_phase_bank_attempted: std::cell::Cell::new(false),
            native_import18_phase_bank: std::cell::RefCell::new(None),
            native_import18_bank_attempted: std::cell::Cell::new(false),
            native_import18_bank_reservation: std::cell::RefCell::new(None),
            native_import18_recipe: std::cell::RefCell::new(ack_peer::Import18RecipeOwner::empty()),
            invocation_snapshot_declaration: None,
            original_coordinator_policy17: None,
            original_coordinator_policy18: None,
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
        program: crucible_node_transport::reference_packet::PacketProgramDefinition,
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
            native_import18_birth_construction: None,
            native_import18_derivation_mechanism: None,
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
            native_import18_declaration: None,
            native_import18_phase_bank_attempted: std::cell::Cell::new(false),
            native_import18_phase_bank: std::cell::RefCell::new(None),
            native_import18_bank_attempted: std::cell::Cell::new(false),
            native_import18_bank_reservation: std::cell::RefCell::new(None),
            native_import18_recipe: std::cell::RefCell::new(ack_peer::Import18RecipeOwner::empty()),
            invocation_snapshot_declaration: None,
            original_coordinator_policy17: None,
            original_coordinator_policy18: None,
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
        })
    }
}
