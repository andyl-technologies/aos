//! Checks closed Source5 declaration and registry paths without native authority.
//!
//! The copied declaration fixture is independent inert data. These controls do
//! not launch a child, install Host2, exercise capture or qualify preservation.

// crucible-lint: allow panic-shortcut -- Assertion panics are the control verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_transport::reference_packet::{
    PacketEvent, PacketProgramDefinition, connected::PacketInputConnection,
    control::PacketNative5StorageSelection, service::PacketNative5StorageLimits,
};
use serde_json::json;
use std::{cell::Cell, rc::Rc};

mod fixture;

pub(super) fn storage_selection() -> PacketNative5StorageSelection {
    PacketNative5StorageSelection {
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65_536),
            control_snapshot_bytes: U64::new(65_536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            hello_bytes: U64::new(2 * 65_536 + 8),
            settlement_bytes: U64::new(1024 * 1024),
        },
        limits: crucible_node_transport::handshake::Limits {
            frame_bytes: U64::new(65_536),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(64),
            blob_chunk_bytes: U64::new(4096),
        },
    }
}

fn content(value: &impl serde::Serialize) -> ContentRef {
    canonical::content_ref(
        &canonical::canonical_json(&json!(value)).unwrap(),
        "application/json",
    )
    .unwrap()
}

pub(super) fn coordinator() -> PacketNative5CoordinatorInstallation {
    complete_coordinator(fixture::five())
}

pub(super) fn coordinator_with_ack() -> PacketNative5CoordinatorInstallation {
    complete_coordinator(fixture::five_with_ack(true))
}

fn complete_coordinator(
    mut installed: PacketNative5CoordinatorInstallation,
) -> PacketNative5CoordinatorInstallation {
    for (index, selected) in installed.participants.iter_mut().enumerate() {
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: selected.realization.bindings[0]
                .compatibility
                .operating_contract
                .facets
                .clone(),
            devices_ref: selected.realization.descriptors[0].model_ref.clone(),
            requirements_ref: serde_json::from_value::<GuaranteeProfile>(
                installed.template["nodes"][index]["guarantees"].clone(),
            )
            .unwrap()
            .limitations_ref,
            extensions: Extensions::new(),
        };
        selected.realization.bindings[0]
            .compatibility
            .capabilities_ref = content(&capabilities);
        selected.realization.owner_bindings[0].node_bindings[0].binding_hash =
            selected.realization.bindings[0].identity().unwrap();
        selected.realize.resource_limits.memory_bytes = U64::new(16 * 1024 * 1024);
        selected.realize.resource_limits.content_bytes = U64::new(4 * 1024 * 1024);
        installed.template["nodes"][index]["binding"] = json!(selected.realization.bindings[0]);
        installed.template["owner_bindings"][index] = json!(selected.realization.owner_bindings[0]);
    }
    let mut world: WorldBinding =
        serde_json::from_value(installed.template["world"].clone()).unwrap();
    for (index, selected) in installed.participants.iter().enumerate() {
        world.node_bindings[index].binding_hash =
            selected.realization.bindings[0].identity().unwrap();
    }
    installed.template["world"] = json!(world);
    let identity = world.identity().unwrap();
    installed.template["activation"]["world_binding_hash"] = json!(identity);
    for selected in &mut installed.participants {
        selected.world = identity.clone();
    }
    installed
}

pub(super) fn installation(
    installed: &PacketNative5CoordinatorInstallation,
    member: usize,
) -> CnpSemanticInstallation {
    let peer = &installed.participants[member];
    let binding = peer.realization.bindings[0].clone();
    let descriptor = peer.realization.descriptors[0].clone();
    let guarantees: GuaranteeProfile =
        serde_json::from_value(installed.template["nodes"][member]["guarantees"].clone()).unwrap();
    CnpSemanticInstallation {
        provider:peer.provider.clone(),profile:peer.provider.supported_profiles[0].clone(),descriptor:descriptor.clone(),
        binding:binding.clone(),capabilities:CapabilityProfile {
            schema_version:1,facets:binding.compatibility.operating_contract.facets.clone(),devices_ref:descriptor.model_ref.clone(),requirements_ref:guarantees.limitations_ref.clone(),extensions:Extensions::new(),
        },
        exact_facet:binding.compatibility.operating_contract.facets.iter().find(|facet|facet.id.as_str()=="source-owned.packet-exact/5").unwrap().clone(),
        guarantees,owner:peer.realization.owner_bindings[0].clone(),realize:peer.realize.clone(),admission:peer.admission.clone(),transaction:peer.transaction.clone(),gate:peer.gate.clone(),admission_receipt:peer.admission_receipt.clone(),world_binding_hash:peer.world.clone(),facets:vec![FacetKind::ExactExecution,FacetKind::Preservation],receipt_schema:crucible_node_transport::reference_packet::continuation_contracts::complete_packet_receipt_schema().unwrap(),maximum_operations:64,maximum_result_bytes:65536,maximum_authorization_bytes:65536,maximum_semantic_bytes:4*1024*1024,
    }
}

pub(super) fn reactive(
    installed: &PacketNative5CoordinatorInstallation,
    member: usize,
) -> PacketConnectedDefinition {
    let world: WorldBinding = serde_json::from_value(installed.template["world"].clone()).unwrap();
    let node = &installed.participants[member].realization.descriptors[0].id;
    PacketConnectedDefinition {
        schema: "source-owned.packet-connected-program/4".into(),
        connections: world
            .connections
            .iter()
            .filter(|route| &route.consumer.node_id == node)
            .map(|route| PacketInputConnection {
                id: route.id.clone(),
                policy: route.policy_ref.clone(),
                producer: route.producer.clone(),
                consumer: route.consumer.clone(),
                delay_ps: route.minimum_latency_ps,
            })
            .collect(),
        output: world
            .connections
            .iter()
            .find(|route| &route.producer.node_id == node)
            .map(|route| route.producer.clone()),
    }
}

pub(super) fn producer() -> PacketProgramDefinition {
    PacketProgramDefinition {
        schema: "source-owned.packet-program.v1".into(),
        events: vec![
            PacketEvent {
                id: Id::new("private-callback-0").unwrap(),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                payload: None,
            },
            PacketEvent {
                id: Id::new("packet-callback-0").unwrap(),
                evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(b"original-producer".to_vec())),
            },
        ],
    }
}

#[test]
fn complete_source_preserves_original_models_and_coordinator() {
    let installed = coordinator();
    let original = canonical::canonical_json(&json!(installed)).unwrap();
    let source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed.clone(),
        storage_selection(),
    )
    .unwrap();
    source
        .authenticate_collecting_world_scope(&installed)
        .unwrap();
    source.authenticate_registration().unwrap();
    assert!(source.authenticate_current_native().is_err());

    for member in [1, 2] {
        let source = PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&installed, member),
            reactive(&installed, member),
            installed.clone(),
            storage_selection(),
        )
        .unwrap();
        source.authenticate_registration().unwrap();
        source
            .authenticate_collecting_world_scope(&installed)
            .unwrap();
        assert!(source.authenticate_current_native().is_err());
    }
    assert_eq!(
        canonical::canonical_json(&json!(installed)).unwrap(),
        original
    );
}

struct CountingPolicy(Cell<usize>);

impl CnpSemanticRegistrationPolicy for CountingPolicy {
    fn authenticate(&self, _: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

struct UnusedAcceptance;

impl CnpSemanticAcceptance for UnusedAcceptance {
    fn authenticate(&self, _: CnpSemanticRealizationScope<'_>) -> Result<(), OperationFailure> {
        Err(refused("component fixture never grants native acceptance"))
    }
}

#[test]
fn ordinary_registry_refuses_complete_source_before_policy_and_credit() {
    let installed = coordinator();
    let source = Rc::new(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&installed, 1),
            reactive(&installed, 1),
            installed,
            storage_selection(),
        )
        .unwrap(),
    );
    let policy = Rc::new(CountingPolicy(Cell::new(0)));
    let mut registry = CnpSemanticRegistry::new(policy.clone(), 1).unwrap();
    for _ in 0..2 {
        assert!(
            registry
                .install(source.clone(), Rc::new(UnusedAcceptance))
                .is_err()
        );
        assert_eq!(policy.0.get(), 0);
    }
    source.authenticate_registration().unwrap();
}

#[test]
fn complete_source_refuses_changed_world_definition_and_dialects() {
    let installed = coordinator();
    let source = PacketCompleteSemanticSource::new_reactive_for_collecting_world(
        installation(&installed, 1),
        reactive(&installed, 1),
        installed.clone(),
        storage_selection(),
    )
    .unwrap();
    let mut changed = installed.clone();
    changed.host.prepared_token = Id::new("foreign-host-preparation").unwrap();
    assert!(
        source
            .authenticate_collecting_world_scope(&changed)
            .is_err()
    );
    source
        .authenticate_collecting_world_scope(&installed)
        .unwrap();

    let mut definition = reactive(&installed, 1);
    definition.connections[0].delay_ps = U64::new(2);
    assert!(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&installed, 1),
            definition,
            installed.clone(),
            storage_selection(),
        )
        .is_err()
    );
    let mut selected = installation(&installed, 1);
    selected.facets = vec![FacetKind::ExactExecution];
    assert!(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            selected,
            reactive(&installed, 1),
            installed.clone(),
            storage_selection(),
        )
        .is_err()
    );
    let mut selected = installation(&installed, 1);
    selected.receipt_schema.id = Id::new("source-owned.packet-receipt/4").unwrap();
    assert!(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            selected,
            reactive(&installed, 1),
            installed,
            storage_selection(),
        )
        .is_err()
    );
}

#[test]
fn complete_source_bank_reservation_is_original_and_actual_before_native_association() {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    assert!(source.original_capture_bank_facts().is_err());
    let limits = PacketCompleteCaptureBankLimits {
        host_protocol_bytes: 2 * 1024 * 1024,
        semantic_bytes: 128 * 1024,
        ancestry_bytes: 128 * 1024,
        journal_bytes: 128 * 1024,
    };

    source
        .reserve_complete_capture_banks(limits, 4 * 1024 * 1024)
        .unwrap();
    let original = source.original_capture_bank_facts().unwrap();
    assert_eq!(original.semantic_bytes, limits.semantic_bytes);
    assert_eq!(original.ancestry_bytes, limits.ancestry_bytes);
    assert_eq!(original.journal_bytes, limits.journal_bytes);
    assert!(original.protocol_bytes > 3 * 1024 * 1024);
    assert_eq!(
        source
            .selected_storage_selection()
            .unwrap()
            .storage
            .protocol_snapshot_bytes
            .get(),
        1024 * 1024
    );
    assert_eq!(original.native_snapshot_bytes, 65_536);
    assert_eq!(original.native_control_bytes, 65_536);
    assert_eq!(original.native_anchor_bytes, 8192);
    assert_eq!(
        original.total_bytes,
        original.semantic_bytes
            + original.ancestry_bytes
            + original.journal_bytes
            + original.protocol_bytes
            + original.native_snapshot_bytes
            + original.native_control_bytes
            + original.native_anchor_bytes
    );
    assert!(source.authenticate_preconstruction_protocol_bound(
        source.selected_capture_profile().unwrap(),
    ).is_err());
    assert_eq!(source.original_capture_bank_facts().unwrap(), original);
    assert!(
        source
            .reserve_complete_capture_banks(limits, 4 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(source.original_capture_bank_facts().unwrap(), original);
}

#[test]
fn complete_source_bank_limit_refusal_keeps_original_selection_unallocated() {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    let selected = source.selected_storage_selection().unwrap().clone();
    let limits = PacketCompleteCaptureBankLimits {
        host_protocol_bytes: 2 * 1024 * 1024,
        semantic_bytes: 128 * 1024,
        ancestry_bytes: 128 * 1024,
        journal_bytes: 128 * 1024,
    };

    assert!(
        source
            .reserve_complete_capture_banks(limits, 128 * 1024)
            .is_err()
    );
    assert!(source.original_capture_bank_facts().is_err());
    assert_eq!(*source.selected_storage_selection().unwrap(), selected);
}

#[test]
fn complete_source_profile_is_bound_before_banks() {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    assert_eq!(source.selected_capture_profile().unwrap(),
        &crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6);
    let selected = crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: U64::new(1024 * 1024),
        native_after_protocol_bytes: U64::new(1024 * 1024),
        host_protocol_bytes: U64::new(2 * 1024 * 1024),
    };
    source
        .bind_original_capture_profile(selected.clone())
        .unwrap();
    assert!(
        source
            .bind_original_capture_profile(selected.clone())
            .is_err()
    );
    assert_eq!(source.selected_capture_profile().unwrap(), &selected);
    assert!(source.original_capture_bank_facts().is_err());

    let mut banks = PacketCompleteCaptureBankLimits {
        host_protocol_bytes: 1024 * 1024,
        semantic_bytes: 128 * 1024,
        ancestry_bytes: 128 * 1024,
        journal_bytes: 128 * 1024,
    };
    assert!(
        source
            .reserve_complete_capture_banks(banks, 4 * 1024 * 1024)
            .is_err()
    );
    assert!(source.original_capture_bank_facts().is_err());
    banks.host_protocol_bytes = 2 * 1024 * 1024;
    source
        .reserve_complete_capture_banks(banks, 4 * 1024 * 1024)
        .unwrap();
    source
        .authenticate_preconstruction_protocol_bound(source.selected_capture_profile().unwrap())
        .unwrap();
    let original = source.original_capture_bank_facts().unwrap();
    assert!(original.protocol_bytes > 3 * 1024 * 1024);
    let retained = source.capture_banks.borrow();
    let retained = retained.as_ref().unwrap();
    let facts = retained
        .protocol
        .as_ref()
        .unwrap()
        .original_allocation_facts()
        .unwrap();
    assert_eq!(facts.maximum_encoded_bytes, banks.host_protocol_bytes);
    assert_eq!(facts.encoded_length, 0);
    assert_eq!(facts.literal.unwrap().maximum_frames_per_direction, 64);
    assert!(retained.settled_protocol.is_none());
    assert!(retained.protocol_payload.is_none());
}

#[test]
fn complete_source_preconstruction_refuses_declarations_and_banks_alone() {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    assert!(source.authenticate_original_preconstruction().is_err());

    let banks = PacketCompleteCaptureBankLimits {
        host_protocol_bytes: 2 * 1024 * 1024,
        semantic_bytes: 128 * 1024,
        ancestry_bytes: 128 * 1024,
        journal_bytes: 128 * 1024,
    };
    source
        .reserve_complete_capture_banks(banks, 4 * 1024 * 1024)
        .unwrap();
    let original = source.original_capture_bank_facts().unwrap();
    assert!(source.authenticate_original_preconstruction().is_err());
    assert_eq!(source.original_capture_bank_facts().unwrap(), original);
    assert!(source.preconstruction.borrow().is_none());
}

#[test]
fn complete_source_receiver_binding_keeps_same_group_and_kernel_path() {
    use std::{
        os::unix::net::UnixDatagram,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct SocketPath(std::path::PathBuf);
    impl Drop for SocketPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    let path = std::env::temp_dir().join(format!(
        "e5-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    let receiver0 = UnixDatagram::bind(&path).unwrap();
    let original_path = SocketPath(path);
    let (_send1, receiver1) = UnixDatagram::pair().unwrap();
    let (_send2, receiver2) = UnixDatagram::pair().unwrap();
    let (group, _reader) = PacketCompleteEffectReceiverGroup::from_original_receivers([
        receiver0, receiver1, receiver2,
    ]);
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();

    source
        .bind_original_effect_receiver(Rc::clone(&group), 0, original_path.0.clone())
        .unwrap();
    source
        .authenticate_original_effect_receiver_binding(&group, 0, &original_path.0)
        .unwrap();
    assert!(
        source
            .bind_original_effect_receiver(Rc::clone(&group), 0, original_path.0.clone())
            .is_err()
    );
    assert!(
        source
            .authenticate_original_effect_receiver_binding(&group, 1, &original_path.0)
            .is_err()
    );
    assert!(
        source
            .authenticate_original_effect_receiver_binding(&group, 0, std::path::Path::new("other"))
            .is_err()
    );

    let (_send0, recv0) = UnixDatagram::pair().unwrap();
    let (_send1, recv1) = UnixDatagram::pair().unwrap();
    let (_send2, recv2) = UnixDatagram::pair().unwrap();
    let (foreign, _foreign_reader) =
        PacketCompleteEffectReceiverGroup::from_original_receivers([recv0, recv1, recv2]);
    assert!(
        source
            .authenticate_original_effect_receiver_binding(&foreign, 0, &original_path.0)
            .is_err()
    );
    source
        .authenticate_original_effect_receiver_binding(&group, 0, &original_path.0)
        .unwrap();
    assert!(source.authenticate_original_preconstruction().is_err());
}

#[test]
fn complete_native_after_return_bank_is_separate_and_selected_before_child() {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    assert!(
        source
            .reserve_original_native_after_return_bank(6 * 1024 * 1024)
            .is_err()
    );
    source
        .reserve_complete_capture_banks(
            PacketCompleteCaptureBankLimits {
                host_protocol_bytes: 2 * 1024 * 1024,
                semantic_bytes: 128 * 1024,
                ancestry_bytes: 128 * 1024,
                journal_bytes: 128 * 1024,
            },
            4 * 1024 * 1024,
        )
        .unwrap();
    let before = source.original_capture_bank_facts().unwrap();
    assert_eq!(before.native_after_protocol_bytes, 0);

    assert!(
        source
            .reserve_original_native_after_return_bank(before.total_bytes)
            .is_err()
    );
    assert_eq!(source.original_capture_bank_facts().unwrap(), before);
    source
        .reserve_original_native_after_return_bank(6 * 1024 * 1024)
        .unwrap();
    let after = source.original_capture_bank_facts().unwrap();
    assert_eq!(after.native_after_protocol_bytes, 1024 * 1024);
    assert_eq!(
        after.total_bytes,
        before.total_bytes + after.native_after_protocol_bytes
    );
    assert_eq!(after.protocol_bytes, before.protocol_bytes);
    assert_eq!(after.native_snapshot_bytes, before.native_snapshot_bytes);
    assert!(
        source
            .reserve_original_native_after_return_bank(6 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(source.original_capture_bank_facts().unwrap(), after);
    assert!(source.authenticate_original_preconstruction().is_err());
}

#[test]
fn complete_source_confirmation_binding_preserves_none_and_refuses_missing_declaration() {
    use crucible_node_transport::reference_packet::service::PacketNative5ConfirmationSelection;

    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    assert_eq!(source.selected_confirmation_selection().unwrap(), None);
    assert!(
        source
            .bind_original_confirmation_selection(Some(
                PacketNative5ConfirmationSelection::AfterProtocolPoll5
            ),)
            .is_err()
    );
    source.bind_original_confirmation_selection(None).unwrap();
    assert!(source.bind_original_confirmation_selection(None).is_err());
    assert_eq!(source.selected_confirmation_selection().unwrap(), None);
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn complete_source_confirmation_selection_refuses_after_bank_reservation() {
    let installed = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&installed, 0),
        producer(),
        installed,
        storage_selection(),
    )
    .unwrap();
    source
        .reserve_complete_capture_banks(
            PacketCompleteCaptureBankLimits {
                host_protocol_bytes: 2 * 1024 * 1024,
                semantic_bytes: 128 * 1024,
                ancestry_bytes: 128 * 1024,
                journal_bytes: 128 * 1024,
            },
            4 * 1024 * 1024,
        )
        .unwrap();
    let before = source.original_capture_bank_facts().unwrap();
    assert!(source.bind_original_confirmation_selection(None).is_err());
    assert_eq!(source.original_capture_bank_facts().unwrap(), before);
    assert_eq!(source.selected_confirmation_selection().unwrap(), None);
}
