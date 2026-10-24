//! Checks physical input moves without constructing a Source, query or native grant.

use super::*;
use crate::bodies::BeginKind;
use crate::envelope::Nullable;
use crate::reference_packet::service::complete_restore::{
    PacketCompleteRestoreRequest, import17::PacketNativeImport17Limits,
};
use crucible_node_format::{Bytes, Phase, Position, Tick, canonical};

fn inputs(label: &str) -> OriginalNativeImport18PrepareInputs {
    let reference = canonical::content_ref(b"unverified input", "application/json").unwrap();
    let owner = canonical::hash("cnp.owner-binding.v1", label.as_bytes()).unwrap();
    let schema = SchemaRef {
        id: Id::new(format!("{label}/schema")).unwrap(),
        version: 1,
        definition: reference.clone(),
        extensions: Default::default(),
    };
    let restoration = PacketCompleteRestoreRequest {
        schema: "unverified restoration".to_owned(),
        archive_index: reference.clone(),
        capture_manifest: reference.clone(),
        owner_state: reference.clone(),
        journal: reference.clone(),
        source_runtime: reference.clone(),
        backend_implementation: reference.clone(),
        backend_schema: schema.clone(),
        archived_cut: Position::new(Tick::new(0), U64::new(0), Phase::BoundaryControl),
        archived_ordinal: U64::new(0),
        target_world: canonical::hash("cnp.world-binding.v1", label.as_bytes()).unwrap(),
        target_owner: Id::new(format!("{label}/owner")).unwrap(),
        target_owner_binding: owner.clone(),
        target_activation: Id::new(format!("{label}/activation")).unwrap(),
        target_generation: U64::new(1),
        target_owner_generation: U64::new(1),
        mapping: reference.clone(),
        nonce: Bytes::new(vec![1; 32]),
    };
    let request = PacketCompleteRestorePrepareRequest {
        schema: "unverified Prepare".to_owned(),
        restoration,
        host_protocol: reference.clone(),
        native_protocol: reference.clone(),
        native_control: reference.clone(),
        native_anchor: reference.clone(),
        transaction_id: Id::new(format!("{label}/transaction")).unwrap(),
        generation: U64::new(1),
        allocation: PacketCompleteRestoreInputAllocation {
            maximum_known_requested_bytes: U64::new(4096),
            maximum_input_bytes: U64::new(1024),
            maximum_nodes: U64::new(64),
            maximum_depth: U64::new(8),
            maximum_owned_backing_bytes: U64::new(1024),
            maximum_tree_entries: U64::new(64),
            maximum_metadata_rows: U64::new(64),
            maximum_literal_backing_bytes: U64::new(1024),
            maximum_content_transfers: U64::new(8),
            maximum_content_objects: U64::new(8),
            maximum_content_groups: U64::new(8),
            maximum_content_bytes: U64::new(1024),
            maximum_content_metadata_bytes: U64::new(1024),
            maximum_model_bytes: U64::new(1024),
        },
    };
    let binding = PacketNativeImport18Binding {
        schema: "unverified binding".to_owned(),
        native_family: PacketNativeImport18NativeFamily::Snapshot17,
        prepare_digest: Bytes::new(vec![2; 32]),
        native_before: reference.clone(),
        controller17: reference.clone(),
        source_family: PacketNativeImport18SourceFamily::Captured17,
        source17: reference.clone(),
        node25: reference.clone(),
        geometry_identity: Bytes::new(vec![3; 32]),
        role_extents: [U64::new(16); 5],
        limits: PacketNativeImport17Limits {
            role_maximums: [U64::new(64); 5],
            immutable_objects: U64::new(8),
            immutable_bytes: U64::new(1024),
            immutable_depth: U64::new(8),
            maximum_nodes: U64::new(64),
            maximum_requested_bytes: U64::new(4096),
            maximum_target_requested_bytes: U64::new(4096),
            maximum_before_bytes: U64::new(1024),
        },
        normalization: reference.clone(),
        normalization_maximum: U64::new(64),
        semantic_spend_family: PacketNativeImport18SemanticSpendFamily::Complete18,
        semantic_spend: reference,
        semantic_spend_maximum: U64::new(64),
    };

    OriginalNativeImport18PrepareInputs {
        request_id: Id::new(format!("{label}/prepare")).unwrap(),
        baseline: BeginRequest {
            kind: BeginKind::PrepareRestore,
            binding_hash: owner,
            owner_generation: U64::new(1),
            activation_id: Nullable(None),
            world_generation: U64::new(1),
            arguments: [("held".to_owned(), Value::String(label.to_owned()))]
                .into_iter()
                .collect(),
            extensions: Default::default(),
        },
        request,
        binding,
        expected_backend_schema: schema,
    }
}

fn input_data(inputs: &OriginalNativeImport18PrepareInputs) -> Value {
    serde_json::to_value((
        &inputs.request_id,
        &inputs.baseline,
        &inputs.request,
        &inputs.binding,
        &inputs.expected_backend_schema,
    ))
    .unwrap()
}

fn assignment_data(owner: &OriginalNativeImport18Assignment) -> Value {
    serde_json::to_value((
        &owner.prepare.request_id,
        &owner.prepare.baseline,
        &owner.prepare.request,
        &owner.binding,
        &owner.expected_backend_schema,
    ))
    .unwrap()
}

fn input_pointers(inputs: &OriginalNativeImport18PrepareInputs) -> [*const u8; 5] {
    [
        inputs.request_id.as_str().as_ptr(),
        inputs.baseline.arguments["held"].as_str().unwrap().as_ptr(),
        inputs.request.restoration.nonce.as_slice().as_ptr(),
        inputs.binding.prepare_digest.as_slice().as_ptr(),
        inputs.expected_backend_schema.id.as_str().as_ptr(),
    ]
}

fn assignment_pointers(owner: &OriginalNativeImport18Assignment) -> [*const u8; 5] {
    [
        owner.prepare.request_id.as_ref().unwrap().as_str().as_ptr(),
        owner.prepare.baseline.as_ref().unwrap().arguments["held"]
            .as_str()
            .unwrap()
            .as_ptr(),
        owner.prepare.request.restoration.nonce.as_slice().as_ptr(),
        owner.binding.prepare_digest.as_slice().as_ptr(),
        owner.expected_backend_schema.id.as_str().as_ptr(),
    ]
}

#[test]
fn actual_fields_move_once_before_their_later_validation() {
    let controller = Rc::new(ProtocolCaptureOwner::new());
    let mut incoming = Some(inputs("first"));
    let expected = input_data(incoming.as_ref().unwrap());
    let pointers = input_pointers(incoming.as_ref().unwrap());
    let mut output = None;

    retain_into(&controller, &mut incoming, &mut output).unwrap();

    assert!(incoming.is_none());
    let owner = output.as_ref().unwrap();
    assert_eq!(assignment_data(owner), expected);
    assert_eq!(assignment_pointers(owner), pointers);
    assert!(Rc::ptr_eq(&owner.controller, &controller));
    assert_eq!(Rc::strong_count(&controller), 2);
    assert!(matches!(owner.prepare.stage, Stage::Preparing));
    assert!(owner.prepare.original.is_none());
    assert!(owner.prepare.cut.is_none());
    assert!(owner.prepare.prepare_receipt.is_none());
    assert_eq!(owner.prepare.bytes.capacity(), 0);
    assert_eq!(owner.normalization.capacity(), 0);
}

#[test]
fn occupied_destination_preserves_both_independent_input_occurrences() {
    let controller = Rc::new(ProtocolCaptureOwner::new());
    let mut original = Some(inputs("original"));
    let mut output = None;
    retain_into(&controller, &mut original, &mut output).unwrap();
    let original_data = assignment_data(output.as_ref().unwrap());
    let original_pointers = assignment_pointers(output.as_ref().unwrap());
    let mut incoming = Some(inputs("incoming"));
    let incoming_data = input_data(incoming.as_ref().unwrap());
    let incoming_pointers = input_pointers(incoming.as_ref().unwrap());

    assert!(retain_into(&controller, &mut incoming, &mut output).is_err());

    assert_eq!(assignment_data(output.as_ref().unwrap()), original_data);
    assert_eq!(
        assignment_pointers(output.as_ref().unwrap()),
        original_pointers
    );
    assert_eq!(input_data(incoming.as_ref().unwrap()), incoming_data);
    assert_eq!(
        input_pointers(incoming.as_ref().unwrap()),
        incoming_pointers
    );
    assert_eq!(Rc::strong_count(&controller), 2);
}

#[test]
fn absent_inputs_leave_the_destination_and_controller_unchanged() {
    let controller = Rc::new(ProtocolCaptureOwner::new());
    let mut incoming = None;
    let mut output = None;

    assert!(retain_into(&controller, &mut incoming, &mut output).is_err());

    assert!(incoming.is_none());
    assert!(output.is_none());
    assert_eq!(Rc::strong_count(&controller), 1);
}

fn bank_inputs() -> OriginalNativeImport18PrepareInputs {
    let mut inputs = inputs("bank-quote");
    let references: [ContentRef; 7] = std::array::from_fn(|index| {
        canonical::content_ref(&vec![b'x'; index + 1], "application/json").unwrap()
    });
    let [
        after,
        control,
        anchor,
        snapshot,
        journal,
        normalization,
        semantic,
    ] = references;
    inputs.request.native_protocol = after;
    inputs.request.native_control = control;
    inputs.request.native_anchor = anchor;
    inputs.request.restoration.owner_state = snapshot;
    inputs.request.restoration.journal = journal;
    inputs.binding.normalization = normalization;
    inputs.binding.semantic_spend = semantic;
    // Captured decoder order differs from native receive order. Distinct exact
    // lengths make a swapped role or ceiling refuse instead of hiding in a sum.
    inputs.binding.limits.role_maximums = [4, 1, 2, 3, 5].map(U64::new);
    inputs.binding.normalization_maximum = U64::new(6);
    inputs.binding.semantic_spend_maximum = U64::new(7);
    inputs
}

#[test]
fn typed_prepare_bank_quote_uses_exact_role_order_and_whole_parent_credit() {
    let inputs = bank_inputs();
    let before = input_data(&inputs);
    let row = inputs
        .native_receiving_bank_backing_construction_data(usize::MAX)
        .unwrap();
    let peak = row.into_iter().sum();

    // Seven bytes banks own 1+...+7 bytes and seven exact full-reference copies.
    let reference_text = "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();
    assert_eq!(row[0], 28 + 7 * reference_text);
    assert_eq!(
        row[2],
        OriginalNativeImport18PrepareInputs::native_receiving_bank_backing_counter_scratch_data()
    );
    assert_eq!(
        inputs
            .native_receiving_bank_backing_construction_data(peak)
            .unwrap(),
        row
    );
    assert!(
        inputs
            .native_receiving_bank_backing_construction_data(peak - 1)
            .is_err()
    );
    assert_eq!(input_data(&inputs), before);
    // A physical quote is still available for these deliberately unverified
    // fixture DTOs; it cannot authenticate their malformed Prepare schema.
    assert!(inputs.request.validate_data().is_err());
}

#[test]
fn typed_prepare_bank_quote_refuses_each_actual_role_ceiling() {
    for index in 0..7 {
        let mut inputs = bank_inputs();
        let short = U64::new(index as u64);
        match index {
            0 => inputs.binding.limits.role_maximums[1] = short,
            1 => inputs.binding.limits.role_maximums[2] = short,
            2 => inputs.binding.limits.role_maximums[3] = short,
            3 => inputs.binding.limits.role_maximums[0] = short,
            4 => inputs.binding.limits.role_maximums[4] = short,
            5 => inputs.binding.normalization_maximum = short,
            6 => inputs.binding.semantic_spend_maximum = short,
            _ => unreachable!(),
        }
        let before = input_data(&inputs);

        assert!(
            inputs
                .native_receiving_bank_backing_construction_data(usize::MAX)
                .is_err(),
            "role {index}"
        );
        assert_eq!(input_data(&inputs), before);
    }
}

#[test]
fn typed_prepare_bank_quote_keeps_original_spare_capacity_separate() {
    let mut inputs = bank_inputs();
    let before = inputs
        .native_receiving_bank_backing_construction_data(usize::MAX)
        .unwrap();
    inputs
        .request
        .native_protocol
        .hash
        .digest
        .reserve_exact(16_384);
    inputs
        .binding
        .semantic_spend
        .media_type
        .reserve_exact(16_384);
    let capacities = [
        inputs.request.native_protocol.hash.digest.capacity(),
        inputs.binding.semantic_spend.media_type.capacity(),
    ];

    assert_eq!(
        inputs
            .native_receiving_bank_backing_construction_data(usize::MAX)
            .unwrap(),
        before
    );
    assert_eq!(
        capacities,
        [
            inputs.request.native_protocol.hash.digest.capacity(),
            inputs.binding.semantic_spend.media_type.capacity(),
        ]
    );
}
