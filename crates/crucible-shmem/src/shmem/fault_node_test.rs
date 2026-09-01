//! Typed node-fault payload codec tests.

use super::*;

fn field(tag: u16, field_type: NodeFaultFieldTypeV1) -> NodeFaultFieldV1 {
    match field_type {
        NodeFaultFieldTypeV1::U32 => NodeFaultFieldV1::u32(tag, 1),
        NodeFaultFieldTypeV1::U64 => NodeFaultFieldV1::u64(tag, 1),
        NodeFaultFieldTypeV1::I64 => NodeFaultFieldV1::i64(tag, -1),
        NodeFaultFieldTypeV1::Bool => NodeFaultFieldV1::boolean(tag, true),
        NodeFaultFieldTypeV1::Ratio => NodeFaultFieldV1::ratio(tag, 1, 2),
        NodeFaultFieldTypeV1::Hash => NodeFaultFieldV1::hash(tag, [tag as u8; 32]),
        NodeFaultFieldTypeV1::Bytes => NodeFaultFieldV1::bytes(tag, policy_json()),
        NodeFaultFieldTypeV1::HashSet => {
            NodeFaultFieldV1::hash_set(tag, &[[tag as u8; 32]]).expect("canonical hash set")
        }
    }
}

fn policy_json() -> Vec<u8> {
    let mut value = NODE_FAULT_POLICY_JSON_MAGIC_V1.to_vec();
    value.extend_from_slice(b"{\"kind\":\"every\"}");
    value
}

fn exhaustive_payload(
    command_kind: FaultCommandKind,
    target_kind: NodeFaultTargetKindV1,
    parameters: &[(u16, NodeFaultFieldTypeV1)],
    targets: &[(u16, NodeFaultFieldTypeV1)],
) -> NodeFaultPayloadV1 {
    let mut fields = parameters
        .iter()
        .chain(targets)
        .map(|(tag, field_type)| field(*tag, *field_type))
        .collect::<Vec<_>>();
    if command_kind == FaultCommandKind::ClockTransform {
        let kind = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P2)
            .expect("clock kind field exists");
        *kind = NodeFaultFieldV1::u32(node_fault_field::P2, 5);
    }
    if command_kind == FaultCommandKind::CpuInstructionTransform {
        let count = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P5)
            .expect("instruction count field exists");
        *count = NodeFaultFieldV1::u32(node_fault_field::P5, 0);
    }
    if command_kind == FaultCommandKind::MemoryAccessTransform {
        let violate_atomicity = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P9)
            .expect("memory atomicity field exists");
        *violate_atomicity = NodeFaultFieldV1::boolean(node_fault_field::P9, false);
        let has_dma_device = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P10)
            .expect("memory DMA selector-presence field exists");
        *has_dma_device = NodeFaultFieldV1::boolean(node_fault_field::P10, false);
        let dma_device = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P11)
            .expect("memory DMA selector field exists");
        *dma_device = NodeFaultFieldV1::hash(node_fault_field::P11, [0; 32]);
    }
    if command_kind == FaultCommandKind::AcceleratorMemoryEvent {
        let has_transform = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P7)
            .expect("accelerator transform-presence field exists");
        *has_transform = NodeFaultFieldV1::boolean(node_fault_field::P7, false);
        let transform = fields
            .iter_mut()
            .find(|field| field.tag == node_fault_field::P8)
            .expect("accelerator transform field exists");
        *transform = NodeFaultFieldV1::bytes(node_fault_field::P8, vec![0]);
    }
    fields.sort_by_key(|value| value.tag);
    NodeFaultPayloadV1 {
        command_kind,
        operation: NodeFaultOperationV1::Upsert,
        target_kind,
        model_phase: 1,
        generation: 1,
        action_hash: [1; 32],
        target_hash: [2; 32],
        schema_hash: [3; 32],
        fields,
    }
}

fn payload() -> NodeFaultPayloadV1 {
    NodeFaultPayloadV1 {
        command_kind: FaultCommandKind::CpuService,
        operation: NodeFaultOperationV1::Upsert,
        target_kind: NodeFaultTargetKindV1::Vcpu,
        model_phase: 10,
        generation: 7,
        action_hash: [1; 32],
        target_hash: [2; 32],
        schema_hash: [3; 32],
        fields: vec![
            NodeFaultFieldV1::bytes(1, policy_json()),
            NodeFaultFieldV1::ratio(2, 1, 2),
            NodeFaultFieldV1::u64(3, 10_000),
            NodeFaultFieldV1::u32(4, 1),
            NodeFaultFieldV1::u32(100, 0),
        ],
    }
}

#[test]
fn typed_node_payload_round_trips() {
    let value = payload();
    let encoded = value.encode().expect("valid fixture encodes");
    assert_eq!(NodeFaultPayloadV1::decode(&encoded), Ok(value));
}

#[test]
fn every_typed_node_command_has_an_exact_closed_schema() {
    use NodeFaultFieldTypeV1 as Ty;
    use node_fault_field::*;

    let vcpu = &[(T1, Ty::U32)][..];
    let register = &[
        (T1, Ty::U32),
        (T2, Ty::Hash),
        (T3, Ty::Hash),
        (T4, Ty::U32),
        (T5, Ty::U32),
    ][..];
    let memory = &[
        (T1, Ty::Hash),
        (T2, Ty::U64),
        (T3, Ty::Bool),
        (T4, Ty::U32),
        (T5, Ty::U64),
    ][..];
    let interrupt = &[(T1, Ty::Hash), (T2, Ty::Hash), (T3, Ty::U32), (T4, Ty::U32)][..];
    let hash_target = &[(T1, Ty::Hash)][..];
    let cases: &[(
        FaultCommandKind,
        NodeFaultTargetKindV1,
        &[(u16, Ty)],
        &[(u16, Ty)],
    )] = &[
        (
            FaultCommandKind::NodeLifecycle,
            NodeFaultTargetKindV1::Node,
            &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::Bytes),
                (P4, Ty::U32),
                (P5, Ty::U32),
            ],
            &[],
        ),
        (
            FaultCommandKind::NodeHang,
            NodeFaultTargetKindV1::Node,
            &[
                (P1, Ty::U32),
                (P2, Ty::Bytes),
                (P3, Ty::Hash),
                (P4, Ty::Bytes),
            ],
            &[],
        ),
        (
            FaultCommandKind::CpuService,
            NodeFaultTargetKindV1::Vcpu,
            &[
                (P1, Ty::Bytes),
                (P2, Ty::Ratio),
                (P3, Ty::U64),
                (P4, Ty::U32),
            ],
            vcpu,
        ),
        (
            FaultCommandKind::CpuVcpuState,
            NodeFaultTargetKindV1::Vcpu,
            &[(P1, Ty::U32), (P2, Ty::Bool), (P3, Ty::Hash)],
            vcpu,
        ),
        (
            FaultCommandKind::CpuRegisterTransform,
            NodeFaultTargetKindV1::Register,
            &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::U32),
                (P4, Ty::U32),
                (P5, Ty::Bytes),
                (P6, Ty::Bool),
                (P7, Ty::Bytes),
                (P8, Ty::Bytes),
            ],
            register,
        ),
        (
            FaultCommandKind::CpuInstructionTransform,
            NodeFaultTargetKindV1::Vcpu,
            &[
                (P1, Ty::Bytes),
                (P2, Ty::U32),
                (P3, Ty::Hash),
                (P4, Ty::Bytes),
                (P5, Ty::U32),
            ],
            vcpu,
        ),
        (
            FaultCommandKind::CpuException,
            NodeFaultTargetKindV1::Vcpu,
            &[(P1, Ty::Bytes)],
            vcpu,
        ),
        (
            FaultCommandKind::InterruptDisposition,
            NodeFaultTargetKindV1::Interrupt,
            &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::U32),
                (P4, Ty::U64),
                (P5, Ty::U32),
            ],
            interrupt,
        ),
        (
            FaultCommandKind::InterruptStorm,
            NodeFaultTargetKindV1::Interrupt,
            &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::U64),
                (P4, Ty::U32),
                (P5, Ty::U32),
                (P6, Ty::Bytes),
            ],
            interrupt,
        ),
        (
            FaultCommandKind::MemoryAccessTransform,
            NodeFaultTargetKindV1::Memory,
            &[
                (P1, Ty::U64),
                (P2, Ty::U64),
                (P3, Ty::U32),
                (P4, Ty::Bytes),
                (P5, Ty::Bool),
                (P6, Ty::Bytes),
                (P7, Ty::Bytes),
                (P8, Ty::U32),
                (P9, Ty::Bool),
                (P10, Ty::Bool),
                (P11, Ty::Hash),
            ],
            memory,
        ),
        (
            FaultCommandKind::MemoryEccEvent,
            NodeFaultTargetKindV1::Memory,
            &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::U64),
                (P4, Ty::Hash),
                (P5, Ty::Hash),
                (P6, Ty::Hash),
                (P7, Ty::Bytes),
                (P8, Ty::U32),
            ],
            memory,
        ),
        (
            FaultCommandKind::MemoryRegionState,
            NodeFaultTargetKindV1::Memory,
            &[(P1, Ty::U64), (P2, Ty::U64), (P3, Ty::U32), (P4, Ty::Bytes)],
            memory,
        ),
        (
            FaultCommandKind::MemoryService,
            NodeFaultTargetKindV1::Memory,
            &[
                (P1, Ty::U64),
                (P2, Ty::Bool),
                (P3, Ty::U64),
                (P4, Ty::Bool),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
            ],
            memory,
        ),
        (
            FaultCommandKind::ClockTransform,
            NodeFaultTargetKindV1::Clock,
            &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::I64),
                (P4, Ty::Ratio),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
                (P7, Ty::U32),
                (P8, Ty::U32),
            ],
            hash_target,
        ),
        (
            FaultCommandKind::ClockSourceState,
            NodeFaultTargetKindV1::Clock,
            &[(P1, Ty::HashSet), (P2, Ty::Bytes), (P3, Ty::Bytes)],
            hash_target,
        ),
        (
            FaultCommandKind::AcceleratorLifecycle,
            NodeFaultTargetKindV1::Accelerator,
            &[(P1, Ty::Hash), (P2, Ty::U32), (P3, Ty::U32), (P4, Ty::U32)],
            hash_target,
        ),
        (
            FaultCommandKind::AcceleratorResultTransform,
            NodeFaultTargetKindV1::Accelerator,
            &[
                (P1, Ty::Bytes),
                (P2, Ty::Bytes),
                (P3, Ty::U64),
                (P4, Ty::Hash),
            ],
            hash_target,
        ),
        (
            FaultCommandKind::AcceleratorMemoryEvent,
            NodeFaultTargetKindV1::Accelerator,
            &[
                (P1, Ty::U64),
                (P2, Ty::U64),
                (P3, Ty::Bool),
                (P4, Ty::U32),
                (P5, Ty::Bool),
                (P6, Ty::U64),
                (P7, Ty::Bool),
                (P8, Ty::Bytes),
            ],
            hash_target,
        ),
        (
            FaultCommandKind::AcceleratorService,
            NodeFaultTargetKindV1::Accelerator,
            &[
                (P1, Ty::Ratio),
                (P2, Ty::Bool),
                (P3, Ty::U64),
                (P4, Ty::Bool),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
            ],
            hash_target,
        ),
    ];
    assert_eq!(cases.len(), 19);
    for (command, target, parameters, targets) in cases {
        let payload = exhaustive_payload(*command, *target, parameters, targets);
        let encoded = payload
            .encode()
            .unwrap_or_else(|error| panic!("schema for {command:?} must encode: {error}"));
        assert_eq!(NodeFaultPayloadV1::decode(&encoded), Ok(payload));
    }
}

#[test]
fn typed_node_payload_rejects_noncanonical_fields() {
    let mut value = payload();
    value.fields.reverse();
    assert_eq!(value.encode(), Err(NodeFaultPayloadError::FieldOrder));
}

#[test]
fn typed_node_payload_rejects_noncanonical_policy_json() {
    use node_fault_field::P1;

    for invalid in [
        b"null".as_slice(),
        b"CRUCJSN1null".as_slice(),
        b"CRUCJSN1 null".as_slice(),
        b"CRUCJSN1{\"b\":1,\"a\":2}".as_slice(),
        b"CRUCJSN1{\"a\":1,\"a\":2}".as_slice(),
        b"CRUCJSN1{\"kind\":\"every\",\"value\":1.0}".as_slice(),
    ] {
        let mut value = payload();
        value.fields[0] = NodeFaultFieldV1::bytes(P1, invalid.to_vec());
        assert_eq!(
            value.encode(),
            Err(NodeFaultPayloadError::PolicyJson { tag: P1 })
        );
    }
}

#[test]
fn typed_node_payload_rejects_command_target_mismatch() {
    let mut value = payload();
    value.target_kind = NodeFaultTargetKindV1::Memory;
    assert_eq!(
        value.encode(),
        Err(NodeFaultPayloadError::TargetSchema {
            command_kind: FaultCommandKind::CpuService as u16,
            target_kind: NodeFaultTargetKindV1::Memory as u16,
        })
    );
}

#[test]
fn typed_node_payload_rejects_unknown_discriminant() {
    use node_fault_field::P4;

    let mut value = payload();
    value.fields[3] = NodeFaultFieldV1::u32(P4, 99);
    assert_eq!(
        value.encode(),
        Err(NodeFaultPayloadError::FieldValue { tag: P4 })
    );
}

#[test]
fn typed_node_payload_rejects_invalid_memory_cross_fields() {
    use NodeFaultFieldTypeV1 as Ty;
    use node_fault_field::*;

    let parameters = &[
        (P1, Ty::U64),
        (P2, Ty::U64),
        (P3, Ty::U32),
        (P4, Ty::Bytes),
        (P5, Ty::Bool),
        (P6, Ty::Bytes),
        (P7, Ty::Bytes),
        (P8, Ty::U32),
        (P9, Ty::Bool),
        (P10, Ty::Bool),
        (P11, Ty::Hash),
    ];
    let target = &[
        (T1, Ty::Hash),
        (T2, Ty::U64),
        (T3, Ty::Bool),
        (T4, Ty::U32),
        (T5, Ty::U64),
    ];
    let mut value = exhaustive_payload(
        FaultCommandKind::MemoryAccessTransform,
        NodeFaultTargetKindV1::Memory,
        parameters,
        target,
    );
    let atomicity = value
        .fields
        .iter_mut()
        .find(|field| field.tag == P9)
        .expect("memory atomicity field exists");
    *atomicity = NodeFaultFieldV1::boolean(P9, true);
    assert_eq!(
        value.encode(),
        Err(NodeFaultPayloadError::FieldValue { tag: P3 })
    );
}

#[test]
fn typed_node_remove_is_parameter_free() {
    let mut value = payload();
    value.operation = NodeFaultOperationV1::Remove;
    assert_eq!(value.encode(), Err(NodeFaultPayloadError::RemoveFields));
    value.fields.clear();
    assert!(value.encode().is_ok());
}

#[test]
fn typed_node_evidence_round_trips_every_identity() {
    let evidence = NodeFaultEvidenceV1 {
        command_kind: FaultCommandKind::CpuService,
        operation: NodeFaultOperationV1::Upsert,
        target_kind: NodeFaultTargetKindV1::Vcpu,
        model_phase: 2,
        generation: 9,
        prior_generation: 7,
        action_hash: [1; 32],
        target_hash: [2; 32],
        schema_hash: [3; 32],
        request_sha256: [4; 32],
        before_sha256: [5; 32],
        after_sha256: [6; 32],
    };
    let encoded = evidence
        .encode()
        .unwrap_or_else(|error| panic!("evidence should encode: {error}"));
    assert_eq!(NodeFaultEvidenceV1::decode(&encoded), Ok(evidence));
}
