//! Unit tests for canonical opportunities and resolved targets.

use super::*;

fn id(value: &str) -> FaultObjectId {
    match FaultObjectId::parse(value) {
        Ok(id) => id,
        Err(error) => panic!("test identifier must be valid: {error}"),
    }
}

fn opportunity(result: Result<FaultOpportunity, FaultContractError>) -> FaultOpportunity {
    match result {
        Ok(opportunity) => opportunity,
        Err(error) => panic!("test opportunity must be valid: {error}"),
    }
}

#[test]
fn opportunity_identity_changes_for_every_identity_field() {
    let target = ResolvedFaultTarget::NetworkSegment {
        segment: id("uplink"),
        direction: FaultDirection::AToB,
    };
    let build = |sequence, phase, protocol_expansion_path| {
        FaultOpportunity::new(
            target.clone(),
            FaultOperation::NetworkTraverse,
            phase,
            FaultCoordinate {
                virtual_nanos: 42,
                retired_instructions: None,
            },
            sequence,
            Some(FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination: id("receiver"),
                producer_sequence: 7,
                protocol_expansion_path,
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: 1_500,
                payload_digest: ContentHash::from_bytes(b"frame"),
            },
        )
    };
    let first = opportunity(build(1, FaultPhase::Resolve, Vec::new()));
    let equal = opportunity(build(1, FaultPhase::Resolve, Vec::new()));
    let next = opportunity(build(2, FaultPhase::Resolve, Vec::new()));
    let delivered = opportunity(build(1, FaultPhase::Deliver, Vec::new()));
    let fragment = opportunity(build(1, FaultPhase::Resolve, vec![0]));
    assert_eq!(first.id(), equal.id());
    assert_ne!(first.id(), next.id());
    assert_ne!(first.id(), delivered.id());
    assert_ne!(first.id(), fragment.id());
}

#[test]
fn reserved_target_material_matches_every_string_encoding_variant() {
    let hash = ContentHash::from_bytes(b"target");
    let targets = [
        ResolvedFaultTarget::NetworkInterface {
            endpoint: id("endpoint"),
            interface: id("interface"),
        },
        ResolvedFaultTarget::NetworkSegment {
            segment: id("segment"),
            direction: FaultDirection::AToB,
        },
        ResolvedFaultTarget::NetworkMedium {
            medium: id("medium"),
            resource: id("resource"),
        },
        ResolvedFaultTarget::NetworkQueue {
            owner: id("owner"),
            queue: id("queue"),
        },
        ResolvedFaultTarget::NetworkForwarder {
            forwarder: id("forwarder"),
        },
        ResolvedFaultTarget::NetworkPath {
            path_version: id("path"),
            direction: FaultDirection::BToA,
        },
        ResolvedFaultTarget::NetworkAttachment {
            endpoint: id("endpoint"),
            interface: id("interface"),
            attachment: id("attachment"),
        },
        ResolvedFaultTarget::NetworkContact {
            plan: id("plan"),
            endpoint_a: id("endpoint-a"),
            endpoint_b: id("endpoint-b"),
            contact: id("contact"),
        },
        ResolvedFaultTarget::BlockDevice { device: hash },
        ResolvedFaultTarget::BlockRange {
            device: hash,
            start_byte: u64::MAX,
            length_bytes: 1,
        },
        ResolvedFaultTarget::StorageController {
            controller: id("controller"),
            namespace_or_path: id("namespace"),
        },
        ResolvedFaultTarget::StorageArray {
            array: id("array"),
            member_or_path: id("member"),
        },
        ResolvedFaultTarget::NinePDevice { device: hash },
        ResolvedFaultTarget::Node { node: id("node") },
        ResolvedFaultTarget::Vcpu {
            node: id("node"),
            vcpu: u32::MAX,
        },
        ResolvedFaultTarget::Register {
            node: id("node"),
            vcpu: u32::MAX,
            architecture: id("architecture"),
            register: id("register"),
            first_bit: u16::MAX,
            bit_count: u16::MAX,
        },
        ResolvedFaultTarget::MemoryRange {
            node: id("node"),
            address_space: id("gva"),
            guest_address: u64::MAX,
            vcpu: Some(u32::MAX),
            length_bytes: u64::MAX,
        },
        ResolvedFaultTarget::Interrupt {
            node: id("node"),
            controller: id("controller"),
            source: id("source"),
            target_vcpu: u32::MAX,
            vector: u32::MAX,
        },
        ResolvedFaultTarget::ClockSource {
            node: id("node"),
            source: id("source"),
        },
        ResolvedFaultTarget::Accelerator {
            node: id("node"),
            device: id("device"),
        },
    ];

    for target in targets {
        let required = target.canonical_material_length();
        let mut material = Vec::new();
        material
            .try_reserve_exact(required)
            .unwrap_or_else(|error| panic!("target reservation should succeed: {error}"));
        target
            .append_canonical_material_bytes(&mut material)
            .unwrap_or_else(|error| panic!("reserved target should encode: {error}"));
        assert_eq!(material, target.canonical_material().as_bytes());

        let mut insufficient = Vec::with_capacity(required - 1);
        let error = match target.append_canonical_material_bytes(&mut insufficient) {
            Ok(()) => panic!("undersized target reservation must fail"),
            Err(error) => error,
        };
        assert_eq!(error.available, required - 1);
        assert_eq!(error.required, required);
        assert!(insufficient.is_empty());
    }
}

#[test]
fn opportunity_rejects_cross_adapter_operation() {
    let result = FaultOpportunity::new(
        ResolvedFaultTarget::Node { node: id("node-a") },
        FaultOperation::StorageRead,
        FaultPhase::Resolve,
        FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: Some(0),
        },
        0,
        None,
        OpportunityPayload::None,
    );
    let error = match result {
        Ok(_) => panic!("cross-adapter operation must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        FaultContractError::AdapterMismatch {
            target: FaultAdapter::Node,
            operation: FaultAdapter::Storage,
        }
    );
}

#[test]
fn malformed_resolved_targets_fail_before_hashing() {
    let target = ResolvedFaultTarget::BlockRange {
        device: ContentHash::from_bytes(b"disk"),
        start_byte: u64::MAX,
        length_bytes: 2,
    };
    assert_eq!(
        target.validate(),
        Err(FaultContractError::InvalidTarget {
            kind: FaultTargetKind::BlockRange,
        })
    );
}
