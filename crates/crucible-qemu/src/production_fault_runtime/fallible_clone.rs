//! Fallible duplication of heap-owning production fault ledger records.
//!
//! Transaction rollback and checkpoint capture must reserve every owned string,
//! vector, and event payload before copying it. Ordinary [`Clone`] is unsuitable
//! for those production paths because allocation refusal would abort the process.

use crucible::NodeId;
use crucible::model::{
    BindingActionCause, FaultObjectId, OpportunityPayload, ResolvedBindingAction,
    ResolvedFaultTarget,
};
use crucible_shmem::DequeuedFaultEvent;

pub(super) fn try_clone_node_id<E>(
    source: &NodeId,
    allocation_error: impl FnOnce() -> E,
) -> Result<NodeId, E> {
    Ok(NodeId {
        name: try_clone_string(&source.name, allocation_error)?,
    })
}

pub(super) fn try_clone_action<E>(
    source: &ResolvedBindingAction,
    mut allocation_error: impl FnMut() -> E,
) -> Result<ResolvedBindingAction, E> {
    Ok(ResolvedBindingAction {
        kind: source.kind,
        binding: try_clone_fault_id(&source.binding, &mut allocation_error)?,
        target: try_clone_target(&source.target, &mut allocation_error)?,
        phase: source.phase,
        effect: source.effect.clone(),
        mapping_output: source.mapping_output.clone(),
        mapped_digest: source.mapped_digest,
        transition_sequence: source.transition_sequence,
        opportunity: source.opportunity,
        coordinate: source.coordinate,
        cause: try_clone_cause(&source.cause, &mut allocation_error)?,
        expected_precondition: source.expected_precondition,
    })
}

pub(super) fn try_clone_fault_events<E>(
    source: &[DequeuedFaultEvent],
    mut allocation_error: impl FnMut() -> E,
) -> Result<Vec<DequeuedFaultEvent>, E> {
    let mut events = Vec::new();
    events
        .try_reserve_exact(source.len())
        .map_err(|_| allocation_error())?;
    for event in source {
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(event.payload.len())
            .map_err(|_| allocation_error())?;
        payload.extend_from_slice(&event.payload);
        events.push(DequeuedFaultEvent {
            header: event.header.clone(),
            payload,
        });
    }
    Ok(events)
}

pub(super) fn try_clone_string<E>(
    source: &str,
    allocation_error: impl FnOnce() -> E,
) -> Result<String, E> {
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| allocation_error())?;
    value.push_str(source);
    Ok(value)
}

pub(super) fn try_clone_fault_id<E>(
    source: &FaultObjectId,
    allocation_error: &mut impl FnMut() -> E,
) -> Result<FaultObjectId, E> {
    let value = try_clone_string(source.as_str(), &mut *allocation_error)?;
    // The source already passed the same closed identifier grammar.
    FaultObjectId::parse(value).map_err(|_| allocation_error())
}

fn try_clone_cause<E>(
    source: &BindingActionCause,
    allocation_error: &mut impl FnMut() -> E,
) -> Result<BindingActionCause, E> {
    Ok(match source {
        BindingActionCause::Signal => BindingActionCause::Signal,
        BindingActionCause::Opportunity { identity, payload } => BindingActionCause::Opportunity {
            identity: *identity,
            payload: try_clone_payload(payload, allocation_error)?,
        },
        BindingActionCause::DynamicMembership {
            path,
            sequence,
            evidence,
        } => BindingActionCause::DynamicMembership {
            path: try_clone_fault_id(path, allocation_error)?,
            sequence: *sequence,
            evidence: *evidence,
        },
    })
}

fn try_clone_payload<E>(
    source: &OpportunityPayload,
    allocation_error: &mut impl FnMut() -> E,
) -> Result<OpportunityPayload, E> {
    Ok(match source {
        OpportunityPayload::None => OpportunityPayload::None,
        OpportunityPayload::NetworkFrame {
            producer,
            destination,
            producer_sequence,
            protocol_expansion_path,
            generated_response_depth,
            generated_response_cause,
            forwarding_mutation_path,
            length_bytes,
            payload_digest,
        } => OpportunityPayload::NetworkFrame {
            producer: try_clone_fault_id(producer, allocation_error)?,
            destination: try_clone_fault_id(destination, allocation_error)?,
            producer_sequence: *producer_sequence,
            protocol_expansion_path: try_clone_slice(protocol_expansion_path, allocation_error)?,
            generated_response_depth: *generated_response_depth,
            generated_response_cause: *generated_response_cause,
            forwarding_mutation_path: try_clone_slice(forwarding_mutation_path, allocation_error)?,
            length_bytes: *length_bytes,
            payload_digest: *payload_digest,
        },
        OpportunityPayload::NetworkControl {
            technology,
            event_sequence,
            request_digest,
            result_schema,
            result_digest,
        } => OpportunityPayload::NetworkControl {
            technology: try_clone_fault_id(technology, allocation_error)?,
            event_sequence: *event_sequence,
            request_digest: *request_digest,
            result_schema: try_clone_fault_id(result_schema, allocation_error)?,
            result_digest: *result_digest,
        },
        OpportunityPayload::StorageRequest {
            request_sequence,
            start_byte,
            length_bytes,
            request_digest,
        } => OpportunityPayload::StorageRequest {
            request_sequence: *request_sequence,
            start_byte: *start_byte,
            length_bytes: *length_bytes,
            request_digest: *request_digest,
        },
        OpportunityPayload::StorageCompletion {
            request_sequence,
            start_byte,
            length_bytes,
            request_digest,
            response_status,
            response_digest,
        } => OpportunityPayload::StorageCompletion {
            request_sequence: *request_sequence,
            start_byte: *start_byte,
            length_bytes: *length_bytes,
            request_digest: *request_digest,
            response_status: *response_status,
            response_digest: *response_digest,
        },
        OpportunityPayload::Instruction {
            program_counter,
            translated_block,
            instruction_digest,
        } => OpportunityPayload::Instruction {
            program_counter: *program_counter,
            translated_block: *translated_block,
            instruction_digest: *instruction_digest,
        },
        OpportunityPayload::MemoryAccess {
            guest_physical_address,
            width_bytes,
        } => OpportunityPayload::MemoryAccess {
            guest_physical_address: *guest_physical_address,
            width_bytes: *width_bytes,
        },
        OpportunityPayload::Interrupt {
            source,
            target_vcpu,
            vector,
        } => OpportunityPayload::Interrupt {
            source: try_clone_fault_id(source, allocation_error)?,
            target_vcpu: *target_vcpu,
            vector: *vector,
        },
        OpportunityPayload::AcceleratorJob {
            job_sequence,
            job_digest,
        } => OpportunityPayload::AcceleratorJob {
            job_sequence: *job_sequence,
            job_digest: *job_digest,
        },
    })
}

fn try_clone_slice<T: Copy, E>(
    source: &[T],
    allocation_error: &mut impl FnMut() -> E,
) -> Result<Vec<T>, E> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(source.len())
        .map_err(|_| allocation_error())?;
    values.extend_from_slice(source);
    Ok(values)
}

pub(super) fn try_clone_target<E>(
    source: &ResolvedFaultTarget,
    allocation_error: &mut impl FnMut() -> E,
) -> Result<ResolvedFaultTarget, E> {
    macro_rules! id {
        ($value:expr) => {
            try_clone_fault_id($value, allocation_error)?
        };
    }
    Ok(match source {
        ResolvedFaultTarget::NetworkInterface {
            endpoint,
            interface,
        } => ResolvedFaultTarget::NetworkInterface {
            endpoint: id!(endpoint),
            interface: id!(interface),
        },
        ResolvedFaultTarget::NetworkSegment { segment, direction } => {
            ResolvedFaultTarget::NetworkSegment {
                segment: id!(segment),
                direction: *direction,
            }
        }
        ResolvedFaultTarget::NetworkMedium { medium, resource } => {
            ResolvedFaultTarget::NetworkMedium {
                medium: id!(medium),
                resource: id!(resource),
            }
        }
        ResolvedFaultTarget::NetworkQueue { owner, queue } => ResolvedFaultTarget::NetworkQueue {
            owner: id!(owner),
            queue: id!(queue),
        },
        ResolvedFaultTarget::NetworkForwarder { forwarder } => {
            ResolvedFaultTarget::NetworkForwarder {
                forwarder: id!(forwarder),
            }
        }
        ResolvedFaultTarget::NetworkPath {
            path_version,
            direction,
        } => ResolvedFaultTarget::NetworkPath {
            path_version: id!(path_version),
            direction: *direction,
        },
        ResolvedFaultTarget::NetworkAttachment {
            endpoint,
            interface,
            attachment,
        } => ResolvedFaultTarget::NetworkAttachment {
            endpoint: id!(endpoint),
            interface: id!(interface),
            attachment: id!(attachment),
        },
        ResolvedFaultTarget::NetworkContact {
            plan,
            endpoint_a,
            endpoint_b,
            contact,
        } => ResolvedFaultTarget::NetworkContact {
            plan: id!(plan),
            endpoint_a: id!(endpoint_a),
            endpoint_b: id!(endpoint_b),
            contact: id!(contact),
        },
        ResolvedFaultTarget::BlockDevice { device } => {
            ResolvedFaultTarget::BlockDevice { device: *device }
        }
        ResolvedFaultTarget::BlockRange {
            device,
            start_byte,
            length_bytes,
        } => ResolvedFaultTarget::BlockRange {
            device: *device,
            start_byte: *start_byte,
            length_bytes: *length_bytes,
        },
        ResolvedFaultTarget::StorageController {
            controller,
            namespace_or_path,
        } => ResolvedFaultTarget::StorageController {
            controller: id!(controller),
            namespace_or_path: id!(namespace_or_path),
        },
        ResolvedFaultTarget::StorageArray {
            array,
            member_or_path,
        } => ResolvedFaultTarget::StorageArray {
            array: id!(array),
            member_or_path: id!(member_or_path),
        },
        ResolvedFaultTarget::NinePDevice { device } => {
            ResolvedFaultTarget::NinePDevice { device: *device }
        }
        ResolvedFaultTarget::Node { node } => ResolvedFaultTarget::Node { node: id!(node) },
        ResolvedFaultTarget::Vcpu { node, vcpu } => ResolvedFaultTarget::Vcpu {
            node: id!(node),
            vcpu: *vcpu,
        },
        ResolvedFaultTarget::Register {
            node,
            vcpu,
            architecture,
            register,
            first_bit,
            bit_count,
        } => ResolvedFaultTarget::Register {
            node: id!(node),
            vcpu: *vcpu,
            architecture: id!(architecture),
            register: id!(register),
            first_bit: *first_bit,
            bit_count: *bit_count,
        },
        ResolvedFaultTarget::MemoryRange {
            node,
            address_space,
            guest_address,
            vcpu,
            length_bytes,
        } => ResolvedFaultTarget::MemoryRange {
            node: id!(node),
            address_space: id!(address_space),
            guest_address: *guest_address,
            vcpu: *vcpu,
            length_bytes: *length_bytes,
        },
        ResolvedFaultTarget::Interrupt {
            node,
            controller,
            source,
            target_vcpu,
            vector,
        } => ResolvedFaultTarget::Interrupt {
            node: id!(node),
            controller: id!(controller),
            source: id!(source),
            target_vcpu: *target_vcpu,
            vector: *vector,
        },
        ResolvedFaultTarget::ClockSource { node, source } => ResolvedFaultTarget::ClockSource {
            node: id!(node),
            source: id!(source),
        },
        ResolvedFaultTarget::Accelerator { node, device } => ResolvedFaultTarget::Accelerator {
            node: id!(node),
            device: id!(device),
        },
    })
}
