//! Structural fault evidence copies; immutable identities retain exact bytes.

use super::*;
use crate::model::{FaultObjectId, FaultObservation, ResolvedFaultTarget};

pub(super) fn copy_observation(source: &FaultObservation) -> Result<FaultObservation, EngineError> {
    Ok(FaultObservation {
        semantic_version: source.semantic_version,
        kind: source.kind,
        coordinate: source.coordinate,
        binding: source.binding.as_ref().map(copy_id).transpose()?,
        target: source.target.as_ref().map(copy_target).transpose()?,
        opportunity: source.opportunity,
        evidence: source.evidence,
    })
}

fn copy_id(source: &FaultObjectId) -> Result<FaultObjectId, EngineError> {
    source.try_clone_admitted()
}

fn copy_target(source: &ResolvedFaultTarget) -> Result<ResolvedFaultTarget, EngineError> {
    use ResolvedFaultTarget as P;
    Ok(match source {
        P::NetworkInterface {
            endpoint,
            interface,
        } => P::NetworkInterface {
            endpoint: copy_id(endpoint)?,
            interface: copy_id(interface)?,
        },
        P::NetworkSegment { segment, direction } => P::NetworkSegment {
            segment: copy_id(segment)?,
            direction: *direction,
        },
        P::NetworkMedium { medium, resource } => P::NetworkMedium {
            medium: copy_id(medium)?,
            resource: copy_id(resource)?,
        },
        P::NetworkQueue { owner, queue } => P::NetworkQueue {
            owner: copy_id(owner)?,
            queue: copy_id(queue)?,
        },
        P::NetworkForwarder { forwarder } => P::NetworkForwarder {
            forwarder: copy_id(forwarder)?,
        },
        P::NetworkPath {
            path_version,
            direction,
        } => P::NetworkPath {
            path_version: copy_id(path_version)?,
            direction: *direction,
        },
        P::NetworkAttachment {
            endpoint,
            interface,
            attachment,
        } => P::NetworkAttachment {
            endpoint: copy_id(endpoint)?,
            interface: copy_id(interface)?,
            attachment: copy_id(attachment)?,
        },
        P::NetworkContact {
            plan,
            endpoint_a,
            endpoint_b,
            contact,
        } => P::NetworkContact {
            plan: copy_id(plan)?,
            endpoint_a: copy_id(endpoint_a)?,
            endpoint_b: copy_id(endpoint_b)?,
            contact: copy_id(contact)?,
        },
        P::BlockDevice { device } => P::BlockDevice { device: *device },
        P::BlockRange {
            device,
            start_byte,
            length_bytes,
        } => P::BlockRange {
            device: *device,
            start_byte: *start_byte,
            length_bytes: *length_bytes,
        },
        P::StorageController {
            controller,
            namespace_or_path,
        } => P::StorageController {
            controller: copy_id(controller)?,
            namespace_or_path: copy_id(namespace_or_path)?,
        },
        P::StorageArray {
            array,
            member_or_path,
        } => P::StorageArray {
            array: copy_id(array)?,
            member_or_path: copy_id(member_or_path)?,
        },
        P::NinePDevice { device } => P::NinePDevice { device: *device },
        P::Node { node } => P::Node {
            node: copy_id(node)?,
        },
        P::Vcpu { node, vcpu } => P::Vcpu {
            node: copy_id(node)?,
            vcpu: *vcpu,
        },
        P::Register {
            node,
            vcpu,
            architecture,
            register,
            first_bit,
            bit_count,
        } => P::Register {
            node: copy_id(node)?,
            vcpu: *vcpu,
            architecture: copy_id(architecture)?,
            register: copy_id(register)?,
            first_bit: *first_bit,
            bit_count: *bit_count,
        },
        P::MemoryRange {
            node,
            address_space,
            guest_address,
            vcpu,
            length_bytes,
        } => P::MemoryRange {
            node: copy_id(node)?,
            address_space: copy_id(address_space)?,
            guest_address: *guest_address,
            vcpu: *vcpu,
            length_bytes: *length_bytes,
        },
        P::Interrupt {
            node,
            controller,
            source,
            target_vcpu,
            vector,
        } => P::Interrupt {
            node: copy_id(node)?,
            controller: copy_id(controller)?,
            source: copy_id(source)?,
            target_vcpu: *target_vcpu,
            vector: *vector,
        },
        P::ClockSource { node, source } => P::ClockSource {
            node: copy_id(node)?,
            source: copy_id(source)?,
        },
        P::Accelerator { node, device } => P::Accelerator {
            node: copy_id(node)?,
            device: copy_id(device)?,
        },
    })
}
