//! World-backed authored target resolution.

use super::*;

pub(super) fn fault_object_id(id: &SignalId) -> Result<FaultObjectId, FaultSignalAuthoringError> {
    FaultObjectId::parse(id.as_str()).map_err(|_| FaultSignalAuthoringError::InvalidSelector)
}

pub(super) fn resolve_world_target_ref(
    target: &WorldFaultTargetRef,
    world: &World,
) -> Result<ResolvedFaultTarget, FaultSignalAuthoringError> {
    let topology = world.fault_topology();
    Ok(match target {
        WorldFaultTargetRef::NetworkInterface { interface } => {
            let declaration = topology
                .network_interfaces
                .iter()
                .find(|candidate| &candidate.id == interface)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkInterface {
                endpoint: fault_object_id(&declaration.endpoint)?,
                interface: fault_object_id(interface)?,
            }
        }
        WorldFaultTargetRef::NetworkSegment { segment, direction } => {
            ResolvedFaultTarget::NetworkSegment {
                segment: fault_object_id(segment)?,
                direction: *direction,
            }
        }
        WorldFaultTargetRef::NetworkMedium { medium, resource } => {
            ResolvedFaultTarget::NetworkMedium {
                medium: fault_object_id(medium)?,
                resource: fault_object_id(resource)?,
            }
        }
        WorldFaultTargetRef::NetworkForwarder { forwarder } => {
            ResolvedFaultTarget::NetworkForwarder {
                forwarder: fault_object_id(forwarder)?,
            }
        }
        WorldFaultTargetRef::NetworkQueue { queue } => {
            let declaration = topology
                .network_queues
                .iter()
                .find(|candidate| &candidate.id == queue)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkQueue {
                owner: fault_object_id(&declaration.owner)?,
                queue: fault_object_id(queue)?,
            }
        }
        WorldFaultTargetRef::NetworkPath { path, direction } => ResolvedFaultTarget::NetworkPath {
            path_version: fault_object_id(path)?,
            direction: *direction,
        },
        WorldFaultTargetRef::NetworkAttachment { attachment } => {
            let declaration = topology
                .network_attachments
                .iter()
                .find(|candidate| &candidate.id == attachment)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let interface = topology
                .network_interfaces
                .iter()
                .find(|candidate| candidate.id == declaration.interface)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkAttachment {
                endpoint: fault_object_id(&interface.endpoint)?,
                interface: fault_object_id(&interface.id)?,
                attachment: fault_object_id(attachment)?,
            }
        }
        WorldFaultTargetRef::NetworkContact { plan, contact } => {
            let declaration = topology
                .network_contact_plans
                .iter()
                .find(|candidate| &candidate.id == plan)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkContact {
                plan: fault_object_id(&declaration.id)?,
                endpoint_a: fault_object_id(&declaration.endpoint_a)?,
                endpoint_b: fault_object_id(&declaration.endpoint_b)?,
                contact: fault_object_id(contact)?,
            }
        }
        WorldFaultTargetRef::BlockDevice { device } => {
            let node = world
                .io_nodes()
                .find(|node| node.id.name == device.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::BlockDevice {
                device: node.fault_target_hash(),
            }
        }
        WorldFaultTargetRef::NinePDevice { device } => {
            let node = world
                .io_nodes()
                .find(|node| node.id.name == device.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NinePDevice {
                device: node.fault_target_hash(),
            }
        }
        WorldFaultTargetRef::StorageController {
            controller,
            namespace_or_path,
        } => ResolvedFaultTarget::StorageController {
            controller: fault_object_id(controller)?,
            namespace_or_path: fault_object_id(namespace_or_path)?,
        },
        WorldFaultTargetRef::StorageArray {
            array,
            member_or_path,
        } => ResolvedFaultTarget::StorageArray {
            array: fault_object_id(array)?,
            member_or_path: fault_object_id(member_or_path)?,
        },
        WorldFaultTargetRef::Node { node } => ResolvedFaultTarget::Node {
            node: fault_object_id(node)?,
        },
    })
}

pub(super) fn take_flat_targets(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    world: &World,
) -> Result<Vec<ResolvedFaultTarget>, FaultSignalAuthoringError> {
    let value = take_value(table, field)?;
    let toml::Value::Array(values) = value else {
        return Err(FaultSignalAuthoringError::InvalidField(field));
    };
    values
        .into_iter()
        .map(|value| resolve_authored_target(value, world))
        .collect::<Result<Vec<_>, _>>()
        .map(|targets| targets.into_iter().flatten().collect())
}

pub(super) fn resolve_authored_target(
    value: toml::Value,
    world: &World,
) -> Result<Vec<ResolvedFaultTarget>, FaultSignalAuthoringError> {
    let mut value = table(value, "selector target")?;
    let kind = take_string(&mut value, "kind")?;
    match kind.as_str() {
        "network_interface" => {
            let endpoint: FaultObjectId = take_typed(&mut value, "endpoint")?;
            let interface: FaultObjectId = take_typed(&mut value, "interface")?;
            ensure_empty(&value, "network interface selector")?;
            let exists = world
                .fault_topology()
                .network_interfaces
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == interface.as_str()
                        && candidate.endpoint.as_str() == endpoint.as_str()
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: interface.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkInterface {
                endpoint,
                interface,
            }])
        }
        "network_segment" => {
            let segment: FaultObjectId = take_typed(&mut value, "segment")?;
            let direction = take_string(&mut value, "direction")?;
            ensure_empty(&value, "network_segment selector")?;
            let exists = world
                .fault_topology()
                .network_segments
                .iter()
                .any(|candidate| candidate.id.as_str() == segment.as_str());
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: segment.to_string(),
                });
            }
            let directions = match direction.as_str() {
                "a_to_b" => vec![FaultDirection::AToB],
                "b_to_a" => vec![FaultDirection::BToA],
                "both" => vec![FaultDirection::AToB, FaultDirection::BToA],
                _ => return Err(FaultSignalAuthoringError::UnknownKind(direction)),
            };
            Ok(directions
                .into_iter()
                .map(|direction| ResolvedFaultTarget::NetworkSegment {
                    segment: segment.clone(),
                    direction,
                })
                .collect())
        }
        "network_medium" => {
            let medium: FaultObjectId = take_typed(&mut value, "medium")?;
            let resource: FaultObjectId = take_typed(&mut value, "resource")?;
            ensure_empty(&value, "network medium selector")?;
            let exists = world
                .fault_topology()
                .network_media
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == medium.as_str()
                        && candidate
                            .resources
                            .iter()
                            .any(|item| item.as_str() == resource.as_str())
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: format!("{medium}:{resource}"),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkMedium {
                medium,
                resource,
            }])
        }
        "network_queue" => {
            let owner: FaultObjectId = take_typed(&mut value, "owner")?;
            let queue: FaultObjectId = take_typed(&mut value, "queue")?;
            ensure_empty(&value, "network queue selector")?;
            let exists = world
                .fault_topology()
                .network_queues
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == queue.as_str()
                        && candidate.owner.as_str() == owner.as_str()
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: queue.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkQueue { owner, queue }])
        }
        "network_forwarder" => {
            let forwarder: FaultObjectId = take_typed(&mut value, "forwarder")?;
            ensure_empty(&value, "network forwarder selector")?;
            let exists = world
                .fault_topology()
                .network_forwarders
                .iter()
                .any(|candidate| candidate.id.as_str() == forwarder.as_str());
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: forwarder.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkForwarder { forwarder }])
        }
        "network_path" => {
            let path_version: FaultObjectId = take_typed(&mut value, "path_version")?;
            let direction: FaultDirection = take_typed(&mut value, "direction")?;
            ensure_empty(&value, "network path selector")?;
            let exists = world
                .fault_topology()
                .network_paths
                .iter()
                .any(|candidate| candidate.id.as_str() == path_version.as_str());
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: path_version.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkPath {
                path_version,
                direction,
            }])
        }
        "network_attachment" => {
            let endpoint: FaultObjectId = take_typed(&mut value, "endpoint")?;
            let interface: FaultObjectId = take_typed(&mut value, "interface")?;
            let attachment: FaultObjectId = take_typed(&mut value, "attachment")?;
            ensure_empty(&value, "network attachment selector")?;
            let topology = world.fault_topology();
            let exists = topology.network_attachments.iter().any(|candidate| {
                candidate.id.as_str() == attachment.as_str()
                    && candidate.interface.as_str() == interface.as_str()
            }) && topology.network_interfaces.iter().any(|candidate| {
                candidate.id.as_str() == interface.as_str()
                    && candidate.endpoint.as_str() == endpoint.as_str()
            });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: attachment.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkAttachment {
                endpoint,
                interface,
                attachment,
            }])
        }
        "network_contact" => {
            let plan: FaultObjectId = take_typed(&mut value, "plan")?;
            let endpoint_a: FaultObjectId = take_typed(&mut value, "endpoint_a")?;
            let endpoint_b: FaultObjectId = take_typed(&mut value, "endpoint_b")?;
            let contact: FaultObjectId = take_typed(&mut value, "contact")?;
            ensure_empty(&value, "network contact selector")?;
            let exists = world
                .fault_topology()
                .network_contact_plans
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == plan.as_str()
                        && candidate.endpoint_a.as_str() == endpoint_a.as_str()
                        && candidate.endpoint_b.as_str() == endpoint_b.as_str()
                        && candidate
                            .contacts
                            .iter()
                            .any(|candidate| candidate.id.as_str() == contact.as_str())
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: contact.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkContact {
                plan,
                endpoint_a,
                endpoint_b,
                contact,
            }])
        }
        "block_device" | "nine_p_device" => {
            let device = take_string(&mut value, "device")?;
            ensure_empty(&value, "storage device selector")?;
            let matched = world.io_nodes().find(|node| {
                let kind_matches = matches!(
                    (&node.kind, kind.as_str()),
                    (WorldIoNodeKind::Block { .. }, "block_device")
                        | (WorldIoNodeKind::NineP { .. }, "nine_p_device")
                );
                kind_matches
                    && (node.id.name == device
                        || format_content_hash_ref(node.fault_target_hash()) == device)
            });
            let node = matched.ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                kind: kind.clone(),
                id: device,
            })?;
            let declared = world
                .fault_topology()
                .storage_devices
                .iter()
                .any(|candidate| {
                    candidate.device.as_str() == node.id.name
                        && matches!(
                            (candidate.kind, kind.as_str()),
                            (WorldStorageKind::Block, "block_device")
                                | (WorldStorageKind::NineP, "nine_p_device")
                        )
                });
            if !declared {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: node.id.name.clone(),
                });
            }
            let target = if kind == "block_device" {
                ResolvedFaultTarget::BlockDevice {
                    device: node.fault_target_hash(),
                }
            } else {
                ResolvedFaultTarget::NinePDevice {
                    device: node.fault_target_hash(),
                }
            };
            Ok(vec![target])
        }
        "block_range" => {
            let device = take_string(&mut value, "device")?;
            let start_byte: u64 = take_typed(&mut value, "start_byte")?;
            let length_bytes: u64 = take_typed(&mut value, "length_bytes")?;
            ensure_empty(&value, "block range selector")?;
            let node = world
                .io_nodes()
                .find(|node| {
                    matches!(node.kind, WorldIoNodeKind::Block { .. })
                        && (node.id.name == device
                            || format_content_hash_ref(node.fault_target_hash()) == device)
                })
                .ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                    kind: kind.clone(),
                    id: device,
                })?;
            let declaration = world
                .fault_topology()
                .storage_devices
                .iter()
                .find(|candidate| {
                    candidate.kind == WorldStorageKind::Block
                        && candidate.device.as_str() == node.id.name
                })
                .ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                    kind: kind.clone(),
                    id: node.id.name.clone(),
                })?;
            let end = start_byte
                .checked_add(length_bytes)
                .filter(|_| length_bytes > 0)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            if end > declaration.persistence.length_bytes {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            }
            Ok(vec![ResolvedFaultTarget::BlockRange {
                device: node.fault_target_hash(),
                start_byte,
                length_bytes,
            }])
        }
        "storage_controller" => {
            let controller: FaultObjectId = take_typed(&mut value, "controller")?;
            let namespace_or_path: FaultObjectId = take_typed(&mut value, "namespace_or_path")?;
            ensure_empty(&value, "storage controller selector")?;
            let exists = world
                .fault_topology()
                .storage_controllers
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == controller.as_str()
                        && (candidate
                            .namespaces
                            .iter()
                            .any(|item| item.id.as_str() == namespace_or_path.as_str())
                            || candidate
                                .paths
                                .iter()
                                .any(|item| item.id.as_str() == namespace_or_path.as_str()))
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: format!("{controller}:{namespace_or_path}"),
                });
            }
            Ok(vec![ResolvedFaultTarget::StorageController {
                controller,
                namespace_or_path,
            }])
        }
        "storage_array" => {
            let array: FaultObjectId = take_typed(&mut value, "array")?;
            let member_or_path: FaultObjectId = take_typed(&mut value, "member_or_path")?;
            ensure_empty(&value, "storage array selector")?;
            let exists = world
                .fault_topology()
                .storage_arrays
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == array.as_str()
                        && (candidate
                            .members
                            .iter()
                            .any(|item| item.id.as_str() == member_or_path.as_str())
                            || candidate
                                .paths
                                .iter()
                                .any(|item| item.id.as_str() == member_or_path.as_str()))
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: format!("{array}:{member_or_path}"),
                });
            }
            Ok(vec![ResolvedFaultTarget::StorageArray {
                array,
                member_or_path,
            }])
        }
        "node" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            ensure_empty(&value, "node selector")?;
            if !world.vm_nodes().iter().any(|candidate| {
                candidate.id.name.as_str() == node.as_str()
                    && (world.fault_topology().node_capabilities.is_empty()
                        || world
                            .fault_topology()
                            .node_capabilities
                            .iter()
                            .any(|capabilities| capabilities.node.as_str() == node.as_str()))
            }) {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: node.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::Node { node }])
        }
        "vcpu" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let vcpu = take_typed(&mut value, "vcpu")?;
            ensure_empty(&value, "vcpu selector")?;
            let declared = world
                .fault_topology()
                .node_capabilities
                .iter()
                .any(|candidate| candidate.node.as_str() == node.as_str());
            let valid = declared
                && world.vm_nodes().iter().any(|candidate| {
                    candidate.id.name == node.as_str() && u32::from(candidate.smp_vcpus) > vcpu
                });
            if !valid {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: format!("{}:{vcpu}", node.as_str()),
                });
            }
            Ok(vec![ResolvedFaultTarget::Vcpu { node, vcpu }])
        }
        "register" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let vcpu: u32 = take_typed(&mut value, "vcpu")?;
            let architecture: FaultObjectId = take_typed(&mut value, "architecture")?;
            let register: FaultObjectId = take_typed(&mut value, "register")?;
            let first_bit: u16 = take_typed(&mut value, "first_bit")?;
            let bit_count: u16 = take_typed(&mut value, "bit_count")?;
            ensure_empty(&value, "register selector")?;
            let vm = world
                .vm_nodes()
                .iter()
                .find(|candidate| candidate.id.name == node.as_str())
                .ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                    kind: kind.clone(),
                    id: node.to_string(),
                })?;
            let capabilities = world
                .fault_topology()
                .node_capabilities
                .iter()
                .find(|candidate| candidate.node.as_str() == node.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let row = capabilities
                .registers
                .iter()
                .find(|candidate| candidate.id.as_str() == register.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let end = first_bit
                .checked_add(bit_count)
                .filter(|_| bit_count > 0)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            if architecture.as_str() != capabilities.architecture.selector_id()
                || vcpu >= u32::from(vm.smp_vcpus)
                || u32::from(end) > row.width_bits
                || !row.range_is_writable(u32::from(first_bit), u32::from(bit_count))
                || (!row.per_vcpu && vcpu != 0)
            {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            }
            Ok(vec![ResolvedFaultTarget::Register {
                node,
                vcpu,
                architecture,
                register,
                first_bit,
                bit_count,
            }])
        }
        "memory_range" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let address_space: FaultObjectId = take_typed(&mut value, "address_space")?;
            let guest_address: u64 = take_typed(&mut value, "guest_address")?;
            let vcpu: Option<u32> = take_optional_typed(&mut value, "vcpu")?;
            let length_bytes: u64 = take_typed(&mut value, "length_bytes")?;
            ensure_empty(&value, "memory range selector")?;
            let capabilities = world
                .fault_topology()
                .node_capabilities
                .iter()
                .find(|candidate| candidate.node.as_str() == node.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let space = capabilities
                .address_spaces
                .iter()
                .find(|candidate| candidate.id.as_str() == address_space.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let end = guest_address
                .checked_add(length_bytes)
                .filter(|_| length_bytes > 0)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let space_end = space
                .start_address
                .checked_add(space.length_bytes)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let vm = world
                .vm_nodes()
                .iter()
                .find(|candidate| candidate.id.name == node.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let context_valid = match address_space.as_str() {
                "gpa" => vcpu.is_none(),
                "gva" => vcpu.is_some_and(|index| index < u32::from(vm.smp_vcpus)),
                _ => false,
            };
            if !context_valid || guest_address < space.start_address || end > space_end {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            }
            Ok(vec![ResolvedFaultTarget::MemoryRange {
                node,
                address_space,
                guest_address,
                vcpu,
                length_bytes,
            }])
        }
        "interrupt" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let controller: FaultObjectId = take_typed(&mut value, "controller")?;
            let source: FaultObjectId = take_typed(&mut value, "source")?;
            let target_vcpu: u32 = take_typed(&mut value, "target_vcpu")?;
            let vector: u32 = take_typed(&mut value, "vector")?;
            ensure_empty(&value, "interrupt selector")?;
            let exists = world
                .fault_topology()
                .node_capabilities
                .iter()
                .find(|candidate| candidate.node.as_str() == node.as_str())
                .is_some_and(|capabilities| {
                    capabilities.interrupts.iter().any(|row| {
                        row.controller.as_str() == controller.as_str()
                            && row.source.as_str() == source.as_str()
                            && (row.vector_start..=row.vector_end).contains(&vector)
                            && row.target_vcpus.contains(&target_vcpu)
                    })
                });
            if !exists {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            }
            Ok(vec![ResolvedFaultTarget::Interrupt {
                node,
                controller,
                source,
                target_vcpu,
                vector,
            }])
        }
        "clock_source" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let source: FaultObjectId = take_typed(&mut value, "source")?;
            ensure_empty(&value, "clock source selector")?;
            let exists = world
                .fault_topology()
                .node_capabilities
                .iter()
                .find(|candidate| candidate.node.as_str() == node.as_str())
                .is_some_and(|capabilities| {
                    capabilities
                        .clock_sources
                        .iter()
                        .any(|row| row.id.as_str() == source.as_str())
                });
            if !exists {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            }
            Ok(vec![ResolvedFaultTarget::ClockSource { node, source }])
        }
        "accelerator" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let device: FaultObjectId = take_typed(&mut value, "device")?;
            ensure_empty(&value, "accelerator selector")?;
            let exists = world
                .fault_topology()
                .node_capabilities
                .iter()
                .find(|candidate| candidate.node.as_str() == node.as_str())
                .is_some_and(|capabilities| {
                    capabilities
                        .accelerators
                        .iter()
                        .any(|row| row.id.as_str() == device.as_str())
                });
            if !exists {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            }
            Ok(vec![ResolvedFaultTarget::Accelerator { node, device }])
        }
        _ => Err(FaultSignalAuthoringError::UnknownKind(kind)),
    }
}
