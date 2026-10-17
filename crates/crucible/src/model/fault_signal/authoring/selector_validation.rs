//! Borrowed validation of already resolved selectors against realized World contracts.
//!
//! Persistence validation does not need an owned authoring projection. The
//! checks below use the same declared memberships and ranges as TOML target
//! resolution while retaining every identity in its original owner.

use super::*;

pub(in crate::model::fault_signal) fn validate_selector_for_world(
    selector: &TargetSelector,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    let valid = match selector {
        TargetSelector::Exact(targets) => {
            targets.targets().len() == 1
                && targets
                    .targets()
                    .iter()
                    .all(|target| valid_target(target, world))
        }
        TargetSelector::TargetSet(targets) => {
            // A one-element authored set remains a TargetSet. An empty set is
            // valid only when its already-admitted contract permits emptiness.
            targets
                .targets()
                .iter()
                .all(|target| valid_target(target, world))
        }
        TargetSelector::FaultDomain { domain, resolved } => world
            .fault_topology()
            .fault_domains
            .iter()
            .any(|declaration| {
                declaration.id.as_str() == domain.as_str()
                    && !resolved.allow_empty()
                    && declaration.targets.len() == resolved.targets().len()
                    && resolved.targets().iter().all(|target| {
                        declaration
                            .targets
                            .iter()
                            .filter(|reference| matches_reference(target, reference, world))
                            .count()
                            == 1
                    })
            }),
        TargetSelector::DynamicPath { path, initial, .. } => world
            .fault_topology()
            .network_paths
            .iter()
            .any(|declaration| {
                declaration.id.as_str() == path.as_str()
                    && !initial.allow_empty()
                    && declaration.hops.len() == initial.targets().len()
                    && initial.targets().iter().all(|target| {
                        declaration
                            .hops
                            .iter()
                            .filter(|hop| match (target, hop) {
                                (
                                    ResolvedFaultTarget::NetworkSegment { segment, direction },
                                    WorldNetworkPathHop::Segment {
                                        segment: expected,
                                        direction: side,
                                    },
                                ) => segment.as_str() == expected.as_str() && direction == side,
                                (
                                    ResolvedFaultTarget::NetworkForwarder { forwarder },
                                    WorldNetworkPathHop::Forwarder {
                                        forwarder: expected,
                                    },
                                ) => forwarder.as_str() == expected.as_str(),
                                (
                                    ResolvedFaultTarget::NetworkQueue { owner, queue },
                                    WorldNetworkPathHop::Queue { queue: expected },
                                ) => {
                                    queue.as_str() == expected.as_str()
                                        && world.fault_topology().network_queues.iter().any(|row| {
                                            row.id == *expected
                                                && row.owner.as_str() == owner.as_str()
                                        })
                                }
                                _ => false,
                            })
                            .count()
                            == 1
                    })
            }),
    };
    if valid {
        Ok(())
    } else {
        Err(FaultSignalAuthoringError::InvalidSelector)
    }
}

fn valid_target(target: &ResolvedFaultTarget, world: &World) -> bool {
    let topology = world.fault_topology();
    match target {
        ResolvedFaultTarget::NetworkInterface {
            endpoint,
            interface,
        } => topology.network_interfaces.iter().any(|row| {
            row.id.as_str() == interface.as_str() && row.endpoint.as_str() == endpoint.as_str()
        }),
        ResolvedFaultTarget::NetworkSegment { segment, .. } => topology
            .network_segments
            .iter()
            .any(|row| row.id.as_str() == segment.as_str()),
        ResolvedFaultTarget::NetworkMedium { medium, resource } => {
            topology.network_media.iter().any(|row| {
                row.id.as_str() == medium.as_str()
                    && row
                        .resources
                        .iter()
                        .any(|item| item.as_str() == resource.as_str())
            })
        }
        ResolvedFaultTarget::NetworkQueue { owner, queue } => topology
            .network_queues
            .iter()
            .any(|row| row.id.as_str() == queue.as_str() && row.owner.as_str() == owner.as_str()),
        ResolvedFaultTarget::NetworkForwarder { forwarder } => topology
            .network_forwarders
            .iter()
            .any(|row| row.id.as_str() == forwarder.as_str()),
        ResolvedFaultTarget::NetworkPath { path_version, .. } => topology
            .network_paths
            .iter()
            .any(|row| row.id.as_str() == path_version.as_str()),
        ResolvedFaultTarget::NetworkAttachment {
            endpoint,
            interface,
            attachment,
        } => {
            topology.network_attachments.iter().any(|row| {
                row.id.as_str() == attachment.as_str()
                    && row.interface.as_str() == interface.as_str()
            }) && topology.network_interfaces.iter().any(|row| {
                row.id.as_str() == interface.as_str() && row.endpoint.as_str() == endpoint.as_str()
            })
        }
        ResolvedFaultTarget::NetworkContact {
            plan,
            endpoint_a,
            endpoint_b,
            contact,
        } => topology.network_contact_plans.iter().any(|row| {
            row.id.as_str() == plan.as_str()
                && row.endpoint_a.as_str() == endpoint_a.as_str()
                && row.endpoint_b.as_str() == endpoint_b.as_str()
                && row
                    .contacts
                    .iter()
                    .any(|item| item.id.as_str() == contact.as_str())
        }),
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::NinePDevice { device } => {
            let kind = if matches!(target, ResolvedFaultTarget::BlockDevice { .. }) {
                WorldStorageKind::Block
            } else {
                WorldStorageKind::NineP
            };
            storage_target(world, *device, kind).is_some()
        }
        ResolvedFaultTarget::BlockRange {
            device,
            start_byte,
            length_bytes,
        } => storage_target(world, *device, WorldStorageKind::Block).is_some_and(|length| {
            *length_bytes > 0
                && start_byte
                    .checked_add(*length_bytes)
                    .is_some_and(|end| end <= length)
        }),
        ResolvedFaultTarget::StorageController {
            controller,
            namespace_or_path,
        } => topology.storage_controllers.iter().any(|row| {
            row.id.as_str() == controller.as_str()
                && (row
                    .namespaces
                    .iter()
                    .any(|item| item.id.as_str() == namespace_or_path.as_str())
                    || row
                        .paths
                        .iter()
                        .any(|item| item.id.as_str() == namespace_or_path.as_str()))
        }),
        ResolvedFaultTarget::StorageArray {
            array,
            member_or_path,
        } => topology.storage_arrays.iter().any(|row| {
            row.id.as_str() == array.as_str()
                && (row
                    .members
                    .iter()
                    .any(|item| item.id.as_str() == member_or_path.as_str())
                    || row
                        .paths
                        .iter()
                        .any(|item| item.id.as_str() == member_or_path.as_str()))
        }),
        ResolvedFaultTarget::Node { node } => {
            world
                .vm_nodes()
                .iter()
                .any(|row| row.id.name == node.as_str())
                && (topology.node_capabilities.is_empty()
                    || topology
                        .node_capabilities
                        .iter()
                        .any(|row| row.node.as_str() == node.as_str()))
        }
        ResolvedFaultTarget::Vcpu { node, vcpu } => {
            topology
                .node_capabilities
                .iter()
                .any(|row| row.node.as_str() == node.as_str())
                && world
                    .vm_nodes()
                    .iter()
                    .any(|row| row.id.name == node.as_str() && *vcpu < u32::from(row.smp_vcpus))
        }
        ResolvedFaultTarget::Register {
            node,
            vcpu,
            architecture,
            register,
            first_bit,
            bit_count,
        } => {
            let Some(vm) = world
                .vm_nodes()
                .iter()
                .find(|row| row.id.name == node.as_str())
            else {
                return false;
            };
            topology
                .node_capabilities
                .iter()
                .find(|row| row.node.as_str() == node.as_str())
                .is_some_and(|capabilities| {
                    architecture.as_str() == capabilities.architecture.selector_id()
                        && *vcpu < u32::from(vm.smp_vcpus)
                        && capabilities.registers.iter().any(|row| {
                            row.id.as_str() == register.as_str()
                                && *bit_count > 0
                                && first_bit
                                    .checked_add(*bit_count)
                                    .is_some_and(|end| u32::from(end) <= row.width_bits)
                                && row
                                    .range_is_writable(u32::from(*first_bit), u32::from(*bit_count))
                                && (row.per_vcpu || *vcpu == 0)
                        })
                })
        }
        ResolvedFaultTarget::MemoryRange {
            node,
            address_space,
            guest_address,
            vcpu,
            length_bytes,
        } => {
            let Some(vm) = world
                .vm_nodes()
                .iter()
                .find(|row| row.id.name == node.as_str())
            else {
                return false;
            };
            let context = match address_space.as_str() {
                "gpa" => vcpu.is_none(),
                "gva" => vcpu.is_some_and(|index| index < u32::from(vm.smp_vcpus)),
                _ => false,
            };
            context
                && *length_bytes > 0
                && topology
                    .node_capabilities
                    .iter()
                    .find(|row| row.node.as_str() == node.as_str())
                    .is_some_and(|capabilities| {
                        capabilities.address_spaces.iter().any(|space| {
                            space.id.as_str() == address_space.as_str()
                                && *guest_address >= space.start_address
                                && guest_address
                                    .checked_add(*length_bytes)
                                    .zip(space.start_address.checked_add(space.length_bytes))
                                    .is_some_and(|(end, limit)| end <= limit)
                        })
                    })
        }
        ResolvedFaultTarget::Interrupt {
            node,
            controller,
            source,
            target_vcpu,
            vector,
        } => topology
            .node_capabilities
            .iter()
            .find(|row| row.node.as_str() == node.as_str())
            .is_some_and(|capabilities| {
                capabilities.interrupts.iter().any(|row| {
                    row.controller.as_str() == controller.as_str()
                        && row.source.as_str() == source.as_str()
                        && (row.vector_start..=row.vector_end).contains(vector)
                        && row.target_vcpus.contains(target_vcpu)
                })
            }),
        ResolvedFaultTarget::ClockSource { node, source } => topology
            .node_capabilities
            .iter()
            .find(|row| row.node.as_str() == node.as_str())
            .is_some_and(|capabilities| {
                capabilities
                    .clock_sources
                    .iter()
                    .any(|row| row.id.as_str() == source.as_str())
            }),
        ResolvedFaultTarget::Accelerator { node, device } => topology
            .node_capabilities
            .iter()
            .find(|row| row.node.as_str() == node.as_str())
            .is_some_and(|capabilities| {
                capabilities
                    .accelerators
                    .iter()
                    .any(|row| row.id.as_str() == device.as_str())
            }),
    }
}

fn storage_target(world: &World, device: ContentHash, kind: WorldStorageKind) -> Option<u64> {
    world
        .io_nodes()
        .find(|node| {
            node.fault_target_hash() == device
                && matches!(
                    (&node.kind, kind),
                    (WorldIoNodeKind::Block { .. }, WorldStorageKind::Block)
                        | (WorldIoNodeKind::NineP { .. }, WorldStorageKind::NineP)
                )
        })
        .and_then(|node| {
            world
                .fault_topology()
                .storage_devices
                .iter()
                .find(|row| row.kind == kind && row.device.as_str() == node.id.name)
        })
        .map(|row| row.persistence.length_bytes)
}

fn matches_reference(
    target: &ResolvedFaultTarget,
    reference: &WorldFaultTargetRef,
    world: &World,
) -> bool {
    match (target, reference) {
        (
            ResolvedFaultTarget::NetworkInterface { interface, .. },
            WorldFaultTargetRef::NetworkInterface {
                interface: expected,
            },
        ) => interface.as_str() == expected.as_str() && valid_target(target, world),
        (
            ResolvedFaultTarget::NetworkSegment { segment, direction },
            WorldFaultTargetRef::NetworkSegment {
                segment: expected,
                direction: side,
            },
        ) => segment.as_str() == expected.as_str() && direction == side,
        (
            ResolvedFaultTarget::NetworkMedium { medium, resource },
            WorldFaultTargetRef::NetworkMedium {
                medium: expected,
                resource: channel,
            },
        ) => medium.as_str() == expected.as_str() && resource.as_str() == channel.as_str(),
        (
            ResolvedFaultTarget::NetworkForwarder { forwarder },
            WorldFaultTargetRef::NetworkForwarder {
                forwarder: expected,
            },
        ) => forwarder.as_str() == expected.as_str(),
        (
            ResolvedFaultTarget::NetworkQueue { queue, .. },
            WorldFaultTargetRef::NetworkQueue { queue: expected },
        ) => queue.as_str() == expected.as_str() && valid_target(target, world),
        (
            ResolvedFaultTarget::NetworkPath {
                path_version,
                direction,
            },
            WorldFaultTargetRef::NetworkPath {
                path,
                direction: side,
            },
        ) => path_version.as_str() == path.as_str() && direction == side,
        (
            ResolvedFaultTarget::NetworkAttachment { attachment, .. },
            WorldFaultTargetRef::NetworkAttachment {
                attachment: expected,
            },
        ) => attachment.as_str() == expected.as_str() && valid_target(target, world),
        (
            ResolvedFaultTarget::NetworkContact { plan, contact, .. },
            WorldFaultTargetRef::NetworkContact {
                plan: expected,
                contact: item,
            },
        ) => {
            plan.as_str() == expected.as_str()
                && contact.as_str() == item.as_str()
                && valid_target(target, world)
        }
        (
            ResolvedFaultTarget::BlockDevice { device },
            WorldFaultTargetRef::BlockDevice { device: expected },
        )
        | (
            ResolvedFaultTarget::NinePDevice { device },
            WorldFaultTargetRef::NinePDevice { device: expected },
        ) => world
            .io_nodes()
            .any(|node| node.id.name == expected.as_str() && node.fault_target_hash() == *device),
        (
            ResolvedFaultTarget::StorageController {
                controller,
                namespace_or_path,
            },
            WorldFaultTargetRef::StorageController {
                controller: expected,
                namespace_or_path: item,
            },
        ) => {
            controller.as_str() == expected.as_str() && namespace_or_path.as_str() == item.as_str()
        }
        (
            ResolvedFaultTarget::StorageArray {
                array,
                member_or_path,
            },
            WorldFaultTargetRef::StorageArray {
                array: expected,
                member_or_path: item,
            },
        ) => array.as_str() == expected.as_str() && member_or_path.as_str() == item.as_str(),
        (ResolvedFaultTarget::Node { node }, WorldFaultTargetRef::Node { node: expected }) => {
            node.as_str() == expected.as_str()
        }
        _ => false,
    }
}
