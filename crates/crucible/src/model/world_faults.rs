//! Executable world declarations addressed by signal-driven fault bindings.
//!
//! The ordinary VM, I/O-node, and point-to-point link declarations describe
//! processes and scheduler participants. This module describes the stable
//! hardware and networking objects inside that world which fault selectors may
//! address. These declarations are immutable, validated, and included in world
//! identity; runtime state is stored by the owning adapter instead.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;

/// Hard maximum number of declarations in any one world fault registry table.
pub const HARD_WORLD_FAULT_DECLARATIONS_PER_KIND: usize = 65_536;
/// Hard maximum number of references carried by one world fault declaration.
pub const HARD_WORLD_FAULT_REFERENCES_PER_DECLARATION: usize = 4_096;

/// Complete immutable world registry used by fault selectors and adapters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldFaultTopology {
    /// Named fault domains which resolve to finite typed target sets.
    pub fault_domains: Vec<WorldFaultDomain>,
    /// Network interfaces owned by VM endpoints.
    pub network_interfaces: Vec<WorldNetworkInterface>,
    /// Directed-capable physical or logical network segments.
    pub network_segments: Vec<WorldNetworkSegment>,
    /// Shared or point-to-point transmission media.
    pub network_media: Vec<WorldNetworkMedium>,
    /// Switches, routers, gateways, and other forwarding elements.
    pub network_forwarders: Vec<WorldNetworkForwarder>,
    /// Bounded queues owned by interfaces, media, or forwarders.
    pub network_queues: Vec<WorldNetworkQueue>,
    /// Ordered routes through declared segments and forwarders.
    pub network_paths: Vec<WorldNetworkPath>,
    /// Association state machines for intermittently attached endpoints.
    pub network_attachments: Vec<WorldNetworkAttachment>,
    /// Scheduled contact plans for delay/disruption-tolerant links.
    pub network_contact_plans: Vec<WorldNetworkContactPlan>,
    /// Mobile endpoints whose truth trajectory is supplied by a signal.
    pub mobile_endpoints: Vec<WorldMobileEndpoint>,
    /// Durability and media contracts for deterministic block/9p nodes.
    pub storage_devices: Vec<WorldStorageFaultDevice>,
    /// Live-QEMU capability contracts for VM nodes.
    pub node_capabilities: Vec<WorldNodeFaultCapabilities>,
}

impl WorldFaultTopology {
    /// Returns whether the registry contains no fault-addressable declarations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Computes the content address of the complete canonical registry.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Codec`] if the closed registry cannot
    /// be encoded by its derived canonical JSON representation.
    pub fn content_hash(&self) -> Result<ContentHash, WorldFaultTopologyError> {
        let mut bytes = b"crucible.model.world-fault-topology.v1\0".to_vec();
        bytes.extend_from_slice(&self.canonical_bytes()?);
        Ok(ContentHash::from_bytes(&bytes))
    }

    /// Encodes the canonical registry payload used by world persistence.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError::Codec`] if the closed derived schema
    /// cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorldFaultTopologyError> {
        serde_json::to_vec(self).map_err(|error| WorldFaultTopologyError::Codec(error.to_string()))
    }

    /// Validates and canonicalizes a complete world fault registry.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError`] for duplicate IDs, excessive
    /// collections, dangling references, self-references, invalid geometry, or
    /// a sensor-backed field which is specification-only in schema v2.
    pub fn admit(mut self, world: &World) -> Result<Self, WorldFaultTopologyError> {
        canonicalize_by_id(&mut self.fault_domains, WorldFaultDomain::id)?;
        canonicalize_by_id(&mut self.network_interfaces, WorldNetworkInterface::id)?;
        canonicalize_by_id(&mut self.network_segments, WorldNetworkSegment::id)?;
        canonicalize_by_id(&mut self.network_media, WorldNetworkMedium::id)?;
        canonicalize_by_id(&mut self.network_forwarders, WorldNetworkForwarder::id)?;
        canonicalize_by_id(&mut self.network_queues, WorldNetworkQueue::id)?;
        canonicalize_by_id(&mut self.network_paths, WorldNetworkPath::id)?;
        canonicalize_by_id(&mut self.network_attachments, WorldNetworkAttachment::id)?;
        canonicalize_by_id(&mut self.network_contact_plans, WorldNetworkContactPlan::id)?;
        canonicalize_by_id(&mut self.mobile_endpoints, WorldMobileEndpoint::id)?;
        canonicalize_by_id(&mut self.storage_devices, WorldStorageFaultDevice::id)?;
        canonicalize_by_id(&mut self.node_capabilities, WorldNodeFaultCapabilities::id)?;

        for domain in &mut self.fault_domains {
            canonicalize_set(&mut domain.targets, "fault domain targets")?;
        }
        for interface in &mut self.network_interfaces {
            canonicalize_set(&mut interface.addresses, "network interface addresses")?;
            canonicalize_set(
                &mut interface.fault_domains,
                "network interface fault domains",
            )?;
        }
        for segment in &mut self.network_segments {
            canonicalize_set(&mut segment.forwarders, "network segment forwarders")?;
            canonicalize_set(&mut segment.fault_domains, "network segment fault domains")?;
        }
        for medium in &mut self.network_media {
            canonicalize_set(&mut medium.resources, "network medium resources")?;
            canonicalize_set(&mut medium.fault_domains, "network medium fault domains")?;
        }
        for forwarder in &mut self.network_forwarders {
            canonicalize_set(&mut forwarder.ports, "network forwarder ports")?;
            canonicalize_set(
                &mut forwarder.fault_domains,
                "network forwarder fault domains",
            )?;
        }
        for queue in &mut self.network_queues {
            canonicalize_set(&mut queue.fault_domains, "network queue fault domains")?;
        }
        for attachment in &mut self.network_attachments {
            canonicalize_set(&mut attachment.candidates, "network attachment candidates")?;
        }
        for storage in &mut self.storage_devices {
            canonicalize_set(&mut storage.fault_domains, "storage device fault domains")?;
        }
        for capabilities in &mut self.node_capabilities {
            canonicalize_set(&mut capabilities.address_spaces, "node address spaces")?;
            canonicalize_set(
                &mut capabilities.interrupt_controllers,
                "node interrupt controllers",
            )?;
            canonicalize_set(&mut capabilities.clock_sources, "node clock sources")?;
            canonicalize_set(&mut capabilities.accelerators, "node accelerators")?;
        }

        let vm_nodes = world
            .vm_nodes()
            .iter()
            .map(|node| node.id.name.as_str())
            .collect::<BTreeSet<_>>();
        let io_nodes = world
            .io_nodes()
            .map(|node| (node.id.name.as_str(), node.kind.family()))
            .collect::<BTreeMap<_, _>>();
        let interfaces = ids(&self.network_interfaces);
        let segments = ids(&self.network_segments);
        let media = ids(&self.network_media);
        let forwarders = ids(&self.network_forwarders);
        let queues = ids(&self.network_queues);
        let fault_domains = ids(&self.fault_domains);

        for interface in &self.network_interfaces {
            require_all(
                &interface.fault_domains,
                &fault_domains,
                "network interface fault domain",
            )?;
        }

        for interface in &self.network_interfaces {
            require(
                vm_nodes.contains(interface.endpoint.as_str()),
                "network interface endpoint",
            )?;
        }
        for segment in &self.network_segments {
            require_all(
                &segment.fault_domains,
                &fault_domains,
                "network segment fault domain",
            )?;
            require(
                segment.interface_a != segment.interface_b,
                "network segment self-loop",
            )?;
            require(
                interfaces.contains(&segment.interface_a),
                "network segment interface_a",
            )?;
            require(
                interfaces.contains(&segment.interface_b),
                "network segment interface_b",
            )?;
            require(
                segment.minimum_latency_nanos > 0,
                "network segment minimum latency",
            )?;
            if let Some(reference) = &segment.medium {
                require(media.contains(reference), "network segment medium")?;
            }
            require_all(
                &segment.forwarders,
                &forwarders,
                "network segment forwarder",
            )?;
        }
        for medium in &self.network_media {
            require_all(
                &medium.fault_domains,
                &fault_domains,
                "network medium fault domain",
            )?;
            require(!medium.resources.is_empty(), "network medium resources")?;
            bounded(&medium.resources, "network medium resources")?;
        }
        for forwarder in &self.network_forwarders {
            require_all(
                &forwarder.fault_domains,
                &fault_domains,
                "network forwarder fault domain",
            )?;
            require(!forwarder.ports.is_empty(), "network forwarder ports")?;
            require_all(&forwarder.ports, &interfaces, "network forwarder port")?;
            require(
                forwarder.table_capacity > 0,
                "network forwarder table capacity",
            )?;
        }
        for queue in &self.network_queues {
            require_all(
                &queue.fault_domains,
                &fault_domains,
                "network queue fault domain",
            )?;
            require(queue.capacity_packets > 0, "network queue capacity")?;
            require(
                interfaces.contains(&queue.owner)
                    || media.contains(&queue.owner)
                    || forwarders.contains(&queue.owner),
                "network queue owner",
            )?;
        }
        for path in &self.network_paths {
            require(!path.hops.is_empty(), "network path hops")?;
            bounded(&path.hops, "network path hops")?;
            for hop in &path.hops {
                match hop {
                    WorldNetworkPathHop::Segment { segment, .. } => {
                        require(segments.contains(segment), "network path segment")?;
                    }
                    WorldNetworkPathHop::Forwarder { forwarder } => {
                        require(forwarders.contains(forwarder), "network path forwarder")?;
                    }
                }
            }
        }
        for attachment in &self.network_attachments {
            require(
                interfaces.contains(&attachment.interface),
                "network attachment interface",
            )?;
            require(
                !attachment.candidates.is_empty(),
                "network attachment candidates",
            )?;
            require_all(
                &attachment.candidates,
                &segments,
                "network attachment candidate",
            )?;
            require(
                attachment.semantic_version == 1,
                "network attachment semantic version",
            )?;
        }
        for plan in &self.network_contact_plans {
            require(
                vm_nodes.contains(plan.endpoint_a.as_str()),
                "contact endpoint_a",
            )?;
            require(
                vm_nodes.contains(plan.endpoint_b.as_str()),
                "contact endpoint_b",
            )?;
            require(plan.endpoint_a != plan.endpoint_b, "contact plan self-loop")?;
            require(!plan.contacts.is_empty(), "contact plan contacts")?;
            let mut previous_end = 0;
            let mut contact_ids = BTreeSet::new();
            for contact in &plan.contacts {
                require(contact_ids.insert(&contact.id), "duplicate contact ID")?;
                require(contact.start_nanos < contact.end_nanos, "contact interval")?;
                require(contact.start_nanos >= previous_end, "contact ordering")?;
                previous_end = contact.end_nanos;
            }
        }
        for endpoint in &self.mobile_endpoints {
            require(
                vm_nodes.contains(endpoint.node.as_str()),
                "mobile endpoint node",
            )?;
        }
        for storage in &self.storage_devices {
            require_all(
                &storage.fault_domains,
                &fault_domains,
                "storage device fault domain",
            )?;
            let family = io_nodes
                .get(storage.device.as_str())
                .ok_or_else(|| invalid("storage device"))?;
            require(
                matches!(
                    (family, storage.kind),
                    (WorldDeviceKind::Block, WorldStorageKind::Block)
                        | (WorldDeviceKind::NineP, WorldStorageKind::NineP)
                ),
                "storage device kind",
            )?;
            storage.validate()?;
        }
        for capabilities in &self.node_capabilities {
            let node = world
                .vm_nodes()
                .iter()
                .find(|node| node.id.name == capabilities.node.as_str())
                .ok_or_else(|| invalid("node capability node"))?;
            require(
                capabilities.architecture.as_str() == node.arch.material(),
                "node capability architecture",
            )?;
            capabilities.validate()?;
        }

        let targets = self.all_target_refs();
        for domain in &self.fault_domains {
            require(!domain.targets.is_empty(), "fault domain targets")?;
            bounded(&domain.targets, "fault domain targets")?;
            for target in &domain.targets {
                require(targets.contains(target), "fault domain target")?;
            }
        }
        let _ = queues;
        Ok(self)
    }

    /// Returns the named fault domain, if declared.
    #[must_use]
    pub fn fault_domain(&self, id: &SignalId) -> Option<&WorldFaultDomain> {
        self.fault_domains.iter().find(|domain| &domain.id == id)
    }

    /// Returns the named network path, if declared.
    #[must_use]
    pub fn network_path(&self, id: &SignalId) -> Option<&WorldNetworkPath> {
        self.network_paths.iter().find(|path| &path.id == id)
    }

    fn all_target_refs(&self) -> BTreeSet<WorldFaultTargetRef> {
        let mut targets = BTreeSet::new();
        targets.extend(self.network_interfaces.iter().map(|item| {
            WorldFaultTargetRef::NetworkInterface {
                interface: item.id.clone(),
            }
        }));
        targets.extend(self.network_segments.iter().flat_map(|item| {
            [FaultDirection::AToB, FaultDirection::BToA].map(|direction| {
                WorldFaultTargetRef::NetworkSegment {
                    segment: item.id.clone(),
                    direction,
                }
            })
        }));
        targets.extend(
            self.network_media
                .iter()
                .map(|item| WorldFaultTargetRef::NetworkMedium {
                    medium: item.id.clone(),
                }),
        );
        targets.extend(self.network_forwarders.iter().map(|item| {
            WorldFaultTargetRef::NetworkForwarder {
                forwarder: item.id.clone(),
            }
        }));
        targets.extend(
            self.network_queues
                .iter()
                .map(|item| WorldFaultTargetRef::NetworkQueue {
                    queue: item.id.clone(),
                }),
        );
        targets.extend(
            self.network_paths
                .iter()
                .map(|item| WorldFaultTargetRef::NetworkPath {
                    path: item.id.clone(),
                }),
        );
        targets.extend(self.network_attachments.iter().map(|item| {
            WorldFaultTargetRef::NetworkAttachment {
                attachment: item.id.clone(),
            }
        }));
        targets.extend(self.network_contact_plans.iter().flat_map(|plan| {
            plan.contacts
                .iter()
                .map(|contact| WorldFaultTargetRef::NetworkContact {
                    plan: plan.id.clone(),
                    contact: contact.id.clone(),
                })
        }));
        targets.extend(self.storage_devices.iter().map(|item| match item.kind {
            WorldStorageKind::Block => WorldFaultTargetRef::BlockDevice {
                device: item.device.clone(),
            },
            WorldStorageKind::NineP => WorldFaultTargetRef::NinePDevice {
                device: item.device.clone(),
            },
        }));
        targets.extend(
            self.node_capabilities
                .iter()
                .map(|item| WorldFaultTargetRef::Node {
                    node: item.node.clone(),
                }),
        );
        targets
    }
}

/// One finite, world-owned fault-domain declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldFaultDomain {
    /// Stable domain ID.
    pub id: SignalId,
    /// Canonical finite target membership.
    pub targets: Vec<WorldFaultTargetRef>,
}
impl WorldFaultDomain {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One typed reference which may be included in a fault domain.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldFaultTargetRef {
    /// One network interface.
    NetworkInterface {
        /// Interface ID.
        interface: SignalId,
    },
    /// One direction of one network segment.
    NetworkSegment {
        /// Segment ID.
        segment: SignalId,
        /// Directed side of the segment.
        direction: FaultDirection,
    },
    /// One network medium.
    NetworkMedium {
        /// Medium ID.
        medium: SignalId,
    },
    /// One forwarding element.
    NetworkForwarder {
        /// Forwarder ID.
        forwarder: SignalId,
    },
    /// One bounded network queue.
    NetworkQueue {
        /// Queue ID.
        queue: SignalId,
    },
    /// One declared network path.
    NetworkPath {
        /// Path ID.
        path: SignalId,
    },
    /// One endpoint attachment state machine.
    NetworkAttachment {
        /// Attachment ID.
        attachment: SignalId,
    },
    /// One scheduled contact in a contact plan.
    NetworkContact {
        /// Contact-plan ID.
        plan: SignalId,
        /// Contact ID.
        contact: SignalId,
    },
    /// One deterministic block node.
    BlockDevice {
        /// Block-node ID.
        device: SignalId,
    },
    /// One deterministic 9p node.
    NinePDevice {
        /// 9p-node ID.
        device: SignalId,
    },
    /// One VM node.
    Node {
        /// VM-node ID.
        node: SignalId,
    },
}

/// Closed network-interface technology family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkTechnology {
    /// IEEE 802.3 family.
    Ethernet,
    /// IEEE 802.11 family.
    Wifi,
    /// Cellular radio family.
    Cellular,
    /// Bluetooth radio family.
    Bluetooth,
    /// LoRa radio family.
    Lora,
    /// Zigbee radio family.
    Zigbee,
    /// Thread radio family.
    Thread,
    /// Controller-area network.
    Can,
    /// Point-to-point serial transport.
    Serial,
    /// Optical transport.
    Optical,
    /// Terrestrial microwave transport.
    Microwave,
    /// Satellite transport.
    Satellite,
    /// Acoustic transport.
    Acoustic,
    /// Purely virtual interface.
    Virtual,
}

/// One world network interface.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkInterface {
    /// Stable interface ID.
    pub id: SignalId,
    /// Owning VM endpoint ID.
    pub endpoint: SignalId,
    /// Interface technology.
    pub technology: WorldNetworkTechnology,
    /// Stable address identifiers.
    pub addresses: Vec<SignalId>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkInterface {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed network-segment technology family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkSegmentKind {
    /// Ethernet link.
    Ethernet,
    /// Wi-Fi link.
    Wifi,
    /// Cellular link.
    Cellular,
    /// Bluetooth link.
    Bluetooth,
    /// Low-power mesh link.
    LowPowerMesh,
    /// Controller-area network.
    Can,
    /// Serial link.
    Serial,
    /// Optical link.
    Optical,
    /// Microwave link.
    Microwave,
    /// Satellite link.
    Satellite,
    /// Acoustic link.
    Acoustic,
    /// Encapsulated tunnel.
    Tunnel,
    /// Purely virtual link.
    Virtual,
}

/// One physical or logical bidirectional segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkSegment {
    /// Stable segment ID.
    pub id: SignalId,
    /// Segment technology.
    pub kind: WorldNetworkSegmentKind,
    /// First interface ID.
    pub interface_a: SignalId,
    /// Second interface ID.
    pub interface_b: SignalId,
    /// Strict lower latency bound.
    pub minimum_latency_nanos: u64,
    /// Optional shared medium ID.
    pub medium: Option<SignalId>,
    /// Forwarding elements traversed by this segment.
    pub forwarders: Vec<SignalId>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkSegment {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed transmission-medium family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkMediumKind {
    /// Dedicated conductive medium.
    DedicatedWire,
    /// Shared conductive medium.
    SharedWire,
    /// Fiber-optic medium.
    Fiber,
    /// Free-space RF medium.
    FreeSpaceRf,
    /// Guided RF medium.
    GuidedRf,
    /// Free-space optical medium.
    OpticalFreeSpace,
    /// Acoustic medium.
    Acoustic,
    /// Purely virtual medium.
    Virtual,
}

/// One shared or dedicated transmission medium.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkMedium {
    /// Stable medium ID.
    pub id: SignalId,
    /// Medium family.
    pub kind: WorldNetworkMediumKind,
    /// Closed resource IDs shared by users of the medium.
    pub resources: Vec<SignalId>,
    /// Registered access-policy ID.
    pub access_policy: SignalId,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkMedium {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed forwarding-element family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkForwarderKind {
    /// Layer-2 bridge.
    Bridge,
    /// Layer-2 switch.
    Switch,
    /// Layer-3 router.
    Router,
    /// Protocol gateway.
    Gateway,
    /// Network-address translator.
    Nat,
    /// Stateful or stateless firewall.
    Firewall,
    /// Physical or logical repeater.
    Repeater,
    /// Satellite relay.
    SatelliteRelay,
}

/// One deterministic forwarding element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkForwarder {
    /// Stable forwarder ID.
    pub id: SignalId,
    /// Forwarder family.
    pub kind: WorldNetworkForwarderKind,
    /// Attached interface IDs.
    pub ports: Vec<SignalId>,
    /// Maximum forwarding-table entries.
    pub table_capacity: u32,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkForwarder {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed queue discipline.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkQueueDiscipline {
    /// First-in, first-out service.
    Fifo,
    /// Strict class priority.
    StrictPriority,
    /// Weighted round-robin service.
    WeightedRoundRobin,
    /// Deficit round-robin service.
    DeficitRoundRobin,
    /// Per-flow fair queueing.
    FairQueue,
}

/// Closed queue overflow behavior.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldNetworkQueueOverflow {
    /// Drops the arriving tail packet.
    DropTail,
    /// Drops the oldest head packet.
    DropHead,
    /// Marks ECN and drops when marking is unavailable.
    MarkEcn,
}

/// One bounded network queue.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkQueue {
    /// Stable queue ID.
    pub id: SignalId,
    /// Owning interface, medium, or forwarder ID.
    pub owner: SignalId,
    /// Packet-count capacity.
    pub capacity_packets: u32,
    /// Byte-count capacity, or zero when only packets bound the queue.
    pub capacity_bytes: u64,
    /// Queue discipline.
    pub discipline: WorldNetworkQueueDiscipline,
    /// Overflow behavior.
    pub overflow: WorldNetworkQueueOverflow,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkQueue {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One hop in an authored network path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldNetworkPathHop {
    /// Traverses one directed segment.
    Segment {
        /// Segment ID.
        segment: SignalId,
        /// Traversal direction.
        direction: FaultDirection,
    },
    /// Traverses one forwarding element.
    Forwarder {
        /// Forwarder ID.
        forwarder: SignalId,
    },
}

/// One ordered network path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkPath {
    /// Stable path ID.
    pub id: SignalId,
    /// Ordered path hops.
    pub hops: Vec<WorldNetworkPathHop>,
    /// Effective path MTU.
    pub mtu_bytes: u32,
}
impl WorldNetworkPath {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One endpoint association state machine.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkAttachment {
    /// Stable attachment-machine ID.
    pub id: SignalId,
    /// Endpoint interface controlled by the machine.
    pub interface: SignalId,
    /// Candidate segment IDs.
    pub candidates: Vec<SignalId>,
    /// Exact attachment-machine semantic version.
    pub semantic_version: u16,
    /// Registered authentication policy.
    pub authentication: SignalId,
    /// Registered address-continuity policy.
    pub address_continuity: SignalId,
}
impl WorldNetworkAttachment {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One interval in a scheduled contact plan.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkContact {
    /// Stable contact ID within its plan.
    pub id: SignalId,
    /// Inclusive contact start.
    pub start_nanos: u64,
    /// Exclusive contact end.
    pub end_nanos: u64,
    /// One-way range delay.
    pub range_delay_nanos: u64,
    /// Contact service rate.
    pub rate_bps: u64,
    /// Optional beam ID.
    pub beam: Option<SignalId>,
    /// Optional gateway ID.
    pub gateway: Option<SignalId>,
}

/// One disruption-tolerant contact plan.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkContactPlan {
    /// Stable contact-plan ID.
    pub id: SignalId,
    /// First VM endpoint.
    pub endpoint_a: SignalId,
    /// Second VM endpoint.
    pub endpoint_b: SignalId,
    /// Ordered non-overlapping contact intervals.
    pub contacts: Vec<WorldNetworkContact>,
    /// Registered routing policy.
    pub routing_policy: SignalId,
    /// Registered custody policy.
    pub custody_policy: SignalId,
}
impl WorldNetworkContactPlan {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One mobile endpoint driven by an executable truth-trajectory signal.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldMobileEndpoint {
    /// Stable mobile-endpoint ID.
    pub id: SignalId,
    /// Owning VM node ID.
    pub node: SignalId,
    /// Spatial truth signal ID.
    pub truth_trajectory: SignalId,
}
impl WorldMobileEndpoint {
    const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Storage adapter family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldStorageKind {
    /// Deterministic block device.
    Block,
    /// Deterministic 9p filesystem endpoint.
    NineP,
}

/// Closed flush ordering contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldFlushSemantics {
    /// A flush is an ordered persistence barrier.
    OrderedBarrier,
    /// A flush drains a writeback cache at the barrier.
    WritebackBarrier,
    /// Durability is expressed through force-unit-access requests.
    ForceUnitAccess,
}

/// Closed discard-result contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldDiscardSemantics {
    /// Discarded bytes read back as zero.
    DeterministicZero,
    /// Discarded bytes retain their prior value.
    ReadsOldData,
    /// Discarded reads use a recorded deterministic result.
    UndefinedRecorded,
}

/// Immutable storage durability contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePersistence {
    /// Logical sector size.
    pub sector_bytes: u32,
    /// Smallest all-or-nothing write size.
    pub atomic_write_bytes: u32,
    /// Volatile write-cache capacity.
    pub volatile_cache_bytes: u64,
    /// Flush ordering contract.
    pub flush_semantics: WorldFlushSemantics,
    /// Discard readback contract.
    pub discard_semantics: WorldDiscardSemantics,
}

/// Closed storage media geometry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldStorageMedia {
    /// Flash media with erase/program geometry and finite endurance.
    Flash {
        /// Erase-block size.
        erase_block_bytes: u64,
        /// Program-page size.
        program_page_bytes: u32,
        /// Rated erase cycles per block.
        endurance_cycles: u64,
    },
    /// Magnetic media with sector/track geometry.
    Magnetic {
        /// Physical sector size.
        sector_bytes: u32,
        /// Track size.
        track_bytes: u64,
    },
    /// Volatile or persistent RAM media.
    Ram {
        /// Page size.
        page_bytes: u32,
    },
    /// Remote media accessed through a registered protocol.
    Remote {
        /// Protocol contract ID.
        protocol: SignalId,
    },
}

/// One storage node's executable durability/media declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageFaultDevice {
    /// Stable storage declaration ID.
    pub id: SignalId,
    /// Referenced block/9p world-node ID.
    pub device: SignalId,
    /// Storage adapter family.
    pub kind: WorldStorageKind,
    /// Durability contract.
    pub persistence: WorldStoragePersistence,
    /// Media geometry.
    pub media: WorldStorageMedia,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageFaultDevice {
    const fn id(&self) -> &SignalId {
        &self.id
    }
    fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.persistence.sector_bytes.is_power_of_two(),
            "storage sector geometry",
        )?;
        require(
            self.persistence.atomic_write_bytes > 0
                && self.persistence.atomic_write_bytes % self.persistence.sector_bytes == 0,
            "storage atomic write geometry",
        )?;
        match self.media {
            WorldStorageMedia::Flash {
                erase_block_bytes,
                program_page_bytes,
                endurance_cycles,
            } => require(
                erase_block_bytes > 0
                    && program_page_bytes > 0
                    && erase_block_bytes % u64::from(program_page_bytes) == 0
                    && endurance_cycles > 0,
                "flash geometry",
            ),
            WorldStorageMedia::Magnetic {
                sector_bytes,
                track_bytes,
            } => require(
                sector_bytes > 0 && track_bytes > 0 && track_bytes % u64::from(sector_bytes) == 0,
                "magnetic geometry",
            ),
            WorldStorageMedia::Ram { page_bytes } => {
                require(page_bytes.is_power_of_two(), "RAM media page geometry")
            }
            WorldStorageMedia::Remote { .. } => Ok(()),
        }
    }
}

/// One closed VM-node fault capability declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNodeFaultCapabilities {
    /// Stable capability declaration ID.
    pub id: SignalId,
    /// Referenced VM-node ID.
    pub node: SignalId,
    /// Registered architecture ABI ID.
    pub architecture: SignalId,
    /// Content address of the exact register schema.
    pub register_schema: ContentHash,
    /// Registered memory address spaces.
    pub address_spaces: Vec<SignalId>,
    /// Guest page size used by memory mutation contracts.
    pub page_bytes: u64,
    /// Registered interrupt-controller IDs.
    pub interrupt_controllers: Vec<SignalId>,
    /// Registered guest-visible clock source IDs.
    pub clock_sources: Vec<SignalId>,
    /// Registered accelerator IDs.
    pub accelerators: Vec<SignalId>,
    /// Exact capability schema semantic version.
    pub semantic_version: u16,
}
impl WorldNodeFaultCapabilities {
    const fn id(&self) -> &SignalId {
        &self.id
    }
    fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.semantic_version == 1,
            "node capability semantic version",
        )?;
        require(self.page_bytes.is_power_of_two(), "node page geometry")?;
        require(!self.address_spaces.is_empty(), "node address spaces")?;
        bounded(&self.address_spaces, "node address spaces")?;
        bounded(&self.interrupt_controllers, "node interrupt controllers")?;
        bounded(&self.clock_sources, "node clock sources")?;
        bounded(&self.accelerators, "node accelerators")
    }
}

/// Error returned while admitting a world fault registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldFaultTopologyError {
    /// A bounded collection exceeds its compiled ceiling.
    CollectionLimit {
        /// Collection name.
        field: &'static str,
        /// Authored element count.
        actual: usize,
        /// Compiled ceiling.
        hard: usize,
    },
    /// Two declarations share one ID in a registry table.
    DuplicateId(SignalId),
    /// A field is invalid or references an absent declaration.
    Invalid(&'static str),
    /// Canonical registry encoding failed.
    Codec(String),
}

impl fmt::Display for WorldFaultTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectionLimit {
                field,
                actual,
                hard,
            } => write!(
                formatter,
                "{field} contains {actual} entries; hard limit is {hard}"
            ),
            Self::DuplicateId(id) => {
                write!(formatter, "duplicate world fault declaration ID `{id}`")
            }
            Self::Invalid(field) => write!(formatter, "invalid or dangling {field}"),
            Self::Codec(reason) => write!(formatter, "world fault registry codec failed: {reason}"),
        }
    }
}
impl Error for WorldFaultTopologyError {}

fn canonicalize_by_id<T>(
    values: &mut Vec<T>,
    id: impl Fn(&T) -> &SignalId,
) -> Result<(), WorldFaultTopologyError> {
    if values.len() > HARD_WORLD_FAULT_DECLARATIONS_PER_KIND {
        return Err(WorldFaultTopologyError::CollectionLimit {
            field: "world fault declarations",
            actual: values.len(),
            hard: HARD_WORLD_FAULT_DECLARATIONS_PER_KIND,
        });
    }
    values.sort_by(|left, right| id(left).cmp(id(right)));
    if let Some(pair) = values.windows(2).find(|pair| id(&pair[0]) == id(&pair[1])) {
        return Err(WorldFaultTopologyError::DuplicateId(id(&pair[0]).clone()));
    }
    Ok(())
}
fn canonicalize_set<T: Ord>(
    values: &mut Vec<T>,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    bounded(values, field)?;
    values.sort();
    require(values.windows(2).all(|pair| pair[0] != pair[1]), field)
}
fn ids<T>(values: &[T]) -> BTreeSet<SignalId>
where
    T: HasWorldFaultId,
{
    values
        .iter()
        .map(|value| value.world_fault_id().clone())
        .collect()
}
trait HasWorldFaultId {
    fn world_fault_id(&self) -> &SignalId;
}
macro_rules! impl_id { ($($ty:ty),+ $(,)?) => { $(impl HasWorldFaultId for $ty { fn world_fault_id(&self) -> &SignalId { &self.id } })+ }; }
impl_id!(
    WorldFaultDomain,
    WorldNetworkInterface,
    WorldNetworkSegment,
    WorldNetworkMedium,
    WorldNetworkForwarder,
    WorldNetworkQueue,
    WorldNetworkPath
);
fn require(condition: bool, field: &'static str) -> Result<(), WorldFaultTopologyError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(field))
    }
}
fn invalid(field: &'static str) -> WorldFaultTopologyError {
    WorldFaultTopologyError::Invalid(field)
}
fn bounded<T>(values: &[T], field: &'static str) -> Result<(), WorldFaultTopologyError> {
    if values.len() <= HARD_WORLD_FAULT_REFERENCES_PER_DECLARATION {
        Ok(())
    } else {
        Err(WorldFaultTopologyError::CollectionLimit {
            field,
            actual: values.len(),
            hard: HARD_WORLD_FAULT_REFERENCES_PER_DECLARATION,
        })
    }
}
fn require_all(
    values: &[SignalId],
    available: &BTreeSet<SignalId>,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    bounded(values, field)?;
    require(values.iter().all(|value| available.contains(value)), field)
}
