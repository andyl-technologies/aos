//! Fault-addressable network and mobility declaration schemas.

use super::*;
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
    pub(super) const fn id(&self) -> &SignalId {
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
        /// Channel or resource ID.
        resource: SignalId,
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
        /// Direction through the path.
        direction: FaultDirection,
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
    /// One namespace or path on a storage controller.
    StorageController {
        /// Controller ID.
        controller: SignalId,
        /// Namespace or path ID.
        namespace_or_path: SignalId,
    },
    /// One member or path of a storage array.
    StorageArray {
        /// Array ID.
        array: SignalId,
        /// Member or path ID.
        member_or_path: SignalId,
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
    pub(super) const fn id(&self) -> &SignalId {
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
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub minimum_latency_nanos: u64,
    /// Positive maximum frame size before a dynamic MTU effect applies.
    pub mtu_bytes: u32,
    /// Optional shared medium ID.
    pub medium: Option<SignalId>,
    /// Forwarding elements traversed by this segment.
    pub forwarders: Vec<SignalId>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkSegment {
    pub(super) const fn id(&self) -> &SignalId {
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
    pub(super) const fn id(&self) -> &SignalId {
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
    pub(super) const fn id(&self) -> &SignalId {
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
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub capacity_bytes: u64,
    /// Queue discipline.
    pub discipline: WorldNetworkQueueDiscipline,
    /// Overflow behavior.
    pub overflow: WorldNetworkQueueOverflow,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldNetworkQueue {
    pub(super) const fn id(&self) -> &SignalId {
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
    /// Traverses one explicitly declared service queue.
    Queue {
        /// Queue ID.
        queue: SignalId,
    },
}

/// One ordered network path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldNetworkPath {
    /// Stable path ID.
    pub id: SignalId,
    /// Direction of the complete authored endpoint-to-endpoint path.
    pub direction: FaultDirection,
    /// Ordered path hops.
    pub hops: Vec<WorldNetworkPathHop>,
    /// Effective path MTU.
    pub mtu_bytes: u32,
}
impl WorldNetworkPath {
    pub(super) const fn id(&self) -> &SignalId {
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
    /// Closed technology contract shared by control-operation effects.
    pub technology: SignalId,
    /// Exact attachment-machine semantic version.
    pub semantic_version: u16,
    /// Registered authentication policy.
    pub authentication: SignalId,
    /// Registered address-continuity policy.
    pub address_continuity: SignalId,
}
impl WorldNetworkAttachment {
    pub(super) const fn id(&self) -> &SignalId {
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
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub start_nanos: u64,
    /// Exclusive contact end.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub end_nanos: u64,
    /// One-way range delay.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub range_delay_nanos: u64,
    /// Contact service rate.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
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
    pub(super) const fn id(&self) -> &SignalId {
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
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}
