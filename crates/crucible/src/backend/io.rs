//! Backend input and guest-originated network-output values.

use super::*;
use crate::LinkId;

/// One scheduler-validated directed route for a guest-originated frame.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendNetworkRoute {
    /// Canonical World link identity.
    pub link: LinkId,
    /// Direction through the canonical link.
    pub direction: crate::device::NetworkLinkDirection,
    /// Destination VM endpoint selected on the directed route.
    pub destination: NodeId,
}

/// Deterministic input delivered to a backend.
///
/// This payload represents backend delivery for model-controlled inputs, not a
/// host-side workload generator. Application workload traffic must originate
/// from guest execution and cross modeled devices as ordinary guest/device I/O.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendInput {
    /// The target node.
    pub node: NodeId,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

/// A guest-originated network frame awaiting scheduler-owned routing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendNetworkOutput {
    /// The VM that emitted the frame.
    pub source: NodeId,
    /// The logical router endpoint that received the guest TX frame.
    ///
    /// The scheduler resolves the Ethernet destination against the World and
    /// does not trust the backend to select a peer VM.
    pub destination: NodeId,
    /// The source VM icount at which the guest emitted the frame.
    pub emit_icount: Icount,
    /// The per-source deterministic frame sequence.
    pub sequence: u64,
    /// The opaque guest Ethernet frame bytes.
    pub payload: Vec<u8>,
    /// Scheduler-validated route selected by a pre-routing interceptor.
    ///
    /// Live backends always publish `None`. The authoritative scheduler or an
    /// in-loop interceptor may expand one multicast frame into route-locked
    /// copies before modeled link mutation. A supplied route is revalidated
    /// against the World and frame destination before use.
    pub route: Option<BackendNetworkRoute>,
}

/// Derives the stable locally administered unicast MAC for a World VM.
///
/// The mapping depends only on the canonical node identity, so launch order and
/// backend slot allocation cannot perturb guest-visible addressing.
#[must_use]
pub fn deterministic_node_mac(node: &NodeId) -> [u8; 6] {
    let hash = ContentHash::from_canonical_material(
        "crucible.world-node-mac.v1",
        &format!("node_name_len={}\nnode_name={}", node.name.len(), node.name),
    );
    let mut mac = [0_u8; 6];
    mac.copy_from_slice(&hash.bytes[..6]);
    mac[0] = (mac[0] | 0x02) & 0xfe;
    mac
}

/// Renders [`deterministic_node_mac`] in canonical QEMU option syntax.
#[must_use]
pub fn deterministic_node_mac_string(node: &NodeId) -> String {
    let mac = deterministic_node_mac(node);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
