//! Exact live-kernel Network postconditions.
//!
//! A decoded [`NetworkKernelPlanV1`](crate::NetworkKernelPlanV1) supplies the
//! expected allocation and policy. The privileged observer supplies concrete
//! namespace, link, address, route, nftables, and tc-BPF facts. Validation is
//! equality-oriented: unknown links, addresses, routes, rules, attachments, or
//! maps are mismatches rather than ignored implementation detail.
//!
//! BPF identity deliberately distinguishes a measured immutable object digest
//! from the loader binding retained in a kernel map. The digest measurement
//! proves which fixed artifact is installed; the binding is a trusted loader
//! assertion tying the attached program IDs and map IDs to that artifact. Both
//! must agree with the plan, and unavailable provenance fails closed.

use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_core::{BrokerAssignment, NetworkEndpointId, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::policy::{
    NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1, NetworkPolicyProgramV1,
    NetworkPortRangeV1, NetworkTransportProtocolV1,
};

const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.kernel-observation.v1\0";
const BPF_ARRAY: u32 = 2;
const BPF_HASH: u32 = 1;
const BPF_F_RDONLY_PROG: u32 = 1 << 7;

/// Reports a malformed, incomplete, extra, conflicting, or unstable observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkKernelObservationError {
    /// The observation has a sentinel or internally inconsistent identity.
    #[error("Network kernel observation has an invalid identity")]
    InvalidIdentity,
    /// The observed namespace, boot, or lifecycle identity differs.
    #[error("Network kernel namespace or lifecycle identity mismatched")]
    NamespaceMismatch,
    /// Link identity or the exact link inventory differs.
    #[error("Network kernel link inventory mismatched")]
    LinkMismatch,
    /// The exact address inventory differs.
    #[error("Network kernel address inventory mismatched")]
    AddressMismatch,
    /// The exact route inventory differs.
    #[error("Network kernel route inventory mismatched")]
    RouteMismatch,
    /// The exact nftables policy differs.
    #[error("Network kernel nftables policy mismatched")]
    NftablesMismatch,
    /// BPF artifact, map, binding, lease, or attachment identity differs.
    #[error("Network kernel tc-BPF lease gate mismatched")]
    BpfMismatch,
    /// Two complete consecutive snapshots did not agree.
    #[error("Network kernel observation changed during validation")]
    Changed,
}

/// Carries the planned veth labels and immutable link attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedVethV1 {
    /// Expected link MTU on both peers.
    pub mtu: u32,
    /// Deterministically derived host-side label.
    pub host_name: String,
    /// Deterministically derived sandbox-side label.
    pub sandbox_name: String,
    /// Expected host-side MAC address.
    pub host_mac: [u8; 6],
    /// Expected sandbox-side MAC address.
    pub sandbox_mac: [u8; 6],
}

/// Carries one planned host/sandbox address pair.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedAddressPairV1 {
    /// Host peer address.
    pub host: ObservedIpAddressV1,
    /// Sandbox peer address.
    pub sandbox: ObservedIpAddressV1,
    /// Point-to-point prefix length.
    pub prefix_length: u8,
}

/// Carries one planned route and its gateway.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedRouteV1 {
    /// Canonical destination prefix.
    pub destination: ObservedIpPrefixV1,
    /// Host peer used as the next hop.
    pub gateway: ObservedIpAddressV1,
}

/// Owns the complete plan-derived observation contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkKernelExpectationV1 {
    assignment: BrokerAssignment,
    network_handle: [u8; 32],
    allocation_generation: u64,
    kind: NetworkKind,
    profile_digest: ObjectDigest,
    enforcement_artifact_digest: ObjectDigest,
    lease_gate_artifact_digest: Option<ObjectDigest>,
    veth: Option<ExpectedVethV1>,
    address_pairs: Vec<ExpectedAddressPairV1>,
    routes: Vec<ExpectedRouteV1>,
    policy: NetworkPolicyProgramV1,
}

impl NetworkKernelExpectationV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        assignment: BrokerAssignment,
        network_handle: [u8; 32],
        allocation_generation: u64,
        kind: NetworkKind,
        profile_digest: ObjectDigest,
        enforcement_artifact_digest: ObjectDigest,
        lease_gate_artifact_digest: Option<ObjectDigest>,
        veth: Option<ExpectedVethV1>,
        address_pairs: Vec<ExpectedAddressPairV1>,
        routes: Vec<ExpectedRouteV1>,
        policy: NetworkPolicyProgramV1,
    ) -> Self {
        Self {
            assignment,
            network_handle,
            allocation_generation,
            kind,
            profile_digest,
            enforcement_artifact_digest,
            lease_gate_artifact_digest,
            veth,
            address_pairs,
            routes,
            policy,
        }
    }

    /// Returns the portable assignment bound to the kernel state.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the opaque reserved namespace handle.
    #[must_use]
    pub const fn network_handle(&self) -> &[u8; 32] {
        &self.network_handle
    }

    /// Returns the never-reused allocation generation.
    #[must_use]
    pub const fn allocation_generation(&self) -> u64 {
        self.allocation_generation
    }

    /// Returns the exposure kind.
    #[must_use]
    pub const fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// Returns the fixed profile commitment.
    #[must_use]
    pub const fn profile_digest(&self) -> ObjectDigest {
        self.profile_digest
    }

    /// Returns the expected immutable enforcement artifact digest.
    #[must_use]
    pub const fn enforcement_artifact_digest(&self) -> ObjectDigest {
        self.enforcement_artifact_digest
    }

    /// Returns the expected immutable lease-gate object digest.
    #[must_use]
    pub const fn lease_gate_artifact_digest(&self) -> Option<ObjectDigest> {
        self.lease_gate_artifact_digest
    }

    /// Returns the expected veth attributes, if any.
    #[must_use]
    pub const fn veth(&self) -> Option<&ExpectedVethV1> {
        self.veth.as_ref()
    }

    /// Returns the canonical address pairs.
    #[must_use]
    pub fn address_pairs(&self) -> &[ExpectedAddressPairV1] {
        &self.address_pairs
    }

    /// Returns the canonical sandbox routes.
    #[must_use]
    pub fn routes(&self) -> &[ExpectedRouteV1] {
        &self.routes
    }

    /// Returns the complete logical packet policy.
    #[must_use]
    pub const fn policy(&self) -> &NetworkPolicyProgramV1 {
        &self.policy
    }

    /// Validates two consecutive complete snapshots and returns their digest.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelObservationError`] if either snapshot is invalid,
    /// differs from the plan, carries any extra object, or the snapshots differ.
    pub fn validate_stable(
        &self,
        expected_boot_id: [u8; 16],
        expected_namespace: (u64, u64),
        expected_lifecycle: &ObservedLeaseStateV1,
        first: &NetworkKernelObservationV1,
        second: &NetworkKernelObservationV1,
    ) -> Result<ObjectDigest, NetworkKernelObservationError> {
        self.validate_one(
            expected_boot_id,
            expected_namespace,
            expected_lifecycle,
            first,
        )?;
        self.validate_one(
            expected_boot_id,
            expected_namespace,
            expected_lifecycle,
            second,
        )?;
        if first != second {
            return Err(NetworkKernelObservationError::Changed);
        }

        Ok(first.digest())
    }

    fn validate_one(
        &self,
        expected_boot_id: [u8; 16],
        expected_namespace: (u64, u64),
        expected_lifecycle: &ObservedLeaseStateV1,
        observed: &NetworkKernelObservationV1,
    ) -> Result<(), NetworkKernelObservationError> {
        if observed.boot_id == [0; 16]
            || observed.namespace_device == 0
            || observed.namespace_inode == 0
            || observed.loopback.ifindex == 0
        {
            return Err(NetworkKernelObservationError::InvalidIdentity);
        }
        if observed.boot_id != expected_boot_id
            || (observed.namespace_device, observed.namespace_inode) != expected_namespace
            || &observed.lifecycle != expected_lifecycle
            || !valid_lifecycle(self, expected_lifecycle)
        {
            return Err(NetworkKernelObservationError::NamespaceMismatch);
        }
        if !valid_loopback(&observed.loopback) {
            return Err(NetworkKernelObservationError::LinkMismatch);
        }

        match (&self.veth, &observed.host_veth, &observed.sandbox_veth) {
            (None, None, None) if observed.sandbox_link_count == 1 => {}
            (Some(expected), Some(host), Some(sandbox))
                if observed.sandbox_link_count == 2
                    && valid_veth(expected, host, sandbox, observed.loopback.ifindex) => {}
            _ => return Err(NetworkKernelObservationError::LinkMismatch),
        }

        if observed.addresses != expected_addresses(self, observed) {
            return Err(NetworkKernelObservationError::AddressMismatch);
        }
        if observed.routes != expected_routes(self, observed) {
            return Err(NetworkKernelObservationError::RouteMismatch);
        }
        if !valid_nftables(self, observed) {
            return Err(NetworkKernelObservationError::NftablesMismatch);
        }
        if !valid_gate(self, observed) {
            return Err(NetworkKernelObservationError::BpfMismatch);
        }
        Ok(())
    }
}

fn valid_lifecycle(
    expected: &NetworkKernelExpectationV1,
    lifecycle: &ObservedLeaseStateV1,
) -> bool {
    lifecycle.format_version == 2
        && valid_lease_direction(expected, &lifecycle.ingress)
        && valid_lease_direction(expected, &lifecycle.egress)
}

fn valid_lease_direction(
    expected: &NetworkKernelExpectationV1,
    direction: &ObservedLeaseDirectionV1,
) -> bool {
    let assignment_matches = direction.format_version == 2
        && direction.assignment_epoch == expected.assignment.epoch().get()
        && direction.assignment_digest == expected.assignment.digest();
    let lease_shape = if direction.armed {
        direction.lease_generation != 0
            && direction.lease_digest.as_bytes() != &[0; 32]
            && direction.deadline_boottime_nanoseconds != 0
    } else {
        direction.lease_generation == 0
            && direction.lease_digest.as_bytes() == &[0; 32]
            && direction.deadline_boottime_nanoseconds == 0
    };
    assignment_matches && lease_shape
}

/// Carries one concrete IPv4 or IPv6 address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedIpAddressV1 {
    /// IPv4 octets in network order.
    Ipv4([u8; 4]),
    /// IPv6 octets in network order.
    Ipv6([u8; 16]),
}

/// Carries one concrete canonical IP prefix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedIpPrefixV1 {
    /// Network address.
    pub address: ObservedIpAddressV1,
    /// Prefix length.
    pub prefix_length: u8,
}

/// Carries one concrete link identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLinkV1 {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Peer interface index, or zero for loopback.
    pub peer_ifindex: u32,
    /// Kernel interface name.
    pub name: String,
    /// Link kind reported by rtnetlink.
    pub kind: String,
    /// Link MTU.
    pub mtu: u32,
    /// Link-layer address.
    pub mac: [u8; 6],
    /// Whether `IFF_UP` is set.
    pub up: bool,
}

/// Carries one concrete interface address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedAddressV1 {
    /// Namespace that gives the interface index meaning.
    pub namespace: ObservedNetworkNamespaceV1,
    /// Interface index owning the address.
    pub ifindex: u32,
    /// Address value.
    pub address: ObservedIpAddressV1,
    /// Prefix length.
    pub prefix_length: u8,
}

/// Carries one concrete route.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedRouteV1 {
    /// Namespace that gives the interface index meaning.
    pub namespace: ObservedNetworkNamespaceV1,
    /// Interface index selected by the route.
    pub ifindex: u32,
    /// Destination prefix.
    pub destination: ObservedIpPrefixV1,
    /// Optional gateway.
    pub gateway: Option<ObservedIpAddressV1>,
    /// Preferred source address selected for the route.
    pub preferred_source: Option<ObservedIpAddressV1>,
    /// Kernel route table ID.
    pub table: u32,
    /// Closed route type.
    pub route_type: ObservedRouteTypeV1,
    /// Closed route scope.
    pub scope: ObservedRouteScopeV1,
    /// Closed route protocol.
    pub protocol: ObservedRouteProtocolV1,
    /// Route priority, with zero representing no explicit metric.
    pub metric: u32,
}

/// Qualifies a namespace-local interface index.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedNetworkNamespaceV1 {
    /// Initial host network namespace.
    Host,
    /// Retained sandbox network namespace.
    Sandbox,
}

/// Names the admitted kernel route type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedRouteTypeV1 {
    /// Ordinary forwarding route.
    Unicast,
}

/// Names the admitted kernel route scope.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedRouteScopeV1 {
    /// Destination is directly reachable on the link.
    Link,
    /// Destination is reachable through a gateway.
    Universe,
}

/// Names the admitted kernel route protocol.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedRouteProtocolV1 {
    /// Route synthesized by the kernel for an assigned address.
    Kernel,
    /// Route installed by the fixed enforcement artifact.
    Static,
}

/// Carries one normalized nftables endpoint-flow rule.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedFlowV1 {
    /// Logical endpoint identity encoded by the fixed compiler.
    pub endpoint_id: NetworkEndpointId,
    /// Flow direction.
    pub direction: NetworkFlowDirectionV1,
    /// Transport protocol.
    pub protocol: NetworkTransportProtocolV1,
    /// Remote address prefix.
    pub remote_prefix: NetworkIpPrefixV1,
    /// Optional transport port range.
    pub ports: Option<NetworkPortRangeV1>,
    /// Exact zero-based rule position in its base chain.
    pub position: u32,
    /// Terminal verdict emitted by the fixed compiler.
    pub verdict: ObservedNftVerdictV1,
}

/// Names one admitted nftables terminal verdict.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservedNftVerdictV1 {
    /// Drops a packet that violates a mandatory guard.
    Drop,
    /// Accepts the packet.
    Accept,
}

/// Carries one exact nftables base-chain contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedNftBaseChainV1 {
    /// Fixed chain name.
    pub name: String,
    /// Fixed netfilter hook name.
    pub hook: String,
    /// Fixed chain type.
    pub chain_type: String,
    /// Hook priority.
    pub priority: i32,
    /// Whether the base chain's policy is drop.
    pub policy_drop: bool,
}

/// Carries one exact local-address anti-spoof rule.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedNftAntiSpoofRuleV1 {
    /// Packet direction governed by the rule.
    pub direction: NetworkFlowDirectionV1,
    /// Namespace-qualified boundary interface.
    pub interface: ObservedInterfaceV1,
    /// Local source (egress) or destination (ingress) address in the guard.
    pub local_address: ObservedIpAddressV1,
    /// Whether the address predicate is inverted.
    pub inverted_match: bool,
    /// Exact zero-based rule position in its base chain.
    pub position: u32,
    /// Terminal verdict for a matching guard.
    pub verdict: ObservedNftVerdictV1,
}

/// Carries one namespace-qualified interface index.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedInterfaceV1 {
    /// Namespace owning the index.
    pub namespace: ObservedNetworkNamespaceV1,
    /// Kernel interface index.
    pub ifindex: u32,
}

/// Carries the exact normalized nftables ruleset owned by one namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedNftablesPolicyV1 {
    /// Table address family.
    pub family: String,
    /// Fixed table name.
    pub table: String,
    /// Whether all fixed base chains have default-drop policy.
    pub default_drop: bool,
    /// Measured SHA-256 of the immutable enforcement executable.
    pub installed_artifact_digest: ObjectDigest,
    /// Artifact commitment stored as nftables userdata by the fixed loader.
    pub loader_artifact_digest: ObjectDigest,
    /// Plan commitment stored as nftables userdata by the fixed loader.
    pub loader_policy_digest: ObjectDigest,
    /// Exact base-chain inventory, including hook, priority, and policy.
    pub base_chains: Vec<ObservedNftBaseChainV1>,
    /// Exact anti-spoof rule inventory.
    pub anti_spoof_rules: Vec<ObservedNftAntiSpoofRuleV1>,
    /// Exact normalized anti-spoof and endpoint flow inventory.
    pub flows: Vec<ObservedFlowV1>,
}

/// Carries one BPF map's concrete kernel identity and schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedBpfMapV1 {
    /// Kernel BPF object ID.
    pub id: u32,
    /// Kernel map type.
    pub map_type: u32,
    /// Kernel map name.
    pub name: String,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum entry count.
    pub max_entries: u32,
    /// Kernel map flags.
    pub flags: u32,
}

/// Carries one concrete tcx link and its attached program identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedBpfAttachmentV1 {
    /// Kernel BPF link ID.
    pub link_id: u32,
    /// Kernel program ID.
    pub program_id: u32,
    /// Kernel program tag over translated instructions.
    pub program_tag: [u8; 8],
    /// Namespace-qualified interface attached by the link.
    pub interface: ObservedInterfaceV1,
    /// Closed attach-type code.
    pub attach_type: u32,
    /// Map IDs referenced by this program in ascending order.
    pub map_ids: Vec<u32>,
}

/// Carries measured and loader-asserted BPF artifact provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedBpfArtifactV1 {
    /// SHA-256 measured over the fixed immutable object file.
    pub installed_object_digest: ObjectDigest,
    /// Format version of the loader provenance assertion.
    pub provenance_version: u16,
    /// Object digest asserted by the loader binding map.
    pub loader_object_digest: ObjectDigest,
    /// Ingress program ID asserted by the loader.
    pub loader_ingress_program_id: u32,
    /// Egress program ID asserted by the loader.
    pub loader_egress_program_id: u32,
}

/// Carries the immutable assignment and physical-link binding map value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedBpfBindingV1 {
    /// ABI format version.
    pub format_version: u16,
    /// Network handle.
    pub network_handle: [u8; 32],
    /// Assignment digest.
    pub assignment_digest: ObjectDigest,
    /// Assignment epoch.
    pub assignment_epoch: u64,
    /// Allocation generation.
    pub allocation_generation: u64,
    /// Kernel boot ID.
    pub boot_id: [u8; 16],
    /// Namespace device.
    pub namespace_device: u64,
    /// Namespace inode.
    pub namespace_inode: u64,
    /// Host interface index.
    pub host_ifindex: u32,
    /// Sandbox peer interface index.
    pub peer_ifindex: u32,
    /// Host MAC address.
    pub host_mac: [u8; 6],
    /// Sandbox peer MAC address.
    pub peer_mac: [u8; 6],
}

/// Carries one direction of the live ownership lease state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLeaseDirectionV1 {
    /// Raw map ABI format version.
    pub format_version: u32,
    /// Whether the direction is armed.
    pub armed: bool,
    /// Assignment epoch copied into the lease.
    pub assignment_epoch: u64,
    /// Assignment digest copied into the lease.
    pub assignment_digest: ObjectDigest,
    /// Monotonic lease generation.
    pub lease_generation: u64,
    /// Lease semantic digest.
    pub lease_digest: ObjectDigest,
    /// Absolute boottime deadline in nanoseconds.
    pub deadline_boottime_nanoseconds: u64,
}

/// Carries the exact expected lease lifecycle at observation time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLeaseStateV1 {
    /// ABI format version.
    pub format_version: u32,
    /// Ingress state.
    pub ingress: ObservedLeaseDirectionV1,
    /// Egress state.
    pub egress: ObservedLeaseDirectionV1,
}

/// Carries the complete concrete lease-gate kernel object graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLeaseGateV1 {
    /// Measured artifact and loader provenance.
    pub artifact: ObservedBpfArtifactV1,
    /// Immutable assignment/link binding.
    pub binding: ObservedBpfBindingV1,
    /// Mutable lease state.
    pub lease_state: ObservedLeaseStateV1,
    /// Binding map identity.
    pub binding_map: ObservedBpfMapV1,
    /// Lease-state map identity.
    pub lease_state_map: ObservedBpfMapV1,
    /// Exact ingress tcx attachment.
    pub ingress: ObservedBpfAttachmentV1,
    /// Exact egress tcx attachment.
    pub egress: ObservedBpfAttachmentV1,
}

/// Owns one complete normalized live-kernel snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkKernelObservationV1 {
    /// Current kernel boot ID.
    pub boot_id: [u8; 16],
    /// Namespace nsfs device.
    pub namespace_device: u64,
    /// Namespace nsfs inode.
    pub namespace_inode: u64,
    /// Exact loopback identity.
    pub loopback: ObservedLinkV1,
    /// Host-side veth identity.
    pub host_veth: Option<ObservedLinkV1>,
    /// Sandbox-side veth identity.
    pub sandbox_veth: Option<ObservedLinkV1>,
    /// Number of links returned by the unfiltered sandbox dump.
    pub sandbox_link_count: u32,
    /// Exact loopback, host-peer, and sandbox-peer address inventory.
    pub addresses: Vec<ObservedAddressV1>,
    /// Exact sandbox route inventory.
    pub routes: Vec<ObservedRouteV1>,
    /// Exact namespace nftables policy.
    pub nftables: ObservedNftablesPolicyV1,
    /// Exact tc-BPF gate, absent only for isolated networking.
    pub lease_gate: Option<ObservedLeaseGateV1>,
    /// Exact lifecycle state expected by the protected caller.
    pub lifecycle: ObservedLeaseStateV1,
}

impl NetworkKernelObservationV1 {
    /// Returns a domain-separated digest of every concrete normalized fact.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(OBSERVATION_DIGEST_DOMAIN);
        digest.update(1_u16.to_be_bytes());
        encode_observation(&mut digest, self);
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

fn valid_loopback(link: &ObservedLinkV1) -> bool {
    link.peer_ifindex == 0
        && link.name == "lo"
        && link.kind == "loopback"
        && link.mtu == 65_536
        && link.mac == [0; 6]
        && link.up
}

fn valid_veth(
    expected: &ExpectedVethV1,
    host: &ObservedLinkV1,
    sandbox: &ObservedLinkV1,
    loopback_ifindex: u32,
) -> bool {
    host.ifindex != 0
        && sandbox.ifindex != 0
        && sandbox.ifindex != loopback_ifindex
        && host.peer_ifindex == sandbox.ifindex
        && sandbox.peer_ifindex == host.ifindex
        && host.name == expected.host_name
        && sandbox.name == expected.sandbox_name
        && host.kind == "veth"
        && sandbox.kind == "veth"
        && host.mtu == expected.mtu
        && sandbox.mtu == expected.mtu
        && host.mac == expected.host_mac
        && sandbox.mac == expected.sandbox_mac
        && host.up
        && sandbox.up
}

fn expected_addresses(
    expected: &NetworkKernelExpectationV1,
    observed: &NetworkKernelObservationV1,
) -> Vec<ObservedAddressV1> {
    let mut addresses = vec![
        ObservedAddressV1 {
            namespace: ObservedNetworkNamespaceV1::Sandbox,
            ifindex: observed.loopback.ifindex,
            address: ObservedIpAddressV1::Ipv4([127, 0, 0, 1]),
            prefix_length: 8,
        },
        ObservedAddressV1 {
            namespace: ObservedNetworkNamespaceV1::Sandbox,
            ifindex: observed.loopback.ifindex,
            address: ObservedIpAddressV1::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            prefix_length: 128,
        },
    ];
    if let (Some(host), Some(sandbox)) = (&observed.host_veth, &observed.sandbox_veth) {
        for pair in &expected.address_pairs {
            addresses.push(ObservedAddressV1 {
                namespace: ObservedNetworkNamespaceV1::Host,
                ifindex: host.ifindex,
                address: pair.host,
                prefix_length: pair.prefix_length,
            });
            addresses.push(ObservedAddressV1 {
                namespace: ObservedNetworkNamespaceV1::Sandbox,
                ifindex: sandbox.ifindex,
                address: pair.sandbox,
                prefix_length: pair.prefix_length,
            });
        }
    }
    addresses.sort_unstable();
    addresses
}

fn expected_routes(
    expected: &NetworkKernelExpectationV1,
    observed: &NetworkKernelObservationV1,
) -> Vec<ObservedRouteV1> {
    let Some(sandbox) = &observed.sandbox_veth else {
        return Vec::new();
    };
    let mut routes = expected
        .address_pairs
        .iter()
        .map(|pair| ObservedRouteV1 {
            namespace: ObservedNetworkNamespaceV1::Sandbox,
            ifindex: sandbox.ifindex,
            destination: point_to_point_prefix(pair.sandbox, pair.prefix_length),
            gateway: None,
            preferred_source: Some(pair.sandbox),
            table: 254,
            route_type: ObservedRouteTypeV1::Unicast,
            scope: ObservedRouteScopeV1::Link,
            protocol: ObservedRouteProtocolV1::Kernel,
            metric: 0,
        })
        .chain(expected.routes.iter().map(|route| ObservedRouteV1 {
            namespace: ObservedNetworkNamespaceV1::Sandbox,
            ifindex: sandbox.ifindex,
            destination: route.destination,
            gateway: Some(route.gateway),
            preferred_source:
                expected.address_pairs.iter().find_map(|pair| {
                    same_family(pair.sandbox, route.gateway).then_some(pair.sandbox)
                }),
            table: 254,
            route_type: ObservedRouteTypeV1::Unicast,
            scope: ObservedRouteScopeV1::Universe,
            protocol: ObservedRouteProtocolV1::Static,
            metric: 0,
        }))
        .collect::<Vec<_>>();
    routes.sort_unstable();
    routes
}

const fn same_family(left: ObservedIpAddressV1, right: ObservedIpAddressV1) -> bool {
    matches!(
        (left, right),
        (ObservedIpAddressV1::Ipv4(_), ObservedIpAddressV1::Ipv4(_))
            | (ObservedIpAddressV1::Ipv6(_), ObservedIpAddressV1::Ipv6(_))
    )
}

fn point_to_point_prefix(address: ObservedIpAddressV1, prefix_length: u8) -> ObservedIpPrefixV1 {
    // Kernel-plan decoding admits only /31 and /127 point-to-point pairs, so
    // neither shift can equal or exceed its integer width.
    let address = match address {
        ObservedIpAddressV1::Ipv4(octets) => {
            let value = u32::from_be_bytes(octets);
            let mask = u32::MAX << (32 - u32::from(prefix_length));
            ObservedIpAddressV1::Ipv4((value & mask).to_be_bytes())
        }
        ObservedIpAddressV1::Ipv6(octets) => {
            let value = u128::from_be_bytes(octets);
            let mask = u128::MAX << (128 - u32::from(prefix_length));
            ObservedIpAddressV1::Ipv6((value & mask).to_be_bytes())
        }
    };
    ObservedIpPrefixV1 {
        address,
        prefix_length,
    }
}

fn valid_nftables(
    expected: &NetworkKernelExpectationV1,
    observation: &NetworkKernelObservationV1,
) -> bool {
    let observed = &observation.nftables;
    let expected_chains = vec![
        base_chain("ingress", "input"),
        base_chain("egress", "output"),
    ];
    let expected_anti_spoof = expected_anti_spoof_rules(expected, observation);
    let expected_flows = expected_flow_rules(expected, &expected_anti_spoof);
    observed.family == "inet"
        && observed.table == "aos_sandbox"
        && observed.default_drop
        && observed.installed_artifact_digest == expected.enforcement_artifact_digest
        && observed.loader_artifact_digest == expected.enforcement_artifact_digest
        && observed.loader_policy_digest == expected.policy.digest()
        && observed.base_chains == expected_chains
        && observed.anti_spoof_rules == expected_anti_spoof
        && observed.flows == expected_flows
}

fn base_chain(name: &str, hook: &str) -> ObservedNftBaseChainV1 {
    ObservedNftBaseChainV1 {
        name: name.to_owned(),
        hook: hook.to_owned(),
        chain_type: "filter".to_owned(),
        priority: 0,
        policy_drop: true,
    }
}

fn expected_anti_spoof_rules(
    expected: &NetworkKernelExpectationV1,
    observed: &NetworkKernelObservationV1,
) -> Vec<ObservedNftAntiSpoofRuleV1> {
    let Some(sandbox) = &observed.sandbox_veth else {
        return Vec::new();
    };
    let interface = ObservedInterfaceV1 {
        namespace: ObservedNetworkNamespaceV1::Sandbox,
        ifindex: sandbox.ifindex,
    };
    let mut rules = Vec::with_capacity(expected.address_pairs.len() * 2);
    let mut ingress_position = 0_u32;
    let mut egress_position = 0_u32;
    for pair in &expected.address_pairs {
        rules.push(ObservedNftAntiSpoofRuleV1 {
            direction: NetworkFlowDirectionV1::Ingress,
            interface,
            local_address: pair.sandbox,
            inverted_match: true,
            position: ingress_position,
            verdict: ObservedNftVerdictV1::Drop,
        });
        rules.push(ObservedNftAntiSpoofRuleV1 {
            direction: NetworkFlowDirectionV1::Egress,
            interface,
            local_address: pair.sandbox,
            inverted_match: true,
            position: egress_position,
            verdict: ObservedNftVerdictV1::Drop,
        });
        ingress_position += 1;
        egress_position += 1;
    }
    rules
}

fn expected_flow_rules(
    expected: &NetworkKernelExpectationV1,
    anti_spoof: &[ObservedNftAntiSpoofRuleV1],
) -> Vec<ObservedFlowV1> {
    let mut next_ingress = anti_spoof
        .iter()
        .filter(|rule| rule.direction == NetworkFlowDirectionV1::Ingress)
        .count() as u32;
    let mut next_egress = anti_spoof
        .iter()
        .filter(|rule| rule.direction == NetworkFlowDirectionV1::Egress)
        .count() as u32;
    let mut rules = Vec::new();
    for endpoint in expected.policy.endpoints() {
        for flow in endpoint.flows() {
            let position = match flow.direction() {
                NetworkFlowDirectionV1::Ingress => {
                    let position = next_ingress;
                    next_ingress += 1;
                    position
                }
                NetworkFlowDirectionV1::Egress => {
                    let position = next_egress;
                    next_egress += 1;
                    position
                }
            };
            rules.push(flow_observation(endpoint.endpoint_id(), *flow, position));
        }
    }
    rules
}

fn flow_observation(
    endpoint_id: NetworkEndpointId,
    flow: NetworkFlowPolicyV1,
    position: u32,
) -> ObservedFlowV1 {
    ObservedFlowV1 {
        endpoint_id,
        direction: flow.direction(),
        protocol: flow.protocol(),
        remote_prefix: flow.remote_prefix(),
        ports: flow.ports(),
        position,
        verdict: ObservedNftVerdictV1::Accept,
    }
}

fn valid_gate(
    expected: &NetworkKernelExpectationV1,
    observed: &NetworkKernelObservationV1,
) -> bool {
    let Some(expected_digest) = expected.lease_gate_artifact_digest else {
        return observed.lease_gate.is_none();
    };
    let (Some(gate), Some(host), Some(sandbox)) = (
        &observed.lease_gate,
        &observed.host_veth,
        &observed.sandbox_veth,
    ) else {
        return false;
    };
    let binding = &gate.binding;
    let mut map_ids = vec![gate.binding_map.id, gate.lease_state_map.id];
    map_ids.sort_unstable();
    valid_map(&gate.binding_map, BPF_ARRAY, "binding")
        && valid_map(&gate.lease_state_map, BPF_HASH, "lease_state")
        && gate.binding_map.id != gate.lease_state_map.id
        && gate.artifact.installed_object_digest == expected_digest
        && gate.artifact.provenance_version == 1
        && gate.artifact.loader_object_digest == expected_digest
        && gate.artifact.loader_ingress_program_id == gate.ingress.program_id
        && gate.artifact.loader_egress_program_id == gate.egress.program_id
        && binding.format_version == 2
        && binding.network_handle == expected.network_handle
        && binding.assignment_digest == expected.assignment.digest()
        && binding.assignment_epoch == expected.assignment.epoch().get()
        && binding.allocation_generation == expected.allocation_generation
        && binding.boot_id == observed.boot_id
        && binding.namespace_device == observed.namespace_device
        && binding.namespace_inode == observed.namespace_inode
        && binding.host_ifindex == host.ifindex
        && binding.peer_ifindex == sandbox.ifindex
        && binding.host_mac == host.mac
        && binding.peer_mac == sandbox.mac
        && gate.lease_state == observed.lifecycle
        && valid_attachment(&gate.ingress, host.ifindex, 46, &map_ids)
        && valid_attachment(&gate.egress, host.ifindex, 47, &map_ids)
        && gate.ingress.link_id != gate.egress.link_id
        && gate.ingress.program_id != gate.egress.program_id
        && gate.ingress.program_tag != [0; 8]
        && gate.egress.program_tag != [0; 8]
}

fn valid_map(map: &ObservedBpfMapV1, map_type: u32, name: &str) -> bool {
    let expected_value_size = match name {
        "binding" => 192,
        "lease_state" => 200,
        _ => return false,
    };
    map.id != 0
        && map.map_type == map_type
        && map.name == name
        && map.key_size == 4
        && map.value_size == expected_value_size
        && map.max_entries == 1
        && map.flags == BPF_F_RDONLY_PROG
}

fn valid_attachment(
    attachment: &ObservedBpfAttachmentV1,
    ifindex: u32,
    attach_type: u32,
    map_ids: &[u32],
) -> bool {
    attachment.link_id != 0
        && attachment.program_id != 0
        && attachment.interface
            == (ObservedInterfaceV1 {
                namespace: ObservedNetworkNamespaceV1::Host,
                ifindex,
            })
        && attachment.attach_type == attach_type
        && attachment.map_ids == map_ids
}

fn encode_observation(digest: &mut Sha256, observation: &NetworkKernelObservationV1) {
    digest.update(observation.boot_id);
    encode_u64(digest, observation.namespace_device);
    encode_u64(digest, observation.namespace_inode);
    encode_link(digest, &observation.loopback);
    encode_optional_link(digest, observation.host_veth.as_ref());
    encode_optional_link(digest, observation.sandbox_veth.as_ref());
    encode_u32(digest, observation.sandbox_link_count);

    encode_length(digest, observation.addresses.len());
    for address in &observation.addresses {
        encode_namespace(digest, address.namespace);
        encode_u32(digest, address.ifindex);
        encode_address(digest, address.address);
        digest.update([address.prefix_length]);
    }

    encode_length(digest, observation.routes.len());
    for route in &observation.routes {
        encode_namespace(digest, route.namespace);
        encode_u32(digest, route.ifindex);
        encode_prefix(digest, route.destination);
        encode_optional_address(digest, route.gateway);
        encode_optional_address(digest, route.preferred_source);
        encode_u32(digest, route.table);
        digest.update([route_type_code(route.route_type)]);
        digest.update([route_scope_code(route.scope)]);
        digest.update([route_protocol_code(route.protocol)]);
        encode_u32(digest, route.metric);
    }

    encode_nftables(digest, &observation.nftables);
    match &observation.lease_gate {
        Some(gate) => {
            digest.update([1]);
            encode_gate(digest, gate);
        }
        None => digest.update([0]),
    }
    encode_lease_state(digest, &observation.lifecycle);
}

fn encode_nftables(digest: &mut Sha256, policy: &ObservedNftablesPolicyV1) {
    encode_text(digest, &policy.family);
    encode_text(digest, &policy.table);
    encode_bool(digest, policy.default_drop);
    encode_object_digest(digest, policy.installed_artifact_digest);
    encode_object_digest(digest, policy.loader_artifact_digest);
    encode_object_digest(digest, policy.loader_policy_digest);

    encode_length(digest, policy.base_chains.len());
    for chain in &policy.base_chains {
        encode_text(digest, &chain.name);
        encode_text(digest, &chain.hook);
        encode_text(digest, &chain.chain_type);
        digest.update(chain.priority.to_be_bytes());
        encode_bool(digest, chain.policy_drop);
    }

    encode_length(digest, policy.anti_spoof_rules.len());
    for rule in &policy.anti_spoof_rules {
        digest.update([direction_code(rule.direction)]);
        encode_interface(digest, rule.interface);
        encode_address(digest, rule.local_address);
        encode_bool(digest, rule.inverted_match);
        encode_u32(digest, rule.position);
        digest.update([verdict_code(rule.verdict)]);
    }

    encode_length(digest, policy.flows.len());
    for flow in &policy.flows {
        digest.update(flow.endpoint_id.as_bytes());
        digest.update([direction_code(flow.direction)]);
        digest.update([protocol_code(flow.protocol)]);
        encode_policy_prefix(digest, flow.remote_prefix);
        match flow.ports {
            Some(ports) => {
                digest.update([1]);
                digest.update(ports.first().to_be_bytes());
                digest.update(ports.last().to_be_bytes());
            }
            None => digest.update([0]),
        }
        encode_u32(digest, flow.position);
        digest.update([verdict_code(flow.verdict)]);
    }
}

fn encode_gate(digest: &mut Sha256, gate: &ObservedLeaseGateV1) {
    encode_object_digest(digest, gate.artifact.installed_object_digest);
    digest.update(gate.artifact.provenance_version.to_be_bytes());
    encode_object_digest(digest, gate.artifact.loader_object_digest);
    encode_u32(digest, gate.artifact.loader_ingress_program_id);
    encode_u32(digest, gate.artifact.loader_egress_program_id);

    digest.update(gate.binding.format_version.to_be_bytes());
    digest.update(gate.binding.network_handle);
    encode_object_digest(digest, gate.binding.assignment_digest);
    encode_u64(digest, gate.binding.assignment_epoch);
    encode_u64(digest, gate.binding.allocation_generation);
    digest.update(gate.binding.boot_id);
    encode_u64(digest, gate.binding.namespace_device);
    encode_u64(digest, gate.binding.namespace_inode);
    encode_u32(digest, gate.binding.host_ifindex);
    encode_u32(digest, gate.binding.peer_ifindex);
    digest.update(gate.binding.host_mac);
    digest.update(gate.binding.peer_mac);

    encode_lease_state(digest, &gate.lease_state);
    encode_bpf_map(digest, &gate.binding_map);
    encode_bpf_map(digest, &gate.lease_state_map);
    encode_bpf_attachment(digest, &gate.ingress);
    encode_bpf_attachment(digest, &gate.egress);
}

fn encode_lease_state(digest: &mut Sha256, state: &ObservedLeaseStateV1) {
    digest.update(state.format_version.to_be_bytes());
    encode_lease_direction(digest, &state.ingress);
    encode_lease_direction(digest, &state.egress);
}

fn encode_lease_direction(digest: &mut Sha256, direction: &ObservedLeaseDirectionV1) {
    encode_u32(digest, direction.format_version);
    encode_bool(digest, direction.armed);
    encode_u64(digest, direction.assignment_epoch);
    encode_object_digest(digest, direction.assignment_digest);
    encode_u64(digest, direction.lease_generation);
    encode_object_digest(digest, direction.lease_digest);
    encode_u64(digest, direction.deadline_boottime_nanoseconds);
}

fn encode_bpf_map(digest: &mut Sha256, map: &ObservedBpfMapV1) {
    encode_u32(digest, map.id);
    encode_u32(digest, map.map_type);
    encode_text(digest, &map.name);
    encode_u32(digest, map.key_size);
    encode_u32(digest, map.value_size);
    encode_u32(digest, map.max_entries);
    encode_u32(digest, map.flags);
}

fn encode_bpf_attachment(digest: &mut Sha256, attachment: &ObservedBpfAttachmentV1) {
    encode_u32(digest, attachment.link_id);
    encode_u32(digest, attachment.program_id);
    digest.update(attachment.program_tag);
    encode_interface(digest, attachment.interface);
    encode_u32(digest, attachment.attach_type);
    encode_length(digest, attachment.map_ids.len());
    for map_id in &attachment.map_ids {
        encode_u32(digest, *map_id);
    }
}

fn encode_link(digest: &mut Sha256, link: &ObservedLinkV1) {
    encode_u32(digest, link.ifindex);
    encode_u32(digest, link.peer_ifindex);
    encode_text(digest, &link.name);
    encode_text(digest, &link.kind);
    encode_u32(digest, link.mtu);
    digest.update(link.mac);
    encode_bool(digest, link.up);
}

fn encode_optional_link(digest: &mut Sha256, link: Option<&ObservedLinkV1>) {
    match link {
        Some(link) => {
            digest.update([1]);
            encode_link(digest, link);
        }
        None => digest.update([0]),
    }
}

fn encode_interface(digest: &mut Sha256, interface: ObservedInterfaceV1) {
    encode_namespace(digest, interface.namespace);
    encode_u32(digest, interface.ifindex);
}

fn encode_namespace(digest: &mut Sha256, namespace: ObservedNetworkNamespaceV1) {
    digest.update([match namespace {
        ObservedNetworkNamespaceV1::Host => 1,
        ObservedNetworkNamespaceV1::Sandbox => 2,
    }]);
}

fn encode_optional_address(digest: &mut Sha256, address: Option<ObservedIpAddressV1>) {
    match address {
        Some(address) => {
            digest.update([1]);
            encode_address(digest, address);
        }
        None => digest.update([0]),
    }
}

fn encode_address(digest: &mut Sha256, address: ObservedIpAddressV1) {
    match address {
        ObservedIpAddressV1::Ipv4(octets) => {
            digest.update([4]);
            digest.update(octets);
        }
        ObservedIpAddressV1::Ipv6(octets) => {
            digest.update([6]);
            digest.update(octets);
        }
    }
}

fn encode_prefix(digest: &mut Sha256, prefix: ObservedIpPrefixV1) {
    encode_address(digest, prefix.address);
    digest.update([prefix.prefix_length]);
}

fn encode_policy_prefix(digest: &mut Sha256, prefix: NetworkIpPrefixV1) {
    match prefix {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            digest.update([4, prefix_length]);
            digest.update(network);
        }
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            digest.update([6, prefix_length]);
            digest.update(network);
        }
    }
}

fn encode_object_digest(digest: &mut Sha256, value: ObjectDigest) {
    digest.update(value.as_bytes());
}

fn encode_text(digest: &mut Sha256, text: &str) {
    encode_length(digest, text.len());
    digest.update(text.as_bytes());
}

fn encode_length(digest: &mut Sha256, length: usize) {
    digest.update(length.to_be_bytes());
}

fn encode_u32(digest: &mut Sha256, value: u32) {
    digest.update(value.to_be_bytes());
}

fn encode_u64(digest: &mut Sha256, value: u64) {
    digest.update(value.to_be_bytes());
}

fn encode_bool(digest: &mut Sha256, value: bool) {
    digest.update([u8::from(value)]);
}

const fn direction_code(direction: NetworkFlowDirectionV1) -> u8 {
    match direction {
        NetworkFlowDirectionV1::Ingress => 1,
        NetworkFlowDirectionV1::Egress => 2,
    }
}

const fn protocol_code(protocol: NetworkTransportProtocolV1) -> u8 {
    match protocol {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    }
}

const fn verdict_code(verdict: ObservedNftVerdictV1) -> u8 {
    match verdict {
        ObservedNftVerdictV1::Drop => 1,
        ObservedNftVerdictV1::Accept => 2,
    }
}

const fn route_type_code(route_type: ObservedRouteTypeV1) -> u8 {
    match route_type {
        ObservedRouteTypeV1::Unicast => 1,
    }
}

const fn route_scope_code(scope: ObservedRouteScopeV1) -> u8 {
    match scope {
        ObservedRouteScopeV1::Link => 1,
        ObservedRouteScopeV1::Universe => 2,
    }
}

const fn route_protocol_code(protocol: ObservedRouteProtocolV1) -> u8 {
    match protocol {
        ObservedRouteProtocolV1::Kernel => 1,
        ObservedRouteProtocolV1::Static => 2,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};

    use super::*;
    use crate::policy::{NetworkEndpointPolicyV1, NetworkPolicyProgramV1};

    const BOOT_ID: [u8; 16] = [0x91; 16];
    const NAMESPACE: (u64, u64) = (71, 81);
    const HOST_IFINDEX: u32 = 7;
    const SANDBOX_IFINDEX: u32 = 7;

    fn object(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn assignment() -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([0x11; 16]),
            IncarnationId::from_bytes([0x22; 16]),
            AssignmentEpoch::new(41),
            DesiredGeneration::new(7),
            object(0x33),
        )
        .unwrap()
    }

    fn policy() -> NetworkPolicyProgramV1 {
        let flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Ingress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([198, 51, 100, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let endpoint =
            NetworkEndpointPolicyV1::new(NetworkEndpointId::from_bytes([0x44; 16]), vec![flow])
                .unwrap();
        NetworkPolicyProgramV1::new(
            NetworkKind::Published,
            object(0x55),
            Some(object(0x66)),
            vec![endpoint],
        )
        .unwrap()
    }

    fn expectation() -> NetworkKernelExpectationV1 {
        NetworkKernelExpectationV1::new(
            assignment(),
            [0x77; 32],
            1,
            NetworkKind::Published,
            object(0x88),
            object(0x55),
            Some(object(0x66)),
            Some(ExpectedVethV1 {
                mtu: 1_500,
                host_name: "aoh000000000001".to_owned(),
                sandbox_name: "aog000000000001".to_owned(),
                host_mac: [0x02, 0xaa, 0xbb, 0, 0, 2],
                sandbox_mac: [0x02, 0xaa, 0xbb, 0, 0, 3],
            }),
            vec![ExpectedAddressPairV1 {
                host: ObservedIpAddressV1::Ipv4([192, 0, 0, 0]),
                sandbox: ObservedIpAddressV1::Ipv4([192, 0, 0, 1]),
                prefix_length: 31,
            }],
            vec![ExpectedRouteV1 {
                destination: ObservedIpPrefixV1 {
                    address: ObservedIpAddressV1::Ipv4([203, 0, 113, 0]),
                    prefix_length: 24,
                },
                gateway: ObservedIpAddressV1::Ipv4([192, 0, 0, 0]),
            }],
            policy(),
        )
    }

    fn lifecycle() -> ObservedLeaseStateV1 {
        let direction = ObservedLeaseDirectionV1 {
            format_version: 2,
            armed: false,
            assignment_epoch: 41,
            assignment_digest: object(0x33),
            lease_generation: 0,
            lease_digest: ObjectDigest::from_bytes([0; 32]),
            deadline_boottime_nanoseconds: 0,
        };
        ObservedLeaseStateV1 {
            format_version: 2,
            ingress: direction.clone(),
            egress: direction,
        }
    }

    fn link(ifindex: u32, peer_ifindex: u32, name: &str, mac: [u8; 6]) -> ObservedLinkV1 {
        ObservedLinkV1 {
            ifindex,
            peer_ifindex,
            name: name.to_owned(),
            kind: "veth".to_owned(),
            mtu: 1_500,
            mac,
            up: true,
        }
    }

    fn observation() -> NetworkKernelObservationV1 {
        let loopback = ObservedLinkV1 {
            ifindex: 1,
            peer_ifindex: 0,
            name: "lo".to_owned(),
            kind: "loopback".to_owned(),
            mtu: 65_536,
            mac: [0; 6],
            up: true,
        };
        let host = link(
            HOST_IFINDEX,
            SANDBOX_IFINDEX,
            "aoh000000000001",
            [0x02, 0xaa, 0xbb, 0, 0, 2],
        );
        let sandbox = link(
            SANDBOX_IFINDEX,
            HOST_IFINDEX,
            "aog000000000001",
            [0x02, 0xaa, 0xbb, 0, 0, 3],
        );
        let mut addresses = vec![
            ObservedAddressV1 {
                namespace: ObservedNetworkNamespaceV1::Sandbox,
                ifindex: 1,
                address: ObservedIpAddressV1::Ipv4([127, 0, 0, 1]),
                prefix_length: 8,
            },
            ObservedAddressV1 {
                namespace: ObservedNetworkNamespaceV1::Sandbox,
                ifindex: 1,
                address: ObservedIpAddressV1::Ipv6([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
                prefix_length: 128,
            },
            ObservedAddressV1 {
                namespace: ObservedNetworkNamespaceV1::Host,
                ifindex: HOST_IFINDEX,
                address: ObservedIpAddressV1::Ipv4([192, 0, 0, 0]),
                prefix_length: 31,
            },
            ObservedAddressV1 {
                namespace: ObservedNetworkNamespaceV1::Sandbox,
                ifindex: SANDBOX_IFINDEX,
                address: ObservedIpAddressV1::Ipv4([192, 0, 0, 1]),
                prefix_length: 31,
            },
        ];
        addresses.sort_unstable();
        let mut routes = vec![
            ObservedRouteV1 {
                namespace: ObservedNetworkNamespaceV1::Sandbox,
                ifindex: SANDBOX_IFINDEX,
                destination: ObservedIpPrefixV1 {
                    address: ObservedIpAddressV1::Ipv4([192, 0, 0, 0]),
                    prefix_length: 31,
                },
                gateway: None,
                preferred_source: Some(ObservedIpAddressV1::Ipv4([192, 0, 0, 1])),
                table: 254,
                route_type: ObservedRouteTypeV1::Unicast,
                scope: ObservedRouteScopeV1::Link,
                protocol: ObservedRouteProtocolV1::Kernel,
                metric: 0,
            },
            ObservedRouteV1 {
                namespace: ObservedNetworkNamespaceV1::Sandbox,
                ifindex: SANDBOX_IFINDEX,
                destination: ObservedIpPrefixV1 {
                    address: ObservedIpAddressV1::Ipv4([203, 0, 113, 0]),
                    prefix_length: 24,
                },
                gateway: Some(ObservedIpAddressV1::Ipv4([192, 0, 0, 0])),
                preferred_source: Some(ObservedIpAddressV1::Ipv4([192, 0, 0, 1])),
                table: 254,
                route_type: ObservedRouteTypeV1::Unicast,
                scope: ObservedRouteScopeV1::Universe,
                protocol: ObservedRouteProtocolV1::Static,
                metric: 0,
            },
        ];
        routes.sort_unstable();

        let policy = policy();
        let interface = ObservedInterfaceV1 {
            namespace: ObservedNetworkNamespaceV1::Host,
            ifindex: HOST_IFINDEX,
        };
        let lifecycle = lifecycle();
        NetworkKernelObservationV1 {
            boot_id: BOOT_ID,
            namespace_device: NAMESPACE.0,
            namespace_inode: NAMESPACE.1,
            loopback,
            host_veth: Some(host.clone()),
            sandbox_veth: Some(sandbox.clone()),
            sandbox_link_count: 2,
            addresses,
            routes,
            nftables: ObservedNftablesPolicyV1 {
                family: "inet".to_owned(),
                table: "aos_sandbox".to_owned(),
                default_drop: true,
                installed_artifact_digest: object(0x55),
                loader_artifact_digest: object(0x55),
                loader_policy_digest: policy.digest(),
                base_chains: vec![
                    base_chain("ingress", "input"),
                    base_chain("egress", "output"),
                ],
                anti_spoof_rules: vec![
                    ObservedNftAntiSpoofRuleV1 {
                        direction: NetworkFlowDirectionV1::Ingress,
                        interface: ObservedInterfaceV1 {
                            namespace: ObservedNetworkNamespaceV1::Sandbox,
                            ifindex: SANDBOX_IFINDEX,
                        },
                        local_address: ObservedIpAddressV1::Ipv4([192, 0, 0, 1]),
                        inverted_match: true,
                        position: 0,
                        verdict: ObservedNftVerdictV1::Drop,
                    },
                    ObservedNftAntiSpoofRuleV1 {
                        direction: NetworkFlowDirectionV1::Egress,
                        interface: ObservedInterfaceV1 {
                            namespace: ObservedNetworkNamespaceV1::Sandbox,
                            ifindex: SANDBOX_IFINDEX,
                        },
                        local_address: ObservedIpAddressV1::Ipv4([192, 0, 0, 1]),
                        inverted_match: true,
                        position: 0,
                        verdict: ObservedNftVerdictV1::Drop,
                    },
                ],
                flows: vec![flow_observation(
                    NetworkEndpointId::from_bytes([0x44; 16]),
                    policy.endpoints()[0].flows()[0],
                    1,
                )],
            },
            lease_gate: Some(ObservedLeaseGateV1 {
                artifact: ObservedBpfArtifactV1 {
                    installed_object_digest: object(0x66),
                    provenance_version: 1,
                    loader_object_digest: object(0x66),
                    loader_ingress_program_id: 21,
                    loader_egress_program_id: 22,
                },
                binding: ObservedBpfBindingV1 {
                    format_version: 2,
                    network_handle: [0x77; 32],
                    assignment_digest: object(0x33),
                    assignment_epoch: 41,
                    allocation_generation: 1,
                    boot_id: BOOT_ID,
                    namespace_device: NAMESPACE.0,
                    namespace_inode: NAMESPACE.1,
                    host_ifindex: HOST_IFINDEX,
                    peer_ifindex: SANDBOX_IFINDEX,
                    host_mac: host.mac,
                    peer_mac: sandbox.mac,
                },
                lease_state: lifecycle.clone(),
                binding_map: ObservedBpfMapV1 {
                    id: 11,
                    map_type: BPF_ARRAY,
                    name: "binding".to_owned(),
                    key_size: 4,
                    value_size: 192,
                    max_entries: 1,
                    flags: BPF_F_RDONLY_PROG,
                },
                lease_state_map: ObservedBpfMapV1 {
                    id: 12,
                    map_type: BPF_HASH,
                    name: "lease_state".to_owned(),
                    key_size: 4,
                    value_size: 200,
                    max_entries: 1,
                    flags: BPF_F_RDONLY_PROG,
                },
                ingress: ObservedBpfAttachmentV1 {
                    link_id: 31,
                    program_id: 21,
                    program_tag: [0xa1; 8],
                    interface,
                    attach_type: 46,
                    map_ids: vec![11, 12],
                },
                egress: ObservedBpfAttachmentV1 {
                    link_id: 32,
                    program_id: 22,
                    program_tag: [0xa2; 8],
                    interface,
                    attach_type: 47,
                    map_ids: vec![11, 12],
                },
            }),
            lifecycle,
        }
    }

    #[test]
    fn exact_stable_snapshot_matches_with_namespace_local_equal_ifindexes() {
        let expected = expectation();
        let observed = observation();

        let digest = expected
            .validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &observed, &observed)
            .unwrap();

        assert_ne!(digest.as_bytes(), &[0; 32]);
        assert_eq!(digest, observed.digest());
    }

    #[test]
    fn extra_or_partial_kernel_inventory_fails_closed() {
        let expected = expectation();
        let baseline = observation();
        let mut extra_link = baseline.clone();
        extra_link.sandbox_link_count += 1;
        let mut extra_route = baseline.clone();
        extra_route.routes.push(extra_route.routes[0]);
        let mut extra_chain = baseline.clone();
        extra_chain
            .nftables
            .base_chains
            .push(base_chain("unexpected", "forward"));

        assert_eq!(
            expected.validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &extra_link, &extra_link),
            Err(NetworkKernelObservationError::LinkMismatch)
        );
        assert_eq!(
            expected.validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &extra_route, &extra_route),
            Err(NetworkKernelObservationError::RouteMismatch)
        );
        assert_eq!(
            expected.validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &extra_chain, &extra_chain),
            Err(NetworkKernelObservationError::NftablesMismatch)
        );
    }

    #[test]
    fn anti_spoof_guard_must_be_inverted_drop_before_accept() {
        let expected = expectation();
        let mut observed = observation();
        observed.nftables.anti_spoof_rules[1].inverted_match = false;

        assert_eq!(
            expected.validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &observed, &observed),
            Err(NetworkKernelObservationError::NftablesMismatch)
        );
    }

    #[test]
    fn bpf_measurement_provenance_map_schema_and_order_are_mandatory() {
        let expected = expectation();
        let baseline = observation();
        let mut wrong_measurement = baseline.clone();
        wrong_measurement
            .lease_gate
            .as_mut()
            .unwrap()
            .artifact
            .installed_object_digest = object(0x67);
        let mut wrong_map_size = baseline.clone();
        wrong_map_size
            .lease_gate
            .as_mut()
            .unwrap()
            .binding_map
            .value_size = 193;
        let mut wrong_map_order = baseline.clone();
        wrong_map_order
            .lease_gate
            .as_mut()
            .unwrap()
            .ingress
            .map_ids
            .reverse();

        for observed in [wrong_measurement, wrong_map_size, wrong_map_order] {
            assert_eq!(
                expected.validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &observed, &observed),
                Err(NetworkKernelObservationError::BpfMismatch)
            );
        }
    }

    #[test]
    fn two_individually_valid_but_different_snapshots_are_rejected() {
        let expected = expectation();
        let first = observation();
        let mut second = first.clone();
        second.lease_gate.as_mut().unwrap().ingress.program_tag = [0xb1; 8];

        assert_eq!(
            expected.validate_stable(BOOT_ID, NAMESPACE, &lifecycle(), &first, &second),
            Err(NetworkKernelObservationError::Changed)
        );
    }
}
