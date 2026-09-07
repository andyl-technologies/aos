//! Closed node-local Network policy programs.
//!
//! Portable sandbox specifications name only a network exposure kind and
//! logical endpoint IDs. This module resolves those portable names into the
//! bounded packet policy that a privileged helper may enact. The resulting
//! digest commits the fixed enforcement artifacts and every typed flow; no
//! interface name, command, nftables text, or arbitrary BPF program enters the
//! contract.

use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_core::{NetworkEndpointId, ObjectDigest};
use sha2::{Digest as _, Sha256};

const PROGRAM_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.policy-program.v1\0";
const ENDPOINT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.endpoint-policy.v1\0";
const MAXIMUM_ENDPOINTS: usize = 256;
const MAXIMUM_FLOWS_PER_ENDPOINT: usize = 64;

/// Reports a malformed or internally inconsistent local Network policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("node-local Network policy program is invalid")]
pub struct NetworkPolicyProgramError;

/// Names the packet direction at the sandbox boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkFlowDirectionV1 {
    /// Admits packets entering the sandbox-facing veth.
    Ingress,
    /// Admits packets leaving the sandbox-facing veth.
    Egress,
}

/// Names one closed layer-4 packet class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkTransportProtocolV1 {
    /// Matches TCP packets and requires a port range.
    Tcp,
    /// Matches UDP packets and requires a port range.
    Udp,
    /// Matches IPv4 ICMP packets and carries no port range.
    IcmpV4,
    /// Matches IPv6 ICMP packets and carries no port range.
    IcmpV6,
}

/// Carries one canonical IP network prefix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkIpPrefixV1 {
    /// Carries an IPv4 network address and prefix length.
    Ipv4 {
        /// Network address with every host bit cleared.
        network: [u8; 4],
        /// CIDR prefix length in the inclusive range 0 through 32.
        prefix_length: u8,
    },
    /// Carries an IPv6 network address and prefix length.
    Ipv6 {
        /// Network address with every host bit cleared.
        network: [u8; 16],
        /// CIDR prefix length in the inclusive range 0 through 128.
        prefix_length: u8,
    },
}

impl NetworkIpPrefixV1 {
    /// Constructs one canonical IPv4 prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPolicyProgramError`] when `prefix_length` exceeds 32
    /// or a host bit in `network` is set.
    pub fn ipv4(network: [u8; 4], prefix_length: u8) -> Result<Self, NetworkPolicyProgramError> {
        if prefix_length > 32 || !canonical_ipv4_network(network, prefix_length) {
            return Err(NetworkPolicyProgramError);
        }

        Ok(Self::Ipv4 {
            network,
            prefix_length,
        })
    }

    /// Constructs one canonical IPv6 prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPolicyProgramError`] when `prefix_length` exceeds 128
    /// or a host bit in `network` is set.
    pub fn ipv6(network: [u8; 16], prefix_length: u8) -> Result<Self, NetworkPolicyProgramError> {
        if prefix_length > 128 || !canonical_ipv6_network(network, prefix_length) {
            return Err(NetworkPolicyProgramError);
        }

        Ok(Self::Ipv6 {
            network,
            prefix_length,
        })
    }
}

/// Carries one inclusive nonzero destination-port range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkPortRangeV1 {
    first: u16,
    last: u16,
}

impl NetworkPortRangeV1 {
    /// Constructs an inclusive canonical port range.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPolicyProgramError`] for port zero or a reversed
    /// range.
    pub fn new(first: u16, last: u16) -> Result<Self, NetworkPolicyProgramError> {
        if first == 0 || first > last {
            return Err(NetworkPolicyProgramError);
        }

        Ok(Self { first, last })
    }

    /// Returns the first admitted destination port.
    #[must_use]
    pub const fn first(self) -> u16 {
        self.first
    }

    /// Returns the last admitted destination port.
    #[must_use]
    pub const fn last(self) -> u16 {
        self.last
    }
}

/// Describes one exact admitted packet flow under an endpoint policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkFlowPolicyV1 {
    direction: NetworkFlowDirectionV1,
    protocol: NetworkTransportProtocolV1,
    remote_prefix: NetworkIpPrefixV1,
    ports: Option<NetworkPortRangeV1>,
}

impl NetworkFlowPolicyV1 {
    /// Constructs one closed direction, protocol, prefix, and port match.
    ///
    /// TCP and UDP require a port range. ICMP requires no port range and must
    /// match its named IP family.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPolicyProgramError`] when protocol, address family,
    /// and port shape disagree.
    pub fn new(
        direction: NetworkFlowDirectionV1,
        protocol: NetworkTransportProtocolV1,
        remote_prefix: NetworkIpPrefixV1,
        ports: Option<NetworkPortRangeV1>,
    ) -> Result<Self, NetworkPolicyProgramError> {
        let valid = matches!(
            (protocol, remote_prefix, ports),
            (
                NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp,
                _,
                Some(_)
            ) | (
                NetworkTransportProtocolV1::IcmpV4,
                NetworkIpPrefixV1::Ipv4 { .. },
                None
            ) | (
                NetworkTransportProtocolV1::IcmpV6,
                NetworkIpPrefixV1::Ipv6 { .. },
                None
            )
        );
        if !valid {
            return Err(NetworkPolicyProgramError);
        }

        Ok(Self {
            direction,
            protocol,
            remote_prefix,
            ports,
        })
    }

    /// Returns the flow direction at the sandbox boundary.
    #[must_use]
    pub const fn direction(self) -> NetworkFlowDirectionV1 {
        self.direction
    }

    /// Returns the closed layer-4 protocol class.
    #[must_use]
    pub const fn protocol(self) -> NetworkTransportProtocolV1 {
        self.protocol
    }

    /// Returns the canonical remote network prefix.
    #[must_use]
    pub const fn remote_prefix(self) -> NetworkIpPrefixV1 {
        self.remote_prefix
    }

    /// Returns the required TCP or UDP destination-port range, when applicable.
    #[must_use]
    pub const fn ports(self) -> Option<NetworkPortRangeV1> {
        self.ports
    }
}

/// Resolves one logical endpoint into a canonical bounded flow set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkEndpointPolicyV1 {
    endpoint_id: NetworkEndpointId,
    flows: Vec<NetworkFlowPolicyV1>,
    digest: ObjectDigest,
}

impl NetworkEndpointPolicyV1 {
    /// Constructs one nonempty canonical endpoint policy.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPolicyProgramError`] for a sentinel endpoint, an empty
    /// or oversized flow set, or flows outside strict canonical order.
    pub fn new(
        endpoint_id: NetworkEndpointId,
        flows: Vec<NetworkFlowPolicyV1>,
    ) -> Result<Self, NetworkPolicyProgramError> {
        if endpoint_id.as_bytes() == &[0; 16]
            || flows.is_empty()
            || flows.len() > MAXIMUM_FLOWS_PER_ENDPOINT
            || flows.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(NetworkPolicyProgramError);
        }

        let digest = endpoint_digest(endpoint_id, &flows);
        Ok(Self {
            endpoint_id,
            flows,
            digest,
        })
    }

    /// Returns the portable logical endpoint identity.
    #[must_use]
    pub const fn endpoint_id(&self) -> NetworkEndpointId {
        self.endpoint_id
    }

    /// Returns the canonical packet-flow set.
    #[must_use]
    pub fn flows(&self) -> &[NetworkFlowPolicyV1] {
        &self.flows
    }

    /// Returns the domain-separated endpoint-policy commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Carries one complete fixed node-local packet-policy selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicyProgramV1 {
    kind: NetworkKind,
    enforcement_program_digest: ObjectDigest,
    lease_gate_program_digest: Option<ObjectDigest>,
    endpoints: Vec<NetworkEndpointPolicyV1>,
    digest: ObjectDigest,
}

impl NetworkPolicyProgramV1 {
    /// Constructs a complete default-deny Network packet-policy program.
    ///
    /// The enforcement digest identifies the fixed reviewed netlink/firewall
    /// implementation. Every veth-backed kind also requires the fixed tc-BPF
    /// lease-gate artifact. Isolated policy has neither a veth gate nor endpoint
    /// flows. Host networking is outside this private-network boundary.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPolicyProgramError`] for sentinel artifact digests,
    /// invalid kind/gate/endpoint shape, a noncanonical endpoint set, or a flow
    /// direction incompatible with Outbound or Published policy.
    pub fn new(
        kind: NetworkKind,
        enforcement_program_digest: ObjectDigest,
        lease_gate_program_digest: Option<ObjectDigest>,
        endpoints: Vec<NetworkEndpointPolicyV1>,
    ) -> Result<Self, NetworkPolicyProgramError> {
        if enforcement_program_digest.as_bytes() == &[0; 32]
            || lease_gate_program_digest.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || endpoints.len() > MAXIMUM_ENDPOINTS
            || endpoints
                .windows(2)
                .any(|pair| pair[0].endpoint_id >= pair[1].endpoint_id)
            || !valid_program_shape(kind, lease_gate_program_digest, &endpoints)
        {
            return Err(NetworkPolicyProgramError);
        }

        let digest = program_digest(
            kind,
            enforcement_program_digest,
            lease_gate_program_digest,
            &endpoints,
        );
        Ok(Self {
            kind,
            enforcement_program_digest,
            lease_gate_program_digest,
            endpoints,
            digest,
        })
    }

    /// Returns the portable exposure kind implemented by this program.
    #[must_use]
    pub const fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// Returns the fixed reviewed enforcement-artifact commitment.
    #[must_use]
    pub const fn enforcement_program_digest(&self) -> ObjectDigest {
        self.enforcement_program_digest
    }

    /// Returns the fixed tc-BPF lease-gate artifact for veth-backed policy.
    #[must_use]
    pub const fn lease_gate_program_digest(&self) -> Option<ObjectDigest> {
        self.lease_gate_program_digest
    }

    /// Returns canonical logical endpoint policy objects.
    #[must_use]
    pub fn endpoints(&self) -> &[NetworkEndpointPolicyV1] {
        &self.endpoints
    }

    /// Returns the commitment to the complete node-local policy program.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

fn valid_program_shape(
    kind: NetworkKind,
    lease_gate_program_digest: Option<ObjectDigest>,
    endpoints: &[NetworkEndpointPolicyV1],
) -> bool {
    match kind {
        NetworkKind::Isolated => lease_gate_program_digest.is_none() && endpoints.is_empty(),
        NetworkKind::Project => lease_gate_program_digest.is_some(),
        NetworkKind::Outbound => {
            lease_gate_program_digest.is_some()
                && endpoints.iter().all(|endpoint| {
                    endpoint
                        .flows
                        .iter()
                        .all(|flow| flow.direction == NetworkFlowDirectionV1::Egress)
                })
        }
        NetworkKind::Published => {
            lease_gate_program_digest.is_some()
                && endpoints.iter().all(|endpoint| {
                    endpoint
                        .flows
                        .iter()
                        .all(|flow| flow.direction == NetworkFlowDirectionV1::Ingress)
                })
        }
        NetworkKind::Host => false,
    }
}

fn endpoint_digest(endpoint_id: NetworkEndpointId, flows: &[NetworkFlowPolicyV1]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ENDPOINT_DIGEST_DOMAIN);
    digest.update(endpoint_id.as_bytes());
    digest.update((flows.len() as u16).to_be_bytes());
    for flow in flows {
        digest.update(encode_flow(*flow));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn program_digest(
    kind: NetworkKind,
    enforcement_program_digest: ObjectDigest,
    lease_gate_program_digest: Option<ObjectDigest>,
    endpoints: &[NetworkEndpointPolicyV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(PROGRAM_DIGEST_DOMAIN);
    digest.update([network_kind_code(kind)]);
    digest.update(enforcement_program_digest.as_bytes());
    match lease_gate_program_digest {
        Some(gate) => {
            digest.update([1]);
            digest.update(gate.as_bytes());
        }
        None => digest.update([0]),
    }
    digest.update((endpoints.len() as u16).to_be_bytes());
    for endpoint in endpoints {
        digest.update(endpoint.endpoint_id.as_bytes());
        digest.update(endpoint.digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_flow(flow: NetworkFlowPolicyV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24);
    bytes.push(direction_code(flow.direction));
    bytes.push(protocol_code(flow.protocol));
    match flow.remote_prefix {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            bytes.extend_from_slice(&[4, prefix_length]);
            bytes.extend_from_slice(&network);
        }
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            bytes.extend_from_slice(&[6, prefix_length]);
            bytes.extend_from_slice(&network);
        }
    }
    match flow.ports {
        Some(ports) => {
            bytes.push(1);
            bytes.extend_from_slice(&ports.first.to_be_bytes());
            bytes.extend_from_slice(&ports.last.to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes
}

fn canonical_ipv4_network(network: [u8; 4], prefix_length: u8) -> bool {
    let value = u32::from_be_bytes(network);
    let host_mask = match prefix_length {
        0 => u32::MAX,
        32 => 0,
        _ => u32::MAX >> prefix_length,
    };
    value & host_mask == 0
}

fn canonical_ipv6_network(network: [u8; 16], prefix_length: u8) -> bool {
    let value = u128::from_be_bytes(network);
    let host_mask = match prefix_length {
        0 => u128::MAX,
        128 => 0,
        _ => u128::MAX >> prefix_length,
    };
    value & host_mask == 0
}

const fn network_kind_code(kind: NetworkKind) -> u8 {
    match kind {
        NetworkKind::Isolated => 1,
        NetworkKind::Project => 2,
        NetworkKind::Outbound => 3,
        NetworkKind::Published => 4,
        NetworkKind::Host => 5,
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tcp_flow(direction: NetworkFlowDirectionV1) -> NetworkFlowPolicyV1 {
        NetworkFlowPolicyV1::new(
            direction,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([10, 20, 0, 0], 16).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap()
    }

    fn endpoint(direction: NetworkFlowDirectionV1) -> NetworkEndpointPolicyV1 {
        NetworkEndpointPolicyV1::new(
            NetworkEndpointId::from_bytes([7; 16]),
            vec![tcp_flow(direction)],
        )
        .unwrap()
    }

    #[test]
    fn canonical_prefixes_and_protocol_shapes_fail_closed() {
        assert!(NetworkIpPrefixV1::ipv4([192, 0, 2, 1], 32).is_ok());
        assert!(NetworkIpPrefixV1::ipv6([1; 16], 128).is_ok());
        assert!(NetworkIpPrefixV1::ipv4([10, 20, 1, 0], 16).is_err());
        assert!(NetworkIpPrefixV1::ipv4([0; 4], 33).is_err());
        assert!(NetworkIpPrefixV1::ipv6([1; 16], 64).is_err());
        assert!(NetworkPortRangeV1::new(0, 1).is_err());
        assert!(NetworkPortRangeV1::new(81, 80).is_err());
        assert!(
            NetworkFlowPolicyV1::new(
                NetworkFlowDirectionV1::Egress,
                NetworkTransportProtocolV1::Tcp,
                NetworkIpPrefixV1::ipv4([0; 4], 0).unwrap(),
                None,
            )
            .is_err()
        );
        assert!(
            NetworkFlowPolicyV1::new(
                NetworkFlowDirectionV1::Egress,
                NetworkTransportProtocolV1::IcmpV4,
                NetworkIpPrefixV1::ipv6([0; 16], 0).unwrap(),
                None,
            )
            .is_err()
        );

        let endpoint_id = NetworkEndpointId::from_bytes([7; 16]);
        let flow = tcp_flow(NetworkFlowDirectionV1::Egress);
        assert!(NetworkEndpointPolicyV1::new(endpoint_id, vec![flow, flow]).is_err());

        let earlier_prefix = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Egress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([10, 0, 0, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let later_prefix = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Egress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([10, 1, 0, 0], 16).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        assert!(
            NetworkEndpointPolicyV1::new(endpoint_id, vec![earlier_prefix, later_prefix]).is_ok()
        );
        assert!(
            NetworkEndpointPolicyV1::new(endpoint_id, vec![later_prefix, earlier_prefix]).is_err()
        );
    }

    #[test]
    fn kind_gate_and_direction_contracts_are_closed() {
        let enforcement = ObjectDigest::from_bytes([1; 32]);
        let gate = ObjectDigest::from_bytes([2; 32]);
        assert!(
            NetworkPolicyProgramV1::new(NetworkKind::Isolated, enforcement, None, Vec::new(),)
                .is_ok()
        );
        assert!(
            NetworkPolicyProgramV1::new(
                NetworkKind::Isolated,
                enforcement,
                Some(gate),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            NetworkPolicyProgramV1::new(
                NetworkKind::Outbound,
                enforcement,
                Some(gate),
                vec![endpoint(NetworkFlowDirectionV1::Ingress)],
            )
            .is_err()
        );
        assert!(
            NetworkPolicyProgramV1::new(
                NetworkKind::Published,
                enforcement,
                Some(gate),
                vec![endpoint(NetworkFlowDirectionV1::Egress)],
            )
            .is_err()
        );
        assert!(
            NetworkPolicyProgramV1::new(NetworkKind::Host, enforcement, None, Vec::new(),).is_err()
        );
    }

    #[test]
    fn policy_digests_bind_artifacts_endpoints_and_flows() {
        let original_endpoint = endpoint(NetworkFlowDirectionV1::Egress);
        let original = NetworkPolicyProgramV1::new(
            NetworkKind::Outbound,
            ObjectDigest::from_bytes([1; 32]),
            Some(ObjectDigest::from_bytes([2; 32])),
            vec![original_endpoint.clone()],
        )
        .unwrap();
        let changed_artifact = NetworkPolicyProgramV1::new(
            NetworkKind::Outbound,
            ObjectDigest::from_bytes([3; 32]),
            Some(ObjectDigest::from_bytes([2; 32])),
            vec![original_endpoint],
        )
        .unwrap();
        let changed_flow = NetworkPolicyProgramV1::new(
            NetworkKind::Outbound,
            ObjectDigest::from_bytes([1; 32]),
            Some(ObjectDigest::from_bytes([2; 32])),
            vec![
                NetworkEndpointPolicyV1::new(
                    NetworkEndpointId::from_bytes([7; 16]),
                    vec![
                        NetworkFlowPolicyV1::new(
                            NetworkFlowDirectionV1::Egress,
                            NetworkTransportProtocolV1::Udp,
                            NetworkIpPrefixV1::ipv4([10, 20, 0, 0], 16).unwrap(),
                            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
                        )
                        .unwrap(),
                    ],
                )
                .unwrap(),
            ],
        )
        .unwrap();

        assert_ne!(original.digest(), changed_artifact.digest());
        assert_ne!(original.digest(), changed_flow.digest());
        assert_ne!(
            original.endpoints()[0].digest(),
            changed_flow.endpoints()[0].digest()
        );
    }
}
