//! Durable node-local Network allocation policy and resolved namespace plans.
//!
//! A portable profile does not carry addresses, interface names, MAC
//! addresses, routes, or MTU. Root configuration supplies a bounded allocation
//! policy, and the protected preparation catalog assigns one never-reused
//! generation. This module deterministically resolves those inputs into the
//! complete pre-effect namespace plan. Interface names are diagnostic creation
//! labels only; later kernel identity must use the namespace, ifindex, peer,
//! MAC, and allocation generation.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::model::NetworkKind;
use sha2::{Digest as _, Sha256};

use crate::policy::{NetworkIpPrefixV1, NetworkPolicyProgramV1};

const ALLOCATION_POLICY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.allocation-policy.v1\0";
const NAMESPACE_PLAN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.namespace-plan.v1\0";
const MAXIMUM_ROUTES: usize = 256;
const MAXIMUM_RESERVATIONS: u64 = 16_384;
const MINIMUM_IPV4_MTU: u32 = 576;
const MINIMUM_IPV6_MTU: u32 = 1_280;
const MAXIMUM_MTU: u32 = 65_535;

/// Reports invalid allocation policy or resolved-plan input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("node-local Network allocation policy is invalid")]
pub struct NetworkAllocationError;

/// Carries one exact IP address without a host-selected string form.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkIpAddressV1 {
    /// Carries an IPv4 address in network byte order.
    Ipv4([u8; 4]),
    /// Carries an IPv6 address in network byte order.
    Ipv6([u8; 16]),
}

impl NetworkIpAddressV1 {
    /// Returns whether this address and prefix use the same address family.
    #[must_use]
    pub const fn matches_prefix(self, prefix: NetworkIpPrefixV1) -> bool {
        matches!(
            (self, prefix),
            (Self::Ipv4(_), NetworkIpPrefixV1::Ipv4 { .. })
                | (Self::Ipv6(_), NetworkIpPrefixV1::Ipv6 { .. })
        )
    }
}

/// Defines one pair-allocation pool large enough for the bounded catalog.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkAddressPoolV1 {
    prefix: NetworkIpPrefixV1,
}

impl NetworkAddressPoolV1 {
    /// Constructs a pool of `/31` IPv4 or `/127` IPv6 point-to-point pairs.
    ///
    /// Every admitted pool has at least 16,384 pairs, matching the protected
    /// preparation catalog's lifetime reservation bound.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkAllocationError`] when the prefix is too narrow to
    /// supply the complete bounded reservation space or is noncanonical.
    pub fn new(prefix: NetworkIpPrefixV1) -> Result<Self, NetworkAllocationError> {
        let sufficient = match prefix {
            NetworkIpPrefixV1::Ipv4 { prefix_length, .. } => prefix_length <= 17,
            NetworkIpPrefixV1::Ipv6 { prefix_length, .. } => prefix_length <= 113,
        };
        if !prefix.is_canonical() || !sufficient {
            return Err(NetworkAllocationError);
        }

        Ok(Self { prefix })
    }

    /// Returns the canonical pool prefix.
    #[must_use]
    pub const fn prefix(self) -> NetworkIpPrefixV1 {
        self.prefix
    }

    pub(crate) fn overlaps(self, other: Self) -> bool {
        match (self.prefix, other.prefix) {
            (
                NetworkIpPrefixV1::Ipv4 {
                    network: left,
                    prefix_length: left_length,
                },
                NetworkIpPrefixV1::Ipv4 {
                    network: right,
                    prefix_length: right_length,
                },
            ) => {
                let common_length = left_length.min(right_length);
                masked_ipv4(left, common_length) == masked_ipv4(right, common_length)
            }
            (
                NetworkIpPrefixV1::Ipv6 {
                    network: left,
                    prefix_length: left_length,
                },
                NetworkIpPrefixV1::Ipv6 {
                    network: right,
                    prefix_length: right_length,
                },
            ) => {
                let common_length = left_length.min(right_length);
                masked_ipv6(left, common_length) == masked_ipv6(right, common_length)
            }
            _ => false,
        }
    }

    fn pair(
        self,
        allocation_generation: u64,
    ) -> Result<NetworkAddressPairV1, NetworkAllocationError> {
        let slot = allocation_generation
            .checked_sub(1)
            .filter(|slot| *slot < MAXIMUM_RESERVATIONS)
            .ok_or(NetworkAllocationError)?;
        let offset = u128::from(slot)
            .checked_mul(2)
            .ok_or(NetworkAllocationError)?;

        match self.prefix {
            NetworkIpPrefixV1::Ipv4 { network, .. } => {
                let base = u128::from(u32::from_be_bytes(network));
                let host = base.checked_add(offset).ok_or(NetworkAllocationError)?;
                let sandbox = host.checked_add(1).ok_or(NetworkAllocationError)?;
                let host = u32::try_from(host).map_err(|_| NetworkAllocationError)?;
                let sandbox = u32::try_from(sandbox).map_err(|_| NetworkAllocationError)?;

                Ok(NetworkAddressPairV1 {
                    host: NetworkIpAddressV1::Ipv4(host.to_be_bytes()),
                    sandbox: NetworkIpAddressV1::Ipv4(sandbox.to_be_bytes()),
                    prefix_length: 31,
                })
            }
            NetworkIpPrefixV1::Ipv6 { network, .. } => {
                let base = u128::from_be_bytes(network);
                let host = base.checked_add(offset).ok_or(NetworkAllocationError)?;
                let sandbox = host.checked_add(1).ok_or(NetworkAllocationError)?;

                Ok(NetworkAddressPairV1 {
                    host: NetworkIpAddressV1::Ipv6(host.to_be_bytes()),
                    sandbox: NetworkIpAddressV1::Ipv6(sandbox.to_be_bytes()),
                    prefix_length: 127,
                })
            }
        }
    }
}

/// Defines the complete allocation input for one root-configured profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkAllocationPolicyV1 {
    mtu: Option<u32>,
    mac_prefix: Option<[u8; 3]>,
    address_pools: Vec<NetworkAddressPoolV1>,
    route_prefixes: Vec<NetworkIpPrefixV1>,
    digest: ObjectDigest,
}

impl NetworkAllocationPolicyV1 {
    /// Constructs the loopback-only allocation policy.
    #[must_use]
    pub fn isolated() -> Self {
        let mut policy = Self {
            mtu: None,
            mac_prefix: None,
            address_pools: Vec::new(),
            route_prefixes: Vec::new(),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        policy.digest = allocation_policy_digest(&policy);
        policy
    }

    /// Constructs one fixed veth allocation policy.
    ///
    /// The three-byte MAC prefix must be locally administered and unicast.
    /// Its final three bytes are reserved for the catalog generation and link
    /// role. Address pools and route prefixes must be strictly ordered. At
    /// most one pool per family is accepted, and every route must have a
    /// configured address family.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkAllocationError`] for an invalid MTU or MAC prefix,
    /// missing, duplicate, oversized, or noncanonical address/route inputs, or
    /// an IPv6 policy whose MTU is below 1280.
    pub fn veth(
        mtu: u32,
        mac_prefix: [u8; 3],
        address_pools: Vec<NetworkAddressPoolV1>,
        route_prefixes: Vec<NetworkIpPrefixV1>,
    ) -> Result<Self, NetworkAllocationError> {
        let ipv4_pool_count = address_pools
            .iter()
            .filter(|pool| matches!(pool.prefix, NetworkIpPrefixV1::Ipv4 { .. }))
            .count();
        let ipv6_pool_count = address_pools
            .iter()
            .filter(|pool| matches!(pool.prefix, NetworkIpPrefixV1::Ipv6 { .. }))
            .count();
        let has_ipv4 = ipv4_pool_count == 1;
        let has_ipv6 = ipv6_pool_count == 1;
        let valid_routes = route_prefixes.iter().all(|route| match route {
            NetworkIpPrefixV1::Ipv4 { .. } => route.is_canonical() && has_ipv4,
            NetworkIpPrefixV1::Ipv6 { .. } => route.is_canonical() && has_ipv6,
        });
        if !(MINIMUM_IPV4_MTU..=MAXIMUM_MTU).contains(&mtu)
            || (has_ipv6 && mtu < MINIMUM_IPV6_MTU)
            || mac_prefix[0] & 0x03 != 0x02
            || address_pools.is_empty()
            || address_pools.len() > 2
            || ipv4_pool_count > 1
            || ipv6_pool_count > 1
            || address_pools.windows(2).any(|pair| pair[0] >= pair[1])
            || route_prefixes.len() > MAXIMUM_ROUTES
            || route_prefixes.windows(2).any(|pair| pair[0] >= pair[1])
            || !valid_routes
        {
            return Err(NetworkAllocationError);
        }

        let mut policy = Self {
            mtu: Some(mtu),
            mac_prefix: Some(mac_prefix),
            address_pools,
            route_prefixes,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        policy.digest = allocation_policy_digest(&policy);
        Ok(policy)
    }

    /// Returns whether this policy creates a veth pair.
    #[must_use]
    pub const fn uses_veth(&self) -> bool {
        self.mtu.is_some()
    }

    /// Returns the veth MTU, or `None` for loopback-only isolation.
    #[must_use]
    pub const fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    /// Returns the root-configured three-byte MAC allocation prefix.
    #[must_use]
    pub const fn mac_prefix(&self) -> Option<[u8; 3]> {
        self.mac_prefix
    }

    /// Returns the canonical address-pair pools.
    #[must_use]
    pub fn address_pools(&self) -> &[NetworkAddressPoolV1] {
        &self.address_pools
    }

    /// Returns canonical route destinations installed through the host peer.
    #[must_use]
    pub fn route_prefixes(&self) -> &[NetworkIpPrefixV1] {
        &self.route_prefixes
    }

    /// Returns the domain-separated allocation-policy commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn compatible_with_kind(&self, kind: NetworkKind) -> bool {
        match kind {
            NetworkKind::Isolated => !self.uses_veth(),
            NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => {
                self.uses_veth()
            }
            NetworkKind::Host => false,
        }
    }
}

/// Carries one locally administered unicast MAC address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkMacAddressV1([u8; 6]);

impl NetworkMacAddressV1 {
    /// Returns the six MAC octets in network order.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

/// Carries the host and sandbox addresses of one point-to-point link family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkAddressPairV1 {
    host: NetworkIpAddressV1,
    sandbox: NetworkIpAddressV1,
    prefix_length: u8,
}

impl NetworkAddressPairV1 {
    /// Returns the address installed on the host-facing peer.
    #[must_use]
    pub const fn host(self) -> NetworkIpAddressV1 {
        self.host
    }

    /// Returns the address installed inside the sandbox namespace.
    #[must_use]
    pub const fn sandbox(self) -> NetworkIpAddressV1 {
        self.sandbox
    }

    /// Returns `/31` for IPv4 or `/127` for IPv6.
    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    pub(crate) fn recover(
        host: NetworkIpAddressV1,
        sandbox: NetworkIpAddressV1,
        prefix_length: u8,
    ) -> Result<Self, NetworkAllocationError> {
        let value = Self {
            host,
            sandbox,
            prefix_length,
        };
        if !valid_recovered_address_pair(&value) {
            return Err(NetworkAllocationError);
        }
        Ok(value)
    }
}

/// Carries one exact route through the corresponding host peer address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkRouteV1 {
    destination: NetworkIpPrefixV1,
    gateway: NetworkIpAddressV1,
}

impl NetworkRouteV1 {
    /// Returns the canonical route destination.
    #[must_use]
    pub const fn destination(self) -> NetworkIpPrefixV1 {
        self.destination
    }

    /// Returns the derived host-peer gateway.
    #[must_use]
    pub const fn gateway(self) -> NetworkIpAddressV1 {
        self.gateway
    }

    pub(crate) fn recover(
        destination: NetworkIpPrefixV1,
        gateway: NetworkIpAddressV1,
    ) -> Result<Self, NetworkAllocationError> {
        if !destination.is_canonical() || !gateway.matches_prefix(destination) {
            return Err(NetworkAllocationError);
        }
        Ok(Self {
            destination,
            gateway,
        })
    }
}

/// Carries one derived Linux interface label used only during creation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkInterfaceNameV1(String);

impl NetworkInterfaceNameV1 {
    /// Returns the fixed ASCII diagnostic label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkProgramCommitmentsV1 {
    kind: NetworkKind,
    packet_program_digest: ObjectDigest,
    enforcement_program_digest: ObjectDigest,
    lease_gate_program_digest: Option<ObjectDigest>,
}

impl NetworkProgramCommitmentsV1 {
    fn from_program(program: &NetworkPolicyProgramV1) -> Self {
        Self {
            kind: program.kind(),
            packet_program_digest: program.digest(),
            enforcement_program_digest: program.enforcement_program_digest(),
            lease_gate_program_digest: program.lease_gate_program_digest(),
        }
    }

    pub(crate) fn new(
        kind: NetworkKind,
        packet_program_digest: ObjectDigest,
        enforcement_program_digest: ObjectDigest,
        lease_gate_program_digest: Option<ObjectDigest>,
    ) -> Result<Self, NetworkAllocationError> {
        let valid_gate = match kind {
            NetworkKind::Isolated => lease_gate_program_digest.is_none(),
            NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => {
                lease_gate_program_digest.is_some()
            }
            NetworkKind::Host => false,
        };
        if packet_program_digest.as_bytes() == &[0; 32]
            || enforcement_program_digest.as_bytes() == &[0; 32]
            || lease_gate_program_digest.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || !valid_gate
        {
            return Err(NetworkAllocationError);
        }

        Ok(Self {
            kind,
            packet_program_digest,
            enforcement_program_digest,
            lease_gate_program_digest,
        })
    }
}

/// Resolves one protected reservation into an exact pre-effect kernel plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkNamespacePlanV1 {
    network_handle: [u8; 32],
    allocation_generation: u64,
    kind: NetworkKind,
    profile_digest: ObjectDigest,
    packet_program_digest: ObjectDigest,
    enforcement_program_digest: ObjectDigest,
    lease_gate_program_digest: Option<ObjectDigest>,
    mtu: Option<u32>,
    host_interface_name: Option<NetworkInterfaceNameV1>,
    sandbox_interface_name: Option<NetworkInterfaceNameV1>,
    host_mac: Option<NetworkMacAddressV1>,
    sandbox_mac: Option<NetworkMacAddressV1>,
    address_pairs: Vec<NetworkAddressPairV1>,
    routes: Vec<NetworkRouteV1>,
    digest: ObjectDigest,
}

impl NetworkNamespacePlanV1 {
    /// Returns the opaque reserved namespace handle.
    #[must_use]
    pub const fn network_handle(&self) -> &[u8; 32] {
        &self.network_handle
    }

    /// Returns the never-reused protected allocation generation.
    #[must_use]
    pub const fn allocation_generation(&self) -> u64 {
        self.allocation_generation
    }

    /// Returns the portable Network exposure kind.
    #[must_use]
    pub const fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// Returns the complete root-configured profile commitment.
    #[must_use]
    pub const fn profile_digest(&self) -> ObjectDigest {
        self.profile_digest
    }

    /// Returns the typed packet-policy program commitment.
    #[must_use]
    pub const fn packet_program_digest(&self) -> ObjectDigest {
        self.packet_program_digest
    }

    /// Returns the fixed reviewed netlink/firewall artifact commitment.
    #[must_use]
    pub const fn enforcement_program_digest(&self) -> ObjectDigest {
        self.enforcement_program_digest
    }

    /// Returns the fixed tc-BPF lease-gate artifact commitment, when required.
    #[must_use]
    pub const fn lease_gate_program_digest(&self) -> Option<ObjectDigest> {
        self.lease_gate_program_digest
    }

    /// Returns the planned veth MTU, or `None` for loopback-only isolation.
    #[must_use]
    pub const fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    /// Returns the derived host-side creation label, when a veth is present.
    #[must_use]
    pub const fn host_interface_name(&self) -> Option<&NetworkInterfaceNameV1> {
        self.host_interface_name.as_ref()
    }

    /// Returns the derived sandbox-side creation label, when a veth is present.
    #[must_use]
    pub const fn sandbox_interface_name(&self) -> Option<&NetworkInterfaceNameV1> {
        self.sandbox_interface_name.as_ref()
    }

    /// Returns the planned host-side MAC address, when a veth is present.
    #[must_use]
    pub const fn host_mac(&self) -> Option<NetworkMacAddressV1> {
        self.host_mac
    }

    /// Returns the planned sandbox-side MAC address, when a veth is present.
    #[must_use]
    pub const fn sandbox_mac(&self) -> Option<NetworkMacAddressV1> {
        self.sandbox_mac
    }

    /// Returns canonical host/sandbox point-to-point address pairs.
    #[must_use]
    pub fn address_pairs(&self) -> &[NetworkAddressPairV1] {
        &self.address_pairs
    }

    /// Returns canonical routes installed through the matching host peer.
    #[must_use]
    pub fn routes(&self) -> &[NetworkRouteV1] {
        &self.routes
    }

    /// Returns the domain-separated commitment to the complete plan.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn derive(
        network_handle: [u8; 32],
        allocation_generation: u64,
        profile_digest: ObjectDigest,
        program: &NetworkPolicyProgramV1,
        allocation: &NetworkAllocationPolicyV1,
    ) -> Result<Self, NetworkAllocationError> {
        Self::derive_from_commitments(
            network_handle,
            allocation_generation,
            profile_digest,
            NetworkProgramCommitmentsV1::from_program(program),
            allocation,
        )
    }

    pub(crate) fn derive_from_commitments(
        network_handle: [u8; 32],
        allocation_generation: u64,
        profile_digest: ObjectDigest,
        program: NetworkProgramCommitmentsV1,
        allocation: &NetworkAllocationPolicyV1,
    ) -> Result<Self, NetworkAllocationError> {
        if network_handle == [0; 32]
            || allocation_generation == 0
            || allocation_generation > MAXIMUM_RESERVATIONS
            || profile_digest.as_bytes() == &[0; 32]
            || !allocation.compatible_with_kind(program.kind)
        {
            return Err(NetworkAllocationError);
        }

        let mut plan = if allocation.uses_veth() {
            derive_veth_plan(
                network_handle,
                allocation_generation,
                program.kind,
                profile_digest,
                program,
                allocation,
            )?
        } else {
            Self {
                network_handle,
                allocation_generation,
                kind: program.kind,
                profile_digest,
                packet_program_digest: program.packet_program_digest,
                enforcement_program_digest: program.enforcement_program_digest,
                lease_gate_program_digest: program.lease_gate_program_digest,
                mtu: None,
                host_interface_name: None,
                sandbox_interface_name: None,
                host_mac: None,
                sandbox_mac: None,
                address_pairs: Vec::new(),
                routes: Vec::new(),
                digest: ObjectDigest::from_bytes([0; 32]),
            }
        };
        plan.digest = namespace_plan_digest(&plan);
        Ok(plan)
    }
}

fn derive_veth_plan(
    network_handle: [u8; 32],
    allocation_generation: u64,
    kind: NetworkKind,
    profile_digest: ObjectDigest,
    program: NetworkProgramCommitmentsV1,
    allocation: &NetworkAllocationPolicyV1,
) -> Result<NetworkNamespacePlanV1, NetworkAllocationError> {
    let mtu = allocation.mtu.ok_or(NetworkAllocationError)?;
    let mac_prefix = allocation.mac_prefix.ok_or(NetworkAllocationError)?;
    let address_pairs = allocation
        .address_pools
        .iter()
        .map(|pool| pool.pair(allocation_generation))
        .collect::<Result<Vec<_>, _>>()?;
    let routes = allocation
        .route_prefixes
        .iter()
        .copied()
        .map(|destination| {
            let gateway = address_pairs
                .iter()
                .map(|pair| pair.host)
                .find(|address| address.matches_prefix(destination))
                .ok_or(NetworkAllocationError)?;
            Ok(NetworkRouteV1 {
                destination,
                gateway,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let suffix = format!("{allocation_generation:012x}");

    Ok(NetworkNamespacePlanV1 {
        network_handle,
        allocation_generation,
        kind,
        profile_digest,
        packet_program_digest: program.packet_program_digest,
        enforcement_program_digest: program.enforcement_program_digest,
        lease_gate_program_digest: program.lease_gate_program_digest,
        mtu: Some(mtu),
        host_interface_name: Some(NetworkInterfaceNameV1(format!("aoh{suffix}"))),
        sandbox_interface_name: Some(NetworkInterfaceNameV1(format!("aog{suffix}"))),
        host_mac: Some(derived_mac(mac_prefix, allocation_generation, 0)?),
        sandbox_mac: Some(derived_mac(mac_prefix, allocation_generation, 1)?),
        address_pairs,
        routes,
        digest: ObjectDigest::from_bytes([0; 32]),
    })
}

fn derived_mac(
    prefix: [u8; 3],
    allocation_generation: u64,
    role: u32,
) -> Result<NetworkMacAddressV1, NetworkAllocationError> {
    let suffix = u32::try_from(allocation_generation)
        .ok()
        .and_then(|generation| generation.checked_mul(2))
        .and_then(|generation| generation.checked_add(role))
        .filter(|value| *value <= 0x00ff_ffff)
        .ok_or(NetworkAllocationError)?;
    let suffix = suffix.to_be_bytes();

    Ok(NetworkMacAddressV1([
        prefix[0], prefix[1], prefix[2], suffix[1], suffix[2], suffix[3],
    ]))
}

fn allocation_policy_digest(policy: &NetworkAllocationPolicyV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ALLOCATION_POLICY_DIGEST_DOMAIN);
    match (policy.mtu, policy.mac_prefix) {
        (Some(mtu), Some(mac_prefix)) => {
            digest.update([1]);
            digest.update(mtu.to_be_bytes());
            digest.update(mac_prefix);
        }
        _ => digest.update([0]),
    }
    digest.update((policy.address_pools.len() as u16).to_be_bytes());
    for pool in &policy.address_pools {
        digest.update(encode_prefix(pool.prefix));
    }
    digest.update((policy.route_prefixes.len() as u16).to_be_bytes());
    for route in &policy.route_prefixes {
        digest.update(encode_prefix(*route));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn namespace_plan_digest(plan: &NetworkNamespacePlanV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(NAMESPACE_PLAN_DIGEST_DOMAIN);
    digest.update(plan.network_handle);
    digest.update(plan.allocation_generation.to_be_bytes());
    digest.update([network_kind_code(plan.kind)]);
    digest.update(plan.profile_digest.as_bytes());
    digest.update(plan.packet_program_digest.as_bytes());
    digest.update(plan.enforcement_program_digest.as_bytes());
    encode_optional_digest(&mut digest, plan.lease_gate_program_digest);
    match (
        plan.mtu,
        &plan.host_interface_name,
        &plan.sandbox_interface_name,
        plan.host_mac,
        plan.sandbox_mac,
    ) {
        (Some(mtu), Some(host_name), Some(sandbox_name), Some(host_mac), Some(sandbox_mac)) => {
            digest.update([1]);
            digest.update(mtu.to_be_bytes());
            digest.update(host_name.as_str().as_bytes());
            digest.update(sandbox_name.as_str().as_bytes());
            digest.update(host_mac.octets());
            digest.update(sandbox_mac.octets());
        }
        _ => digest.update([0]),
    }
    digest.update((plan.address_pairs.len() as u16).to_be_bytes());
    for pair in &plan.address_pairs {
        digest.update(encode_address(pair.host));
        digest.update(encode_address(pair.sandbox));
        digest.update([pair.prefix_length]);
    }
    digest.update((plan.routes.len() as u16).to_be_bytes());
    for route in &plan.routes {
        digest.update(encode_prefix(route.destination));
        digest.update(encode_address(route.gateway));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_optional_digest(digest: &mut Sha256, value: Option<ObjectDigest>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn encode_address(address: NetworkIpAddressV1) -> Vec<u8> {
    match address {
        NetworkIpAddressV1::Ipv4(address) => {
            let mut bytes = Vec::with_capacity(5);
            bytes.push(4);
            bytes.extend_from_slice(&address);
            bytes
        }
        NetworkIpAddressV1::Ipv6(address) => {
            let mut bytes = Vec::with_capacity(17);
            bytes.push(6);
            bytes.extend_from_slice(&address);
            bytes
        }
    }
}

fn encode_prefix(prefix: NetworkIpPrefixV1) -> Vec<u8> {
    match prefix {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            let mut bytes = Vec::with_capacity(6);
            bytes.extend_from_slice(&[4, prefix_length]);
            bytes.extend_from_slice(&network);
            bytes
        }
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            let mut bytes = Vec::with_capacity(18);
            bytes.extend_from_slice(&[6, prefix_length]);
            bytes.extend_from_slice(&network);
            bytes
        }
    }
}

impl NetworkNamespacePlanV1 {
    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSNNP02");
        bytes.extend_from_slice(&self.network_handle);
        bytes.extend_from_slice(&self.allocation_generation.to_be_bytes());
        bytes.push(allocation_kind_code(self.kind));
        bytes.push(u8::from(self.lease_gate_program_digest.is_some()));
        bytes.push(u8::from(self.mtu.is_some()));
        bytes.push(u8::from(self.host_interface_name.is_some()));
        bytes.extend_from_slice(&(self.address_pairs.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.routes.len() as u16).to_be_bytes());
        for digest in [
            self.profile_digest,
            self.packet_program_digest,
            self.enforcement_program_digest,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(
            &self
                .lease_gate_program_digest
                .map_or([0; 32], |value| *value.as_bytes()),
        );
        bytes.extend_from_slice(&self.mtu.unwrap_or(0).to_be_bytes());
        for name in [&self.host_interface_name, &self.sandbox_interface_name] {
            let value = name
                .as_ref()
                .map_or(&[][..], |name| name.as_str().as_bytes());
            bytes.push(value.len() as u8);
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.host_mac.map_or([0; 6], NetworkMacAddressV1::octets));
        bytes.extend_from_slice(&self.sandbox_mac.map_or([0; 6], NetworkMacAddressV1::octets));
        for pair in &self.address_pairs {
            bytes.extend_from_slice(&encode_address(pair.host));
            bytes.extend_from_slice(&encode_address(pair.sandbox));
            bytes.push(pair.prefix_length);
        }
        for route in &self.routes {
            bytes.extend_from_slice(&encode_prefix(route.destination));
            bytes.extend_from_slice(&encode_address(route.gateway));
        }
        bytes
    }

    pub(crate) fn decode_recovery(bytes: &[u8]) -> Result<Self, NetworkAllocationError> {
        if bytes.len() > 65_536 || bytes.get(..8) != Some(b"AOSNNP02") {
            return Err(NetworkAllocationError);
        }
        let mut cursor = 8;
        let network_handle = allocation_take_array(bytes, &mut cursor)?;
        let allocation_generation = u64::from_be_bytes(allocation_take_array(bytes, &mut cursor)?);
        let kind = allocation_decode_kind(allocation_take_byte(bytes, &mut cursor)?)?;
        let gate_present = allocation_take_bool(bytes, &mut cursor)?;
        let mtu_present = allocation_take_bool(bytes, &mut cursor)?;
        let interfaces_present = allocation_take_bool(bytes, &mut cursor)?;
        let pair_count = usize::from(u16::from_be_bytes(allocation_take_array(
            bytes,
            &mut cursor,
        )?));
        let route_count = usize::from(u16::from_be_bytes(allocation_take_array(
            bytes,
            &mut cursor,
        )?));
        if pair_count > 2 || route_count > MAXIMUM_ROUTES {
            return Err(NetworkAllocationError);
        }
        let profile_digest = ObjectDigest::from_bytes(allocation_take_array(bytes, &mut cursor)?);
        let packet_program_digest =
            ObjectDigest::from_bytes(allocation_take_array(bytes, &mut cursor)?);
        let enforcement_program_digest =
            ObjectDigest::from_bytes(allocation_take_array(bytes, &mut cursor)?);
        let gate_bytes = allocation_take_array::<32>(bytes, &mut cursor)?;
        let lease_gate_program_digest =
            gate_present.then_some(ObjectDigest::from_bytes(gate_bytes));
        if !gate_present && gate_bytes != [0; 32] {
            return Err(NetworkAllocationError);
        }
        let mtu_value = u32::from_be_bytes(allocation_take_array(bytes, &mut cursor)?);
        let mtu = mtu_present.then_some(mtu_value);
        if !mtu_present && mtu_value != 0 {
            return Err(NetworkAllocationError);
        }
        let host_interface_name = allocation_take_name(bytes, &mut cursor, interfaces_present)?;
        let sandbox_interface_name = allocation_take_name(bytes, &mut cursor, interfaces_present)?;
        let host_mac_bytes = allocation_take_array::<6>(bytes, &mut cursor)?;
        let sandbox_mac_bytes = allocation_take_array::<6>(bytes, &mut cursor)?;
        let host_mac = interfaces_present.then_some(NetworkMacAddressV1(host_mac_bytes));
        let sandbox_mac = interfaces_present.then_some(NetworkMacAddressV1(sandbox_mac_bytes));
        if !interfaces_present && (host_mac_bytes != [0; 6] || sandbox_mac_bytes != [0; 6]) {
            return Err(NetworkAllocationError);
        }
        let mut address_pairs = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            address_pairs.push(NetworkAddressPairV1 {
                host: allocation_take_address(bytes, &mut cursor)?,
                sandbox: allocation_take_address(bytes, &mut cursor)?,
                prefix_length: allocation_take_byte(bytes, &mut cursor)?,
            });
        }
        let mut routes = Vec::with_capacity(route_count);
        for _ in 0..route_count {
            routes.push(NetworkRouteV1 {
                destination: allocation_take_prefix(bytes, &mut cursor)?,
                gateway: allocation_take_address(bytes, &mut cursor)?,
            });
        }
        if cursor != bytes.len()
            || network_handle == [0; 32]
            || allocation_generation == 0
            || allocation_generation > MAXIMUM_RESERVATIONS
            || profile_digest.as_bytes() == &[0; 32]
            || packet_program_digest.as_bytes() == &[0; 32]
            || enforcement_program_digest.as_bytes() == &[0; 32]
        {
            return Err(NetworkAllocationError);
        }
        let mut value = Self {
            network_handle,
            allocation_generation,
            kind,
            profile_digest,
            packet_program_digest,
            enforcement_program_digest,
            lease_gate_program_digest,
            mtu,
            host_interface_name,
            sandbox_interface_name,
            host_mac,
            sandbox_mac,
            address_pairs,
            routes,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        if !valid_recovered_namespace_plan(&value) {
            return Err(NetworkAllocationError);
        }
        value.digest = namespace_plan_digest(&value);
        if value.encode_recovery() != bytes {
            return Err(NetworkAllocationError);
        }
        Ok(value)
    }
}

fn valid_recovered_namespace_plan(value: &NetworkNamespacePlanV1) -> bool {
    let isolated = value.kind == NetworkKind::Isolated;
    if isolated {
        return value.lease_gate_program_digest.is_none()
            && value.mtu.is_none()
            && value.host_interface_name.is_none()
            && value.sandbox_interface_name.is_none()
            && value.host_mac.is_none()
            && value.sandbox_mac.is_none()
            && value.address_pairs.is_empty()
            && value.routes.is_empty();
    }
    let suffix = format!("{:012x}", value.allocation_generation);
    value.lease_gate_program_digest.is_some()
        && value
            .mtu
            .is_some_and(|mtu| (MINIMUM_IPV4_MTU..=MAXIMUM_MTU).contains(&mtu))
        && (!value
            .address_pairs
            .iter()
            .any(|pair| matches!(pair.host, NetworkIpAddressV1::Ipv6(_)))
            || value.mtu.is_some_and(|mtu| mtu >= MINIMUM_IPV6_MTU))
        && value
            .host_interface_name
            .as_ref()
            .is_some_and(|name| name.as_str() == format!("aoh{suffix}"))
        && value
            .sandbox_interface_name
            .as_ref()
            .is_some_and(|name| name.as_str() == format!("aog{suffix}"))
        && value
            .host_mac
            .is_some_and(|mac| mac.octets()[0] & 0x03 == 0x02)
        && value
            .sandbox_mac
            .is_some_and(|mac| mac.octets()[0] & 0x03 == 0x02)
        && value
            .host_mac
            .zip(value.sandbox_mac)
            .is_some_and(|(host, sandbox)| {
                let host = host.octets();
                let sandbox = sandbox.octets();
                host != sandbox && host[..3] == sandbox[..3]
            })
        && !value.address_pairs.is_empty()
        && value.address_pairs.iter().all(valid_recovered_address_pair)
        && value.address_pairs.windows(2).all(|pair| pair[0] < pair[1])
        && value.routes.windows(2).all(|pair| pair[0] < pair[1])
        && value.routes.iter().all(|route| {
            route.destination.is_canonical()
                && value.address_pairs.iter().any(|pair| {
                    route.gateway == pair.host && route.gateway.matches_prefix(route.destination)
                })
        })
}

fn valid_recovered_address_pair(pair: &NetworkAddressPairV1) -> bool {
    match (pair.host, pair.sandbox, pair.prefix_length) {
        (NetworkIpAddressV1::Ipv4(host), NetworkIpAddressV1::Ipv4(sandbox), 31) => {
            u32::from_be_bytes(host).checked_add(1) == Some(u32::from_be_bytes(sandbox))
        }
        (NetworkIpAddressV1::Ipv6(host), NetworkIpAddressV1::Ipv6(sandbox), 127) => {
            u128::from_be_bytes(host).checked_add(1) == Some(u128::from_be_bytes(sandbox))
        }
        _ => false,
    }
}

fn allocation_take_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, NetworkAllocationError> {
    let value = *bytes.get(*cursor).ok_or(NetworkAllocationError)?;
    *cursor = cursor.checked_add(1).ok_or(NetworkAllocationError)?;
    Ok(value)
}
fn allocation_take_bool(bytes: &[u8], cursor: &mut usize) -> Result<bool, NetworkAllocationError> {
    match allocation_take_byte(bytes, cursor)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(NetworkAllocationError),
    }
}
fn allocation_take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], NetworkAllocationError> {
    let end = cursor.checked_add(N).ok_or(NetworkAllocationError)?;
    let mut value = [0; N];
    value.copy_from_slice(bytes.get(*cursor..end).ok_or(NetworkAllocationError)?);
    *cursor = end;
    Ok(value)
}
fn allocation_take_name(
    bytes: &[u8],
    cursor: &mut usize,
    present: bool,
) -> Result<Option<NetworkInterfaceNameV1>, NetworkAllocationError> {
    let length = usize::from(allocation_take_byte(bytes, cursor)?);
    let end = cursor.checked_add(length).ok_or(NetworkAllocationError)?;
    let text = core::str::from_utf8(bytes.get(*cursor..end).ok_or(NetworkAllocationError)?)
        .map_err(|_| NetworkAllocationError)?;
    *cursor = end;
    if present && !text.is_empty() {
        Ok(Some(NetworkInterfaceNameV1(text.to_owned())))
    } else if !present && text.is_empty() {
        Ok(None)
    } else {
        Err(NetworkAllocationError)
    }
}
fn allocation_take_address(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<NetworkIpAddressV1, NetworkAllocationError> {
    match allocation_take_byte(bytes, cursor)? {
        4 => Ok(NetworkIpAddressV1::Ipv4(allocation_take_array(
            bytes, cursor,
        )?)),
        6 => Ok(NetworkIpAddressV1::Ipv6(allocation_take_array(
            bytes, cursor,
        )?)),
        _ => Err(NetworkAllocationError),
    }
}
fn allocation_take_prefix(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<NetworkIpPrefixV1, NetworkAllocationError> {
    let family = allocation_take_byte(bytes, cursor)?;
    let length = allocation_take_byte(bytes, cursor)?;
    match family {
        4 => NetworkIpPrefixV1::ipv4(allocation_take_array(bytes, cursor)?, length)
            .map_err(|_| NetworkAllocationError),
        6 => NetworkIpPrefixV1::ipv6(allocation_take_array(bytes, cursor)?, length)
            .map_err(|_| NetworkAllocationError),
        _ => Err(NetworkAllocationError),
    }
}
fn allocation_kind_code(kind: NetworkKind) -> u8 {
    match kind {
        NetworkKind::Isolated => 1,
        NetworkKind::Project => 2,
        NetworkKind::Outbound => 3,
        NetworkKind::Published => 4,
        NetworkKind::Host => 5,
    }
}
fn allocation_decode_kind(value: u8) -> Result<NetworkKind, NetworkAllocationError> {
    match value {
        1 => Ok(NetworkKind::Isolated),
        2 => Ok(NetworkKind::Project),
        3 => Ok(NetworkKind::Outbound),
        4 => Ok(NetworkKind::Published),
        _ => Err(NetworkAllocationError),
    }
}

fn masked_ipv4(address: [u8; 4], prefix_length: u8) -> u32 {
    let mask = match prefix_length {
        0 => 0,
        32 => u32::MAX,
        length => u32::MAX << (32 - length),
    };
    u32::from_be_bytes(address) & mask
}

fn masked_ipv6(address: [u8; 16], prefix_length: u8) -> u128 {
    let mask = match prefix_length {
        0 => 0,
        128 => u128::MAX,
        length => u128::MAX << (128 - length),
    };
    u128::from_be_bytes(address) & mask
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::NetworkEndpointId;

    use super::*;
    use crate::policy::{
        NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkPortRangeV1,
        NetworkTransportProtocolV1,
    };

    fn program(kind: NetworkKind) -> NetworkPolicyProgramV1 {
        let endpoints = if kind == NetworkKind::Isolated {
            Vec::new()
        } else {
            vec![
                NetworkEndpointPolicyV1::new(
                    NetworkEndpointId::from_bytes([7; 16]),
                    vec![
                        NetworkFlowPolicyV1::new(
                            NetworkFlowDirectionV1::Egress,
                            NetworkTransportProtocolV1::Tcp,
                            NetworkIpPrefixV1::ipv4([0; 4], 0).unwrap(),
                            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
                        )
                        .unwrap(),
                    ],
                )
                .unwrap(),
            ]
        };
        NetworkPolicyProgramV1::new(
            kind,
            ObjectDigest::from_bytes([1; 32]),
            (kind != NetworkKind::Isolated).then_some(ObjectDigest::from_bytes([2; 32])),
            endpoints,
        )
        .unwrap()
    }

    fn dual_stack_policy() -> NetworkAllocationPolicyV1 {
        NetworkAllocationPolicyV1::veth(
            1_500,
            [0x02, 0xaa, 0xbb],
            vec![
                NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 40, 0, 0], 17).unwrap())
                    .unwrap(),
                NetworkAddressPoolV1::new(
                    NetworkIpPrefixV1::ipv6(
                        [0xfd, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        64,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ],
            vec![
                NetworkIpPrefixV1::ipv4([0; 4], 0).unwrap(),
                NetworkIpPrefixV1::ipv6([0; 16], 0).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn pools_and_veth_policy_are_closed_and_bounded() {
        assert!(
            NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 0, 0, 0], 18).unwrap()).is_err()
        );
        assert!(
            NetworkAddressPoolV1::new(
                NetworkIpPrefixV1::ipv6([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 114,)
                    .unwrap(),
            )
            .is_err()
        );
        assert!(
            NetworkAddressPoolV1::new(NetworkIpPrefixV1::Ipv4 {
                network: [10, 0, 1, 0],
                prefix_length: 16,
            })
            .is_err()
        );
        assert!(NetworkAllocationPolicyV1::veth(1_500, [0, 0, 0], Vec::new(), Vec::new()).is_err());
        assert!(
            NetworkAllocationPolicyV1::veth(
                1_500,
                [0x02, 0xaa, 0xbb],
                vec![
                    NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 0, 0, 0], 17).unwrap(),)
                        .unwrap(),
                    NetworkAddressPoolV1::new(
                        NetworkIpPrefixV1::ipv4([10, 0, 128, 0], 17).unwrap(),
                    )
                    .unwrap(),
                ],
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            NetworkAllocationPolicyV1::veth(
                1_500,
                [0x02, 0xaa, 0xbb],
                vec![
                    NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 0, 0, 0], 16).unwrap(),)
                        .unwrap(),
                ],
                vec![NetworkIpPrefixV1::Ipv4 {
                    network: [10, 1, 0, 0],
                    prefix_length: 8,
                }],
            )
            .is_err()
        );
        assert!(
            NetworkAllocationPolicyV1::veth(
                1_200,
                [0x02, 0xaa, 0xbb],
                vec![
                    NetworkAddressPoolV1::new(
                        NetworkIpPrefixV1::ipv6(
                            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            64,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ],
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn generation_derives_exact_names_macs_addresses_and_routes() {
        let program = program(NetworkKind::Project);
        let allocation = dual_stack_policy();
        let plan = NetworkNamespacePlanV1::derive(
            [9; 32],
            2,
            ObjectDigest::from_bytes([8; 32]),
            &program,
            &allocation,
        )
        .unwrap();

        assert_eq!(
            plan.host_interface_name().unwrap().as_str(),
            "aoh000000000002"
        );
        assert_eq!(
            plan.sandbox_interface_name().unwrap().as_str(),
            "aog000000000002"
        );
        assert_eq!(
            plan.host_mac().unwrap().octets(),
            [0x02, 0xaa, 0xbb, 0, 0, 4]
        );
        assert_eq!(
            plan.sandbox_mac().unwrap().octets(),
            [0x02, 0xaa, 0xbb, 0, 0, 5]
        );
        assert_eq!(
            plan.address_pairs()[0].host(),
            NetworkIpAddressV1::Ipv4([10, 40, 0, 2])
        );
        assert_eq!(
            plan.address_pairs()[0].sandbox(),
            NetworkIpAddressV1::Ipv4([10, 40, 0, 3])
        );
        assert_eq!(plan.routes()[0].gateway(), plan.address_pairs()[0].host());
        assert_ne!(plan.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn isolated_and_overlap_semantics_are_explicit() {
        let isolated = NetworkNamespacePlanV1::derive(
            [9; 32],
            1,
            ObjectDigest::from_bytes([8; 32]),
            &program(NetworkKind::Isolated),
            &NetworkAllocationPolicyV1::isolated(),
        )
        .unwrap();
        assert!(isolated.host_interface_name().is_none());
        assert!(isolated.address_pairs().is_empty());

        let broad = NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 40, 0, 0], 16).unwrap())
            .unwrap();
        let nested =
            NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 40, 0, 0], 17).unwrap())
                .unwrap();
        let separate =
            NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 41, 0, 0], 17).unwrap())
                .unwrap();
        assert!(broad.overlaps(nested));
        assert!(!nested.overlaps(separate));
    }
}
