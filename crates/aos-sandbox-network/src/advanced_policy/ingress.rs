//! Node-global external ingress allocation, translation, and reuse fencing.
//!
//! The protected registry is one node-wide keyspace: project identity is part
//! of each owner, never a partitioning shortcut. Listener rows retain explicit
//! Reserved, Active, Releasing, or Tombstone state. Reuse requires both a
//! later global generation and a strictly newer owner revision.

use aos_sandbox_core::{NetworkEndpointId, NodeId, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::allocation::{NetworkIpAddressV1, NetworkNamespacePlanV1};
use crate::policy::{NetworkIpPrefixV1, NetworkPortRangeV1, NetworkTransportProtocolV1};

use super::identity::{
    AdvancedNetworkIdentityV1, ProtectedCurrentnessWitnessV1, ProtectedRecoveryAuthoritiesV1,
    ProtectedWitnessPurposeV1, node_namespace,
};
use super::recovery_reader::RecoveryReader as IngressReader;
use super::{AdvancedNetworkPolicyError, nonzero_digest, strictly_increasing};

const ALLOCATION_DOMAIN: &[u8] = b"aos.sandbox.network.external-ingress.v2\0";
const SET_DOMAIN: &[u8] = b"aos.sandbox.network.ingress-set.v2\0";
const POOL_DOMAIN: &[u8] = b"aos.sandbox.network.ingress-pool.v1\0";
const REGISTRY_DOMAIN: &[u8] = b"aos.sandbox.network.node-ingress-registry.v1\0";
const TRANSLATION_DOMAIN: &[u8] = b"aos.sandbox.network.ingress-translation.v1\0";
const MAXIMUM_POLICY_ALLOCATIONS: usize = 256;
const MAXIMUM_NODE_ROWS: usize = 1024;
const MAXIMUM_ALLOWED_SOURCES: usize = 32;
const MAXIMUM_POOL_PREFIXES: usize = 32;
const MAXIMUM_POOL_PORT_RANGES: usize = 64;

/// Identifies one globally unique external TCP or UDP listener tuple.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExternalIngressKeyV1 {
    address: NetworkIpAddressV1,
    port: u16,
    protocol: NetworkTransportProtocolV1,
}

impl ExternalIngressKeyV1 {
    /// Constructs one exact external listener key.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] for an unspecified
    /// address or port, or a transport other than TCP or UDP.
    pub fn new(
        address: NetworkIpAddressV1,
        port: u16,
        protocol: NetworkTransportProtocolV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let nonzero = match address {
            NetworkIpAddressV1::Ipv4(value) => value != [0; 4],
            NetworkIpAddressV1::Ipv6(value) => value != [0; 16],
        };
        if !nonzero
            || port == 0
            || !matches!(
                protocol,
                NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp
            )
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Self {
            address,
            port,
            protocol,
        })
    }

    /// Returns the exact external address.
    #[must_use]
    pub const fn address(self) -> NetworkIpAddressV1 {
        self.address
    }

    /// Returns the nonzero external port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Returns TCP or UDP.
    #[must_use]
    pub const fn protocol(self) -> NetworkTransportProtocolV1 {
        self.protocol
    }
}

/// Allocates one external listener to an assignment-bound logical endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedIngressAllocationV1 {
    allocation_id: NetworkEndpointId,
    target_endpoint_id: NetworkEndpointId,
    owner: AdvancedNetworkIdentityV1,
    external: ExternalIngressKeyV1,
    target_ports: NetworkPortRangeV1,
    allowed_sources: Vec<NetworkIpPrefixV1>,
    digest: ObjectDigest,
}

impl PublishedIngressAllocationV1 {
    /// Constructs one explicit source-restricted ingress allocation.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for sentinel identity, a
    /// non-singleton target port, an empty or oversized source set, a
    /// noncanonical prefix, or family mismatch.
    pub fn new(
        allocation_id: NetworkEndpointId,
        target_endpoint_id: NetworkEndpointId,
        owner: AdvancedNetworkIdentityV1,
        external: ExternalIngressKeyV1,
        target_ports: NetworkPortRangeV1,
        allowed_sources: Vec<NetworkIpPrefixV1>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if allocation_id.as_bytes() == &[0; 16] || target_endpoint_id.as_bytes() == &[0; 16] {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        if target_ports.first() != target_ports.last()
            || allowed_sources.is_empty()
            || allowed_sources.len() > MAXIMUM_ALLOWED_SOURCES
            || !strictly_increasing(&allowed_sources)
            || allowed_sources
                .iter()
                .any(|source| !source.is_canonical() || !external.address.matches_prefix(*source))
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let digest = allocation_digest(
            allocation_id,
            target_endpoint_id,
            &owner,
            external,
            target_ports,
            &allowed_sources,
        );
        Ok(Self {
            allocation_id,
            target_endpoint_id,
            owner,
            external,
            target_ports,
            allowed_sources,
            digest,
        })
    }

    /// Returns stable external-allocation identity.
    #[must_use]
    pub const fn allocation_id(&self) -> NetworkEndpointId {
        self.allocation_id
    }

    /// Returns the logical endpoint receiving translated packets.
    #[must_use]
    pub const fn target_endpoint_id(&self) -> NetworkEndpointId {
        self.target_endpoint_id
    }

    /// Returns the complete owner fence.
    #[must_use]
    pub const fn owner(&self) -> &AdvancedNetworkIdentityV1 {
        &self.owner
    }

    /// Returns the globally coordinated listener tuple.
    #[must_use]
    pub const fn external(&self) -> ExternalIngressKeyV1 {
        self.external
    }

    /// Returns the exact sandbox-side destination port as a singleton range.
    #[must_use]
    pub const fn target_ports(&self) -> NetworkPortRangeV1 {
        self.target_ports
    }

    /// Returns canonical admitted source prefixes.
    #[must_use]
    pub fn allowed_sources(&self) -> &[NetworkIpPrefixV1] {
        &self.allowed_sources
    }

    /// Returns the complete allocation commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Stores the complete canonical ingress set for one policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressAllocationSetV1 {
    owner: AdvancedNetworkIdentityV1,
    allocations: Vec<PublishedIngressAllocationV1>,
    digest: ObjectDigest,
}

impl IngressAllocationSetV1 {
    /// Constructs one externally-keyed canonical allocation set.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for excess, duplicate, unordered,
    /// foreign-owner, or duplicate-allocation-ID entries.
    pub fn new(
        owner: AdvancedNetworkIdentityV1,
        allocations: Vec<PublishedIngressAllocationV1>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if allocations.len() > MAXIMUM_POLICY_ALLOCATIONS
            || allocations
                .windows(2)
                .any(|pair| pair[0].external >= pair[1].external)
            || allocations.iter().any(|row| row.owner != owner)
            || duplicate_ids(allocations.iter())
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let digest = set_digest(&owner, &allocations);
        Ok(Self {
            owner,
            allocations,
            digest,
        })
    }

    /// Returns the exact policy owner.
    #[must_use]
    pub const fn owner(&self) -> &AdvancedNetworkIdentityV1 {
        &self.owner
    }

    /// Returns allocations in strict external-key order.
    #[must_use]
    pub fn allocations(&self) -> &[PublishedIngressAllocationV1] {
        &self.allocations
    }

    /// Returns the allocation-set commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSIAS01");
        bytes.extend_from_slice(&self.owner.encode_recovery());
        bytes.extend_from_slice(&(self.allocations.len() as u16).to_be_bytes());
        for allocation in &self.allocations {
            encode_ingress_allocation(&mut bytes, allocation);
        }
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 1024 * 1024 || bytes.get(..8) != Some(b"AOSIAS01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = IngressReader::new(&bytes[8..]);
        let owner = AdvancedNetworkIdentityV1::decode_recovery(reader.take(398)?, authorities)?;
        let count = usize::from(reader.u16()?);
        if count > MAXIMUM_POLICY_ALLOCATIONS {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut allocations = Vec::with_capacity(count);
        for _ in 0..count {
            allocations.push(decode_ingress_allocation(&mut reader, authorities)?);
        }
        if !reader.finished() {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::new(owner, allocations)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

/// Defines one canonical protocol and port range in the external-listener pool.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IngressPoolPortRangeV1 {
    protocol: NetworkTransportProtocolV1,
    ports: NetworkPortRangeV1,
}

impl IngressPoolPortRangeV1 {
    /// Constructs one TCP or UDP pool port range.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] for ICMP.
    pub fn new(
        protocol: NetworkTransportProtocolV1,
        ports: NetworkPortRangeV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !matches!(
            protocol,
            NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp
        ) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Self { protocol, ports })
    }

    /// Reports whether this range contains one listener key's protocol and port.
    #[must_use]
    pub fn contains(self, key: ExternalIngressKeyV1) -> bool {
        self.protocol == key.protocol
            && self.ports.first() <= key.port
            && key.port <= self.ports.last()
    }

    /// Returns the admitted transport protocol.
    #[must_use]
    pub const fn protocol(self) -> NetworkTransportProtocolV1 {
        self.protocol
    }

    /// Returns the inclusive admitted port range.
    #[must_use]
    pub const fn ports(self) -> NetworkPortRangeV1 {
        self.ports
    }
}

/// Defines the protected node-wide external-listener pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressPoolAuthorityV1 {
    node: NodeId,
    address_prefixes: Vec<NetworkIpPrefixV1>,
    port_ranges: Vec<IngressPoolPortRangeV1>,
    maximum_live: u16,
    reuse_delay_generations: u64,
    digest: ObjectDigest,
    currentness: ProtectedCurrentnessWitnessV1,
}

impl IngressPoolAuthorityV1 {
    /// Computes the exact pool-definition commitment to witness.
    #[must_use]
    pub fn commitment(
        node: NodeId,
        address_prefixes: &[NetworkIpPrefixV1],
        port_ranges: &[IngressPoolPortRangeV1],
        maximum_live: u16,
        reuse_delay_generations: u64,
    ) -> ObjectDigest {
        pool_digest(
            address_prefixes,
            port_ranges,
            node,
            maximum_live,
            reuse_delay_generations,
        )
    }

    /// Constructs one bounded pool and exact protected currentness witness.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for a noncanonical pool, zero
    /// capacity/reuse fence, or witness not committing the pool definition.
    pub fn new(
        node: NodeId,
        address_prefixes: Vec<NetworkIpPrefixV1>,
        port_ranges: Vec<IngressPoolPortRangeV1>,
        maximum_live: u16,
        reuse_delay_generations: u64,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if node.as_bytes() == &[0; 16]
            || address_prefixes.is_empty()
            || address_prefixes.len() > MAXIMUM_POOL_PREFIXES
            || !strictly_increasing(&address_prefixes)
            || address_prefixes.iter().any(|prefix| !prefix.is_canonical())
            || port_ranges.is_empty()
            || port_ranges.len() > MAXIMUM_POOL_PORT_RANGES
            || !strictly_increasing(&port_ranges)
            || port_ranges.windows(2).any(|pair| {
                pair[0].protocol == pair[1].protocol
                    && pair[1].ports.first() <= pair[0].ports.last()
            })
            || maximum_live == 0
            || usize::from(maximum_live) > MAXIMUM_NODE_ROWS
            || reuse_delay_generations == 0
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let content_digest = pool_digest(
            &address_prefixes,
            &port_ranges,
            node,
            maximum_live,
            reuse_delay_generations,
        );
        if currentness.purpose() != ProtectedWitnessPurposeV1::IngressPool
            || currentness.namespace() != node_namespace(node)
            || currentness.record_digest() != content_digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let digest = protected_pool_digest(content_digest, currentness);
        Ok(Self {
            node,
            address_prefixes,
            port_ranges,
            maximum_live,
            reuse_delay_generations,
            digest,
            currentness,
        })
    }

    /// Reports whether one key belongs to the configured address pool.
    #[must_use]
    pub fn admits(&self, key: ExternalIngressKeyV1) -> bool {
        self.address_prefixes
            .iter()
            .any(|prefix| address_in_prefix(key.address, *prefix))
            && self.port_ranges.iter().any(|range| range.contains(key))
    }

    /// Returns the node authority domain.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns canonical admitted external-address prefixes.
    #[must_use]
    pub fn address_prefixes(&self) -> &[NetworkIpPrefixV1] {
        &self.address_prefixes
    }

    /// Returns the maximum simultaneous reserved, active, or releasing rows.
    #[must_use]
    pub const fn maximum_live(&self) -> u16 {
        self.maximum_live
    }

    /// Returns canonical admitted protocol/port ranges.
    #[must_use]
    pub fn port_ranges(&self) -> &[IngressPoolPortRangeV1] {
        &self.port_ranges
    }

    /// Returns the minimum tombstone delay before reuse.
    #[must_use]
    pub const fn reuse_delay_generations(&self) -> u64 {
        self.reuse_delay_generations
    }

    /// Returns the pool commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns protected pool-currentness evidence.
    #[must_use]
    pub const fn currentness(&self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSIPA01");
        bytes.extend_from_slice(self.node.as_bytes());
        bytes.extend_from_slice(&self.maximum_live.to_be_bytes());
        bytes.extend_from_slice(&self.reuse_delay_generations.to_be_bytes());
        bytes.extend_from_slice(&self.currentness.encode_recovery());
        bytes.push(self.address_prefixes.len() as u8);
        for prefix in &self.address_prefixes {
            encode_ingress_prefix(&mut bytes, *prefix);
        }
        bytes.push(self.port_ranges.len() as u8);
        for range in &self.port_ranges {
            bytes.push(ingress_protocol_code(range.protocol));
            bytes.extend_from_slice(&range.ports.first().to_be_bytes());
            bytes.extend_from_slice(&range.ports.last().to_be_bytes());
        }
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 4096 || bytes.get(..8) != Some(b"AOSIPA01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = IngressReader::new(&bytes[8..]);
        let node = NodeId::from_bytes(reader.array()?);
        let maximum_live = reader.u16()?;
        let reuse = reader.u64()?;
        let currentness =
            ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
        let prefix_count = usize::from(reader.byte()?);
        if prefix_count > MAXIMUM_POOL_PREFIXES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut prefixes = Vec::with_capacity(prefix_count);
        for _ in 0..prefix_count {
            prefixes.push(decode_ingress_prefix(&mut reader)?);
        }
        let range_count = usize::from(reader.byte()?);
        if range_count > MAXIMUM_POOL_PORT_RANGES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut ranges = Vec::with_capacity(range_count);
        for _ in 0..range_count {
            let protocol = decode_ingress_protocol(reader.byte()?)?;
            let ports = NetworkPortRangeV1::new(reader.u16()?, reader.u16()?)
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
            ranges.push(IngressPoolPortRangeV1::new(protocol, ports)?);
        }
        if !reader.finished() {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::new(node, prefixes, ranges, maximum_live, reuse, currentness)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

/// Names one closed node-global listener lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressRegistryRowStateV1 {
    /// A candidate exclusively reserves an unused listener.
    Reserved,
    /// One owner is authoritative for the listener.
    Active,
    /// An active owner is retained while removal or transfer is unresolved.
    Releasing,
    /// No effects remain, but reuse remains fenced.
    Tombstone,
}

/// Stores one node-global listener row and optional successor reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressRegistryRowV1 {
    key: ExternalIngressKeyV1,
    state: IngressRegistryRowStateV1,
    active: Option<PublishedIngressAllocationV1>,
    successor: Option<PublishedIngressAllocationV1>,
    fence_generation: u64,
    reuse_after_generation: u64,
}

impl IngressRegistryRowV1 {
    /// Reconstructs one protected active row during owner recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::IngressConflict`] for zero fence.
    pub fn recovered_active(
        allocation: PublishedIngressAllocationV1,
        fence_generation: u64,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if fence_generation == 0 {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(active_row(allocation, fence_generation))
    }

    /// Reconstructs one protected exclusive reservation during owner recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::IngressConflict`] for zero fence.
    pub fn recovered_reserved(
        allocation: PublishedIngressAllocationV1,
        fence_generation: u64,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if fence_generation == 0 {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(reserved_row(allocation, fence_generation))
    }

    /// Reconstructs one protected release or transfer during owner recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::IngressConflict`] for zero fence
    /// or a successor that names a different external listener.
    pub fn recovered_releasing(
        active: PublishedIngressAllocationV1,
        successor: Option<PublishedIngressAllocationV1>,
        fence_generation: u64,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if fence_generation == 0
            || successor.as_ref().is_some_and(|value| {
                value.external != active.external || !active.owner.admits_successor(&value.owner)
            })
        {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(IngressRegistryRowV1 {
            key: active.external,
            state: IngressRegistryRowStateV1::Releasing,
            active: Some(active),
            successor,
            fence_generation,
            reuse_after_generation: 0,
        })
    }

    /// Reconstructs one protected tombstone during owner recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::IngressConflict`] unless reuse is
    /// strictly later than its nonzero fence generation.
    pub fn recovered_tombstone(
        key: ExternalIngressKeyV1,
        fence_generation: u64,
        reuse_after_generation: u64,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if fence_generation == 0 || reuse_after_generation <= fence_generation {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(tombstone_row(key, fence_generation, reuse_after_generation))
    }

    /// Returns the globally unique listener key.
    #[must_use]
    pub const fn key(&self) -> ExternalIngressKeyV1 {
        self.key
    }

    /// Returns the closed lifecycle state.
    #[must_use]
    pub const fn state(&self) -> IngressRegistryRowStateV1 {
        self.state
    }

    /// Returns the currently effect-authoritative allocation.
    #[must_use]
    pub const fn active(&self) -> Option<&PublishedIngressAllocationV1> {
        self.active.as_ref()
    }

    /// Returns the reserved successor, when present.
    #[must_use]
    pub const fn successor(&self) -> Option<&PublishedIngressAllocationV1> {
        self.successor.as_ref()
    }

    /// Returns the global generation that last fenced this row.
    #[must_use]
    pub const fn fence_generation(&self) -> u64 {
        self.fence_generation
    }

    /// Returns the first generation at which a tombstone may be reused.
    #[must_use]
    pub const fn reuse_after_generation(&self) -> u64 {
        self.reuse_after_generation
    }
}

/// Supplies exact node-global registry compare-and-swap evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressRegistryCasV1 {
    generation: u64,
    registry_digest: ObjectDigest,
}

impl IngressRegistryCasV1 {
    /// Returns the expected global registry generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the expected complete registry digest.
    #[must_use]
    pub const fn registry_digest(self) -> ObjectDigest {
        self.registry_digest
    }
}

/// Stores one immutable node-global ingress registry generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalIngressRegistryV1 {
    node: NodeId,
    generation: u64,
    rows: Vec<IngressRegistryRowV1>,
    digest: ObjectDigest,
}

impl ExternalIngressRegistryV1 {
    /// Constructs an empty first-generation node-global registry.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unspecified`] for a sentinel node.
    pub fn empty(
        node: NodeId,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        Self::recover(node, 1, Vec::new(), currentness)
    }

    /// Computes the exact registry record commitment a protected owner witnesses.
    #[must_use]
    pub fn commitment(
        node: NodeId,
        generation: u64,
        rows: &[IngressRegistryRowV1],
    ) -> ObjectDigest {
        registry_digest(node, generation, rows)
    }

    /// Reconstructs an exact protected node-global registry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::IngressConflict`] for invalid
    /// generation, ordering, lifecycle shape, identity collision, or bounds.
    pub fn recover(
        node: NodeId,
        generation: u64,
        rows: Vec<IngressRegistryRowV1>,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if node.as_bytes() == &[0; 16] {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        Self::validate_rows(generation, &rows)?;
        let registry = Self::from_rows(node, generation, rows);
        if currentness.purpose() != ProtectedWitnessPurposeV1::IngressRegistry
            || currentness.namespace() != node_namespace(node)
            || currentness.record_digest() != registry.digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        Ok(registry)
    }

    /// Returns the immutable global generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the node-wide authority domain.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns rows in strict listener-key order.
    #[must_use]
    pub fn rows(&self) -> &[IngressRegistryRowV1] {
        &self.rows
    }

    /// Returns the complete global registry commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns exact global compare-and-swap evidence.
    #[must_use]
    pub const fn cas(&self) -> IngressRegistryCasV1 {
        IngressRegistryCasV1 {
            generation: self.generation,
            registry_digest: self.digest,
        }
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSIRG01");
        bytes.extend_from_slice(self.node.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&(self.rows.len() as u16).to_be_bytes());
        for row in &self.rows {
            encode_ingress_key(&mut bytes, row.key);
            bytes.push(match row.state {
                IngressRegistryRowStateV1::Reserved => 1,
                IngressRegistryRowStateV1::Active => 2,
                IngressRegistryRowStateV1::Releasing => 3,
                IngressRegistryRowStateV1::Tombstone => 4,
            });
            encode_optional_allocation(&mut bytes, row.active.as_ref());
            encode_optional_allocation(&mut bytes, row.successor.as_ref());
            bytes.extend_from_slice(&row.fence_generation.to_be_bytes());
            bytes.extend_from_slice(&row.reuse_after_generation.to_be_bytes());
        }
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        currentness: ProtectedCurrentnessWitnessV1,
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 4 * 1024 * 1024 || bytes.get(..8) != Some(b"AOSIRG01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = IngressReader::new(&bytes[8..]);
        let node = NodeId::from_bytes(reader.array()?);
        let generation = reader.u64()?;
        let count = usize::from(reader.u16()?);
        if count > MAXIMUM_NODE_ROWS {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            let key = decode_ingress_key(&mut reader)?;
            let state = reader.byte()?;
            let active = decode_optional_allocation(&mut reader, authorities)?;
            let successor = decode_optional_allocation(&mut reader, authorities)?;
            let fence = reader.u64()?;
            let reuse = reader.u64()?;
            let stored_shape_is_valid = match state {
                1 => active.is_none() && successor.is_some() && reuse == 0,
                2 => active.is_some() && successor.is_none() && reuse == 0,
                3 => active.is_some() && reuse == 0,
                4 => active.is_none() && successor.is_none(),
                _ => false,
            };
            if !stored_shape_is_valid {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            let row = match state {
                1 => IngressRegistryRowV1::recovered_reserved(
                    successor.ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
                    fence,
                )?,
                2 => IngressRegistryRowV1::recovered_active(
                    active.ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
                    fence,
                )?,
                3 => IngressRegistryRowV1::recovered_releasing(
                    active.ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
                    successor,
                    fence,
                )?,
                4 => IngressRegistryRowV1::recovered_tombstone(key, fence, reuse)?,
                _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
            };
            if row.key != key {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            rows.push(row);
        }
        if !reader.finished() {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::recover(node, generation, rows, currentness)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }

    /// Verifies that active rows exactly equal one policy allocation scope.
    #[must_use]
    pub fn contains_policy(&self, policy: &IngressAllocationSetV1) -> bool {
        let matching = self
            .rows
            .iter()
            .filter_map(IngressRegistryRowV1::active)
            .filter(|row| row.owner.has_same_allocation_scope(&policy.owner))
            .collect::<Vec<_>>();
        matching.len() == policy.allocations.len()
            && policy
                .allocations
                .iter()
                .all(|expected| matching.contains(&expected))
    }

    pub(crate) fn retains_policy(&self, policy: &IngressAllocationSetV1) -> bool {
        let retained = self
            .rows
            .iter()
            .filter_map(|row| row.active.as_ref())
            .filter(|row| row.owner.has_same_allocation_scope(&policy.owner))
            .collect::<Vec<_>>();
        retained.len() == policy.allocations.len()
            && policy
                .allocations
                .iter()
                .all(|expected| retained.contains(&expected))
    }

    pub(crate) fn has_in_flight_lineage(&self) -> bool {
        self.rows.iter().any(|row| {
            matches!(
                row.state,
                IngressRegistryRowStateV1::Reserved | IngressRegistryRowStateV1::Releasing
            )
        })
    }

    /// Reserves a complete successor set under one global CAS transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for stale CAS/pool state,
    /// predecessor mismatch, collision, exhaustion, or premature tombstone use.
    pub fn reserve_replacement(
        &self,
        cas: IngressRegistryCasV1,
        currentness: ProtectedCurrentnessWitnessV1,
        predecessor: &IngressAllocationSetV1,
        candidate: &IngressAllocationSetV1,
        pool: &IngressPoolAuthorityV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if cas != self.cas()
            || currentness.purpose() != ProtectedWitnessPurposeV1::IngressRegistry
            || currentness.namespace() != node_namespace(self.node)
            || currentness.record_digest() != self.digest
            || pool.node != self.node
            || !predecessor.owner.admits_successor(&candidate.owner)
            || !self.contains_policy(predecessor)
            || self.rows.iter().any(|row| {
                matches!(
                    row.state,
                    IngressRegistryRowStateV1::Reserved | IngressRegistryRowStateV1::Releasing
                )
            })
            || candidate
                .allocations
                .iter()
                .any(|row| !pool.admits(row.external))
        {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        let next = self.next_generation()?;
        let mut rows = Vec::with_capacity(
            self.rows
                .len()
                .checked_add(candidate.allocations.len())
                .ok_or(AdvancedNetworkPolicyError::IngressConflict)?,
        );
        for row in &self.rows {
            let old = row
                .active
                .as_ref()
                .filter(|active| active.owner.has_same_allocation_scope(&predecessor.owner));
            if old.is_some() {
                let successor = candidate
                    .allocations
                    .binary_search_by_key(&row.key, |value| value.external)
                    .ok()
                    .and_then(|index| candidate.allocations.get(index))
                    .cloned();
                rows.push(IngressRegistryRowV1 {
                    key: row.key,
                    state: IngressRegistryRowStateV1::Releasing,
                    active: old.cloned(),
                    successor,
                    fence_generation: next,
                    reuse_after_generation: 0,
                });
            } else {
                rows.push(row.clone());
            }
        }
        for candidate_row in &candidate.allocations {
            if predecessor
                .allocations
                .binary_search_by_key(&candidate_row.external, |value| value.external)
                .is_ok()
            {
                continue;
            }
            match rows
                .iter()
                .position(|row| row.key == candidate_row.external)
            {
                Some(index)
                    if rows[index].state == IngressRegistryRowStateV1::Tombstone
                        && currentness.sequence() >= rows[index].reuse_after_generation =>
                {
                    rows[index] = reserved_row(candidate_row.clone(), next);
                }
                Some(_) => return Err(AdvancedNetworkPolicyError::IngressConflict),
                None => rows.push(reserved_row(candidate_row.clone(), next)),
            }
        }
        rows.sort_by_key(IngressRegistryRowV1::key);
        let live = rows
            .iter()
            .filter(|row| row.state != IngressRegistryRowStateV1::Tombstone)
            .count();
        if live > usize::from(pool.maximum_live) {
            return Err(AdvancedNetworkPolicyError::PoolExhausted);
        }
        Self::validate_rows(next, &rows)?;
        Ok(Self::from_rows(self.node, next, rows))
    }

    /// Commits every reserved successor and tombstones released listeners.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless the exact candidate is
    /// wholly reserved or on generation overflow.
    pub fn commit_replacement(
        &self,
        candidate: &IngressAllocationSetV1,
        reuse_delay: u64,
        reuse_fence_base: u64,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if reuse_delay == 0 {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        let next = self.next_generation()?;
        if reuse_fence_base < self.generation {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        let reuse_after = reuse_fence_base
            .max(next)
            .checked_add(reuse_delay)
            .ok_or(AdvancedNetworkPolicyError::IngressConflict)?;
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            match row.state {
                IngressRegistryRowStateV1::Reserved
                    if row
                        .successor
                        .as_ref()
                        .is_some_and(|value| value.owner == candidate.owner) =>
                {
                    rows.push(active_row(
                        row.successor
                            .clone()
                            .ok_or(AdvancedNetworkPolicyError::IngressConflict)?,
                        next,
                    ));
                }
                IngressRegistryRowStateV1::Releasing
                    if row.active.as_ref().is_some_and(|value| {
                        value.owner.has_same_allocation_scope(&candidate.owner)
                    }) =>
                {
                    match row.successor.clone() {
                        Some(successor) if successor.owner == candidate.owner => {
                            rows.push(active_row(successor, next));
                        }
                        None => rows.push(tombstone_row(row.key, next, reuse_after)),
                        _ => return Err(AdvancedNetworkPolicyError::IngressConflict),
                    }
                }
                _ => rows.push(row.clone()),
            }
        }
        Self::validate_rows(next, &rows)?;
        let committed = Self::from_rows(self.node, next, rows);
        if !committed.contains_policy(candidate) {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(committed)
    }

    /// Rolls back a reservation without changing active predecessor effects.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for generation overflow or a
    /// reservation not owned by the exact candidate.
    pub fn rollback_reservation(
        &self,
        predecessor: &IngressAllocationSetV1,
        candidate: &IngressAllocationSetV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let next = self.next_generation()?;
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            match row.state {
                IngressRegistryRowStateV1::Reserved
                    if row
                        .successor
                        .as_ref()
                        .is_some_and(|value| value.owner == candidate.owner) => {}
                IngressRegistryRowStateV1::Releasing
                    if row.active.as_ref().is_some_and(|value| {
                        value.owner.has_same_allocation_scope(&predecessor.owner)
                    }) =>
                {
                    rows.push(active_row(
                        row.active
                            .clone()
                            .ok_or(AdvancedNetworkPolicyError::IngressConflict)?,
                        next,
                    ));
                }
                _ => rows.push(row.clone()),
            }
        }
        Self::validate_rows(next, &rows)?;
        let rolled_back = Self::from_rows(self.node, next, rows);
        if !rolled_back.contains_policy(predecessor) {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(rolled_back)
    }

    /// Removes only tombstones whose reuse fence has elapsed under global CAS.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::IngressConflict`] for stale CAS,
    /// generation overflow, or when no tombstone is yet collectable.
    pub fn collect_reusable_tombstones(
        &self,
        cas: IngressRegistryCasV1,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if cas != self.cas()
            || currentness.purpose() != ProtectedWitnessPurposeV1::IngressRegistry
            || currentness.namespace() != node_namespace(self.node)
            || currentness.record_digest() != self.digest
        {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        let mut rows = self.rows.clone();
        let before = rows.len();
        rows.retain(|row| {
            row.state != IngressRegistryRowStateV1::Tombstone
                || currentness.sequence() < row.reuse_after_generation
        });
        if rows.len() == before {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        let next = self.next_generation()?;
        Self::validate_rows(next, &rows)?;
        Ok(Self::from_rows(self.node, next, rows))
    }

    fn next_generation(&self) -> Result<u64, AdvancedNetworkPolicyError> {
        self.generation
            .checked_add(1)
            .ok_or(AdvancedNetworkPolicyError::IngressConflict)
    }

    fn validate_rows(
        generation: u64,
        rows: &[IngressRegistryRowV1],
    ) -> Result<(), AdvancedNetworkPolicyError> {
        if generation == 0
            || rows.len() > MAXIMUM_NODE_ROWS
            || rows.windows(2).any(|pair| pair[0].key >= pair[1].key)
            || has_registry_id_collision(rows)
            || has_registry_lineage_collision(rows)
            || has_impossible_in_flight_lineage(rows)
            || rows.iter().any(|row| !valid_row(row, generation))
        {
            return Err(AdvancedNetworkPolicyError::IngressConflict);
        }
        Ok(())
    }

    fn from_rows(node: NodeId, generation: u64, rows: Vec<IngressRegistryRowV1>) -> Self {
        let digest = registry_digest(node, generation, &rows);
        Self {
            node,
            generation,
            rows,
            digest,
        }
    }
}

/// Maps one external listener to one concrete sandbox-side target address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressTranslationV1 {
    allocation: PublishedIngressAllocationV1,
    target_address: NetworkIpAddressV1,
}

impl IngressTranslationV1 {
    /// Returns the complete external listener and target-port allocation.
    #[must_use]
    pub const fn allocation(&self) -> &PublishedIngressAllocationV1 {
        &self.allocation
    }

    /// Returns the concrete sandbox-side DNAT address.
    #[must_use]
    pub const fn target_address(&self) -> NetworkIpAddressV1 {
        self.target_address
    }

    /// Returns the exact sandbox-side DNAT port.
    #[must_use]
    pub const fn target_port(&self) -> u16 {
        self.allocation.target_ports.first()
    }
}

/// Stores the immutable external-listener-to-address translation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressTranslationPlanV1 {
    owner_digest: ObjectDigest,
    entries: Vec<IngressTranslationV1>,
    digest: ObjectDigest,
}

impl IngressTranslationPlanV1 {
    /// Compiles exact listener/DNAT intent against a physical namespace plan.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unrepresentable`] if any external
    /// listener lacks a sandbox-side target address of the same family.
    pub fn compile(
        allocations: &IngressAllocationSetV1,
        namespace: &NetworkNamespacePlanV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let mut entries = Vec::with_capacity(allocations.allocations.len());
        for allocation in &allocations.allocations {
            let target_address = namespace
                .address_pairs()
                .iter()
                .map(|pair| pair.sandbox())
                .find(|address| address.matches_prefix(address_prefix(allocation.external.address)))
                .ok_or(AdvancedNetworkPolicyError::Unrepresentable)?;
            entries.push(IngressTranslationV1 {
                allocation: allocation.clone(),
                target_address,
            });
        }
        let digest = translation_digest(allocations.owner.digest(), &entries);
        Ok(Self {
            owner_digest: allocations.owner.digest(),
            entries,
            digest,
        })
    }

    /// Returns the exact policy owner commitment.
    #[must_use]
    pub const fn owner_digest(&self) -> ObjectDigest {
        self.owner_digest
    }

    /// Returns canonical external-to-concrete-target mappings.
    #[must_use]
    pub fn entries(&self) -> &[IngressTranslationV1] {
        &self.entries
    }

    /// Returns the immutable translation-plan commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

fn reserved_row(value: PublishedIngressAllocationV1, generation: u64) -> IngressRegistryRowV1 {
    IngressRegistryRowV1 {
        key: value.external,
        state: IngressRegistryRowStateV1::Reserved,
        active: None,
        successor: Some(value),
        fence_generation: generation,
        reuse_after_generation: 0,
    }
}

fn active_row(value: PublishedIngressAllocationV1, generation: u64) -> IngressRegistryRowV1 {
    IngressRegistryRowV1 {
        key: value.external,
        state: IngressRegistryRowStateV1::Active,
        active: Some(value),
        successor: None,
        fence_generation: generation,
        reuse_after_generation: 0,
    }
}

fn tombstone_row(
    key: ExternalIngressKeyV1,
    generation: u64,
    reuse_after_generation: u64,
) -> IngressRegistryRowV1 {
    IngressRegistryRowV1 {
        key,
        state: IngressRegistryRowStateV1::Tombstone,
        active: None,
        successor: None,
        fence_generation: generation,
        reuse_after_generation,
    }
}

fn valid_row(row: &IngressRegistryRowV1, generation: u64) -> bool {
    if row.fence_generation == 0 || row.fence_generation > generation {
        return false;
    }
    if row
        .active
        .as_ref()
        .is_some_and(|value| value.external != row.key)
        || row
            .successor
            .as_ref()
            .is_some_and(|value| value.external != row.key)
    {
        return false;
    }
    match row.state {
        IngressRegistryRowStateV1::Reserved => {
            row.active.is_none() && row.successor.is_some() && row.reuse_after_generation == 0
        }
        IngressRegistryRowStateV1::Active => {
            row.active.is_some() && row.successor.is_none() && row.reuse_after_generation == 0
        }
        IngressRegistryRowStateV1::Releasing => {
            row.active.is_some()
                && row.reuse_after_generation == 0
                && row.successor.as_ref().map_or(true, |successor| {
                    row.active
                        .as_ref()
                        .is_some_and(|active| active.owner.admits_successor(&successor.owner))
                })
        }
        IngressRegistryRowStateV1::Tombstone => {
            row.active.is_none()
                && row.successor.is_none()
                && row.reuse_after_generation > row.fence_generation
        }
    }
}

fn duplicate_ids<'a>(values: impl Iterator<Item = &'a PublishedIngressAllocationV1>) -> bool {
    let mut ids = values
        .map(PublishedIngressAllocationV1::allocation_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.windows(2).any(|pair| pair[0] == pair[1])
}

fn has_registry_id_collision(rows: &[IngressRegistryRowV1]) -> bool {
    let values = rows
        .iter()
        .flat_map(|row| {
            row.active
                .iter()
                .chain(row.successor.iter())
                .map(move |allocation| (row.key, allocation.allocation_id))
        })
        .collect::<Vec<_>>();
    values.iter().enumerate().any(|(index, value)| {
        values[index + 1..]
            .iter()
            .any(|other| value.1 == other.1 && value.0 != other.0)
    })
}

fn has_registry_lineage_collision(rows: &[IngressRegistryRowV1]) -> bool {
    let allocations = rows
        .iter()
        .flat_map(|row| row.active.iter().chain(row.successor.iter()))
        .collect::<Vec<_>>();
    allocations.iter().enumerate().any(|(index, allocation)| {
        allocations[index + 1..].iter().any(|other| {
            allocation.owner.has_same_allocation_scope(&other.owner)
                && allocation.owner != other.owner
                && !allocation.owner.admits_successor(&other.owner)
                && !other.owner.admits_successor(&allocation.owner)
        })
    })
}

fn has_impossible_in_flight_lineage(rows: &[IngressRegistryRowV1]) -> bool {
    let predecessors = rows
        .iter()
        .filter(|row| row.state == IngressRegistryRowStateV1::Releasing)
        .filter_map(|row| row.active.as_ref())
        .map(PublishedIngressAllocationV1::owner)
        .collect::<Vec<_>>();
    let successors = rows
        .iter()
        .filter(|row| {
            matches!(
                row.state,
                IngressRegistryRowStateV1::Reserved | IngressRegistryRowStateV1::Releasing
            )
        })
        .filter_map(|row| row.successor.as_ref())
        .map(PublishedIngressAllocationV1::owner)
        .collect::<Vec<_>>();
    let predecessor = predecessors.first().copied();
    let successor = successors.first().copied();
    predecessors.iter().any(|owner| Some(*owner) != predecessor)
        || successors.iter().any(|owner| Some(*owner) != successor)
        || match (predecessor, successor) {
            (Some(old), Some(new)) => {
                !old.admits_successor(new)
                    || rows.iter().any(|row| {
                        row.state == IngressRegistryRowStateV1::Active
                            && row.active.as_ref().is_some_and(|active| {
                                active.owner.has_same_allocation_scope(old)
                                    || active.owner.has_same_allocation_scope(new)
                            })
                    })
            }
            (None, Some(_)) => rows.iter().any(|row| {
                row.state == IngressRegistryRowStateV1::Active
                    && row.active.as_ref().is_some_and(|active| {
                        successor.is_some_and(|new| {
                            active.owner.has_same_allocation_scope(new) && &active.owner != new
                        })
                    })
            }),
            (Some(old), None) => rows.iter().any(|row| {
                row.state == IngressRegistryRowStateV1::Active
                    && row
                        .active
                        .as_ref()
                        .is_some_and(|active| active.owner.has_same_allocation_scope(old))
            }),
            (None, None) => false,
        }
}

fn address_in_prefix(address: NetworkIpAddressV1, prefix: NetworkIpPrefixV1) -> bool {
    match (address, prefix) {
        (
            NetworkIpAddressV1::Ipv4(address),
            NetworkIpPrefixV1::Ipv4 {
                network,
                prefix_length,
            },
        ) => {
            let address = u32::from_be_bytes(address);
            let network = u32::from_be_bytes(network);
            let mask = if prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_length)
            };
            address & mask == network
        }
        (
            NetworkIpAddressV1::Ipv6(address),
            NetworkIpPrefixV1::Ipv6 {
                network,
                prefix_length,
            },
        ) => {
            let address = u128::from_be_bytes(address);
            let network = u128::from_be_bytes(network);
            let mask = if prefix_length == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_length)
            };
            address & mask == network
        }
        _ => false,
    }
}

fn allocation_digest(
    id: NetworkEndpointId,
    target_endpoint_id: NetworkEndpointId,
    owner: &AdvancedNetworkIdentityV1,
    external: ExternalIngressKeyV1,
    ports: NetworkPortRangeV1,
    sources: &[NetworkIpPrefixV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ALLOCATION_DOMAIN);
    digest.update(id.as_bytes());
    digest.update(target_endpoint_id.as_bytes());
    digest.update(owner.digest().as_bytes());
    digest.update(encode_external(external));
    digest.update(ports.first().to_be_bytes());
    digest.update(ports.last().to_be_bytes());
    digest.update((sources.len() as u16).to_be_bytes());
    for source in sources {
        digest.update(encode_prefix(*source));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn set_digest(
    owner: &AdvancedNetworkIdentityV1,
    values: &[PublishedIngressAllocationV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(SET_DOMAIN);
    digest.update(owner.digest().as_bytes());
    digest.update((values.len() as u16).to_be_bytes());
    for value in values {
        digest.update(value.digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn pool_digest(
    prefixes: &[NetworkIpPrefixV1],
    ports: &[IngressPoolPortRangeV1],
    node: NodeId,
    maximum: u16,
    delay: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(POOL_DOMAIN);
    digest.update(node.as_bytes());
    digest.update(maximum.to_be_bytes());
    digest.update(delay.to_be_bytes());
    digest.update((prefixes.len() as u16).to_be_bytes());
    for prefix in prefixes {
        digest.update(encode_prefix(*prefix));
    }
    digest.update((ports.len() as u16).to_be_bytes());
    for range in ports {
        digest.update([match range.protocol {
            NetworkTransportProtocolV1::Tcp => 1,
            NetworkTransportProtocolV1::Udp => 2,
            NetworkTransportProtocolV1::IcmpV4 => 3,
            NetworkTransportProtocolV1::IcmpV6 => 4,
        }]);
        digest.update(range.ports.first().to_be_bytes());
        digest.update(range.ports.last().to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn protected_pool_digest(
    content: ObjectDigest,
    witness: ProtectedCurrentnessWitnessV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.protected-ingress-pool.v1\0");
    digest.update(content.as_bytes());
    digest.update(witness.current_head().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn registry_digest(node: NodeId, generation: u64, rows: &[IngressRegistryRowV1]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(REGISTRY_DOMAIN);
    digest.update(node.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update((rows.len() as u16).to_be_bytes());
    for row in rows {
        digest.update(encode_external(row.key));
        digest.update([match row.state {
            IngressRegistryRowStateV1::Reserved => 1,
            IngressRegistryRowStateV1::Active => 2,
            IngressRegistryRowStateV1::Releasing => 3,
            IngressRegistryRowStateV1::Tombstone => 4,
        }]);
        digest.update(
            row.active
                .as_ref()
                .map_or([0; 32], |value| *value.digest.as_bytes()),
        );
        digest.update(
            row.successor
                .as_ref()
                .map_or([0; 32], |value| *value.digest.as_bytes()),
        );
        digest.update(row.fence_generation.to_be_bytes());
        digest.update(row.reuse_after_generation.to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn translation_digest(owner: ObjectDigest, values: &[IngressTranslationV1]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TRANSLATION_DOMAIN);
    digest.update(owner.as_bytes());
    digest.update((values.len() as u16).to_be_bytes());
    for value in values {
        digest.update(value.allocation.digest.as_bytes());
        digest.update(encode_address(value.target_address));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn address_prefix(address: NetworkIpAddressV1) -> NetworkIpPrefixV1 {
    match address {
        NetworkIpAddressV1::Ipv4(network) => NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length: 32,
        },
        NetworkIpAddressV1::Ipv6(network) => NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length: 128,
        },
    }
}

fn encode_address(value: NetworkIpAddressV1) -> [u8; 17] {
    let mut bytes = [0; 17];
    match value {
        NetworkIpAddressV1::Ipv4(address) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address);
        }
        NetworkIpAddressV1::Ipv6(address) => {
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&address);
        }
    }
    bytes
}

fn encode_ingress_allocation(bytes: &mut Vec<u8>, value: &PublishedIngressAllocationV1) {
    bytes.extend_from_slice(value.allocation_id.as_bytes());
    bytes.extend_from_slice(value.target_endpoint_id.as_bytes());
    bytes.extend_from_slice(&value.owner.encode_recovery());
    encode_ingress_key(bytes, value.external);
    bytes.extend_from_slice(&value.target_ports.first().to_be_bytes());
    bytes.extend_from_slice(&value.target_ports.last().to_be_bytes());
    bytes.push(value.allowed_sources.len() as u8);
    for prefix in &value.allowed_sources {
        encode_ingress_prefix(bytes, *prefix);
    }
}

fn decode_ingress_allocation(
    reader: &mut IngressReader<'_>,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<PublishedIngressAllocationV1, AdvancedNetworkPolicyError> {
    let allocation_id = NetworkEndpointId::from_bytes(reader.array()?);
    let target_id = NetworkEndpointId::from_bytes(reader.array()?);
    let owner = AdvancedNetworkIdentityV1::decode_recovery(reader.take(398)?, authorities)?;
    let external = decode_ingress_key(reader)?;
    let ports = NetworkPortRangeV1::new(reader.u16()?, reader.u16()?)
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    let count = usize::from(reader.byte()?);
    if count > MAXIMUM_ALLOWED_SOURCES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut sources = Vec::with_capacity(count);
    for _ in 0..count {
        sources.push(decode_ingress_prefix(reader)?);
    }
    PublishedIngressAllocationV1::new(allocation_id, target_id, owner, external, ports, sources)
}

fn encode_optional_allocation(bytes: &mut Vec<u8>, value: Option<&PublishedIngressAllocationV1>) {
    match value {
        Some(value) => {
            let mut encoded = Vec::new();
            encode_ingress_allocation(&mut encoded, value);
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        None => bytes.extend_from_slice(&0_u32.to_be_bytes()),
    }
}

fn decode_optional_allocation(
    reader: &mut IngressReader<'_>,
    authorities: &ProtectedRecoveryAuthoritiesV1,
) -> Result<Option<PublishedIngressAllocationV1>, AdvancedNetworkPolicyError> {
    let length =
        usize::try_from(reader.u32()?).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    if length == 0 {
        return Ok(None);
    }
    if length > 128 * 1024 {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut nested = IngressReader::new(reader.take(length)?);
    let value = decode_ingress_allocation(&mut nested, authorities)?;
    if !nested.finished() {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(Some(value))
}

fn encode_ingress_key(bytes: &mut Vec<u8>, key: ExternalIngressKeyV1) {
    bytes.extend_from_slice(&encode_address(key.address));
    bytes.extend_from_slice(&key.port.to_be_bytes());
    bytes.push(ingress_protocol_code(key.protocol));
}
fn decode_ingress_key(
    reader: &mut IngressReader<'_>,
) -> Result<ExternalIngressKeyV1, AdvancedNetworkPolicyError> {
    let address = decode_ingress_address(reader)?;
    let port = reader.u16()?;
    let protocol = decode_ingress_protocol(reader.byte()?)?;
    ExternalIngressKeyV1::new(address, port, protocol)
}
fn encode_ingress_prefix(bytes: &mut Vec<u8>, prefix: NetworkIpPrefixV1) {
    bytes.extend_from_slice(&encode_prefix(prefix));
}
fn decode_ingress_prefix(
    reader: &mut IngressReader<'_>,
) -> Result<NetworkIpPrefixV1, AdvancedNetworkPolicyError> {
    let family = reader.byte()?;
    let length = reader.byte()?;
    match family {
        4 => {
            let raw = reader.array::<16>()?;
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            NetworkIpPrefixV1::ipv4(
                raw[..4]
                    .try_into()
                    .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
                length,
            )
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
        }
        6 => NetworkIpPrefixV1::ipv6(reader.array()?, length)
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}
fn decode_ingress_address(
    reader: &mut IngressReader<'_>,
) -> Result<NetworkIpAddressV1, AdvancedNetworkPolicyError> {
    match reader.byte()? {
        4 => {
            let raw = reader.array::<16>()?;
            if raw[4..].iter().any(|byte| *byte != 0) {
                Err(AdvancedNetworkPolicyError::NonCanonical)
            } else {
                Ok(NetworkIpAddressV1::Ipv4(
                    raw[..4]
                        .try_into()
                        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
                ))
            }
        }
        6 => Ok(NetworkIpAddressV1::Ipv6(reader.array()?)),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}
fn ingress_protocol_code(value: NetworkTransportProtocolV1) -> u8 {
    match value {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    }
}
fn decode_ingress_protocol(
    value: u8,
) -> Result<NetworkTransportProtocolV1, AdvancedNetworkPolicyError> {
    match value {
        1 => Ok(NetworkTransportProtocolV1::Tcp),
        2 => Ok(NetworkTransportProtocolV1::Udp),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}

fn encode_external(value: ExternalIngressKeyV1) -> [u8; 20] {
    let mut bytes = [0; 20];
    match value.address {
        NetworkIpAddressV1::Ipv4(address) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address);
        }
        NetworkIpAddressV1::Ipv6(address) => {
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&address);
        }
    }
    bytes[17..19].copy_from_slice(&value.port.to_be_bytes());
    bytes[19] = match value.protocol {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    };
    bytes
}

fn encode_prefix(value: NetworkIpPrefixV1) -> [u8; 18] {
    let mut bytes = [0; 18];
    match value {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            bytes[0] = 4;
            bytes[1] = prefix_length;
            bytes[2..6].copy_from_slice(&network);
        }
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            bytes[0] = 6;
            bytes[1] = prefix_length;
            bytes[2..18].copy_from_slice(&network);
        }
    }
    bytes
}
