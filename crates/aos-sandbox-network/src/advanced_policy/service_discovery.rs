//! Immutable project service-discovery snapshots.
//!
//! A snapshot is a bounded, strictly ordered map from portable service IDs to
//! exact logical endpoints and address/port tuples. Its project, generation,
//! contents, and digest are immutable. Consumers must carry a
//! [`ServiceDiscoveryExpectationV1`] and reject a non-exact snapshot rather
//! than silently resolving against newer or foreign project state.

use aos_sandbox_core::{NetworkEndpointId, ObjectDigest, ProjectId, SandboxId, ServiceId};
use sha2::{Digest as _, Sha256};

use crate::policy::{NetworkIpPrefixV1, NetworkPortRangeV1, NetworkTransportProtocolV1};

use super::identity::{
    ProtectedCurrentnessWitnessV1, ProtectedRecoveryAuthoritiesV1, ProtectedWitnessPurposeV1,
    project_namespace,
};
use super::{AdvancedNetworkPolicyError, nonzero_digest, strictly_increasing};

const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.service-discovery.v1\0";
const MAXIMUM_PROJECT_SERVICES: usize = 256;
const MAXIMUM_ADDRESSES_PER_SERVICE: usize = 16;
const MAXIMUM_DISCLOSED_SANDBOXES: usize = 256;

/// Carries protected publisher, lease, revocation, and sibling disclosure authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServicePublicationAuthorityV1 {
    publisher: SandboxId,
    publisher_assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    revocation_generation: u64,
    disclosed_sandboxes: Vec<SandboxId>,
}

impl ServicePublicationAuthorityV1 {
    /// Constructs one bounded service-publication authority record.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for sentinel publisher, lease, or
    /// assignment state, a lease not newer than the revocation high-water, or
    /// noncanonical disclosure membership.
    pub fn new(
        publisher: SandboxId,
        publisher_assignment_digest: ObjectDigest,
        lease_generation: u64,
        lease_digest: ObjectDigest,
        revocation_generation: u64,
        disclosed_sandboxes: Vec<SandboxId>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if publisher.as_bytes() == &[0; 16]
            || !nonzero_digest(publisher_assignment_digest)
            || lease_generation == 0
            || !nonzero_digest(lease_digest)
        {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        if lease_generation <= revocation_generation {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        if disclosed_sandboxes.is_empty()
            || disclosed_sandboxes.len() > MAXIMUM_DISCLOSED_SANDBOXES
            || !strictly_increasing(&disclosed_sandboxes)
            || disclosed_sandboxes
                .iter()
                .any(|sandbox| sandbox.as_bytes() == &[0; 16])
        {
            return Err(AdvancedNetworkPolicyError::DisclosureDenied);
        }
        Ok(Self {
            publisher,
            publisher_assignment_digest,
            lease_generation,
            lease_digest,
            revocation_generation,
            disclosed_sandboxes,
        })
    }

    /// Reports whether one sibling sandbox is explicitly disclosed.
    #[must_use]
    pub fn discloses(&self, sandbox: SandboxId) -> bool {
        self.disclosed_sandboxes.binary_search(&sandbox).is_ok()
    }

    /// Returns the publishing sandbox identity.
    #[must_use]
    pub const fn publisher(&self) -> SandboxId {
        self.publisher
    }

    /// Returns the publisher assignment commitment.
    #[must_use]
    pub const fn publisher_assignment_digest(&self) -> ObjectDigest {
        self.publisher_assignment_digest
    }

    /// Returns the protected publication lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the protected publication lease commitment.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the observed revocation high-water preceding this live lease.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns explicitly disclosed sibling sandboxes.
    #[must_use]
    pub fn disclosed_sandboxes(&self) -> &[SandboxId] {
        &self.disclosed_sandboxes
    }
}

/// Describes one exact TCP or UDP address advertised by a project service.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectServiceAddressV1 {
    protocol: NetworkTransportProtocolV1,
    address: NetworkIpPrefixV1,
    ports: NetworkPortRangeV1,
}

impl ProjectServiceAddressV1 {
    /// Constructs one exact host-prefix service address and port range.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] unless the
    /// protocol is TCP or UDP and the address is a nonzero exact `/32` or
    /// `/128` host prefix.
    pub fn new(
        protocol: NetworkTransportProtocolV1,
        address: NetworkIpPrefixV1,
        ports: NetworkPortRangeV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let exact_address = matches!(
            address,
            NetworkIpPrefixV1::Ipv4 {
                prefix_length: 32,
                ..
            } | NetworkIpPrefixV1::Ipv6 {
                prefix_length: 128,
                ..
            }
        );
        let nonzero_address = match address {
            NetworkIpPrefixV1::Ipv4 { network, .. } => network != [0; 4],
            NetworkIpPrefixV1::Ipv6 { network, .. } => network != [0; 16],
        };
        if !address.is_canonical()
            || !matches!(
                protocol,
                NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp
            )
            || !exact_address
            || !nonzero_address
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        Ok(Self {
            protocol,
            address,
            ports,
        })
    }

    /// Returns the closed transport protocol.
    #[must_use]
    pub const fn protocol(self) -> NetworkTransportProtocolV1 {
        self.protocol
    }

    /// Returns the exact canonical host prefix.
    #[must_use]
    pub const fn address(self) -> NetworkIpPrefixV1 {
        self.address
    }

    /// Returns the advertised destination-port range.
    #[must_use]
    pub const fn ports(self) -> NetworkPortRangeV1 {
        self.ports
    }
}

/// Resolves one portable service ID to one endpoint and canonical address set.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscoveredProjectServiceV1 {
    service_id: ServiceId,
    endpoint_id: NetworkEndpointId,
    addresses: Vec<ProjectServiceAddressV1>,
    authority: ServicePublicationAuthorityV1,
}

impl DiscoveredProjectServiceV1 {
    /// Constructs one nonempty, bounded service resolution.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for sentinel identities or an
    /// empty, oversized, duplicated, or unordered address set.
    pub fn new(
        service_id: ServiceId,
        endpoint_id: NetworkEndpointId,
        addresses: Vec<ProjectServiceAddressV1>,
        authority: ServicePublicationAuthorityV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if service_id.as_bytes() == &[0; 16] || endpoint_id.as_bytes() == &[0; 16] {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        if addresses.is_empty()
            || addresses.len() > MAXIMUM_ADDRESSES_PER_SERVICE
            || !strictly_increasing(&addresses)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        Ok(Self {
            service_id,
            endpoint_id,
            addresses,
            authority,
        })
    }

    /// Returns the portable project service identity.
    #[must_use]
    pub const fn service_id(&self) -> ServiceId {
        self.service_id
    }

    /// Returns the logical Network endpoint receiving the service flows.
    #[must_use]
    pub const fn endpoint_id(&self) -> NetworkEndpointId {
        self.endpoint_id
    }

    /// Returns the canonical immutable address set.
    #[must_use]
    pub fn addresses(&self) -> &[ProjectServiceAddressV1] {
        &self.addresses
    }

    /// Returns protected publisher, lease, revocation, and disclosure state.
    #[must_use]
    pub const fn authority(&self) -> &ServicePublicationAuthorityV1 {
        &self.authority
    }
}

/// Commits the exact project discovery snapshot a policy was compiled against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDiscoveryExpectationV1 {
    project: ProjectId,
    generation: u64,
    snapshot_digest: ObjectDigest,
}

impl ServiceDiscoveryExpectationV1 {
    /// Constructs an exact immutable snapshot expectation.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unspecified`] for a sentinel
    /// project, zero generation, or zero digest.
    pub fn new(
        project: ProjectId,
        generation: u64,
        snapshot_digest: ObjectDigest,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if project.as_bytes() == &[0; 16] || generation == 0 || !nonzero_digest(snapshot_digest) {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }

        Ok(Self {
            project,
            generation,
            snapshot_digest,
        })
    }

    /// Returns the expected project authority domain.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact expected discovery generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact expected snapshot digest.
    #[must_use]
    pub const fn snapshot_digest(self) -> ObjectDigest {
        self.snapshot_digest
    }
}

/// Stores one immutable, canonical project service-discovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectServiceDiscoverySnapshotV1 {
    project: ProjectId,
    generation: u64,
    services: Vec<DiscoveredProjectServiceV1>,
    currentness: ProtectedCurrentnessWitnessV1,
    digest: ObjectDigest,
}

impl ProjectServiceDiscoverySnapshotV1 {
    /// Computes the commitment a protected owner must witness.
    #[must_use]
    pub fn commitment(
        project: ProjectId,
        generation: u64,
        services: &[DiscoveredProjectServiceV1],
    ) -> ObjectDigest {
        snapshot_digest(project, generation, services)
    }

    /// Constructs a bounded immutable project discovery snapshot.
    ///
    /// Empty snapshots are valid and mean that no project service is currently
    /// discoverable. Nonempty entries must be in strict service-ID order.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for a sentinel project, zero
    /// generation, excess services, duplicate IDs, or unordered entries.
    pub fn new(
        project: ProjectId,
        generation: u64,
        services: Vec<DiscoveredProjectServiceV1>,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if project.as_bytes() == &[0; 16] || generation == 0 {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        if services.len() > MAXIMUM_PROJECT_SERVICES
            || services
                .windows(2)
                .any(|pair| pair[0].service_id >= pair[1].service_id)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        let digest = snapshot_digest(project, generation, &services);
        if currentness.purpose() != ProtectedWitnessPurposeV1::Discovery
            || currentness.namespace() != project_namespace(project)
            || currentness.record_digest() != digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        Ok(Self {
            project,
            generation,
            services,
            currentness,
            digest,
        })
    }

    /// Returns the snapshot's project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the immutable project-local generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the canonical service map.
    #[must_use]
    pub fn services(&self) -> &[DiscoveredProjectServiceV1] {
        &self.services
    }

    /// Returns the domain-separated snapshot commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the protected snapshot-currentness witness.
    #[must_use]
    pub const fn currentness(&self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }

    /// Verifies that every selected service discloses to `consumer`.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::DisclosureDenied`] when a service
    /// is not authorized to the named sibling sandbox.
    pub fn verify_disclosure(&self, consumer: SandboxId) -> Result<(), AdvancedNetworkPolicyError> {
        if self
            .services
            .iter()
            .any(|service| !service.authority.discloses(consumer))
        {
            return Err(AdvancedNetworkPolicyError::DisclosureDenied);
        }
        Ok(())
    }

    /// Returns the exact expectation represented by this snapshot.
    #[must_use]
    pub const fn expectation(&self) -> ServiceDiscoveryExpectationV1 {
        ServiceDiscoveryExpectationV1 {
            project: self.project,
            generation: self.generation,
            snapshot_digest: self.digest,
        }
    }

    /// Verifies that this is exactly the snapshot selected by a policy.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::StaleServiceDiscovery`] for any
    /// project, generation, or digest mismatch.
    pub fn verify_current(
        &self,
        expectation: ServiceDiscoveryExpectationV1,
    ) -> Result<(), AdvancedNetworkPolicyError> {
        if self.expectation() != expectation {
            return Err(AdvancedNetworkPolicyError::StaleServiceDiscovery);
        }
        Ok(())
    }

    /// Resolves one exact service ID without accepting aliases.
    #[must_use]
    pub fn service(&self, service_id: ServiceId) -> Option<&DiscoveredProjectServiceV1> {
        self.services
            .binary_search_by_key(&service_id, DiscoveredProjectServiceV1::service_id)
            .ok()
            .and_then(|index| self.services.get(index))
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSASD01");
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.currentness.encode_recovery());
        bytes.extend_from_slice(&(self.services.len() as u16).to_be_bytes());
        for service in &self.services {
            bytes.extend_from_slice(service.service_id.as_bytes());
            bytes.extend_from_slice(service.endpoint_id.as_bytes());
            let authority = &service.authority;
            bytes.extend_from_slice(authority.publisher.as_bytes());
            bytes.extend_from_slice(authority.publisher_assignment_digest.as_bytes());
            bytes.extend_from_slice(&authority.lease_generation.to_be_bytes());
            bytes.extend_from_slice(authority.lease_digest.as_bytes());
            bytes.extend_from_slice(&authority.revocation_generation.to_be_bytes());
            bytes.extend_from_slice(&(authority.disclosed_sandboxes.len() as u16).to_be_bytes());
            for sandbox in &authority.disclosed_sandboxes {
                bytes.extend_from_slice(sandbox.as_bytes());
            }
            bytes.push(service.addresses.len() as u8);
            for address in &service.addresses {
                bytes.push(discovery_protocol_code(address.protocol));
                encode_discovery_prefix(&mut bytes, address.address);
                bytes.extend_from_slice(&address.ports.first().to_be_bytes());
                bytes.extend_from_slice(&address.ports.last().to_be_bytes());
            }
        }
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 2 * 1024 * 1024 || bytes.get(..8) != Some(b"AOSASD01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = DiscoveryReader::new(&bytes[8..]);
        let project = ProjectId::from_bytes(reader.array()?);
        let generation = reader.u64()?;
        let currentness =
            ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
        let count = usize::from(reader.u16()?);
        if count > MAXIMUM_PROJECT_SERVICES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut services = Vec::with_capacity(count);
        for _ in 0..count {
            let service_id = ServiceId::from_bytes(reader.array()?);
            let endpoint_id = NetworkEndpointId::from_bytes(reader.array()?);
            let publisher = SandboxId::from_bytes(reader.array()?);
            let publisher_assignment = ObjectDigest::from_bytes(reader.array()?);
            let lease_generation = reader.u64()?;
            let lease_digest = ObjectDigest::from_bytes(reader.array()?);
            let revocation_generation = reader.u64()?;
            let disclosure_count = usize::from(reader.u16()?);
            if disclosure_count > MAXIMUM_DISCLOSED_SANDBOXES {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            let mut disclosures = Vec::with_capacity(disclosure_count);
            for _ in 0..disclosure_count {
                disclosures.push(SandboxId::from_bytes(reader.array()?));
            }
            let authority = ServicePublicationAuthorityV1::new(
                publisher,
                publisher_assignment,
                lease_generation,
                lease_digest,
                revocation_generation,
                disclosures,
            )?;
            let address_count = usize::from(reader.byte()?);
            if address_count > MAXIMUM_ADDRESSES_PER_SERVICE {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            let mut addresses = Vec::with_capacity(address_count);
            for _ in 0..address_count {
                let protocol = decode_discovery_protocol(reader.byte()?)?;
                let prefix = decode_discovery_prefix(&mut reader)?;
                let ports = NetworkPortRangeV1::new(reader.u16()?, reader.u16()?)
                    .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
                addresses.push(ProjectServiceAddressV1::new(protocol, prefix, ports)?);
            }
            services.push(DiscoveredProjectServiceV1::new(
                service_id,
                endpoint_id,
                addresses,
                authority,
            )?);
        }
        if !reader.finished() {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::new(project, generation, services, currentness)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

struct DiscoveryReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> DiscoveryReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], AdvancedNetworkPolicyError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AdvancedNetworkPolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
    }
    fn byte(&mut self) -> Result<u8, AdvancedNetworkPolicyError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, AdvancedNetworkPolicyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, AdvancedNetworkPolicyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn encode_discovery_prefix(bytes: &mut Vec<u8>, prefix: NetworkIpPrefixV1) {
    match prefix {
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
}
fn decode_discovery_prefix(
    reader: &mut DiscoveryReader<'_>,
) -> Result<NetworkIpPrefixV1, AdvancedNetworkPolicyError> {
    let family = reader.byte()?;
    let length = reader.byte()?;
    match family {
        4 => NetworkIpPrefixV1::ipv4(reader.array()?, length)
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical),
        6 => NetworkIpPrefixV1::ipv6(reader.array()?, length)
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}
fn discovery_protocol_code(value: NetworkTransportProtocolV1) -> u8 {
    match value {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    }
}
fn decode_discovery_protocol(
    value: u8,
) -> Result<NetworkTransportProtocolV1, AdvancedNetworkPolicyError> {
    match value {
        1 => Ok(NetworkTransportProtocolV1::Tcp),
        2 => Ok(NetworkTransportProtocolV1::Udp),
        _ => Err(AdvancedNetworkPolicyError::NonCanonical),
    }
}

fn snapshot_digest(
    project: ProjectId,
    generation: u64,
    services: &[DiscoveredProjectServiceV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_DIGEST_DOMAIN);
    digest.update(project.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update((services.len() as u16).to_be_bytes());
    for service in services {
        digest.update(service.service_id.as_bytes());
        digest.update(service.endpoint_id.as_bytes());
        digest.update(service.authority.publisher.as_bytes());
        digest.update(service.authority.publisher_assignment_digest.as_bytes());
        digest.update(service.authority.lease_generation.to_be_bytes());
        digest.update(service.authority.lease_digest.as_bytes());
        digest.update(service.authority.revocation_generation.to_be_bytes());
        digest.update((service.authority.disclosed_sandboxes.len() as u16).to_be_bytes());
        for sandbox in &service.authority.disclosed_sandboxes {
            digest.update(sandbox.as_bytes());
        }
        digest.update((service.addresses.len() as u16).to_be_bytes());
        for address in &service.addresses {
            digest.update(encode_address(*address));
        }
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_address(address: ProjectServiceAddressV1) -> [u8; 23] {
    let mut encoded = [0_u8; 23];
    encoded[0] = match address.protocol {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    };
    match address.address {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => {
            encoded[1] = 4;
            encoded[2] = prefix_length;
            encoded[3..7].copy_from_slice(&network);
        }
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => {
            encoded[1] = 6;
            encoded[2] = prefix_length;
            encoded[3..19].copy_from_slice(&network);
        }
    }
    encoded[19..21].copy_from_slice(&address.ports.first().to_be_bytes());
    encoded[21..23].copy_from_slice(&address.ports.last().to_be_bytes());
    encoded
}
