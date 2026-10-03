//! Mediated, default-deny egress policy.
//!
//! Callers cannot supply arbitrary remote prefixes. Each admitted destination
//! names one exact project service and protocol in an immutable discovery
//! snapshot. The compiler resolves addresses only from that snapshot; every
//! destination not present in the canonical allow set remains denied.

use aos_sandbox_core::{NetworkEndpointId, ObjectDigest, ServiceId};
use sha2::{Digest as _, Sha256};

use crate::policy::NetworkTransportProtocolV1;

use super::service_discovery::ServiceDiscoveryExpectationV1;
use super::{AdvancedNetworkPolicyError, strictly_increasing};

const EGRESS_POLICY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.mediated-egress.v1\0";
const MAXIMUM_MEDIATED_DESTINATIONS: usize = 256;

/// Selects one protocol of one exact project service as an egress destination.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MediatedEgressDestinationV1 {
    service_id: ServiceId,
    endpoint_id: NetworkEndpointId,
    protocol: NetworkTransportProtocolV1,
}

impl MediatedEgressDestinationV1 {
    /// Constructs one project-service-mediated destination.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for a sentinel service or
    /// endpoint identity, or for a protocol other than TCP or UDP.
    pub fn new(
        service_id: ServiceId,
        endpoint_id: NetworkEndpointId,
        protocol: NetworkTransportProtocolV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if service_id.as_bytes() == &[0; 16] || endpoint_id.as_bytes() == &[0; 16] {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        if !matches!(
            protocol,
            NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp
        ) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        Ok(Self {
            service_id,
            endpoint_id,
            protocol,
        })
    }

    /// Returns the immutable project service identity.
    #[must_use]
    pub const fn service_id(self) -> ServiceId {
        self.service_id
    }

    /// Returns the expected logical endpoint identity.
    #[must_use]
    pub const fn endpoint_id(self) -> NetworkEndpointId {
        self.endpoint_id
    }

    /// Returns the selected TCP or UDP protocol.
    #[must_use]
    pub const fn protocol(self) -> NetworkTransportProtocolV1 {
        self.protocol
    }
}

/// Stores a bounded egress allow set tied to one discovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediatedEgressPolicyV1 {
    discovery: ServiceDiscoveryExpectationV1,
    destinations: Vec<MediatedEgressDestinationV1>,
    digest: ObjectDigest,
}

impl MediatedEgressPolicyV1 {
    /// Constructs one canonical project-mediated egress policy.
    ///
    /// An empty destination set is valid and represents explicit default deny.
    /// Nonempty destinations must be strictly ordered by service, endpoint, and
    /// protocol.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::NonCanonical`] for an oversized,
    /// duplicated, or unordered destination set.
    pub fn new(
        discovery: ServiceDiscoveryExpectationV1,
        destinations: Vec<MediatedEgressDestinationV1>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if destinations.len() > MAXIMUM_MEDIATED_DESTINATIONS || !strictly_increasing(&destinations)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        let digest = egress_digest(discovery, &destinations);
        Ok(Self {
            discovery,
            destinations,
            digest,
        })
    }

    /// Returns the exact project discovery snapshot expectation.
    #[must_use]
    pub const fn discovery(&self) -> ServiceDiscoveryExpectationV1 {
        self.discovery
    }

    /// Returns the complete egress allow set.
    #[must_use]
    pub fn destinations(&self) -> &[MediatedEgressDestinationV1] {
        &self.destinations
    }

    /// Reports whether this policy denies every egress destination.
    #[must_use]
    pub fn is_default_deny(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Returns the domain-separated egress-policy commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(66 + self.destinations.len() * 33);
        bytes.extend_from_slice(b"AOSAEG01");
        bytes.extend_from_slice(self.discovery.project().as_bytes());
        bytes.extend_from_slice(&self.discovery.generation().to_be_bytes());
        bytes.extend_from_slice(self.discovery.snapshot_digest().as_bytes());
        bytes.extend_from_slice(&(self.destinations.len() as u16).to_be_bytes());
        for destination in &self.destinations {
            bytes.extend_from_slice(destination.service_id.as_bytes());
            bytes.extend_from_slice(destination.endpoint_id.as_bytes());
            bytes.push(protocol_code(destination.protocol));
        }
        bytes
    }

    pub(crate) fn decode_recovery(bytes: &[u8]) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() < 66 || bytes.len() > 8_514 || bytes.get(..8) != Some(b"AOSAEG01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let project = aos_sandbox_core::ProjectId::from_bytes(
            bytes[8..24]
                .try_into()
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
        let generation = u64::from_be_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
        let snapshot = ObjectDigest::from_bytes(
            bytes[32..64]
                .try_into()
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
        let count = usize::from(u16::from_be_bytes(
            bytes[64..66]
                .try_into()
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        ));
        let expected = 66_usize
            .checked_add(
                count
                    .checked_mul(33)
                    .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
            )
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        if count > MAXIMUM_MEDIATED_DESTINATIONS || bytes.len() != expected {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let expectation = ServiceDiscoveryExpectationV1::new(project, generation, snapshot)?;
        let mut destinations = Vec::with_capacity(count);
        let mut cursor = 66;
        for _ in 0..count {
            let service = ServiceId::from_bytes(
                bytes[cursor..cursor + 16]
                    .try_into()
                    .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
            );
            let endpoint = NetworkEndpointId::from_bytes(
                bytes[cursor + 16..cursor + 32]
                    .try_into()
                    .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
            );
            let protocol = match bytes[cursor + 32] {
                1 => NetworkTransportProtocolV1::Tcp,
                2 => NetworkTransportProtocolV1::Udp,
                _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
            };
            destinations.push(MediatedEgressDestinationV1::new(
                service, endpoint, protocol,
            )?);
            cursor += 33;
        }
        let value = Self::new(expectation, destinations)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

fn egress_digest(
    discovery: ServiceDiscoveryExpectationV1,
    destinations: &[MediatedEgressDestinationV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(EGRESS_POLICY_DIGEST_DOMAIN);
    digest.update(discovery.project().as_bytes());
    digest.update(discovery.generation().to_be_bytes());
    digest.update(discovery.snapshot_digest().as_bytes());
    digest.update((destinations.len() as u16).to_be_bytes());
    for destination in destinations {
        digest.update(destination.service_id.as_bytes());
        digest.update(destination.endpoint_id.as_bytes());
        digest.update([protocol_code(destination.protocol)]);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn protocol_code(protocol: NetworkTransportProtocolV1) -> u8 {
    match protocol {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    }
}
