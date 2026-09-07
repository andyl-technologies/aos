//! Protected network-preparation catalog commitments.
//!
//! This increment models only pre-effect policy allocation: a protected policy
//! profile, canonical endpoint-policy bindings, and a broker-reserved opaque
//! result handle. It deliberately contains no speculative existing-resource or
//! kernel-identity model.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.network.catalog.prepare.v1\0";
const MAXIMUM_ENDPOINTS: usize = 256;

/// Opaque identity of one exact protected preparation resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkCatalogBindingV1 {
    generation: u64,
    digest: ObjectDigest,
}

impl NetworkCatalogBindingV1 {
    /// Returns the protected catalog generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the digest of exact preparation-resolution bytes.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Binds one logical endpoint to its exact local policy object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedEndpointV1 {
    id: [u8; 16],
    policy_digest: ObjectDigest,
}

impl ResolvedEndpointV1 {
    /// Constructs one nonzero endpoint resolution.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for a sentinel ID or digest.
    pub fn new(id: [u8; 16], policy_digest: ObjectDigest) -> Result<Self, CatalogError> {
        if id == [0; 16] || policy_digest.as_bytes() == &[0; 32] {
            Err(CatalogError)
        } else {
            Ok(Self { id, policy_digest })
        }
    }

    /// Returns the portable logical endpoint ID.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns the exact local policy-object digest for this endpoint.
    #[must_use]
    pub const fn policy_digest(&self) -> ObjectDigest {
        self.policy_digest
    }
}

/// Resolves protected pre-effect policy inputs for network preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNetworkPreparationV1 {
    binding: NetworkCatalogBindingV1,
    reserved_network_handle: [u8; 32],
    profile_digest: ObjectDigest,
    endpoints: Vec<ResolvedEndpointV1>,
}

impl ResolvedNetworkPreparationV1 {
    /// Constructs untrusted preparation-resolution data without kernel claims.
    ///
    /// The result is not catalog evidence. Production admission requires an
    /// [`AuthenticatedNetworkPreparationV1`] issued by the future protected
    /// catalog publisher.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for sentinels or noncanonical endpoints.
    pub fn new(
        generation: u64,
        reserved_network_handle: [u8; 32],
        profile_digest: ObjectDigest,
        endpoints: Vec<ResolvedEndpointV1>,
    ) -> Result<Self, CatalogError> {
        if generation == 0
            || reserved_network_handle == [0; 32]
            || profile_digest.as_bytes() == &[0; 32]
            || endpoints.is_empty()
            || endpoints.len() > MAXIMUM_ENDPOINTS
            || endpoints.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(CatalogError);
        }
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(generation.to_be_bytes());
        hasher.update(reserved_network_handle);
        hasher.update(profile_digest.as_bytes());
        hasher.update((endpoints.len() as u16).to_be_bytes());
        for endpoint in &endpoints {
            hasher.update(endpoint.id);
            hasher.update(endpoint.policy_digest.as_bytes());
        }
        Ok(Self {
            binding: NetworkCatalogBindingV1 {
                generation,
                digest: ObjectDigest::from_bytes(hasher.finalize().into()),
            },
            reserved_network_handle,
            profile_digest,
            endpoints,
        })
    }

    /// Returns the exact preparation binding.
    #[must_use]
    pub const fn binding(&self) -> NetworkCatalogBindingV1 {
        self.binding
    }

    /// Returns the protected broker-reserved result handle.
    #[must_use]
    pub const fn reserved_network_handle(&self) -> &[u8; 32] {
        &self.reserved_network_handle
    }

    /// Returns the exact selected policy-profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> ObjectDigest {
        self.profile_digest
    }

    /// Returns the exact canonical endpoint resolutions.
    #[must_use]
    pub fn endpoints(&self) -> &[ResolvedEndpointV1] {
        &self.endpoints
    }
}

/// Carries one authority-authenticated protected preparation resolution.
///
/// No production constructor exists in this increment: a future distinct
/// root-owned catalog publisher must issue this token from its protected
/// snapshot. Consequently, Apply remains unreachable and unadvertised.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedNetworkPreparationV1 {
    pub(crate) resolution: ResolvedNetworkPreparationV1,
    pub(crate) sealed: Vec<u8>,
}

impl AuthenticatedNetworkPreparationV1 {
    /// Returns the authenticated preparation resolution.
    #[must_use]
    pub const fn resolution(&self) -> &ResolvedNetworkPreparationV1 {
        &self.resolution
    }
}

pub(crate) fn encode_resolution(catalog: &ResolvedNetworkPreparationV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(80 + catalog.endpoints().len() * 48);
    bytes.extend_from_slice(&catalog.binding().generation().to_be_bytes());
    bytes.extend_from_slice(catalog.reserved_network_handle());
    bytes.extend_from_slice(catalog.profile_digest().as_bytes());
    bytes.extend_from_slice(&(catalog.endpoints().len() as u16).to_be_bytes());
    for endpoint in catalog.endpoints() {
        bytes.extend_from_slice(endpoint.id());
        bytes.extend_from_slice(endpoint.policy_digest().as_bytes());
    }
    bytes
}

/// Reports invalid preparation catalog data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("network preparation catalog resolution is invalid")]
pub struct CatalogError;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn preparation_has_no_kernel_identity_input() {
        let resolution = ResolvedNetworkPreparationV1::new(
            1,
            [3; 32],
            ObjectDigest::from_bytes([4; 32]),
            vec![ResolvedEndpointV1::new([1; 16], ObjectDigest::from_bytes([2; 32])).unwrap()],
        )
        .unwrap();
        assert_eq!(resolution.endpoints().len(), 1);
    }

    fn resolution(
        generation: u64,
        handle: u8,
        profile: u8,
        endpoints: Vec<ResolvedEndpointV1>,
    ) -> ResolvedNetworkPreparationV1 {
        ResolvedNetworkPreparationV1::new(
            generation,
            [handle; 32],
            ObjectDigest::from_bytes([profile; 32]),
            endpoints,
        )
        .unwrap()
    }

    #[test]
    fn preparation_rejects_empty_duplicate_unsorted_and_oversized_endpoints() {
        assert!(
            ResolvedNetworkPreparationV1::new(
                1,
                [3; 32],
                ObjectDigest::from_bytes([4; 32]),
                Vec::new(),
            )
            .is_err()
        );
        let first = ResolvedEndpointV1::new([1; 16], ObjectDigest::from_bytes([2; 32])).unwrap();
        let second = ResolvedEndpointV1::new([2; 16], ObjectDigest::from_bytes([3; 32])).unwrap();
        assert!(
            ResolvedNetworkPreparationV1::new(
                1,
                [3; 32],
                ObjectDigest::from_bytes([4; 32]),
                vec![first, first],
            )
            .is_err()
        );
        assert!(
            ResolvedNetworkPreparationV1::new(
                1,
                [3; 32],
                ObjectDigest::from_bytes([4; 32]),
                vec![second, first],
            )
            .is_err()
        );
        let oversized = (1_u16..=257)
            .map(|id| {
                let mut bytes = [0; 16];
                bytes[14..].copy_from_slice(&id.to_be_bytes());
                ResolvedEndpointV1::new(bytes, ObjectDigest::from_bytes([5; 32])).unwrap()
            })
            .collect();
        assert!(
            ResolvedNetworkPreparationV1::new(
                1,
                [3; 32],
                ObjectDigest::from_bytes([4; 32]),
                oversized,
            )
            .is_err()
        );
    }

    #[test]
    fn preparation_digest_binds_every_field() {
        let endpoint = ResolvedEndpointV1::new([1; 16], ObjectDigest::from_bytes([2; 32])).unwrap();
        let original = resolution(1, 3, 4, vec![endpoint]).binding().digest();
        let variants = [
            resolution(2, 3, 4, vec![endpoint]),
            resolution(1, 5, 4, vec![endpoint]),
            resolution(1, 3, 6, vec![endpoint]),
            resolution(
                1,
                3,
                4,
                vec![ResolvedEndpointV1::new([1; 16], ObjectDigest::from_bytes([7; 32])).unwrap()],
            ),
            resolution(
                1,
                3,
                4,
                vec![ResolvedEndpointV1::new([8; 16], ObjectDigest::from_bytes([2; 32])).unwrap()],
            ),
        ];
        assert!(
            variants
                .iter()
                .all(|value| value.binding().digest() != original)
        );
    }
}
