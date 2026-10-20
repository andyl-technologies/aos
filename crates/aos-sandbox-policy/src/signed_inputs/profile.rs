//! Normalizes explicit typed deployment declarations and checks signed bytes.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::policy_data::canonical_bytes;
use crate::{
    BackendCapabilitiesV1, EndpointCatalogEntryV1, NamespaceDestinationV1, NodePolicyInputV1,
    SitePolicyInputV1, canonical_endpoint_catalog_v1, canonical_namespace_catalog_v1,
};
use super::deployment::{
    MAXIMUM_INPUT_BYTES, PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, verify_historical_packet,
};
use super::{SignedPolicyInputDataErrorV1, read_i64, read_u64};

/// Separates the four existing typed deployment declaration preimages.
pub const INPUT_DOMAINS: [&[u8]; 4] = [
    b"aos.sandbox.policy-deployment-input.node.v2",
    b"aos.sandbox.policy-deployment-input.site.v2",
    b"aos.sandbox.policy-deployment-input.backend.v2",
    b"aos.sandbox.policy-deployment-input.catalogs.v2",
];

/// Retains closed catalog declarations without current-owner authentication.
#[derive(Clone, Debug)]
pub struct PolicyDeploymentCatalogDeclarationsV2 {
    endpoints: Vec<EndpointCatalogEntryV1>,
    destinations: Vec<NamespaceDestinationV1>,
    endpoint_descriptor: ObjectDescriptor,
    destination_descriptor: ObjectDescriptor,
}

impl PolicyDeploymentCatalogDeclarationsV2 {
    /// Validates declarations using the existing catalog shape and byte codecs.
    ///
    /// # Errors
    ///
    /// Rejects unordered, duplicated, sentinel, or oversized declarations.
    /// This constructor does not produce authenticated compiler catalogs.
    pub fn new(
        endpoints: Vec<EndpointCatalogEntryV1>,
        destinations: Vec<NamespaceDestinationV1>,
    ) -> Result<Self, SignedPolicyInputDataErrorV1> {
        let (endpoint_descriptor, _) = canonical_endpoint_catalog_v1(&endpoints)
            .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
        let (destination_descriptor, _) = canonical_namespace_catalog_v1(&destinations)
            .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
        Ok(Self {
            endpoints,
            destinations,
            endpoint_descriptor,
            destination_descriptor,
        })
    }

    /// Returns declared endpoint bindings, not a live-owner catalog proof.
    #[must_use]
    pub fn endpoints(&self) -> &[EndpointCatalogEntryV1] {
        &self.endpoints
    }

    /// Returns declared destination bindings, not a live-owner catalog proof.
    #[must_use]
    pub fn destinations(&self) -> &[NamespaceDestinationV1] {
        &self.destinations
    }

    /// Returns the exact canonical endpoint-declaration descriptor.
    #[must_use]
    pub const fn endpoint_descriptor(&self) -> &ObjectDescriptor {
        &self.endpoint_descriptor
    }

    /// Returns the exact canonical destination-declaration descriptor.
    #[must_use]
    pub const fn destination_descriptor(&self) -> &ObjectDescriptor {
        &self.destination_descriptor
    }
}

/// Retains explicit normalized inputs for the versioned deployment profile.
///
/// All fields are supplied as existing constructor-validated compiler models.
/// No grant, namespace rule, backend feature, or catalog entry is defaulted.
/// This declaration contains no project/request mapping or live owner proof.
#[derive(Clone, Debug)]
pub struct PolicyDeploymentInputProfileV2 {
    generation: u64,
    signer_generation: u64,
    node: NodePolicyInputV1,
    site: SitePolicyInputV1,
    backend: BackendCapabilitiesV1,
    catalogs: PolicyDeploymentCatalogDeclarationsV2,
}

impl PolicyDeploymentInputProfileV2 {
    /// Constructs explicit typed declarations for one deployment generation.
    ///
    /// # Errors
    ///
    /// Rejects zero generations or any canonical input above the unchanged
    /// 64-KiB per-input bound. Policy constructors retain their own stricter
    /// semantic checks, including rejection of unregistered Profile selectors.
    pub fn new(
        generation: u64,
        signer_generation: u64,
        node: NodePolicyInputV1,
        site: SitePolicyInputV1,
        backend: BackendCapabilitiesV1,
        catalogs: PolicyDeploymentCatalogDeclarationsV2,
    ) -> Result<Self, SignedPolicyInputDataErrorV1> {
        if generation == 0 || signer_generation == 0 {
            return Err(SignedPolicyInputDataErrorV1::InvalidHead);
        }
        let profile = Self {
            generation,
            signer_generation,
            node,
            site,
            backend,
            catalogs,
        };
        profile.canonical_inputs()?;
        Ok(profile)
    }

    /// Returns the declared head generation, not a rollback-floor proof.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the signer generation that verification must independently pin.
    #[must_use]
    pub const fn signer_generation(&self) -> u64 {
        self.signer_generation
    }

    /// Returns the complete declared Node ceiling.
    #[must_use]
    pub const fn node(&self) -> &NodePolicyInputV1 {
        &self.node
    }

    /// Returns the complete declared Site ceiling.
    #[must_use]
    pub const fn site(&self) -> &SitePolicyInputV1 {
        &self.site
    }

    /// Returns backend declarations, not installed enforcement evidence.
    #[must_use]
    pub const fn backend(&self) -> &BackendCapabilitiesV1 {
        &self.backend
    }

    /// Returns catalog declarations requiring separate live-owner verification.
    #[must_use]
    pub const fn catalogs(&self) -> &PolicyDeploymentCatalogDeclarationsV2 {
        &self.catalogs
    }

    /// Encodes all four inputs with the existing typed canonical serializer.
    ///
    /// # Errors
    ///
    /// Rejects serialization failure or a per-input bound violation. The bytes
    /// become signed declarations only after the exact deployment head verifies.
    pub fn canonical_inputs(&self) -> Result<[Vec<u8>; 4], SignedPolicyInputDataErrorV1> {
        let prefix = (2_u16, self.generation, self.signer_generation);
        let inputs = [
            canonical_bytes(INPUT_DOMAINS[0], &(prefix, self.node.layer())),
            canonical_bytes(INPUT_DOMAINS[1], &(prefix, self.site.layer())),
            canonical_bytes(INPUT_DOMAINS[2], &(prefix, &self.backend)),
            canonical_bytes(
                INPUT_DOMAINS[3],
                &(
                    prefix,
                    (
                        &self.catalogs.endpoint_descriptor,
                        &self.catalogs.endpoints,
                        &self.catalogs.destination_descriptor,
                        &self.catalogs.destinations,
                    ),
                ),
            ),
        ];
        let [node, site, backend, catalogs] = inputs.map(|result| {
            let bytes = result.map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
            if bytes.len() > MAXIMUM_INPUT_BYTES {
                return Err(SignedPolicyInputDataErrorV1::InvalidHead);
            }
            Ok(bytes)
        });
        Ok([node?, site?, backend?, catalogs?])
    }
}

/// Checks signed deployment bytes against explicit normalized declarations.
///
/// The supplied key and declarations remain comparison DATA; protected pins and
/// current native owner admission are independent.
///
/// # Errors
///
/// Rejects a declaration mismatch, malformed signature/framing, expired packet
/// or any mismatch between the signed digests and canonical typed declarations.
pub fn verify_policy_deployment_profile_data_v2(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, SignedPolicyInputDataErrorV1> {
    let expected = profile.canonical_inputs()?;
    let provided = [inputs.node, inputs.site, inputs.backend, inputs.catalogs];
    if provided
        .into_iter()
        .zip(&expected)
        .any(|(bytes, exact)| bytes != exact)
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    verify_historical_packet(packet, verifying_key)?;
    let issued_at = read_i64(packet, 16)?;
    let expires_at = read_i64(packet, 24)?;
    if read_u64(packet, 8)? != profile.generation
        || issued_at > now_unix_seconds
        || now_unix_seconds >= expires_at
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let input_digests: [[u8; 32]; 4] = expected
        .each_ref()
        .map(|input| Sha256::digest(input).into());
    for (index, digest) in input_digests.iter().enumerate() {
        if packet.get(32 + index * 32..64 + index * 32) != Some(digest.as_slice()) {
            return Err(SignedPolicyInputDataErrorV1::InvalidHead);
        }
    }
    Ok(PolicyDeploymentHeadV1 {
        generation: profile.generation,
        expires_at,
        packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
        input_digests,
    })
}
