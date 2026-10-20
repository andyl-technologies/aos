//! Decodes the exact signed deployment head and bounded V1 typed inputs.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId, ResourceDimension,
};
use aos_sandbox_protocol::policy_data::canonical_bytes;
use crate::{
    AuthenticatedEndpointCatalogV1, AuthenticatedNamespaceCatalogV1, BackendCapabilitiesV1,
    BackendEnforcementSetV1, EndpointCatalogEntryV1, EndpointCatalogVerifierV1, HardEnforcementV1,
    HardLimitRequestV1, HardLimitValueV1, HardResourceKeyV1, HardResourceProfileV1,
    NamespaceCatalogVerifierV1, NamespaceDestinationV1, NodePolicyInputV1,
    PORTABLE_LIMIT_DIMENSIONS, PolicyLayerV1, SitePolicyInputV1,
};
use super::{SignedPolicyInputDataErrorV1, read_u64, read_i64};

/// Identifies the existing signed deployment packet format.
pub const MAGIC: &[u8; 8] = b"AOSPDH01";
/// Separates the existing deployment signature preimage from other roles.
pub const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-deployment-head.v1\0";
/// Bounds the exact unsigned deployment packet prefix.
pub const PAYLOAD_BYTES: usize = 160;
/// Bounds the exact signed deployment packet including its signature.
pub const PACKET_BYTES: usize = PAYLOAD_BYTES + 64;
pub(super) const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
/// Identifies the four existing canonical JSON declaration formats.
pub const INPUT_MAGICS: [&str; 4] = ["AOSPNI01", "AOSPSI01", "AOSPBI01", "AOSPCI01"];

/// Retains the four exact canonical deployment inputs bound by one signed head.
pub struct PolicyDeploymentInputsV1<'a> {
    /// Canonical node-policy input bytes.
    pub node: &'a [u8],
    /// Canonical site-policy input bytes.
    pub site: &'a [u8],
    /// Canonical backend-capability input bytes.
    pub backend: &'a [u8],
    /// Canonical endpoint and namespace-catalog input bytes.
    pub catalogs: &'a [u8],
}

/// Reports one authenticated, current deployment-input head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDeploymentHeadV1 {
    pub(super) generation: u64,
    pub(super) expires_at: i64,
    pub(super) packet_digest: ObjectDigest,
    pub(super) input_digests: [[u8; 32]; 4],
}

/// Retains constructor-validated node, site, backend, and empty catalogs.
///
/// V1 deliberately supports only finite or inherited hard limits. Grants,
/// namespace rules, advisory actions, nonempty catalogs, and unlimited limits
/// require separate authenticated source contracts and are rejected here.
pub struct PolicyDeploymentSourcesV1 {
    node: NodePolicyInputV1,
    site: SitePolicyInputV1,
    backend: BackendCapabilitiesV1,
    endpoints: AuthenticatedEndpointCatalogV1,
    destinations: AuthenticatedNamespaceCatalogV1,
}

/// Retains the common signed project-head commitments used by the V2 source.
///
/// The fields remain part of the explicit V2 signed source's base. A decoded
/// head identifies provenance and does not authenticate public Create admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedProjectPolicyHeadV1 {
    pub(super) project: ProjectId,
    pub(super) generation: u64,
    pub(super) packet_digest: ObjectDigest,
    pub(super) input_digest: ObjectDigest,
    pub(super) publisher_generation: u64,
    pub(super) publisher_digest: ObjectDigest,
    pub(super) prerequisites: [ObjectDigest; 4],
    pub(super) expires_at: i64,
}

impl SignedProjectPolicyHeadV1 {
    /// Returns the exact signed project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the monotone project-source generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact signed packet commitment for protected currentness.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the digest of the exact canonical signed project-layer bytes.
    #[must_use]
    pub const fn input_digest(self) -> ObjectDigest {
        self.input_digest
    }

    /// Returns the publisher generation that a later Create join must match.
    #[must_use]
    pub const fn publisher_generation(self) -> u64 {
        self.publisher_generation
    }

    /// Returns the publisher descriptor digest a later Create join must match.
    #[must_use]
    pub const fn publisher_digest(self) -> ObjectDigest {
        self.publisher_digest
    }

    /// Returns signed ancestry, compiler, cache, and revocation head claims.
    ///
    /// These are commitments only; a later issuer must prove each head is
    /// independently current before using them as prerequisites.
    #[must_use]
    pub const fn prerequisite_claims(self) -> [ObjectDigest; 4] {
        self.prerequisites
    }

    /// Returns the exclusive signed expiry in Unix seconds.
    #[must_use]
    pub const fn expires_at(self) -> i64 {
        self.expires_at
    }
}

impl PolicyDeploymentSourcesV1 {
    /// Returns the signed, constructor-validated node policy input.
    #[must_use]
    pub const fn node(&self) -> &NodePolicyInputV1 {
        &self.node
    }

    /// Returns the signed, constructor-validated site policy input.
    #[must_use]
    pub const fn site(&self) -> &SitePolicyInputV1 {
        &self.site
    }

    /// Returns the signed, constructor-validated backend capabilities.
    #[must_use]
    pub const fn backend(&self) -> &BackendCapabilitiesV1 {
        &self.backend
    }

    /// Returns the exact signed empty endpoint catalog.
    #[must_use]
    pub const fn endpoints(&self) -> &AuthenticatedEndpointCatalogV1 {
        &self.endpoints
    }

    /// Returns the exact signed empty namespace-destination catalog.
    #[must_use]
    pub const fn destinations(&self) -> &AuthenticatedNamespaceCatalogV1 {
        &self.destinations
    }
}

struct SignedEmptyCatalogVerifier {
    endpoint_bytes: Vec<u8>,
    destination_bytes: Vec<u8>,
}

impl SignedEmptyCatalogVerifier {
    fn matches(descriptor: &ObjectDescriptor, bytes: &[u8], expected: &[u8]) -> bool {
        let Ok(media) = MediaType::new(PortableMediaType::Content.as_str()) else {
            return false;
        };

        bytes == expected && descriptor == &descriptor_for_bytes(media, expected)
    }
}

impl EndpointCatalogVerifierV1 for SignedEmptyCatalogVerifier {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool {
        Self::matches(descriptor, canonical_bytes, &self.endpoint_bytes)
    }
}

impl NamespaceCatalogVerifierV1 for SignedEmptyCatalogVerifier {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool {
        Self::matches(descriptor, canonical_bytes, &self.destination_bytes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentEnvelopeV1<T> {
    generation: u64,
    input: T,
    magic: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Deserializes unsigned resource declaration DATA without native authority.
///
/// The canonical decoder separately checks both complete dimension vectors and
/// each finite/inherited limit. Deserialization does not establish provenance.
pub struct DeploymentLayerV1 {
    pub(super) portable: Vec<DeploymentLimitV1>,
    pub(super) accounting: Vec<DeploymentLimitV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeploymentLimitV1 {
    kind: String,
    amount: Option<u64>,
    enforcement: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBackendV1 {
    enforcement: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentCatalogsV1 {
    endpoints: Vec<Value>,
    destinations: Vec<Value>,
}

impl PolicyDeploymentHeadV1 {
    /// Returns the exact deployment head generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exclusive signed expiry in Unix seconds.
    #[must_use]
    pub const fn expires_at(self) -> i64 {
        self.expires_at
    }

    /// Returns the exact signed packet commitment for protected currentness.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the node, site, backend, and catalog input commitments in order.
    #[must_use]
    pub const fn input_digests(self) -> [[u8; 32]; 4] {
        self.input_digests
    }
}

/// Verifies a dedicated signature and exact canonical deployment inputs.
///
/// The deployment signer is provisioned separately from broker-plan and
/// assignment keys. This check establishes source provenance, not compiler
/// authority or current project ancestry.
///
/// # Errors
///
/// Returns [`SignedPolicyInputDataErrorV1`] for malformed or noncanonical
/// inputs, mismatched digests, an invalid signature, or an expired head.
pub fn verify_policy_deployment_head_v1(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, SignedPolicyInputDataErrorV1> {
    let payload = packet
        .get(..PAYLOAD_BYTES)
        .filter(|_| packet.len() == PACKET_BYTES)
        .ok_or(SignedPolicyInputDataErrorV1::InvalidHead)?;
    if &payload[..8] != MAGIC {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }

    let generation = read_u64(payload, 8)?;
    let issued_at = read_i64(payload, 16)?;
    let expires_at = read_i64(payload, 24)?;
    if generation == 0
        || issued_at >= expires_at
        || issued_at > now_unix_seconds
        || now_unix_seconds >= expires_at
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }

    let provided = [inputs.node, inputs.site, inputs.backend, inputs.catalogs];
    let mut input_digests = [[0; 32]; 4];
    for (index, input) in provided.into_iter().enumerate() {
        validate_canonical_input(input, INPUT_MAGICS[index], generation)?;
        let digest: [u8; 32] = Sha256::digest(input).into();
        if payload[32 + index * 32..64 + index * 32] != digest {
            return Err(SignedPolicyInputDataErrorV1::InvalidHead);
        }
        input_digests[index] = digest;
    }

    verify_historical_packet(packet, verifying_key)?;

    Ok(PolicyDeploymentHeadV1 {
        generation,
        expires_at,
        packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
        input_digests,
    })
}

/// Decodes the signed deployment bytes into the bounded v1 typed source class.
///
/// The caller must first verify the exact packet and input commitments with
/// [`verify_policy_deployment_head_v1`]. The fixed root owner also invokes this
/// decoder before admitting a head, so it cannot durably bless an unsupported
/// input shape.
///
/// # Errors
///
/// Returns [`SignedPolicyInputDataErrorV1::InvalidHead`] for an unsupported
/// feature, incomplete resource profile, mismatched generation, or malformed
/// typed input.
pub fn decode_policy_deployment_sources_v1(
    inputs: &PolicyDeploymentInputsV1<'_>,
    head: PolicyDeploymentHeadV1,
) -> Result<PolicyDeploymentSourcesV1, SignedPolicyInputDataErrorV1> {
    let provided = [inputs.node, inputs.site, inputs.backend, inputs.catalogs];
    if provided
        .into_iter()
        .zip(head.input_digests())
        .any(|(bytes, digest)| Sha256::digest(bytes).as_slice() != digest)
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }

    let node: DeploymentEnvelopeV1<DeploymentLayerV1> =
        decode_envelope(inputs.node, INPUT_MAGICS[0], head.generation)?;
    let site: DeploymentEnvelopeV1<DeploymentLayerV1> =
        decode_envelope(inputs.site, INPUT_MAGICS[1], head.generation)?;
    let backend: DeploymentEnvelopeV1<DeploymentBackendV1> =
        decode_envelope(inputs.backend, INPUT_MAGICS[2], head.generation)?;
    let catalogs: DeploymentEnvelopeV1<DeploymentCatalogsV1> =
        decode_envelope(inputs.catalogs, INPUT_MAGICS[3], head.generation)?;
    if !catalogs.input.endpoints.is_empty() || !catalogs.input.destinations.is_empty() {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }

    // The verified deployment packet commits the exact generation and canonical
    // empty catalog input. V1 cannot issue nonempty endpoint or destination
    // authority; the branded compiler catalogs must remain empty too.
    let verifier = SignedEmptyCatalogVerifier {
        endpoint_bytes: canonical_bytes(
            b"aos.sandbox.endpoint-catalog.v2",
            &Vec::<EndpointCatalogEntryV1>::new(),
        )
        .map_err(crate::PolicyModelError::from)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?,
        destination_bytes: canonical_bytes(
            b"aos.sandbox.namespace-destination-catalog.v2",
            &Vec::<NamespaceDestinationV1>::new(),
        )
        .map_err(crate::PolicyModelError::from)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?,
    };
    let endpoints = AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let destinations = AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;

    let node = NodePolicyInputV1::new(decode_layer(node.input)?)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let site = SitePolicyInputV1::new(decode_layer(site.input)?)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let enforcement = backend
        .input
        .enforcement
        .iter()
        .map(|name| decode_enforcement(name))
        .collect::<Result<Vec<_>, _>>()?;
    let enforcement = BackendEnforcementSetV1::new(enforcement)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let backend = BackendCapabilitiesV1::new(enforcement, Vec::new(), Vec::new())
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;

    Ok(PolicyDeploymentSourcesV1 {
        node,
        site,
        backend,
        endpoints,
        destinations,
    })
}

fn decode_envelope<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    magic: &str,
    generation: u64,
) -> Result<DeploymentEnvelopeV1<T>, SignedPolicyInputDataErrorV1> {
    let envelope: DeploymentEnvelopeV1<T> =
        serde_json::from_slice(bytes).map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    if envelope.magic != magic || envelope.generation != generation {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    Ok(envelope)
}

/// Validates unsigned declarations using the existing typed resource models.
///
/// # Errors
///
/// Rejects missing or extra dimensions, unsupported limit shapes, or a resource
/// value or enforcement rejected by the canonical Policy constructors.
pub fn decode_layer(
    wire: DeploymentLayerV1,
) -> Result<PolicyLayerV1, SignedPolicyInputDataErrorV1> {
    if wire.portable.len() != PORTABLE_LIMIT_DIMENSIONS.len()
        || wire.accounting.len() != ResourceDimension::COUNT
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let portable = wire
        .portable
        .into_iter()
        .zip(PORTABLE_LIMIT_DIMENSIONS)
        .map(|(limit, dimension)| decode_limit(limit, HardResourceKeyV1::Portable(dimension)))
        .collect::<Result<Vec<_>, _>>()?;
    let accounting = wire
        .accounting
        .into_iter()
        .zip(ResourceDimension::ALL)
        .map(|(limit, dimension)| decode_limit(limit, HardResourceKeyV1::Accounting(dimension)))
        .collect::<Result<Vec<_>, _>>()?;
    let resources = HardResourceProfileV1::new(portable, accounting)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    PolicyLayerV1::new(
        Vec::new(),
        resources,
        Vec::new(),
        Vec::new(),
        crate::CacheDomainInputV1::Inherit,
        crate::RevocationInputV1::Inherit,
    )
    .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)
}

fn decode_limit(
    wire: DeploymentLimitV1,
    key: HardResourceKeyV1,
) -> Result<HardLimitRequestV1, SignedPolicyInputDataErrorV1> {
    let (value, enforcement) = match (wire.kind.as_str(), wire.amount, wire.enforcement) {
        ("inherit", None, None) => (HardLimitValueV1::Inherit, None),
        ("bounded", Some(amount), Some(name)) => (
            HardLimitValueV1::Bounded(amount),
            Some(decode_enforcement(&name)?),
        ),
        _ => return Err(SignedPolicyInputDataErrorV1::InvalidHead),
    };
    HardLimitRequestV1::new(key, value, enforcement)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)
}

fn decode_enforcement(name: &str) -> Result<HardEnforcementV1, SignedPolicyInputDataErrorV1> {
    match name {
        "cgroup-v2" => Ok(HardEnforcementV1::CgroupV2),
        "broker-ledger" => Ok(HardEnforcementV1::BrokerLedger),
        "zfs-quota" => Ok(HardEnforcementV1::ZfsQuota),
        "node-bounded-shared-residency" => Ok(HardEnforcementV1::NodeBoundedSharedResidency),
        "hard-isolated-residency" => Ok(HardEnforcementV1::HardIsolatedResidency),
        "combined-file-descriptor" => Ok(HardEnforcementV1::CombinedFileDescriptor),
        "combined-memory-accounting" => Ok(HardEnforcementV1::CombinedMemoryAccounting),
        _ => Err(SignedPolicyInputDataErrorV1::InvalidHead),
    }
}

/// Checks an existing deployment packet signature and structural interval.
///
/// This does not establish present expiry, stored pins or native currentness.
///
/// # Errors
///
/// Rejects malformed framing, zero generation, an inverted validity interval or
/// an invalid signature under the supplied comparison key.
pub fn verify_historical_packet(
    packet: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), SignedPolicyInputDataErrorV1> {
    if packet.len() != PACKET_BYTES || &packet[..8] != MAGIC {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let issued_at = read_i64(packet, 16)?;
    let expires_at = read_i64(packet, 24)?;
    if read_u64(packet, 8)? == 0 || issued_at >= expires_at {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }

    let signature_bytes: [u8; 64] = packet[PAYLOAD_BYTES..]
        .try_into()
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let mut signed = Vec::with_capacity(SIGNING_DOMAIN.len() + PAYLOAD_BYTES);
    signed.extend_from_slice(SIGNING_DOMAIN);
    signed.extend_from_slice(&packet[..PAYLOAD_BYTES]);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidSignature)
}

pub(super) fn validate_canonical_input(
    bytes: &[u8],
    expected_magic: &str,
    generation: u64,
) -> Result<(), SignedPolicyInputDataErrorV1> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_INPUT_BYTES {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    if value.get("magic").and_then(Value::as_str) != Some(expected_magic)
        || value.get("generation").and_then(Value::as_u64) != Some(generation)
        || value.get("input").and_then(Value::as_object).is_none()
        || serde_json::to_vec(&value).map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?
            != bytes
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    Ok(())
}

/// Bounds decoding of the actual private deployment and project wire models.
///
/// The caller separately retains and prices its raw originals, file slots,
/// native owners and role-currentness diagnostics before any decoding starts.
/// Returns `None` if the existing checked representation recipe overflows.
#[must_use]
pub fn fixed_root_startup_decoding_bytes_v1() -> Option<usize> {
    let input = MAXIMUM_INPUT_BYTES;
    let project_input = 3 * 1024usize;
    let value_cell = std::mem::size_of::<(String, Value, [usize; 3])>();
    let limit_cell = std::mem::size_of::<DeploymentLimitV1>();

    // validate_canonical_input owns one complete Value at a time. A malformed
    // byte can nominate a Value/key/link cell; three copies include spare
    // capacity and canonical encoding/validation overlap. Typed decoding then
    // retains node/site, backend and catalogs together with the final sources.
    let canonical = input.checked_mul(3)?.checked_mul(value_cell)?;
    let node_site = input
        .checked_mul(2)?
        .checked_mul(3)?
        .checked_mul(limit_cell)?;
    let backend = input
        .checked_mul(3)?
        .checked_mul(std::mem::size_of::<String>())?;
    let catalogs = input.checked_mul(3)?.checked_mul(value_cell)?;
    let project = project_input
        .checked_mul(3)?
        .checked_mul(value_cell.checked_add(limit_cell)?)?;
    let encoding = input
        .checked_mul(4)?
        .checked_add(project_input)?
        .checked_mul(8)?;
    let wrappers = std::mem::size_of::<PolicyDeploymentSourcesV1>()
        .checked_add(
            std::mem::size_of::<DeploymentEnvelopeV1<DeploymentLayerV1>>().checked_mul(2)?,
        )?
        .checked_add(std::mem::size_of::<DeploymentEnvelopeV1<DeploymentBackendV1>>())?
        .checked_add(std::mem::size_of::<DeploymentEnvelopeV1<DeploymentCatalogsV1>>())?;
    canonical.checked_add(node_site)?.checked_add(backend)?.checked_add(catalogs)?
        .checked_add(project)?.checked_add(encoding)?.checked_add(wrappers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_empty_catalog_verifier_rejects_descriptor_substitution() {
        let expected = canonical_bytes(
            b"aos.sandbox.endpoint-catalog.v2",
            &Vec::<EndpointCatalogEntryV1>::new(),
        )
        .map_err(crate::PolicyModelError::from)
        .expect("empty catalog bytes");
        let media = MediaType::new(PortableMediaType::Content.as_str()).expect("content media");
        let exact = descriptor_for_bytes(media.clone(), &expected);
        let changed = descriptor_for_bytes(media, b"changed");

        assert!(SignedEmptyCatalogVerifier::matches(
            &exact, &expected, &expected
        ));
        assert!(!SignedEmptyCatalogVerifier::matches(
            &changed, &expected, &expected
        ));
        assert!(!SignedEmptyCatalogVerifier::matches(
            &exact, b"changed", &expected
        ));
    }
}
