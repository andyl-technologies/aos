//! Verifies exact explicit project provenance and derives inert policy choices.

use aos_sandbox_model::model::{CacheDomain, CacheDomainKind, RevocationPolicy};
use aos_sandbox_model::{CacheDomainId, ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use crate::{
    AuthenticatedCacheDomainV1, CacheDomainBindingV1, CacheDomainInputV1, PolicyLayerV1,
    RevocationInputV1,
};
use super::deployment::{
    DeploymentLayerV1, DeploymentLimitV1, SignedProjectPolicyHeadV1, decode_layer,
    validate_canonical_input,
};
use super::{SignedPolicyInputDataErrorV1, read_digest, read_i64, read_u64};

/// Identifies the existing explicit signed project packet format.
pub const MAGIC: &[u8; 8] = b"AOSPPH02";
/// Identifies the existing explicit project declaration format.
pub const INPUT_MAGIC: &str = "AOSPPL02";
/// Separates the project signature preimage from other signing roles.
pub const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head.v2\0";
/// Bounds the existing unsigned project packet prefix.
pub const PAYLOAD_BYTES: usize = 264;
/// Bounds the signed project packet including its signature.
pub const PACKET_BYTES: usize = PAYLOAD_BYTES + 64;
const MAXIMUM_INPUT_BYTES: usize = 3 * 1024;

/// Identifies a signed explicit project policy and both signer generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedProjectPolicyHeadV2 {
    base: SignedProjectPolicyHeadV1,
    deployment_signer_generation: u64,
    project_signer_generation: u64,
}

impl SignedProjectPolicyHeadV2 {
    /// Returns the signed base commitments as comparison DATA.
    ///
    /// Current hierarchy, publisher and protected Root owners must independently
    /// rejoin these claims before admitting or publishing any project source.
    #[must_use]
    pub const fn base_data_v1(self) -> SignedProjectPolicyHeadV1 {
        self.base
    }

    /// Returns the exact signed project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.base.project()
    }

    /// Returns the contiguous project-source generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.base.generation()
    }

    /// Returns the content digest of the complete signed packet.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.base.packet_digest()
    }

    /// Returns the exact canonical input digest.
    #[must_use]
    pub const fn input_digest(self) -> ObjectDigest {
        self.base.input_digest()
    }

    /// Returns the signed current publisher generation.
    #[must_use]
    pub const fn publisher_generation(self) -> u64 {
        self.base.publisher_generation()
    }

    /// Returns the signed current publisher descriptor digest.
    #[must_use]
    pub const fn publisher_digest(self) -> ObjectDigest {
        self.base.publisher_digest()
    }

    /// Returns the four signed ancestry, deployment, cache, and revocation claims.
    #[must_use]
    pub const fn prerequisite_claims(self) -> [ObjectDigest; 4] {
        self.base.prerequisite_claims()
    }

    /// Returns the exclusive signed expiry.
    #[must_use]
    pub const fn expires_at(self) -> i64 {
        self.base.expires_at()
    }

    /// Returns the pinned deployment signer generation claimed by this packet.
    #[must_use]
    pub const fn deployment_signer_generation(self) -> u64 {
        self.deployment_signer_generation
    }

    /// Returns the pinned project signer generation claimed by this packet.
    #[must_use]
    pub const fn project_signer_generation(self) -> u64 {
        self.project_signer_generation
    }
}

/// Retains verified signature provenance without current-owner authority.
pub struct VerifiedSignedProjectPolicySourceV2 {
    head: SignedProjectPolicyHeadV2,
    inherited_layer: PolicyLayerV1,
    cache_domain: CacheDomain,
    revocation: RevocationPolicy,
}

impl VerifiedSignedProjectPolicySourceV2 {
    /// Borrows the signed resource choices without a current owner grant.
    #[must_use]
    pub const fn inherited_layer_data_v1(&self) -> &PolicyLayerV1 {
        &self.inherited_layer
    }

    /// Returns the signed head, which still carries unproven current-head claims.
    #[must_use]
    pub const fn head(&self) -> SignedProjectPolicyHeadV2 {
        self.head
    }

    /// Returns the explicit signed project disclosure domain.
    #[must_use]
    pub const fn cache_domain(&self) -> CacheDomain {
        self.cache_domain
    }

    /// Returns the explicit signed revocation behavior.
    #[must_use]
    pub const fn revocation(&self) -> RevocationPolicy {
        self.revocation
    }

    /// Borrows verified choices as inert compiler-input DATA.
    ///
    /// The actual native owner independently supplies its authenticated current
    /// binding; this recipe neither admits nor authorizes a project source.
    #[cfg(target_os = "linux")]
    pub const fn q04_layer_recipe(&self) -> Q04SignedProjectLayerRecipeV1<'_> {
        Q04SignedProjectLayerRecipeV1 { source: self }
    }

    /// Checks a proposed compiler layer against the signed explicit choices.
    ///
    /// This does not authenticate the candidate's cache-domain verifier or
    /// prove that the publisher and root owners currently retain this source.
    #[must_use]
    pub fn matches_candidate_layer(&self, candidate: &PolicyLayerV1) -> bool {
        let domain_matches = match candidate.cache_domain() {
            CacheDomainInputV1::Exact(binding) => {
                binding.domain() == self.cache_domain
                    && binding.binding() == CacheDomainBindingV1::Project(self.head.project())
            }
            CacheDomainInputV1::Inherit => false,
        };
        domain_matches
            && candidate.revocation() == RevocationInputV1::Exact(self.revocation)
            && candidate.resources() == self.inherited_layer.resources()
            && candidate.grants().is_empty()
            && candidate.namespace_rules().is_empty()
            && candidate.advisory_actions().is_empty()
    }
}

/// Borrows signed-input DATA without an admitted project or current owner loan.
#[cfg(target_os = "linux")]
pub struct Q04SignedProjectLayerRecipeV1<'signed> {
    source: &'signed VerifiedSignedProjectPolicySourceV2,
}

#[cfg(target_os = "linux")]
impl Q04SignedProjectLayerRecipeV1<'_> {
    // V2 verification already rejects grants/rules/advisories, unlimited limits
    // and inherited cross-cutting inputs. No decode or materialization is needed.
    /// Quotes namespace entries from the existing validated resource choices.
    #[must_use]
    pub fn compiler_namespace_entries_v1(
        &self,
        deployment: &super::PolicyDeploymentSourcesV1,
    ) -> Option<u64> {
        crate::inherited_parentless_resource_namespace_entries_v1([
            deployment.node().layer().resources(),
            deployment.site().layer().resources(),
            self.source.inherited_layer.resources(),
        ])
    }

    /// Derives inert compiler input using an independently authenticated binding.
    ///
    /// This derivation does not prove native currentness or publication custody.
    ///
    /// # Errors
    ///
    /// Rejects a binding for a different signed project/domain or a canonical
    /// Policy constructor refusal.
    pub fn materialize_with_authenticated_binding(
        &self,
        binding: AuthenticatedCacheDomainV1,
    ) -> Result<PolicyLayerV1, SignedPolicyInputDataErrorV1> {
        if binding.domain() != self.source.cache_domain
            || binding.binding() != CacheDomainBindingV1::Project(self.source.head.project())
        {
            return Err(SignedPolicyInputDataErrorV1::InvalidHead);
        }

        explicit_layer_with_authenticated_binding(self.source, binding)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectEnvelopeV2 {
    generation: u64,
    input: ProjectLayerV2,
    magic: String,
    project_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectLayerV2 {
    accounting: Vec<DeploymentLimitV1>,
    advisory_actions: Vec<Value>,
    cache_domain: String,
    grants: Vec<Value>,
    namespace_rules: Vec<Value>,
    portable: Vec<DeploymentLimitV1>,
    revocation: RevocationPolicy,
}

// The fixed startup model supplier and each independently entered project
// verifier share this exact original JSON/typed-model representation recipe.
pub(super) fn project_input_decoding_bytes_v2(input_bytes: usize) -> Option<usize> {
    let value_cell = std::mem::size_of::<(String, Value, [usize; 3])>();
    let limit_cell = std::mem::size_of::<DeploymentLimitV1>();
    input_bytes
        .checked_mul(3)?
        .checked_mul(value_cell.checked_add(limit_cell)?)?
        .checked_add(input_bytes.checked_mul(8)?)
}

// The native caller independently pays this DATA before entering the same
// existing signature/JSON verifier. Invalid widths retain its early no-model
// branch; this quote neither verifies bytes nor creates a native role.
#[cfg(feature = "native-journal")]
pub(crate) fn project_source_verification_receiving_bytes_v2(
    packet_bytes: usize,
    input_bytes: usize,
) -> Option<usize> {
    let controls = std::mem::size_of::<VerifiedSignedProjectPolicySourceV2>()
        .checked_mul(3)?
        .checked_add(
            std::mem::size_of::<
                Result<VerifiedSignedProjectPolicySourceV2, SignedPolicyInputDataErrorV1>,
            >()
            .checked_mul(3)?,
        )?
        .checked_add(std::mem::size_of::<Signature>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Sha256>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Vec<u8>>().checked_mul(3)?)?;
    if packet_bytes != PACKET_BYTES || input_bytes > MAXIMUM_INPUT_BYTES {
        return Some(controls);
    }
    let typed = std::mem::size_of::<ProjectEnvelopeV2>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<ProjectLayerV2>().checked_mul(3)?)?;
    let resource_count = crate::PORTABLE_LIMIT_DIMENSIONS
        .len()
        .checked_add(aos_sandbox_model::ResourceDimension::COUNT)?;
    let resource_backing = resource_count
        .checked_mul(3)?
        .checked_mul(std::mem::size_of::<crate::HardLimitRequestV1>())?;
    let preimage = SIGNING_DOMAIN
        .len()
        .checked_add(PAYLOAD_BYTES)?
        .checked_mul(3)?;
    controls
        .checked_add(typed)?
        .checked_add(resource_backing)?
        .checked_add(preimage)?
        .checked_add(project_input_decoding_bytes_v2(input_bytes)?)
}

/// Verifies a version-2 project signature and exact canonical input framing.
///
/// The supplied key is not selected by this function and the result grants no
/// authority. Protected admission compares it to immutable root signer pins,
/// then checks every signed current-head claim under independent writers.
///
/// # Errors
///
/// Rejects malformed framing, an invalid signature, inherited cross-cutting
/// choices, mismatched project identity, or noncanonical resources.
pub fn verify_signed_project_policy_source_v2(
    packet: &[u8],
    input: &[u8],
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<VerifiedSignedProjectPolicySourceV2, SignedPolicyInputDataErrorV1> {
    if packet.len() != PACKET_BYTES || input.len() > MAXIMUM_INPUT_BYTES || &packet[..8] != MAGIC {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let signature: [u8; 64] = packet[PAYLOAD_BYTES..]
        .try_into()
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let mut signed = Vec::with_capacity(SIGNING_DOMAIN.len() + PAYLOAD_BYTES);
    signed.extend_from_slice(SIGNING_DOMAIN);
    signed.extend_from_slice(&packet[..PAYLOAD_BYTES]);
    verifying_key
        .verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidSignature)?;

    let project_bytes: [u8; 16] = packet[8..24]
        .try_into()
        .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    let project = ProjectId::from_bytes(project_bytes);
    let generation = read_u64(packet, 24)?;
    let issued_at = read_i64(packet, 32)?;
    let expires_at = read_i64(packet, 40)?;
    let publisher_generation = read_u64(packet, 48)?;
    let deployment_signer_generation = read_u64(packet, 248)?;
    let project_signer_generation = read_u64(packet, 256)?;
    if project_bytes == [0; 16]
        || generation == 0
        || publisher_generation == 0
        || deployment_signer_generation == 0
        || project_signer_generation == 0
        || issued_at >= expires_at
        || issued_at > now_unix_seconds
        || now_unix_seconds >= expires_at
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let publisher_digest = ObjectDigest::from_bytes(read_digest(packet, 56)?);
    let input_digest = ObjectDigest::from_bytes(read_digest(packet, 88)?);
    let prerequisites = [
        ObjectDigest::from_bytes(read_digest(packet, 120)?),
        ObjectDigest::from_bytes(read_digest(packet, 152)?),
        ObjectDigest::from_bytes(read_digest(packet, 184)?),
        ObjectDigest::from_bytes(read_digest(packet, 216)?),
    ];
    if publisher_digest.as_bytes() == &[0; 32]
        || prerequisites.iter().any(|head| head.as_bytes() == &[0; 32])
        || input_digest.as_bytes() != Sha256::digest(input).as_slice()
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }

    validate_canonical_input(input, INPUT_MAGIC, generation)?;
    let envelope: ProjectEnvelopeV2 =
        serde_json::from_slice(input).map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)?;
    if envelope.magic != INPUT_MAGIC
        || envelope.generation != generation
        || envelope.project_id != project.to_string()
        || envelope.input.cache_domain != "project"
        || !envelope.input.grants.is_empty()
        || !envelope.input.namespace_rules.is_empty()
        || !envelope.input.advisory_actions.is_empty()
    {
        return Err(SignedPolicyInputDataErrorV1::InvalidHead);
    }
    let inherited_layer = decode_layer(DeploymentLayerV1 {
        portable: envelope.input.portable,
        accounting: envelope.input.accounting,
    })?;
    Ok(VerifiedSignedProjectPolicySourceV2 {
        head: SignedProjectPolicyHeadV2 {
            base: SignedProjectPolicyHeadV1 {
                project,
                generation,
                packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
                input_digest,
                publisher_generation,
                publisher_digest,
                prerequisites,
                expires_at,
            },
            deployment_signer_generation,
            project_signer_generation,
        },
        inherited_layer,
        cache_domain: CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(project_bytes),
        ),
        revocation: envelope.input.revocation,
    })
}

/// Derives inert compiler DATA from verified declarations and a supplied binding.
///
/// The native caller independently establishes the binding's current project
/// association. This constructor neither admits nor publishes the result.
///
/// # Errors
///
/// Returns the original invalid-head DATA classification when a canonical
/// Policy layer constructor rejects the existing choices.
pub fn explicit_layer_with_authenticated_binding(
    verified: &VerifiedSignedProjectPolicySourceV2,
    binding: AuthenticatedCacheDomainV1,
) -> Result<PolicyLayerV1, SignedPolicyInputDataErrorV1> {
    PolicyLayerV1::new(
        Vec::new(),
        verified.inherited_layer.resources().clone(),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Exact(binding),
        RevocationInputV1::Exact(verified.revocation),
    )
    .map_err(|_| SignedPolicyInputDataErrorV1::InvalidHead)
}
