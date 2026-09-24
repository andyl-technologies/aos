//! Signed explicit project policy beneath a pinned deployment head.
//!
//! `AOSPPH02` retains the V1 project and four prerequisite commitments, then
//! adds both signer generations before a domain-separated signature. Its
//! canonical `AOSPPL02` input explicitly selects the project cache domain and
//! revocation behavior. Signature verification is provenance only; the
//! protected root admission checks immutable signer pins and every independent
//! current head while controller and source-domain writers remain held.
//!
//! ```text
//! AOSPPH02 | project[16] | project_generation:u64 | issued:i64 | expires:i64 |
//! publisher_generation:u64 | publisher_digest[32] | input_digest[32] |
//! ancestry/deployment/cache-domain/revocation heads[4][32] |
//! deployment_signer_generation:u64 | project_signer_generation:u64 |
//! Ed25519 signature[64]
//! ```

use std::path::Path;

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind, RevocationPolicy};
use aos_sandbox_core::{
    CacheDomainId, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId,
    RevocationScopeId,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::hierarchy::protected_journal::HierarchyProtectedJournalOwnerV1;
use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

use super::deployment_head::{
    DeploymentLayerV1, DeploymentLimitV1, HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY,
    SIGNER_PINS_KEY, SignedProjectPolicyHeadV1, bind_signed_project_to_controller_currentness,
    decode_layer, encode_policy_signer_pins_v1, validate_canonical_input,
};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::{
    AuthenticatedCacheDomainV1, CacheDomainBindingV1, CacheDomainInputV1, CacheDomainVerifierV1,
    PolicyDeploymentHeadErrorV1, PolicyDeploymentInputsV1, PolicyLayerV1, RevocationInputV1,
    decode_policy_deployment_sources_v1, verify_policy_deployment_head_v1,
};

const MAGIC: &[u8; 8] = b"AOSPPH02";
const INPUT_MAGIC: &str = "AOSPPL02";
const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head-transaction.v2\0";
const PAYLOAD_BYTES: usize = 264;
const PACKET_BYTES: usize = PAYLOAD_BYTES + 64;
const MAXIMUM_INPUT_BYTES: usize = 3 * 1024;
pub(super) const HEAD_KEY_V2: &[u8] = b"\0aos-policy-project-head-v2\0";
pub(super) const INPUT_KEY_V2: &[u8] = b"\0aos-policy-project-input-v2\0";

/// Identifies a signed explicit project policy and both signer generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedProjectPolicyHeadV2 {
    base: SignedProjectPolicyHeadV1,
    deployment_signer_generation: u64,
    project_signer_generation: u64,
}

impl SignedProjectPolicyHeadV2 {
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
}

/// Retains the explicit layer only after protected root/current-head admission.
pub struct AdmittedSignedProjectPolicySourceV2 {
    head: SignedProjectPolicyHeadV2,
    layer: PolicyLayerV1,
}

impl AdmittedSignedProjectPolicySourceV2 {
    /// Returns the independently checked signed project head.
    #[must_use]
    pub const fn head(&self) -> SignedProjectPolicyHeadV2 {
        self.head
    }

    /// Returns the compiler layer with current project cache and revocation inputs.
    #[must_use]
    pub const fn layer(&self) -> &PolicyLayerV1 {
        &self.layer
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
) -> Result<VerifiedSignedProjectPolicySourceV2, PolicyDeploymentHeadErrorV1> {
    if packet.len() != PACKET_BYTES || input.len() > MAXIMUM_INPUT_BYTES || &packet[..8] != MAGIC {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let signature: [u8; 64] = packet[PAYLOAD_BYTES..]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let mut signed = Vec::with_capacity(SIGNING_DOMAIN.len() + PAYLOAD_BYTES);
    signed.extend_from_slice(SIGNING_DOMAIN);
    signed.extend_from_slice(&packet[..PAYLOAD_BYTES]);
    verifying_key
        .verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidSignature)?;

    let project_bytes: [u8; 16] = packet[8..24]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
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
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
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
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }

    validate_canonical_input(input, INPUT_MAGIC, generation)?;
    let envelope: ProjectEnvelopeV2 =
        serde_json::from_slice(input).map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    if envelope.magic != INPUT_MAGIC
        || envelope.generation != generation
        || envelope.project_id != project.to_string()
        || envelope.input.cache_domain != "project"
        || !envelope.input.grants.is_empty()
        || !envelope.input.namespace_rules.is_empty()
        || !envelope.input.advisory_actions.is_empty()
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
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

/// Admits an exact V2 signed project source under protected owner custody.
///
/// The caller holds the controller writer before this function opens the
/// source-domain writer, then the root policy writer. Signer keys and their
/// generations must be supplied by privileged deployment configuration;
/// the protected root journal independently compares immutable exact pins.
/// A legacy V1 project head cannot be migrated implicitly. This admission
/// does not authorize a Create, policy publication, or an effect.
///
/// # Errors
///
/// Rejects missing or rotated pins, a stale deployment or independent owner
/// head, a mismatched explicit policy, legacy V1 state, conflicting replay,
/// or failed protected CAS/readback.
#[allow(clippy::too_many_arguments)]
pub fn admit_fixed_signed_project_policy_source_v2(
    controller_journal: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    trusted_revocation_scope: RevocationScopeId,
    packet: &[u8],
    input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_signer_generation: u64,
    now_unix_seconds: i64,
) -> Result<AdmittedSignedProjectPolicySourceV2, PolicyDeploymentHeadErrorV1> {
    controller_journal.ensure_protected_authority()?;
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(source_domains)?;
    let (mut authority_journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    admit_signed_project_policy_source_with_journals_v2(
        controller_journal,
        &hierarchy,
        &mut authority_journal,
        trusted_revocation_scope,
        packet,
        input,
        project_key,
        project_signer_generation,
        deployment_packet,
        deployment_inputs,
        deployment_key,
        deployment_signer_generation,
        now_unix_seconds,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admit_signed_project_policy_source_with_journals_v2(
    controller_journal: &mut Journal,
    hierarchy: &HierarchyProtectedJournalOwnerV1<'_>,
    authority_journal: &mut Journal,
    trusted_revocation_scope: RevocationScopeId,
    packet: &[u8],
    input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_signer_generation: u64,
    now_unix_seconds: i64,
) -> Result<AdmittedSignedProjectPolicySourceV2, PolicyDeploymentHeadErrorV1> {
    let pins = encode_policy_signer_pins_v1(
        deployment_signer_generation,
        deployment_key,
        project_signer_generation,
        project_key,
    )?;
    let mut authority =
        authority_journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(pins.as_slice())
        || authority.get(HEAD_KEY)? != Some(deployment_packet)
        || authority.get(PROJECT_HEAD_KEY)?.is_some()
        || authority.get(PROJECT_INPUT_KEY)?.is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let deployment = verify_policy_deployment_head_v1(
        deployment_packet,
        deployment_inputs,
        deployment_key,
        now_unix_seconds,
    )?;
    let _deployment_sources = decode_policy_deployment_sources_v1(deployment_inputs, deployment)?;
    let verified =
        verify_signed_project_policy_source_v2(packet, input, project_key, now_unix_seconds)?;
    if verified.head.deployment_signer_generation != deployment_signer_generation
        || verified.head.project_signer_generation != project_signer_generation
        || verified.head.base.prerequisites[1] != deployment.packet_digest()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let ancestry = hierarchy
        .project_ancestry_head(verified.head.project())?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if verified.head.base.prerequisites[0] != ancestry.evidence().head() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let prior_head = authority.get(HEAD_KEY_V2)?;
    let prior_input = authority.get(INPUT_KEY_V2)?;
    if prior_head.is_some() != prior_input.is_some() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let replay = prior_head == Some(packet) && prior_input == Some(input);
    if !replay {
        let predecessor = prior_head
            .zip(prior_input)
            .map(|(current, current_input)| {
                let historical_time = read_i64(current, 32)?;
                let prior = verify_signed_project_policy_source_v2(
                    current,
                    current_input,
                    project_key,
                    historical_time,
                )?;
                if prior.head.project() != verified.head.project()
                    || prior.head.deployment_signer_generation != deployment_signer_generation
                    || prior.head.project_signer_generation != project_signer_generation
                {
                    return Err(PolicyDeploymentHeadErrorV1::StaleHead);
                }
                Ok(prior.head.generation())
            })
            .transpose()?
            .unwrap_or(0);
        if predecessor.checked_add(1) != Some(verified.head.generation()) {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
    }

    let layer = current_explicit_layer(
        controller_journal,
        trusted_revocation_scope,
        &verified,
        now_unix_seconds,
    )?;
    bind_signed_project_to_controller_currentness(
        controller_journal,
        verified.head.base,
        trusted_revocation_scope,
        now_unix_seconds,
    )?;
    if !replay {
        let transaction_digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(packet)
            .finalize();
        let transaction_id: [u8; 16] = transaction_digest[..16]
            .try_into()
            .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY_V2.to_vec(),
                    packet.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    INPUT_KEY_V2.to_vec(),
                    input.to_vec(),
                ),
            ],
        )?;
        authority.commit(&transaction)?;
    }
    if authority.get(HEAD_KEY_V2)? != Some(packet)
        || authority.get(INPUT_KEY_V2)? != Some(input)
        || hierarchy
            .project_ancestry_head(verified.head.project())?
            .is_none_or(|current| current.evidence().head() != ancestry.evidence().head())
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    current_explicit_layer(
        controller_journal,
        trusted_revocation_scope,
        &verified,
        now_unix_seconds,
    )?;
    Ok(AdmittedSignedProjectPolicySourceV2 {
        head: verified.head,
        layer,
    })
}

fn current_explicit_layer(
    controller_journal: &mut Journal,
    trusted_revocation_scope: RevocationScopeId,
    verified: &VerifiedSignedProjectPolicySourceV2,
    now_unix_seconds: i64,
) -> Result<PolicyLayerV1, PolicyDeploymentHeadErrorV1> {
    let publisher =
        PublisherPolicyStore::load(controller_journal, PublisherPolicyLimits::default())?;
    let current = publisher
        .current_policy(verified.head.project())?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let current_cache = publisher
        .project_cache_domain_head(verified.head.project())?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let current_revocation = publisher
        .revocation_head(trusted_revocation_scope)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let expected_revocation = crate::publisher_policy::project_revocation_digest(
        verified.head.project(),
        trusted_revocation_scope,
        current_revocation.generation,
    );
    if current.generation() != verified.head.publisher_generation()
        || current.descriptor().digest() != verified.head.publisher_digest()
        || now_unix_seconds < current.not_before()
        || now_unix_seconds >= current.expires_at()
        || current.policy().cache_domain() != verified.cache_domain
        || current.policy().revocation() != verified.revocation
        || current_cache.digest() != verified.head.prerequisite_claims()[2]
        || expected_revocation != verified.head.prerequisite_claims()[3]
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let domain = current.policy().cache_domain();
    drop(publisher);

    // The signed input selected this exact project domain. Current publisher
    // replay independently confirmed it before the private verifier brands
    // the canonical compiler binding; no request can nominate this verifier.
    let binding = AuthenticatedCacheDomainV1::authenticate(
        domain,
        CacheDomainBindingV1::Project(verified.head.project()),
        &CurrentPublisherDomainVerifierV2,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    PolicyLayerV1::new(
        Vec::new(),
        verified.inherited_layer.resources().clone(),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Exact(binding),
        RevocationInputV1::Exact(verified.revocation),
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)
}

struct CurrentPublisherDomainVerifierV2;

impl CacheDomainVerifierV1 for CurrentPublisherDomainVerifierV2 {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool {
        let Ok(media) = MediaType::new(PortableMediaType::Content.as_str()) else {
            return false;
        };
        !canonical_bytes.is_empty() && descriptor_for_bytes(media, canonical_bytes) == *descriptor
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PolicyDeploymentHeadErrorV1> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|part| part.try_into().ok())
            .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?,
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, PolicyDeploymentHeadErrorV1> {
    Ok(i64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|part| part.try_into().ok())
            .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?,
    ))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32], PolicyDeploymentHeadErrorV1> {
    bytes
        .get(offset..offset + 32)
        .and_then(|part| part.try_into().ok())
        .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn input(project: ProjectId, cache_domain: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": {
                "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
                "advisory_actions": [],
                "cache_domain": cache_domain,
                "grants": [],
                "namespace_rules": [],
                "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
                "revocation": {"grace_nanos": 0, "mode": "deny-new"},
            },
            "magic": INPUT_MAGIC,
            "project_id": project.to_string(),
        }))
        .expect("canonical signed source input")
    }

    fn packet(project: ProjectId, input: &[u8], key: &SigningKey) -> Vec<u8> {
        let mut packet = MAGIC.to_vec();
        packet.extend_from_slice(project.as_bytes());
        packet.extend_from_slice(&1_u64.to_be_bytes());
        packet.extend_from_slice(&10_i64.to_be_bytes());
        packet.extend_from_slice(&30_i64.to_be_bytes());
        packet.extend_from_slice(&1_u64.to_be_bytes());
        packet.extend_from_slice(&[4; 32]);
        packet.extend_from_slice(&Sha256::digest(input));
        for head in [[5; 32], [6; 32], [7; 32], [8; 32]] {
            packet.extend_from_slice(&head);
        }
        packet.extend_from_slice(&2_u64.to_be_bytes());
        packet.extend_from_slice(&3_u64.to_be_bytes());
        assert_eq!(packet.len(), PAYLOAD_BYTES);
        let mut signed = SIGNING_DOMAIN.to_vec();
        signed.extend_from_slice(&packet);
        packet.extend_from_slice(&key.sign(&signed).to_bytes());
        packet
    }

    #[test]
    fn explicit_signed_project_source_rejects_v1_inheritance_and_substitution() {
        let project = ProjectId::from_bytes([1; 16]);
        let key = SigningKey::from_bytes(&[2; 32]);
        let project_input = input(project, "project");
        let signed_packet = packet(project, &project_input, &key);
        let verified = verify_signed_project_policy_source_v2(
            &signed_packet,
            &project_input,
            &key.verifying_key(),
            20,
        )
        .expect("versioned signed source");
        assert_eq!(verified.head().deployment_signer_generation(), 2);
        assert_eq!(verified.head().project_signer_generation(), 3);
        assert_eq!(verified.cache_domain().kind(), CacheDomainKind::Project);

        let inherited = input(project, "inherit");
        let inherited_packet = packet(project, &inherited, &key);
        assert!(
            verify_signed_project_policy_source_v2(
                &inherited_packet,
                &inherited,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
        assert!(
            verify_signed_project_policy_source_v2(
                &signed_packet,
                &inherited,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
        let mut legacy_magic = signed_packet.clone();
        legacy_magic[..8].copy_from_slice(b"AOSPPH01");
        assert!(
            verify_signed_project_policy_source_v2(
                &legacy_magic,
                &project_input,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
        let mut changed_generation = signed_packet;
        changed_generation[263] ^= 1;
        assert!(
            verify_signed_project_policy_source_v2(
                &changed_generation,
                &project_input,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
    }
}
