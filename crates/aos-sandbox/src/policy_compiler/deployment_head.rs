//! Signed deployment-input head for the privileged policy authority.
//!
//! The fixed-width `AOSPDH01` packet commits four separately provisioned,
//! canonical JSON inputs. Its Ed25519 signature covers the domain-separated
//! 160-byte payload; the 64-byte signature follows the payload. This head is
//! deployment provenance only. It does not grant an `AOSPCB01` compiler binding
//! or authorize a public Create operation.
//!
//! ```text
//! magic[8] | generation:u64be | issued_at:i64be | expires_at:i64be
//! node_sha256[32] | site_sha256[32] | backend_sha256[32] | catalogs_sha256[32]
//! ed25519_signature[64]
//! ```
//!
//! Each input is compact, canonical JSON with the same generation, a distinct
//! `magic` (`AOSPNI01`, `AOSPSI01`, `AOSPBI01`, or `AOSPCI01`), and an `input`
//! object. Node and site inputs contain complete ordered `portable` (16) and
//! `accounting` (22) limit arrays. Each entry is either
//! `{"kind":"inherit"}` or
//! `{"amount":4096,"enforcement":"zfs-quota","kind":"bounded"}` with
//! an enforcement registered for its exact dimension. Backend input carries
//! a strictly ordered `enforcement` array; catalog input requires empty
//! `destinations` and `endpoints` arrays in this bounded v1. Unsupported
//! shapes never become policy authority.
//!
//! A second dedicated signer supplies one explicit parentless project layer
//! as a 312-byte `AOSPPH01` packet plus canonical `AOSPPL01` JSON. The packet
//! pins the project, source and publisher generations, current publisher
//! policy descriptor digest, four prerequisite-head claims, and the JSON
//! digest. The root owner commits packet and JSON atomically under the exact
//! current deployment head. The protected source-domain project tree and
//! publisher-owned cache-domain and revocation heads are checked while their
//! writers remain held through the root commit. The exact public Create,
//! physical cache state, and effect handoff still need independent proof
//! before AOSPCB01.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceDimension, RevocationScopeId};

use crate::hierarchy::protected_journal::{
    HierarchyProtectedJournalErrorV1, HierarchyProtectedJournalOwnerV1,
};
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::publisher_policy::{
    PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore, project_revocation_digest,
};

use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::{
    BackendCapabilitiesV1, BackendEnforcementSetV1, HardEnforcementV1, HardLimitRequestV1,
    HardLimitValueV1, HardResourceKeyV1, HardResourceProfileV1, NodePolicyInputV1,
    PORTABLE_LIMIT_DIMENSIONS, PolicyLayerV1, SitePolicyInputV1,
};

const MAGIC: &[u8; 8] = b"AOSPDH01";
const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-deployment-head.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-deployment-head-transaction.v1\0";
pub(super) const HEAD_KEY: &[u8] = b"\0aos-policy-deployment-head-v1\0";
const PAYLOAD_BYTES: usize = 160;
const PACKET_BYTES: usize = PAYLOAD_BYTES + 64;
const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
const INPUT_MAGICS: [&str; 4] = ["AOSPNI01", "AOSPSI01", "AOSPBI01", "AOSPCI01"];
const PROJECT_MAGIC: &[u8; 8] = b"AOSPPH01";
const PROJECT_SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head.v1\0";
const PROJECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head-transaction.v1\0";
const PROJECT_REVOCATION_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-project-revocation-binding-transaction.v1\0";
pub(super) const PROJECT_HEAD_KEY: &[u8] = b"\0aos-policy-project-head-v1\0";
pub(super) const PROJECT_INPUT_KEY: &[u8] = b"\0aos-policy-project-input-v1\0";
const PROJECT_PAYLOAD_BYTES: usize = 248;
const PROJECT_PACKET_BYTES: usize = PROJECT_PAYLOAD_BYTES + 64;
const MAXIMUM_PROJECT_INPUT_BYTES: usize = 3 * 1024;
pub(super) const SIGNER_PINS_KEY: &[u8] = b"\0aos-policy-signer-pins-v1\0";
const SIGNER_PINS_MAGIC: &[u8; 8] = b"AOSPKP01";
const SIGNER_PINS_DOMAIN: &[u8] = b"aos.sandbox.policy-signer-pins.v1\0";
const SIGNER_PINS_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-signer-pins-transaction.v1\0";

/// Reports a rejected signed deployment input or protected head transition.
#[derive(Debug, thiserror::Error)]
pub enum PolicyDeploymentHeadErrorV1 {
    /// The signed packet, input, or validity interval is malformed.
    #[error("invalid deployment policy head")]
    InvalidHead,
    /// The dedicated deployment key did not sign this exact head.
    #[error("deployment policy head signature is invalid")]
    InvalidSignature,
    /// The packet does not extend the current protected head.
    #[error("deployment policy head generation is not current")]
    StaleHead,
    /// Protected journal replay or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Protected publisher policy or revocation state is unavailable.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
    /// Protected source-domain hierarchy currentness is unavailable.
    #[error(transparent)]
    Hierarchy(#[from] HierarchyProtectedJournalErrorV1),
}

/// Pins both role-specific deployment verifier generations in root custody.
///
/// The service obtains these values only from its fixed protected deployment
/// credentials before admitting a signed head. Exact replay is accepted;
/// missing pins alongside an existing head or any key/generation change fails
/// closed until an explicit, separately audited rotation migration exists.
///
/// # Errors
///
/// Rejects zero generations, stale or legacy protected state, unsafe root
/// custody, ambiguous commit, or failed exact readback.
pub fn admit_fixed_policy_signer_pins_v1(
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    admit_policy_signer_pins_in_journal_v1(
        &mut journal,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
}

pub(super) fn admit_policy_signer_pins_in_journal_v1(
    journal: &mut Journal,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    let encoded = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )?;

    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    match authority.get(SIGNER_PINS_KEY)? {
        Some(current) if current == encoded.as_slice() => return Ok(()),
        Some(_) => return Err(PolicyDeploymentHeadErrorV1::StaleHead),
        None => {}
    }
    if !authority.is_materialized_empty()? {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let digest = Sha256::new()
        .chain_update(SIGNER_PINS_TRANSACTION_DOMAIN)
        .chain_update(&encoded)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            SIGNER_PINS_KEY.to_vec(),
            encoded.clone(),
        )],
    )?;
    authority.commit(&transaction)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(encoded.as_slice()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(())
}

pub(super) fn encode_policy_signer_pins_v1(
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<Vec<u8>, PolicyDeploymentHeadErrorV1> {
    if deployment_generation == 0 || project_generation == 0 {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let mut encoded = Vec::with_capacity(120);
    encoded.extend_from_slice(SIGNER_PINS_MAGIC);
    encoded.extend_from_slice(&deployment_generation.to_be_bytes());
    encoded.extend_from_slice(deployment_key.as_bytes());
    encoded.extend_from_slice(&project_generation.to_be_bytes());
    encoded.extend_from_slice(project_key.as_bytes());
    let checksum = Sha256::new()
        .chain_update(SIGNER_PINS_DOMAIN)
        .chain_update(&encoded)
        .finalize();
    encoded.extend_from_slice(&checksum);
    Ok(encoded)
}

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
    generation: u64,
    expires_at: i64,
    packet_digest: ObjectDigest,
    input_digests: [[u8; 32]; 4],
}

/// Retains constructor-validated node, site, and backend policy sources.
///
/// V1 deliberately supports only finite or inherited hard limits. Grants,
/// namespace rules, advisory actions, nonempty catalogs, and unlimited limits
/// require separate authenticated source contracts and are rejected here.
pub struct PolicyDeploymentSourcesV1 {
    node: NodePolicyInputV1,
    site: SitePolicyInputV1,
    backend: BackendCapabilitiesV1,
}

/// Identifies one externally signed, parentless project-layer source.
///
/// V1 signs one project at a time and requires all resource, grant, namespace,
/// advisory, cache-domain, and revocation choices to be explicit in its
/// canonical input. It does not authenticate a public Create admission.
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

/// Retains exact project-layer choices typed after dedicated signature check.
pub struct SignedProjectPolicySourceV1 {
    head: SignedProjectPolicyHeadV1,
    layer: PolicyLayerV1,
}

impl SignedProjectPolicySourceV1 {
    /// Returns the signed source head.
    #[must_use]
    pub const fn head(&self) -> SignedProjectPolicyHeadV1 {
        self.head
    }

    /// Returns the constructor-validated project layer.
    #[must_use]
    pub const fn layer(&self) -> &PolicyLayerV1 {
        &self.layer
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
pub(super) struct DeploymentLayerV1 {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectEnvelopeV1 {
    generation: u64,
    input: ProjectLayerV1,
    magic: String,
    project_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectLayerV1 {
    accounting: Vec<DeploymentLimitV1>,
    advisory_actions: Vec<Value>,
    cache_domain: String,
    grants: Vec<Value>,
    namespace_rules: Vec<Value>,
    portable: Vec<DeploymentLimitV1>,
    revocation: String,
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
/// Returns [`PolicyDeploymentHeadErrorV1`] for malformed or noncanonical
/// inputs, mismatched digests, an invalid signature, or an expired head.
pub fn verify_policy_deployment_head_v1(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let payload = packet
        .get(..PAYLOAD_BYTES)
        .filter(|_| packet.len() == PACKET_BYTES)
        .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?;
    if &payload[..8] != MAGIC {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }

    let generation = read_u64(payload, 8)?;
    let issued_at = read_i64(payload, 16)?;
    let expires_at = read_i64(payload, 24)?;
    if generation == 0
        || issued_at >= expires_at
        || issued_at > now_unix_seconds
        || now_unix_seconds >= expires_at
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }

    let provided = [inputs.node, inputs.site, inputs.backend, inputs.catalogs];
    let mut input_digests = [[0; 32]; 4];
    for (index, input) in provided.into_iter().enumerate() {
        validate_canonical_input(input, INPUT_MAGICS[index], generation)?;
        let digest: [u8; 32] = Sha256::digest(input).into();
        if payload[32 + index * 32..64 + index * 32] != digest {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
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
/// Returns [`PolicyDeploymentHeadErrorV1::InvalidHead`] for an unsupported
/// feature, incomplete resource profile, mismatched generation, or malformed
/// typed input.
pub fn decode_policy_deployment_sources_v1(
    inputs: &PolicyDeploymentInputsV1<'_>,
    head: PolicyDeploymentHeadV1,
) -> Result<PolicyDeploymentSourcesV1, PolicyDeploymentHeadErrorV1> {
    let node: DeploymentEnvelopeV1<DeploymentLayerV1> =
        decode_envelope(inputs.node, INPUT_MAGICS[0], head.generation)?;
    let site: DeploymentEnvelopeV1<DeploymentLayerV1> =
        decode_envelope(inputs.site, INPUT_MAGICS[1], head.generation)?;
    let backend: DeploymentEnvelopeV1<DeploymentBackendV1> =
        decode_envelope(inputs.backend, INPUT_MAGICS[2], head.generation)?;
    let catalogs: DeploymentEnvelopeV1<DeploymentCatalogsV1> =
        decode_envelope(inputs.catalogs, INPUT_MAGICS[3], head.generation)?;
    if !catalogs.input.endpoints.is_empty() || !catalogs.input.destinations.is_empty() {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }

    let node = NodePolicyInputV1::new(decode_layer(node.input)?)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let site = SitePolicyInputV1::new(decode_layer(site.input)?)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let enforcement = backend
        .input
        .enforcement
        .iter()
        .map(|name| decode_enforcement(name))
        .collect::<Result<Vec<_>, _>>()?;
    let enforcement = BackendEnforcementSetV1::new(enforcement)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let backend = BackendCapabilitiesV1::new(enforcement, Vec::new(), Vec::new())
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;

    Ok(PolicyDeploymentSourcesV1 {
        node,
        site,
        backend,
    })
}

/// Commits the verified head to the fixed root-owned policy authority journal.
///
/// Exact packet replay is harmless. A successor must advance the protected
/// generation by one; no caller can replace a current head with an unrelated
/// same-generation packet. The service must recheck expiry before each later
/// policy-binding decision.
///
/// # Errors
///
/// Returns [`PolicyDeploymentHeadErrorV1`] if source verification, protected
/// replay, generation ordering, durable commit, or readback fails.
pub fn admit_fixed_policy_deployment_head_v1(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let verified =
        verify_policy_deployment_head_v1(packet, inputs, verifying_key, now_unix_seconds)?;
    let _sources = decode_policy_deployment_sources_v1(inputs, verified)?;
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;

    let existing = authority.get(HEAD_KEY)?;
    if existing == Some(packet) {
        return Ok(verified);
    }
    let predecessor_generation = existing
        .map(|current| {
            verify_historical_packet(current, verifying_key)?;
            read_u64(current, 8)
        })
        .transpose()?
        .unwrap_or(0);
    if predecessor_generation.checked_add(1) != Some(verified.generation) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let transaction_digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(packet)
        .finalize();
    let transaction_id: [u8; 16] = transaction_digest[..16]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            HEAD_KEY.to_vec(),
            packet.to_vec(),
        )],
    )?;
    authority.commit(&transaction)?;
    if authority.get(HEAD_KEY)? != Some(packet) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(verified)
}

/// Verifies one externally signed, explicit project-layer source.
///
/// `AOSPPH01` is a 312-byte packet: magic[8], project[16], generation[8],
/// issued/expires[8 each], publisher_generation[8], publisher_digest[32],
/// canonical_project_input_sha256[32], ancestry/compiler/cache/revocation
/// claims[32 each], and a 64-byte Ed25519 signature over the 248-byte
/// payload prefixed by the project signing domain. Only one parentless project
/// is supported by the fixed privileged service in this version.
///
/// # Errors
///
/// Returns an error for an invalid signature, noncanonical or unsupported
/// layer, mismatched project/publisher head, or expired source.
pub fn verify_signed_project_policy_source_v1(
    packet: &[u8],
    input: &[u8],
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<SignedProjectPolicySourceV1, PolicyDeploymentHeadErrorV1> {
    if input.len() > MAXIMUM_PROJECT_INPUT_BYTES {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    verify_project_packet_signature(packet, verifying_key)?;
    let project_bytes: [u8; 16] = packet[8..24]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let project = ProjectId::from_bytes(project_bytes);
    let generation = read_u64(packet, 24)?;
    let issued_at = read_i64(packet, 32)?;
    let expires_at = read_i64(packet, 40)?;
    let publisher_generation = read_u64(packet, 48)?;
    if project_bytes == [0; 16]
        || generation == 0
        || publisher_generation == 0
        || issued_at >= expires_at
        || issued_at > now_unix_seconds
        || now_unix_seconds >= expires_at
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let publisher_digest = ObjectDigest::from_bytes(read_digest(packet, 56)?);
    let input_digest = read_digest(packet, 88)?;
    let prerequisites = [
        ObjectDigest::from_bytes(read_digest(packet, 120)?),
        ObjectDigest::from_bytes(read_digest(packet, 152)?),
        ObjectDigest::from_bytes(read_digest(packet, 184)?),
        ObjectDigest::from_bytes(read_digest(packet, 216)?),
    ];
    if publisher_digest.as_bytes() == &[0; 32]
        || prerequisites
            .iter()
            .any(|claim| claim.as_bytes() == &[0; 32])
        || Sha256::digest(input).as_slice() != input_digest
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    validate_canonical_input(input, "AOSPPL01", generation)?;
    let envelope: ProjectEnvelopeV1 =
        serde_json::from_slice(input).map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    if envelope.magic != "AOSPPL01"
        || envelope.generation != generation
        || envelope.project_id != project.to_string()
        || !envelope.input.grants.is_empty()
        || !envelope.input.namespace_rules.is_empty()
        || !envelope.input.advisory_actions.is_empty()
        || envelope.input.cache_domain != "inherit"
        || envelope.input.revocation != "inherit"
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let layer = decode_layer(DeploymentLayerV1 {
        portable: envelope.input.portable,
        accounting: envelope.input.accounting,
    })?;
    Ok(SignedProjectPolicySourceV1 {
        head: SignedProjectPolicyHeadV1 {
            project,
            generation,
            packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
            input_digest: ObjectDigest::from_bytes(input_digest),
            publisher_generation,
            publisher_digest,
            prerequisites,
            expires_at,
        },
        layer,
    })
}

/// Commits one typed signed project head beneath the current deployment head.
///
/// The trusted controller supplies the project revocation scope independently
/// of the signed packet and the time from its protected clock adapter. Neither
/// value may come from the packet or public request. The caller holds the
/// controller journal before the source-domain writer, and this function opens
/// the root policy journal last. All three remain held while the protected
/// hierarchy tree, publisher revision, cache-domain head, and revocation
/// generation are checked, the immutable mapping is installed if absent, and
/// the signed head is committed under the current AOSPDH01 packet.
///
/// The project tree head alone does not prove the exact Create or complete
/// ancestry transition. Physical cache and effect handoff also remain outside
/// this bounded barrier. This record cannot authorize AOSPCB01 publication.
/// If the second journal commit fails, the trusted immutable mapping may
/// remain; the caller receives no admitted project head.
///
/// # Errors
///
/// Returns an error for invalid source, absent or mismatched protected tree,
/// publisher, cache-domain or revocation currentness, project substitution,
/// noncontiguous generation, or failed protected commit.
pub fn admit_fixed_signed_project_policy_source_v1(
    controller_journal: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    trusted_revocation_scope: RevocationScopeId,
    packet: &[u8],
    input: &[u8],
    verifying_key: &VerifyingKey,
    deployment_packet: &[u8],
    now_unix_seconds: i64,
) -> Result<SignedProjectPolicySourceV1, PolicyDeploymentHeadErrorV1> {
    controller_journal.ensure_protected_authority()?;
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(source_domains)?;
    let (mut authority_journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    admit_signed_project_policy_source_with_journals_v1(
        controller_journal,
        &hierarchy,
        &mut authority_journal,
        trusted_revocation_scope,
        packet,
        input,
        verifying_key,
        deployment_packet,
        now_unix_seconds,
    )
}

/// Holds the fixed root policy-head writer through one bounded action.
///
/// The expected packet is matched to the independently retained root record;
/// this is a lease primitive, not a signed-key verifier or AOSPCB02 issuer.
/// A caller must establish its own trusted signer generation and acquire
/// writers in this order: controller, source-domain ancestry, physical Cache,
/// then this root policy journal. Each prior writer must remain held through
/// root completion. Reversing the order risks a cross-service deadlock.
///
/// # Errors
///
/// Rejects an absent or changed protected deployment head, unsafe root
/// custody, or a failed post-action snapshot check.
pub fn with_fixed_current_policy_head_lease_v1<R>(
    expected_packet: &[u8],
    action: impl FnOnce() -> R,
) -> Result<R, PolicyDeploymentHeadErrorV1> {
    let (journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    with_current_policy_head_lease_from_journal_v1(journal, expected_packet, action)
}

fn with_current_policy_head_lease_from_journal_v1<R>(
    mut journal: Journal,
    expected_packet: &[u8],
    action: impl FnOnce() -> R,
) -> Result<R, PolicyDeploymentHeadErrorV1> {
    with_current_policy_head_lease_in_journal_v1(&mut journal, expected_packet, action)
}

fn with_current_policy_head_lease_in_journal_v1<R>(
    journal: &mut Journal,
    expected_packet: &[u8],
    action: impl FnOnce() -> R,
) -> Result<R, PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(HEAD_KEY)? != Some(expected_packet) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let snapshot = authority.snapshot()?;
    let result = action();
    authority.validate_snapshot_for_effect(&snapshot)?;
    Ok(result)
}

/// Reads an ancestry head while its owning Source writer remains held.
///
/// Policy model tests use an explicit model-only reader so their policy checks
/// do not imply that a bare Tree has production ancestry authority.
pub(super) trait ProjectAncestryHeadReaderV1 {
    /// Returns the exact head for one project under the retained Source cut.
    fn project_ancestry_head_digest(
        &self,
        project: ProjectId,
    ) -> Result<Option<ObjectDigest>, HierarchyProtectedJournalErrorV1>;
}

impl ProjectAncestryHeadReaderV1 for HierarchyProtectedJournalOwnerV1<'_> {
    fn project_ancestry_head_digest(
        &self,
        project: ProjectId,
    ) -> Result<Option<ObjectDigest>, HierarchyProtectedJournalErrorV1> {
        Ok(self
            .project_ancestry_head(project)?
            .map(|current| current.evidence().head()))
    }
}

fn admit_signed_project_policy_source_with_journals_v1(
    controller_journal: &mut Journal,
    hierarchy: &impl ProjectAncestryHeadReaderV1,
    authority_journal: &mut Journal,
    trusted_revocation_scope: RevocationScopeId,
    packet: &[u8],
    input: &[u8],
    verifying_key: &VerifyingKey,
    deployment_packet: &[u8],
    now_unix_seconds: i64,
) -> Result<SignedProjectPolicySourceV1, PolicyDeploymentHeadErrorV1> {
    let verified =
        verify_signed_project_policy_source_v1(packet, input, verifying_key, now_unix_seconds)?;
    let ancestry = hierarchy
        .project_ancestry_head_digest(verified.head.project)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if verified.head.prerequisites[0] != ancestry {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let mut authority =
        authority_journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if authority.get(HEAD_KEY)? != Some(deployment_packet)
        || authority.get(HEAD_KEY_V2)?.is_some()
        || authority.get(INPUT_KEY_V2)?.is_some()
        || verified.head.prerequisites[1].as_bytes() != Sha256::digest(deployment_packet).as_slice()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let existing = authority.get(PROJECT_HEAD_KEY)?;
    let existing_input = authority.get(PROJECT_INPUT_KEY)?;
    if existing.is_some() != existing_input.is_some() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let replay = existing == Some(packet) && existing_input == Some(input);
    if !replay {
        let predecessor = existing
            .zip(existing_input)
            .map(|(current, current_input)| {
                let historical_time = read_i64(current, 32)?;
                verify_signed_project_policy_source_v1(
                    current,
                    current_input,
                    verifying_key,
                    historical_time,
                )?;
                let project: [u8; 16] = current[8..24]
                    .try_into()
                    .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
                if project.as_slice() != verified.head.project.as_bytes() {
                    return Err(PolicyDeploymentHeadErrorV1::StaleHead);
                }
                read_u64(current, 24)
            })
            .transpose()?
            .unwrap_or(0);
        if predecessor.checked_add(1) != Some(verified.head.generation) {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
    }

    bind_signed_project_to_controller_currentness(
        controller_journal,
        verified.head,
        trusted_revocation_scope,
        now_unix_seconds,
    )?;
    if replay {
        return Ok(verified);
    }

    let transaction_digest = Sha256::new()
        .chain_update(PROJECT_TRANSACTION_DOMAIN)
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
                PROJECT_HEAD_KEY.to_vec(),
                packet.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                PROJECT_INPUT_KEY.to_vec(),
                input.to_vec(),
            ),
        ],
    )?;
    authority.commit(&transaction)?;
    if authority.get(PROJECT_HEAD_KEY)? != Some(packet)
        || authority.get(PROJECT_INPUT_KEY)? != Some(input)
        || hierarchy.project_ancestry_head_digest(verified.head.project)? != Some(ancestry)
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(verified)
}

pub(super) fn bind_signed_project_to_controller_currentness(
    controller_journal: &mut Journal,
    head: SignedProjectPolicyHeadV1,
    trusted_revocation_scope: RevocationScopeId,
    now_unix_seconds: i64,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    let mut publisher =
        PublisherPolicyStore::load(controller_journal, PublisherPolicyLimits::default())?;
    let current_policy = publisher
        .current_policy(head.project)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let current_revocation = publisher
        .revocation_head(trusted_revocation_scope)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let current_cache_domain = publisher
        .project_cache_domain_head(head.project)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let revocation_digest = project_revocation_digest(
        head.project,
        trusted_revocation_scope,
        current_revocation.generation,
    );
    if current_policy.generation() != head.publisher_generation
        || current_policy.descriptor().digest() != head.publisher_digest
        || now_unix_seconds < current_policy.not_before()
        || now_unix_seconds >= current_policy.expires_at()
        || current_cache_domain.generation() != current_policy.generation()
        || current_cache_domain.policy_digest() != current_policy.descriptor().digest()
        || head.prerequisites[2] != current_cache_domain.digest()
        || head.prerequisites[3] != revocation_digest
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    match publisher.project_revocation_head(head.project)? {
        Some(bound) if bound.scope() == trusted_revocation_scope => {}
        Some(_) => return Err(PolicyDeploymentHeadErrorV1::StaleHead),
        None => {
            let transaction_digest = Sha256::new()
                .chain_update(PROJECT_REVOCATION_TRANSACTION_DOMAIN)
                .chain_update(head.project.as_bytes())
                .chain_update(trusted_revocation_scope.as_bytes())
                .finalize();
            let transaction_id: [u8; 16] = transaction_digest[..16]
                .try_into()
                .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
            publisher.bind_project_revocation_scope_from_trusted_controller(
                transaction_id,
                head.project,
                trusted_revocation_scope,
            )?;
        }
    }
    let bound = publisher
        .project_revocation_head(head.project)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if bound.generation() != current_revocation.generation || bound.digest() != revocation_digest {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(())
}

fn verify_project_packet_signature(
    packet: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if packet.len() != PROJECT_PACKET_BYTES || &packet[..8] != PROJECT_MAGIC {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let signature_bytes: [u8; 64] = packet[PROJECT_PAYLOAD_BYTES..]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let mut signed = Vec::with_capacity(PROJECT_SIGNING_DOMAIN.len() + PROJECT_PAYLOAD_BYTES);
    signed.extend_from_slice(PROJECT_SIGNING_DOMAIN);
    signed.extend_from_slice(&packet[..PROJECT_PAYLOAD_BYTES]);
    verifying_key
        .verify(&signed, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidSignature)
}

fn read_digest(packet: &[u8], offset: usize) -> Result<[u8; 32], PolicyDeploymentHeadErrorV1> {
    packet
        .get(offset..offset + 32)
        .and_then(|part| part.try_into().ok())
        .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)
}

fn decode_envelope<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    magic: &str,
    generation: u64,
) -> Result<DeploymentEnvelopeV1<T>, PolicyDeploymentHeadErrorV1> {
    let envelope: DeploymentEnvelopeV1<T> =
        serde_json::from_slice(bytes).map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    if envelope.magic != magic || envelope.generation != generation {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    Ok(envelope)
}

pub(super) fn decode_layer(
    wire: DeploymentLayerV1,
) -> Result<PolicyLayerV1, PolicyDeploymentHeadErrorV1> {
    if wire.portable.len() != PORTABLE_LIMIT_DIMENSIONS.len()
        || wire.accounting.len() != ResourceDimension::COUNT
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
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
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    PolicyLayerV1::new(
        Vec::new(),
        resources,
        Vec::new(),
        Vec::new(),
        super::CacheDomainInputV1::Inherit,
        super::RevocationInputV1::Inherit,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)
}

fn decode_limit(
    wire: DeploymentLimitV1,
    key: HardResourceKeyV1,
) -> Result<HardLimitRequestV1, PolicyDeploymentHeadErrorV1> {
    let (value, enforcement) = match (wire.kind.as_str(), wire.amount, wire.enforcement) {
        ("inherit", None, None) => (HardLimitValueV1::Inherit, None),
        ("bounded", Some(amount), Some(name)) => (
            HardLimitValueV1::Bounded(amount),
            Some(decode_enforcement(&name)?),
        ),
        _ => return Err(PolicyDeploymentHeadErrorV1::InvalidHead),
    };
    HardLimitRequestV1::new(key, value, enforcement)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)
}

fn decode_enforcement(name: &str) -> Result<HardEnforcementV1, PolicyDeploymentHeadErrorV1> {
    match name {
        "cgroup-v2" => Ok(HardEnforcementV1::CgroupV2),
        "broker-ledger" => Ok(HardEnforcementV1::BrokerLedger),
        "zfs-quota" => Ok(HardEnforcementV1::ZfsQuota),
        "node-bounded-shared-residency" => Ok(HardEnforcementV1::NodeBoundedSharedResidency),
        "hard-isolated-residency" => Ok(HardEnforcementV1::HardIsolatedResidency),
        "combined-file-descriptor" => Ok(HardEnforcementV1::CombinedFileDescriptor),
        "combined-memory-accounting" => Ok(HardEnforcementV1::CombinedMemoryAccounting),
        _ => Err(PolicyDeploymentHeadErrorV1::InvalidHead),
    }
}

pub(super) fn verify_historical_packet(
    packet: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if packet.len() != PACKET_BYTES || &packet[..8] != MAGIC {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let issued_at = read_i64(packet, 16)?;
    let expires_at = read_i64(packet, 24)?;
    if read_u64(packet, 8)? == 0 || issued_at >= expires_at {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }

    let signature_bytes: [u8; 64] = packet[PAYLOAD_BYTES..]
        .try_into()
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let mut signed = Vec::with_capacity(SIGNING_DOMAIN.len() + PAYLOAD_BYTES);
    signed.extend_from_slice(SIGNING_DOMAIN);
    signed.extend_from_slice(&packet[..PAYLOAD_BYTES]);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidSignature)
}

pub(super) fn validate_canonical_input(
    bytes: &[u8],
    expected_magic: &str,
    generation: u64,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_INPUT_BYTES {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    if value.get("magic").and_then(Value::as_str) != Some(expected_magic)
        || value.get("generation").and_then(Value::as_u64) != Some(generation)
        || value.get("input").and_then(Value::as_object).is_none()
        || serde_json::to_vec(&value).map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?
            != bytes
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Read as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use aos_sandbox_core::format::encode_policy;
    use aos_sandbox_core::model::{
        CacheDomain, CacheDomainKind, LimitDimension, Policy, ResourceProfile, RevocationMode,
        RevocationPolicy,
    };
    use aos_sandbox_core::{CacheDomainId, DecodeLimits, ObjectDescriptor, Revision, SandboxId};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::JournalLimits;
    use crate::hierarchy::graph::SandboxTreeV1;
    use crate::hierarchy::model::TreeLimitsV1;
    use crate::hierarchy::protected_journal::{
        HierarchyProtectedJournalKeyV1, HierarchyProtectedRecordKindV1,
        HierarchyProtectedReplayValidatorV1, HierarchyReducerRecordV1,
        claim_hierarchy_protected_journal_v1, hierarchy_reducer_envelope_v1,
        replay_project_ancestry_head_v1,
    };
    use crate::policy_compiler::project_source_v2::admit_signed_project_policy_source_with_journals_v2;
    use crate::policy_compiler::{
        AuthenticatedEndpointCatalogV1, AuthenticatedNamespaceCatalogV1,
        AuthenticatedSandboxProjectRelationV1, EndpointCatalogVerifierV1,
        NamespaceCatalogVerifierV1, PolicyCompilerInputV1, PolicyCompilerLimitsV1,
        PolicyCompilerV1, ProjectPolicyInputV1, RequestPolicyInputV1,
        SandboxProjectRelationVerifierV1,
    };
    use crate::publisher_policy::{PreparedPublisherPolicyRevisionV1, PublisherRevocationHeadV1};

    struct CompilerFixtureVerifier;

    impl SandboxProjectRelationVerifierV1 for CompilerFixtureVerifier {
        fn verify(&self, _: SandboxId, _: ProjectId, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl EndpointCatalogVerifierV1 for CompilerFixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    impl NamespaceCatalogVerifierV1 for CompilerFixtureVerifier {
        fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
            true
        }
    }

    fn open_journal(directory: &std::path::Path, name: &str) -> Journal {
        let uid = fs::metadata(directory)
            .expect("test directory metadata")
            .uid();
        Journal::open_protected_at_uid(directory, name, JournalLimits::default(), uid)
            .expect("protected journal")
            .0
    }

    fn project_input(project: ProjectId) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": {
                "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
                "advisory_actions": [],
                "cache_domain": "inherit",
                "grants": [],
                "namespace_rules": [],
                "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
                "revocation": "inherit",
            },
            "magic": "AOSPPL01",
            "project_id": project.to_string(),
        }))
        .expect("canonical project input")
    }

    fn signed_project_packet(
        project: ProjectId,
        publisher_digest: ObjectDigest,
        ancestry_digest: ObjectDigest,
        cache_domain_digest: ObjectDigest,
        revocation_digest: ObjectDigest,
        deployment_packet: &[u8],
        input: &[u8],
        key: &SigningKey,
    ) -> Vec<u8> {
        let mut packet = PROJECT_MAGIC.to_vec();
        packet.extend_from_slice(project.as_bytes());
        packet.extend_from_slice(&1_u64.to_be_bytes());
        packet.extend_from_slice(&10_i64.to_be_bytes());
        packet.extend_from_slice(&30_i64.to_be_bytes());
        packet.extend_from_slice(&1_u64.to_be_bytes());
        packet.extend_from_slice(publisher_digest.as_bytes());
        packet.extend_from_slice(&Sha256::digest(input));
        packet.extend_from_slice(ancestry_digest.as_bytes());
        packet.extend_from_slice(&Sha256::digest(deployment_packet));
        packet.extend_from_slice(cache_domain_digest.as_bytes());
        packet.extend_from_slice(revocation_digest.as_bytes());

        let mut signed = PROJECT_SIGNING_DOMAIN.to_vec();
        signed.extend_from_slice(&packet);
        packet.extend_from_slice(&key.sign(&signed).to_bytes());
        packet
    }

    fn fixture() -> (
        tempfile::TempDir,
        Journal,
        ProtectedSourceDomainJournalOwnerV1,
        Journal,
        ProjectId,
        RevocationScopeId,
        ObjectDigest,
    ) {
        let directory = tempfile::tempdir().expect("test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let mut controller = open_journal(directory.path(), "controller.journal");
        let project = ProjectId::from_bytes([1; 16]);
        let mut source_domains = ProtectedSourceDomainJournalOwnerV1::from_test_journal(
            open_journal(directory.path(), "source-domains.journal"),
        );
        install_tree_revision(&mut source_domains, project, 1, None);
        let mut authority = open_journal(directory.path(), "authority.journal");
        let scope = RevocationScopeId::from_bytes([7; 16]);
        let domain = CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([1; 16]));
        let policy = Policy::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResourceProfile::new(Vec::new()).expect("empty resource profile"),
            Vec::new(),
            domain,
            RevocationPolicy::new(RevocationMode::DenyNew, 0),
            None,
            Vec::new(),
        )
        .expect("publisher policy");
        let prepared = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            project,
            1,
            10,
            30,
            &encode_policy(&policy),
            DecodeLimits::default(),
        )
        .expect("prepared policy");
        let publisher_digest = prepared.descriptor().digest();
        let mut store =
            PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
                .expect("publisher store");
        store
            .publish_policy_from_trusted_controller([1; 16], None, &prepared)
            .expect("current publisher policy");
        store
            .advance_revocation_from_trusted_controller(
                [2; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope,
                    generation: 1,
                },
            )
            .expect("current revocation head");
        drop(store);

        // This test exercises the project transition after deployment custody.
        let deployment_packet = b"current-deployment";
        let transaction = JournalTransaction::new(
            [3; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                HEAD_KEY.to_vec(),
                deployment_packet.to_vec(),
            )],
        )
        .expect("deployment transaction");
        authority
            .commit(&transaction)
            .expect("current deployment head");
        (
            directory,
            controller,
            source_domains,
            authority,
            project,
            scope,
            publisher_digest,
        )
    }

    fn install_tree_revision(
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        project: ProjectId,
        generation: u64,
        predecessor: Option<ObjectDigest>,
    ) {
        let limits = TreeLimitsV1::new(1, 8, 8, 7, 7, 7, 7).expect("tree limits");
        let tree =
            SandboxTreeV1::from_records(project, Revision::new(generation), limits, Vec::new())
                .expect("canonical empty project tree");
        let mut identity = Vec::with_capacity(48);
        for _ in 0..3 {
            identity.extend_from_slice(project.as_bytes());
        }
        let key =
            HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)
                .expect("tree key");
        let validator =
            HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])
                .expect("empty hierarchy head validator");
        let envelope = hierarchy_reducer_envelope_v1(
            key,
            generation,
            predecessor,
            HierarchyReducerRecordV1::Tree(&tree),
            &validator,
        )
        .expect("tree envelope");
        let mut journal = claim_hierarchy_protected_journal_v1(source_domains.journal(), validator)
            .expect("claimed hierarchy journal");
        let prepared = journal
            .plan([generation as u8; 16], vec![envelope])
            .expect("tree transaction");
        assert!(matches!(
            journal.commit(prepared).expect("tree commit"),
            crate::hierarchy::protected_journal::HierarchyJournalCommitOutcomeV1::Applied(_)
        ));
    }

    fn current_ancestry_head(
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        project: ProjectId,
    ) -> ObjectDigest {
        model_ancestry_head(source_domains, project).expect("model project tree")
    }

    fn model_ancestry_head(
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        project: ProjectId,
    ) -> Option<ObjectDigest> {
        // These policy tests use a synthetic, unsigned Tree to exercise
        // policy-head matching; production ancestry readers reject that Tree.
        let validator =
            HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])
                .expect("model hierarchy validator");
        let journal = claim_hierarchy_protected_journal_v1(source_domains.journal(), validator)
            .expect("model hierarchy journal");
        let projection = journal.replay().expect("model hierarchy projection");
        let key = hierarchy_project_tree_key(project);
        projection
            .records()
            .iter()
            .find(|record| record.key() == &key)
            .map(|record| record.digest())
    }

    fn hierarchy_project_tree_key(project: ProjectId) -> HierarchyProtectedJournalKeyV1 {
        let mut identity = Vec::with_capacity(48);
        for _ in 0..3 {
            identity.extend_from_slice(project.as_bytes());
        }
        HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)
            .expect("model Tree key")
    }

    struct ModelOnlyAncestryReaderV1 {
        project: ProjectId,
        head: Option<ObjectDigest>,
    }

    impl ProjectAncestryHeadReaderV1 for ModelOnlyAncestryReaderV1 {
        fn project_ancestry_head_digest(
            &self,
            project: ProjectId,
        ) -> Result<Option<ObjectDigest>, HierarchyProtectedJournalErrorV1> {
            Ok(if project == self.project {
                self.head
            } else {
                None
            })
        }
    }

    fn model_ancestry_reader(
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        project: ProjectId,
    ) -> ModelOnlyAncestryReaderV1 {
        ModelOnlyAncestryReaderV1 {
            project,
            head: model_ancestry_head(source_domains, project),
        }
    }

    #[test]
    fn bare_tree_has_no_cold_ancestry_authority() {
        let (_directory, _controller, mut source_domains, _authority, project, _, _) = fixture();

        assert!(matches!(
            HierarchyProtectedJournalOwnerV1::claim(&mut source_domains),
            Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)
        ));
        assert!(matches!(
            replay_project_ancestry_head_v1(source_domains.journal(), project),
            Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)
        ));
    }

    #[test]
    fn absent_tree_preserves_unrelated_source_state() {
        let directory = tempfile::tempdir().expect("private source fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private source directory");
        let mut journal = open_journal(directory.path(), "source-domains.journal");
        let transaction = JournalTransaction::new(
            [86; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"unrelated-source-state".to_vec(),
                vec![1],
            )],
        )
        .expect("unrelated source transaction");
        journal
            .commit(&transaction)
            .expect("unrelated source record");

        let project = ProjectId::from_bytes([87; 16]);
        let mut source_domains = ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal);
        let hierarchy = HierarchyProtectedJournalOwnerV1::claim(&mut source_domains)
            .expect("empty hierarchy claim");
        assert!(
            hierarchy
                .project_ancestry_head(project)
                .expect("absent project tree")
                .is_none()
        );
        drop(hierarchy);
        assert!(
            replay_project_ancestry_head_v1(source_domains.journal(), project)
                .expect("cold absent project tree")
                .is_none()
        );
    }

    fn admit_with_test_source(
        controller: &mut Journal,
        source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
        authority: &mut Journal,
        scope: RevocationScopeId,
        packet: &[u8],
        input: &[u8],
        key: &VerifyingKey,
        deployment_packet: &[u8],
        now: i64,
    ) -> Result<SignedProjectPolicySourceV1, PolicyDeploymentHeadErrorV1> {
        let project = packet
            .get(8..24)
            .and_then(|bytes| bytes.try_into().ok())
            .map(ProjectId::from_bytes)
            .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?;
        let hierarchy = model_ancestry_reader(source_domains, project);
        admit_signed_project_policy_source_with_journals_v1(
            controller,
            &hierarchy,
            authority,
            scope,
            packet,
            input,
            key,
            deployment_packet,
            now,
        )
    }

    fn current_cache_domain_digest(controller: &mut Journal, project: ProjectId) -> ObjectDigest {
        PublisherPolicyStore::load(controller, PublisherPolicyLimits::default())
            .expect("publisher store")
            .project_cache_domain_head(project)
            .expect("project cache-domain currentness")
            .expect("current cache-domain head")
            .digest()
    }

    fn deployment_input(magic: &str, input: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": input,
            "magic": magic,
        }))
        .expect("canonical deployment input")
    }

    fn signed_deployment_fixture(key: &SigningKey) -> (Vec<u8>, [Vec<u8>; 4]) {
        let portable = PORTABLE_LIMIT_DIMENSIONS
            .map(|dimension| {
                let enforcement = match dimension {
                    LimitDimension::Bytes
                    | LimitDimension::Inodes
                    | LimitDimension::SnapshotCount => "zfs-quota",
                    LimitDimension::Processes
                    | LimitDimension::Memory
                    | LimitDimension::CpuWeight
                    | LimitDimension::CpuQuota
                    | LimitDimension::IoWeight
                    | LimitDimension::IoBandwidth => "cgroup-v2",
                    LimitDimension::OpenFiles => "combined-file-descriptor",
                    LimitDimension::FuseMemory => "combined-memory-accounting",
                    LimitDimension::CacheBytes => "node-bounded-shared-residency",
                    LimitDimension::MountCount
                    | LimitDimension::FuseRequests
                    | LimitDimension::ChildCount
                    | LimitDimension::ExecutionCount => "broker-ledger",
                };
                serde_json::json!({"amount": 4096, "enforcement": enforcement, "kind": "bounded"})
            })
            .to_vec();
        let accounting = vec![
            serde_json::json!({"amount": 4096, "enforcement": "broker-ledger", "kind": "bounded"});
            ResourceDimension::COUNT
        ];
        let bounded = serde_json::json!({
            "accounting": accounting,
            "portable": portable,
        });
        let inputs = [
            deployment_input("AOSPNI01", bounded.clone()),
            deployment_input("AOSPSI01", bounded),
            deployment_input(
                "AOSPBI01",
                serde_json::json!({
                    "enforcement": [
                        "cgroup-v2", "broker-ledger", "zfs-quota",
                        "node-bounded-shared-residency", "combined-file-descriptor",
                        "combined-memory-accounting"
                    ]
                }),
            ),
            deployment_input(
                "AOSPCI01",
                serde_json::json!({"destinations": [], "endpoints": []}),
            ),
        ];
        let mut packet = MAGIC.to_vec();
        packet.extend_from_slice(&1_u64.to_be_bytes());
        packet.extend_from_slice(&10_i64.to_be_bytes());
        packet.extend_from_slice(&30_i64.to_be_bytes());
        for input in &inputs {
            packet.extend_from_slice(&Sha256::digest(input));
        }
        let mut signed = SIGNING_DOMAIN.to_vec();
        signed.extend_from_slice(&packet);
        packet.extend_from_slice(&key.sign(&signed).to_bytes());
        (packet, inputs)
    }

    fn explicit_project_input(project: ProjectId) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": {
                "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
                "advisory_actions": [],
                "cache_domain": "project",
                "grants": [],
                "namespace_rules": [],
                "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
                "revocation": {"grace_nanos": 0, "mode": "deny-new"},
            },
            "magic": "AOSPPL02",
            "project_id": project.to_string(),
        }))
        .expect("canonical explicit project input")
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_explicit_project_packet(
        project: ProjectId,
        publisher_digest: ObjectDigest,
        ancestry_digest: ObjectDigest,
        cache_domain_digest: ObjectDigest,
        revocation_digest: ObjectDigest,
        deployment_packet: &[u8],
        input: &[u8],
        key: &SigningKey,
    ) -> Vec<u8> {
        let mut packet = signed_project_packet(
            project,
            publisher_digest,
            ancestry_digest,
            cache_domain_digest,
            revocation_digest,
            deployment_packet,
            input,
            key,
        );
        packet.truncate(PROJECT_PAYLOAD_BYTES);
        packet[..8].copy_from_slice(b"AOSPPH02");
        packet.extend_from_slice(&2_u64.to_be_bytes());
        packet.extend_from_slice(&3_u64.to_be_bytes());
        let mut signed = b"aos.sandbox.policy-project-head.v2\0".to_vec();
        signed.extend_from_slice(&packet);
        packet.extend_from_slice(&key.sign(&signed).to_bytes());
        packet
    }

    #[test]
    fn explicit_project_source_replays_durably_and_rejects_pin_rotation_or_stale_ancestry() {
        let (
            directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let deployment_key = SigningKey::from_bytes(&[5; 32]);
        let project_key = SigningKey::from_bytes(&[6; 32]);
        let (deployment_packet, deployment_input_bytes) =
            signed_deployment_fixture(&deployment_key);
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: &deployment_input_bytes[0],
            site: &deployment_input_bytes[1],
            backend: &deployment_input_bytes[2],
            catalogs: &deployment_input_bytes[3],
        };
        let pins = encode_policy_signer_pins_v1(
            2,
            &deployment_key.verifying_key(),
            3,
            &project_key.verifying_key(),
        )
        .expect("fixed signer pins");
        let transaction = JournalTransaction::new(
            [41; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY.to_vec(),
                    deployment_packet.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SIGNER_PINS_KEY.to_vec(),
                    pins,
                ),
            ],
        )
        .expect("root source transaction");
        authority.commit(&transaction).expect("root source custody");

        let ancestry = current_ancestry_head(&mut source_domains, project);
        let input = explicit_project_input(project);
        let packet = signed_explicit_project_packet(
            project,
            publisher_digest,
            ancestry,
            current_cache_domain_digest(&mut controller, project),
            project_revocation_digest(project, scope, 1),
            &deployment_packet,
            &input,
            &project_key,
        );
        let admit = |controller: &mut Journal,
                     sources: &mut ProtectedSourceDomainJournalOwnerV1,
                     authority: &mut Journal,
                     deployment_generation: u64| {
            let hierarchy = model_ancestry_reader(sources, project);
            admit_signed_project_policy_source_with_journals_v2(
                controller,
                &hierarchy,
                authority,
                scope,
                &packet,
                &input,
                &project_key.verifying_key(),
                3,
                &deployment_packet,
                &deployment_inputs,
                &deployment_key.verifying_key(),
                deployment_generation,
                20,
            )
        };
        let admitted = admit(&mut controller, &mut source_domains, &mut authority, 2)
            .expect("explicit current source");
        assert_eq!(
            admitted.head().packet_digest().as_bytes(),
            Sha256::digest(&packet).as_slice()
        );
        assert!(matches!(
            admitted.layer().cache_domain(),
            crate::policy_compiler::CacheDomainInputV1::Exact(_)
        ));
        assert!(matches!(
            admitted.layer().revocation(),
            crate::policy_compiler::RevocationInputV1::Exact(_)
        ));
        let deployment_head = verify_policy_deployment_head_v1(
            &deployment_packet,
            &deployment_inputs,
            &deployment_key.verifying_key(),
            20,
        )
        .expect("current signed deployment head");
        let deployment = decode_policy_deployment_sources_v1(&deployment_inputs, deployment_head)
            .expect("typed deployment sources");
        let inherited_wire = serde_json::json!({
            "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
            "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
        });
        let inherited =
            decode_layer(serde_json::from_value(inherited_wire).expect("inherited request source"))
                .expect("typed inherited request");
        let verifier = CompilerFixtureVerifier;
        let sandbox = SandboxId::from_bytes([11; 16]);
        let compiler_input = PolicyCompilerInputV1::new(
            AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &verifier)
                .expect("current relation"),
            deployment.node().clone(),
            deployment.site().clone(),
            ProjectPolicyInputV1::new(project, admitted.layer().clone())
                .expect("explicit project layer"),
            Vec::new(),
            RequestPolicyInputV1::new(inherited).expect("inherited request"),
            AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("empty catalog"),
            AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
                .expect("empty namespace catalog"),
            deployment.backend().clone(),
            PolicyCompilerLimitsV1::DEFAULT,
        )
        .expect("complete compiler input");
        PolicyCompilerV1::compile(compiler_input).expect("explicit project choices resolve");

        let legacy_input = project_input(project);
        let legacy_packet = signed_project_packet(
            project,
            publisher_digest,
            ancestry,
            current_cache_domain_digest(&mut controller, project),
            project_revocation_digest(project, scope, 1),
            &deployment_packet,
            &legacy_input,
            &project_key,
        );
        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &legacy_packet,
                &legacy_input,
                &project_key.verifying_key(),
                &deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        drop(authority);

        let mut reopened = open_journal(directory.path(), "authority.journal");
        admit(&mut controller, &mut source_domains, &mut reopened, 2)
            .expect("durable exact replay");
        assert!(matches!(
            admit(&mut controller, &mut source_domains, &mut reopened, 4),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        install_tree_revision(&mut source_domains, project, 2, Some(ancestry));
        assert!(matches!(
            admit(&mut controller, &mut source_domains, &mut reopened, 2),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
    }

    #[test]
    fn root_signer_pins_replay_exactly_and_reject_rotation_or_legacy_head() {
        let directory = tempfile::tempdir().expect("private root fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let deployment = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[6; 32]).verifying_key();
        let mut journal = open_journal(directory.path(), "signer-pins.journal");

        admit_policy_signer_pins_in_journal_v1(&mut journal, 3, &deployment, 9, &project)
            .expect("initial protected pins");
        admit_policy_signer_pins_in_journal_v1(&mut journal, 3, &deployment, 9, &project)
            .expect("exact replay");
        assert!(matches!(
            admit_policy_signer_pins_in_journal_v1(&mut journal, 4, &deployment, 9, &project),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        assert!(matches!(
            admit_policy_signer_pins_in_journal_v1(&mut journal, 3, &project, 9, &deployment),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        drop(journal);

        let mut reopened = open_journal(directory.path(), "signer-pins.journal");
        admit_policy_signer_pins_in_journal_v1(&mut reopened, 3, &deployment, 9, &project)
            .expect("durable exact replay");

        let (_directory, _controller, _sources, mut legacy, ..) = fixture();
        assert!(matches!(
            admit_policy_signer_pins_in_journal_v1(&mut legacy, 3, &deployment, 9, &project),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));

        let unknown_directory = tempfile::tempdir().expect("legacy root fixture");
        fs::set_permissions(unknown_directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let mut unknown = open_journal(unknown_directory.path(), "legacy.journal");
        let transaction = JournalTransaction::new(
            [31; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"legacy-unknown".to_vec(),
                vec![1],
            )],
        )
        .expect("legacy transaction");
        unknown.commit(&transaction).expect("legacy record");
        assert!(matches!(
            admit_policy_signer_pins_in_journal_v1(&mut unknown, 3, &deployment, 9, &project),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
    }

    #[test]
    fn root_head_lease_holds_exact_packet_and_rejects_stale_before_action() {
        let (_directory, _controller, _source_domains, mut authority, ..) = fixture();
        let mut action_count = 0;

        assert!(matches!(
            with_current_policy_head_lease_in_journal_v1(
                &mut authority,
                b"stale-deployment",
                || action_count += 1,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        assert_eq!(action_count, 0);

        with_current_policy_head_lease_in_journal_v1(&mut authority, b"current-deployment", || {
            action_count += 1
        })
        .expect("current protected root head");
        assert_eq!(action_count, 1);
    }

    #[test]
    fn root_head_lease_disconnect_releases_writer_without_completion() {
        let (directory, _controller, _source_domains, authority, ..) = fixture();
        let (mut server, client) = UnixStream::pair().expect("local lease pair");
        drop(client);

        let completed = with_current_policy_head_lease_from_journal_v1(
            authority,
            b"current-deployment",
            || {
                let uid = fs::metadata(directory.path())
                    .expect("directory metadata")
                    .uid();
                assert!(matches!(
                    Journal::open_protected_at_uid(
                        directory.path(),
                        "authority.journal",
                        JournalLimits::default(),
                        uid,
                    ),
                    Err(JournalError::AlreadyLocked)
                ));
                let mut acknowledgement = [0_u8; 1];
                server.read_exact(&mut acknowledgement)
            },
        )
        .expect("current root head");
        assert_eq!(
            completed.expect_err("disconnected peer").kind(),
            io::ErrorKind::UnexpectedEof
        );

        let _reopened = open_journal(directory.path(), "authority.journal");
    }

    #[test]
    fn root_head_lease_timeout_releases_writer_without_completion() {
        let (directory, _controller, _source_domains, authority, ..) = fixture();
        let (mut server, _client) = UnixStream::pair().expect("local lease pair");
        server
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("bounded lease timeout");

        let completed = with_current_policy_head_lease_from_journal_v1(
            authority,
            b"current-deployment",
            || {
                let mut acknowledgement = [0_u8; 1];
                server.read_exact(&mut acknowledgement)
            },
        )
        .expect("current root head");
        let error = completed.expect_err("unacknowledged lease");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));

        let _reopened = open_journal(directory.path(), "authority.journal");
    }

    #[test]
    fn signed_project_admission_installs_trusted_revocation_mapping_and_rechecks_replay() {
        let (
            _directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let revocation_digest = project_revocation_digest(project, scope, 1);
        let packet = signed_project_packet(
            project,
            publisher_digest,
            current_ancestry_head(&mut source_domains, project),
            current_cache_domain_digest(&mut controller, project),
            revocation_digest,
            deployment_packet,
            &input,
            &key,
        );

        let admitted = admit_with_test_source(
            &mut controller,
            &mut source_domains,
            &mut authority,
            scope,
            &packet,
            &input,
            &key.verifying_key(),
            deployment_packet,
            20,
        )
        .expect("signed project admission");
        assert_eq!(admitted.head().prerequisite_claims()[3], revocation_digest);
        assert_eq!(
            authority.get(RecordNamespace::DesiredState, PROJECT_HEAD_KEY),
            Some(packet.as_slice())
        );
        let mut store =
            PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
                .expect("publisher store");
        let bound = store
            .project_revocation_head(project)
            .expect("protected mapping")
            .expect("installed mapping");
        assert_eq!(bound.scope(), scope);
        assert_eq!(bound.digest(), revocation_digest);
        store
            .advance_revocation_from_trusted_controller(
                [4; 16],
                Some(1),
                PublisherRevocationHeadV1 {
                    scope,
                    generation: 2,
                },
            )
            .expect("revocation advancement");
        drop(store);

        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
    }

    #[test]
    fn mismatched_signed_revocation_claim_does_not_install_mapping_or_head() {
        let (
            _directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let packet = signed_project_packet(
            project,
            publisher_digest,
            current_ancestry_head(&mut source_domains, project),
            current_cache_domain_digest(&mut controller, project),
            ObjectDigest::from_bytes([5; 32]),
            deployment_packet,
            &input,
            &key,
        );

        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        assert!(
            PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
                .expect("publisher store")
                .project_revocation_head(project)
                .expect("protected mapping")
                .is_none()
        );
        assert!(
            authority
                .get(RecordNamespace::DesiredState, PROJECT_HEAD_KEY)
                .is_none()
        );
    }

    #[test]
    fn mismatched_signed_cache_domain_claim_does_not_install_mapping_or_head() {
        let (
            _directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let current_cache_domain = current_cache_domain_digest(&mut controller, project);
        let wrong_cache_domain = ObjectDigest::from_bytes([4; 32]);
        assert_ne!(current_cache_domain, wrong_cache_domain);
        let packet = signed_project_packet(
            project,
            publisher_digest,
            current_ancestry_head(&mut source_domains, project),
            wrong_cache_domain,
            project_revocation_digest(project, scope, 1),
            deployment_packet,
            &input,
            &key,
        );

        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        assert!(
            PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
                .expect("publisher store")
                .project_revocation_head(project)
                .expect("protected mapping")
                .is_none()
        );
        assert!(
            authority
                .get(RecordNamespace::DesiredState, PROJECT_HEAD_KEY)
                .is_none()
        );
    }

    #[test]
    fn mismatched_signed_ancestry_claim_does_not_install_mapping_or_head() {
        let (
            _directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let wrong_ancestry = ObjectDigest::from_bytes([3; 32]);
        assert_ne!(
            current_ancestry_head(&mut source_domains, project),
            wrong_ancestry
        );
        let packet = signed_project_packet(
            project,
            publisher_digest,
            wrong_ancestry,
            current_cache_domain_digest(&mut controller, project),
            project_revocation_digest(project, scope, 1),
            deployment_packet,
            &input,
            &key,
        );

        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        assert!(
            PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
                .expect("publisher store")
                .project_revocation_head(project)
                .expect("protected mapping")
                .is_none()
        );
        assert!(
            authority
                .get(RecordNamespace::DesiredState, PROJECT_HEAD_KEY)
                .is_none()
        );
    }

    #[test]
    fn absent_protected_project_tree_rejects_signed_ancestry_claim() {
        let (
            directory,
            mut controller,
            source_domains,
            authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        drop(authority);
        drop(source_domains);
        let mut source_domains = ProtectedSourceDomainJournalOwnerV1::from_test_journal(
            open_journal(directory.path(), "empty-source-domains.journal"),
        );
        let mut authority = open_journal(directory.path(), "authority.journal");
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let packet = signed_project_packet(
            project,
            publisher_digest,
            ObjectDigest::from_bytes([3; 32]),
            current_cache_domain_digest(&mut controller, project),
            project_revocation_digest(project, scope, 1),
            deployment_packet,
            &input,
            &key,
        );

        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        assert!(
            authority
                .get(RecordNamespace::DesiredState, PROJECT_HEAD_KEY)
                .is_none()
        );
    }

    #[test]
    fn source_domain_tree_successor_invalidates_signed_project_replay() {
        let (
            directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let initial_ancestry = current_ancestry_head(&mut source_domains, project);
        let packet = signed_project_packet(
            project,
            publisher_digest,
            initial_ancestry,
            current_cache_domain_digest(&mut controller, project),
            project_revocation_digest(project, scope, 1),
            deployment_packet,
            &input,
            &key,
        );
        admit_with_test_source(
            &mut controller,
            &mut source_domains,
            &mut authority,
            scope,
            &packet,
            &input,
            &key.verifying_key(),
            deployment_packet,
            20,
        )
        .expect("initial signed project admission");

        // Release both owners before cold replay, and reacquire the source
        // writer ahead of the root journal under the same lock order.
        drop(authority);
        drop(source_domains);
        let mut source_domains = ProtectedSourceDomainJournalOwnerV1::from_test_journal(
            open_journal(directory.path(), "source-domains.journal"),
        );
        assert_eq!(
            current_ancestry_head(&mut source_domains, project),
            initial_ancestry
        );
        install_tree_revision(&mut source_domains, project, 2, Some(initial_ancestry));
        drop(source_domains);
        let mut source_domains = ProtectedSourceDomainJournalOwnerV1::from_test_journal(
            open_journal(directory.path(), "source-domains.journal"),
        );
        let mut authority = open_journal(directory.path(), "authority.journal");
        assert_ne!(
            current_ancestry_head(&mut source_domains, project),
            initial_ancestry
        );
        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
    }

    #[test]
    fn trusted_scope_cannot_replace_an_existing_project_mapping() {
        let (
            _directory,
            mut controller,
            mut source_domains,
            mut authority,
            project,
            scope,
            publisher_digest,
        ) = fixture();
        let other_scope = RevocationScopeId::from_bytes([9; 16]);
        let mut store =
            PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
                .expect("publisher store");
        store
            .bind_project_revocation_scope_from_trusted_controller([4; 16], project, scope)
            .expect("existing project mapping");
        store
            .advance_revocation_from_trusted_controller(
                [5; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope: other_scope,
                    generation: 1,
                },
            )
            .expect("other revocation scope");
        drop(store);

        let key = SigningKey::from_bytes(&[9; 32]);
        let input = project_input(project);
        let deployment_packet = b"current-deployment";
        let packet = signed_project_packet(
            project,
            publisher_digest,
            current_ancestry_head(&mut source_domains, project),
            current_cache_domain_digest(&mut controller, project),
            project_revocation_digest(project, other_scope, 1),
            deployment_packet,
            &input,
            &key,
        );

        assert!(matches!(
            admit_with_test_source(
                &mut controller,
                &mut source_domains,
                &mut authority,
                other_scope,
                &packet,
                &input,
                &key.verifying_key(),
                deployment_packet,
                20,
            ),
            Err(PolicyDeploymentHeadErrorV1::StaleHead)
        ));
        let bound = PublisherPolicyStore::load(&mut controller, PublisherPolicyLimits::default())
            .expect("publisher store")
            .project_revocation_head(project)
            .expect("protected mapping")
            .expect("existing mapping remains");
        assert_eq!(bound.scope(), scope);
        assert!(
            authority
                .get(RecordNamespace::DesiredState, PROJECT_HEAD_KEY)
                .is_none()
        );
    }
}
