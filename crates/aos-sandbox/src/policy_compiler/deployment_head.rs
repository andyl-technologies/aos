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
//! current deployment head. Only the deployment-head cross-link is verified
//! here; the other claims and public Create admission need independent proof
//! before an AOSPCB01 binding can be issued.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceDimension};

use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

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
const HEAD_KEY: &[u8] = b"\0aos-policy-deployment-head-v1\0";
const PAYLOAD_BYTES: usize = 160;
const PACKET_BYTES: usize = PAYLOAD_BYTES + 64;
const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
const INPUT_MAGICS: [&str; 4] = ["AOSPNI01", "AOSPSI01", "AOSPBI01", "AOSPCI01"];
const PROJECT_MAGIC: &[u8; 8] = b"AOSPPH01";
const PROJECT_SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head.v1\0";
const PROJECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head-transaction.v1\0";
const PROJECT_HEAD_KEY: &[u8] = b"\0aos-policy-project-head-v1\0";
const PROJECT_INPUT_KEY: &[u8] = b"\0aos-policy-project-input-v1\0";
const PROJECT_PAYLOAD_BYTES: usize = 248;
const PROJECT_PACKET_BYTES: usize = PROJECT_PAYLOAD_BYTES + 64;
const MAXIMUM_PROJECT_INPUT_BYTES: usize = 3 * 1024;

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
    project: ProjectId,
    generation: u64,
    publisher_generation: u64,
    publisher_digest: ObjectDigest,
    prerequisites: [ObjectDigest; 4],
    expires_at: i64,
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
struct DeploymentLayerV1 {
    portable: Vec<DeploymentLimitV1>,
    accounting: Vec<DeploymentLimitV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentLimitV1 {
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
/// The packet's compiler-authority claim must equal SHA-256 of the exact
/// current protected AOSPDH01 packet. Other prerequisite claims remain
/// unverified and cannot authorize AOSPCB01 publication from this record.
///
/// # Errors
///
/// Returns an error for invalid source, mismatched deployment currentness,
/// project substitution, noncontiguous generation, or failed protected commit.
pub fn admit_fixed_signed_project_policy_source_v1(
    packet: &[u8],
    input: &[u8],
    verifying_key: &VerifyingKey,
    deployment_packet: &[u8],
    now_unix_seconds: i64,
) -> Result<SignedProjectPolicySourceV1, PolicyDeploymentHeadErrorV1> {
    let verified =
        verify_signed_project_policy_source_v1(packet, input, verifying_key, now_unix_seconds)?;
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(HEAD_KEY)? != Some(deployment_packet)
        || verified.head.prerequisites[1].as_bytes() != Sha256::digest(deployment_packet).as_slice()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }

    let existing = authority.get(PROJECT_HEAD_KEY)?;
    let existing_input = authority.get(PROJECT_INPUT_KEY)?;
    if existing.is_some() != existing_input.is_some() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    if existing == Some(packet) && existing_input == Some(input) {
        return Ok(verified);
    }
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
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(verified)
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

fn decode_layer(wire: DeploymentLayerV1) -> Result<PolicyLayerV1, PolicyDeploymentHeadErrorV1> {
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

fn verify_historical_packet(
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

fn validate_canonical_input(
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
