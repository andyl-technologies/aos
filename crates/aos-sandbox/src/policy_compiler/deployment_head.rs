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

use std::path::Path;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::ResourceDimension;

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
