//! Canonical signed Mount-manager SourceRoot custody control records.
//!
//! The protocol is transport independent. A fresh handoff is not evidence of
//! manager custody until a signed `descriptor_accepted` outcome is followed by
//! a distinct signed `present` readback. Removal likewise requires signed
//! `descriptor_removed` and subsequent `absent` outcomes.
//!
//! ```text
//! AOSMMCRQ1 request-json || sha256
//! AOSMMCRO1 outcome-json || sha256
//! AOSMMCSG1 outcome-record || ed25519-signature
//! ```

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    MountManagerStartupCaptureV1, MountManagerStartupFormatError, MountManagerStartupPolicyV1,
    StartupExecutionIdentityV1, encode_mount_manager_startup_policy_v1,
    startup_execution_identity_commitment_v1,
};

/// Maximum bytes in one canonical manager-control record.
pub const MAXIMUM_MANAGER_CONTROL_RECORD_BYTES_V1: usize = 64 * 1024;

const REQUEST_DOMAIN: &[u8] = b"AOSMMCRQ1";
const OUTCOME_DOMAIN: &[u8] = b"AOSMMCRO1";
const SIGNATURE_DOMAIN: &[u8] = b"AOSMMCSG1";

/// Selects the only manager SourceRoot control operations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagerSourceControlOperationV1 {
    /// Transfers a fresh SourceRoot descriptor into manager custody.
    Handoff,
    /// Removes a previously admitted SourceRoot from manager custody.
    Remove,
}

/// Selects the closed sequence of signed manager observations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagerSourceControlOutcomeKindV1 {
    /// The manager accepted the transferred descriptor.
    DescriptorAccepted,
    /// A distinct readback found that exact descriptor present.
    Present,
    /// The manager removed the exact descriptor.
    DescriptorRemoved,
    /// A distinct readback found that exact descriptor absent.
    Absent,
}

/// Pins the protected policy and manager execution used by one operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerControlPolicyWitnessV1 {
    /// Exact policy generation.
    pub policy_generation: u64,
    /// Exact sealed policy digest.
    pub policy_digest: [u8; 32],
    /// Stable control key identity.
    pub control_key_id: [u8; 16],
    /// Monotone control key generation.
    pub control_key_generation: u64,
    /// Exact Ed25519 verification key.
    pub control_public_key: [u8; 32],
    /// Gap-free startup capture sequence authorizing this execution.
    pub capture_sequence: u64,
    /// Immutable startup capture identity.
    pub capture_id: [u8; 32],
    /// Exact startup capture digest.
    pub capture_record_digest: [u8; 32],
    /// Full initial descriptor-table count.
    pub descriptor_count: u32,
    /// Exact activation-label count.
    pub activation_count: u32,
    /// Protected expected-descriptor count.
    pub expected_descriptor_count: u32,
    /// Total cleanup and terminal source-subject count.
    pub source_subject_count: u32,
    /// Cleanup source-subject count.
    pub cleanup_subject_count: u32,
    /// Terminal source-subject count.
    pub terminal_subject_count: u32,
    /// Full descriptor-table digest.
    pub descriptor_table_digest: [u8; 32],
    /// Activation-label table digest.
    pub activation_table_digest: [u8; 32],
    /// Protected expected-table digest.
    pub expected_table_digest: [u8; 32],
    /// Cleanup and terminal source-subject digest.
    pub source_subjects_digest: [u8; 32],
    /// Exact currently authorized manager execution.
    pub manager_execution: StartupExecutionIdentityV1,
    /// Commitment to the complete manager execution identity.
    pub manager_execution_commitment: [u8; 32],
}

/// Binds one source row and physical descriptor identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerControlSourceV1 {
    /// Exact AOSMSA acquisition identity.
    pub acquisition_id: [u8; 32],
    /// Exact AOSMSA acquisition revision.
    pub acquisition_revision: u64,
    /// Exact AOSMSA acquisition record digest.
    pub acquisition_record_digest: [u8; 32],
    /// Stable SourceRoot realization handle.
    pub source_realization_handle: [u8; 32],
    /// Exact SourceRoot descriptor commitment.
    pub descriptor_commitment: [u8; 32],
    /// SourceRoot kernel boot.
    pub kernel_boot_id: [u8; 16],
    /// SourceRoot device.
    pub device: u64,
    /// SourceRoot inode.
    pub inode: u64,
    /// SourceRoot unique Mount ID.
    pub unique_mount_id: u64,
    /// Protected manager activation name.
    pub activation_name: String,
}

/// Stores one canonical manager SourceRoot control request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerSourceControlRequestV1 {
    /// Exact operation.
    pub operation: ManagerSourceControlOperationV1,
    /// Unpredictable nonzero operation nonce.
    pub operation_nonce: [u8; 32],
    /// Stable manager-control session identity.
    pub session_id: [u8; 32],
    /// Manager epoch derived from the startup capture sequence.
    pub manager_epoch: u64,
    /// Gap-free request revision within this session.
    pub request_revision: u64,
    /// Policy, capture, and execution witness.
    pub policy: ManagerControlPolicyWitnessV1,
    /// Exact source and physical descriptor identity.
    pub source: ManagerControlSourceV1,
    /// Prior fresh-presence commitment for removal, otherwise zero.
    pub prior_presence_commitment: [u8; 32],
    /// Exact manager descriptor number for removal, absent before handoff.
    pub target_descriptor_number: Option<u32>,
    /// Commitment joining the capture epoch and exact source entry.
    pub source_entry_commitment: [u8; 32],
    /// Deterministic request identity.
    pub request_id: [u8; 32],
    /// Self-digest of the canonical request.
    pub record_digest: [u8; 32],
}

/// Stores one signed manager outcome or distinct readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerSourceControlOutcomeV1 {
    /// Exact request identity.
    pub request_id: [u8; 32],
    /// Exact request record digest.
    pub request_record_digest: [u8; 32],
    /// Repeated operation nonce.
    pub operation_nonce: [u8; 32],
    /// Repeated session identity.
    pub session_id: [u8; 32],
    /// Repeated manager epoch.
    pub manager_epoch: u64,
    /// Repeated request revision.
    pub request_revision: u64,
    /// Monotone observation revision: one for mutation, two for readback.
    pub outcome_revision: u8,
    /// Closed outcome kind.
    pub kind: ManagerSourceControlOutcomeKindV1,
    /// Preceding mutation outcome identity for a readback, otherwise zero.
    pub predecessor_outcome_id: [u8; 32],
    /// Preceding mutation outcome digest for a readback, otherwise zero.
    pub predecessor_outcome_digest: [u8; 32],
    /// Repeated stable SourceRoot realization handle.
    pub source_realization_handle: [u8; 32],
    /// Repeated exact descriptor commitment.
    pub descriptor_commitment: [u8; 32],
    /// Exact descriptor number assigned by the manager.
    pub manager_descriptor_number: u32,
    /// Deterministic outcome identity.
    pub outcome_id: [u8; 32],
    /// Self-digest of the canonical outcome.
    pub record_digest: [u8; 32],
}

/// Carries an exact manager outcome and its Ed25519 signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManagerSourceControlOutcomeV1 {
    /// Canonical sealed outcome.
    pub outcome: ManagerSourceControlOutcomeV1,
    /// Ed25519 signature over the domain-separated canonical outcome record.
    pub signature: Vec<u8>,
}

/// Reports malformed, inconsistent, or unauthenticated manager control bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManagerSourceControlProtocolError {
    /// A field or transition violates the closed control protocol.
    #[error("invalid Mount-manager source control record")]
    InvalidRecord,
    /// A record exceeds its fixed encoded size bound.
    #[error("Mount-manager source control record exceeds its bound")]
    InvalidSize,
    /// The manager signature is malformed or does not verify.
    #[error("invalid Mount-manager source control signature")]
    InvalidSignature,
}

/// Projects a protected policy and startup capture into a control witness.
///
/// # Errors
///
/// Returns an error when the supplied policy is not sealed or does not match
/// the supplied capture policy identity.
pub fn manager_control_policy_witness_v1(
    policy: &MountManagerStartupPolicyV1,
    capture: &MountManagerStartupCaptureV1,
) -> Result<ManagerControlPolicyWitnessV1, ManagerSourceControlProtocolError> {
    encode_mount_manager_startup_policy_v1(policy).map_err(invalid_format)?;
    if capture.capture_sequence == 0
        || capture.capture_id == [0; 32]
        || capture.record_digest == [0; 32]
        || (capture.policy_generation, capture.policy_digest)
            != (policy.generation, policy.record_digest)
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    Ok(ManagerControlPolicyWitnessV1 {
        policy_generation: policy.generation,
        policy_digest: policy.record_digest,
        control_key_id: policy.manager_control_key_id,
        control_key_generation: policy.manager_control_key_generation,
        control_public_key: policy.manager_control_public_key,
        capture_sequence: capture.capture_sequence,
        capture_id: capture.capture_id,
        capture_record_digest: capture.record_digest,
        descriptor_count: capture.descriptor_count,
        activation_count: capture.activation_count,
        expected_descriptor_count: capture.expected_descriptor_count,
        source_subject_count: capture.source_subject_count,
        cleanup_subject_count: capture.cleanup_subject_count,
        terminal_subject_count: capture.terminal_subject_count,
        descriptor_table_digest: capture.descriptor_table_digest,
        activation_table_digest: capture.activation_table_digest,
        expected_table_digest: capture.expected_table_digest,
        source_subjects_digest: capture.source_subjects_digest,
        manager_execution: capture.execution.clone(),
        manager_execution_commitment: startup_execution_identity_commitment_v1(&capture.execution)
            .map_err(invalid_format)?,
    })
}

/// Seals one internally assembled request.
///
/// # Errors
///
/// Returns an error for a zero identity, invalid source, invalid epoch, or an
/// oversized canonical encoding.
pub fn seal_manager_source_control_request_v1(
    mut request: ManagerSourceControlRequestV1,
) -> Result<ManagerSourceControlRequestV1, ManagerSourceControlProtocolError> {
    request.source_entry_commitment = source_entry_commitment(&request)?;
    request.request_id = request_identity(&request)?;
    request.record_digest = [0; 32];
    validate_request(&request, false)?;
    request.record_digest = request_record_digest(&request)?;
    Ok(request)
}

/// Encodes one sealed request as canonical bounded JSON.
///
/// # Errors
///
/// Returns an error for an invalid, unsealed, or oversized request.
pub fn encode_manager_source_control_request_v1(
    request: &ManagerSourceControlRequestV1,
) -> Result<Vec<u8>, ManagerSourceControlProtocolError> {
    validate_request(request, true)?;
    encode_record(request)
}

/// Decodes and canonical-reencodes one request.
///
/// # Errors
///
/// Returns an error for malformed, noncanonical, unsealed, or oversized bytes.
pub fn decode_manager_source_control_request_v1(
    bytes: &[u8],
) -> Result<ManagerSourceControlRequestV1, ManagerSourceControlProtocolError> {
    let request: ManagerSourceControlRequestV1 = decode_record(bytes)?;
    let retained_digest = request.record_digest;
    validate_request(&request, true)?;
    if retained_digest != request_record_digest(&request)? {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    if encode_record(&request)? != bytes {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    Ok(request)
}

/// Seals one internally assembled outcome against its exact request.
///
/// # Errors
///
/// Returns an error when repeated bindings or transition ordering differ.
pub fn seal_manager_source_control_outcome_v1(
    request: &ManagerSourceControlRequestV1,
    predecessor: Option<&ManagerSourceControlOutcomeV1>,
    mut outcome: ManagerSourceControlOutcomeV1,
) -> Result<ManagerSourceControlOutcomeV1, ManagerSourceControlProtocolError> {
    validate_request(request, true)?;
    outcome.outcome_id = outcome_identity(&outcome)?;
    outcome.record_digest = [0; 32];
    validate_outcome(request, predecessor, &outcome, false)?;
    outcome.record_digest = outcome_record_digest(&outcome)?;
    Ok(outcome)
}

/// Returns the exact bytes a manager control key signs.
///
/// # Errors
///
/// Returns an error when the outcome is unsealed or oversized.
pub fn manager_source_control_outcome_signing_bytes_v1(
    outcome: &ManagerSourceControlOutcomeV1,
) -> Result<Vec<u8>, ManagerSourceControlProtocolError> {
    if outcome.record_digest == [0; 32] || outcome_record_digest(outcome)? != outcome.record_digest
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    let encoded = encode_record(outcome)?;
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

/// Signs one sealed outcome with the exact policy-pinned control key.
///
/// # Errors
///
/// Returns an error when the outcome is unsealed or the signing key does not
/// correspond to the request's pinned public key.
pub fn sign_manager_source_control_outcome_v1(
    request: &ManagerSourceControlRequestV1,
    predecessor: Option<&ManagerSourceControlOutcomeV1>,
    outcome: ManagerSourceControlOutcomeV1,
    signing_key: &SigningKey,
) -> Result<SignedManagerSourceControlOutcomeV1, ManagerSourceControlProtocolError> {
    validate_request(request, true)?;
    validate_outcome(request, predecessor, &outcome, true)?;
    if signing_key.verifying_key().to_bytes() != request.policy.control_public_key {
        return Err(ManagerSourceControlProtocolError::InvalidSignature);
    }
    let signature = signing_key
        .sign(&manager_source_control_outcome_signing_bytes_v1(&outcome)?)
        .to_bytes()
        .to_vec();
    Ok(SignedManagerSourceControlOutcomeV1 { outcome, signature })
}

/// Encodes one signed outcome as canonical bounded JSON.
///
/// # Errors
///
/// Returns an error for a malformed signature or oversized encoding.
pub fn encode_signed_manager_source_control_outcome_v1(
    signed: &SignedManagerSourceControlOutcomeV1,
) -> Result<Vec<u8>, ManagerSourceControlProtocolError> {
    if signed.signature.len() != 64 || signed.outcome.record_digest == [0; 32] {
        return Err(ManagerSourceControlProtocolError::InvalidSignature);
    }
    encode_record(signed)
}

/// Decodes and canonical-reencodes one signed outcome.
///
/// Signature authentication remains the responsibility of
/// [`verify_signed_manager_source_control_outcome_v1`].
///
/// # Errors
///
/// Returns an error for malformed, noncanonical, or oversized bytes.
pub fn decode_signed_manager_source_control_outcome_v1(
    bytes: &[u8],
) -> Result<SignedManagerSourceControlOutcomeV1, ManagerSourceControlProtocolError> {
    let signed: SignedManagerSourceControlOutcomeV1 = decode_record(bytes)?;
    if signed.signature.len() != 64
        || signed.outcome.record_digest == [0; 32]
        || encode_record(&signed)? != bytes
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    Ok(signed)
}

/// Verifies one signed outcome and its exact protocol transition.
///
/// # Errors
///
/// Returns an error for mismatched request fields, transition order, pinned
/// key identity, malformed signature, or failed Ed25519 verification.
pub fn verify_signed_manager_source_control_outcome_v1(
    request: &ManagerSourceControlRequestV1,
    predecessor: Option<&ManagerSourceControlOutcomeV1>,
    signed: &SignedManagerSourceControlOutcomeV1,
) -> Result<(), ManagerSourceControlProtocolError> {
    validate_request(request, true)?;
    validate_outcome(request, predecessor, &signed.outcome, true)?;
    let key = VerifyingKey::from_bytes(&request.policy.control_public_key)
        .map_err(|_| ManagerSourceControlProtocolError::InvalidSignature)?;
    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ManagerSourceControlProtocolError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(
        &manager_source_control_outcome_signing_bytes_v1(&signed.outcome)?,
        &signature,
    )
    .map_err(|_| ManagerSourceControlProtocolError::InvalidSignature)
}

fn validate_request(
    request: &ManagerSourceControlRequestV1,
    require_digest: bool,
) -> Result<(), ManagerSourceControlProtocolError> {
    let source = &request.source;
    let policy = &request.policy;
    if request.operation_nonce == [0; 32]
        || request.session_id == [0; 32]
        || request.manager_epoch == 0
        || request.manager_epoch != policy.capture_sequence
        || request.request_revision == 0
        || request.request_id == [0; 32]
        || request.request_id != request_identity(request)?
        || policy.policy_generation == 0
        || policy.policy_digest == [0; 32]
        || policy.control_key_id == [0; 16]
        || policy.control_key_generation == 0
        || VerifyingKey::from_bytes(&policy.control_public_key).is_err()
        || policy.capture_id == [0; 32]
        || policy.capture_record_digest == [0; 32]
        || policy.descriptor_count == 0
        || policy.activation_count == 0
        || policy.expected_descriptor_count == 0
        || policy.activation_count > policy.descriptor_count
        || policy.expected_descriptor_count > policy.descriptor_count
        || policy
            .cleanup_subject_count
            .checked_add(policy.terminal_subject_count)
            != Some(policy.source_subject_count)
        || policy.descriptor_table_digest == [0; 32]
        || policy.activation_table_digest == [0; 32]
        || policy.expected_table_digest == [0; 32]
        || policy.source_subjects_digest == [0; 32]
        || policy.manager_execution_commitment == [0; 32]
        || startup_execution_identity_commitment_v1(&policy.manager_execution)
            .map_err(invalid_format)?
            != policy.manager_execution_commitment
        || source.acquisition_id == [0; 32]
        || source.acquisition_revision == 0
        || source.acquisition_record_digest == [0; 32]
        || source.source_realization_handle == [0; 32]
        || source.descriptor_commitment == [0; 32]
        || source.kernel_boot_id == [0; 16]
        || source.device == 0
        || source.inode == 0
        || source.unique_mount_id == 0
        || request.source_entry_commitment == [0; 32]
        || request.source_entry_commitment != source_entry_commitment(request)?
        || source.activation_name.is_empty()
        || source.activation_name.len() > 255
        || !source
            .activation_name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
        || match request.operation {
            ManagerSourceControlOperationV1::Handoff => {
                request.prior_presence_commitment != [0; 32]
                    || request.target_descriptor_number.is_some()
            }
            ManagerSourceControlOperationV1::Remove => {
                request.prior_presence_commitment == [0; 32]
                    || request
                        .target_descriptor_number
                        .is_none_or(|number| number < 3)
            }
        }
        || (require_digest && request.record_digest == [0; 32])
        || (require_digest && request_record_digest(request)? != request.record_digest)
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    Ok(())
}

fn validate_outcome(
    request: &ManagerSourceControlRequestV1,
    predecessor: Option<&ManagerSourceControlOutcomeV1>,
    outcome: &ManagerSourceControlOutcomeV1,
    require_digest: bool,
) -> Result<(), ManagerSourceControlProtocolError> {
    if outcome.request_id != request.request_id
        || outcome.request_record_digest != request.record_digest
        || outcome.operation_nonce != request.operation_nonce
        || outcome.session_id != request.session_id
        || outcome.manager_epoch != request.manager_epoch
        || outcome.request_revision != request.request_revision
        || outcome.source_realization_handle != request.source.source_realization_handle
        || outcome.descriptor_commitment != request.source.descriptor_commitment
        || outcome.manager_descriptor_number < 3
        || outcome.outcome_id == [0; 32]
        || outcome.outcome_id != outcome_identity(outcome)?
        || (require_digest && outcome.record_digest == [0; 32])
        || (require_digest && outcome_record_digest(outcome)? != outcome.record_digest)
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    let (first, second) = match request.operation {
        ManagerSourceControlOperationV1::Handoff => (
            ManagerSourceControlOutcomeKindV1::DescriptorAccepted,
            ManagerSourceControlOutcomeKindV1::Present,
        ),
        ManagerSourceControlOperationV1::Remove => (
            ManagerSourceControlOutcomeKindV1::DescriptorRemoved,
            ManagerSourceControlOutcomeKindV1::Absent,
        ),
    };
    if request
        .target_descriptor_number
        .is_some_and(|number| number != outcome.manager_descriptor_number)
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord);
    }
    match (outcome.outcome_revision, outcome.kind, predecessor) {
        (1, kind, None)
            if kind == first
                && outcome.predecessor_outcome_id == [0; 32]
                && outcome.predecessor_outcome_digest == [0; 32] => {}
        (2, kind, Some(previous))
            if kind == second
                && previous.outcome_revision == 1
                && previous.kind == first
                && outcome.predecessor_outcome_id == previous.outcome_id
                && outcome.predecessor_outcome_digest == previous.record_digest
                && outcome.manager_descriptor_number == previous.manager_descriptor_number => {}
        _ => return Err(ManagerSourceControlProtocolError::InvalidRecord),
    }
    Ok(())
}

fn request_identity(
    request: &ManagerSourceControlRequestV1,
) -> Result<[u8; 32], ManagerSourceControlProtocolError> {
    let mut value = request.clone();
    value.request_id = [0; 32];
    value.record_digest = [0; 32];
    digest_record(b"aos.sandbox.mount-manager.control-request-id.v1\0", &value)
}

fn source_entry_commitment(
    request: &ManagerSourceControlRequestV1,
) -> Result<[u8; 32], ManagerSourceControlProtocolError> {
    #[derive(Serialize)]
    struct SourceEntry<'a> {
        capture_sequence: u64,
        capture_id: [u8; 32],
        capture_record_digest: [u8; 32],
        manager_execution: &'a StartupExecutionIdentityV1,
        source: &'a ManagerControlSourceV1,
    }
    digest_record(
        b"aos.sandbox.mount-manager.fresh-source-entry.v1\0",
        &SourceEntry {
            capture_sequence: request.policy.capture_sequence,
            capture_id: request.policy.capture_id,
            capture_record_digest: request.policy.capture_record_digest,
            manager_execution: &request.policy.manager_execution,
            source: &request.source,
        },
    )
}

fn request_record_digest(
    request: &ManagerSourceControlRequestV1,
) -> Result<[u8; 32], ManagerSourceControlProtocolError> {
    let mut value = request.clone();
    value.record_digest = [0; 32];
    digest_record(REQUEST_DOMAIN, &value)
}

fn outcome_identity(
    outcome: &ManagerSourceControlOutcomeV1,
) -> Result<[u8; 32], ManagerSourceControlProtocolError> {
    let mut value = outcome.clone();
    value.outcome_id = [0; 32];
    value.record_digest = [0; 32];
    digest_record(b"aos.sandbox.mount-manager.control-outcome-id.v1\0", &value)
}

fn outcome_record_digest(
    outcome: &ManagerSourceControlOutcomeV1,
) -> Result<[u8; 32], ManagerSourceControlProtocolError> {
    let mut value = outcome.clone();
    value.record_digest = [0; 32];
    digest_record(OUTCOME_DOMAIN, &value)
}

fn digest_record<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], ManagerSourceControlProtocolError> {
    let bytes = encode_record(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn encode_record<T: Serialize>(value: &T) -> Result<Vec<u8>, ManagerSourceControlProtocolError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| ManagerSourceControlProtocolError::InvalidRecord)?;
    if bytes.len() > MAXIMUM_MANAGER_CONTROL_RECORD_BYTES_V1 {
        return Err(ManagerSourceControlProtocolError::InvalidSize);
    }
    Ok(bytes)
}

fn decode_record<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, ManagerSourceControlProtocolError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_MANAGER_CONTROL_RECORD_BYTES_V1 {
        return Err(ManagerSourceControlProtocolError::InvalidSize);
    }
    serde_json::from_slice(bytes).map_err(|_| ManagerSourceControlProtocolError::InvalidRecord)
}

const fn invalid_format(_: MountManagerStartupFormatError) -> ManagerSourceControlProtocolError {
    ManagerSourceControlProtocolError::InvalidRecord
}
