//! Canonical OpenSSH holder proof for an execution attachment mutation.
//!
//! The SSHSIG signs the entire protobuf request with its proof field empty.
//! Thus the execution, mutation fence, required features, and holder key all
//! enter one domain-separated statement. The public API still authorizes the
//! registered TLS peer independently; proof of the SSH key is not a capability.

use aos_proto::aos::sandbox::v1::{ExecutionControlAction, ExecutionControlRequest};
use buffa::Message as _;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

const SSHSIG_NAMESPACE: &str = "aos.sandbox.execution.attach-holder-proof.v1";
const MAXIMUM_STATEMENT_BYTES: u32 = 128 * 1024;
const MAXIMUM_PUBLIC_KEY_BYTES: usize = 4 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 8 * 1024;

/// Reports an invalid or unverifiable execution-attachment holder proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AttachHolderProofErrorV1 {
    /// The request is not a bounded attach mutation with a complete fence.
    #[error("attachment holder proof has an invalid request")]
    InvalidRequest,
    /// The holder key is not a canonical Ed25519 OpenSSH public key.
    #[error("attachment holder proof has an invalid public key")]
    InvalidPublicKey,
    /// The supplied SSHSIG is malformed or has an unsupported profile.
    #[error("attachment holder proof has an invalid signature")]
    InvalidSignature,
    /// The SSHSIG does not prove possession of the named key for this request.
    #[error("attachment holder proof does not match this request")]
    ProofMismatch,
    /// The private key is encrypted, malformed, or does not match the request.
    #[error("attachment holder private key does not match this request")]
    PrivateKeyMismatch,
}

/// Verifies one Ed25519 SSHSIG over the exact attach request mutation.
///
/// The verified key may later receive only a separately authorized, short-lived
/// execution certificate. This function does not authenticate the TLS peer,
/// authorize the execution, consume idempotency, or issue a route.
///
/// # Errors
///
/// Rejects a malformed request, noncanonical key, unsupported signature
/// profile, or a signature over a different request.
pub fn verify_attach_holder_proof_v1(
    request: &ExecutionControlRequest,
) -> Result<(), AttachHolderProofErrorV1> {
    let public_key = canonical_public_key(&request.client_public_key)?;
    if request.proof_of_possession.is_empty()
        || request.proof_of_possession.len() > MAXIMUM_SIGNATURE_BYTES
    {
        return Err(AttachHolderProofErrorV1::InvalidSignature);
    }
    let signature = SshSig::from_pem(&request.proof_of_possession)
        .map_err(|_| AttachHolderProofErrorV1::InvalidSignature)?;
    if signature.hash_alg() != HashAlg::Sha256
        || !signature.reserved().is_empty()
        || signature
            .to_pem(LineEnding::LF)
            .map_err(|_| AttachHolderProofErrorV1::InvalidSignature)?
            .as_bytes()
            != request.proof_of_possession
    {
        return Err(AttachHolderProofErrorV1::InvalidSignature);
    }
    let statement = proof_statement(request)?;
    public_key
        .verify(SSHSIG_NAMESPACE, &statement, &signature)
        .map_err(|_| AttachHolderProofErrorV1::ProofMismatch)
}

/// Signs the exact attach mutation with one unencrypted Ed25519 OpenSSH key.
///
/// The request must already contain its final mutation fence. Its holder key
/// and proof are replaced together; callers must not change any signed field
/// before transmission.
///
/// # Errors
///
/// Rejects an invalid request or private key, or a failed signature encoding.
pub fn sign_attach_holder_proof_v1(
    request: &mut ExecutionControlRequest,
    private_key_bytes: &[u8],
) -> Result<(), AttachHolderProofErrorV1> {
    let private_key = PrivateKey::from_openssh(private_key_bytes)
        .map_err(|_| AttachHolderProofErrorV1::PrivateKeyMismatch)?;
    if private_key.is_encrypted() || private_key.algorithm() != Algorithm::Ed25519 {
        return Err(AttachHolderProofErrorV1::PrivateKeyMismatch);
    }
    let public_key = PublicKey::new(private_key.public_key().key_data().clone(), "");
    request.client_public_key = public_key
        .to_openssh()
        .map_err(|_| AttachHolderProofErrorV1::InvalidPublicKey)?
        .into_bytes();
    request.proof_of_possession.clear();

    let statement = proof_statement(request)?;
    let signature = private_key
        .sign(SSHSIG_NAMESPACE, HashAlg::Sha256, &statement)
        .map_err(|_| AttachHolderProofErrorV1::InvalidSignature)?;
    let proof = signature
        .to_pem(LineEnding::LF)
        .map_err(|_| AttachHolderProofErrorV1::InvalidSignature)?;
    if proof.len() > MAXIMUM_SIGNATURE_BYTES {
        return Err(AttachHolderProofErrorV1::InvalidSignature);
    }
    request.proof_of_possession = proof.into_bytes();
    Ok(())
}

/// Confirms that the retained private key is the one proven by a request.
///
/// # Errors
///
/// Rejects a mismatched private key or an invalid request proof.
pub fn verify_attach_holder_private_key_v1(
    request: &ExecutionControlRequest,
    private_key_bytes: &[u8],
) -> Result<(), AttachHolderProofErrorV1> {
    let private_key = PrivateKey::from_openssh(private_key_bytes)
        .map_err(|_| AttachHolderProofErrorV1::PrivateKeyMismatch)?;
    if private_key.is_encrypted() || private_key.algorithm() != Algorithm::Ed25519 {
        return Err(AttachHolderProofErrorV1::PrivateKeyMismatch);
    }
    let public_key = canonical_public_key(&request.client_public_key)?;
    if private_key.public_key().key_data() != public_key.key_data() {
        return Err(AttachHolderProofErrorV1::PrivateKeyMismatch);
    }
    verify_attach_holder_proof_v1(request)
}

fn canonical_public_key(bytes: &[u8]) -> Result<PublicKey, AttachHolderProofErrorV1> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_PUBLIC_KEY_BYTES {
        return Err(AttachHolderProofErrorV1::InvalidPublicKey);
    }
    let line =
        std::str::from_utf8(bytes).map_err(|_| AttachHolderProofErrorV1::InvalidPublicKey)?;
    let key =
        PublicKey::from_openssh(line).map_err(|_| AttachHolderProofErrorV1::InvalidPublicKey)?;
    if key.algorithm() != Algorithm::Ed25519
        || key
            .to_openssh()
            .map_err(|_| AttachHolderProofErrorV1::InvalidPublicKey)?
            .as_bytes()
            != bytes
    {
        return Err(AttachHolderProofErrorV1::InvalidPublicKey);
    }
    Ok(key)
}

fn proof_statement(request: &ExecutionControlRequest) -> Result<Vec<u8>, AttachHolderProofErrorV1> {
    if request.action.as_known() != Some(ExecutionControlAction::EXECUTION_CONTROL_ACTION_ATTACH)
        || request.execution_id.len() != 16
        || request.terminal_rows != 0
        || request.terminal_columns != 0
        || request.signal.to_i32() != 0
        || !request.__buffa_unknown_fields.is_empty()
    {
        return Err(AttachHolderProofErrorV1::InvalidRequest);
    }

    let mutation = request
        .mutation
        .as_option()
        .ok_or(AttachHolderProofErrorV1::InvalidRequest)?;
    let timeout = mutation
        .operation_timeout
        .as_option()
        .ok_or(AttachHolderProofErrorV1::InvalidRequest)?;
    if mutation.idempotency_key.is_empty()
        || mutation.expected_resource_version.is_empty()
        || mutation.expected_incarnation_id.len() != 16
        || timeout.nanoseconds == 0
        || !mutation.__buffa_unknown_fields.is_empty()
        || !timeout.__buffa_unknown_fields.is_empty()
        || mutation
            .required_features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
        || !crate::controller_query::contains_semantic_features_v1(
            &mutation.required_features,
            &[crate::controller_query::EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1],
        )
    {
        return Err(AttachHolderProofErrorV1::InvalidRequest);
    }

    let mut unsigned = request.clone();
    unsigned.proof_of_possession.clear();
    if unsigned.encoded_len() > MAXIMUM_STATEMENT_BYTES {
        return Err(AttachHolderProofErrorV1::InvalidRequest);
    }
    let mut statement = Vec::new();
    statement
        .try_reserve_exact(unsigned.encoded_len() as usize)
        .map_err(|_| AttachHolderProofErrorV1::InvalidRequest)?;
    unsigned
        .try_encode(&mut statement)
        .map_err(|_| AttachHolderProofErrorV1::InvalidRequest)?;
    Ok(statement)
}
