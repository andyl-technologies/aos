//! Canonical OpenSSH holder proof for creating an execution.
//!
//! The SSHSIG covers the complete request with only its proof field cleared.
//! The holder key is not an authorization credential: the public API must
//! authenticate and authorize the TLS peer independently.

use aos_proto::aos::sandbox::v1::CreateExecutionRequest;
use buffa::Message as _;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

const SSHSIG_NAMESPACE: &str = "aos.sandbox.execution.create-holder-proof.v1";
// A valid execution command may contain an 8 MiB argument vector. Keep the
// proof envelope aligned with the public canonical-request ceiling.
const MAXIMUM_STATEMENT_BYTES: u32 = 16 * 1024 * 1024;
const MAXIMUM_PUBLIC_KEY_BYTES: usize = 4 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 8 * 1024;

/// Reports an invalid or unverifiable execution-creation holder proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CreateHolderProofErrorV1 {
    /// The request has an incomplete fence, missing feature, or unknown fields.
    #[error("execution holder proof has an invalid request")]
    InvalidRequest,
    /// The holder key is not a canonical Ed25519 OpenSSH public key.
    #[error("execution holder proof has an invalid public key")]
    InvalidPublicKey,
    /// The supplied SSHSIG is malformed or has an unsupported profile.
    #[error("execution holder proof has an invalid signature")]
    InvalidSignature,
    /// The SSHSIG does not prove possession of the named key for this request.
    #[error("execution holder proof does not match this request")]
    ProofMismatch,
    /// The private key is encrypted, malformed, or does not match the request.
    #[error("execution holder private key does not match this request")]
    PrivateKeyMismatch,
}

/// Verifies one Ed25519 SSHSIG over the exact execution-creation mutation.
///
/// This proof binds the holder key, command, and optimistic mutation fence; it
/// does not authenticate the TLS peer, authorize execution, or issue a route.
///
/// # Errors
///
/// Rejects a malformed request, noncanonical key, unsupported signature
/// profile, or a signature over a different request.
pub fn verify_create_holder_proof_v1(
    request: &CreateExecutionRequest,
) -> Result<(), CreateHolderProofErrorV1> {
    let public_key = canonical_public_key(&request.client_public_key)?;
    if request.proof_of_possession.is_empty()
        || request.proof_of_possession.len() > MAXIMUM_SIGNATURE_BYTES
    {
        return Err(CreateHolderProofErrorV1::InvalidSignature);
    }
    let signature = SshSig::from_pem(&request.proof_of_possession)
        .map_err(|_| CreateHolderProofErrorV1::InvalidSignature)?;
    if signature.hash_alg() != HashAlg::Sha256
        || !signature.reserved().is_empty()
        || signature
            .to_pem(LineEnding::LF)
            .map_err(|_| CreateHolderProofErrorV1::InvalidSignature)?
            .as_bytes()
            != request.proof_of_possession
    {
        return Err(CreateHolderProofErrorV1::InvalidSignature);
    }
    let statement = proof_statement(request)?;
    public_key
        .verify(SSHSIG_NAMESPACE, &statement, &signature)
        .map_err(|_| CreateHolderProofErrorV1::ProofMismatch)
}

/// Signs the exact execution-creation mutation with an unencrypted Ed25519 key.
///
/// The request must contain its final command and mutation fence. This replaces
/// its holder key and proof together; no signed field may change afterward.
///
/// # Errors
///
/// Rejects an invalid request or private key, or a failed signature encoding.
pub fn sign_create_holder_proof_v1(
    request: &mut CreateExecutionRequest,
    private_key_bytes: &[u8],
) -> Result<(), CreateHolderProofErrorV1> {
    let private_key = PrivateKey::from_openssh(private_key_bytes)
        .map_err(|_| CreateHolderProofErrorV1::PrivateKeyMismatch)?;
    if private_key.is_encrypted() || private_key.algorithm() != Algorithm::Ed25519 {
        return Err(CreateHolderProofErrorV1::PrivateKeyMismatch);
    }
    let public_key = PublicKey::new(private_key.public_key().key_data().clone(), "");
    request.client_public_key = public_key
        .to_openssh()
        .map_err(|_| CreateHolderProofErrorV1::InvalidPublicKey)?
        .into_bytes();
    request.proof_of_possession.clear();

    let statement = proof_statement(request)?;
    let signature = private_key
        .sign(SSHSIG_NAMESPACE, HashAlg::Sha256, &statement)
        .map_err(|_| CreateHolderProofErrorV1::InvalidSignature)?;
    let proof = signature
        .to_pem(LineEnding::LF)
        .map_err(|_| CreateHolderProofErrorV1::InvalidSignature)?;
    if proof.len() > MAXIMUM_SIGNATURE_BYTES {
        return Err(CreateHolderProofErrorV1::InvalidSignature);
    }
    request.proof_of_possession = proof.into_bytes();
    Ok(())
}

/// Confirms that a retained private key matches the proven request holder.
///
/// # Errors
///
/// Rejects a mismatched private key or an invalid request proof.
pub fn verify_create_holder_private_key_v1(
    request: &CreateExecutionRequest,
    private_key_bytes: &[u8],
) -> Result<(), CreateHolderProofErrorV1> {
    let private_key = PrivateKey::from_openssh(private_key_bytes)
        .map_err(|_| CreateHolderProofErrorV1::PrivateKeyMismatch)?;
    if private_key.is_encrypted() || private_key.algorithm() != Algorithm::Ed25519 {
        return Err(CreateHolderProofErrorV1::PrivateKeyMismatch);
    }
    let public_key = canonical_public_key(&request.client_public_key)?;
    if private_key.public_key().key_data() != public_key.key_data() {
        return Err(CreateHolderProofErrorV1::PrivateKeyMismatch);
    }
    verify_create_holder_proof_v1(request)
}

fn canonical_public_key(bytes: &[u8]) -> Result<PublicKey, CreateHolderProofErrorV1> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_PUBLIC_KEY_BYTES {
        return Err(CreateHolderProofErrorV1::InvalidPublicKey);
    }
    let line =
        std::str::from_utf8(bytes).map_err(|_| CreateHolderProofErrorV1::InvalidPublicKey)?;
    let key =
        PublicKey::from_openssh(line).map_err(|_| CreateHolderProofErrorV1::InvalidPublicKey)?;
    if key.algorithm() != Algorithm::Ed25519
        || key
            .to_openssh()
            .map_err(|_| CreateHolderProofErrorV1::InvalidPublicKey)?
            .as_bytes()
            != bytes
    {
        return Err(CreateHolderProofErrorV1::InvalidPublicKey);
    }
    Ok(key)
}

fn proof_statement(request: &CreateExecutionRequest) -> Result<Vec<u8>, CreateHolderProofErrorV1> {
    let command = request
        .command
        .as_option()
        .ok_or(CreateHolderProofErrorV1::InvalidRequest)?;
    let mutation = request
        .mutation
        .as_option()
        .ok_or(CreateHolderProofErrorV1::InvalidRequest)?;
    let timeout = mutation
        .operation_timeout
        .as_option()
        .ok_or(CreateHolderProofErrorV1::InvalidRequest)?;
    let execution_timeout = command
        .execution_timeout
        .as_option()
        .ok_or(CreateHolderProofErrorV1::InvalidRequest)?;

    if request.sandbox_id.len() != 16
        || mutation.idempotency_key.is_empty()
        || mutation.expected_resource_version.is_empty()
        || mutation.expected_incarnation_id.len() != 16
        || timeout.nanoseconds == 0
        || execution_timeout.nanoseconds == 0
        || !request.__buffa_unknown_fields.is_empty()
        || !command.__buffa_unknown_fields.is_empty()
        || !mutation.__buffa_unknown_fields.is_empty()
        || !timeout.__buffa_unknown_fields.is_empty()
        || !execution_timeout.__buffa_unknown_fields.is_empty()
        || command
            .environment
            .iter()
            .any(|variable| !variable.__buffa_unknown_fields.is_empty())
        || command
            .stream_features
            .iter()
            .chain(&mutation.required_features)
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
        || !crate::controller_query::contains_semantic_features_v1(
            &mutation.required_features,
            &[crate::controller_query::EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1],
        )
    {
        return Err(CreateHolderProofErrorV1::InvalidRequest);
    }

    let mut unsigned = request.clone();
    unsigned.proof_of_possession.clear();
    if unsigned.encoded_len() > MAXIMUM_STATEMENT_BYTES {
        return Err(CreateHolderProofErrorV1::InvalidRequest);
    }
    let mut statement = Vec::new();
    statement
        .try_reserve_exact(unsigned.encoded_len() as usize)
        .map_err(|_| CreateHolderProofErrorV1::InvalidRequest)?;
    unsigned
        .try_encode(&mut statement)
        .map_err(|_| CreateHolderProofErrorV1::InvalidRequest)?;
    Ok(statement)
}
