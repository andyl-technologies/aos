//! Signs annotated tags with authenticated capability terminal keys (REF-20).
//!
//! ```text
//! preimage = canonical {1: tag, 2: commit, 3: attestation, 4: terminal_key_hex}
//! signature = Ed25519(preimage)
//! ```

use super::Rejected;
use crate::{
    auth::{IssuerKey, Request, Token, Verb},
    identity::Digest,
    refs::{RefName, SnapshotEnvelope},
};
use alloc::string::String;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

fn terminal_key_name(key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in key {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 15)]));
    }
    name
}

fn authenticate_snapshot(
    envelope: &SnapshotEnvelope,
    token: &Token,
    keys: &[IssuerKey],
    source_request: &Request<'_>,
) -> Result<[u8; 32], Rejected> {
    if !matches!(source_request.verb, Verb::Tag | Verb::Admin) {
        return Err(Rejected);
    }
    envelope.signature_preimage().map_err(|_| Rejected)?;
    token
        .verify(keys, source_request.now)
        .map_err(|_| Rejected)?
        .authorize(source_request)
        .map_err(|_| Rejected)?;
    Ok(token.signing_public_key())
}

/// Signs an annotated tag with the currently authorized token's terminal key.
///
/// Sets `signer_key` to that key's lowercase 64-character hexadecimal name.
/// The guard supplies a fresh `tag` request on the authorized source ref;
/// an `admin` grant also implies this operation. An explicitly authorized
/// `admin` request is accepted. The request's ref is the source, not the new
/// tag name. The envelope signature binds the new tag and selected commit.
///
/// The guard separately validates the complete current source record and epoch,
/// target reachability, current ACL intersection, and applicable target namespace
/// and caveats. This pure helper grants no publication authority (REF-19/20).
///
/// # Errors
/// Returns [`Rejected`] for malformed envelope data, missing current authority,
/// an unauthorized source request or unsupported verb, or a secret different
/// from the token terminal key.
pub fn sign_snapshot(
    mut envelope: SnapshotEnvelope,
    token: &Token,
    secret: &[u8; 32],
    keys: &[IssuerKey],
    source_request: &Request<'_>,
) -> Result<SnapshotEnvelope, Rejected> {
    let public_key = authenticate_snapshot(&envelope, token, keys, source_request)?;
    let key = SigningKey::from_bytes(secret);
    if key.verifying_key().to_bytes() != public_key {
        return Err(Rejected);
    }
    envelope.signer_key = terminal_key_name(&public_key);
    envelope.signature = key
        .sign(&envelope.signature_preimage().map_err(|_| Rejected)?)
        .to_bytes();
    Ok(envelope)
}

/// Verifies an annotated tag against its expected name, target, and source scope.
///
/// The authenticated token binds the claimed terminal public key and authorizes
/// the supplied source `tag` or `admin` request. The expected tag and commit come
/// from the guard's publication context. Complete source snapshot revalidation,
/// target reachability, namespace/caveats, immutable-tag update policy, and
/// current ACL checks remain the guard's responsibility.
///
/// # Errors
/// Returns [`Rejected`] for an unexpected target/tag, malformed envelope,
/// missing current authority, a mismatched terminal-key name, or bad signature.
pub fn verify_snapshot(
    envelope: &SnapshotEnvelope,
    expected_tag: &RefName,
    expected_commit: Digest,
    token: &Token,
    keys: &[IssuerKey],
    source_request: &Request<'_>,
) -> Result<(), Rejected> {
    if envelope.tag != *expected_tag || envelope.commit != expected_commit {
        return Err(Rejected);
    }
    let public_key = authenticate_snapshot(envelope, token, keys, source_request)?;
    if envelope.signer_key != terminal_key_name(&public_key) {
        return Err(Rejected);
    }
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| Rejected)?;
    key.verify_strict(
        &envelope.signature_preimage().map_err(|_| Rejected)?,
        &Signature::from_bytes(&envelope.signature),
    )
    .map_err(|_| Rejected)
}
