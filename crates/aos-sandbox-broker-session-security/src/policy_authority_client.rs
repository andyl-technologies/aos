//! Read-only authenticated access to the privileged deployment policy head.
//!
//! `AOSPHQ02` is a 32-byte request containing a fresh nonce. `AOSPHR02`
//! echoes that nonce, then carries the exact 224-byte signed deployment head,
//! four length-prefixed canonical deployment documents, the 312-byte signed
//! project head, and its length-prefixed canonical layer. This exchange proves
//! current head custody at query time; it does not issue a compiler binding.
//! `AOSPHQ03` frames the same receipt while root retains its writer lock
//! through a nonce-bound action ACK and post-action snapshot validation.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aos_sandbox::policy_compiler::{
    CurrentCreateProjectPolicySourceV1, PolicyDeploymentHeadV1, PolicyDeploymentInputsV1,
    PolicyDeploymentSourcesV1, SignedProjectPolicySourceV1, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
};
use ed25519_dalek::VerifyingKey;

/// Names the fixed root-owned local policy-authority endpoint.
pub const POLICY_AUTHORITY_SOCKET_PATH_V2: &str =
    "/run/aos/sandbox-policy-authority/current-head.sock";
/// Identifies a bounded current-head query.
pub const POLICY_HEAD_QUERY_MAGIC_V2: &[u8; 8] = b"AOSPHQ02";
/// Identifies the nonce-linked signed-head receipt.
pub const POLICY_HEAD_RECEIPT_MAGIC_V2: &[u8; 8] = b"AOSPHR02";
/// Begins a root-held policy-head lease rather than a one-shot observation.
pub const POLICY_HEAD_LEASE_QUERY_MAGIC_V3: &[u8; 8] = b"AOSPHQ03";
/// Acknowledges completion of the client action under the exact lease nonce.
pub const POLICY_HEAD_LEASE_ACK_MAGIC_V3: &[u8; 8] = b"AOSPHA03";
/// Confirms that root-side post-action snapshot validation completed.
pub const POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3: &[u8; 8] = b"AOSPHC03";
const PACKET_BYTES: usize = 224;
const PROJECT_PACKET_BYTES: usize = 312;
const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
const MAXIMUM_PROJECT_INPUT_BYTES: usize = 3 * 1024;
const MAXIMUM_RECEIPT_BYTES: usize = 24
    + PACKET_BYTES
    + 4 * (4 + MAXIMUM_INPUT_BYTES)
    + PROJECT_PACKET_BYTES
    + 4
    + MAXIMUM_PROJECT_INPUT_BYTES;

/// Retains an exact signed head and constructor-validated deployment sources.
///
/// The receipt is a query-time observation only. A later AOSPCB01 issuance
/// must independently fence the current protected head and dynamic inputs.
pub struct PolicyAuthorityHeadReceiptV2 {
    head: PolicyDeploymentHeadV1,
    sources: PolicyDeploymentSourcesV1,
    project: SignedProjectPolicySourceV1,
}

impl PolicyAuthorityHeadReceiptV2 {
    /// Returns the verified signed deployment head.
    #[must_use]
    pub const fn head(&self) -> PolicyDeploymentHeadV1 {
        self.head
    }

    /// Returns constructor-validated, signed node/site/backend sources.
    #[must_use]
    pub const fn sources(&self) -> &PolicyDeploymentSourcesV1 {
        &self.sources
    }

    /// Returns the separately signed, explicit project-layer source.
    #[must_use]
    pub const fn project(&self) -> &SignedProjectPolicySourceV1 {
        &self.project
    }

    /// Joins a protected parentless Create to the signed publisher head.
    ///
    /// This validates project identity, current publisher generation and
    /// descriptor only. It does not authenticate the other prerequisite-head
    /// claims or issue a compiler binding.
    #[must_use]
    pub fn matches_current_create(&self, create: &CurrentCreateProjectPolicySourceV1) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let Ok(now) = i64::try_from(now.as_secs()) else {
            return false;
        };
        let head = self.project.head();
        now < self.head.expires_at()
            && now < head.expires_at()
            && head.project() == create.project()
            && head.publisher_generation() == create.policy_generation()
            && head.publisher_digest() == create.policy_digest()
    }
}

/// Queries the root-owned policy authority using the pinned deployment key.
///
/// # Errors
///
/// Returns an error if kernel peer credentials do not identify root, the
/// exchange is malformed, or the signed head and typed inputs fail validation.
pub fn query_current_policy_deployment_head_v2(
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
) -> io::Result<PolicyAuthorityHeadReceiptV2> {
    let mut stream = UnixStream::connect(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    if !peer.uid.is_root() {
        return Err(invalid_receipt());
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut nonce = [0_u8; 16];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(io::Error::other)?;
    let mut request = [0_u8; 32];
    request[..8].copy_from_slice(POLICY_HEAD_QUERY_MAGIC_V2);
    request[8..24].copy_from_slice(&nonce);
    stream.write_all(&request)?;

    let mut receipt = Vec::new();
    stream
        .take(u64::try_from(MAXIMUM_RECEIPT_BYTES + 1).map_err(io::Error::other)?)
        .read_to_end(&mut receipt)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let now_unix_seconds = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
    decode_receipt(
        &receipt,
        nonce,
        deployment_verifying_key,
        project_verifying_key,
        now_unix_seconds,
    )
}

/// Runs one action while the root service holds its protected policy-head lock.
///
/// The controller must already hold its controller, source-domain ancestry,
/// and physical Cache writers, in that order, before this call acquires the
/// root writer. The callback is for read-only candidate inspection; it must
/// not publish a binding or perform an effect. A missing ACK times out at the
/// root service without returning a completion to this caller.
/// The root service independently compares its current packet to its pinned
/// credential, retains root journal custody until the nonce-bound ACK, then
/// validates its snapshot before completion. This is a lease primitive only:
/// it does not authorize AOSPCB02 binding CAS or production effects.
///
/// # Errors
///
/// Rejects an unexpected root peer, malformed or stale signed receipt,
/// failed callback, closed connection, or missing post-lease confirmation.
pub fn with_current_policy_head_lease_v3<R>(
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
    action: impl FnOnce(&PolicyAuthorityHeadReceiptV2) -> io::Result<R>,
) -> io::Result<R> {
    let mut stream = UnixStream::connect(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    if !peer.uid.is_root() {
        return Err(invalid_receipt());
    }
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut nonce = [0_u8; 16];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(io::Error::other)?;
    let mut request = [0_u8; 32];
    request[..8].copy_from_slice(POLICY_HEAD_LEASE_QUERY_MAGIC_V3);
    request[8..24].copy_from_slice(&nonce);
    stream.write_all(&request)?;

    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
    if length == 0 || length > MAXIMUM_RECEIPT_BYTES {
        return Err(invalid_receipt());
    }
    let mut receipt = vec![0_u8; length];
    stream.read_exact(&mut receipt)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let now_unix_seconds = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
    let receipt = decode_receipt(
        &receipt,
        nonce,
        deployment_verifying_key,
        project_verifying_key,
        now_unix_seconds,
    )?;

    let result = action(&receipt)?;
    stream.write_all(POLICY_HEAD_LEASE_ACK_MAGIC_V3)?;
    stream.write_all(&nonce)?;
    let mut completion = [0_u8; 24];
    stream.read_exact(&mut completion)?;
    validate_lease_completion(&completion, nonce)?;
    Ok(result)
}

fn validate_lease_completion(completion: &[u8; 24], nonce: [u8; 16]) -> io::Result<()> {
    if &completion[..8] != POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3 || completion[8..] != nonce {
        return Err(invalid_receipt());
    }
    Ok(())
}

fn decode_receipt(
    receipt: &[u8],
    nonce: [u8; 16],
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> io::Result<PolicyAuthorityHeadReceiptV2> {
    if receipt.len() > MAXIMUM_RECEIPT_BYTES
        || receipt.get(..8) != Some(POLICY_HEAD_RECEIPT_MAGIC_V2)
        || receipt.get(8..24) != Some(nonce.as_slice())
    {
        return Err(invalid_receipt());
    }
    let packet = receipt
        .get(24..24 + PACKET_BYTES)
        .ok_or_else(invalid_receipt)?;
    let mut position = 24 + PACKET_BYTES;
    let mut inputs = Vec::with_capacity(4);
    for _ in 0..4 {
        let length = receipt
            .get(position..position + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(invalid_receipt)?;
        position += 4;
        let length = usize::try_from(length).map_err(|_| invalid_receipt())?;
        if length == 0 || length > MAXIMUM_INPUT_BYTES {
            return Err(invalid_receipt());
        }
        inputs.push(
            receipt
                .get(position..position + length)
                .ok_or_else(invalid_receipt)?,
        );
        position += length;
    }
    let project_packet = receipt
        .get(position..position + PROJECT_PACKET_BYTES)
        .ok_or_else(invalid_receipt)?;
    position += PROJECT_PACKET_BYTES;
    let project_length = receipt
        .get(position..position + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(invalid_receipt)?;
    position += 4;
    let project_length = usize::try_from(project_length).map_err(|_| invalid_receipt())?;
    if project_length == 0 || project_length > MAXIMUM_PROJECT_INPUT_BYTES {
        return Err(invalid_receipt());
    }
    let project_input = receipt
        .get(position..position + project_length)
        .ok_or_else(invalid_receipt)?;
    position += project_length;
    if position != receipt.len() {
        return Err(invalid_receipt());
    }
    let exact = PolicyDeploymentInputsV1 {
        node: inputs[0],
        site: inputs[1],
        backend: inputs[2],
        catalogs: inputs[3],
    };
    let head = verify_policy_deployment_head_v1(
        packet,
        &exact,
        deployment_verifying_key,
        now_unix_seconds,
    )
    .map_err(|_| invalid_receipt())?;
    let sources =
        decode_policy_deployment_sources_v1(&exact, head).map_err(|_| invalid_receipt())?;
    let project = verify_signed_project_policy_source_v1(
        project_packet,
        project_input,
        project_verifying_key,
        now_unix_seconds,
    )
    .map_err(|_| invalid_receipt())?;
    if project.head().prerequisite_claims()[1] != head.packet_digest() {
        return Err(invalid_receipt());
    }
    Ok(PolicyAuthorityHeadReceiptV2 {
        head,
        sources,
        project,
    })
}

fn invalid_receipt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid policy authority receipt",
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{
        MAXIMUM_RECEIPT_BYTES, POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3, POLICY_HEAD_RECEIPT_MAGIC_V2,
        decode_receipt, validate_lease_completion,
    };

    #[test]
    fn rejects_nonce_substitution_and_excessive_receipts() {
        let verifying_key = SigningKey::from_bytes(&[19; 32]).verifying_key();
        let nonce = [7; 16];
        let mut receipt = Vec::new();
        receipt.extend_from_slice(POLICY_HEAD_RECEIPT_MAGIC_V2);
        receipt.extend_from_slice(&[8; 16]);
        receipt.resize(24 + 224, 0);

        assert!(decode_receipt(&receipt, nonce, &verifying_key, &verifying_key, 20).is_err());

        receipt[8..24].copy_from_slice(&nonce);
        receipt.resize(MAXIMUM_RECEIPT_BYTES + 1, 0);
        assert!(decode_receipt(&receipt, nonce, &verifying_key, &verifying_key, 20).is_err());
    }

    #[test]
    fn lease_completion_rejects_nonce_or_version_substitution() {
        let nonce = [7; 16];
        let mut completion = [0_u8; 24];
        completion[..8].copy_from_slice(POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3);
        completion[8..].copy_from_slice(&nonce);
        assert!(validate_lease_completion(&completion, nonce).is_ok());

        assert!(validate_lease_completion(&completion, [8; 16]).is_err());
        completion[0] ^= 1;
        assert!(validate_lease_completion(&completion, nonce).is_err());
    }
}
