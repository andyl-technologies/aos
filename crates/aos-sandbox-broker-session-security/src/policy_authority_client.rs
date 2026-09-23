//! Read-only authenticated access to the privileged deployment policy head.
//!
//! `AOSPHQ01` is a 32-byte request containing a fresh nonce. `AOSPHR01`
//! echoes that nonce, then carries the exact 224-byte signed deployment head
//! and four length-prefixed canonical input documents. This exchange proves
//! current head custody at query time; it does not issue a compiler binding.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aos_sandbox::policy_compiler::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    decode_policy_deployment_sources_v1, verify_policy_deployment_head_v1,
};
use ed25519_dalek::VerifyingKey;

/// Names the fixed root-owned local policy-authority endpoint.
pub const POLICY_AUTHORITY_SOCKET_PATH_V1: &str =
    "/run/aos/sandbox-policy-authority/current-head.sock";
/// Identifies a bounded current-head query.
pub const POLICY_HEAD_QUERY_MAGIC_V1: &[u8; 8] = b"AOSPHQ01";
/// Identifies the nonce-linked signed-head receipt.
pub const POLICY_HEAD_RECEIPT_MAGIC_V1: &[u8; 8] = b"AOSPHR01";
const PACKET_BYTES: usize = 224;
const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
const MAXIMUM_RECEIPT_BYTES: usize = 24 + PACKET_BYTES + 4 * (4 + MAXIMUM_INPUT_BYTES);

/// Retains an exact signed head and constructor-validated deployment sources.
///
/// The receipt is a query-time observation only. A later AOSPCB01 issuance
/// must independently fence the current protected head and dynamic inputs.
pub struct PolicyAuthorityHeadReceiptV1 {
    head: PolicyDeploymentHeadV1,
    sources: PolicyDeploymentSourcesV1,
}

impl PolicyAuthorityHeadReceiptV1 {
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
}

/// Queries the root-owned policy authority using the pinned deployment key.
///
/// # Errors
///
/// Returns an error if kernel peer credentials do not identify root, the
/// exchange is malformed, or the signed head and typed inputs fail validation.
pub fn query_current_policy_deployment_head_v1(
    verifying_key: &VerifyingKey,
) -> io::Result<PolicyAuthorityHeadReceiptV1> {
    let mut stream = UnixStream::connect(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V1))?;
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
    request[..8].copy_from_slice(POLICY_HEAD_QUERY_MAGIC_V1);
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
    decode_receipt(&receipt, nonce, verifying_key, now_unix_seconds)
}

fn decode_receipt(
    receipt: &[u8],
    nonce: [u8; 16],
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> io::Result<PolicyAuthorityHeadReceiptV1> {
    if receipt.len() > MAXIMUM_RECEIPT_BYTES
        || receipt.get(..8) != Some(POLICY_HEAD_RECEIPT_MAGIC_V1)
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
    if position != receipt.len() {
        return Err(invalid_receipt());
    }
    let exact = PolicyDeploymentInputsV1 {
        node: inputs[0],
        site: inputs[1],
        backend: inputs[2],
        catalogs: inputs[3],
    };
    let head = verify_policy_deployment_head_v1(packet, &exact, verifying_key, now_unix_seconds)
        .map_err(|_| invalid_receipt())?;
    let sources =
        decode_policy_deployment_sources_v1(&exact, head).map_err(|_| invalid_receipt())?;
    Ok(PolicyAuthorityHeadReceiptV1 { head, sources })
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

    use super::{MAXIMUM_RECEIPT_BYTES, POLICY_HEAD_RECEIPT_MAGIC_V1, decode_receipt};

    #[test]
    fn rejects_nonce_substitution_and_excessive_receipts() {
        let verifying_key = SigningKey::from_bytes(&[19; 32]).verifying_key();
        let nonce = [7; 16];
        let mut receipt = Vec::new();
        receipt.extend_from_slice(POLICY_HEAD_RECEIPT_MAGIC_V1);
        receipt.extend_from_slice(&[8; 16]);
        receipt.resize(24 + 224, 0);

        assert!(decode_receipt(&receipt, nonce, &verifying_key, 20).is_err());

        receipt[8..24].copy_from_slice(&nonce);
        receipt.resize(MAXIMUM_RECEIPT_BYTES + 1, 0);
        assert!(decode_receipt(&receipt, nonce, &verifying_key, 20).is_err());
    }
}
