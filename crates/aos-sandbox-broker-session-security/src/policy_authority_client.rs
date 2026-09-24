//! Authenticated observations and closed CAS at the privileged policy head.
//!
//! `AOSPHQ02` is a 32-byte request containing a fresh nonce. `AOSPHR02`
//! echoes that nonce, then carries the exact 224-byte signed deployment head,
//! four length-prefixed canonical deployment documents, the 312-byte signed
//! project head, and its length-prefixed canonical layer. This exchange proves
//! current head custody at query time; it does not issue a compiler binding.
//! `AOSPHQ03` frames the same receipt while root retains its writer lock
//! through a nonce-bound action ACK and post-action snapshot validation.
//! `AOSPHQ04` additionally accepts one canonical AOSPCB02 proposal and
//! commits a closed root CAS. Its response never authorizes publication.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aos_sandbox::policy_compiler::{
    CLOSED_POLICY_BINDING_BYTES_V2, CurrentCreateProjectPolicySourceV1, PolicyDeploymentHeadV1,
    PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1, SignedProjectPolicySourceV1,
    closed_policy_binding_digest_v2, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
};
use aos_sandbox_core::ObjectDigest;
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
/// Begins a root-held closed AOSPCB02 compare-and-swap exchange.
pub const POLICY_BINDING_QUERY_MAGIC_V4: &[u8; 8] = b"AOSPHQ04";
/// Identifies root-derived CAS and signer-generation base fields.
pub const POLICY_BINDING_BASE_MAGIC_V4: &[u8; 8] = b"AOSPHB04";
/// Frames one exact AOSPCB02 proposal under the root-held nonce.
pub const POLICY_BINDING_SUBMIT_MAGIC_V4: &[u8; 8] = b"AOSPBS04";
/// Reports a durable but non-authorizing root compare-and-swap.
pub const POLICY_BINDING_COMMITTED_MAGIC_V4: &[u8; 8] = b"AOSPBC04";
/// Acknowledges the retained epoch without conferring an effect.
pub const POLICY_BINDING_ACK_MAGIC_V4: &[u8; 8] = b"AOSPHA04";
/// Confirms exact root postcommit readback and snapshot validation.
pub const POLICY_BINDING_COMPLETE_MAGIC_V4: &[u8; 8] = b"AOSPHC04";
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
const CLOSED_BINDING_FRAME_BYTES: usize = 8 + 16 + 32 + 8;
const CLOSED_BINDING_BASE_BYTES: usize = 8 + 16 + 32 + 8 + 8 + 8;

/// Reports root-owned fields required to propose a closed binding.
///
/// The service rechecks these values under its writer at CAS. They are not a
/// substitute for controller, source-domain, or physical Cache custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedPolicyBindingBaseV4 {
    issuer_owner: [u8; 16],
    predecessor: ObjectDigest,
    next_generation: u64,
    deployment_signer_generation: u64,
    project_signer_generation: u64,
}

impl ClosedPolicyBindingBaseV4 {
    /// Returns the root-derived controller owner commitment.
    #[must_use]
    pub const fn issuer_owner(self) -> [u8; 16] {
        self.issuer_owner
    }

    /// Returns the protected root binding predecessor.
    #[must_use]
    pub const fn predecessor(self) -> ObjectDigest {
        self.predecessor
    }

    /// Returns the required next root and handoff generation.
    #[must_use]
    pub const fn next_generation(self) -> u64 {
        self.next_generation
    }

    /// Returns the pinned deployment signer generation.
    #[must_use]
    pub const fn deployment_signer_generation(self) -> u64 {
        self.deployment_signer_generation
    }

    /// Returns the pinned project signer generation.
    #[must_use]
    pub const fn project_signer_generation(self) -> u64 {
        self.project_signer_generation
    }
}

/// Reports one durable root CAS that still cannot authorize an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedPolicyBindingClientObservationV4 {
    binding: ObjectDigest,
    handoff_epoch: u64,
}

impl ClosedPolicyBindingClientObservationV4 {
    /// Returns the exact content-addressed closed binding head.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root-retained handoff epoch.
    #[must_use]
    pub const fn handoff_epoch(self) -> u64 {
        self.handoff_epoch
    }
}

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

/// Sends one closed AOSPCB02 proposal under the root-owned same-session CAS.
///
/// The caller must first hold controller, source-domain, and physical Cache
/// writers in that order. Root independently pins its signer generations,
/// signed heads, predecessor, and CAS epoch; the other fields remain claims.
/// A successful response is not a policy-publication or effect capability.
/// There is no live controller callsite until complete replay and handoff are
/// independently connected. The verification keys here only check the signed
/// receipt; they do not nominate the root service's signer or head.
///
/// # Errors
///
/// Rejects an unexpected root peer, malformed or stale signed receipt,
/// noncanonical proposal, changed CAS response, or missing completion.
pub fn commit_closed_policy_binding_v4(
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
    propose: impl FnOnce(
        &PolicyAuthorityHeadReceiptV2,
        ClosedPolicyBindingBaseV4,
    ) -> io::Result<Vec<u8>>,
) -> io::Result<ClosedPolicyBindingClientObservationV4> {
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
    request[..8].copy_from_slice(POLICY_BINDING_QUERY_MAGIC_V4);
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

    let mut base = [0_u8; CLOSED_BINDING_BASE_BYTES];
    stream.read_exact(&mut base)?;
    let base = decode_closed_binding_base(&base)?;

    let proposed = propose(&receipt, base)?;
    if proposed.len() != CLOSED_POLICY_BINDING_BYTES_V2 {
        return Err(invalid_receipt());
    }
    let binding = closed_policy_binding_digest_v2(&proposed).map_err(io::Error::other)?;
    stream.write_all(POLICY_BINDING_SUBMIT_MAGIC_V4)?;
    stream.write_all(&nonce)?;
    stream.write_all(
        &u32::try_from(proposed.len())
            .map_err(io::Error::other)?
            .to_be_bytes(),
    )?;
    stream.write_all(&proposed)?;

    let mut committed = [0_u8; CLOSED_BINDING_FRAME_BYTES];
    stream.read_exact(&mut committed)?;
    let epoch = validate_closed_binding_frame(
        &committed,
        POLICY_BINDING_COMMITTED_MAGIC_V4,
        nonce,
        binding,
    )?;
    stream.write_all(POLICY_BINDING_ACK_MAGIC_V4)?;
    stream.write_all(&nonce)?;
    stream.write_all(binding.as_bytes())?;
    stream.write_all(&epoch.to_be_bytes())?;

    let mut completion = [0_u8; CLOSED_BINDING_FRAME_BYTES];
    stream.read_exact(&mut completion)?;
    if validate_closed_binding_frame(
        &completion,
        POLICY_BINDING_COMPLETE_MAGIC_V4,
        nonce,
        binding,
    )? != epoch
    {
        return Err(invalid_receipt());
    }
    Ok(ClosedPolicyBindingClientObservationV4 {
        binding,
        handoff_epoch: epoch,
    })
}

fn decode_closed_binding_base(
    frame: &[u8; CLOSED_BINDING_BASE_BYTES],
) -> io::Result<ClosedPolicyBindingBaseV4> {
    if &frame[..8] != POLICY_BINDING_BASE_MAGIC_V4 {
        return Err(invalid_receipt());
    }
    let issuer_owner: [u8; 16] = frame[8..24].try_into().map_err(|_| invalid_receipt())?;
    let predecessor =
        ObjectDigest::from_bytes(frame[24..56].try_into().map_err(|_| invalid_receipt())?);
    let next_generation =
        u64::from_be_bytes(frame[56..64].try_into().map_err(|_| invalid_receipt())?);
    let deployment_signer_generation =
        u64::from_be_bytes(frame[64..72].try_into().map_err(|_| invalid_receipt())?);
    let project_signer_generation =
        u64::from_be_bytes(frame[72..80].try_into().map_err(|_| invalid_receipt())?);
    if issuer_owner == [0; 16]
        || next_generation == 0
        || deployment_signer_generation == 0
        || project_signer_generation == 0
        || (next_generation == 1) != (predecessor.as_bytes() == &[0; 32])
    {
        return Err(invalid_receipt());
    }
    Ok(ClosedPolicyBindingBaseV4 {
        issuer_owner,
        predecessor,
        next_generation,
        deployment_signer_generation,
        project_signer_generation,
    })
}

fn validate_closed_binding_frame(
    frame: &[u8; CLOSED_BINDING_FRAME_BYTES],
    magic: &[u8; 8],
    nonce: [u8; 16],
    binding: ObjectDigest,
) -> io::Result<u64> {
    if &frame[..8] != magic || frame[8..24] != nonce || &frame[24..56] != binding.as_bytes() {
        return Err(invalid_receipt());
    }
    let epoch = u64::from_be_bytes(frame[56..64].try_into().map_err(|_| invalid_receipt())?);
    if epoch == 0 {
        return Err(invalid_receipt());
    }
    Ok(epoch)
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
        CLOSED_BINDING_BASE_BYTES, CLOSED_BINDING_FRAME_BYTES, MAXIMUM_RECEIPT_BYTES, ObjectDigest,
        POLICY_BINDING_BASE_MAGIC_V4, POLICY_BINDING_COMMITTED_MAGIC_V4,
        POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3, POLICY_HEAD_RECEIPT_MAGIC_V2,
        decode_closed_binding_base, decode_receipt, validate_closed_binding_frame,
        validate_lease_completion,
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

    #[test]
    fn closed_binding_frame_rejects_substituted_nonce_head_epoch_and_version() {
        let nonce = [7; 16];
        let binding = ObjectDigest::from_bytes([8; 32]);
        let mut frame = [0_u8; CLOSED_BINDING_FRAME_BYTES];
        frame[..8].copy_from_slice(POLICY_BINDING_COMMITTED_MAGIC_V4);
        frame[8..24].copy_from_slice(&nonce);
        frame[24..56].copy_from_slice(binding.as_bytes());
        frame[56..64].copy_from_slice(&3_u64.to_be_bytes());
        assert_eq!(
            validate_closed_binding_frame(
                &frame,
                POLICY_BINDING_COMMITTED_MAGIC_V4,
                nonce,
                binding
            )
            .expect("exact root frame"),
            3
        );

        assert!(
            validate_closed_binding_frame(
                &frame,
                POLICY_BINDING_COMMITTED_MAGIC_V4,
                [9; 16],
                binding,
            )
            .is_err()
        );
        assert!(
            validate_closed_binding_frame(
                &frame,
                POLICY_BINDING_COMMITTED_MAGIC_V4,
                nonce,
                ObjectDigest::from_bytes([9; 32]),
            )
            .is_err()
        );
        frame[56..64].fill(0);
        assert!(
            validate_closed_binding_frame(
                &frame,
                POLICY_BINDING_COMMITTED_MAGIC_V4,
                nonce,
                binding,
            )
            .is_err()
        );
        frame[0] ^= 1;
        assert!(
            validate_closed_binding_frame(
                &frame,
                POLICY_BINDING_COMMITTED_MAGIC_V4,
                nonce,
                binding,
            )
            .is_err()
        );
    }

    #[test]
    fn closed_binding_base_rejects_stale_or_unscoped_root_state() {
        let mut frame = [0_u8; CLOSED_BINDING_BASE_BYTES];
        frame[..8].copy_from_slice(POLICY_BINDING_BASE_MAGIC_V4);
        frame[8..24].fill(1);
        frame[56..64].copy_from_slice(&1_u64.to_be_bytes());
        frame[64..72].copy_from_slice(&2_u64.to_be_bytes());
        frame[72..80].copy_from_slice(&3_u64.to_be_bytes());
        let base = decode_closed_binding_base(&frame).expect("genesis root state");
        assert_eq!(base.next_generation(), 1);
        assert_eq!(base.deployment_signer_generation(), 2);
        assert_eq!(base.project_signer_generation(), 3);

        frame[56..64].copy_from_slice(&2_u64.to_be_bytes());
        assert!(decode_closed_binding_base(&frame).is_err());
        frame[24..56].fill(4);
        assert!(decode_closed_binding_base(&frame).is_ok());
        frame[64..72].fill(0);
        assert!(decode_closed_binding_base(&frame).is_err());
        frame[0] ^= 1;
        assert!(decode_closed_binding_base(&frame).is_err());
    }
}
