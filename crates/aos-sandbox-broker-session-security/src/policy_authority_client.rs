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
//! commits a closed root CAS. It requires an `AOSPHR04` receipt with an
//! `AOSPPH02` project source; the V1 receipt cannot downgrade this exchange.
//! Its response never authorizes publication.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aos_sandbox::policy_compiler::{
    CLOSED_POLICY_BINDING_BYTES_V2, CurrentCreateProjectPolicySourceV1, PolicyCompilerInputV1,
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    SignedProjectPolicySourceV1, VerifiedSignedProjectPolicySourceV2,
    closed_policy_binding_digest_v2, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
    verify_signed_project_policy_source_v2,
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
/// Identifies the nonce-linked V2 project-source receipt for closed CAS.
pub const POLICY_BINDING_RECEIPT_MAGIC_V4: &[u8; 8] = b"AOSPHR04";
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
const EXPLICIT_PROJECT_PACKET_BYTES: usize = 328;
const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
const MAXIMUM_PROJECT_INPUT_BYTES: usize = 3 * 1024;
const MAXIMUM_RECEIPT_BYTES: usize = 24
    + PACKET_BYTES
    + 4 * (4 + MAXIMUM_INPUT_BYTES)
    + PROJECT_PACKET_BYTES
    + 4
    + MAXIMUM_PROJECT_INPUT_BYTES;
const MAXIMUM_EXPLICIT_RECEIPT_BYTES: usize =
    MAXIMUM_RECEIPT_BYTES - PROJECT_PACKET_BYTES + EXPLICIT_PROJECT_PACKET_BYTES;
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

/// Retains a signed explicit project source from the root-held Q04 exchange.
///
/// Signature and deployment provenance are verified, but independent
/// controller, ancestry, and Cache heads remain unproven by this receipt.
/// Compiler input checks below are read-only and never grant publication.
pub struct PolicyAuthorityExplicitHeadReceiptV4 {
    head: PolicyDeploymentHeadV1,
    sources: PolicyDeploymentSourcesV1,
    project: VerifiedSignedProjectPolicySourceV2,
}

impl PolicyAuthorityExplicitHeadReceiptV4 {
    /// Returns the signed deployment head.
    #[must_use]
    pub const fn head(&self) -> PolicyDeploymentHeadV1 {
        self.head
    }

    /// Returns the typed, signed deployment sources.
    #[must_use]
    pub const fn sources(&self) -> &PolicyDeploymentSourcesV1 {
        &self.sources
    }

    /// Returns the V2 signed project source without protected admission.
    #[must_use]
    pub const fn project(&self) -> &VerifiedSignedProjectPolicySourceV2 {
        &self.project
    }

    /// Checks a candidate input against the signed sources and current Create.
    ///
    /// The caller must still construct the exact project cache-domain binding
    /// from protected publisher custody and prove the all-owner cut. This
    /// check only rejects substitutions before a closed proposal.
    #[must_use]
    pub fn matches_compiler_input(
        &self,
        create: &CurrentCreateProjectPolicySourceV1,
        input: &PolicyCompilerInputV1,
    ) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let Ok(now) = i64::try_from(now.as_secs()) else {
            return false;
        };
        let project_head = self.project.head();
        now < self.head.expires_at()
            && now < project_head.expires_at()
            && project_head.project() == create.project()
            && project_head.publisher_generation() == create.policy_generation()
            && project_head.publisher_digest() == create.policy_digest()
            && self.project.cache_domain() == create.cache_domain()
            && project_head.prerequisite_claims()[2] == create.cache_domain_head()
            && project_head.prerequisite_claims()[3] == create.revocation_head()
            && input.sandbox() == create.sandbox()
            && input.project().project() == create.project()
            && self
                .project
                .matches_candidate_layer(input.project().layer())
            && input.node() == self.sources.node()
            && input.site() == self.sources.site()
            && input.backend() == self.sources.backend()
            && input.ancestors().is_empty()
            && input.endpoints().entries().is_empty()
            && input.destinations().entries().is_empty()
    }
}

pub(crate) fn connect_policy_query(
    magic: &[u8; 8],
    read_timeout: Duration,
) -> io::Result<(UnixStream, [u8; 16])> {
    let mut stream = UnixStream::connect(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    if !peer.uid.is_root() {
        return Err(invalid_receipt());
    }
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut nonce = [0_u8; 16];
    rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
        .map_err(io::Error::other)?;
    stream.write_all(&policy_query_request(magic, nonce))?;
    Ok((stream, nonce))
}

fn policy_query_request(magic: &[u8; 8], nonce: [u8; 16]) -> [u8; 32] {
    let mut request = [0_u8; 32];
    request[..8].copy_from_slice(magic);
    request[8..24].copy_from_slice(&nonce);
    request
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
    let (stream, nonce) = connect_policy_query(POLICY_HEAD_QUERY_MAGIC_V2, Duration::from_secs(5))?;

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
    let (mut stream, nonce) =
        connect_policy_query(POLICY_HEAD_LEASE_QUERY_MAGIC_V3, Duration::from_secs(35))?;

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
        &PolicyAuthorityExplicitHeadReceiptV4,
        ClosedPolicyBindingBaseV4,
    ) -> io::Result<Vec<u8>>,
) -> io::Result<ClosedPolicyBindingClientObservationV4> {
    let (mut stream, nonce) =
        connect_policy_query(POLICY_BINDING_QUERY_MAGIC_V4, Duration::from_secs(35))?;

    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
    if length == 0 || length > MAXIMUM_EXPLICIT_RECEIPT_BYTES {
        return Err(invalid_receipt());
    }
    let mut receipt = vec![0_u8; length];
    stream.read_exact(&mut receipt)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let now_unix_seconds = i64::try_from(now.as_secs()).map_err(io::Error::other)?;
    let receipt = decode_explicit_receipt_v4(
        &receipt,
        nonce,
        deployment_verifying_key,
        project_verifying_key,
        now_unix_seconds,
    )?;

    let mut base = [0_u8; CLOSED_BINDING_BASE_BYTES];
    stream.read_exact(&mut base)?;
    let base = decode_closed_binding_base(&base)?;
    validate_receipt_signer_generations(&receipt, base)?;

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

fn validate_receipt_signer_generations(
    receipt: &PolicyAuthorityExplicitHeadReceiptV4,
    base: ClosedPolicyBindingBaseV4,
) -> io::Result<()> {
    let signed = receipt.project().head();
    if signed.deployment_signer_generation() != base.deployment_signer_generation()
        || signed.project_signer_generation() != base.project_signer_generation()
    {
        return Err(invalid_receipt());
    }
    Ok(())
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
    let frame = parse_receipt_frame(
        receipt,
        nonce,
        POLICY_HEAD_RECEIPT_MAGIC_V2,
        MAXIMUM_RECEIPT_BYTES,
        PROJECT_PACKET_BYTES,
    )?;
    let exact = PolicyDeploymentInputsV1 {
        node: frame.inputs[0],
        site: frame.inputs[1],
        backend: frame.inputs[2],
        catalogs: frame.inputs[3],
    };
    let head = verify_policy_deployment_head_v1(
        frame.packet,
        &exact,
        deployment_verifying_key,
        now_unix_seconds,
    )
    .map_err(|_| invalid_receipt())?;
    let sources =
        decode_policy_deployment_sources_v1(&exact, head).map_err(|_| invalid_receipt())?;
    let project = verify_signed_project_policy_source_v1(
        frame.project_packet,
        frame.project_input,
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

fn decode_explicit_receipt_v4(
    receipt: &[u8],
    nonce: [u8; 16],
    deployment_verifying_key: &VerifyingKey,
    project_verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> io::Result<PolicyAuthorityExplicitHeadReceiptV4> {
    let frame = parse_receipt_frame(
        receipt,
        nonce,
        POLICY_BINDING_RECEIPT_MAGIC_V4,
        MAXIMUM_EXPLICIT_RECEIPT_BYTES,
        EXPLICIT_PROJECT_PACKET_BYTES,
    )?;

    let exact = PolicyDeploymentInputsV1 {
        node: frame.inputs[0],
        site: frame.inputs[1],
        backend: frame.inputs[2],
        catalogs: frame.inputs[3],
    };
    let head = verify_policy_deployment_head_v1(
        frame.packet,
        &exact,
        deployment_verifying_key,
        now_unix_seconds,
    )
    .map_err(|_| invalid_receipt())?;
    let sources =
        decode_policy_deployment_sources_v1(&exact, head).map_err(|_| invalid_receipt())?;
    let project = verify_signed_project_policy_source_v2(
        frame.project_packet,
        frame.project_input,
        project_verifying_key,
        now_unix_seconds,
    )
    .map_err(|_| invalid_receipt())?;
    if project.head().prerequisite_claims()[1] != head.packet_digest() {
        return Err(invalid_receipt());
    }
    Ok(PolicyAuthorityExplicitHeadReceiptV4 {
        head,
        sources,
        project,
    })
}

struct ReceiptFrame<'a> {
    packet: &'a [u8],
    inputs: [&'a [u8]; 4],
    project_packet: &'a [u8],
    project_input: &'a [u8],
}

fn parse_receipt_frame<'a>(
    receipt: &'a [u8],
    nonce: [u8; 16],
    magic: &[u8; 8],
    maximum_receipt_bytes: usize,
    project_packet_bytes: usize,
) -> io::Result<ReceiptFrame<'a>> {
    if receipt.len() > maximum_receipt_bytes
        || receipt.get(..8) != Some(magic.as_slice())
        || receipt.get(8..24) != Some(nonce.as_slice())
    {
        return Err(invalid_receipt());
    }
    let packet = receipt
        .get(24..24 + PACKET_BYTES)
        .ok_or_else(invalid_receipt)?;
    let mut position = 24 + PACKET_BYTES;
    let mut inputs = [&[][..]; 4];
    for input in &mut inputs {
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
        *input = receipt
            .get(position..position + length)
            .ok_or_else(invalid_receipt)?;
        position += length;
    }
    let project_packet = receipt
        .get(position..position + project_packet_bytes)
        .ok_or_else(invalid_receipt)?;
    position += project_packet_bytes;
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
    Ok(ReceiptFrame {
        packet,
        inputs,
        project_packet,
        project_input,
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
    use aos_sandbox_core::ProjectId;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};

    use super::{
        CLOSED_BINDING_BASE_BYTES, CLOSED_BINDING_FRAME_BYTES, EXPLICIT_PROJECT_PACKET_BYTES,
        MAXIMUM_EXPLICIT_RECEIPT_BYTES, MAXIMUM_INPUT_BYTES, MAXIMUM_PROJECT_INPUT_BYTES,
        MAXIMUM_RECEIPT_BYTES, ObjectDigest, PACKET_BYTES, POLICY_BINDING_BASE_MAGIC_V4,
        POLICY_BINDING_COMMITTED_MAGIC_V4, POLICY_BINDING_QUERY_MAGIC_V4,
        POLICY_BINDING_RECEIPT_MAGIC_V4, POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3,
        POLICY_HEAD_LEASE_QUERY_MAGIC_V3, POLICY_HEAD_QUERY_MAGIC_V2, POLICY_HEAD_RECEIPT_MAGIC_V2,
        PROJECT_PACKET_BYTES, decode_closed_binding_base, decode_explicit_receipt_v4,
        decode_receipt, parse_receipt_frame, policy_query_request, validate_closed_binding_frame,
        validate_lease_completion, validate_receipt_signer_generations,
    };

    #[test]
    fn policy_queries_keep_exact_magic_nonce_and_reserved_bytes() {
        let nonce = [7; 16];
        for magic in [
            POLICY_HEAD_QUERY_MAGIC_V2,
            POLICY_HEAD_LEASE_QUERY_MAGIC_V3,
            POLICY_BINDING_QUERY_MAGIC_V4,
        ] {
            let request = policy_query_request(magic, nonce);
            assert_eq!(&request[..8], magic);
            assert_eq!(&request[8..24], &nonce);
            assert_eq!(&request[24..], &[0; 8]);
        }
    }

    fn framed_receipt(magic: &[u8; 8], project_packet_bytes: usize) -> Vec<u8> {
        let mut receipt = magic.to_vec();
        receipt.extend_from_slice(&[7; 16]);
        receipt.extend_from_slice(&[1; PACKET_BYTES]);
        for marker in 2..=5 {
            receipt.extend_from_slice(&1_u32.to_be_bytes());
            receipt.push(marker);
        }
        receipt.extend_from_slice(&vec![6; project_packet_bytes]);
        receipt.extend_from_slice(&1_u32.to_be_bytes());
        receipt.push(7);
        receipt
    }

    #[test]
    fn receipt_framing_preserves_both_project_packet_lengths() {
        for (magic, maximum, project_bytes) in [
            (
                POLICY_HEAD_RECEIPT_MAGIC_V2,
                MAXIMUM_RECEIPT_BYTES,
                PROJECT_PACKET_BYTES,
            ),
            (
                POLICY_BINDING_RECEIPT_MAGIC_V4,
                MAXIMUM_EXPLICIT_RECEIPT_BYTES,
                EXPLICIT_PROJECT_PACKET_BYTES,
            ),
        ] {
            let receipt = framed_receipt(magic, project_bytes);
            let frame = parse_receipt_frame(&receipt, [7; 16], magic, maximum, project_bytes)
                .expect("exact frame");
            assert_eq!(frame.packet, &[1; PACKET_BYTES]);
            assert_eq!(frame.inputs, [&[2][..], &[3], &[4], &[5]]);
            assert_eq!(frame.project_packet, vec![6; project_bytes]);
            assert_eq!(frame.project_input, &[7]);
        }
    }

    #[test]
    fn receipt_framing_rejects_substitution_bounds_and_trailing_bytes() {
        for (magic, maximum, project_bytes) in [
            (
                POLICY_HEAD_RECEIPT_MAGIC_V2,
                MAXIMUM_RECEIPT_BYTES,
                PROJECT_PACKET_BYTES,
            ),
            (
                POLICY_BINDING_RECEIPT_MAGIC_V4,
                MAXIMUM_EXPLICIT_RECEIPT_BYTES,
                EXPLICIT_PROJECT_PACKET_BYTES,
            ),
        ] {
            let receipt = framed_receipt(magic, project_bytes);
            let parse = |bytes: &[u8]| {
                parse_receipt_frame(bytes, [7; 16], magic, maximum, project_bytes).is_err()
            };
            assert!(parse(&receipt[..receipt.len() - 1]));
            let mut trailing = receipt.clone();
            trailing.push(0);
            assert!(parse(&trailing));
            assert!(parse_receipt_frame(&receipt, [8; 16], magic, maximum, project_bytes).is_err());
            let mut wrong_magic = receipt.clone();
            wrong_magic[0] ^= 1;
            assert!(parse(&wrong_magic));

            let mut empty_input = receipt.clone();
            empty_input[24 + PACKET_BYTES..24 + PACKET_BYTES + 4]
                .copy_from_slice(&0_u32.to_be_bytes());
            assert!(parse(&empty_input));
            let mut oversized_input = receipt.clone();
            oversized_input[24 + PACKET_BYTES..24 + PACKET_BYTES + 4].copy_from_slice(
                &u32::try_from(MAXIMUM_INPUT_BYTES + 1)
                    .unwrap()
                    .to_be_bytes(),
            );
            assert!(parse(&oversized_input));

            let project_length_offset = receipt.len() - 5;
            let mut empty_project = receipt.clone();
            empty_project[project_length_offset..project_length_offset + 4]
                .copy_from_slice(&0_u32.to_be_bytes());
            assert!(parse(&empty_project));
            let mut oversized_project = receipt.clone();
            oversized_project[project_length_offset..project_length_offset + 4].copy_from_slice(
                &u32::try_from(MAXIMUM_PROJECT_INPUT_BYTES + 1)
                    .unwrap()
                    .to_be_bytes(),
            );
            assert!(parse(&oversized_project));

            let mut excessive = receipt.clone();
            excessive.resize(maximum + 1, 0);
            assert!(parse(&excessive));
        }
    }

    fn signed_explicit_receipt() -> (Vec<u8>, SigningKey, SigningKey, [u8; 16]) {
        let deployment_key = SigningKey::from_bytes(&[21; 32]);
        let project_key = SigningKey::from_bytes(&[22; 32]);
        let project = ProjectId::from_bytes([1; 16]);
        let nonce = [7; 16];
        let inherited = serde_json::json!({"kind": "inherit"});
        let limits = serde_json::json!({
            "accounting": vec![inherited.clone(); 22],
            "portable": vec![inherited; 16],
        });
        let inputs = [
            serde_json::to_vec(&serde_json::json!({
                "generation": 1, "input": limits.clone(), "magic": "AOSPNI01"
            }))
            .expect("node input"),
            serde_json::to_vec(&serde_json::json!({
                "generation": 1, "input": limits, "magic": "AOSPSI01"
            }))
            .expect("site input"),
            serde_json::to_vec(&serde_json::json!({
                "generation": 1, "input": {"enforcement": []}, "magic": "AOSPBI01"
            }))
            .expect("backend input"),
            serde_json::to_vec(&serde_json::json!({
                "generation": 1,
                "input": {"destinations": [], "endpoints": []},
                "magic": "AOSPCI01"
            }))
            .expect("catalog input"),
        ];
        let mut deployment = b"AOSPDH01".to_vec();
        deployment.extend_from_slice(&1_u64.to_be_bytes());
        deployment.extend_from_slice(&10_i64.to_be_bytes());
        deployment.extend_from_slice(&30_i64.to_be_bytes());
        for input in &inputs {
            deployment.extend_from_slice(&Sha256::digest(input));
        }
        let mut signed_deployment = b"aos.sandbox.policy-deployment-head.v1\0".to_vec();
        signed_deployment.extend_from_slice(&deployment);
        deployment.extend_from_slice(&deployment_key.sign(&signed_deployment).to_bytes());

        let project_input = serde_json::to_vec(&serde_json::json!({
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
        .expect("explicit project input");
        let mut project_packet = b"AOSPPH02".to_vec();
        project_packet.extend_from_slice(project.as_bytes());
        project_packet.extend_from_slice(&1_u64.to_be_bytes());
        project_packet.extend_from_slice(&10_i64.to_be_bytes());
        project_packet.extend_from_slice(&30_i64.to_be_bytes());
        project_packet.extend_from_slice(&1_u64.to_be_bytes());
        project_packet.extend_from_slice(&[4; 32]);
        project_packet.extend_from_slice(&Sha256::digest(&project_input));
        for head in [
            [5; 32],
            Sha256::digest(&deployment).into(),
            [7; 32],
            [8; 32],
        ] {
            project_packet.extend_from_slice(&head);
        }
        project_packet.extend_from_slice(&2_u64.to_be_bytes());
        project_packet.extend_from_slice(&3_u64.to_be_bytes());
        let mut signed_project = b"aos.sandbox.policy-project-head.v2\0".to_vec();
        signed_project.extend_from_slice(&project_packet);
        project_packet.extend_from_slice(&project_key.sign(&signed_project).to_bytes());

        let mut receipt = POLICY_BINDING_RECEIPT_MAGIC_V4.to_vec();
        receipt.extend_from_slice(&nonce);
        receipt.extend_from_slice(&deployment);
        for input in &inputs {
            receipt.extend_from_slice(&u32::try_from(input.len()).unwrap().to_be_bytes());
            receipt.extend_from_slice(input);
        }
        receipt.extend_from_slice(&project_packet);
        receipt.extend_from_slice(&u32::try_from(project_input.len()).unwrap().to_be_bytes());
        receipt.extend_from_slice(&project_input);
        (receipt, deployment_key, project_key, nonce)
    }

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
    fn explicit_receipt_requires_v2_signatures_nonce_and_pinned_generations() {
        let (mut bytes, deployment_key, project_key, nonce) = signed_explicit_receipt();
        let deployment_verifier = deployment_key.verifying_key();
        let project_verifier = project_key.verifying_key();
        let decoded =
            decode_explicit_receipt_v4(&bytes, nonce, &deployment_verifier, &project_verifier, 20)
                .expect("signed V2 receipt");
        assert_eq!(decoded.project().head().deployment_signer_generation(), 2);
        assert_eq!(decoded.project().head().project_signer_generation(), 3);

        let mut base = [0_u8; CLOSED_BINDING_BASE_BYTES];
        base[..8].copy_from_slice(POLICY_BINDING_BASE_MAGIC_V4);
        base[8..24].fill(1);
        base[56..64].copy_from_slice(&1_u64.to_be_bytes());
        base[64..72].copy_from_slice(&2_u64.to_be_bytes());
        base[72..80].copy_from_slice(&3_u64.to_be_bytes());
        let current = decode_closed_binding_base(&base).expect("current signer base");
        assert!(validate_receipt_signer_generations(&decoded, current).is_ok());
        base[72..80].copy_from_slice(&4_u64.to_be_bytes());
        let rotated = decode_closed_binding_base(&base).expect("rotated signer base");
        assert!(validate_receipt_signer_generations(&decoded, rotated).is_err());

        assert!(
            decode_explicit_receipt_v4(
                &bytes,
                [8; 16],
                &deployment_verifier,
                &project_verifier,
                20,
            )
            .is_err()
        );
        assert!(
            decode_explicit_receipt_v4(&bytes, nonce, &deployment_verifier, &project_verifier, 30,)
                .is_err()
        );
        bytes[..8].copy_from_slice(POLICY_HEAD_RECEIPT_MAGIC_V2);
        assert!(
            decode_explicit_receipt_v4(&bytes, nonce, &deployment_verifier, &project_verifier, 20,)
                .is_err()
        );
        bytes[..8].copy_from_slice(POLICY_BINDING_RECEIPT_MAGIC_V4);
        bytes.push(0);
        assert!(
            decode_explicit_receipt_v4(&bytes, nonce, &deployment_verifier, &project_verifier, 20,)
                .is_err()
        );
        bytes.pop();
        let project_offset = bytes
            .windows(8)
            .position(|window| window == b"AOSPPH02")
            .expect("V2 project packet");
        bytes[project_offset..project_offset + 8].copy_from_slice(b"AOSPPH01");
        assert!(
            decode_explicit_receipt_v4(&bytes, nonce, &deployment_verifier, &project_verifier, 20,)
                .is_err()
        );
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
