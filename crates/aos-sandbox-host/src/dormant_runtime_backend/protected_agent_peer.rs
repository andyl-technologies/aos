//! Protected-journal loader for dormant Host-to-agent peer currentness.
//!
//! The loader has no caller-scalar constructor. It claims the
//! existing protected Host namespace, reads its singular current peer record,
//! validates the record's canonical digest and Ed25519 key, reconstructs exact
//! core and agent runtime bindings, and is the only module that calls the
//! crate-private peer constructor.
//!
//! ```text
//! AOSHPE01 || peer_key[32] || sandbox[16] || incarnation[16] || node[16]
//! || assignment_epoch:u64be || assignment_digest[32]
//! || desired_generation:u64be || namespace_generation:u64be
//! || plan_commitment[32] || runtime_handle[32] || payload_boot_id[16]
//! || channel_binding[32] || next_observation_sequence:u64be
//! || record_digest[32]
//! ```

use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction,
    ProtectedJournalAuthority, RecordNamespace,
};
use aos_sandbox_agent::{AgentHandshakeRequestV1, AgentRuntimeBindingV1};
use aos_sandbox_core::runtime_backend::{RuntimeCurrentnessV1, RuntimeHandleCommitmentV1};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    ObservationSequence, SandboxId,
};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use super::agent_session::{DormantAgentPeerV1, DormantPendingAgentHandshakeV1};

const PEER_CURRENT_KEY: &[u8] = b"dormant-agent-peer-current-v1";
const PEER_RECORD_MAGIC: &[u8; 8] = b"AOSHPE01";
const PEER_RECORD_BYTES: usize = 296;
const PEER_RECORD_DIGEST_OFFSET: usize = PEER_RECORD_BYTES - 32;
const AUTHORITY_DOMAIN: &[u8] = b"aos.sandbox.host.agent-peer-authority.v1\0";
const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const PEER_JOURNAL_NAME: &str = "runtime-agent-peer.journal";

/// Owns the fixed protected Host peer journal without accepting caller paths.
pub struct DormantHostAgentPeerOwnerV1 {
    journal: Journal,
}

impl DormantHostAgentPeerOwnerV1 {
    /// Opens the fixed root-owned Host runtime-agent peer journal.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedAgentPeerErrorV1`] when fixed-root protected
    /// resolution, exclusive ownership, or replay fails.
    pub fn open() -> Result<Self, DormantProtectedAgentPeerErrorV1> {
        let (journal, _) = Journal::open_protected_at(
            HOST_STATE_ROOT,
            PEER_JOURNAL_NAME,
            JournalLimits::default(),
        )?;
        Ok(Self { journal })
    }

    /// Claims the current authenticated peer while retaining journal ownership.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedAgentPeerErrorV1`] when the singular current
    /// peer is absent, malformed, stale, or unavailable.
    pub fn claim_peer(
        &mut self,
    ) -> Result<DormantHostAgentPeerClaimV1<'_>, DormantProtectedAgentPeerErrorV1> {
        resolve_dormant_agent_peer_v1(&mut self.journal)
            .map(|lease| DormantHostAgentPeerClaimV1 { lease })
    }
}

/// Retains one fixed-root protected peer claim through handshake creation.
pub struct DormantHostAgentPeerClaimV1<'owner> {
    lease: DormantProtectedAgentPeerLeaseV1<'owner>,
}

impl<'owner> DormantHostAgentPeerClaimV1<'owner> {
    /// Returns the exact evidence authority required by runtime admission.
    #[must_use]
    pub fn evidence_authority_binding(&self) -> ObjectDigest {
        self.lease.evidence_authority_binding()
    }

    /// Consumes the claim into a protected-current pending handshake.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedAgentPeerErrorV1`] when protected currentness
    /// changed or the request differs from the fixed-root peer record.
    pub fn begin_handshake(
        self,
        request: AgentHandshakeRequestV1,
    ) -> Result<DormantPendingAgentHandshakeV1<'owner>, DormantProtectedAgentPeerErrorV1> {
        self.lease.begin_handshake(request)
    }
}

/// Resolves the sole current dormant agent peer from protected Host state.
///
/// Only [`DormantHostAgentPeerOwnerV1`] calls this raw resolver. Fixed-root
/// journal provenance and the canonical current record mint the returned
/// lease, rather than any caller-provided identity scalar.
///
/// # Errors
///
/// Returns [`DormantProtectedAgentPeerErrorV1`] when protected state is
/// unavailable, the current record is absent or noncanonical, the peer key is
/// malformed, or the stored runtime bindings disagree.
pub(crate) fn resolve_dormant_agent_peer_v1(
    journal: &mut Journal,
) -> Result<DormantProtectedAgentPeerLeaseV1<'_>, DormantProtectedAgentPeerErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::HostExecution)?;
    let protected_sequence = authority.snapshot()?.sequence();
    let bytes = authority
        .get(PEER_CURRENT_KEY)?
        .ok_or(DormantProtectedAgentPeerErrorV1::Missing)?;
    let decoded = decode_peer_record(bytes)?;
    VerifyingKey::from_bytes(&decoded.public_key)
        .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)?;

    let currentness = RuntimeCurrentnessV1::new(
        decoded.sandbox,
        decoded.incarnation,
        decoded.node,
        decoded.assignment_epoch,
        decoded.assignment_digest,
        decoded.desired_generation,
        decoded.namespace_generation,
    )
    .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)?;
    let runtime = RuntimeHandleCommitmentV1::new(
        currentness,
        decoded.plan_commitment,
        decoded.runtime_handle,
    )
    .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)?;
    let agent_runtime = AgentRuntimeBindingV1::new(
        decoded.sandbox,
        decoded.incarnation,
        decoded.assignment_epoch,
        decoded.assignment_digest,
        decoded.desired_generation,
        decoded.namespace_generation,
        decoded.payload_boot_id,
    )
    .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)?;
    let protected_authority_binding = protected_authority_binding(
        protected_sequence,
        decoded.record_digest,
        decoded.public_key,
        decoded.runtime_handle,
        decoded.channel_binding,
    );

    let peer = DormantAgentPeerV1::new(
        decoded.public_key,
        runtime,
        agent_runtime,
        decoded.channel_binding,
        decoded.next_observation_sequence,
        protected_authority_binding,
    )
    .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)?;
    let record = bytes.to_vec();

    Ok(DormantProtectedAgentPeerLeaseV1 {
        authority,
        protected_sequence,
        record,
        peer,
        closed: false,
    })
}

/// Retains exclusive protected-current ownership for a Host/agent session.
///
/// The lease keeps the protected journal borrowed from cold resolution through
/// handshake, dispatch, outcome acceptance, and explicit supersession.
pub(crate) struct DormantProtectedAgentPeerLeaseV1<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
    protected_sequence: u64,
    record: Vec<u8>,
    peer: DormantAgentPeerV1,
    closed: bool,
}

impl<'journal> DormantProtectedAgentPeerLeaseV1<'journal> {
    /// Returns the evidence-authority binding required by runtime admission.
    #[must_use]
    pub(crate) fn evidence_authority_binding(&self) -> ObjectDigest {
        backend_authority_binding(&self.peer, self.evidence_trust_context())
    }

    /// Consumes the protected owner into a pending authenticated handshake.
    ///
    /// # Errors
    ///
    /// Returns [`DormantProtectedAgentPeerErrorV1`] if protected currentness
    /// changed or the request differs from the resolved runtime/channel.
    pub(crate) fn begin_handshake(
        self,
        request: AgentHandshakeRequestV1,
    ) -> Result<DormantPendingAgentHandshakeV1<'journal>, DormantProtectedAgentPeerErrorV1> {
        self.validate_current()?;
        DormantPendingAgentHandshakeV1::from_protected_lease(self, request)
            .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)
    }

    pub(super) fn peer(&self) -> &DormantAgentPeerV1 {
        &self.peer
    }

    pub(super) fn evidence_trust_context(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.host.agent-peer-evidence-trust.v1\0");
        digest.update(self.peer.runtime.handle().as_bytes());
        digest.update(self.peer.protected_authority_binding().as_bytes());
        ObjectDigest::from_bytes(digest.finalize().into())
    }

    pub(super) fn validate_current(&self) -> Result<(), DormantProtectedAgentPeerErrorV1> {
        if self.closed
            || self.authority.snapshot()?.sequence() != self.protected_sequence
            || self.authority.get(PEER_CURRENT_KEY)? != Some(self.record.as_slice())
        {
            return Err(DormantProtectedAgentPeerErrorV1::Stale);
        }
        Ok(())
    }

    pub(super) fn close(&mut self) {
        self.closed = true;
    }

    /// Durably revokes the exact current record before closing the lease.
    ///
    /// A failed append poisons protected authority, so a possibly committed
    /// revocation can only be resolved by cold reopening the journal.
    pub(super) fn revoke_current(&mut self) -> Result<(), DormantProtectedAgentPeerErrorV1> {
        self.validate_current()?;
        let transaction = JournalTransaction::new(
            revocation_transaction_id(self.protected_sequence, &self.record),
            vec![JournalRecord::delete(
                RecordNamespace::HostExecution,
                PEER_CURRENT_KEY.to_vec(),
            )],
        )?;
        let preflight = self
            .authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        let result = self.authority.commit(&transaction);
        self.closed = true;
        result.map(|_| ()).map_err(Into::into)
    }
}

fn backend_authority_binding(
    peer: &DormantAgentPeerV1,
    evidence_trust_context: ObjectDigest,
) -> ObjectDigest {
    aos_sandbox_core::runtime_backend::backend_evidence_authority_binding_v1(
        peer.public_key(),
        evidence_trust_context,
        peer.channel_binding(),
    )
}

struct DecodedPeerRecordV1 {
    public_key: [u8; 32],
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    assignment_epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    namespace_generation: NamespaceGeneration,
    plan_commitment: ObjectDigest,
    runtime_handle: ObjectDigest,
    payload_boot_id: [u8; 16],
    channel_binding: ObjectDigest,
    next_observation_sequence: ObservationSequence,
    record_digest: ObjectDigest,
}

fn decode_peer_record(
    bytes: &[u8],
) -> Result<DecodedPeerRecordV1, DormantProtectedAgentPeerErrorV1> {
    if bytes.len() != PEER_RECORD_BYTES || bytes.get(..8) != Some(PEER_RECORD_MAGIC.as_slice()) {
        return Err(DormantProtectedAgentPeerErrorV1::Malformed);
    }
    let record_digest = digest(
        bytes
            .get(..PEER_RECORD_DIGEST_OFFSET)
            .ok_or(DormantProtectedAgentPeerErrorV1::Malformed)?,
    );
    if bytes.get(PEER_RECORD_DIGEST_OFFSET..) != Some(record_digest.as_bytes().as_slice()) {
        return Err(DormantProtectedAgentPeerErrorV1::Malformed);
    }

    Ok(DecodedPeerRecordV1 {
        public_key: read_array(bytes, 8)?,
        sandbox: SandboxId::from_bytes(read_array(bytes, 40)?),
        incarnation: IncarnationId::from_bytes(read_array(bytes, 56)?),
        node: NodeId::from_bytes(read_array(bytes, 72)?),
        assignment_epoch: AssignmentEpoch::new(read_u64(bytes, 88)?),
        assignment_digest: ObjectDigest::from_bytes(read_array(bytes, 96)?),
        desired_generation: DesiredGeneration::new(read_u64(bytes, 128)?),
        namespace_generation: NamespaceGeneration::new(read_u64(bytes, 136)?),
        plan_commitment: ObjectDigest::from_bytes(read_array(bytes, 144)?),
        runtime_handle: ObjectDigest::from_bytes(read_array(bytes, 176)?),
        payload_boot_id: read_array(bytes, 208)?,
        channel_binding: ObjectDigest::from_bytes(read_array(bytes, 224)?),
        next_observation_sequence: ObservationSequence::new(read_u64(bytes, 256)?),
        record_digest,
    })
}

fn protected_authority_binding(
    protected_sequence: u64,
    record_digest: ObjectDigest,
    public_key: [u8; 32],
    runtime_handle: ObjectDigest,
    channel_binding: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_DOMAIN);
    digest.update(protected_sequence.to_be_bytes());
    digest.update(record_digest.as_bytes());
    digest.update(public_key);
    digest.update(runtime_handle.as_bytes());
    digest.update(channel_binding.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DormantProtectedAgentPeerErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], DormantProtectedAgentPeerErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(DormantProtectedAgentPeerErrorV1::Malformed)?;
    bytes
        .get(offset..end)
        .ok_or(DormantProtectedAgentPeerErrorV1::Malformed)?
        .try_into()
        .map_err(|_| DormantProtectedAgentPeerErrorV1::Malformed)
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn revocation_transaction_id(protected_sequence: u64, record: &[u8]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.agent-peer-revocation.v1\0");
    digest.update(protected_sequence.to_be_bytes());
    digest.update(record);
    let full: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&full[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

/// Reports a fail-closed dormant protected peer resolution failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantProtectedAgentPeerErrorV1 {
    /// The protected journal rejected access or authenticated replay.
    #[error("dormant Host agent peer journal failed: {0}")]
    Journal(#[from] JournalError),
    /// The singular protected current peer record is absent.
    #[error("dormant Host agent peer record is missing")]
    Missing,
    /// The protected current peer record is noncanonical or invalid.
    #[error("dormant Host agent peer record is malformed")]
    Malformed,
    /// The protected journal head or singular current record changed.
    #[error("dormant Host agent peer currentness is stale or closed")]
    Stale,
}
