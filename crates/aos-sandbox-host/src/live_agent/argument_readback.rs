//! Host custody of signed Guest runtime-argument measurements.
//!
//! A retained, authenticated AOSAGE channel issues a fresh challenge. The
//! exact signed reply is verified against the fixed protected runtime peer and
//! committed to a dedicated root-owned journal before evidence is returned.
//! Cold reads are historical audit records, not authority to construct a new
//! execution specification: the Guest's later exec limit can differ.
//!
//! ```text
//! /var/lib/aos/sandbox-host/runtime-argument-readback.journal
//! HostExecution key = "runtime-argument-readback-v1/" || SHA256(request)[32]
//! value = AOSHRB01 || request-length:u16be || packet-length:u16be
//!         || canonical-request || signed-packet || SHA256(preceding-value)[32]
//! ```

use std::time::Instant;

use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::runtime_execution::{
    AuthenticatedRuntimeArgumentReadbackV1, DormantRuntimeExecutionClaimV1,
    RecoveredRuntimeArgumentChallengeV1,
};
use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_agent::{
    AgentFeatureV1, AgentRuntimeBindingV1, GuestRuntimeArgumentObservationErrorV1,
    GuestRuntimeArgumentObserveRequestV1, GuestRuntimeArgumentReadbackV1,
    verify_guest_runtime_argument_readback_v1,
};
use aos_sandbox_core::{
    ExecutionId, ExecutionRuntimeArgumentLimitV1, FeatureRef, ObjectDigest, OperationId,
};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use super::{
    HostAgentLiveErrorV1, HostAgentLiveSessionV1, agent_runtime, receive_record, send_frame,
};

const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const JOURNAL_NAME: &str = "runtime-argument-readback.journal";
const KEY_PREFIX: &[u8] = b"runtime-argument-readback-v1/";
const RECORD_MAGIC: &[u8; 8] = b"AOSHRB01";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.host.runtime-argument-readback-transaction.v1\0";
const PROFILE_NAMESPACE: &str = "aos.sandbox.runtime.linux-systemd";
const MAXIMUM_REQUEST_BYTES: usize = 512;
const MAXIMUM_PACKET_BYTES: usize = 1024;
const MAXIMUM_RECORD_BYTES: usize = 8 + 2 + 2 + MAXIMUM_REQUEST_BYTES + MAXIMUM_PACKET_BYTES + 32;

// Observations are audit evidence, not an unbounded append capability.
fn readback_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 2048,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 4096,
        maximum_transactions: 10_000,
        maximum_materialized_bytes: 16 * 1024 * 1024,
        maximum_materialized_records: 10_000,
    }
}

/// Reports an unauthenticated, stale, or uncommitted Guest argument measurement.
#[derive(Debug, thiserror::Error)]
pub enum HostRuntimeArgumentReadbackErrorV1 {
    /// The retained AOSAGE channel or protected runtime claim failed.
    #[error(transparent)]
    Live(#[from] HostAgentLiveErrorV1),
    /// The Guest request or detached signature was invalid.
    #[error(transparent)]
    Guest(#[from] GuestRuntimeArgumentObservationErrorV1),
    /// The fixed protected journal could not be opened or committed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The protected peer, profile, or stored record is not exact.
    #[error("Host runtime argument readback is not current and canonical")]
    Binding,
}

/// Holds a just-measured Guest limit after signature verification and durable custody.
///
/// This value remains nonauthorizing: a later exec child needs independent
/// stack-limit/profile continuity before its specification may use the limit.
pub struct HostRuntimeArgumentReadbackReceiptV1 {
    readback: GuestRuntimeArgumentReadbackV1,
    request_digest: ObjectDigest,
    canonical_request: Vec<u8>,
    signed_packet: Vec<u8>,
    journal_value_digest: ObjectDigest,
    journal_sequence_after_custody: u64,
}

/// Joins Host packet custody to the runtime owner's consumed one-shot challenge.
pub struct HostRuntimeArgumentReadbackCompletionV1 {
    host: HostRuntimeArgumentReadbackReceiptV1,
    protected: AuthenticatedRuntimeArgumentReadbackV1,
}

impl HostRuntimeArgumentReadbackCompletionV1 {
    /// Borrows the exact signed packet retained in the fixed Host journal.
    #[must_use]
    pub const fn host_custody(&self) -> &HostRuntimeArgumentReadbackReceiptV1 {
        &self.host
    }

    /// Borrows the independent protected owner proof required by spec production.
    #[must_use]
    pub const fn protected_readback(&self) -> &AuthenticatedRuntimeArgumentReadbackV1 {
        &self.protected
    }
}

impl HostRuntimeArgumentReadbackReceiptV1 {
    /// Borrows the signed Guest measurement for a future continuity check.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionRuntimeArgumentLimitV1 {
        self.readback.evidence()
    }

    /// Returns the exact journal key suffix of this request.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the digest of the exact signed Guest packet.
    #[must_use]
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.readback.packet_digest()
    }

    /// Borrows the exact Host challenge for independent protected verification.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    /// Borrows the exact signed Guest packet committed by the Host journal.
    #[must_use]
    pub fn signed_packet(&self) -> &[u8] {
        &self.signed_packet
    }

    /// Returns the digest of the exact canonical protected journal value.
    #[must_use]
    pub const fn journal_value_digest(&self) -> ObjectDigest {
        self.journal_value_digest
    }

    /// Returns the protected journal sequence observed after this record was present.
    #[must_use]
    pub const fn journal_sequence_after_custody(&self) -> u64 {
        self.journal_sequence_after_custody
    }
}

/// Reports a cold-verified historical packet without granting fresh exec authority.
pub struct HistoricalRuntimeArgumentReadbackV1 {
    request_digest: ObjectDigest,
    packet_digest: ObjectDigest,
}

impl HistoricalRuntimeArgumentReadbackV1 {
    /// Returns the exact signed request digest retained by the Host journal.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the exact signed reply digest retained by the Host journal.
    #[must_use]
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.packet_digest
    }
}

/// Opens the fixed protected journal of Guest runtime-argument readbacks.
pub struct HostRuntimeArgumentReadbackJournalV1 {
    journal: Journal,
}

impl HostRuntimeArgumentReadbackJournalV1 {
    /// Opens the sole root-owned Host argument readback journal.
    ///
    /// # Errors
    ///
    /// Rejects an absent or insecure protected root, lock, or journal record.
    pub fn open() -> Result<Self, HostRuntimeArgumentReadbackErrorV1> {
        let (mut journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, JOURNAL_NAME, readback_journal_limits())?;
        let authority = journal.claim_protected_authority(RecordNamespace::HostExecution)?;
        drop(authority);
        Ok(Self { journal })
    }

    /// Cold-verifies one historical signed packet against current protected peer custody.
    ///
    /// The result intentionally exposes no measured limit. A fresh retained
    /// channel must perform a new observation before execution spec production.
    ///
    /// # Errors
    ///
    /// Rejects missing, malformed, unsigned, or different-runtime records.
    pub fn read_historical(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request_digest: ObjectDigest,
    ) -> Result<Option<HistoricalRuntimeArgumentReadbackV1>, HostRuntimeArgumentReadbackErrorV1>
    {
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let Some(value) = authority.get(&record_key(request_digest))? else {
            return Ok(None);
        };
        let (request, packet) = decode_record(value)?;
        let verified = verify_record(claim, request, packet, request_digest)?;
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;

        Ok(Some(HistoricalRuntimeArgumentReadbackV1 {
            request_digest,
            packet_digest: verified.packet_digest(),
        }))
    }

    /// Recovers a prior process's challenge solely from its signed Host packet.
    ///
    /// A missing protected challenge returns `None`. A present challenge with
    /// no exact Host packet is quarantined; no new session is asked to resend it.
    /// Recovery returns only historical digests, never fresh exec evidence.
    ///
    /// # Errors
    ///
    /// Rejects stale accepted-Create/currentness, missing or altered packet
    /// custody, or a conflicting one-shot owner completion.
    pub fn recover_reopened_challenge(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        controller: &mut Journal,
        execution: ExecutionId,
        create_operation: OperationId,
        parent: &ExecutionParentResourceSourceV1,
    ) -> Result<Option<HistoricalRuntimeArgumentReadbackV1>, HostRuntimeArgumentReadbackErrorV1>
    {
        let Some(challenge) = claim
            .recover_runtime_argument_observation_v1(
                controller,
                execution,
                create_operation,
                parent,
            )
            .map_err(HostAgentLiveErrorV1::from)?
        else {
            return Ok(None);
        };
        let completion = self.recover_reopened_packet(claim, &challenge)?;
        Ok(Some(completion))
    }

    fn recover_reopened_packet(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        challenge: &RecoveredRuntimeArgumentChallengeV1,
    ) -> Result<HistoricalRuntimeArgumentReadbackV1, HostRuntimeArgumentReadbackErrorV1> {
        let request = challenge.request();
        let packet = self.load_exact_packet(claim, request)?;
        let host = self.record(claim, request, &packet)?;
        claim
            .complete_recovered_runtime_argument_observation_v1(challenge, &packet)
            .map_err(HostAgentLiveErrorV1::from)?;
        Ok(HistoricalRuntimeArgumentReadbackV1 {
            request_digest: host.request_digest(),
            packet_digest: host.packet_digest(),
        })
    }

    fn load_exact_packet(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &GuestRuntimeArgumentObserveRequestV1,
    ) -> Result<Vec<u8>, HostRuntimeArgumentReadbackErrorV1> {
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        let request_bytes = request.encode();
        let digest = ObjectDigest::from_bytes(Sha256::digest(&request_bytes).into());
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let value = authority
            .get(&record_key(digest))?
            .ok_or(HostRuntimeArgumentReadbackErrorV1::Binding)?;
        let (stored_request, stored_packet) = decode_record(value)?;
        if stored_request != request_bytes {
            return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
        }
        verify_record(claim, stored_request, stored_packet, digest)?;
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        Ok(stored_packet.to_vec())
    }

    fn record(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &GuestRuntimeArgumentObserveRequestV1,
        packet: &[u8],
    ) -> Result<HostRuntimeArgumentReadbackReceiptV1, HostRuntimeArgumentReadbackErrorV1> {
        let request_bytes = request.encode();
        let request_digest = ObjectDigest::from_bytes(Sha256::digest(&request_bytes).into());
        let readback = verify_record(claim, &request_bytes, packet, request_digest)?;
        let value = encode_record(&request_bytes, packet)?;
        let journal_value_digest = ObjectDigest::from_bytes(Sha256::digest(&value).into());
        let key = record_key(request_digest);
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        if let Some(previous) = authority.get(&key)? {
            if previous != value {
                return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
            }
        } else {
            let mut hash = Sha256::new();
            hash.update(TRANSACTION_DOMAIN);
            hash.update(request_digest.as_bytes());
            hash.update(readback.packet_digest().as_bytes());
            let transaction_id: [u8; 16] = hash.finalize()[..16]
                .try_into()
                .map_err(|_| HostRuntimeArgumentReadbackErrorV1::Binding)?;
            if transaction_id == [0; 16] {
                return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
            }
            let transaction = JournalTransaction::new(
                transaction_id,
                vec![JournalRecord::put(
                    RecordNamespace::HostExecution,
                    key,
                    value,
                )],
            )?;
            authority.commit(&transaction)?;
        }
        let journal_sequence_after_custody = authority.snapshot()?.sequence();
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;

        Ok(HostRuntimeArgumentReadbackReceiptV1 {
            readback,
            request_digest,
            canonical_request: request_bytes,
            signed_packet: packet.to_vec(),
            journal_value_digest,
            journal_sequence_after_custody,
        })
    }
}

fn join_completion(
    host: HostRuntimeArgumentReadbackReceiptV1,
    protected: AuthenticatedRuntimeArgumentReadbackV1,
    execution: ExecutionId,
    create_operation: OperationId,
) -> Result<HostRuntimeArgumentReadbackCompletionV1, HostRuntimeArgumentReadbackErrorV1> {
    if protected.execution() != execution
        || protected.create_operation() != create_operation
        || protected.request_digest() != host.request_digest()
        || protected.packet_digest() != host.packet_digest()
        || protected.evidence() != host.evidence()
    {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    Ok(HostRuntimeArgumentReadbackCompletionV1 { host, protected })
}

impl HostAgentLiveSessionV1 {
    /// Requests, verifies, and durably records a fresh Guest `ARG_MAX` reading.
    ///
    /// This dormant operation requires negotiated feature 7. The published
    /// Guest root currently lacks that feature, so production calls fail closed.
    /// The protected owner reserves the exact challenge before any socket send.
    /// Existing challenges are handled only by digest-only cold recovery,
    /// never resent. Any post-send ambiguity poisons this
    /// stop-and-wait channel rather than risking a queued reply on later use.
    ///
    /// # Errors
    ///
    /// Rejects missing feature 7, stale accepted-Create/currentness, a foreign
    /// signed session, invalid Guest signature, channel loss, deadline, or
    /// failed protected challenge/packet custody.
    pub fn observe_runtime_argument_limit(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        controller: &mut Journal,
        execution: ExecutionId,
        create_operation: OperationId,
        parent: &ExecutionParentResourceSourceV1,
        deadline: Instant,
    ) -> Result<HostRuntimeArgumentReadbackCompletionV1, HostRuntimeArgumentReadbackErrorV1> {
        if self.poisoned
            || !self
                .response
                .features()
                .contains(AgentFeatureV1::RuntimeArgumentObservation)
        {
            return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
        }
        self.validate_claim(claim)?;
        let mut journal = HostRuntimeArgumentReadbackJournalV1::open()?;
        let challenge = claim
            .begin_runtime_argument_observation_v1(
                controller,
                execution,
                create_operation,
                parent,
                &self.handshake,
                &self.response,
            )
            .map_err(HostAgentLiveErrorV1::from)?;
        let request = challenge.request();
        if challenge.handshake() != &self.handshake
            || challenge.response() != &self.response
            || request.session() != self.binding
            || request.runtime() != &agent_runtime(claim.currentness())?
            || request.channel() != claim.agent_peer().channel_binding()
            || request.profile() != &fixed_runtime_profile()?
            || request.profile_commitment() != claim.runtime_profile_commitment()
        {
            return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
        }
        if challenge.is_completed() {
            return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
        }

        self.poisoned = true;
        send_frame(&mut self.socket, &request.encode(), deadline, None)?;
        let packet = receive_record(&mut self.socket, MAXIMUM_PACKET_BYTES, deadline, None)?;
        self.validate_claim(claim)?;
        let host = journal.record(claim, request, &packet)?;
        let protected = claim
            .complete_runtime_argument_observation_v1(&challenge, &packet)
            .map_err(HostAgentLiveErrorV1::from)?;
        let completion = join_completion(host, protected, execution, create_operation)?;
        self.poisoned = false;
        Ok(completion)
    }
}

pub(super) fn fixed_runtime_profile() -> Result<FeatureRef, HostRuntimeArgumentReadbackErrorV1> {
    FeatureRef::new(PROFILE_NAMESPACE, 1, 0)
        .map_err(|_| HostRuntimeArgumentReadbackErrorV1::Binding)
}

fn record_key(digest: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + 32);
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(digest.as_bytes());
    key
}

fn verify_record(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    request_bytes: &[u8],
    packet: &[u8],
    request_digest: ObjectDigest,
) -> Result<GuestRuntimeArgumentReadbackV1, HostRuntimeArgumentReadbackErrorV1> {
    let runtime = agent_runtime(claim.currentness())?;
    let key = VerifyingKey::from_bytes(&claim.agent_peer().public_key())
        .map_err(|_| HostRuntimeArgumentReadbackErrorV1::Binding)?;
    verify_record_against_profile(
        request_bytes,
        packet,
        request_digest,
        &runtime,
        claim.agent_peer().channel_binding(),
        claim.runtime_profile_commitment(),
        &key,
    )
}

fn verify_record_against_profile(
    request_bytes: &[u8],
    packet: &[u8],
    request_digest: ObjectDigest,
    runtime: &AgentRuntimeBindingV1,
    channel: ObjectDigest,
    profile_commitment: ObjectDigest,
    key: &VerifyingKey,
) -> Result<GuestRuntimeArgumentReadbackV1, HostRuntimeArgumentReadbackErrorV1> {
    if ObjectDigest::from_bytes(Sha256::digest(request_bytes).into()) != request_digest {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    let request = GuestRuntimeArgumentObserveRequestV1::decode(request_bytes)?;
    if request.runtime() != runtime || request.channel() != channel {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    let verified = verify_guest_runtime_argument_readback_v1(packet, &request, key)?;
    if verified.evidence().runtime_profile() != &fixed_runtime_profile()?
        || verified.evidence().runtime_profile_commitment() != profile_commitment
    {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    Ok(verified)
}

fn encode_record(
    request: &[u8],
    packet: &[u8],
) -> Result<Vec<u8>, HostRuntimeArgumentReadbackErrorV1> {
    let request_length =
        u16::try_from(request.len()).map_err(|_| HostRuntimeArgumentReadbackErrorV1::Binding)?;
    let packet_length =
        u16::try_from(packet.len()).map_err(|_| HostRuntimeArgumentReadbackErrorV1::Binding)?;
    if request.len() > MAXIMUM_REQUEST_BYTES || packet.len() > MAXIMUM_PACKET_BYTES {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    let mut value = Vec::with_capacity(8 + 2 + 2 + request.len() + packet.len() + 32);
    value.extend_from_slice(RECORD_MAGIC);
    value.extend_from_slice(&request_length.to_be_bytes());
    value.extend_from_slice(&packet_length.to_be_bytes());
    value.extend_from_slice(request);
    value.extend_from_slice(packet);
    let digest = Sha256::digest(&value);
    value.extend_from_slice(&digest);
    Ok(value)
}

fn decode_record(value: &[u8]) -> Result<(&[u8], &[u8]), HostRuntimeArgumentReadbackErrorV1> {
    if value.len() < 44 || value.len() > MAXIMUM_RECORD_BYTES || value[..8] != *RECORD_MAGIC {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    let request_length = usize::from(u16::from_be_bytes([value[8], value[9]]));
    let packet_length = usize::from(u16::from_be_bytes([value[10], value[11]]));
    if request_length > MAXIMUM_REQUEST_BYTES
        || packet_length > MAXIMUM_PACKET_BYTES
        || value.len() != 12 + request_length + packet_length + 32
    {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    let digest_start = value.len() - 32;
    if Sha256::digest(&value[..digest_start]).as_slice() != &value[digest_start..] {
        return Err(HostRuntimeArgumentReadbackErrorV1::Binding);
    }
    Ok((
        &value[12..12 + request_length],
        &value[12 + request_length..digest_start],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_agent::AgentSessionBindingV1;
    use aos_sandbox_agent::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1;
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, SandboxId,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signed_fixture() -> (Vec<u8>, Vec<u8>, AgentRuntimeBindingV1, VerifyingKey) {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
            DesiredGeneration::new(5),
            NamespaceGeneration::new(6),
            [7; 16],
        )
        .unwrap();
        let request = GuestRuntimeArgumentObserveRequestV1::new(
            runtime.clone(),
            AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([8; 32])).unwrap(),
            ObjectDigest::from_bytes([9; 32]),
            [10; 32],
            fixed_runtime_profile().unwrap(),
            ObjectDigest::from_bytes([11; 32]),
        )
        .unwrap()
        .encode();
        let mut packet = Vec::new();
        packet.extend_from_slice(b"AOSARP01");
        packet.extend_from_slice(&u16::try_from(request.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&request);
        packet.extend_from_slice(&131_072_u64.to_be_bytes());
        let signer = SigningKey::from_bytes(&[12; 32]);
        let mut message = b"aos.sandbox.guest-argument-readback.v1\0".to_vec();
        message.extend_from_slice(&packet);
        packet.extend_from_slice(&signer.sign(&message).to_bytes());
        (request, packet, runtime, signer.verifying_key())
    }

    #[test]
    fn fixed_profile_is_registered_and_not_caller_selected() {
        let profile = fixed_runtime_profile().unwrap();
        assert_eq!(profile.namespace(), PROFILE_NAMESPACE);
        assert_eq!(profile.major(), 1);
        assert_eq!(profile.minor(), 0);
        let feature_bit = 1_u16 << (AgentFeatureV1::RuntimeArgumentObservation as u8 - 1);
        assert_eq!(CONCRETE_GUEST_FEATURE_MASK_V1 & feature_bit, 0);
    }

    #[test]
    fn journal_record_rejects_length_and_digest_tampering() {
        let request = b"exact-request";
        let packet = b"signed-packet";
        let value = encode_record(request, packet).unwrap();
        assert_eq!(
            decode_record(&value).unwrap(),
            (request.as_slice(), packet.as_slice())
        );

        let mut changed_length = value.clone();
        changed_length[9] += 1;
        assert!(decode_record(&changed_length).is_err());

        let mut changed_packet = value;
        changed_packet[12 + request.len()] ^= 1;
        assert!(decode_record(&changed_packet).is_err());
    }

    #[test]
    fn signed_receipt_requires_exact_runtime_channel_profile_and_peer_key() {
        let (request, packet, runtime, key) = signed_fixture();
        let digest = ObjectDigest::from_bytes(Sha256::digest(&request).into());
        let channel = ObjectDigest::from_bytes([9; 32]);
        let profile = ObjectDigest::from_bytes([11; 32]);

        let verified = verify_record_against_profile(
            &request, &packet, digest, &runtime, channel, profile, &key,
        )
        .unwrap();
        assert_eq!(verified.evidence().runtime_limit_bytes(), 131_072);
        let changed_runtime = AgentRuntimeBindingV1::new(
            runtime.sandbox(),
            runtime.incarnation(),
            runtime.assignment_epoch(),
            runtime.assignment_digest(),
            runtime.desired_generation(),
            runtime.namespace_generation(),
            [16; 16],
        )
        .unwrap();
        assert!(
            verify_record_against_profile(
                &request,
                &packet,
                digest,
                &changed_runtime,
                channel,
                profile,
                &key,
            )
            .is_err()
        );
        assert!(
            verify_record_against_profile(
                &request,
                &packet,
                ObjectDigest::from_bytes([17; 32]),
                &runtime,
                channel,
                profile,
                &key,
            )
            .is_err()
        );
        assert!(
            verify_record_against_profile(
                &request,
                &packet,
                digest,
                &runtime,
                ObjectDigest::from_bytes([13; 32]),
                profile,
                &key,
            )
            .is_err()
        );
        assert!(
            verify_record_against_profile(
                &request,
                &packet,
                digest,
                &runtime,
                channel,
                ObjectDigest::from_bytes([14; 32]),
                &key,
            )
            .is_err()
        );
        assert!(
            verify_record_against_profile(
                &request,
                &packet,
                digest,
                &runtime,
                channel,
                profile,
                &SigningKey::from_bytes(&[15; 32]).verifying_key(),
            )
            .is_err()
        );
    }
}
