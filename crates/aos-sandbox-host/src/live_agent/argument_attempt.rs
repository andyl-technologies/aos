//! Protected one-shot Host custody for Controller method-37 Guest observations.
//!
//! The exact AOSCIA02 source and signed-plan digests are committed before any
//! Guest send. Reopening an existing execution never mints or resends a nonce.
//! Method-38 reads only a historical AOSHQR01 digest result. A committed
//! packet can form AOSHAR01 only in the original retained live session after
//! fixed-key signature verification and protected currentness revalidation.
//!
//! ```text
//! /var/lib/aos/sandbox-host/runtime-argument-attempt.journal
//! key = "argument-attempt-v1/" || execution[16]
//! AOSHAA01 || phase:u8 || AOSCIA02[336] || signed-plan[32]
//!          || semantic-request[32] || runtime-handle[32]
//!          || original-append-sequence:u64be
//!          || request-length:u16be || packet-length:u16be
//!          || exact-Guest-request || exact-signed-Guest-packet
//!          || SHA256(domain || preceding)[32]
//! ```

use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, ProtectedHostOutputReservationV1,
};
use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_agent::{
    AgentFeatureV1, GuestRuntimeArgumentObservationErrorV1, GuestRuntimeArgumentObserveRequestV1,
    GuestRuntimeArgumentReadbackV1, verify_guest_runtime_argument_readback_v1,
};
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_protocol::host_execution_argument::receipt::{
    HistoricalHostArgumentStatusV1, HostExecutionArgumentFreshReceiptV1,
    HostExecutionArgumentHistoricalReceiptV1, HostExecutionArgumentReceiptErrorV1,
};
use ed25519_dalek::VerifyingKey;
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};
use std::time::Instant;

use super::{
    HostAgentLiveErrorV1, HostAgentLiveSessionV1, agent_runtime, receive_record, send_frame,
};

const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const JOURNAL_NAME: &str = "runtime-argument-attempt.journal";
const KEY_PREFIX: &[u8] = b"argument-attempt-v1/";
const RECORD_MAGIC: &[u8; 8] = b"AOSHAA01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.host-argument-attempt-record.v1\0";
const BEGIN_DOMAIN: &[u8] = b"aos.sandbox.host-argument-attempt-begin.v1\0";
const COMPLETE_DOMAIN: &[u8] = b"aos.sandbox.host-argument-attempt-complete.v1\0";
const MAXIMUM_REQUEST_BYTES: usize = 512;
const MAXIMUM_PACKET_BYTES: usize = 1024;
const MINIMUM_RECORD_BYTES: usize = 8 + 1 + 336 + 32 + 32 + 32 + 8 + 2 + 2 + 32;
const MAXIMUM_RECORD_BYTES: usize =
    8 + 1 + 336 + 32 + 32 + 32 + 8 + 2 + 2 + MAXIMUM_REQUEST_BYTES + MAXIMUM_PACKET_BYTES + 32;

/// Reports a stale, ambiguous, or non-one-shot Host argument observation.
#[derive(Debug, thiserror::Error)]
pub enum HostArgumentAttemptErrorV1 {
    /// The source, current Host owners, retained session, or packet differs.
    #[error("Host argument observation is not current or canonical")]
    Binding,
    /// An execution already has an original challenge, including after crash.
    #[error("Host argument observation already has a one-shot attempt")]
    AlreadyAttempted,
    /// The protected append may have committed; only cold query is safe.
    #[error("Host argument observation outcome is unknown; cold query required")]
    OutcomeUnknown,
    /// The Guest channel failed or is poisoned.
    #[error(transparent)]
    Live(#[from] HostAgentLiveErrorV1),
    /// The Guest request or signature is invalid.
    #[error(transparent)]
    Guest(#[from] GuestRuntimeArgumentObservationErrorV1),
    /// The fixed protected Host journal cannot be opened or read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The bounded Host receipt cannot be encoded.
    #[error(transparent)]
    Receipt(#[from] HostExecutionArgumentReceiptErrorV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptPhase {
    Pending = 1,
    Complete = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostArgumentAttemptRecordV1 {
    phase: AttemptPhase,
    source: ControllerExecutionArgumentAttemptV1,
    plan_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    runtime_handle: ObjectDigest,
    custody_sequence: u64,
    canonical_request: Vec<u8>,
    signed_packet: Vec<u8>,
}

impl HostArgumentAttemptRecordV1 {
    fn encode(&self) -> Result<Vec<u8>, HostArgumentAttemptErrorV1> {
        if !self.is_consistent() {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let mut bytes = Vec::with_capacity(MAXIMUM_RECORD_BYTES);
        bytes.extend_from_slice(RECORD_MAGIC);
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(&self.source.canonical_bytes());
        bytes.extend_from_slice(self.plan_digest.as_bytes());
        bytes.extend_from_slice(self.semantic_digest.as_bytes());
        bytes.extend_from_slice(self.runtime_handle.as_bytes());
        bytes.extend_from_slice(&self.custody_sequence.to_be_bytes());
        bytes.extend_from_slice(&(self.canonical_request.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.signed_packet.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.canonical_request);
        bytes.extend_from_slice(&self.signed_packet);
        bytes.extend_from_slice(&record_digest(&bytes));
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, HostArgumentAttemptErrorV1> {
        if bytes.len() < MINIMUM_RECORD_BYTES
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes.get(..8) != Some(RECORD_MAGIC.as_slice())
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let mut cursor = &bytes[8..];
        let phase = match take::<1>(&mut cursor)?[0] {
            1 => AttemptPhase::Pending,
            2 => AttemptPhase::Complete,
            _ => return Err(HostArgumentAttemptErrorV1::Binding),
        };
        let source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(&take::<336>(&mut cursor)?)
                .map_err(|_| HostArgumentAttemptErrorV1::Binding)?;
        let plan_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let semantic_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let runtime_handle = ObjectDigest::from_bytes(take(&mut cursor)?);
        let custody_sequence = u64::from_be_bytes(take(&mut cursor)?);
        let request_length = usize::from(u16::from_be_bytes(take(&mut cursor)?));
        let packet_length = usize::from(u16::from_be_bytes(take(&mut cursor)?));
        if request_length > MAXIMUM_REQUEST_BYTES
            || packet_length > MAXIMUM_PACKET_BYTES
            || cursor.len() != request_length + packet_length + 32
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let canonical_request = take_slice(&mut cursor, request_length)?.to_vec();
        let signed_packet = take_slice(&mut cursor, packet_length)?.to_vec();
        let checksum = take::<32>(&mut cursor)?;
        if !cursor.is_empty() || checksum != record_digest(&bytes[..bytes.len() - 32]) {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let record = Self {
            phase,
            source,
            plan_digest,
            semantic_digest,
            runtime_handle,
            custody_sequence,
            canonical_request,
            signed_packet,
        };
        if !record.is_consistent() || record.encode()? != bytes {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        Ok(record)
    }

    fn is_consistent(&self) -> bool {
        let Ok(request) = GuestRuntimeArgumentObserveRequestV1::decode(&self.canonical_request)
        else {
            return false;
        };
        self.plan_digest.as_bytes() != &[0; 32]
            && self.semantic_digest.as_bytes() != &[0; 32]
            && self.runtime_handle.as_bytes() != &[0; 32]
            && self.custody_sequence != 0
            && self.canonical_request.len() <= MAXIMUM_REQUEST_BYTES
            && self.signed_packet.len() <= MAXIMUM_PACKET_BYTES
            && self.source.assignment_digest() == request.runtime().assignment_digest()
            && match self.phase {
                AttemptPhase::Pending => self.signed_packet.is_empty(),
                AttemptPhase::Complete => {
                    packet_limit(&self.signed_packet, &self.canonical_request).is_some()
                }
            }
    }
}

/// Owns the protected Host journal for original Guest observation attempts.
pub(crate) struct HostArgumentAttemptJournalV1 {
    journal: Journal,
    instance: [u8; 16],
}

/// Proves this process committed the original pre-send attempt.
///
/// Cold recovery cannot reconstruct or clone this token.
struct FreshPendingHostArgumentAttemptV1 {
    record: HostArgumentAttemptRecordV1,
    journal_instance: [u8; 16],
}

impl HostArgumentAttemptJournalV1 {
    /// Opens the fixed root-owned Host attempt journal.
    ///
    /// # Errors
    ///
    /// Rejects an insecure or corrupt protected journal.
    pub(crate) fn open() -> Result<Self, HostArgumentAttemptErrorV1> {
        let (mut journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, JOURNAL_NAME, journal_limits())?;
        let authority = journal.claim_protected_authority(RecordNamespace::HostExecution)?;
        drop(authority);
        let mut instance = [0; 16];
        OsRng
            .try_fill_bytes(&mut instance)
            .map_err(|_| HostAgentLiveErrorV1::Entropy)?;
        if instance == [0; 16] {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        Ok(Self { journal, instance })
    }

    fn begin(
        &mut self,
        record: &HostArgumentAttemptRecordV1,
    ) -> Result<FreshPendingHostArgumentAttemptV1, HostArgumentAttemptErrorV1> {
        if record.phase != AttemptPhase::Pending {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let key = record_key(record.source.execution());
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        if authority.get(&key)?.is_some() {
            return Err(HostArgumentAttemptErrorV1::AlreadyAttempted);
        }
        // A one-record journal transaction has begin, record, and commit
        // frames. Retain the commit frame sequence in the protected value so
        // a later unrelated transaction cannot rewrite historical custody.
        let sequence = authority
            .snapshot()?
            .sequence()
            .checked_add(2)
            .ok_or(HostArgumentAttemptErrorV1::Binding)?;
        let record = HostArgumentAttemptRecordV1 {
            custody_sequence: sequence,
            ..record.clone()
        };
        let value = record.encode()?;
        let transaction = JournalTransaction::new(
            transaction_id(BEGIN_DOMAIN, record.source.record_digest()),
            vec![JournalRecord::put(
                RecordNamespace::HostExecution,
                key.clone(),
                value.clone(),
            )],
        )?;
        let committed = authority
            .commit(&transaction)
            .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        if committed.commit_sequence != sequence
            || authority
                .get(&key)
                .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?
                != Some(value.as_slice())
        {
            return Err(HostArgumentAttemptErrorV1::OutcomeUnknown);
        }
        Ok(FreshPendingHostArgumentAttemptV1 {
            record,
            journal_instance: self.instance,
        })
    }

    fn complete(
        &mut self,
        pending: FreshPendingHostArgumentAttemptV1,
        packet: &[u8],
    ) -> Result<(ObjectDigest, u64), HostArgumentAttemptErrorV1> {
        if pending.journal_instance != self.instance {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let pending = pending.record;
        let key = record_key(pending.source.execution());
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        if authority.get(&key)? != Some(pending.encode()?.as_slice()) {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let sequence = authority
            .snapshot()?
            .sequence()
            .checked_add(2)
            .ok_or(HostArgumentAttemptErrorV1::Binding)?;
        let completed = HostArgumentAttemptRecordV1 {
            phase: AttemptPhase::Complete,
            custody_sequence: sequence,
            signed_packet: packet.to_vec(),
            ..pending.clone()
        };
        let value = completed.encode()?;
        let value_digest = ObjectDigest::from_bytes(Sha256::digest(&value).into());
        let transaction = JournalTransaction::new(
            transaction_id(COMPLETE_DOMAIN, pending.source.record_digest()),
            vec![JournalRecord::put(
                RecordNamespace::HostExecution,
                key.clone(),
                value.clone(),
            )],
        )?;
        let committed = authority
            .commit(&transaction)
            .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        if committed.commit_sequence != sequence
            || authority
                .get(&key)
                .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?
                != Some(value.as_slice())
        {
            return Err(HostArgumentAttemptErrorV1::OutcomeUnknown);
        }
        Ok((value_digest, sequence))
    }

    /// Reads an original attempt without minting a nonce or returning fresh evidence.
    ///
    /// # Errors
    ///
    /// Rejects a foreign original attempt, corrupt Host custody, or protected
    /// readback failure. A pending result is quarantine, never permission to resend.
    pub(crate) fn query_historical(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<HostExecutionArgumentHistoricalReceiptV1, HostArgumentAttemptErrorV1> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let Some(value) = authority.get(&record_key(source.execution()))? else {
            return Ok(HostExecutionArgumentHistoricalReceiptV1::new(
                source.canonical_bytes(),
                HistoricalHostArgumentStatusV1::Absent,
                ObjectDigest::from_bytes([0; 32]),
                ObjectDigest::from_bytes([0; 32]),
                ObjectDigest::from_bytes([0; 32]),
                0,
            )?);
        };
        let record = HostArgumentAttemptRecordV1::decode(value)?;
        if record.source != *source {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let packet_digest = if record.phase == AttemptPhase::Complete {
            ObjectDigest::from_bytes(Sha256::digest(&record.signed_packet).into())
        } else {
            ObjectDigest::from_bytes([0; 32])
        };
        let status = if record.phase == AttemptPhase::Complete {
            HistoricalHostArgumentStatusV1::Complete
        } else {
            HistoricalHostArgumentStatusV1::Pending
        };
        Ok(HostExecutionArgumentHistoricalReceiptV1::new(
            source.canonical_bytes(),
            status,
            ObjectDigest::from_bytes(Sha256::digest(&record.canonical_request).into()),
            packet_digest,
            ObjectDigest::from_bytes(Sha256::digest(value).into()),
            record.custody_sequence,
        )?)
    }
}

impl HostAgentLiveSessionV1 {
    /// Performs the original Host-owned one-shot Guest argument observation.
    ///
    /// This internal operation is deliberately not broker-dispatched yet. Its
    /// caller must hold a pinned signed method-37 grant that matches `source`,
    /// `plan_digest`, and `semantic_digest`; the production hello excludes 37.
    /// The Host AOSEOR02/AOSHOP01 pair and retained agent are checked here.
    ///
    /// # Errors
    ///
    /// Rejects missing feature 7, stale Host owner/output, a repeated attempt,
    /// bad Guest signature, ambiguous journal custody, or channel failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_execution_argument_once<F>(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        source: &ControllerExecutionArgumentAttemptV1,
        plan_digest: ObjectDigest,
        semantic_digest: ObjectDigest,
        mut trusted_clock: F,
        deadline: Instant,
    ) -> Result<HostExecutionArgumentFreshReceiptV1, HostArgumentAttemptErrorV1>
    where
        F: FnMut() -> Result<RawPairedClockSample, HostArgumentAttemptErrorV1>,
    {
        if self.poisoned
            || !self
                .response
                .features()
                .contains(AgentFeatureV1::RuntimeArgumentObservation)
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        self.validate_claim(claim)?;
        if claim
            .has_unsettled_host_agent_route()
            .map_err(HostAgentLiveErrorV1::from)?
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let output = claim
            .host_output_for_argument_v1(source)
            .map_err(HostAgentLiveErrorV1::from)?;
        validate_source(claim, source, output, trusted_clock()?)?;
        let mut journal = HostArgumentAttemptJournalV1::open()?;
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| HostAgentLiveErrorV1::Entropy)?;
        let request = GuestRuntimeArgumentObserveRequestV1::new(
            agent_runtime(claim.currentness())?,
            self.binding,
            claim.agent_peer().channel_binding(),
            nonce,
            super::argument_readback::fixed_runtime_profile()
                .map_err(|_| HostArgumentAttemptErrorV1::Binding)?,
            claim.runtime_profile_commitment(),
        )?;
        let pending = HostArgumentAttemptRecordV1 {
            phase: AttemptPhase::Pending,
            source: source.clone(),
            plan_digest,
            semantic_digest,
            runtime_handle: claim.currentness().runtime().handle(),
            custody_sequence: 1,
            canonical_request: request.encode(),
            signed_packet: Vec::new(),
        };
        let fresh_attempt = journal.begin(&pending)?;

        // From this point a reply may be queued even if the call returns an
        // error. Never reuse this stop-and-wait session after ambiguity.
        self.poisoned = true;
        send_frame(
            &mut self.socket,
            &pending.canonical_request,
            deadline,
            Some(source.deadline_boottime_nanoseconds()),
        )?;
        let packet = receive_record(
            &mut self.socket,
            MAXIMUM_PACKET_BYTES,
            deadline,
            Some(source.deadline_boottime_nanoseconds()),
        )?;
        self.validate_claim(claim)?;
        let verified = verify_packet(claim, &request, &packet)?;
        let (custody_digest, custody_sequence) = journal.complete(fresh_attempt, &packet)?;
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        let output = claim
            .host_output_for_argument_v1(source)
            .map_err(HostAgentLiveErrorV1::from)?;
        validate_source(claim, source, output, trusted_clock()?)?;
        let fresh = HostExecutionArgumentFreshReceiptV1::new(
            source.canonical_bytes(),
            pending.runtime_handle,
            custody_digest,
            custody_sequence,
            &request,
            &packet,
            &verified,
        )?;
        self.poisoned = false;
        Ok(fresh)
    }
}

fn validate_source(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    source: &ControllerExecutionArgumentAttemptV1,
    output: ProtectedHostOutputReservationV1,
    clock: RawPairedClockSample,
) -> Result<(), HostArgumentAttemptErrorV1> {
    let runtime = claim.currentness().runtime().currentness();
    if source.assignment_digest() != runtime.assignment_digest()
        || source.host_boot_id() != claim.host_verifier().boot_id()
        || clock.host_boot_id() != source.host_boot_id()
        || clock.boottime_nanoseconds() >= source.deadline_boottime_nanoseconds()
        || output.execution() != source.execution()
        || output.create_operation() != source.create_operation()
        || output.claim_digest() != source.output_claim_digest()
        || output.correlation_digest() != source.host_correlation_digest()
    {
        return Err(HostArgumentAttemptErrorV1::Binding);
    }
    Ok(())
}

fn verify_packet(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    request: &GuestRuntimeArgumentObserveRequestV1,
    packet: &[u8],
) -> Result<GuestRuntimeArgumentReadbackV1, HostArgumentAttemptErrorV1> {
    let key = VerifyingKey::from_bytes(&claim.agent_peer().public_key())
        .map_err(|_| HostArgumentAttemptErrorV1::Binding)?;
    let verified = verify_guest_runtime_argument_readback_v1(packet, request, &key)?;
    if verified.evidence().runtime_profile() != request.profile()
        || verified.evidence().runtime_profile_commitment() != claim.runtime_profile_commitment()
    {
        return Err(HostArgumentAttemptErrorV1::Binding);
    }
    Ok(verified)
}

fn journal_limits() -> JournalLimits {
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

fn record_key(execution: aos_sandbox_core::ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + 16);
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key
}

fn transaction_id(domain: &[u8], source: ObjectDigest) -> [u8; 16] {
    let hash = Sha256::new()
        .chain_update(domain)
        .chain_update(source.as_bytes())
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

fn record_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(RECORD_DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn packet_limit(packet: &[u8], request: &[u8]) -> Option<u64> {
    if packet.get(..8)? != b"AOSARP01" || packet.len() > MAXIMUM_PACKET_BYTES {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(packet.get(8..10)?.try_into().ok()?));
    if length != request.len()
        || packet.len() != 10 + length + 8 + 64
        || packet.get(10..10 + length)? != request
    {
        return None;
    }
    let limit = u64::from_be_bytes(packet.get(10 + length..18 + length)?.try_into().ok()?);
    (limit != 0).then_some(limit)
}

fn take<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], HostArgumentAttemptErrorV1> {
    take_slice(cursor, N)?
        .try_into()
        .map_err(|_| HostArgumentAttemptErrorV1::Binding)
}

fn take_slice<'a>(
    cursor: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], HostArgumentAttemptErrorV1> {
    let (head, tail) = cursor
        .split_at_checked(length)
        .ok_or(HostArgumentAttemptErrorV1::Binding)?;
    *cursor = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_agent::{AgentRuntimeBindingV1, AgentSessionBindingV1};
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NamespaceGeneration,
        SandboxId,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use tempfile::TempDir;

    use super::*;

    fn source() -> ControllerExecutionArgumentAttemptV1 {
        let mut bytes = [0; 336];
        bytes[..8].copy_from_slice(b"AOSCIA02");
        bytes[8..56].fill(1);
        bytes[56..248].fill(2);
        bytes[184..216].fill(5);
        bytes[248..296].fill(3);
        bytes[296..304].copy_from_slice(&100_u64.to_be_bytes());
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&bytes[..304])
            .finalize()
            .into();
        bytes[304..].copy_from_slice(&digest);
        ControllerExecutionArgumentAttemptV1::decode_canonical(&bytes).unwrap()
    }

    fn pending() -> HostArgumentAttemptRecordV1 {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([5; 32]),
            DesiredGeneration::new(4),
            NamespaceGeneration::new(5),
            [6; 16],
        )
        .unwrap();
        let request = GuestRuntimeArgumentObserveRequestV1::new(
            runtime,
            AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([7; 32])).unwrap(),
            ObjectDigest::from_bytes([8; 32]),
            [9; 32],
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            ObjectDigest::from_bytes([10; 32]),
        )
        .unwrap();
        HostArgumentAttemptRecordV1 {
            phase: AttemptPhase::Pending,
            source: source(),
            plan_digest: ObjectDigest::from_bytes([11; 32]),
            semantic_digest: ObjectDigest::from_bytes([12; 32]),
            runtime_handle: ObjectDigest::from_bytes([13; 32]),
            custody_sequence: 3,
            canonical_request: request.encode(),
            signed_packet: Vec::new(),
        }
    }

    fn packet(request: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"AOSARP01");
        packet.extend_from_slice(&(request.len() as u16).to_be_bytes());
        packet.extend_from_slice(request);
        packet.extend_from_slice(&131_072_u64.to_be_bytes());
        let signer = SigningKey::from_bytes(&[14; 32]);
        let mut message = b"aos.sandbox.guest-argument-readback.v1\0".to_vec();
        message.extend_from_slice(&packet);
        packet.extend_from_slice(&signer.sign(&message).to_bytes());
        packet
    }

    #[test]
    fn attempt_record_rejects_tampering_and_wrong_phase() {
        let pending = pending();
        let bytes = pending.encode().unwrap();
        assert_eq!(
            HostArgumentAttemptRecordV1::decode(&bytes).unwrap(),
            pending
        );

        let mut changed = bytes.clone();
        changed[9] ^= 1;
        assert!(HostArgumentAttemptRecordV1::decode(&changed).is_err());
        changed = bytes;
        changed[8] = AttemptPhase::Complete as u8;
        assert!(HostArgumentAttemptRecordV1::decode(&changed).is_err());
    }

    #[test]
    fn cold_reopen_never_resends_pending_or_returns_fresh_evidence() {
        let directory = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let pending = pending();
        let (journal, _) = Journal::open_protected_at_for_uid(
            directory.path(),
            JOURNAL_NAME,
            journal_limits(),
            uid,
        )
        .unwrap();
        let mut owner = HostArgumentAttemptJournalV1 {
            journal,
            instance: [1; 16],
        };
        let old_token = owner.begin(&pending).unwrap();
        drop(owner);

        let (journal, _) = Journal::open_protected_at_for_uid(
            directory.path(),
            JOURNAL_NAME,
            journal_limits(),
            uid,
        )
        .unwrap();
        let mut recovered = HostArgumentAttemptJournalV1 {
            journal,
            instance: [2; 16],
        };
        assert!(matches!(
            recovered.begin(&pending),
            Err(HostArgumentAttemptErrorV1::AlreadyAttempted)
        ));
        let historical = recovered.query_historical(&pending.source).unwrap();
        assert_eq!(historical.status(), HistoricalHostArgumentStatusV1::Pending);
        assert_eq!(historical.packet_digest().as_bytes(), &[0; 32]);
        assert_eq!(historical.custody_sequence(), 3);

        let mut changed_source = pending.source.canonical_bytes();
        changed_source[152] ^= 1;
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&changed_source[..304])
            .finalize()
            .into();
        changed_source[304..].copy_from_slice(&checksum);
        let changed_source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(&changed_source).unwrap();
        assert!(recovered.query_historical(&changed_source).is_err());

        let signed_packet = packet(&pending.canonical_request);
        assert!(recovered.complete(old_token, &signed_packet).is_err());
        assert_eq!(
            recovered
                .query_historical(&pending.source)
                .unwrap()
                .status(),
            HistoricalHostArgumentStatusV1::Pending
        );
    }

    #[test]
    fn completed_fresh_attempt_reopens_as_historical_only() {
        let directory = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let pending = pending();
        let signed_packet = packet(&pending.canonical_request);
        let (journal, _) = Journal::open_protected_at_for_uid(
            directory.path(),
            JOURNAL_NAME,
            journal_limits(),
            uid,
        )
        .unwrap();
        let mut owner = HostArgumentAttemptJournalV1 {
            journal,
            instance: [3; 16],
        };
        let fresh_token = owner.begin(&pending).unwrap();
        let (digest, sequence) = owner.complete(fresh_token, &signed_packet).unwrap();
        assert_ne!(digest.as_bytes(), &[0; 32]);
        assert!(sequence > 0);
        drop(owner);

        let (journal, _) = Journal::open_protected_at_for_uid(
            directory.path(),
            JOURNAL_NAME,
            journal_limits(),
            uid,
        )
        .unwrap();
        let mut recovered = HostArgumentAttemptJournalV1 {
            journal,
            instance: [4; 16],
        };
        assert!(matches!(
            recovered.begin(&pending),
            Err(HostArgumentAttemptErrorV1::AlreadyAttempted)
        ));
        let historical = recovered.query_historical(&pending.source).unwrap();
        assert_eq!(
            historical.status(),
            HistoricalHostArgumentStatusV1::Complete
        );
        assert_eq!(
            historical.packet_digest().as_bytes(),
            Sha256::digest(&signed_packet).as_slice()
        );
        assert_eq!(historical.custody_sequence(), sequence);

        let mut another_source = pending.source.canonical_bytes();
        another_source[8..24].fill(35);
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&another_source[..304])
            .finalize()
            .into();
        another_source[304..].copy_from_slice(&checksum);
        let mut another_pending = pending.clone();
        another_pending.source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(&another_source).unwrap();
        recovered.begin(&another_pending).unwrap();
        assert_eq!(
            recovered
                .query_historical(&pending.source)
                .unwrap()
                .custody_sequence(),
            sequence,
        );
    }
}
