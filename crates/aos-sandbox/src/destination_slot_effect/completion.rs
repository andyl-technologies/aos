//! Authenticated destination-slot replies and durable completion records.
//!
//! A completion retains the exact successful broker body beside the digest of
//! the durable-before-I/O attempt that authorized it:
//!
//! ```text
//! AOSDSC01 | reserved:4 | request-id:16 | attempt-digest:32 |
//! receipt-size:4 | receipt | record-digest:32
//! ```

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerMethod, DestinationSlotAction, DestinationSlotLifecycle,
    Feature,
};
use aos_sandbox_core::{FeatureRef, ObjectDigest, ProtocolId, RawPairedClockSample};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE;
use aos_sandbox_protocol::{
    ValidatedDestinationSlotInventoryRecord, decode_destination_slot_response,
    decode_response_envelope, decode_server_hello,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::attempt::{DurableCurrentDestinationSlotAttemptV1, History as AttemptHistory, Record};
use super::{CARRIER_VERSION, DestinationSlotEffectError, METHOD, RESPONSE_BYTES, decode_request};
use crate::mount_preparation::transport;
use crate::mount_preparation::{MountServiceIdentity, ServiceExecution};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const NAMESPACE: RecordNamespace = RecordNamespace::DestinationSlotCompletion;
const MAGIC: &[u8; 8] = b"AOSDSC01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.destination-slot-completion.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.destination-slot-completion.transaction.v1\0";
pub(super) const FIXED_RECORD_BYTES: usize = 96;
const MAXIMUM_COMPLETIONS: usize = 16_384;
const MAXIMUM_NAMESPACE_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = RESPONSE_BYTES as usize + FIXED_RECORD_BYTES;

/// Reports whether a successful destination-slot receipt committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationSlotCompletionOutcomeV1 {
    /// The successful receipt became durable in this call.
    Recorded,
    /// The same receipt was already durable for the exact attempt.
    Replay,
}

/// Owns one authenticated Mount channel for an admitted destination-slot packet.
pub struct DestinationSlotDispatchClient {
    socket: DescriptorSubjectSocket,
    expected_mount: MountServiceIdentity,
}

impl DestinationSlotDispatchClient {
    /// Configures an exclusively owned connected Mount channel before sending.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, incompatible socket, or unavailable
    /// kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_mount: MountServiceIdentity,
    ) -> Result<Self, DestinationSlotEffectError> {
        expected_mount.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_mount,
        })
    }

    fn dispatch(
        mut self,
        attempt: &DurableCurrentDestinationSlotAttemptV1,
    ) -> Result<DispatchSuccess, DestinationSlotEffectError> {
        let dispatch = attempt.dispatch_attempt();
        let request = decode_request(dispatch.body(), dispatch.deadline_boottime_nanoseconds())?;
        let deadline = transport::exchange_deadline(dispatch.deadline_boottime_nanoseconds())?;
        let feature = FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(), 1, 0)
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let hello = BrokerClientHello {
            protocol_major: u32::from(CARRIER_VERSION.major()),
            protocol_minor: u32::from(CARRIER_VERSION.minor()),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: vec![Feature {
                namespace: SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
                major: 1,
                minor: 0,
                ..Default::default()
            }],
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![METHOD.into()],
            ..Default::default()
        };

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)?;
        let response = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )?;
        let (hello_bytes, subject, _) = response.into_parts();
        let mount = ServiceExecution::new(&self.expected_mount, subject)?;
        let session = decode_server_hello(
            &hello_bytes,
            ProtocolId::MountBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            CARRIER_VERSION,
            &[feature],
            &[METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(request.header())?;
        let decoded = session.decode_request(dispatch.packet(), 0)?;
        if decoded.authorization().is_none() || decoded.body() != dispatch.body() {
            return Err(DestinationSlotEffectError::CorruptState);
        }

        mount.recheck(&self.expected_mount)?;
        transport::send(&mut self.socket, dispatch.packet(), deadline)?;
        let response = transport::receive(
            &mut self.socket,
            usize::try_from(request.header().maximum_response_bytes())
                .map_err(|_| DestinationSlotEffectError::CorruptState)?,
            deadline,
        )?;
        mount.validate_response(&self.expected_mount, response.subject())?;
        let envelope = decode_response_envelope(
            response.payload(),
            request.header().request_id(),
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
            &[],
            response.descriptors().len(),
            session.maximum_response_bytes(),
            request.header().maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(DestinationSlotEffectError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
        let receipt = envelope.body().to_vec();
        let result = validate_receipt(attempt.record(), &receipt)?;
        transport::check_deadline(deadline)?;
        Ok(DispatchSuccess { receipt, result })
    }
}

/// Retains a current successful destination-slot result and its durable receipt.
pub struct CompletedCurrentDestinationSlotAttemptV1 {
    attempt: DurableCurrentDestinationSlotAttemptV1,
    result: ValidatedDestinationSlotInventoryRecord,
    record: CompletionRecord,
    outcome: DestinationSlotCompletionOutcomeV1,
}

impl CompletedCurrentDestinationSlotAttemptV1 {
    /// Returns whether the exact successful receipt was recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> DestinationSlotCompletionOutcomeV1 {
        self.outcome
    }

    /// Returns the stable logical operation identity shared with Mount.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete durable completion record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Borrows the fully validated terminal destination-slot resource row.
    #[must_use]
    pub const fn result(&self) -> &ValidatedDestinationSlotInventoryRecord {
        &self.result
    }

    /// Borrows the durable-before-I/O attempt and its retained live authority.
    #[must_use]
    pub const fn attempt(&self) -> &DurableCurrentDestinationSlotAttemptV1 {
        &self.attempt
    }
}

struct DispatchSuccess {
    receipt: Vec<u8>,
    result: ValidatedDestinationSlotInventoryRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompletionRecord {
    pub(super) request_id: [u8; 16],
    pub(super) attempt_digest: [u8; 32],
    pub(super) receipt: Vec<u8>,
    pub(super) digest: [u8; 32],
}

impl CompletionRecord {
    pub(super) fn from_attempt(
        attempt: &Record,
        receipt: Vec<u8>,
    ) -> Result<(Self, ValidatedDestinationSlotInventoryRecord), DestinationSlotEffectError> {
        let result = validate_receipt(attempt, &receipt)?;
        let mut record = Self {
            request_id: attempt.request_id(),
            attempt_digest: *attempt.record_digest().as_bytes(),
            receipt,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate(attempt)?;
        Ok((record, result))
    }

    pub(super) fn validate(&self, attempt: &Record) -> Result<(), DestinationSlotEffectError> {
        if self.request_id == [0; 16]
            || self.attempt_digest == [0; 32]
            || self.receipt.is_empty()
            || self.receipt.len() > RESPONSE_BYTES as usize
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.request_id != attempt.request_id()
            || self.attempt_digest != *attempt.record_digest().as_bytes()
            || self.compute_digest() != self.digest
        {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        validate_receipt(attempt, &self.receipt).map(|_| ())
    }

    pub(super) fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(17);
        key.push(b'c');
        key.extend_from_slice(&self.request_id);
        key
    }

    pub(super) fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES.saturating_add(self.receipt.len())
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(RECORD_DOMAIN);
        digest.update(self.request_id);
        digest.update(self.attempt_digest);
        digest.update((self.receipt.len() as u64).to_be_bytes());
        digest.update(&self.receipt);
        digest.finalize().into()
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.attempt_digest);
        bytes.extend_from_slice(&(self.receipt.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.receipt);
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DestinationSlotEffectError> {
        if bytes.len() < FIXED_RECORD_BYTES || bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC || take::<4>(&mut bytes)? != [0; 4] {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        let request_id = take(&mut bytes)?;
        let attempt_digest = take(&mut bytes)?;
        let receipt_len = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        let receipt = take_slice(&mut bytes, receipt_len)?.to_vec();
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(DestinationSlotEffectError::CorruptState);
        }
        Ok(Self {
            request_id,
            attempt_digest,
            receipt,
            digest,
        })
    }

    pub(super) fn transaction(&self) -> Result<JournalTransaction, DestinationSlotEffectError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| DestinationSlotEffectError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, self.key(), self.encode())],
        )?)
    }
}

#[derive(Default)]
struct History {
    records: BTreeMap<[u8; 16], CompletionRecord>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &mut Journal) -> Result<Self, DestinationSlotEffectError> {
        let attempts = AttemptHistory::load(journal)?;
        let mut history = Self::default();
        for (key, value) in journal.records(NAMESPACE) {
            history.retained_bytes = history
                .retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(DestinationSlotEffectError::Capacity)?;
            if history.records.len() >= MAXIMUM_COMPLETIONS
                || history.retained_bytes > MAXIMUM_NAMESPACE_BYTES
                || value.len() > MAXIMUM_RECORD_BYTES
            {
                return Err(DestinationSlotEffectError::Capacity);
            }
            let record = CompletionRecord::decode(value)?;
            if key != record.key() {
                return Err(DestinationSlotEffectError::CorruptState);
            }
            let attempt = attempts
                .records
                .get(&record.request_id)
                .ok_or(DestinationSlotEffectError::CorruptState)?;
            record.validate(attempt)?;
            if history.records.insert(record.request_id, record).is_some() {
                return Err(DestinationSlotEffectError::CorruptState);
            }
        }
        Ok(history)
    }

    fn ensure_capacity(&self, record: &CompletionRecord) -> Result<(), DestinationSlotEffectError> {
        let next = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(DestinationSlotEffectError::Capacity)?;
        if self.records.len() >= MAXIMUM_COMPLETIONS || next > MAXIMUM_NAMESPACE_BYTES {
            return Err(DestinationSlotEffectError::Capacity);
        }
        Ok(())
    }
}

pub(super) fn dispatch_current<T>(
    journal: &mut Journal,
    attempt: DurableCurrentDestinationSlotAttemptV1,
    client: DestinationSlotDispatchClient,
    clock: &mut T,
) -> Result<CompletedCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt.recheck(journal, clock)?;
    let success = client.dispatch(&attempt)?;
    let history = History::load(journal)?;
    let (record, validated) = CompletionRecord::from_attempt(attempt.record(), success.receipt)?;
    if validated != success.result {
        return Err(DestinationSlotEffectError::CorruptState);
    }
    let outcome = match history.records.get(&record.request_id) {
        Some(existing) if existing == &record => DestinationSlotCompletionOutcomeV1::Replay,
        Some(_) => return Err(DestinationSlotEffectError::Conflict),
        None => {
            history.ensure_capacity(&record)?;
            journal.commit(&record.transaction()?)?;
            DestinationSlotCompletionOutcomeV1::Recorded
        }
    };
    let committed = History::load(journal)?;
    if committed.records.get(&record.request_id) != Some(&record) {
        return Err(DestinationSlotEffectError::CorruptState);
    }

    // The completion commit intentionally invalidates the planning inventory.
    // Preserve the receipt, then return a live token only if logical authority
    // is still current after the external effect.
    attempt.recheck_live(journal, clock)?;
    Ok(CompletedCurrentDestinationSlotAttemptV1 {
        attempt,
        result: validated,
        record,
        outcome,
    })
}

pub(super) fn contains(
    journal: &mut Journal,
    request_id: [u8; 16],
) -> Result<bool, DestinationSlotEffectError> {
    Ok(History::load(journal)?.records.contains_key(&request_id))
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), DestinationSlotEffectError> {
    History::load(journal).map(|_| ())
}

pub(super) fn state_records(
    journal: &mut Journal,
) -> Result<Vec<super::ControllerStateRecord>, DestinationSlotEffectError> {
    Ok(History::load(journal)?
        .records
        .into_iter()
        .map(|(request_id, record)| (request_id, record.digest))
        .collect())
}

fn validate_receipt(
    attempt: &Record,
    receipt: &[u8],
) -> Result<ValidatedDestinationSlotInventoryRecord, DestinationSlotEffectError> {
    let request = decode_request(attempt.body(), attempt.deadline_boottime_nanoseconds())?;
    let result = decode_destination_slot_response(receipt, RESPONSE_BYTES)?;
    let request_digest: [u8; 32] = Sha256::digest(attempt.body()).into();
    if result.fence() != request.binding_fence()
        || result.namespace_generation() != request.namespace_generation()
        || result.destination_slot_id() != request.destination_slot_id()
        || result.sandbox_spec() != request.sandbox_spec()
    {
        return Err(DestinationSlotEffectError::Conflict);
    }
    match request.action() {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => {
            if result.lifecycle() != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY
                || result.materialization().operation_id() != request.header().request_id()
                || result.materialization().request_digest() != &request_digest
                || result.reap().is_some()
            {
                return Err(DestinationSlotEffectError::Conflict);
            }
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => {
            let ready = attempt
                .ready_expectation()
                .ok_or(DestinationSlotEffectError::CorruptState)?;
            let reap = result.reap().ok_or(DestinationSlotEffectError::Conflict)?;
            if result.lifecycle() != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
                || !ready.matches_preserved(&result)
                || reap.operation().operation_id() != request.header().request_id()
                || reap.operation().request_digest() != &request_digest
                || reap.expected_resource_digest() != &ready.ready_resource_digest
            {
                return Err(DestinationSlotEffectError::Conflict);
            }
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            return Err(DestinationSlotEffectError::CorruptState);
        }
    }
    Ok(result)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], DestinationSlotEffectError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| DestinationSlotEffectError::CorruptState)
}

fn take_slice<'a>(
    bytes: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], DestinationSlotEffectError> {
    let value = bytes
        .get(..length)
        .ok_or(DestinationSlotEffectError::CorruptState)?;
    *bytes = bytes
        .get(length..)
        .ok_or(DestinationSlotEffectError::CorruptState)?;
    Ok(value)
}
