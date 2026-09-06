//! Authenticates Mount Apply replies and durably records exact success receipts.
//!
//! The controller transmits only an already durable attempt. A successful
//! response is bound back to that attempt and committed before the live result
//! token is returned. Transport errors and broker rejections are deliberately
//! non-terminal: the broker may already hold an intermediate durable resource,
//! so authoritative inventory must decide recovery.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerClientHello, BrokerMethod, Feature};
use aos_sandbox_core::{
    FeatureRef, ObjectDigest, ProtocolId, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE;
use aos_sandbox_protocol::{
    ValidatedMountResult, decode_mount_result_for_apply, decode_response_envelope,
    decode_server_hello,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    DurableCurrentMountAttemptV1, History as AttemptHistory, MountAttemptError, Record,
    decode_attempt_body,
};
use crate::mount_preparation::transport;
use crate::mount_preparation::{
    MountCatalogPreparationError, MountServiceIdentity, ServiceExecution,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

mod format;

const NAMESPACE: RecordNamespace = RecordNamespace::MountCompletion;
const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_MOUNT_APPLY;
const RESPONSE_BYTES: u32 = 16 * 1024;
const MAXIMUM_COMPLETIONS: usize = 4096;
const MAXIMUM_NAMESPACE_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = RESPONSE_BYTES as usize + format::FIXED_RECORD_BYTES;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.mount-completion.transaction.v1\0";

/// Reports whether a successful Mount receipt committed or replayed exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountCompletionOutcomeV1 {
    /// The successful receipt became durable in this call.
    Recorded,
    /// The same successful receipt was already durable for this attempt.
    Replay,
}

/// Owns one connected channel for an exact, already durable Mount Apply.
pub struct MountDispatchClient {
    socket: DescriptorSubjectSocket,
    expected_mount: MountServiceIdentity,
}

impl MountDispatchClient {
    /// Configures an exclusively owned connected Mount channel before sending.
    ///
    /// The actual hello and response writers are authenticated through kernel
    /// record subjects against the configured service UID, GID, and retained
    /// cgroup. Connection-establisher credentials are not treated as service
    /// identity under socket activation.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, an incompatible socket, or
    /// unavailable kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_mount: MountServiceIdentity,
    ) -> Result<Self, MountAttemptError> {
        expected_mount.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_mount,
        })
    }

    fn dispatch(
        mut self,
        attempt: &DurableCurrentMountAttemptV1,
    ) -> Result<DispatchSuccess, MountAttemptError> {
        let request = decode_attempt_body(
            attempt.attempt.body(),
            attempt.attempt.deadline_boottime_nanoseconds(),
        )?;
        let deadline =
            transport::exchange_deadline(attempt.attempt.deadline_boottime_nanoseconds())
                .map_err(MountAttemptError::Preparation)?;
        let feature = FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(), 1, 0)
            .map_err(|_| {
                aos_sandbox_protocol::ProtocolValidationError::InvalidField(
                    "required Mount authorization feature",
                )
            })?;
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 2,
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

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)
            .map_err(MountAttemptError::Preparation)?;
        let response = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )
        .map_err(MountAttemptError::Preparation)?;
        let (hello_bytes, subject, _) = response.into_parts();
        let mount =
            ServiceExecution::new(&self.expected_mount, subject).map_err(map_service_error)?;
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
        let decoded = session.decode_request(attempt.attempt.packet(), 0)?;
        if decoded.authorization().is_none() || decoded.body() != attempt.attempt.body() {
            return Err(aos_sandbox_protocol::ProtocolValidationError::InvalidField(
                "Mount Apply authorization packet",
            )
            .into());
        }

        mount
            .recheck(&self.expected_mount)
            .map_err(map_service_error)?;
        transport::send(&mut self.socket, attempt.attempt.packet(), deadline)
            .map_err(MountAttemptError::Preparation)?;
        let response = transport::receive(
            &mut self.socket,
            usize::try_from(request.header().maximum_response_bytes())
                .map_err(|_| MountAttemptError::CorruptState)?,
            deadline,
        )
        .map_err(MountAttemptError::Preparation)?;
        mount
            .validate_response(&self.expected_mount, response.subject())
            .map_err(map_service_error)?;
        let envelope = decode_response_envelope(
            response.payload(),
            request.header().request_id(),
            METHOD,
            &[],
            response.descriptors().len(),
            session.maximum_response_bytes(),
            request.header().maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(MountAttemptError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
        let receipt = envelope.body().to_vec();
        let result = decode_mount_result_for_apply(&receipt, &request, attempt.attempt.body())?;

        Ok(DispatchSuccess { receipt, result })
    }
}

/// Retains a current successful Mount result whose exact receipt is durable.
///
/// The token remains live and non-cloneable because the underlying catalog and
/// namespace proof cannot be reconstructed from journal bytes. It proves one
/// broker result, not complete attachment readiness or post-restart presence.
pub struct CompletedCurrentMountAttemptV1 {
    attempt: DurableCurrentMountAttemptV1,
    result: ValidatedMountResult,
    record: CompletionRecord,
    outcome: MountCompletionOutcomeV1,
}

impl CompletedCurrentMountAttemptV1 {
    /// Returns whether this call recorded or replayed the exact success receipt.
    #[must_use]
    pub const fn outcome(&self) -> MountCompletionOutcomeV1 {
        self.outcome
    }

    /// Returns the stable request identity shared with admission and Mount.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete successful completion record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Borrows the successful result validated against the exact Apply bytes.
    #[must_use]
    pub const fn result(&self) -> &ValidatedMountResult {
        &self.result
    }

    /// Borrows the durable-before-I/O attempt and its retained live authority.
    #[must_use]
    pub const fn attempt(&self) -> &DurableCurrentMountAttemptV1 {
        &self.attempt
    }
}

struct DispatchSuccess {
    receipt: Vec<u8>,
    result: ValidatedMountResult,
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
    ) -> Result<(Self, ValidatedMountResult), MountAttemptError> {
        let result = validate_receipt(attempt, &receipt)?;
        let mut record = Self {
            request_id: attempt.request_id,
            attempt_digest: attempt.digest,
            receipt,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        Ok((record, result))
    }

    pub(super) fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(17);
        key.push(b'c');
        key.extend_from_slice(&self.request_id);
        key
    }

    pub(super) fn transaction(&self) -> Result<JournalTransaction, MountAttemptError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| MountAttemptError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, self.key(), self.encode())],
        )?)
    }

    pub(super) fn encoded_len(&self) -> usize {
        format::FIXED_RECORD_BYTES.saturating_add(self.receipt.len())
    }

    fn validate(&self, attempt: &Record) -> Result<(), MountAttemptError> {
        if self.request_id == [0; 16]
            || self.attempt_digest == [0; 32]
            || self.receipt.is_empty()
            || self.receipt.len() > RESPONSE_BYTES as usize
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
            || self.request_id != attempt.request_id
            || self.attempt_digest != attempt.digest
        {
            return Err(MountAttemptError::CorruptState);
        }
        validate_receipt(attempt, &self.receipt).map(|_| ())
    }
}

#[derive(Default)]
pub(super) struct CompletionHistory {
    pub(super) records: BTreeMap<[u8; 16], CompletionRecord>,
    pub(super) retained_bytes: usize,
}

impl CompletionHistory {
    pub(super) fn load(journal: &mut Journal) -> Result<Self, MountAttemptError> {
        let attempts = AttemptHistory::load(journal)?;
        let mut records = BTreeMap::new();
        let mut retained_bytes = 0_usize;

        for (key, value) in journal.records(NAMESPACE) {
            retained_bytes = retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(MountAttemptError::Capacity)?;
            if records.len() >= MAXIMUM_COMPLETIONS
                || retained_bytes > MAXIMUM_NAMESPACE_BYTES
                || value.len() > MAXIMUM_RECORD_BYTES
            {
                return Err(MountAttemptError::Capacity);
            }

            let record = CompletionRecord::decode(value)?;
            if key != record.key() {
                return Err(MountAttemptError::CorruptState);
            }
            let attempt = attempts
                .records
                .get(&record.request_id)
                .ok_or(MountAttemptError::CorruptState)?;
            record.validate(attempt)?;
            if records.insert(record.request_id, record).is_some() {
                return Err(MountAttemptError::CorruptState);
            }
        }

        Ok(Self {
            records,
            retained_bytes,
        })
    }

    pub(super) fn outcome(
        &self,
        record: &CompletionRecord,
    ) -> Result<Option<MountCompletionOutcomeV1>, MountAttemptError> {
        match self.records.get(&record.request_id) {
            Some(existing) if existing == record => Ok(Some(MountCompletionOutcomeV1::Replay)),
            Some(_) => Err(MountAttemptError::Conflict),
            None => Ok(None),
        }
    }

    fn ensure_capacity(&self, record: &CompletionRecord) -> Result<(), MountAttemptError> {
        let next_bytes = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(MountAttemptError::Capacity)?;
        if self.records.len() >= MAXIMUM_COMPLETIONS || next_bytes > MAXIMUM_NAMESPACE_BYTES {
            return Err(MountAttemptError::Capacity);
        }
        Ok(())
    }
}

pub(crate) fn dispatch_current<T>(
    journal: &mut Journal,
    attempt: DurableCurrentMountAttemptV1,
    client: MountDispatchClient,
    clock: &mut T,
) -> Result<CompletedCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt.recheck(journal, clock)?;
    let success = client.dispatch(&attempt)?;
    let (record, result) = CompletionRecord::from_attempt(&attempt.record, success.receipt)?;
    if result != success.result {
        return Err(MountAttemptError::CorruptState);
    }

    let history = CompletionHistory::load(journal)?;
    let outcome = match history.outcome(&record)? {
        Some(outcome) => outcome,
        None => {
            history.ensure_capacity(&record)?;
            journal.commit(&record.transaction()?)?;
            MountCompletionOutcomeV1::Recorded
        }
    };

    // Once Mount replies, the effect may exist even if authority changes.
    // Persist its exact success first, then withhold a live token when stale.
    let committed = CompletionHistory::load(journal)?;
    if committed.records.get(&record.request_id) != Some(&record) {
        return Err(MountAttemptError::CorruptState);
    }
    attempt.recheck(journal, clock)?;

    Ok(CompletedCurrentMountAttemptV1 {
        attempt,
        result,
        record,
        outcome,
    })
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), MountAttemptError> {
    CompletionHistory::load(journal).map(|_| ())
}

fn validate_receipt(
    attempt: &Record,
    receipt: &[u8],
) -> Result<ValidatedMountResult, MountAttemptError> {
    let request = decode_attempt_body(&attempt.body, attempt.deadline_boottime_nanoseconds)?;
    decode_mount_result_for_apply(receipt, &request, &attempt.body).map_err(Into::into)
}

fn map_service_error(error: MountCatalogPreparationError) -> MountAttemptError {
    match error {
        MountCatalogPreparationError::MountIdentity => MountAttemptError::MountIdentity,
        other => MountAttemptError::Preparation(other),
    }
}
