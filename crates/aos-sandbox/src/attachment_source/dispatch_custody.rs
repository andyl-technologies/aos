//! Atomic exact-packet custody for authenticated Mount source effects.
//!
//! ```text
//! AOSASD01 | operation-id:16 | source-attempt-digest:32 |
//! packet-length:u32be | exact-authorized-packet | digest:32
//! ```
//!
//! The packet embeds the exact signed Mount plan and signed ownership lease.
//! Historical decoding is nonauthorizing; only a freshly bound live dispatch
//! token can send it, and cold recovery must independently revalidate it.

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceRequest, BrokerMethod, BrokerRequestEnvelope,
    ReleaseMountSourceAcquisitionRequest,
};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::model::AttachmentConsistency;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::{
    decode_acquire_mount_source_response, decode_historical_acquire_mount_source_request,
    decode_release_mount_source_acquisition_response, mount_source_acquisition_request_digest_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::custody::{
    AttachmentSourceAttemptKindV1, AttemptRecord, CustodyHistory, DurableAttachmentSourceAttemptV1,
};
use super::planning::{self, AttachmentSourceError};
use crate::BrokerDispatchAttemptV1;
use crate::attachment_state::{self, DurableAttachmentDesiredStateV1};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentNamespaceTarget, CurrentRuntimeScope};
use crate::{Journal, JournalRecord, RecordNamespace};

mod live_consumer;

pub use live_consumer::ClosedControllerLiveConsumerSourceV1;

const NAMESPACE: RecordNamespace = RecordNamespace::AttachmentSourceDispatch;
const MAGIC: &[u8; 8] = b"AOSASD01";
const DOMAIN: &[u8] = b"aos.sandbox.attachment-source-dispatch.v1\0";
const MAXIMUM_PACKET_BYTES: usize = 2 * 1024 * 1024;
const FIXED_BYTES: usize = 8 + 16 + 32 + 4 + 32;

/// Retains the live exact authorized packet after atomic protected admission.
///
/// This token is deliberately not recoverable by decoding a sidecar alone.
/// Cold recovery must revalidate the exact signed artifacts and Mount
/// terminal/readback before it may issue an original request again.
#[must_use = "send or drain this exact authenticated Mount Acquire request"]
pub struct DurableCurrentAttachmentSourceDispatchV1 {
    source: DurableAttachmentSourceAttemptV1,
    dispatch: BrokerDispatchAttemptV1,
    target: CurrentNamespaceTarget,
    source_scope: Option<CurrentRuntimeScope>,
    desired: DurableAttachmentDesiredStateV1,
}

impl DurableCurrentAttachmentSourceDispatchV1 {
    fn recheck_source<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let Some(scope) = &self.source_scope else {
            if self.source.record.kind == AttachmentSourceAttemptKindV1::Acquire
                && self.desired.intent().consistency() == AttachmentConsistency::LocalLive
            {
                return Err(AttachmentSourceError::Conflict);
            }
            return Ok(());
        };
        if self.source.record.kind != AttachmentSourceAttemptKindV1::Acquire {
            return scope.recheck(journal, clock).map_err(Into::into);
        }

        // An unchanged Host assignment cannot authorize a changed View. Recreate
        // both commitments from the protected View, then compare to the durable
        // request rather than trusting a broker-provided source description.
        let request =
            decode_historical_acquire_mount_source_request(&self.source.record.request_body)
                .map_err(|_| AttachmentSourceError::CorruptState)?;
        let sample = clock()?;
        let (binding, template) = planning::source_projection(
            journal,
            self.desired.intent(),
            &self.target,
            Some(scope),
            sample,
            clock,
        )?;
        if binding.digest() != request.source_binding().digest()
            || template.digest() != request.prospective_mount_template_digest()
        {
            return Err(AttachmentSourceError::Changed);
        }
        Ok(())
    }

    /// Returns the exact Mount source effect retained by this token.
    #[must_use]
    pub const fn kind(&self) -> AttachmentSourceAttemptKindV1 {
        self.source.record.kind
    }

    /// Borrows the exact durable source-custody attempt.
    #[must_use]
    pub const fn source_attempt(&self) -> &DurableAttachmentSourceAttemptV1 {
        &self.source
    }

    /// Borrows the exact authorized packet retained before broker I/O.
    #[must_use]
    pub const fn dispatch_attempt(&self) -> &BrokerDispatchAttemptV1 {
        &self.dispatch
    }

    /// Rechecks live Host and protected packet custody before dispatch.
    ///
    /// # Errors
    ///
    /// Rejects changed desired or Host authority, a superseding custody
    /// lineage, or any missing or substituted exact sidecar.
    pub fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        journal.ensure_protected_authority()?;
        attachment_state::recheck_current(journal, &self.desired)?;
        self.target.recheck(journal, clock)?;
        self.recheck_source(journal, clock)?;
        let history = CustodyHistory::load(journal)?;
        if history.open_attempt(self.source.record.attachment_id) != Some(&self.source.record) {
            return Err(AttachmentSourceError::Changed);
        }
        let sidecar =
            current(journal, &self.source.record)?.ok_or(AttachmentSourceError::CorruptState)?;
        if sidecar.packet != self.dispatch.packet() {
            return Err(AttachmentSourceError::Changed);
        }
        self.target.recheck(journal, clock)?;
        self.recheck_source(journal, clock)?;
        Ok(())
    }

    /// Validates one terminal signed source outcome without claiming readiness.
    ///
    /// A later fresh paired Mount inventory must confirm Active custody before
    /// the protected source completion may be recorded.
    ///
    /// # Errors
    ///
    /// Rejects a different method, request, direction, signed error, or
    /// noncanonical response that does not name this exact acquisition.
    pub fn validate_terminal_outcome(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), AttachmentSourceError> {
        let method = match self.source.record.kind {
            AttachmentSourceAttemptKindV1::Acquire => {
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            }
            AttachmentSourceAttemptKindV1::Release => {
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            }
            AttachmentSourceAttemptKindV1::Consume => return Err(AttachmentSourceError::Conflict),
        };
        if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != method
            || outcome.request().exact_body() != self.dispatch.body()
        {
            return Err(AttachmentSourceError::Conflict);
        }
        let exact_body = match outcome.result() {
            AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
            AuthenticatedBrokerMethodResultV1::Error(_) => {
                return Err(AttachmentSourceError::Faulted);
            }
        };
        let acquisition_id = match self.source.record.kind {
            AttachmentSourceAttemptKindV1::Acquire => {
                let request = decode_historical_acquire_mount_source_request(self.dispatch.body())
                    .map_err(|_| AttachmentSourceError::Protocol)?;
                let response = decode_acquire_mount_source_response(exact_body, request.request())
                    .map_err(|_| AttachmentSourceError::Protocol)?;
                *response.acquisition_id()
            }
            AttachmentSourceAttemptKindV1::Release => {
                let request = super::custody::decode_live_release(self.dispatch.body())?;
                let response =
                    decode_release_mount_source_acquisition_response(exact_body, request.request())
                        .map_err(|_| AttachmentSourceError::Protocol)?;
                *response.acquisition_id()
            }
            AttachmentSourceAttemptKindV1::Consume => return Err(AttachmentSourceError::Conflict),
        };
        if acquisition_id != *self.source.acquisition_id().as_bytes() {
            return Err(AttachmentSourceError::Conflict);
        }
        Ok(())
    }
}

pub(super) fn live_dispatch(
    source: DurableAttachmentSourceAttemptV1,
    dispatch: BrokerDispatchAttemptV1,
    target: CurrentNamespaceTarget,
    source_scope: Option<CurrentRuntimeScope>,
    desired: DurableAttachmentDesiredStateV1,
) -> DurableCurrentAttachmentSourceDispatchV1 {
    DurableCurrentAttachmentSourceDispatchV1 {
        source,
        dispatch,
        target,
        source_scope,
        desired,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DispatchRecord {
    pub(super) operation_id: [u8; 16],
    pub(super) source_attempt_digest: [u8; 32],
    pub(super) packet: Vec<u8>,
    digest: [u8; 32],
}

impl DispatchRecord {
    pub(super) fn new(
        attempt: &AttemptRecord,
        packet: Vec<u8>,
    ) -> Result<Self, AttachmentSourceError> {
        let mut record = Self {
            operation_id: attempt.operation_id,
            source_attempt_digest: attempt.digest,
            packet,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate(attempt)?;
        Ok(record)
    }

    pub(super) fn journal_record(&self) -> JournalRecord {
        JournalRecord::put(NAMESPACE, self.operation_id.to_vec(), self.encode())
    }

    pub(super) fn encoded_len(&self) -> usize {
        FIXED_BYTES.saturating_add(self.packet.len())
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.operation_id);
        bytes.extend_from_slice(&self.source_attempt_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.packet.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.packet);
        bytes
    }

    fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, AttachmentSourceError> {
        if bytes.len() < FIXED_BYTES || bytes.len() > FIXED_BYTES + MAXIMUM_PACKET_BYTES {
            return Err(AttachmentSourceError::CorruptState);
        }
        let (magic, remaining) = bytes.split_at(8);
        if magic != MAGIC {
            return Err(AttachmentSourceError::CorruptState);
        }
        let operation_id = exact::<16>(remaining, 0)?;
        let source_attempt_digest = exact::<32>(remaining, 16)?;
        let packet_len = u32::from_be_bytes(exact::<4>(remaining, 48)?) as usize;
        if packet_len > MAXIMUM_PACKET_BYTES || bytes.len() != FIXED_BYTES + packet_len {
            return Err(AttachmentSourceError::CorruptState);
        }
        let packet = remaining
            .get(52..52 + packet_len)
            .ok_or(AttachmentSourceError::CorruptState)?
            .to_vec();
        let digest = exact::<32>(remaining, 52 + packet_len)?;
        Ok(Self {
            operation_id,
            source_attempt_digest,
            packet,
            digest,
        })
    }

    fn validate(&self, attempt: &AttemptRecord) -> Result<(), AttachmentSourceError> {
        if attempt.kind == AttachmentSourceAttemptKindV1::Consume
            || self.operation_id != attempt.operation_id
            || self.source_attempt_digest != attempt.digest
            || self.packet.is_empty()
            || self.packet.len() > MAXIMUM_PACKET_BYTES
            || self.digest == [0; 32]
            || self.compute_digest() != self.digest
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        let envelope = BrokerRequestEnvelope::decode_from_slice(&self.packet)
            .map_err(|_| AttachmentSourceError::CorruptState)?;
        let authorization = envelope
            .authorization
            .as_option()
            .ok_or(AttachmentSourceError::CorruptState)?;
        let (method, request_id) = match attempt.kind {
            AttachmentSourceAttemptKindV1::Acquire => {
                let request = AcquireMountSourceRequest::decode_from_slice(&envelope.body)
                    .map_err(|_| AttachmentSourceError::CorruptState)?;
                let header = request
                    .header
                    .as_option()
                    .ok_or(AttachmentSourceError::CorruptState)?;
                (
                    BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
                    header.request_id.clone(),
                )
            }
            AttachmentSourceAttemptKindV1::Release => {
                let request =
                    ReleaseMountSourceAcquisitionRequest::decode_from_slice(&envelope.body)
                        .map_err(|_| AttachmentSourceError::CorruptState)?;
                let header = request
                    .header
                    .as_option()
                    .ok_or(AttachmentSourceError::CorruptState)?;
                (
                    BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
                    header.request_id.clone(),
                )
            }
            AttachmentSourceAttemptKindV1::Consume => {
                return Err(AttachmentSourceError::CorruptState);
            }
        };
        if envelope.encode_to_vec() != self.packet
            || envelope.method.as_known() != Some(method)
            || envelope.body != attempt.request_body
            || !envelope.descriptors.is_empty()
            || !envelope.signed_session_request.is_empty()
            || envelope.semantic_bindings.as_option().is_some()
            || authorization.broker_plan.is_empty()
            || authorization.broker_plan_signature.is_empty()
            || authorization.ownership_lease.is_empty()
            || authorization.ownership_lease_signature.is_empty()
            || request_id.as_slice() != attempt.operation_id
            || mount_source_acquisition_request_digest_v1(&envelope.body).as_bytes()
                != &attempt.request_digest
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        Ok(())
    }
}

fn exact<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], AttachmentSourceError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .ok_or(AttachmentSourceError::CorruptState)?
        .try_into()
        .map_err(|_| AttachmentSourceError::CorruptState)
}

pub(super) fn current(
    journal: &mut Journal,
    attempt: &AttemptRecord,
) -> Result<Option<DispatchRecord>, AttachmentSourceError> {
    let Some(bytes) = journal.get(NAMESPACE, &attempt.operation_id) else {
        return Ok(None);
    };
    let record = DispatchRecord::decode(bytes)?;
    record.validate(attempt)?;
    Ok(Some(record))
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), AttachmentSourceError> {
    let attempts = super::custody::CustodyHistory::load(journal)?;
    let mut bytes = 0usize;
    for (key, value) in journal.records(NAMESPACE) {
        bytes = bytes
            .checked_add(key.len())
            .and_then(|value_len| value_len.checked_add(value.len()))
            .filter(|length| *length <= 256 * 1024 * 1024)
            .ok_or(AttachmentSourceError::Capacity)?;
        let record = DispatchRecord::decode(value)?;
        let attempt = attempts
            .attempts
            .get(&record.operation_id)
            .ok_or(AttachmentSourceError::CorruptState)?;
        if key != record.operation_id {
            return Err(AttachmentSourceError::CorruptState);
        }
        record.validate(attempt)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment_source::AttachmentSourceAttemptKindV1;
    use aos_proto::aos::sandbox::local::v1::{BrokerAuthorizationArtifactsV1, RequestHeader};

    fn fixture() -> (AttemptRecord, Vec<u8>) {
        let request = AcquireMountSourceRequest {
            header: Some(RequestHeader {
                request_id: vec![1; 16],
                deadline_boottime_nanoseconds: 7,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let body = request.encode_to_vec();
        let packet = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE.into(),
            body: body.clone(),
            authorization: Some(BrokerAuthorizationArtifactsV1 {
                broker_plan: vec![1],
                broker_plan_signature: vec![2],
                ownership_lease: vec![3],
                ownership_lease_signature: vec![4],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let attempt = AttemptRecord {
            kind: AttachmentSourceAttemptKindV1::Acquire,
            operation_id: [1; 16],
            request_digest: *mount_source_acquisition_request_digest_v1(&body).as_bytes(),
            attachment_id: [2; 16],
            desired_generation: 1,
            desired_digest: [3; 32],
            acquisition_id: [4; 32],
            predecessor: None,
            mount_completion_digest: None,
            plan_digest: [5; 32],
            request_body: body,
            plan_bytes: vec![0; 637],
            digest: [6; 32],
        };
        (attempt, packet)
    }

    #[test]
    fn sidecar_links_exact_attempt_and_full_authorized_packet() {
        let (attempt, packet) = fixture();
        let record = DispatchRecord::new(&attempt, packet).unwrap();
        let decoded = DispatchRecord::decode(&record.encode()).unwrap();
        decoded.validate(&attempt).unwrap();

        let mut changed = attempt.clone();
        changed.digest[0] ^= 1;
        assert!(decoded.validate(&changed).is_err());
    }

    #[test]
    fn sidecar_rejects_packet_without_signed_artifacts() {
        let (attempt, packet) = fixture();
        let mut envelope = BrokerRequestEnvelope::decode_from_slice(&packet).unwrap();
        envelope.authorization = Default::default();
        assert!(DispatchRecord::new(&attempt, envelope.encode_to_vec()).is_err());
    }

    #[test]
    fn release_sidecar_requires_exact_release_method_and_body() {
        let (mut attempt, packet) = fixture();
        let mut envelope = BrokerRequestEnvelope::decode_from_slice(&packet).unwrap();
        let request = ReleaseMountSourceAcquisitionRequest {
            header: Some(RequestHeader {
                request_id: vec![1; 16],
                deadline_boottime_nanoseconds: 7,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        attempt.kind = AttachmentSourceAttemptKindV1::Release;
        attempt.request_body = request.encode_to_vec();
        attempt.request_digest =
            *mount_source_acquisition_request_digest_v1(&attempt.request_body).as_bytes();
        envelope.body = attempt.request_body.clone();
        assert!(DispatchRecord::new(&attempt, envelope.encode_to_vec()).is_err());

        envelope.method = BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION.into();
        let record = DispatchRecord::new(&attempt, envelope.encode_to_vec()).unwrap();
        record.validate(&attempt).unwrap();
    }
}
