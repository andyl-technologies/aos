//! Verifies the sole signed ongoing physical Capture grant on the Storage fence.
//!
//! Actual dispatch still requires the same paid F worker, durable attempt,
//! authenticated Host readback, current physical catalog and allocation policy.
//! Historical acquisition DATA cannot construct this private admission owner.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantMethodV1;

pub(crate) struct VerifiedCaptureReserveOngoingAdmissionV3 {
    original_records: aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1,
    request_id: [u8; 16],
    session: [u8; 32],
    signed_request: [u8; 32],
    lifetime: aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
}

impl VerifiedCaptureReserveOngoingAdmissionV3 {
    pub(crate) fn source_v3(&self)
        -> &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2
    { self.lifetime.source_v3() }

    pub(crate) fn original_records_v3(&self)
        -> &aos_sandbox_protocol::storage_output_reserve::StorageOutputReserveRecordsV1
    { &self.original_records }

    pub(crate) fn lifetime_v3(&self) -> &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3 {
        &self.lifetime
    }

    // This receiver exists only after the actual signed60 admission above.
    // Native entry still borrows the SAME paid Session and physical-worker
    // state; no DATA receipt, decoded Source or arbitrary clock creates it.
    pub(crate) fn borrow_worker_flight_v3<'flight, 'cut, 'original>(
        &self,
        lifecycle: &'flight mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
        journal: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        request: &AuthenticatedBrokerMethodRequestV1,
        demand: aos_sandbox_core::ResourceVector,
    ) -> Result<aos_sandbox::StoragePhysicalWorkerLoanV1<'flight, 'original>,
        aos_sandbox::StorageReceivingClosedV1>
    {
        if self.request_id != request.request_id() || self.session != request.session_binding()
            || self.signed_request != request.signed_request_digest()
        {
            return Err(aos_sandbox::StorageReceivingClosedV1);
        }
        lifecycle.borrow_capture_worker_flight_ongoing_v3(
            journal, socket, request, &self.lifetime, demand,
        )
    }

    pub(crate) fn matches_v3(&self, other: &Self) -> bool {
        self.original_records == other.original_records && self.request_id == other.request_id
            && self.session == other.session && self.signed_request == other.signed_request
            && self.source_v3() == other.source_v3()
            && self.lifetime.admission_v3().effect.plan_digest()
                == other.lifetime.admission_v3().effect.plan_digest()
            && self.lifetime.admission_v3().effect.transport_request_digest()
                == other.lifetime.admission_v3().effect.transport_request_digest()
            && self.lifetime.admission_v3().effect.lease_digest()
                == other.lifetime.admission_v3().effect.lease_digest()
            && self.lifetime.acquisition_deadline_v3() == other.lifetime.acquisition_deadline_v3()
            && self.lifetime.ongoing_deadline_v3() == other.lifetime.ongoing_deadline_v3()
    }
}

impl StorageAuthorityV1 {
    pub(crate) fn admit_capture_reserve_ongoing_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedCaptureReserveOngoingAdmissionV3, StorageAdmissionError> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
            || request.peer_policy().audience != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(StorageAdmissionError::RequestMismatch);
        }
        let source = request.storage_execution_capture_source_ongoing_v2()
            .ok_or(StorageAdmissionError::RequestMismatch)?;
        let original_records = *request.storage_execution_capture_output_records_v2()
            .ok_or(StorageAdmissionError::RequestMismatch)?;
        let grant = source.broker_grant_v2(StorageCaptureGrantMethodV1::Reserve, request.request_id())
            .map_err(|_| StorageAdmissionError::RequestMismatch)?;
        if request.semantic_commitment() != *grant.argument_commitment().digest().as_bytes() {
            return Err(StorageAdmissionError::RequestMismatch);
        }
        let artifacts = request.authorization().ok_or(StorageAdmissionError::RequestMismatch)?;
        let lifetime = self.0.admit_storage_capture_lifetime_v3(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Storage, protocol: ProtocolId::StorageBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment: source.original_source_v1().assignment(), request_id: request.request_id(),
                request_body: request.exact_body(), descriptor_count: 0,
                verb: grant.verb(), target: grant.target(), argument_commitment: grant.argument_commitment(),
                request_deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds(),
            },
            source, clock, prior_fence,
        )?;
        let effect = &lifetime.admission_v3().effect;
        if effect.status() != BrokerEffectStatusV1::Pending
            || effect.verb() != BrokerVerb::StorageReserveExecutionCapture
            || effect.request_id() != &request.request_id()
            || effect.request_digest() != grant.argument_commitment().digest()
            || effect.transport_request_digest() != ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into())
        { return Err(StorageAdmissionError::RequestMismatch); }
        Ok(VerifiedCaptureReserveOngoingAdmissionV3 {
            original_records, request_id: request.request_id(), session: request.session_binding(),
            signed_request: request.signed_request_digest(), lifetime,
        })
    }
}

/// Holds only one actual freshly signed historical Query61 admission.
///
/// This private type never lends a physical worker or an ongoing reserve
/// lifetime. Historical Source944 may outlive its original effect horizon;
/// the independently verified current Query grant and original lease may not.
pub(crate) struct VerifiedCaptureQueryOngoingAdmissionV3 {
    source: aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    request_id: [u8; 16],
    session: [u8; 32],
    signed_request: [u8; 32],
    admission: VerifiedBrokerAdmission,
}

impl VerifiedCaptureQueryOngoingAdmissionV3 {
    pub(crate) fn source_v3(&self)
        -> &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2
    { &self.source }

    pub(crate) fn matches_v3(&self, other: &Self) -> bool {
        self.source == other.source && self.request_id == other.request_id
            && self.session == other.session && self.signed_request == other.signed_request
            && self.admission.fence.assignment() == other.admission.fence.assignment()
            && self.admission.fence.local_lease_record() == other.admission.fence.local_lease_record()
            && self.admission.effect.plan_digest() == other.admission.effect.plan_digest()
            && self.admission.effect.transport_request_digest() == other.admission.effect.transport_request_digest()
    }
}

impl StorageAuthorityV1 {
    pub(crate) fn admit_capture_query_ongoing_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedCaptureQueryOngoingAdmissionV3, StorageAdmissionError> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1
            || request.peer_policy().audience != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(StorageAdmissionError::RequestMismatch);
        }
        let source = request.storage_execution_capture_source_ongoing_v2()
            .ok_or(StorageAdmissionError::RequestMismatch)?;
        let grant = source.broker_grant_v2(StorageCaptureGrantMethodV1::Query, request.request_id())
            .map_err(|_| StorageAdmissionError::RequestMismatch)?;
        if request.semantic_commitment() != *grant.argument_commitment().digest().as_bytes() {
            return Err(StorageAdmissionError::RequestMismatch);
        }
        let artifacts = request.authorization().ok_or(StorageAdmissionError::RequestMismatch)?;
        let admission = self.0.admit_storage_capture_query_v2(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Storage, protocol: ProtocolId::StorageBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment: source.original_source_v1().assignment(), request_id: request.request_id(),
                request_body: request.exact_body(), descriptor_count: 0,
                verb: grant.verb(), target: grant.target(), argument_commitment: grant.argument_commitment(),
                request_deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds(),
            }, clock, prior_fence,
        )?;
        let effect = &admission.effect;
        if effect.status() != BrokerEffectStatusV1::Pending
            || effect.verb() != BrokerVerb::StorageQueryExecutionCapture
            || effect.request_id() != &request.request_id()
            || effect.request_digest() != grant.argument_commitment().digest()
            || effect.transport_request_digest() != ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into())
        { return Err(StorageAdmissionError::RequestMismatch); }
        Ok(VerifiedCaptureQueryOngoingAdmissionV3 {
            source: *source, request_id: request.request_id(), session: request.session_binding(),
            signed_request: request.signed_request_digest(), admission,
        })
    }
}
