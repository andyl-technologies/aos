//! Joins fresh signed Query61 to the same current Storage State fence.
//!
//! This comparison never writes State or Output and cannot lend a worker.

use super::*;
use crate::runtime::capture_query::CaptureQueryErrorV3;

pub(crate) struct CaptureQueryCutV3 {
    admission: crate::authorization::VerifiedCaptureQueryOngoingAdmissionV3,
    authority_head: u64,
    fence_digest: ObjectDigest,
    catalog: (u64, ObjectDigest),
}

impl CaptureQueryCutV3 {
    pub(crate) fn source_v3(&self)
        -> &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2
    { self.admission.source_v3() }

    pub(crate) fn matches_v3(&self, other: &Self) -> bool {
        self.admission.matches_v3(&other.admission) && self.authority_head == other.authority_head
            && self.fence_digest == other.fence_digest && self.catalog == other.catalog
    }
}

impl StorageAdmissionCoordinator {
    pub(crate) fn authenticate_capture_query_ongoing_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        clock: &RawPairedClockSample,
    ) -> Result<CaptureQueryCutV3, CaptureQueryErrorV3> {
        let source = request.storage_execution_capture_source_ongoing_v2()
            .ok_or(CaptureQueryErrorV3::Closed)?;
        let prior = self.transactions.authority_record(RecordNamespace::DesiredState,
            source.original_source_v1().assignment().sandbox().as_bytes())?
            .ok_or(CaptureQueryErrorV3::Closed)?;
        let admission = self.authority.admit_capture_query_ongoing_v3(request, clock, prior)?;
        let physical = self.transactions.verified_resolver_journal()?;
        let binding = physical.physical().binding();
        Ok(CaptureQueryCutV3 {
            admission, authority_head: self.transactions.authority_head_sequence()?,
            fence_digest: ObjectDigest::from_bytes(Sha256::digest(prior).into()),
            catalog: (binding.generation(), binding.digest()),
        })
    }
}
