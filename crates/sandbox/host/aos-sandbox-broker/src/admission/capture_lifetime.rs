//! Owns the independently verified ongoing bound of one signed physical Capture.
//!
//! The original request-local effect remains short. Only this closed actual
//! admission can bind the signed full SourceV2 lifetime to the verified plan,
//! installed lease and actual native admitted pair. This owner is neither a
//! physical writer permit nor completion evidence.

use super::*;
use aos_sandbox_protocol::storage_capture_grant::{
    StorageCaptureGrantMethodV1, StorageCaptureGrantSourceV2,
};

/// Retains one actual signed60 admission and its independently verified lifetime.
///
/// Its fields and constructor are private. Decoding a lifetime or an expired
/// ordinary effect cannot manufacture this owner or renew either deadline.
#[derive(Debug)]
pub struct VerifiedStorageCaptureLifetimeV3 {
    source: StorageCaptureGrantSourceV2,
    admitted_clock: RawPairedClockSample,
    admission: VerifiedBrokerAdmission,
    ongoing_deadline: u64,
}

impl VerifiedStorageCaptureLifetimeV3 {
    /// Borrows the exact whole-source bytes bound by the signed grant.
    #[must_use]
    pub const fn source_v3(&self) -> &StorageCaptureGrantSourceV2 { &self.source }

    /// Borrows the actual pending fence/effect and verified installed lease.
    #[must_use]
    pub const fn admission_v3(&self) -> &VerifiedBrokerAdmission { &self.admission }

    /// Returns the original short admission deadline, without renewal.
    #[must_use]
    pub fn acquisition_deadline_v3(&self) -> u64 {
        self.admission.effect.effect_deadline_boottime_nanoseconds()
            .min(self.source.original_source_v1().original_deadline_boottime_nanoseconds())
    }

    /// Returns the independently verified, conservatively tightened execution bound.
    #[must_use]
    pub const fn ongoing_deadline_v3(&self) -> u64 { self.ongoing_deadline }

    /// Borrows the same native pair consumed by actual signed60 admission.
    #[must_use]
    pub const fn admitted_clock_v3(&self) -> &RawPairedClockSample { &self.admitted_clock }

    /// Rechecks ongoing time under the original verified plan and lease ceilings.
    ///
    /// This never permits a new admission or physical worker. Its caller must
    /// already hold the same occupied F session, committed attempt and physical
    /// owner. The short acquisition deadline remains a separate entry gate.
    ///
    /// # Errors
    /// Rejects changed reader/boot, backwards time, drift, lifetime expiry or
    /// either original signed wall expiry. No native sampling occurs here.
    pub fn require_ongoing_clock_v3(&self, current: &RawPairedClockSample)
        -> Result<(), BrokerAdmissionError>
    {
        require_effect_paired_clock_v3(&self.admission.effect, current)?;
        if current.boottime_nanoseconds() >= self.ongoing_deadline
            || current.wall_seconds() >= self.admission.effect.plan_expires_seconds()
            || current.wall_seconds() >= self.admission.effect.authority_expires_seconds()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(())
    }
}

impl BrokerAuthority {
    /// Verifies a full signed physical Capture lifetime beside its short effect.
    ///
    /// The exact original assignment fence and lease are required by the sole
    /// existing Capture admission engine. The full version-two Source digest
    /// selects the signed grant; its base source supplies acquisition DATA only.
    ///
    /// # Errors
    /// Rejects a foreign domain/protocol/assignment/grant, stale acquisition,
    /// substituted original lease, clock discontinuity or exhausted lifetime.
    pub fn admit_storage_capture_lifetime_v3(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        source: &StorageCaptureGrantSourceV2,
        current: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedStorageCaptureLifetimeV3, BrokerAdmissionError> {
        let original = source.original_source_v1();
        let grant = source.broker_grant_v2(StorageCaptureGrantMethodV1::Reserve, request.request_id)
            .map_err(|_| BrokerAdmissionError::RequestMismatch)?;
        if request.audience != BrokerAudience::Storage
            || request.protocol != ProtocolId::StorageBroker
            || request.protocol_version != ProtocolVersion::new(1, 0)
            || request.assignment != original.assignment()
            || request.verb != grant.verb() || request.target != grant.target()
            || request.argument_commitment != grant.argument_commitment()
            || request.descriptor_count != 0
            || original.host_boot_id() != current.host_boot_id()
            || current.boottime_nanoseconds() >= original.original_deadline_boottime_nanoseconds()
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let admission = self.admit_storage_capture_reserve_v2(artifacts, request, current, prior_fence)?;
        let lease = &admission.verified_lease;
        source.lifetime_v2().require_original_lease_data_v2(
            lease.lease_digest(), lease.lease().lease_generation(),
            lease.lease().authority_expires_seconds(), lease.lease().maximum_clock_skew_seconds(),
        ).map_err(|_| BrokerAdmissionError::FenceRejected)?;
        let ongoing_deadline = source.lifetime_v2().tighten_admitted_deadline_data_v2(
            *current, admission.effect.plan_expires_seconds(),
            admission.effect.local_lease_record().fail_stop_boottime_nanoseconds(),
        ).map_err(|_| BrokerAdmissionError::FenceRejected)?;
        Ok(VerifiedStorageCaptureLifetimeV3 {
            source: *source, admitted_clock: *current, admission, ongoing_deadline,
        })
    }
}
