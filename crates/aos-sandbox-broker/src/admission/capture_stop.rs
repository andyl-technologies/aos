//! Verifies fresh Stop permission for one retained Storage Capture original.
//!
//! The same enrolled Root-plan and Ownership engines authenticate the forwarded
//! Host Stop. This closed inspection creates no Host effect, Storage effect,
//! local lease, positive execution lifetime, physical worker or disposal proof.

use super::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerSignedAdmissionOriginalV4,
    conservative_plan_deadline,
};
use crate::record::BrokerDomain;
use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerGrantTarget, BrokerPlanRequest, BrokerResourceHandle,
    BrokerVerb, ObjectDigest, ProtocolId, ProtocolVersion, RawPairedClockSample,
    VerifiedBrokerPlan, VerifiedOwnershipLease,
};
use aos_sandbox_protocol::LiveHostRuntimeEnvelopeDataV2;
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
use aos_sandbox_protocol::storage_capture_session::stop_cleanup::CaptureStopCleanupRequestDataV4;

/// Retains the exact structural or shared authority refusal of fresh cleanup.
#[derive(Debug, thiserror::Error)]
pub enum StorageCaptureStopInspectionErrorV4 {
    /// The complete original Host request failed its sole DATA decoder.
    #[error(transparent)]
    Body(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// The actual typed Host action has no canonical authority semantics.
    #[error(transparent)]
    Semantics(#[from] aos_sandbox_protocol::semantics::host::HostSemanticError),
    /// The actual typed assignment cannot form a canonical Core identity.
    #[error(transparent)]
    Assignment(#[from] aos_sandbox_core::InvalidBrokerAuthorizationPlan),
    /// The same Root-plan, lease, target or original Stop cutoff check refused.
    #[error(transparent)]
    Authority(#[from] BrokerAdmissionError),
}

/// Retains verified fresh Stop permission beside the original Capture debt.
///
/// Only the actual Storage authority can produce this owner. It permits no
/// positive Capture IO or completion. Its actual worker borrower must separately
/// match the original READY, F, State, Output, Source and attempt identities.
#[derive(Debug)]
pub struct VerifiedStorageCaptureStopCleanupV4 {
    assignment: BrokerAssignment,
    runtime: [u8; 32],
    source: ObjectDigest,
    request: [u8; 16],
    frame: [u8; 32],
    clock: RawPairedClockSample,
    cutoff: u64,
    plan: VerifiedBrokerPlan,
    lease: VerifiedOwnershipLease,
}

impl VerifiedStorageCaptureStopCleanupV4 {
    /// Returns the exact assignment bound by both fresh signed authorities.
    #[must_use]
    pub const fn assignment_v4(&self) -> BrokerAssignment {
        self.assignment
    }
    /// Returns the runtime derived by the sole canonical Host target helper.
    #[must_use]
    pub const fn runtime_handle_v4(&self) -> &[u8; 32] {
        &self.runtime
    }
    /// Returns the exact complete Source944 digest, without adopting that DATA.
    #[must_use]
    pub const fn source_digest_v4(&self) -> ObjectDigest {
        self.source
    }
    /// Returns the exact freshly signed Stop request identifier.
    #[must_use]
    pub const fn request_id_v4(&self) -> &[u8; 16] {
        &self.request
    }
    /// Returns the exact forwarding frame commitment for the held-channel join.
    #[must_use]
    pub const fn frame_digest_v4(&self) -> &[u8; 32] {
        &self.frame
    }
    /// Returns only the fresh Stop cleanup cutoff, never a Capture renewal.
    #[must_use]
    pub const fn cutoff_v4(&self) -> u64 {
        self.cutoff
    }
    /// Returns the actual verified fresh Root plan digest.
    #[must_use]
    pub fn plan_digest_v4(&self) -> ObjectDigest {
        self.plan.plan_digest()
    }
    /// Returns the actual verified fresh ownership lease digest.
    #[must_use]
    pub fn lease_digest_v4(&self) -> ObjectDigest {
        self.lease.lease_digest()
    }

    /// Checks a later actual paired sample under this fresh negative permission.
    ///
    /// # Errors
    /// Rejects a different reader or boot, clock rollback/drift, or elapsed
    /// fresh Stop, plan or lease bound. The old Capture deadline is not renewed.
    pub fn require_current_sample_v4(
        &self,
        sample: &RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
        self.clock
            .validate_later_sample(*sample)
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        // The actual first projection remains immutable. This fresh check
        // also rejects a wall jump into the existing lease skew/safety guard;
        // it never extends the first Stop cutoff with a later sample.
        sample
            .conservative_lease_expiry_deadline_data_v2(
                self.lease.lease().authority_expires_seconds(),
                self.lease.lease().maximum_clock_skew_seconds(),
            )
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if sample.boottime_nanoseconds() >= self.cutoff
            || sample.wall_seconds() >= self.plan.plan().expires_seconds()
            || sample.wall_seconds() >= self.lease.lease().authority_expires_seconds()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(())
    }

    /// Compares the same retained original's complete signed Source association.
    ///
    /// # Errors
    /// Rejects another source, assignment, boot or canonical runtime target.
    /// The actual caller must borrow this source from its occupied native owner.
    pub fn require_source_v4(
        &self,
        source: &StorageCaptureGrantSourceV2,
    ) -> Result<(), BrokerAdmissionError> {
        if source.source_digest_v2() != self.source
            || source.lifetime_v2().assignment_v2() != self.assignment
            || source.original_source_v1().host_boot_id() != self.clock.host_boot_id()
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        Ok(())
    }
}

/// Retains the original request model, typed signature causes and once result.
///
/// Empty construction performs no verification, IO, role lending or allocation.
/// Its actual receiver must pay the complete model and trust recipe first.
pub struct StorageCaptureStopInspectionOriginalV4 {
    runtime: Option<
        Result<LiveHostRuntimeEnvelopeDataV2, aos_sandbox_protocol::ProtocolValidationError>,
    >,
    signed: BrokerSignedAdmissionOriginalV4,
    result:
        Option<Result<VerifiedStorageCaptureStopCleanupV4, StorageCaptureStopInspectionErrorV4>>,
    closed: Option<BrokerAdmissionError>,
}

impl Default for StorageCaptureStopInspectionOriginalV4 {
    fn default() -> Self {
        Self {
            runtime: None,
            signed: Default::default(),
            result: None,
            closed: None,
        }
    }
}

impl StorageCaptureStopInspectionOriginalV4 {
    /// Creates inert once-only verification destinations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks the exact fresh Stop with the actual enrolled Storage trust owner.
    ///
    /// # Errors
    /// Retains body, canonical/signature, semantic, assignment, target and time
    /// refusals. Reentry never replaces an earlier model, error or permission.
    pub fn observe_once_v4(
        &mut self,
        authority: &BrokerAuthority,
        wire: &CaptureStopCleanupRequestDataV4<'_>,
        source: &StorageCaptureGrantSourceV2,
        sample: &RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
        if self.runtime.is_some() || self.result.is_some() || self.closed.is_some() {
            self.closed
                .get_or_insert(BrokerAdmissionError::RequestMismatch);
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.runtime = Some(
            aos_sandbox_protocol::decode_canonical_live_host_stop_envelope_data_v4(
                wire.stop_body_v4(),
            ),
        );
        self.result = Some(self.verify_inner_v4(authority, wire, source, sample));
        self.verified_v4()
            .map(|_| ())
            .ok_or(BrokerAdmissionError::RequestMismatch)
    }

    fn verify_inner_v4(
        &mut self,
        authority: &BrokerAuthority,
        wire: &CaptureStopCleanupRequestDataV4<'_>,
        source: &StorageCaptureGrantSourceV2,
        sample: &RawPairedClockSample,
    ) -> Result<VerifiedStorageCaptureStopCleanupV4, StorageCaptureStopInspectionErrorV4> {
        if authority.domain != BrokerDomain::Storage {
            return Err(BrokerAdmissionError::RequestMismatch.into());
        }
        let runtime = self
            .runtime
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(BrokerAdmissionError::RequestMismatch)?;
        let template = runtime.template_v1();
        let semantics =
            aos_sandbox_protocol::semantics::host::canonical_host_template_semantics_v1(template)?;
        let assignment = template.fence().broker_assignment()?;
        let target = aos_sandbox_protocol::semantics::host::runtime_handle_v1(
            assignment.incarnation().as_bytes(),
            assignment.epoch().get(),
            assignment.digest().as_bytes(),
        );
        let target_handle = BrokerResourceHandle::from_bytes(target)
            .map_err(|_| BrokerAdmissionError::RequestMismatch)?;
        if semantics.verb() != BrokerVerb::HostStop
            || semantics.target() != BrokerGrantTarget::Resource(target_handle)
            || template.launch_plan().is_some()
            || assignment != source.lifetime_v2().assignment_v2()
            || wire.source_digest_v4() != source.source_digest_v2().as_bytes()
            || source.original_source_v1().host_boot_id() != sample.host_boot_id()
            || wire.cutoff_v4() <= sample.boottime_nanoseconds()
            || wire.cutoff_v4() > runtime.deadline_boottime_nanoseconds_v1()
        {
            return Err(BrokerAdmissionError::RequestMismatch.into());
        }
        let request = AdmissionRequest {
            audience: BrokerAudience::Host,
            protocol: ProtocolId::HostBroker,
            protocol_version: ProtocolVersion::new(1, 0),
            assignment,
            request_id: *runtime.request_id_v1(),
            request_body: wire.stop_body_v4(),
            descriptor_count: 0,
            verb: semantics.verb(),
            target: semantics.target(),
            argument_commitment: semantics.commitment(),
            request_deadline_boottime_nanoseconds: runtime.deadline_boottime_nanoseconds_v1(),
        };
        let artifacts = wire.authorization_v4();
        let plan = authority.verify_signed_plan_retaining_v4(
            artifacts,
            &request,
            sample,
            Some(&mut self.signed),
        )?;
        plan.match_request(BrokerPlanRequest {
            verb: request.verb,
            target: request.target,
            argument_commitment: request.argument_commitment,
            request_bytes: u32::try_from(request.request_body.len())
                .map_err(|_| BrokerAdmissionError::RequestMismatch)?,
            descriptor_count: 0,
        })
        .map_err(|cause| {
            self.signed.retain_plan_v4(cause);
            BrokerAdmissionError::RequestMismatch
        })?;
        let lease = authority.verify_signed_lease_retaining_v4(
            artifacts,
            &plan,
            &request,
            sample,
            Some(&mut self.signed),
        )?;
        let lease_cutoff = sample
            .conservative_lease_expiry_deadline_data_v2(
                lease.lease().authority_expires_seconds(),
                lease.lease().maximum_clock_skew_seconds(),
            )
            .map_err(|cause| {
                self.signed.retain_lease_v4(cause);
                BrokerAdmissionError::FenceRejected
            })?;
        let signed_cutoff =
            conservative_plan_deadline(plan.plan().expires_seconds(), sample)?.min(lease_cutoff);
        if wire.cutoff_v4() > signed_cutoff {
            return Err(BrokerAdmissionError::FenceRejected.into());
        }
        Ok(VerifiedStorageCaptureStopCleanupV4 {
            assignment,
            runtime: target,
            source: source.source_digest_v2(),
            request: *runtime.request_id_v1(),
            frame: wire.digest_v4(),
            clock: *sample,
            cutoff: wire.cutoff_v4(),
            plan,
            lease,
        })
    }

    /// Borrows only the actual successful once-only verified permission.
    #[must_use]
    pub fn verified_v4(&self) -> Option<&VerifiedStorageCaptureStopCleanupV4> {
        if self.closed.is_some() || self.failure().is_some() {
            return None;
        }
        self.result.as_ref()?.as_ref().ok()
    }

    /// Borrows the earliest actual typed cause without another decode or check.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.runtime
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.signed.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl BrokerAuthority {
    /// Prices the same hostile Host decoder and actual held trust verification.
    ///
    /// Returns `None` for another domain, an excessive frame or overflow. This
    /// passive byte recipe creates no receiving loan or native cleanup authority.
    #[must_use]
    pub fn storage_capture_stop_inspection_receiving_bytes_v4(
        &self,
        bytes: usize,
    ) -> Option<usize> {
        if self.domain != BrokerDomain::Storage
            || bytes > aos_sandbox_protocol::storage_capture_session::stop_cleanup::MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4 {
            return None;
        }
        let model =
            aos_sandbox_protocol::storage_root_export::launch::decoding_receiving_bytes_v2(
                aos_sandbox_protocol::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4)?
                .checked_add(aos_sandbox_protocol::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4)?;
        let plan_bytes = aos_sandbox_protocol::session::MAXIMUM_BROKER_PLAN_BYTES
            .checked_add(aos_sandbox_protocol::session::MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES)?;
        let plan = self
            .plan_anchor
            .verification_receiving_bytes_v1(plan_bytes)?;
        let lease = aos_sandbox_core::ownership_lease::retained::verification_dynamic_bytes_v2(
            &self.lease_anchor,
            aos_sandbox_protocol::session::MAXIMUM_OWNERSHIP_LEASE_BYTES.checked_add(
                aos_sandbox_protocol::session::MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
            )?,
        )?;
        model.checked_add(plan)?.checked_add(lease)?.checked_add(
            std::mem::size_of::<StorageCaptureStopInspectionOriginalV4>().checked_mul(3)?,
        )
    }
}
