//! Storage-owned inspection of the original signed Host launch.
//!
//! This comparison uses the same enrolled Root-plan and Ownership trust
//! engines as ordinary broker admission. It creates no local lease, fence,
//! pending effect, worker allowance, or Host execution permission. Actual
//! Storage export still requires its genuine financial/native owner and fresh
//! protected catalog and physical publication checks.

use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerGrantTarget, BrokerPlanRequest, BrokerVerb,
    ObjectDigest, ProtocolId, ProtocolVersion, RawPairedClockSample, VerifiedBrokerPlan,
    VerifiedOwnershipLease,
};
use aos_sandbox_protocol::LiveHostRuntimeEnvelopeDataV2;
use aos_sandbox_protocol::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2;
use aos_sandbox_protocol::semantics::host::canonical_host_template_semantics_v1;
use aos_sandbox_protocol::storage_root_export::launch::StorageRootLaunchExportRequestV2;

use super::{AdmissionRequest, BrokerAdmissionError, BrokerAuthority, conservative_plan_deadline};
use crate::record::BrokerDomain;

/// Retains the original structural or shared-authority comparison refusal.
#[derive(Debug, thiserror::Error)]
pub enum StorageHostLaunchExportInspectionErrorV2 {
    /// The complete original Host body failed the existing DATA decoder.
    #[error(transparent)]
    Body(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// The complete typed Host body has no canonical launch semantics.
    #[error(transparent)]
    Semantics(#[from] aos_sandbox_protocol::semantics::host::HostSemanticError),
    /// The typed assignment cannot form the existing canonical Core identity.
    #[error(transparent)]
    Assignment(#[from] aos_sandbox_core::InvalidBrokerAuthorizationPlan),
    /// The shared signature, signed-grant or original-cutoff check failed.
    #[error(transparent)]
    Authority(#[from] BrokerAdmissionError),
}

/// Retains a signature-checked comparison for one original Host root export.
///
/// Private construction requires the actual Storage authority's enrolled trust
/// anchors. This owner cannot be used as `VerifiedBrokerAdmission` and carries
/// no local lease/effect record or physical worker loan. Its deadline is exactly
/// the forwarded original cutoff after checking every signed upper bound.
#[derive(Debug)]
pub struct VerifiedStorageHostLaunchExportV2 {
    runtime: LiveHostRuntimeEnvelopeDataV2,
    plan: VerifiedBrokerPlan,
    lease: VerifiedOwnershipLease,
    assignment: BrokerAssignment,
    current_guest_root_publication: Option<StorageGuestRootCurrentPublicationDataV2>,
    original_cutoff: u64,
    frame_digest: [u8; 32],
    clock: RawPairedClockSample,
}

impl VerifiedStorageHostLaunchExportV2 {
    /// Borrows the same parsed header and complete inert Host body DATA.
    #[must_use]
    pub const fn runtime_data_v2(&self) -> &LiveHostRuntimeEnvelopeDataV2 {
        &self.runtime
    }

    /// Returns the exact assignment covered by both signed authorities.
    #[must_use]
    pub const fn assignment_v2(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Borrows the exact current-publication record committed by the signed Host body.
    ///
    /// Storage must compare this against its protected completed method31
    /// record before and after native export. It is not a physical-root permit.
    #[must_use]
    pub const fn current_guest_root_publication_v2(&self)
        -> Option<&StorageGuestRootCurrentPublicationDataV2>
    {
        self.current_guest_root_publication.as_ref()
    }

    /// Returns the actual original paired sample's boot identifier as DATA.
    #[must_use]
    pub const fn host_boot_id_v2(&self) -> [u8; 16] {
        self.clock.host_boot_id()
    }

    /// Returns the original cutoff without deriving a new execution horizon.
    #[must_use]
    pub const fn original_cutoff_v2(&self) -> u64 {
        self.original_cutoff
    }

    /// Returns the complete forwarding-frame digest for same-request joins.
    #[must_use]
    pub const fn request_digest_v2(&self) -> [u8; 32] {
        self.frame_digest
    }

    /// Returns the exact authenticated Root-plan digest.
    #[must_use]
    pub const fn plan_digest_v2(&self) -> ObjectDigest {
        self.plan.plan_digest()
    }

    /// Returns the exact authenticated original ownership-lease digest.
    #[must_use]
    pub const fn lease_digest_v2(&self) -> ObjectDigest {
        self.lease.lease_digest()
    }

    /// Compares a later actual paired sample without renewing any authority.
    ///
    /// The caller must obtain that sample through its retained native owner;
    /// this comparison performs no IO and does not establish native currentness.
    ///
    /// # Errors
    /// Rejects another boot, elapsed original cutoff, backward observation, or
    /// either signed wall expiry being reached.
    pub fn require_current_sample_v2(
        &self,
        sample: &RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
        if sample.host_boot_id() != self.clock.host_boot_id()
            || sample.boottime_nanoseconds() < self.clock.boottime_nanoseconds()
            || sample.boottime_nanoseconds() >= self.original_cutoff
            || sample.wall_seconds() < self.clock.wall_seconds()
            || sample.wall_seconds() >= self.plan.plan().expires_seconds()
            || sample.wall_seconds() >= self.lease.lease().authority_expires_seconds()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(())
    }
}

impl BrokerAuthority {
    /// Bounds original launch verification against this actual enrolled trust owner.
    ///
    /// This passive byte sum prices the complete Host/Guardian artifact graph
    /// and both exact held verification policies before decoding. It grants no
    /// funding, receiver, role or effect. Native/State/catalog/worker footprints
    /// and the actual compiled upper owner must be admitted separately.
    /// `None` reports overflow, another owning domain, or an excessive frame.
    #[must_use]
    pub fn storage_host_launch_export_receiving_bytes_v2(
        &self,
        encoded_bytes: usize,
    ) -> Option<usize> {
        if self.domain != BrokerDomain::Storage {
            return None;
        }
        let models = aos_sandbox_protocol::storage_root_export::launch::
            decoding_receiving_bytes_v2(encoded_bytes)?;
        let plan = self.plan_anchor.verification_receiving_bytes_v1(encoded_bytes)?;
        let lease = aos_sandbox_core::ownership_lease::retained::
            verification_dynamic_bytes_v2(&self.lease_anchor, encoded_bytes)?;
        models.checked_add(plan)?.checked_add(lease)?
            .checked_add(std::mem::size_of::<VerifiedStorageHostLaunchExportV2>().checked_mul(3)?)
    }

    /// Checks original HostLaunch artifacts using the actual Storage trust owner.
    ///
    /// The complete original body supplies its own header and semantics through
    /// the sole peer-free DATA decoder. This method checks signatures and bounds
    /// without admitting a Host/Storage effect or creating a local lease/fence.
    /// The native Host peer, actual Storage funding, fresh catalog/publication,
    /// descriptor custody and independently owed posts remain mandatory.
    ///
    /// # Errors
    /// Rejects another owning domain, non-Launch body, changed assignment/proof,
    /// invalid signatures or lease, unmatched semantics, or a cutoff beyond the
    /// original Apply request or either conservative signed wall-time bound.
    pub fn inspect_storage_host_launch_export_v2(
        &self,
        wire: &StorageRootLaunchExportRequestV2<'_>,
        current_clock: &RawPairedClockSample,
    ) -> Result<VerifiedStorageHostLaunchExportV2, StorageHostLaunchExportInspectionErrorV2> {
        if self.domain != BrokerDomain::Storage {
            return Err(BrokerAdmissionError::RequestMismatch.into());
        }
        let runtime = aos_sandbox_protocol::decode_live_host_runtime_envelope_data_v2(
            wire.original_apply(),
        )?;
        let template = runtime.template_v1();
        let semantics = canonical_host_template_semantics_v1(template)?;
        let assignment = template.fence().broker_assignment()?;
        let launch = template.launch_plan().ok_or(BrokerAdmissionError::RequestMismatch)?;
        let proof = &wire.request().proof;
        let cutoff = wire.request().deadline_boottime_nanoseconds;
        if semantics.verb() != BrokerVerb::HostLaunch
            || semantics.target() != BrokerGrantTarget::Assignment
            || proof.sandbox != *template.fence().sandbox_id()
            || proof.incarnation != *template.fence().incarnation_id()
            || proof.assignment_epoch != template.fence().assignment_epoch()
            || proof.workspace_handle != *launch.workspace_handle()
            || proof.root_image_digest != *launch.root_image().digest().as_bytes()
            || cutoff <= current_clock.boottime_nanoseconds()
            || cutoff > runtime.deadline_boottime_nanoseconds_v1()
        {
            return Err(BrokerAdmissionError::RequestMismatch.into());
        }
        let current_guest_root_publication = launch.current_guest_root_publication_v2().copied();
        match current_guest_root_publication.as_ref() {
            Some(current) => {
                if current.current_assignment_v2()? != assignment
                    || current.arguments_v2().canonical_bytes()[104..136] != proof.workspace_handle
                    || current.arguments_v2().canonical_bytes()[136..152] != proof.creation_operation
                {
                    return Err(BrokerAdmissionError::RequestMismatch.into());
                }
            }
            None if proof.assignment_digest == *template.fence().assignment_digest() => {}
            None => return Err(BrokerAdmissionError::RequestMismatch.into()),
        }
        let request = AdmissionRequest {
            audience: BrokerAudience::Host,
            protocol: ProtocolId::HostBroker,
            protocol_version: ProtocolVersion::new(1, 0),
            assignment,
            request_id: *runtime.request_id_v1(),
            request_body: wire.original_apply(),
            descriptor_count: 0,
            verb: semantics.verb(),
            target: semantics.target(),
            argument_commitment: semantics.commitment(),
            request_deadline_boottime_nanoseconds: runtime.deadline_boottime_nanoseconds_v1(),
        };
        let artifacts = wire.authorization();
        let plan = self.verify_signed_plan(artifacts, &request, current_clock)?;
        plan.match_request(BrokerPlanRequest {
            verb: request.verb,
            target: request.target,
            argument_commitment: request.argument_commitment,
            request_bytes: u32::try_from(request.request_body.len())
                .map_err(|_| BrokerAdmissionError::RequestMismatch)?,
            descriptor_count: 0,
        }).map_err(|_| BrokerAdmissionError::RequestMismatch)?;
        let lease = self.verify_signed_lease(artifacts, &plan, &request, current_clock)?;
        if current_guest_root_publication.as_ref().is_some_and(|current|
            current.ownership_lease_digest_v2() != lease.lease_digest().as_bytes())
        {
            return Err(BrokerAdmissionError::RequestMismatch.into());
        }
        let signed_cutoff = conservative_plan_deadline(plan.plan().expires_seconds(), current_clock)?
            .min(conservative_plan_deadline(lease.lease().authority_expires_seconds(), current_clock)?);
        if cutoff > signed_cutoff {
            return Err(BrokerAdmissionError::FenceRejected.into());
        }
        Ok(VerifiedStorageHostLaunchExportV2 {
            runtime,
            plan,
            lease,
            assignment,
            current_guest_root_publication,
            original_cutoff: cutoff,
            frame_digest: wire.digest(),
            clock: *current_clock,
        })
    }
}
