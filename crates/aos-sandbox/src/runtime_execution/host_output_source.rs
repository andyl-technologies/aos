//! Signed, lease-intersected source for provisional Host output custody.
//!
//! AOSCIR01 is Controller-origin structural data. This adapter matches its
//! exact bytes to a Host-audience broker-plan/lease intersection and checks
//! the current Host assignment and boot before the runtime owner may reserve
//! AOSEOR02. The Host broker must still durably admit its local effect intent
//! before invoking the protected store; this value is not execution authority.

use aos_sandbox_core::{
    BrokerAdmissionIntersection, BrokerAssignment, BrokerGrantTarget, BrokerVerb, NodeId,
    ObjectDigest, RawPairedClockSample,
};
use aos_sandbox_protocol::semantics::host_output_reserve_grant_v1;

use crate::controller_execution_preissue::ControllerExecutionReserveSourceV1;

/// Rejects a provisional source without an exact signed grant and current Host context.
#[derive(Debug, thiserror::Error)]
pub enum HostOutputReserveSourceErrorV1 {
    /// The Controller carrier disagrees with the matched Host grant or runtime.
    #[error("Host output reserve source does not match signed current authority")]
    Mismatch,
}

/// Retains an exact Controller carrier matched to a Host broker-plan/lease intersection.
///
/// Only [`verify_host_output_reserve_source_v1`] constructs this type. Its
/// private fields prevent a raw AOSCIR01 carrier from reaching the protected
/// reservation path without the matched grant and current Host boot check.
pub struct VerifiedHostOutputReserveSourceV1 {
    source: ControllerExecutionReserveSourceV1,
    original_request_id: [u8; 16],
    assignment_digest: ObjectDigest,
    host_boot_id: [u8; 16],
    plan_digest: ObjectDigest,
    semantic_request_digest: ObjectDigest,
}

impl VerifiedHostOutputReserveSourceV1 {
    pub(crate) const fn source(&self) -> &ControllerExecutionReserveSourceV1 {
        &self.source
    }

    pub(crate) const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }

    pub(crate) const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    pub(crate) const fn host_boot_id(&self) -> [u8; 16] {
        self.host_boot_id
    }

    pub(crate) const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    pub(crate) const fn semantic_request_digest(&self) -> ObjectDigest {
        self.semantic_request_digest
    }
}

/// Matches one exact AOSCIR01 carrier to an authenticated Host reserve attempt.
///
/// Parent capacity remains Controller-sourced through the signed carrier. The
/// Host independently checks its current assignment/boot and accounts the
/// capacity under its own protected ledger; this does not establish physical
/// capture backing or authorize an execution.
///
/// # Errors
///
/// Rejects a stale boot/deadline, assignment, method, or plan/lease request
/// semantic mismatch.
pub fn verify_host_output_reserve_source_v1(
    source: ControllerExecutionReserveSourceV1,
    assignment: BrokerAssignment,
    host_node: NodeId,
    intersection: &BrokerAdmissionIntersection,
    current_clock: RawPairedClockSample,
) -> Result<VerifiedHostOutputReserveSourceV1, HostOutputReserveSourceErrorV1> {
    let request_id = *intersection.request_id();
    let semantic = host_output_reserve_grant_v1(assignment, request_id, &source.canonical_bytes())
        .map_err(|_| HostOutputReserveSourceErrorV1::Mismatch)?;
    let deadline = source.preissue().deadline_boottime_nanoseconds();
    let host_boot_id = current_clock.host_boot_id();
    if intersection.verb() != BrokerVerb::HostReserveExecutionOutput
        || intersection.target() != BrokerGrantTarget::Assignment
        || intersection.request_digest() != semantic.commitment().digest()
        || intersection.host_boot_id() != &host_boot_id
        || current_clock.wall_seconds() >= intersection.plan_expires_seconds()
        || current_clock.wall_seconds() >= intersection.authority_expires_seconds()
        || current_clock.boottime_nanoseconds() >= intersection.fail_stop_boottime_nanoseconds()
        || current_clock.boottime_nanoseconds() >= deadline
        || source.preissue().host_boot_id() != host_boot_id
        || source.sandbox() != assignment.sandbox()
        || source.incarnation() != assignment.incarnation()
        || source.node() != host_node
        || source.assignment_epoch() != assignment.epoch().get()
        || source.desired_generation() != assignment.desired_generation().get()
        || source.assignment_manifest_digest() != assignment.digest()
    {
        return Err(HostOutputReserveSourceErrorV1::Mismatch);
    }

    Ok(VerifiedHostOutputReserveSourceV1 {
        source,
        original_request_id: request_id,
        assignment_digest: assignment.digest(),
        host_boot_id,
        plan_digest: intersection.plan_digest(),
        semantic_request_digest: intersection.request_digest(),
    })
}
