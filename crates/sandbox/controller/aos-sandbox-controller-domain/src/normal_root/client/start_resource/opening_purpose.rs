//! Selects only the genuine Start originals for the one Root opening engine.
//!
//! Resource openings require a freshly verified Ownership renewal. The separate
//! assignment-input opening precedes that renewal and lends only signed policy
//! DATA. Neither variant accepts a payer callback, caller horizon or native DTO.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::{
    StartAssignmentInputsQueryDataV2, StartAssignmentInputsSubjectDataV2,
    StartAssignmentInputsReplyDataV2, StartAssignmentInputsAdmissionDataV2,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum StartOpeningPurposeV2 {
    Network,
    Mount,
    Storage,
    Host,
    AssignmentInputs,
}

impl StartOpeningPurposeV2 {
    pub(super) fn resource_v2(self) -> Option<&'static [u8; 1]> {
        match self {
            Self::Network => Some(&[HostResourcePurposeDataV1::NetworkPrepare as u8]),
            Self::Mount => Some(&[HostResourcePurposeDataV1::MountNamespace as u8]),
            Self::Storage => Some(&[HostResourcePurposeDataV1::StorageGuestRoot as u8]),
            Self::Host => Some(&[HostResourcePurposeDataV1::HostLaunch as u8]),
            Self::AssignmentInputs => None,
        }
    }

    pub(super) fn reply_v2(self) -> RootReplyPurposeV1 {
        match self {
            Self::AssignmentInputs => RootReplyPurposeV1::StartAssignmentInputs,
            _ => RootReplyPurposeV1::Start,
        }
    }
}

pub(super) enum StartOpeningLoanV2<'loan, 'turn, 'intake> {
    Resource(&'loan mut OriginalStartHostRootLoanV1<'turn, 'intake>),
    AssignmentInputs(&'loan mut crate::OriginalStartAssignmentInputsLoanV2<'turn, 'intake>),
}

impl<'loan, 'turn, 'intake> StartOpeningLoanV2<'loan, 'turn, 'intake> {
    pub(super) fn require_inputs_v2(&self, purpose: StartOpeningPurposeV2,
        controller: &Journal, ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Resource(loan) if purpose.resource_v2().is_some() => {
                loan.require_original_input_data_v1(controller, ready, preparation)?;
                loan.fresh_ownership_lease_v1().map(|_| ())
            }
            Self::AssignmentInputs(loan) if purpose == StartOpeningPurposeV2::AssignmentInputs => {
                loan.require_current_v2(controller)?;
                loan.original_create_v2().require_storage_apply_inputs_v1(ready, preparation)
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(super) fn horizon_v2(&self) -> (RawPairedClockSample, u64) {
        match self {
            Self::Resource(loan) => loan.original_horizon_v1(),
            Self::AssignmentInputs(loan) => loan.original_horizon_v2(),
        }
    }

    pub(super) fn expiry_v2(&self) -> Result<i64, ResourceReservationErrorV1> {
        match self {
            Self::Resource(loan) => loan.original_wall_expiry_v1(),
            Self::AssignmentInputs(loan) => loan.original_wall_expiry_v2(),
        }
    }

    pub(super) fn parent_v2(&self) -> OperationId {
        match self {
            Self::Resource(loan) => loan.parent_operation_v1(),
            Self::AssignmentInputs(loan) => loan.parent_operation_v2(),
        }
    }

    pub(super) fn turn_v2(&self) -> u64 {
        match self {
            Self::Resource(loan) => loan.native_turn_v1(),
            Self::AssignmentInputs(loan) => loan.native_turn_v2(),
        }
    }

    pub(super) fn profile_v2(&self) -> &ProductionControllerNormalRootProfileV1 {
        match self {
            Self::Resource(loan) => loan.profile_v1(),
            Self::AssignmentInputs(loan) => loan.profile_v2(),
        }
    }

    pub(super) fn retained_profile_v2(&self) -> Arc<ProductionControllerNormalRootProfileV1> {
        match self {
            Self::Resource(loan) => loan.retained_profile_v1(),
            Self::AssignmentInputs(loan) => loan.retained_profile_v2(),
        }
    }

    pub(super) fn complete_v2(&mut self, controller: &Journal, demand: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Resource(loan) => loan.require_complete_v1(controller, demand),
            Self::AssignmentInputs(loan) => loan.require_complete_v2(controller, demand),
        }
    }

    pub(super) fn funding_v2(&mut self) -> RootClientLoanV1<'_, 'turn, 'intake, '_, '_, '_> {
        match self {
            Self::Resource(loan) => RootClientLoanV1::Start(loan),
            Self::AssignmentInputs(loan) => RootClientLoanV1::StartAssignmentInputs(loan),
        }
    }

    pub(super) fn account_v2<'journal>(&self, controller: &'journal Journal)
        -> Result<&'journal [u8], ResourceReservationErrorV1> {
        match self {
            Self::Resource(loan) => loan.controller_account_head_v1(controller),
            Self::AssignmentInputs(loan) => loan.controller_account_head_v2(controller),
        }
    }

    pub(super) fn original_create_v2(&self)
        -> &crate::controller_resource_reservation::CreateStorageCompletedIntakeOriginalV1<'_> {
        match self {
            Self::Resource(loan) => loan.original_create_v1(),
            Self::AssignmentInputs(loan) => loan.original_create_v2(),
        }
    }

    pub(super) fn initial_cutoff_v2(&self, origin: RawPairedClockSample,
        original_cutoff: u64, expiry: i64, before: RawPairedClockSample,
    ) -> Result<u64, HistoryErrorV1> {
        match self {
            Self::Resource(loan) => initial_cutoff_v1(origin, original_cutoff, expiry,
                before, loan.fresh_ownership_lease_v1().map_err(|_| HistoryErrorV1::Malformed)?),
            Self::AssignmentInputs(_) => initial_accepted_cutoff_v2(origin, original_cutoff, expiry, before),
        }
    }

    pub(super) fn require_temporal_v2(&self, origin: RawPairedClockSample,
        original_cutoff: u64, expiry: i64, query: StartOpeningQueryV2,
        admission: StartOpeningAdmissionV2, before: RawPairedClockSample,
        after: RawPairedClockSample,
    ) -> Result<u64, HistoryErrorV1> {
        match (self, query, admission) {
            (Self::Resource(loan), StartOpeningQueryV2::Resource(query),
                StartOpeningAdmissionV2::Resource(admission)) => require_temporal_v1(
                    origin, original_cutoff, expiry, query, admission, before, after,
                    loan.fresh_ownership_lease_v1().map_err(|_| HistoryErrorV1::Malformed)?,
                ),
            (Self::AssignmentInputs(_), StartOpeningQueryV2::AssignmentInputs(query),
                StartOpeningAdmissionV2::AssignmentInputs(admission)) => {
                    let initial = initial_accepted_cutoff_v2(origin, original_cutoff, expiry, before)?;
                    require_opening_sample_order_v2(origin, original_cutoff, expiry,
                        query.controller_nonce, query.digest_v2()?, admission.into(), before, after, initial)
                }
            _ => Err(HistoryErrorV1::Malformed),
        }
    }

    pub(super) fn subject_v2<'held>(&'held self, controller: &'held Journal,
        purpose: StartOpeningPurposeV2, ready: &'held [u8],
        preparation: &'held AuthenticatedBrokerMethodOutcomeV1, request_body: &'held [u8],
        parent: &'held [u8; 16], root_closed: &'held [u8], head: &'held [u8],
    ) -> Result<StartOpeningSubjectV2<'held>, ResourceReservationErrorV1> {
        match self {
            Self::Resource(loan) => {
                let purpose = purpose.resource_v2().ok_or(ResourceReservationErrorV1::Conflict)?;
                Ok(StartOpeningSubjectV2::Resource(subject_v1(loan, controller, ready,
                    preparation, request_body, parent, root_closed, head, purpose)?))
            }
            Self::AssignmentInputs(loan) if purpose == StartOpeningPurposeV2::AssignmentInputs => {
                let accepted_start = controller.get(crate::RecordNamespace::Operation, parent)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                Ok(StartOpeningSubjectV2::AssignmentInputs(StartAssignmentInputsSubjectDataV2 {
                    start_operation: parent, accepted_start, canonical_request: loan.canonical_request_v2()?,
                    ready, prepare_request: preparation.request().canonical_packet(),
                    prepare_outcome: preparation.canonical_packet(), root_closed, controller_account: head,
                }))
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

pub(super) enum StartOpeningSubjectV2<'held> {
    Resource(HostLaunchSubjectDataV1<'held>),
    AssignmentInputs(StartAssignmentInputsSubjectDataV2<'held>),
}

impl<'held> StartOpeningSubjectV2<'held> {
    pub(super) fn encoded_bytes_v2(&self) -> Result<usize, HistoryErrorV1> {
        match self {
            Self::Resource(subject) => subject.encoded_bytes_v1(),
            Self::AssignmentInputs(subject) => subject.encoded_bytes_v2(),
        }
    }

    pub(super) fn digest_v2(&self) -> Result<[u8; 32], HistoryErrorV1> {
        match self {
            Self::Resource(subject) => subject.digest_v1(),
            Self::AssignmentInputs(subject) => subject.digest_v2(),
        }
    }

    pub(super) fn stream_v2(self) -> RootSubjectDataV1<'held> {
        match self {
            Self::Resource(subject) => RootSubjectDataV1::Start(subject),
            Self::AssignmentInputs(subject) => RootSubjectDataV1::StartAssignmentInputs(subject),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum StartOpeningQueryV2 {
    Resource(HostLaunchQueryDataV1),
    AssignmentInputs(StartAssignmentInputsQueryDataV2),
}

impl StartOpeningQueryV2 {
    pub(super) fn subject_bytes_v2(self) -> u64 {
        match self {
            Self::Resource(query) => query.subject_bytes,
            Self::AssignmentInputs(query) => query.subject_bytes,
        }
    }

    pub(super) fn encode_v2(self) -> Result<[u8; QUERY_BYTES_V1], HistoryErrorV1> {
        match self {
            Self::Resource(query) => query.encode_v1(),
            Self::AssignmentInputs(query) => query.encode_v2(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum StartOpeningAdmissionV2 {
    Resource(HostResourceAdmissionDataV1),
    AssignmentInputs(StartAssignmentInputsAdmissionDataV2),
}

impl StartOpeningAdmissionV2 {
    pub(super) fn decode_v2(purpose: StartOpeningPurposeV2, bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        match purpose {
            StartOpeningPurposeV2::AssignmentInputs => {
                let reply = StartAssignmentInputsReplyDataV2::decode_v2(bytes)?;
                Ok(Self::AssignmentInputs(StartAssignmentInputsAdmissionDataV2::decode_v2(reply.admission)?))
            }
            _ => {
                let reply = HostResourceReplyDataV1::decode_v1(bytes)?;
                Ok(Self::Resource(HostResourceAdmissionDataV1::decode_v1(reply.admission)?))
            }
        }
    }

    pub(super) fn cutoff_v2(self) -> u64 {
        match self {
            Self::Resource(admission) => admission.cutoff_ns,
            Self::AssignmentInputs(admission) => admission.cutoff_ns,
        }
    }
}

/// Carries only the common paired-clock comparison fields of a decoded reply.
/// No value of this private DATA type can create a live opening or admission.
pub(super) struct OpeningTemporalFieldsV2 {
    controller_nonce: [u8; 16],
    query_digest: [u8; 32],
    original_boot: [u8; 16],
    original_boottime_ns: u64,
    original_cutoff_ns: u64,
    observed_wall_seconds: i64,
    observed_boottime_ns: u64,
    cutoff_ns: u64,
    policy_expires_seconds: i64,
    accepted_expires_seconds: i64,
}

macro_rules! temporal_fields {
    ($data:ty) => {
        impl From<$data> for OpeningTemporalFieldsV2 {
            fn from(data: $data) -> Self {
                Self {
                    controller_nonce: data.controller_nonce, query_digest: data.query_digest,
                    original_boot: data.original_boot, original_boottime_ns: data.original_boottime_ns,
                    original_cutoff_ns: data.original_cutoff_ns, observed_wall_seconds: data.observed_wall_seconds,
                    observed_boottime_ns: data.observed_boottime_ns, cutoff_ns: data.cutoff_ns,
                    policy_expires_seconds: data.policy_expires_seconds,
                    accepted_expires_seconds: data.accepted_expires_seconds,
                }
            }
        }
    };
}

temporal_fields!(HostResourceAdmissionDataV1);
temporal_fields!(StartAssignmentInputsAdmissionDataV2);

pub(super) fn initial_accepted_cutoff_v2(origin: RawPairedClockSample,
    original_cutoff: u64, accepted_expiry: i64, before: RawPairedClockSample,
) -> Result<u64, HistoryErrorV1> {
    origin.validate_later_sample(before).map_err(|_| HistoryErrorV1::Malformed)?;
    let accepted = before.conservative_expiry_deadline_data_v1(accepted_expiry)
        .ok_or(HistoryErrorV1::Malformed)?;
    let cutoff = original_cutoff.min(accepted);
    if before.boottime_nanoseconds() >= cutoff {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(cutoff)
}

pub(super) fn require_opening_sample_order_v2(origin: RawPairedClockSample,
    original_cutoff: u64, accepted_expiry: i64, controller_nonce: [u8; 16],
    query_digest: [u8; 32], admission: OpeningTemporalFieldsV2,
    before: RawPairedClockSample, after: RawPairedClockSample, initial: u64,
) -> Result<u64, HistoryErrorV1> {
    let bad = || HistoryErrorV1::Malformed;
    before.validate_later_sample(after).map_err(|_| bad())?;
    let observed = RawPairedClockSample::new_untrusted(origin.provenance(), admission.original_boot,
        admission.observed_wall_seconds, admission.observed_boottime_ns).map_err(|_| bad())?;
    before.validate_later_sample(observed).map_err(|_| bad())?;
    observed.validate_later_sample(after).map_err(|_| bad())?;
    let policy = before.conservative_expiry_deadline_data_v1(admission.policy_expires_seconds).ok_or_else(bad)?;
    let cutoff = initial.min(policy).min(admission.cutoff_ns);
    if controller_nonce != admission.controller_nonce || query_digest != admission.query_digest
        || admission.original_boot != origin.host_boot_id()
        || admission.original_boottime_ns != origin.boottime_nanoseconds()
        || admission.original_cutoff_ns != original_cutoff
        || admission.accepted_expires_seconds != accepted_expiry
        || after.wall_seconds() >= accepted_expiry
        || after.wall_seconds() >= admission.policy_expires_seconds || after.boottime_nanoseconds() >= cutoff {
        return Err(bad());
    }
    Ok(cutoff)
}
