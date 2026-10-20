//! Keeps actual repair DTOs through shared subject and semantic validation.
//!
//! Both concrete protocols use the same retained nested-envelope decoder.
//! The private plan carries borrowed actual semantic evidence; it confers
//! no Native stage, effect grant or financial authority.

use super::*;
use crate::pin_worker::result_envelope::PinResultEnvelopeOriginalV1;
use crate::pin_worker::subject_observation::SubjectLivenessOriginalV1;
use crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1;

#[derive(Clone, Copy)]
pub(super) enum RepairPlanV1<'a> {
    Observation { attempt_id: [u8; 16], probe_digest: ObjectDigest },
    Admission(&'a WorkspacePinRepairAdmissionProbeV1),
}

pub(super) enum RepairResultV1 {
    Observation(WorkspacePinRepairObserverResultV1),
    Admission(ValidatedWorkspacePinRepairAdmissionObservationV1),
}

enum EnvelopeOriginalV1 {
    Observation(PinResultEnvelopeOriginalV1<WorkspacePinRepairObserverResultV1>),
    Admission(PinResultEnvelopeOriginalV1<WorkspacePinRepairAdmissionResultV1>),
}

pub(super) struct RepairResultOriginalV1 {
    liveness: SubjectLivenessOriginalV1,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: worker_subject::MembershipObservationV1,
    membership_result: Option<Result<(), ZfsWorkerError>>,
    envelope: EnvelopeOriginalV1,
    decoded: Option<Result<(), ZfsWorkerError>>,
    validated: Option<Result<ValidatedWorkspacePinRepairAdmissionObservationV1, ZfsWorkerError>>,
    result: Option<Result<(), ZfsWorkerError>>,
    retain: bool,
}

impl RepairResultOriginalV1 {
    pub(super) fn new(plan: RepairPlanV1<'_>) -> Self { Self::with_disposition(plan, true) }
    pub(super) fn ordinary(plan: RepairPlanV1<'_>) -> Self { Self::with_disposition(plan, false) }

    fn with_disposition(plan: RepairPlanV1<'_>, retain: bool) -> Self {
        let envelope = match plan {
            RepairPlanV1::Observation { .. } => EnvelopeOriginalV1::Observation(PinResultEnvelopeOriginalV1::new()),
            RepairPlanV1::Admission(_) => EnvelopeOriginalV1::Admission(PinResultEnvelopeOriginalV1::new()),
        };
        Self {
            liveness: SubjectLivenessOriginalV1::new(), subject: None,
            membership: worker_subject::MembershipObservationV1::new(), membership_result: None,
            envelope, decoded: None, validated: None, result: None, retain,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        plan: RepairPlanV1<'_>,
        anchor: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        if self.result.is_some() { return Err(marker()); }
        self.result = Some(self.observe_inner(response, ready, plan, anchor));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
    }

    fn observe_inner(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        plan: RepairPlanV1<'_>,
        anchor: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        self.subject = Some(crate::pin_worker::subject_observation::verify_with_originals_v1(
            ready, response.subject(), self.retain.then_some(&mut self.liveness),
        ));
        if !matches!(self.subject, Some(Ok(()))) { return Err(marker()); }
        self.membership_result = Some(verify_exact_worker_subject_with_originals_v1(
            response.subject(), anchor, self.retain.then_some(&mut self.membership),
        ));
        if !matches!(self.membership_result, Some(Ok(()))) { return Err(marker()); }
        match (&mut self.envelope, plan) {
            (EnvelopeOriginalV1::Observation(original), RepairPlanV1::Observation { attempt_id, probe_digest }) => {
                self.decoded = Some(original.capture_once(response.payload()));
                let Some(result) = original.output() else { return Err(marker()); };
                if result.observation().attempt_id() != attempt_id || result.probe_digest() != probe_digest {
                    return Err(ZfsWorkerError::Authority);
                }
            }
            (EnvelopeOriginalV1::Admission(original), RepairPlanV1::Admission(probe)) => {
                self.decoded = Some(original.capture_once(response.payload()));
                let Some(result) = original.output() else { return Err(marker()); };
                self.validated = Some(ValidatedWorkspacePinRepairAdmissionObservationV1::from_retained_result_v1(probe, result));
                if !matches!(self.validated, Some(Ok(_))) { return Err(marker()); }
            }
            _ => return Err(ZfsWorkerError::Authority),
        }
        Ok(())
    }

    pub(super) fn take_positive(&mut self) -> Option<RepairResultV1> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        match &mut self.envelope {
            EnvelopeOriginalV1::Observation(original) => original.take_positive().map(RepairResultV1::Observation),
            EnvelopeOriginalV1::Admission(_) => match self.validated.take() {
                Some(Ok(result)) => Some(RepairResultV1::Admission(result)),
                _ => std::process::abort(),
            },
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.liveness.failure()
            .or_else(|| self.subject.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.membership.failure())
            .or_else(|| self.membership_result.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| match &self.envelope {
                EnvelopeOriginalV1::Observation(original) => original.failure(),
                EnvelopeOriginalV1::Admission(original) => original.failure(),
            })
            .or_else(|| self.validated.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }

    pub(super) fn into_ordinary_result(mut self) -> Result<RepairResultV1, ZfsWorkerError> {
        if let Some(output) = self.take_positive() { return Ok(output); }
        if let Some(Err(error)) = self.subject { return Err(error); }
        if let Some(Err(error)) = self.membership_result { return Err(error); }
        if matches!(self.decoded, Some(Err(_))) {
            return match self.envelope {
                EnvelopeOriginalV1::Observation(original) => original.into_ordinary_result_v1().map(RepairResultV1::Observation),
                EnvelopeOriginalV1::Admission(original) => match original.into_ordinary_result_v1() {
                    Err(error) => Err(error),
                    Ok(_) => Err(marker()),
                },
            };
        }
        if let Some(Err(error)) = self.validated { return Err(error); }
        match self.result { Some(Err(error)) => Err(error), _ => Err(marker()) }
    }

    pub(super) fn requested_bytes_v1(plan: RepairPlanV1<'_>) -> Option<usize> {
        let nested = match plan {
            RepairPlanV1::Observation { .. } => PinResultEnvelopeOriginalV1::<WorkspacePinRepairObserverResultV1>::requested_bytes_v1()?,
            RepairPlanV1::Admission(_) => PinResultEnvelopeOriginalV1::<WorkspacePinRepairAdmissionResultV1>::requested_bytes_v1()?,
        };
        // Admission's same predicate constructs one expected dataset name.
        let expected_name = if matches!(plan, RepairPlanV1::Admission(_)) { 4096 } else { 0 };
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(nested)?.checked_add(expected_name)?
            .checked_add(aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(6 * 256)
    }

}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("repair reply validation original retained")
}
