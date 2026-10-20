//! Retains the actual pin reply and the same shared subject/codec checks.
//!
//! The bounded decoder keeps partial strings and completed proof DTOs before
//! later semantic refusal. Ordinary callers immediately move their original
//! result/error out; selected callers retain this owner through outer posts.

use super::*;
use crate::pin_worker::PinResultDecodeOriginalV1;
use crate::pin_worker::subject_observation::SubjectLivenessOriginalV1;

pub(super) struct PinResultOriginalV1 {
    liveness: SubjectLivenessOriginalV1,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: worker_subject::MembershipObservationV1,
    membership_result: Option<Result<(), ZfsWorkerError>>,
    decoded: PinResultDecodeOriginalV1,
    decoded_result: Option<Result<(), ZfsWorkerError>>,
    result: Option<Result<(), ZfsWorkerError>>,
    retain: bool,
}

impl PinResultOriginalV1 {
    pub(super) fn new() -> Self { Self::with_disposition(true) }
    pub(super) fn ordinary() -> Self { Self::with_disposition(false) }

    fn with_disposition(retain: bool) -> Self {
        Self {
            liveness: SubjectLivenessOriginalV1::new(), subject: None,
            membership: worker_subject::MembershipObservationV1::new(), membership_result: None,
            decoded: PinResultDecodeOriginalV1::new(), decoded_result: None,
            result: None, retain,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
        anchor: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        if self.result.is_some() { return Err(marker()); }
        self.result = Some(self.observe_inner(response, ready, attempt, anchor));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
    }

    fn observe_inner(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
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
        self.decoded_result = Some(self.decoded.capture_once(response.payload()));
        let Some(result) = self.decoded.output() else { return Err(marker()); };
        if result.attempt_id() != attempt.attempt_id() { return Err(ZfsWorkerError::Authority); }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.liveness.failure()
            .or_else(|| self.subject.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.membership.failure())
            .or_else(|| self.membership_result.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.decoded.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }

    pub(super) fn take_positive(&mut self) -> Option<WorkspacePinWorkerResultV1> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.decoded.take_positive()
    }

    pub(super) fn into_ordinary_result(self) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
        if let Some(Err(error)) = self.subject { return Err(error); }
        if let Some(Err(error)) = self.membership_result { return Err(error); }
        if matches!(self.decoded_result, Some(Err(_))) {
            return self.decoded.into_ordinary_result_v1();
        }
        match self.result {
            Some(Ok(())) => self.decoded.into_ordinary_result_v1(),
            Some(Err(error)) => Err(error),
            None => Err(marker()),
        }
    }

    pub(super) fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(PinResultDecodeOriginalV1::requested_bytes_v1()?)?
            .checked_add(aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(6 * 256)
    }

}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("pin reply validation original retained")
}
