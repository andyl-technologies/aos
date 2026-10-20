//! Retains method31's physical reply under the shared worker exchange.
//!
//! The current assignment is authenticated by the sealed request. The reply
//! proves the unchanged physical creation identity; it cannot adopt a new
//! assignment or create a current-publication binding by itself.

use super::*;
use aos_sandbox_guest_protocol::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1;
use crate::pin_worker::subject_observation::SubjectLivenessOriginalV1;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum GuestRootReplyDataV2 {
    Publication(GuestRootPublicationProofV1),
    StartupHealth,
}

pub(super) struct GuestRootResultOriginalV2 {
    liveness: SubjectLivenessOriginalV1,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: worker_subject::MembershipObservationV1,
    membership_result: Option<Result<(), ZfsWorkerError>>,
    decoded: Option<Result<GuestRootReplyDataV2, ZfsWorkerError>>,
    result: Option<Result<(), ZfsWorkerError>>,
}

impl GuestRootResultOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            liveness: SubjectLivenessOriginalV1::new(),
            subject: None,
            membership: worker_subject::MembershipObservationV1::new(),
            membership_result: None,
            decoded: None,
            result: None,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        attempt: Option<&crate::guest_root_attempt::GuestRootPublicationAttemptV2>,
        anchor: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        if self.result.is_some() {
            if matches!(self.result, Some(Ok(()))) { self.result = Some(Err(marker())); }
            return Err(marker());
        }
        self.result = Some(self.observe_inner(response, ready, attempt, anchor));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
    }

    fn observe_inner(
        &mut self,
        response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject,
        attempt: Option<&crate::guest_root_attempt::GuestRootPublicationAttemptV2>,
        anchor: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        self.subject = Some(crate::pin_worker::subject_observation::verify_with_originals_v1(
            ready, response.subject(), Some(&mut self.liveness),
        ));
        if !matches!(self.subject, Some(Ok(()))) { return Err(marker()); }
        self.membership_result = Some(verify_exact_worker_subject_with_originals_v1(
            response.subject(), anchor, Some(&mut self.membership),
        ));
        if !matches!(self.membership_result, Some(Ok(()))) { return Err(marker()); }
        if !response.descriptors().is_empty() { return Err(ZfsWorkerError::PeerMismatch); }
        self.decoded = Some(decode_reply_v2(response.payload(), attempt.map(|attempt| attempt.expected_proof)));
        if matches!(self.decoded, Some(Ok(_))) { Ok(()) } else { Err(marker()) }
    }

    pub(super) fn take_positive(&mut self) -> Option<GuestRootReplyDataV2> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.decoded.take()?.ok()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.liveness.failure()
            .or_else(|| self.subject.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.membership.failure())
            .or_else(|| self.membership_result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.decoded.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(super) fn requested_bytes_v2() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(6 * 256)
    }
}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("guest-root reply original retained")
}

// A passive byte check after the SAME original subject and membership checks.
// A health reply is never interpreted as a publication result or effect proof.
fn decode_reply_v2(bytes: &[u8], expected: Option<GuestRootPublicationProofV1>)
    -> Result<GuestRootReplyDataV2, ZfsWorkerError>
{
    match expected {
        Some(expected) => crate::guest_root_worker::decode_result(bytes).and_then(|proof| {
            if proof == expected { Ok(GuestRootReplyDataV2::Publication(proof)) }
            else { Err(ZfsWorkerError::Authority) }
        }),
        None if bytes == crate::guest_root_worker::HEALTH_RESULT_MAGIC =>
            Ok(GuestRootReplyDataV2::StartupHealth),
        None => Err(ZfsWorkerError::Authority),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reply_cannot_become_a_publication_result_or_accept_a_suffix() {
        let health = crate::guest_root_worker::HEALTH_RESULT_MAGIC;
        assert_eq!(decode_reply_v2(health, None).unwrap(), GuestRootReplyDataV2::StartupHealth);
        let mut suffix = health.to_vec();
        suffix.push(0);
        assert!(decode_reply_v2(&suffix, None).is_err());
        assert!(decode_reply_v2(&health[..7], None).is_err());

        let expected = GuestRootPublicationProofV1 {
            sandbox: [1; 16], incarnation: [2; 16], assignment_epoch: 3,
            assignment_digest: [4; 32], creation_operation: [5; 16], workspace_handle: [6; 32],
            dataset_guid: 7, root_image_digest: [8; 32], package_binding: [9; 32],
            root_tree_digest: [10; 32], feature_mask: 0x003f,
        };
        assert!(decode_reply_v2(health, Some(expected)).is_err());
        let mut publication = b"AOSGPR01".to_vec();
        publication.extend_from_slice(&expected.encode().unwrap());
        assert_eq!(decode_reply_v2(&publication, Some(expected)).unwrap(),
            GuestRootReplyDataV2::Publication(expected));
        assert!(decode_reply_v2(&publication, None).is_err());
        let mut substituted = expected;
        substituted.workspace_handle = [11; 32];
        assert!(decode_reply_v2(&publication, Some(substituted)).is_err());
    }
}
