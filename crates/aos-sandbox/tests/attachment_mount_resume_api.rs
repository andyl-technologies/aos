//! Verifies that exact pending Mount resumption is reachable through public API.

#![cfg(target_os = "linux")]

use aos_proto::aos::sandbox::local::v1::MountAction;
use aos_sandbox::{
    CompletedCurrentAttachmentMountAttemptV1, DurableCurrentAttachmentMountAttemptV1,
    PreparedCurrentAttachmentMountResumeDispatchV1, PreparedCurrentAttachmentMountResumeV1,
};
use aos_sandbox_core::ObjectDigest;

#[test]
fn downstream_code_can_name_attachment_mount_resume_tokens() {
    fn accept_resume_tokens(
        _: Option<PreparedCurrentAttachmentMountResumeV1>,
        _: Option<PreparedCurrentAttachmentMountResumeDispatchV1>,
    ) {
    }

    let plan_digest: fn(&PreparedCurrentAttachmentMountResumeV1) -> ObjectDigest =
        PreparedCurrentAttachmentMountResumeV1::broker_plan_digest;
    let pending_action: fn(&PreparedCurrentAttachmentMountResumeV1) -> MountAction =
        PreparedCurrentAttachmentMountResumeV1::mount_action;
    let issued_action: fn(&DurableCurrentAttachmentMountAttemptV1) -> MountAction =
        DurableCurrentAttachmentMountAttemptV1::mount_action;
    let completed_action: fn(&CompletedCurrentAttachmentMountAttemptV1) -> MountAction =
        CompletedCurrentAttachmentMountAttemptV1::mount_action;

    let _ = (
        accept_resume_tokens,
        plan_digest,
        pending_action,
        issued_action,
        completed_action,
    );
}
