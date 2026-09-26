//! Protects controller custody of Mount source acquisitions used by attachments.
//!
//! This module adds a nonauthorizing planning layer over one exact joined Mount
//! resource/source inventory and append-only controller records for three
//! custody milestones: Acquire, consume the source during detached creation,
//! and Release. A rowless Acquire can be closed by an exact cancellation
//! completion before a superseding lineage begins. This module never carries a
//! file descriptor, constructs provider authority, or dispatches a broker
//! request.
//!
//! Namespace 43 stores `AOSASA01` attempt plans. Namespace 44 stores
//! `AOSASC01` completions. Both are bounded, digest protected, and linked by an
//! exact predecessor-completion digest per attachment.

mod custody;
mod dispatch_custody;
mod format;
mod planning;
mod preparation;

pub use custody::{
    AttachmentSourceAttemptKindV1, AttachmentSourceAttemptOutcomeV1,
    AttachmentSourceCompletionOutcomeV1, DurableAttachmentSourceAttemptV1,
    DurableAttachmentSourceCompletionV1, ExpiredAttachmentSourceAcquireV1,
    PostDeadlineRowlessAcquireV1,
};
pub use dispatch_custody::{
    ClosedControllerLiveConsumerSourceV1, DurableCurrentAttachmentSourceDispatchV1,
};
pub use planning::{
    AttachmentSourceActionV1, AttachmentSourceBoundsV1, AttachmentSourceError,
    CurrentAttachmentSourcePlanV1,
};
pub use preparation::{
    PreparedCurrentAttachmentSourceAcquireV1, PreparedCurrentAttachmentSourceDispatchV1,
    PreparedCurrentAttachmentSourceReleaseDispatchV1, PreparedCurrentAttachmentSourceReleaseV1,
    PreparedCurrentAttachmentSourceResumeV1,
};

pub(crate) use custody::{
    begin_expired_acquire, bind_post_deadline_rowless, current_predecessor, record_completion,
    record_current_attempt, record_recovered_current_consume, record_rowless_cancellation,
    recover_open_attempt, validate_attempt_namespace, validate_completion_namespace,
};
pub(crate) use dispatch_custody::validate_namespace as validate_dispatch_namespace;
pub(crate) use planning::{plan_current, plan_current_with_live_source};
pub(crate) use preparation::{
    prepare_current_acquire, prepare_current_release, prepare_current_resume,
};
