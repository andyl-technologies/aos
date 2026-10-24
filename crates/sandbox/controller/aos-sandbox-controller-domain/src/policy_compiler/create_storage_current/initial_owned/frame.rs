//! Runs the sole subject loop while retaining actual upper arm failures.
//!
//! The opaque native frame owns all IO and subject/clock results. This adapter
//! acquires real Initial/L/U only at the two old financial arm slots. Positive
//! before and after owners are disposed by the native provider at their old
//! frontiers; an after-arm refusal cannot suppress the independent late clock.

use aos_sandbox_policy::native::{RootInitialOpenErrorV1, RootInitialSubjectFrameBorrowV1};

use super::{First, RootInitialCurrentActionErrorV1 as ActionError};
use crate::normal_root::ProductionNormalRootStartupV1;
use crate::policy_compiler::create_storage_current::RootCreateStorageCurrentErrorV1 as Error;

pub(super) struct FrameTrace {
    pub(super) before: Option<Result<(), ActionError>>,
    pub(super) subject: Option<Result<(), RootInitialOpenErrorV1>>,
    pub(super) after: Option<Result<(), ActionError>>,
    pub(super) result: Option<Result<(), RootInitialOpenErrorV1>>,
}

impl FrameTrace {
    pub(super) const fn new() -> Self {
        Self {
            before: None,
            subject: None,
            after: None,
            result: None,
        }
    }
}

pub(super) fn receive_frame_v1(
    startup: &ProductionNormalRootStartupV1,
    frame: &mut RootInitialSubjectFrameBorrowV1<'_, '_>,
    trace: &mut FrameTrace,
    first: &mut Option<First>,
) -> Result<(), Error> {
    macro_rules! stage {
        (completed_exact_v1) => {
            frame.completed_exact_v1()
        };
        (require_empty_once_v1) => {{
            trace.result = Some(frame.require_empty_once_v1());
            if !matches!(trace.result, Some(Ok(()))) {
                first.get_or_insert(if frame.failure_v1().is_some() {
                    First::Native
                } else {
                    First::FrameResult
                });
                return Err(Error::Ready);
            }
        }};
        (observe_before_once_v1) => {{
            trace.before = Some(startup.arm_owned_current_frame_before_v1(frame));
            if !matches!(trace.before, Some(Ok(()))) {
                // The native arm may have already retained its richer source;
                // an upper lock refusal remains its own actual owning slot.
                first.get_or_insert(if frame.failure_v1().is_some() {
                    First::Native
                } else {
                    First::FrameBefore
                });
                return Err(Error::Ready);
            }
            trace.result = Some(frame.observe_before_once_v1());
            if !matches!(trace.result, Some(Ok(()))) {
                first.get_or_insert(if frame.failure_v1().is_some() {
                    First::Native
                } else {
                    First::FrameResult
                });
                return Err(Error::Ready);
            }
        }};
        (poll_receive_once_v1) => {
            frame.poll_receive_once_v1()
        };
        (observe_subject_copy_once_v1) => {{
            trace.subject = Some(frame.observe_subject_copy_once_v1());
            if frame.failure_v1().is_some() {
                first.get_or_insert(First::Native);
            } else if matches!(trace.subject, Some(Err(_))) {
                first.get_or_insert(First::FrameSubject);
            }
        }};
        (observe_after_once_v1) => {{
            // Classify the reached read/subject/copy before the later lock.
            if frame.failure_v1().is_some() {
                first.get_or_insert(First::Native);
            }
            trace.after = Some(startup.arm_owned_current_frame_after_v1(frame));
            if !matches!(trace.after, Some(Ok(()))) {
                first.get_or_insert(First::FrameAfter);
                frame.refuse_after_arm_once_v1();
            }
            frame.observe_after_once_v1();
            if frame.failure_v1().is_some() {
                first.get_or_insert(First::Native);
            }
        }};
        (observe_clock_once_v1) => {{
            frame.observe_clock_once_v1();
            if frame.failure_v1().is_some() {
                first.get_or_insert(First::Native);
            }
        }};
        (require_positive_once_v1) => {{
            trace.result = Some(frame.require_positive_once_v1());
            if !matches!(trace.result, Some(Ok(()))) {
                first.get_or_insert(if frame.failure_v1().is_some() {
                    First::Native
                } else {
                    First::FrameResult
                });
                return Err(Error::Ready);
            }
            if matches!(trace.subject, Some(Err(_))) || matches!(trace.after, Some(Err(_))) {
                return Err(Error::Ready);
            }
        }};
        (dispose_positive_once_v1) => {{
            trace.result = Some(frame.dispose_positive_once_v1());
            if !matches!(trace.result, Some(Ok(()))) {
                first.get_or_insert(if frame.failure_v1().is_some() {
                    First::Native
                } else {
                    First::FrameResult
                });
                return Err(Error::Ready);
            }
            // Only this actual positive native disposal clears upper Ok slots.
            *trace = FrameTrace::new();
        }};
    }
    aos_sandbox_broker::root_subject_chunk_programme_v1!(stage)
}
