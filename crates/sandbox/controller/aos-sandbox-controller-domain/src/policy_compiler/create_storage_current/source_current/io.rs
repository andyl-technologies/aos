//! Uses the shared finite original-deadline stream IO custody engine.

pub(super) use crate::policy_compiler::bounded_stream_io::{
    FixedDeadlineStreamIoV1 as FixedSourceCurrentIoV1,
    DeadlineStreamDirectionV1 as SourceIoDirectionV1,
};
