//! Shares the exact live-subject predicate and optional native Result custody.

use super::*;

pub(crate) struct SubjectLivenessOriginalV1 {
    expected: Option<Result<bool, aos_sandbox_linux::Error>>,
    actual: Option<Result<bool, aos_sandbox_linux::Error>>,
}

impl SubjectLivenessOriginalV1 {
    pub(crate) const fn new() -> Self { Self { expected: None, actual: None } }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.expected.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.actual.as_ref()?.as_ref().err())
            .map(|error| error as _)
    }
}

pub(crate) fn verify_with_originals_v1(expected: &KernelAuthorizedRecordSubject,
    actual: &KernelAuthorizedRecordSubject, retained: Option<&mut SubjectLivenessOriginalV1>,
) -> Result<(), ZfsWorkerError> {
    let live = match retained {
        None => expected.is_alive()? && actual.is_alive()?,
        Some(original) => {
            if original.expected.is_some() || original.actual.is_some() {
                return Err(ZfsWorkerError::Protocol("worker subject original is occupied"));
            }
            original.expected = Some(expected.is_alive());
            match original.expected.as_ref() {
                Some(Ok(false)) => false,
                Some(Ok(true)) => {
                    original.actual = Some(actual.is_alive());
                    match original.actual.as_ref() {
                        Some(Ok(value)) => *value,
                        _ => return Err(ZfsWorkerError::Protocol("worker subject native original retained")),
                    }
                }
                _ => return Err(ZfsWorkerError::Protocol("worker subject native original retained")),
            }
        }
    };
    if !live { return Err(ZfsWorkerError::PeerMismatch); }
    if expected.credentials() != actual.credentials()
        || expected.initial_info().pid() != actual.initial_info().pid()
        || expected.initial_info().thread_group_id() != actual.initial_info().thread_group_id()
        || expected.initial_info().cgroup_id() != actual.initial_info().cgroup_id()
    { return Err(ZfsWorkerError::PeerMismatch); }
    Ok(())
}
