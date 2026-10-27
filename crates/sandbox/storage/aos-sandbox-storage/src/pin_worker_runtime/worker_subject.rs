//! Supplies retained destinations to the existing pin worker subject predicates.
//!
//! The ordinary caller still runs the same membership recipe directly. An
//! entered, genuinely funded selected exchange supplies an actual native sink;
//! the sink retains kernel DATA and never grants physical or service authority.

use super::*;
use aos_sandbox_linux::cgroup::{
    ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1,
};
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdInfo;

pub(super) struct MembershipObservationV1 {
    original: ExactCgroupMembershipReadbackV1,
    result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
}

impl MembershipObservationV1 {
    pub(super) fn new() -> Self {
        Self { original: ExactCgroupMembershipReadbackV1::new(), result: None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure().map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }
}

pub(super) fn capture_membership_v1(
    anchor: &RetainedCgroupAnchor,
    process: &PidFd,
    retained: Option<&mut MembershipObservationV1>,
) -> Result<PidFdInfo, ZfsWorkerError> {
    let Some(retained) = retained else {
        return anchor.verify_exact_membership(process).map_err(Into::into);
    };
    if retained.result.is_some() {
        return Err(ZfsWorkerError::Protocol("pin membership observation is occupied"));
    }
    retained.result = Some(retained.original.capture_once(anchor, process));
    if !matches!(retained.result, Some(Ok(()))) {
        return Err(ZfsWorkerError::Protocol("pin membership native original retained"));
    }
    let Some(Ok(info)) = retained.original.result() else { std::process::abort() };
    Ok(*info)
}
