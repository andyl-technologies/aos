//! Retains shared lower membership results for the actual Controller peer.
//!
//! This wrapper adds no membership semantics or authority. The same lower
//! recipe owns both active-file probes and every returned kernel observation.

use std::error::Error as StdError;

use aos_sandbox_linux::cgroup::{
    ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1, RetainedCgroupAnchor,
};
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdInfo;

use super::{Error, positive};

#[derive(Default)]
pub(super) struct RootControllerMembershipV1 {
    readback: ExactCgroupMembershipReadbackV1,
    entered: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    reentry: Option<Error>,
}

impl RootControllerMembershipV1 {
    pub(super) fn capture_once(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        process: &PidFd,
    ) -> Result<(), Error> {
        if self.entered.is_some() {
            self.reentry.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.entered = Some(self.readback.capture_once(anchor, process));
        self.info().map(|_| ())
    }

    pub(super) fn info(&self) -> Result<&PidFdInfo, Error> {
        positive(&self.entered)?;
        if self.failure().is_some() {
            return Err(Error::Service);
        }
        self.readback
            .result()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Error::Service)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.readback
            .failure()
            .map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| {
                self.entered
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            })
            .or_else(|| {
                self.reentry
                    .as_ref()
                    .map(|cause| cause as &(dyn StdError + 'static))
            })
    }
}
