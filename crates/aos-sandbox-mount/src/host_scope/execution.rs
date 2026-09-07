//! Retained actual-writer identity across a socket-activated Host exchange.

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;

use super::{HostScopeError, Result};

pub(super) struct HostExecution {
    cgroup: RetainedCgroupAnchor,
    subject: KernelAuthorizedRecordSubject,
    info: PidFdInfo,
}

impl HostExecution {
    pub(super) fn new(
        cgroup: RetainedCgroupAnchor,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self> {
        let info = validate_subject(&cgroup, &subject)?;

        Ok(Self {
            cgroup,
            subject,
            info,
        })
    }

    pub(super) fn recheck(&self) -> Result<PidFdInfo> {
        let fresh = validate_subject(&self.cgroup, &self.subject)?;
        if fresh != self.info {
            return Err(HostScopeError::HostIdentity);
        }

        Ok(fresh)
    }

    pub(super) fn validate_response(&self, subject: &KernelAuthorizedRecordSubject) -> Result<()> {
        let before = self.recheck()?;
        let response = validate_subject(&self.cgroup, subject)?;
        let after = self.recheck()?;
        if before != response || after != response {
            return Err(HostScopeError::HostIdentity);
        }

        Ok(())
    }
}

fn validate_subject(
    cgroup: &RetainedCgroupAnchor,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<PidFdInfo> {
    let credentials = subject.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 || !subject.is_alive()? {
        return Err(HostScopeError::HostIdentity);
    }

    let info = cgroup.verify_exact_membership(subject.pidfd())?;
    if info.pid() != info.thread_group_id() {
        return Err(HostScopeError::HostIdentity);
    }

    Ok(info)
}
