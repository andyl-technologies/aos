//! Shares catalog reply validation while retaining actual native/model results.
//!
//! Ordinary callers move the same error/model out at the existing function
//! boundary. Selected callers keep this owner through all physical and service
//! posts. No decoded summary or detached export descriptor grants freshness.

use super::*;
use crate::pin_worker::subject_observation::{SubjectLivenessOriginalV1, verify_with_originals_v1};

pub(super) struct CatalogResultOriginalV1 {
    live: SubjectLivenessOriginalV1,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: worker_subject::MembershipObservationV1,
    membership_result: Option<Result<(), ZfsWorkerError>>,
    decoded: Option<Result<WorkspaceCatalogObservationResultV1, ZfsWorkerError>>,
    request_canonical: Vec<u8>,
    matches: Option<Result<bool, ZfsWorkerError>>,
    stat: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    mount: Option<Result<MountId, aos_linux_descriptors::Error>>,
    statvfs: Option<Result<rustix::fs::StatVfs, rustix::io::Errno>>,
    result: Option<Result<(), ZfsWorkerError>>,
    retain: bool,
}

impl CatalogResultOriginalV1 {
    pub(super) fn new() -> Self { Self::with_disposition(true) }
    pub(super) fn ordinary() -> Self { Self::with_disposition(false) }

    fn with_disposition(retain: bool) -> Self {
        Self { live: SubjectLivenessOriginalV1::new(), subject: None,
            membership: worker_subject::MembershipObservationV1::new(), membership_result: None,
            decoded: None, request_canonical: Vec::new(), matches: None,
            stat: None, mount: None, statvfs: None, result: None, retain }
    }

    pub(super) fn observe_once(&mut self, response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject, request: &WorkspaceCatalogObservationRequestV1,
        cgroup: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        if self.result.is_some() { return Err(marker()); }
        self.result = Some(self.observe_inner(response, ready, request, cgroup));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
    }

    fn observe_inner(&mut self, response: &ReceivedDescriptorRecord,
        ready: &KernelAuthorizedRecordSubject, request: &WorkspaceCatalogObservationRequestV1,
        cgroup: &RetainedCgroupAnchor,
    ) -> Result<(), ZfsWorkerError> {
        self.subject = Some(verify_with_originals_v1(ready, response.subject(),
            self.retain.then_some(&mut self.live)));
        if !matches!(self.subject, Some(Ok(()))) { return Err(marker()); }
        self.membership_result = Some(verify_exact_worker_subject_with_originals_v1(
            response.subject(), cgroup, self.retain.then_some(&mut self.membership),
        ));
        if !matches!(self.membership_result, Some(Ok(()))) { return Err(marker()); }
        self.decoded = Some(decode_catalog_observation_result(response.payload()));
        let Some(Ok(result)) = self.decoded.as_ref() else { return Err(marker()); };
        self.matches = Some(if self.retain {
            result.matches_request_retaining_v1(request, &mut self.request_canonical)
        } else { result.matches_request(request) });
        match self.matches.as_ref() {
            Some(Ok(true)) => {}
            Some(Ok(false)) => return Err(ZfsWorkerError::Authority),
            _ => return Err(marker()),
        }
        match (request.exports_mount(), response.descriptors()) {
            (false, []) => {}
            (true, [descriptor]) => {
                let handle = request.root_export().map(|proof| proof.workspace_handle)
                    .or_else(|| request.live_export()).ok_or(ZfsWorkerError::Authority)?;
                let target = request.targets().iter().find(|target| target.workspace_handle() == handle)
                    .ok_or(ZfsWorkerError::Authority)?;
                let WorkspaceCatalogObservationExpectationV1::Present { root_device, root_inode, .. } =
                    target.expectation() else { return Err(ZfsWorkerError::Authority); };
                self.stat = Some(rustix::fs::fstat(descriptor));
                let Some(Ok(stat)) = self.stat.as_ref() else { return Err(marker()); };
                // Preserve the old short circuit: device/inode mismatch does
                // not perform mount-id or live-export statvfs observations.
                if stat.st_dev != root_device || stat.st_ino != root_inode {
                    return Err(ZfsWorkerError::Authority);
                }
                self.mount = Some(MountId::from_fd(descriptor.as_fd()));
                let Some(Ok(mount)) = self.mount.as_ref() else { return Err(marker()); };
                if mount.get() == 0 { return Err(ZfsWorkerError::Authority); }
                if request.live_export().is_some() {
                    self.statvfs = Some(rustix::fs::fstatvfs(descriptor));
                    let Some(Ok(stat)) = self.statvfs.as_ref() else { return Err(marker()); };
                    if !stat.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY
                        | rustix::fs::StatVfsMountFlags::NOSUID | rustix::fs::StatVfsMountFlags::NODEV)
                    { return Err(ZfsWorkerError::Authority); }
                }
            }
            _ => return Err(ZfsWorkerError::Protocol("catalog root export descriptor role is invalid")),
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|error| error as _) }
        self.live.failure().or_else(|| cause(&self.subject))
            .or_else(|| self.membership.failure()).or_else(|| cause(&self.membership_result))
            .or_else(|| cause(&self.decoded)).or_else(|| cause(&self.matches))
            .or_else(|| cause(&self.stat)).or_else(|| cause(&self.mount))
            .or_else(|| cause(&self.statvfs)).or_else(|| cause(&self.result))
    }

    pub(super) fn take_positive(&mut self) -> Option<WorkspaceCatalogObservationResultV1> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        match self.decoded.take() { Some(Ok(value)) => Some(value), _ => std::process::abort() }
    }

    pub(super) fn into_ordinary_result(mut self) -> Result<WorkspaceCatalogObservationResultV1, ZfsWorkerError> {
        if let Some(output) = self.take_positive() { return Ok(output); }
        if let Some(Err(error)) = self.subject.take() { return Err(error); }
        if let Some(Err(error)) = self.membership_result.take() { return Err(error); }
        if let Some(Err(error)) = self.decoded.take() { return Err(error); }
        if let Some(Err(error)) = self.matches.take() { return Err(error); }
        if let Some(Err(error)) = self.stat.take() { return Err(error.into()); }
        if let Some(Err(error)) = self.mount.take() { return Err(error.into()); }
        if let Some(Err(error)) = self.statvfs.take() { return Err(error.into()); }
        match self.result.take() { Some(Err(error)) => Err(error), _ => Err(marker()) }
    }

    pub(super) fn requested_bytes_v1(request: &WorkspaceCatalogObservationRequestV1) -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(request.canonical_construction_bound_v1()?)?
            .checked_add(aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?
            .checked_add(3 * MAXIMUM_CATALOG_OBSERVATION_RESULT_BYTES)?
            .checked_add(2 * std::mem::size_of::<rustix::fs::Stat>())?
            .checked_add(2 * std::mem::size_of::<rustix::fs::StatVfs>())?
            .checked_add(crate::observation_protocol::digest_construction_bytes_v1()?.checked_mul(2)?)?
            .checked_add(2 * std::mem::size_of::<Vec<u8>>() + 5 * 32)?
            .checked_add(8 * 256)
    }

}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("catalog result original retained")
}
