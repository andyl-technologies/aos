//! Retains one actual Root writer chunk through its genuine Source posts.
//!
//! Complete paid stages separately bookend image, policy and PID1 inputs. This
//! per-chunk recipe joins exact socket SID/creator credentials, live writer
//! pidfd and fixed Root cgroup/process DATA before payload copy and disposal.

use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use crate::signer::SourceReceivingGeometryErrorV1 as ResourceReservationErrorV1;

use super::{profile, positive, require_root_process_identity, Refusal, SourceRootPeerConnectionV1, SourceRootPeerInputsV1};

#[derive(Default)]
pub(crate) struct SourceRootChunkReadbackV1 {
    stream_before: Option<Result<(), aos_sandbox_linux::Error>>,
    nomination: Option<Result<(), Refusal>>,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    alive_binding: Option<Result<(), Refusal>>,
    membership: ExactCgroupMembershipReadbackV1,
    membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    identity: Option<Result<(), Refusal>>,
    stream_after: Option<Result<(), aos_sandbox_linux::Error>>,
    completion: Option<Result<(), Refusal>>,
    closed: Option<Refusal>,
}

impl SourceRootChunkReadbackV1 {
    pub(crate) fn demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let bytes = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(error)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| error())?)
            .with(D::OpenFiles, ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::MetadataEntries, 8))
    }

    pub(crate) fn capture_once(
        &mut self,
        inputs: &SourceRootPeerInputsV1,
        peer: &SourceRootPeerConnectionV1,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), Refusal> {
        if self.completion.is_some() {
            self.closed.get_or_insert(Refusal::Service);
            return Err(Refusal::Service);
        }
        self.stream_before = Some(stream.revalidate_original());
        self.nomination = Some((|| {
            let profile = inputs.profile()?;
            let actual = chunk.subject().credentials();
            let original = stream.peer().credentials();
            if original.uid() != 0 || original.gid() != profile.identities[1]
                || chunk.socket_context() != profile::CONTEXT.as_bytes()
                || actual.pid() != original.pid() || actual.uid() != original.uid()
                || actual.gid() != original.gid()
            {
                return Err(Refusal::Service);
            }
            Ok(())
        })());
        if matches!(self.nomination, Some(Ok(()))) {
            self.alive = Some(chunk.subject().is_alive());
            // A successful dead result is the first policy refusal even if
            // a later independent membership/native observation also fails.
            self.alive_binding = Some(if matches!(self.alive, Some(Ok(true))) {
                Ok(())
            } else {
                Err(Refusal::Service)
            });
            if let Some(anchor) = peer.anchor_data_v1() {
                self.membership_result = Some(self.membership.capture_once(anchor, chunk.subject().pidfd()));
            }
            self.identity = Some((|| {
                let info = self.membership.result().and_then(|result| result.as_ref().ok()).ok_or(Refusal::Service)?;
                require_root_process_identity(stream.peer().credentials().pid(), inputs.profile()?.identities[1], info)
            })());
        }
        self.stream_after = Some(stream.revalidate_original());
        self.completion = Some((|| {
            positive(&self.stream_before)?;
            positive(&self.nomination)?;
            positive(&self.alive_binding)?;
            positive(&self.identity)?;
            positive(&self.stream_after)?;
            Ok(())
        })());
        positive(&self.completion).map(|_| ())
    }

    pub(crate) fn complete(&self) -> bool {
        self.closed.is_none() && matches!(self.completion, Some(Ok(())))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        super::failure(&self.stream_before).or_else(|| super::failure(&self.nomination))
            .or_else(|| super::failure(&self.alive))
            .or_else(|| super::failure(&self.alive_binding))
            .or_else(|| self.membership.failure().map(|error| error as _))
            .or_else(|| super::failure(&self.membership_result))
            .or_else(|| super::failure(&self.identity))
            .or_else(|| super::failure(&self.stream_after))
            .or_else(|| super::failure(&self.completion))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}
