//! Joins one actual stream chunk to the already admitted Controller process.
//!
//! Successful byte receipt is not a current-cut proof. The enclosing Root
//! transport retains the chunk and this complete sample until its independent
//! Root/Controller posts and cumulative payload copy have actually succeeded.

use std::error::Error as StdError;

use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use super::{Error, RootControllerMembershipV1, RootSelectedControllerPeerOriginalV1, positive};

#[derive(Default)]
/// Retains one actual subject comparison against the held Controller.
///
/// Successful byte receipt alone is not a currentness or mutation grant.
pub struct RootSelectedControllerSubjectSampleV1 {
    entered: bool,
    body_unwind: Option<Box<dyn std::any::Any + Send>>,
    after_unwind: Option<Box<dyn std::any::Any + Send>>,
    closed: Option<Error>,
    entry: Option<Result<(), Error>>,
    stream_before: Option<Result<(), aos_sandbox_linux::Error>>,
    nomination: Option<Result<(), Error>>,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    alive_binding: Option<Result<(), Error>>,
    membership: RootControllerMembershipV1,
    identity: Option<Result<(), Error>>,
    stream_after: Option<Result<(), aos_sandbox_linux::Error>>,
    completion: Option<Result<(), Error>>,
}

impl RootSelectedControllerSubjectSampleV1 {
    /// Measures the existing subject framing for the fixed Controller context.
    ///
    /// # Errors
    /// Preserves the canonical subject-receive geometry refusal.
    pub fn receive_geometry_v1() -> Result<
        aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        aos_sandbox_linux::seqpacket::SeqpacketError,
    > {
        aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1::for_context_bytes(
            crate::profile_data::delivery::CONTEXT.len(),
        )
    }

    /// Joins one received subject to the same actual admitted Controller.
    ///
    /// # Errors
    /// Retains the original stream, subject, liveness, membership or identity
    /// refusal and independent stream post; reentry never replaces the sample.
    pub fn capture_once(
        &mut self,
        peer: &RootSelectedControllerPeerOriginalV1<'_>,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), Error> {
        if self.entered {
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.entered = true;
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.entry = Some(peer.require_completed());
            self.stream_before = Some(stream.revalidate_original());
            self.nomination = Some((|| {
                positive(&self.entry)?;
                let nominated = chunk.subject().credentials();
                let original = stream.peer().credentials();
                if chunk.socket_context() != crate::profile_data::delivery::CONTEXT.as_bytes()
                    || nominated.pid() != original.pid()
                    || nominated.uid() != original.uid()
                    || nominated.gid() != original.gid()
                {
                    return Err(Error::Service);
                }
                Ok(())
            })());
            if matches!(self.nomination, Some(Ok(()))) {
                self.alive = Some(chunk.subject().is_alive());
                self.alive_binding = Some((|| {
                    if !*positive(&self.alive)? {
                        return Err(Error::Service);
                    }
                    Ok(())
                })());
                if let Some((_, cgroup)) = &peer.cgroup {
                    let _membership = self
                        .membership
                        .capture_once(cgroup, chunk.subject().pidfd());
                    self.identity = Some(self.membership.info().and_then(|info| {
                        super::require_controller_process_identity(
                            peer.startup,
                            stream.peer().credentials().pid(),
                            info,
                        )
                    }));
                }
            }
        }));
        if let Err(payload) = body {
            self.body_unwind = Some(payload);
            self.closed.get_or_insert(Error::Service);
        }
        let after = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.stream_after = Some(stream.revalidate_original());
        }));
        if let Err(payload) = after {
            self.after_unwind = Some(payload);
            self.closed.get_or_insert(Error::Service);
        }
        if let Some(payload) = self.body_unwind.take().or_else(|| self.after_unwind.take()) {
            std::panic::resume_unwind(payload);
        }
        self.completion = Some((|| {
            if self.closed.is_some() {
                return Err(Error::Service);
            }
            positive(&self.entry)?;
            positive(&self.stream_before)?;
            positive(&self.nomination)?;
            positive(&self.alive_binding)?;
            self.membership.info()?;
            positive(&self.identity)?;
            positive(&self.stream_after)?;
            Ok(())
        })());
        positive(&self.completion).map(|_| ())
    }

    /// Requires the same complete subject comparison without another capture.
    ///
    /// # Errors
    /// Refuses missing, failed, repeated or unreturned native subject custody.
    pub fn require_complete_v1(&self) -> Result<(), Error> {
        if self.failure().is_some() || self.body_unwind.is_some() || self.after_unwind.is_some() {
            return Err(Error::Service);
        }
        positive(&self.completion).map(|_| ())
    }

    /// Counts this concrete resident, construction and unwind-control overlap.
    ///
    /// This passive supplier grants no subject entry or receiving permission.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(
                std::mem::size_of::<Result<(), Box<dyn std::any::Any + Send>>>().checked_mul(6)?,
            )?
            .checked_add(std::mem::size_of::<Result<(), Error>>().checked_mul(6)?)
    }

    /// Measures this subject owner and its actual membership native destination.
    ///
    /// The caller separately pays the received chunk/ancillary geometry and its
    /// own enclosing controls before receipt; this supplier grants no IO.
    ///
    /// # Errors
    /// Refuses checked carrier or underlying native supplier overflow.
    pub fn demand_v1() -> Result<aos_sandbox_core::ResourceVector, Error> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let bytes = Self::receiving_construction_bytes_v1()
            .and_then(|bytes| {
                bytes.checked_add(
                aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::
                    dominant_requested_bytes_v1()?,
            )
            })
            .and_then(|bytes| bytes.checked_add(8 * 4096))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(Error::Service)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, 2))
    }

    /// Borrows the earliest actual resident cause without native entry.
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.entry)
            .or_else(|| cause!(self.stream_before))
            .or_else(|| cause!(self.nomination))
            .or_else(|| cause!(self.alive))
            .or_else(|| cause!(self.alive_binding))
            .or_else(|| self.membership.failure())
            .or_else(|| cause!(self.identity))
            .or_else(|| cause!(self.stream_after))
            .or_else(|| cause!(self.completion))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}
