//! Shares one native poll/deadline recipe for fixed subject-stream purposes.
//!
//! Readiness is native DATA, never admission or completion of a role. The
//! retained post-poll BOOTTIME sample refuses late positive readiness before
//! any caller may perform IO or dispose its local native leaf.

use std::error::Error;
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::time::{ClockId, Timespec, clock_gettime};
use crate::cache_current_signer_exchange::CacheCurrentSignerExchangeClosedV1 as Closed;

/// Polls the same borrowed endpoint into its existing native result fields.
///
/// Both the syscall result and returned flags survive an interrupted or failed
/// poll. No owning result or flags tuple crosses the helper's return. The purpose owner keeps them resident while independently owed posts
/// run, then applies its existing readiness and absolute-deadline rules.
/// This function neither retries nor authorizes IO, adoption or disposal.
pub fn poll_fixed_stream_once_v1(
    descriptor: std::os::fd::BorrowedFd<'_>,
    interest: PollFlags,
    timeout: &Timespec,
    result: &mut Option<rustix::io::Result<usize>>,
    flags: &mut Option<PollFlags>,
) {
    let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
    *result = Some(poll(&mut descriptors, Some(timeout)));
    *flags = Some(descriptors[0].revents());
}

/// Retains one original native readiness observation and both deadline samples.
///
/// This carrier has no financial authority or socket constructor. The actual
/// purpose owner supplies its already-held endpoint and genuine absolute cutoff,
/// pays this byte layout, and keeps failures through its independent posts.
#[derive(Default)]
pub struct FixedStreamReadinessOriginalV1 {
    now: Option<Timespec>,
    timeout: Option<Result<Timespec, Closed>>,
    pub(crate) poll: Option<rustix::io::Result<usize>>,
    flags: Option<PollFlags>,
    after_clock: Option<Timespec>,
    after_deadline: Option<Result<Timespec, Closed>>,
    completion: Option<Result<(), Closed>>,
}

impl FixedStreamReadinessOriginalV1 {
    /// Waits for actual readable readiness before the absolute BOOTTIME cutoff.
    ///
    /// # Errors
    /// Retains expired before/after samples, original poll failures or invalid
    /// native readiness. Refuses reentry without replacing its first result.
    pub fn observe_readable_once(&mut self, stream: &RetainedUnixStream, cutoff: u64)
        -> Result<(), Closed>
    {
        self.observe_once(stream, cutoff, PollFlags::IN)
    }

    /// Waits for actual writable readiness before the absolute BOOTTIME cutoff.
    ///
    /// # Errors
    /// Retains expired before/after samples, original poll failures or invalid
    /// native readiness. Refuses reentry without replacing its first result.
    pub fn observe_writable_once(&mut self, stream: &RetainedUnixStream, cutoff: u64)
        -> Result<(), Closed>
    {
        self.observe_once(stream, cutoff, PollFlags::OUT)
    }

    fn observe_once(&mut self, stream: &RetainedUnixStream, cutoff: u64, expected: PollFlags) -> Result<(), Closed> {
        if self.now.is_some() { return Err(Closed::Order); }
        let now = clock_gettime(ClockId::Boottime);
        self.now = Some(now);
        self.timeout = Some(crate::cache_signer_connection::deadline_timeout_v1(now, cutoff)
            .map_err(|_| Closed::Deadline));
        if let Some(Ok(timeout)) = self.timeout.as_ref() {
            poll_fixed_stream_once_v1(
                stream.as_fd(), expected, timeout, &mut self.poll, &mut self.flags,
            );
        }
        if self.poll.is_some() {
            let now = clock_gettime(ClockId::Boottime);
            self.after_clock = Some(now);
            self.after_deadline = Some(crate::cache_signer_connection::deadline_timeout_v1(now, cutoff)
                .map_err(|_| Closed::Deadline));
        }
        self.completion = Some(if matches!(self.poll, Some(Ok(count)) if count != 0)
            && matches!(self.after_deadline, Some(Ok(_)))
            && self.flags.is_some_and(|flags| !flags.contains(PollFlags::NVAL)
                && flags.intersects(expected | PollFlags::HUP | PollFlags::ERR))
        { Ok(()) } else { Err(Closed::Deadline) });
        if matches!(self.completion, Some(Ok(()))) { Ok(()) } else { Err(Closed::Retained) }
    }

    /// Borrows the earliest actual retained timeout, poll or completion cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.timeout).or_else(|| cause(&self.poll))
            .or_else(|| cause(&self.after_deadline)).or_else(|| cause(&self.completion))
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
