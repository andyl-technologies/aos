//! Retains the actual bounded reply write on an already-owned request stream.
//!
//! Packet construction and purpose admission remain in the enclosing private
//! service. Every write uses the same absolute cutoff, and successful scratch
//! retires only after its post-send clock. The endpoint post remains owed even
//! when readiness, send progress or shutdown fails.

use std::error::Error;

use aos_sandbox_broker::cache_signer_connection::{
    CacheSignerConnectionClosedV1, deadline_timeout_v1,
};
use aos_sandbox_broker::fixed_stream_readiness::FixedStreamReadinessOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use rustix::time::{ClockId, Timespec, clock_gettime};

use super::{CacheSignerReceivingClosedV1 as Closed, cause};

#[derive(Clone, Copy)]
enum First {
    Order,
    Before,
    Readiness,
    Write,
    Progress,
    WriteLate,
    Shutdown,
    After,
    AfterLate,
}

#[derive(Default)]
pub(super) struct CacheReplyOriginalV1 {
    before: Option<Result<(), aos_linux_descriptors::Error>>,
    wait: Option<FixedStreamReadinessOriginalV1>,
    write: Option<rustix::io::Result<usize>>,
    progress: Option<Result<(), Closed>>,
    sent: usize,
    write_clock: Option<Timespec>,
    write_deadline: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    shutdown: Option<rustix::io::Result<()>>,
    after: Option<Result<(), aos_linux_descriptors::Error>>,
    after_clock: Option<Timespec>,
    after_deadline: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    completion: Option<Result<(), Closed>>,
    first: Option<First>,
}

impl CacheReplyOriginalV1 {
    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        // Native send installs no descriptors. The request keeps its actual
        // endpoint/peer and the service keeps the complete fixed packet.
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<FixedStreamReadinessOriginalV1>())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    pub(super) fn send_once(
        &mut self,
        stream: &RetainedUnixStream,
        bytes: &[u8],
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.before.is_some() {
            return self.refuse(First::Order);
        }
        self.before = Some(stream.revalidate_original());
        if !matches!(self.before, Some(Ok(()))) {
            self.mark(First::Before);
        }
        while self.first.is_none() && self.sent < bytes.len() {
            self.wait = Some(FixedStreamReadinessOriginalV1::default());
            let waited = self
                .wait
                .as_mut()
                .ok_or(Closed)?
                .observe_writable_once(stream, cutoff);
            if waited.is_err() {
                self.mark(First::Readiness);
                break;
            }
            self.write = Some(rustix::net::send(
                stream.as_fd(),
                &bytes[self.sent..],
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            ));
            self.progress = Some(match self.write {
                Some(Ok(count)) if count != 0 && count <= bytes.len() - self.sent => {
                    self.sent += count;
                    Ok(())
                }
                Some(Err(_)) => {
                    self.first.get_or_insert(First::Write);
                    Err(Closed)
                }
                _ => {
                    self.first.get_or_insert(First::Progress);
                    Err(Closed)
                }
            });
            let now = clock_gettime(ClockId::Boottime);
            self.write_clock = Some(now);
            self.write_deadline = Some(deadline_timeout_v1(now, cutoff));
            if !matches!(self.write_deadline, Some(Ok(_))) {
                self.mark(First::WriteLate);
            }
            if self.first.is_none() {
                // The native send returned, bounded progress was checked and
                // its own cutoff post completed. No descriptor was produced.
                self.wait = None;
                self.write = None;
                self.progress = None;
                self.write_clock = None;
                self.write_deadline = None;
            }
        }
        if self.first.is_none() {
            self.shutdown = Some(rustix::net::shutdown(
                stream.as_fd(),
                rustix::net::Shutdown::Write,
            ));
            if !matches!(self.shutdown, Some(Ok(()))) {
                self.mark(First::Shutdown);
            }
        }
        self.after = Some(stream.revalidate_original());
        if !matches!(self.after, Some(Ok(()))) {
            self.mark(First::After);
        }
        let now = clock_gettime(ClockId::Boottime);
        self.after_clock = Some(now);
        self.after_deadline = Some(deadline_timeout_v1(now, cutoff));
        if !matches!(self.after_deadline, Some(Ok(_))) {
            self.mark(First::AfterLate);
        }
        self.completion = Some(if self.first.is_none() && self.sent == bytes.len() {
            Ok(())
        } else {
            Err(Closed)
        });
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    fn mark(&mut self, stage: First) {
        self.first.get_or_insert(stage);
    }

    fn refuse(&mut self, stage: First) -> Result<(), Closed> {
        self.mark(stage);
        Err(Closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Order => Some(&Closed),
            First::Before => cause(&self.before),
            First::Readiness => self
                .wait
                .as_ref()
                .and_then(FixedStreamReadinessOriginalV1::failure),
            First::Write => cause(&self.write),
            First::Progress => cause(&self.progress),
            First::WriteLate => cause(&self.write_deadline),
            First::Shutdown => cause(&self.shutdown),
            First::After => cause(&self.after),
            First::AfterLate => cause(&self.after_deadline),
        }
    }
}
