//! Retains one prepaid bootstrap or owed-ACK wait on actual native originals.
//!
//! A genuine Source lender supplies its continuously held Netd PIDFD. The
//! socket may have a PID1 activation peer, which cannot replace that donor.
//! The one poll waits for a record or actual donor death without creating a
//! deadline, retry budget, Source, currentness or effect permission. Positive
//! admitted IO uses the unchanged optional native cutoff; only bootstrap and
//! already-owed negative disposition omit it.

use super::{DescriptorSubjectSocket, OriginalObservationV1, SeqpacketError};
use aos_linux_descriptors::Error;
use aos_linux_descriptors::pidfd::PidFd;
use crate::seqpacket::NetworkWorkerNativeCutoffV4;
use crate::seqpacket::RecordBindingError;
use crate::seqpacket::socket_binding::ConnectedSocketBinding;
use rustix::event::{PollFd, PollFlags, poll};
use std::error::Error as StdError;
use std::os::fd::OwnedFd;

/// Reports refusal while the actual wait owner retains every reached cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Network bootstrap wait original retained")]
pub struct NetworkWorkerBootstrapWaitRefusalV3;

#[derive(Clone, Copy, Debug)]
enum First {
    Order,
    Entry,
    BeforeCarrier,
    BeforeDonor,
    BeforeCutoff,
    Poll,
    Readiness,
    AfterDonor,
    AfterCarrier,
    AfterCutoff,
}

/// Owns one same-channel, same-donor native wait and its independent posts.
#[derive(Debug, Default)]
pub struct NetworkWorkerBootstrapWaitOriginalV3 {
    entered: bool,
    origin: Option<ConnectedSocketBinding>,
    entry: Option<SeqpacketError>,
    before_carrier: Option<Result<(), RecordBindingError>>,
    before_cookie: Option<Result<u64, Error>>,
    before_donor: Option<Result<bool, Error>>,
    cutoff: Option<NetworkWorkerNativeCutoffV4>,
    before_cutoff: Option<Result<u64, Error>>,
    timeout: Option<rustix::event::Timespec>,
    native: Option<Result<usize, rustix::io::Errno>>,
    events: Option<[PollFlags; 2]>,
    after_donor: Option<Result<bool, Error>>,
    after_carrier: Option<Result<(), RecordBindingError>>,
    after_cookie: Option<Result<u64, Error>>,
    after_cutoff: Option<Result<u64, Error>>,
    retained_socket: Option<OwnedFd>,
    first: Option<First>,
}

impl NetworkWorkerBootstrapWaitOriginalV3 {
    /// Constructs an inert owner without allocation, IO or native permission.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs exactly one prepaid native poll on the held channel and donor.
    ///
    /// The actual caller supplies its genuine Source's original donor PIDFD,
    /// completes its own Source/peer posts and then performs its separately
    /// paid strict receive. Positive admitted IO supplies the existing cutoff;
    /// its timeout is only the remaining original deadline, with both native
    /// clock observations retained. A wait means readable DATA only. A late
    /// owed wait grants no renewed D or positive effect permission. Interrupted
    /// or failed polls are retained and never retried by this programme.
    ///
    /// # Errors
    /// Refuses reentry, carrier mismatch, donor death, native failure or a
    /// result without readable data and both independent positive posts.
    pub fn observe_once_v3(
        &mut self,
        socket: &mut DescriptorSubjectSocket,
        actual_source_donor: &PidFd,
        original_cutoff: Option<NetworkWorkerNativeCutoffV4>,
    ) -> Result<(), NetworkWorkerBootstrapWaitRefusalV3> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(NetworkWorkerBootstrapWaitRefusalV3);
        }
        self.entered = true;
        let origin = socket.peer.binding;
        self.origin = Some(origin);
        self.cutoff = original_cutoff;
        let mut observation = match OriginalObservationV1::begin(&socket.fd, &mut socket.retention)
        {
            Ok(observation) => observation,
            Err(error) => {
                self.entry = Some(error);
                self.first = Some(First::Entry);
                return Err(NetworkWorkerBootstrapWaitRefusalV3);
            }
        };
        let fd = match observation.fd() {
            Ok(fd) => fd,
            Err(error) => {
                self.entry = Some(error);
                self.first = Some(First::Entry);
                return Err(NetworkWorkerBootstrapWaitRefusalV3);
            }
        };

        self.before_carrier =
            Some(origin.require_current_with_originals_v1(fd, Some(&mut self.before_cookie)));
        self.before_donor = Some(actual_source_donor.is_alive());
        if !matches!(self.before_carrier, Some(Ok(()))) {
            self.first = Some(First::BeforeCarrier);
        }
        if !matches!(self.before_donor, Some(Ok(true))) {
            self.first.get_or_insert(First::BeforeDonor);
        }
        if let Some(cutoff) = self.cutoff {
            self.before_cutoff = Some(cutoff.observe_native_v4());
            match self.before_cutoff.as_ref() {
                Some(Ok(now)) => {
                    let remaining = cutoff.original_deadline_v4().saturating_sub(*now);
                    self.timeout = Some(rustix::event::Timespec {
                        tv_sec: (remaining / 1_000_000_000) as i64,
                        tv_nsec: (remaining % 1_000_000_000) as i64,
                    });
                }
                _ => {
                    self.first.get_or_insert(First::BeforeCutoff);
                }
            }
        }
        if self.first.is_none() {
            let donor_fd = actual_source_donor.as_fd();
            let mut descriptors = [
                PollFd::new(&fd, PollFlags::IN),
                PollFd::new(&donor_fd, PollFlags::IN),
            ];
            self.native = Some(poll(&mut descriptors, self.timeout.as_ref()));
            self.events = Some(descriptors.map(|descriptor| descriptor.revents()));
            if !matches!(self.native, Some(Ok(count)) if count != 0) {
                self.first = Some(First::Poll);
            }
            let valid = self.events.is_some_and(|[channel, donor]| {
                channel.contains(PollFlags::IN)
                    && !channel.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                    && donor.is_empty()
            });
            if !valid {
                self.first.get_or_insert(First::Readiness);
            }
        }

        // Both native posts remain owed after every returned primary failure.
        self.after_donor = Some(actual_source_donor.is_alive());
        self.after_carrier =
            Some(origin.require_current_with_originals_v1(fd, Some(&mut self.after_cookie)));
        if !matches!(self.after_donor, Some(Ok(true))) {
            self.first.get_or_insert(First::AfterDonor);
        }
        if !matches!(self.after_carrier, Some(Ok(()))) {
            self.first.get_or_insert(First::AfterCarrier);
        }
        if let Some(cutoff) = self.cutoff {
            self.after_cutoff = Some(cutoff.observe_native_v4());
            if !matches!(self.after_cutoff, Some(Ok(_))) {
                self.first.get_or_insert(First::AfterCutoff);
            }
        }
        if self.first.is_none() {
            observation.complete();
        }
        drop(observation);
        if self.first.is_some() {
            self.retained_socket = socket.fd.take();
            Err(NetworkWorkerBootstrapWaitRefusalV3)
        } else {
            Ok(())
        }
    }

    /// Borrows the first actual native cause without replacing later posts.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let cause: Option<&(dyn StdError + 'static)> = match self.first? {
            First::Entry => self.entry.as_ref().map(|error| error as _),
            First::BeforeCarrier => self
                .before_cookie
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as _)
                .or_else(|| {
                    self.before_carrier
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|error| error as _)
                }),
            First::BeforeDonor => self
                .before_donor
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::BeforeCutoff => self
                .before_cutoff
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Poll => self.native.as_ref()?.as_ref().err().map(|error| error as _),
            First::AfterDonor => self
                .after_donor
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::AfterCarrier => self
                .after_cookie
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as _)
                .or_else(|| {
                    self.after_carrier
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|error| error as _)
                }),
            First::AfterCutoff => self
                .after_cutoff
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Order | First::Readiness => None,
        };
        cause.or(Some(&NetworkWorkerBootstrapWaitRefusalV3))
    }

    /// Prices this owner, its one poll frame and original native error carriers.
    #[must_use]
    pub fn receiving_bytes_v3() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<[PollFd<'_>; 2]>())?
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?
            .checked_add(4 * std::mem::size_of::<std::io::Error>())?
            .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?.checked_mul(2)?)?
            .checked_add(4 * 256)
    }
}
