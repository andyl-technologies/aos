//! Shares Root native readiness while keeping upper deadline DATA checks local.

use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use rustix::event::PollFlags;

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

pub(super) fn wait(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), SourceGenesisErrorV1> {
    aos_sandbox_broker::controller_receiving::profile::root_flight::wait_original_root_v1(descriptor, interest, deadline,
    ).map_err(SourceGenesisErrorV1::from)
}

pub(super) fn require_remaining(deadline: Instant) -> Result<Duration, SourceGenesisErrorV1> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(SourceGenesisErrorV1::Stale)
}
