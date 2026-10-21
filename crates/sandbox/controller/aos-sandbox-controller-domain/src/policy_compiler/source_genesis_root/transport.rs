//! Shares Root native readiness while keeping upper deadline DATA checks local.

use std::time::{Duration, Instant};


use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;


pub(super) fn require_remaining(deadline: Instant) -> Result<Duration, SourceGenesisErrorV1> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(SourceGenesisErrorV1::Stale)
}
