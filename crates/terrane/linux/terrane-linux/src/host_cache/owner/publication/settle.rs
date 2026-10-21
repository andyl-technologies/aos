//! Completes genuine publication cleanup before transferring cache custody.
//!
//! The local delay is conservative scheduling only. The original worker still
//! checks its registered job and obtains real publisher final-removal replies;
//! elapsed time never acknowledges cleanup or releases durable protection.

use super::{NativeCacheHandoffReport, NativeInlinePublication, NativeManifestPublication};
use crate::host_cache::NativeMetadataOwner;
use std::{io, time::Duration};
use terrane_sdk::store::{Clock, TokioClock};

pub(super) fn cleanup_schedule(interval: Duration, has_sources: bool) -> io::Result<Duration> {
    let now = TokioClock.monotonic();
    if !has_sources {
        return Ok(now);
    }
    // Completion follows every source retirement. Waiting one extra clock tick
    // also covers the publisher's upward-rounded durable Unix-second deadline.
    now.checked_add(interval)
        .and_then(|end| end.checked_add(Duration::from_secs(1)))
        .ok_or_else(|| io::Error::other("publication cleanup schedule overflows"))
}

async fn wait(deadline: Duration) -> io::Result<()> {
    let remaining = deadline.saturating_sub(TokioClock.monotonic());
    if !remaining.is_zero() {
        TokioClock.sleep(remaining).await?;
    }
    Ok(())
}

impl NativeInlinePublication {
    /// Completes source cleanup and transfers this publication into cache custody.
    ///
    /// Closes externally issued producer views, waits out the configured native
    /// retirement interval measured from actual publication completion, obtains
    /// original final-removal acknowledgements and synchronizes cache handoff.
    /// Independently pinned consumers keep their original grants. Cancellation
    /// retains the registered physical job and its funding for reconciliation.
    ///
    /// # Errors
    /// Refuses foreign or changed custody, active producer reads, unavailable
    /// timers or queues, premature publisher deadlines, failed native cleanup,
    /// durability errors and failed original quota reconciliation. An error may
    /// follow accepted effects; it never claims their resources were released.
    pub async fn complete_cache_handoff(
        self,
        owner: &NativeMetadataOwner,
    ) -> io::Result<NativeCacheHandoffReport> {
        self.close_resident_reads(owner).await?;
        wait(self.completion.cleanup_not_before).await?;
        self.finish_retired_sources(owner).await?;
        self.into_cache(owner).await.map_err(io::Error::other)
    }
}

impl NativeManifestPublication {
    /// Completes source cleanup and transfers this manifest into cache custody.
    ///
    /// Preserves reconstruction metadata and independent consumer grants while
    /// closing producer views, waiting out the original configured retirement
    /// interval, completing genuine final removals and synchronizing handoff.
    /// Accepted physical work remains owned after cancellation or an error.
    ///
    /// # Errors
    /// Refuses foreign or changed custody, active producer reads, unavailable
    /// timers or queues, premature publisher deadlines, failed native cleanup,
    /// durability errors and failed original quota reconciliation. An error may
    /// follow accepted effects and requires reconciliation before another attempt.
    pub async fn complete_cache_handoff(
        self,
        owner: &NativeMetadataOwner,
    ) -> io::Result<NativeCacheHandoffReport> {
        self.close_resident_reads(owner).await?;
        wait(self.completion.cleanup_not_before).await?;
        self.finish_retired_sources(owner).await?;
        self.into_cache(owner).await.map_err(io::Error::other)
    }
}
