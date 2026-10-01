//! Invocation-owned cancellation and bounded dispatch time for copy streams.
//!
//! The caller supplies authenticated plan/lease limits and checks their actual
//! retained floor. This helper adds native timers; it does not issue permission.
//! A blocked native read or write is therefore canceled without waiting for its
//! next chunk. Cancellation never acknowledges the permanent physical turn.

use std::{future::Future, time::Duration};

use anyhow::{ensure, Result};
use futures_util::future::{select, Either};

pub(super) struct DispatchWindow<'a> {
    pub(super) expires_at: i64,
    pub(super) uncertainty: i64,
    pub(super) client_signal: &'a worker::web_sys::AbortSignal,
    pub(super) fresh: &'a dyn Fn() -> Result<()>,
    pub(super) lifetime: super::lifetime::Lifetime,
}

impl DispatchWindow<'_> {
    /// Checks actual cancellation, caller-owned authority and conservative time.
    ///
    /// # Errors
    /// Refuses canceled clients, stale floors or unqualified/expired deadlines.
    pub(super) fn check(&self) -> Result<()> {
        self.lifetime.check()?;
        ensure!(!self.client_signal.aborted(), "copy invocation canceled");
        (self.fresh)()?;
        self.remaining()?;
        Ok(())
    }

    fn remaining(&self) -> Result<u64> {
        ensure!(
            (0..=29).contains(&self.uncertainty),
            "copy clock unqualified"
        );
        let latest = aos_hub_core::clock::now_unix_secs()
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("copy clock overflow"))?;
        let remaining = self
            .expires_at
            .checked_sub(latest)
            .ok_or_else(|| anyhow::anyhow!("copy dispatch deadline overflow"))?;
        // The application plan is at most 30 seconds, with bounded cross-node
        // skew. A caller cannot turn this helper into an unbounded SDK owner.
        ensure!(
            (1..=60).contains(&remaining),
            "copy dispatch expired or unbounded"
        );
        Ok(remaining as u64)
    }

    /// Bounds a native I/O future while retaining its ordinary cancellation owner.
    ///
    /// # Errors
    /// Refuses any failed work, cancellation, deadline or post-await authority check.
    pub(super) async fn run<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.check()?;
        let seconds = self.remaining()?;
        let timeout = async {
            worker::Delay::from(Duration::from_secs(seconds)).await;
            anyhow::bail!("copy dispatch deadline elapsed")
        };
        let cancellation = async {
            loop {
                self.check()?;
                // Each timer belongs to this invocation's I/O context. No
                // callback or waker is retained by another DO or global pool.
                worker::Delay::from(Duration::from_millis(50)).await;
            }
        };
        let stop = async {
            futures_util::pin_mut!(timeout, cancellation);
            match select(timeout, cancellation).await {
                Either::Left((result, _)) | Either::Right((result, _)) => result,
            }
        };
        futures_util::pin_mut!(work, stop);
        match select(work, stop).await {
            Either::Left((result, _)) => {
                self.check()?;
                result
            }
            Either::Right((result, _)) => result,
        }
    }
}
