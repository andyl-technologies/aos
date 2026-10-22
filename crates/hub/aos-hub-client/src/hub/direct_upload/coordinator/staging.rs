//! Drains bounded groups of independent, already packed staging batches.
//!
//! Small server reply limits can require several control batches within one
//! admitted descriptor wave. Metadata shares the coordinator's provider and
//! byte pools across those batches. Content retains its existing scheduling.

use std::future::Future;

use aos_transfer::direct_upload::DirectClientError;
use futures_util::future::join_all;

// Small advertised control batches still share one admitted descriptor wave
// and the coordinator's global provider limits across independent metadata.
pub(super) const MAX_PARALLEL_BATCHES: usize = 8;

/// Finishes every dispatched neighbor before reporting a failed batch.
///
/// # Errors
/// Refuses an invalid concurrency bound or returns the first error after its
/// entire dispatched group has drained, without starting another group.
pub(super) async fn run<T, F, Fut>(
    batches: Vec<T>,
    maximum: usize,
    mut dispatch: F,
) -> Result<(), DirectClientError>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<(), DirectClientError>>,
{
    if !(1..=MAX_PARALLEL_BATCHES).contains(&maximum) {
        return Err(DirectClientError::Invalid);
    }

    let mut batches = batches.into_iter();
    loop {
        let active: Vec<_> = batches.by_ref().take(maximum).map(&mut dispatch).collect();
        if active.is_empty() {
            return Ok(());
        }

        // Returning early must not drop neighboring futures with unknown
        // provider effects. A later group starts only after every result is OK.
        for result in join_all(active).await {
            result?;
        }
    }
}

#[cfg(test)]
mod tests;
