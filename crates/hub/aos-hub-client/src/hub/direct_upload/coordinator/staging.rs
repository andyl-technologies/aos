//! Drains bounded independent, already packed staging batches.
//!
//! Small server reply limits can require several control batches within one
//! admitted descriptor wave. Metadata shares the coordinator's provider and
//! byte pools across those batches. Content retains its existing scheduling.

use std::future::Future;

use aos_transfer::direct_upload::DirectClientError;
use futures_util::{StreamExt as _, stream::FuturesUnordered};

// Small advertised control batches still share one admitted descriptor wave
// and the coordinator's global provider limits across independent metadata.
pub(super) const MAX_PARALLEL_BATCHES: usize = 8;

/// Finishes every dispatched neighbor before reporting a failed batch.
///
/// # Errors
/// Refuses an invalid concurrency bound or returns the earliest input error
/// after every dispatched neighbor drains. Observing an error stops admission.
pub(super) async fn run<T, F, Fut>(
    batches: Vec<T>,
    maximum: usize,
    dispatch: F,
) -> Result<(), DirectClientError>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<(), DirectClientError>>,
{
    run_fallible(batches, maximum, dispatch).await
}

pub(super) async fn run_fallible<T, F, Fut, E>(
    batches: Vec<T>,
    maximum: usize,
    mut dispatch: F,
) -> Result<(), E>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: From<DirectClientError>,
{
    if !(1..=MAX_PARALLEL_BATCHES).contains(&maximum) {
        return Err(DirectClientError::Invalid.into());
    }

    let mut batches = batches.into_iter().enumerate();
    let mut active = FuturesUnordered::new();
    for (index, batch) in batches.by_ref().take(maximum) {
        active.push(indexed(index, dispatch(batch)));
    }

    let mut failure = None;
    while let Some((index, result)) = active.next().await {
        if let Err(error) = result {
            if failure
                .as_ref()
                .is_none_or(|(earliest, _)| index < *earliest)
            {
                failure = Some((index, error));
            }
        }

        // A completed batch frees one position without waiting for slower
        // neighbors. After a refusal, drain every dispatched effect before
        // returning; undispatched batches remain untouched for exact retry.
        if failure.is_none() {
            if let Some((index, batch)) = batches.next() {
                active.push(indexed(index, dispatch(batch)));
            }
        }
    }

    match failure {
        Some((_, error)) => Err(error),
        None => Ok(()),
    }
}

async fn indexed<Fut>(index: usize, future: Fut) -> (usize, Fut::Output)
where
    Fut: Future,
{
    (index, future.await)
}

#[cfg(test)]
mod tests;
