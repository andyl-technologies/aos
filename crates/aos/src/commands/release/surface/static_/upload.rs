//! Bounded immutable file PUTs followed by the unchanged visibility barriers.
//!
//! This scheduler does not implement multipart or durable part resume. It holds
//! each caller-owned upload future until completion, including after a failure.

use std::future::Future;

use anyhow::Result;
use aos_remote::hub_types::RegistryPublicationObjectInput;
use futures_util::{StreamExt as _, stream::FuturesUnordered};

use super::upload_rank;

/// Bounds concurrent snapshots, backend identities and streamed file PUTs.
const IMMUTABLE_UPLOAD_CONCURRENCY: usize = 8;

/// Awaits all immutable prerequisites before any sequential pointer mutation.
///
/// The first observed failure stops new scheduling. Futures already admitted to
/// the immutable window remain owned and are awaited, so error reporting cannot
/// detach a backend write or cross the visibility barrier while writes continue.
pub(super) async fn ordered<'a, F, U>(
    selected: &[&'a RegistryPublicationObjectInput],
    mut upload: F,
    mut completed: impl FnMut(usize),
) -> Result<()>
where
    F: FnMut(&'a RegistryPublicationObjectInput) -> U,
    U: Future<Output = Result<()>>,
{
    let mut ordered = selected.to_vec();
    ordered.sort_by_key(|object| (upload_rank(object), object.path.clone()));
    let immutable_count = ordered
        .iter()
        .take_while(|object| upload_rank(object) == 0)
        .count();
    let mut immutable = ordered[..immutable_count].iter().copied();
    let mut active = FuturesUnordered::new();
    for object in immutable.by_ref().take(IMMUTABLE_UPLOAD_CONCURRENCY) {
        active.push(upload(object));
    }

    let mut failure = None;
    let mut count = 0;
    while let Some(result) = active.next().await {
        match result {
            Ok(()) => {
                count += 1;
                completed(count);
            }
            Err(error) if failure.is_none() => failure = Some(error),
            Err(_) => {}
        }
        if failure.is_none() {
            if let Some(object) = immutable.next() {
                active.push(upload(object));
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }

    // Pointer, info/refs and HEAD retain their prior serial order. The separate
    // timestamp CAS remains after this complete immutable prerequisite barrier.
    for object in &ordered[immutable_count..] {
        upload(object).await?;
        count += 1;
        completed(count);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
