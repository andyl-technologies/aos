//! Ordered admission for the retained buffers inside one guarded Git batch.
//!
//! Two shard groups may run together, each with one loose fallback at a time.
//! These limits complement the operation's isolate graph-buffer permit; they
//! do not acquire another buffer or provider permit. Dropping or failing the
//! collector drops all pending reads and their existing cancellation owners.

use std::future::Future;

use anyhow::{Result, ensure};
use futures_util::{StreamExt as _, TryStreamExt as _};

/// Collects compact results in input order with at most two pending reads.
///
/// # Errors
/// Refuses a limit outside one or two, or propagates the first ordered read
/// failure while dropping the remaining read futures.
pub(crate) async fn collect<T, F>(
    reads: impl IntoIterator<Item = F>,
    maximum: usize,
) -> Result<Vec<T>>
where
    F: Future<Output = Result<T>>,
{
    ensure!(
        (1..=2).contains(&maximum),
        "guarded Git read concurrency exceeds its buffer budget"
    );
    futures_util::stream::iter(reads)
        .buffered(maximum)
        .try_collect()
        .await
}

/// Decodes only the content that can fit a guarded Git projection.
///
/// # Errors
/// Refuses excess inflation, malformed framing, an OID mismatch or content
/// beyond the existing compact reply cap. Framing has a separate 64-byte allowance.
pub(crate) fn decode_projection(
    loose: &[u8],
    oid: aos_registry_surface::object::Oid,
) -> Result<(aos_registry_surface::object::ObjectKind, Vec<u8>)> {
    let maximum = aos_hub_core::storage_work::MAX_GIT_INSPECTION_CONTENT_BYTES;
    let decoded = aos_registry_surface::object::decode_loose_with_limit(
        loose,
        Some(oid),
        maximum as u64 + 64,
    )?;
    ensure!(
        decoded.1.len() <= maximum,
        "Git object projection exceeds the semantic response limit"
    );
    Ok(decoded)
}

#[cfg(test)]
mod tests;
