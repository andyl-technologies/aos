//! Bounded destination-copy waves retaining exact original part geometry.

use std::future::Future;

use anyhow::{ensure, Result};
use aos_hub_db::direct_upload::DirectManifestPart;
use futures_util::future::join_all;

use crate::external_object::MAX_PENDING_DESTINATION_PARTS;

/// Copies independent original parts without canceling dispatched neighbors.
///
/// A failed wave is fully drained before returning its error. Later waves and
/// destination completion remain undispatched; successful receipts retain their
/// original order for the final manifest. Provider admission still enforces the
/// shared capacity and original Native permission at each actual dispatch.
///
/// # Errors
/// Refuses changed part geometry or any failed copy.
pub(super) async fn copy_parts<'a, F, T>(
    parts: &'a [DirectManifestPart],
    copy: F,
) -> Result<Vec<DirectManifestPart>>
where
    F: Fn(&'a DirectManifestPart) -> T,
    T: Future<Output = Result<DirectManifestPart>>,
{
    // Pipeline compact journal controls up to the journal's own pending-turn
    // bound. Object and provider limits govern different resources: every
    // actual Fetch still acquires the shared, metadata-reserving provider pool.
    let mut copied = Vec::with_capacity(parts.len());
    for wave in parts.chunks(MAX_PENDING_DESTINATION_PARTS) {
        let results = join_all(wave.iter().map(&copy)).await;
        for (original, result) in wave.iter().zip(results) {
            let part = result?;
            ensure!(
                part.part == original.part,
                "direct external copied original descriptor changed"
            );
            copied.push(part);
        }
    }
    Ok(copied)
}

#[cfg(test)]
mod tests;
