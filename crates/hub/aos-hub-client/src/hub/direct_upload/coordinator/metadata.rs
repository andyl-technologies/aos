//! Admits replacement metadata batches only when prior descriptor custody ends.
//!
//! Batch descriptions carry no admitted sources. At most eight batches own
//! sources concurrently, with at most 64 descriptors across those batches.
//! Provider streams retain the coordinator's existing shared capacity limits.

use std::future::Future;

use aos_transfer::direct_upload::SourceWaveBudget;

use super::{
    DirectClientError, DirectDependencyPhase, DirectStageFile, DirectUploadCoordinator,
    MAX_DIRECT_BATCH_ITEMS, staging,
};

impl DirectUploadCoordinator {
    /// Stages single-part metadata through lazily admitted bounded batches.
    ///
    /// The preparer opens one original source per description. Descriptions may
    /// cover the full inventory; source descriptors are retained only by active
    /// batches. Every dispatched batch drains after a preparation or staging
    /// failure, and no new batch starts after that failure is observed.
    ///
    /// # Errors
    /// Returns preparation or staging errors, or refuses a content source,
    /// multipart metadata, or invalid advertised batch geometry.
    pub async fn stage_metadata_batches<T, F, Fut, E>(
        &self,
        descriptions: Vec<T>,
        prepare: F,
    ) -> Result<(), E>
    where
        F: Fn(T) -> Fut,
        Fut: Future<Output = Result<DirectStageFile, E>>,
        E: From<DirectClientError>,
    {
        let batch_items = self.capabilities.maximum_batch_items as usize;
        let prepare = &prepare;
        run_batches(
            descriptions,
            batch_items,
            |description| async move {
                let file = prepare(description).await?;
                if file.phase == DirectDependencyPhase::Content
                    || file.source.byte_size() > file.source.part_size()
                {
                    return Err(DirectClientError::Invalid.into());
                }
                Ok(file)
            },
            // A control-byte limit may split this admitted batch again. Keep
            // those pieces serial so nested scheduling cannot multiply slots.
            |files| async move { self.stage_with_parallelism(files, 1).await.map_err(E::from) },
        )
        .await
    }
}

async fn run_batches<T, S, F, Fut, G, Staged, E>(
    descriptions: Vec<T>,
    batch_items: usize,
    prepare: F,
    stage: G,
) -> Result<(), E>
where
    F: Fn(T) -> Fut,
    Fut: Future<Output = Result<S, E>>,
    G: Fn(Vec<S>) -> Staged,
    Staged: Future<Output = Result<(), E>>,
    E: From<DirectClientError>,
{
    if batch_items == 0
        || batch_items > MAX_DIRECT_BATCH_ITEMS
        || batch_items > SourceWaveBudget::MAX_FILES
    {
        return Err(DirectClientError::Invalid.into());
    }
    let maximum = (SourceWaveBudget::MAX_FILES / batch_items).min(staging::MAX_PARALLEL_BATCHES);
    let mut remaining = descriptions.into_iter();
    let mut batches = Vec::new();
    loop {
        let batch: Vec<_> = remaining.by_ref().take(batch_items).collect();
        if batch.is_empty() {
            break;
        }
        batches.push(batch);
    }

    staging::run_fallible(batches, maximum, |batch| {
        let prepare = &prepare;
        let stage = &stage;
        async move {
            let mut files = Vec::with_capacity(batch.len());
            for description in batch {
                files.push(prepare(description).await?);
            }
            stage(files).await
        }
    })
    .await
}

#[cfg(test)]
mod tests;
