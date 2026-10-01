//! Bounded independent final readback followed by per-object SQL publication.
//!
//! Positive producer state is retained before any challenge. A refused item
//! or lost reply leaves its original held; only successful SQL publications
//! produce acknowledgement controls.

use futures_util::StreamExt as _;

use aos_hub_core::mirror_guard::batch::{
    MirrorGuardBatchItem, VerifiedMirrorGuardBatchItem, MIRROR_GUARD_BATCH_MAX_ITEMS,
};
use aos_hub_core::mirror_work::MirrorOriginal;

use super::*;

const ENCODED_ITEMS_BUDGET: usize = 230 * 1024;

pub(super) async fn commit(
    db: &Database,
    work: &RemoteStorageWorkClient,
    positive: Vec<(MirrorOriginal, MirrorProgress)>,
    publication_id: &str,
) -> Vec<Result<MirrorBatchItem>> {
    let mut results = Vec::new();
    let mut group = Vec::new();
    let mut group_bytes = 0usize;

    for (original, progress) in positive {
        let retained = db
            .record_mirror_import_progress(
                &original,
                &progress,
                false,
                aos_hub_core::clock::now_unix_secs(),
            )
            .await;
        if let Err(error) = retained {
            results.push(Err(error));
            continue;
        }

        let item_bytes = match serde_json::to_vec(&MirrorGuardBatchItem {
            original: original.clone(),
            expected: progress.clone(),
        }) {
            Ok(bytes) if bytes.len() <= ENCODED_ITEMS_BUDGET => bytes.len(),
            Ok(_) => {
                results.push(Err(anyhow::anyhow!(
                    "mirror final proof item exceeds its bounded control"
                )));
                continue;
            }
            Err(error) => {
                results.push(Err(error.into()));
                continue;
            }
        };
        if !group.is_empty()
            && (group.len() == MIRROR_GUARD_BATCH_MAX_ITEMS
                || group_bytes.saturating_add(item_bytes) > ENCODED_ITEMS_BUDGET)
        {
            results
                .extend(commit_group(db, work, std::mem::take(&mut group), publication_id).await);
            group_bytes = 0;
        }
        group_bytes += item_bytes;
        group.push((original, progress));
    }
    if !group.is_empty() {
        results.extend(commit_group(db, work, group, publication_id).await);
    }
    results
}

async fn commit_group(
    db: &Database,
    work: &RemoteStorageWorkClient,
    group: Vec<(MirrorOriginal, MirrorProgress)>,
    publication_id: &str,
) -> Vec<Result<MirrorBatchItem>> {
    let proofs = match work.lookup_mirror_final_guards(&group).await {
        Ok(proofs) => proofs,
        Err(error) => {
            return group
                .into_iter()
                .map(|_| {
                    Err(anyhow::anyhow!(
                        "mirror final batch remains held: {error:#}"
                    ))
                })
                .collect();
        }
    };
    if proofs.len() != group.len() {
        return group
            .into_iter()
            .map(|_| {
                Err(anyhow::anyhow!(
                    "mirror final guard batch changed its item count"
                ))
            })
            .collect();
    }

    futures_util::stream::iter(group.into_iter().zip(proofs).map(
        |((original, progress), proof)| async move {
            let VerifiedMirrorGuardBatchItem::Positive(proof) = proof else {
                anyhow::bail!("mirror final guard refused its retained publication");
            };
            db.commit_mirror_import(
                &original,
                &progress,
                &proof,
                Some(publication_id),
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?;
            Ok(MirrorBatchItem {
                step: MirrorStep::Acknowledge {
                    commit_digest: progress.commit_digest(&original)?,
                },
                original,
            })
        },
    ))
    .buffer_unordered(8)
    .collect()
    .await
}
