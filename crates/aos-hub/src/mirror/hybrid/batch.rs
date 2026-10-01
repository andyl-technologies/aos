//! Real bounded phase transport for independent retained mirror originals.
//!
//! Request and retained-progress sizes split a group before encoding. Every
//! item receives fresh current SQL checks; independent refusals remain local
//! while all admitted effects settle. No permission is retained between phases.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::Database;
use aos_hub_core::mirror_batch::{MirrorBatchItem, MirrorBatchOutcome};
use aos_hub_core::mirror_work::{MirrorProgress, MirrorStep};
use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};

use crate::storage_work::RemoteStorageWorkClient;

mod commit;

#[cfg(test)]
mod tests;

pub(super) async fn prepare(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &aos_hub_core::db::RegistryRecord,
    selected: Vec<(String, aos_hub_core::mirror_work::MirrorVerification)>,
) -> Result<Vec<super::PreparedObject>> {
    prepare_selected(db, work, registry, selected, None).await
}

pub(super) async fn prepare_selected(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &aos_hub_core::db::RegistryRecord,
    selected: Vec<(String, aos_hub_core::mirror_work::MirrorVerification)>,
    selection: Option<&super::selection::Selection>,
) -> Result<Vec<super::PreparedObject>> {
    use futures_util::StreamExt as _;

    let mut admissions =
        futures_util::stream::iter(selected.into_iter().map(|(path, proof)| async move {
            super::admit_object(db, work, registry, &path, proof, selection).await
        }))
        .buffer_unordered(8);
    let mut active = std::collections::BTreeMap::new();
    let mut finished = Vec::new();
    let mut first_failure = None;
    while let Some(admission) = admissions.next().await {
        match admission {
            Ok(super::Admission::Ready(prepared)) => finished.push(prepared),
            Ok(super::Admission::Active { original, progress }) => {
                active.insert(original.job_id.clone(), (original, progress));
            }
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }
    while !active.is_empty() {
        let mut items = Vec::with_capacity(active.len());
        let mut verified = Vec::new();
        for (job, (original, progress)) in &active {
            match next_private_step(original, progress.as_ref()) {
                Some(step) => items.push(MirrorBatchItem {
                    original: original.clone(),
                    step,
                }),
                None => verified.push(job.clone()),
            }
        }
        for job in verified {
            if let Some((original, Some(progress))) = active.remove(&job) {
                finished.push(super::prepared(original, &progress, false)?);
            }
        }
        if items.is_empty() {
            break;
        }
        for (job, result) in run(db, work, items, None).await {
            match result {
                Ok(progress) => {
                    let entry = active
                        .get_mut(&job)
                        .context("mirror phase returned another job")?;
                    entry.1 = Some(progress);
                }
                Err(error) => {
                    active.remove(&job);
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    Ok(finished)
}

fn next_private_step(
    original: &aos_hub_core::mirror_work::MirrorOriginal,
    progress: Option<&MirrorProgress>,
) -> Option<MirrorStep> {
    let Some(progress) = progress else {
        return Some(MirrorStep::Status { destination: false });
    };
    if progress.stage_upload_id.is_none() && progress.stage_object.is_none() {
        return Some(MirrorStep::Begin);
    }
    let part_count = original
        .verification
        .size()
        .div_ceil(aos_hub_core::mirror_work::MIRROR_PART_BYTES) as usize;
    if progress.stage_parts.len() < part_count {
        return Some(MirrorStep::UploadParts {
            first_part: progress.stage_parts.len() as u32 + 1,
            maximum_parts: aos_hub_core::mirror_work::MIRROR_MAX_PARTS_PER_STEP,
        });
    }
    if progress.stage_object.is_none() {
        return Some(MirrorStep::CloseStage);
    }
    if progress.verified.is_none() {
        return Some(MirrorStep::VerifyStage);
    }
    None
}

pub(super) async fn publish(
    db: &Database,
    work: &RemoteStorageWorkClient,
    prepared: Vec<super::PreparedObject>,
    publication_id: &str,
) -> Result<usize> {
    let mut active = std::collections::BTreeMap::new();
    let mut completed = 0;
    let mut first_failure = None;
    for object in prepared {
        if object.committed {
            match super::archived_progress(work, &object.original, &object.verified).await {
                Ok(_) => completed += 1,
                Err(error) if first_failure.is_none() => first_failure = Some(error),
                Err(_) => {}
            }
            continue;
        }
        let retained = db
            .mirror_import(&object.original.job_id)
            .await?
            .context("prepared mirror original disappeared")?;
        ensure!(
            retained.original == object.original,
            "prepared mirror original changed"
        );
        let progress = retained
            .progress
            .context("prepared mirror progress disappeared")?;
        ensure!(
            progress.verified.as_ref() == Some(&object.verified),
            "prepared mirror verification changed during manifest admission"
        );
        let final_positive = progress.destination.is_some();
        active.insert(
            object.original.job_id.clone(),
            (object.original, progress, final_positive),
        );
    }
    let mut positive = Vec::new();
    while !active.is_empty() {
        let mut items = Vec::new();
        let mut finished = Vec::new();
        for (job, (original, progress, observed)) in &active {
            let step = if !observed {
                Some(MirrorStep::Status { destination: true })
            } else {
                next_destination_step(original, progress)
            };
            match step {
                Some(step) => items.push(MirrorBatchItem {
                    original: original.clone(),
                    step,
                }),
                None => finished.push(job.clone()),
            }
        }
        for job in finished {
            if let Some((original, progress, _)) = active.remove(&job) {
                positive.push((original, progress));
            }
        }
        if items.is_empty() {
            break;
        }
        for (job, result) in run(db, work, items, Some(publication_id)).await {
            match result {
                Ok(progress) => {
                    let entry = active
                        .get_mut(&job)
                        .context("mirror destination returned another job")?;
                    // An empty destination Status cannot replace the separately
                    // retained source verification or its immutable receipts.
                    if progress.verified.is_some() {
                        entry.1 = progress;
                    }
                    entry.2 = true;
                }
                Err(error) => {
                    active.remove(&job);
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
    }

    // Retained positives precede independent readback and atomic SQL publication.
    // All successful commits are ACKed even when another item's quota or proof
    // refuses; uncertain provider state cannot cancel an independent success.
    let mut acknowledgements = Vec::new();
    for result in commit::commit(db, work, positive, publication_id).await {
        match result {
            Ok(item) => acknowledgements.push(item),
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }
    for (_, result) in run(db, work, acknowledgements, Some(publication_id)).await {
        match result {
            Ok(_) => completed += 1,
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }
    match first_failure {
        Some(error) => Err(error),
        None => Ok(completed),
    }
}

fn next_destination_step(
    original: &aos_hub_core::mirror_work::MirrorOriginal,
    progress: &MirrorProgress,
) -> Option<MirrorStep> {
    if progress.destination.is_some() {
        return None;
    }
    if progress.destination_upload_id.is_none() {
        return Some(MirrorStep::BeginPromotion);
    }
    let count = original
        .verification
        .size()
        .div_ceil(aos_hub_core::mirror_work::MIRROR_PART_BYTES) as usize;
    if progress.destination_parts.len() < count {
        return Some(MirrorStep::CopyParts {
            first_part: progress.destination_parts.len() as u32 + 1,
            maximum_parts: aos_hub_core::mirror_work::MIRROR_MAX_PARTS_PER_STEP,
        });
    }
    Some(MirrorStep::CompletePromotion)
}

pub(super) async fn run(
    db: &Database,
    work: &RemoteStorageWorkClient,
    items: Vec<MirrorBatchItem>,
    publication_id: Option<&str>,
) -> Vec<(String, Result<MirrorProgress>)> {
    let mut results = Vec::with_capacity(items.len());
    let mut group = Vec::new();
    let mut estimated_reply = 0;
    for item in items {
        let retained = match preflight(db, work, &item, publication_id).await {
            Ok(retained) => retained,
            Err(error) => {
                results.push((item.original.job_id.clone(), Err(error)));
                continue;
            }
        };
        let estimate = retained
            .progress
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map(|bytes| bytes.map_or(0, |bytes| bytes.len()));
        let estimate = match estimate {
            Ok(bytes) => bytes + 2048 + item.original.path.len(),
            Err(error) => {
                results.push((item.original.job_id.clone(), Err(error.into())));
                continue;
            }
        };
        let request_size = serde_json::to_vec(&item)
            .map(|body| body.len())
            .unwrap_or(usize::MAX);
        let group_bytes = group.iter().map(|(_, _, bytes)| *bytes).sum::<usize>();
        if !group.is_empty()
            && (group.len() == 64
                || group_bytes.saturating_add(request_size) > 230 * 1024
                || estimated_reply + estimate > 230 * 1024)
        {
            results.extend(exchange(db, work, std::mem::take(&mut group)).await);
            estimated_reply = 0;
        }
        estimated_reply += estimate;
        group.push((item, retained, request_size));
    }
    if !group.is_empty() {
        results.extend(exchange(db, work, group).await);
    }
    results
}

async fn preflight(
    db: &Database,
    work: &RemoteStorageWorkClient,
    item: &MirrorBatchItem,
    publication_id: Option<&str>,
) -> Result<aos_hub_core::db::MirrorImportRecord> {
    let retained = db
        .mirror_import(&item.original.job_id)
        .await?
        .context("mirror phase original disappeared")?;
    ensure!(
        retained.original == item.original,
        "mirror phase changed retained original"
    );
    if let MirrorStep::Acknowledge { commit_digest } = &item.step {
        let progress = retained
            .progress
            .as_ref()
            .context("mirror ACK lacks retained final proof")?;
        ensure!(
            retained.state == "committed"
                && progress.commit_digest(&item.original)? == *commit_digest,
            "mirror ACK lacks exact Native terminal identity"
        );
        return Ok(retained);
    }
    db.validate_mirror_import_authority(&item.original).await?;
    ensure!(
        work.mirror_managed_profile_digest()? == item.original.protected_profile_digest,
        "mirror phase accepted profile changed"
    );
    if matches!(
        item.step,
        MirrorStep::BeginPromotion | MirrorStep::CopyParts { .. } | MirrorStep::CompletePromotion
    ) {
        db.validate_mirror_publication_dispatch(
            &item.original,
            retained
                .progress
                .as_ref()
                .context("mirror promotion lacks retained verification")?,
            publication_id,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await?;
    }
    Ok(retained)
}

async fn exchange(
    db: &Database,
    work: &RemoteStorageWorkClient,
    group: Vec<(MirrorBatchItem, aos_hub_core::db::MirrorImportRecord, usize)>,
) -> Vec<(String, Result<MirrorProgress>)> {
    let attempt = async {
        let first = &group
            .first()
            .context("mirror phase group is empty")?
            .0
            .original;
        let items = group.iter().map(|(item, _, _)| item.clone()).collect();
        let now = aos_hub_core::clock::now_unix_secs();
        let plan = aos_hub_core::storage_work::StorageWorkPlan {
            version: 1,
            plan_id: uuid::Uuid::new_v4().simple().to_string(),
            deployment_id: work.deployment_id().into(),
            issued_at: now,
            expires_at: now.checked_add(30).context("mirror phase clock overflow")?,
            placement_id: first.placement_id,
            placement_resource_version: first.placement_resource_version,
            binding_id: first.binding_id,
            binding_resource_version: first.binding_resource_version,
            binding_kind: "deployment_r2".into(),
            placement_prefix: first.placement_prefix.clone(),
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            operation: StorageWorkOperation::MirrorTransferBatch { items },
        };
        let result = work.execute(&plan).await?;
        let StorageWorkOutcome::MirrorBatch { items } = result.outcome else {
            anyhow::bail!("mirror phase transport returned another result");
        };
        Ok::<_, anyhow::Error>(items)
    }
    .await;
    let returned = match attempt {
        Ok(returned) => returned,
        Err(error) => {
            let message =
                format!("mirror batch control failed; exact originals remain retained: {error:#}");
            return group
                .into_iter()
                .map(|(item, _, _)| (item.original.job_id, Err(anyhow::anyhow!(message.clone()))))
                .collect();
        }
    };
    let mut settled = Vec::with_capacity(group.len());
    for ((item, retained, _), returned) in group.into_iter().zip(returned) {
        let progress = match returned.outcome {
            MirrorBatchOutcome::Refused => {
                Err(anyhow::anyhow!("mirror item is refused or unsettled"))
            }
            MirrorBatchOutcome::Progress { progress, .. } => {
                let persist = if matches!(item.step, MirrorStep::Acknowledge { .. }) {
                    db.retire_acknowledged_mirror_import(&item.original, &progress)
                        .await
                        .map(|_| ())
                } else if !matches!(item.step, MirrorStep::Status { .. })
                    || retained.progress.is_none()
                {
                    db.record_mirror_import_progress(
                        &item.original,
                        &progress,
                        retained.state == "committed",
                        aos_hub_core::clock::now_unix_secs(),
                    )
                    .await
                    .map(|_| ())
                } else {
                    db.validate_mirror_import_authority(&item.original).await
                };
                persist.map(|_| progress)
            }
        };
        settled.push((item.original.job_id, progress));
    }
    settled
}
