//! Publishes exact current restoration after any required closed local cancellation.
//!
//! Fresh current qualification and actual native maintenance descriptors remain
//! held through selection, cache projection and the executor-only durable result.
//! A qualified local owner is durably cancelled before the active exclusion clears.
//! Remote and copied owners remain refused. No Trash age, creator journal,
//! persisted mark or caller tuple grants permission.
//!
//! ```text
//! current roots + retained pair -> eligible catalog successor + exact binding clear
//! -> selected slot -> pointer/cache projection -> native durable acknowledgment
//! ```

use super::super::artifact_seal::restore_publication::{RestoreInputs, restore_plan};
use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, Mutability, NativeEffectFailure, PortableCurrent,
    PortableSnapshot, PredecessorSlot, ProjectionEntry, PublicationCommit, PublicationTransaction,
    StoreFailure, corrupt, digest, hex, io_failure, projectable, unsupported,
};
use crate::selected_bridge::native_collection_restore::{CheckedLocalCancellation, CheckedRestore};
use terrane_format::gc::publication::PublicationProof;

fn failure(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => io_failure(error),
    }
}

async fn entropy<const N: usize, F: LocalFs>(fs: &F) -> Result<[u8; N], StoreFailure> {
    fs.random_bytes(N)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())
}

async fn capture<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedRestore<'_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    capture_current(fs, checked.current(), checked.reads()).await
}

async fn capture_current<F: LocalFs + BucketBinding>(
    fs: &F,
    current: &crate::selected_bridge::CheckedRestoreCurrent<'_, '_>,
    reads: &[crate::bucket::publication::receipts::RecordRead],
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    let (mut frame, control) = super::collection_checkpoints::retained_controls_frame(
        fs,
        current.observed(),
        current.guard_record(),
        current.effect_context(),
    )
    .await?;
    for read in current.inputs().iter().chain(reads) {
        let policy = FencePolicy::Payload { owner: frame.owner };
        if read.bytes().is_none() {
            if read.metadata().is_some()
                || frame.actual_read(fs, read.path(), policy).await?.is_some()
            {
                return Err(corrupt());
            }
        } else {
            frame
                .observed_read(fs, read.path(), read.bytes(), read.metadata(), policy)
                .await?;
        }
    }
    Ok((frame, control))
}

/// Selects and durably acknowledges only the closed producer's exact restore.
///
/// # Errors
/// Refuses changed current roots, controls, lease or pair, unsafe preimages,
/// selection conflicts and failed or missing executor durability acknowledgment.
pub(crate) async fn publish_checked<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedRestore<'_, '_>,
) -> Result<(), StoreFailure> {
    let current = checked.current();
    current.revalidate().await?;
    let observed = current.observed();
    let root = observed.identity().root();
    let (mut frame, control) = capture(fs, checked).await?;
    // Track only actual completed writes, including projection repairs/removals.
    frame.writes = Some(super::CompletedWrites {
        records: std::collections::BTreeMap::new(),
    });
    let owner = frame.owner;
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;
    for change in checked.changes() {
        if change.key != "CAPABILITIES" {
            frame
                .install(
                    fs,
                    root,
                    &change.key,
                    change.new.as_deref().ok_or_else(corrupt)?,
                    FencePolicy::Payload { owner },
                    Mutability::Immutable,
                )
                .await?;
        }
    }
    let nonce = entropy::<32, _>(fs).await?;
    let operation = hex(&nonce);
    let snapshot = PortableSnapshot {
        revision: checked.next().revision,
        origin: checked.next().binding.clone(),
        projection: checked
            .changes()
            .iter()
            .filter(|row| projectable(&row.key))
            .map(|row| ProjectionEntry {
                key: row.key.clone(),
                value: row.new.clone(),
            })
            .collect(),
        predecessor: Some(observed.snapshot().clone()),
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!(
            "publication/snapshots/{}:{operation}",
            checked.next().revision
        ),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: checked.next().clone(),
        changes: checked.changes().to_vec(),
        proof: PublicationProof::Raw,
        predecessor: Some(PredecessorSlot {
            revision: observed.stamp().0,
            digest: observed.stamp().1,
        }),
        snapshot: pointer.clone(),
    };
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            root,
            &pointer.key,
            &snapshot_bytes,
            FencePolicy::Payload { owner },
            Mutability::Immutable,
        )
        .await?;
    let transaction_key = format!("publication/transactions/{operation}");
    transaction
        .check_key(&transaction_key)
        .map_err(|_| corrupt())?;
    let transaction_bytes = transaction.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;
    current.revalidate().await?;
    let slot = PublicationCommit {
        revision: checked.next().revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    let slot_bytes = slot.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &format!("publication/commits/{}", slot.revision),
            &slot_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;
    let mut logical = observed.logical().clone();
    for change in checked.changes() {
        logical.insert(change.key.clone(), change.new.clone());
    }
    frame.project(fs, root, &pointer, &logical).await?;
    let (plan, receiver) = restore_plan(RestoreInputs {
        root,
        control: &control,
        checked,
        exclusions: &frame.exclusions,
        writes: frame.writes.as_ref().ok_or_else(unsupported)?,
        slot: &slot,
        transaction: &transaction,
        snapshot: &snapshot_bytes,
        owner,
    })
    .map_err(failure)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(failure)?;
    // Visible selected bytes and a unit callback cannot replace the native result.
    current.effect_context().final_check().recheck()?;
    Ok(())
}

/// Durably cancels actual local ownership before any restore exclusion clear.
///
/// # Errors
/// Refuses absent containers, changed current authority or incomplete native durability.
pub(crate) async fn cancel_local_owner<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedLocalCancellation<'_, '_>,
    owned: std::sync::Arc<super::collection_local_deletion::NativeLocalDeletion>,
) -> Result<(), StoreFailure> {
    let current = checked.current();
    current.revalidate().await?;
    let (mut frame, control) = capture_current(fs, current, &[]).await?;
    let key = owned.operation().authorization.operation_key();
    let policy = FencePolicy::ProtectedRecord { owner: frame.owner };
    let bytes = frame
        .actual_read(fs, &control.join(&key), policy)
        .await?
        .ok_or_else(corrupt)?;
    if bytes != owned.operation().encode().map_err(|_| corrupt())? {
        return Err(corrupt());
    }
    for version in &owned.operation().authorization.artifacts {
        let path = super::super::artifact_seal::journal_path(&control, &version.key);
        frame
            .actual_read(fs, &path, policy)
            .await?
            .ok_or_else(corrupt)?;
    }
    // Cancellation uses the same retained artifact descriptors as deletion.
    // Fence their actual current ancestry before the closed executor opens it.
    let root = current.observed().identity().root();
    for version in &owned.operation().authorization.artifacts {
        let path = root.join(&version.key);
        let mut parent = path.parent();
        while let Some(directory) = parent {
            frame
                .directory(
                    fs,
                    directory,
                    FencePolicy::ProtectedAncestor { owner: frame.owner },
                )
                .await?;
            if directory == root {
                break;
            }
            parent = directory.parent();
        }
    }

    let nonce = entropy::<16, _>(fs).await?;
    let (request, receiver) =
        super::super::artifact_seal::local_deletion::effects::cancellation_plan(
            checked, owned, nonce,
        )
        .map_err(failure)?;
    if frame
        .actual_read(fs, request.temporary(), policy)
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    let mut parent = control.join(&key).parent().map(std::path::Path::to_owned);
    while let Some(directory) = parent {
        frame
            .directory(
                fs,
                &directory,
                FencePolicy::PrivateControlDirectory { owner: frame.owner },
            )
            .await?;
        if directory == control {
            break;
        }
        parent = directory.parent().map(std::path::Path::to_owned);
    }
    let journal_directory = control.join(".terrane-creation");
    frame
        .directory(
            fs,
            &journal_directory,
            FencePolicy::PrivateControlDirectory { owner: frame.owner },
        )
        .await?;
    frame
        .execute(fs, super::Plan::AdvanceLocalDeletion(Box::new(request)))
        .await?;
    let operation = receiver.take().map_err(failure)?;
    if operation.phase != terrane_format::gc::DeletePhase::Cancelled {
        return Err(corrupt());
    }
    current.revalidate().await?;
    current.effect_context().final_check().recheck()?;
    Ok(())
}
