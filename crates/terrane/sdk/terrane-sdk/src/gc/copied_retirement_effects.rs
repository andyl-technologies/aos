//! Publishes closed copied-retirement phases through actual native Frames.
//!
//! The selected bridge owns semantic qualification. This descendant owns exact
//! installation, whole selected compares and executor acknowledgment channels.
//! No physical deletion is dispatched by this first-ownership group.

pub(crate) use super::super::artifact_seal::copied_retirement::NativeBarrier;

#[path = "copied_retirement_effects/trash.rs"]
mod trash;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "copied_retirement_effects/pair_bracketing_tests.rs"]
mod pair_bracketing_tests;

use super::super::artifact_seal::copied_retirement::{
    NativePreparation, ownership_plan, preparation_plan,
};
use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, Mutability, NativeEffectFailure, PortableCurrent,
    PortableSnapshot, PredecessorSlot, ProjectionEntry, PublicationCommit, PublicationTransaction,
    StoreFailure, corrupt, digest, hex, io_failure, projectable, unsupported,
};
use crate::bucket::publication::receipts::RecordRead;
use crate::selected_bridge::native_copied_placement::{CheckedDataPlacement, PlacementArtifacts};
use crate::selected_bridge::native_copied_retirement::{CheckedOwnership, CheckedPreparation};
use terrane_format::gc::publication::{LogicalChange, PublicationProof, PublicationState};

fn native(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => io_failure(error),
    }
}

enum Selected<'a, 'operation, 'held> {
    Preparing(&'a CheckedPreparation<'operation, 'held>),
    Ownership(&'a CheckedOwnership<'operation, 'held>),
}

impl<'operation, 'held> Selected<'_, 'operation, 'held> {
    fn data(&self) -> &CheckedDataPlacement<'operation, 'held> {
        match self {
            Self::Preparing(checked) => checked.data().data(),
            Self::Ownership(checked) => checked.data().data(),
        }
    }

    fn artifacts(&self) -> &PlacementArtifacts {
        match self {
            Self::Preparing(checked) => checked.artifacts(),
            Self::Ownership(checked) => checked.artifacts(),
        }
    }

    fn changes(&self) -> &[LogicalChange] {
        match self {
            Self::Preparing(checked) => checked.changes(),
            Self::Ownership(checked) => checked.changes(),
        }
    }

    fn next(&self) -> &PublicationState {
        match self {
            Self::Preparing(checked) => checked.next(),
            Self::Ownership(checked) => checked.next(),
        }
    }

    fn guard(&self) -> &RecordRead {
        match self {
            Self::Preparing(_) => self.data().guard(),
            Self::Ownership(checked) => checked.barrier().guard(),
        }
    }

    fn proof(&self) -> Result<PublicationProof, StoreFailure> {
        match self {
            Self::Preparing(_) => Ok(PublicationProof::Raw),
            Self::Ownership(checked) => Ok(PublicationProof::PermanentRetirement {
                authorization: checked
                    .operation()
                    .authorization
                    .encode()
                    .map_err(|_| corrupt())?,
                carried: Vec::new(),
            }),
        }
    }
}

async fn capture<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &Selected<'_, '_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    let data = selected.data();
    let observed = data.observed();
    let root = observed.identity().root();
    let (mut frame, control) = super::collection_checkpoints::retained_controls_frame(
        fs,
        observed,
        selected.guard(),
        data.effects(),
    )
    .await?;
    // Final ownership retains the actual immutable barrier before any submitted
    // worker. Cancellation cannot release it while snapshot or slot staging is
    // still executing, and mutable current checks remain independently live.
    if let Selected::Ownership(checked) = selected {
        let current = frame.final_check.as_ref().ok_or_else(corrupt)?;
        frame.final_check = Some(current.with_copied_barrier(checked.barrier()));
    }

    // Rebuild from the same current authority and complete acquired prefix.
    // Wrapping the previous pair check recursively duplicates its observations.
    let base_current = frame.final_check.clone().ok_or_else(corrupt)?;
    let mut pairs = Vec::with_capacity(data.packs().len());

    // Each selected DATA pack is retained by a genuine executor-produced
    // metadata-only pair. Copied old containers need no creator journal; their
    // descriptors and current associations remain checked through every later
    // Frame, including workers that outlive cancellation of the caller.
    for pack in data.packs() {
        // The metadata-only pair must consume the exact independently observed
        // index preimage before retaining either container descriptor.
        frame
            .observed_read(
                fs,
                pack.index().path(),
                pack.index().bytes(),
                pack.index().metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
        let (plan, receiver) = super::super::artifact_seal::restore_pair::eligible_data_pair_plan(
            root,
            &control,
            pack,
            frame.owner,
        )
        .map_err(native)?;
        frame.execute(fs, plan).await?;
        let pair = receiver.take().map_err(native)?;
        pairs.push(pair);
        frame.final_check = Some(base_current.with_restore_pairs(&pairs));
    }
    let preparing: &[RecordRead] = match selected {
        Selected::Preparing(checked) => checked.reads(),
        Selected::Ownership(_) => &[],
    };
    for read in data
        .reads()
        .iter()
        .chain(preparing)
        .chain(selected.artifacts().absent())
    {
        let policy = if read.path().starts_with(&control) {
            FencePolicy::ProtectedRecord { owner: frame.owner }
        } else if read.path().starts_with(root) {
            FencePolicy::Payload { owner: frame.owner }
        } else {
            return Err(corrupt());
        };
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

struct Published {
    slot: PublicationCommit,
    transaction: PublicationTransaction,
    snapshot: Vec<u8>,
}

async fn install<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &Selected<'_, '_, '_>,
    frame: &mut Frame,
    control: &std::path::Path,
) -> Result<Published, StoreFailure> {
    let data = selected.data();
    data.revalidate().await?;
    let observed = data.observed();
    let root = observed.identity().root();
    let owner = frame.owner;
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;
    let artifacts = selected.artifacts();
    frame
        .install(
            fs,
            control,
            &artifacts.fence().0.key,
            artifacts.fence().1,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;
    for change in selected.changes() {
        if change.key == "CAPABILITIES" {
            continue;
        }
        let mutability = if change.expected.is_some() {
            Mutability::CompareAndSwap
        } else if change.key.ends_with("/roots") || change.key.contains("/mark/") {
            Mutability::CreateOnce
        } else {
            Mutability::Immutable
        };
        frame
            .install(
                fs,
                root,
                &change.key,
                change.new.as_deref().ok_or_else(corrupt)?,
                FencePolicy::Payload { owner },
                mutability,
            )
            .await?;
    }
    let nonce: [u8; 32] = fs
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())?;
    let operation = hex(&nonce);
    let snapshot = PortableSnapshot {
        revision: selected.next().revision,
        origin: selected.next().binding.clone(),
        projection: selected
            .changes()
            .iter()
            .filter(|change| projectable(&change.key))
            .map(|change| ProjectionEntry {
                key: change.key.clone(),
                value: change.new.clone(),
            })
            .collect(),
        predecessor: Some(observed.snapshot().clone()),
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!(
            "publication/snapshots/{}:{operation}",
            selected.next().revision
        ),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: selected.next().clone(),
        changes: selected.changes().to_vec(),
        proof: selected.proof()?,
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
            control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;
    data.revalidate().await?;
    if let Selected::Ownership(checked) = selected {
        checked.barrier().elapsed().map_err(native)?;
    }
    let slot = PublicationCommit {
        revision: selected.next().revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    frame
        .install(
            fs,
            control,
            &format!("publication/commits/{}", slot.revision),
            &slot.encode().map_err(|_| corrupt())?,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;
    let mut logical = observed.logical().clone();
    for change in selected.changes() {
        logical.insert(change.key.clone(), change.new.clone());
    }
    frame.project(fs, root, &pointer, &logical).await?;
    Ok(Published {
        slot,
        transaction,
        snapshot: snapshot_bytes,
    })
}

/// Selects and genuinely acknowledges preparation before creating NEW Trash.
///
/// # Errors
/// Refuses changed complete current inputs, occupied names, missing real native
/// acknowledgment or any actual publication/creation durability failure.
pub(crate) async fn prepare<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedPreparation<'_, '_>,
) -> Result<NativeBarrier, StoreFailure> {
    let selected = Selected::Preparing(checked);
    let (mut frame, control) = capture(fs, &selected).await?;
    let root = checked.data().data().observed().identity().root();
    let reserved = trash::reserve(fs, &mut frame, root, &control, checked).await?;
    let published = install(fs, &selected, &mut frame, &control).await?;
    let (plan, receiver) = preparation_plan(
        checked,
        &published.slot,
        &published.transaction,
        &published.snapshot,
    )
    .map_err(native)?;
    frame.execute(fs, plan).await?;
    let preparation: NativePreparation = receiver.take().map_err(native)?;
    let barrier = trash::create(fs, &mut frame, root, &control, &preparation, reserved).await?;
    checked.data().data().effects().final_check().recheck()?;
    Ok(barrier)
}

/// Publishes and genuinely acknowledges the closed final copied first owner.
///
/// # Errors
/// Refuses changed whole current inputs, stale lease/control/barrier, occupied
/// immutable names, absent real native ACK or actual synchronization failure.
pub(crate) async fn own<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedOwnership<'_, '_>,
) -> Result<(), StoreFailure> {
    let selected = Selected::Ownership(checked);
    let (mut frame, control) = capture(fs, &selected).await?;
    let published = install(fs, &selected, &mut frame, &control).await?;
    let (plan, receiver) = ownership_plan(
        checked,
        &published.slot,
        &published.transaction,
        &published.snapshot,
    )
    .map_err(native)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(native)?;
    checked.data().data().effects().final_check().recheck()
}
