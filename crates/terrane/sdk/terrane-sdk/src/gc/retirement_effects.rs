//! Selects one checked exclusion before genuinely creating its immutable Trash.
//!
//! This descendant consumes only the closed repository retirement producer.
//! Every worker retains the actual current pair and complete native frame. A
//! closed native barrier result precedes Pending, same-descriptor Trash sync and
//! protected Committed acknowledgment. No physical delete or restore is issued.
//!
//! ```text
//! current proof + pair -> case-2 exclusion slot -> native durable barrier
//! -> Trash Pending -> native Pending -> immutable Trash -> seal -> Committed
//! ```

use super::super::artifact_seal::retirement_barrier::{BarrierInputs, barrier_plan};
use super::super::artifact_seal::{commit_plan, pending::pending_plan, seal_plan};
use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, Mutability, NativeEffectFailure, Plan,
    PortableCurrent, PortableSnapshot, PredecessorSlot, ProjectionEntry, PublicationCommit,
    PublicationTransaction, StoreFailure, corrupt, digest, hex, io_failure, projectable,
    unsupported,
};
use crate::selected_bridge::native_collection_retirement::CheckedRetirement;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::PublicationProof;
use terrane_format::gc::{ArtifactBinding, CreationJournal, JournalState};

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

fn validate(checked: &CheckedRetirement<'_, '_>) -> Result<(), StoreFailure> {
    let current = checked.current();
    let observed = current.observed();
    let pair = checked.pair();
    let tombstone = checked.tombstone();
    let mut expected = observed.state().clone();
    expected.revision = expected.revision.checked_add(1).ok_or_else(corrupt)?;
    expected.loss_generation = expected
        .loss_generation
        .checked_add(1)
        .ok_or_else(corrupt)?;
    let sources = current.sources().ok_or_else(corrupt)?;
    expected.sources = sources
        .lineages()
        .iter()
        .map(|(row, _)| row.clone())
        .collect();
    if checked.next() != &expected
        || tombstone.pack != pair.inventory().pack_id
        || tombstone.cycle != current.selected_checkpoint().0.cycle
        || tombstone.epoch != current.effect_context().lease().epoch
        || !current.members_unmarked(pair.snapshot())
        || tombstone.removed
            != u64::try_from(pair.snapshot().entries().len()).map_err(|_| corrupt())?
    {
        return Err(corrupt());
    }
    let cap = checked
        .changes()
        .iter()
        .find(|change| change.key == "CAPABILITIES")
        .ok_or_else(corrupt)?;
    if cap.expected.as_deref()
        != observed
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
    {
        return Err(corrupt());
    }
    let old_cap = BucketCapabilities::decode(cap.expected.as_deref().ok_or_else(corrupt)?)
        .map_err(|_| corrupt())?;
    let new_cap = BucketCapabilities::decode(cap.new.as_deref().ok_or_else(corrupt)?)
        .map_err(|_| corrupt())?;
    let generation = new_cap.generation.ok_or_else(corrupt)?;
    if generation <= old_cap.generation.ok_or_else(corrupt)? {
        return Err(corrupt());
    }
    let mut allowed = old_cap.clone();
    allowed.generation = Some(generation);
    if new_cap != allowed {
        return Err(corrupt());
    }
    let key = format!("objects/index/{generation}/MANIFEST");
    let row = checked
        .changes()
        .iter()
        .find(|change| change.key == key)
        .ok_or_else(corrupt)?;
    let manifest = GenerationManifest::decode(row.new.as_deref().ok_or_else(corrupt)?)
        .map_err(|_| corrupt())?;
    let previous = GenerationManifest::decode(
        observed
            .logical()
            .get(&format!(
                "objects/index/{}/MANIFEST",
                old_cap.generation.ok_or_else(corrupt)?
            ))
            .and_then(Option::as_deref)
            .ok_or_else(corrupt)?,
    )
    .map_err(|_| corrupt())?;
    let mut exclusions = previous.exclusions.clone().ok_or_else(unsupported)?;
    let position = match exclusions.binary_search_by_key(&tombstone.pack, |row| row.pack_id) {
        Err(position) => position,
        Ok(_) => return Err(corrupt()),
    };
    exclusions.insert(
        position,
        terrane_format::bucket::PackExclusion {
            pack_id: tombstone.pack,
            cycle: tombstone.cycle,
            epoch: tombstone.epoch,
        },
    );
    if manifest.generation != generation
        || manifest.cycle != tombstone.cycle
        || manifest.inventory != previous.inventory
        || manifest.burns != previous.burns
        || manifest.exclusions.as_ref() != Some(&exclusions)
        || manifest
            .inventory
            .as_ref()
            .is_none_or(|inventory| !inventory.contains(pair.inventory()))
        || manifest
            .burns
            .as_ref()
            .is_none_or(|burns| burns.binary_search(&tombstone.pack).is_ok())
    {
        return Err(corrupt());
    }
    if checked.changes().iter().any(|row| {
        row.key != "CAPABILITIES" && !row.key.starts_with(&format!("objects/index/{generation}/"))
    }) {
        return Err(corrupt());
    }
    if checked.fence().0 != format!("gc/{}/fence/{}", tombstone.cycle, observed.state().revision)
        || checked.fence().1 != current.fence().encode().map_err(|_| corrupt())?
    {
        return Err(corrupt());
    }
    Ok(())
}

async fn capture<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedRetirement<'_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    let current = checked.current();
    let observed = current.observed();
    let (mut frame, control) = super::collection_checkpoints::retained_frame(
        fs,
        observed,
        current.reads(),
        current.effect_context(),
    )
    .await?;
    frame.retain_current_pair(observed.identity().root(), &control, checked.pair())?;
    for read in std::iter::once(current.reads().roots())
        .chain(std::iter::once(current.reads().state()))
        .chain(current.reads().inputs())
        .chain(checked.reads())
    {
        let policy = FencePolicy::Payload { owner: frame.owner };
        if read.bytes().is_none() {
            // A reserved generation can have a missing parent. Retain that
            // exact absence until directory creation acknowledges its replacement.
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
    for read in current.sources().ok_or_else(corrupt)?.protected() {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::ProtectedRecord { owner: frame.owner },
            )
            .await?;
    }
    for mark in current.reads().marks() {
        let crate::selected_bridge::GcMarkRead::Revision { record: read, .. } = mark;
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
    }
    Ok((frame, control))
}

async fn prepare_trash<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &std::path::Path,
    control: &std::path::Path,
    checked: &CheckedRetirement<'_, '_>,
) -> Result<(String, String), StoreFailure> {
    let key = format!(
        "trash/{}/{}",
        checked.tombstone().cycle,
        crate::pack::PackId::from_random_bytes(checked.tombstone().pack)
    );
    let suffix = hex(blake3::hash(key.as_bytes()).as_bytes());
    let journal = control.join(format!(".terrane-creation/{suffix}"));
    let payload = FencePolicy::Payload { owner: frame.owner };
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    if frame
        .actual_read(fs, &root.join(&key), payload)
        .await?
        .is_some()
    {
        return Err(unsupported());
    }
    let prior = frame.actual_read(fs, &journal, protected).await?;
    let previous = prior
        .as_deref()
        .map(CreationJournal::decode)
        .transpose()
        .map_err(|_| corrupt())?;
    // Any old protected journal means this cycle/ID already has an incarnation.
    // A failed earlier Pending is not backfilled by this first-retirement lane.
    if previous.is_some() {
        return Err(unsupported());
    }
    Ok((key, suffix))
}

async fn trash<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &std::path::Path,
    control: &std::path::Path,
    checked: &CheckedRetirement<'_, '_>,
    prepared: (String, String),
) -> Result<(), StoreFailure> {
    let (key, suffix) = prepared;
    let body = checked.tombstone().encode();
    let journal = control.join(format!(".terrane-creation/{suffix}"));
    let payload = FencePolicy::Payload { owner: frame.owner };
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    let nonce = entropy::<32, _>(fs).await?;
    let pending = CreationJournal {
        key: key.clone(),
        nonce,
        state: JournalState::Pending,
    }
    .encode()
    .map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            control,
            &format!(".terrane-creation/{suffix}"),
            &pending,
            protected,
            Mutability::CompareAndSwap,
        )
        .await?;
    let (plan, receiver) =
        pending_plan(root, control, &key, &pending, frame.owner).map_err(failure)?;
    frame.execute(fs, plan).await?;
    let receipt = receiver.take().map_err(failure)?;
    frame
        .install(fs, root, &key, &body, payload, Mutability::Immutable)
        .await?;
    let (plan, receiver) = seal_plan(receipt, &body).map_err(failure)?;
    frame.execute(fs, plan).await?;
    let seal = receiver.take().map_err(failure)?;
    let (request, receiver) = commit_plan(
        seal,
        control,
        &pending,
        ArtifactBinding::Trash(body.clone()),
        entropy::<16, _>(fs).await?,
    )
    .map_err(failure)?;
    let temporary = request.temporary_path().to_owned();
    if frame
        .actual_read(fs, &temporary, protected)
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    frame
        .execute(fs, Plan::CommitCreation(Box::new(request)))
        .await?;
    receiver.take().map_err(failure)?;
    // Only the acknowledged Pending replacement changes a retained preimage.
    frame.reads.retain(|read| read.path != journal);
    let bytes = frame
        .actual_read(fs, &journal, protected)
        .await?
        .ok_or_else(corrupt)?;
    let committed = CreationJournal::decode(&bytes).map_err(|_| corrupt())?;
    if committed.key != key
        || committed.nonce != nonce
        || !matches!(committed.state,JournalState::Committed{binding:ArtifactBinding::Trash(ref actual),..} if actual==&body)
    {
        return Err(corrupt());
    }
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await
}

/// Selects the exact exclusion and creates Trash only after closed durable acknowledgment.
///
/// # Errors
/// Refuses a different successor/current proof, unsafe or changed retained pair,
/// malformed catalog/fence, lost lease or incomplete native durability. Failure
/// after exclusion selection leaves the pack excluded and undeletable; this
/// initial producer does not backfill missing Trash or advance deletion progress.
pub(crate) async fn publish_checked<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedRetirement<'_, '_>,
) -> Result<(), StoreFailure> {
    validate(checked)?;
    let current = checked.current();
    current.revalidate().await?;
    let observed = current.observed();
    let root = observed.identity().root();
    let (mut frame, control) = capture(fs, checked).await?;
    let owner = frame.owner;
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;
    // Exact Trash and journal preflight precedes the exclusion selection. Those
    // original observations remain in the Frame across all intervening effects.
    let prepared = prepare_trash(fs, &mut frame, root, &control, checked).await?;
    frame
        .install(
            fs,
            &control,
            checked.fence().0,
            checked.fence().1,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
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
    for (row, bytes) in current.sources().ok_or_else(corrupt)?.lineages() {
        if row.digest != digest(bytes) {
            return Err(corrupt());
        }
        frame
            .install(
                fs,
                &control,
                &format!("publication/lineage/{}", hex(&row.digest)),
                bytes,
                FencePolicy::ProtectedRecord { owner },
                Mutability::Immutable,
            )
            .await?;
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
        proof: PublicationProof::Collection {
            fence_key: checked.fence().0.into(),
            fence_digest: digest(checked.fence().1),
            removed: vec![checked.removed()],
            carried: current.sources().ok_or_else(corrupt)?.prior().to_vec(),
        },
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
    let (plan, receiver) = barrier_plan(BarrierInputs {
        root,
        control: &control,
        pair: checked.pair(),
        exclusions: &frame.exclusions,
        slot: &slot,
        transaction: &transaction,
        snapshot: &snapshot_bytes,
        fence: checked.fence().1,
        owner,
    })
    .map_err(failure)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(failure)?;
    // The one-shot native result, not visible bytes or unit callback success,
    // establishes the closed exclusion durability boundary before any Pending.
    trash(fs, &mut frame, root, &control, checked, prepared).await?;
    current.effect_context().final_check().recheck()?;
    Ok(())
}
