//! Creates a fresh destination Trash only after real preparation acknowledgment.
//!
//! Pending, same-descriptor sealing and Committed each consume their genuine
//! native completion channel. The barrier clock begins only after the executor
//! validates and synchronizes that exact committed journal and Trash incarnation.

use super::super::super::artifact_seal::copied_retirement::barrier_plan;
use super::super::super::artifact_seal::{commit_plan, pending::pending_plan, seal_plan};
use super::{
    BucketBinding, CheckedPreparation, FencePolicy, Frame, LocalFs, Mutability, NativeBarrier,
    NativePreparation, StoreFailure, corrupt, hex, io_failure, native, unsupported,
};
use crate::store::native_effect::Plan;
use terrane_format::gc::retirement::{CopiedRetirementPreparation, LocalBarrierArtifact};
use terrane_format::gc::{ArtifactBinding, CreationJournal, JournalState, Tombstone};

async fn entropy<const N: usize, F: LocalFs>(fs: &F) -> Result<[u8; N], StoreFailure> {
    fs.random_bytes(N)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())
}

fn trash_key(preparation: &CopiedRetirementPreparation) -> Result<String, StoreFailure> {
    let plan = &preparation.plan;
    let tombstone = Tombstone::decode(&plan.tombstone).map_err(|_| corrupt())?;
    if tombstone.pack != plan.exclusion.pack
        || tombstone.cycle != plan.exclusion.cycle
        || tombstone.epoch != plan.exclusion.epoch
        || tombstone.removed != 0
        || tombstone.encode() != plan.tombstone
    {
        return Err(corrupt());
    }
    Ok(format!(
        "trash/{}/{}",
        tombstone.cycle,
        crate::pack::PackId::from_random_bytes(tombstone.pack)
    ))
}

/// Observes actual absence of both fresh destination Trash and its journal.
///
/// # Errors
/// Refuses any prior incarnation, unsafe path or actual observation failure.
pub(super) async fn reserve<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &std::path::Path,
    control: &std::path::Path,
    checked: &CheckedPreparation<'_, '_>,
) -> Result<(String, String), StoreFailure> {
    let key = trash_key(checked.preparation())?;
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

/// Creates and observes a barrier only after genuine native preparation ACK.
///
/// # Errors
/// Refuses changed retained preimages, failed creation or synchronization, a
/// different journal binding or any absent native completion acknowledgment.
pub(super) async fn create<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &std::path::Path,
    control: &std::path::Path,
    checked: &NativePreparation,
    prepared: (String, String),
) -> Result<NativeBarrier, StoreFailure> {
    let (key, suffix) = prepared;
    if key != trash_key(checked.preparation())? {
        return Err(corrupt());
    }
    let body = checked.preparation().plan.tombstone.clone();
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
        pending_plan(root, control, &key, &pending, frame.owner).map_err(native)?;
    frame.execute(fs, plan).await?;
    let receipt = receiver.take().map_err(native)?;
    frame
        .install(fs, root, &key, &body, payload, Mutability::Immutable)
        .await?;
    let (plan, receiver) = seal_plan(receipt, &body).map_err(native)?;
    frame.execute(fs, plan).await?;
    let seal = receiver.take().map_err(native)?;
    let (request, receiver) = commit_plan(
        seal,
        control,
        &pending,
        ArtifactBinding::Trash(body.clone()),
        entropy::<16, _>(fs).await?,
    )
    .map_err(native)?;
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
    receiver.take().map_err(native)?;
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
    let JournalState::Committed {
        binding,
        file_identity,
    } = committed.state
    else {
        return Err(corrupt());
    };
    if binding != ArtifactBinding::Trash(body.clone()) {
        return Err(corrupt());
    }
    let artifact = LocalBarrierArtifact {
        key,
        nonce,
        tombstone: body,
        file_identity,
    };
    let (plan, receiver) = barrier_plan(checked, artifact).map_err(native)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(native)
}
