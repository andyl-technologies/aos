//! Captures current authority and acknowledges protected first ownership only.

use super::super::artifact_seal::local_ownership::{ownership, triple_plan};
use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, Plan, StoreFailure, corrupt, hex, io_failure,
    unsupported,
};

/// Exposes the native worker's opaque triple observation to the genuine selector.
pub(crate) use super::super::artifact_seal::local_ownership::NativeLocalTriple;
/// Exposes transparent owning-test observers through their actual native parent.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use super::super::artifact_seal::local_ownership::test_fs::{
    OwnershipFs, OwnershipPhase, WorkerSelection,
};
use crate::bucket::publication::receipts::{GcPackRead, RecordRead};
use crate::selected_bridge::{
    CheckedCurrentCollection, native_local_ownership::CheckedLocalOwnership,
};
use terrane_format::gc::{CreationJournal, DeleteOperation, DeletePhase, JournalState, Tombstone};

/// Emits only the fixed first-ownership caller boundaries, with numeric data.
#[cfg(all(test, feature = "std"))]
struct OwnershipCost {
    started: Option<crate::diagnostic_clock::Tick>,
}

#[cfg(all(test, feature = "std"))]
impl OwnershipCost {
    fn new() -> Self {
        let enabled = std::env::var_os("TERRANE_REF_PHASE_TRACE").as_deref()
            == Some(std::ffi::OsStr::new("stages"));
        let trace = Self {
            started: enabled.then(crate::diagnostic_clock::tick),
        };
        trace.mark("entry", None);
        trace
    }

    fn mark(&self, phase: &'static str, boundary: Option<u8>) {
        use std::io::Write;

        let Some(started) = self.started else {
            return;
        };
        let at = crate::diagnostic_clock::tick();
        let _ = writeln!(
            std::io::stderr().lock(),
            "native-cost role=ownership-caller boundary={boundary:?} phase={phase} process_at={at:?} elapsed={:?}",
            at.saturating_sub(started),
        );
    }
}

fn failure(error: super::NativeEffectFailure) -> StoreFailure {
    match error {
        super::NativeEffectFailure::Rejected(error) => error,
        super::NativeEffectFailure::Io(error) => io_failure(error),
    }
}

async fn capture<F: LocalFs + BucketBinding>(
    fs: &F,
    current: &CheckedCurrentCollection<'_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    current.revalidate().await?;
    let (mut frame, control) = super::collection_checkpoints::retained_frame(
        fs,
        current.observed(),
        current.reads(),
        current.effect_context(),
    )
    .await?;
    let policy = FencePolicy::Payload { owner: frame.owner };
    for read in std::iter::once(current.reads().roots())
        .chain(std::iter::once(current.reads().state()))
        .chain(current.reads().inputs())
    {
        frame
            .observed_read(fs, read.path(), read.bytes(), read.metadata(), policy)
            .await?;
    }
    for mark in current.reads().marks() {
        let crate::selected_bridge::GcMarkRead::Revision { record: read, .. } = mark;
        frame
            .observed_read(fs, read.path(), read.bytes(), read.metadata(), policy)
            .await?;
    }
    Ok((frame, control))
}

/// Observes genuine current pack/index/Trash descriptors and their three creator journals.
///
/// # Errors
/// Refuses unsafe or unknown creator evidence, altered native inputs and unexecuted workers.
pub(crate) async fn observe<F: LocalFs + BucketBinding>(
    fs: &F,
    current: &CheckedCurrentCollection<'_, '_>,
    read: &GcPackRead,
    trash: &RecordRead,
    tombstone: &Tombstone,
) -> Result<NativeLocalTriple, StoreFailure> {
    let (mut frame, control) = capture(fs, current).await?;
    let selected = current.observed();
    let root = selected.identity().root();
    let id = read.snapshot().header().id();
    let keys = [
        id.pack_key(),
        id.index_key(),
        format!("trash/{}/{}", tombstone.cycle, id),
    ];
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    let mut journals = Vec::new();
    for key in &keys {
        let path = control
            .join(".terrane-creation")
            .join(hex(blake3::hash(key.as_bytes()).as_bytes()));
        journals.push(
            frame
                .actual_read(fs, &path, protected)
                .await?
                .ok_or_else(unsupported)?,
        );
    }
    let payload = FencePolicy::Payload { owner: frame.owner };
    for record in [read.index(), trash] {
        frame
            .observed_read(
                fs,
                record.path(),
                record.bytes(),
                record.metadata(),
                payload,
            )
            .await?;
    }
    let (plan, receiver) = triple_plan(
        root,
        &control,
        read,
        journals.try_into().map_err(|_| corrupt())?,
        trash,
        tombstone,
        frame.owner,
    )
    .map_err(failure)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(failure)
}

/// Publishes Authorized, each conditional owner journal and finally Invalidated.
///
/// # Errors
/// Preserves precise current-authority, native identity and actual durability failures.
pub(crate) async fn publish<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedLocalOwnership<'_, '_>,
) -> Result<DeleteOperation, StoreFailure> {
    #[cfg(all(test, feature = "std"))]
    let cost = OwnershipCost::new();
    checked.triple().recheck().map_err(failure)?;
    let current = checked.current();
    #[cfg(all(test, feature = "std"))]
    cost.mark("capture-start", None);
    let (mut frame, control) = capture(fs, current).await?;
    #[cfg(all(test, feature = "std"))]
    cost.mark("capture-complete", None);
    let policy = FencePolicy::ProtectedRecord { owner: frame.owner };
    let operation = checked.operation();
    let key = operation.authorization.operation_key();
    if frame
        .actual_read(fs, &control.join(&key), policy)
        .await?
        .is_some()
    {
        return Err(unsupported());
    }
    for version in &operation.authorization.artifacts {
        let original = CreationJournal {
            key: version.key.clone(),
            nonce: version.nonce,
            state: JournalState::Committed {
                binding: version.binding.clone(),
                file_identity: version.file_identity.clone(),
            },
        };
        let path = control
            .join(".terrane-creation")
            .join(hex(blake3::hash(version.key.as_bytes()).as_bytes()));
        if frame.actual_read(fs, &path, policy).await?.as_deref()
            != Some(original.encode().map_err(|_| corrupt())?.as_slice())
        {
            return Err(corrupt());
        }
    }
    #[cfg(all(test, feature = "std"))]
    cost.mark("preflight-complete", None);
    for boundary in 0..=4 {
        #[cfg(all(test, feature = "std"))]
        cost.mark("boundary-start", Some(boundary));
        current.revalidate().await?;
        checked.triple().recheck().map_err(failure)?;
        let nonce: [u8; 16] = fs
            .random_bytes(16)
            .await
            .map_err(io_failure)?
            .try_into()
            .map_err(|_| unsupported())?;
        let (request, receiver) = ownership::plan(checked, boundary, nonce).map_err(failure)?;
        let (target, expected) = request.destination();
        let target = target.to_owned();
        let temporary = request.temporary_path().to_owned();
        let body = request.body().to_vec();
        let relative = target.strip_prefix(&control).map_err(|_| corrupt())?;
        let mut parent = control.clone();
        for part in relative.parent().ok_or_else(corrupt)?.components() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err(corrupt());
            }
            parent.push(part);
            frame
                .directory(
                    fs,
                    &parent,
                    FencePolicy::PrivateControlDirectory { owner: frame.owner },
                )
                .await?;
        }
        #[cfg(all(test, feature = "std"))]
        cost.mark("directories-complete", Some(boundary));
        if frame.actual_read(fs, &target, policy).await?.as_deref() != expected
            || frame.actual_read(fs, &temporary, policy).await?.is_some()
        {
            return Err(corrupt());
        }
        #[cfg(all(test, feature = "std"))]
        cost.mark("dispatch", Some(boundary));
        frame
            .execute(fs, Plan::AcknowledgeLocalOwnership(Box::new(request)))
            .await?;
        receiver.take().map_err(failure)?;
        #[cfg(all(test, feature = "std"))]
        cost.mark("acknowledged", Some(boundary));
        // Rebind only the native worker's exact acknowledged protected replacement.
        frame
            .reads
            .retain(|read| read.path != target && read.path != temporary);
        if frame.actual_read(fs, &target, policy).await?.as_deref() != Some(body.as_slice()) {
            return Err(corrupt());
        }
    }
    current.revalidate().await?;
    let context = current.effect_context();
    if context.controls().len() != context.control_owners().len() {
        return Err(corrupt());
    }
    for (retained, owner) in context.controls().iter().zip(context.control_owners()) {
        crate::selected_bridge::native_collection::revalidate_controls(fs, retained, owner.pins())
            .await?;
    }
    context.final_check().recheck()?;
    checked.triple().recheck().map_err(failure)?;
    #[cfg(all(test, feature = "std"))]
    cost.mark("final-checks-complete", None);
    operation
        .advance(DeletePhase::Invalidated, operation.current_lease.clone())
        .map_err(|_| corrupt())
}
