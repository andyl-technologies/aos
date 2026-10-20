//! Captures maintenance pairs through the genuine retained native executor.
//!
//! The optional protected journal reads qualify refusal and continuity only.
//! Unknown creator or Trash-age evidence is retained without backfilling it.

use super::super::artifact_seal::restore_pair::{NativeRestorePair, pair_plan};
use super::{BucketBinding, FencePolicy, LocalFs, StoreFailure, io_failure};
use crate::bucket::publication::{SelectedObservation, receipts::GcPackRead};
use terrane_format::bucket::PackExclusion;

fn failure(error: super::NativeEffectFailure) -> StoreFailure {
    match error {
        super::NativeEffectFailure::Rejected(error) => error,
        super::NativeEffectFailure::Io(error) => io_failure(error),
    }
}

/// Observes exact native maintenance descriptors without minting creator evidence.
///
/// # Errors
/// Refuses unsafe or changed retained inputs, represented deletion ownership,
/// read-only access and unit success without actual completed execution.
pub(crate) async fn observe<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &SelectedObservation<'_>,
    observed: &GcPackRead,
    exclusion: &PackExclusion,
) -> Result<NativeRestorePair, StoreFailure> {
    observe_inner(fs, selected, observed, exclusion, None).await
}

/// Captures a maintenance pair backed by an executor-owned local deletion receipt.
///
/// # Errors
/// Refuses absent artifacts, wrong owner association or changed physical evidence.
pub(crate) async fn observe_cancellation<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &SelectedObservation<'_>,
    observed: &GcPackRead,
    exclusion: &PackExclusion,
    receipt: std::sync::Arc<super::collection_local_deletion::NativeLocalDeletion>,
) -> Result<NativeRestorePair, StoreFailure> {
    let authorization = &receipt.operation().authorization;
    if authorization.pack_id != exclusion.pack_id
        || authorization.cycle != exclusion.cycle
        || authorization.epoch != exclusion.epoch
    {
        return Err(super::corrupt());
    }
    observe_inner(fs, selected, observed, exclusion, Some(receipt)).await
}

async fn observe_inner<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &SelectedObservation<'_>,
    observed: &GcPackRead,
    exclusion: &PackExclusion,
    receipt: Option<std::sync::Arc<super::collection_local_deletion::NativeLocalDeletion>>,
) -> Result<NativeRestorePair, StoreFailure> {
    if observed.inventory().pack_id != exclusion.pack_id {
        return Err(super::corrupt());
    }
    let (mut frame, control) = super::raw::backend_with_control(fs, selected).await?;
    let id = observed.snapshot().header().id();
    let keys = [
        id.pack_key(),
        id.index_key(),
        format!("trash/{}/{id}", exclusion.cycle),
    ];
    let mut journals = Vec::new();
    for key in &keys {
        let path = super::super::artifact_seal::journal_path(&control, key);
        journals.push(
            frame
                .actual_read(
                    fs,
                    &path,
                    FencePolicy::ProtectedRecord { owner: frame.owner },
                )
                .await?,
        );
    }
    let read = observed.index();
    read.require_effect_compatible()?;
    frame
        .observed_read(
            fs,
            read.path(),
            read.bytes(),
            read.metadata(),
            FencePolicy::Payload { owner: frame.owner },
        )
        .await?;
    let journals = journals.try_into().map_err(|_| super::corrupt())?;
    let (plan, receiver) = if let Some(receipt) = receipt {
        super::super::artifact_seal::restore_pair::cancellation_pair_plan(
            selected.identity().root(),
            &control,
            observed,
            journals,
            keys,
            frame.owner,
            receipt,
        )
    } else {
        pair_plan(
            selected.identity().root(),
            &control,
            observed,
            journals,
            keys,
            frame.owner,
        )
    }
    .map_err(failure)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(failure)
}
