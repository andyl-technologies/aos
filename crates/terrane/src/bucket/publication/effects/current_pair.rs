//! Captures neutral collector observations under the existing genuine native Frame.
//!
//! The private native result owns actual descriptors. Neither GcPackRead nor
//! this read-only backend capture supplies mark, grace or retirement authority.

use super::super::artifact_seal::current_pair::{NativeCurrentPair, pair_plan};
use super::{BucketBinding, FencePolicy, Frame, LocalFs, StoreFailure, io_failure, unsupported};
use crate::bucket::publication::{SelectedObservation, receipts::GcPackRead};

fn failure(error: super::NativeEffectFailure) -> StoreFailure {
    match error {
        super::NativeEffectFailure::Rejected(error) => error,
        super::NativeEffectFailure::Io(error) => io_failure(error),
    }
}

impl Frame {
    /// Retains a closed current pair through each subsequently submitted effect.
    ///
    /// The Frame's complete selected inputs and final authority check remain
    /// independent. This observation alone cannot authorize an effect.
    ///
    /// # Errors
    /// Refuses changed native versions or a Frame missing original actual exclusions.
    pub(super) fn retain_current_pair(
        &mut self,
        root: &std::path::Path,
        control: &std::path::Path,
        pair: &NativeCurrentPair,
    ) -> Result<(), StoreFailure> {
        self.pairs.push(
            pair.retention(root, control, &self.exclusions)
                .map_err(failure)?,
        );
        Ok(())
    }
}

/// Obtains current native descriptors from a genuine held backend observation.
///
/// This backend-only observation grants no creator, retirement or deletion permission.
/// The genuine repository producer separately checks roots, marks, grace and lease.
///
/// # Errors
/// Refuses read-only access, unsafe inputs, Unknown journals, unavailable actual
/// retention, mismatched neutral observations and no-op native acknowledgment.
pub(crate) async fn observe<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &SelectedObservation<'_>,
    observed: &GcPackRead,
) -> Result<NativeCurrentPair, StoreFailure> {
    let (mut frame, control) = super::raw::backend_with_control(fs, selected).await?;
    let root = selected.identity().root();
    let id = observed.snapshot().header().id();
    let keys = [id.pack_key(), id.index_key()];
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    let mut journals = Vec::new();
    for key in &keys {
        let suffix: String = blake3::hash(key.as_bytes())
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = control.join(".terrane-creation").join(suffix);
        journals.push(
            frame
                .actual_read(fs, &path, protected)
                .await?
                .ok_or_else(unsupported)?,
        );
    }
    let journals = journals.try_into().map_err(|_| unsupported())?;
    let payload = FencePolicy::Payload { owner: frame.owner };
    observed.index().require_effect_compatible()?;
    frame
        .observed_read(
            fs,
            observed.index().path(),
            observed.index().bytes(),
            observed.index().metadata(),
            payload,
        )
        .await?;
    let (plan, receiver) =
        pair_plan(root, &control, observed, journals, frame.owner).map_err(failure)?;
    frame.execute(fs, plan).await?;
    receiver.take().map_err(failure)
}

/// Exercises subsequent real dispatch while preserving all ordinary Frame checks.
///
/// # Errors
/// Refuses changed actual pair/control inputs or failed native dispatch/sync.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) async fn recheck_for_test<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &SelectedObservation<'_>,
    pair: &NativeCurrentPair,
) -> Result<(), StoreFailure> {
    let (mut frame, control) = super::raw::backend_with_control(fs, selected).await?;
    frame.retain_current_pair(selected.identity().root(), &control, pair)?;
    frame
        .execute(
            fs,
            super::Plan::SyncDirectory {
                path: selected.identity().root().to_owned(),
            },
        )
        .await
}
