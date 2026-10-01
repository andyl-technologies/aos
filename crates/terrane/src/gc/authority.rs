//! Authenticates maintenance metadata through actual historical Guard state.
//!
//! Maintenance setup grants no actor verb. The ordinary complete historical
//! verifier records genuinely consumed policy and original-control dependencies.

use super::{Guard, StoreFailure};
use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::store::{Clock, ContentValidator, LocalFs, NativeEffectClock};

/// Borrows a metadata-only store while preserving genuine original verification.
///
/// # Errors
/// Rejects unavailable synchronized historical configuration. Every later
/// verification still rereads exact protected association and bootstrap records.
pub(crate) fn historical_guard<'operation, 'held, F, B, V, C>(
    guard: &Guard<crate::bucket::FileBucket<F, B, V>, C>,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &crate::bucket::publication::SelectedObservation<'_>,
    session: &'operation crate::gc::runner::session::Session,
    clock: NativeEffectClock,
) -> Result<Guard<MetadataStore<'operation, 'held, F, B, V>, NativeEffectClock>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let result = Guard::new(
        MetadataStore::new(held, observed, session),
        clock,
        guard.keys.clone(),
        guard.config.clone(),
    );
    *result
        .original_verifier
        .write()
        .map_err(|_| super::invalid())? = guard
        .original_verifier
        .read()
        .map_err(|_| super::invalid())?
        .clone();
    *result
        .original_baselines
        .write()
        .map_err(|_| super::invalid())? = guard
        .original_baselines
        .read()
        .map_err(|_| super::invalid())?
        .clone();
    *result
        .original_commits
        .write()
        .map_err(|_| super::invalid())? = guard
        .original_commits
        .read()
        .map_err(|_| super::invalid())?
        .clone();
    Ok(result)
}
