//! Recomputes authenticated ordinary Sweep DATA under current retention policy.
//!
//! This path uses the genuine current historical Guard and ordinary collector
//! walker. It preserves actual parent cutoffs and checked proof contexts rather
//! than treating expired ancestry as an unbounded copied physical hold. It never
//! enables restore eligibility for the permanently burned candidate family.

use super::*;
use crate::gc::runner::{roots, walk};
use crate::guard::HistoryObservation;
use std::collections::BTreeSet;
use terrane_format::gc::{GcRoots, Windows};

/// Contains the actual completed current authenticated walk and its read set.
pub(super) struct CurrentData {
    /// Exact qualified roots, including their original same-clock timestamp.
    pub(super) roots: GcRoots,
    /// Actual completed authenticated expansion rows and marked identities.
    pub(super) traversal: data::Traversal,
    /// Genuine metadata/history observations consumed by the current walk.
    pub(super) reads: Vec<RecordRead>,
}

/// Completes fresh authenticated ordinary DATA using independently configured windows.
///
/// # Errors
/// Refuses unavailable current Original/policy/history, lost whole lease,
/// unresolved currently retained DATA, invalid cutoffs or checked proof contexts
/// and every genuine lower-verifier refusal. Burned placements remain denied.
pub(super) async fn check<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    consumed: &ConsumedResolver,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &SelectedObservation<'_>,
    session: &Session,
    retained: Option<&RetainedControls>,
    windows: &Windows,
) -> Result<CurrentData, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let history = crate::guard::collection_authority::historical_guard(
        guard,
        held,
        observed,
        session,
        session.clock()?,
    )?;
    if let Some(retained) = retained {
        history.retain_original_controls(retained)?;
    }
    let entropy = held.fs().random_bytes(8).await.map_err(|error| {
        StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
    })?;
    let cycle = u64::from_be_bytes(entropy.try_into().map_err(|_| denied())?);
    let qualified = super::super::native_collection_roots::current(
        &history,
        consumed,
        held,
        observed,
        session,
        (cycle, *windows),
    )
    .await?;
    let snapshot = qualified.snapshot().clone();
    let mut state = roots::initial(&snapshot);
    let mut marks = BTreeSet::new();
    let observation = HistoryObservation::held(observed.identity()).tracked(consumed);
    while !state.pending.is_empty() {
        session.recheck()?;
        walk::expand(
            &history,
            consumed,
            observation,
            &qualified,
            &mut state,
            &mut marks,
        )
        .await?;
    }
    for identity in history.store().identities()? {
        marks.insert(identity.terrane_v1_digest().map_err(|_| denied())?);
    }
    let mut reads = qualified.current_inputs()?.to_vec();
    reads.extend(history.store().reads()?);
    observed.revalidate().await?;
    session.recheck()?;
    Ok(CurrentData {
        roots: snapshot,
        traversal: data::Traversal {
            commits: state.expanded,
            objects: state.objects,
            hashes: marks.into_iter().collect(),
        },
        reads,
    })
}
