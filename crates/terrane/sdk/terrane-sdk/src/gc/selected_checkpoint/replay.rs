//! Replays persisted traversal claims through the same held metadata walker.
//!
//! Selected roots, state and marks remain data. The caller binds them to actual
//! selected records and retains the genuine session, historical Guard and
//! consumed controls; successful replay grants no retirement authority.

use super::{CollectionError, Session, denied, roots, walk};
use crate::bucket::BucketBinding;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::selected_bridge::QualifiedCollectionRoots;
use crate::store::{Clock, ContentValidator, LocalFs};
use std::collections::BTreeSet;
use terrane_format::gc::GcState;

/// Verifies exact persisted completion and semantic marks against authentic metadata.
///
/// # Errors
/// Preserves historical verification and storage failures, and refuses stale
/// sessions, impossible completion claims or a different exact mark set.
pub(in crate::selected_bridge) async fn verify<F, B, V, C>(
    history: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    session: &Session,
    root_histories: &QualifiedCollectionRoots<'_>,
    state: &GcState,
    marks: &BTreeSet<[u8; 32]>,
) -> Result<(), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    root_histories.check_binding(observation, consumed)?;
    if root_histories.cycle_state()? != state {
        return Err(denied().into());
    }
    let roots = root_histories.snapshot();
    // Each root was independently completed in its own signed scope by the
    // closed cycle factory. Replay reuses those exact same held histories.
    let mut replay = roots::initial(roots);
    let mut replay_marks = BTreeSet::new();
    let mut replayed = false;
    while !same_traversal(&replay, state) {
        if replay.pending.is_empty() {
            return Err(denied().into());
        }
        session.recheck()?;
        walk::expand(
            history,
            consumed,
            observation,
            root_histories,
            &mut replay,
            &mut replay_marks,
        )
        .await?;
        if !replay_is_contained(&replay, state) {
            return Err(denied().into());
        }
        replayed = true;
    }
    if replayed {
        for identity in history.store().identities()? {
            replay_marks.insert(identity.terrane_v1_digest().map_err(|_| denied())?);
        }
    }
    if &replay_marks != marks {
        return Err(denied().into());
    }
    Ok(())
}

/// Compares exact persisted traversal claims independently of publication fields.
pub(super) fn same_traversal(left: &GcState, right: &GcState) -> bool {
    left.cycle == right.cycle
        && left.snapshot_at == right.snapshot_at
        && left.pending == right.pending
        && left.expanded == right.expanded
        && left.objects == right.objects
        && left.progress == right.progress
}

// Only persisted completed claims can be introduced during replay. Together
// with the finite root cutoffs, this bounds authentic expansions without a
// global history-size ceiling: stronger cutoff revisits are finite, while
// already covered work removes a frontier entry without adding dependencies.
// Equality of the final whole frontier and marks still establishes completion.
/// Refuses a replay claim absent from the exact persisted completion contexts.
pub(super) fn replay_is_contained(replay: &GcState, target: &GcState) -> bool {
    replay.expanded.iter().all(|context| {
        target.expanded.iter().any(|completed| {
            completed.commit == context.commit
                && completed.proof_context == context.proof_context
                && completed.parent_cutoff.covers(context.parent_cutoff)
        })
    }) && replay
        .objects
        .iter()
        .all(|object| target.objects.binary_search(object).is_ok())
}
