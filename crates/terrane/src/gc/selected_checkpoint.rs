//! Constructs private checkpoint carriers from real held selections and controls.
//!
//! Decoder output is reverified through the actual historical Guard before this
//! descendant can construct a fixed native checkpoint. Foreign control owners and
//! disclosure histories require their separate genuine paired factories.

use super::{
    CheckedGcCheckpoint, GcCheckpointEffectContext, GcCheckpointPublication, GcCheckpointReads,
    GcControlOwner, GcMarkRead, GcMarkRevision, OwnedFinalCheck,
};
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::runner::{CollectionError, denied, roots, session::Session, walk};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority};
use crate::store::{Clock, ContentValidator, LocalFs};
use std::collections::BTreeSet;
use terrane_core::gc::{CheckpointPointer, GcMark, GcRoots, GcState, Phase, Windows};

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

enum Action<'a> {
    Begin,
    Resume,
    Advance {
        roots: &'a GcRoots,
        state: &'a GcState,
        limit: usize,
        finish: bool,
    },
}

/// Selects one closed marking operation without accepting caller effect paths.
pub(crate) enum Step {
    /// Expands at most this many authenticated commit contexts.
    Mark {
        /// Maximum number of pending commit contexts to consume.
        limit: usize,
    },
    /// Completes only a genuinely empty marking frontier.
    Finish,
}

/// Authenticates every inventoried root before selecting its initial state.
///
/// # Errors
/// Refuses existing cycles, stale authority, incomplete roots and unsafe native effects.
pub(crate) async fn begin<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &Session,
    cycle: u64,
    windows: Windows,
) -> Result<(GcRoots, GcState), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    execute(guard, authority, session, cycle, windows, Action::Begin).await
}

/// Replays persisted mark contexts against freshly checked historical metadata.
///
/// # Errors
/// Rejects altered progress, stale original controls and unavailable persisted marks.
pub(crate) async fn resume<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &Session,
    cycle: u64,
    windows: Windows,
) -> Result<(GcRoots, GcState), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    execute(guard, authority, session, cycle, windows, Action::Resume).await
}

/// Advances only the exact whole checkpoint previously acknowledged by the session.
///
/// # Errors
/// Refuses a stale whole state, incomplete marking, lost lease and changed protected inputs.
pub(crate) async fn advance<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &Session,
    roots: &GcRoots,
    state: &GcState,
    windows: Windows,
    step: Step,
) -> Result<GcState, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (limit, finish) = match step {
        Step::Mark { limit } => (limit, false),
        Step::Finish => (0, true),
    };
    Ok(execute(
        guard,
        authority,
        session,
        roots.cycle,
        windows,
        Action::Advance {
            roots,
            state,
            limit,
            finish,
        },
    )
    .await?
    .1)
}

async fn execute<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &Session,
    cycle: u64,
    windows: Windows,
    action: Action<'_>,
) -> Result<(GcRoots, GcState), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let now = session.recheck()?;
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await?;
    let selected_lease = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(terrane_core::gc::GcLease::decode)
        .transpose()?;
    session
        .lease()
        .check(selected_lease.as_ref(), session.recheck()?)?;
    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    if held.selected_guard_snapshot(&observed).await?.as_deref()
        != Some(consumed.snapshot_bytes()?.as_slice())
    {
        return Err(denied().into());
    }
    let history = crate::guard::collection_authority::historical_guard(
        guard,
        &held,
        &observed,
        session,
        session.clock()?,
    )?;
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let root_key = format!("gc/{cycle}/roots");
    let state_key = format!("gc/{cycle}/state");
    let previous_roots = observed.logical().get(&root_key).cloned().flatten();
    let previous_state = observed.logical().get(&state_key).cloned().flatten();
    let root_read = collection_observation::record(&held, &root_key).await?;
    let state_read = collection_observation::record(&held, &state_key).await?;
    let mut inputs = Vec::new();
    let mut mark_reads = Vec::new();
    let mut marks = BTreeSet::new();

    let (roots, mut state) = if matches!(action, Action::Begin) {
        if previous_roots.is_some() || previous_state.is_some() {
            return Err(denied().into());
        }
        let refs = collection_observation::inventory(&held, &observed, &mut inputs).await?;
        let roots = roots::snapshot(
            &history,
            &consumed,
            observation,
            refs,
            roots::SnapshotSettings {
                cycle,
                epoch: session.lease().epoch,
                timestamp: now,
                windows,
            },
        )
        .await?;
        let state = roots::initial(&roots);
        (roots, state)
    } else {
        let roots = GcRoots::decode(previous_roots.as_deref().ok_or_else(denied)?)?;
        let state = GcState::decode(previous_state.as_deref().ok_or_else(denied)?)?;
        if roots.cycle != cycle
            || state.cycle != cycle
            || state.snapshot_at != roots.timestamp
            || state.epoch != session.lease().epoch
            || roots.epoch != state.epoch
            || !matches!(state.phase, Phase::Mark | Phase::Sweep)
            || !state.progress.is_empty()
        {
            return Err(denied().into());
        }
        if let Action::Advance {
            roots: expected_roots,
            state: expected_state,
            ..
        } = &action
            && (*expected_roots != &roots || *expected_state != &state)
        {
            return Err(denied().into());
        }
        for pointer in &state.checkpoints {
            let record = collection_observation::record(
                &held,
                &format!("gc/{cycle}/mark/{}/{}", pointer.shard, pointer.revision),
            )
            .await?;
            let bytes = record.bytes().ok_or_else(denied)?;
            let mark = GcMark::decode(bytes)?;
            if digest(bytes) != pointer.hash
                || mark.cycle() != cycle
                || mark.epoch() != state.epoch
                || mark.shard() != pointer.shard
            {
                return Err(denied().into());
            }
            marks.extend(mark.hashes().iter().copied());
            mark_reads.push(GcMarkRead::Revision {
                shard: pointer.shard,
                revision: pointer.revision,
                record,
            });
        }
        // Revisit every signed destination before replaying its persisted contexts.
        for root in &roots.roots {
            session.recheck()?;
            history
                .verified_tree_observed(root.commit, observation)
                .await?;
        }
        let mut replay = roots::initial(&roots);
        let mut replay_marks = BTreeSet::new();
        let mut replayed = false;
        while !same_traversal(&replay, &state) {
            if replay.pending.is_empty() {
                return Err(denied().into());
            }
            session.recheck()?;
            walk::expand(
                &history,
                &consumed,
                observation,
                &mut replay,
                &mut replay_marks,
            )
            .await?;
            if !replay_is_contained(&replay, &state) {
                return Err(denied().into());
            }
            replayed = true;
        }
        if replayed {
            for identity in history.store().identities()? {
                replay_marks.insert(identity.terrane_v1_digest().map_err(|_| denied())?);
            }
        }
        if replay_marks != marks {
            return Err(denied().into());
        }
        (roots, state)
    };

    let publication = match action {
        Action::Begin => Some(GcCheckpointPublication::Begin {
            state: state.clone(),
        }),
        Action::Resume => None,
        Action::Advance { limit, finish, .. } => {
            if state.phase != Phase::Mark {
                return Err(denied().into());
            }
            state.epoch = session.lease().epoch;
            if finish {
                if !state.pending.is_empty() {
                    return Err(denied().into());
                }
                // GC-7 permits complete selected revisions to remain the final
                // representation. A bare shard file would collide with its
                // native revision directory, so this lane writes no optional leaf.
                state.phase = Phase::Sweep;
                Some(GcCheckpointPublication::FinishMark {
                    state: state.clone(),
                    final_marks: Vec::new(),
                })
            } else {
                if limit == 0 || limit > 65_536 {
                    return Err(denied().into());
                }
                for _ in 0..limit {
                    if state.pending.is_empty() {
                        break;
                    }
                    session.recheck()?;
                    walk::expand(&history, &consumed, observation, &mut state, &mut marks).await?;
                }
                for identity in history.store().identities()? {
                    marks.insert(identity.terrane_v1_digest().map_err(|_| denied())?);
                }
                let mut revisions = Vec::new();
                for shard in 0..=u8::MAX {
                    let hashes = marks
                        .iter()
                        .filter(|hash| hash[0] == shard)
                        .copied()
                        .collect::<Vec<_>>();
                    if hashes.is_empty() {
                        continue;
                    }
                    let mark = GcMark::new(cycle, state.epoch, shard, hashes)?;
                    let position = state
                        .checkpoints
                        .binary_search_by_key(&shard, |pointer| pointer.shard);
                    if position.is_ok_and(|position| {
                        state.checkpoints[position].hash == digest(&mark.encode())
                    }) {
                        continue;
                    }
                    let revision = match position {
                        Ok(position) => state.checkpoints[position]
                            .revision
                            .checked_add(1)
                            .ok_or(terrane_core::gc::GcError::Exhausted)?,
                        Err(_) => 0,
                    };
                    let pointer = CheckpointPointer {
                        shard,
                        revision,
                        hash: digest(&mark.encode()),
                    };
                    match position {
                        Ok(position) => state.checkpoints[position] = pointer.clone(),
                        Err(position) => state.checkpoints.insert(position, pointer.clone()),
                    }
                    revisions.push(GcMarkRevision { pointer, mark });
                }
                Some(GcCheckpointPublication::Progress {
                    state: state.clone(),
                    revisions,
                })
            }
        }
    };

    let used = consumed.finish()?;
    let owner = crate::guard::consumed_registration(authority);
    if used.controls.is_empty() || used.controls.iter().any(|pin| pin.owner != owner) {
        // Foreign ownership needs a genuine paired source holder and its own UID.
        return Err(
            crate::store::StoreFailure::new(crate::store::StoreErrorKind::Unsupported).into(),
        );
    }
    let mut controls = guard
        .hold_original_registration(authority, observed.identity())
        .await?;
    let retained = controls.retain_used(&used.controls).await?;
    observed.revalidate().await?;
    controls.revalidate().await?;
    session.recheck()?;
    if let Some(publication) = publication {
        inputs.extend(history.store().reads()?);
        let mut next = observed.state().clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(terrane_core::gc::GcError::Exhausted)?;
        let checked = CheckedGcCheckpoint {
            observed: &observed,
            sources: Vec::new(),
            next,
            roots_digest: digest(&roots.encode()),
            roots: roots.clone(),
            previous_roots,
            previous_state,
            publication,
            reads: GcCheckpointReads {
                roots: root_read,
                state: state_read,
                marks: mark_reads,
                inputs,
            },
            effects: GcCheckpointEffectContext {
                lease: session.lease().clone(),
                final_check: OwnedFinalCheck {
                    check: Shared::new(session.owned_check()),
                },
                control_owners: vec![GcControlOwner {
                    registration: owner,
                    configured_operator_uid: guard
                        .store()
                        .publication_operator_uid()
                        .ok_or_else(denied)?,
                    pins: used.controls,
                }],
                controls: vec![retained],
            },
        };
        let selected =
            crate::store::native_publication_effects::collection_checkpoints::publish_checked(
                held.fs(),
                &checked,
            )
            .await?;
        let after = held.observe_publication_unrepaired().await?;
        let mut expected = observed.logical().clone();
        expected.insert(root_key.clone(), Some(roots.encode()));
        expected.insert(state_key.clone(), Some(state.encode()?));
        if after.stamp() != (selected.revision, selected.digest)
            || after.state() != checked.next()
            || after.logical() != &expected
        {
            return Err(denied().into());
        }
        controls.revalidate().await?;
        checked.recheck_before_slot()?;
    }
    Ok((roots, state))
}

fn same_traversal(left: &GcState, right: &GcState) -> bool {
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
fn replay_is_contained(replay: &GcState, target: &GcState) -> bool {
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

#[cfg(test)]
mod tests {
    //! Qualifies replay claim containment without constructing native authority.

    use super::*;
    use terrane_core::gc::{ExpandedContext, ExpandedObject, ParentCutoff, ProofContext};

    fn empty_state() -> GcState {
        roots::initial(&GcRoots {
            cycle: 1,
            epoch: 1,
            timestamp: 100,
            roots: Vec::new(),
        })
    }

    #[test]
    fn gc_replay_accepts_persisted_cutoff_strengthening_and_refuses_impossible_targets()
    -> Result<(), terrane_core::gc::GcError> {
        let mut target = empty_state();
        target.expanded.push(ExpandedContext {
            commit: [1; 32],
            parent_cutoff: ParentCutoff::Since(10),
            proof_context: None,
        });
        let mut replay = target.clone();

        for cutoff in [
            ParentCutoff::RootsOnly,
            ParentCutoff::Since(100),
            ParentCutoff::Since(10),
        ] {
            replay.expanded[0].parent_cutoff = cutoff;
            assert!(replay_is_contained(&replay, &target));
        }
        assert!(same_traversal(&replay, &target));

        replay.expanded[0].parent_cutoff = ParentCutoff::Unbounded;
        assert!(!replay_is_contained(&replay, &target));
        replay.expanded[0].parent_cutoff = ParentCutoff::Since(10);
        replay.expanded[0].commit = [2; 32];
        assert!(!replay_is_contained(&replay, &target));
        replay.expanded[0].commit = [1; 32];
        replay.expanded[0].proof_context =
            Some(ProofContext::new([1; 32], [3; 32], b"/file".to_vec())?);
        assert!(!replay_is_contained(&replay, &target));
        Ok(())
    }

    #[test]
    fn gc_replay_keeps_exact_full_witness_and_destination_object_claims() {
        let mut target = empty_state();
        target.objects.push(ExpandedObject {
            kind: 2,
            hash: [2; 32],
            flags: 2,
            proof_context: None,
        });
        let mut replay = target.clone();
        assert!(replay_is_contained(&replay, &target));

        replay.objects[0].flags |= 8;
        assert!(!replay_is_contained(&replay, &target));
        target.objects.push(replay.objects[0].clone());
        target.objects.sort();
        assert!(replay_is_contained(&replay, &target));

        replay.objects[0].kind = 3;
        assert!(!replay_is_contained(&replay, &target));
        replay.objects[0].kind = 2;
        replay.objects[0].hash = [3; 32];
        assert!(!replay_is_contained(&replay, &target));
    }
}
