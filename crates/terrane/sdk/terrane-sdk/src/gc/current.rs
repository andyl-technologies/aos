//! Reconciles completed cycle marks with independently verified current roots.
//!
//! This producer borrows an actual held namespace for its entire result. The
//! selected checkpoint remains cycle data; fresh marking uses another metadata
//! adapter and the common collector walker. Neither this result nor serialized
//! fence bytes select retirement, qualify backend age or grant deletion.

use super::{
    CheckedCurrentCollection, GcCheckpointEffectContext, GcCheckpointReads, GcControlOwner,
    GcMarkRead, OwnedFinalCheck,
};
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{SelectedObservation, collection_observation};
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::runner::{CollectionError, denied, roots, session::Session, walk};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::collections::BTreeSet;
use terrane_format::bucket::{BucketCapabilities, BucketKey};
use terrane_format::gc::publication::CommittedSelection;
use terrane_format::gc::retirement::{CurrentCollectionFence, FenceRef, RecordPointer};
use terrane_format::gc::{GcLease, GcMark, GcRoots, GcState, Phase, RootReason, Windows};
use terrane_format::refs::RefClass;

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}

// Time can narrow content roots into retention witnesses. A witness never
// covers a full visit; a full visit covers the narrower witness at that same
// signed identity, and cutoff dominance applies only within that identity.
fn covered_at_later_time(earlier: &GcRoots, later: &GcRoots) -> bool {
    earlier.cycle == later.cycle
        && earlier.epoch == later.epoch
        && earlier.timestamp <= later.timestamp
        && later.roots.iter().all(|current| {
            earlier.roots.iter().any(|previous| {
                previous.reference == current.reference
                    && previous.commit == current.commit
                    && previous.parent_cutoff.covers(current.parent_cutoff)
                    && (previous.reason != RootReason::RetentionWitness
                        || current.reason == RootReason::RetentionWitness)
            })
        })
}

fn fence_refs(
    observed: &SelectedObservation<'_>,
    capabilities: &BucketCapabilities,
    roots: &[collection_observation::RootRef],
) -> Result<Vec<FenceRef>, StoreFailure> {
    let names = capabilities.ref_names.as_ref().ok_or_else(unsupported)?;
    let mut rows = Vec::with_capacity(names.len());
    for name in names {
        let key = BucketKey::ref_record(name).map_err(|_| denied())?;
        let current = observed
            .logical()
            .get(key.as_str())
            .ok_or_else(denied)?
            .clone();
        let class = terrane_format::refs::RefName::parse(name)
            .map_err(|_| denied())?
            .class();
        let branch = matches!(
            class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        );
        let (selection, log) = if branch {
            let selected = observed
                .state()
                .branches
                .iter()
                .find(|row| row.name == *name)
                .ok_or_else(denied)?;
            let log = match &selected.selection {
                CommittedSelection::Unknown => return Err(unsupported()),
                CommittedSelection::Never if current.is_none() => None,
                CommittedSelection::Never => return Err(denied()),
                CommittedSelection::Selected(last) => {
                    let reference = roots
                        .iter()
                        .find(|row| row.name.as_str() == name)
                        .ok_or_else(denied)?;
                    Some(
                        reference
                            .logs
                            .iter()
                            .find(|log| log.record == **last)
                            .ok_or_else(denied)?
                            .clone(),
                    )
                }
            };
            (selected.selection.clone(), log)
        } else {
            // Notes are authoritative opaque bytes, even when they resemble a
            // RefRecord. Tags retain their whole bytes without branch selection.
            (CommittedSelection::Never, None)
        };
        rows.push(FenceRef {
            name: name.clone(),
            current,
            selection,
            log,
        });
    }
    Ok(rows)
}

/// Verifies a completed selected cycle and fresh roots under the caller's actual holder.
///
/// The caller starts a genuine Session operation, renews its whole lease before
/// acquiring the namespace, and keeps that operation and holder alive through
/// any subsequent checked producer. The result borrows the exact selected
/// observation and Session; it cannot outlive either. A consumer must retain
/// the returned controls and final check in every submitted native worker.
///
/// # Errors
/// Preserves Guard, storage and canonical checkpoint failures. Refuses changed
/// selected progress, incomplete catalogs/roots/history, foreign control owners
/// lacking their paired factory, time rollback, cancellation or lease expiry.
pub(crate) async fn qualify<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    checkpoint: (&GcRoots, &GcState),
    windows: Windows,
) -> Result<CheckedCurrentCollection<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    qualify_retained(
        guard,
        authority,
        session,
        held,
        observed,
        (checkpoint, windows),
        None,
    )
    .await
}

/// Requalifies complete current roots while reusing genuine consumed-control exclusion.
///
/// # Errors
/// Preserves full qualification failures and refuses changed or incomplete retained controls.
pub(crate) async fn qualify_retained<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    settings: ((&GcRoots, &GcState), Windows),
    retained_controls: Option<&crate::guard::RetainedControls>,
) -> Result<CheckedCurrentCollection<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    qualify_inner(
        guard,
        authority,
        session,
        held,
        observed,
        QualificationSettings {
            checkpoint: settings.0,
            windows: settings.1,
            carry_sources: false,
        },
        retained_controls,
    )
    .await
}

/// Completes current roots and independent full source visits for retirement.
///
/// # Errors
/// Preserves current qualification and independent source visitation failures.
/// No source mark or lineage body is accepted from the caller.
pub(crate) async fn qualify_retirement<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    checkpoint: (&GcRoots, &GcState),
    windows: Windows,
) -> Result<CheckedCurrentCollection<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    qualify_inner(
        guard,
        authority,
        session,
        held,
        observed,
        QualificationSettings {
            checkpoint,
            windows,
            carry_sources: true,
        },
        None,
    )
    .await
}

struct QualificationSettings<'a> {
    checkpoint: (&'a GcRoots, &'a GcState),
    windows: Windows,
    carry_sources: bool,
}

async fn qualify_inner<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    settings: QualificationSettings<'_>,
    retained_controls: Option<&crate::guard::RetainedControls>,
) -> Result<CheckedCurrentCollection<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let QualificationSettings {
        checkpoint,
        windows,
        carry_sources,
    } = settings;
    #[cfg(test)]
    qualification_stage("selected-checks", carry_sources);
    let (expected_roots, expected_state) = checkpoint;
    let now = session.recheck()?;
    let lease = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(GcLease::decode)
        .transpose()?;
    session.lease().check(lease.as_ref(), now)?;
    observed.revalidate().await?;
    if held.root() != observed.identity().root()
        || held.physical_identity() != observed.identity().physical_identity()
        || guard.store().publication_operator_uid() != Some(observed.configured_operator_uid())
        || !observed.identity().writable()
    {
        return Err(unsupported().into());
    }
    held.retained_namespace()?;
    observed.identity().retained_namespace()?;

    let root_key = format!("gc/{}/roots", expected_roots.cycle);
    let state_key = format!("gc/{}/state", expected_roots.cycle);
    let root_bytes = observed
        .logical()
        .get(&root_key)
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let state_bytes = observed
        .logical()
        .get(&state_key)
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let selected_roots = GcRoots::decode(root_bytes)?;
    let selected_state = GcState::decode(state_bytes)?;
    if &selected_roots != expected_roots
        || &selected_state != expected_state
        || selected_state.phase != Phase::Sweep
        || !selected_state.pending.is_empty()
        || !selected_state.progress.is_empty()
        || selected_roots.cycle != selected_state.cycle
        || selected_roots.timestamp != selected_state.snapshot_at
        || selected_roots.epoch != selected_state.epoch
        || selected_state.epoch != session.lease().epoch
    {
        return Err(denied().into());
    }
    #[cfg(test)]
    qualification_stage("checkpoint-reads", carry_sources);
    let mut mark_reads = Vec::new();
    let mut cycle_marks = BTreeSet::new();
    for pointer in &selected_state.checkpoints {
        session.recheck()?;
        let record = collection_observation::record(
            held,
            &format!(
                "gc/{}/mark/{}/{}",
                selected_roots.cycle, pointer.shard, pointer.revision
            ),
        )
        .await?;
        let bytes = record.bytes().ok_or_else(denied)?;
        let mark = GcMark::decode(bytes)?;
        if digest(bytes) != pointer.hash
            || mark.cycle() != selected_roots.cycle
            || mark.epoch() != selected_state.epoch
            || mark.shard() != pointer.shard
        {
            return Err(denied().into());
        }
        cycle_marks.extend(mark.hashes().iter().copied());
        mark_reads.push(GcMarkRead::Revision {
            shard: pointer.shard,
            revision: pointer.revision,
            record,
        });
    }

    #[cfg(test)]
    qualification_stage("guard-configuration", carry_sources);
    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    let snapshot_bytes = consumed.snapshot_bytes()?;
    let guard_record = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(denied)?;
    if observed.state().guard != Some(digest(&snapshot_bytes))
        || guard_record.bytes() != Some(snapshot_bytes.as_slice())
    {
        return Err(denied().into());
    }
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);

    // Replay is a data check only. Its metadata cache and fetched identities
    // must never contaminate the independently recomputed current mark set.
    let replay = crate::guard::collection_authority::historical_guard(
        guard,
        held,
        observed,
        session,
        session.clock()?,
    )?;
    if let Some(retained) = retained_controls {
        replay.retain_original_controls(retained)?;
    }
    #[cfg(test)]
    qualification_stage("cycle-histories", carry_sources);
    let cycle_histories = super::native_collection_roots::cycle(
        &replay,
        &consumed,
        held,
        observed,
        session,
        selected_roots.cycle,
    )
    .await?;
    let (root_read, state_read) = cycle_histories.cycle_reads()?;
    let (root_read, state_read) = (root_read.clone(), state_read.clone());
    let (cycle_root_bytes, cycle_state_bytes) = cycle_histories.cycle_bytes()?;
    #[cfg(test)]
    qualification_stage("cycle-replay", carry_sources);
    crate::selected_bridge::native_collection_checkpoints::replay::verify(
        &replay,
        &consumed,
        observation,
        session,
        &cycle_histories,
        &selected_state,
        &cycle_marks,
    )
    .await?;
    #[cfg(test)]
    qualification_stage("current-catalog", carry_sources);
    let history = crate::guard::collection_authority::historical_guard(
        guard,
        held,
        observed,
        session,
        session.clock()?,
    )?;
    if let Some(retained) = retained_controls {
        history.retain_original_controls(retained)?;
    }
    let catalog = history.store().collection_catalog().await?;
    catalog.inventory()?;
    catalog.exclusions()?;
    catalog.burns()?;
    #[cfg(test)]
    qualification_stage("current-inventory", carry_sources);
    let mut inputs = Vec::new();
    let refs = collection_observation::inventory(held, observed, &mut inputs).await?;
    let capabilities =
        BucketCapabilities::decode(catalog.capability_bytes()).map_err(|_| denied())?;
    let rows = fence_refs(observed, &capabilities, &refs)?;
    // Retain the full selected log-chain observations separately from fence
    // head rows, including every absent branch's last selected predecessor.
    #[cfg(test)]
    qualification_stage("current-histories", carry_sources);
    let current_histories = super::native_collection_roots::current(
        &history,
        &consumed,
        held,
        observed,
        session,
        (selected_roots.cycle, windows),
    )
    .await?;
    inputs.extend(current_histories.current_inputs()?.iter().cloned());
    let current_roots = current_histories.snapshot().clone();
    let mut current_state = roots::initial(&current_roots);
    let mut current_marks = BTreeSet::new();
    #[cfg(test)]
    qualification_stage("current-mark", carry_sources);
    while !current_state.pending.is_empty() {
        session.recheck()?;
        walk::expand(
            &history,
            &consumed,
            observation,
            &current_histories,
            &mut current_state,
            &mut current_marks,
        )
        .await?;
    }

    // Retention evaluation uses actual current Session time. It can narrow
    // roots while the immutable ref/policy set stays held; exact equality to
    // the cycle snapshot or an earlier conservative cutoff is unnecessary.
    #[cfg(test)]
    qualification_stage("late-roots", carry_sources);
    let late_refs = collection_observation::inventory(held, observed, &mut inputs).await?;
    let late_roots = roots::snapshot(
        &history,
        &consumed,
        observation,
        late_refs,
        roots::SnapshotSettings {
            cycle: selected_roots.cycle,
            epoch: session.lease().epoch,
            timestamp: session.recheck()?,
            windows,
        },
    )
    .await?;
    if !covered_at_later_time(&current_roots, &late_roots) {
        return Err(denied().into());
    }
    for identity in history.store().identities()? {
        current_marks.insert(identity.terrane_v1_digest().map_err(|_| denied())?);
    }
    inputs.extend(replay.store().reads()?);
    inputs.extend(history.store().reads()?);
    let mut eligibility_marks = cycle_marks.clone();
    eligibility_marks.extend(current_marks.iter().copied());

    #[cfg(test)]
    qualification_stage("sources", carry_sources);
    let sources = if carry_sources {
        Some(
            super::native_collection_sources::qualify(
                guard,
                authority,
                session,
                held,
                observed,
                (&current_histories, retained_controls),
            )
            .await?,
        )
    } else {
        None
    };
    let mut used = consumed.finish()?;
    if let Some(sources) = &sources {
        eligibility_marks.extend(sources.marks().iter().copied());
        inputs.extend(sources.inputs().iter().cloned());
        used.controls = sources.merge_controls(&used.controls)?;
    }
    let owner = crate::guard::consumed_registration(authority);
    if used.controls.is_empty() || used.controls.iter().any(|pin| pin.owner != owner) {
        // Genuine foreign imports need the paired native holder and independently
        // configured owner. Destination UID never substitutes for that factory.
        return Err(unsupported().into());
    }
    #[cfg(test)]
    qualification_stage("controls", carry_sources);
    let mut controls = None;
    let retained = match retained_controls {
        Some(retained) => {
            if retained.directory() != authority.control()
                || retained.owner() != observed.configured_operator_uid()
            {
                return Err(denied().into());
            }
            super::native_collection::revalidate_controls(held.fs(), retained, &used.controls)
                .await?;
            retained.clone()
        }
        None => {
            let mut acquired = guard
                .hold_original_registration(authority, observed.identity())
                .await?;
            let retained = acquired.retain_used(&used.controls).await?;
            controls = Some(acquired);
            retained
        }
    };
    let generation = capabilities.generation.ok_or_else(unsupported)?;
    let manifest = observed
        .logical()
        .get(&format!("objects/index/{generation}/MANIFEST"))
        .and_then(Option::as_ref)
        .ok_or_else(denied)?
        .clone();
    let fence = CurrentCollectionFence {
        capabilities: catalog.capability_bytes().to_vec(),
        manifest: Some(manifest),
        refs: rows,
        guard: digest(&snapshot_bytes),
        state: observed.state().clone(),
        roots: RecordPointer {
            key: root_key,
            digest: digest(cycle_root_bytes),
        },
        marks: RecordPointer {
            key: state_key,
            digest: digest(cycle_state_bytes),
        },
        backend: observed.state().binding.clone(),
        controls: used.controls.clone(),
    };
    fence.encode().map_err(|_| denied())?;
    #[cfg(test)]
    qualification_stage("closing-revalidation", carry_sources);
    observed.revalidate().await?;
    if let Some(controls) = &mut controls {
        controls.revalidate().await?;
    }
    if controls.is_none() {
        super::native_collection::revalidate_controls(held.fs(), &retained, &used.controls).await?;
    }
    session.recheck()?;
    #[cfg(test)]
    qualification_stage("complete", carry_sources);
    Ok(CheckedCurrentCollection {
        observed,
        session,
        fence,
        selected_roots,
        selected_state,
        #[cfg(all(test, feature = "tokio", unix))]
        current_roots,
        #[cfg(all(test, feature = "tokio", unix))]
        late_roots,
        #[cfg(all(test, feature = "tokio", unix))]
        current_state,
        #[cfg(all(test, feature = "tokio", unix))]
        cycle_marks,
        #[cfg(all(test, feature = "tokio", unix))]
        current_marks,
        eligibility_marks,
        sources,
        reads: GcCheckpointReads {
            roots: root_read,
            state: state_read,
            marks: mark_reads,
            inputs,
            guard: guard_record,
        },
        effects: GcCheckpointEffectContext {
            lease: session.lease().clone(),
            final_check: OwnedFinalCheck {
                check: Shared::new(session.owned_check()),
            },
            control_owners: vec![GcControlOwner {
                registration: owner,
                configured_operator_uid: observed.configured_operator_uid(),
                pins: used.controls,
            }],
            controls: vec![retained],
        },
    })
}

/// Qualifies fresh current roots for restore without consuming old cycle marks.
///
/// # Errors
/// Refuses incomplete or changed selection, unqualified candidate metadata,
/// mismatched actual Guard/holder/Session, lost lease, controls or clock continuity.
pub(crate) async fn qualify_restore<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    settings: (u64, Windows),
    pair: &crate::store::native_publication_effects::NativeRestorePair,
) -> Result<super::CheckedRestoreCurrent<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    qualify_restore_retained(
        guard,
        authority,
        session,
        held,
        observed,
        (settings, None),
        pair,
    )
    .await
}

/// Requalifies restoration using the same genuine retained Original exclusion.
///
/// # Errors
/// Preserves complete current qualification failures and refuses altered receipts or controls.
pub(crate) async fn qualify_restore_retained<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    settings: ((u64, Windows), Option<&crate::guard::RetainedControls>),
    pair: &crate::store::native_publication_effects::NativeRestorePair,
) -> Result<super::CheckedRestoreCurrent<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (settings, retained_controls) = settings;
    let now = session.recheck()?;
    let lease = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(GcLease::decode)
        .transpose()?;
    session.lease().check(lease.as_ref(), now)?;
    observed.revalidate().await?;
    if held.root() != observed.identity().root()
        || held.physical_identity() != observed.identity().physical_identity()
        || guard.store().publication_operator_uid() != Some(observed.configured_operator_uid())
        || !observed.identity().writable()
    {
        return Err(unsupported().into());
    }
    held.retained_namespace()?;
    pair.check_root(held.root())
        .map_err(super::native_restore_failure)?;

    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    let snapshot = consumed.snapshot_bytes()?;
    let guard_record = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(denied)?;
    if observed.state().guard != Some(digest(&snapshot))
        || guard_record.bytes() != Some(snapshot.as_slice())
    {
        return Err(denied().into());
    }
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let history = crate::guard::collection_authority::historical_guard(
        guard,
        held,
        observed,
        session,
        session.clock()?,
    )?;
    if let Some(retained) = retained_controls {
        history.retain_original_controls(retained)?;
    }
    history.store().enable_restore(pair).await?;
    let catalog = history.store().collection_catalog().await?;
    catalog.inventory()?;
    catalog.exclusions()?;
    catalog.burns()?;
    let mut inputs = Vec::new();
    let refs = collection_observation::inventory(held, observed, &mut inputs).await?;
    let capabilities =
        BucketCapabilities::decode(catalog.capability_bytes()).map_err(|_| denied())?;
    fence_refs(observed, &capabilities, &refs)?;
    let histories = super::native_collection_roots::current(
        &history, &consumed, held, observed, session, settings,
    )
    .await?;
    inputs.extend(histories.current_inputs()?.iter().cloned());
    let current = histories.snapshot().clone();
    let mut state = roots::initial(&current);
    let mut marks = BTreeSet::new();
    while !state.pending.is_empty() {
        session.recheck()?;
        walk::expand(
            &history,
            &consumed,
            observation,
            &histories,
            &mut state,
            &mut marks,
        )
        .await?;
    }
    // Time can narrow retention while the same exact current input set is held.
    let late_refs = collection_observation::inventory(held, observed, &mut inputs).await?;
    let late = roots::snapshot(
        &history,
        &consumed,
        observation,
        late_refs,
        roots::SnapshotSettings {
            cycle: settings.0,
            epoch: session.lease().epoch,
            timestamp: session.recheck()?,
            windows: settings.1,
        },
    )
    .await?;
    if !covered_at_later_time(&current, &late) {
        return Err(denied().into());
    }
    inputs.extend(history.store().reads()?);
    let used = consumed.finish()?;
    let owner = crate::guard::consumed_registration(authority);
    if used.controls.is_empty() || used.controls.iter().any(|pin| pin.owner != owner) {
        return Err(unsupported().into());
    }
    let retained = match retained_controls {
        Some(retained) => {
            if retained.directory() != authority.control()
                || retained.owner() != observed.configured_operator_uid()
            {
                return Err(denied().into());
            }
            super::native_collection::revalidate_controls(held.fs(), retained, &used.controls)
                .await?;
            retained.clone()
        }
        None => {
            let mut controls = guard
                .hold_original_registration(authority, observed.identity())
                .await?;
            let retained = controls.retain_used(&used.controls).await?;
            controls.revalidate().await?;
            retained
        }
    };
    observed.revalidate().await?;
    session.recheck()?;
    let final_check = OwnedFinalCheck {
        check: Shared::new(session.owned_check()),
    }
    .with_restore_pair(pair);
    Ok(super::CheckedRestoreCurrent {
        observed,
        session,
        inputs,
        guard: guard_record,
        effects: GcCheckpointEffectContext {
            lease: session.lease().clone(),
            final_check,
            control_owners: vec![GcControlOwner {
                registration: owner,
                configured_operator_uid: observed.configured_operator_uid(),
                pins: used.controls,
            }],
            controls: vec![retained],
        },
    })
}

/// Reports qualification phases without supplying collector time or authority.
#[cfg(test)]
fn qualification_stage(phase: &'static str, carry_sources: bool) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!(
            "gc-current-stage phase={phase} carry_sources={carry_sources} process_at={:?}",
            crate::diagnostic_clock::tick(),
        );
    }
}

#[cfg(test)]
#[path = "current/tests.rs"]
mod tests;
