//! Derives roots from exact selected refs and genuinely authenticated history.

use super::CollectionError;
use crate::bucket::publication::collection_observation::RootRef;
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::store::{Clock, Store};
use terrane_core::gc::{
    GcRoot, GcRoots, GcState, ParentCutoff, Pending, Phase, ReflogRetention, RetentionPolicy,
    RetentionTimes, RootReason, Windows,
};
use terrane_core::refs::{RefClass, RefRecord, Retention};

/// Contains snapshot coordinates read from the actual collector session.
pub(crate) struct SnapshotSettings {
    /// Canonical collection cycle selected by the caller.
    pub(crate) cycle: u64,
    /// Whole current lease's fencing epoch.
    pub(crate) epoch: u64,
    /// Actual retained clock's Unix seconds at the root observation.
    pub(crate) timestamp: u64,
    /// Trusted validated collection windows.
    pub(crate) windows: Windows,
}

/// Derives the exact initial frontier from an authenticated root snapshot.
pub(crate) fn initial(roots: &GcRoots) -> GcState {
    GcState {
        cycle: roots.cycle,
        epoch: roots.epoch,
        phase: Phase::Mark,
        snapshot_at: roots.timestamp,
        checkpoints: Vec::new(),
        pending: roots
            .roots
            .iter()
            .map(|root| Pending {
                kind: 3,
                hash: root.commit,
                parent_cutoff: root.parent_cutoff,
                flags: if root.reason == RootReason::RetentionWitness {
                    8
                } else {
                    0
                },
                proof_context: None,
            })
            .collect(),
        expanded: Vec::new(),
        progress: Vec::new(),
        objects: Vec::new(),
    }
}

async fn policy<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    record: &RefRecord,
    windows: Windows,
) -> Result<(terrane_core::provenance::VerifiedCommit, RetentionPolicy), CollectionError> {
    let verified = guard
        .verified_tree_observed(record.commit, observation.tracked(consumed))
        .await?;
    let tree = verified
        .evidence
        .tree(verified.evidence.root, guard.config().min_chunk_size)?;
    let policy = RetentionPolicy::resolve(
        tree.props().unwrap_or_default(),
        RetentionPolicy::default_for(windows),
        record.policy.as_ref().and_then(|policy| policy.retention),
    )?;
    Ok((verified.commit, policy))
}

/// Resolves the current roots and committed sequence retention with actual timestamps.
///
/// # Errors
/// Rejects invalid signatures, original history, root properties and incomplete logs.
pub(crate) async fn snapshot<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    refs: Vec<RootRef>,
    settings: SnapshotSettings,
) -> Result<GcRoots, CollectionError> {
    let SnapshotSettings {
        cycle,
        epoch,
        timestamp,
        windows,
    } = settings;
    let mut roots = Vec::new();
    for mut reference in refs {
        let mut current_policy = None;
        let mut current_expiry = None;
        if let Some(record) = &reference.current {
            let (commit, policy) = policy(guard, consumed, observation, record, windows).await?;
            current_policy = Some(policy);
            current_expiry = commit
                .commit()
                .profile_pair
                .lease
                .as_ref()
                .map(|lease| lease.expiry);
            let times = RetentionTimes {
                now: timestamp,
                commit: commit.commit().timestamp,
                reflog: timestamp,
                lease_expiry: current_expiry,
            };
            let reason = match reference.name.class() {
                RefClass::Tags => RootReason::Tag,
                RefClass::Jobs if current_expiry.is_some_and(|expiry| timestamp < expiry) => {
                    RootReason::Job
                }
                RefClass::Jobs => RootReason::RetentionWitness,
                _ if policy.mode == Retention::Lease && !policy.retains(times, 0) => {
                    RootReason::RetentionWitness
                }
                _ if policy.mode == Retention::Lease => RootReason::Lease,
                _ => RootReason::Current,
            };
            roots.push(GcRoot {
                reference: reference.name.clone(),
                commit: record.commit,
                parent_cutoff: policy.parent_cutoff(timestamp),
                reason,
            });
        }

        reference
            .logs
            .sort_by_key(|log| std::cmp::Reverse(log.record.seq));
        if reference
            .logs
            .windows(2)
            .any(|pair| pair[0].record.seq == pair[1].record.seq)
        {
            return Err(terrane_core::gc::GcError::Schema.into());
        }
        for (rank, log) in reference.logs.iter().enumerate() {
            let (commit, historical_policy) =
                policy(guard, consumed, observation, &log.record, windows).await?;
            let policy = current_policy.unwrap_or(historical_policy);
            let expiry = if reference.current.is_some() {
                current_expiry
            } else {
                commit
                    .commit()
                    .profile_pair
                    .lease
                    .as_ref()
                    .map(|lease| lease.expiry)
            };
            let times = RetentionTimes {
                now: timestamp,
                commit: commit.commit().timestamp,
                reflog: log.timestamp,
                lease_expiry: expiry,
            };
            let reason = if policy.retains(
                times,
                u64::try_from(rank).map_err(|_| terrane_core::gc::GcError::Exhausted)?,
            ) {
                match policy.mode {
                    Retention::Gc => match policy.reflog {
                        ReflogRetention::Duration(_) => RootReason::ReflogGc,
                        ReflogRetention::Count(_) => RootReason::ReflogCount,
                    },
                    Retention::Ttl(_) => RootReason::ReflogTtl,
                    Retention::Lease => RootReason::Lease,
                    Retention::Forever => RootReason::Forever,
                }
            } else {
                RootReason::RetentionWitness
            };
            roots.push(GcRoot {
                reference: reference.name.clone(),
                commit: log.record.commit,
                parent_cutoff: policy.parent_cutoff(timestamp),
                reason,
            });
            if let Some(previous) = log.previous_commit {
                guard
                    .verified_tree_observed(previous, observation.tracked(consumed))
                    .await?;
                roots.push(GcRoot {
                    reference: reference.name.clone(),
                    commit: previous,
                    parent_cutoff: ParentCutoff::RootsOnly,
                    reason: RootReason::RetentionWitness,
                });
            }
        }
    }
    Ok(GcRoots {
        cycle,
        epoch,
        timestamp,
        roots,
    })
}
