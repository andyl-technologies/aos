//! Derives roots from exact selected refs and genuinely authenticated history.

use super::CollectionError;
use crate::bucket::publication::collection_observation::RootRef;
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::store::{Clock, Store};
use terrane_format::gc::{
    GcError, GcRoot, GcRoots, GcState, ParentCutoff, Pending, Phase, ReflogRetention,
    RetentionPolicy, RetentionTimes, RootReason, Windows,
};
use terrane_format::properties::{PropertyName, RootLayer, Value};
use terrane_format::refs::{RefClass, RefRecord, Retention};

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

/// Resolves explicit local retention under the completed view's own interpretation.
///
/// # Errors
/// Preserves complete history, selected scope and property validation refusals;
/// rejects absent canonical root occurrences or inconsistent typed retention.
async fn policy<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    record: &RefRecord,
    windows: Windows,
) -> Result<(terrane_format::provenance::VerifiedCommit, RetentionPolicy), CollectionError> {
    let checked = guard
        .verified_collection_tree_observed(record.commit, observation.tracked(consumed))
        .await?;
    let verified = checked.tree();
    let tree = verified
        .evidence
        .tree(verified.evidence.root, guard.config().min_chunk_size)?;
    let properties = tree.props().unwrap_or_default();
    let occurrences = guard.collection_occurrences(&checked)?;
    let root = occurrences
        .iter()
        .find(|occurrence| occurrence.root() == verified.evidence.root && occurrence.path() == b"/")
        .ok_or_else(super::denied)?;
    let effective = root.interpretation().resolve(
        &[RootLayer {
            properties,
            overrides: &[],
        }],
        guard.defaults_for(&verified.evidence),
    )?;

    // The selected resolver validates every local property before projection.
    // Its registry defaults must not shorten the collector's retention window;
    // only explicit local values replace window-derived defaults.
    let mut policy = RetentionPolicy::default_for(windows);
    if properties
        .iter()
        .any(|property| property.name == PropertyName::Retain.as_str())
    {
        policy.mode = match effective.get(PropertyName::Retain) {
            Some(Value::Text("gc")) => Retention::Gc,
            Some(Value::Text("lease")) => Retention::Lease,
            Some(Value::Text("forever")) => Retention::Forever,
            Some(Value::Ttl(duration)) => Retention::Ttl(*duration),
            _ => return Err(GcError::Schema.into()),
        };
    }
    if properties
        .iter()
        .any(|property| property.name == PropertyName::ReflogRetain.as_str())
    {
        policy.reflog = match effective.get(PropertyName::ReflogRetain) {
            Some(Value::Unsigned(duration)) => ReflogRetention::Duration(*duration),
            Some(Value::Count(count)) => ReflogRetention::Count(*count),
            _ => return Err(GcError::Schema.into()),
        };
    }
    if let Some(mode) = record.policy.as_ref().and_then(|policy| policy.retention) {
        policy.mode = mode;
    }
    Ok((verified.commit.clone(), policy))
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
            return Err(terrane_format::gc::GcError::Schema.into());
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
                u64::try_from(rank).map_err(|_| terrane_format::gc::GcError::Exhausted)?,
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
