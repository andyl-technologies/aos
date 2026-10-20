//! Releases expired pin promises after their original durable grace deadline.
//!
//! Automatic expiry needs no new grace timestamp: the acknowledged lease expiry
//! already survives restart. Explicit release uses a private owner label whose
//! deadline already includes grace, so it must never acquire a second grace.
//!
//! ```text
//! consumer:<32 lowercase hex>        live consumer pin and metadata hold
//! consumer-grace:<32 lowercase hex>  revoked pin with a durable grace deadline
//! ```
//!
//! These names describe policy lifecycle only. Serving still requires the actual
//! registered native job and immutable backing; a name never creates a handle.

use super::{Phase, clock, invalid, lifecycle::accounting, state};
use crate::host_cache::owner::{retention::NativeOwnerExecutor, snapshot};
use std::{collections::BTreeSet, io, sync::Arc};
use terrane_sdk::host::cache::{CacheState, LeaseRecord, PinRecord};

/// Runs bounded expiry under this executor's actual acknowledged Running context.
///
/// # Errors
/// Refuses stale native custody, invalid policy relationships, unavailable clocks,
/// unrepresentable deadlines, actual IO failure or unknown/excessive quota.
pub(in crate::host_cache::owner) async fn run(
    executor: &mut NativeOwnerExecutor,
) -> io::Result<usize> {
    executor.check_physical_worker()?;
    executor.reclaim_removed_consumer_jobs()?;
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let custody = Arc::clone(executor.custody());
    let now = clock::now_seconds()?;
    let prepared = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("consumer sweep custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        state::check_bootstrap(&owner, &running)?;
        let (mut next, removed, expired_pins) = expired_policy(
            &owner.state,
            now,
            owner.preparation.config.policy.release_grace,
        )?;
        if expired_pins == 0 {
            return Ok(0);
        }
        let mut affected = Vec::new();
        for resource in executor.consumer_jobs() {
            let job = resource
                .lock()
                .map_err(|_| invalid("consumer sweep job poisoned"))?;
            let registration = match &job.phase {
                Phase::Live(deadline) => Some((job.view.owner.as_str(), deadline.expires)),
                Phase::Grace { owner, end } => Some((owner.as_str(), *end)),
                Phase::Pending | Phase::Removed => None,
            };
            if let Some((name, expiry)) = registration.filter(|(name, _)| removed.contains(*name)) {
                state::check_job(&owner, &job, name, expiry)?;
                affected.try_reserve(1).map_err(io::Error::other)?;
                affected.push((Arc::clone(resource), Arc::clone(&job.source)));
            }
        }
        // A hold is removed only for an actual current consumer job or the
        // original reconciled cold consumer ledger. Other purposes stay owned.
        let hold = owner.preparation.config.metadata_sync_hold_bytes;
        let bootstrap = state::hex(running.retained_bootstrap_id());
        let mut released_holds = std::collections::BTreeMap::new();
        for name in &removed {
            let Some(token) = consumer_token(name) else {
                continue;
            };
            if token == bootstrap
                || next
                    .leases
                    .iter()
                    .any(|row| consumer_token(&row.owner) == Some(token))
            {
                continue;
            }
            let mut actual_job = false;
            for (resource, _) in &affected {
                if resource
                    .lock()
                    .map_err(|_| invalid("consumer sweep job poisoned"))?
                    .token
                    == token
                {
                    actual_job = true;
                    break;
                }
            }
            let original_cold = owner.recovery_cold.as_ref().and_then(|cold| {
                cold.retained_consumer_hold(token, &owner.preparation.config.quota_owner)
            });
            if actual_job {
                released_holds.insert(token.to_owned(), hold);
            } else if let Some(bytes) = original_cold {
                released_holds.insert(token.to_owned(), bytes);
            }
        }
        next.reservations.retain(|row| {
            !(released_holds.get(&row.id) == Some(&row.bytes)
                && row.owner == owner.preparation.config.quota_owner)
        });
        let removed_leases = owner
            .state
            .leases
            .len()
            .checked_sub(next.leases.len())
            .ok_or_else(|| invalid("consumer sweep lease count increased"))?;
        for (resource, _) in &affected {
            resource
                .lock()
                .map_err(|_| invalid("consumer sweep job poisoned"))?
                .view
                .close();
        }
        let write = state::begin(executor, &mut owner, &running, next, 0, None)?;
        (write, owner.generation, affected, removed_leases)
    };
    let (write, generation, affected, removed_leases) = prepared;
    snapshot::persist(executor, write).await?;
    let mut measured = Vec::new();
    measured
        .try_reserve_exact(affected.len())
        .map_err(io::Error::other)?;
    for (resource, source) in affected {
        let allocated = source.synchronize_pin_backing()?;
        measured.push((resource, allocated));
    }
    state::synchronize_policy(executor)?;
    running.check_current().map_err(io::Error::other)?;
    let observation = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("consumer sweep custody poisoned"))?;
        for (resource, _) in &measured {
            resource
                .lock()
                .map_err(|_| invalid("consumer sweep job poisoned"))?
                .source
                .check_consumer_backing(&owner)?;
        }
        state::finish(&mut owner, generation)?
    };
    for (resource, allocated) in measured {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("consumer sweep job poisoned"))?;
        let accounting = accounting(
            allocated,
            state::PolicyObservation {
                charged: observation.charged,
                future: observation.future,
            },
        );
        job.phase = Phase::Removed;
        job.accounting = Some(accounting);
        job.view.record_release(accounting);
    }
    executor.reclaim_removed_consumer_jobs()?;
    Ok(removed_leases)
}

/// Avoids RPC/quota traffic when no expired protection needs mutation.
///
/// # Errors
/// Refuses poisoned custody, invalid policy deadlines and actual sweep failures.
pub(in crate::host_cache::owner) async fn background(
    executor: &mut NativeOwnerExecutor,
) -> io::Result<()> {
    executor.reclaim_removed_consumer_jobs()?;
    let now = clock::now_seconds()?;
    let needed = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("consumer sweep custody poisoned"))?;
        if owner.faulted || owner.recovery_required {
            return Ok(());
        }
        owner.state.pins.iter().try_fold(false, |needed, pin| {
            let lease = owner
                .state
                .leases
                .iter()
                .find(|row| row.owner == pin.owner)
                .ok_or_else(|| invalid("consumer pin lost its owner lease"))?;
            Ok::<_, io::Error>(
                needed
                    || (pin.expires.min(lease.expires) != super::super::RETAINED_LEASE_DEADLINE
                        && pin.expires.min(lease.expires) <= now
                        && protection_end(
                            pin,
                            lease,
                            owner.preparation.config.policy.release_grace,
                        )? <= now),
            )
        })?
    };
    if needed {
        let result = run(executor).await;
        #[cfg(feature = "native-test-fixtures")]
        if let Err(error) = &result {
            eprintln!("actual native consumer sweep refused: {error}");
        }
        result?;
    }
    Ok(())
}

fn expired_policy(
    current: &CacheState,
    now: u64,
    grace: std::time::Duration,
) -> io::Result<(CacheState, BTreeSet<String>, usize)> {
    let mut next = current.clone();
    let mut removed = BTreeSet::new();
    let mut pins = Vec::new();
    pins.try_reserve_exact(current.pins.len())
        .map_err(io::Error::other)?;
    for pin in &current.pins {
        let lease = current
            .leases
            .iter()
            .find(|row| row.owner == pin.owner)
            .ok_or_else(|| invalid("consumer pin lost its owner lease"))?;
        if pin.expires.min(lease.expires) != super::super::RETAINED_LEASE_DEADLINE
            && pin.expires.min(lease.expires) <= now
            && protection_end(pin, lease, grace)? <= now
        {
            removed.insert(pin.owner.clone());
        } else {
            pins.push(pin.clone());
        }
    }
    let expired_pins = current.pins.len() - pins.len();
    next.pins = pins;
    next.leases.retain(|row| {
        !(removed.contains(&row.owner)
            && row.expires <= now
            && !next.pins.iter().any(|pin| pin.owner == row.owner))
    });
    // A partially expired multi-pin owner keeps its remaining records and hold.
    removed.retain(|name| !next.leases.iter().any(|row| &row.owner == name));
    Ok((next, removed, expired_pins))
}

fn protection_end(
    pin: &PinRecord,
    lease: &LeaseRecord,
    grace: std::time::Duration,
) -> io::Result<u64> {
    let expiry = pin.expires.min(lease.expires);
    let cache_grace = lease
        .owner
        .strip_prefix("publication-grace:")
        .or_else(|| lease.owner.strip_prefix("admission-grace:"))
        .is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    // These labels interpret an already durable deadline. They establish no
    // native ownership or read authority; original physical custody does that.
    if cache_grace
        || (lease.owner.starts_with("consumer-grace:") && consumer_token(&lease.owner).is_some())
    {
        Ok(expiry)
    } else if expiry == super::super::RETAINED_LEASE_DEADLINE {
        // Producer custody has no automatic expiry. Adding finite grace to the
        // maximum representable deadline would manufacture an overflow failure.
        Ok(expiry)
    } else {
        clock::grace_end(Some(expiry), grace)
    }
}

fn consumer_token(owner: &str) -> Option<&str> {
    let token = owner
        .strip_prefix("consumer:")
        .or_else(|| owner.strip_prefix("consumer-grace:"))?;
    (token.len() == 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn policy(owner: &str, lease_expiry: u64, pin_expiries: &[u64]) -> CacheState {
        let mut state = CacheState::default();
        state.leases.push(LeaseRecord {
            owner: owner.into(),
            expires: lease_expiry,
        });
        state.pins = pin_expiries
            .iter()
            .enumerate()
            .map(|(index, expires)| PinRecord {
                owner: owner.into(),
                hash: format!("{index:064x}"),
                expires: *expires,
            })
            .collect();
        state
    }

    #[test]
    fn delayed_sweep_uses_original_expiry_and_never_restarts_grace() -> io::Result<()> {
        let original = policy("finite-owner", 10, &[10]);
        let (protected, owners, count) = expired_policy(&original, 39, Duration::from_secs(30))?;
        assert_eq!(protected.pins.len(), 1);
        assert!(owners.is_empty());
        assert_eq!(count, 0);

        for now in [40, 400] {
            let (expired, owners, count) = expired_policy(&original, now, Duration::from_secs(30))?;
            assert!(expired.pins.is_empty());
            assert!(expired.leases.is_empty());
            assert_eq!(owners, BTreeSet::from(["finite-owner".to_owned()]));
            assert_eq!(count, 1);
        }
        Ok(())
    }

    #[test]
    fn explicit_grace_has_no_second_grace_and_retained_producers_do_not_expire() -> io::Result<()> {
        for owner in [
            "consumer-grace:0123456789abcdef0123456789abcdef",
            "publication-grace:0123456789abcdef0123456789abcdef",
            "admission-grace:0123456789abcdef0123456789abcdef",
        ] {
            let explicit = policy(owner, 40, &[40]);
            let (expired, _, count) = expired_policy(&explicit, 40, Duration::from_secs(30))?;
            assert!(expired.pins.is_empty());
            assert!(expired.leases.is_empty());
            assert_eq!(count, 1);
        }

        let retained = policy(
            "publication:original",
            super::super::super::RETAINED_LEASE_DEADLINE,
            &[super::super::super::RETAINED_LEASE_DEADLINE],
        );
        let (unchanged, owners, count) = expired_policy(&retained, u64::MAX, Duration::MAX)?;
        assert_eq!(unchanged.pins.len(), 1);
        assert_eq!(unchanged.leases.len(), 1);
        assert!(owners.is_empty());
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn partial_pin_expiry_is_persisted_without_releasing_the_remaining_owner() -> io::Result<()> {
        let original = policy("multi-pin-owner", 100, &[10, 100]);
        let (partial, owners, count) = expired_policy(&original, 40, Duration::from_secs(30))?;
        assert_eq!(partial.pins.len(), 1);
        assert_eq!(partial.pins[0].expires, 100);
        assert_eq!(partial.leases.len(), 1);
        assert!(owners.is_empty());
        assert_eq!(count, 1);

        let (expired, owners, count) = expired_policy(&partial, 130, Duration::from_secs(30))?;
        assert!(expired.pins.is_empty());
        assert!(expired.leases.is_empty());
        assert_eq!(owners, BTreeSet::from(["multi-pin-owner".to_owned()]));
        assert_eq!(count, 1);
        Ok(())
    }
}
