//! Produces checked leases from actual selected Guard, registration and clock inputs.
//!
//! This logical descendant of `selected_bridge` alone initializes the private
//! collector carrier. Canonical bytes remain data until the configured maintenance
//! factory has retained real namespace and consumed control exclusions.

use crate::bucket::held::SingleHeld;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::lease::{LeaseError, LeaseReceipt, Proposal};
use crate::guard::{ConsumedResolver, Guard, OriginalAuthority};
use crate::store::{
    Clock, ContentValidator, LocalFs, NativeEffectClock, StoreErrorKind, StoreFailure,
};
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};
use terrane_core::gc::GcLease;
use terrane_core::gc::publication::LogicalChange;

use super::{CheckedGcLease, GcLeaseEffectContext, OwnedFinalCheck};

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

fn denied() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-lease",
        pattern: "configured collector lease".into(),
    })
}

struct LeaseClock {
    clock: NativeEffectClock,
    last: Mutex<(Duration, Duration)>,
    expiry: u64,
    renewal_expiry: Option<u64>,
}

impl LeaseClock {
    fn recheck(&self) -> Result<(), StoreFailure> {
        let monotonic = self.clock.monotonic();
        let wall = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?;
        let mut last = self.last.lock().map_err(|_| denied())?;
        if monotonic < last.0
            || wall < last.1
            || wall.as_secs() >= self.expiry
            || self
                .renewal_expiry
                .is_some_and(|expiry| wall.as_secs() >= expiry)
        {
            return Err(denied());
        }
        *last = (monotonic, wall);
        Ok(())
    }
}

/// Selects one lease successor using actual configured maintenance authority.
///
/// # Errors
/// Refuses live competition, stale whole renewals, stale selected Guard/configuration
/// or registration, unavailable retention, discontinuous clocks and failed effects.
pub(crate) async fn publish<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    proposal: Proposal,
) -> Result<LeaseReceipt, LeaseError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let exclusion = SingleHeld::acquire(guard.store()).await?;
    let held = exclusion.destination();
    let observed = held.observe_publication_unrepaired().await?;
    let current = observed
        .logical()
        .get("gc/lease")
        .ok_or_else(denied)?
        .as_deref()
        .map(GcLease::decode)
        .transpose()?;

    // Read the same retained injected clock that submitted workers will use.
    let clock = guard.clock().retain_native_clock().map_err(|error| {
        StoreFailure::with_source(
            if error.kind() == std::io::ErrorKind::Unsupported {
                StoreErrorKind::Unsupported
            } else {
                StoreErrorKind::Unavailable { retry_after: None }
            },
            error,
        )
    })?;
    let started = clock.monotonic();
    let started_wall = clock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| denied())?;
    let wall = started_wall.as_secs();
    let (lease, renewal_expiry) = match proposal {
        Proposal::Acquire { holder, duration } => (
            GcLease::acquire(holder, wall, duration, current.as_ref())?,
            None,
        ),
        Proposal::Renew {
            current: expected,
            duration,
        } => {
            expected.check(current.as_ref(), wall)?;
            (expected.renew(wall, duration)?, Some(expected.expiry))
        }
    };

    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    let snapshot = consumed.snapshot_bytes()?;
    let mut controls = guard
        .hold_original_registration(authority, observed.identity())
        .await?;
    let guard_record = held
        .selected_guard_snapshot_record(&observed)
        .await?
        .ok_or_else(denied)?;
    if guard_record.bytes() != Some(snapshot.as_slice()) {
        return Err(denied().into());
    }
    let used = consumed.finish()?;
    let owner = crate::guard::consumed_registration(authority);
    if used.controls.is_empty() || used.controls.iter().any(|pin| pin.owner != owner) {
        return Err(denied().into());
    }
    let retained = controls.retain_used(&used.controls).await?;
    observed.revalidate().await?;
    controls.revalidate().await?;

    let checks = LeaseClock {
        clock,
        last: Mutex::new((started, started_wall)),
        expiry: lease.expiry,
        renewal_expiry,
    };
    checks.recheck()?;
    let final_check = OwnedFinalCheck {
        check: Shared::new(move || checks.recheck()),
    };
    let mut next = observed.state().clone();
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(terrane_core::gc::GcError::Exhausted)?;
    let change = LogicalChange {
        key: "gc/lease".into(),
        expected: observed
            .logical()
            .get("gc/lease")
            .ok_or_else(denied)?
            .clone(),
        new: Some(lease.encode()?),
    };
    let checked = CheckedGcLease {
        observed: &observed,
        guard: guard_record,
        next,
        change,
        effects: GcLeaseEffectContext {
            final_check,
            controls: vec![retained],
        },
    };
    let selected =
        crate::store::native_publication_effects::collection::publish_checked(held.fs(), &checked)
            .await?;

    // Resolve the actual complete selection again, rather than acknowledging a cache.
    let after = held.observe_publication_unrepaired().await?;
    let mut expected_logical = observed.logical().clone();
    expected_logical.insert("gc/lease".into(), checked.change().new.clone());
    if after.stamp() != (selected.revision, selected.digest)
        || after.state() != checked.next()
        || after.logical() != &expected_logical
    {
        return Err(denied().into());
    }
    controls.revalidate().await?;
    checked.recheck_before_slot()?;
    Ok(LeaseReceipt {
        lease,
        revision: selected.revision,
    })
}
