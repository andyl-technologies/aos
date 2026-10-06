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

/// Retains reusable lease publication beneath one genuinely held namespace.
#[path = "lease/held.rs"]
mod held;

/// Exposes the closed held context to genuine collector/session producers.
pub(crate) use held::HeldLeaseContext;

/// Constructs a context from configured authority and the actual namespace holder.
///
/// # Errors
/// Refuses mismatched selected Guard/registration, unsafe or unavailable native
/// control retention and unsupported or discontinuous retained clocks.
pub(crate) async fn context<'held, 'configuration, F, B, V, C>(
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    held: &'held crate::bucket::held::HeldBucket<'configuration, F, B, V, true>,
    controls: Option<&crate::guard::RetainedControls>,
) -> Result<HeldLeaseContext<'held, 'configuration, F, B, V, C>, LeaseError>
where
    'configuration: 'held,
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    match controls {
        Some(controls) => HeldLeaseContext::from_retained(guard, authority, held, controls).await,
        None => HeldLeaseContext::new(guard, authority, held).await,
    }
}

/// Selects one lease successor using actual configured maintenance authority.
///
/// # Errors
/// Refuses live competition, stale whole renewals, changed selected Guard or
/// registration, unavailable retention, discontinuous clocks and failed effects.
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
    let mut context = context(guard, authority, &held, None).await?;
    context.publish(proposal, None).await
}
