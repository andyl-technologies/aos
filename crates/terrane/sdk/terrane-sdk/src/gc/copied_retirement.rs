//! Coordinates destination-local copied retirement through checked first ownership.
//!
//! Complete current DATA, a fresh destination preparation and actual committed
//! Trash establish separate facts. The retained native barrier measures full G
//! and D across real same-holder lease renewals. Final current checkpoints are
//! fresh; they do not reset or claim the immutable barrier's age.
//! No physical deletion or remote-provider operation is dispatched here.

use super::*;
use crate::selected_bridge::{native_copied_placement, native_copied_retirement};
use crate::store::native_publication_effects::collection_copied_retirement as effects;
use std::time::Duration;
use terrane_format::gc::retirement::PermanentDeleteOperation;

/// Owns a destination-local lease for copied first ownership without source pruning.
///
/// Acquisition does not authenticate ordinary collection roots or infer foreign
/// Original authority. Every requested pack subsequently requires complete
/// independently qualified destination DATA and its own genuine NEW barrier.
pub struct CopiedRetirement<'configuration, F, B, V, C> {
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    session: session::Session,
    windows: Windows,
}

impl<'configuration, F, B, V, C> CopiedRetirement<'configuration, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Acquires a genuine whole collector lease before copied DATA qualification.
    ///
    /// # Errors
    /// Refuses competing current ownership, unavailable native clock, invalid
    /// lease duration or actual protected lease publication failure.
    pub async fn start(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        holder: String,
        duration: u64,
        windows: Windows,
    ) -> Result<Self, CollectionError> {
        let lease = Collector::new(guard, authority)
            .acquire(holder, duration)
            .await?
            .lease;
        let clock = guard.clock().retain_native_clock().map_err(|_| denied())?;
        let session = session::Session::new(lease, duration, clock)?;
        Ok(Self {
            guard,
            authority,
            session,
            windows,
        })
    }

    /// Selects destination-local permanent first ownership of one copied burn.
    ///
    /// The returned operation is acknowledged status, not a reusable permission.
    /// Its independently qualified current DATA carries no foreign lineage. This
    /// method never unlinks the copied pack, index or old Trash.
    ///
    /// # Errors
    /// Refuses different coordinator configuration, invalid enforced windows,
    /// incomplete DATA/history, unsafe native controls, stale whole lease,
    /// changed original controls/barrier, discontinuous time or failed native
    /// publication. Cancellation or failure permanently stops this Session.
    pub async fn own_copied_pack(
        &mut self,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        pack: [u8; 16],
    ) -> Result<PermanentDeleteOperation, CollectionError> {
        if !std::ptr::eq(self.guard, coordinator.guard()) {
            return Err(denied().into());
        }
        let maximum = coordinator.maximum_commit_duration();
        let commit = maximum
            .as_secs()
            .checked_add(u64::from(maximum.subsec_nanos() != 0))
            .ok_or(GcError::Exhausted)?;
        if self.windows.commit() != commit
            || self.windows.grace() <= commit
            || self.windows.deletion() < self.windows.grace()
        {
            return Err(GcError::Window.into());
        }
        let operation = self.session.operation()?;
        let collector = Collector::new(self.guard, self.authority);
        self.session.renew(&collector).await?;

        let barrier = {
            let holder = collector.hold_namespace().await?;
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await?;
            let data = native_copied_placement::qualify(
                self.guard,
                self.authority,
                &self.session,
                &held,
                &observed,
                pack,
                None,
            )
            .await?;
            let checked =
                native_copied_retirement::prepare(data, &held, &self.session, self.windows).await?;
            effects::prepare(held.fs(), &checked).await?
        };
        let required = Duration::from_secs(self.windows.deletion().max(self.windows.grace()));
        self.windows
            .deletion()
            .checked_mul(1_000_000_000)
            .ok_or(GcError::Exhausted)?;
        self.windows
            .grace()
            .checked_mul(1_000_000_000)
            .ok_or(GcError::Exhausted)?;
        let controls = barrier.controls().first().ok_or_else(denied)?;
        let interval = self
            .session
            .renewal_duration()
            .checked_div(3)
            .filter(|interval| !interval.is_zero())
            .ok_or(GcError::Exhausted)?
            .min(Duration::from_secs(30));
        let reserve = interval
            .as_secs()
            .checked_add(u64::from(interval.subsec_nanos() != 0))
            .ok_or(GcError::Exhausted)?;
        let mut last_renew_elapsed = None;

        loop {
            let now = self.session.recheck()?;
            let elapsed = barrier.elapsed().map_err(native)?;
            if elapsed >= required {
                break;
            }
            let since_renewal = last_renew_elapsed
                .map(|last| elapsed.checked_sub(last).ok_or(GcError::Exhausted))
                .transpose()?;
            let budget = self
                .session
                .lease()
                .expiry
                .checked_sub(now)
                .ok_or(GcError::Exhausted)?;
            let renew = since_renewal.is_none_or(|since| since >= interval) || budget <= reserve;

            // The first wait renewal stays immediate. Later effect-free polls
            // retain clock/barrier checks without publishing selected progress.
            // Every due renewal still obtains complete current held authority.
            if renew {
                let holder = collector.hold_namespace().await?;
                let held = holder.destination();
                let mut context = collector.held(&held, Some(controls)).await?;
                self.session.renew_held(&mut context).await?;
            }
            let now = self.session.recheck()?;
            let elapsed = barrier.elapsed().map_err(native)?;
            if renew {
                // A queued, canceled or unacknowledged renewal cannot advance
                // the schedule. Its genuine ACK and post samples precede this.
                last_renew_elapsed = Some(elapsed);
            }
            let Some(remaining) = required.checked_sub(elapsed).filter(|time| !time.is_zero())
            else {
                continue;
            };
            let since_renewal = elapsed
                .checked_sub(last_renew_elapsed.ok_or(GcError::Exhausted)?)
                .ok_or(GcError::Exhausted)?;
            let Some(cadence_remaining) = interval
                .checked_sub(since_renewal)
                .filter(|time| !time.is_zero())
            else {
                continue;
            };
            let budget = self
                .session
                .lease()
                .expiry
                .checked_sub(now)
                .ok_or(GcError::Exhausted)?;
            if budget <= reserve {
                continue;
            }

            barrier
                .sleep(remaining.min(cadence_remaining).min(Duration::from_secs(1)))
                .await
                .map_err(native)?;
        }

        let result = {
            let holder = collector.hold_namespace().await?;
            let held = holder.destination();
            {
                let mut context = collector.held(&held, Some(controls)).await?;
                self.session.renew_held(&mut context).await?;
            }
            let observed = held.observe_publication_unrepaired().await?;
            let data = native_copied_placement::qualify(
                self.guard,
                self.authority,
                &self.session,
                &held,
                &observed,
                pack,
                Some(controls),
            )
            .await?;
            let checked =
                native_copied_retirement::authorize(data, &held, &self.session, &barrier).await?;
            effects::own(held.fs(), &checked).await?;
            checked.operation().clone()
        };
        self.session.recheck()?;
        operation.complete();
        Ok(result)
    }
}

fn native(error: crate::store::NativeEffectFailure) -> StoreFailure {
    match error {
        crate::store::NativeEffectFailure::Rejected(error) => error,
        crate::store::NativeEffectFailure::Io(error) => {
            StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
        }
    }
}
