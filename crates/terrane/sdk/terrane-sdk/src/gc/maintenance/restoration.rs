//! Pages nonburned startup exclusions without creating marking checkpoints.
//!
//! The cursor advances once through pack order and never wraps. Restoring an
//! earlier candidate cannot prevent completion. A new cursor starts another
//! pass; neither a position nor a returned selector grants effect permission.

use super::{CollectionError, MAX_HINTS, Restoration, denied};
use crate::bucket::BucketBinding;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::gc::lease::Collector;
use crate::store::{Clock, ContentValidator, LocalFs};
use terrane_format::bucket::PackExclusion;

/// Retains the last examined pack in one ascending startup pass.
///
/// New exclusions below that position require another pass. The collector's
/// whole lease excludes another collector from creating such retirements while
/// this startup pass owns it. Returned hints still require fresh qualification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RestorationCursor {
    after: Option<[u8; 16]>,
}

impl<F, B, V, C> Restoration<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Selects bounded nonburned exclusions before ordinary marking begins.
    ///
    /// Renews the original whole lease and observes the actual selected catalog.
    /// Returns at most `maximum` exact selectors in ascending pack order, after
    /// this cursor's previous page. Empty means the current pass is exhausted.
    /// It reads no root bodies and creates no checkpoints. Burned families stay
    /// in permanent recovery. Local intent status must be checked independently
    /// before choosing restoration or ordinary deletion recovery.
    ///
    /// # Errors
    /// Rejects bounds outside `1..=MAX_HINTS`, lost ownership, unsafe or incomplete
    /// catalog observations and cancellation. Failure leaves the cursor unchanged;
    /// invalid bounds perform no effects, while actual failure stops the session.
    pub async fn restoration_hints(
        &mut self,
        cursor: &mut RestorationCursor,
        maximum: usize,
    ) -> Result<Vec<PackExclusion>, CollectionError> {
        if !(1..=MAX_HINTS).contains(&maximum) {
            return Err(denied().into());
        }
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        let holder = SingleHeld::acquire(self.guard.store()).await?;
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await?;
        let selected = observed
            .logical()
            .get("gc/lease")
            .and_then(Option::as_deref)
            .map(terrane_format::gc::GcLease::decode)
            .transpose()?;
        self.session
            .lease()
            .check(selected.as_ref(), self.session.recheck()?)?;
        let metadata = MetadataStore::new(&held, &observed, &self.session);
        let catalog = metadata.collection_catalog().await?;
        let burns = catalog.burns()?;
        let hints: Vec<_> = catalog
            .exclusions()?
            .iter()
            .filter(|row| cursor.after.is_none_or(|previous| row.pack_id > previous))
            .filter(|row| burns.binary_search(&row.pack_id).is_err())
            .take(maximum)
            .cloned()
            .collect();

        observed.revalidate().await?;
        self.session.recheck()?;
        if let Some(last) = hints.last() {
            cursor.after = Some(last.pack_id);
        }
        operation.complete();
        Ok(hints)
    }
}
