//! Selects fair bounded maintenance hints from an actual current publication.
//!
//! Independent cursors revisit burned families and nonburned exclusions. Neither
//! cursors nor returned hints retain authority: each consumer must invoke its
//! genuine native producer with fresh current qualification. Completed passes
//! never remove a permanent owner from this recurring inventory.

use super::{Collection, CollectionError, Restoration, denied, session::Session};
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::lease::Collector;
use crate::guard::{Guard, OriginalAuthority};
use crate::pack::PackId;
use crate::store::{Clock, ContentValidator, LocalFs};
use terrane_format::bucket::PackExclusion;
use terrane_format::gc::retirement::{PermanentBurnOwner, PermanentOwnerSelection};

/// Discovers retained ordinary local-v1 intents independently of permanent owners.
#[path = "maintenance/local_deletion.rs"]
pub mod local_deletion;

/// Owns a finite startup scan that does not depend on ordinary root traversal.
#[path = "maintenance/restoration.rs"]
pub mod restoration;

/// Limits the number of returned lookup hints, independently of native work bounds.
pub const MAX_HINTS: usize = 256;

/// Retains scheduling positions without retaining a snapshot or effect permission.
///
/// Reusing this cursor across calls fairly revisits a finite stable inventory.
/// New entries before either position become eligible on its next wrap. Removed
/// entries do not invalidate the cursor. Fairness assumes calls continue and
/// the inventory eventually stops changing; continuous growth is not bounded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceCursor {
    owner: Option<[u8; 16]>,
    exclusion: Option<[u8; 16]>,
    next_exclusion: bool,
}

/// Names one current lookup candidate without certifying eligibility or ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceHint {
    /// Requests fresh native reconciliation of an independently selected owner.
    PermanentOwner {
        /// Burned family whose owner must be independently requalified.
        pack: PackId,
        /// Current selected operation key, used only as a lookup hint.
        operation_key: String,
    },
    /// Requests independent first-ownership qualification for copied visibility.
    CopiedRetirement {
        /// Burned family whose destination retirement duty remains outstanding.
        pack: PackId,
    },
    /// Requests fresh restoration or retirement qualification for an exclusion.
    ExcludedPack(PackExclusion),
}

impl<F, B, V, C> Restoration<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Selects current maintenance hints before ordinary marking begins.
    ///
    /// Renews this original session and observes the actual selected catalog;
    /// it does not traverse root bodies or create a checkpoint. Hints include
    /// permanently owned families that restoration must not attempt to restore.
    /// Each consumer still requires its own independent native qualification.
    ///
    /// # Errors
    /// Preserves bound, ownership and native observation failures from
    /// [`Collection::maintenance_hints`]. Cancellation poisons this session.
    pub async fn maintenance_hints(
        &mut self,
        cursor: &mut MaintenanceCursor,
        maximum: usize,
    ) -> Result<Vec<MaintenanceHint>, CollectionError> {
        observe(
            self.guard,
            self.authority,
            &mut self.session,
            cursor,
            maximum,
        )
        .await
    }
}

impl<F, B, V, C> Collection<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Selects recurring current owner and exclusion hints under the original session.
    ///
    /// Returns at most `maximum` distinct hints and commits cursor advancement
    /// only after the held observation is revalidated. The original whole lease
    /// is renewed; marking roots and checkpoints remain unchanged. This does not
    /// enumerate legacy deletion intents or authorize any native effect.
    ///
    /// # Errors
    /// Rejects bounds outside `1..=MAX_HINTS`, lost ownership, unavailable complete
    /// inventories and changed native observations. Failure or cancellation of
    /// actual work stops the session; invalid bounds perform no effects.
    pub async fn maintenance_hints(
        &mut self,
        cursor: &mut MaintenanceCursor,
        maximum: usize,
    ) -> Result<Vec<MaintenanceHint>, CollectionError> {
        observe(
            self.guard,
            self.authority,
            &mut self.session,
            cursor,
            maximum,
        )
        .await
    }
}

pub(super) async fn observe<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &mut Session,
    cursor: &mut MaintenanceCursor,
    maximum: usize,
) -> Result<Vec<MaintenanceHint>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    if !(1..=MAX_HINTS).contains(&maximum) {
        return Err(denied().into());
    }
    let operation = session.operation()?;
    session.renew(&Collector::new(guard, authority)).await?;
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await?;
    let selected = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(terrane_format::gc::GcLease::decode)
        .transpose()?;
    session
        .lease()
        .check(selected.as_ref(), session.recheck()?)?;
    let metadata = MetadataStore::new(&held, &observed, session);
    let catalog = metadata.collection_catalog().await?;
    let owners = observed.state().burn_owners.as_deref().ok_or_else(denied)?;
    let mut next_cursor = cursor.clone();
    let hints = select(
        owners,
        catalog.exclusions()?,
        catalog.burns()?,
        &mut next_cursor,
        maximum,
    );

    observed.revalidate().await?;
    session.recheck()?;
    *cursor = next_cursor;
    operation.complete();
    Ok(hints)
}

/// Alternates the two independently ordered families without materializing a catalog.
fn select(
    owners: &[PermanentBurnOwner],
    exclusions: &[PackExclusion],
    burns: &[[u8; 16]],
    cursor: &mut MaintenanceCursor,
    maximum: usize,
) -> Vec<MaintenanceHint> {
    let mut hints = Vec::with_capacity(maximum);
    let mut first_owner = None;
    let mut first_exclusion = None;
    let mut exhausted = [false; 2];

    while hints.len() < maximum && !exhausted.iter().all(|value| *value) {
        let exclusion = cursor.next_exclusion;
        cursor.next_exclusion = !exclusion;
        let family = usize::from(exclusion);
        if exhausted[family] {
            continue;
        }
        if exclusion {
            let start = cursor.exclusion.map_or(0, |previous| {
                exclusions.partition_point(|row| row.pack_id <= previous)
            });
            let next = exclusions[start..]
                .iter()
                .chain(&exclusions[..start])
                .find(|row| burns.binary_search(&row.pack_id).is_err());
            let Some(next) = next.filter(|row| first_exclusion != Some(row.pack_id)) else {
                exhausted[family] = true;
                continue;
            };
            first_exclusion.get_or_insert(next.pack_id);
            cursor.exclusion = Some(next.pack_id);
            hints.push(MaintenanceHint::ExcludedPack(next.clone()));
        } else {
            let start = cursor.owner.map_or(0, |previous| {
                owners.partition_point(|row| row.pack <= previous)
            });
            let next = owners.get(start).or_else(|| owners.first());
            let Some(next) = next.filter(|row| first_owner != Some(row.pack)) else {
                exhausted[family] = true;
                continue;
            };
            first_owner.get_or_insert(next.pack);
            cursor.owner = Some(next.pack);
            let pack = PackId::from_random_bytes(next.pack);
            hints.push(match &next.selection {
                PermanentOwnerSelection::CopiedVisibility => {
                    MaintenanceHint::CopiedRetirement { pack }
                }
                PermanentOwnerSelection::Permanent(pointer) => MaintenanceHint::PermanentOwner {
                    pack,
                    operation_key: pointer.key.clone(),
                },
            });
        }
    }
    hints
}

#[cfg(test)]
#[path = "maintenance/tests.rs"]
mod tests;
