//! Discovers retained ordinary local-v1 intent without changing its Done semantics.
//!
//! Protected native intent files supply lookup candidates, never effect
//! permission. Terminal records remain visible so a scheduler can distinguish
//! an already completed incarnation from new work.
//! Permanent-v2 owners and copied preparations stay in their separate protocol.

use super::{Collection, CollectionError, MAX_HINTS, denied};
use crate::bucket::BucketBinding;
use crate::bucket::held::SingleHeld;
use crate::gc::lease::Collector;
use crate::store::{Clock, ContentValidator, LocalFs};
use std::collections::BTreeSet;
use terrane_format::bucket::PackExclusion;
use terrane_format::gc::{DeleteOperation, DeletePhase, GcError};

/// Retains an ordering position without retaining a publication or deletion authority.
///
/// Repeated calls revisit every intent in a finite stable inventory. Removed
/// positions are harmless; new lower keys become eligible on the next wrap.
/// Continuous inventory growth has no bounded fairness guarantee.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalDeletionCursor {
    after: Option<String>,
}

/// Names retained local-v1 progress without authorizing recovery or a new deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDeletionHint {
    /// Exact registered operation key for independent native recovery qualification.
    pub operation_key: String,
    /// Original exclusion incarnation, including its cycle and fencing epoch.
    pub exclusion: PackExclusion,
    /// Current protected phase, including Done and Cancelled terminal records.
    pub phase: DeletePhase,
}

impl<F, B, V, C> Collection<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Selects bounded ordinary deletion hints under the original live session.
    ///
    /// Includes terminal intents and excludes the disjoint permanent-v2 protocol.
    /// Renews the original whole lease without changing roots or checkpoints.
    /// Bounds limit retained keys and returned hints, not native directory enumeration.
    /// Each decoded witness is dropped before examining another record. The binding
    /// owns each immediate-directory allocation; no complete key inventory is retained.
    ///
    /// # Errors
    /// Rejects bounds outside `1..=MAX_HINTS`, unfinished marking, malformed
    /// protected delete records, lost leases and changed native observations.
    /// Actual work failure or cancellation stops the session. Failure leaves the
    /// cursor unchanged; invalid bounds perform no effects.
    pub async fn local_deletion_hints(
        &mut self,
        cursor: &mut LocalDeletionCursor,
        maximum: usize,
    ) -> Result<Vec<LocalDeletionHint>, CollectionError> {
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
        let current = crate::selected_bridge::native_current_collection::qualify(
            self.guard,
            self.authority,
            &self.session,
            &held,
            &observed,
            (&self.roots, &self.state),
            self.windows,
        )
        .await?;
        let hints = crate::store::native_publication_effects::collection_local_deletion::discover(
            held.fs(),
            &current,
            cursor.after.as_deref(),
            maximum,
        )
        .await?;
        current.revalidate().await?;
        self.session.recheck()?;
        if let Some(last) = hints.last() {
            cursor.after = Some(last.operation_key.clone());
        }
        operation.complete();
        Ok(hints)
    }
}

/// Keeps only the next bounded cyclic keys while scanning the native directory tree.
pub(crate) struct Candidates<'cursor> {
    after: Option<&'cursor str>,
    maximum: usize,
    keys: BTreeSet<(bool, String)>,
}

impl<'cursor> Candidates<'cursor> {
    /// Starts a neutral bounded selection after an optional prior ordering key.
    pub(crate) fn new(after: Option<&'cursor str>, maximum: usize) -> Self {
        Self {
            after,
            maximum,
            keys: BTreeSet::new(),
        }
    }

    /// Retains the next cyclic keys regardless of directory enumeration order.
    pub(crate) fn insert(&mut self, key: String) {
        let wrapped = self.after.is_some_and(|after| key.as_str() <= after);
        self.keys.insert((wrapped, key));
        if self.keys.len() > self.maximum {
            self.keys.pop_last();
        }
    }

    /// Returns selected keys once in their cyclic processing order.
    pub(crate) fn into_keys(self) -> impl Iterator<Item = String> {
        self.keys.into_iter().map(|(_, key)| key)
    }
}

/// Reduces a canonical protected local-v1 record to neutral scheduling status.
///
/// # Errors
/// Rejects malformed bytes, another protocol version and mismatched operation keys.
pub(crate) fn decode_hint(key: String, bytes: &[u8]) -> Result<LocalDeletionHint, GcError> {
    let value = DeleteOperation::decode(bytes, &key)?;
    Ok(LocalDeletionHint {
        operation_key: key,
        exclusion: PackExclusion {
            pack_id: value.authorization.pack_id,
            cycle: value.authorization.cycle,
            epoch: value.authorization.epoch,
        },
        phase: value.phase,
    })
}

#[cfg(test)]
#[path = "local_deletion/tests.rs"]
mod tests;
