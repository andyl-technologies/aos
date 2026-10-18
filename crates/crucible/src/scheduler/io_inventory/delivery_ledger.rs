//! Retained physical delivery origins for one imported queue.
//!
//! The ledger maps each physical [`FrameDeliveryKey`] to the canonical event it
//! was assigned on import. It has two parts:
//!
//! - live deliveries are not yet published. Each one is still in the queue's
//!   current snapshot, so the queue's depth bounds this part;
//! - retired deliveries are published. They stay only until the owning node's
//!   authenticated stopped tick passes their delivery tick. After that, no
//!   later import can name them, because a new completion must not precede
//!   the stopped tick.
//!
//! Scheduler staging copies are made several times per quantum. The retired
//! part therefore sits behind a reference count, so a copy shares it until the
//! copy publishes or prunes a delivery. After pruning, the retired part holds
//! only deliveries published since the last import, plus any published at
//! exactly the stopped tick. A staging copy thus never copies run history.
//!
//! The continuation encodes the two parts as one ordered map, with the same
//! shape an owned map would produce:
//!
//! ```text
//! { FrameDeliveryKey => { completion, key, published } , ... }   ascending keys
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::ImportedIoDelivery;
use crucible_device::FrameDeliveryKey;

/// The physical delivery origins retained for one imported queue.
///
/// Every live entry is unpublished and every retired entry is published; the
/// constructor paths keep the two parts disjoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct DeliveryLedger {
    live: BTreeMap<FrameDeliveryKey, ImportedIoDelivery>,
    retired: Arc<BTreeMap<FrameDeliveryKey, ImportedIoDelivery>>,
}

impl DeliveryLedger {
    /// Returns the retained origin for `key`, published or not.
    pub(super) fn get(&self, key: &FrameDeliveryKey) -> Option<&ImportedIoDelivery> {
        self.live.get(key).or_else(|| self.retired.get(key))
    }

    /// Records a newly imported, unpublished delivery.
    ///
    /// The caller has already established that `key` is not retained.
    pub(super) fn insert_live(&mut self, key: FrameDeliveryKey, delivery: ImportedIoDelivery) {
        self.live.insert(key, delivery);
    }

    /// Marks a live delivery as published and moves it into the retired part.
    ///
    /// Returns `false`, leaving the ledger unchanged, when `key` names no live
    /// delivery.
    pub(super) fn retire(&mut self, key: &FrameDeliveryKey) -> bool {
        let Some(mut delivery) = self.live.remove(key) else {
            return false;
        };

        delivery.published = true;
        Arc::make_mut(&mut self.retired).insert(*key, delivery);
        true
    }

    /// Drops every retired delivery whose delivery tick precedes `floor`.
    ///
    /// The kept entries are copied into a fresh retired map rather than
    /// splitting a possibly shared one, so a prune never copies the entries it
    /// discards.
    pub(super) fn prune_retired_below(&mut self, floor: u64) {
        let first_kept = FrameDeliveryKey {
            delivery_icount: floor,
            src_node: 0,
            seq: 0,
        };
        let has_stale = self
            .retired
            .first_key_value()
            .is_some_and(|(key, _)| *key < first_kept);
        if !has_stale {
            return;
        }

        let kept = self
            .retired
            .range(first_kept..)
            .map(|(key, delivery)| (*key, delivery.clone()))
            .collect();
        self.retired = Arc::new(kept);
    }

    /// Returns every retained origin, live entries first.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&FrameDeliveryKey, &ImportedIoDelivery)> {
        self.live.iter().chain(self.retired.iter())
    }

    /// Returns the number of retained origins.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.live.len() + self.retired.len()
    }

    /// Returns whether this ledger and `other` share one retired allocation.
    #[cfg(test)]
    pub(super) fn shares_retired_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.retired, &other.retired)
    }

    /// Returns every retained origin in ascending key order.
    fn ordered(&self) -> impl Iterator<Item = (&FrameDeliveryKey, &ImportedIoDelivery)> {
        let mut live = self.live.iter().peekable();
        let mut retired = self.retired.iter().peekable();
        std::iter::from_fn(move || match (live.peek(), retired.peek()) {
            (Some((live_key, _)), Some((retired_key, _))) if live_key < retired_key => live.next(),
            (Some(_), None) => live.next(),
            _ => retired.next(),
        })
    }
}

impl Serialize for DeliveryLedger {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // A definite length keeps the encoding byte-identical to an owned
        // ordered map; an iterator without an exact size hint would not.
        let mut map = serializer.serialize_map(Some(self.live.len() + self.retired.len()))?;
        for (key, delivery) in self.ordered() {
            map.serialize_entry(key, delivery)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for DeliveryLedger {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = BTreeMap::<FrameDeliveryKey, ImportedIoDelivery>::deserialize(deserializer)?;
        let (retired, live) = entries
            .into_iter()
            .partition::<BTreeMap<_, _>, _>(|(_, delivery)| delivery.published);
        Ok(Self {
            live,
            retired: Arc::new(retired),
        })
    }
}

#[cfg(test)]
#[path = "delivery_ledger/tests.rs"]
mod tests;
