//! Reconstructs the current pass from actual consecutive selected progress slots.
//!
//! Immutable protected event bodies are independently associated with the exact
//! selecting transaction and its predecessor. A cache or an isolated public
//! delta cannot certify accumulated duties or completion.

use super::{CheckedPermanentLocalOwner, denied, physical::PhysicalReads, selection};
use crate::bucket::BucketBinding;
use crate::bucket::publication::receipts::RecordRead;
use crate::store::{LocalFs, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::gc::retirement::{
    ObservationState, ObservedArtifact, PassPhase, PermanentDeleteOperation, PermanentDeletePass,
    RecordPointer, RequestObservation,
};

/// Bounds native directory descriptor retention without limiting a family or pass.
pub(crate) const NATIVE_BATCH_CYCLES: usize = 128;

/// Retains complete selected events of the currently selected pass.
pub(crate) struct History {
    events: Vec<PermanentDeletePass>,
    reads: Vec<RecordRead>,
}

impl History {
    /// Borrows every current-pass event in its exact selected order.
    pub(crate) fn events(&self) -> &[PermanentDeletePass] {
        &self.events
    }

    /// Borrows actual immutable protected inputs used to reconstruct the pass.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }

    /// Lists previously selected trash candidates even if their directories vanished.
    pub(crate) fn cycles(&self) -> BTreeSet<u64> {
        self.events
            .iter()
            .flat_map(|event| event.observations.iter())
            .filter_map(|row| match row.artifact {
                ObservedArtifact::Trash(cycle) => Some(cycle),
                _ => None,
            })
            .collect()
    }

    /// Returns prior actual traversal rows only while continuing an Open pass.
    pub(crate) fn visited(&self) -> BTreeSet<u64> {
        if self
            .events
            .last()
            .is_some_and(|event| event.phase == PassPhase::Open)
        {
            self.cycles()
        } else {
            BTreeSet::new()
        }
    }

    /// Chooses one bounded event while fairly revisiting unresolved duties.
    ///
    /// A fresh candidate receives a slot even when earlier duties fill the
    /// event. Remaining Planned cycles are ordered least recently observed first;
    /// a recurring late residue cannot monopolize the traversal's first cycle.
    pub(crate) fn batch(&self, current: &[u64]) -> Vec<u64> {
        let visited = self.visited();
        let mut unseen = current
            .iter()
            .copied()
            .filter(|cycle| !visited.contains(cycle));
        let mut selected = Vec::new();
        if let Some(cycle) = unseen.next() {
            selected.push(cycle);
        }
        let mut duties = BTreeMap::new();
        if !visited.is_empty() {
            for (index, event) in self.events.iter().enumerate() {
                for row in &event.observations {
                    if let ObservedArtifact::Trash(cycle) = row.artifact {
                        duties.insert(cycle, (index, row.state));
                    }
                }
            }
        }
        let mut pending: Vec<_> = duties
            .into_iter()
            .filter_map(|(cycle, (index, state))| {
                (state == ObservationState::Planned).then_some((index, cycle))
            })
            .collect();
        pending.sort_unstable();
        let maximum = NATIVE_BATCH_CYCLES.min(terrane_format::gc::retirement::MAX_OBSERVATIONS - 2);
        for (_, cycle) in pending {
            if selected.len() == maximum {
                break;
            }
            selected.push(cycle);
        }
        for cycle in unseen {
            if selected.len() == maximum {
                break;
            }
            selected.push(cycle);
        }
        selected.sort_unstable();
        selected.dedup();
        selected
    }

    /// Checks all accumulated duties after a proposed current native delta.
    pub(crate) fn resolved_after(&self, current: &[RequestObservation]) -> bool {
        let mut duties = BTreeMap::new();
        if self
            .events
            .last()
            .is_some_and(|event| event.phase == PassPhase::Open)
        {
            for event in &self.events {
                for row in &event.observations {
                    duties.insert((row.artifact, row.instance.clone()), row.state);
                }
            }
        }
        for row in current {
            duties.insert((row.artifact, row.instance.clone()), row.state);
        }
        duties
            .values()
            .all(|state| *state != ObservationState::Planned)
    }

    /// Rotates requests through actual current Planned rows using selected event order.
    ///
    /// This determines scheduling only. Each resulting row still needs
    /// independent current request qualification and an actual physical receipt.
    pub(crate) fn next(&self, current: &[RequestObservation]) -> Option<RequestObservation> {
        let planned: Vec<_> = current
            .iter()
            .filter(|row| row.state == ObservationState::Planned)
            .collect();
        if planned.is_empty() {
            return None;
        }
        let event = self.events.last().map_or(0, |event| event.event);
        let count = u64::try_from(planned.len()).ok()?;
        let index = usize::try_from(event % count).ok()?;
        planned.get(index).map(|row| (**row).clone())
    }
}

/// Resolves all events of the latest pass from genuine selected immutable history.
///
/// # Errors
/// Refuses missing selected slots or events, changed actual owner/current inputs,
/// inconsistent typed progress, omitted counters and contradictory associations.
pub(crate) async fn selected<F: LocalFs + BucketBinding>(
    fs: &F,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
) -> Result<History, StoreFailure> {
    owner.revalidate().await?;
    let observed = owner.observed();
    let current = PermanentDeleteOperation::decode(
        observed
            .logical()
            .get(owner.key())
            .and_then(Option::as_deref)
            .ok_or_else(denied)?,
    )
    .map_err(|_| denied())?;
    let mut events = Vec::new();
    let mut reads = Vec::new();
    let mut latest: Option<RecordPointer> = None;
    let physical = PhysicalReads::new(observed);
    for revision in owner.owner().revision..=observed.stamp().0 {
        let (_, transaction) =
            selection::transaction(&physical, owner.backend_control(), revision)?;
        let Some(change) = transaction
            .changes
            .iter()
            .find(|change| change.key == owner.key())
        else {
            continue;
        };
        let bytes = change.new.as_deref().ok_or_else(denied)?;
        let operation = PermanentDeleteOperation::decode(bytes).map_err(|_| denied())?;
        if &operation.authorization != owner.authorization() {
            return Err(denied());
        }
        let Some(pointer) = operation.pass.as_ref() else {
            continue;
        };
        if latest.as_ref() == Some(pointer) {
            continue;
        }
        let read = crate::bucket::permanent_restore::read_pass(
            fs,
            owner.backend_control(),
            &pointer.key,
            observed.configured_operator_uid(),
            owner.authorization().exclusion().cycle,
        )
        .await?;
        let body = read.bytes().ok_or_else(denied)?;
        operation
            .check_pass(body, owner.key())
            .map_err(|_| denied())?;
        let event = PermanentDeletePass::decode(body).map_err(|_| denied())?;
        if transaction.old.as_ref() != Some(&event.state)
            || transaction.predecessor.as_ref().is_none_or(|slot| {
                slot.revision != event.predecessor.revision
                    || slot.digest != event.predecessor.digest
            })
            || transaction.nonce != event.nonce
        {
            return Err(denied());
        }
        if let Some(previous) = events.last() {
            let previous: &PermanentDeletePass = previous;
            previous.check_successor(&event).map_err(|_| denied())?;
            if previous.pass != event.pass {
                events.clear();
                reads.clear();
            }
        }
        latest = Some(pointer.clone());
        events.push(event);
        reads.push(read);
    }
    if latest != current.pass {
        return Err(denied());
    }
    if !events.is_empty() {
        PermanentDeletePass::check_pass_history(&events).map_err(|_| denied())?;
    }
    owner.revalidate().await?;
    Ok(History { events, reads })
}
