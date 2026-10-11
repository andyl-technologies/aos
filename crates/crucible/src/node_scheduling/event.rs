//! Canonical event lineage and checked node-wide sequence allocation.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, Endpoint, EventKey, Id, Phase, Position, U64};
use serde::{Deserialize, Serialize};

use super::SchedulingError;

/// Retains publication and recipient delivery coordinates as distinct evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    /// Names the admitted connection whose original delivery policy applies.
    #[serde(deserialize_with = "required_nullable")]
    pub connection_id: Option<Id>,
    /// Retains the selected connection policy independently of later changes.
    #[serde(deserialize_with = "required_nullable")]
    pub connection_policy_ref: Option<ContentRef>,
    /// Names the declared root lane when this input has no transport connection.
    #[serde(deserialize_with = "required_nullable")]
    pub external_root: Option<Endpoint>,
    /// Retains authentic original native production or external-source provenance.
    pub provenance_ref: ContentRef,
    /// Identifies common publication lineage across recipient fanout.
    pub publication_id: Id,
    /// Names the original producer node independently of transport epochs.
    pub producer: Id,
    /// Names this recipient without changing the original causal parent.
    pub consumer: Id,
    /// Retains the exact original producer port and lane.
    pub producer_endpoint: Endpoint,
    /// Retains the exact destination port and lane for native input routing.
    pub consumer_endpoint: Endpoint,
    /// Orders all public events of this producer across ports and recipients.
    pub source_sequence: U64,
    /// Retains the producer's original native FIFO identity as separate provenance.
    pub native_sequence: U64,
    /// Retains exact evaluation when applicable, without inventing hardware timing.
    #[serde(deserialize_with = "required_nullable")]
    pub evaluation: Option<Position>,
    /// Retains original causal membership independently of recipient conversion.
    pub causal_parents: Vec<Position>,
    /// Retains the original phase-one publication coordinate.
    pub publication: Position,
    /// Retains the converted phase-two destination coordinate.
    pub delivery: Position,
    /// Retains immutable payload content without native pointers.
    pub payload: ContentRef,
}

impl Delivery {
    /// Returns the baseline deterministic recipient delivery order.
    pub fn key(&self) -> EventKey {
        EventKey {
            position: self.delivery,
            consumer_node_id: self.consumer.clone(),
            producer_node_id: self.producer.clone(),
            source_sequence: self.source_sequence,
        }
    }
}

/// Preserves every producer's next sequence and permanent exhaustion state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProducerSequences(BTreeMap<Id, Option<U64>>);

impl ProducerSequences {
    /// Returns the next identity, or permanent exhaustion, without allocating.
    pub fn next(&self, producer: &Id) -> Option<U64> {
        self.0.get(producer).copied().unwrap_or(Some(U64::new(0)))
    }

    pub(crate) fn restore_next(&mut self, producer: Id, next: Option<U64>) {
        self.0.insert(producer, next);
    }

    /// Allocates a distinct node-wide sequence before publishing any effect.
    ///
    /// # Errors
    /// Refuses a producer whose final `u64::MAX` identity was already allocated.
    pub fn allocate(&mut self, producer: &Id) -> Result<U64, SchedulingError> {
        let next = self.0.entry(producer.clone()).or_insert(Some(U64::new(0)));
        let sequence = next.ok_or(SchedulingError::SequenceExhausted)?;
        *next = sequence.get().checked_add(1).map(U64::new);
        Ok(sequence)
    }

    /// Reserves all recipient identities atomically before publishing a fanout.
    ///
    /// # Errors
    /// Refuses an unrepresentable count or insufficient remaining identities
    /// without consuming any identity from the producer's continuation.
    pub fn allocate_fanout(
        &mut self,
        producer: &Id,
        recipients: usize,
    ) -> Result<Vec<U64>, SchedulingError> {
        if recipients == 0 {
            return Ok(Vec::new());
        }
        if recipients > crucible_node_contract::MAX_ARRAY_ELEMENTS {
            return Err(SchedulingError::SequenceExhausted);
        }
        let count = u64::try_from(recipients).map_err(|_| SchedulingError::SequenceExhausted)?;
        let next = self
            .0
            .get(producer)
            .copied()
            .unwrap_or(Some(U64::new(0)))
            .ok_or(SchedulingError::SequenceExhausted)?;
        let last = next
            .get()
            .checked_add(count - 1)
            .ok_or(SchedulingError::SequenceExhausted)?;
        let identities = (next.get()..=last).map(U64::new).collect();
        self.0
            .insert(producer.clone(), last.checked_add(1).map(U64::new));
        Ok(identities)
    }
}

/// Derives publication causality without fabricating modeled latency.
///
/// A reaction evaluated at the publication's physical instant advances the
/// causal microstep. A publication prepared at an earlier instant is a root at
/// its later instant. Direct transfer is handled separately from reactions.
///
/// # Errors
/// Refuses time regression, arithmetic overflow and exhausted finite closure.
pub fn reaction_publication(
    parents: &[Position],
    evaluation: Position,
    time_ps: U64,
    maximum_microsteps: U64,
) -> Result<Position, SchedulingError> {
    if time_ps < evaluation.time_ps || parents.iter().any(|parent| *parent > evaluation) {
        return Err(SchedulingError::CausalRegression);
    }
    if time_ps > evaluation.time_ps {
        return Ok(Position::new(time_ps, U64::new(0), Phase::Publication));
    }

    // Evaluation itself is semantic work, including an independently armed
    // native alarm. It cannot emit into an earlier phase of its own microstep.
    let greatest = parents.iter().copied().fold(evaluation, std::cmp::max);
    greatest
        .reaction_publication(maximum_microsteps)
        .map_err(|_| SchedulingError::SameTimeNonconvergence)
}

/// Converts a retained publication into a direct delivery coordinate.
///
/// # Errors
/// Refuses a non-publication source, latency overflow or an invalid grid result.
pub fn direct_delivery(
    publication: Position,
    latency_ps: U64,
    destination_grid: Option<crucible_node_contract::QuantumGrid>,
) -> Result<Position, SchedulingError> {
    if publication.phase != Phase::Publication {
        return Err(SchedulingError::InvalidPublication);
    }
    let arrival = publication.time_ps.checked_add(latency_ps)?;
    let sampled = match destination_grid {
        Some(grid) => grid.successor(arrival)?,
        None => arrival,
    };
    let microstep = if sampled == publication.time_ps {
        publication.microstep
    } else {
        U64::new(0)
    };
    Ok(Position::new(sampled, microstep, Phase::Delivery))
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
