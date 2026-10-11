//! Native bounded output-only packet program for independent CNP source witnesses.
//!
//! The program owns its actual effect socket and finite event/original journals.
//! Construction supplies no common admission, readiness or vendor qualification.
//! A separately installed source oracle must bind these native facts to the
//! original CNP realization, complete activation and behavioral acceptance.

use std::{collections::BTreeMap, os::unix::net::UnixDatagram};

use crucible_node_contract::{Bytes, Id, Phase, Position, U64, Validate};
use serde::{Deserialize, Serialize};

use crate::ProviderError;

const MAXIMUM_EVENTS: usize = 32;
const MAXIMUM_OPERATIONS: usize = 64;
const MAXIMUM_PAYLOAD: usize = 1024;

pub mod common;
pub mod contracts;
pub mod control;
pub mod coordinator;
pub mod endpoint;
pub mod original_gate;
pub mod service;

/// Binds the complete original source configuration independently of wire claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketProgramDefinition {
    /// Names the selected format, `source-owned.packet-program.v1`.
    pub schema: String,
    /// Lists every original native callback and its exact effect in FIFO order.
    pub events: Vec<PacketEvent>,
}

/// Defines one indivisible actual source callback and its native effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketEvent {
    /// Names the original native event independently of public fanout IDs.
    pub id: Id,
    /// Gives the first semantic transition within this callback.
    pub evaluation: Position,
    /// Gives its last semantic transition; the entire callback requires this below the cut.
    pub completion: Position,
    /// Carries output bytes, or null for an independently observable private mutation.
    pub payload: Option<Bytes>,
}

/// Retains the actual complete stopped inventory beneath the native program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketInventory {
    /// Gives the actual native cursor, without implying inbound EOF.
    pub reached: Position,
    /// Distinguishes the native gate from transport connection readiness.
    pub gate_closed: bool,
    /// Lists every future callback in original native order.
    pub pending: Vec<PacketEvent>,
    /// Lists original emitted publications not yet consumed by the host.
    pub retained_outputs: Vec<PacketPublication>,
    /// Counts genuine private native transitions observed independently by the host.
    pub private_mutations: U64,
    /// Counts genuine packet effects observed independently by the host.
    pub packet_effects: U64,
}

/// Retains a complete original output under native FIFO custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketPublication {
    /// Names the original callback, never a regenerated retry identity.
    pub event: Id,
    /// Names the genuine original grant that caused this birth.
    pub operation: Id,
    /// Preserves the native FIFO sequence assigned at actual output birth.
    pub sequence: U64,
    /// Gives the genuine semantic evaluation position.
    pub evaluation: Position,
    /// Gives the genuine phase-one output publication position.
    pub publication: Position,
    /// Retains complete immutable original packet bytes through native ACK.
    pub payload: Bytes,
}

/// Reports an actual retained grant without authorizing common runtime progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketGrant {
    /// Names the original finite native operation.
    pub operation: Id,
    /// Retains the original exclusive interval.
    pub start: Position,
    /// Retains the original exclusive ceiling.
    pub limit: Position,
    /// Retains the resulting complete original inventory.
    pub inventory: PacketInventory,
    /// Retains this grant's actual newly born FIFO population.
    pub newborn: Vec<PacketPublication>,
    /// Distinguishes complete original execution from a native I/O failure.
    pub complete: bool,
}

/// Retains original native events, effects, output bytes and grant decisions.
///
/// This is an output-only source. No input lane, architectural CPU, physical
/// pause, preservation, restart or repeatability capability follows from it.
/// Its socket is exclusively owned and each callback sends an independently
/// observable native trace before completing the same original grant.
pub struct PacketProgram {
    effect_socket: UnixDatagram,
    events: Vec<PacketEvent>,
    next_event: usize,
    reached: Position,
    gate_closed: bool,
    outputs: Vec<PacketPublication>,
    grants: BTreeMap<Id, PacketGrant>,
    private_mutations: u64,
    packet_effects: u64,
    retired: BTreeMap<Id, Vec<Id>>,
    failed: bool,
}

impl PacketProgram {
    /// Takes one genuine owned effect socket and a closed finite source program.
    ///
    /// All event, payload and journal capacity is reserved before any effect.
    /// No operation is possible while the initial native gate remains closed.
    ///
    /// # Errors
    /// Refuses an empty, overwide, unordered or malformed complete native program.
    pub fn new(
        events: Vec<PacketEvent>,
        effect_socket: UnixDatagram,
    ) -> Result<Self, ProviderError> {
        if events.is_empty() || events.len() > MAXIMUM_EVENTS {
            return Err(ProviderError::ResourceExhausted("packet native events"));
        }
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let mut previous = zero;
        let mut ids = std::collections::BTreeSet::new();
        for event in &events {
            event.id.validate()?;
            event.evaluation.validate()?;
            event.completion.validate()?;
            if !ids.insert(&event.id)
                || event.evaluation < previous
                || event.evaluation > event.completion
                || event.evaluation.phase != Phase::Reaction
                || event.payload.as_ref().is_some_and(|payload| {
                    payload.as_slice().len() > MAXIMUM_PAYLOAD
                        || event.completion.phase != Phase::Publication
                        || event.completion <= event.evaluation
                })
            {
                return Err(ProviderError::Frame("packet native event shape"));
            }
            previous = event.completion;
        }
        Ok(Self {
            effect_socket,
            events,
            next_event: 0,
            reached: zero,
            gate_closed: true,
            outputs: Vec::with_capacity(MAXIMUM_EVENTS),
            grants: BTreeMap::new(),
            private_mutations: 0,
            packet_effects: 0,
            retired: BTreeMap::new(),
            failed: false,
        })
    }

    /// Borrows the source-owned finite original grant population.
    pub fn original(&self, operation: &Id) -> Option<&PacketGrant> {
        self.grants.get(operation)
    }

    /// Returns the complete source configuration, including already executed callbacks.
    pub fn definition(&self) -> PacketProgramDefinition {
        PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: self.events.clone(),
        }
    }

    /// Reads complete original callback and output custody without execution.
    pub fn inventory(&self) -> PacketInventory {
        PacketInventory {
            reached: self.reached,
            gate_closed: self.gate_closed,
            pending: self.events[self.next_event..].to_vec(),
            retained_outputs: self.outputs.clone(),
            private_mutations: U64::new(self.private_mutations),
            packet_effects: U64::new(self.packet_effects),
        }
    }

    /// Opens the initial native gate after the caller authenticates complete global publication.
    ///
    /// This native setter deliberately grants no public Ready or activation token.
    /// A source-installed controller must first authenticate its original host
    /// transaction, all-owner preparation and actual durable coordinator body.
    ///
    /// # Errors
    /// Refuses repeated opening, used or failed native state.
    pub fn open_gate(&mut self) -> Result<(), ProviderError> {
        if !self.gate_closed || self.failed || !self.grants.is_empty() || self.next_event != 0 {
            return Err(ProviderError::Conflict("packet initial gate"));
        }
        self.gate_closed = false;
        Ok(())
    }

    /// Plans the complete bounded resulting record without performing a callback.
    ///
    /// This is only source-owned prospective data for credit reservation. It is
    /// not evidence that execution occurred; the actual original and independent
    /// native effect observation must still authenticate the resulting record.
    ///
    /// # Errors
    /// Refuses invalid or foreign intervals and unavailable original/output custody.
    pub fn preview(
        &self,
        operation: &Id,
        start: Position,
        limit: Position,
    ) -> Result<PacketGrant, ProviderError> {
        if let Some(original) = self.grants.get(operation) {
            if original.start == start && original.limit == limit && original.complete {
                return Ok(original.clone());
            }
            return Err(ProviderError::Conflict("packet original preview"));
        }
        if self.gate_closed
            || self.failed
            || start != self.reached
            || start > limit
            || self.grants.len() >= MAXIMUM_OPERATIONS
            || !self.outputs.is_empty()
        {
            return Err(ProviderError::Correlation(
                "packet prospective native scope",
            ));
        }
        start.validate()?;
        limit.validate()?;
        let events = self.events[self.next_event..]
            .iter()
            .take_while(|event| event.completion < limit);
        let mut inventory = self.inventory();
        let mut newborn = Vec::with_capacity(self.events.len());
        let mut completed = 0;
        for event in events {
            if let Some(payload) = &event.payload {
                inventory.packet_effects = U64::new(inventory.packet_effects.get() + 1);
                newborn.push(PacketPublication {
                    event: event.id.clone(),
                    operation: operation.clone(),
                    sequence: inventory.packet_effects,
                    evaluation: event.evaluation,
                    publication: event.completion,
                    payload: payload.clone(),
                });
            } else {
                inventory.private_mutations = U64::new(inventory.private_mutations.get() + 1);
            }
            completed += 1;
        }
        inventory.pending = self.events[self.next_event + completed..].to_vec();
        inventory.retained_outputs = newborn.clone();
        inventory.reached = inventory
            .pending
            .first()
            .filter(|event| event.evaluation < limit)
            .map_or(limit, |event| event.evaluation);
        Ok(PacketGrant {
            operation: operation.clone(),
            start,
            limit,
            inventory,
            newborn,
            complete: true,
        })
    }

    /// Executes only whole original callbacks strictly inside the supplied grant.
    ///
    /// A callback that straddles the exclusive ceiling is left completely intact.
    /// Reusing an identical original returns its retained result; changed material
    /// refuses. Native I/O uncertainty fences all later original operations.
    ///
    /// # Errors
    /// Refuses a closed gate, changed original, unavailable native output credit,
    /// noncontiguous interval or exhausted original journal before effects. Native
    /// socket failures retain the incomplete same grant and prevent redispatch.
    pub fn execute(
        &mut self,
        operation: Id,
        start: Position,
        limit: Position,
    ) -> Result<&PacketGrant, ProviderError> {
        if let Some(original) = self.grants.get(&operation) {
            if original.start != start || original.limit != limit {
                return Err(ProviderError::Conflict("packet original grant"));
            }
            if !original.complete {
                return Err(ProviderError::Correlation(
                    "packet original effect remains uncertain",
                ));
            }
            return self
                .grants
                .get(&operation)
                .ok_or(ProviderError::Frame("packet original absent"));
        }
        start.validate()?;
        limit.validate()?;
        if self.gate_closed || self.failed || start != self.reached || start > limit {
            return Err(ProviderError::Correlation("packet native grant scope"));
        }
        if self.grants.len() >= MAXIMUM_OPERATIONS || !self.outputs.is_empty() {
            return Err(ProviderError::ResourceExhausted(
                "packet original/output custody",
            ));
        }
        // Prepare every trace, owned output and complete resulting inventory
        // before the first socket effect. The result remains prospective until
        // every whole callback completes; the retained incomplete original is
        // never treated as evidence of those future effects.
        let completed = self.preview(&operation, start, limit)?;
        let end = self.events.len() - self.next_event - completed.inventory.pending.len();
        let mut publications = completed.newborn.clone().into_iter();
        let mut callbacks = Vec::with_capacity(end);
        for event in &self.events[self.next_event..self.next_event + end] {
            let mut trace = Vec::with_capacity(MAXIMUM_PAYLOAD + 1);
            trace.push(u8::from(event.payload.is_some()));
            if let Some(payload) = &event.payload {
                trace.extend_from_slice(payload.as_slice());
            }
            let publication = if event.payload.is_some() {
                Some(
                    publications
                        .next()
                        .ok_or(ProviderError::Frame("packet prospective output population"))?,
                )
            } else {
                None
            };
            callbacks.push((trace, publication));
        }
        if publications.next().is_some() || self.outputs.capacity() < completed.newborn.len() {
            return Err(ProviderError::ResourceExhausted(
                "packet callback output plan",
            ));
        }
        let original = PacketGrant {
            operation: operation.clone(),
            start,
            limit,
            inventory: self.inventory(),
            newborn: Vec::new(),
            complete: false,
        };
        self.grants.insert(operation.clone(), original);
        for (trace, publication) in callbacks {
            // An I/O error may have transmitted. Keep the same incomplete
            // original and genuine native prefix; never repeat its callbacks.
            if let Err(error) = self.effect_socket.send(&trace) {
                self.failed = true;
                return Err(error.into());
            }
            if let Some(publication) = publication {
                self.packet_effects += 1;
                self.outputs.push(publication);
            } else {
                self.private_mutations += 1;
            }
            self.next_event += 1;
        }
        self.reached = completed.inventory.reached;
        let retained = self
            .grants
            .get_mut(&operation)
            .ok_or(ProviderError::Frame("packet original absent"))?;
        *retained = completed;
        self.grants
            .get(&operation)
            .ok_or(ProviderError::Frame("packet original absent"))
    }

    /// Acknowledges exactly the complete original output population once.
    ///
    /// Retained grants keep full original bytes and native FIFO identities after
    /// ACK. Identical repeated retirement is inert; changed output IDs refuse.
    ///
    /// # Errors
    /// Refuses missing/incomplete originals or changed original output custody.
    pub fn retire(&mut self, operation: &Id, events: &[Id]) -> Result<(), ProviderError> {
        if let Some(original) = self.retired.get(operation) {
            return if original == events {
                Ok(())
            } else {
                Err(ProviderError::Conflict("packet original retirement"))
            };
        }
        let original = self
            .grants
            .get(operation)
            .filter(|original| original.complete)
            .ok_or(ProviderError::Correlation(
                "packet retirement original absent",
            ))?;
        let expected = original
            .newborn
            .iter()
            .map(|output| output.event.clone())
            .collect::<Vec<_>>();
        if expected != events
            || self
                .outputs
                .iter()
                .any(|output| &output.operation != operation)
        {
            return Err(ProviderError::Conflict("packet output population"));
        }
        self.retired.insert(operation.clone(), expected);
        self.outputs.clear();
        Ok(())
    }
}

#[cfg(test)]
#[path = "reference_packet_tests.rs"]
mod tests;
