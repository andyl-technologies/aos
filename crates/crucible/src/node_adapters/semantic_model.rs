//! Owned assertion execution and unchanged continuation over native input facts.
//!
//! The model evaluates the existing host assertion engine, retains its exact
//! checked event-log segments and full-position sidecar, and queues original
//! outcomes. Installed adapters authenticate every source route before exposing
//! this model as a simulation node. These constructors issue no native proof.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, Endpoint, HashRef, Phase, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::{
    BlackBoxHostOracle, EventLog, EventLogOffset, HostAssertionEvaluator,
    HostAssertionEvaluatorCheckpoint, IoEventKind, NodeId, ObservableEvent, ObservableEventPayload,
    Properties, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload,
    VirtualTime,
    model::{PropertyNamespace, PropertyObservation},
    node_contract::{EffectKnowledge, OperationFailure},
    node_scheduling::event::Delivery,
};

/// Selects a genuinely decoded source completion surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSemanticInputKind {
    /// Decodes a terminal block reply without claiming its original request kind.
    BlockCompletion,
}

/// Binds an installed observation adapter to its actual source output lane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSemanticInput {
    /// Names the exact original native producer endpoint.
    pub source: Endpoint,
    /// Selects the immutable installed payload projection.
    pub kind: HostSemanticInputKind,
}

/// Retains immutable property bytes and the complete admitted input projections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSemanticDefinition {
    /// Selects the independent semantic model edition, one.
    pub version: u16,
    /// Contains unchanged compact property bytes.
    pub properties: Bytes,
    /// Lists original producer lanes in increasing endpoint order.
    pub inputs: Vec<HostSemanticInput>,
}

/// Retains one original assertion outcome awaiting native publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSemanticPublication {
    /// Preserves actual evaluation position independently of outcome deadline time.
    pub evaluation: Position,
    /// Retains the consumed delivery that caused this result, when applicable.
    pub parents: Vec<Position>,
    /// Binds the unchanged canonical outcome payload.
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    position: Position,
    input: Option<Delivery>,
    entries: Vec<SchedulerEventLogEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    format: String,
    version: u16,
    definition: HashRef,
    position: Position,
    prefix: EventLogOffset,
    segments: Vec<Segment>,
    assertions: Bytes,
    pending: Vec<HostSemanticPublication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<HostSemanticTerminal>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomePayload {
    format: String,
    version: u16,
    assertion: String,
    quantifier: crate::AssertionQuantifierKind,
    outcome_time_ps: u64,
    evaluation: Position,
    kind: crate::HostAssertionOutcomeKind,
    lifecycle: crate::PropertyLifecycleState,
    message: String,
    reason: String,
}

/// Owns actual assertion evaluation, checked history and retained original outputs.
///
/// Mutations stage a complete finite model copy before replacing the live
/// state. Restoration reconstructs log storage and installs the original
/// assertion checkpoint without reevaluating inputs or emitting results again.
#[derive(Clone, Debug)]
pub struct HostSemanticModel {
    definition: HostSemanticDefinition,
    definition_hash: HashRef,
    properties: Properties,
    evaluator: HostAssertionEvaluator,
    log: EventLog,
    position: Position,
    segments: Vec<Segment>,
    pending: Vec<HostSemanticPublication>,
    maximum_bytes: usize,
    maximum_events: usize,
    reported: BTreeSet<String>,
    terminal: Option<HostSemanticTerminal>,
}

impl HostSemanticModel {
    /// Constructs an inactive model from exact properties and installed routes.
    ///
    /// # Errors
    /// Refuses unknown editions, duplicate/excessive routes, unavailable
    /// predicate surfaces, malformed property bytes or invalid finite ceilings.
    pub fn new(
        definition: HostSemanticDefinition,
        maximum_bytes: usize,
        maximum_events: usize,
    ) -> Result<Self, OperationFailure> {
        if !matches!(definition.version, 1 | 2)
            || definition.inputs.len() > 64
            || maximum_events == 0
            || maximum_events > 65_536
            || maximum_bytes == 0
            || maximum_bytes > 16 * 1024 * 1024
            || definition.properties.as_slice().len() > maximum_bytes
            || definition
                .inputs
                .windows(2)
                .any(|pair| endpoint_key(&pair[0].source) >= endpoint_key(&pair[1].source))
        {
            return Err(failure("semantic model edition, routes or bounds refused"));
        }
        let mut nodes = BTreeMap::<NodeId, BTreeSet<PropertyObservation>>::new();
        for input in &definition.inputs {
            input
                .source
                .validate()
                .map_err(|_| failure("semantic source endpoint invalid"))?;
            nodes
                .entry(NodeId {
                    name: input.source.node_id.as_str().into(),
                })
                .or_default()
                .insert(PropertyObservation::Io(IoEventKind::Any));
        }
        let namespace =
            PropertyNamespace::new(nodes, false, definition.version == 2, BTreeSet::new())
                .map_err(|error| failure(&error.to_string()))?;
        let properties = Properties::from_compact_binary_for_namespace(
            &namespace,
            definition.properties.as_slice(),
        )
        .map_err(|error| failure(&error.to_string()))?;
        let definition_hash = canonical::json_hash(
            if definition.version == 1 {
                "crucible.host-semantic-definition.v1"
            } else {
                "crucible.host-semantic-definition.v2"
            },
            &definition,
        )
        .map_err(|error| failure(&error.to_string()))?;
        let model = Self {
            definition,
            definition_hash,
            evaluator: HostAssertionEvaluator::new(&properties),
            properties,
            log: EventLog::new(),
            position: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
            segments: Vec::new(),
            pending: Vec::new(),
            maximum_bytes,
            maximum_events,
            reported: BTreeSet::new(),
            terminal: None,
        };
        model.capture()?;
        Ok(model)
    }

    /// Returns the exact immutable model definition for installed qualification.
    pub fn definition(&self) -> &HostSemanticDefinition {
        &self.definition
    }

    /// Returns the exact admitted properties without replacing their definitions.
    pub fn properties(&self) -> &Properties {
        &self.properties
    }

    /// Returns the original full native execution position.
    pub fn position(&self) -> Position {
        self.position
    }

    /// Returns the first retained original delivery without evaluating its prefix.
    ///
    /// The borrowed record contains historical data only. Native capture and
    /// continuation verifiers independently authenticate its source association.
    pub fn first_original_input(&self) -> Option<&Delivery> {
        self.segments
            .iter()
            .find_map(|segment| segment.input.as_ref())
    }

    // Retained evaluator facts validate a debugger candidate without replaying
    // its input prefix or trusting a separately serialized outcome marker.
    pub(crate) fn retained_condition_outcomes(&self) -> Vec<crate::HostAssertionOutcome> {
        self.evaluator.retained_terminal_outcomes()
    }

    /// Returns the number of retained original publications.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns the earliest original outcome or declared property evaluation.
    ///
    /// Deadline expiry is evaluated after the complete physical deadline instant,
    /// so same-instant input microsteps remain eligible to satisfy the obligation.
    pub fn next_position(&self) -> Option<Position> {
        let declared = self
            .properties
            .assertions()
            .iter()
            .flat_map(|assertion| property_times(&assertion.property))
            .map(|time| Position::new(U64::new(time), U64::new(0), Phase::Reaction))
            .filter(|at| *at > self.position)
            .min();
        let expiry = self
            .evaluator
            .next_eventually_deadline()
            .and_then(|deadline| deadline.ticks.checked_add(1))
            .map(|time| Position::new(U64::new(time), U64::new(0), Phase::Reaction))
            .filter(|at| *at > self.position);
        self.pending
            .iter()
            .map(|output| output.evaluation)
            .chain(declared)
            .chain(expiry)
            .min()
    }

    /// Parks native time only after every earlier semantic action was settled.
    ///
    /// # Errors
    /// Refuses backwards progress or parking past retained work or outputs.
    pub fn park(&mut self, at: Position) -> Result<(), OperationFailure> {
        self.require_open()?;
        at.validate()
            .map_err(|_| failure("semantic parked position invalid"))?;
        if at < self.position || self.next_position().is_some_and(|next| next < at) {
            return Err(failure("semantic parking would skip original pending work"));
        }
        self.position = at;
        Ok(())
    }

    /// Validates a source completion without consuming or reevaluating it.
    ///
    /// # Errors
    /// Refuses a foreign source lane, changed payload bytes, nonterminal block
    /// reply, duplicate original input or noncanonical delivery ordering.
    pub fn validate_input(
        &self,
        delivery: &Delivery,
        bytes: &[u8],
    ) -> Result<(), OperationFailure> {
        if delivery.producer != delivery.producer_endpoint.node_id
            || delivery.consumer != delivery.consumer_endpoint.node_id
            || delivery.publication.phase != Phase::Publication
            || delivery.delivery.phase != Phase::Delivery
            || delivery.publication >= delivery.delivery
            || delivery
                .evaluation
                .is_some_and(|evaluation| evaluation >= delivery.publication)
        {
            return Err(failure(
                "semantic original delivery lineage is inconsistent",
            ));
        }
        for at in delivery
            .evaluation
            .iter()
            .chain([&delivery.publication, &delivery.delivery])
            .chain(delivery.causal_parents.iter())
        {
            at.validate()
                .map_err(|_| failure("semantic original delivery position invalid"))?;
        }
        let input = self
            .definition
            .inputs
            .iter()
            .find(|input| input.source == delivery.producer_endpoint)
            .ok_or_else(|| failure("semantic input is not an installed source route"))?;
        delivery
            .payload
            .verify(bytes)
            .map_err(|_| failure("semantic input payload differs from original custody"))?;
        let response = match input.kind {
            HostSemanticInputKind::BlockCompletion => crucible_device::BlockResponse::decode(bytes)
                .map_err(|error| failure(&error.to_string()))?,
        };
        if !matches!(
            response.status,
            crucible_device::BlockStatus::Ok | crucible_device::BlockStatus::Error
        ) {
            return Err(failure(
                "transport disposition is not a semantic I/O completion",
            ));
        }
        if self
            .segments
            .iter()
            .filter_map(|segment| segment.input.as_ref())
            .any(|original| {
                original.producer == delivery.producer
                    && original.source_sequence == delivery.source_sequence
            })
        {
            return Err(failure("original semantic input already consumed"));
        }
        if self
            .segments
            .iter()
            .rev()
            .find_map(|segment| segment.input.as_ref())
            .is_some_and(|previous| previous.key() >= delivery.key())
        {
            return Err(failure(
                "semantic input is outside original canonical prefix order",
            ));
        }
        Ok(())
    }

    /// Consumes one genuine staged completion at its unchanged reaction position.
    ///
    /// # Errors
    /// Refuses invalid input, changed reaction coordinates, backwards progress or
    /// exhausted state/output credit before changing the original model.
    pub fn consume(
        &mut self,
        delivery: &Delivery,
        bytes: &[u8],
        at: Position,
    ) -> Result<(), OperationFailure> {
        self.require_open()?;
        self.validate_input(delivery, bytes)?;
        let expected = Position::new(
            delivery.delivery.time_ps,
            delivery
                .delivery
                .microstep
                .checked_add(U64::new(1))
                .map_err(|_| failure("semantic reaction microstep exhausted"))?,
            Phase::Reaction,
        );
        if at != expected
            || at < self.position
            || self.next_position().is_some_and(|next| next < at)
        {
            return Err(failure(
                "semantic reaction does not match original delivery",
            ));
        }
        let event = ObservableEvent::io_completion(
            VirtualTime {
                ticks: at.time_ps.get(),
            },
            NodeId {
                name: delivery.producer.as_str().into(),
            },
            IoEventKind::Any,
            bytes.to_vec(),
        );
        self.apply(at, Some(delivery.clone()), vec![event])
    }

    /// Evaluates the next declared native reaction without converting its full cut.
    ///
    /// # Errors
    /// Refuses an undeclared/backwards/duplicate reaction or exhausted state credit.
    pub fn settle(&mut self, at: Position) -> Result<(), OperationFailure> {
        self.require_open()?;
        at.validate()
            .map_err(|_| failure("semantic boundary invalid"))?;
        if at <= self.position || self.next_position() != Some(at) {
            return Err(failure(
                "semantic settlement must match the next original reaction",
            ));
        }
        self.apply(at, None, Vec::new())
    }

    fn apply(
        &mut self,
        at: Position,
        input: Option<Delivery>,
        events: Vec<ObservableEvent>,
    ) -> Result<(), OperationFailure> {
        if self.segments.len() >= self.maximum_events || self.pending.len() >= self.maximum_events {
            return Err(failure("semantic continuation event credit exhausted"));
        }
        let mut staged = self.clone();
        let appended = staged
            .log
            .append_observations_at_boundary(
                events,
                VirtualTime {
                    ticks: at.time_ps.get(),
                },
                SchedulerEvaluationBoundaryKind::Quantum,
            )
            .map_err(|error| failure(&error.to_string()))?;
        let outcomes = staged
            .evaluator
            .observe_prefix(staged.log.condition_prefix(), &mut BlackBoxHostOracle);
        for outcome in outcomes {
            if staged.definition.version == 2 {
                staged.reported.insert(outcome.assertion.name.clone());
            }
            if staged.pending.len() >= staged.maximum_events {
                return Err(failure("semantic publication credit exhausted"));
            }
            let bytes = canonical::canonical_json(&serde_json::json!({
                "format": "crucible.host-assertion-outcome",
                "version": 1,
                "assertion": outcome.assertion.name,
                "quantifier": outcome.quantifier,
                "outcome_time_ps": outcome.at.ticks,
                "evaluation": at,
                "kind": outcome.kind,
                "lifecycle": outcome.lifecycle,
                "message": outcome.message,
                "reason": outcome.reason,
            }))
            .map_err(|error| failure(&error.to_string()))?;
            staged.pending.push(HostSemanticPublication {
                evaluation: at,
                parents: input
                    .as_ref()
                    .map(|delivery| vec![delivery.delivery])
                    .unwrap_or_default(),
                bytes: Bytes::new(bytes),
            });
        }
        staged.position = at;
        staged.segments.push(Segment {
            position: at,
            input,
            entries: appended.entries,
        });
        staged.capture()?;
        *self = staged;
        Ok(())
    }

    /// Transfers original queued outcomes without reevaluation or renumbering.
    pub fn take_publications(&mut self) -> Vec<HostSemanticPublication> {
        std::mem::take(&mut self.pending)
    }

    /// Transfers only original outcomes due at the actual native evaluation cut.
    pub fn take_publications_at(&mut self, at: Position) -> Vec<HostSemanticPublication> {
        let count = self
            .pending
            .iter()
            .take_while(|publication| publication.evaluation <= at)
            .count();
        self.pending.drain(..count).collect()
    }

    /// Encodes the complete original evaluator, prefix, inputs and pending outputs.
    ///
    /// # Errors
    /// Refuses evaluator encoding failures or complete state beyond its ceiling.
    pub fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        let assertions = self
            .evaluator
            .checkpoint()
            .canonical_bytes()
            .map_err(|error| failure(&error.to_string()))?;
        let wire = Continuation {
            format: "crucible.host-semantic-continuation".into(),
            version: self.definition.version,
            definition: self.definition_hash.clone(),
            position: self.position,
            prefix: self.log.offset(),
            segments: self.segments.clone(),
            assertions: Bytes::new(assertions),
            pending: self.pending.clone(),
            reported: self.reported.iter().cloned().collect(),
            terminal: self.terminal.clone(),
        };
        let value = serde_json::to_value(wire).map_err(|error| failure(&error.to_string()))?;
        let bytes =
            canonical::canonical_json(&value).map_err(|error| failure(&error.to_string()))?;
        if bytes.len() > self.maximum_bytes {
            return Err(failure(
                "complete semantic continuation byte credit exhausted",
            ));
        }
        Ok(bytes)
    }

    pub(super) fn restore_continuation(&mut self, bytes: &[u8]) -> Result<(), OperationFailure> {
        let restored = Self::restore(
            self.definition.clone(),
            bytes,
            self.maximum_bytes,
            self.maximum_events,
        )?;
        *self = restored;
        Ok(())
    }

    /// Restores original typed state without executing the retained event prefix.
    ///
    /// Native qualification must authenticate the original signed capture and
    /// fresh owner bindings separately before this portable material is used.
    ///
    /// # Errors
    /// Refuses changed definitions, invalid canonical bytes, incomplete prefix,
    /// original input ordering, checkpoint binding or finite state ceilings.
    pub fn restore(
        definition: HostSemanticDefinition,
        bytes: &[u8],
        maximum_bytes: usize,
        maximum_events: usize,
    ) -> Result<Self, OperationFailure> {
        let value = canonical::parse_json(bytes, maximum_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        let wire: Continuation =
            serde_json::from_value(value).map_err(|error| failure(&error.to_string()))?;
        let mut model = Self::new(definition, maximum_bytes, maximum_events)?;
        if wire.format != "crucible.host-semantic-continuation"
            || wire.version != model.definition.version
            || wire.definition != model.definition_hash
            || wire.segments.len() > maximum_events
            || wire.pending.len() > maximum_events
        {
            return Err(failure(
                "semantic continuation edition, definition or bounds differ",
            ));
        }
        wire.position
            .validate()
            .map_err(|_| failure("semantic saved position invalid"))?;
        for (index, segment) in wire.segments.iter().enumerate() {
            if segment.position < model.position
                || (segment.position == model.position
                    && segment.input.is_none()
                    && !(wire.terminal.is_some() && index + 1 == wire.segments.len()))
                || segment.position > wire.position
            {
                return Err(failure("semantic saved prefix position or entries invalid"));
            }
            segment
                .position
                .validate()
                .map_err(|_| failure("semantic saved segment position invalid"))?;
            match &segment.input {
                Some(delivery) => {
                    let [observation, boundary] = segment.entries.as_slice() else {
                        return Err(failure("semantic input segment is incomplete"));
                    };
                    let SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::IoCompletion {
                            node,
                            kind: IoEventKind::Any,
                            payload,
                        },
                    ) = observation.payload()
                    else {
                        return Err(failure(
                            "semantic saved input has a different observation surface",
                        ));
                    };
                    model.validate_input(delivery, payload)?;
                    let expected = Position::new(
                        delivery.delivery.time_ps,
                        delivery
                            .delivery
                            .microstep
                            .checked_add(U64::new(1))
                            .map_err(|_| failure("semantic saved reaction exhausted"))?,
                        Phase::Reaction,
                    );
                    if segment.position != expected
                        || node.name != delivery.producer.as_str()
                        || observation.at().ticks != segment.position.time_ps.get()
                    {
                        return Err(failure(
                            "semantic saved input lost its original reaction or producer",
                        ));
                    }
                    validate_boundary(boundary, segment.position)?;
                }
                None => {
                    let [boundary] = segment.entries.as_slice() else {
                        return Err(failure("semantic saved settlement segment is incomplete"));
                    };
                    validate_boundary(boundary, segment.position)?;
                }
            }
            model
                .log
                .append_entries(segment.entries.clone())
                .map_err(|error| failure(&error.to_string()))?;
            model.position = segment.position;
            model.segments.push(segment.clone());
        }
        if model.log.offset() != wire.prefix {
            return Err(failure("semantic original prefix or final cut differs"));
        }
        let checkpoint =
            HostAssertionEvaluatorCheckpoint::from_canonical_bytes(wire.assertions.as_slice())
                .map_err(|error| failure(&error.to_string()))?;
        checkpoint
            .restore_into(&mut model.evaluator, model.log.condition_prefix())
            .map_err(|error| failure(&error.to_string()))?;
        for publication in &wire.pending {
            model.validate_publication(publication)?;
        }
        if wire
            .pending
            .windows(2)
            .any(|pair| pair[0].evaluation > pair[1].evaluation)
        {
            return Err(failure(
                "semantic pending publications are out of original order",
            ));
        }
        model.pending = wire.pending;
        model.park(wire.position)?;
        if wire.reported.windows(2).any(|pair| pair[0] >= pair[1])
            || wire.reported.iter().any(|name| {
                !model
                    .properties
                    .assertions()
                    .iter()
                    .any(|assertion| &assertion.id.name == name)
            })
            || (model.definition.version == 1
                && (!wire.reported.is_empty() || wire.terminal.is_some()))
        {
            return Err(failure(
                "semantic emitted registry or terminal edition invalid",
            ));
        }
        model.reported = wire.reported.into_iter().collect();
        let retained_outcomes: BTreeSet<_> = model
            .evaluator
            .retained_terminal_outcomes()
            .into_iter()
            .map(|outcome| outcome.assertion.name)
            .collect();
        if model.evaluator.has_terminal_scheduler_quiescence() != wire.terminal.is_some()
            || (model.definition.version == 2 && model.reported != retained_outcomes)
        {
            return Err(failure(
                "semantic original finalization or emission marker omitted",
            ));
        }

        if let Some(terminal) = &wire.terminal {
            model.validate_terminal_saved(terminal)?;
        }
        model.terminal = wire.terminal;
        if model.capture()?.as_slice() != bytes {
            return Err(failure(
                "semantic continuation is not exact canonical state",
            ));
        }
        Ok(model)
    }

    fn validate_publication(
        &self,
        publication: &HostSemanticPublication,
    ) -> Result<(), OperationFailure> {
        let value = canonical::parse_json(publication.bytes.as_slice(), self.maximum_bytes)
            .map_err(|_| failure("semantic pending outcome payload invalid"))?;
        if canonical::canonical_json(&value)
            .map_err(|_| failure("semantic pending outcome canonical encoding failed"))?
            != publication.bytes.as_slice()
        {
            return Err(failure(
                "semantic pending outcome is not exact canonical bytes",
            ));
        }
        let outcome: OutcomePayload = serde_json::from_value(value)
            .map_err(|_| failure("semantic pending outcome schema invalid"))?;
        let assertion = self
            .properties
            .assertions()
            .iter()
            .find(|assertion| assertion.id.name == outcome.assertion)
            .ok_or_else(|| failure("semantic pending outcome names another assertion"))?;
        let original = self
            .segments
            .iter()
            .find(|segment| {
                segment.position == publication.evaluation
                    && segment
                        .input
                        .iter()
                        .map(|delivery| delivery.delivery)
                        .eq(publication.parents.iter().copied())
            })
            .ok_or_else(|| failure("semantic pending outcome lacks original evaluation"))?;
        let parents: Vec<_> = original
            .input
            .iter()
            .map(|delivery| delivery.delivery)
            .collect();
        if outcome.format != "crucible.host-assertion-outcome"
            || outcome.version != 1
            || outcome.evaluation != publication.evaluation
            || outcome.outcome_time_ps > outcome.evaluation.time_ps.get()
            || outcome.message != assertion.message
            || publication.parents != parents
        {
            return Err(failure(
                "semantic pending outcome differs from original context",
            ));
        }
        // These fields are typed above, without replaying the event prefix to
        // infer a replacement result. Native capture authenticates their bytes.
        let _ = (
            outcome.quantifier,
            outcome.kind,
            outcome.lifecycle,
            outcome.reason,
        );
        Ok(())
    }
}

fn property_times(property: &crate::Property) -> Vec<u64> {
    match property {
        crate::Property::Always { predicate }
        | crate::Property::Sometimes { predicate }
        | crate::Property::AfterQuiescence { predicate }
        | crate::Property::Reachable { predicate, .. } => predicate_times(predicate),
        crate::Property::Eventually {
            trigger, property, ..
        } => {
            let mut times = predicate_times(trigger);
            times.extend(predicate_times(property));
            times
        }
    }
}

fn predicate_times(predicate: &crate::Predicate) -> Vec<u64> {
    match predicate {
        crate::Predicate::At { at } => vec![at.ticks],
        crate::Predicate::AllOf { predicates } | crate::Predicate::AnyOf { predicates } => {
            predicates.iter().flat_map(predicate_times).collect()
        }
        crate::Predicate::Once { predicate } | crate::Predicate::Not { predicate } => {
            predicate_times(predicate)
        }
        _ => Vec::new(),
    }
}

fn validate_boundary(entry: &SchedulerEventLogEntry, at: Position) -> Result<(), OperationFailure> {
    if entry.at().ticks != at.time_ps.get()
        || !matches!(
            entry.payload(),
            SchedulerEventLogPayload::EvaluationBoundary(SchedulerEvaluationBoundaryKind::Quantum)
        )
    {
        return Err(failure(
            "semantic saved evaluation boundary differs from the full-position sidecar",
        ));
    }
    Ok(())
}

fn endpoint_key(endpoint: &Endpoint) -> (&str, &str, &str) {
    (
        endpoint.node_id.as_str(),
        endpoint.port_id.as_str(),
        endpoint.lane_id.as_str(),
    )
}

fn failure(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "semantic_model_tests.rs"]
mod tests;

#[path = "semantic_model_terminal.rs"]
mod terminal;
use terminal::HostSemanticTerminal;
