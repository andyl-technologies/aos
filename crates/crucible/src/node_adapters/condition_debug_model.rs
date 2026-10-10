//! Retains genuine event-condition evaluation without claiming a world stop.
//!
//! A matching input produces an immutable candidate. Only a separately admitted
//! live runtime fence can establish a common stopped cut and authorize report
//! publication or resume. This model never substitutes terminal finalization,
//! empty queues, a serialized marker or diagnostic host time for that proof.
//!
//! ```text
//! {"format":"crucible.host-condition-model","version":1,
//!  "definition":{...},"evaluation":[...],"candidate":null,"resumed":false}
//! ```

use crucible_node_contract::{Bytes, ContentRef, Id, Phase, Position, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::semantic_model::{HostSemanticDefinition, HostSemanticModel, HostSemanticPublication};
use crate::node_contract::{EffectKnowledge, OperationFailure};
use crate::node_scheduling::event::Delivery;
use crate::{
    AssertionQuantifierKind, HostAssertionOutcome, HostAssertionOutcomeKind, IoEventKind,
    Predicate, Property, PropertyLifecycleState,
};

/// Binds a named canonical condition to one qualified BlockCompletion lane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionDebugDefinition {
    /// Selects the independent condition-model grammar, currently one.
    pub version: u16,
    /// Names the single immutable condition, independent of a live session ID.
    pub condition: Id,
    /// Retains exact compact properties and the actual source projection.
    pub evaluation: HostSemanticDefinition,
}

/// Retains an original match without asserting a physical or common-world stop.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionHitCandidate {
    /// Names the immutable condition that actually became true.
    pub condition: Id,
    /// Retains the actual input/evaluation coordinate, not a guessed stop cut.
    pub evaluation: Position,
    /// Retains the original matching delivery and its native evidence association.
    pub input: Delivery,
    /// Retains the exact original evaluator outcome bytes and causal parents.
    pub outcome: HostSemanticPublication,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    format: String,
    version: u16,
    definition: ConditionDebugDefinition,
    evaluation: Bytes,
    candidate: Option<ConditionHitCandidate>,
    resumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    journal: Option<ContentRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provenance: Vec<ContentRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceIndex {
    format: String,
    schema_version: u16,
    node: Id,
    stage_operation: Id,
    batch: Id,
    inventory: ContentRef,
    roots: Vec<ContentRef>,
    objects: Vec<ContentRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalOutcome {
    format: String,
    version: u16,
    assertion: String,
    quantifier: AssertionQuantifierKind,
    outcome_time_ps: u64,
    evaluation: Position,
    kind: HostAssertionOutcomeKind,
    lifecycle: PropertyLifecycleState,
    message: String,
    reason: String,
}

/// Owns the original evaluator checkpoint and first-match candidate.
///
/// Constructors and decoding establish model consistency only. They create no
/// native operation, stop, publication, ACK or resume authority.
#[derive(Clone, Debug)]
pub struct ConditionDebugModel {
    definition: ConditionDebugDefinition,
    evaluation: HostSemanticModel,
    candidate: Option<ConditionHitCandidate>,
    resumed: bool,
    maximum_bytes: usize,
    maximum_events: usize,
    journal: Option<native::NativeControlJournal>,
    provenance: Vec<crate::node_contract::SavedInputProvenance>,
}

impl ConditionDebugModel {
    /// Constructs a bounded, inactive single-condition observation model.
    ///
    /// # Errors
    /// Refuses unknown editions, multiple or unqualified lanes, a non-IoAny
    /// condition, changed names, unsupported quantifiers or finite state limits.
    pub fn new(
        definition: ConditionDebugDefinition,
        maximum_bytes: usize,
        maximum_events: usize,
    ) -> Result<Self, OperationFailure> {
        let evaluation =
            HostSemanticModel::new(definition.evaluation.clone(), maximum_bytes, maximum_events)?;
        let assertions = evaluation.properties().assertions();
        if definition.version != 1
            || definition.evaluation.version != 1
            || definition.evaluation.inputs.len() != 1
            || assertions.len() != 1
            || assertions[0].id.name != definition.condition.as_str()
        {
            return Err(refuse("condition profile, name or original lane refused"));
        }
        let source = &definition.evaluation.inputs[0].source.node_id;
        match &assertions[0].property {
            Property::Sometimes {
                predicate: Predicate::IoPattern { node, kind },
            } if node.name == source.as_str() && *kind == IoEventKind::Any => {}
            _ => {
                return Err(refuse(
                    "condition requires an actual terminal IoAny completion",
                ));
            }
        }
        let model = Self {
            definition,
            evaluation,
            candidate: None,
            resumed: false,
            maximum_bytes,
            maximum_events,
            journal: None,
            provenance: Vec::new(),
        };
        model.capture()?;
        Ok(model)
    }

    /// Returns the unchanged immutable installed definition.
    pub fn definition(&self) -> &ConditionDebugDefinition {
        &self.definition
    }

    fn expansion_credit(&self) -> Result<native::ExpansionCredit, OperationFailure> {
        let mut expanded = native::ExpansionCredit::new();
        expanded.charge(1, self.evaluation.capture()?.len())?;
        if let Some(hit) = &self.candidate {
            expanded.charge(
                1 + hit.outcome.parents.len(),
                hit.outcome.bytes.as_slice().len(),
            )?;
        }
        for saved in &self.provenance {
            expanded.provenance(saved)?;
        }
        if let Some(journal) = &self.journal {
            expanded.record(
                &journal.stop,
                usize::try_from(journal.barrier.length.get())
                    .map_err(|_| refuse("condition expanded index length overflow"))?,
            )?;
            expanded.charge(1, journal.report.bytes.len())?;
            if let Some(resume) = &journal.resume {
                expanded.charge(1, native::canonical_bytes(resume)?.len())?;
            }
        }
        Ok(expanded)
    }

    /// Returns the actual original evaluation cursor.
    pub fn position(&self) -> Position {
        self.evaluation.position()
    }

    /// Returns an original candidate without upgrading it to stopped-world proof.
    pub fn candidate(&self) -> Option<&ConditionHitCandidate> {
        self.candidate.as_ref()
    }

    /// Returns whether the selected native model still awaits stop/resume control.
    pub fn awaiting_control(&self) -> bool {
        self.candidate.is_some() && !self.resumed
    }

    /// Consumes a qualified original input and retains its first actual match.
    ///
    /// # Errors
    /// Refuses input after an unresolved hit, foreign/duplicate lineage, invalid
    /// reaction positions or exhausted state credit before replacing live state.
    pub fn consume(
        &mut self,
        delivery: &Delivery,
        bytes: &[u8],
        at: Position,
    ) -> Result<(), OperationFailure> {
        if self.awaiting_control() {
            return Err(refuse(
                "original condition hit must settle before later input",
            ));
        }
        let mut expanded = self.expansion_credit()?;
        expanded.charge(1, bytes.len())?;
        let mut staged = self.clone();
        staged.evaluation.consume(delivery, bytes, at)?;
        let outcomes = staged.evaluation.take_publications();
        if !outcomes.is_empty() {
            if outcomes.len() != 1 || staged.candidate.is_some() {
                return Err(refuse(
                    "original single-hit condition emitted an extra outcome",
                ));
            }
            let outcome = &outcomes[0];
            staged.validate_candidate(delivery, outcome)?;
            staged.candidate = Some(ConditionHitCandidate {
                condition: staged.definition.condition.clone(),
                evaluation: at,
                input: delivery.clone(),
                outcome: outcome.clone(),
            });
        }
        staged.capture()?;
        *self = staged;
        Ok(())
    }

    pub(super) fn validate_input(
        &self,
        input: &Delivery,
        bytes: &[u8],
    ) -> Result<(), OperationFailure> {
        if self.awaiting_control() {
            return Err(refuse("condition hit still awaits original control"));
        }
        self.evaluation.validate_input(input, bytes)
    }

    /// Parks only native cursor bookkeeping without claiming global suspension.
    ///
    /// After a hit, same-instant settlement may reach the separately checked
    /// common cut. Advancing physical time before live resume authority refuses.
    ///
    /// # Errors
    /// Refuses backwards progress, skipped evaluator work or physical progress
    /// past an unresolved original hit.
    pub fn park(&mut self, at: Position) -> Result<(), OperationFailure> {
        if self.awaiting_control()
            && self
                .candidate
                .as_ref()
                .is_some_and(|hit| at.time_ps != hit.evaluation.time_ps)
        {
            return Err(refuse("unresolved condition cannot advance physical time"));
        }
        self.evaluation.park(at)
    }

    /// Encodes exact original checkpoint/candidate state without finalization.
    ///
    /// # Errors
    /// Refuses canonical encoding failure or the complete bounded byte ceiling.
    pub fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        let (root, store) = self.capture_dag()?;
        store.encode(vec![root])
    }

    pub(super) fn capture_dag(&self) -> Result<(ContentRef, dag::EvidenceDag), OperationFailure> {
        self.expansion_credit()?;
        let maximum_objects = self
            .maximum_events
            .checked_mul(8)
            .and_then(|count| count.checked_add(16))
            .ok_or_else(|| refuse("condition DAG object count overflow"))?;
        let mut store = dag::EvidenceDag::new(maximum_objects, self.maximum_bytes);
        let mut provenance = Vec::new();
        for saved in &self.provenance {
            let mut objects = Vec::new();
            for object in &saved.objects {
                store.insert(
                    object.reference.clone(),
                    &object.bytes,
                    Self::original_dependencies(&object.bytes)?,
                )?;
                objects.push(object.reference.clone());
            }
            let index = ProvenanceIndex {
                format: "crucible.host-condition-provenance-index".into(),
                schema_version: saved.schema_version,
                node: saved.node.clone(),
                stage_operation: saved.stage_operation.clone(),
                batch: saved.batch.clone(),
                inventory: saved.inventory.clone(),
                roots: saved.roots.clone(),
                objects: objects.clone(),
            };
            let bytes = native::canonical_bytes(&index)?;
            provenance.push(store.add(&bytes, "application/json", objects)?);
        }
        let journal = self
            .journal
            .as_ref()
            .map(|journal| journal.store(&mut store))
            .transpose()?;
        let wire = Continuation {
            format: "crucible.host-condition-model-index".into(),
            version: 1,
            definition: self.definition.clone(),
            evaluation: Bytes::new(self.evaluation.capture()?),
            candidate: self.candidate.clone(),
            resumed: self.resumed,
            journal: journal.clone(),
            provenance: provenance.clone(),
        };
        let mut dependencies = provenance;
        dependencies.extend(journal);
        let bytes = native::canonical_bytes(&wire)?;
        let reference = store.add(&bytes, "application/octet-stream", dependencies)?;
        // This complete closure check reserves serialized as well as raw body
        // credit before a caller can replace any native model state.
        store.encode(vec![reference.clone()])?;
        Ok((reference, store))
    }

    pub(crate) fn original_dependencies(bytes: &[u8]) -> Result<Vec<ContentRef>, OperationFailure> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Ok(Vec::new());
        };
        if value.get("schema_version") == Some(&serde_json::json!(1))
            && value.get("profile").and_then(serde_json::Value::as_str)
                == Some(super::host::HOST_EXACT_PROFILE)
        {
            return super::host::condition_provenance::original_receipt_dependencies(bytes);
        }
        match value.get("format").and_then(serde_json::Value::as_str) {
            Some("crucible.host-condition-model-index") => {
                let wire: Continuation =
                    serde_json::from_value(value).map_err(|error| refuse(&error.to_string()))?;
                let mut dependencies = wire.provenance;
                dependencies.extend(wire.journal);
                dependencies.sort();
                dependencies.dedup();
                Ok(dependencies)
            }
            Some("crucible.host-condition-provenance-index") => {
                let index: ProvenanceIndex =
                    serde_json::from_value(value).map_err(|error| refuse(&error.to_string()))?;
                Ok(index.objects)
            }
            Some("crucible.host-condition-native-index") => {
                super::host::condition_state::original_dependencies(bytes)
            }
            Some("crucible.host-condition-journal-index") => {
                native::NativeControlJournal::index_dependencies(bytes)
            }
            Some("crucible.host-condition-stop-inventory") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Inventory {
                    format: String,
                    version: u16,
                    activation: crate::node_contract::SavedRuntimeActivation,
                    node: Id,
                    owners: Vec<crate::node_contract::OwnerIdentity>,
                    boundary: Position,
                    native: ContentRef,
                }
                let inventory: Inventory =
                    serde_json::from_value(value).map_err(|error| refuse(&error.to_string()))?;
                if inventory.version != 1
                    || inventory.format != "crucible.host-condition-stop-inventory"
                    || inventory.owners.is_empty()
                    || inventory.node.as_str().is_empty()
                    || inventory.boundary.validate().is_err()
                    || inventory.activation.generation.get() == 0
                {
                    return Err(refuse(
                        "condition original native inventory selected grammar changed",
                    ));
                }
                Ok(vec![inventory.native])
            }
            _ if value.get("native").is_some_and(serde_json::Value::is_array)
                && value.get("hit").is_some() =>
            {
                let stop: crate::node_contract::ConditionStopRecord =
                    serde_json::from_value(value).map_err(|error| refuse(&error.to_string()))?;
                if stop.version != 1 {
                    return Err(refuse("condition original stop selected grammar changed"));
                }
                Ok(stop
                    .native
                    .into_iter()
                    .map(|inventory| inventory.receipt.reference)
                    .collect())
            }
            _ if value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                == Some(4)
                && value.get("profile").and_then(serde_json::Value::as_str)
                    == Some(super::host::HOST_CONDITION_INVENTORY_PROFILE) =>
            {
                let reference: ContentRef = serde_json::from_value(
                    value
                        .get("native")
                        .ok_or_else(|| refuse("condition native receipt omitted its model"))?
                        .clone(),
                )
                .map_err(|error| refuse(&error.to_string()))?;
                Ok(vec![reference])
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Installs original model data without reevaluating a matched prefix.
    ///
    /// # Errors
    /// Refuses changed definitions, unsupported records, invalid original hit
    /// associations or finite state limits. Parsed data creates no authority.
    pub fn restore(
        definition: ConditionDebugDefinition,
        bytes: &[u8],
        maximum_bytes: usize,
        maximum_events: usize,
    ) -> Result<Self, OperationFailure> {
        if bytes.len() > maximum_bytes {
            return Err(refuse("condition checkpoint byte credit exhausted"));
        }
        let maximum_objects = maximum_events
            .checked_mul(8)
            .and_then(|count| count.checked_add(16))
            .ok_or_else(|| refuse("condition DAG object count overflow"))?;
        let (store, roots) = dag::EvidenceDag::decode(bytes, maximum_objects, maximum_bytes)?;
        if roots.len() != 1 {
            return Err(refuse(
                "condition model DAG requires its single original index",
            ));
        }
        let wire: Continuation = serde_json::from_slice(store.body(&roots[0])?)
            .map_err(|error| refuse(&error.to_string()))?;
        if wire.format != "crucible.host-condition-model-index"
            || wire.version != 1
            || wire.definition != definition
        {
            return Err(refuse(
                "condition original definition or control history changed",
            ));
        }
        // Preflight all repeated byte-bearing associations before the native
        // journal or provenance decoder copies any original body.
        let mut expanded = native::ExpansionCredit::new();
        expanded.charge(1, wire.evaluation.as_slice().len())?;
        if wire.provenance.len() > maximum_events {
            return Err(refuse("condition expanded provenance history exhausted"));
        }
        for reference in &wire.provenance {
            let index: ProvenanceIndex = serde_json::from_slice(store.body(reference)?)
                .map_err(|error| refuse(&error.to_string()))?;
            if index.format != "crucible.host-condition-provenance-index" {
                return Err(refuse(
                    "condition original provenance index grammar changed",
                ));
            }
            expanded.charge(1 + index.roots.len(), 0)?;
            for reference in &index.objects {
                expanded.charge(1, store.body(reference)?.len())?;
            }
        }
        if let Some(reference) = &wire.journal {
            native::NativeControlJournal::preflight_restore(&store, reference, &mut expanded)?;
        }
        let mut model = Self::new(definition, maximum_bytes, maximum_events)?;
        model.evaluation = HostSemanticModel::restore(
            model.definition.evaluation.clone(),
            wire.evaluation.as_slice(),
            maximum_bytes,
            maximum_events,
        )?;
        if model.evaluation.pending_count() != 0 {
            return Err(refuse(
                "condition candidate omitted original queued evaluator outcome",
            ));
        }
        if let Some(hit) = &wire.candidate {
            if hit.condition != model.definition.condition
                || hit.evaluation != hit.outcome.evaluation
                || hit.evaluation > model.position()
                || hit.evaluation.phase != Phase::Reaction
                || model.evaluation.first_original_input() != Some(&hit.input)
            {
                return Err(refuse("condition original hit coordinate changed"));
            }
            model.validate_candidate(&hit.input, &hit.outcome)?;
        } else if !model.evaluation.retained_condition_outcomes().is_empty() {
            return Err(refuse("condition checkpoint omitted its original hit"));
        }
        model.candidate = wire.candidate;
        model.resumed = wire.resumed;
        model.journal = wire
            .journal
            .map(|reference| native::NativeControlJournal::restore(&store, &reference))
            .transpose()?;
        model.provenance = wire
            .provenance
            .iter()
            .map(|reference| {
                let index: ProvenanceIndex = serde_json::from_slice(store.body(reference)?)
                    .map_err(|error| refuse(&error.to_string()))?;
                if index.format != "crucible.host-condition-provenance-index" {
                    return Err(refuse(
                        "condition original provenance index grammar changed",
                    ));
                }
                let objects = index
                    .objects
                    .iter()
                    .map(|reference| {
                        Ok(crate::node_scheduling::InputPayload {
                            reference: reference.clone(),
                            bytes: store.body(reference)?.to_vec(),
                        })
                    })
                    .collect::<Result<Vec<_>, OperationFailure>>()?;
                Ok(crate::node_contract::SavedInputProvenance {
                    schema_version: index.schema_version,
                    node: index.node,
                    stage_operation: index.stage_operation,
                    batch: index.batch,
                    inventory: index.inventory,
                    roots: index.roots,
                    objects,
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        model.validate_provenance()?;
        model.validate_native_journal()?;
        if model.capture()? != bytes {
            return Err(refuse(
                "condition original DAG edges or canonical history changed",
            ));
        }
        Ok(model)
    }

    /// Installs the unchanged complete original native model continuation.
    ///
    /// # Errors
    /// Refuses changed installed definition, malformed history or finite limits;
    /// decoding creates no restored control or current publication authority.
    pub fn restore_continuation(&mut self, bytes: &[u8]) -> Result<(), OperationFailure> {
        let restored = Self::restore(
            self.definition.clone(),
            bytes,
            self.maximum_bytes,
            self.maximum_events,
        )?;
        *self = restored;
        Ok(())
    }

    fn validate_candidate(
        &self,
        delivery: &Delivery,
        outcome: &HostSemanticPublication,
    ) -> Result<(), OperationFailure> {
        let original = self.evaluation.retained_condition_outcomes();
        if original.len() != 1 {
            return Err(refuse(
                "condition candidate omitted its original evaluator fact",
            ));
        }
        validate_outcome(&self.definition, delivery, outcome, &original[0])
    }
}

fn validate_outcome(
    definition: &ConditionDebugDefinition,
    delivery: &Delivery,
    outcome: &HostSemanticPublication,
    original: &HostAssertionOutcome,
) -> Result<(), OperationFailure> {
    let value: OriginalOutcome = serde_json::from_slice(outcome.bytes.as_slice())
        .map_err(|error| refuse(&error.to_string()))?;
    let encoded = canonical::canonical_json(
        &serde_json::to_value(&value).map_err(|error| refuse(&error.to_string()))?,
    )
    .map_err(|error| refuse(&error.to_string()))?;
    if encoded != outcome.bytes.as_slice()
        || value.format != "crucible.host-assertion-outcome"
        || value.version != 1
        || value.assertion != definition.condition.as_str()
        || value.assertion != original.assertion.name
        || value.quantifier != AssertionQuantifierKind::Sometimes
        || value.quantifier != original.quantifier
        || value.kind != HostAssertionOutcomeKind::Satisfied
        || value.kind != original.kind
        || value.lifecycle != PropertyLifecycleState::Satisfied
        || value.lifecycle != original.lifecycle
        || value.outcome_time_ps != original.at.ticks
        || value.outcome_time_ps != outcome.evaluation.time_ps.get()
        || value.evaluation != outcome.evaluation
        || value.message != original.message
        || value.reason != original.reason
        || value.reason != "sometimes predicate became true"
        || outcome.evaluation.phase != Phase::Reaction
        || outcome.parents != [delivery.delivery]
        || outcome.evaluation.time_ps != delivery.delivery.time_ps
        || outcome.evaluation.microstep.get()
            != delivery
                .delivery
                .microstep
                .get()
                .checked_add(1)
                .ok_or_else(|| refuse("condition original reaction microstep overflow"))?
    {
        return Err(refuse(
            "condition candidate differs from its original evaluator outcome",
        ));
    }
    Ok(())
}

pub(super) fn refuse(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "condition_debug_model_tests.rs"]
mod tests;

#[path = "condition_debug_native.rs"]
pub(super) mod native;

#[path = "condition_debug_dag.rs"]
pub(super) mod dag;
