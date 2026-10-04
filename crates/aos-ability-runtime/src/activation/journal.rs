//! Durable records and replay state for module activation transactions.
//!
//! Records carry a tagged JSON body inside the shared journal frame:
//! `begin` retains the graph, `started` retains an exact invocation, `finished`
//! retains checked results, and `commit` closes the active transaction.
//! `restoration-started` and `restoration-finished` reestablish completed
//! resources without replacing the primary intent or its consumed results.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Effect, Handler, Lifetime};
use aos_contract::canonical;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::journal::{JournalError, JournalLimits, JournalPayload};

use super::{Action, Invocation, PreviousState};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Event {
    Begin {
        transaction: String,
        document: Value,
        retire: Vec<String>,
    },
    Started {
        invocation: Box<Invocation>,
    },
    Finished {
        outputs: Value,
    },
    RestorationStarted {
        invocation: Box<Invocation>,
    },
    RestorationFinished {
        outputs: Value,
    },
    Released,
    Commit,
}

impl JournalPayload for Event {
    fn validate_for_journal(&self, limits: JournalLimits) -> Result<(), JournalError> {
        let bounds = aos_contract::limits::JsonLimits {
            max_bytes: limits.max_body_bytes,
            max_depth: limits.max_depth,
            max_items: limits.max_items,
            max_string_bytes: limits.max_string_bytes,
        };
        let values: Vec<&Value> = match self {
            Self::Begin { document, .. } => vec![document],
            Self::Started { invocation } | Self::RestorationStarted { invocation } => {
                vec![&invocation.input]
            }
            Self::Finished { outputs } | Self::RestorationFinished { outputs } => vec![outputs],
            Self::Released | Self::Commit => vec![],
        };
        for value in values {
            bounds
                .check_value(value, "activation journal value")
                .map_err(|error| JournalError::Limit(error.to_string()))?;
        }
        let mut writer = aos_contract::limits::BoundedWriter::new(
            limits.max_body_bytes as u64,
            "activation journal record",
        );
        serde_json::to_writer(&mut writer, self)
            .map_err(|error| JournalError::Limit(error.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Retained {
    pub invocation: Invocation,
    pub outputs: Value,
}

#[derive(Default)]
pub(super) struct State {
    pub active: Option<CheckedModuleGraph>,
    pub transaction: Option<String>,
    pub sequence: u64,
    pub completed: Option<(String, String, BTreeMap<String, Value>)>,
    pub retire: Vec<String>,
    pub pending: Option<Invocation>,
    pub restoration: Vec<Invocation>,
    pub retained: BTreeMap<String, Retained>,
    pub established: Vec<String>,
    pub retired: BTreeSet<String>,
    pub transaction_results: BTreeMap<String, Value>,
    pub releases: VecDeque<Effect>,
}

impl State {
    pub fn check(&self, event: &Event) -> Result<()> {
        self.check_event(event).map(|_| ())
    }

    // Reuse the validated graph when applying a Begin record. Inspection replays
    // every historical graph, so decoding it again would duplicate that work.
    fn check_event(&self, event: &Event) -> Result<Option<CheckedModuleGraph>> {
        ensure!(
            self.restoration.is_empty()
                || matches!(
                    event,
                    Event::RestorationStarted { .. } | Event::RestorationFinished { .. }
                ),
            "activation has an unfinished restoration"
        );
        match event {
            Event::RestorationStarted { invocation } => {
                let graph = self
                    .active
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("restoration outside an activation"))?;
                let retained = self
                    .retained
                    .get(&invocation.id)
                    .ok_or_else(|| anyhow::anyhow!("restoration of unknown effect"))?;
                ensure!(
                    self.transaction_results.contains_key(&invocation.id)
                        && invocation.action == Action::Apply
                        && invocation.effect.lifetime != Lifetime::Transaction
                        && matches!(invocation.effect.handler, Handler::Process { .. }),
                    "restoration must name a completed non-transaction process effect"
                );
                let effect = graph.graph().nodes.get(&invocation.id).ok_or_else(|| {
                    anyhow::anyhow!("restoration effect absent from active graph")
                })?;
                ensure!(
                    canonical::to_vec(effect)? == canonical::to_vec(&invocation.effect)?
                        && canonical::to_vec(&retained.invocation)?
                            == canonical::to_vec(invocation.as_ref())?,
                    "restoration differs from original completed invocation"
                );
                ensure!(
                    self.releases.is_empty(),
                    "restoration before artifact cleanup"
                );
                if let Some(parent) = self.restoration.last() {
                    let order = &graph.graph().order;
                    let earlier = order.iter().position(|id| id == &invocation.id);
                    let later = order.iter().position(|id| id == &parent.id);
                    ensure!(
                        earlier
                            .zip(later)
                            .is_some_and(|(earlier, later)| earlier < later),
                        "nested restoration must precede its suspended parent"
                    );
                }
                ensure!(
                    self.restoration.len() < graph.graph().nodes.len(),
                    "restoration stack exceeds graph bounds"
                );
                ensure!(
                    graph
                        .graph()
                        .order
                        .iter()
                        .take_while(|id| *id != &invocation.id)
                        .all(|id| self.transaction_results.contains_key(id)),
                    "restoration violates completed graph prefix"
                );
            }
            Event::RestorationFinished { outputs } => {
                let invocation = self
                    .restoration
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("restoration completion without intent"))?;
                invocation.effect.check_results(outputs)?;
                ensure!(
                    canonical::to_vec(outputs)?
                        == canonical::to_vec(&self.transaction_results[&invocation.id])?,
                    "restoration changed already consumed outputs"
                );
            }
            Event::Begin {
                transaction,
                document,
                retire,
            } => {
                ensure!(
                    self.active.is_none() && self.pending.is_none(),
                    "activation transaction already active"
                );
                ensure!(
                    !transaction.is_empty() && transaction.len() <= 256,
                    "invalid transaction identity"
                );
                let desired = CheckedModuleGraph::decode(&canonical::canonical_json(document)?)?;
                let unique: std::collections::BTreeSet<_> = retire.iter().collect();
                ensure!(
                    unique.len() == retire.len(),
                    "duplicate retirement identity"
                );
                ensure!(
                    retire.iter().all(|id| (self.retained.contains_key(id)
                        || self.retired.contains(id))
                        && !desired.graph().nodes.contains_key(id)),
                    "retirement must name retained or already retired, unconfigured state"
                );
                return Ok(Some(desired));
            }
            Event::Started { invocation } => {
                let graph = self
                    .active
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("dispatch outside an activation"))?;
                ensure!(
                    self.pending.is_none(),
                    "activation already has a pending dispatch"
                );
                ensure!(self.releases.is_empty(), "dispatch before artifact cleanup");
                invocation.effect.check_input(&invocation.input)?;
                let expected = match invocation.action {
                    Action::Apply => {
                        let next = graph
                            .graph()
                            .order
                            .iter()
                            .find(|id| !self.transaction_results.contains_key(*id));
                        ensure!(
                            next == Some(&invocation.id),
                            "dispatch violates graph order"
                        );
                        self.application(&invocation.id)?
                    }
                    Action::Remove => {
                        let retained = self
                            .retained
                            .get(&invocation.id)
                            .ok_or_else(|| anyhow::anyhow!("teardown of unknown state"))?;
                        let absent = !graph.graph().nodes.contains_key(&invocation.id);
                        let temporary =
                            retained.invocation.effect.lifetime == Lifetime::Transaction;
                        ensure!(
                            (absent
                                && (retained.invocation.effect.lifetime != Lifetime::Persistent
                                    || self.retire.contains(&invocation.id)))
                                || (temporary
                                    && self.transaction_results.len() == graph.graph().nodes.len()),
                            "teardown is not authorized by the active transaction"
                        );
                        let mut expected = retained.invocation.clone();
                        expected.action = Action::Remove;
                        expected.previous = None;
                        expected
                    }
                };
                ensure!(
                    canonical::to_vec(&expected)? == canonical::to_vec(invocation.as_ref())?,
                    "dispatch differs from checked activation state"
                );
            }
            Event::Finished { outputs } => {
                let invocation = self
                    .pending
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("completion without dispatch"))?;
                match invocation.action {
                    Action::Apply => invocation.effect.check_results(outputs)?,
                    Action::Remove => ensure!(
                        outputs == &serde_json::json!({}),
                        "teardown must return no results"
                    ),
                }
            }
            Event::Released => ensure!(
                !self.releases.is_empty(),
                "artifact release without retained cleanup"
            ),
            Event::Commit => {
                let graph = self
                    .active
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("commit outside an activation"))?;
                ensure!(self.pending.is_none(), "commit with a pending dispatch");
                ensure!(self.releases.is_empty(), "commit before artifact cleanup");
                ensure!(
                    self.transaction_results.len() == graph.graph().nodes.len(),
                    "commit before graph completion"
                );
                ensure!(
                    self.retained.iter().all(|(id, state)| {
                        state.invocation.effect.lifetime != Lifetime::Transaction
                            && (graph.graph().nodes.contains_key(id)
                                || (state.invocation.effect.lifetime == Lifetime::Persistent
                                    && !self.retire.contains(id)))
                    }),
                    "commit before required teardown"
                );
            }
        }
        Ok(None)
    }

    /// Reconstructs the only application authorized by the active graph.
    pub fn application(&self, id: &str) -> Result<Invocation> {
        let graph = self
            .active
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active graph"))?;
        let effect = graph
            .graph()
            .nodes
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("unknown effect"))?;
        // The checked graph's dependency set contains every deferred reference.
        // Project only those outputs, preserving fresh transaction precedence,
        // rather than cloning the growing retained inventory for each dispatch.
        let results: BTreeMap<_, _> = effect
            .dependencies
            .iter()
            .filter_map(|id| {
                self.transaction_results
                    .get(id)
                    .or_else(|| self.retained.get(id).map(|state| &state.outputs))
                    .map(|outputs| (id.clone(), outputs.clone()))
            })
            .collect();
        let input = effect.resolve_input(&results)?;
        let revision = aos_contract::Sha256Digest::of_bytes(canonical::to_vec(&(
            effect.revision.as_str(),
            &input,
        ))?)
        .hex();
        let previous = self.retained.get(id).map(|state| PreviousState {
            effect: state.invocation.effect.clone(),
            input: state.invocation.input.clone(),
            outputs: state.outputs.clone(),
            revision: state.invocation.revision.clone(),
        });
        Ok(Invocation {
            id: id.to_owned(),
            effect: effect.clone(),
            input,
            revision,
            action: Action::Apply,
            previous,
        })
    }

    pub fn apply(&mut self, event: &Event) -> Result<()> {
        let checked_graph = self.check_event(event)?;
        match event {
            Event::RestorationStarted { invocation } => {
                self.restoration.push(invocation.as_ref().clone());
            }
            Event::RestorationFinished { .. } => {
                // Repair proves live state without replacing any consumed receipt.
                self.restoration.pop();
            }
            Event::Begin {
                transaction,
                retire,
                ..
            } => {
                let desired = checked_graph
                    .ok_or_else(|| anyhow::anyhow!("begin without a checked graph"))?;

                self.transaction = Some(transaction.clone());
                self.sequence += 1;
                self.active = Some(desired);
                self.retire = retire.clone();
                self.transaction_results.clear();
            }
            Event::Started { invocation } => {
                self.pending = Some(invocation.as_ref().clone());
            }
            Event::Finished { outputs } => {
                let invocation = self
                    .pending
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("completion without dispatch"))?;
                match invocation.action {
                    Action::Apply => {
                        if let Some(previous) = self.retained.get(&invocation.id) {
                            if artifact(&previous.invocation.effect).is_some()
                                && artifact(&previous.invocation.effect)
                                    != artifact(&invocation.effect)
                            {
                                self.releases.push_back(previous.invocation.effect.clone());
                            }
                        }
                        self.retired.remove(&invocation.id);
                        self.retained.insert(
                            invocation.id.clone(),
                            Retained {
                                invocation: invocation.clone(),
                                outputs: outputs.clone(),
                            },
                        );
                        self.established.retain(|id| id != &invocation.id);
                        self.established.push(invocation.id.clone());
                        self.transaction_results
                            .insert(invocation.id.clone(), outputs.clone());
                    }
                    Action::Remove => {
                        if artifact(&invocation.effect).is_some() {
                            self.releases.push_back(invocation.effect.clone());
                        }
                        self.retained.remove(&invocation.id);
                        self.retired.insert(invocation.id.clone());
                        self.established.retain(|id| id != &invocation.id);
                    }
                }
                self.pending = None;
            }
            Event::Released => {
                self.releases.pop_front();
            }
            Event::Commit => {
                let active = self
                    .active
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("commit without active graph"))?;
                let transaction = self
                    .transaction
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("commit without transaction identity"))?;
                self.completed = Some((
                    transaction,
                    fingerprint(active, &self.retire)?,
                    self.transaction_results.clone(),
                ));
                self.active = None;
                self.retire.clear();
                self.transaction_results.clear();
            }
        }
        Ok(())
    }
}

fn artifact(effect: &Effect) -> Option<&str> {
    match &effect.handler {
        Handler::Process { artifact, .. } => Some(artifact),
        Handler::Composition { .. } => None,
    }
}

pub(super) fn fingerprint(graph: &CheckedModuleGraph, retire: &[String]) -> Result<String> {
    Ok(aos_contract::Sha256Digest::of_bytes(canonical::to_vec(&(
        graph.canonical_bytes()?,
        retire,
    ))?)
    .hex())
}

#[cfg(test)]
mod tests {
    use aos_ability_plan::module_graph::identity_key;
    use serde_json::json;

    use super::*;

    fn referenced_graph() -> (CheckedModuleGraph, String, String, String) {
        let template = super::super::tests::graph(Some("template"), "persistent");
        let template =
            serde_json::to_value(template.graph().nodes.values().next().unwrap()).unwrap();
        let identities: Vec<_> = ["first", "second", "consumer"]
            .into_iter()
            .map(|instance| vec!["test".to_owned(), "echo".to_owned(), instance.to_owned()])
            .collect();
        let keys: Vec<_> = identities
            .iter()
            .map(|identity| identity_key(identity).unwrap())
            .collect();
        let mut nodes = serde_json::Map::new();
        for (index, identity) in identities.iter().enumerate() {
            let mut node = template.clone();
            node["identity"] = json!(identity);
            node["input"] = if index == 2 {
                json!({
                    "first": {"_type":"aos-effect-output", "identity":identities[0], "output":"value", "schema":{"kind":"string"}},
                    "second": {"_type":"aos-effect-output", "identity":identities[1], "output":"value", "schema":{"kind":"string"}}
                })
            } else {
                json!({"value":format!("producer-{index}")})
            };
            if index == 2 {
                node["input_type"] = json!({"kind":"submodule","open":false,"fields":{
                    "first":{"kind":"string"},"second":{"kind":"string"}
                }});
                node["results"] = json!({"first":{"kind":"string"},"second":{"kind":"string"}});
                node["dependencies"] = json!([keys[0], keys[1]]);
            }
            let mut semantic = node.as_object().unwrap().clone();
            semantic.remove("revision");
            semantic.remove("dependencies");
            semantic.remove("inputs");
            node["revision"] = json!(
                aos_contract::Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap()).hex()
            );
            nodes.insert(keys[index].clone(), node);
        }
        let graph = CheckedModuleGraph::decode(
            &serde_json::to_vec(&json!({
                "schema":"aos.activation.graph","nodes":nodes,"order":keys
            }))
            .unwrap(),
        )
        .unwrap();
        (graph, keys[0].clone(), keys[1].clone(), keys[2].clone())
    }

    #[test]
    fn begin_validation_rejects_invalid_records_before_mutating_state() {
        let graph = super::super::tests::graph(Some("desired"), "persistent");
        let document = serde_json::to_value(graph.graph()).unwrap();
        let configured = graph.graph().nodes.keys().next().unwrap().clone();
        let mut state = State {
            sequence: 7,
            retired: BTreeSet::from(["already-retired".to_owned()]),
            ..State::default()
        };
        let invalid_records = [
            Event::Begin {
                transaction: String::new(),
                document: document.clone(),
                retire: vec![],
            },
            Event::Begin {
                transaction: "invalid-graph".into(),
                document: json!({}),
                retire: vec![],
            },
            Event::Begin {
                transaction: "duplicate-retirement".into(),
                document: document.clone(),
                retire: vec!["already-retired".into(), "already-retired".into()],
            },
            Event::Begin {
                transaction: "unknown-retirement".into(),
                document: document.clone(),
                retire: vec!["unknown".into()],
            },
            Event::Begin {
                transaction: "configured-retirement".into(),
                document: document.clone(),
                retire: vec![configured],
            },
        ];

        for event in invalid_records {
            assert!(state.check(&event).is_err());
            assert!(state.apply(&event).is_err());
            assert_eq!(state.sequence, 7);
            assert!(state.active.is_none());
            assert!(state.transaction.is_none());
            assert!(state.retire.is_empty());
            assert!(state.transaction_results.is_empty());
        }

        let valid = Event::Begin {
            transaction: "checked-begin".into(),
            document,
            retire: vec!["already-retired".into()],
        };
        state.check(&valid).unwrap();
        state.apply(&valid).unwrap();

        assert_eq!(state.sequence, 8);
        assert_eq!(state.transaction.as_deref(), Some("checked-begin"));
        assert_eq!(state.retire, vec!["already-retired"]);
        assert_eq!(
            state.active.as_ref().unwrap().canonical_bytes().unwrap(),
            graph.canonical_bytes().unwrap()
        );
        assert!(state.apply(&valid).is_err());
        assert_eq!(state.sequence, 8);
        assert_eq!(state.transaction.as_deref(), Some("checked-begin"));
    }

    #[test]
    fn application_resolves_retained_and_fresh_dependencies_without_unrelated_outputs() {
        let (graph, first, second, consumer) = referenced_graph();
        let mut state = State {
            active: Some(graph),
            ..State::default()
        };
        for (id, value) in [(&first, "retained-first"), (&second, "retained-second")] {
            let invocation = state.application(id).unwrap();
            state.retained.insert(
                id.clone(),
                Retained {
                    invocation,
                    outputs: json!({"value":value}),
                },
            );
        }
        let old = state.application(&consumer).unwrap();
        state.retained.insert(
            consumer.clone(),
            Retained {
                invocation: old.clone(),
                outputs: json!({"first":"old","second":"old"}),
            },
        );
        let mut unrelated = old.clone();
        unrelated.id = "unrelated-persistent-orphan".into();
        state.retained.insert(
            unrelated.id.clone(),
            Retained {
                invocation: unrelated,
                outputs: json!({"large": "x".repeat(1_048_576)}),
            },
        );
        state
            .transaction_results
            .insert(first.clone(), json!({"value":"fresh-first"}));
        state.transaction_results.insert(
            "unrelated-completed".into(),
            json!({"large":"y".repeat(1_048_576)}),
        );

        let resolved = state.application(&consumer).unwrap();

        assert_eq!(
            old.input,
            json!({"first":"retained-first","second":"retained-second"})
        );
        assert_eq!(
            resolved.input,
            json!({"first":"fresh-first","second":"retained-second"})
        );
        assert_eq!(resolved.previous.as_ref().unwrap().revision, old.revision);
        assert_eq!(resolved.previous.as_ref().unwrap().input, old.input);
        state.retained.remove("unrelated-persistent-orphan");
        state.transaction_results.remove("unrelated-completed");
        let without_unrelated = state.application(&consumer).unwrap();
        assert_eq!(resolved.input, without_unrelated.input);
        assert_eq!(resolved.revision, without_unrelated.revision);

        state
            .transaction_results
            .insert(second, json!({"value":"retained-second"}));
        state
            .check(&Event::Started {
                invocation: Box::new(resolved.clone()),
            })
            .unwrap();
        let mut forged = resolved;
        forged.input["first"] = json!("retained-first");
        assert!(
            state
                .check(&Event::Started {
                    invocation: Box::new(forged)
                })
                .is_err()
        );
    }
}
