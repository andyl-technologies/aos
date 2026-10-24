//! Durable records and replay state for module activation transactions.
//!
//! Records carry a tagged JSON body inside the shared journal frame:
//! `begin` retains the graph, `started` retains an exact invocation, `finished`
//! retains checked results, and `commit` closes the active transaction.
//! `begin-installation` binds restricted execution; `deferred-commit` closes it
//! with the exact unexecuted dependency closure. `reused-installation` carries
//! an existing one-shot outcome into startup without dispatching it again.
//! `restoration-started` and `restoration-finished` reestablish completed
//! resources without replacing the primary intent or its consumed results.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, ensure};
use aos_core::json;
use aos_module_format::graph::{CheckedModuleGraph, Effect, Handler, Lifetime};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::journal::{JournalError, JournalLimits, JournalPayload};

use super::{Action, ExecutionPolicy, Invocation, PreviousState};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Event {
    Begin {
        transaction: String,
        document: Value,
        retire: Vec<String>,
    },
    BeginInstallation {
        transaction: String,
        document: Value,
        retire: Vec<String>,
    },
    DeferredCommit {
        deferred: BTreeSet<String>,
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
    ReusedInstallation {
        id: String,
    },
    Released,
    Commit,
}

impl JournalPayload for Event {
    fn validate_for_journal(&self, limits: JournalLimits) -> Result<(), JournalError> {
        let bounds = aos_core::limits::JsonLimits {
            max_bytes: limits.max_body_bytes,
            max_depth: limits.max_depth,
            max_items: limits.max_items,
            max_string_bytes: limits.max_string_bytes,
        };
        let values: Vec<&Value> = match self {
            Self::Begin { document, .. } | Self::BeginInstallation { document, .. } => {
                vec![document]
            }
            Self::Started { invocation } | Self::RestorationStarted { invocation } => {
                vec![&invocation.input]
            }
            Self::Finished { outputs } | Self::RestorationFinished { outputs } => vec![outputs],
            Self::Released
            | Self::Commit
            | Self::DeferredCommit { .. }
            | Self::ReusedInstallation { .. } => vec![],
        };
        for value in values {
            bounds
                .check_value(value, "activation journal value")
                .map_err(|error| JournalError::Limit(error.to_string()))?;
        }
        let mut writer = aos_core::limits::BoundedWriter::new(
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
    pub policy: ExecutionPolicy,
    pub completed_policy: ExecutionPolicy,
    pub completed_deferred: BTreeSet<String>,
    pub deferred: BTreeSet<String>,
    startup_desired: BTreeSet<String>,
    startup_established: BTreeSet<String>,
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
                    effect == &invocation.effect && &retained.invocation == invocation.as_ref(),
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
                        .all(|id| self.deferred.contains(id)
                            || self.transaction_results.contains_key(id)),
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
                    json::to_vec(outputs)?
                        == json::to_vec(&self.transaction_results[&invocation.id])?,
                    "restoration changed already consumed outputs"
                );
            }
            Event::Begin {
                transaction,
                document,
                retire,
            }
            | Event::BeginInstallation {
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
                let desired = CheckedModuleGraph::decode(&json::canonical_json(document)?)?;
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
                        let next = graph.graph().order.iter().find(|id| {
                            !self.deferred.contains(*id)
                                && !self.transaction_results.contains_key(*id)
                        });
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
                                && self.removal_allowed(&retained.invocation.effect)
                                && (retained.invocation.effect.lifetime != Lifetime::Persistent
                                    || self.retire.contains(&invocation.id)))
                                || (temporary
                                    && self.removal_allowed(&retained.invocation.effect)
                                    && self.transaction_results.len() == graph.graph().nodes.len()),
                            "teardown is not authorized by the active transaction"
                        );
                        let mut expected = retained.invocation.clone();
                        expected.action = Action::Remove;
                        expected.previous = None;
                        expected
                    }
                };
                // Equality includes every invocation field. Canonical encoding
                // remains a separate frame invariant, without replay allocations.
                ensure!(
                    &expected == invocation.as_ref(),
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
            Event::ReusedInstallation { id } => {
                ensure!(
                    self.policy == ExecutionPolicy::Complete
                        && self.completed_policy == ExecutionPolicy::Installation,
                    "installation reuse requires startup completion"
                );
                ensure!(
                    self.pending.is_none() && self.releases.is_empty(),
                    "reuse during unfinished dispatch or cleanup"
                );
                let graph = self
                    .active
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("reuse outside activation"))?;
                ensure!(
                    graph
                        .graph()
                        .order
                        .iter()
                        .find(|id| !self.transaction_results.contains_key(*id))
                        == Some(id),
                    "reuse violates graph order"
                );
                ensure!(
                    self.can_reuse_installation(id)?,
                    "reuse does not match an established installation outcome"
                );
            }
            Event::Released => ensure!(
                !self.releases.is_empty(),
                "artifact release without retained cleanup"
            ),
            Event::DeferredCommit { deferred } => {
                let graph = self
                    .active
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("completion outside activation"))?;
                ensure!(
                    self.policy == ExecutionPolicy::Installation,
                    "deferred completion outside installation"
                );
                ensure!(
                    self.pending.is_none() && self.releases.is_empty(),
                    "completion before dispatch or cleanup finishes"
                );
                ensure!(
                    deferred == &self.deferred,
                    "deferred completion differs from checked phase closure"
                );
                ensure!(
                    self.transaction_results.len() + deferred.len() == graph.graph().nodes.len(),
                    "installation completed before eligible effects"
                );
                ensure!(
                    self.transaction_results
                        .keys()
                        .all(|id| graph.graph().nodes.contains_key(id) && !deferred.contains(id)),
                    "installation outcome overlaps deferred effects"
                );
                ensure!(
                    self.retained.iter().all(|(id, retained)| {
                        !self.removal_allowed(&retained.invocation.effect)
                            || graph.graph().nodes.contains_key(id)
                            || (retained.invocation.effect.lifetime == Lifetime::Persistent
                                && !self.retire.contains(id))
                    }),
                    "installation completion before required teardown"
                );
            }
            Event::Commit => {
                ensure!(
                    self.policy == ExecutionPolicy::Complete,
                    "complete commit outside complete execution policy"
                );
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

    pub fn removal_allowed(&self, effect: &Effect) -> bool {
        if self.policy == ExecutionPolicy::Complete {
            return true;
        }
        // Preserve the original graph's lifecycle requirement even when a
        // transaction-scoped prerequisite has already been released.
        effect.phase != aos_module_format::graph::ExecutionPhase::Startup
            && !aos_module_format::graph::identity_key(&effect.identity)
                .is_ok_and(|id| self.startup_established.contains(&id))
    }

    pub fn can_reuse_installation(&self, id: &str) -> Result<bool> {
        if self.policy != ExecutionPolicy::Complete
            || self.completed_policy != ExecutionPolicy::Installation
        {
            return Ok(false);
        }
        let Some(previous) = self.retained.get(id) else {
            return Ok(false);
        };
        if previous.invocation.effect.lifetime != Lifetime::Transaction
            || previous.invocation.effect.phase
                != aos_module_format::graph::ExecutionPhase::Installation
            || self.completed_deferred.contains(id)
        {
            return Ok(false);
        }
        let invocation = self.application(id)?;
        Ok(previous.invocation.revision == invocation.revision
            && previous.invocation.effect == invocation.effect
            && self
                .completed
                .as_ref()
                .is_some_and(|(_, _, outputs)| outputs.get(id) == Some(&previous.outputs)))
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
        let revision =
            aos_core::Sha256Digest::of_bytes(json::to_vec(&(effect.revision.as_str(), &input))?)
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
            }
            | Event::BeginInstallation {
                transaction,
                retire,
                ..
            } => {
                let desired = checked_graph
                    .ok_or_else(|| anyhow::anyhow!("begin without a checked graph"))?;

                self.policy = if matches!(event, Event::BeginInstallation { .. }) {
                    ExecutionPolicy::Installation
                } else {
                    ExecutionPolicy::Complete
                };
                self.deferred = self.policy.deferred_effects(&desired);
                self.startup_desired = ExecutionPolicy::Installation.deferred_effects(&desired);
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
                        if self.startup_desired.contains(&invocation.id) {
                            self.startup_established.insert(invocation.id.clone());
                        } else {
                            self.startup_established.remove(&invocation.id);
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
                        self.startup_established.remove(&invocation.id);
                        self.retained.remove(&invocation.id);
                        self.retired.insert(invocation.id.clone());
                        self.established.retain(|id| id != &invocation.id);
                    }
                }
                self.pending = None;
            }
            Event::ReusedInstallation { id } => {
                let previous = self
                    .retained
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("reused installation outcome is absent"))?;
                self.transaction_results
                    .insert(id.clone(), previous.outputs.clone());
            }
            Event::Released => {
                self.releases.pop_front();
            }
            Event::Commit | Event::DeferredCommit { .. } => {
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
                    policy_fingerprint(active, &self.retire, self.policy)?,
                    self.transaction_results.clone(),
                ));
                self.completed_policy = self.policy;
                self.completed_deferred = self.deferred.clone();
                self.deferred.clear();
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
    Ok(aos_core::Sha256Digest::of_bytes(json::to_vec(&(graph.canonical_bytes()?, retire))?).hex())
}

#[cfg(test)]
mod tests {
    use aos_module_format::graph::{InputOption, identity_key};
    use serde_json::json;

    use super::*;

    #[test]
    fn replay_compares_full_contracts_and_previous_state() {
        let graph = super::super::tests::graph(Some("expected"), "instance");
        let document = graph.document().clone();
        let id = &graph.graph().order[0];
        let mut state = State::default();
        state
            .apply(&Event::Begin {
                transaction: "original".into(),
                document: document.clone(),
                retire: vec![],
            })
            .unwrap();
        let original = state.application(id).unwrap();
        state
            .apply(&Event::Started {
                invocation: Box::new(original.clone()),
            })
            .unwrap();
        state
            .apply(&Event::Finished {
                outputs: original.input.clone(),
            })
            .unwrap();

        // Documentation does not affect a desired revision, but it still
        // belongs to the exact contract retained for replay and restoration.
        let mut changed_contract = original.clone();
        changed_contract.effect.inputs.insert(
            "value".into(),
            InputOption {
                description: "substituted contract".into(),
                value_type: original.effect.results["value"].clone(),
            },
        );
        assert!(
            state
                .check(&Event::RestorationStarted {
                    invocation: Box::new(changed_contract),
                })
                .is_err()
        );
        state
            .check(&Event::RestorationStarted {
                invocation: Box::new(original),
            })
            .unwrap();

        state.apply(&Event::Commit).unwrap();
        state
            .apply(&Event::Begin {
                transaction: "next".into(),
                document,
                retire: vec![],
            })
            .unwrap();
        let expected = state.application(id).unwrap();
        let decoded: Invocation =
            json::from_slice(&json::to_vec(&expected).unwrap(), "invocation").unwrap();
        state
            .check(&Event::Started {
                invocation: Box::new(decoded),
            })
            .unwrap();

        let mut changed_previous_contract = expected.clone();
        changed_previous_contract
            .previous
            .as_mut()
            .unwrap()
            .effect
            .owner = "another-owner".into();
        let mut changed_previous_input = expected.clone();
        changed_previous_input.previous.as_mut().unwrap().input = json!({"value":"forged"});
        let mut changed_previous_output = expected;
        changed_previous_output.previous.as_mut().unwrap().outputs = json!({"value":"forged"});

        for invocation in [
            changed_previous_contract,
            changed_previous_input,
            changed_previous_output,
        ] {
            assert!(
                state
                    .check(&Event::Started {
                        invocation: Box::new(invocation),
                    })
                    .is_err()
            );
        }
    }

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
                aos_core::Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap()).hex()
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

pub(super) fn policy_fingerprint(
    graph: &CheckedModuleGraph,
    retire: &[String],
    policy: ExecutionPolicy,
) -> Result<String> {
    let content = fingerprint(graph, retire)?;
    if policy == ExecutionPolicy::Complete {
        return Ok(content);
    }
    Ok(aos_core::Sha256Digest::of_bytes(json::to_vec(&(content, policy))?).hex())
}
