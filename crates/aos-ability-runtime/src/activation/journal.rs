//! Durable records and replay state for module activation transactions.
//!
//! Records carry a tagged JSON body inside the shared journal frame:
//! `begin` retains the graph, `started` retains an exact invocation, `finished`
//! retains checked results, and `commit` closes the active transaction.

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
            Self::Started { invocation } => vec![&invocation.input],
            Self::Finished { outputs } => vec![outputs],
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
    pub retained: BTreeMap<String, Retained>,
    pub established: Vec<String>,
    pub retired: BTreeSet<String>,
    pub transaction_results: BTreeMap<String, Value>,
    pub releases: VecDeque<Effect>,
}

impl State {
    pub fn check(&self, event: &Event) -> Result<()> {
        match event {
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
                let desired = CheckedModuleGraph::decode(&canonical::to_vec(document)?)?;
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
        Ok(())
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
        let mut results: BTreeMap<_, _> = self
            .retained
            .iter()
            .map(|(id, state)| (id.clone(), state.outputs.clone()))
            .collect();
        results.extend(self.transaction_results.clone());
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
        self.check(event)?;
        match event {
            Event::Begin {
                transaction,
                document,
                retire,
            } => {
                self.transaction = Some(transaction.clone());
                self.sequence += 1;
                self.active = Some(CheckedModuleGraph::decode(&canonical::to_vec(document)?)?);
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
