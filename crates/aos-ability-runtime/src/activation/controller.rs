//! Serial, journaled convergence and teardown of module-owned effects.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Handler, Lifetime, resolve};

use crate::adapter::CancellationToken;
use crate::journal::{FileJournal, JournalLimits};

use super::journal::{Event, State};
use super::{Action, ActivationAdapter, ActivationResults, Invocation, Observation};

/// Owns the exclusive activation journal and its recovered resource state.
pub struct Activation {
    journal: FileJournal<Event>,
    state: State,
}

impl Activation {
    /// Opens and replays the shared durable journal without executing handlers.
    ///
    /// # Errors
    /// Returns an error for lock contention, invalid records, corruption, or
    /// journal I/O failure. Only an incomplete final frame may be repaired.
    pub fn open(path: impl AsRef<Path>, limits: JournalLimits) -> Result<Self> {
        let opened = FileJournal::<Event>::open(path, limits)?;
        let mut state = State::default();
        for record in opened.recovery.records() {
            state.apply(record.body())?;
        }
        Ok(Self {
            journal: opened.journal,
            state,
        })
    }

    /// Converges a checked graph, recovering any unfinished prior transaction.
    ///
    /// `retire` explicitly authorizes deletion of named persistent effects that
    /// are absent from the desired graph. All required artifacts are admitted
    /// and retained before recording or executing a new transaction.
    ///
    /// # Errors
    /// Returns an error for inadmissible artifacts, invalid retirement,
    /// cancellation, uncertain observation, handler failure, or journal failure.
    pub fn activate(
        &mut self,
        desired: &CheckedModuleGraph,
        retire: &BTreeSet<String>,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<ActivationResults> {
        self.preflight(desired, adapter)?;
        if let Some(active) = self.state.active.clone() {
            self.preflight(&active, adapter)?;
            let same_transaction = active.canonical_bytes()? == desired.canonical_bytes()?
                && self.state.retire.iter().cloned().collect::<BTreeSet<_>>() == *retire;
            let results = self.run(&active, adapter, cancellation)?;
            if same_transaction {
                return Ok(results);
            }
        }

        for id in retire {
            ensure!(
                !desired.graph().nodes.contains_key(id),
                "cannot retire an effect that remains configured"
            );
            ensure!(
                self.state.retained.contains_key(id),
                "cannot retire an unknown effect"
            );
        }
        let document = serde_json::from_slice(&desired.canonical_bytes()?)?;
        self.record(Event::Begin {
            document,
            retire: retire.iter().cloned().collect(),
        })?;
        self.run(desired, adapter, cancellation)
    }

    /// Lists currently retained resources, including persistent orphaned state.
    #[must_use]
    pub fn retained(&self) -> ActivationResults {
        self.state
            .retained
            .iter()
            .map(|(id, state)| (id.clone(), state.outputs.clone()))
            .collect()
    }

    fn preflight(
        &self,
        graph: &CheckedModuleGraph,
        adapter: &mut impl ActivationAdapter,
    ) -> Result<()> {
        for effect in graph.graph().nodes.values().chain(
            self.state
                .retained
                .values()
                .map(|state| &state.invocation.effect),
        ) {
            adapter.retain(effect)?;
        }
        for effect in &self.state.releases {
            adapter.retain(effect)?;
        }
        if let Some(pending) = &self.state.pending {
            adapter.retain(&pending.effect)?;
        }
        Ok(())
    }

    fn record(&mut self, event: Event) -> Result<()> {
        self.state.check(&event)?;
        self.journal.append(&event)?;
        self.state.apply(&event)
    }

    fn run(
        &mut self,
        graph: &CheckedModuleGraph,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<ActivationResults> {
        self.drain_releases(adapter)?;
        if let Some(pending) = self.state.pending.clone() {
            self.recover(&pending, adapter, cancellation)?;
        }

        let removals: Vec<_> = self
            .state
            .established
            .iter()
            .rev()
            .filter(|id| {
                let retained = &self.state.retained[*id];
                match graph.graph().nodes.get(*id) {
                    Some(_) => false,
                    None => {
                        retained.invocation.effect.lifetime != Lifetime::Persistent
                            || self.state.retire.contains(id)
                    }
                }
            })
            .cloned()
            .collect();
        for id in removals {
            self.remove(&id, adapter, cancellation)?;
        }

        let mut results = self.retained();
        results.extend(self.state.transaction_results.clone());
        for id in &graph.graph().order {
            if self.state.transaction_results.contains_key(id) {
                continue;
            }
            ensure!(
                !cancellation.is_cancelled(),
                "activation cancelled before dispatch"
            );
            let effect = &graph.graph().nodes[id];
            let invocation = self.state.application(id)?;

            self.journal.ensure_capacity(3)?;
            self.record(Event::Started {
                invocation: Box::new(invocation.clone()),
            })?;
            let outputs = match &effect.handler {
                Handler::Composition { exports, .. } => {
                    resolve(&serde_json::to_value(exports)?, &results)?
                }
                Handler::Process { .. } => {
                    let previous = self.state.retained.get(id);
                    if previous
                        .is_some_and(|state| state.invocation.revision == invocation.revision)
                    {
                        match adapter.observe(&invocation, cancellation)? {
                            Observation::Current(outputs) => outputs,
                            Observation::RetrySafe | Observation::Absent => {
                                adapter.invoke(&invocation, cancellation)?
                            }
                            Observation::Indeterminate => {
                                anyhow::bail!("retained effect cannot be observed safely")
                            }
                        }
                    } else {
                        adapter.invoke(&invocation, cancellation)?
                    }
                }
            };
            self.record(Event::Finished {
                outputs: outputs.clone(),
            })?;
            self.drain_releases(adapter)?;
            results.insert(id.clone(), outputs);
        }

        // Transaction-scoped resources are released only after every consumer
        // has completed, in the reverse of the actual establishment order.
        let temporary: Vec<_> = self
            .state
            .established
            .iter()
            .rev()
            .filter(|id| {
                self.state.retained[*id].invocation.effect.lifetime == Lifetime::Transaction
            })
            .cloned()
            .collect();
        for id in temporary {
            self.remove(&id, adapter, cancellation)?;
        }
        self.record(Event::Commit)?;
        Ok(results)
    }

    fn remove(
        &mut self,
        id: &str,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        ensure!(
            !cancellation.is_cancelled(),
            "activation cancelled before teardown"
        );
        let mut invocation = self
            .state
            .retained
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("missing retained effect"))?
            .invocation
            .clone();
        invocation.action = Action::Remove;
        invocation.previous = None;
        self.journal.ensure_capacity(3)?;
        self.record(Event::Started {
            invocation: Box::new(invocation.clone()),
        })?;
        let outputs = match invocation.effect.handler {
            Handler::Composition { .. } => serde_json::json!({}),
            Handler::Process { .. } => adapter.invoke(&invocation, cancellation)?,
        };
        self.record(Event::Finished { outputs })?;
        self.drain_releases(adapter)
    }

    fn recover(
        &mut self,
        invocation: &Invocation,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        ensure!(
            !cancellation.is_cancelled(),
            "activation recovery cancelled"
        );
        let outputs = match &invocation.effect.handler {
            Handler::Composition { exports, .. } if invocation.action == Action::Apply => {
                resolve(&serde_json::to_value(exports)?, &self.retained())?
            }
            Handler::Composition { .. } => serde_json::json!({}),
            Handler::Process { .. } => match adapter.observe(invocation, cancellation)? {
                Observation::Current(outputs) if invocation.action == Action::Apply => outputs,
                Observation::Absent if invocation.action == Action::Remove => serde_json::json!({}),
                Observation::RetrySafe => adapter.invoke(invocation, cancellation)?,
                _ => anyhow::bail!(
                    "interrupted effect requires an authoritative recovery observation"
                ),
            },
        };
        self.record(Event::Finished { outputs })?;
        self.drain_releases(adapter)
    }

    fn drain_releases(&mut self, adapter: &mut impl ActivationAdapter) -> Result<()> {
        while let Some(effect) = self.state.releases.front().cloned() {
            self.journal.ensure_capacity(1)?;
            adapter.release(&effect)?;
            self.record(Event::Released)?;
        }
        Ok(())
    }
}
