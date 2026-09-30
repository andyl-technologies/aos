//! Serial, journaled convergence and teardown of module-owned effects.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Handler, Lifetime, resolve};

use crate::adapter::CancellationToken;
use crate::journal::{FileJournal, JournalLimits};

use super::journal::{Event, State};
use super::{
    Action, ActivationAdapter, ActivationResults, Boundary, BoundaryEvent, Invocation, Observation,
};

/// Owns the exclusive activation journal and its recovered resource state.
pub struct Activation {
    journal: FileJournal<Event>,
    state: State,
    pending_sequence: Option<u64>,
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
        let mut pending_sequence = None;
        for record in opened.recovery.records() {
            state.apply(record.body())?;
            match record.body() {
                Event::Started { .. } => pending_sequence = Some(record.sequence()),
                Event::Finished { .. } => pending_sequence = None,
                _ => {}
            }
        }
        Ok(Self {
            journal: opened.journal,
            state,
            pending_sequence,
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
        self.activate_keyed(None, desired, retire, adapter, cancellation)
    }

    /// Resumes a caller-identified transaction across process restarts.
    ///
    /// A completed transaction returns its durable receipt without repeating
    /// transaction-scoped effects when its caller is recovering a generation commit.
    /// The receipt covers the most recent transaction; callers must use fresh
    /// identities for subsequent transactions and recover them in order.
    ///
    /// # Errors
    /// Returns an error when an identity is reused with different content or
    /// when activation, observation, retention, or journal operations fail.
    pub fn activate_once(
        &mut self,
        transaction: &str,
        desired: &CheckedModuleGraph,
        retire: &BTreeSet<String>,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<ActivationResults> {
        self.activate_keyed(Some(transaction), desired, retire, adapter, cancellation)
    }

    fn activate_keyed(
        &mut self,
        transaction: Option<&str>,
        desired: &CheckedModuleGraph,
        retire: &BTreeSet<String>,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<ActivationResults> {
        let retirement: Vec<_> = retire.iter().cloned().collect();
        let fingerprint = super::journal::fingerprint(desired, &retirement)?;
        if let Some((id, content, outputs)) = &self.state.completed {
            if transaction == Some(id.as_str()) {
                ensure!(
                    content == &fingerprint,
                    "transaction identity reused with different content"
                );
                return Ok(outputs.clone());
            }
        }
        self.preflight(desired, adapter)?;
        if let Some(active) = self.state.active.clone() {
            self.preflight(&active, adapter)?;
            let same_transaction = active.canonical_bytes()? == desired.canonical_bytes()?
                && self.state.retire.iter().cloned().collect::<BTreeSet<_>>() == *retire;
            let same_identity =
                transaction.is_none() || transaction == self.state.transaction.as_deref();
            ensure!(
                !same_identity || same_transaction || transaction.is_none(),
                "active transaction identity reused with different content"
            );
            let results = self.run(&active, adapter, cancellation)?;
            if same_transaction && same_identity {
                return Ok(results);
            }
        }

        for id in retire {
            ensure!(
                !desired.graph().nodes.contains_key(id),
                "cannot retire an effect that remains configured"
            );
            ensure!(
                self.state.retained.contains_key(id) || self.state.retired.contains(id),
                "cannot retire an unknown effect"
            );
        }
        let document = serde_json::from_slice(&desired.canonical_bytes()?)?;
        self.record(Event::Begin {
            transaction: transaction
                .map(str::to_owned)
                .unwrap_or_else(|| format!("local-{}", self.state.sequence + 1)),
            document,
            retire: retire.iter().cloned().collect(),
        })?;
        self.run(desired, adapter, cancellation)
    }

    /// Returns identities with a durable removal outcome and no later application.
    ///
    /// This inventory makes declarative retirement repeatable across generations
    /// without treating an unknown identity as successfully removed.
    #[must_use]
    pub fn retired(&self) -> &BTreeSet<String> {
        &self.state.retired
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

    fn record(&mut self, event: Event) -> Result<u64> {
        self.state.check(&event)?;
        let sequence = self.journal.append(&event)?.sequence();
        self.state.apply(&event)?;
        match event {
            Event::Started { .. } => self.pending_sequence = Some(sequence),
            Event::Finished { .. } => self.pending_sequence = None,
            _ => {}
        }
        Ok(sequence)
    }

    fn boundary(
        &self,
        invocation: &Invocation,
        sequence: u64,
        boundary: Boundary,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let event = BoundaryEvent {
            schema: "aos.activation.boundary".into(),
            transaction: self
                .state
                .transaction
                .clone()
                .ok_or_else(|| anyhow::anyhow!("boundary outside activation transaction"))?,
            effect: invocation.id.clone(),
            revision: invocation.revision.clone(),
            action: invocation.action,
            journal_sequence: sequence,
            boundary,
        };
        adapter.boundary(&event, cancellation)?;
        ensure!(
            !cancellation.is_cancelled(),
            "activation cancelled at execution boundary"
        );
        Ok(())
    }

    fn observe(
        &self,
        invocation: &Invocation,
        sequence: u64,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<Observation> {
        self.boundary(
            invocation,
            sequence,
            Boundary::ObservationStarted,
            adapter,
            cancellation,
        )?;
        let observation = adapter.observe(invocation, cancellation)?;
        self.boundary(
            invocation,
            sequence,
            Boundary::ObservationReturned,
            adapter,
            cancellation,
        )?;
        Ok(observation)
    }

    fn invoke(
        &self,
        invocation: &Invocation,
        sequence: u64,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<serde_json::Value> {
        self.boundary(
            invocation,
            sequence,
            Boundary::DispatchStarted,
            adapter,
            cancellation,
        )?;
        let outputs = adapter.invoke(invocation, cancellation)?;
        self.boundary(
            invocation,
            sequence,
            Boundary::DispatchReturned,
            adapter,
            cancellation,
        )?;
        Ok(outputs)
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
            let sequence = self.record(Event::Started {
                invocation: Box::new(invocation.clone()),
            })?;
            self.boundary(
                &invocation,
                sequence,
                Boundary::IntentDurable,
                adapter,
                cancellation,
            )?;
            let outputs = match &effect.handler {
                Handler::Composition { exports, .. } => {
                    resolve(&serde_json::to_value(exports)?, &results)?
                }
                Handler::Process { .. } => {
                    let previous = self.state.retained.get(id);
                    if previous
                        .is_some_and(|state| state.invocation.revision == invocation.revision)
                    {
                        match self.observe(&invocation, sequence, adapter, cancellation)? {
                            Observation::Current(outputs) => outputs,
                            Observation::RetrySafe | Observation::Absent => {
                                self.invoke(&invocation, sequence, adapter, cancellation)?
                            }
                            Observation::Indeterminate => {
                                anyhow::bail!("retained effect cannot be observed safely")
                            }
                        }
                    } else {
                        self.invoke(&invocation, sequence, adapter, cancellation)?
                    }
                }
            };
            self.record(Event::Finished {
                outputs: outputs.clone(),
            })?;
            self.boundary(
                &invocation,
                sequence,
                Boundary::OutcomeDurable,
                adapter,
                cancellation,
            )?;
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
        results.retain(|id, _| graph.graph().nodes.contains_key(id));
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
        let sequence = self.record(Event::Started {
            invocation: Box::new(invocation.clone()),
        })?;
        self.boundary(
            &invocation,
            sequence,
            Boundary::IntentDurable,
            adapter,
            cancellation,
        )?;
        let outputs = match invocation.effect.handler {
            Handler::Composition { .. } => serde_json::json!({}),
            Handler::Process { .. } => self.invoke(&invocation, sequence, adapter, cancellation)?,
        };
        self.record(Event::Finished { outputs })?;
        self.boundary(
            &invocation,
            sequence,
            Boundary::OutcomeDurable,
            adapter,
            cancellation,
        )?;
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
        let sequence = self
            .pending_sequence
            .ok_or_else(|| anyhow::anyhow!("pending invocation has no durable intent"))?;
        self.boundary(
            invocation,
            sequence,
            Boundary::IntentDurable,
            adapter,
            cancellation,
        )?;
        let outputs = match &invocation.effect.handler {
            Handler::Composition { exports, .. } if invocation.action == Action::Apply => {
                resolve(&serde_json::to_value(exports)?, &self.retained())?
            }
            Handler::Composition { .. } => serde_json::json!({}),
            Handler::Process { .. } => {
                match self.observe(invocation, sequence, adapter, cancellation)? {
                    Observation::Current(outputs) if invocation.action == Action::Apply => outputs,
                    Observation::Absent if invocation.action == Action::Remove => {
                        serde_json::json!({})
                    }
                    Observation::RetrySafe => {
                        self.invoke(invocation, sequence, adapter, cancellation)?
                    }
                    _ => anyhow::bail!(
                        "interrupted effect requires an authoritative recovery observation"
                    ),
                }
            }
        };
        self.record(Event::Finished { outputs })?;
        self.boundary(
            invocation,
            sequence,
            Boundary::OutcomeDurable,
            adapter,
            cancellation,
        )?;
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
