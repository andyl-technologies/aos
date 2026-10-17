//! Serial, journaled convergence and teardown of module-owned effects.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Handler, Lifetime, resolve};

use crate::adapter::CancellationToken;
use crate::journal::{FileJournal, JournalLimits};

use super::journal::{Event, State};
use super::{
    Action, ActivationAdapter, ActivationOutcome, ActivationResults, Boundary, BoundaryEvent,
    ExecutionPolicy, Invocation, Observation,
};

#[path = "restoration.rs"]
mod restoration;

/// Owns the exclusive activation journal and its recovered resource state.
pub struct Activation {
    journal: FileJournal<Event>,
    state: State,
    pending_sequence: Option<u64>,
    restoration_sequences: Vec<u64>,
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
        let mut restoration_sequences = Vec::new();
        for record in opened.recovery.records() {
            state.apply(record.body())?;
            match record.body() {
                Event::Started { .. } => pending_sequence = Some(record.sequence()),
                Event::Finished { .. } => pending_sequence = None,
                Event::RestorationStarted { .. } => restoration_sequences.push(record.sequence()),
                Event::RestorationFinished { .. } => {
                    restoration_sequences.pop();
                }
                _ => {}
            }
        }
        Ok(Self {
            journal: opened.journal,
            state,
            pending_sequence,
            restoration_sequences,
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
        self.activate_keyed(
            None,
            desired,
            retire,
            ExecutionPolicy::Complete,
            adapter,
            cancellation,
        )
        .map(|outcome| outcome.outputs)
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
        self.activate_once_with_policy(
            transaction,
            desired,
            retire,
            ExecutionPolicy::Complete,
            adapter,
            cancellation,
        )
        .map(|outcome| outcome.outputs)
    }

    /// Executes a caller-identified transaction under the available lifecycle policy.
    ///
    /// Installation completion closes the transaction durably while recording
    /// only actual outcomes and the exact dependency closure awaiting startup.
    /// Subsequent installation transactions may replace unstarted desired work.
    ///
    /// # Errors
    /// Returns an error for identity reuse, admission, recovery, handler, or
    /// journal failures. Recovery requires the original execution policy.
    pub fn activate_once_with_policy(
        &mut self,
        transaction: &str,
        desired: &CheckedModuleGraph,
        retire: &BTreeSet<String>,
        policy: ExecutionPolicy,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<ActivationOutcome> {
        self.activate_keyed(
            Some(transaction),
            desired,
            retire,
            policy,
            adapter,
            cancellation,
        )
    }

    fn activate_keyed(
        &mut self,
        transaction: Option<&str>,
        desired: &CheckedModuleGraph,
        retire: &BTreeSet<String>,
        policy: ExecutionPolicy,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<ActivationOutcome> {
        let retirement: Vec<_> = retire.iter().cloned().collect();
        let fingerprint = super::journal::policy_fingerprint(desired, &retirement, policy)?;
        if let Some((id, content, outputs)) = &self.state.completed
            && transaction == Some(id.as_str())
        {
            ensure!(
                content == &fingerprint,
                "transaction identity reused with different content"
            );
            self.preflight(desired, adapter)?;
            return Ok(ActivationOutcome {
                outputs: outputs.clone(),
                deferred: self.state.completed_deferred.clone(),
            });
        }
        self.preflight(desired, adapter)?;
        if let Some(active) = self.state.active.clone() {
            self.preflight(&active, adapter)?;
            let same_transaction = self.state.policy == policy
                && active.canonical_bytes()? == desired.canonical_bytes()?
                && self.state.retire.iter().cloned().collect::<BTreeSet<_>>() == *retire;
            let same_identity =
                transaction.is_none() || transaction == self.state.transaction.as_deref();
            ensure!(
                !same_identity || same_transaction || transaction.is_none(),
                "active transaction identity reused with different content"
            );
            ensure!(
                self.state.policy == policy,
                "unfinished activation requires its original execution policy"
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
        let begin = Event::Begin {
            transaction: transaction
                .map(str::to_owned)
                .unwrap_or_else(|| format!("local-{}", self.state.sequence + 1)),
            document,
            retire: retire.iter().cloned().collect(),
        };
        self.record(match (policy, begin) {
            (
                ExecutionPolicy::Installation,
                Event::Begin {
                    transaction,
                    document,
                    retire,
                },
            ) => Event::BeginInstallation {
                transaction,
                document,
                retire,
            },
            (_, begin) => begin,
        })?;
        self.run(desired, adapter, cancellation)
    }

    /// Borrows the identity of the last durably completed transaction.
    ///
    /// This reports journal completion, not current external resource state.
    /// A caller recovering publication can distinguish cached completion from
    /// an activation that still needs live observation and repair.
    #[must_use]
    pub fn completed_transaction(&self) -> Option<&str> {
        self.state
            .completed
            .as_ref()
            .map(|(identity, _, _)| identity.as_str())
    }

    /// Returns identities with a durable removal outcome and no later application.
    ///
    /// This inventory makes declarative retirement repeatable across generations
    /// without treating an unknown identity as successfully removed.
    #[must_use]
    pub fn retired(&self) -> &BTreeSet<String> {
        &self.state.retired
    }

    /// Returns the latest durable receipt without observing external resources.
    #[must_use]
    pub fn completed_receipt(&self) -> Option<super::CompletedTransaction> {
        self.state
            .completed
            .as_ref()
            .map(
                |(transaction, content, outputs)| super::CompletedTransaction {
                    transaction: transaction.clone(),
                    content: content.clone(),
                    deferred: self.state.completed_deferred.clone(),
                    policy: self.state.completed_policy,
                    outputs: outputs.clone(),
                },
            )
    }

    /// Borrows the active transaction identity, checked graph, and execution policy.
    #[must_use]
    pub fn active_transaction(&self) -> Option<(&str, &CheckedModuleGraph, ExecutionPolicy)> {
        self.state
            .transaction
            .as_deref()
            .zip(self.state.active.as_ref())
            .map(|(transaction, graph)| (transaction, graph, self.state.policy))
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

    /// Restores handler retention from the checked journal without dispatching effects.
    ///
    /// Callers may lose their GC-root filesystem across boot while retaining the
    /// journal. Original artifacts must still pass admission before their exact
    /// ownership roots can be recreated.
    ///
    /// # Errors
    /// Returns an error when any active, retained, pending, or retiring handler
    /// cannot be authenticated or retained.
    pub fn restore_retention(&self, adapter: &mut impl ActivationAdapter) -> Result<()> {
        let effects = self
            .state
            .active
            .iter()
            .flat_map(|graph| graph.graph().nodes.values())
            .chain(self.retention_effects())
            .collect::<Vec<_>>();
        adapter.retain_batch(&effects)
    }

    fn retention_effects(&self) -> impl Iterator<Item = &aos_ability_plan::module_graph::Effect> {
        self.state
            .retained
            .values()
            .map(|state| &state.invocation.effect)
            .chain(&self.state.releases)
            .chain(self.state.pending.as_ref().map(|pending| &pending.effect))
            .chain(self.state.restoration.iter().map(|pending| &pending.effect))
    }

    fn preflight(
        &self,
        graph: &CheckedModuleGraph,
        adapter: &mut impl ActivationAdapter,
    ) -> Result<()> {
        let effects = graph
            .graph()
            .nodes
            .values()
            .chain(self.retention_effects())
            .collect::<Vec<_>>();
        adapter.retain_batch(&effects)
    }

    fn record(&mut self, event: Event) -> Result<u64> {
        self.state.check(&event)?;
        let sequence = self.journal.append(&event)?.sequence();
        self.state.apply(&event)?;
        match event {
            Event::Started { .. } => self.pending_sequence = Some(sequence),
            Event::Finished { .. } => self.pending_sequence = None,
            Event::RestorationStarted { .. } => self.restoration_sequences.push(sequence),
            Event::RestorationFinished { .. } => {
                self.restoration_sequences.pop();
            }
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
    ) -> Result<ActivationOutcome> {
        self.drain_releases(adapter)?;
        self.restore_completed_prefix(graph, adapter, cancellation)?;
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
                        self.state.removal_allowed(&retained.invocation.effect)
                            && (retained.invocation.effect.lifetime != Lifetime::Persistent
                                || self.state.retire.contains(id))
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
            if self.state.deferred.contains(id) || self.state.transaction_results.contains_key(id) {
                continue;
            }
            ensure!(
                !cancellation.is_cancelled(),
                "activation cancelled before dispatch"
            );
            let effect = &graph.graph().nodes[id];
            let invocation = self.state.application(id)?;
            if self.state.can_reuse_installation(id)? {
                self.record(Event::ReusedInstallation { id: id.clone() })?;
                results.insert(id.clone(), self.state.transaction_results[id].clone());
                continue;
            }

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
                    if previous.is_some_and(|state| {
                        effect.lifetime != Lifetime::Transaction
                            && state.invocation.revision == invocation.revision
                    }) {
                        match self.observe(&invocation, sequence, adapter, cancellation)? {
                            Observation::Current(outputs) => outputs,
                            Observation::RetrySafe | Observation::Absent => {
                                self.invoke(&invocation, sequence, adapter, cancellation)?
                            }
                            Observation::Indeterminate => {
                                anyhow::bail!(
                                    "retained effect {} ({}) cannot be observed safely",
                                    invocation.id,
                                    invocation.effect.identity.join("/")
                                )
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
                self.state.policy == ExecutionPolicy::Complete
                    && self
                        .state
                        .removal_allowed(&self.state.retained[*id].invocation.effect)
                    && self.state.retained[*id].invocation.effect.lifetime == Lifetime::Transaction
            })
            .cloned()
            .collect();
        for id in temporary {
            self.remove(&id, adapter, cancellation)?;
        }
        // Historical retained outcomes cannot stand in for deferred desired work.
        let outputs = self.state.transaction_results.clone();
        let deferred = self.state.deferred.clone();
        let event = if self.state.policy == ExecutionPolicy::Installation {
            Event::DeferredCommit {
                deferred: deferred.clone(),
            }
        } else {
            Event::Commit
        };
        self.record(event)?;
        Ok(ActivationOutcome { outputs, deferred })
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
