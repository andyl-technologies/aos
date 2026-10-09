//! Durable package generations coordinated with the effect journal.
//!
//! A prepared generation retains its exact module transaction before dispatch.
//! The activation journal records a caller-supplied transaction identity, so a
//! restart between effect completion and generation commit does not repeat
//! one-shot operations. The committed journal record is the authoritative
//! generation pointer; profile frontends may publish their links from it.
//! Live reconciliation has its own recoverable execution identity and preserves
//! that generation's publication while refreshing its checked effect results.
//!
//! ```text
//! prepared { sequence, document, packages }
//! committed { sequence, outputs }
//! reconciliation-prepared { sequence, attempt, content }
//! reconciled { sequence, attempt, outputs }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::activation::{Activation, ActivationResults, ExecutionPolicy};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::{
    FileJournal, JournalError, JournalLimits, JournalPayload, JournalReader,
};
use aos_contract::{
    canonical,
    limits::{BoundedWriter, JsonLimits},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::handler::{HandlerArtifacts, ProcessAdapter};
use super::model::{Deployment, ResolvedPackages};

/// Bounds native generation and effect journals using the deployment document contract.
///
/// A prepared generation contains both the transaction and its resolved package
/// context. The latter duplicates a subset of the transaction, so records admit
/// two document budgets plus the event envelope. Additional nesting covers
/// invocation migration state. Readers must use the same policy as writers.
///
/// The file budget leaves room for multi-record dispatch reservations and bounded
/// history. Reaching it still stops activation; it does not enable compaction or
/// remove the journal's record-count, integrity, or durable-write checks.
#[must_use]
pub fn journal_limits() -> JournalLimits {
    let max_body_bytes = 2 * GRAPH_LIMITS.max_bytes + 1024;
    JournalLimits {
        max_body_bytes,
        max_depth: GRAPH_LIMITS.max_depth + 4,
        max_items: 2 * GRAPH_LIMITS.max_items + 16,
        max_string_bytes: GRAPH_LIMITS.max_string_bytes,
        max_file_bytes: 8 * max_body_bytes as u64,
        ..JournalLimits::default()
    }
}

/// Retains deployment inputs and handler closures in the owning package store.
pub trait DeploymentStore: HandlerArtifacts {
    /// Retains a generation's payloads, module sources, dependency outputs, and runtime library.
    ///
    /// The implementation must preserve all retained generations across restart
    /// and admit only artifacts authenticated by package resolution.
    ///
    /// # Errors
    /// Returns an error if any artifact is unavailable or cannot be retained.
    fn retain_generation(&mut self, generation: &str, deployment: &Deployment) -> Result<()>;

    /// Releases a forgotten generation while preserving independent effect roots.
    ///
    /// This operation must be idempotent: journal recovery can repeat it.
    ///
    /// # Errors
    /// Returns an error if any generation root cannot be released durably.
    fn release_generation(&mut self, generation: &str, deployment: &Deployment) -> Result<()>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
enum Event {
    Prepared {
        sequence: u64,
        document: Value,
        packages: ResolvedPackages,
        policy: ExecutionPolicy,
    },
    Committed {
        sequence: u64,
        outputs: ActivationResults,
        deferred: BTreeSet<String>,
    },
    ReconciliationPrepared {
        sequence: u64,
        attempt: u64,
        content: String,
        policy: ExecutionPolicy,
    },
    Reconciled {
        sequence: u64,
        attempt: u64,
        outputs: ActivationResults,
        deferred: BTreeSet<String>,
    },
    Pruning {
        sequence: u64,
    },
    Pruned {
        sequence: u64,
    },
}

impl JournalPayload for Event {
    fn validate_for_journal(&self, limits: JournalLimits) -> Result<(), JournalError> {
        let mut counter =
            BoundedWriter::new(limits.max_body_bytes as u64, "package transaction journal");
        serde_json::to_writer(&mut counter, self)
            .map_err(|error| JournalError::Limit(error.to_string()))?;
        let bytes =
            serde_json::to_vec(self).map_err(|error| JournalError::Limit(error.to_string()))?;
        let bounds = JsonLimits {
            max_bytes: limits.max_body_bytes,
            max_depth: limits.max_depth,
            max_items: limits.max_items,
            max_string_bytes: limits.max_string_bytes,
        };
        bounds
            .decode::<Value>(&bytes, "package transaction journal")
            .map_err(|error| JournalError::Limit(error.to_string()))?;
        Ok(())
    }
}

/// Identifies a completed package generation and its checked operation results.
#[derive(Clone, Debug)]
pub struct Generation {
    /// Monotonically orders generation attempts within this deployment scope.
    pub sequence: u64,
    /// Identifies the desired transaction document by content.
    pub content: String,
    /// Contains named runtime outputs for its configured effects.
    pub outputs: ActivationResults,
    /// Names startup effects that have not produced an installation result.
    pub deferred: BTreeSet<String>,
    /// Retains the exact document for inspection or a subsequent rollback transaction.
    pub deployment: Deployment,
    /// Distinguishes an installation receipt from complete runtime convergence.
    pub policy: ExecutionPolicy,
}

struct Pending {
    sequence: u64,
    deployment: Deployment,
    policy: ExecutionPolicy,
}

struct Reconciliation {
    sequence: u64,
    attempt: u64,
    content: String,
    policy: ExecutionPolicy,
}

impl Reconciliation {
    fn identity(&self) -> String {
        format!(
            "reconcile-{}-{}-{}",
            self.sequence, self.attempt, self.content
        )
    }
}

/// Identifies a package deployment that recovery must complete live.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveRecovery {
    /// Orders the original package publication attempt.
    pub(crate) sequence: u64,
    /// Binds the exact desired deployment recovered by that attempt.
    pub(crate) content: String,
}

fn package_identity(sequence: u64, content: &str) -> String {
    format!("package-{sequence}-{content}")
}

/// Owns one installation scope's generation and effect journals.
pub struct Transactions<S> {
    journal: FileJournal<Event>,
    activation: Activation,
    adapter: ProcessAdapter<S>,
    state: GenerationState,
}

impl<S: DeploymentStore> Transactions<S> {
    /// Selects optional instrumentation for subsequent activation and recovery.
    ///
    /// The owning profile must authenticate the observer configuration. Clearing
    /// an observer is an explicit caller decision, never an error fallback.
    pub fn set_observer(
        &mut self,
        observer: Option<Box<dyn aos_ability_runtime::activation::BoundaryObserver>>,
    ) {
        self.adapter.set_observer(observer);
    }

    /// Opens an existing private scope directory and recovers both durable journals.
    ///
    /// # Errors
    /// Returns an error for lock contention, invalid journal history, or I/O failure.
    pub fn open(directory: &Path, store: S, limits: JournalLimits) -> Result<Self> {
        let opened = FileJournal::<Event>::open(directory.join("generations.journal"), limits)?;
        let activation = Activation::open(directory.join("effects.journal"), limits)?;
        let mut result = Self {
            journal: opened.journal,
            activation,
            adapter: ProcessAdapter::new(store),
            state: GenerationState::default(),
        };
        for record in opened.recovery.records() {
            result.state.replay(record.body())?;
        }
        let completed = result.activation.completed_receipt();
        let active = result
            .activation
            .active_transaction()
            .map(|(identity, graph, policy)| (identity, graph.document(), policy));
        verify_journal_pair(&result.state, active, completed.as_ref())?;
        Ok(result)
    }

    /// Returns the last durably committed generation, if any.
    #[must_use]
    pub fn current(&self) -> Option<&Generation> {
        self.state.current()
    }

    /// Returns the committed generation history retained by this scope.
    #[must_use]
    pub fn generations(&self) -> &BTreeMap<u64, Generation> {
        &self.state.generations
    }

    /// Reports the next generation sequence while this scope is exclusively locked.
    ///
    /// Consumers can durably associate a staged profile generation with this sequence
    /// before calling `apply`. The value is not a reservation: it remains valid only
    /// while the caller retains this transaction owner without applying another document.
    ///
    /// # Errors
    /// Returns an error when activation or pruning still needs recovery, or the
    /// sequence space is exhausted.
    pub fn next_sequence(&self) -> Result<u64> {
        self.state.next_sequence()
    }

    /// Returns the desired document awaiting generation or reconciliation recovery.
    #[must_use]
    pub fn pending(&self) -> Option<&Deployment> {
        self.state.pending_deployment()
    }

    /// Returns the generation sequence associated with pending recovery.
    ///
    /// Reconciliation uses its already committed generation. Publication uses
    /// the staged generation, even when desired content matches an older one.
    #[must_use]
    pub fn pending_sequence(&self) -> Option<u64> {
        self.state.pending_sequence()
    }

    /// Returns the recorded policy that interruption recovery must preserve.
    #[must_use]
    pub fn pending_policy(&self) -> Option<ExecutionPolicy> {
        self.state
            .pending
            .as_ref()
            .map(|pending| pending.policy)
            .or_else(|| {
                self.state
                    .reconciliation
                    .as_ref()
                    .map(|pending| pending.policy)
            })
    }

    /// Lists retained effect results, including persistent state absent from the current graph.
    #[must_use]
    pub fn retained_effects(&self) -> ActivationResults {
        self.activation.retained()
    }

    /// Recreates retention roots from exclusively locked, replayed journal state.
    ///
    /// A boot stage can preserve its journals on a filesystem without symlinks
    /// while keeping Nix GC roots on a private transient filesystem. Restoration
    /// admits the original artifacts and preserves their original ownership keys;
    /// it neither prepares a generation nor invokes a handler.
    ///
    /// # Errors
    /// Returns an error when any recorded generation input or handler cannot be
    /// authenticated or retained.
    pub(crate) fn restore_retention(&mut self) -> Result<()> {
        for generation in self.state.generations.values() {
            if self.state.pruning == Some(generation.sequence) {
                continue;
            }
            let identity = package_identity(generation.sequence, &generation.content);
            self.adapter
                .artifacts_mut()
                .retain_generation(&identity, &generation.deployment)?;
        }
        if let Some(pending) = &self.state.pending {
            let identity = package_identity(pending.sequence, &pending.deployment.id()?);
            self.adapter
                .artifacts_mut()
                .retain_generation(&identity, &pending.deployment)?;
        }
        self.activation.restore_retention(&mut self.adapter)
    }

    /// Recovers recorded work before reconciling unchanged or applying changed content.
    ///
    /// Completing the requested pending transaction is the whole recovery attempt;
    /// it must not immediately start a second transaction-scoped invocation. A
    /// fresh invocation against unchanged content repairs live state without
    /// publishing a package generation for every boot.
    ///
    /// # Errors
    /// Returns an error for failed recovery, reconciliation, or application.
    pub(crate) fn converge(
        &mut self,
        deployment: &Deployment,
        cancellation: &CancellationToken,
    ) -> Result<Generation> {
        let recovering = self.pending().is_some();
        self.resume(cancellation)?;
        if let Some(current) = self.current()
            && current.content == deployment.id()?
        {
            if recovering {
                return Ok(current.clone());
            }
            return self.reconcile_current(cancellation);
        }
        self.apply(deployment, cancellation)
    }

    /// Replaces artifact admission without releasing either journal lock.
    pub(crate) fn replace_store(&mut self, store: S) {
        *self.adapter.artifacts_mut() = store;
    }

    // Both journals remain exclusively locked. A completed effects transaction
    // only needs publication repair; it has not observed live state this boot.
    pub(crate) fn pending_live_package(&self) -> Result<Option<LiveRecovery>> {
        let Some(pending) = &self.state.pending else {
            return Ok(None);
        };
        let content = pending.deployment.id()?;
        let identity = package_identity(pending.sequence, &content);
        Ok(
            (self.activation.completed_transaction() != Some(identity.as_str())).then_some(
                LiveRecovery {
                    sequence: pending.sequence,
                    content,
                },
            ),
        )
    }

    pub(crate) fn pending_reconciliation(&self) -> bool {
        self.state.reconciliation.is_some()
    }

    /// Resumes prepared generation or live reconciliation work.
    ///
    /// # Errors
    /// Returns an error for failed artifact admission, uncertain effects, failed
    /// recovery, cancellation, or failure to commit the generation journal.
    pub fn resume(&mut self, cancellation: &CancellationToken) -> Result<Option<Generation>> {
        self.finish_pruning()?;
        if self.state.reconciliation.is_some() {
            return self.resume_reconciliation(cancellation).map(Some);
        }
        let Some(pending) = &self.state.pending else {
            return Ok(None);
        };
        let content = pending.deployment.id()?;
        let identity = package_identity(pending.sequence, &content);
        self.adapter
            .artifacts_mut()
            .retain_generation(&identity, &pending.deployment)?;
        self.activate_pending(cancellation).map(Some)
    }

    // Fresh preparation already admitted and durably retained every input.
    // Recovery enters through resume, which repeats that verification first.
    fn activate_pending(&mut self, cancellation: &CancellationToken) -> Result<Generation> {
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("prepared generation is absent"))?;
        let identity = package_identity(pending.sequence, &pending.deployment.id()?);
        self.journal.ensure_capacity(1)?;
        let outcome = self.activation.activate_once_with_policy(
            &identity,
            pending.deployment.graph(),
            pending.deployment.retire(),
            pending.policy,
            &mut self.adapter,
            cancellation,
        )?;
        let event = Event::Committed {
            sequence: pending.sequence,
            outputs: outcome.outputs,
            deferred: outcome.deferred,
        };
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        self.current()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("prepared generation did not commit"))
    }

    /// Observes and repairs the committed deployment without publishing a generation.
    ///
    /// Each attempt has a durable activation identity bound to the current
    /// generation and content. Recovery resumes that identity; a later call
    /// observes live state again rather than reusing an earlier completion.
    /// Existing generation roots and checked runtime results remain authoritative.
    ///
    /// # Errors
    /// Returns an error when no generation is committed, recovery or artifact
    /// admission fails, an effect is uncertain, cancellation occurs, or a
    /// reconciliation record cannot be committed durably.
    pub fn reconcile_current(&mut self, cancellation: &CancellationToken) -> Result<Generation> {
        self.reconcile_current_with_policy(ExecutionPolicy::Complete, cancellation)
    }

    /// Reconciles the current generation within the selected execution phase.
    ///
    /// Installation records real results and explicitly pending startup work.
    /// It never turns pending startup effects into a completed activation.
    ///
    /// # Errors
    /// Returns an error for journal recovery, admission, dispatch or publication failure.
    pub fn reconcile_current_with_policy(
        &mut self,
        policy: ExecutionPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Generation> {
        let recovering = self.state.reconciliation.is_some();
        self.resume(cancellation)?;
        if recovering {
            return self
                .current()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("reconciled generation is absent"));
        }

        let current = self
            .current()
            .ok_or_else(|| anyhow::anyhow!("no committed generation to reconcile"))?;
        let event = Event::ReconciliationPrepared {
            sequence: current.sequence,
            attempt: self.state.next_reconciliation_attempt()?,
            content: current.content.clone(),
            policy,
        };
        self.journal.ensure_capacity(2)?;
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        self.resume_reconciliation(cancellation)
    }

    fn resume_reconciliation(&mut self, cancellation: &CancellationToken) -> Result<Generation> {
        let reconciliation = self
            .state
            .reconciliation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("reconciliation intent is absent"))?;
        let current = self
            .state
            .current()
            .ok_or_else(|| anyhow::anyhow!("reconciliation has no committed generation"))?;
        let identity = reconciliation.identity();
        let retained_identity = package_identity(current.sequence, &current.content);
        self.adapter
            .artifacts_mut()
            .retain_generation(&retained_identity, &current.deployment)?;
        self.journal.ensure_capacity(1)?;
        let outcome = self.activation.activate_once_with_policy(
            &identity,
            current.deployment.graph(),
            current.deployment.retire(),
            reconciliation.policy,
            &mut self.adapter,
            cancellation,
        )?;
        let event = Event::Reconciled {
            sequence: reconciliation.sequence,
            attempt: reconciliation.attempt,
            outputs: outcome.outputs,
            deferred: outcome.deferred,
        };
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        self.current()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("reconciled generation is absent"))
    }

    /// Prepares and activates a package generation in this installation scope.
    ///
    /// Reconfiguration and rollback use the same method with a newly evaluated
    /// desired package set. A scope change requires a different journal directory.
    ///
    /// # Errors
    /// Returns an error for a mismatched scope, failed preparation, or any resume error.
    pub fn apply(
        &mut self,
        deployment: &Deployment,
        cancellation: &CancellationToken,
    ) -> Result<Generation> {
        self.apply_with_policy(deployment, ExecutionPolicy::Complete, cancellation)
    }

    /// Publishes installed desired state and an explicit startup receipt.
    ///
    /// The recorded policy also governs interruption recovery. A later installation
    /// can supersede unstarted effects without trying to start the previous runtime.
    ///
    /// # Errors
    /// Returns an error for incompatible scope, admission, recovery or execution failure.
    pub fn apply_with_policy(
        &mut self,
        deployment: &Deployment,
        policy: ExecutionPolicy,
        cancellation: &CancellationToken,
    ) -> Result<Generation> {
        self.finish_pruning()?;
        if self.state.reconciliation.is_some() {
            self.resume_reconciliation(cancellation)?;
        }
        if let Some(pending) = &self.state.pending {
            let same = pending.deployment.id()? == deployment.id()?;
            let recovered = self.resume(cancellation)?;
            if same {
                return recovered.ok_or_else(|| anyhow::anyhow!("recovered generation is absent"));
            }
        }
        ensure!(
            self.state
                .scope
                .as_deref()
                .is_none_or(|scope| scope == deployment.scope()),
            "transaction targets a different installation scope"
        );
        let retained = self.activation.retained();
        for id in deployment.retire() {
            ensure!(
                !deployment.graph().graph().nodes.contains_key(id),
                "cannot retire a configured effect"
            );
            ensure!(
                retained.contains_key(id) || self.activation.retired().contains(id),
                "cannot retire an unknown effect"
            );
        }
        let sequence = self.next_sequence()?;
        let identity = package_identity(sequence, &deployment.id()?);
        self.adapter
            .artifacts_mut()
            .retain_generation(&identity, deployment)?;
        self.journal.ensure_capacity(2)?;
        let event = Event::Prepared {
            sequence,
            document: serde_json::from_slice(&deployment.canonical_bytes()?)?,
            packages: deployment.resolved(),
            policy,
        };
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        self.activate_pending(cancellation)
    }

    /// Forgets an old generation and durably releases its artifact roots.
    ///
    /// Current and pending generations cannot be pruned. Persistent effects keep
    /// their own handler roots even after their originating generation is forgotten.
    ///
    /// # Errors
    /// Returns an error for an unknown or current generation, pending activation,
    /// artifact release failure, or journal failure.
    pub fn prune(&mut self, sequence: u64) -> Result<()> {
        let recovering = self.state.pruning == Some(sequence);
        self.finish_pruning()?;
        if recovering {
            return Ok(());
        }
        ensure!(
            self.state.pending.is_none() && self.state.reconciliation.is_none(),
            "cannot prune during pending activation"
        );
        ensure!(
            self.state.generations.contains_key(&sequence),
            "cannot prune an unknown generation"
        );
        ensure!(
            self.current()
                .is_some_and(|current| current.sequence != sequence),
            "cannot prune the current generation"
        );
        self.journal.ensure_capacity(2)?;
        let event = Event::Pruning { sequence };
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        self.finish_pruning()
    }

    fn finish_pruning(&mut self) -> Result<()> {
        let Some(sequence) = self.state.pruning else {
            return Ok(());
        };
        let generation = self
            .state
            .generations
            .get(&sequence)
            .ok_or_else(|| anyhow::anyhow!("pruned generation is absent"))?;
        let identity = package_identity(sequence, &generation.content);
        self.journal.ensure_capacity(1)?;
        self.adapter
            .artifacts_mut()
            .release_generation(&identity, &generation.deployment)?;
        let event = Event::Pruned { sequence };
        self.journal.append(&event)?;
        self.state.replay(&event)
    }
}

#[derive(Default)]
struct GenerationState {
    scope: Option<Vec<String>>,
    pending: Option<Pending>,
    reconciliation: Option<Reconciliation>,
    reconciliation_attempt: u64,
    completed_activation: Option<String>,
    generations: BTreeMap<u64, Generation>,
    pruning: Option<u64>,
}

impl GenerationState {
    fn pending_deployment(&self) -> Option<&Deployment> {
        self.pending
            .as_ref()
            .map(|pending| &pending.deployment)
            .or_else(|| {
                self.reconciliation
                    .as_ref()
                    .and_then(|_| self.current().map(|current| &current.deployment))
            })
    }

    fn pending_sequence(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .map(|pending| pending.sequence)
            .or_else(|| self.reconciliation.as_ref().map(|pending| pending.sequence))
    }

    fn pending_identity(&self) -> Result<Option<String>> {
        if let Some(reconciliation) = &self.reconciliation {
            return Ok(Some(reconciliation.identity()));
        }
        self.pending
            .as_ref()
            .map(|pending| {
                pending
                    .deployment
                    .id()
                    .map(|content| package_identity(pending.sequence, &content))
            })
            .transpose()
    }

    fn next_reconciliation_attempt(&self) -> Result<u64> {
        ensure!(
            self.pending.is_none() && self.reconciliation.is_none() && self.pruning.is_none(),
            "generation work is pending"
        );
        self.reconciliation_attempt
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("reconciliation attempt sequence is exhausted"))
    }

    fn current(&self) -> Option<&Generation> {
        self.generations
            .last_key_value()
            .map(|(_, generation)| generation)
    }

    fn next_sequence(&self) -> Result<u64> {
        ensure!(
            self.pending.is_none() && self.reconciliation.is_none(),
            "package generation recovery is pending"
        );
        ensure!(self.pruning.is_none(), "generation pruning is pending");
        self.current().map_or(Ok(1), |generation| {
            generation
                .sequence
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("package generation sequence is exhausted"))
        })
    }

    fn replay(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Prepared {
                sequence,
                document,
                packages,
                policy,
            } => {
                ensure!(self.pruning.is_none(), "generation pruning is pending");
                ensure!(
                    self.pending.is_none() && self.reconciliation.is_none(),
                    "package generation already pending"
                );
                ensure!(
                    *sequence == self.next_sequence()?,
                    "invalid package generation sequence"
                );
                let deployment = Deployment::decode(&canonical::to_vec(document)?, packages)?;
                ensure!(
                    self.scope
                        .as_deref()
                        .is_none_or(|scope| scope == deployment.scope()),
                    "generation scope changed"
                );
                self.scope = Some(deployment.scope().to_vec());
                self.pending = Some(Pending {
                    sequence: *sequence,
                    deployment,
                    policy: *policy,
                });
            }
            Event::Committed {
                sequence,
                outputs,
                deferred,
            } => {
                let pending = self
                    .pending
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("commit without prepared package generation"))?;
                ensure!(
                    pending.sequence == *sequence,
                    "package generation commit mismatch"
                );
                check_receipt(&pending.deployment, outputs, deferred, pending.policy)?;
                let generation = Generation {
                    sequence: *sequence,
                    content: pending.deployment.id()?,
                    outputs: outputs.clone(),
                    deferred: deferred.clone(),
                    deployment: pending.deployment.clone(),
                    policy: pending.policy,
                };
                self.completed_activation = Some(package_identity(*sequence, &generation.content));
                self.generations.insert(*sequence, generation);
                self.pending = None;
            }
            Event::ReconciliationPrepared {
                sequence,
                attempt,
                content,
                policy,
            } => {
                ensure!(
                    *attempt == self.next_reconciliation_attempt()?,
                    "invalid reconciliation attempt sequence"
                );
                let current = self
                    .current()
                    .ok_or_else(|| anyhow::anyhow!("reconciliation has no committed generation"))?;
                ensure!(
                    current.sequence == *sequence && current.content == *content,
                    "reconciliation differs from the committed generation"
                );
                self.reconciliation = Some(Reconciliation {
                    sequence: *sequence,
                    attempt: *attempt,
                    content: content.clone(),
                    policy: *policy,
                });
                self.reconciliation_attempt = *attempt;
            }
            Event::Reconciled {
                sequence,
                attempt,
                outputs,
                deferred,
            } => {
                let pending = self
                    .reconciliation
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("completion without prepared reconciliation"))?;
                ensure!(
                    pending.sequence == *sequence && pending.attempt == *attempt,
                    "reconciliation completion mismatch"
                );
                let current = self
                    .current()
                    .ok_or_else(|| anyhow::anyhow!("reconciliation has no committed generation"))?;
                ensure!(
                    current.sequence == pending.sequence && current.content == pending.content,
                    "reconciliation differs from the committed generation"
                );
                check_receipt(&current.deployment, outputs, deferred, pending.policy)?;
                let identity = pending.identity();
                let generation = self
                    .generations
                    .get_mut(sequence)
                    .ok_or_else(|| anyhow::anyhow!("reconciled generation is absent"))?;
                generation.outputs = outputs.clone();
                generation.deferred = deferred.clone();
                generation.policy = pending.policy;
                self.completed_activation = Some(identity);
                self.reconciliation = None;
            }
            Event::Pruning { sequence } => {
                ensure!(
                    self.pending.is_none()
                        && self.reconciliation.is_none()
                        && self.pruning.is_none(),
                    "generation work is pending"
                );
                ensure!(
                    self.generations.contains_key(sequence),
                    "cannot prune an unknown generation"
                );
                ensure!(
                    self.current()
                        .is_some_and(|current| current.sequence != *sequence),
                    "cannot prune the current generation"
                );
                self.pruning = Some(*sequence);
            }
            Event::Pruned { sequence } => {
                ensure!(
                    self.pruning == Some(*sequence),
                    "generation pruning mismatch"
                );
                self.generations.remove(sequence);
                self.pruning = None;
            }
        }
        Ok(())
    }
}

fn check_receipt(
    deployment: &Deployment,
    outputs: &ActivationResults,
    deferred: &BTreeSet<String>,
    policy: ExecutionPolicy,
) -> Result<()> {
    ensure!(
        *deferred == policy.deferred_effects(deployment.graph()),
        "generation deferred effects differ from the execution policy"
    );
    ensure!(
        outputs.len() + deferred.len() == deployment.graph().graph().nodes.len(),
        "generation result set differs from its graph"
    );
    for (id, effect) in &deployment.graph().graph().nodes {
        if deferred.contains(id) {
            ensure!(
                !outputs.contains_key(id),
                "deferred effect has fabricated results"
            );
            continue;
        }
        effect.check_results(
            outputs
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("generation omitted effect results"))?,
        )?;
    }
    Ok(())
}

/// Holds a read-only, replay-checked view of package and activation history.
///
/// The generation journal's shared lock remains held until this value is
/// dropped. Writers acquire that journal before the activation journal, so
/// profile links can be read consistently while this snapshot is retained.
/// Retained outcomes do not establish the current state of external resources.
pub struct Snapshot {
    journal: JournalReader<Event>,
    state: GenerationState,
    activation: aos_ability_runtime::activation::ActivationInspection,
}

impl Snapshot {
    /// Returns the last durably committed generation.
    #[must_use]
    pub fn current(&self) -> Option<&Generation> {
        self.state.current()
    }

    /// Returns the retained committed generation history.
    #[must_use]
    pub fn generations(&self) -> &BTreeMap<u64, Generation> {
        &self.state.generations
    }

    /// Returns the desired document awaiting generation or reconciliation completion.
    #[must_use]
    pub fn pending(&self) -> Option<&Deployment> {
        self.state.pending_deployment()
    }

    /// Returns the generation sequence associated with pending recovery.
    #[must_use]
    pub fn pending_sequence(&self) -> Option<u64> {
        self.state.pending_sequence()
    }

    /// Reports whether activation or pruning requires writable recovery.
    #[must_use]
    pub fn has_pending_work(&self) -> bool {
        self.state.pending.is_some()
            || self.state.reconciliation.is_some()
            || self.state.pruning.is_some()
            || self.activation.transaction.is_some()
            || self.activation.restoration.is_some()
    }

    /// Reports incomplete generation bytes without repairing them.
    #[must_use]
    pub fn incomplete_tail_bytes(&self) -> u64 {
        self.journal.snapshot().incomplete_tail_bytes()
    }

    /// Returns the checked effect history without claiming live verification.
    #[must_use]
    pub fn activation(&self) -> &aos_ability_runtime::activation::ActivationInspection {
        &self.activation
    }
}

/// Inspects existing native journals without creation, repair, or execution.
///
/// The same event decoder and generation state machine serve readers and
/// writers. The shared generation lock is held for the returned snapshot's
/// lifetime, including reads of profile links protected by that journal.
///
/// # Errors
/// Returns an error for missing or insecure journals, lock contention, corrupt
/// complete frames, exceeded limits, or invalid generation/activation history.
pub fn inspect(directory: &Path, limits: JournalLimits) -> Result<Snapshot> {
    let journal = FileJournal::<Event>::read_only(directory.join("generations.journal"), limits)?;
    let mut state = GenerationState::default();
    for record in journal.snapshot().records() {
        state.replay(record.body())?;
    }
    let activation =
        aos_ability_runtime::activation::inspect(directory.join("effects.journal"), limits)?;
    let active = activation
        .transaction
        .as_deref()
        .zip(activation.desired.as_ref())
        .zip(activation.policy)
        .map(|((identity, graph), policy)| (identity, graph, policy));
    verify_journal_pair(&state, active, activation.completed.as_ref())?;
    Ok(Snapshot {
        journal,
        state,
        activation,
    })
}

/// Checks publication authority against exact durable effect receipts.
fn verify_journal_pair(
    state: &GenerationState,
    active: Option<(&str, &Value, ExecutionPolicy)>,
    completed: Option<&aos_ability_runtime::activation::CompletedTransaction>,
) -> Result<()> {
    let pending_identity = state.pending_identity()?;
    let current_identity = &state.completed_activation;
    if let Some((identity, graph, policy)) = active {
        ensure!(
            Some(identity) == pending_identity.as_deref(),
            "activation journal does not match the pending package generation"
        );
        let desired = state
            .pending_deployment()
            .context("active effect journal has no pending deployment")?;
        let expected_policy = state
            .pending
            .as_ref()
            .map(|pending| pending.policy)
            .or_else(|| state.reconciliation.as_ref().map(|pending| pending.policy))
            .context("active effect journal has no pending policy")?;
        ensure!(
            graph == desired.graph().document() && policy == expected_policy,
            "active effect journal differs from pending package content or policy"
        );
    }
    let Some(completed) = completed else {
        ensure!(
            current_identity.is_none(),
            "committed generation has no activation receipt"
        );
        return Ok(());
    };
    ensure!(
        Some(&completed.transaction) == current_identity.as_ref()
            || Some(&completed.transaction) == pending_identity.as_ref(),
        "activation receipt does not match package generation history"
    );
    let (policy, desired, outputs) = if Some(&completed.transaction) == current_identity.as_ref() {
        let current = state
            .current()
            .context("activation receipt has no generation")?;
        (current.policy, &current.deployment, Some(&current.outputs))
    } else if let Some(pending) = &state.pending {
        (pending.policy, &pending.deployment, None)
    } else {
        let pending = state
            .reconciliation
            .as_ref()
            .context("activation receipt has no pending work")?;
        let current = state
            .current()
            .context("pending reconciliation has no generation")?;
        (pending.policy, &current.deployment, None)
    };
    check_receipt(desired, &completed.outputs, &completed.deferred, policy)?;
    ensure!(
        completed.policy == policy
            && completed.content == policy.content_identity(desired.graph(), desired.retire())?,
        "activation receipt differs from package content or policy"
    );
    if let Some(outputs) = outputs {
        ensure!(
            outputs == &completed.outputs,
            "package results differ from the durable activation receipt"
        );
    }
    Ok(())
}
