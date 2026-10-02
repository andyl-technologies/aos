//! Durable package generations coordinated with the effect journal.
//!
//! A prepared generation retains its exact module transaction before dispatch.
//! The activation journal records a caller-supplied transaction identity, so a
//! restart between effect completion and generation commit does not repeat
//! one-shot operations. The committed journal record is the authoritative
//! generation pointer; profile frontends may publish their links from it.
//!
//! ```text
//! prepared { sequence, document, packages }
//! committed { sequence, outputs }
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::activation::{Activation, ActivationResults};
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
    },
    Committed {
        sequence: u64,
        outputs: ActivationResults,
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
    /// Retains the exact document for inspection or a subsequent rollback transaction.
    pub deployment: Deployment,
}

struct Pending {
    sequence: u64,
    deployment: Deployment,
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

    /// Returns the prepared document when recovery or activation is still pending.
    #[must_use]
    pub fn pending(&self) -> Option<&Deployment> {
        self.state
            .pending
            .as_ref()
            .map(|pending| &pending.deployment)
    }

    /// Returns the durable sequence of the generation awaiting recovery.
    ///
    /// The sequence identifies its staged inputs even when several generations
    /// evaluate to identical deployment content.
    #[must_use]
    pub fn pending_sequence(&self) -> Option<u64> {
        self.state.pending.as_ref().map(|pending| pending.sequence)
    }

    /// Lists retained effect results, including persistent state absent from the current graph.
    #[must_use]
    pub fn retained_effects(&self) -> ActivationResults {
        self.activation.retained()
    }

    /// Resumes a prepared generation before accepting another package transaction.
    ///
    /// # Errors
    /// Returns an error for failed artifact admission, uncertain effects, failed
    /// recovery, cancellation, or failure to commit the generation journal.
    pub fn resume(&mut self, cancellation: &CancellationToken) -> Result<Option<Generation>> {
        self.finish_pruning()?;
        let Some(pending) = &self.state.pending else {
            return Ok(None);
        };
        let content = pending.deployment.id()?;
        let identity = format!("package-{}-{content}", pending.sequence);
        self.adapter
            .artifacts_mut()
            .retain_generation(&identity, &pending.deployment)?;
        self.journal.ensure_capacity(1)?;
        let outputs = self.activation.activate_once(
            &identity,
            pending.deployment.graph(),
            pending.deployment.retire(),
            &mut self.adapter,
            cancellation,
        )?;
        let event = Event::Committed {
            sequence: pending.sequence,
            outputs,
        };
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        Ok(self.current().cloned())
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
        self.finish_pruning()?;
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
        let identity = format!("package-{sequence}-{}", deployment.id()?);
        self.adapter
            .artifacts_mut()
            .retain_generation(&identity, deployment)?;
        self.journal.ensure_capacity(2)?;
        let event = Event::Prepared {
            sequence,
            document: serde_json::from_slice(&deployment.canonical_bytes()?)?,
            packages: deployment.resolved(),
        };
        self.journal.append(&event)?;
        self.state.replay(&event)?;
        self.resume(cancellation)?
            .ok_or_else(|| anyhow::anyhow!("prepared generation did not commit"))
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
            self.state.pending.is_none(),
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
        let identity = format!("package-{sequence}-{}", generation.content);
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
    generations: BTreeMap<u64, Generation>,
    pruning: Option<u64>,
}

impl GenerationState {
    fn current(&self) -> Option<&Generation> {
        self.generations
            .last_key_value()
            .map(|(_, generation)| generation)
    }

    fn next_sequence(&self) -> Result<u64> {
        ensure!(
            self.pending.is_none(),
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
            } => {
                ensure!(self.pruning.is_none(), "generation pruning is pending");
                ensure!(self.pending.is_none(), "package generation already pending");
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
                });
            }
            Event::Committed { sequence, outputs } => {
                let pending = self
                    .pending
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("commit without prepared package generation"))?;
                ensure!(
                    pending.sequence == *sequence,
                    "package generation commit mismatch"
                );
                ensure!(
                    outputs.len() == pending.deployment.graph().graph().nodes.len(),
                    "generation result set differs from its graph"
                );
                for (id, effect) in &pending.deployment.graph().graph().nodes {
                    effect.check_results(
                        outputs
                            .get(id)
                            .ok_or_else(|| anyhow::anyhow!("generation omitted effect results"))?,
                    )?;
                }
                let generation = Generation {
                    sequence: *sequence,
                    content: pending.deployment.id()?,
                    outputs: outputs.clone(),
                    deployment: pending.deployment.clone(),
                };
                self.generations.insert(*sequence, generation);
                self.pending = None;
            }
            Event::Pruning { sequence } => {
                ensure!(
                    self.pending.is_none() && self.pruning.is_none(),
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

    /// Returns the prepared document awaiting completion, if any.
    #[must_use]
    pub fn pending(&self) -> Option<&Deployment> {
        self.state
            .pending
            .as_ref()
            .map(|pending| &pending.deployment)
    }

    /// Returns the exact durable sequence of a pending generation.
    #[must_use]
    pub fn pending_sequence(&self) -> Option<u64> {
        self.state.pending.as_ref().map(|pending| pending.sequence)
    }

    /// Reports whether activation or pruning requires writable recovery.
    #[must_use]
    pub fn has_pending_work(&self) -> bool {
        self.state.pending.is_some()
            || self.state.pruning.is_some()
            || self.activation.transaction.is_some()
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
    let pending_identity = state
        .pending
        .as_ref()
        .map(|pending| {
            pending
                .deployment
                .id()
                .map(|content| format!("package-{}-{content}", pending.sequence))
        })
        .transpose()?;
    let current_identity = state
        .current()
        .map(|current| format!("package-{}-{}", current.sequence, current.content));
    if let Some(active) = &activation.transaction {
        ensure!(
            Some(active) == pending_identity.as_ref(),
            "activation journal does not match the pending package generation"
        );
    }
    if let Some(completed) = &activation.completed {
        ensure!(
            Some(&completed.transaction) == current_identity.as_ref()
                || Some(&completed.transaction) == pending_identity.as_ref(),
            "activation receipt does not match package generation history"
        );
    } else {
        ensure!(
            current_identity.is_none(),
            "committed generation has no activation receipt"
        );
    }
    Ok(Snapshot {
        journal,
        state,
        activation,
    })
}
