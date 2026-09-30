//! Durable package generations coordinated with the effect journal.
//!
//! A prepared generation retains its exact module transaction before dispatch.
//! The activation journal records a caller-supplied transaction identity, so a
//! restart between effect completion and generation commit does not repeat
//! one-shot operations. The committed journal record is the authoritative
//! generation pointer; profile frontends may publish their links from it.
//!
//! ```text
//! prepared { sequence, document, packages, retire }
//! committed { sequence, outputs }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, ensure};
use aos_ability_runtime::activation::{Activation, ActivationResults};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::{FileJournal, JournalError, JournalLimits, JournalPayload};
use aos_contract::{
    canonical,
    limits::{BoundedWriter, JsonLimits},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::handler::{HandlerArtifacts, ProcessAdapter};
use super::model::{Deployment, ResolvedPackages};

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
        retire: BTreeSet<String>,
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
    retire: BTreeSet<String>,
}

/// Owns one installation scope's generation and effect journals.
pub struct Transactions<S> {
    journal: FileJournal<Event>,
    activation: Activation,
    adapter: ProcessAdapter<S>,
    scope: Option<Vec<String>>,
    pending: Option<Pending>,
    generations: BTreeMap<u64, Generation>,
    pruning: Option<u64>,
}

impl<S: DeploymentStore> Transactions<S> {
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
            scope: None,
            pending: None,
            generations: BTreeMap::new(),
            pruning: None,
        };
        for record in opened.recovery.records() {
            result.replay(record.body())?;
        }
        Ok(result)
    }

    /// Returns the last durably committed generation, if any.
    #[must_use]
    pub fn current(&self) -> Option<&Generation> {
        self.generations
            .last_key_value()
            .map(|(_, generation)| generation)
    }

    /// Returns the committed generation history retained by this scope.
    #[must_use]
    pub fn generations(&self) -> &BTreeMap<u64, Generation> {
        &self.generations
    }

    /// Returns the prepared document when recovery or activation is still pending.
    #[must_use]
    pub fn pending(&self) -> Option<&Deployment> {
        self.pending.as_ref().map(|pending| &pending.deployment)
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
        let Some(pending) = &self.pending else {
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
            &pending.retire,
            &mut self.adapter,
            cancellation,
        )?;
        let event = Event::Committed {
            sequence: pending.sequence,
            outputs,
        };
        self.journal.append(&event)?;
        self.replay(&event)?;
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
        retire: BTreeSet<String>,
        cancellation: &CancellationToken,
    ) -> Result<Generation> {
        self.finish_pruning()?;
        if let Some(pending) = &self.pending {
            let same = pending.deployment.id()? == deployment.id()? && pending.retire == retire;
            let recovered = self.resume(cancellation)?;
            if same {
                return recovered.ok_or_else(|| anyhow::anyhow!("recovered generation is absent"));
            }
        }
        ensure!(
            self.scope
                .as_deref()
                .is_none_or(|scope| scope == deployment.scope()),
            "transaction targets a different installation scope"
        );
        let retained = self.activation.retained();
        for id in &retire {
            ensure!(
                !deployment.graph().graph().nodes.contains_key(id),
                "cannot retire a configured effect"
            );
            ensure!(retained.contains_key(id), "cannot retire an unknown effect");
        }
        let sequence = self
            .current()
            .map_or(1, |generation| generation.sequence + 1);
        let identity = format!("package-{sequence}-{}", deployment.id()?);
        self.adapter
            .artifacts_mut()
            .retain_generation(&identity, deployment)?;
        self.journal.ensure_capacity(2)?;
        let event = Event::Prepared {
            sequence,
            document: serde_json::from_slice(&deployment.canonical_bytes()?)?,
            packages: deployment.resolved(),
            retire,
        };
        self.journal.append(&event)?;
        self.replay(&event)?;
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
        let recovering = self.pruning == Some(sequence);
        self.finish_pruning()?;
        if recovering {
            return Ok(());
        }
        ensure!(
            self.pending.is_none(),
            "cannot prune during pending activation"
        );
        ensure!(
            self.generations.contains_key(&sequence),
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
        self.replay(&event)?;
        self.finish_pruning()
    }

    fn finish_pruning(&mut self) -> Result<()> {
        let Some(sequence) = self.pruning else {
            return Ok(());
        };
        let generation = self
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
        self.replay(&event)
    }

    fn replay(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Prepared {
                sequence,
                document,
                packages,
                retire,
            } => {
                ensure!(self.pruning.is_none(), "generation pruning is pending");
                ensure!(self.pending.is_none(), "package generation already pending");
                ensure!(
                    *sequence
                        == self
                            .current()
                            .map_or(1, |generation| generation.sequence + 1),
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
                    retire: retire.clone(),
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
