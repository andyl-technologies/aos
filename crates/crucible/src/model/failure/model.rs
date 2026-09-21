//! Failure findings, signatures, clustering, reports, and triage artifacts.

use super::*;

#[path = "model/clustering.rs"]
mod clustering;
#[path = "model/reporting.rs"]
mod reporting;
#[path = "model/signature.rs"]
mod signature;
#[path = "model/signature_policy.rs"]
mod signature_policy;
#[path = "model/triage.rs"]
mod triage;

pub use clustering::*;
pub use reporting::*;
pub use signature::*;
pub use signature_policy::*;
pub use triage::*;

/// Discovery path that produced an interesting finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingDiscoveryPath {
    /// Finding was produced by a campaign fork operation.
    CampaignFork,
    /// Finding was produced by state-space search.
    StateSpaceSearch,
    /// Finding was produced by coverage-guided fuzzing.
    CoverageGuidedFuzzing,
    /// Finding is a retained coverage-guided corpus entry.
    RetainedCorpusEntry,
}

/// Self-contained reproduction artifact attached to one interesting finding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FindingReproductionArtifact {
    /// Discovery path that produced the finding.
    pub discovery_path: FindingDiscoveryPath,
    /// Stable finding fingerprint supplied by the discovering oracle.
    pub finding_fingerprint: ContentHash,
    /// Content-addressed execution configuration captured by the artifact.
    pub configuration: ContentHash,
    /// Self-contained `(seed, scenario, schedule)` artifact.
    pub artifact: ReproductionArtifact,
    /// Replay evidence proving the artifact reduces without snapshots.
    pub replay: ReproductionReplay,
}

impl FindingReproductionArtifact {
    /// Captures a finding artifact from a pinned scenario form and configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario` is
    /// not the concrete form for `configuration`. Returns other [`EngineError`]
    /// values when artifact capture or replay validation fails.
    pub fn capture(
        discovery_path: FindingDiscoveryPath,
        finding_fingerprint: ContentHash,
        scenario: &ScenarioDefForm,
        configuration: &Configuration,
    ) -> Result<Self, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != configuration.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: configuration.def.id,
                actual: scenario_def.id,
            });
        }
        let expected_state = reduce(&configuration.def, &configuration.schedule)?.id;
        let artifact = ReproductionArtifact::capture(scenario, &configuration.schedule)?;
        let replay = artifact.verify_replay(expected_state)?;
        Ok(Self {
            discovery_path,
            finding_fingerprint,
            configuration: configuration.id(),
            artifact,
            replay,
        })
    }

    /// Stores this finding's self-contained artifact bytes in `store`.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when `store` cannot persist the artifact bytes.
    pub fn store_artifact<S>(&self, store: &S) -> Result<ContentHash, DagStoreError>
    where
        S: DagStore + ?Sized,
    {
        store.put(&self.artifact.to_compact_binary())
    }

    /// Rebuilds a finding artifact from a stored self-contained artifact.
    ///
    /// # Errors
    ///
    /// Returns [`FindingReproductionArtifactError::Store`] when the store cannot
    /// read `artifact_key`. Returns [`FindingReproductionArtifactError::Engine`]
    /// when the stored artifact bytes are malformed or fail replay validation.
    pub fn load_from_store<S>(
        discovery_path: FindingDiscoveryPath,
        finding_fingerprint: ContentHash,
        store: &S,
        artifact_key: ContentHash,
    ) -> Result<Self, FindingReproductionArtifactError>
    where
        S: DagStore + ?Sized,
    {
        let bytes =
            store
                .get(&artifact_key)
                .map_err(|source| FindingReproductionArtifactError::Store {
                    operation: "get-finding-artifact",
                    source,
                })?;
        let artifact = ReproductionArtifact::from_compact_binary(&bytes).map_err(|source| {
            FindingReproductionArtifactError::Engine {
                operation: "decode-finding-artifact",
                source: Box::new(source),
            }
        })?;
        let replay =
            artifact
                .replay()
                .map_err(|source| FindingReproductionArtifactError::Engine {
                    operation: "replay-finding-artifact",
                    source: Box::new(source),
                })?;
        let configuration = Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        };
        Ok(Self {
            discovery_path,
            finding_fingerprint,
            configuration: configuration.id(),
            artifact,
            replay,
        })
    }

    /// Shrinks this finding while preserving its failure fingerprint.
    ///
    /// The minimizer admits a bounded lexicographic window of shorter recorded
    /// schedule subsequences in shortest-first order, then applies seeded
    /// content-address tie-breaks within that admitted window.
    /// Every candidate is replayed as a self-contained artifact before
    /// `failure_fingerprint` is consulted, and the first preserving candidate is
    /// therefore the stable shortest artifact within the compiled bounded
    /// policy under the supplied failure oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] or
    /// [`EngineError::ReproductionArtifactReplayMismatch`] when this public value
    /// does not match its embedded artifact/replay evidence, or when the starting
    /// artifact does not reproduce this finding's fingerprint. Returns other
    /// [`EngineError`] values when candidate capture, replay validation, or the
    /// caller-supplied failure oracle fails.
    pub fn minimize<F>(
        &self,
        config: MinimizationConfig,
        mut failure_fingerprint: F,
    ) -> Result<MinimizationRun, EngineError>
    where
        F: FnMut(&FindingReproductionArtifact) -> Result<Option<ContentHash>, EngineError>,
    {
        let original = self.validated()?;
        let target = original.finding_fingerprint;
        let initial = failure_fingerprint(&original)?;
        if initial != Some(target) {
            return Err(EngineError::ReplayTargetMismatch {
                expected: target,
                actual: initial.unwrap_or_default(),
            });
        }

        let mut attempts = Vec::new();
        let mut minimized = original.clone();
        let candidates = minimization_candidates(
            config,
            original.artifact.id(),
            original.artifact.schedule(),
            minimization_candidate_limit(&original.artifact),
        )?;

        for (sequence, candidate) in candidates.into_iter().enumerate() {
            let configuration = Configuration {
                def: original.artifact.scenario_def(),
                schedule: candidate.schedule,
            };
            let finding = FindingReproductionArtifact::capture(
                original.discovery_path,
                target,
                original.artifact.scenario_form(),
                &configuration,
            )?;
            let observed_fingerprint = failure_fingerprint(&finding)?;
            let accepted_candidate = observed_fingerprint == Some(target);
            attempts.push(MinimizationAttempt {
                sequence: sequence as u64,
                removed_indices: candidate.removed_indices,
                removed_decisions: candidate.removed_decisions,
                candidate_artifact: finding.artifact.id(),
                candidate_schedule: finding.artifact.schedule().content_hash(),
                replayed_state: finding.replay.state,
                observed_fingerprint,
                accepted: accepted_candidate,
            });

            if accepted_candidate {
                minimized = finding;
                break;
            }
        }

        Ok(MinimizationRun {
            seed: config.seed,
            interesting_window: config.interesting_window(),
            target_fingerprint: target,
            original,
            minimized,
            attempts,
        })
    }

    fn validated(&self) -> Result<Self, EngineError> {
        let replay = self.artifact.replay()?;
        if replay != self.replay {
            return Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: self.artifact.id(),
                expected: self.replay.state,
                actual: replay.state,
            });
        }
        let configuration = Configuration {
            def: self.artifact.scenario_def(),
            schedule: self.artifact.schedule().clone(),
        };
        let configuration_id = configuration.id();
        if configuration_id != self.configuration {
            return Err(EngineError::ReplayTargetMismatch {
                expected: self.configuration,
                actual: configuration_id,
            });
        }
        Ok(Self {
            discovery_path: self.discovery_path,
            finding_fingerprint: self.finding_fingerprint,
            configuration: configuration_id,
            artifact: self.artifact.clone(),
            replay,
        })
    }
}
