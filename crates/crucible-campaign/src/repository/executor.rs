//! Executor-facing campaign publication and recovery capability.

use super::*;

/// Narrow immutable-record capability supplied to a local campaign executor.
///
/// This facade deliberately exposes no campaign head, mutable-ref, owner
/// projection, or coordinator transaction methods. It can authenticate the
/// records needed to execute one attempt and publish a content-addressed
/// observation candidate for later coordinator admission.
#[derive(Clone)]
pub struct CampaignExecutorStore {
    repository: Arc<CampaignRepository>,
}

impl CampaignExecutorStore {
    /// Creates a narrow executor capability over one campaign repository.
    #[must_use]
    pub const fn new(repository: Arc<CampaignRepository>) -> Self {
        Self { repository }
    }

    /// Reauthenticates an operational execution scope during durable recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when a savepoint owner fact or its immutable attempt
    /// closure is unavailable, corrupt, or inconsistent with the supplied key.
    pub fn validate_execution_scope(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        start_mode: AttemptStartMode,
    ) -> Result<(), CampaignRepositoryError> {
        self.repository
            .validate_executor_execution_scope(lineage, attempt, start_mode)
    }

    /// Authenticates one admission-bound policy used for automatic finding retention.
    ///
    /// # Errors
    ///
    /// Returns an error when the admission, attempt, lineage, policy, or their
    /// canonical relationships are unavailable or inconsistent.
    pub fn validate_attempt_retention_policy_basis(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        basis: AttemptRetentionPolicyBasis,
    ) -> Result<crate::RetentionPolicy, CampaignRepositoryError> {
        self.repository
            .validate_attempt_retention_policy_basis(lineage, attempt, basis)?;
        self.repository
            .read_policy(basis.policy().content_id())
            .map(|policy| policy.retention())
    }

    /// Loads and authenticates one campaign compatibility lineage.
    ///
    /// # Errors
    ///
    /// Returns an error when the lineage is missing, corrupt, or inconsistent.
    pub fn load_lineage(
        &self,
        id: CampaignLineageId,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        self.repository.load_lineage(id)
    }

    /// Loads and authenticates one execution-model scenario artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is missing, corrupt, or inconsistent.
    pub fn load_scenario_artifact(
        &self,
        id: ScenarioArtifactId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        self.repository.load_scenario_artifact(id)
    }

    /// Loads and authenticates one semantic attempt closure.
    ///
    /// # Errors
    ///
    /// Returns an error when the attempt or one of its references is missing,
    /// corrupt, or inconsistent.
    pub fn load_attempt(&self, id: AttemptId) -> Result<Attempt, CampaignRepositoryError> {
        self.repository.load_attempt(id)
    }

    /// Loads one attempt and its complete authenticated continuation ancestry.
    ///
    /// Entries are returned newest first and share one bounded validation
    /// cache, preserving linear work for long selected-savepoint histories.
    ///
    /// # Errors
    ///
    /// Returns an error when any attempt or referenced object is unavailable,
    /// malformed, or semantically inconsistent.
    pub fn load_attempt_origin_chain(
        &self,
        id: AttemptId,
    ) -> Result<Vec<Attempt>, CampaignRepositoryError> {
        self.repository.load_attempt_origin_chain(id)
    }

    /// Loads and authenticates one modeled observation closure.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation or one of its referenced records
    /// is missing, corrupt, or inconsistent.
    pub fn load_observation(
        &self,
        id: ObservationId,
    ) -> Result<Observation, CampaignRepositoryError> {
        self.repository.load_observation(id)
    }

    /// Loads and authenticates one semantic branch path.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is missing, corrupt, or inconsistent.
    pub fn load_branch_path(
        &self,
        id: BranchPathId,
    ) -> Result<BranchPath, CampaignRepositoryError> {
        self.repository.load_branch_path(id)
    }

    /// Loads and authenticates one exact configuration artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is missing, corrupt, or inconsistent.
    pub fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        self.repository.load_configuration_artifact(id)
    }

    /// Resolves one selection with its authenticated opportunity and domain.
    ///
    /// # Errors
    ///
    /// Returns an error when any exact selection reference is missing, corrupt,
    /// or semantically inconsistent.
    pub fn resolve_selection(
        &self,
        id: SelectionId,
    ) -> Result<ResolvedSelection, CampaignRepositoryError> {
        self.repository.resolve_selection(id)
    }

    /// Resolves a bounded batch of selections with shared authenticated dependencies.
    ///
    /// Repeated opportunities, declarations, and domains are decoded once. The
    /// aggregate unique canonical record envelopes are bounded independently of
    /// the number and ordering of selections.
    ///
    /// # Errors
    ///
    /// Returns an error when the batch exceeds its record or byte bound, or
    /// when any exact selection reference is missing, corrupt, or inconsistent.
    pub fn resolve_selections(
        &self,
        ids: &[SelectionId],
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.repository.resolve_selections(ids)
    }

    /// Resolves selections against stored records and one unpublished observation candidate.
    ///
    /// An executor may need to replay a configuration produced by its current
    /// execution before that observation has entered the repository. Selections
    /// carried by `owned` are authenticated by [`ObservationCandidate`]'s
    /// constructor; every other selection is resolved through the repository.
    /// The result preserves the order and cardinality of `ids`.
    ///
    /// # Errors
    ///
    /// Returns an error when an owned selection cannot be identified, its
    /// discovery closure is inconsistent, or a remaining selection cannot be
    /// authenticated by the repository.
    pub fn resolve_selections_with_owned_candidate(
        &self,
        ids: &[SelectionId],
        owned: &ObservationCandidate,
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        let owned_discoveries = owned
            .discovered_choices
            .iter()
            .map(|discovery| {
                discovery
                    .opportunity
                    .id()
                    .map(|id| (id, discovery))
                    .map_err(CampaignRepositoryError::from)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let owned_selections = owned
            .produced_selections
            .iter()
            .map(|selection| {
                selection
                    .id()
                    .map(|id| (id, selection))
                    .map_err(CampaignRepositoryError::from)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let stored_ids = ids
            .iter()
            .filter(|id| !owned_selections.contains_key(id))
            .copied()
            .collect::<Vec<_>>();
        let stored = self
            .repository
            .resolve_selections(&stored_ids)?
            .into_iter()
            .map(|selection| {
                selection
                    .selection()
                    .id()
                    .map(|id| (id, selection))
                    .map_err(CampaignRepositoryError::from)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        ids.iter()
            .map(|id| {
                if let Some(selection) = owned_selections.get(id) {
                    let discovery = owned_discoveries.get(&selection.opportunity()).ok_or(
                        CampaignRepositoryError::Integrity {
                            reason: "owned-candidate-selection-opportunity-missing",
                        },
                    )?;
                    selection
                        .validate_resolved_references(&discovery.opportunity, &discovery.domain)?;
                    Ok(ResolvedSelection {
                        selection: (*selection).clone(),
                        opportunity: Arc::new(discovery.opportunity.clone()),
                        declaration: Arc::clone(&discovery.declaration),
                        domain: Arc::clone(&discovery.domain),
                    })
                } else {
                    stored
                        .get(id)
                        .cloned()
                        .ok_or(CampaignRepositoryError::Integrity {
                            reason: "owned-candidate-selection-resolution-inexact",
                        })
                }
            })
            .collect()
    }

    /// Resolves a bounded batch within a caller-supplied canonical byte limit.
    ///
    /// The limit covers every unique selection, opportunity, declaration, and
    /// domain body decoded by the batch. It lets an executor reserve for the
    /// decoded representation before repository resolution allocates it.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError::SelectionResolutionBudgetExceeded`]
    /// when the unique canonical closure exceeds `maximum_canonical_bytes`, or
    /// the ordinary resolution error for missing, corrupt, or inconsistent
    /// records.
    pub fn resolve_selections_with_canonical_byte_limit(
        &self,
        ids: &[SelectionId],
        maximum_canonical_bytes: usize,
    ) -> Result<Vec<ResolvedSelection>, CampaignRepositoryError> {
        self.repository
            .resolve_selections_with_canonical_byte_limit(ids, maximum_canonical_bytes)
    }

    /// Publishes a validated immutable observation candidate without advancing a campaign.
    ///
    /// # Errors
    ///
    /// Returns an error before writing when the bundle or any already-published
    /// dependency is missing, corrupt, oversized, or inconsistent. A storage
    /// failure after publication starts may leave unreachable immutable data.
    pub fn publish_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<ObservationId, CampaignRepositoryError> {
        self.repository.publish_observation_candidate(candidate)
    }

    /// Publishes one executor-authenticated opaque evidence leaf.
    ///
    /// The caller supplies the exact content identity derived from independently
    /// verified bytes. Only trace leaves are accepted, keeping this capability
    /// narrower than arbitrary immutable-store access.
    ///
    /// # Errors
    ///
    /// Returns an error when `expected` is not a trace identity, the bytes do
    /// not derive that identity, or durable placement returns another identity.
    pub fn publish_executor_trace_leaf(
        &self,
        expected: ContentId,
        payload_schema: u32,
        bytes: &[u8],
    ) -> Result<ContentId, CampaignRepositoryError> {
        if expected.kind() != ObjectKind::Trace
            || ContentId::for_bytes(ObjectKind::Trace, payload_schema, bytes) != expected
        {
            return Err(integrity("executor-trace-leaf-identity-mismatch"));
        }
        let receipt = self
            .repository
            .blobs
            .put_if_absent(expected, &BlobHandle::from_bytes(bytes.to_vec()))?;
        if receipt.id != expected {
            return Err(integrity("executor-trace-leaf-publication-mismatch"));
        }
        Ok(expected)
    }

    /// Reads one authenticated raw evidence leaf owned by a measurement set.
    ///
    /// # Errors
    ///
    /// Returns an error when the measurement set does not name the leaf, the
    /// leaf is not trace content, its declared size exceeds `max_bytes`, or the
    /// backend cannot complete an authenticated read.
    pub fn read_measurement_evidence_leaf(
        &self,
        measurements: MeasurementSetId,
        evidence: ContentId,
        max_bytes: u64,
    ) -> Result<Vec<u8>, CampaignRepositoryError> {
        let retained = self.repository.load_measurement_set(measurements)?;
        let evaluation = retained.evaluation();
        if evidence.kind() != ObjectKind::Trace || !evaluation.evidence().contains(&evidence) {
            return Err(integrity("measurement-evidence-leaf-is-not-owned"));
        }

        self.repository
            .blobs
            .read(evidence, None)?
            .read_all(max_bytes)
            .map_err(Into::into)
    }

    /// Loads and authenticates one bounded executor evidence leaf.
    ///
    /// # Errors
    ///
    /// Returns an error when `expected` is not a trace identity, the object is
    /// absent or corrupt, or its logical length exceeds `maximum_bytes`.
    pub fn load_executor_trace_leaf(
        &self,
        expected: ContentId,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, CampaignRepositoryError> {
        if expected.kind() != ObjectKind::Trace {
            return Err(integrity("executor-trace-leaf-kind-mismatch"));
        }
        let bytes = self
            .repository
            .blobs
            .read(expected, None)?
            .read_all(maximum_bytes)?;
        if !expected.authenticates(&bytes) {
            return Err(integrity("executor-trace-leaf-content-mismatch"));
        }
        Ok(bytes)
    }

    /// Publishes one executor-verified replay choice domain.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact record cannot be stored and authenticated.
    pub fn publish_executor_choice_domain(
        &self,
        domain: &ChoiceDomain,
    ) -> Result<ChoiceDomainId, CampaignRepositoryError> {
        self.repository.publish_choice_domain(domain)
    }

    /// Publishes one executor-verified replay selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact record cannot be stored and authenticated.
    pub fn publish_executor_selectable(
        &self,
        selectable: &SelectableDeclaration,
    ) -> Result<SelectableId, CampaignRepositoryError> {
        self.repository.publish_selectable(selectable)
    }

    /// Publishes one executor-verified replay choice opportunity.
    ///
    /// # Errors
    ///
    /// Returns an error when a dependency is absent or the exact record cannot
    /// be stored and authenticated.
    pub fn publish_executor_choice_opportunity(
        &self,
        opportunity: &ChoiceOpportunity,
    ) -> Result<ChoiceOpportunityId, CampaignRepositoryError> {
        self.repository.publish_choice_opportunity(opportunity)
    }

    /// Publishes one executor-verified replay selection.
    ///
    /// # Errors
    ///
    /// Returns an error when its opportunity is absent or its exact value is invalid.
    pub fn publish_executor_selection(
        &self,
        selection: &Selection,
    ) -> Result<SelectionId, CampaignRepositoryError> {
        self.repository.publish_selection(selection)
    }

    /// Publishes one executor-verified replay measurement set.
    ///
    /// # Errors
    ///
    /// Returns an error when a transitive evidence dependency is absent or the
    /// exact record cannot be stored and authenticated.
    pub fn publish_executor_measurement_set(
        &self,
        value: &MeasurementSet,
    ) -> Result<MeasurementSetId, CampaignRepositoryError> {
        self.repository.publish_measurement_set(value)
    }

    /// Publishes one executor-verified replay property-verdict set.
    ///
    /// # Errors
    ///
    /// Returns an error when a transitive evidence dependency is absent or the
    /// exact record cannot be stored and authenticated.
    pub fn publish_executor_property_verdict_set(
        &self,
        value: &PropertyVerdictSet,
    ) -> Result<PropertyVerdictSetId, CampaignRepositoryError> {
        self.repository.publish_property_verdict_set(value)
    }

    /// Publishes one executor-verified replay coverage projection.
    ///
    /// # Errors
    ///
    /// Returns an error when a transitive evidence dependency is absent or the
    /// exact record cannot be stored and authenticated.
    pub fn publish_executor_coverage_projection(
        &self,
        value: &CoverageProjection,
    ) -> Result<CoverageProjectionId, CampaignRepositoryError> {
        self.repository.publish_coverage_projection(value)
    }

    /// Validates an observation candidate without writing any bundle member.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle or an already-published dependency is
    /// missing, corrupt, oversized, or inconsistent.
    pub fn validate_observation_candidate(
        &self,
        candidate: &ObservationCandidate,
    ) -> Result<(), CampaignRepositoryError> {
        self.repository.validate_observation_candidate(candidate)
    }

    /// Publishes one executor-derived configuration artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the scenario dependency is unavailable or the
    /// exact configuration cannot be durably stored and authenticated.
    pub fn publish_executor_configuration(
        &self,
        artifact: &ConfigurationArtifact,
    ) -> Result<ConfigurationArtifactId, CampaignRepositoryError> {
        self.repository.publish_configuration_artifact(
            artifact.scenario(),
            artifact.scenario_artifact(),
            artifact.configuration(),
            artifact.payload_schema(),
            artifact.payload().to_vec(),
        )
    }

    /// Publishes one executor-verified original or minimized reproduction.
    ///
    /// # Errors
    ///
    /// Returns an error when the prepared reproduction or any dependency is
    /// missing, corrupt, inconsistent, or unavailable for durable storage.
    pub fn publish_executor_reproduction(
        &self,
        artifact: &ReproductionArtifact,
    ) -> Result<ReproductionArtifactId, CampaignRepositoryError> {
        match artifact.minimization() {
            Some(minimization) => self.repository.publish_minimized_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
                minimization.clone(),
            ),
            None => self.repository.publish_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.payload_schema(),
                artifact.payload().to_vec(),
            ),
        }
    }

    /// Publishes one executor-prepared finding-candidate root.
    ///
    /// # Errors
    ///
    /// Returns an error when any exact descendant is unavailable or the bundle
    /// fails repository authentication.
    pub fn publish_executor_finding_candidate(
        &self,
        bundle: &FindingCandidateBundle,
        authenticator: &dyn FindingExactCheckpointAuthenticator,
    ) -> Result<FindingCandidateBundleId, CampaignRepositoryError> {
        let expected = bundle.id()?;
        if self.repository.blobs.contains(expected.content_id())? {
            let published = self.repository.load_finding_candidate_bundle(expected)?;
            if &published != bundle {
                return Err(CampaignRepositoryError::Integrity {
                    reason: "prepared-finding-bundle-publication-mismatch",
                });
            }
            return Ok(expected);
        }

        self.repository
            .publish_finding_candidate_bundle_with_authenticator(bundle, authenticator)
    }

    /// Publishes one executor-prepared native finding replay record.
    ///
    /// # Errors
    ///
    /// Returns an error when the reproduction or observed-signature closure is
    /// unavailable or inconsistent.
    pub fn publish_executor_finding_triage_replay_evidence(
        &self,
        evidence: &FindingTriageReplayEvidence,
    ) -> Result<FindingTriageReplayEvidenceId, CampaignRepositoryError> {
        self.repository
            .publish_finding_triage_replay_evidence(evidence)
    }
}
