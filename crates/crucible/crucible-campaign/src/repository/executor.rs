//! Executor-facing campaign publication and recovery capability.

use super::*;
use crucible_store::content_store::PutReceipt;

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

/// GC-excluded immutable-object access for one executor finding handoff.
///
/// This capability admits replay-capture publication while its repository
/// guard protects prepublished roots until the finding candidate becomes an
/// operational root. It does not expose the backend or mutable campaign refs.
pub struct CampaignExecutorPublicationGuard<'a> {
    repository: &'a CampaignRepository,
    _gc_exclusion: CampaignRepositoryGcExclusionGuard<'a>,
}

impl CampaignExecutorStore {
    /// Creates a narrow executor capability over one campaign repository.
    #[must_use]
    pub const fn new(repository: Arc<CampaignRepository>) -> Self {
        Self { repository }
    }

    /// Excludes destructive GC while one attempt may use unpublished CAS roots.
    ///
    /// An exact terminal restart publishes a local v9 root for immediate
    /// restore while it remains outside durable campaign references.
    /// The caller retains this guard across execution, including every paused
    /// successor launch, so GC cannot remove objects between semantic decode
    /// and descriptor-backed materialization.
    ///
    /// # Errors
    ///
    /// Returns a repository error if shared ref-inventory exclusion is unavailable.
    pub fn acquire_execution_gc_exclusion_guard(
        &self,
    ) -> Result<CampaignRepositoryGcExclusionGuard<'_>, CampaignRepositoryError> {
        self.repository.acquire_gc_exclusion_guard()
    }

    /// Returns whether a selected capture requires an actual exact restore.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected request is missing or corrupt at its
    /// authenticated source snapshot.
    pub fn selected_capture_requires_exact_restore(
        &self,
        snapshot: CampaignSnapshotId,
        request: CampaignFactId,
    ) -> Result<bool, CampaignRepositoryError> {
        let capture = self
            .repository
            .savepoint_capture_request_at(snapshot, request)?
            .ok_or(CampaignRepositoryError::Integrity {
                reason: "selected exact capture request is missing",
            })?;
        Ok(capture.reason == crate::PUBLIC_EXACT_CAPTURE_REASON)
    }

    /// Acquires GC-excluded access for a finding publication handoff.
    ///
    /// The caller holds the returned guard from the first capture write until
    /// the assignment transition makes every capture manifest an operational
    /// root.
    ///
    /// # Errors
    ///
    /// Returns an error when GC exclusion cannot be acquired or the immutable
    /// backend lacks required durable storage capabilities.
    pub fn acquire_finding_replay_publication_guard(
        &self,
    ) -> Result<CampaignExecutorPublicationGuard<'_>, CampaignRepositoryError> {
        let capabilities = self.repository.blobs.capabilities();
        for (available, capability) in [
            (capabilities.durable, "durable"),
            (capabilities.streaming_read, "streaming-read"),
            (capabilities.streaming_put, "streaming-put"),
            (capabilities.conditional_create, "conditional-create"),
        ] {
            if !available {
                return Err(StoreError::Unsupported { capability }.into());
            }
        }
        let gc_exclusion = self.repository.acquire_gc_exclusion_guard()?;
        Ok(CampaignExecutorPublicationGuard {
            repository: &self.repository,
            _gc_exclusion: gc_exclusion,
        })
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

    /// Loads an admission-authenticated attempt timeout policy for local supervision.
    ///
    /// The modeled bounds are already part of the canonical attempt stop. The
    /// host watchdog is read from the same immutable policy selected by the
    /// admission, never from the current mutable campaign head.
    ///
    /// # Errors
    ///
    /// Returns an error when the admission, attempt, lineage, or policy cannot
    /// be authenticated from the exact execution basis.
    pub fn load_attempt_timeout_policy(
        &self,
        lineage: CampaignLineageId,
        attempt: AttemptId,
        basis: AttemptRetentionPolicyBasis,
    ) -> Result<Option<crate::CampaignAttemptTimeoutPolicy>, CampaignRepositoryError> {
        self.repository
            .validate_attempt_retention_policy_basis(lineage, attempt, basis)?;
        self.repository
            .read_policy(basis.policy().content_id())
            .map(|policy| policy.attempt_timeout_policy())
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

    /// Starts a streamed selection resolver over the repository.
    ///
    /// The resolver authenticates one selection per call and shares decoded
    /// declarations and domains through bounded caches, so callers can fold
    /// over any number of selections.
    #[must_use]
    pub fn selection_resolver(&self) -> SelectionResolver<'_> {
        SelectionResolver::new(&self.repository)
    }

    /// Starts a streamed resolver whose resident decoded records stay within a limit.
    ///
    /// The limit covers the resolver's cached declarations and domains plus
    /// every uncached record of the selection being resolved. It lets an
    /// executor reserve for the decoded representation before resolution
    /// allocates it. Values a caller keeps after [`SelectionResolver::resolve`]
    /// returns are the caller's to account for.
    #[must_use]
    pub fn selection_resolver_within(
        &self,
        maximum_resident_canonical_bytes: usize,
    ) -> SelectionResolver<'_> {
        SelectionResolver::within(&self.repository, maximum_resident_canonical_bytes)
    }

    /// Starts a streamed resolver that also serves one unpublished candidate's selections.
    ///
    /// An executor may need to replay a configuration produced by its current
    /// execution before that observation has entered the repository. Selections
    /// carried by `owned` are authenticated by [`ObservationCandidate`]'s
    /// constructor; every other selection is resolved through the repository.
    ///
    /// # Errors
    ///
    /// Returns an error when an owned selection cannot be identified.
    pub fn selection_resolver_with_owned_candidate<'a>(
        &'a self,
        owned: &'a ObservationCandidate,
    ) -> Result<SelectionResolver<'a>, CampaignRepositoryError> {
        SelectionResolver::with_owned_candidate(&self.repository, owned)
    }

    /// Visits each selection of `ids` in order, fully authenticated.
    ///
    /// Repeated identities are visited repeatedly. Shared dependencies are
    /// decoded once while they fit the resolver's bounded caches.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a repository error when any
    /// exact selection reference is missing, corrupt, or inconsistent.
    pub fn for_each_resolved_selection<E>(
        &self,
        ids: &[SelectionId],
        mut visit: impl FnMut(ResolvedSelection) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        let mut resolver = self.selection_resolver();
        for id in ids {
            visit(resolver.resolve(*id)?)?;
        }
        Ok(())
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
                artifact.reproduction_payload().clone(),
                minimization.clone(),
            ),
            None => self.repository.publish_reproduction_artifact(
                artifact.scenario(),
                artifact.scenario_artifact(),
                artifact.configuration(),
                artifact.configuration_artifact(),
                artifact.finding_fingerprint(),
                artifact.reproduction_payload().clone(),
            ),
        }
    }

    /// Publishes one executor-verified reproduction payload segment.
    ///
    /// # Errors
    ///
    /// Returns the errors of
    /// [`CampaignRepository::publish_reproduction_payload_segment`].
    pub fn publish_executor_reproduction_payload_segment(
        &self,
        segment: ReproductionPayloadSegment,
        bytes: &[u8],
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.repository
            .publish_reproduction_payload_segment(segment, bytes)
    }

    /// Publishes one executor-verified attempt-log segment of a triage replay.
    ///
    /// # Errors
    ///
    /// Returns the errors of
    /// [`CampaignRepository::publish_finding_triage_replay_log_segment`].
    pub fn publish_executor_triage_replay_log_segment(
        &self,
        segment: crate::FindingTriageReplayLogSegment,
        bytes: &[u8],
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.repository
            .publish_finding_triage_replay_log_segment(segment, bytes)
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

impl CampaignExecutorPublicationGuard<'_> {
    /// Reads one capture leaf or manifest while GC remains excluded.
    ///
    /// # Errors
    ///
    /// Returns an error for another kind/schema or when the backend cannot
    /// return an authenticated handle.
    pub fn read_finding_replay_capture_object(
        &self,
        id: ContentId,
    ) -> Result<BlobHandle, CampaignRepositoryError> {
        self.repository.read_finding_replay_capture_object(id)
    }

    /// Idempotently writes one capture leaf or manifest while GC remains excluded.
    ///
    /// # Errors
    ///
    /// Returns an error for another kind/schema or when durable placement fails.
    pub fn put_finding_replay_capture_object(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, CampaignRepositoryError> {
        validate_finding_replay_capture_object_id(id)?;
        self.repository
            .blobs
            .put_if_absent(id, source)
            .map_err(Into::into)
    }
}

impl CampaignRepository {
    /// Reads one immutable finding replay capture manifest or leaf.
    ///
    /// This read-only path is used after an imported archive has authenticated
    /// the complete finding closure. Publication still requires the separate
    /// GC-excluded [`CampaignExecutorPublicationGuard`].
    ///
    /// # Errors
    ///
    /// Returns an error for another kind/schema or when the backend cannot
    /// return an authenticated handle.
    pub fn read_finding_replay_capture_object(
        &self,
        id: ContentId,
    ) -> Result<BlobHandle, CampaignRepositoryError> {
        validate_finding_replay_capture_object_id(id)?;
        self.blobs.read(id, None).map_err(Into::into)
    }
}

/// Admits a current capture manifest or one of its version 1 trace leaves.
fn validate_finding_replay_capture_object_id(id: ContentId) -> Result<(), CampaignRepositoryError> {
    let admitted = match id.kind() {
        ObjectKind::ExactManifest => {
            crate::FindingReplayCaptureEvidenceId::from_manifest_content_id(id).is_ok()
        }
        ObjectKind::Trace => id.schema_version() == 1,
        _ => false,
    };
    if !admitted {
        return Err(integrity("finding-replay-capture-object-kind"));
    }
    Ok(())
}

impl CampaignRepositoryError {
    /// Maps read-only executor validation failure into the wire rejection vocabulary.
    ///
    /// Missing or temporarily unreadable immutable input remains retryable under
    /// a fresh assignment. Authenticated incompatibility and corrupt canonical
    /// structure fail stably, while backend authorization remains distinct.
    #[must_use]
    pub fn executor_rejection(&self) -> ExecutorRejection {
        match self {
            Self::Store(error) => store_executor_rejection(error),
            Self::Merkle(crate::CampaignStoreError::Store(error)) => {
                store_executor_rejection(error)
            }
            Self::NotFound | Self::Poisoned | Self::Scratch { .. } => {
                ExecutorRejection::UnavailableInput
            }
            Self::Budget(_)
            | Self::Codec(_)
            | Self::SelectionResolutionBudgetExceeded { .. }
            | Self::Merkle(_)
            | Self::AlreadyExists
            | Self::Stale { .. }
            | Self::CommandReuse
            | Self::RefConflict { .. }
            | Self::InvalidRequest { .. }
            | Self::Integrity { .. }
            | Self::InvalidTransition { .. } => ExecutorRejection::Incompatible,
        }
    }
}

fn store_executor_rejection(error: &StoreError) -> ExecutorRejection {
    match error {
        StoreError::NotFound { .. }
        | StoreError::Quota
        | StoreError::Unavailable
        | StoreError::Poisoned { .. }
        | StoreError::Io { .. }
        | StoreError::StreamIo { .. } => ExecutorRejection::UnavailableInput,
        StoreError::Unauthorized => ExecutorRejection::Unauthorized,
        StoreError::Corrupt { .. }
        | StoreError::InvalidId
        | StoreError::InvalidRefName { .. }
        | StoreError::InvalidRange { .. }
        | StoreError::InvalidComposition { .. }
        | StoreError::InvalidGraph { .. }
        | StoreError::DurabilityUnsatisfied { .. }
        | StoreError::Incompatible
        | StoreError::InvalidSourceLength { .. }
        | StoreError::MultipartCleanupRequired
        | StoreError::Unsupported { .. } => ExecutorRejection::Incompatible,
    }
}
