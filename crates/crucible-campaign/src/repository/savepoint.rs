//! Durable attempt-stop savepoint capture intent and projection.
//!
//! One accepted request binds an existing immutable attempt to its exact
//! starting configuration artifact. Capture is
//! queued in a separate operational scope: it does not admit a semantic attempt,
//! consume budget, or advance the strict semantic commit frontier.

use super::*;
/// Maximum accounting entries consumed by one pending-capture projection page.
pub const MAX_SAVEPOINT_CAPTURE_SCAN_PAGE_ITEMS: usize = 10_000;

/// Opaque continuation for one pending savepoint-capture scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavepointCaptureCursor {
    snapshot: CampaignSnapshotId,
    accounting_after: CampaignHash,
}

/// One immutable capture request awaiting a terminal coordinator disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSavepointCapture {
    request: CampaignFactId,
    capture: SavepointCaptureRequest,
}

impl PendingSavepointCapture {
    /// Returns the immutable fact that owns this capture's operational scope.
    #[must_use]
    pub const fn request(&self) -> CampaignFactId {
        self.request
    }

    /// Returns the authenticated immutable capture description.
    #[must_use]
    pub const fn capture(&self) -> &SavepointCaptureRequest {
        &self.capture
    }
}

/// One bounded page of unresolved operational savepoint captures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSavepointCapturePage {
    snapshot: CampaignSnapshotId,
    captures: Vec<PendingSavepointCapture>,
    next: Option<SavepointCaptureCursor>,
}

impl PendingSavepointCapturePage {
    /// Returns the exact immutable snapshot projected by this page.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns unresolved capture requests in canonical accounting-key order.
    #[must_use]
    pub fn captures(&self) -> &[PendingSavepointCapture] {
        &self.captures
    }

    /// Returns the exclusive cursor for the next bounded page.
    #[must_use]
    pub const fn next(&self) -> Option<SavepointCaptureCursor> {
        self.next
    }
}

/// Stable result of accepting or replaying one savepoint capture request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavepointCaptureResult {
    /// Snapshot named by the accepted request's precondition.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by the accepted request.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact immutable attempt whose stop boundary is captured.
    pub attempt: AttemptId,
    /// Immutable campaign fact that owns the operational capture scope.
    pub request: CampaignFactId,
    /// Exact configuration artifact bound to the capture.
    pub configuration: ConfigurationArtifactId,
    /// Whether this call observed a previously committed request.
    pub replayed: bool,
}

/// Stable result of resolving one operational savepoint capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavepointCaptureResolutionResult {
    /// Snapshot named by the accepted resolution's precondition.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot first produced by the accepted resolution.
    pub new_snapshot: CampaignSnapshotId,
    /// Immutable capture request fact that reached a terminal outcome.
    pub request: CampaignFactId,
    /// Authenticated operational outcome recorded by the coordinator.
    pub outcome: SavepointCaptureOutcome,
    /// Whether this call observed a previously committed resolution.
    pub replayed: bool,
}

impl CampaignRepository {
    /// Atomically records one request to capture an immutable attempt at its stop.
    ///
    /// Command lookup precedes stale-precondition checking. An exact retry
    /// therefore returns the original successor after later mutations. The
    /// immutable attempt description is reachable from the capture fact but is
    /// absent from ordinary admission indexes and budgets.
    ///
    /// # Errors
    ///
    /// Returns an error for command reuse, stale input, an inactive campaign,
    /// an invalid configuration or stop boundary, publication failure, or
    /// final ref conflict.
    pub fn request_savepoint_capture(
        &self,
        name: &str,
        request: &SavepointCaptureRequest,
    ) -> Result<SavepointCaptureResult, CampaignRepositoryError> {
        request.validate()?;
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, command_key)?
        {
            return match self.read_fact(fact_content)? {
                CampaignFact::SavepointCaptureRequested(prior) if prior == *request => {
                    self.find_savepoint_capture_result(current_content, request, true)
                }
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::BranchRequestAccepted { .. }
                | CampaignFact::PinCommandAccepted(_)
                | CampaignFact::DiscoveryRequested(_)
                | CampaignFact::SavepointCaptureRequested(_)
                | CampaignFact::SavepointCaptureResolved(_) => {
                    Err(CampaignRepositoryError::CommandReuse)
                }
                _ => Err(integrity("command-index-value-is-not-mutation-fact")),
            };
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if request.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: request.expected_snapshot,
                current: current_id,
            });
        }
        self.savepoint_capture_basis(&current, request)?;
        let transition = CampaignFact::SavepointCaptureRequested(request.clone());
        let transition_content = self.put_fact(&transition)?;
        let transition_id = CampaignFactId::from_content_id(transition_content)?;
        let accounting_upserts = BTreeMap::from([
            (command_key, transition_content),
            (
                savepoint_capture_request_key(transition_id),
                transition_content,
            ),
        ]);
        let mut accounting = current.snapshot.roots().accounting;
        for (key, value) in accounting_upserts {
            accounting = self.merkle.insert(accounting, key, value)?.content_id();
        }
        let mut roots = current.snapshot.roots();
        roots.accounting = accounting;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(SavepointCaptureResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    attempt: request.attempt,
                    request: transition_id,
                    configuration: request.configuration,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Resolves one capture after authenticating its exact scoped status response.
    ///
    /// This transition records no executor-local identity or checkpoint root;
    /// those remain authoritative in the scoped operational ledger. Command
    /// replay is resolved before the stale-snapshot precondition.
    ///
    /// # Errors
    ///
    /// Returns an error for command reuse, stale input, a missing or already
    /// resolved capture, assignment/request mismatch, an unauthenticated status
    /// response, a status that differs from the requested outcome, publication
    /// failure, or final ref conflict.
    pub fn resolve_savepoint_capture(
        &self,
        name: &str,
        resolution: &SavepointCaptureResolution,
        assignment: &SubmitAttemptRequest,
        status: &GetAttemptExecutionResponse,
    ) -> Result<SavepointCaptureResolutionResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let command_key = map_key_hash("accounting.command", resolution.command.as_hash());
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, command_key)?
        {
            return match self.read_fact(fact_content)? {
                CampaignFact::SavepointCaptureResolved(prior) if prior == *resolution => {
                    self.find_savepoint_capture_resolution_result(current_content, resolution, true)
                }
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::BranchRequestAccepted { .. }
                | CampaignFact::PinCommandAccepted(_)
                | CampaignFact::DiscoveryRequested(_)
                | CampaignFact::SavepointCaptureRequested(_)
                | CampaignFact::SavepointCaptureResolved(_) => {
                    Err(CampaignRepositoryError::CommandReuse)
                }
                _ => Err(integrity("command-index-value-is-not-mutation-fact")),
            };
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if resolution.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: resolution.expected_snapshot,
                current: current_id,
            });
        }

        let capture = self
            .savepoint_capture_request_at(current_id, resolution.request)?
            .ok_or(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-request-is-not-in-current-history",
            })?;
        let query = GetAttemptExecutionRequest::new(assignment, status.execution())?;
        status.validate_for(&query)?;
        validate_savepoint_capture_status(resolution.outcome, status.disposition())?;
        validate_savepoint_capture_assignment(
            current.snapshot.lineage(),
            resolution.request,
            &capture,
            assignment,
        )?;
        let prior_resolution = self.merkle.get(
            current.snapshot.roots().accounting,
            savepoint_capture_resolution_key(resolution.request),
        )?;
        validate_resolution_predecessor(self, resolution, prior_resolution)?;
        let transition = CampaignFact::SavepointCaptureResolved(resolution.clone());
        let transition_content = self.put_fact(&transition)?;
        let accounting_upserts = BTreeMap::from([
            (command_key, transition_content),
            (
                savepoint_capture_resolution_key(resolution.request),
                transition_content,
            ),
        ]);
        let mut accounting = current.snapshot.roots().accounting;
        for (key, value) in accounting_upserts {
            accounting = self.merkle.insert(accounting, key, value)?.content_id();
        }

        let mut roots = current.snapshot.roots();
        roots.accounting = accounting;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(SavepointCaptureResolutionResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    request: resolution.request,
                    outcome: resolution.outcome,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Returns one authenticated capture request fact at a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot closure, intent projection, or
    /// attempt/configuration binding is corrupt or unavailable.
    pub fn savepoint_capture_request_at(
        &self,
        snapshot: CampaignSnapshotId,
        capture: CampaignFactId,
    ) -> Result<Option<SavepointCaptureRequest>, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        self.savepoint_capture_request_in_loaded(&loaded, capture)
    }

    fn savepoint_capture_request_in_loaded(
        &self,
        loaded: &LoadedSnapshot,
        capture: CampaignFactId,
    ) -> Result<Option<SavepointCaptureRequest>, CampaignRepositoryError> {
        let Some(content) = self.merkle.get(
            loaded.snapshot.roots().accounting,
            savepoint_capture_request_key(capture),
        )?
        else {
            return Ok(None);
        };
        let CampaignFact::SavepointCaptureRequested(request) = self.read_fact(content)? else {
            return Err(integrity(
                "savepoint-capture-index-value-is-not-capture-request",
            ));
        };
        if content != capture.content_id() {
            return Err(integrity("savepoint-capture-request-index-mismatch"));
        }
        self.validate_persisted_savepoint_capture(loaded, content, &request)?;
        Ok(Some(request))
    }

    /// Returns the latest authenticated resolution for one capture at a snapshot.
    ///
    /// A ready capture may be followed only by an explicit discarded
    /// resolution. The returned value therefore represents the current durable
    /// retention disposition for the request.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot closure, resolution index, or fact
    /// correspondence is malformed or unavailable.
    pub fn savepoint_capture_resolution_at(
        &self,
        snapshot: CampaignSnapshotId,
        capture: CampaignFactId,
    ) -> Result<Option<SavepointCaptureResolution>, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        let Some(content) = self.merkle.get(
            loaded.snapshot.roots().accounting,
            savepoint_capture_resolution_key(capture),
        )?
        else {
            return Ok(None);
        };
        let CampaignFact::SavepointCaptureResolved(resolution) = self.read_fact(content)? else {
            return Err(integrity(
                "savepoint-capture-resolution-index-value-is-not-resolution",
            ));
        };
        if resolution.request != capture {
            return Err(integrity("savepoint-capture-resolution-index-mismatch"));
        }
        Ok(Some(resolution))
    }

    /// Projects one bounded page of captures without a terminal disposition.
    ///
    /// The cursor is bound to the immutable campaign snapshot. A head change
    /// returns a typed stale error so the coordinator restarts from the new
    /// accounting root.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing campaign, a stale cursor, an invalid scan
    /// limit, or malformed capture accounting and fact closure.
    pub fn project_pending_savepoint_captures(
        &self,
        name: &str,
        cursor: Option<SavepointCaptureCursor>,
        scan_limit: usize,
    ) -> Result<PendingSavepointCapturePage, CampaignRepositoryError> {
        if scan_limit == 0 || scan_limit > MAX_SAVEPOINT_CAPTURE_SCAN_PAGE_ITEMS {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-scan-limit-is-invalid",
            });
        }
        let head = self.head(name)?;
        let snapshot = head.snapshot_id();
        let after = match cursor {
            Some(cursor) if cursor.snapshot != snapshot => {
                return Err(CampaignRepositoryError::Stale {
                    expected: cursor.snapshot,
                    current: snapshot,
                });
            }
            Some(cursor) => Some(cursor.accounting_after),
            None => None,
        };
        let accounting = head.snapshot().roots().accounting;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        let page = self.merkle.scan(accounting, after, scan_limit)?;
        let mut captures = Vec::new();
        for (key, content) in page.entries() {
            let envelope = self.read_envelope(*content)?;
            if envelope.record_kind() != crate::CampaignRecordKind::Fact {
                continue;
            }
            let fact = CampaignFact::from_canonical_bytes(envelope.body())?;
            let CampaignFact::SavepointCaptureRequested(capture) = fact else {
                continue;
            };
            let request = CampaignFactId::from_content_id(*content)?;
            if *key != savepoint_capture_request_key(request) {
                continue;
            }
            self.validate_persisted_savepoint_capture(&loaded, *content, &capture)?;
            if self
                .merkle
                .get(accounting, savepoint_capture_resolution_key(request))?
                .is_none()
            {
                captures.push(PendingSavepointCapture { request, capture });
            }
        }
        Ok(PendingSavepointCapturePage {
            snapshot,
            captures,
            next: page
                .next_after()
                .map(|accounting_after| SavepointCaptureCursor {
                    snapshot,
                    accounting_after,
                }),
        })
    }

    pub(super) fn savepoint_capture_basis(
        &self,
        parent: &LoadedSnapshot,
        request: &SavepointCaptureRequest,
    ) -> Result<Attempt, CampaignRepositoryError> {
        if request.expected_snapshot != parent.snapshot.id()? {
            return Err(integrity("savepoint-capture-precondition-parent-mismatch"));
        }
        let state = self
            .current_lifecycle(parent.envelope.content_id())?
            .visible;
        if state != CampaignState::Running {
            return Err(CampaignRepositoryError::InvalidTransition { state });
        }

        self.validate_savepoint_capture_basis(parent, request)
    }

    pub(super) fn validate_savepoint_capture_basis(
        &self,
        parent: &LoadedSnapshot,
        request: &SavepointCaptureRequest,
    ) -> Result<Attempt, CampaignRepositoryError> {
        let roots = parent.snapshot.roots();
        let artifact = self.read_configuration_artifact(request.configuration.content_id())?;
        if artifact.configuration() != request.semantic_configuration
            || self.merkle.get(
                roots.graph,
                map_key_hash(
                    "graph.configuration",
                    request.semantic_configuration.as_hash(),
                ),
            )? != Some(request.configuration.content_id())
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-configuration-is-not-authoritative",
            });
        }
        request.stop.validate()?;
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if let StopCondition::NamedBoundary(name) = &request.stop
            && !policy.stop_conditions().contains(name)
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-stop-boundary-is-not-in-active-policy",
            });
        }

        let attempt = self.load_attempt(request.attempt)?;
        let start_configuration = match attempt.start() {
            AttemptStart::Discover { configuration } => configuration,
            AttemptStart::Branch { parent, .. } => parent,
        };
        if start_configuration != request.configuration || attempt.stop() != &request.stop {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-attempt-does-not-match-request",
            });
        }
        Ok(attempt)
    }

    fn validate_persisted_savepoint_capture(
        &self,
        snapshot: &LoadedSnapshot,
        transition_content: ContentId,
        request: &SavepointCaptureRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        if self.merkle.get(
            roots.accounting,
            savepoint_capture_request_key(CampaignFactId::from_content_id(transition_content)?),
        )? != Some(transition_content)
        {
            return Err(integrity("savepoint-capture-persisted-index-mismatch"));
        }
        let attempt = self.read_attempt(request.attempt.content_id())?;
        let start_configuration = match attempt.start() {
            AttemptStart::Discover { configuration } => configuration,
            AttemptStart::Branch { parent, .. } => parent,
        };
        if start_configuration != request.configuration || attempt.stop() != &request.stop {
            return Err(integrity("savepoint-capture-persisted-attempt-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_savepoint_capture_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        request: &SavepointCaptureRequest,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("savepoint-capture-changed-lineage-or-policy"));
        }
        self.validate_savepoint_capture_basis(parent, request)?;

        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity("savepoint-capture-changed-unrelated-root"));
        }
        let transition_id = CampaignFactId::from_content_id(transition_content)?;
        let accounting_upserts = BTreeMap::from([
            (
                map_key_hash("accounting.command", request.command.as_hash()),
                transition_content,
            ),
            (
                savepoint_capture_request_key(transition_id),
                transition_content,
            ),
        ]);
        if !self.merkle.equals_after_upserts(
            prior.accounting,
            next.accounting,
            &accounting_upserts,
        )? {
            return Err(integrity("savepoint-capture-accounting-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("savepoint-capture-coordination-root-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_savepoint_capture_resolution_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        resolution: &SavepointCaptureResolution,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "savepoint-capture-resolution-changed-lineage-or-policy",
            ));
        }
        if resolution.expected_snapshot != parent.snapshot.id()? {
            return Err(integrity(
                "savepoint-capture-resolution-precondition-parent-mismatch",
            ));
        }
        self.savepoint_capture_request_in_loaded(parent, resolution.request)?
            .ok_or_else(|| {
                integrity("savepoint-capture-resolution-request-is-not-in-parent-history")
            })?;
        let prior_resolution = self.merkle.get(
            parent.snapshot.roots().accounting,
            savepoint_capture_resolution_key(resolution.request),
        )?;
        validate_resolution_predecessor(self, resolution, prior_resolution)
            .map_err(|_| integrity("savepoint-capture-resolution-predecessor-mismatch"))?;
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity(
                "savepoint-capture-resolution-changed-unrelated-root",
            ));
        }
        let accounting_upserts = BTreeMap::from([
            (
                map_key_hash("accounting.command", resolution.command.as_hash()),
                transition_content,
            ),
            (
                savepoint_capture_resolution_key(resolution.request),
                transition_content,
            ),
        ]);
        if !self.merkle.equals_after_upserts(
            prior.accounting,
            next.accounting,
            &accounting_upserts,
        )? {
            return Err(integrity(
                "savepoint-capture-resolution-accounting-root-mismatch",
            ));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity(
                "savepoint-capture-resolution-coordination-root-mismatch",
            ));
        }
        Ok(())
    }
}

fn validate_savepoint_capture_assignment(
    lineage: CampaignLineageId,
    request_id: CampaignFactId,
    capture: &SavepointCaptureRequest,
    assignment: &SubmitAttemptRequest,
) -> Result<(), CampaignRepositoryError> {
    let AttemptStartMode::SavepointCapture {
        request,
        configuration,
    } = assignment.start_mode()
    else {
        return Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-resolution-assignment-is-not-scoped-capture",
        });
    };
    if request != request_id
        || configuration != capture.configuration
        || assignment.lineage() != lineage
        || assignment.attempt() != capture.attempt
    {
        return Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-resolution-assignment-basis-mismatch",
        });
    }
    Ok(())
}

fn validate_savepoint_capture_status(
    outcome: SavepointCaptureOutcome,
    disposition: GetAttemptExecutionDisposition,
) -> Result<(), CampaignRepositoryError> {
    let matches = matches!(
        (outcome, disposition),
        (
            SavepointCaptureOutcome::Ready,
            GetAttemptExecutionDisposition::Paused { .. }
        ) | (
            SavepointCaptureOutcome::Canceled,
            GetAttemptExecutionDisposition::Canceled
        ) | (
            SavepointCaptureOutcome::Failed,
            GetAttemptExecutionDisposition::TerminalFailure
        ) | (
            SavepointCaptureOutcome::Discarded,
            GetAttemptExecutionDisposition::Paused { .. }
        )
    );
    if matches {
        Ok(())
    } else {
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-resolution-status-mismatch",
        })
    }
}

fn validate_resolution_predecessor(
    repository: &CampaignRepository,
    resolution: &SavepointCaptureResolution,
    prior_content: Option<ContentId>,
) -> Result<(), CampaignRepositoryError> {
    match (resolution.outcome, prior_content) {
        (SavepointCaptureOutcome::Discarded, Some(content)) => {
            let CampaignFact::SavepointCaptureResolved(prior) = repository.read_fact(content)?
            else {
                return Err(integrity(
                    "savepoint-capture-resolution-index-value-is-not-resolution",
                ));
            };
            if prior.request == resolution.request
                && prior.outcome == SavepointCaptureOutcome::Ready
            {
                Ok(())
            } else {
                Err(CampaignRepositoryError::InvalidRequest {
                    reason: "savepoint-capture-discard-requires-ready-resolution",
                })
            }
        }
        (SavepointCaptureOutcome::Discarded, None) => {
            Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-discard-requires-ready-resolution",
            })
        }
        (_, None) => Ok(()),
        (_, Some(_)) => Err(CampaignRepositoryError::InvalidRequest {
            reason: "savepoint-capture-is-already-resolved",
        }),
    }
}
