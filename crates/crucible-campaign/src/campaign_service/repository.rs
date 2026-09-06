//! Principal authorization and semantic repository dispatch for campaign services.
//!
//! This adapter validates operational authority before invoking repository
//! mutations or queries, then binds responses to the authenticated request.
//! Repository and store failures map to stable service-boundary errors here.

use super::*;

/// Error from the repository-backed campaign-service adapter.
#[derive(Debug, Error)]
pub enum RepositoryCampaignServiceError {
    /// Principal authorization denied or was unavailable.
    #[error(transparent)]
    Authorization(#[from] CampaignAuthorizationError),
    /// The semantic repository owner rejected the operation.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Response construction or binding failed.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
}

impl CampaignServiceFailureSource for RepositoryCampaignServiceError {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        match self {
            Self::Authorization(CampaignAuthorizationError::Unauthorized) => {
                CampaignServiceFailure::Unauthorized
            }
            Self::Authorization(CampaignAuthorizationError::Unavailable) => {
                CampaignServiceFailure::AuthorizationUnavailable
            }
            Self::Repository(error) => repository_service_failure(error),
            Self::Codec(_) => CampaignServiceFailure::IntegrityFailure,
        }
    }
}

impl CampaignServiceFailureSource for CampaignRepositoryError {
    fn campaign_service_failure(&self) -> CampaignServiceFailure {
        repository_service_failure(self)
    }
}

pub(super) fn repository_service_failure(
    error: &CampaignRepositoryError,
) -> CampaignServiceFailure {
    match error {
        CampaignRepositoryError::Budget(_) => CampaignServiceFailure::ResourceExhausted,
        CampaignRepositoryError::Store(error) => store_service_failure(error),
        CampaignRepositoryError::Codec(_) => CampaignServiceFailure::IntegrityFailure,
        CampaignRepositoryError::Merkle(crate::CampaignStoreError::Store(error)) => {
            store_service_failure(error)
        }
        CampaignRepositoryError::Merkle(_) => CampaignServiceFailure::IntegrityFailure,
        CampaignRepositoryError::AlreadyExists => CampaignServiceFailure::AlreadyExists,
        CampaignRepositoryError::NotFound => CampaignServiceFailure::NotFound,
        CampaignRepositoryError::Stale { expected, current } => CampaignServiceFailure::Stale {
            expected: *expected,
            current: *current,
        },
        CampaignRepositoryError::CommandReuse => CampaignServiceFailure::CommandReuse,
        CampaignRepositoryError::RefConflict { .. } => CampaignServiceFailure::ConcurrentUpdate,
        CampaignRepositoryError::InvalidRequest { .. } => CampaignServiceFailure::InvalidRequest,
        CampaignRepositoryError::Integrity { .. } => CampaignServiceFailure::IntegrityFailure,
        CampaignRepositoryError::InvalidTransition { state } => {
            CampaignServiceFailure::InvalidTransition { state: *state }
        }
        CampaignRepositoryError::Poisoned => CampaignServiceFailure::IntegrityFailure,
    }
}

pub(super) fn store_service_failure(error: &StoreError) -> CampaignServiceFailure {
    match error {
        StoreError::Unauthorized => CampaignServiceFailure::BackendUnauthorized,
        StoreError::Quota => CampaignServiceFailure::ResourceExhausted,
        StoreError::NotFound { .. }
        | StoreError::Unavailable
        | StoreError::Io { .. }
        | StoreError::StreamIo { .. } => CampaignServiceFailure::Unavailable,
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
        | StoreError::Poisoned { .. }
        | StoreError::Unsupported { .. } => CampaignServiceFailure::IntegrityFailure,
    }
}

/// Principal-aware direct adapter over the semantic campaign repository owner.
pub struct RepositoryCampaignService<'a, A> {
    repository: &'a CampaignRepository,
    authorizer: A,
    operational_status: Option<&'a dyn CampaignOperationalStatusProvider>,
}

impl<'a, A> RepositoryCampaignService<'a, A> {
    /// Creates a direct service with mandatory principal authorization.
    #[must_use]
    pub const fn new(repository: &'a CampaignRepository, authorizer: A) -> Self {
        Self {
            repository,
            authorizer,
            operational_status: None,
        }
    }

    /// Installs the daemon owner that supplies generation-bound operational evidence.
    #[must_use]
    pub const fn with_operational_status(
        mut self,
        operational_status: &'a dyn CampaignOperationalStatusProvider,
    ) -> Self {
        self.operational_status = Some(operational_status);
        self
    }
}

impl<A> CampaignService for RepositoryCampaignService<'_, A>
where
    A: CampaignPrincipalAuthorizer,
{
    type Error = RepositoryCampaignServiceError;

    fn list_campaigns(
        &self,
        request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, Self::Error> {
        self.authorizer.authorize_all_campaigns(
            request.principal(),
            CampaignServiceOperation::ListCampaigns,
            request.request_digest(),
        )?;
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-list-page-size-is-invalid",
            }
        })?;
        let page = self
            .repository
            .list_heads(request.after().map(CampaignName::as_str), limit)?;
        let mut entries = Vec::with_capacity(page.heads().len());
        for head in page.heads() {
            let state = self.repository.state_at_snapshot(head.snapshot_id())?;
            entries.push(CampaignListEntry::new(
                CampaignName::new(head.name())?,
                head.snapshot_id(),
                head.snapshot().lineage(),
                head.snapshot().active_policy(),
                state,
            ));
        }
        let next_after = page.next_after().map(CampaignName::new).transpose()?;
        Ok(ListCampaignsResponse::new(
            request,
            entries,
            next_after,
            page.visited_refs(),
        )?)
    }

    fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::CreateCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        match self.repository.create_from_stored(
            request.campaign().as_str(),
            request.lineage(),
            request.policy(),
        ) {
            Ok(head) => Ok(CreateCampaignResponse::new(
                request,
                head.snapshot_id(),
                false,
            )?),
            Err(CampaignRepositoryError::AlreadyExists) => {
                let genesis = self.repository.genesis(request.campaign().as_str())?;
                if genesis.snapshot().lineage() != request.lineage().id()?
                    || genesis.snapshot().active_policy() != request.policy().id()?
                {
                    return Err(CampaignRepositoryError::AlreadyExists.into());
                }
                Ok(CreateCampaignResponse::new(
                    request,
                    genesis.snapshot_id(),
                    true,
                )?)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        for campaign in [request.source_campaign(), request.target_campaign()] {
            self.authorizer.authorize(
                request.principal(),
                CampaignServiceOperation::DeriveCampaign,
                campaign,
                request.request_digest(),
            )?;
        }
        let result = self.repository.derive_campaign(
            request.source_campaign().as_str(),
            request.source_snapshot(),
            request.target_campaign().as_str(),
            request.policy(),
        )?;
        Ok(DeriveCampaignResponse::new(request, result)?)
    }

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        let (head, state) = self
            .repository
            .head_with_state(request.campaign().as_str())?;
        Ok(GetCampaignResponse::new(
            request,
            head.snapshot_id(),
            head.snapshot().lineage(),
            head.snapshot().active_policy(),
            state,
        )?)
    }

    fn get_campaign_status(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignStatus,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let semantic = self.repository.semantic_status_at(request.snapshot())?;
        let operational = self
            .operational_status
            .map_or(CampaignOperationalStatus::Unavailable, |provider| {
                provider.operational_status(request.campaign(), request.snapshot())
            });
        let current = self.repository.head(request.campaign().as_str())?;
        if current.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: current.snapshot_id(),
            }
            .into());
        }
        Ok(GetCampaignStatusResponse::new(
            request,
            CampaignStatusSummary::new(semantic, operational),
        )?)
    }

    fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignSnapshot,
            request.campaign(),
            request.request_digest(),
        )?;
        let snapshot = self
            .repository
            .snapshot_in_campaign(request.campaign().as_str(), request.snapshot())?;
        Ok(GetCampaignSnapshotResponse::new(request, snapshot)?)
    }

    fn watch_campaign(
        &self,
        request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::WatchCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        let (head, state) = self
            .repository
            .head_with_state(request.campaign().as_str())?;
        Ok(WatchCampaignResponse::new(
            request,
            head.snapshot_id(),
            head.snapshot().lineage(),
            head.snapshot().active_policy(),
            state,
        )?)
    }

    fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignGraph,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-query-page-size-is-invalid",
            }
        })?;
        let (page, proof) = self.repository.scan_graph_page(
            head.snapshot().roots().graph,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
            .collect();
        Ok(QueryCampaignGraphResponse::new(
            request,
            head.snapshot().clone(),
            entries,
            page.next_after(),
            proof,
        )?)
    }

    fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignGraphObject,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (object, proof) = self
            .repository
            .graph_object_with_proof(head.snapshot().roots().graph, request.key())?;
        Ok(GetCampaignGraphObjectResponse::new(
            request,
            head.snapshot().clone(),
            object,
            proof,
        )?)
    }

    fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignChoices,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-choice-query-page-size-is-invalid",
            }
        })?;
        let (page, index_proof, page_proof) = self.repository.scan_choice_page(
            head.snapshot().roots().graph,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(_, object)| {
                ChoiceOpportunityId::from_content_id(*object).map(CampaignChoiceEntry::new)
            })
            .collect::<Result<Vec<_>, CampaignCodecError>>()?;
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.opportunity()));
        Ok(QueryCampaignChoicesResponse::new(
            request,
            head.snapshot().clone(),
            entries,
            next_after,
            index_proof,
            page_proof,
        )?)
    }

    fn query_campaign_frontier(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignFrontier,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-frontier-query-page-size-is-invalid",
            }
        })?;
        let (page, index_proof, page_proof) = self.repository.scan_frontier_page(
            head.snapshot().roots().exploration,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(_, object)| self.repository.read_continuation_projection(*object))
            .collect::<Result<Vec<_>, CampaignRepositoryError>>()?;
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.request()));
        Ok(QueryCampaignFrontierResponse::new(
            request,
            head.snapshot().clone(),
            entries,
            next_after,
            index_proof,
            page_proof,
        )?)
    }

    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignFindings,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-finding-query-page-size-is-invalid",
            }
        })?;
        let (page, proof) = self.repository.scan_findings_page(
            head.snapshot().roots().findings,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(_, object)| self.repository.read_finding(*object))
            .collect::<Result<Vec<_>, CampaignRepositoryError>>()?;
        Ok(QueryCampaignFindingsResponse::new(
            request,
            head.snapshot().clone(),
            entries,
            page.next_after(),
            proof,
        )?)
    }

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignFindingObject,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (finding, proof) = self
            .repository
            .finding_with_proof(head.snapshot().roots().findings, request.finding())?;
        let object = match request.kind() {
            CampaignFindingObjectKind::Observation => CampaignFindingObject::Observation(
                self.repository
                    .read_observation(finding.observation().content_id())?,
            ),
            CampaignFindingObjectKind::LatestOccurrence => CampaignFindingObject::LatestOccurrence(
                self.repository
                    .read_observation(finding.latest_occurrence().content_id())?,
            ),
            CampaignFindingObjectKind::Reproduction => CampaignFindingObject::Reproduction(
                self.repository
                    .read_reproduction_artifact(finding.reproduction().content_id())?,
            ),
            CampaignFindingObjectKind::MinimizedReproduction => {
                let minimized =
                    finding
                        .minimized()
                        .ok_or(CampaignRepositoryError::InvalidRequest {
                            reason: "campaign-finding-has-no-minimized-reproduction",
                        })?;
                CampaignFindingObject::MinimizedReproduction(
                    self.repository
                        .read_reproduction_artifact(minimized.content_id())?,
                )
            }
        };
        Ok(GetCampaignFindingObjectResponse::new(
            request,
            head.snapshot().clone(),
            finding,
            object,
            proof,
        )?)
    }

    fn explain_campaign_attempt(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::ExplainCampaignAttempt,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let roots = head.snapshot().roots();
        let (attempt, attempt_proof) = self
            .repository
            .attempt_with_proof(roots.accounting, request.attempt())?;
        let (admission, admission_proof) = self
            .repository
            .attempt_execution_basis_with_proof(roots.accounting, request.attempt())?;
        let path = self.repository.load_branch_path(attempt.path())?;
        let (selection, proposal, proposal_proof, planner_step, planner_step_proof) =
            match attempt.start() {
                crate::AttemptStart::Discover { .. } => (None, None, None, None, None),
                crate::AttemptStart::Branch { selection, .. } => {
                    let resolved = self.repository.resolve_selection(selection)?;
                    let crate::AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    } = admission.role()
                    else {
                        return Err(CampaignRepositoryError::Integrity {
                            reason: "campaign-attempt-branch-execution-basis-has-no-proposal",
                        }
                        .into());
                    };
                    let (proposal, proof) = self
                        .repository
                        .proposal_with_proof(roots.exploration, proposal)?;
                    let (planner_step, planner_step_proof) = match proposal.planner_invocation() {
                        Some(invocation) => {
                            let (step, proof) =
                                self.repository.planner_step_for_invocation_with_proof(
                                    roots.coordination,
                                    invocation,
                                )?;
                            (Some(step), Some(proof))
                        }
                        None => (None, None),
                    };
                    (
                        Some(resolved.selection().clone()),
                        Some(proposal),
                        Some(proof),
                        planner_step,
                        planner_step_proof,
                    )
                }
            };
        let (observation, observation_proof) = self
            .repository
            .attempt_observation_with_proof(roots.observations, request.attempt())?;
        Ok(ExplainCampaignAttemptResponse::new(
            request,
            head.snapshot().clone(),
            attempt,
            admission,
            path,
            selection,
            proposal,
            planner_step,
            observation,
            attempt_proof,
            admission_proof,
            proposal_proof,
            planner_step_proof,
            observation_proof,
        )?)
    }

    fn get_campaign_planner_rankings(
        &self,
        request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignPlannerRankings,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (step, proof) = self
            .repository
            .planner_step_with_proof(head.snapshot().roots().coordination, request.step())?;
        let planner_request = self.repository.load_planner_request(step.request())?;
        Ok(GetCampaignPlannerRankingsResponse::new(
            request,
            head.snapshot().clone(),
            step,
            planner_request,
            proof,
        )?)
    }

    fn get_campaign_frontier_object(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignFrontierObject,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (projection_content, index_proof, object_proof) = self
            .repository
            .lookup_frontier_projection(head.snapshot().roots().exploration, request.request())?;
        let projection = self
            .repository
            .read_continuation_projection(projection_content)?;
        let object = self
            .repository
            .read_branch_request(request.request().content_id())?;
        Ok(GetCampaignFrontierObjectResponse::new(
            request,
            head.snapshot().clone(),
            projection,
            object,
            index_proof,
            object_proof,
        )?)
    }

    fn get_campaign_choice_object(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignChoiceObject,
            request.campaign(),
            request.request_digest(),
        )?;
        let snapshot = self
            .repository
            .snapshot_in_campaign(request.campaign().as_str(), request.snapshot())?;
        let (_, proof) = self.repository.graph_object_with_proof(
            snapshot.roots().graph,
            crate::repository::authoritative_choice_key(request.opportunity()),
        )?;
        let (opportunity, declaration, domain) = self
            .repository
            .load_choice_opportunity_dependencies(request.opportunity())?;
        let object = match request.kind() {
            CampaignChoiceObjectKind::Declaration => CampaignChoiceObject::Declaration(declaration),
            CampaignChoiceObjectKind::Domain => CampaignChoiceObject::Domain(domain),
        };
        Ok(GetCampaignChoiceObjectResponse::new(
            request,
            snapshot,
            opportunity,
            object,
            proof,
        )?)
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::ApplyCampaignCommand,
            request.campaign(),
            request.request_digest(),
        )?;
        let result = self
            .repository
            .apply_control(request.campaign().as_str(), request.command())?;
        Ok(ApplyCampaignCommandResponse::new(request, result)?)
    }

    fn pin_campaign(
        &self,
        request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::PinCampaign,
            request.campaign(),
            request.request_digest(),
        )?;
        let result = self
            .repository
            .apply_pin(request.campaign().as_str(), request.command())?;
        Ok(PinCampaignResponse::new(request, result)?)
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::SubmitBranchRequest,
            request.campaign(),
            request.request_digest(),
        )?;
        let result = match request.request().cause() {
            crate::BranchRequestCause::Operator(_) => {
                self.repository.submit_operator_branch_request(
                    request.campaign().as_str(),
                    request.expected_snapshot(),
                    request.request(),
                )?
            }
            crate::BranchRequestCause::ExhaustivePolicy(_)
            | crate::BranchRequestCause::ScenarioDefault(_) => {
                self.repository.submit_branch_request(
                    request.campaign().as_str(),
                    request.expected_snapshot(),
                    request.request(),
                )?
            }
            crate::BranchRequestCause::Planner(_) | crate::BranchRequestCause::Debugger(_) => {
                return Err(CampaignRepositoryError::Integrity {
                    reason: "branch-request-cause-requires-authority-specific-adapter",
                }
                .into());
            }
        };
        Ok(SubmitCampaignBranchResponse::new(request, result)?)
    }
}
