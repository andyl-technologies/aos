//! Service contracts.

use super::*;

/// Closed pure planner implementation without coordinator or host I/O authority.
pub trait PurePlannerEngine {
    /// Engine-specific deterministic evaluation failure.
    type Error;

    /// Evaluates one complete immutable planning request.
    ///
    /// # Errors
    ///
    /// Returns the engine-specific error when deterministic evaluation cannot
    /// produce a bounded result.
    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error>;
}

/// One supervised evaluation result with adapter-measured fuel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisedPlannerExecution<E> {
    result: Result<PlannerEngineOutput, E>,
    measured_fuel: u64,
}

impl<E> SupervisedPlannerExecution<E> {
    /// Binds an engine result to the supervisor's fuel measurement.
    #[must_use]
    pub const fn new(result: Result<PlannerEngineOutput, E>, measured_fuel: u64) -> Self {
        Self {
            result,
            measured_fuel,
        }
    }

    /// Separates the engine result from its measured fuel.
    pub fn into_parts(self) -> (Result<PlannerEngineOutput, E>, u64) {
        (self.result, self.measured_fuel)
    }
}

/// Killable supervisor for one bounded pure planner evaluation.
///
/// The supervisor, not the pure engine, owns the authoritative fuel
/// observation. A production implementation must enforce the request fuel
/// budget and a finite wall-clock deadline, observe cancellation, and terminate
/// an evaluation that exceeds any bound. This trait deliberately owns the
/// execution call instead of wrapping an uninterruptible in-process closure.
pub trait PlannerExecutionSupervisor<E: PurePlannerEngine> {
    /// Supervisor-specific execution or measurement failure.
    type Error;

    /// Executes one evaluation and returns its result with measured fuel.
    ///
    /// The returned fuel covers the complete operation, including an operation
    /// that returns an engine error. Implementations must not derive fuel from
    /// planner-provided claims.
    ///
    /// # Errors
    ///
    /// Returns the supervisor-specific error when the operation cannot be run,
    /// bounded, terminated, or measured authoritatively.
    fn execute(
        &mut self,
        engine: &mut E,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<E::Error>, Self::Error>;
}

/// Implementor-facing authenticated planner component service.
pub trait PlannerService {
    /// Component-specific transport or evaluation failure.
    type Error;

    /// Evaluates and authenticates one planner request.
    ///
    /// # Errors
    ///
    /// Returns the component-specific error when no authenticated submission
    /// can be produced. Semantic planner output remains untrusted until the
    /// checked client and coordinator validate it.
    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error>;
}

/// Supervised authority adapter over one pure planner engine.
pub struct AuthorizedPlannerService<E, M> {
    engine: E,
    supervisor: M,
    authority: PlannerAuthorityKey,
}

impl<E, M> AuthorizedPlannerService<E, M> {
    /// Binds a pure engine and supervised meter to planner authority.
    #[must_use]
    pub const fn new(engine: E, supervisor: M, authority: PlannerAuthorityKey) -> Self {
        Self {
            engine,
            supervisor,
            authority,
        }
    }

    /// Returns the engine and meter after component shutdown.
    #[must_use]
    pub fn into_parts(self) -> (E, M) {
        (self.engine, self.supervisor)
    }
}

impl<E: PurePlannerEngine, M: PlannerExecutionSupervisor<E>> PlannerService
    for AuthorizedPlannerService<E, M>
{
    type Error = AuthorizedPlannerServiceError<E::Error, M::Error>;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error> {
        let execution = self
            .supervisor
            .execute(&mut self.engine, request)
            .map_err(AuthorizedPlannerServiceError::Supervisor)?;
        let (output, fuel) = execution.into_parts();
        let output = output.map_err(AuthorizedPlannerServiceError::Engine)?;
        let measured = measured_planning_usage(request, output.proposal(), fuel)
            .map_err(AuthorizedPlannerServiceError::InvalidOutput)?;
        validate_planner_output(request, output.proposal(), measured)
            .map_err(AuthorizedPlannerServiceError::InvalidOutput)?;
        let submission = PlannerSubmission::authorize(
            &self.authority,
            request.expected_snapshot(),
            output.proposal,
            measured,
        )
        .map_err(AuthorizedPlannerServiceError::InvalidOutput)?;
        PlannerResponse::authorize(&self.authority, request, submission)
            .map_err(AuthorizedPlannerServiceError::InvalidOutput)
    }
}

/// Failure from a supervised planner authority adapter.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorizedPlannerServiceError<E, M> {
    /// The pure engine failed before producing output.
    #[error("pure planner engine failed: {0}")]
    Engine(E),
    /// The supervisor could not bound or measure the engine evaluation.
    #[error("planner execution supervisor failed: {0}")]
    Supervisor(M),
    /// The engine produced output outside the exact request contract.
    #[error(transparent)]
    InvalidOutput(CampaignCodecError),
}

/// Coordinator-facing checked client over one direct or RPC planner service.
pub struct PlannerClient<S> {
    service: S,
    authority: PlannerAuthorityKey,
}

impl<S> PlannerClient<S> {
    /// Wraps one component service with its exact verification authority.
    #[must_use]
    pub const fn new(service: S, authority: PlannerAuthorityKey) -> Self {
        Self { service, authority }
    }

    /// Returns the wrapped service after coordinator ownership ends.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.service
    }

    pub(crate) const fn authority(&self) -> &PlannerAuthorityKey {
        &self.authority
    }
}

impl<S: PlannerService> PlannerClient<S> {
    /// Evaluates a request and validates response authority and exact basis.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerClientError::Service`] when the component cannot
    /// produce a submission, or [`PlannerClientError::InvalidResponse`] when
    /// the response is unauthenticated or does not match the exact request.
    pub fn plan(
        &mut self,
        request: &PlannerRequest,
    ) -> Result<PlannerResponse, PlannerClientError<S::Error>> {
        let response = self
            .service
            .plan(request)
            .map_err(PlannerClientError::Service)?;
        if !response.verify(&self.authority) || !response.submission().verify(&self.authority) {
            return Err(PlannerClientError::InvalidResponse(
                CampaignCodecError::InvalidValue {
                    reason: "planner response authentication failed",
                },
            ));
        }
        response
            .validate_for(request)
            .map_err(PlannerClientError::InvalidResponse)?;
        Ok(response)
    }
}

/// Failure from the coordinator-facing checked planner client.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlannerClientError<E> {
    /// The direct or RPC planner component failed to produce a response.
    #[error("planner service failed: {0}")]
    Service(E),
    /// The component returned an unauthenticated or cross-request response.
    #[error(transparent)]
    InvalidResponse(CampaignCodecError),
}

pub(super) fn validate_planner_output(
    request: &PlannerRequest,
    proposal: &PlannerStepProposal,
    measured: PlanningUsage,
) -> Result<(), CampaignCodecError> {
    let invocation = request.invocation();
    let budget = invocation.budget();
    if proposal.invocation() != request.invocation_id()?
        || proposal.next_state().engine() != invocation.engine()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner response invocation or next-state engine mismatch",
        });
    }

    let claimed = proposal.usage_claim();
    if claimed.branch_requests > u64::from(budget.branch_requests())
        || claimed.proposals > u64::from(budget.proposals())
        || claimed.input_objects > u64::from(budget.input_objects())
        || claimed.input_bytes > budget.input_bytes()
        || claimed.fuel > budget.fuel()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner response usage claim exceeds budget",
        });
    }

    let (branch_requests, proposals) = match proposal.disposition() {
        PlannerProposalDisposition::Issue {
            branch_requests,
            proposals,
            ..
        } => (branch_requests.len(), proposals.len()),
        PlannerProposalDisposition::ContinueScan { .. } | PlannerProposalDisposition::NoWork => {
            (0, 0)
        }
    };
    if measured.branch_requests != usize_to_u64(branch_requests)?
        || measured.proposals != usize_to_u64(proposals)?
        || measured.branch_requests > u64::from(budget.branch_requests())
        || measured.proposals > u64::from(budget.proposals())
        || measured.input_objects != invocation.scan_page().input_objects()
        || measured.input_bytes != invocation.scan_page().input_bytes()
        || measured.fuel > budget.fuel()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner measured usage disagrees with request or output",
        });
    }

    match proposal.disposition() {
        PlannerProposalDisposition::ContinueScan { cursor }
            if !invocation.scan_page().complete()
                && cursor.input_view() == invocation.input_view()
                && cursor.after() == invocation.scan_page().last() =>
        {
            Ok(())
        }
        PlannerProposalDisposition::Issue { .. } | PlannerProposalDisposition::NoWork
            if invocation.scan_page().complete() =>
        {
            Ok(())
        }
        PlannerProposalDisposition::ContinueScan { .. }
        | PlannerProposalDisposition::Issue { .. }
        | PlannerProposalDisposition::NoWork => Err(CampaignCodecError::InvalidValue {
            reason: "planner response disposition disagrees with served scan page",
        }),
    }
}

pub(super) fn measured_planning_usage(
    request: &PlannerRequest,
    proposal: &PlannerStepProposal,
    fuel: u64,
) -> Result<PlanningUsage, CampaignCodecError> {
    let (branch_requests, proposals) = match proposal.disposition() {
        PlannerProposalDisposition::Issue {
            branch_requests,
            proposals,
            ..
        } => (branch_requests.len(), proposals.len()),
        PlannerProposalDisposition::ContinueScan { .. } | PlannerProposalDisposition::NoWork => {
            (0, 0)
        }
    };
    Ok(PlanningUsage {
        branch_requests: usize_to_u64(branch_requests)?,
        proposals: usize_to_u64(proposals)?,
        input_objects: request.invocation().scan_page().input_objects(),
        input_bytes: request.invocation().scan_page().input_bytes(),
        fuel,
    })
}

fn usize_to_u64(value: usize) -> Result<u64, CampaignCodecError> {
    u64::try_from(value).map_err(|_| CampaignCodecError::LimitExceeded {
        limit: "planner-output-count",
    })
}

pub(super) fn planner_request_digest(request: &PlannerRequest) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.planner-request-digest.v1",
        &request.canonical_bytes(),
    )
}

pub(super) fn ensure_retained_planner_request_shape(
    bundle_objects: usize,
    encoded_bytes: usize,
) -> Result<(), CampaignCodecError> {
    if bundle_objects > MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "retained-planner-request-bundle-object-count",
        });
    }
    if encoded_bytes > MAX_RETAINED_PLANNER_REQUEST_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "retained-planner-request-encoded-bytes",
        });
    }
    Ok(())
}

pub(super) fn planner_response_basis(
    request_digest: CampaignHash,
    submission: &PlannerSubmission,
) -> Vec<u8> {
    let mut encoder = Encoder::new();
    PLANNER_RESPONSE_SCHEMA_VERSION.encode(&mut encoder);
    request_digest.encode(&mut encoder);
    submission.encode(&mut encoder);
    encoder.finish()
}
