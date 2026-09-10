//! Snapshot-bound campaign completion and statistical reports.
//!
//! A report combines bounded exploration totals with a page of canonical
//! estimator endpoints. The response labels descriptive, guidance-biased, and
//! statistically weighted results explicitly. Operator and debugger execution
//! bases remain separate from the policy population, including when a later
//! cause deduplicates onto an earlier admitted attempt.

use super::*;
use crate::{
    AttemptId, BranchPathId, CampaignMode, PlannerStepId, ProposalId, StatisticalRational,
    StatisticalWeightDiagnostics,
};

/// Maximum estimator endpoints returned by one campaign report page.
pub const MAX_CAMPAIGN_REPORT_PAGE_ITEMS: u32 = 32;

/// Interpretation permitted for aggregate campaign results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignEstimateLabel {
    /// Statistical policy population is not yet complete enough to estimate.
    NoEstimate,
    /// Exact observed counts with no population-probability claim.
    Descriptive,
    /// Observed frequency from adaptive guidance, with no population claim.
    GuidanceBiased,
    /// Policy-declared target population estimated with authenticated weights.
    StatisticallyWeighted,
}

impl Canonical for CampaignEstimateLabel {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Descriptive => 0,
            Self::GuidanceBiased => 1,
            Self::StatisticallyWeighted => 2,
            Self::NoEstimate => 3,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Descriptive),
            1 => Ok(Self::GuidanceBiased),
            2 => Ok(Self::StatisticallyWeighted),
            3 => Ok(Self::NoEstimate),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-estimate-label",
                tag,
            }),
        }
    }
}

/// Exact outcomes observed at one authenticated campaign snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignOutcomeCounts {
    explored: u64,
    requested_stops: u64,
    terminal_successes: u64,
    failures: u64,
    findings: u64,
}

impl CampaignOutcomeCounts {
    /// Builds internally consistent outcome counts.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the outcome classes do not sum to
    /// `explored`.
    pub fn new(
        explored: u64,
        requested_stops: u64,
        terminal_successes: u64,
        failures: u64,
        findings: u64,
    ) -> Result<Self, CampaignCodecError> {
        let classified = requested_stops
            .checked_add(terminal_successes)
            .and_then(|count| count.checked_add(failures))
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "campaign report outcome count overflowed",
            })?;
        if classified != explored {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report outcome counts are inconsistent",
            });
        }
        Ok(Self {
            explored,
            requested_stops,
            terminal_successes,
            failures,
            findings,
        })
    }

    /// Returns attempts with one canonical observation.
    #[must_use]
    pub const fn explored(self) -> u64 {
        self.explored
    }

    /// Returns observations that reached the requested semantic stop.
    #[must_use]
    pub const fn requested_stops(self) -> u64 {
        self.requested_stops
    }

    /// Returns observations that reached modeled terminal success.
    #[must_use]
    pub const fn terminal_successes(self) -> u64 {
        self.terminal_successes
    }

    /// Returns modeled timeout, crash, assertion, and scenario failures.
    #[must_use]
    pub const fn failures(self) -> u64 {
        self.failures
    }

    /// Returns deduplicated canonical findings retained at this snapshot.
    #[must_use]
    pub const fn findings(self) -> u64 {
        self.findings
    }
}

impl Canonical for CampaignOutcomeCounts {
    fn encode(&self, encoder: &mut Encoder) {
        self.explored.encode(encoder);
        self.requested_stops.encode(encoder);
        self.terminal_successes.encode(encoder);
        self.failures.encode(encoder);
        self.findings.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Provenance counts for admitted execution bases and deduplicated causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignExecutionBasisCounts {
    policy: u64,
    operator: u64,
    debugger: u64,
    additional_causes: u64,
}

impl CampaignExecutionBasisCounts {
    /// Builds exact provenance counts.
    #[must_use]
    pub const fn new(policy: u64, operator: u64, debugger: u64, additional_causes: u64) -> Self {
        Self {
            policy,
            operator,
            debugger,
            additional_causes,
        }
    }

    /// Returns planner, exhaustive-policy, and scenario-default executions.
    #[must_use]
    pub const fn policy(self) -> u64 {
        self.policy
    }

    /// Returns executions whose immutable basis is an operator intervention.
    #[must_use]
    pub const fn operator(self) -> u64 {
        self.operator
    }

    /// Returns executions whose immutable basis is a debugger intervention.
    #[must_use]
    pub const fn debugger(self) -> u64 {
        self.debugger
    }

    /// Returns later proposal causes deduplicated onto admitted attempts.
    #[must_use]
    pub const fn additional_causes(self) -> u64 {
        self.additional_causes
    }

    fn execution_bases(self) -> Result<u64, CampaignCodecError> {
        self.policy
            .checked_add(self.operator)
            .and_then(|count| count.checked_add(self.debugger))
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "campaign report execution-basis count overflowed",
            })
    }
}

impl Canonical for CampaignExecutionBasisCounts {
    fn encode(&self, encoder: &mut Encoder) {
        self.policy.encode(encoder);
        self.operator.encode(encoder);
        self.debugger.encode(encoder);
        self.additional_causes.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let counts = Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        );
        counts.execution_bases()?;
        Ok(counts)
    }
}

/// Retained planner chain available for independent explanation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignPlannerEvidence {
    steps: u64,
    latest: Option<PlannerStepId>,
}

impl CampaignPlannerEvidence {
    /// Builds a consistent planner-chain summary.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when an empty chain names a head or a
    /// nonempty chain omits it.
    pub fn new(steps: u64, latest: Option<PlannerStepId>) -> Result<Self, CampaignCodecError> {
        if (steps == 0) != latest.is_none() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report planner evidence is inconsistent",
            });
        }
        Ok(Self { steps, latest })
    }

    /// Returns accepted planner steps in the authenticated chain.
    #[must_use]
    pub const fn steps(self) -> u64 {
        self.steps
    }

    /// Returns the latest accepted step for the public rankings command.
    #[must_use]
    pub const fn latest(self) -> Option<PlannerStepId> {
        self.latest
    }
}

impl Canonical for CampaignPlannerEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.steps.encode(encoder);
        self.latest.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u64::decode(decoder)?, Option::decode(decoder)?)
    }
}

/// Aggregate interpretation and diagnostics for one report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignEstimateSummary {
    label: CampaignEstimateLabel,
    endpoints: u32,
    diagnostics: Option<StatisticalWeightDiagnostics>,
}

impl CampaignEstimateSummary {
    /// Builds a report interpretation with optional statistical diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] unless weighted reports have at least
    /// one endpoint and diagnostics, and other labels have neither.
    pub fn new(
        label: CampaignEstimateLabel,
        endpoints: u32,
        diagnostics: Option<StatisticalWeightDiagnostics>,
    ) -> Result<Self, CampaignCodecError> {
        let weighted = label == CampaignEstimateLabel::StatisticallyWeighted;
        if weighted != (endpoints != 0 && diagnostics.is_some())
            || (!weighted && (endpoints != 0 || diagnostics.is_some()))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report estimate summary is inconsistent",
            });
        }
        if let Some(diagnostics) = diagnostics {
            let one = StatisticalRational::one();
            let endpoint_count = StatisticalRational::new(u128::from(endpoints), 1)?;
            let minimum_concentration = one.checked_divide(endpoint_count)?;
            if diagnostics
                .concentration()
                .checked_cmp(minimum_concentration)?
                .is_lt()
                || diagnostics
                    .effective_sample_size()
                    .checked_cmp(one)?
                    .is_lt()
                || diagnostics
                    .effective_sample_size()
                    .checked_cmp(endpoint_count)?
                    .is_gt()
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "campaign report weight diagnostics exceed endpoint bounds",
                });
            }
        }
        Ok(Self {
            label,
            endpoints,
            diagnostics,
        })
    }

    /// Returns the permitted interpretation of aggregate results.
    #[must_use]
    pub const fn label(self) -> CampaignEstimateLabel {
        self.label
    }

    /// Returns policy-population endpoints available through report pages.
    #[must_use]
    pub const fn endpoints(self) -> u32 {
        self.endpoints
    }

    /// Returns descriptive weight diagnostics for a weighted report.
    #[must_use]
    pub const fn diagnostics(self) -> Option<StatisticalWeightDiagnostics> {
        self.diagnostics
    }
}

impl Canonical for CampaignEstimateSummary {
    fn encode(&self, encoder: &mut Encoder) {
        self.label.encode(encoder);
        self.endpoints.encode(encoder);
        self.diagnostics.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignEstimateLabel::decode(decoder)?,
            u32::decode(decoder)?,
            Option::decode(decoder)?,
        )
    }
}

/// Complete bounded summary for one authenticated campaign snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignReportSummary {
    state: CampaignState,
    mode: CampaignMode,
    semantic: CampaignSemanticStatus,
    outcomes: CampaignOutcomeCounts,
    execution_bases: CampaignExecutionBasisCounts,
    planner: CampaignPlannerEvidence,
    estimate: CampaignEstimateSummary,
}

impl CampaignReportSummary {
    /// Builds a report summary whose execution bases match semantic admission.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when execution-basis totals disagree
    /// with the authenticated semantic attempt count, observed outcomes exceed
    /// admitted attempts, or the estimate label contradicts the campaign mode.
    pub fn new(
        state: CampaignState,
        mode: CampaignMode,
        semantic: CampaignSemanticStatus,
        outcomes: CampaignOutcomeCounts,
        execution_bases: CampaignExecutionBasisCounts,
        planner: CampaignPlannerEvidence,
        estimate: CampaignEstimateSummary,
    ) -> Result<Self, CampaignCodecError> {
        let statistical_estimate = matches!(
            estimate.label(),
            CampaignEstimateLabel::NoEstimate | CampaignEstimateLabel::StatisticallyWeighted
        );
        if execution_bases.execution_bases()? != semantic.admitted_attempts()
            || outcomes.explored() > semantic.admitted_attempts()
            || (mode == CampaignMode::Statistical) != statistical_estimate
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report summary disagrees with semantic status",
            });
        }
        Ok(Self {
            state,
            mode,
            semantic,
            outcomes,
            execution_bases,
            planner,
            estimate,
        })
    }

    /// Returns the durable lifecycle state at the report snapshot.
    #[must_use]
    pub const fn state(self) -> CampaignState {
        self.state
    }

    /// Returns the active policy's reproducibility and claim mode.
    #[must_use]
    pub const fn mode(self) -> CampaignMode {
        self.mode
    }

    /// Returns bounded continuation, attempt, and graph counts.
    #[must_use]
    pub const fn semantic(self) -> CampaignSemanticStatus {
        self.semantic
    }

    /// Returns exact observed outcome counts.
    #[must_use]
    pub const fn outcomes(self) -> CampaignOutcomeCounts {
        self.outcomes
    }

    /// Returns immutable execution-provenance counts.
    #[must_use]
    pub const fn execution_bases(self) -> CampaignExecutionBasisCounts {
        self.execution_bases
    }

    /// Returns retained planner-chain evidence.
    #[must_use]
    pub const fn planner(self) -> CampaignPlannerEvidence {
        self.planner
    }

    /// Returns the aggregate claim label and estimator diagnostics.
    #[must_use]
    pub const fn estimate(self) -> CampaignEstimateSummary {
        self.estimate
    }
}

impl Canonical for CampaignReportSummary {
    fn encode(&self, encoder: &mut Encoder) {
        self.state.encode(encoder);
        self.mode.encode(encoder);
        self.semantic.encode(encoder);
        self.outcomes.encode(encoder);
        self.execution_bases.encode(encoder);
        self.planner.encode(encoder);
        self.estimate.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            CampaignState::decode(decoder)?,
            CampaignMode::decode(decoder)?,
            CampaignSemanticStatus::decode(decoder)?,
            CampaignOutcomeCounts::decode(decoder)?,
            CampaignExecutionBasisCounts::decode(decoder)?,
            CampaignPlannerEvidence::decode(decoder)?,
            CampaignEstimateSummary::decode(decoder)?,
        )
    }
}

/// One canonical estimator endpoint in report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignReportEndpoint {
    ordinal: u32,
    stage: Option<u32>,
    source_coordinate: u64,
    proposal: ProposalId,
    attempt: AttemptId,
    observation: crate::ObservationId,
    path: BranchPathId,
    target_probability: StatisticalRational,
    proposal_probability: StatisticalRational,
    estimator_weight: StatisticalRational,
}

impl CampaignReportEndpoint {
    /// Builds one finite-flight or final-particle endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a zero ordinal, invalid probability,
    /// or zero estimator weight.
    // crucible-lint: allow rust-allow -- the endpoint keeps every authenticated estimator identity and exact probability explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordinal: u32,
        stage: Option<u32>,
        source_coordinate: u64,
        proposal: ProposalId,
        attempt: AttemptId,
        observation: crate::ObservationId,
        path: BranchPathId,
        target_probability: StatisticalRational,
        proposal_probability: StatisticalRational,
        estimator_weight: StatisticalRational,
    ) -> Result<Self, CampaignCodecError> {
        let valid_probability = |value: StatisticalRational| {
            value.numerator() != 0 && value.numerator() <= value.denominator()
        };
        if ordinal == 0
            || !valid_probability(target_probability)
            || !valid_probability(proposal_probability)
            || estimator_weight.numerator() == 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report endpoint is invalid",
            });
        }
        Ok(Self {
            ordinal,
            stage,
            source_coordinate,
            proposal,
            attempt,
            observation,
            path,
            target_probability,
            proposal_probability,
            estimator_weight,
        })
    }

    /// Returns the one-based stable report cursor.
    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    /// Returns the SMC transition stage, absent for a finite-flight endpoint.
    #[must_use]
    pub const fn stage(self) -> Option<u32> {
        self.stage
    }

    /// Returns the policy-declared finite source coordinate.
    #[must_use]
    pub const fn source_coordinate(self) -> u64 {
        self.source_coordinate
    }

    /// Returns the proposal that supplied the endpoint.
    #[must_use]
    pub const fn proposal(self) -> ProposalId {
        self.proposal
    }

    /// Returns the semantic attempt, which may be shared by endpoints.
    #[must_use]
    pub const fn attempt(self) -> AttemptId {
        self.attempt
    }

    /// Returns the canonical observation, which may be shared by endpoints.
    #[must_use]
    pub const fn observation(self) -> crate::ObservationId {
        self.observation
    }

    /// Returns the authenticated semantic path.
    #[must_use]
    pub const fn path(self) -> BranchPathId {
        self.path
    }

    /// Returns exact cumulative target probability `P`.
    #[must_use]
    pub const fn target_probability(self) -> StatisticalRational {
        self.target_probability
    }

    /// Returns exact cumulative proposal probability `Q`.
    #[must_use]
    pub const fn proposal_probability(self) -> StatisticalRational {
        self.proposal_probability
    }

    /// Returns the exact estimator weight.
    #[must_use]
    pub const fn estimator_weight(self) -> StatisticalRational {
        self.estimator_weight
    }
}

impl Canonical for CampaignReportEndpoint {
    fn encode(&self, encoder: &mut Encoder) {
        self.ordinal.encode(encoder);
        self.stage.encode(encoder);
        self.source_coordinate.encode(encoder);
        self.proposal.encode(encoder);
        self.attempt.encode(encoder);
        self.observation.encode(encoder);
        self.path.encode(encoder);
        self.target_probability.encode(encoder);
        self.proposal_probability.encode(encoder);
        self.estimator_weight.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            Option::decode(decoder)?,
            u64::decode(decoder)?,
            ProposalId::decode(decoder)?,
            AttemptId::decode(decoder)?,
            crate::ObservationId::decode(decoder)?,
            BranchPathId::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
        )
    }
}

/// Strict request for one page of a snapshot-bound campaign report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignReportRequest {
    schema_version: u32,
    principal: CampaignPrincipal,
    campaign: CampaignName,
    snapshot: CampaignSnapshotId,
    after: Option<u32>,
    limit: u32,
}

impl QueryCampaignReportRequest {
    /// Builds one bounded report request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a zero cursor, invalid page size, or
    /// an oversized request.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        snapshot: CampaignSnapshotId,
        after: Option<u32>,
        limit: u32,
    ) -> Result<Self, CampaignCodecError> {
        if after == Some(0) || limit == 0 || limit > MAX_CAMPAIGN_REPORT_PAGE_ITEMS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report cursor or page size is invalid",
            });
        }
        let request = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            principal,
            campaign,
            snapshot,
            after,
            limit,
        };
        ensure_message_size(&request, "query-campaign-report-request-encoded-bytes")?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the canonical campaign name.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the exact current snapshot that pins all report evidence.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the exclusive one-based endpoint cursor.
    #[must_use]
    pub const fn after(&self) -> Option<u32> {
        self.after
    }

    /// Returns the maximum endpoints requested.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        service_request_digest("query-campaign-report", self)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded report request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-report-request-encoded-bytes")
    }
}

impl Canonical for QueryCampaignReportRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.principal.encode(encoder);
        self.campaign.encode(encoder);
        self.snapshot.encode(encoder);
        self.after.encode(encoder);
        self.limit.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        Self::new(
            CampaignPrincipal::decode(decoder)?,
            CampaignName::decode(decoder)?,
            CampaignSnapshotId::decode(decoder)?,
            Option::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// One checked page of a complete campaign report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCampaignReportResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    snapshot: CampaignSnapshot,
    summary: CampaignReportSummary,
    endpoints: Vec<CampaignReportEndpoint>,
    next_after: Option<u32>,
}

impl QueryCampaignReportResponse {
    /// Builds a response bound to every request field and the snapshot body.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when snapshot identity, endpoint order,
    /// cursor relation, or the component-message size is invalid.
    pub fn new(
        request: &QueryCampaignReportRequest,
        snapshot: CampaignSnapshot,
        summary: CampaignReportSummary,
        endpoints: Vec<CampaignReportEndpoint>,
    ) -> Result<Self, CampaignCodecError> {
        let next_after = endpoints.last().and_then(|endpoint| {
            (endpoint.ordinal() < summary.estimate().endpoints()).then_some(endpoint.ordinal())
        });
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: request.request_digest(),
            snapshot,
            summary,
            endpoints,
            next_after,
        };
        response.validate_body_for(request)?;
        ensure_message_size(&response, "query-campaign-report-response-encoded-bytes")?;
        Ok(response)
    }

    /// Returns the authenticated snapshot body and all root identities.
    #[must_use]
    pub const fn snapshot(&self) -> &CampaignSnapshot {
        &self.snapshot
    }

    /// Returns the complete bounded report summary.
    #[must_use]
    pub const fn summary(&self) -> CampaignReportSummary {
        self.summary
    }

    /// Returns canonical estimator endpoints in stable report order.
    #[must_use]
    pub fn endpoints(&self) -> &[CampaignReportEndpoint] {
        &self.endpoints
    }

    /// Returns the exclusive cursor for another page.
    #[must_use]
    pub const fn next_after(&self) -> Option<u32> {
        self.next_after
    }

    /// Validates exact request, snapshot, page, and cursor binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to another
    /// request or violates the canonical report page relation.
    pub fn validate_for(
        &self,
        request: &QueryCampaignReportRequest,
    ) -> Result<(), CampaignCodecError> {
        validate_request_digest(self.request_digest, request.request_digest())?;
        self.validate_body_for(request)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict bounded report response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// unsupported, or oversized input. Use [`Self::validate_for`] before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_message(bytes, "query-campaign-report-response-encoded-bytes")
    }

    fn validate_body_for(
        &self,
        request: &QueryCampaignReportRequest,
    ) -> Result<(), CampaignCodecError> {
        if self.snapshot.id()? != request.snapshot()
            || self.endpoints.len() > request.limit() as usize
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report response basis is invalid",
            });
        }
        let first = request.after().unwrap_or(0).checked_add(1).ok_or(
            CampaignCodecError::InvalidValue {
                reason: "campaign report cursor overflowed",
            },
        )?;
        if self.endpoints.iter().enumerate().any(|(index, endpoint)| {
            u32::try_from(index)
                .ok()
                .and_then(|offset| first.checked_add(offset))
                != Some(endpoint.ordinal())
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report endpoint order is invalid",
            });
        }
        let total = self.summary.estimate().endpoints();
        let expected_next = self
            .endpoints
            .last()
            .and_then(|endpoint| (endpoint.ordinal() < total).then_some(endpoint.ordinal()));
        if self.next_after != expected_next
            || self
                .endpoints
                .last()
                .is_some_and(|endpoint| endpoint.ordinal() > total)
            || self.endpoints.is_empty() && request.after().unwrap_or(0) < total
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign report response cursor is invalid",
            });
        }
        Ok(())
    }
}

impl Canonical for QueryCampaignReportResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.snapshot.encode(encoder);
        self.summary.encode(encoder);
        self.endpoints.encode(encoder);
        self.next_after.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_service_version(u32::decode(decoder)?)?;
        let response = Self {
            schema_version: CAMPAIGN_SERVICE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            snapshot: CampaignSnapshot::decode(decoder)?,
            summary: CampaignReportSummary::decode(decoder)?,
            endpoints: decoder.sequence_bounded(
                MAX_CAMPAIGN_REPORT_PAGE_ITEMS as usize,
                "campaign-report-page-items",
                CampaignReportEndpoint::decode,
            )?,
            next_after: Option::decode(decoder)?,
        };
        ensure_message_size(&response, "query-campaign-report-response-encoded-bytes")?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- unit fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;
    use crucible_cas::content_store::{ContentId, ObjectKind};

    #[test]
    fn report_pages_round_trip_and_bind_every_cursor() {
        let snapshot = snapshot_body();
        let first_request = QueryCampaignReportRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot.id().expect("snapshot ID"),
            None,
            2,
        )
        .expect("first report request");
        assert_eq!(
            QueryCampaignReportRequest::from_canonical_bytes(&first_request.canonical_bytes())
                .expect("decode request"),
            first_request
        );

        let summary = weighted_summary();
        let endpoints = (1..=3).map(endpoint).collect::<Vec<_>>();
        let first = QueryCampaignReportResponse::new(
            &first_request,
            snapshot.clone(),
            summary,
            endpoints[..2].to_vec(),
        )
        .expect("first report page");
        assert_eq!(first.next_after(), Some(2));
        let decoded = QueryCampaignReportResponse::from_canonical_bytes(&first.canonical_bytes())
            .expect("decode first report page");
        decoded
            .validate_for(&first_request)
            .expect("validate decoded report page");
        assert_eq!(decoded, first);

        let second_request = QueryCampaignReportRequest::new(
            first_request.principal().clone(),
            first_request.campaign().clone(),
            first_request.snapshot(),
            first.next_after(),
            2,
        )
        .expect("second report request");
        let second = QueryCampaignReportResponse::new(
            &second_request,
            snapshot,
            summary,
            endpoints[2..].to_vec(),
        )
        .expect("second report page");
        assert_eq!(second.next_after(), None);
        assert_eq!(second.endpoints()[0].ordinal(), 3);

        let mut forged = first;
        forged.endpoints.swap(0, 1);
        assert!(forged.validate_for(&first_request).is_err());
        assert!(forged.validate_for(&second_request).is_err());
    }

    #[test]
    fn partial_statistical_summary_has_an_explicit_no_estimate_state() {
        let semantic = CampaignSemanticStatus::new(
            CampaignContinuationStatus::new(1, 1, 1, 1, 1),
            2,
            3,
            5,
            128,
        )
        .expect("semantic status");
        let summary = CampaignReportSummary::new(
            CampaignState::Running,
            CampaignMode::Statistical,
            semantic,
            CampaignOutcomeCounts::new(1, 1, 0, 0, 0).expect("outcomes"),
            CampaignExecutionBasisCounts::new(1, 1, 0, 0),
            CampaignPlannerEvidence::new(0, None).expect("planner evidence"),
            CampaignEstimateSummary::new(CampaignEstimateLabel::NoEstimate, 0, None)
                .expect("no-estimate summary"),
        )
        .expect("partial statistical report");
        assert_eq!(
            summary.estimate().label(),
            CampaignEstimateLabel::NoEstimate
        );
        assert_eq!(
            CampaignReportSummary::decode(&mut Decoder::new(&codec::encode(&summary)))
                .expect("decode summary"),
            summary
        );
        assert!(
            CampaignEstimateSummary::new(CampaignEstimateLabel::StatisticallyWeighted, 0, None,)
                .is_err()
        );
        assert!(
            CampaignReportSummary::new(
                CampaignState::Running,
                CampaignMode::Strict,
                semantic,
                CampaignOutcomeCounts::new(1, 1, 0, 0, 0).expect("outcomes"),
                CampaignExecutionBasisCounts::new(1, 1, 0, 0),
                CampaignPlannerEvidence::new(0, None).expect("planner evidence"),
                CampaignEstimateSummary::new(CampaignEstimateLabel::NoEstimate, 0, None)
                    .expect("no-estimate summary"),
            )
            .is_err()
        );
        assert!(
            CampaignEstimateSummary::new(
                CampaignEstimateLabel::StatisticallyWeighted,
                2,
                Some(StatisticalWeightDiagnostics::new(
                    StatisticalRational::new(1, 3).expect("concentration"),
                    StatisticalRational::new(2, 1).expect("ESS"),
                )),
            )
            .is_err()
        );
    }

    #[test]
    fn one_observation_can_retain_multiple_distinct_findings() {
        let outcomes = CampaignOutcomeCounts::new(1, 0, 0, 1, 2).expect("outcomes");

        assert_eq!(outcomes.explored(), 1);
        assert_eq!(outcomes.findings(), 2);
    }

    fn weighted_summary() -> CampaignReportSummary {
        let semantic =
            CampaignSemanticStatus::new(CampaignContinuationStatus::default(), 3, 3, 0, 0)
                .expect("semantic status");
        CampaignReportSummary::new(
            CampaignState::Completed,
            CampaignMode::Statistical,
            semantic,
            CampaignOutcomeCounts::new(3, 1, 1, 1, 0).expect("outcomes"),
            CampaignExecutionBasisCounts::new(3, 0, 0, 0),
            CampaignPlannerEvidence::new(0, None).expect("planner evidence"),
            CampaignEstimateSummary::new(
                CampaignEstimateLabel::StatisticallyWeighted,
                3,
                Some(StatisticalWeightDiagnostics::new(
                    StatisticalRational::new(1, 3).expect("concentration"),
                    StatisticalRational::new(3, 1).expect("ESS"),
                )),
            )
            .expect("estimate summary"),
        )
        .expect("report summary")
    }

    fn endpoint(ordinal: u32) -> CampaignReportEndpoint {
        let id = |kind: &str, object_kind: ObjectKind, version| {
            ContentId::for_bytes(object_kind, version, format!("{kind}-{ordinal}").as_bytes())
        };
        CampaignReportEndpoint::new(
            ordinal,
            None,
            u64::from(ordinal - 1),
            ProposalId::from_content_id(id("proposal", ObjectKind::CampaignFact, 2))
                .expect("proposal ID"),
            AttemptId::from_content_id(id("attempt", ObjectKind::CampaignFact, 8))
                .expect("attempt ID"),
            crate::ObservationId::from_content_id(id("observation", ObjectKind::Observation, 12))
                .expect("observation ID"),
            BranchPathId::from_content_id(id("path", ObjectKind::CampaignFact, 2))
                .expect("path ID"),
            StatisticalRational::new(1, 2).expect("target probability"),
            StatisticalRational::new(1, 2).expect("proposal probability"),
            StatisticalRational::one(),
        )
        .expect("endpoint")
    }

    fn snapshot_body() -> CampaignSnapshot {
        let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"report-root");
        CampaignSnapshot::genesis(
            CampaignLineageId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"report-lineage",
            ))
            .expect("lineage ID"),
            CampaignPolicyId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                1,
                b"report-policy",
            ))
            .expect("policy ID"),
            crate::CampaignRoots {
                graph: root,
                exploration: root,
                observations: root,
                corpus: root,
                coverage: root,
                findings: root,
                pins: root,
                accounting: root,
                coordination: root,
            },
        )
        .expect("snapshot")
    }
}
