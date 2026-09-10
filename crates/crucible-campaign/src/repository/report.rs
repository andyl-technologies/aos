//! Authenticated campaign report projection.
//!
//! The projection reuses the repository's canonical semantic-status and
//! statistical estimators. It adds bounded scans for exact modeled outcomes,
//! admission provenance, retained findings, and the accepted planner chain.

use super::*;
use crate::{
    AttemptAdmissionRole, BranchRequestCause, CampaignEstimateLabel, CampaignEstimateSummary,
    CampaignExecutionBasisCounts, CampaignOutcomeCounts, CampaignPlannerEvidence,
    CampaignReportEndpoint, CampaignReportSummary, CampaignRoots, ExplorerPolicy,
    StatisticalEndpointEstimate, StatisticalParticleOutcome, StopOutcome,
};

const REPORT_SCAN_PAGE_ITEMS: usize = 10_000;
const MAX_REPORT_SCAN_RECORDS: u64 = 1_000_000;
const MAX_REPORT_SCAN_BYTES: u64 = 128 * 1024 * 1024;

impl CampaignRepository {
    /// Projects a complete summary and canonical estimator endpoints.
    ///
    /// The named campaign must still have `expected_snapshot` as its current
    /// head. Statistical campaigns return only owner-verified finite-flight or
    /// final SMC endpoints; intervention ancestry therefore fails closed in
    /// the existing estimator verifier.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] for a stale snapshot, invalid
    /// closure, intervention ancestry in a complete statistical population,
    /// corrupt evidence, or a registered report scan bound being exceeded.
    pub fn project_campaign_report(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<(CampaignReportSummary, Vec<CampaignReportEndpoint>), CampaignRepositoryError> {
        let head = self.head(name)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }

        self.validate_complete_head(expected_snapshot.content_id())?;
        let snapshot = self.read_snapshot(expected_snapshot.content_id())?;
        let roots = snapshot.snapshot.roots();
        let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        let state = self.state_at_snapshot(expected_snapshot)?;
        let semantic = self.semantic_status_at(expected_snapshot)?;

        let outcomes = self.project_report_outcomes(roots, semantic.admitted_attempts())?;
        let execution_bases = self.project_report_execution_bases(roots.accounting)?;
        let planner = self.project_report_planner_evidence(roots.coordination)?;
        let (estimate, endpoints) =
            self.project_report_estimate(name, &policy, expected_snapshot)?;

        let current = self.head(name)?;
        if current.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current.snapshot_id(),
            });
        }

        let summary = CampaignReportSummary::new(
            state,
            policy.mode(),
            semantic,
            outcomes,
            execution_bases,
            planner,
            estimate,
        )?;
        Ok((summary, endpoints))
    }

    fn project_report_outcomes(
        &self,
        roots: CampaignRoots,
        admitted_attempts: u64,
    ) -> Result<CampaignOutcomeCounts, CampaignRepositoryError> {
        if admitted_attempts > MAX_REPORT_SCAN_RECORDS {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-report-observation-record-limit",
            });
        }

        let mut explored = 0_u64;
        let mut requested_stops = 0_u64;
        let mut terminal_successes = 0_u64;
        let mut failures = 0_u64;
        let mut scanned_bytes = 0_u64;
        for value in 1..=admitted_attempts {
            let Some(content) = self.merkle.get(
                roots.accounting,
                observation_ordinal_key(AdmissionOrdinal::new(value)),
            )?
            else {
                continue;
            };
            let observation = self.read_observation(content)?;
            scanned_bytes = checked_report_bytes(
                scanned_bytes,
                observation.canonical_bytes().len(),
                "campaign-report-observation-byte-limit",
            )?;
            explored =
                checked_report_increment(explored, "campaign-report-outcome-count-overflow")?;
            match observation.stop() {
                StopOutcome::Reached(_) | StopOutcome::ObservationReached(_) => {
                    requested_stops = checked_report_increment(
                        requested_stops,
                        "campaign-report-outcome-count-overflow",
                    )?;
                }
                StopOutcome::TerminalSuccess => {
                    terminal_successes = checked_report_increment(
                        terminal_successes,
                        "campaign-report-outcome-count-overflow",
                    )?;
                }
                StopOutcome::ModeledTimeout(_)
                | StopOutcome::GuestCrash(_)
                | StopOutcome::AssertionFailure(_)
                | StopOutcome::ScenarioFailure(_) => {
                    failures = checked_report_increment(
                        failures,
                        "campaign-report-outcome-count-overflow",
                    )?;
                }
            }
        }

        let findings = self.project_report_findings(roots.findings)?;
        CampaignOutcomeCounts::new(
            explored,
            requested_stops,
            terminal_successes,
            failures,
            findings,
        )
        .map_err(Into::into)
    }

    fn project_report_findings(&self, findings: ContentId) -> Result<u64, CampaignRepositoryError> {
        let root_entries = self.merkle.inspect_shallow(findings)?.entry_count();
        if root_entries > MAX_REPORT_SCAN_RECORDS {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-report-finding-record-limit",
            });
        }

        let mut scanned = 0_u64;
        let mut scanned_bytes = 0_u64;
        let mut after = None;
        loop {
            let page = self.merkle.scan(findings, after, REPORT_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                let finding = self.read_finding(*content)?;
                scanned_bytes = checked_report_bytes(
                    scanned_bytes,
                    finding.canonical_bytes().len(),
                    "campaign-report-finding-byte-limit",
                )?;
                if *key != super::finding::finding_signature_key(finding.signature().cluster_key())
                {
                    return Err(integrity("campaign-report-finding-index-mismatch"));
                }
                scanned =
                    checked_report_increment(scanned, "campaign-report-finding-count-overflow")?;
            }

            let Some(next) = page.next_after() else {
                break;
            };
            if after.is_some_and(|current| next <= current) {
                return Err(integrity("campaign-report-finding-cursor-did-not-advance"));
            }
            after = Some(next);
        }
        if scanned != root_entries {
            return Err(integrity("campaign-report-finding-root-scan-mismatch"));
        }
        Ok(scanned)
    }

    fn project_report_execution_bases(
        &self,
        accounting: ContentId,
    ) -> Result<CampaignExecutionBasisCounts, CampaignRepositoryError> {
        if self.merkle.inspect_shallow(accounting)?.entry_count() > MAX_REPORT_SCAN_RECORDS {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-report-accounting-record-limit",
            });
        }

        let mut policy = 0_u64;
        let mut operator = 0_u64;
        let mut debugger = 0_u64;
        let mut additional_causes = 0_u64;
        let mut scanned_bytes = 0_u64;
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(accounting, after, REPORT_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                if *key != map_key_content("accounting.attempt-admission", *content) {
                    continue;
                }
                let admission = self.read_attempt_admission(*content)?;
                scanned_bytes = checked_report_bytes(
                    scanned_bytes,
                    admission.canonical_bytes().len(),
                    "campaign-report-admission-byte-limit",
                )?;
                match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis { cause, .. } => match cause {
                        BranchRequestCause::Planner(_)
                        | BranchRequestCause::ExhaustivePolicy(_)
                        | BranchRequestCause::ScenarioDefault(_) => {
                            policy = checked_report_increment(
                                policy,
                                "campaign-report-execution-basis-count-overflow",
                            )?;
                        }
                        BranchRequestCause::Operator(_) => {
                            operator = checked_report_increment(
                                operator,
                                "campaign-report-execution-basis-count-overflow",
                            )?;
                        }
                        BranchRequestCause::Debugger(_) => {
                            debugger = checked_report_increment(
                                debugger,
                                "campaign-report-execution-basis-count-overflow",
                            )?;
                        }
                    },
                    AttemptAdmissionRole::AdditionalCause { .. } => {
                        additional_causes = checked_report_increment(
                            additional_causes,
                            "campaign-report-additional-cause-count-overflow",
                        )?;
                    }
                }
            }

            let Some(next) = page.next_after() else {
                break;
            };
            if after.is_some_and(|current| next <= current) {
                return Err(integrity(
                    "campaign-report-accounting-cursor-did-not-advance",
                ));
            }
            after = Some(next);
        }

        Ok(CampaignExecutionBasisCounts::new(
            policy,
            operator,
            debugger,
            additional_causes,
        ))
    }

    fn project_report_planner_evidence(
        &self,
        coordination: ContentId,
    ) -> Result<CampaignPlannerEvidence, CampaignRepositoryError> {
        let Some(head_content) = self.merkle.get(coordination, planner_head_key())? else {
            return CampaignPlannerEvidence::new(0, None).map_err(Into::into);
        };
        let latest = PlannerStepId::from_content_id(head_content)?;
        let mut cursor = Some(latest);
        let mut steps = 0_u64;
        let mut scanned_bytes = 0_u64;
        while let Some(step_id) = cursor {
            steps = checked_report_increment(steps, "campaign-report-planner-record-limit")?;
            if steps > MAX_REPORT_SCAN_RECORDS {
                return Err(CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-report-planner-record-limit",
                });
            }
            if self.merkle.get(coordination, planner_step_key(step_id))?
                != Some(step_id.content_id())
            {
                return Err(integrity("campaign-report-planner-step-is-not-indexed"));
            }
            let step = self.read_planner_step(step_id.content_id())?;
            scanned_bytes = checked_report_bytes(
                scanned_bytes,
                step.canonical_bytes().len(),
                "campaign-report-planner-byte-limit",
            )?;
            cursor = step.parent();
        }
        CampaignPlannerEvidence::new(steps, Some(latest)).map_err(Into::into)
    }

    fn project_report_estimate(
        &self,
        name: &str,
        policy: &CampaignPolicy,
        snapshot: CampaignSnapshotId,
    ) -> Result<(CampaignEstimateSummary, Vec<CampaignReportEndpoint>), CampaignRepositoryError>
    {
        if policy.mode() != CampaignMode::Statistical {
            let label = match policy.explorer() {
                ExplorerPolicy::Exhaustive { .. } => CampaignEstimateLabel::Descriptive,
                ExplorerPolicy::TreeSearch { .. } | ExplorerPolicy::Beam { .. } => {
                    CampaignEstimateLabel::GuidanceBiased
                }
            };
            return Ok((CampaignEstimateSummary::new(label, 0, None)?, Vec::new()));
        }

        if !self.statistical_population_is_complete(policy, snapshot)? {
            return Ok((
                CampaignEstimateSummary::new(CampaignEstimateLabel::NoEstimate, 0, None)?,
                Vec::new(),
            ));
        }

        if policy.sequential_monte_carlo_design().is_some() {
            let report = self.project_sequential_monte_carlo_estimate(name, snapshot)?;
            let endpoints = report
                .final_particles()
                .iter()
                .map(report_endpoint_from_particle)
                .collect::<Result<Vec<_>, CampaignCodecError>>()?;
            let count = u32::try_from(endpoints.len()).map_err(|_| {
                CampaignRepositoryError::InvalidRequest {
                    reason: "campaign-report-endpoint-count-overflow",
                }
            })?;
            return Ok((
                CampaignEstimateSummary::new(
                    CampaignEstimateLabel::StatisticallyWeighted,
                    count,
                    Some(report.diagnostics()),
                )?,
                endpoints,
            ));
        }

        let report = self.project_statistical_estimate(name, snapshot)?;
        let endpoints = report
            .endpoints()
            .iter()
            .enumerate()
            .map(|(index, endpoint)| report_endpoint_from_finite(index, endpoint))
            .collect::<Result<Vec<_>, CampaignCodecError>>()?;
        let count = u32::try_from(endpoints.len()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-report-endpoint-count-overflow",
            }
        })?;
        Ok((
            CampaignEstimateSummary::new(
                CampaignEstimateLabel::StatisticallyWeighted,
                count,
                Some(report.diagnostics()),
            )?,
            endpoints,
        ))
    }

    fn statistical_population_is_complete(
        &self,
        policy: &CampaignPolicy,
        snapshot: CampaignSnapshotId,
    ) -> Result<bool, CampaignRepositoryError> {
        let loaded = self.read_snapshot(snapshot.content_id())?;
        let roots = loaded.snapshot.roots();
        let initial = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("statistical-report-policy-lacks-design"))?;
        for coordinate in initial.draws().keys().copied() {
            let Some(proposal) = self
                .merkle
                .get(roots.accounting, statistical_draw_proposal_key(coordinate))?
            else {
                return Ok(false);
            };
            if !self.statistical_proposal_has_observation(roots, proposal)? {
                return Ok(false);
            }
        }

        let Some(smc) = policy.sequential_monte_carlo_design() else {
            return Ok(true);
        };
        for stage in smc.stages().keys().copied() {
            for slot in 0..smc.particle_count() {
                let Some(proposal) = self
                    .merkle
                    .get(roots.accounting, smc_transition_proposal_key(stage, slot))?
                else {
                    return Ok(false);
                };
                if !self.statistical_proposal_has_observation(roots, proposal)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn statistical_proposal_has_observation(
        &self,
        roots: CampaignRoots,
        proposal: ContentId,
    ) -> Result<bool, CampaignRepositoryError> {
        let Some(admission) = self.merkle.get(
            roots.accounting,
            map_key_content("accounting.proposal-admission", proposal),
        )?
        else {
            return Ok(false);
        };
        let admission = self.read_attempt_admission(admission)?;
        Ok(self
            .merkle
            .get(
                roots.observations,
                map_key_content("observations.attempt", admission.attempt().content_id()),
            )?
            .is_some())
    }
}

fn report_endpoint_from_finite(
    index: usize,
    endpoint: &StatisticalEndpointEstimate,
) -> Result<CampaignReportEndpoint, CampaignCodecError> {
    let ordinal = u32::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "campaign report endpoint ordinal overflowed",
        })?;
    CampaignReportEndpoint::new(
        ordinal,
        None,
        endpoint.coordinate(),
        endpoint.proposal(),
        endpoint.attempt(),
        endpoint.observation(),
        endpoint.path(),
        endpoint.target_probability(),
        endpoint.proposal_probability(),
        endpoint.importance_weight(),
    )
}

fn report_endpoint_from_particle(
    particle: &StatisticalParticleOutcome,
) -> Result<CampaignReportEndpoint, CampaignCodecError> {
    CampaignReportEndpoint::new(
        particle
            .slot()
            .checked_add(1)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "campaign report endpoint ordinal overflowed",
            })?,
        Some(particle.stage()),
        particle.source_coordinate(),
        particle.proposal(),
        particle.attempt(),
        particle.observation(),
        particle.path(),
        particle.cumulative_target_probability(),
        particle.cumulative_proposal_probability(),
        particle.estimator_weight(),
    )
}

fn checked_report_increment(
    value: u64,
    reason: &'static str,
) -> Result<u64, CampaignRepositoryError> {
    value.checked_add(1).ok_or_else(|| integrity(reason))
}

fn checked_report_bytes(
    total: u64,
    additional: usize,
    reason: &'static str,
) -> Result<u64, CampaignRepositoryError> {
    let additional = u64::try_from(additional).map_err(|_| integrity(reason))?;
    let total = total
        .checked_add(additional)
        .ok_or_else(|| integrity(reason))?;
    if total > MAX_REPORT_SCAN_BYTES {
        return Err(CampaignRepositoryError::InvalidRequest { reason });
    }
    Ok(total)
}
