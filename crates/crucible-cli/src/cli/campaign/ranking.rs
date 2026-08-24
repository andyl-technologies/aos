//! Proof-bearing planner-ranking chain queries and reports.

use super::object::campaign_choice_value_label;
use super::*;

use crucible_campaign::{
    CampaignPolicyId, CampaignViewId, GetCampaignPlannerRankingsRequest, PlannerCandidateRanking,
    PlannerEngineId, PlannerStepId, PolicyArtifactId,
};

const CAMPAIGN_RANKING_REPORT_SCHEMA: &str = "crucible.cli.campaign-rankings.v1";
const MAX_CAMPAIGN_RANKING_PAGES: u32 = 64;
const MAX_CAMPAIGN_RANKING_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Serialize)]
pub(super) struct CampaignRankingReport {
    schema: &'static str,
    campaign: String,
    snapshot: String,
    start_step: String,
    pages: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_step: Option<String>,
    rankings: Vec<CampaignRankingEntry>,
}

#[derive(Serialize)]
struct CampaignRankingEntry {
    rank: usize,
    step: String,
    proposal: String,
    branch_point: String,
    source: String,
    value: String,
    edge: String,
    parent_visits: u64,
    edge_visits: u64,
    reward_sum_micros: i64,
    prior_micros: u64,
    mean_reward_micros: i64,
    exploration_bonus_micros: u64,
    novelty_bonus_micros: u64,
    fairness_bonus_micros: u64,
    total_micros: i64,
}

struct RankedPageCandidate {
    step: PlannerStepId,
    ranking: PlannerCandidateRanking,
}

pub(super) fn validate_campaign_rankings_command(
    command: &CampaignCommand,
) -> Result<(), CliError> {
    let CampaignCommand::Rankings(args) = command else {
        return Err(backend_error(
            "campaign rankings validation reached another command",
        ));
    };
    campaign_name(&args.name)?;
    CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign ranking snapshot: {error}")))?;
    PlannerStepId::parse(&args.step)
        .map_err(|error| usage_error(format!("invalid campaign ranking step: {error}")))?;
    if args.pages == 0 || args.pages > MAX_CAMPAIGN_RANKING_PAGES {
        return Err(usage_error(format!(
            "campaign ranking pages must be between 1 and {MAX_CAMPAIGN_RANKING_PAGES}"
        )));
    }
    Ok(())
}

pub(super) fn query_campaign_rankings<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignRankingReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let CampaignCommand::Rankings(args) = command else {
        return Err(backend_error(
            "campaign rankings query reached another command",
        ));
    };
    let campaign = campaign_name(&args.name)?;
    let snapshot = CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign ranking snapshot: {error}")))?;
    let start_step = PlannerStepId::parse(&args.step)
        .map_err(|error| usage_error(format!("invalid campaign ranking step: {error}")))?;

    let mut step = Some(start_step);
    let mut seen = BTreeSet::new();
    let mut pages = 0_u32;
    let mut response_bytes = 0_usize;
    let mut candidates = Vec::new();
    let mut chain_basis: Option<(
        CampaignPolicyId,
        PlannerEngineId,
        PolicyArtifactId,
        CampaignViewId,
    )> = None;
    while pages < args.pages {
        let Some(current) = step else {
            break;
        };
        if !seen.insert(current) {
            return Err(backend_error(
                "campaign planner-step chain contains a cycle",
            ));
        }
        let request = GetCampaignPlannerRankingsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            current,
        )
        .map_err(|error| usage_error(format!("invalid campaign ranking request: {error}")))?;
        let response = client
            .get_campaign_planner_rankings(&request)
            .map_err(|error| backend_error(format!("campaign ranking query failed: {error}")))?;
        response_bytes = response_bytes
            .checked_add(response.canonical_bytes().len())
            .ok_or_else(|| backend_error("campaign ranking response byte count overflowed"))?;
        if response_bytes > MAX_CAMPAIGN_RANKING_RESPONSE_BYTES {
            return Err(backend_error(
                "campaign ranking chain exceeds the 128 MiB response budget",
            ));
        }
        let response_step = response.step();
        let page_basis = (
            response_step.policy(),
            response_step.engine(),
            response_step.policy_artifact(),
            response_step.input_view(),
        );
        if chain_basis.is_some_and(|basis| basis != page_basis) {
            step = Some(current);
            break;
        }
        chain_basis = Some(page_basis);
        candidates.extend(
            response
                .ranked_candidates()
                .map_err(|error| backend_error(format!("campaign ranking is invalid: {error}")))?
                .into_iter()
                .map(|ranking| RankedPageCandidate {
                    step: current,
                    ranking,
                }),
        );
        step = response.parent();
        pages += 1;
    }

    candidates.sort_by(|left, right| {
        left.ranking
            .best_first_cmp(&right.ranking)
            .then_with(|| left.step.cmp(&right.step))
    });
    let rankings = candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| ranking_entry(index + 1, candidate))
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(CampaignRankingReport {
        schema: CAMPAIGN_RANKING_REPORT_SCHEMA,
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        start_step: start_step.to_string(),
        pages,
        next_step: step.map(|value| value.to_string()),
        rankings,
    })
}

fn ranking_entry(
    rank: usize,
    candidate: RankedPageCandidate,
) -> Result<CampaignRankingEntry, CliError> {
    let proposal = candidate.ranking.proposal();
    let guidance = candidate.ranking.guidance();
    let statistics = guidance.statistics();
    let score = candidate.ranking.score();
    Ok(CampaignRankingEntry {
        rank,
        step: candidate.step.to_string(),
        proposal: proposal
            .id()
            .map_err(|error| backend_error(format!("campaign proposal ID failed: {error}")))?
            .to_string(),
        branch_point: proposal.branch_point().to_string(),
        source: proposal.request().to_string(),
        value: campaign_choice_value_label(proposal.value()),
        edge: guidance.edge().to_string(),
        parent_visits: statistics.parent_visits(),
        edge_visits: statistics.edge_visits(),
        reward_sum_micros: statistics.reward_sum_micros(),
        prior_micros: statistics.prior_micros(),
        mean_reward_micros: score.mean_reward_micros(),
        exploration_bonus_micros: score.exploration_bonus_micros(),
        novelty_bonus_micros: score.novelty_bonus_micros(),
        fairness_bonus_micros: score.fairness_bonus_micros(),
        total_micros: score.total_micros(),
    })
}

pub(super) fn render_campaign_rankings(
    report: &CampaignRankingReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(render_ranking_rows(report, false)),
        OutputFormat::Markdown => Ok(render_ranking_rows(report, true)),
    }
}

fn render_ranking_rows(report: &CampaignRankingReport, markdown: bool) -> String {
    let mut output = if markdown {
        String::from(
            "| Rank | Proposal | Value | Total | Mean | Explore | Novelty | Fairness | Step |\n| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n",
        )
    } else {
        String::from("rank total proposal value step\n")
    };
    for entry in &report.rankings {
        if markdown {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                entry.rank,
                entry.proposal,
                entry.value,
                entry.total_micros,
                entry.mean_reward_micros,
                entry.exploration_bonus_micros,
                entry.novelty_bonus_micros,
                entry.fairness_bonus_micros,
                entry.step,
            ));
        } else {
            output.push_str(&format!(
                "{} {} {} {} {}\n",
                entry.rank, entry.total_micros, entry.proposal, entry.value, entry.step,
            ));
        }
    }
    output.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crucible_campaign::{CampaignRecordKind, PlannerStepId};
    use crucible_cas::content_store::ContentId;

    use super::*;

    fn planner_step(label: &[u8]) -> PlannerStepId {
        PlannerStepId::parse(&format!(
            "crucible.campaign.planner-step@{}",
            ContentId::for_bytes(
                CampaignRecordKind::PlannerStep.object_kind(),
                CampaignRecordKind::PlannerStep.schema_version(),
                label,
            )
        ))
        .expect("planner step ID")
    }

    #[test]
    fn ranking_page_bounds_fail_before_transport_setup() {
        let command = CampaignCommand::Rankings(CampaignRankingsArgs {
            name: "example".to_owned(),
            snapshot: CampaignSnapshotId::parse(&format!(
                "crucible.campaign.snapshot@{}",
                ContentId::for_bytes(
                    CampaignRecordKind::Snapshot.object_kind(),
                    CampaignRecordKind::Snapshot.schema_version(),
                    b"ranking snapshot",
                )
            ))
            .expect("snapshot ID")
            .to_string(),
            step: planner_step(b"ranking step").to_string(),
            pages: MAX_CAMPAIGN_RANKING_PAGES + 1,
        });
        assert!(validate_campaign_rankings_command(&command).is_err());
    }

    #[test]
    fn ranking_reports_render_machine_and_human_views() {
        let report = CampaignRankingReport {
            schema: CAMPAIGN_RANKING_REPORT_SCHEMA,
            campaign: "example".to_owned(),
            snapshot: "snapshot".to_owned(),
            start_step: "step".to_owned(),
            pages: 1,
            next_step: Some("parent".to_owned()),
            rankings: vec![CampaignRankingEntry {
                rank: 1,
                step: "step".to_owned(),
                proposal: "proposal".to_owned(),
                branch_point: "point".to_owned(),
                source: "source".to_owned(),
                value: "true".to_owned(),
                edge: "edge".to_owned(),
                parent_visits: 8,
                edge_visits: 2,
                reward_sum_micros: 3,
                prior_micros: 4,
                mean_reward_micros: 5,
                exploration_bonus_micros: 6,
                novelty_bonus_micros: 7,
                fairness_bonus_micros: 8,
                total_micros: 26,
            }],
        };
        let json = render_campaign_rankings(&report, OutputFormat::Json).expect("ranking JSON");
        assert!(json.contains(CAMPAIGN_RANKING_REPORT_SCHEMA));
        assert!(json.contains("\"next_step\": \"parent\""));
        let table = render_campaign_rankings(&report, OutputFormat::Table).expect("ranking table");
        assert!(table.contains("1 26 proposal true step"));
        let markdown =
            render_campaign_rankings(&report, OutputFormat::Markdown).expect("ranking Markdown");
        assert!(markdown.contains("| 1 | proposal | true | 26 |"));
    }
}
