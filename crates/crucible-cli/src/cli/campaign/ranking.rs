//! Proof-bearing planner-ranking chain queries and reports.

use super::object::campaign_choice_value_label;
use super::*;

use crucible_campaign::{
    BranchPointId, BranchRequestId, CampaignPolicyId, CampaignViewId,
    GetCampaignPlannerRankingsRequest, PlannerCandidateRanking, PlannerEngineId, PlannerStepId,
    PolicyArtifactId,
};

const CAMPAIGN_RANKING_REPORT_SCHEMA: &str = "crucible.cli.campaign-rankings.v2";
const CAMPAIGN_POLICY_RANKING_REPORT_SCHEMA: &str = "crucible.cli.campaign-policy-rankings.v1";
const MAX_CAMPAIGN_RANKING_PAGES: u32 = 64;
const MAX_CAMPAIGN_RANKING_RESULTS: u32 = 65_536;
const MAX_CAMPAIGN_RANKING_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Serialize)]
pub(super) struct CampaignRankingReport {
    schema: &'static str,
    campaign: String,
    snapshot: String,
    start_step: String,
    pages: u32,
    filters: CampaignRankingFilters,
    matched_candidates: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_step: Option<String>,
    rankings: Vec<CampaignRankingEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_groups: Vec<CampaignPolicyRankingGroup>,
}

#[derive(Clone, Serialize)]
struct CampaignRankingFilters {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    policy_groups: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    branch_point: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top: Option<u32>,
}

#[derive(Serialize)]
struct CampaignPolicyRankingGroup {
    group: usize,
    policy: String,
    newest_step: String,
    oldest_step: String,
    pages: u32,
    matched_candidates: u64,
    bases: Vec<CampaignRankingBasisGroup>,
}

#[derive(Serialize)]
struct CampaignRankingBasisGroup {
    basis: usize,
    engine: String,
    policy_artifact: String,
    input_view: String,
    newest_step: String,
    oldest_step: String,
    pages: u32,
    matched_candidates: u64,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RankingBasis {
    policy: CampaignPolicyId,
    engine: PlannerEngineId,
    policy_artifact: PolicyArtifactId,
    input_view: CampaignViewId,
}

struct CollectedPolicyRankingGroup {
    basis: RankingBasis,
    newest_step: PlannerStepId,
    oldest_step: PlannerStepId,
    pages: u32,
    candidates: Vec<RankedPageCandidate>,
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
    if let Some(branch_point) = &args.branch_point {
        BranchPointId::parse(branch_point).map_err(|error| {
            usage_error(format!("invalid campaign ranking branch point: {error}"))
        })?;
    }
    if let Some(source) = &args.source {
        BranchRequestId::parse(source)
            .map_err(|error| usage_error(format!("invalid campaign ranking source: {error}")))?;
    }
    if args.pages == 0 || args.pages > MAX_CAMPAIGN_RANKING_PAGES {
        return Err(usage_error(format!(
            "campaign ranking pages must be between 1 and {MAX_CAMPAIGN_RANKING_PAGES}"
        )));
    }
    if args
        .top
        .is_some_and(|top| top == 0 || top > MAX_CAMPAIGN_RANKING_RESULTS)
    {
        return Err(usage_error(format!(
            "campaign ranking top count must be between 1 and {MAX_CAMPAIGN_RANKING_RESULTS}"
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
    let branch_point = args
        .branch_point
        .as_deref()
        .map(BranchPointId::parse)
        .transpose()
        .map_err(|error| usage_error(format!("invalid campaign ranking branch point: {error}")))?;
    let source = args
        .source
        .as_deref()
        .map(BranchRequestId::parse)
        .transpose()
        .map_err(|error| usage_error(format!("invalid campaign ranking source: {error}")))?;

    let mut step = Some(start_step);
    let mut seen = BTreeSet::new();
    let mut pages = 0_u32;
    let mut response_bytes = 0_usize;
    let mut candidates = Vec::new();
    let mut policy_groups = Vec::new();
    let mut chain_basis = None;
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
        let page_basis = RankingBasis {
            policy: response_step.policy(),
            engine: response_step.engine(),
            policy_artifact: response_step.policy_artifact(),
            input_view: response_step.input_view(),
        };
        if ranking_basis_boundary(args.policy_groups, chain_basis, page_basis) {
            step = Some(current);
            break;
        }
        chain_basis = Some(page_basis);
        let page_candidates = response
            .ranked_candidates()
            .map_err(|error| backend_error(format!("campaign ranking is invalid: {error}")))?
            .into_iter()
            .filter(|ranking| {
                branch_point.is_none_or(|expected| ranking.proposal().branch_point() == expected)
                    && source.is_none_or(|expected| ranking.proposal().request() == expected)
            })
            .map(|ranking| RankedPageCandidate {
                step: current,
                ranking,
            })
            .collect::<Vec<_>>();
        if args.policy_groups {
            collect_policy_ranking_page(&mut policy_groups, page_basis, current, page_candidates)?;
        } else {
            candidates.extend(page_candidates);
        }
        step = response.parent();
        pages += 1;
    }

    let (matched_candidates, rankings, policy_groups) = if args.policy_groups {
        let (matched, groups) = finish_policy_ranking_groups(policy_groups, args.top)?;
        (matched, Vec::new(), groups)
    } else {
        sort_ranked_candidates(&mut candidates);
        let matched = candidate_count(candidates.len())?;
        truncate_ranked_candidates(&mut candidates, args.top)?;
        (matched, ranking_entries(candidates)?, Vec::new())
    };
    Ok(CampaignRankingReport {
        schema: if args.policy_groups {
            CAMPAIGN_POLICY_RANKING_REPORT_SCHEMA
        } else {
            CAMPAIGN_RANKING_REPORT_SCHEMA
        },
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        start_step: start_step.to_string(),
        pages,
        filters: CampaignRankingFilters {
            policy_groups: args.policy_groups,
            branch_point: branch_point.map(|value| value.to_string()),
            source: source.map(|value| value.to_string()),
            top: args.top,
        },
        matched_candidates,
        next_step: step.map(|value| value.to_string()),
        rankings,
        policy_groups,
    })
}

fn ranking_basis_boundary(
    policy_groups: bool,
    current: Option<RankingBasis>,
    next: RankingBasis,
) -> bool {
    !policy_groups && current.is_some_and(|basis| basis != next)
}

fn collect_policy_ranking_page(
    groups: &mut Vec<CollectedPolicyRankingGroup>,
    basis: RankingBasis,
    step: PlannerStepId,
    candidates: Vec<RankedPageCandidate>,
) -> Result<(), CliError> {
    if let Some(group) = groups.last_mut().filter(|group| group.basis == basis) {
        group.oldest_step = step;
        group.pages = group
            .pages
            .checked_add(1)
            .ok_or_else(|| backend_error("campaign policy-ranking page count overflowed"))?;
        group.candidates.extend(candidates);
    } else {
        groups.push(CollectedPolicyRankingGroup {
            basis,
            newest_step: step,
            oldest_step: step,
            pages: 1,
            candidates,
        });
    }
    Ok(())
}

fn finish_policy_ranking_groups(
    groups: Vec<CollectedPolicyRankingGroup>,
    top: Option<u32>,
) -> Result<(u64, Vec<CampaignPolicyRankingGroup>), CliError> {
    let mut total_matched = 0_u64;
    let mut policy_groups = Vec::<CampaignPolicyRankingGroup>::new();
    for mut group in groups {
        sort_ranked_candidates(&mut group.candidates);
        let matched_candidates = candidate_count(group.candidates.len())?;
        total_matched = total_matched
            .checked_add(matched_candidates)
            .ok_or_else(|| backend_error("campaign policy-ranking match count overflowed"))?;
        truncate_ranked_candidates(&mut group.candidates, top)?;

        let policy = group.basis.policy.to_string();
        let policy_group = if policy_groups
            .last()
            .is_some_and(|current| current.policy == policy)
        {
            policy_groups
                .last_mut()
                .ok_or_else(|| backend_error("campaign policy-ranking group disappeared"))?
        } else {
            let index = policy_groups
                .len()
                .checked_add(1)
                .ok_or_else(|| backend_error("campaign policy-ranking group count overflowed"))?;
            policy_groups.push(CampaignPolicyRankingGroup {
                group: index,
                policy,
                newest_step: group.newest_step.to_string(),
                oldest_step: group.oldest_step.to_string(),
                pages: 0,
                matched_candidates: 0,
                bases: Vec::new(),
            });
            policy_groups
                .last_mut()
                .ok_or_else(|| backend_error("campaign policy-ranking group was not retained"))?
        };
        policy_group.oldest_step = group.oldest_step.to_string();
        policy_group.pages = policy_group
            .pages
            .checked_add(group.pages)
            .ok_or_else(|| backend_error("campaign policy-ranking page count overflowed"))?;
        policy_group.matched_candidates = policy_group
            .matched_candidates
            .checked_add(matched_candidates)
            .ok_or_else(|| backend_error("campaign policy-ranking match count overflowed"))?;
        let basis = policy_group
            .bases
            .len()
            .checked_add(1)
            .ok_or_else(|| backend_error("campaign ranking-basis group count overflowed"))?;
        policy_group.bases.push(CampaignRankingBasisGroup {
            basis,
            engine: group.basis.engine.to_string(),
            policy_artifact: group.basis.policy_artifact.to_string(),
            input_view: group.basis.input_view.to_string(),
            newest_step: group.newest_step.to_string(),
            oldest_step: group.oldest_step.to_string(),
            pages: group.pages,
            matched_candidates,
            rankings: ranking_entries(group.candidates)?,
        });
    }
    Ok((total_matched, policy_groups))
}

fn sort_ranked_candidates(candidates: &mut [RankedPageCandidate]) {
    candidates.sort_by(|left, right| {
        left.ranking
            .best_first_cmp(&right.ranking)
            .then_with(|| left.step.cmp(&right.step))
    });
}

fn candidate_count(count: usize) -> Result<u64, CliError> {
    u64::try_from(count).map_err(|_| backend_error("campaign ranking match count does not fit u64"))
}

fn truncate_ranked_candidates(
    candidates: &mut Vec<RankedPageCandidate>,
    top: Option<u32>,
) -> Result<(), CliError> {
    if let Some(top) = top {
        let top = usize::try_from(top)
            .map_err(|_| backend_error("campaign ranking top count does not fit usize"))?;
        candidates.truncate(top);
    }
    Ok(())
}

fn ranking_entries(
    candidates: Vec<RankedPageCandidate>,
) -> Result<Vec<CampaignRankingEntry>, CliError> {
    candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| ranking_entry(index + 1, candidate))
        .collect()
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
    if !report.policy_groups.is_empty() {
        return render_policy_ranking_rows(report, markdown);
    }
    render_ranking_entries(&report.rankings, markdown)
        .trim_end()
        .to_owned()
}

fn render_policy_ranking_rows(report: &CampaignRankingReport, markdown: bool) -> String {
    let mut output = String::new();
    for group in &report.policy_groups {
        if !output.is_empty() {
            output.push('\n');
        }
        if markdown {
            output.push_str(&format!(
                "## Policy group {}\n\nPolicy: `{}`  \nNewest step: `{}`  \nOldest step: `{}`  \nPages: {}  \nMatched candidates: {}\n",
                group.group,
                group.policy,
                group.newest_step,
                group.oldest_step,
                group.pages,
                group.matched_candidates,
            ));
        } else {
            output.push_str(&format!(
                "policy-group {} policy={} newest={} oldest={} pages={} matched={}\n",
                group.group,
                group.policy,
                group.newest_step,
                group.oldest_step,
                group.pages,
                group.matched_candidates,
            ));
        }
        for basis in &group.bases {
            if markdown {
                output.push_str(&format!(
                    "\n### Comparable basis {}\n\nEngine: `{}`  \nPolicy artifact: `{}`  \nInput view: `{}`  \nNewest step: `{}`  \nOldest step: `{}`  \nPages: {}  \nMatched candidates: {}\n\n",
                    basis.basis,
                    basis.engine,
                    basis.policy_artifact,
                    basis.input_view,
                    basis.newest_step,
                    basis.oldest_step,
                    basis.pages,
                    basis.matched_candidates,
                ));
            } else {
                output.push_str(&format!(
                    "basis {} engine={} artifact={} view={} newest={} oldest={} pages={} matched={}\n",
                    basis.basis,
                    basis.engine,
                    basis.policy_artifact,
                    basis.input_view,
                    basis.newest_step,
                    basis.oldest_step,
                    basis.pages,
                    basis.matched_candidates,
                ));
            }
            output.push_str(&render_ranking_entries(&basis.rankings, markdown));
        }
    }
    output.trim_end().to_owned()
}

fn render_ranking_entries(entries: &[CampaignRankingEntry], markdown: bool) -> String {
    let mut output = if markdown {
        String::from(
            "| Rank | Proposal | Value | Total | Mean | Explore | Novelty | Fairness | Step |\n| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n",
        )
    } else {
        String::from("rank total proposal value step\n")
    };
    for entry in entries {
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
    output
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

    fn ranking_basis(label: &[u8]) -> RankingBasis {
        let id = |kind: CampaignRecordKind| {
            ContentId::for_bytes(kind.object_kind(), kind.schema_version(), label)
        };
        RankingBasis {
            policy: CampaignPolicyId::parse(&format!(
                "crucible.campaign.policy@{}",
                id(CampaignRecordKind::Policy)
            ))
            .expect("policy ID"),
            engine: PlannerEngineId::parse(&format!(
                "crucible.campaign.planner-engine@{}",
                id(CampaignRecordKind::PlannerEngine)
            ))
            .expect("planner engine ID"),
            policy_artifact: PolicyArtifactId::parse(&format!(
                "crucible.campaign.policy-artifact@{}",
                id(CampaignRecordKind::PolicyArtifact)
            ))
            .expect("policy artifact ID"),
            input_view: CampaignViewId::parse(&format!(
                "crucible.campaign.planning-view@{}",
                id(CampaignRecordKind::PlanningView)
            ))
            .expect("planning view ID"),
        }
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
            policy_groups: false,
            branch_point: None,
            source: None,
            top: None,
        });
        assert!(validate_campaign_rankings_command(&command).is_err());

        let CampaignCommand::Rankings(mut args) = command else {
            panic!("ranking command")
        };
        args.pages = 1;
        args.top = Some(0);
        assert!(validate_campaign_rankings_command(&CampaignCommand::Rankings(args)).is_err());
    }

    #[test]
    fn ranking_reports_render_machine_and_human_views() {
        let report = CampaignRankingReport {
            schema: CAMPAIGN_RANKING_REPORT_SCHEMA,
            campaign: "example".to_owned(),
            snapshot: "snapshot".to_owned(),
            start_step: "step".to_owned(),
            pages: 1,
            filters: CampaignRankingFilters {
                policy_groups: false,
                branch_point: Some("point".to_owned()),
                source: None,
                top: Some(1),
            },
            matched_candidates: 2,
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
            policy_groups: Vec::new(),
        };
        let json = render_campaign_rankings(&report, OutputFormat::Json).expect("ranking JSON");
        assert!(json.contains(CAMPAIGN_RANKING_REPORT_SCHEMA));
        assert!(json.contains("\"branch_point\": \"point\""));
        assert!(json.contains("\"matched_candidates\": 2"));
        assert!(json.contains("\"next_step\": \"parent\""));
        assert!(!json.contains("\"policy_groups\""));
        let table = render_campaign_rankings(&report, OutputFormat::Table).expect("ranking table");
        assert!(table.contains("1 26 proposal true step"));
        let markdown =
            render_campaign_rankings(&report, OutputFormat::Markdown).expect("ranking Markdown");
        assert!(markdown.contains("| 1 | proposal | true | 26 |"));
    }

    #[test]
    fn policy_ranking_groups_preserve_exact_comparison_epochs() {
        let first = ranking_basis(b"first policy basis");
        let second = ranking_basis(b"second policy basis");
        let first_newest = planner_step(b"first newest step");
        let first_oldest = planner_step(b"first oldest step");
        let first_changed_view_step = planner_step(b"first changed view step");
        let second_step = planner_step(b"second step");
        let resumed_first_step = planner_step(b"resumed first policy step");
        let mut first_changed_view = ranking_basis(b"first changed view");
        first_changed_view.policy = first.policy;
        first_changed_view.engine = first.engine;
        first_changed_view.policy_artifact = first.policy_artifact;
        assert!(ranking_basis_boundary(
            false,
            Some(first),
            first_changed_view
        ));
        assert!(!ranking_basis_boundary(
            true,
            Some(first),
            first_changed_view
        ));
        let mut groups = Vec::new();
        collect_policy_ranking_page(&mut groups, first, first_newest, Vec::new())
            .expect("first policy page");
        collect_policy_ranking_page(&mut groups, first, first_oldest, Vec::new())
            .expect("second page in first policy");
        collect_policy_ranking_page(
            &mut groups,
            first_changed_view,
            first_changed_view_step,
            Vec::new(),
        )
        .expect("changed basis in first policy");
        collect_policy_ranking_page(&mut groups, second, second_step, Vec::new())
            .expect("second policy page");
        collect_policy_ranking_page(&mut groups, first, resumed_first_step, Vec::new())
            .expect("resumed first policy page");

        let (matched, groups) =
            finish_policy_ranking_groups(groups, Some(1)).expect("finished policy groups");
        assert_eq!(matched, 0);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].pages, 3);
        assert_eq!(groups[0].newest_step, first_newest.to_string());
        assert_eq!(groups[0].oldest_step, first_changed_view_step.to_string());
        assert_eq!(groups[0].bases.len(), 2);
        assert_eq!(groups[0].bases[0].pages, 2);
        assert_eq!(groups[0].bases[0].oldest_step, first_oldest.to_string());
        assert_eq!(groups[1].policy, second.policy.to_string());
        assert_eq!(groups[2].policy, first.policy.to_string());
        assert_eq!(groups[2].newest_step, resumed_first_step.to_string());

        let report = CampaignRankingReport {
            schema: CAMPAIGN_POLICY_RANKING_REPORT_SCHEMA,
            campaign: "example".to_owned(),
            snapshot: "snapshot".to_owned(),
            start_step: first_newest.to_string(),
            pages: 5,
            filters: CampaignRankingFilters {
                policy_groups: true,
                branch_point: None,
                source: None,
                top: Some(1),
            },
            matched_candidates: matched,
            next_step: None,
            rankings: Vec::new(),
            policy_groups: groups,
        };
        let json = render_campaign_rankings(&report, OutputFormat::Json).expect("policy JSON");
        assert!(json.contains(CAMPAIGN_POLICY_RANKING_REPORT_SCHEMA));
        assert!(json.contains("\"policy_groups\": true"));
        assert!(json.contains("\"bases\""));
        assert!(json.contains("\"pages\": 3"));
        let table = render_campaign_rankings(&report, OutputFormat::Table).expect("policy table");
        assert!(table.contains("policy-group 1"));
        assert!(table.contains("pages=3 matched=0"));
        assert!(table.contains("basis 2"));
        let markdown =
            render_campaign_rankings(&report, OutputFormat::Markdown).expect("policy Markdown");
        assert!(markdown.contains("## Policy group 3"));
        assert!(markdown.contains("### Comparable basis 2"));
        assert!(markdown.contains("Matched candidates: 0"));
    }
}
