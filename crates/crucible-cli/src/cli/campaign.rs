//! Thin local client for authenticated lazy-campaign inspection and control.

use super::*;

#[path = "campaign/object.rs"]
mod object;

use object::{query_campaign_object, render_campaign_object, validate_campaign_object_basis};

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::net::UnixStream;

use crucible_campaign::{
    ActiveAttemptPolicy, AlternativeId, ApplyCampaignCommandRequest, BranchBudget, BranchPointId,
    BranchRequest, BranchRequestCause, BranchRequestId, BudgetGrant, CampaignClient,
    CampaignCommandId, CampaignControlAction, CampaignHash, CampaignLineage, CampaignName,
    CampaignPolicy, CampaignPolicyId, CampaignPrincipal, CampaignService,
    CampaignServiceFailureSource, CampaignSnapshotId, CampaignState, CandidateSource,
    ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId, ContinuationState,
    ControlRequest, CreateCampaignRequest, DeriveCampaignRequest, GetCampaignRequest, IntegerValue,
    MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES, QueryCampaignChoicesRequest,
    QueryCampaignFrontierRequest, QueryCampaignGraphRequest, StopCondition,
    SubmitCampaignBranchRequest, WatchCampaignRequest,
};
use crucible_daemon::LoopbackCampaignService;
use serde::Serialize;

const CAMPAIGN_HEAD_REPORT_SCHEMA: &str = "crucible.cli.campaign-head.v1";
const CAMPAIGN_MUTATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-mutation.v1";
const CAMPAIGN_PAGE_REPORT_SCHEMA: &str = "crucible.cli.campaign-page.v1";
const CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA: &str = "crucible.cli.campaign-acceptance.v1";

#[derive(Serialize)]
struct CampaignHeadReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    lineage: String,
    policy: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    advanced: Option<bool>,
}

#[derive(Serialize)]
struct CampaignMutationReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    command: String,
    prior_snapshot: String,
    new_snapshot: String,
    replayed: bool,
}

#[derive(Serialize)]
struct CampaignPageReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after: Option<String>,
    entries: Vec<CampaignPageEntry>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CampaignPageEntry {
    Graph {
        key: String,
        object: String,
    },
    Choice {
        opportunity: String,
    },
    Frontier {
        request: String,
        branch_point: String,
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        completed_visits: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        required_visits: Option<u64>,
    },
}

enum PreparedCampaignCommand {
    Create(CreateCampaignRequest),
    Derive(DeriveCampaignRequest),
    Branch(SubmitCampaignBranchRequest),
}

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum CampaignAcceptanceReport {
    Create {
        schema: &'static str,
        campaign: String,
        snapshot: String,
        lineage: String,
        active_policy: String,
        replayed: bool,
    },
    Derive {
        schema: &'static str,
        source_campaign: String,
        source_snapshot: String,
        campaign: String,
        new_snapshot: String,
        active_policy: String,
        replayed: bool,
    },
    Branch {
        schema: &'static str,
        campaign: String,
        request: String,
        prior_snapshot: String,
        new_snapshot: String,
        replayed: bool,
    },
}

#[derive(Clone, Copy)]
struct CampaignMutationBasisRef<'a> {
    name: &'a str,
    expected: &'a str,
    command: &'a str,
}

pub(super) fn run_campaign_invocation(cli: &Cli, args: &CampaignArgs) -> Result<(), CliError> {
    let principal = CampaignPrincipal::new(args.principal.clone())
        .map_err(|error| usage_error(format!("invalid campaign principal: {error}")))?;
    let prepared = prepare_campaign_command(&args.command, &principal)?;
    let stream = UnixStream::connect(&args.socket).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!(
                "could not connect to campaign service at {}: {error}",
                args.socket.display()
            ),
        ))
    })?;
    let service = LoopbackCampaignService::new(stream)
        .map_err(|error| backend_error(format!("campaign transport setup failed: {error}")))?;
    let client = CampaignClient::new(service);
    let rendered = match &args.command {
        CampaignCommand::Create(_) | CampaignCommand::Derive(_) | CampaignCommand::Branch(_) => {
            let prepared = prepared.ok_or_else(|| {
                backend_error("campaign acceptance command was not prepared before connection")
            })?;
            let report = apply_campaign_acceptance(&client, prepared)?;
            render_campaign_acceptance(&report, cli.output_format())?
        }
        CampaignCommand::Status(_) | CampaignCommand::Watch(_) => {
            let report = query_campaign_head(&client, principal, &args.command)?;
            render_campaign_head(&report, cli.output_format())?
        }
        CampaignCommand::Graph(_) | CampaignCommand::Choices(_) | CampaignCommand::Frontier(_) => {
            let report = query_campaign_page(&client, principal, &args.command)?;
            render_campaign_page(&report, cli.output_format())?
        }
        CampaignCommand::GraphObject(_)
        | CampaignCommand::ChoiceObject(_)
        | CampaignCommand::FrontierObject(_) => {
            let report = query_campaign_object(&client, principal, &args.command)?;
            render_campaign_object(&report, cli.output_format())?
        }
        _ => {
            let report = apply_campaign_mutation(&client, principal, &args.command)?;
            render_campaign_mutation(&report, cli.output_format())?
        }
    };

    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
fn validate_campaign_command(command: &CampaignCommand) -> Result<(), CliError> {
    let principal = CampaignPrincipal::new("validation")
        .map_err(|error| backend_error(format!("validation principal is invalid: {error}")))?;
    prepare_campaign_command(command, &principal).map(|_| ())
}

fn prepare_campaign_command(
    command: &CampaignCommand,
    principal: &CampaignPrincipal,
) -> Result<Option<PreparedCampaignCommand>, CliError> {
    match command {
        CampaignCommand::Create(create) => {
            let campaign = campaign_name(&create.name)?;
            let lineage = CampaignLineage::from_canonical_bytes(&read_campaign_record(
                &create.lineage,
                "campaign lineage",
            )?)
            .map_err(|error| usage_error(format!("invalid campaign lineage record: {error}")))?;
            let policy = CampaignPolicy::from_canonical_bytes(&read_campaign_record(
                &create.policy,
                "campaign policy",
            )?)
            .map_err(|error| usage_error(format!("invalid campaign policy record: {error}")))?;
            let request = CreateCampaignRequest::new(principal.clone(), campaign, lineage, policy)
                .map_err(|error| {
                    usage_error(format!("invalid campaign creation basis: {error}"))
                })?;
            Ok(Some(PreparedCampaignCommand::Create(request)))
        }
        CampaignCommand::Derive(derive) => {
            let source = campaign_name(&derive.source)?;
            let target = campaign_name(&derive.target)?;
            let snapshot = CampaignSnapshotId::parse(&derive.snapshot)
                .map_err(|error| usage_error(format!("invalid derivation snapshot: {error}")))?;
            let policy = derive
                .policy
                .as_ref()
                .map(|path| {
                    CampaignPolicy::from_canonical_bytes(&read_campaign_record(
                        path,
                        "campaign policy",
                    )?)
                    .map_err(|error| {
                        usage_error(format!("invalid campaign policy record: {error}"))
                    })
                })
                .transpose()?;
            let request =
                DeriveCampaignRequest::new(principal.clone(), source, snapshot, target, policy)
                    .map_err(|error| {
                        usage_error(format!("invalid campaign derivation basis: {error}"))
                    })?;
            Ok(Some(PreparedCampaignCommand::Derive(request)))
        }
        CampaignCommand::Branch(branch) => prepare_campaign_branch(branch, principal).map(Some),
        CampaignCommand::Status(status) => {
            campaign_name(&status.name)?;
            Ok(None)
        }
        CampaignCommand::Watch(watch) => {
            campaign_name(&watch.name)?;
            watch
                .after
                .as_deref()
                .map(CampaignSnapshotId::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign watch cursor: {error}")))?;
            Ok(None)
        }
        CampaignCommand::Graph(page) => {
            validate_campaign_page(page, "graph", MAX_CAMPAIGN_QUERY_PAGE_ITEMS, |cursor| {
                CampaignHash::parse(cursor).map(|_| ())
            })?;
            Ok(None)
        }
        CampaignCommand::Choices(page) => {
            validate_campaign_page(
                page,
                "choice",
                MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS,
                |cursor| ChoiceOpportunityId::parse(cursor).map(|_| ()),
            )?;
            Ok(None)
        }
        CampaignCommand::Frontier(page) => {
            validate_campaign_page(
                page,
                "frontier",
                MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS,
                |cursor| BranchRequestId::parse(cursor).map(|_| ()),
            )?;
            Ok(None)
        }
        CampaignCommand::GraphObject(object) => {
            validate_campaign_object_basis(&object.name, &object.snapshot)?;
            CampaignHash::parse(&object.key)
                .map_err(|error| usage_error(format!("invalid campaign graph key: {error}")))?;
            Ok(None)
        }
        CampaignCommand::ChoiceObject(object) => {
            validate_campaign_object_basis(&object.name, &object.snapshot)?;
            ChoiceOpportunityId::parse(&object.opportunity).map_err(|error| {
                usage_error(format!("invalid campaign choice opportunity: {error}"))
            })?;
            Ok(None)
        }
        CampaignCommand::FrontierObject(object) => {
            validate_campaign_object_basis(&object.name, &object.snapshot)?;
            BranchRequestId::parse(&object.request).map_err(|error| {
                usage_error(format!("invalid campaign frontier request: {error}"))
            })?;
            Ok(None)
        }
        _ => {
            let (basis, _, _) = campaign_mutation_spec(command)?;
            campaign_name(basis.name)?;
            CampaignCommandId::parse(basis.command)
                .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
            CampaignSnapshotId::parse(basis.expected).map_err(|error| {
                usage_error(format!("invalid campaign snapshot precondition: {error}"))
            })?;
            Ok(None)
        }
    }
}

fn read_campaign_record(path: &Path, kind: &str) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not open {kind} at {}: {error}", path.display()),
        ))
    })?;
    let maximum = u64::try_from(MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES)
        .map_err(|_| backend_error("campaign message bound exceeds u64"))?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!("could not read {kind} at {}: {error}", path.display()),
            ))
        })?;
    if bytes.len() > MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES {
        return Err(usage_error(format!(
            "{kind} exceeds the {MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES}-byte campaign message bound"
        )));
    }
    Ok(bytes)
}

fn prepare_campaign_branch(
    branch: &CampaignBranchArgs,
    principal: &CampaignPrincipal,
) -> Result<PreparedCampaignCommand, CliError> {
    let campaign = campaign_name(&branch.name)?;
    let expected = CampaignSnapshotId::parse(&branch.expected)
        .map_err(|error| usage_error(format!("invalid campaign snapshot precondition: {error}")))?;
    let command = CampaignCommandId::parse(&branch.command)
        .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
    let branch_point = BranchPointId::parse(&branch.branch_point)
        .map_err(|error| usage_error(format!("invalid branch-point ID: {error}")))?;
    let parent = ConfigurationArtifactId::parse(&branch.parent)
        .map_err(|error| usage_error(format!("invalid parent configuration artifact: {error}")))?;
    let opportunity = ChoiceOpportunityId::parse(&branch.opportunity)
        .map_err(|error| usage_error(format!("invalid choice opportunity: {error}")))?;
    let domain = ChoiceDomainId::parse(&branch.domain)
        .map_err(|error| usage_error(format!("invalid choice domain: {error}")))?;

    let mut values = BTreeSet::new();
    for value in &branch.values {
        let value = parse_campaign_choice_value(value)?;
        if !values.insert(value) {
            return Err(usage_error("campaign branch contains a duplicate value"));
        }
    }
    let proposals =
        branch
            .proposals
            .unwrap_or(u64::try_from(values.len()).map_err(|_| {
                usage_error("campaign branch value count exceeds the budget width")
            })?);
    let budget = BranchBudget::new(proposals, branch.attempts)
        .map_err(|error| usage_error(format!("invalid campaign branch budget: {error}")))?;
    let request = BranchRequest::new(
        branch_point,
        parent,
        opportunity,
        domain,
        CandidateSource::finite(values)
            .map_err(|error| usage_error(format!("invalid finite branch source: {error}")))?,
        BranchRequestCause::Operator(command),
        budget,
        parse_campaign_stop_condition(&branch.stop)?,
    )
    .map_err(|error| usage_error(format!("invalid campaign branch request: {error}")))?;

    let submission =
        SubmitCampaignBranchRequest::new(principal.clone(), campaign, expected, request)
            .map_err(|error| usage_error(format!("invalid campaign branch submission: {error}")))?;
    Ok(PreparedCampaignCommand::Branch(submission))
}

fn parse_campaign_choice_value(value: &str) -> Result<ChoiceValue, CliError> {
    match value {
        "true" => Ok(ChoiceValue::Boolean(true)),
        "false" => Ok(ChoiceValue::Boolean(false)),
        _ => {
            let (kind, body) = value.split_once(':').ok_or_else(|| {
                usage_error(
                    "campaign branch value must be true, false, i64:N, u64:N, or discrete:ID",
                )
            })?;
            match kind {
                "i64" => body
                    .parse::<i64>()
                    .map(IntegerValue::Signed)
                    .map(ChoiceValue::Integer)
                    .map_err(|error| usage_error(format!("invalid signed branch value: {error}"))),
                "u64" => body
                    .parse::<u64>()
                    .map(IntegerValue::Unsigned)
                    .map(ChoiceValue::Integer)
                    .map_err(|error| {
                        usage_error(format!("invalid unsigned branch value: {error}"))
                    }),
                "discrete" => AlternativeId::parse(body)
                    .map(ChoiceValue::Discrete)
                    .map_err(|error| {
                        usage_error(format!("invalid discrete branch value: {error}"))
                    }),
                _ => Err(usage_error(
                    "campaign branch value kind must be i64, u64, or discrete",
                )),
            }
        }
    }
}

fn parse_campaign_stop_condition(value: &str) -> Result<StopCondition, CliError> {
    match value {
        "next-choice" => Ok(StopCondition::NextChoice),
        "terminal" => Ok(StopCondition::Terminal),
        _ => {
            let (kind, body) = value.split_once(':').ok_or_else(|| {
                usage_error(
                    "campaign stop must be next-choice, terminal, boundary:NAME, virtual-time-ns:N, or events:N",
                )
            })?;
            match kind {
                "boundary" => Ok(StopCondition::NamedBoundary(body.to_owned())),
                "virtual-time-ns" => body
                    .parse::<u64>()
                    .map(StopCondition::VirtualTimeNanoseconds)
                    .map_err(|error| usage_error(format!("invalid virtual-time stop: {error}"))),
                "events" => body
                    .parse::<u64>()
                    .map(StopCondition::EventCount)
                    .map_err(|error| usage_error(format!("invalid event-count stop: {error}"))),
                _ => Err(usage_error("unknown campaign stop-condition kind")),
            }
        }
    }
}

fn validate_campaign_page<F>(
    page: &CampaignPageArgs,
    kind: &str,
    maximum: u32,
    parse_cursor: F,
) -> Result<(), CliError>
where
    F: FnOnce(&str) -> Result<(), crucible_campaign::CampaignCodecError>,
{
    campaign_name(&page.name)?;
    CampaignSnapshotId::parse(&page.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign page snapshot: {error}")))?;
    if let Some(after) = page.after.as_deref() {
        parse_cursor(after)
            .map_err(|error| usage_error(format!("invalid campaign {kind} cursor: {error}")))?;
    }
    if page.limit == 0 || page.limit > maximum {
        return Err(usage_error(format!(
            "campaign {kind} page limit must be between 1 and {maximum}"
        )));
    }
    Ok(())
}

fn query_campaign_head<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignHeadReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    match command {
        CampaignCommand::Status(status) => {
            let campaign = campaign_name(&status.name)?;
            let request =
                GetCampaignRequest::new(principal, campaign.clone()).map_err(|error| {
                    usage_error(format!("invalid campaign status request: {error}"))
                })?;
            let response = client
                .get_campaign(&request)
                .map_err(|error| backend_error(format!("campaign status failed: {error}")))?;
            Ok(CampaignHeadReport {
                schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
                operation: "status",
                campaign: campaign.as_str().to_owned(),
                snapshot: response.snapshot().to_string(),
                lineage: response.lineage().to_string(),
                policy: response.policy().to_string(),
                state: campaign_state_label(response.state()),
                advanced: None,
            })
        }
        CampaignCommand::Watch(watch) => {
            let campaign = campaign_name(&watch.name)?;
            let after = watch
                .after
                .as_deref()
                .map(CampaignSnapshotId::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign watch cursor: {error}")))?;
            let request = WatchCampaignRequest::new(principal, campaign.clone(), after)
                .map_err(|error| usage_error(format!("invalid campaign watch request: {error}")))?;
            let response = client
                .watch_campaign(&request)
                .map_err(|error| backend_error(format!("campaign watch failed: {error}")))?;
            Ok(CampaignHeadReport {
                schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
                operation: "watch",
                campaign: campaign.as_str().to_owned(),
                snapshot: response.snapshot().to_string(),
                lineage: response.lineage().to_string(),
                policy: response.policy().to_string(),
                state: campaign_state_label(response.state()),
                advanced: Some(response.advanced()),
            })
        }
        _ => Err(backend_error(
            "campaign mutation reached the read-only command path",
        )),
    }
}

fn query_campaign_page<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignPageReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    match command {
        CampaignCommand::Graph(page) => {
            let (campaign, snapshot) = campaign_page_basis(page)?;
            let after = page
                .after
                .as_deref()
                .map(CampaignHash::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign graph cursor: {error}")))?;
            let request = QueryCampaignGraphRequest::new(
                principal,
                campaign.clone(),
                snapshot,
                after,
                page.limit,
            )
            .map_err(|error| usage_error(format!("invalid campaign graph query: {error}")))?;
            let response = client
                .query_campaign_graph(&request)
                .map_err(|error| backend_error(format!("campaign graph query failed: {error}")))?;
            Ok(CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "graph",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                next_after: response.next_after().map(|cursor| cursor.to_hex()),
                entries: response
                    .entries()
                    .iter()
                    .map(|entry| CampaignPageEntry::Graph {
                        key: entry.key().to_hex(),
                        object: entry.object().to_string(),
                    })
                    .collect(),
            })
        }
        CampaignCommand::Choices(page) => {
            let (campaign, snapshot) = campaign_page_basis(page)?;
            let after = page
                .after
                .as_deref()
                .map(ChoiceOpportunityId::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign choice cursor: {error}")))?;
            let request = QueryCampaignChoicesRequest::new(
                principal,
                campaign.clone(),
                snapshot,
                after,
                page.limit,
            )
            .map_err(|error| usage_error(format!("invalid campaign choices query: {error}")))?;
            let response = client.query_campaign_choices(&request).map_err(|error| {
                backend_error(format!("campaign choices query failed: {error}"))
            })?;
            Ok(CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "choices",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                next_after: response.next_after().map(|cursor| cursor.to_string()),
                entries: response
                    .entries()
                    .iter()
                    .map(|entry| CampaignPageEntry::Choice {
                        opportunity: entry.opportunity().to_string(),
                    })
                    .collect(),
            })
        }
        CampaignCommand::Frontier(page) => {
            let (campaign, snapshot) = campaign_page_basis(page)?;
            let after = page
                .after
                .as_deref()
                .map(BranchRequestId::parse)
                .transpose()
                .map_err(|error| {
                    usage_error(format!("invalid campaign frontier cursor: {error}"))
                })?;
            let request = QueryCampaignFrontierRequest::new(
                principal,
                campaign.clone(),
                snapshot,
                after,
                page.limit,
            )
            .map_err(|error| usage_error(format!("invalid campaign frontier query: {error}")))?;
            let response = client.query_campaign_frontier(&request).map_err(|error| {
                backend_error(format!("campaign frontier query failed: {error}"))
            })?;
            Ok(CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "frontier",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                next_after: response.next_after().map(|cursor| cursor.to_string()),
                entries: response
                    .entries()
                    .iter()
                    .map(|projection| {
                        let (state, completed_visits, required_visits) =
                            continuation_state_report(projection.state());
                        CampaignPageEntry::Frontier {
                            request: projection.request().to_string(),
                            branch_point: projection.branch_point().to_string(),
                            state,
                            completed_visits,
                            required_visits,
                        }
                    })
                    .collect(),
            })
        }
        _ => Err(backend_error(
            "non-page campaign command reached the page query path",
        )),
    }
}

fn campaign_page_basis(
    page: &CampaignPageArgs,
) -> Result<(CampaignName, CampaignSnapshotId), CliError> {
    let campaign = campaign_name(&page.name)?;
    let snapshot = CampaignSnapshotId::parse(&page.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign page snapshot: {error}")))?;
    Ok((campaign, snapshot))
}

const fn continuation_state_report(
    state: ContinuationState,
) -> (&'static str, Option<u64>, Option<u64>) {
    match state {
        ContinuationState::Ready => ("ready", None, None),
        ContinuationState::WaitingForFeedback(wait) => (
            "waiting-for-feedback",
            Some(wait.completed_visits()),
            Some(wait.required_visits()),
        ),
        ContinuationState::Open => ("open", None, None),
        ContinuationState::Exhausted => ("exhausted", None, None),
        ContinuationState::Closed => ("closed", None, None),
    }
}

fn apply_campaign_acceptance<S>(
    client: &CampaignClient<S>,
    prepared: PreparedCampaignCommand,
) -> Result<CampaignAcceptanceReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    match prepared {
        PreparedCampaignCommand::Create(request) => {
            let response = client
                .create_campaign(&request)
                .map_err(|error| backend_error(format!("campaign creation failed: {error}")))?;
            Ok(CampaignAcceptanceReport::Create {
                schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
                campaign: request.campaign().as_str().to_owned(),
                snapshot: response.snapshot().to_string(),
                lineage: response.lineage().to_string(),
                active_policy: response.active_policy().to_string(),
                replayed: response.replayed(),
            })
        }
        PreparedCampaignCommand::Derive(request) => {
            let response = client
                .derive_campaign(&request)
                .map_err(|error| backend_error(format!("campaign derivation failed: {error}")))?;
            Ok(CampaignAcceptanceReport::Derive {
                schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
                source_campaign: request.source_campaign().as_str().to_owned(),
                source_snapshot: response.source_snapshot().to_string(),
                campaign: request.target_campaign().as_str().to_owned(),
                new_snapshot: response.new_snapshot().to_string(),
                active_policy: response.active_policy().to_string(),
                replayed: response.replayed(),
            })
        }
        PreparedCampaignCommand::Branch(request) => {
            let response = client
                .submit_branch_request(&request)
                .map_err(|error| backend_error(format!("campaign branch failed: {error}")))?;
            Ok(CampaignAcceptanceReport::Branch {
                schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
                campaign: request.campaign().as_str().to_owned(),
                request: response.request().to_string(),
                prior_snapshot: response.prior_snapshot().to_string(),
                new_snapshot: response.new_snapshot().to_string(),
                replayed: response.replayed(),
            })
        }
    }
}

fn apply_campaign_mutation<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignMutationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let (basis, operation, action) = campaign_mutation_spec(command)?;
    let campaign = campaign_name(basis.name)?;
    let command_id = CampaignCommandId::parse(basis.command)
        .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
    let expected_snapshot = CampaignSnapshotId::parse(basis.expected)
        .map_err(|error| usage_error(format!("invalid campaign snapshot precondition: {error}")))?;
    let control = ControlRequest {
        command: command_id,
        expected_snapshot,
        action,
    };
    let request = ApplyCampaignCommandRequest::new(principal, campaign.clone(), control)
        .map_err(|error| usage_error(format!("invalid campaign mutation request: {error}")))?;
    let response = client
        .apply_campaign_command(&request)
        .map_err(|error| backend_error(format!("campaign {operation} failed: {error}")))?;

    Ok(CampaignMutationReport {
        schema: CAMPAIGN_MUTATION_REPORT_SCHEMA,
        operation,
        campaign: campaign.as_str().to_owned(),
        command: command_id.to_string(),
        prior_snapshot: response.prior_snapshot().to_string(),
        new_snapshot: response.new_snapshot().to_string(),
        replayed: response.replayed(),
    })
}

fn campaign_mutation_spec(
    command: &CampaignCommand,
) -> Result<
    (
        CampaignMutationBasisRef<'_>,
        &'static str,
        CampaignControlAction,
    ),
    CliError,
> {
    match command {
        CampaignCommand::Resume(basis) => Ok((
            mutation_basis_ref(basis),
            "resume",
            CampaignControlAction::Resume,
        )),
        CampaignCommand::Pause(pause) => Ok((
            mutation_basis_ref(&pause.basis),
            "pause",
            CampaignControlAction::Pause(pause.active.control_policy()),
        )),
        CampaignCommand::Stop(stop) => Ok((
            mutation_basis_ref(&stop.basis),
            if stop.seal { "seal" } else { "stop" },
            if stop.seal {
                CampaignControlAction::Seal
            } else {
                CampaignControlAction::Complete
            },
        )),
        CampaignCommand::Unseal(basis) => Ok((
            mutation_basis_ref(basis),
            "unseal",
            CampaignControlAction::Unseal,
        )),
        CampaignCommand::Budget(budget) => {
            let CampaignBudgetCommand::Add(add) = &budget.operation;
            let grant = BudgetGrant::new(add.proposals, add.attempts)
                .map_err(|error| usage_error(format!("invalid campaign budget grant: {error}")))?;
            Ok((
                CampaignMutationBasisRef {
                    name: &budget.name,
                    expected: &budget.expected,
                    command: &budget.command,
                },
                "budget-add",
                CampaignControlAction::GrantBudget(grant),
            ))
        }
        CampaignCommand::Steer(steer) => {
            let policy = CampaignPolicyId::parse(&steer.policy)
                .map_err(|error| usage_error(format!("invalid campaign policy ID: {error}")))?;
            Ok((
                mutation_basis_ref(&steer.basis),
                "steer",
                CampaignControlAction::ActivatePolicy(policy),
            ))
        }
        CampaignCommand::Create(_)
        | CampaignCommand::Derive(_)
        | CampaignCommand::Branch(_)
        | CampaignCommand::Status(_)
        | CampaignCommand::Watch(_)
        | CampaignCommand::Graph(_)
        | CampaignCommand::GraphObject(_)
        | CampaignCommand::Choices(_)
        | CampaignCommand::ChoiceObject(_)
        | CampaignCommand::Frontier(_)
        | CampaignCommand::FrontierObject(_) => Err(backend_error(
            "campaign non-control operation reached the control-mutation path",
        )),
    }
}

fn mutation_basis_ref(basis: &CampaignMutationBasisArgs) -> CampaignMutationBasisRef<'_> {
    CampaignMutationBasisRef {
        name: &basis.name,
        expected: &basis.expected,
        command: &basis.command,
    }
}

impl CampaignPausePolicyArg {
    const fn control_policy(self) -> ActiveAttemptPolicy {
        match self {
            Self::Drain => ActiveAttemptPolicy::Drain,
            Self::Checkpoint => ActiveAttemptPolicy::ExactCheckpoint,
            Self::Retry => ActiveAttemptPolicy::CancelAndRetry,
        }
    }
}

fn campaign_name(value: &str) -> Result<CampaignName, CliError> {
    CampaignName::new(value.to_owned())
        .map_err(|error| usage_error(format!("invalid campaign name: {error}")))
}

const fn campaign_state_label(state: CampaignState) -> &'static str {
    match state {
        CampaignState::Created => "created",
        CampaignState::Running => "running",
        CampaignState::Paused => "paused",
        CampaignState::Completed => "completed",
        CampaignState::Sealed => "sealed",
    }
}

fn render_campaign_head(
    report: &CampaignHeadReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => {
            let mut rows = vec![
                ("campaign", report.campaign.as_str()),
                ("snapshot", report.snapshot.as_str()),
                ("lineage", report.lineage.as_str()),
                ("policy", report.policy.as_str()),
                ("state", report.state),
            ];
            let advanced;
            if let Some(value) = report.advanced {
                advanced = value.to_string();
                rows.push(("advanced", advanced.as_str()));
            }
            Ok(rows
                .into_iter()
                .map(|(field, value)| format!("{field:<10} {value}"))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in [
                ("campaign", report.campaign.as_str()),
                ("snapshot", report.snapshot.as_str()),
                ("lineage", report.lineage.as_str()),
                ("policy", report.policy.as_str()),
                ("state", report.state),
            ] {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            if let Some(advanced) = report.advanced {
                output.push_str(&format!("| advanced | {advanced} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn render_campaign_mutation(
    report: &CampaignMutationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok([
            format!("{:<15} {}", "campaign", report.campaign),
            format!("{:<15} {}", "operation", report.operation),
            format!("{:<15} {}", "command", report.command),
            format!("{:<15} {}", "prior_snapshot", report.prior_snapshot),
            format!("{:<15} {}", "new_snapshot", report.new_snapshot),
            format!("{:<15} {}", "replayed", report.replayed),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| operation | {} |\n| command | {} |\n| prior_snapshot | {} |\n| new_snapshot | {} |\n| replayed | {} |",
            report.campaign,
            report.operation,
            report.command,
            report.prior_snapshot,
            report.new_snapshot,
            report.replayed
        )),
    }
}

fn render_campaign_acceptance(
    report: &CampaignAcceptanceReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(campaign_acceptance_fields(report)
            .into_iter()
            .map(|(field, value)| format!("{field:<16} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in campaign_acceptance_fields(report) {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn campaign_acceptance_fields(report: &CampaignAcceptanceReport) -> Vec<(&'static str, &str)> {
    match report {
        CampaignAcceptanceReport::Create {
            campaign,
            snapshot,
            lineage,
            active_policy,
            replayed,
            ..
        } => vec![
            ("operation", "create"),
            ("campaign", campaign),
            ("snapshot", snapshot),
            ("lineage", lineage),
            ("active_policy", active_policy),
            ("replayed", if *replayed { "true" } else { "false" }),
        ],
        CampaignAcceptanceReport::Derive {
            source_campaign,
            source_snapshot,
            campaign,
            new_snapshot,
            active_policy,
            replayed,
            ..
        } => vec![
            ("operation", "derive"),
            ("source_campaign", source_campaign),
            ("source_snapshot", source_snapshot),
            ("campaign", campaign),
            ("new_snapshot", new_snapshot),
            ("active_policy", active_policy),
            ("replayed", if *replayed { "true" } else { "false" }),
        ],
        CampaignAcceptanceReport::Branch {
            campaign,
            request,
            prior_snapshot,
            new_snapshot,
            replayed,
            ..
        } => vec![
            ("operation", "branch"),
            ("campaign", campaign),
            ("request", request),
            ("prior_snapshot", prior_snapshot),
            ("new_snapshot", new_snapshot),
            ("replayed", if *replayed { "true" } else { "false" }),
        ],
    }
}

fn render_campaign_page(
    report: &CampaignPageReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => render_campaign_page_table(report),
        OutputFormat::Markdown => Ok(render_campaign_page_markdown(report)),
    }
}

fn render_campaign_page_table(report: &CampaignPageReport) -> Result<String, CliError> {
    let mut lines = vec![
        format!("{:<11} {}", "campaign", report.campaign),
        format!("{:<11} {}", "snapshot", report.snapshot),
        format!(
            "{:<11} {}",
            "next_after",
            report.next_after.as_deref().unwrap_or("-")
        ),
        format!("{:<11} {}", "entries", report.entries.len()),
        String::new(),
    ];
    match report.operation {
        "graph" => lines.push(String::from("key\tobject")),
        "choices" => lines.push(String::from("opportunity")),
        "frontier" => lines.push(String::from(
            "request\tbranch_point\tstate\tcompleted_visits\trequired_visits",
        )),
        _ => return Err(backend_error("unknown campaign page report operation")),
    }
    for entry in &report.entries {
        lines.push(campaign_page_entry_row(entry, "\t"));
    }
    Ok(lines.join("\n"))
}

fn render_campaign_page_markdown(report: &CampaignPageReport) -> String {
    let mut output = format!(
        "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| snapshot | {} |\n| next_after | {} |\n| entries | {} |\n\n",
        report.campaign,
        report.snapshot,
        report.next_after.as_deref().unwrap_or("-"),
        report.entries.len()
    );
    match report.operation {
        "graph" => output.push_str("| Key | Object |\n| --- | --- |\n"),
        "choices" => output.push_str("| Opportunity |\n| --- |\n"),
        "frontier" => output.push_str(
            "| Request | Branch point | State | Completed visits | Required visits |\n| --- | --- | --- | --- | --- |\n",
        ),
        _ => {}
    }
    for entry in &report.entries {
        output.push_str("| ");
        output.push_str(&campaign_page_entry_row(entry, " | "));
        output.push_str(" |\n");
    }
    output.trim_end().to_owned()
}

fn campaign_page_entry_row(entry: &CampaignPageEntry, separator: &str) -> String {
    match entry {
        CampaignPageEntry::Graph { key, object } => format!("{key}{separator}{object}"),
        CampaignPageEntry::Choice { opportunity } => opportunity.clone(),
        CampaignPageEntry::Frontier {
            request,
            branch_point,
            state,
            completed_visits,
            required_visits,
        } => format!(
            "{request}{separator}{branch_point}{separator}{state}{separator}{}{separator}{}",
            completed_visits.map_or_else(|| "-".to_owned(), |value| value.to_string()),
            required_visits.map_or_else(|| "-".to_owned(), |value| value.to_string())
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::thread;

    use crucible_campaign::*;
    use crucible_cas::content_store::{ContentId, MemoryBlobBackend, ObjectKind};
    use crucible_daemon::serve_loopback_campaign_once;

    #[derive(Clone, Copy)]
    struct FixedHeadService;

    struct GraphPageService {
        map: MerkleMap,
        root: ContentId,
        snapshot: CampaignSnapshot,
        object_key: CampaignHash,
        object: ObjectEnvelope,
    }

    impl CampaignService for FixedHeadService {
        type Error = Infallible;

        fn create_campaign(
            &self,
            request: &CreateCampaignRequest,
        ) -> Result<CreateCampaignResponse, Self::Error> {
            Ok(
                CreateCampaignResponse::new(request, snapshot("created"), false)
                    .expect("fixed create response"),
            )
        }

        fn derive_campaign(
            &self,
            request: &DeriveCampaignRequest,
        ) -> Result<DeriveCampaignResponse, Self::Error> {
            let active_policy = request
                .policy()
                .map(CampaignPolicy::id)
                .transpose()
                .expect("derived policy ID")
                .unwrap_or_else(|| policy("policy"));
            Ok(DeriveCampaignResponse::new(
                request,
                CampaignDerivationResult {
                    source_snapshot: request.source_snapshot(),
                    new_snapshot: snapshot("derived"),
                    active_policy,
                    replayed: false,
                },
            )
            .expect("fixed derive response"))
        }

        fn get_campaign(
            &self,
            request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            Ok(GetCampaignResponse::new(
                request,
                snapshot("current"),
                lineage("lineage"),
                policy("policy"),
                CampaignState::Running,
            )
            .expect("fixed get response"))
        }

        fn get_campaign_snapshot(
            &self,
            _request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn watch_campaign(
            &self,
            request: &WatchCampaignRequest,
        ) -> Result<WatchCampaignResponse, Self::Error> {
            Ok(WatchCampaignResponse::new(
                request,
                snapshot("current"),
                lineage("lineage"),
                policy("policy"),
                CampaignState::Running,
            )
            .expect("fixed watch response"))
        }

        fn query_campaign_graph(
            &self,
            _request: &QueryCampaignGraphRequest,
        ) -> Result<QueryCampaignGraphResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_graph_object(
            &self,
            _request: &GetCampaignGraphObjectRequest,
        ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn query_campaign_choices(
            &self,
            _request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn query_campaign_frontier(
            &self,
            _request: &QueryCampaignFrontierRequest,
        ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_frontier_object(
            &self,
            _request: &GetCampaignFrontierObjectRequest,
        ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_choice_object(
            &self,
            _request: &GetCampaignChoiceObjectRequest,
        ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn apply_campaign_command(
            &self,
            request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            assert!(matches!(
                request.command().action,
                CampaignControlAction::Pause(ActiveAttemptPolicy::ExactCheckpoint)
            ));
            Ok(ApplyCampaignCommandResponse::new(
                request,
                CampaignCommandResult {
                    prior_snapshot: request.command().expected_snapshot,
                    new_snapshot: snapshot("mutated"),
                    replayed: false,
                },
            )
            .expect("fixed campaign mutation response"))
        }

        fn submit_branch_request(
            &self,
            request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            Ok(SubmitCampaignBranchResponse::new(
                request,
                BranchRequestResult {
                    prior_snapshot: request.expected_snapshot(),
                    new_snapshot: snapshot("branched"),
                    request: request.request().id().expect("branch request ID"),
                    replayed: false,
                },
            )
            .expect("fixed branch response"))
        }
    }

    impl CampaignService for GraphPageService {
        type Error = Infallible;

        fn create_campaign(
            &self,
            _request: &CreateCampaignRequest,
        ) -> Result<CreateCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn derive_campaign(
            &self,
            _request: &DeriveCampaignRequest,
        ) -> Result<DeriveCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign(
            &self,
            _request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_snapshot(
            &self,
            _request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn watch_campaign(
            &self,
            _request: &WatchCampaignRequest,
        ) -> Result<WatchCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn query_campaign_graph(
            &self,
            request: &QueryCampaignGraphRequest,
        ) -> Result<QueryCampaignGraphResponse, Self::Error> {
            let (page, proof) = self
                .map
                .scan_with_proof(self.root, request.after(), request.limit() as usize)
                .expect("proof-bearing graph page");
            let entries = page
                .entries()
                .iter()
                .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
                .collect();
            Ok(QueryCampaignGraphResponse::new(
                request,
                self.snapshot.clone(),
                entries,
                page.next_after(),
                proof,
            )
            .expect("bound graph response"))
        }

        fn get_campaign_graph_object(
            &self,
            request: &GetCampaignGraphObjectRequest,
        ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
            assert_eq!(request.key(), self.object_key);
            let (_, proof) = self
                .map
                .get_with_proof(self.root, request.key())
                .expect("proof-bearing graph object");
            Ok(GetCampaignGraphObjectResponse::new(
                request,
                self.snapshot.clone(),
                self.object.clone(),
                proof,
            )
            .expect("bound graph object response"))
        }

        fn query_campaign_choices(
            &self,
            _request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn query_campaign_frontier(
            &self,
            _request: &QueryCampaignFrontierRequest,
        ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_frontier_object(
            &self,
            _request: &GetCampaignFrontierObjectRequest,
        ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_choice_object(
            &self,
            _request: &GetCampaignChoiceObjectRequest,
        ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn apply_campaign_command(
            &self,
            _request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn submit_branch_request(
            &self,
            _request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }
    }

    #[test]
    fn campaign_head_report_renders_machine_and_human_forms() {
        let report = CampaignHeadReport {
            schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
            operation: "watch",
            campaign: "example".to_owned(),
            snapshot: "snapshot".to_owned(),
            lineage: "lineage".to_owned(),
            policy: "policy".to_owned(),
            state: "running",
            advanced: Some(true),
        };

        let json = render_campaign_head(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_HEAD_REPORT_SCHEMA);
        assert_eq!(decoded["advanced"], true);

        let table = render_campaign_head(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("campaign   example"));
        assert!(table.contains("advanced   true"));

        let markdown =
            render_campaign_head(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| state | running |"));
    }

    #[test]
    fn campaign_mutation_report_renders_exact_transition_basis() {
        let report = CampaignMutationReport {
            schema: CAMPAIGN_MUTATION_REPORT_SCHEMA,
            operation: "pause",
            campaign: "example".to_owned(),
            command: hash("pause").to_hex(),
            prior_snapshot: snapshot("prior").to_string(),
            new_snapshot: snapshot("next").to_string(),
            replayed: true,
        };

        let json = render_campaign_mutation(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_MUTATION_REPORT_SCHEMA);
        assert_eq!(decoded["prior_snapshot"], report.prior_snapshot);
        assert_eq!(decoded["new_snapshot"], report.new_snapshot);
        assert_eq!(decoded["replayed"], true);

        let table = render_campaign_mutation(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("operation       pause"));
        assert!(table.contains("replayed        true"));

        let markdown =
            render_campaign_mutation(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| prior_snapshot |"));
        assert!(markdown.contains("| new_snapshot |"));
    }

    #[test]
    fn campaign_acceptance_reports_render_exact_idempotent_results() {
        let reports = [
            CampaignAcceptanceReport::Create {
                schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
                campaign: "created".to_owned(),
                snapshot: snapshot("created").to_string(),
                lineage: lineage("lineage").to_string(),
                active_policy: policy("policy").to_string(),
                replayed: false,
            },
            CampaignAcceptanceReport::Derive {
                schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
                source_campaign: "source".to_owned(),
                source_snapshot: snapshot("source").to_string(),
                campaign: "derived".to_owned(),
                new_snapshot: snapshot("derived").to_string(),
                active_policy: policy("policy").to_string(),
                replayed: true,
            },
            CampaignAcceptanceReport::Branch {
                schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
                campaign: "created".to_owned(),
                request: branch_request("render")
                    .id()
                    .expect("request ID")
                    .to_string(),
                prior_snapshot: snapshot("prior").to_string(),
                new_snapshot: snapshot("next").to_string(),
                replayed: false,
            },
        ];

        for report in reports {
            let json =
                render_campaign_acceptance(&report, OutputFormat::Json).expect("JSON report");
            let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
            assert_eq!(decoded["schema"], CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA);
            assert!(decoded.get("operation").is_some());
            assert!(decoded.get("replayed").is_some());

            let table =
                render_campaign_acceptance(&report, OutputFormat::Table).expect("table report");
            assert!(table.contains("operation"));
            assert!(table.contains("replayed"));
            let markdown = render_campaign_acceptance(&report, OutputFormat::Markdown)
                .expect("Markdown report");
            assert!(markdown.contains("| replayed |"));
        }
    }

    #[test]
    fn campaign_page_reports_render_all_query_shapes() {
        let snapshot = snapshot("page").to_string();
        let reports = [
            CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "graph",
                campaign: "example".to_owned(),
                snapshot: snapshot.clone(),
                next_after: Some(hash("cursor").to_hex()),
                entries: vec![CampaignPageEntry::Graph {
                    key: hash("graph-key").to_hex(),
                    object: ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"object")
                        .to_string(),
                }],
            },
            CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "choices",
                campaign: "example".to_owned(),
                snapshot: snapshot.clone(),
                next_after: None,
                entries: vec![CampaignPageEntry::Choice {
                    opportunity: "choice".to_owned(),
                }],
            },
            CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "frontier",
                campaign: "example".to_owned(),
                snapshot,
                next_after: None,
                entries: vec![CampaignPageEntry::Frontier {
                    request: "request".to_owned(),
                    branch_point: "branch-point".to_owned(),
                    state: "waiting-for-feedback",
                    completed_visits: Some(3),
                    required_visits: Some(5),
                }],
            },
        ];

        for report in reports {
            let json = render_campaign_page(&report, OutputFormat::Json).expect("JSON page");
            let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
            assert_eq!(decoded["schema"], CAMPAIGN_PAGE_REPORT_SCHEMA);
            assert_eq!(decoded["operation"], report.operation);
            assert_eq!(decoded["entries"].as_array().map(Vec::len), Some(1));

            let table = render_campaign_page(&report, OutputFormat::Table).expect("table page");
            assert!(table.contains("campaign    example"));
            let markdown =
                render_campaign_page(&report, OutputFormat::Markdown).expect("Markdown page");
            assert!(markdown.contains("| entries | 1 |"));
        }
    }

    #[test]
    fn campaign_status_and_watch_use_the_checked_loopback_transport() {
        let status = CampaignCommand::Status(CampaignStatusArgs {
            name: "example".to_owned(),
        });
        let status_report = query_over_loopback(&status);
        assert_eq!(status_report.operation, "status");
        assert_eq!(status_report.snapshot, snapshot("current").to_string());
        assert_eq!(status_report.advanced, None);

        let watch = CampaignCommand::Watch(CampaignWatchArgs {
            name: "example".to_owned(),
            after: Some(snapshot("previous").to_string()),
        });
        let watch_report = query_over_loopback(&watch);
        assert_eq!(watch_report.operation, "watch");
        assert_eq!(watch_report.state, "running");
        assert_eq!(watch_report.advanced, Some(true));
    }

    #[test]
    fn campaign_graph_page_uses_the_checked_proof_bearing_transport() {
        let (service, snapshot) = graph_page_service();
        let command = CampaignCommand::Graph(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            after: None,
            limit: 1,
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve graph page request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_page(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked graph query");
        server.join().expect("campaign server thread");

        assert_eq!(report.operation, "graph");
        assert_eq!(report.snapshot, snapshot.to_string());
        assert_eq!(report.entries.len(), 1);
        assert!(report.next_after.is_some());
    }

    #[test]
    fn campaign_graph_object_uses_the_checked_proof_bearing_transport() {
        let (service, snapshot) = graph_page_service();
        let key = service.object_key;
        let command = CampaignCommand::GraphObject(CampaignGraphObjectArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            key: key.to_hex(),
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve graph object request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_object(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked graph object query");
        server.join().expect("campaign server thread");

        let rendered = render_campaign_object(&report, OutputFormat::Json).expect("object JSON");
        let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(decoded["schema"], "crucible.cli.campaign-object.v1");
        assert_eq!(decoded["operation"], "graph-object");
        assert_eq!(decoded["snapshot"], snapshot.to_string());
        assert_eq!(decoded["object"]["kind"], "configuration");
        assert_eq!(decoded["object"]["key"], key.to_hex());
    }

    #[test]
    fn campaign_create_derive_and_branch_use_checked_loopback_transport() {
        let (lineage_record, policy_record) = campaign_records();
        let principal = CampaignPrincipal::new("operator").expect("campaign principal");
        let create = accept_over_loopback(PreparedCampaignCommand::Create(
            CreateCampaignRequest::new(
                principal.clone(),
                CampaignName::new("created").expect("campaign name"),
                lineage_record,
                policy_record.clone(),
            )
            .expect("create request"),
        ));
        assert!(matches!(
            create,
            CampaignAcceptanceReport::Create { snapshot: value, replayed: false, .. }
                if value == snapshot("created").to_string()
        ));

        let derive = accept_over_loopback(PreparedCampaignCommand::Derive(
            DeriveCampaignRequest::new(
                principal.clone(),
                CampaignName::new("created").expect("source name"),
                snapshot("created"),
                CampaignName::new("derived").expect("target name"),
                Some(policy_record),
            )
            .expect("derive request"),
        ));
        assert!(matches!(
            derive,
            CampaignAcceptanceReport::Derive { new_snapshot, replayed: false, .. }
                if new_snapshot == snapshot("derived").to_string()
        ));

        let branch = accept_over_loopback(
            prepare_campaign_branch(&branch_args("branch"), &principal)
                .expect("prepared finite branch request"),
        );
        assert!(matches!(
            branch,
            CampaignAcceptanceReport::Branch { new_snapshot, replayed: false, .. }
                if new_snapshot == snapshot("branched").to_string()
        ));
    }

    #[test]
    fn campaign_create_and_derive_records_are_prepared_before_connection() {
        let temporary = tempfile::tempdir().expect("temporary campaign inputs");
        let lineage_path = temporary.path().join("lineage.bin");
        let policy_path = temporary.path().join("policy.bin");
        let (lineage_record, policy_record) = campaign_records();
        std::fs::write(&lineage_path, lineage_record.canonical_bytes()).expect("write lineage");
        std::fs::write(&policy_path, policy_record.canonical_bytes()).expect("write policy");

        let principal = CampaignPrincipal::new("operator").expect("campaign principal");
        let create = prepare_campaign_command(
            &CampaignCommand::Create(CampaignCreateArgs {
                name: "created".to_owned(),
                lineage: lineage_path,
                policy: policy_path.clone(),
            }),
            &principal,
        )
        .expect("prepare creation")
        .expect("prepared creation request");
        assert!(matches!(create, PreparedCampaignCommand::Create(_)));

        let derive = prepare_campaign_command(
            &CampaignCommand::Derive(CampaignDeriveArgs {
                source: "created".to_owned(),
                snapshot: snapshot("created").to_string(),
                target: "derived".to_owned(),
                policy: Some(policy_path),
            }),
            &principal,
        )
        .expect("prepare derivation")
        .expect("prepared derivation request");
        assert!(matches!(derive, PreparedCampaignCommand::Derive(_)));

        let corrupt_path = temporary.path().join("corrupt.bin");
        std::fs::write(&corrupt_path, b"not canonical").expect("write corrupt input");
        assert!(
            prepare_campaign_command(
                &CampaignCommand::Create(CampaignCreateArgs {
                    name: "invalid".to_owned(),
                    lineage: corrupt_path,
                    policy: temporary.path().join("absent-policy.bin"),
                }),
                &principal,
            )
            .is_err()
        );
    }

    #[test]
    fn campaign_mutation_uses_the_checked_loopback_transport() {
        let command = CampaignCommand::Pause(CampaignPauseArgs {
            basis: mutation_basis("pause"),
            active: CampaignPausePolicyArg::Checkpoint,
        });
        let report = mutate_over_loopback(&command);

        assert_eq!(report.operation, "pause");
        assert_eq!(report.command, hash("pause").to_hex());
        assert_eq!(report.prior_snapshot, snapshot("current").to_string());
        assert_eq!(report.new_snapshot, snapshot("mutated").to_string());
        assert!(!report.replayed);
    }

    #[test]
    fn campaign_mutation_actions_preserve_exact_operator_intent() {
        let resume = CampaignCommand::Resume(mutation_basis("resume"));
        assert!(matches!(
            campaign_mutation_spec(&resume).expect("resume mutation").2,
            CampaignControlAction::Resume
        ));

        for (active, expected) in [
            (CampaignPausePolicyArg::Drain, ActiveAttemptPolicy::Drain),
            (
                CampaignPausePolicyArg::Checkpoint,
                ActiveAttemptPolicy::ExactCheckpoint,
            ),
            (
                CampaignPausePolicyArg::Retry,
                ActiveAttemptPolicy::CancelAndRetry,
            ),
        ] {
            let pause = CampaignCommand::Pause(CampaignPauseArgs {
                basis: mutation_basis("pause"),
                active,
            });
            assert!(matches!(
                campaign_mutation_spec(&pause).expect("pause mutation").2,
                CampaignControlAction::Pause(policy) if policy == expected
            ));
        }

        let stop = CampaignCommand::Stop(CampaignStopArgs {
            basis: mutation_basis("stop"),
            seal: false,
        });
        assert!(matches!(
            campaign_mutation_spec(&stop).expect("stop mutation").2,
            CampaignControlAction::Complete
        ));
        let seal = CampaignCommand::Stop(CampaignStopArgs {
            basis: mutation_basis("seal"),
            seal: true,
        });
        assert!(matches!(
            campaign_mutation_spec(&seal).expect("seal mutation").2,
            CampaignControlAction::Seal
        ));

        let unseal = CampaignCommand::Unseal(mutation_basis("unseal"));
        assert!(matches!(
            campaign_mutation_spec(&unseal).expect("unseal mutation").2,
            CampaignControlAction::Unseal
        ));

        let budget = CampaignCommand::Budget(CampaignBudgetArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash("budget").to_hex(),
            operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                attempts: 11,
                proposals: 13,
            }),
        });
        assert!(matches!(
            campaign_mutation_spec(&budget).expect("budget mutation").2,
            CampaignControlAction::GrantBudget(grant)
                if grant.attempts() == 11 && grant.proposals() == 13
        ));
        let empty_budget = CampaignCommand::Budget(CampaignBudgetArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash("empty-budget").to_hex(),
            operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                attempts: 0,
                proposals: 0,
            }),
        });
        assert!(campaign_mutation_spec(&empty_budget).is_err());

        let steer = CampaignCommand::Steer(CampaignSteerArgs {
            basis: mutation_basis("steer"),
            policy: policy("next").to_string(),
        });
        assert!(matches!(
            campaign_mutation_spec(&steer).expect("steer mutation").2,
            CampaignControlAction::ActivatePolicy(next) if next == policy("next")
        ));
    }

    #[test]
    fn campaign_inputs_fail_before_transport_setup() {
        assert_eq!(
            parse_campaign_choice_value("i64:-7").expect("signed value"),
            ChoiceValue::Integer(IntegerValue::Signed(-7))
        );
        assert_eq!(
            parse_campaign_choice_value("u64:9").expect("unsigned value"),
            ChoiceValue::Integer(IntegerValue::Unsigned(9))
        );
        let alternative = AlternativeId::from_hash(hash("alternative"));
        assert_eq!(
            parse_campaign_choice_value(&format!("discrete:{alternative}"))
                .expect("discrete value"),
            ChoiceValue::Discrete(alternative)
        );

        let bad_watch = CampaignCommand::Watch(CampaignWatchArgs {
            name: "example".to_owned(),
            after: Some("not-a-snapshot".to_owned()),
        });
        assert!(validate_campaign_command(&bad_watch).is_err());

        let bad_graph_cursor = CampaignCommand::Graph(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            after: Some("not-a-hash".to_owned()),
            limit: 8,
        });
        assert!(validate_campaign_command(&bad_graph_cursor).is_err());
        let empty_choices_page = CampaignCommand::Choices(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            after: None,
            limit: 0,
        });
        assert!(validate_campaign_command(&empty_choices_page).is_err());
        let oversized_graph_page = CampaignCommand::Graph(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            after: None,
            limit: MAX_CAMPAIGN_QUERY_PAGE_ITEMS + 1,
        });
        assert!(validate_campaign_command(&oversized_graph_page).is_err());
        let bad_frontier_cursor = CampaignCommand::Frontier(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            after: Some("not-a-branch-request".to_owned()),
            limit: 8,
        });
        assert!(validate_campaign_command(&bad_frontier_cursor).is_err());
        let bad_graph_object = CampaignCommand::GraphObject(CampaignGraphObjectArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            key: "not-a-hash".to_owned(),
        });
        assert!(validate_campaign_command(&bad_graph_object).is_err());
        let bad_choice_object = CampaignCommand::ChoiceObject(CampaignChoiceObjectArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            opportunity: "not-an-opportunity".to_owned(),
            kind: CampaignChoiceObjectKindArg::Declaration,
        });
        assert!(validate_campaign_command(&bad_choice_object).is_err());
        let bad_frontier_object = CampaignCommand::FrontierObject(CampaignFrontierObjectArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            request: "not-a-request".to_owned(),
        });
        assert!(validate_campaign_command(&bad_frontier_object).is_err());

        let mut duplicate_branch = branch_args("duplicate");
        duplicate_branch.values = vec!["true".to_owned(), "true".to_owned()];
        assert!(validate_campaign_command(&CampaignCommand::Branch(duplicate_branch)).is_err());
        let mut invalid_stop = branch_args("invalid-stop");
        invalid_stop.stop = "events:0".to_owned();
        assert!(validate_campaign_command(&CampaignCommand::Branch(invalid_stop)).is_err());
        let mut invalid_budget = branch_args("invalid-budget");
        invalid_budget.proposals = Some(1);
        invalid_budget.attempts = 2;
        assert!(validate_campaign_command(&CampaignCommand::Branch(invalid_budget)).is_err());

        let mut bad_command_basis = mutation_basis("bad-command");
        bad_command_basis.command = "not-a-command".to_owned();
        assert!(validate_campaign_command(&CampaignCommand::Resume(bad_command_basis)).is_err());

        let empty_budget = CampaignCommand::Budget(CampaignBudgetArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash("empty-budget-validation").to_hex(),
            operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                attempts: 0,
                proposals: 0,
            }),
        });
        assert!(validate_campaign_command(&empty_budget).is_err());
    }

    #[test]
    fn campaign_status_and_watch_parse_under_the_nested_cli() {
        let status = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "status",
            "example",
        ])
        .expect("campaign status arguments");
        assert!(matches!(
            status.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Status(CampaignStatusArgs { ref name }),
                ..
            }) if name == "example"
        ));

        let cursor = snapshot("cursor").to_string();
        let watch = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "watch",
            "example",
            "--after",
            &cursor,
        ])
        .expect("campaign watch arguments");
        assert!(matches!(
            watch.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Watch(CampaignWatchArgs { after: Some(_), .. }),
                ..
            })
        ));

        for operation in ["graph", "choices", "frontier"] {
            let page = Cli::try_parse_from([
                "crucible",
                "campaign",
                "--socket",
                "/run/crucible/campaign.sock",
                "--principal",
                "operator",
                operation,
                "example",
                "--snapshot",
                &snapshot("page").to_string(),
                "--limit",
                "3",
            ])
            .expect("campaign page arguments");
            assert!(matches!(
                page.command,
                Commands::Campaign(CampaignArgs {
                    command: CampaignCommand::Graph(CampaignPageArgs { limit: 3, .. })
                        | CampaignCommand::Choices(CampaignPageArgs { limit: 3, .. })
                        | CampaignCommand::Frontier(CampaignPageArgs { limit: 3, .. }),
                    ..
                })
            ));
        }

        let object_snapshot = snapshot("object").to_string();
        let graph_object = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "graph-object",
            "example",
            "--snapshot",
            &object_snapshot,
            "--key",
            &hash("graph-object").to_hex(),
        ])
        .expect("campaign graph-object arguments");
        assert!(matches!(
            graph_object.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::GraphObject(_),
                ..
            })
        ));

        let object_branch = branch_args("objects");
        let choice_object = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "choice-object",
            "example",
            "--snapshot",
            &object_snapshot,
            "--opportunity",
            &object_branch.opportunity,
            "--kind",
            "domain",
        ])
        .expect("campaign choice-object arguments");
        assert!(matches!(
            choice_object.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::ChoiceObject(CampaignChoiceObjectArgs {
                    kind: CampaignChoiceObjectKindArg::Domain,
                    ..
                }),
                ..
            })
        ));

        let frontier_object = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "frontier-object",
            "example",
            "--snapshot",
            &object_snapshot,
            "--request",
            &branch_request("objects")
                .id()
                .expect("request ID")
                .to_string(),
        ])
        .expect("campaign frontier-object arguments");
        assert!(matches!(
            frontier_object.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::FrontierObject(_),
                ..
            })
        ));

        let create = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "create",
            "created",
            "--lineage",
            "lineage.bin",
            "--policy",
            "policy.bin",
        ])
        .expect("campaign create arguments");
        assert!(matches!(
            create.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Create(CampaignCreateArgs { ref name, .. }),
                ..
            }) if name == "created"
        ));

        let derive = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "derive",
            "created",
            "--snapshot",
            &snapshot("created").to_string(),
            "derived",
            "--policy",
            "policy.bin",
        ])
        .expect("campaign derive arguments");
        assert!(matches!(
            derive.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Derive(CampaignDeriveArgs {
                    ref source,
                    ref target,
                    ..
                }),
                ..
            }) if source == "created" && target == "derived"
        ));

        let branch = branch_args("parse");
        let branch_cli = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "branch",
            "created",
            "--expected",
            &branch.expected,
            "--command",
            &branch.command,
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--opportunity",
            &branch.opportunity,
            "--domain",
            &branch.domain,
            "--value",
            "false",
            "--value",
            "true",
            "--attempts",
            "1",
            "--stop",
            "next-choice",
        ])
        .expect("campaign branch arguments");
        assert!(matches!(
            branch_cli.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Branch(CampaignBranchArgs { ref values, .. }),
                ..
            }) if values == &["false", "true"]
        ));

        let expected = snapshot("current").to_string();
        let command = hash("pause").to_hex();
        let pause = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "pause",
            "example",
            "--expected",
            &expected,
            "--command",
            &command,
            "--active",
            "checkpoint",
        ])
        .expect("campaign pause arguments");
        assert!(matches!(
            pause.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Pause(CampaignPauseArgs {
                    active: CampaignPausePolicyArg::Checkpoint,
                    ..
                }),
                ..
            })
        ));

        let budget = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "budget",
            "example",
            "--expected",
            &expected,
            "--command",
            &hash("budget").to_hex(),
            "add",
            "11",
            "--proposals",
            "13",
        ])
        .expect("campaign budget arguments");
        assert!(matches!(
            budget.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Budget(CampaignBudgetArgs {
                    operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                        attempts: 11,
                        proposals: 13,
                    }),
                    ..
                }),
                ..
            })
        ));
    }

    fn query_over_loopback(command: &CampaignCommand) -> CampaignHeadReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign request");
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report = query_campaign_head(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            command,
        )
        .expect("checked campaign query");
        server.join().expect("campaign server thread");
        report
    }

    fn mutate_over_loopback(command: &CampaignCommand) -> CampaignMutationReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign mutation");
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report = apply_campaign_mutation(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            command,
        )
        .expect("checked campaign mutation");
        server.join().expect("campaign server thread");
        report
    }

    fn accept_over_loopback(prepared: PreparedCampaignCommand) -> CampaignAcceptanceReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign acceptance");
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report =
            apply_campaign_acceptance(&client, prepared).expect("checked campaign acceptance");
        server.join().expect("campaign server thread");
        report
    }

    fn campaign_records() -> (CampaignLineage, CampaignPolicy) {
        let scenario = ScenarioDefId::from_hash(hash("scenario"));
        let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario-artifact".to_vec())
            .expect("scenario artifact");
        let scenario_artifact_id = scenario_artifact.id().expect("scenario artifact ID");
        let genesis = ConfigurationId::from_hash(hash("genesis"));
        let genesis_artifact = ConfigurationArtifact::new(
            scenario,
            scenario_artifact_id,
            genesis,
            1,
            b"genesis-artifact".to_vec(),
        )
        .expect("genesis artifact");
        let lineage = CampaignLineage::new(
            scenario,
            scenario_artifact_id,
            genesis,
            genesis_artifact.id().expect("genesis artifact ID"),
            "crucible-test",
            "qemu-test",
            BTreeMap::from([("control".to_owned(), 1)]),
            1,
            1,
        )
        .expect("campaign lineage");
        let policy = CampaignPolicy::new(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 64,
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("campaign policy");
        (lineage, policy)
    }

    fn branch_args(label: &str) -> CampaignBranchArgs {
        CampaignBranchArgs {
            name: "created".to_owned(),
            expected: snapshot("created").to_string(),
            command: CampaignCommandId::from_hash(hash(&format!("{label}-command"))).to_string(),
            branch_point: BranchPointId::from_hash(hash(&format!("{label}-point"))).to_string(),
            parent: ConfigurationArtifactId::parse(&format!(
                "crucible.campaign.configuration-artifact@{}",
                ContentId::for_bytes(
                    ObjectKind::Configuration,
                    1,
                    format!("{label}-parent").as_bytes(),
                )
                .encode()
            ))
            .expect("parent ID")
            .to_string(),
            opportunity: ChoiceOpportunityId::parse(&format!(
                "crucible.campaign.choice-opportunity@{}",
                ContentId::for_bytes(
                    ObjectKind::CampaignFact,
                    1,
                    format!("{label}-opportunity").as_bytes(),
                )
                .encode()
            ))
            .expect("opportunity ID")
            .to_string(),
            domain: ChoiceDomainId::parse(&format!(
                "crucible.campaign.choice-domain@{}",
                ContentId::for_bytes(
                    ObjectKind::CampaignFact,
                    1,
                    format!("{label}-domain").as_bytes(),
                )
                .encode()
            ))
            .expect("domain ID")
            .to_string(),
            values: vec!["false".to_owned(), "true".to_owned()],
            proposals: None,
            attempts: 1,
            stop: "next-choice".to_owned(),
        }
    }

    fn branch_request(label: &str) -> BranchRequest {
        let principal = CampaignPrincipal::new("operator").expect("campaign principal");
        let PreparedCampaignCommand::Branch(request) =
            prepare_campaign_branch(&branch_args(label), &principal).expect("branch request")
        else {
            unreachable!("branch preparation returned another operation")
        };
        request.request().clone()
    }

    fn graph_page_service() -> (GraphPageService, CampaignSnapshotId) {
        let backend = Arc::new(MemoryBlobBackend::new("cli-graph-page", u64::MAX));
        let map = MerkleMap::new(backend);
        let mut root = map.empty().expect("empty graph root");
        let scenario_artifact = ScenarioArtifactId::parse(&format!(
            "crucible.campaign.scenario-artifact@{}",
            ContentId::for_bytes(ObjectKind::Scenario, 1, b"cli-graph-scenario").encode()
        ))
        .expect("scenario artifact ID");
        let configuration = ConfigurationArtifact::new(
            ScenarioDefId::from_hash(hash("scenario")),
            scenario_artifact,
            ConfigurationId::from_hash(hash("configuration")),
            1,
            b"configuration".to_vec(),
        )
        .expect("configuration artifact");
        let object = ObjectEnvelope::for_configuration_artifact(&configuration)
            .expect("configuration envelope");
        let object_key = hash("first");
        root = map
            .insert(root.content_id(), object_key, object.content_id())
            .expect("configuration graph insertion");
        root = map
            .insert(
                root.content_id(),
                hash("second"),
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"second"),
            )
            .expect("second graph insertion");
        let roots = CampaignRoots {
            graph: root.content_id(),
            exploration: root.content_id(),
            observations: root.content_id(),
            corpus: root.content_id(),
            coverage: root.content_id(),
            findings: root.content_id(),
            pins: root.content_id(),
            accounting: root.content_id(),
            coordination: root.content_id(),
        };
        let snapshot = CampaignSnapshot::genesis(lineage("lineage"), policy("policy"), roots)
            .expect("graph snapshot");
        let snapshot_id = snapshot.id().expect("graph snapshot ID");
        (
            GraphPageService {
                map,
                root: root.content_id(),
                snapshot,
                object_key,
                object,
            },
            snapshot_id,
        )
    }

    fn mutation_basis(label: &str) -> CampaignMutationBasisArgs {
        CampaignMutationBasisArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash(label).to_hex(),
        }
    }

    fn hash(label: &str) -> CampaignHash {
        CampaignHash::derive("crucible-cli-campaign-test", label.as_bytes())
    }

    fn snapshot(label: &str) -> CampaignSnapshotId {
        CampaignSnapshotId::parse(&format!(
            "crucible.campaign.snapshot@{}",
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, 2, label.as_bytes()).encode()
        ))
        .expect("snapshot id")
    }

    fn lineage(label: &str) -> CampaignLineageId {
        CampaignLineageId::parse(&format!(
            "crucible.campaign.lineage@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()).encode()
        ))
        .expect("lineage id")
    }

    fn policy(label: &str) -> CampaignPolicyId {
        CampaignPolicyId::parse(&format!(
            "crucible.campaign.policy@{}",
            ContentId::for_bytes(ObjectKind::Policy, 1, label.as_bytes()).encode()
        ))
        .expect("policy id")
    }
}
