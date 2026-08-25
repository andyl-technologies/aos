//! Thin local client for authenticated lazy-campaign inspection and control.

use super::cli_campaign_import::{
    CampaignImportValidationReport, validate_campaign_import_manifests,
};
use super::*;

#[path = "campaign/explain.rs"]
mod explain;
#[path = "campaign/fixture.rs"]
mod fixture;
#[path = "campaign/object.rs"]
mod object;
#[path = "campaign/ranking.rs"]
mod ranking;
#[path = "campaign/snapshot.rs"]
mod snapshot;

use explain::{
    query_campaign_attempt_explanation, query_campaign_explanation,
    query_campaign_finding_explanation, render_campaign_attempt_explanation,
    render_campaign_explanation, render_campaign_finding_explanation,
    validate_campaign_attempt_explain_command, validate_campaign_explain_command,
    validate_campaign_finding_explain_command,
};
use fixture::{generate_worked_network_fixture, render_worked_network_fixture};
use object::{query_campaign_object, render_campaign_object, validate_campaign_object_basis};
use ranking::{
    query_campaign_rankings, render_campaign_rankings, validate_campaign_rankings_command,
};
use snapshot::{
    query_campaign_snapshot, render_campaign_snapshot, validate_campaign_snapshot_command,
};

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::net::UnixStream;

use crucible_campaign::{
    ActiveAttemptPolicy, AlternativeId, ApplyCampaignCommandRequest, BranchBudget, BranchPointId,
    BranchRequest, BranchRequestCause, BranchRequestId, BudgetGrant, CampaignChoiceObject,
    CampaignChoiceObjectKind, CampaignClient, CampaignCommandId, CampaignControlAction,
    CampaignHash, CampaignLineage, CampaignName, CampaignPolicy, CampaignPolicyId,
    CampaignPrincipal, CampaignService, CampaignServiceFailureSource, CampaignSnapshotId,
    CampaignState, CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateGeneratorSpecId,
    CandidateSource, ChoiceDomain, ChoiceDomainId, ChoiceOpportunityId, ChoiceValue,
    ConfigurationArtifactId, ConfigurationId, ContinuationState, ControlRequest,
    CreateCampaignRequest, DeriveCampaignRequest, FindingKind, GetCampaignChoiceObjectRequest,
    GetCampaignRequest, IntegerValue, MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES, PinCampaignRequest,
    PinChange, PinRequest, PinRetention, QueryCampaignChoicesRequest, QueryCampaignFindingsRequest,
    QueryCampaignFrontierRequest, QueryCampaignGraphRequest,
    STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION, SelectableDeclaration, SelectableId,
    StopCondition, SubmitCampaignBranchRequest, WatchCampaignRequest,
};
use crucible_daemon::LoopbackCampaignService;
use serde::Serialize;

const CAMPAIGN_HEAD_REPORT_SCHEMA: &str = "crucible.cli.campaign-head.v1";
const CAMPAIGN_MUTATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-mutation.v1";
const CAMPAIGN_PAGE_REPORT_SCHEMA: &str = "crucible.cli.campaign-page.v1";
const CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA: &str = "crucible.cli.campaign-acceptance.v2";
const MAX_CAMPAIGN_SELECTOR_SCAN_ITEMS: u32 = 4_096;
const MAX_CAMPAIGN_SELECTOR_PREDICATES: usize = 16;

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
    Finding {
        finding: String,
        cluster: String,
        finding_kind: &'static str,
        fingerprint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        property: Option<String>,
        failure_class: String,
        observation: String,
        occurrences: u32,
        reproduction: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimized: Option<String>,
    },
}

enum PreparedCampaignCommand {
    Create(CreateCampaignRequest),
    CreateAndStart(CreateCampaignRequest, CampaignCommandId),
    Derive(DeriveCampaignRequest),
    Branch(SubmitCampaignBranchRequest),
}

#[derive(Serialize)]
struct CampaignCreateStartReport {
    command: String,
    prior_snapshot: String,
    new_snapshot: String,
    replayed: bool,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        start: Option<CampaignCreateStartReport>,
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

struct ParsedCampaignBranchBasis {
    campaign: CampaignName,
    expected: CampaignSnapshotId,
    command: Option<CampaignCommandId>,
    branch_point: BranchPointId,
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
    domain: ChoiceDomainId,
    stop: StopCondition,
}

struct ParsedCampaignBranchCommonBasis {
    campaign: CampaignName,
    expected: CampaignSnapshotId,
    command: Option<CampaignCommandId>,
    branch_point: BranchPointId,
    parent: ConfigurationArtifactId,
    stop: StopCondition,
}

enum CampaignChoiceSelector {
    Name(String),
    Declaration(SelectableId),
    Tag(String),
}

pub(super) fn run_campaign_invocation(cli: &Cli, args: &CampaignArgs) -> Result<(), CliError> {
    if let CampaignCommand::Fixture(fixture) = &args.command {
        let report = match &fixture.fixture {
            CampaignFixtureCommand::WorkedNetwork(worked) => {
                generate_worked_network_fixture(&worked.output)?
            }
        };
        println!(
            "{}",
            render_worked_network_fixture(&report, cli.output_format())?
        );
        return Ok(());
    }
    if let CampaignCommand::ValidateImport(validate) = &args.command {
        let report = validate_campaign_import_manifests(&validate.manifests)?;
        println!(
            "{}",
            render_campaign_import_validation(&report, cli.output_format())?
        );
        return Ok(());
    }

    let socket = args
        .socket
        .as_ref()
        .ok_or_else(|| usage_error("connected campaign commands require --socket <path>"))?;
    let principal = args.principal.as_ref().ok_or_else(|| {
        usage_error("connected campaign commands require --principal <principal>")
    })?;
    let principal = CampaignPrincipal::new(principal.clone())
        .map_err(|error| usage_error(format!("invalid campaign principal: {error}")))?;
    let prepared = prepare_campaign_command(&args.command, &principal)?;
    let stream = UnixStream::connect(socket).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!(
                "could not connect to campaign service at {}: {error}",
                socket.display()
            ),
        ))
    })?;
    let service = LoopbackCampaignService::new(stream)
        .map_err(|error| backend_error(format!("campaign transport setup failed: {error}")))?;
    let client = CampaignClient::new(service);
    let rendered = match &args.command {
        CampaignCommand::ValidateImport(_) => {
            return Err(backend_error(
                "offline campaign import validation reached the connected dispatch path",
            ));
        }
        CampaignCommand::Fixture(_) => {
            return Err(backend_error(
                "offline campaign fixture generation reached the connected dispatch path",
            ));
        }
        CampaignCommand::Create(_) | CampaignCommand::Derive(_) => {
            let prepared = prepared.ok_or_else(|| {
                backend_error("campaign acceptance command was not prepared before connection")
            })?;
            let report = apply_campaign_acceptance(&client, prepared)?;
            render_campaign_acceptance(&report, cli.output_format())?
        }
        CampaignCommand::Branch(branch) => {
            let report = if !branch.selector.is_empty() {
                apply_campaign_selector_branch(&client, principal.clone(), branch)?
            } else if branch.all {
                apply_campaign_all_branch(&client, principal.clone(), branch)?
            } else {
                let prepared = prepared.ok_or_else(|| {
                    backend_error("campaign branch was not prepared before connection")
                })?;
                apply_campaign_acceptance(&client, prepared)?
            };
            render_campaign_acceptance(&report, cli.output_format())?
        }
        CampaignCommand::Status(_) | CampaignCommand::Watch(_) => {
            let report = query_campaign_head(&client, principal, &args.command)?;
            render_campaign_head(&report, cli.output_format())?
        }
        CampaignCommand::Snapshot(_) | CampaignCommand::Compare(_) => {
            let report = query_campaign_snapshot(&client, principal, &args.command)?;
            render_campaign_snapshot(&report, cli.output_format())?
        }
        CampaignCommand::Explain(_) => {
            let report = query_campaign_explanation(&client, principal, &args.command)?;
            render_campaign_explanation(&report, cli.output_format())?
        }
        CampaignCommand::ExplainFinding(_) => {
            let report = query_campaign_finding_explanation(&client, principal, &args.command)?;
            render_campaign_finding_explanation(&report, cli.output_format())?
        }
        CampaignCommand::ExplainAttempt(_) => {
            let report = query_campaign_attempt_explanation(&client, principal, &args.command)?;
            render_campaign_attempt_explanation(&report, cli.output_format())?
        }
        CampaignCommand::Rankings(_) => {
            let report = query_campaign_rankings(&client, principal, &args.command)?;
            render_campaign_rankings(&report, cli.output_format())?
        }
        CampaignCommand::Graph(_)
        | CampaignCommand::Choices(_)
        | CampaignCommand::Frontier(_)
        | CampaignCommand::Findings(_) => {
            let report = query_campaign_page(&client, principal, &args.command)?;
            render_campaign_page(&report, cli.output_format())?
        }
        CampaignCommand::GraphObject(_)
        | CampaignCommand::ChoiceObject(_)
        | CampaignCommand::FrontierObject(_) => {
            let report = query_campaign_object(&client, principal, &args.command)?;
            render_campaign_object(&report, cli.output_format())?
        }
        CampaignCommand::Pin(_) | CampaignCommand::Unpin(_) => {
            let report = apply_campaign_pin(&client, principal, &args.command)?;
            render_campaign_mutation(&report, cli.output_format())?
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
        CampaignCommand::Fixture(_) => Ok(None),
        CampaignCommand::ValidateImport(_) => Ok(None),
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
            let start_command = create
                .start_command
                .as_deref()
                .map(CampaignCommandId::parse)
                .transpose()
                .map_err(|error| {
                    usage_error(format!("invalid campaign start command ID: {error}"))
                })?;
            Ok(Some(match start_command {
                Some(command) => PreparedCampaignCommand::CreateAndStart(request, command),
                None => PreparedCampaignCommand::Create(request),
            }))
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
        CampaignCommand::Branch(branch) if !branch.selector.is_empty() => {
            parse_campaign_branch_common_basis(branch)?;
            parse_campaign_choice_selectors(&branch.selector)?;
            validate_campaign_selector_scan_limit(branch.selector_scan_limit)?;
            if let Some(instance) = &branch.instance {
                validate_campaign_selector_atom(instance, "campaign choice instance")?;
            }
            if branch.all
                && (branch.command.is_some()
                    || !branch.values.is_empty()
                    || branch.generator.is_some()
                    || branch.proposals.is_some())
            {
                return Err(usage_error(concat!(
                    "campaign --all branch cannot carry an operator command, values, ",
                    "a generator, or a proposal budget",
                )));
            }
            if !branch.all && branch.generator.is_none() && branch.values.is_empty() {
                return Err(usage_error(
                    "campaign selector branch requires finite values, a generator, or --all",
                ));
            }
            Ok(None)
        }
        CampaignCommand::Branch(branch) if branch.all => {
            parse_campaign_branch_basis(branch)?;
            if branch.command.is_some()
                || !branch.values.is_empty()
                || branch.generator.is_some()
                || branch.proposals.is_some()
            {
                return Err(usage_error(concat!(
                    "campaign --all branch cannot carry an operator command, values, ",
                    "a generator, or a proposal budget",
                )));
            }
            Ok(None)
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
        CampaignCommand::Findings(page) => {
            validate_campaign_page(
                page,
                "finding",
                MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
                |cursor| CampaignHash::parse(cursor).map(|_| ()),
            )?;
            Ok(None)
        }
        CampaignCommand::GraphObject(object) => {
            validate_campaign_object_basis(&object.name, &object.snapshot)?;
            CampaignHash::parse(&object.key)
                .map_err(|error| usage_error(format!("invalid campaign graph key: {error}")))?;
            Ok(None)
        }
        CampaignCommand::Snapshot(_) | CampaignCommand::Compare(_) => {
            validate_campaign_snapshot_command(command)?;
            Ok(None)
        }
        CampaignCommand::Explain(_) => {
            validate_campaign_explain_command(command)?;
            Ok(None)
        }
        CampaignCommand::ExplainFinding(_) => {
            validate_campaign_finding_explain_command(command)?;
            Ok(None)
        }
        CampaignCommand::ExplainAttempt(_) => {
            validate_campaign_attempt_explain_command(command)?;
            Ok(None)
        }
        CampaignCommand::Rankings(_) => {
            validate_campaign_rankings_command(command)?;
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
        CampaignCommand::Pin(_) | CampaignCommand::Unpin(_) => {
            let (basis, _, _) = campaign_pin_spec(command)?;
            campaign_name(basis.name)?;
            CampaignCommandId::parse(basis.command)
                .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
            CampaignSnapshotId::parse(basis.expected).map_err(|error| {
                usage_error(format!("invalid campaign snapshot precondition: {error}"))
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

fn render_campaign_import_validation(
    report: &CampaignImportValidationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!("campaign import JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!("campaign import JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<16} {}", "manifests", report.manifest_count()),
                format!("{:<16} {}", "configurations", report.configurations().len()),
                format!("{:<16} {}", "generators", report.generators().len()),
            ];
            lines.extend(
                report
                    .configurations()
                    .iter()
                    .map(|id| format!("{:<16} {id}", "configuration")),
            );
            lines.extend(
                report
                    .generators()
                    .iter()
                    .map(|id| format!("{:<16} {id}", "generator")),
            );
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| Kind | Identity |"),
                String::from("| --- | --- |"),
                format!("| manifests | {} |", report.manifest_count()),
            ];
            lines.extend(
                report
                    .configurations()
                    .iter()
                    .map(|id| format!("| configuration | {id} |")),
            );
            lines.extend(
                report
                    .generators()
                    .iter()
                    .map(|id| format!("| generator | {id} |")),
            );
            Ok(lines.join("\n"))
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
    let basis = parse_campaign_branch_basis(branch)?;
    prepare_campaign_branch_with_basis(branch, principal, basis)
}

fn prepare_campaign_branch_with_basis(
    branch: &CampaignBranchArgs,
    principal: &CampaignPrincipal,
    basis: ParsedCampaignBranchBasis,
) -> Result<PreparedCampaignCommand, CliError> {
    if branch.all || (branch.generator.is_some() && !branch.values.is_empty()) {
        return Err(usage_error(
            "campaign branch must use exactly one of finite values, a generator, or --all",
        ));
    }
    let mut values = BTreeSet::new();
    for value in &branch.values {
        let value = parse_campaign_choice_value(value)?;
        if !values.insert(value) {
            return Err(usage_error("campaign branch contains a duplicate value"));
        }
    }
    let (source, proposals) = if let Some(generator) = &branch.generator {
        let generator = CandidateGeneratorSpecId::parse(generator)
            .map_err(|error| usage_error(format!("invalid candidate generator: {error}")))?;
        let proposals = branch.proposals.ok_or_else(|| {
            usage_error("campaign generated branch requires an explicit proposal budget")
        })?;
        (CandidateSource::generated(generator), proposals)
    } else {
        let proposals = branch
            .proposals
            .unwrap_or(u64::try_from(values.len()).map_err(|_| {
                usage_error("campaign branch value count exceeds the budget width")
            })?);
        let source = CandidateSource::finite(values)
            .map_err(|error| usage_error(format!("invalid finite branch source: {error}")))?;
        (source, proposals)
    };
    let budget = BranchBudget::new(proposals, branch.attempts)
        .map_err(|error| usage_error(format!("invalid campaign branch budget: {error}")))?;
    let request =
        BranchRequest::new(
            basis.branch_point,
            basis.parent,
            basis.opportunity,
            basis.domain,
            source,
            BranchRequestCause::Operator(basis.command.ok_or_else(|| {
                usage_error("campaign operator branch requires an exact command ID")
            })?),
            budget,
            basis.stop,
        )
        .map_err(|error| usage_error(format!("invalid campaign branch request: {error}")))?;

    let submission = SubmitCampaignBranchRequest::new(
        principal.clone(),
        basis.campaign,
        basis.expected,
        request,
    )
    .map_err(|error| usage_error(format!("invalid campaign branch submission: {error}")))?;
    Ok(PreparedCampaignCommand::Branch(submission))
}

fn apply_campaign_selector_branch<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    branch: &CampaignBranchArgs,
) -> Result<CampaignAcceptanceReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let selectors = parse_campaign_choice_selectors(&branch.selector)?;
    let scan_limit = validate_campaign_selector_scan_limit(branch.selector_scan_limit)?;
    let common = parse_campaign_branch_common_basis(branch)?;
    let (opportunity, domain) = resolve_campaign_choice_selector(
        client,
        &principal,
        &common.campaign,
        common.expected,
        &selectors,
        branch.instance.as_deref(),
        scan_limit,
    )?;
    let basis = parse_campaign_branch_basis_with_choice(
        branch,
        &opportunity.to_string(),
        &domain.to_string(),
    )?;

    if branch.all {
        return apply_campaign_all_branch_with_basis(client, principal, branch, basis);
    }
    let prepared = prepare_campaign_branch_with_basis(branch, &principal, basis)?;
    apply_campaign_acceptance(client, prepared)
}

fn resolve_campaign_choice_selector<S>(
    client: &CampaignClient<S>,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    selectors: &[CampaignChoiceSelector],
    instance: Option<&str>,
    scan_limit: usize,
) -> Result<(ChoiceOpportunityId, ChoiceDomainId), CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let mut after = None;
    let mut scanned = 0usize;
    let mut matched = None;
    loop {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            return Err(usage_error(format!(
                "campaign selector scan exceeded {scan_limit} authenticated opportunities"
            )));
        }
        let limit = u32::try_from(
            remaining.min(
                usize::try_from(MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS)
                    .map_err(|_| backend_error("campaign choice page bound exceeds usize"))?,
            ),
        )
        .map_err(|_| backend_error("campaign selector page bound exceeds u32"))?;
        let request = QueryCampaignChoicesRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            limit,
        )
        .map_err(|error| usage_error(format!("invalid campaign selector query: {error}")))?;
        let response = client.query_campaign_choices(&request).map_err(|error| {
            backend_error(format!("campaign selector choice scan failed: {error}"))
        })?;
        scanned = scanned
            .checked_add(response.entries().len())
            .ok_or_else(|| backend_error("campaign selector scan count overflowed"))?;

        for entry in response.entries() {
            let opportunity_id = entry.opportunity();
            let declaration_request = GetCampaignChoiceObjectRequest::new(
                principal.clone(),
                campaign.clone(),
                snapshot,
                opportunity_id,
                CampaignChoiceObjectKind::Declaration,
            )
            .map_err(|error| usage_error(format!("invalid selector declaration query: {error}")))?;
            let declaration_response = client
                .get_campaign_choice_object(&declaration_request)
                .map_err(|error| {
                    backend_error(format!(
                        "campaign selector declaration query failed: {error}"
                    ))
                })?;
            let CampaignChoiceObject::Declaration(declaration) = declaration_response.object()
            else {
                return Err(backend_error(
                    "authenticated selector declaration query returned another object kind",
                ));
            };
            let opportunity = declaration_response.opportunity();
            if instance.is_some_and(|expected| opportunity.instance() != expected) {
                continue;
            }
            if !campaign_choice_selectors_match(selectors, declaration)? {
                continue;
            }
            if matched
                .replace((opportunity_id, opportunity.domain()))
                .is_some()
            {
                return Err(usage_error(
                    "campaign selector matches multiple opportunities; add --instance or use --opportunity",
                ));
            }
        }

        after = response.next_after();
        if after.is_none() {
            break;
        }
    }

    let (opportunity, domain) = matched.ok_or_else(|| {
        usage_error("campaign selector matches no authenticated choice opportunity")
    })?;
    let domain_request = GetCampaignChoiceObjectRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot,
        opportunity,
        CampaignChoiceObjectKind::Domain,
    )
    .map_err(|error| usage_error(format!("invalid selector domain query: {error}")))?;
    let domain_response = client
        .get_campaign_choice_object(&domain_request)
        .map_err(|error| {
            backend_error(format!("campaign selector domain query failed: {error}"))
        })?;
    let CampaignChoiceObject::Domain(value) = domain_response.object() else {
        return Err(backend_error(
            "authenticated selector domain query returned another object kind",
        ));
    };
    if value
        .id()
        .map_err(|error| backend_error(format!("selector domain identity failed: {error}")))?
        != domain
    {
        return Err(backend_error(
            "authenticated selector domain differs from its opportunity",
        ));
    }
    Ok((opportunity, domain))
}

fn parse_campaign_choice_selector(value: &str) -> Result<CampaignChoiceSelector, CliError> {
    if let Some(value) = value.strip_prefix("id:") {
        return SelectableId::parse(value)
            .map(CampaignChoiceSelector::Declaration)
            .map_err(|error| usage_error(format!("invalid campaign selectable ID: {error}")));
    }
    if let Some(value) = value.strip_prefix("tag:") {
        validate_campaign_selector_atom(value, "campaign choice tag")?;
        return Ok(CampaignChoiceSelector::Tag(value.to_owned()));
    }
    let value = value.strip_prefix("name:").unwrap_or(value);
    validate_campaign_selector_atom(value, "campaign choice name")?;
    Ok(CampaignChoiceSelector::Name(value.to_owned()))
}

fn parse_campaign_choice_selectors(
    values: &[String],
) -> Result<Vec<CampaignChoiceSelector>, CliError> {
    if values.is_empty() || values.len() > MAX_CAMPAIGN_SELECTOR_PREDICATES {
        return Err(usage_error(format!(
            "campaign branch requires 1..={MAX_CAMPAIGN_SELECTOR_PREDICATES} selectors"
        )));
    }
    values
        .iter()
        .map(|value| parse_campaign_choice_selector(value))
        .collect()
}

fn validate_campaign_selector_atom(value: &str, label: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/:".contains(&byte))
    {
        return Err(usage_error(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_campaign_selector_scan_limit(value: u32) -> Result<usize, CliError> {
    if value == 0 || value > MAX_CAMPAIGN_SELECTOR_SCAN_ITEMS {
        return Err(usage_error(format!(
            "campaign selector scan limit must be within 1..={MAX_CAMPAIGN_SELECTOR_SCAN_ITEMS}"
        )));
    }
    usize::try_from(value).map_err(|_| backend_error("campaign selector scan limit exceeds usize"))
}

fn campaign_choice_selector_matches(
    selector: &CampaignChoiceSelector,
    declaration: &SelectableDeclaration,
) -> Result<bool, CliError> {
    match selector {
        CampaignChoiceSelector::Name(name) => Ok(declaration.name() == name),
        CampaignChoiceSelector::Declaration(id) => declaration
            .id()
            .map(|actual| actual == *id)
            .map_err(|error| {
                backend_error(format!(
                    "authenticated selectable declaration identity failed: {error}"
                ))
            }),
        CampaignChoiceSelector::Tag(tag) => Ok(declaration.semantic_tags().contains(tag)),
    }
}

fn campaign_choice_selectors_match(
    selectors: &[CampaignChoiceSelector],
    declaration: &SelectableDeclaration,
) -> Result<bool, CliError> {
    for selector in selectors {
        if !campaign_choice_selector_matches(selector, declaration)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn parse_campaign_branch_basis(
    branch: &CampaignBranchArgs,
) -> Result<ParsedCampaignBranchBasis, CliError> {
    let opportunity = branch.opportunity.as_deref().ok_or_else(|| {
        usage_error("campaign branch requires --opportunity unless --selector is used")
    })?;
    let domain = branch.domain.as_deref().ok_or_else(|| {
        usage_error("campaign branch requires --domain unless --selector is used")
    })?;
    parse_campaign_branch_basis_with_choice(branch, opportunity, domain)
}

fn parse_campaign_branch_basis_with_choice(
    branch: &CampaignBranchArgs,
    opportunity: &str,
    domain: &str,
) -> Result<ParsedCampaignBranchBasis, CliError> {
    let common = parse_campaign_branch_common_basis(branch)?;
    Ok(ParsedCampaignBranchBasis {
        campaign: common.campaign,
        expected: common.expected,
        command: common.command,
        branch_point: common.branch_point,
        parent: common.parent,
        opportunity: ChoiceOpportunityId::parse(opportunity)
            .map_err(|error| usage_error(format!("invalid choice opportunity: {error}")))?,
        domain: ChoiceDomainId::parse(domain)
            .map_err(|error| usage_error(format!("invalid choice domain: {error}")))?,
        stop: common.stop,
    })
}

fn parse_campaign_branch_common_basis(
    branch: &CampaignBranchArgs,
) -> Result<ParsedCampaignBranchCommonBasis, CliError> {
    Ok(ParsedCampaignBranchCommonBasis {
        campaign: campaign_name(&branch.name)?,
        expected: CampaignSnapshotId::parse(&branch.expected).map_err(|error| {
            usage_error(format!("invalid campaign snapshot precondition: {error}"))
        })?,
        command: branch
            .command
            .as_deref()
            .map(CampaignCommandId::parse)
            .transpose()
            .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?,
        branch_point: BranchPointId::parse(&branch.branch_point)
            .map_err(|error| usage_error(format!("invalid branch-point ID: {error}")))?,
        parent: ConfigurationArtifactId::parse(&branch.parent).map_err(|error| {
            usage_error(format!("invalid parent configuration artifact: {error}"))
        })?,
        stop: parse_campaign_stop_condition(&branch.stop)?,
    })
}

fn apply_campaign_all_branch<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    branch: &CampaignBranchArgs,
) -> Result<CampaignAcceptanceReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let basis = parse_campaign_branch_basis(branch)?;
    apply_campaign_all_branch_with_basis(client, principal, branch, basis)
}

fn apply_campaign_all_branch_with_basis<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    branch: &CampaignBranchArgs,
    basis: ParsedCampaignBranchBasis,
) -> Result<CampaignAcceptanceReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let domain_request = GetCampaignChoiceObjectRequest::new(
        principal.clone(),
        basis.campaign.clone(),
        basis.expected,
        basis.opportunity,
        CampaignChoiceObjectKind::Domain,
    )
    .map_err(|error| usage_error(format!("invalid exhaustive domain query: {error}")))?;
    let domain_response = client
        .get_campaign_choice_object(&domain_request)
        .map_err(|error| {
            backend_error(format!("campaign exhaustive domain query failed: {error}"))
        })?;
    let CampaignChoiceObject::Domain(domain) = domain_response.object() else {
        return Err(backend_error(
            "authenticated exhaustive domain query returned another object kind",
        ));
    };
    if domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated exhaustive domain identity failed: {error}"
        ))
    })? != basis.domain
    {
        return Err(usage_error(
            "campaign --all domain differs from the authenticated opportunity domain",
        ));
    }
    if !matches!(domain, ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_)) {
        return Err(usage_error(
            "campaign --all currently supports only finite Boolean or discrete domains",
        ));
    }
    let proposals = u64::try_from(domain.cardinality())
        .map_err(|_| usage_error("campaign --all domain cardinality exceeds u64"))?;
    let generator = CandidateGeneratorSpec::new(
        STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .map_err(|error| backend_error(format!("canonical all generator is invalid: {error}")))?
    .id()
    .map_err(|error| backend_error(format!("canonical all generator identity failed: {error}")))?;
    let request = BranchRequest::new(
        basis.branch_point,
        basis.parent,
        basis.opportunity,
        basis.domain,
        CandidateSource::generated(generator),
        BranchRequestCause::ExhaustivePolicy(domain_response.snapshot_body().active_policy()),
        BranchBudget::new(proposals, branch.attempts)
            .map_err(|error| usage_error(format!("invalid campaign --all budget: {error}")))?,
        basis.stop,
    )
    .map_err(|error| usage_error(format!("invalid campaign --all request: {error}")))?;
    let submission =
        SubmitCampaignBranchRequest::new(principal, basis.campaign, basis.expected, request)
            .map_err(|error| usage_error(format!("invalid campaign --all submission: {error}")))?;
    apply_campaign_acceptance(client, PreparedCampaignCommand::Branch(submission))
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
        CampaignCommand::Findings(page) => {
            let (campaign, snapshot) = campaign_page_basis(page)?;
            let after = page
                .after
                .as_deref()
                .map(CampaignHash::parse)
                .transpose()
                .map_err(|error| {
                    usage_error(format!("invalid campaign finding cursor: {error}"))
                })?;
            let request = QueryCampaignFindingsRequest::new(
                principal,
                campaign.clone(),
                snapshot,
                after,
                page.limit,
            )
            .map_err(|error| usage_error(format!("invalid campaign findings query: {error}")))?;
            let response = client.query_campaign_findings(&request).map_err(|error| {
                backend_error(format!("campaign findings query failed: {error}"))
            })?;
            Ok(CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "findings",
                campaign: campaign.as_str().to_owned(),
                snapshot: snapshot.to_string(),
                next_after: response.next_after().map(|cursor| cursor.to_hex()),
                entries: response
                    .entries()
                    .iter()
                    .map(|finding| {
                        let finding_id = finding.id().map_err(|error| {
                            backend_error(format!("validated finding identity failed: {error}"))
                        })?;
                        Ok(CampaignPageEntry::Finding {
                            finding: finding_id.to_string(),
                            cluster: finding.signature().cluster_key().to_hex(),
                            finding_kind: finding_kind_label(finding.signature().kind()),
                            fingerprint: finding.signature().fingerprint().to_hex(),
                            property: finding.signature().property().map(str::to_owned),
                            failure_class: finding.signature().failure_class().to_owned(),
                            observation: finding.observation().to_string(),
                            occurrences: finding.occurrence_count(),
                            reproduction: finding.reproduction().to_string(),
                            minimized: finding.minimized().map(|id| id.to_string()),
                        })
                    })
                    .collect::<Result<Vec<_>, CliError>>()?,
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
        PreparedCampaignCommand::Create(request) => apply_campaign_create(client, request, None),
        PreparedCampaignCommand::CreateAndStart(request, command) => {
            apply_campaign_create(client, request, Some(command))
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

fn apply_campaign_create<S>(
    client: &CampaignClient<S>,
    request: CreateCampaignRequest,
    start_command: Option<CampaignCommandId>,
) -> Result<CampaignAcceptanceReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let response = client
        .create_campaign(&request)
        .map_err(|error| backend_error(format!("campaign creation failed: {error}")))?;
    let start = if let Some(command) = start_command {
        let control = ControlRequest {
            command,
            expected_snapshot: response.snapshot(),
            action: CampaignControlAction::Resume,
        };
        let start_request = ApplyCampaignCommandRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            control,
        )
        .map_err(|error| usage_error(format!("invalid campaign start request: {error}")))?;
        let started = client
            .apply_campaign_command(&start_request)
            .map_err(|error| {
                backend_error(format!(
                    "campaign was created but immediate start failed: {error}"
                ))
            })?;
        Some(CampaignCreateStartReport {
            command: command.to_string(),
            prior_snapshot: started.prior_snapshot().to_string(),
            new_snapshot: started.new_snapshot().to_string(),
            replayed: started.replayed(),
        })
    } else {
        None
    };

    Ok(CampaignAcceptanceReport::Create {
        schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
        campaign: request.campaign().as_str().to_owned(),
        snapshot: response.snapshot().to_string(),
        lineage: response.lineage().to_string(),
        active_policy: response.active_policy().to_string(),
        replayed: response.replayed(),
        start,
    })
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

fn apply_campaign_pin<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignMutationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let (basis, operation, change) = campaign_pin_spec(command)?;
    let campaign = campaign_name(basis.name)?;
    let command_id = CampaignCommandId::parse(basis.command)
        .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
    let expected_snapshot = CampaignSnapshotId::parse(basis.expected)
        .map_err(|error| usage_error(format!("invalid campaign snapshot precondition: {error}")))?;
    let request = PinCampaignRequest::new(
        principal,
        campaign.clone(),
        PinRequest {
            command: command_id,
            expected_snapshot,
            change,
        },
    )
    .map_err(|error| usage_error(format!("invalid campaign pin request: {error}")))?;
    let response = client
        .pin_campaign(&request)
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

fn campaign_pin_spec(
    command: &CampaignCommand,
) -> Result<(CampaignMutationBasisRef<'_>, &'static str, PinChange), CliError> {
    let (basis, operation, configuration, retention, reason) = match command {
        CampaignCommand::Pin(pin) => (
            mutation_basis_ref(&pin.basis),
            "pin",
            pin.configuration.as_str(),
            Some(match pin.tier {
                CampaignPinRetentionArg::Thin => PinRetention::Thin,
                CampaignPinRetentionArg::Exact => PinRetention::Exact,
            }),
            pin.reason.as_str(),
        ),
        CampaignCommand::Unpin(unpin) => (
            mutation_basis_ref(&unpin.basis),
            "unpin",
            unpin.configuration.as_str(),
            None,
            unpin.reason.as_str(),
        ),
        _ => {
            return Err(backend_error(
                "campaign non-pin operation reached the pin-mutation path",
            ));
        }
    };
    let configuration = ConfigurationId::parse(configuration)
        .map_err(|error| usage_error(format!("invalid campaign configuration ID: {error}")))?;
    let change = PinChange::new(configuration, retention, reason)
        .map_err(|error| usage_error(format!("invalid campaign pin change: {error}")))?;
    Ok((basis, operation, change))
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
        CampaignCommand::Start(basis) => Ok((
            mutation_basis_ref(basis),
            "start",
            CampaignControlAction::Resume,
        )),
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
        CampaignCommand::ValidateImport(_)
        | CampaignCommand::Fixture(_)
        | CampaignCommand::Create(_)
        | CampaignCommand::Derive(_)
        | CampaignCommand::Branch(_)
        | CampaignCommand::Status(_)
        | CampaignCommand::Watch(_)
        | CampaignCommand::Snapshot(_)
        | CampaignCommand::Compare(_)
        | CampaignCommand::Explain(_)
        | CampaignCommand::ExplainFinding(_)
        | CampaignCommand::ExplainAttempt(_)
        | CampaignCommand::Rankings(_)
        | CampaignCommand::Graph(_)
        | CampaignCommand::GraphObject(_)
        | CampaignCommand::Choices(_)
        | CampaignCommand::ChoiceObject(_)
        | CampaignCommand::Frontier(_)
        | CampaignCommand::Findings(_)
        | CampaignCommand::FrontierObject(_)
        | CampaignCommand::Pin(_)
        | CampaignCommand::Unpin(_) => Err(backend_error(
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
            start,
            ..
        } => {
            let mut fields = vec![
                ("operation", "create"),
                ("campaign", campaign.as_str()),
                ("snapshot", snapshot.as_str()),
                ("lineage", lineage.as_str()),
                ("active_policy", active_policy.as_str()),
                ("replayed", if *replayed { "true" } else { "false" }),
            ];
            if let Some(start) = start {
                fields.extend([
                    ("start_command", start.command.as_str()),
                    ("start_prior_snapshot", start.prior_snapshot.as_str()),
                    ("start_snapshot", start.new_snapshot.as_str()),
                    (
                        "start_replayed",
                        if start.replayed { "true" } else { "false" },
                    ),
                ]);
            }
            fields
        }
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
        "findings" => lines.push(String::from(
            "finding\tcluster\tkind\tfingerprint\tproperty\tfailure_class\tobservation\toccurrences\treproduction\tminimized",
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
        "findings" => output.push_str(
            "| Finding | Cluster | Kind | Fingerprint | Property | Failure class | Observation | Occurrences | Reproduction | Minimized |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
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
        CampaignPageEntry::Finding {
            finding,
            cluster,
            finding_kind,
            fingerprint,
            property,
            failure_class,
            observation,
            occurrences,
            reproduction,
            minimized,
        } => format!(
            "{finding}{separator}{cluster}{separator}{finding_kind}{separator}{fingerprint}{separator}{}{separator}{failure_class}{separator}{observation}{separator}{occurrences}{separator}{reproduction}{separator}{}",
            property.as_deref().unwrap_or("-"),
            minimized.as_deref().unwrap_or("-")
        ),
    }
}

const fn finding_kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::PropertyViolation => "property-violation",
        FindingKind::Divergence => "divergence",
        FindingKind::Timeout => "timeout",
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
        snapshots: BTreeMap<CampaignSnapshotId, CampaignSnapshot>,
        object_key: CampaignHash,
        object: ObjectEnvelope,
        declaration: SelectableDeclaration,
        domain: ChoiceDomain,
        opportunity: ChoiceOpportunity,
        additional_choices: Vec<(ChoiceOpportunity, SelectableDeclaration, ChoiceDomain)>,
        branch_request: BranchRequest,
        frontier_projection: ContinuationProjection,
        finding: Finding,
        finding_root: ContentId,
        finding_observation: Observation,
        finding_reproduction: ReproductionArtifact,
        attempt: Attempt,
        attempt_admission: AttemptAdmission,
        attempt_path: BranchPath,
        attempt_selection: Selection,
        attempt_proposal: Proposal,
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

        fn query_campaign_findings(
            &self,
            _request: &QueryCampaignFindingsRequest,
        ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_finding_object(
            &self,
            _request: &GetCampaignFindingObjectRequest,
        ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn explain_campaign_attempt(
            &self,
            _request: &ExplainCampaignAttemptRequest,
        ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_planner_rankings(
            &self,
            _request: &GetCampaignPlannerRankingsRequest,
        ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
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
                    | CampaignControlAction::Resume
            ));
            let next = match request.command().action {
                CampaignControlAction::Resume => snapshot("started"),
                _ => snapshot("mutated"),
            };
            Ok(ApplyCampaignCommandResponse::new(
                request,
                CampaignCommandResult {
                    prior_snapshot: request.command().expected_snapshot,
                    new_snapshot: next,
                    replayed: false,
                },
            )
            .expect("fixed campaign mutation response"))
        }

        fn pin_campaign(
            &self,
            request: &PinCampaignRequest,
        ) -> Result<PinCampaignResponse, Self::Error> {
            Ok(PinCampaignResponse::new(
                request,
                CampaignCommandResult {
                    prior_snapshot: request.command().expected_snapshot,
                    new_snapshot: snapshot("pinned"),
                    replayed: false,
                },
            )
            .expect("fixed campaign pin response"))
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
            request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            let snapshot = self
                .snapshots
                .get(&request.snapshot())
                .expect("requested fixture snapshot")
                .clone();
            Ok(GetCampaignSnapshotResponse::new(request, snapshot)
                .expect("bound campaign snapshot response"))
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

        fn query_campaign_findings(
            &self,
            request: &QueryCampaignFindingsRequest,
        ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
            let (page, proof) = self
                .map
                .scan_with_proof(self.finding_root, request.after(), request.limit() as usize)
                .expect("proof-bearing finding page");
            Ok(QueryCampaignFindingsResponse::new(
                request,
                self.snapshot.clone(),
                vec![self.finding.clone()],
                page.next_after(),
                proof,
            )
            .expect("bound finding response"))
        }

        fn get_campaign_finding_object(
            &self,
            request: &GetCampaignFindingObjectRequest,
        ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
            assert_eq!(
                request.finding(),
                self.finding.id().expect("explanation finding ID")
            );
            let (_, proof) = self
                .map
                .get_with_proof(
                    self.finding_root,
                    finding_index_key(self.finding.signature().cluster_key()),
                )
                .expect("finding explanation membership proof");
            let object = match request.kind() {
                CampaignFindingObjectKind::Observation => {
                    CampaignFindingObject::Observation(self.finding_observation.clone())
                }
                CampaignFindingObjectKind::LatestOccurrence => {
                    CampaignFindingObject::LatestOccurrence(self.finding_observation.clone())
                }
                CampaignFindingObjectKind::Reproduction => {
                    CampaignFindingObject::Reproduction(self.finding_reproduction.clone())
                }
                CampaignFindingObjectKind::MinimizedReproduction => {
                    unreachable!("fixture finding has no minimized reproduction")
                }
            };
            Ok(GetCampaignFindingObjectResponse::new(
                request,
                self.snapshot.clone(),
                self.finding.clone(),
                object,
                proof,
            )
            .expect("bound finding explanation response"))
        }

        fn explain_campaign_attempt(
            &self,
            request: &ExplainCampaignAttemptRequest,
        ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
            assert_eq!(
                request.attempt(),
                self.attempt.id().expect("explanation attempt ID")
            );
            let roots = self.snapshot.roots();
            let (_, attempt_proof) = self
                .map
                .get_with_proof(
                    roots.accounting,
                    content_index_key("accounting.attempt", request.attempt().content_id()),
                )
                .expect("attempt explanation proof");
            let (_, admission_proof) = self
                .map
                .get_with_proof(
                    roots.accounting,
                    content_index_key(
                        "accounting.attempt-execution-basis",
                        request.attempt().content_id(),
                    ),
                )
                .expect("attempt admission explanation proof");
            let proposal_id = self
                .attempt_proposal
                .id()
                .expect("attempt explanation proposal ID");
            let (_, proposal_proof) = self
                .map
                .get_with_proof(
                    roots.exploration,
                    content_index_key("exploration.proposal", proposal_id.content_id()),
                )
                .expect("attempt proposal explanation proof");
            let (_, observation_proof) = self
                .map
                .get_with_proof(
                    roots.observations,
                    content_index_key("observations.attempt", request.attempt().content_id()),
                )
                .expect("attempt observation explanation proof");
            Ok(ExplainCampaignAttemptResponse::new(
                request,
                self.snapshot.clone(),
                self.attempt.clone(),
                self.attempt_admission,
                self.attempt_path.clone(),
                Some(self.attempt_selection.clone()),
                Some(self.attempt_proposal.clone()),
                None,
                Some(self.finding_observation.clone()),
                attempt_proof,
                admission_proof,
                Some(proposal_proof),
                None,
                observation_proof,
            )
            .expect("bound attempt explanation response"))
        }

        fn get_campaign_planner_rankings(
            &self,
            _request: &GetCampaignPlannerRankingsRequest,
        ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
            unreachable!("graph fixture has no retained planner request")
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
            request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
            let graph = self.snapshot.roots().graph;
            let (_, index_proof) = self
                .map
                .get_with_proof(graph, CampaignChoiceEntry::index_anchor_key())
                .expect("selector choice index proof");
            let index = self
                .map
                .get(graph, CampaignChoiceEntry::index_anchor_key())
                .expect("selector choice index lookup")
                .expect("selector choice index root");
            let (page, page_proof) = self
                .map
                .scan_with_proof(
                    index,
                    request
                        .after()
                        .map(|value| CampaignChoiceEntry::new(value).index_key()),
                    usize::try_from(request.limit()).expect("selector page limit"),
                )
                .expect("selector choice page proof");
            let entries = page
                .entries()
                .iter()
                .map(|(_, value)| {
                    let selected = std::iter::once(&self.opportunity)
                        .chain(self.additional_choices.iter().map(|(value, _, _)| value))
                        .find_map(|candidate| {
                            let id = candidate.id().expect("selector opportunity ID");
                            (id.content_id() == *value).then_some(id)
                        })
                        .expect("selector indexed opportunity ID");
                    CampaignChoiceEntry::new(selected)
                })
                .collect();
            Ok(QueryCampaignChoicesResponse::new(
                request,
                self.snapshot.clone(),
                entries,
                page.next_after().map(|_| {
                    page.entries()
                        .last()
                        .and_then(|(_, value)| {
                            std::iter::once(&self.opportunity)
                                .chain(
                                    self.additional_choices
                                        .iter()
                                        .map(|(candidate, _, _)| candidate),
                                )
                                .find_map(|candidate| {
                                    let id = candidate.id().expect("selector opportunity ID");
                                    (id.content_id() == *value).then_some(id)
                                })
                        })
                        .expect("selector page cursor opportunity")
                }),
                index_proof,
                page_proof,
            )
            .expect("bound selector choice page"))
        }

        fn query_campaign_frontier(
            &self,
            _request: &QueryCampaignFrontierRequest,
        ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_frontier_object(
            &self,
            request: &GetCampaignFrontierObjectRequest,
        ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
            assert_eq!(request.request(), self.frontier_projection.request());
            let exploration = self.snapshot.roots().exploration;
            let anchor =
                CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b"");
            let (_, index_proof) = self
                .map
                .get_with_proof(exploration, anchor)
                .expect("frontier explanation index proof");
            let frontier_index = self
                .map
                .get(exploration, anchor)
                .expect("frontier explanation index lookup")
                .expect("frontier explanation index root");
            let (_, object_proof) = self
                .map
                .get_with_proof(
                    frontier_index,
                    CampaignHash::from_bytes(request.request().content_id().digest()),
                )
                .expect("frontier explanation membership proof");
            Ok(GetCampaignFrontierObjectResponse::new(
                request,
                self.snapshot.clone(),
                self.frontier_projection,
                self.branch_request.clone(),
                index_proof,
                object_proof,
            )
            .expect("bound frontier explanation response"))
        }

        fn get_campaign_choice_object(
            &self,
            request: &GetCampaignChoiceObjectRequest,
        ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
            let (opportunity, declaration, domain) = if request.opportunity()
                == self.opportunity.id().expect("explanation opportunity ID")
            {
                (&self.opportunity, &self.declaration, &self.domain)
            } else {
                let (opportunity, declaration, domain) = self
                    .additional_choices
                    .iter()
                    .find(|(value, _, _)| {
                        value.id().expect("additional opportunity ID") == request.opportunity()
                    })
                    .expect("requested choice fixture");
                (opportunity, declaration, domain)
            };
            let (_, proof) = self
                .map
                .get_with_proof(
                    self.snapshot.roots().graph,
                    CampaignChoiceEntry::new(request.opportunity()).graph_key(),
                )
                .expect("choice explanation membership proof");
            let object = match request.kind() {
                CampaignChoiceObjectKind::Declaration => {
                    CampaignChoiceObject::Declaration(declaration.clone())
                }
                CampaignChoiceObjectKind::Domain => CampaignChoiceObject::Domain(domain.clone()),
            };
            Ok(GetCampaignChoiceObjectResponse::new(
                request,
                self.snapshot.clone(),
                opportunity.clone(),
                object,
                proof,
            )
            .expect("bound choice explanation response"))
        }

        fn apply_campaign_command(
            &self,
            _request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn pin_campaign(
            &self,
            _request: &PinCampaignRequest,
        ) -> Result<PinCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn submit_branch_request(
            &self,
            request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            Ok(SubmitCampaignBranchResponse::new(
                request,
                BranchRequestResult {
                    prior_snapshot: request.expected_snapshot(),
                    new_snapshot: snapshot("graph-page-branched"),
                    request: request.request().id().expect("branch request ID"),
                    replayed: false,
                },
            )
            .expect("fixed graph-page branch response"))
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
                start: Some(CampaignCreateStartReport {
                    command: hash("start").to_hex(),
                    prior_snapshot: snapshot("created").to_string(),
                    new_snapshot: snapshot("started").to_string(),
                    replayed: false,
                }),
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
            if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
                assert_eq!(decoded["start"]["command"], hash("start").to_hex());
                assert_eq!(
                    decoded["start"]["prior_snapshot"],
                    snapshot("created").to_string()
                );
                assert_eq!(
                    decoded["start"]["new_snapshot"],
                    snapshot("started").to_string()
                );
            }

            let table =
                render_campaign_acceptance(&report, OutputFormat::Table).expect("table report");
            assert!(table.contains("operation"));
            assert!(table.contains("replayed"));
            if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
                assert!(table.contains("start_command"));
                assert!(table.contains("start_snapshot"));
            }
            let markdown = render_campaign_acceptance(&report, OutputFormat::Markdown)
                .expect("Markdown report");
            assert!(markdown.contains("| replayed |"));
            if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
                assert!(markdown.contains("| start_prior_snapshot |"));
                assert!(markdown.contains("| start_replayed |"));
            }
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
                snapshot: snapshot.clone(),
                next_after: None,
                entries: vec![CampaignPageEntry::Frontier {
                    request: "request".to_owned(),
                    branch_point: "branch-point".to_owned(),
                    state: "waiting-for-feedback",
                    completed_visits: Some(3),
                    required_visits: Some(5),
                }],
            },
            CampaignPageReport {
                schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
                operation: "findings",
                campaign: "example".to_owned(),
                snapshot,
                next_after: Some(hash("finding-cursor").to_hex()),
                entries: vec![CampaignPageEntry::Finding {
                    finding: "finding".to_owned(),
                    cluster: hash("cluster").to_hex(),
                    finding_kind: "timeout",
                    fingerprint: hash("fingerprint").to_hex(),
                    property: None,
                    failure_class: "timeout.execution".to_owned(),
                    observation: "observation".to_owned(),
                    occurrences: 3,
                    reproduction: "reproduction".to_owned(),
                    minimized: None,
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
        let (service, snapshot, _) = graph_page_service();
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
    fn campaign_findings_page_uses_the_checked_proof_bearing_transport() {
        let (service, snapshot, _) = graph_page_service();
        let command = CampaignCommand::Findings(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            after: None,
            limit: 1,
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve finding page request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_page(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked findings query");
        server.join().expect("campaign server thread");

        assert_eq!(report.operation, "findings");
        assert_eq!(report.snapshot, snapshot.to_string());
        assert_eq!(report.entries.len(), 1);
        assert!(report.next_after.is_none());
        assert!(matches!(
            &report.entries[0],
            CampaignPageEntry::Finding {
                finding_kind: "timeout",
                occurrences: 3,
                ..
            }
        ));
    }

    #[test]
    fn campaign_graph_object_uses_the_checked_proof_bearing_transport() {
        let (service, snapshot, _) = graph_page_service();
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
    fn campaign_compare_uses_two_checked_historical_snapshot_reads() {
        let (service, right, left) = graph_page_service();
        let command = CampaignCommand::Compare(CampaignCompareArgs {
            name: "example".to_owned(),
            left: left.to_string(),
            right: right.to_string(),
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve left snapshot request");
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve right snapshot request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_snapshot(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked campaign comparison");
        server.join().expect("campaign server thread");

        let rendered = render_campaign_snapshot(&report, OutputFormat::Json).expect("compare JSON");
        let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(decoded["schema"], "crucible.cli.campaign-compare.v1");
        assert_eq!(decoded["direct_relationship"], "left-parent-of-right");
        assert_eq!(decoded["left"]["id"], left.to_string());
        assert_eq!(decoded["right"]["id"], right.to_string());
        assert_eq!(decoded["changed"]["active_policy"], true);
    }

    #[test]
    fn campaign_explain_joins_two_checked_proof_bearing_records() {
        let (service, snapshot, _) = graph_page_service();
        let opportunity = service
            .opportunity
            .id()
            .expect("explanation opportunity ID");
        let request = service.branch_request.id().expect("explanation request ID");
        let command = CampaignCommand::Explain(CampaignExplainArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            opportunity: opportunity.to_string(),
            request: request.to_string(),
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve explanation choice request");
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve explanation frontier request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_explanation(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked campaign explanation");
        server.join().expect("campaign server thread");

        let rendered =
            render_campaign_explanation(&report, OutputFormat::Json).expect("explanation JSON");
        let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(decoded["schema"], "crucible.cli.campaign-explanation.v1");
        assert_eq!(decoded["opportunity"]["id"], opportunity.to_string());
        assert_eq!(decoded["legality"]["domain_kind"], "boolean");
        assert_eq!(decoded["legality"]["required"], true);
        assert_eq!(decoded["cause"]["request"], request.to_string());
        assert_eq!(decoded["cause"]["continuation_state"], "ready");
        assert_eq!(decoded["cause"]["finite_values"][0], "true");
    }

    #[test]
    fn campaign_finding_explain_joins_observation_and_reproduction_proofs() {
        let (service, snapshot, _) = graph_page_service();
        let finding = service.finding.id().expect("explanation finding ID");
        let command = CampaignCommand::ExplainFinding(CampaignFindingExplainArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            finding: finding.to_string(),
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve finding observation request");
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve finding reproduction request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_finding_explanation(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked finding explanation");
        server.join().expect("campaign server thread");

        let rendered = render_campaign_finding_explanation(&report, OutputFormat::Json)
            .expect("finding explanation JSON");
        let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(
            decoded["schema"],
            "crucible.cli.campaign-finding-explanation.v1"
        );
        assert_eq!(decoded["finding"]["id"], finding.to_string());
        assert_eq!(decoded["finding"]["kind"], "timeout");
        assert_eq!(decoded["observation"]["stop"], "modeled-timeout:execution");
        assert_eq!(decoded["reproduction"]["payload_schema"], 1);
        assert_eq!(decoded["reproduction"]["payload_bytes"], 17);
    }

    #[test]
    fn campaign_attempt_explain_authenticates_proposal_and_completion() {
        let (service, snapshot, _) = graph_page_service();
        let attempt = service.attempt.id().expect("explanation attempt ID");
        let proposal = service
            .attempt_proposal
            .id()
            .expect("explanation proposal ID");
        let observation = service
            .finding_observation
            .id()
            .expect("explanation observation ID");
        let command = CampaignCommand::ExplainAttempt(CampaignAttemptExplainArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            attempt: attempt.to_string(),
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve attempt explanation request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let report = query_campaign_attempt_explanation(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect("checked attempt explanation");
        server.join().expect("campaign server thread");

        let rendered = render_campaign_attempt_explanation(&report, OutputFormat::Json)
            .expect("attempt explanation JSON");
        let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(
            decoded["schema"],
            "crucible.cli.campaign-attempt-explanation.v2"
        );
        assert_eq!(decoded["attempt"]["id"], attempt.to_string());
        assert_eq!(decoded["attempt"]["start"], "branch");
        assert_eq!(decoded["proposal"]["id"], proposal.to_string());
        assert_eq!(decoded["selection"]["value"], "true");
        assert_eq!(decoded["observation"]["id"], observation.to_string());
    }

    #[test]
    fn campaign_explain_rejects_individually_authenticated_unrelated_records() {
        let (service, _, _) = graph_page_service();
        let (service, snapshot) = mismatch_explanation_frontier(service);
        let opportunity = service
            .opportunity
            .id()
            .expect("explanation opportunity ID");
        let request = service
            .branch_request
            .id()
            .expect("mismatched explanation request ID");
        let command = CampaignCommand::Explain(CampaignExplainArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            opportunity: opportunity.to_string(),
            request: request.to_string(),
        });
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve mismatched explanation choice request");
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve mismatched explanation frontier request");
        });
        let client = CampaignClient::new(
            LoopbackCampaignService::new(client_stream).expect("loopback client"),
        );

        let error = query_campaign_explanation(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            &command,
        )
        .expect_err("unrelated explanation records must fail closed");
        server.join().expect("campaign server thread");
        assert!(
            error
                .to_string()
                .contains("do not share one opportunity and domain")
        );
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

        let started = accept_start_over_loopback(
            CreateCampaignRequest::new(
                principal.clone(),
                CampaignName::new("started").expect("started campaign name"),
                campaign_records().0,
                policy_record.clone(),
            )
            .expect("create-and-start request"),
            CampaignCommandId::from_hash(hash("start-command")),
        );
        assert!(matches!(
            started,
            CampaignAcceptanceReport::Create {
                snapshot: value,
                replayed: false,
                start: Some(CampaignCreateStartReport {
                    prior_snapshot,
                    new_snapshot,
                    replayed: false,
                    ..
                }),
                ..
            } if value == snapshot("created").to_string()
                && prior_snapshot == snapshot("created").to_string()
                && new_snapshot == snapshot("started").to_string()
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
    fn campaign_all_branch_derives_authenticated_generator_policy_and_budget() {
        let (service, source_snapshot, _) = graph_page_service();
        let template = service.branch_request.clone();
        let active_policy = service.snapshot.active_policy();
        let all_generator = CandidateGeneratorSpec::new(
            STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
            CandidateGeneratorAlgorithm::All,
        )
        .expect("all generator")
        .id()
        .expect("all generator ID");
        let branch = CampaignBranchArgs {
            name: "example".to_owned(),
            expected: source_snapshot.to_string(),
            command: None,
            branch_point: template.branch_point().to_string(),
            parent: template.parent().to_string(),
            opportunity: Some(template.opportunity().to_string()),
            domain: Some(template.domain().to_string()),
            selector: Vec::new(),
            instance: None,
            selector_scan_limit: 256,
            values: Vec::new(),
            generator: None,
            all: true,
            proposals: None,
            attempts: 2,
            stop: "next-choice".to_owned(),
        };
        let expected = BranchRequest::new(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
            CandidateSource::generated(all_generator),
            BranchRequestCause::ExhaustivePolicy(active_policy),
            BranchBudget::new(2, 2).expect("all budget"),
            StopCondition::NextChoice,
        )
        .expect("expected all request")
        .id()
        .expect("expected all request ID");
        let report = apply_campaign_all_branch(
            &CampaignClient::new(service),
            CampaignPrincipal::new("operator").expect("principal"),
            &branch,
        )
        .expect("apply exhaustive branch");
        assert!(matches!(
            report,
            CampaignAcceptanceReport::Branch {
                request,
                prior_snapshot,
                replayed: false,
                ..
            } if request == expected.to_string() && prior_snapshot == source_snapshot.to_string()
        ));
    }

    #[test]
    fn campaign_branch_selector_resolves_authenticated_name_and_domain() {
        let (service, source_snapshot, _) = graph_page_service();
        let template = service.branch_request.clone();
        let declaration_id = service.declaration.id().expect("selector declaration ID");
        let branch = CampaignBranchArgs {
            name: "example".to_owned(),
            expected: source_snapshot.to_string(),
            command: Some(CampaignCommandId::from_hash(hash("selector-command")).to_string()),
            branch_point: template.branch_point().to_string(),
            parent: template.parent().to_string(),
            opportunity: None,
            domain: None,
            selector: vec![
                "product.network.retry".to_owned(),
                "tag:network".to_owned(),
                format!("id:{declaration_id}"),
            ],
            instance: Some("network-retry".to_owned()),
            selector_scan_limit: 8,
            values: vec!["true".to_owned()],
            generator: None,
            all: false,
            proposals: None,
            attempts: 1,
            stop: "next-choice".to_owned(),
        };
        let expected = BranchRequest::new(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("selector finite source"),
            BranchRequestCause::Operator(
                CampaignCommandId::parse(branch.command.as_deref().expect("selector command"))
                    .expect("selector command ID"),
            ),
            BranchBudget::new(1, 1).expect("selector budget"),
            StopCondition::NextChoice,
        )
        .expect("expected selector request")
        .id()
        .expect("expected selector request ID");

        let report = apply_campaign_selector_branch(
            &CampaignClient::new(service),
            CampaignPrincipal::new("operator").expect("principal"),
            &branch,
        )
        .expect("apply selector branch");

        assert!(matches!(
            report,
            CampaignAcceptanceReport::Branch { request, .. }
                if request == expected.to_string()
        ));
        assert!(matches!(
            parse_campaign_choice_selector("tag:network").expect("tag selector"),
            CampaignChoiceSelector::Tag(tag) if tag == "network"
        ));
        assert!(matches!(
            parse_campaign_choice_selector(&format!("id:{declaration_id}"))
                .expect("declaration selector"),
            CampaignChoiceSelector::Declaration(id) if id == declaration_id
        ));
    }

    #[test]
    fn campaign_branch_selector_rejects_ambiguity_and_scan_truncation() {
        let (service, _, _) = graph_page_service();
        let (service, snapshot) = add_ambiguous_selector_choice(service);
        let template = service.branch_request.clone();
        let mut branch = CampaignBranchArgs {
            name: "example".to_owned(),
            expected: snapshot.to_string(),
            command: Some(
                CampaignCommandId::from_hash(hash("ambiguous-selector-command")).to_string(),
            ),
            branch_point: template.branch_point().to_string(),
            parent: template.parent().to_string(),
            opportunity: None,
            domain: None,
            selector: vec!["tag:network".to_owned()],
            instance: None,
            selector_scan_limit: 8,
            values: vec!["true".to_owned()],
            generator: None,
            all: false,
            proposals: None,
            attempts: 1,
            stop: "next-choice".to_owned(),
        };
        let client = CampaignClient::new(service);
        let principal = CampaignPrincipal::new("operator").expect("principal");

        let ambiguity = match apply_campaign_selector_branch(&client, principal.clone(), &branch) {
            Ok(_) => panic!("ambiguous selector must fail"),
            Err(error) => error,
        };
        assert!(
            ambiguity
                .to_string()
                .contains("matches multiple opportunities")
        );

        branch.selector_scan_limit = 1;
        let truncated = match apply_campaign_selector_branch(&client, principal, &branch) {
            Ok(_) => panic!("truncated selector scan must fail"),
            Err(error) => error,
        };
        assert!(truncated.to_string().contains("selector scan exceeded 1"));
        assert!(validate_campaign_selector_scan_limit(0).is_err());
        assert!(
            validate_campaign_selector_scan_limit(MAX_CAMPAIGN_SELECTOR_SCAN_ITEMS + 1).is_err()
        );
        assert!(
            parse_campaign_choice_selectors(&vec![
                String::from("tag:network");
                MAX_CAMPAIGN_SELECTOR_PREDICATES + 1
            ])
            .is_err()
        );
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
                lineage: lineage_path.clone(),
                policy: policy_path.clone(),
                start_command: None,
            }),
            &principal,
        )
        .expect("prepare creation")
        .expect("prepared creation request");
        assert!(matches!(create, PreparedCampaignCommand::Create(_)));

        let start_command = CampaignCommandId::from_hash(hash("start-created"));
        let create_and_start = prepare_campaign_command(
            &CampaignCommand::Create(CampaignCreateArgs {
                name: "started".to_owned(),
                lineage: lineage_path,
                policy: policy_path.clone(),
                start_command: Some(start_command.to_string()),
            }),
            &principal,
        )
        .expect("prepare creation with immediate start")
        .expect("prepared create-and-start request");
        assert!(matches!(
            create_and_start,
            PreparedCampaignCommand::CreateAndStart(_, command) if command == start_command
        ));

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
                    start_command: None,
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
    fn campaign_start_uses_the_checked_resume_transition() {
        let command = CampaignCommand::Start(mutation_basis("start"));
        let report = mutate_over_loopback(&command);

        assert_eq!(report.operation, "start");
        assert_eq!(report.command, hash("start").to_hex());
        assert_eq!(report.prior_snapshot, snapshot("current").to_string());
        assert_eq!(report.new_snapshot, snapshot("started").to_string());
        assert!(!report.replayed);
    }

    #[test]
    fn campaign_pin_uses_the_checked_loopback_transport() {
        let configuration = ConfigurationId::from_hash(hash("pin-configuration"));
        let command = CampaignCommand::Pin(CampaignPinArgs {
            basis: mutation_basis("pin"),
            configuration: configuration.to_string(),
            tier: CampaignPinRetentionArg::Exact,
            reason: "retain reproducer".to_owned(),
        });
        let report = pin_over_loopback(&command);

        assert_eq!(report.operation, "pin");
        assert_eq!(report.command, hash("pin").to_hex());
        assert_eq!(report.prior_snapshot, snapshot("current").to_string());
        assert_eq!(report.new_snapshot, snapshot("pinned").to_string());
        assert!(!report.replayed);
    }

    #[test]
    fn campaign_mutation_actions_preserve_exact_operator_intent() {
        let start = CampaignCommand::Start(mutation_basis("start"));
        let (basis, operation, action) = campaign_mutation_spec(&start).expect("start mutation");
        assert_eq!(basis.command, hash("start").to_hex());
        assert_eq!(operation, "start");
        assert!(matches!(action, CampaignControlAction::Resume));

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

        let configuration = ConfigurationId::from_hash(hash("pin-configuration"));
        let pin = CampaignCommand::Pin(CampaignPinArgs {
            basis: mutation_basis("pin"),
            configuration: configuration.to_string(),
            tier: CampaignPinRetentionArg::Exact,
            reason: "retain reproducer".to_owned(),
        });
        let pin_change = campaign_pin_spec(&pin).expect("pin mutation").2;
        assert_eq!(pin_change.configuration(), configuration);
        assert_eq!(pin_change.retention(), Some(PinRetention::Exact));
        assert_eq!(pin_change.reason(), "retain reproducer");

        let unpin = CampaignCommand::Unpin(CampaignUnpinArgs {
            basis: mutation_basis("unpin"),
            configuration: configuration.to_string(),
            reason: "resolved".to_owned(),
        });
        let unpin_change = campaign_pin_spec(&unpin).expect("unpin mutation").2;
        assert_eq!(unpin_change.configuration(), configuration);
        assert_eq!(unpin_change.retention(), None);
        assert_eq!(unpin_change.reason(), "resolved");
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
        let bad_snapshot = CampaignCommand::Snapshot(CampaignSnapshotArgs {
            name: "example".to_owned(),
            snapshot: "not-a-snapshot".to_owned(),
        });
        assert!(validate_campaign_command(&bad_snapshot).is_err());
        let bad_compare = CampaignCommand::Compare(CampaignCompareArgs {
            name: "example".to_owned(),
            left: snapshot("left").to_string(),
            right: "not-a-snapshot".to_owned(),
        });
        assert!(validate_campaign_command(&bad_compare).is_err());
        let bad_explain = CampaignCommand::Explain(CampaignExplainArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            opportunity: branch_request("explain-validation")
                .opportunity()
                .to_string(),
            request: "not-a-branch-request".to_owned(),
        });
        assert!(validate_campaign_command(&bad_explain).is_err());

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
        let bad_finding_cursor = CampaignCommand::Findings(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot("current").to_string(),
            after: Some("not-a-hash".to_owned()),
            limit: 1,
        });
        assert!(validate_campaign_command(&bad_finding_cursor).is_err());
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
        let generator = CandidateGeneratorSpecId::parse(&format!(
            "crucible.campaign.candidate-generator-spec@{}",
            ContentId::for_bytes(ObjectKind::Policy, 1, b"branch-generator").encode()
        ))
        .expect("candidate generator ID");
        let mut generated_branch = branch_args("generated");
        generated_branch.values.clear();
        generated_branch.generator = Some(generator.to_string());
        generated_branch.proposals = Some(8);
        let PreparedCampaignCommand::Branch(generated) = prepare_campaign_branch(
            &generated_branch,
            &CampaignPrincipal::new("operator").expect("campaign principal"),
        )
        .expect("generated branch request") else {
            unreachable!("generated branch preparation returned another operation")
        };
        assert_eq!(generated.request().source().generator(), Some(generator));
        assert_eq!(generated.request().budget().maximum_proposals(), 8);

        let mut missing_generated_budget = generated_branch.clone();
        missing_generated_budget.proposals = None;
        assert!(
            validate_campaign_command(&CampaignCommand::Branch(missing_generated_budget)).is_err()
        );
        let mut mixed_source = generated_branch;
        mixed_source.values.push("true".to_owned());
        assert!(validate_campaign_command(&CampaignCommand::Branch(mixed_source)).is_err());

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
        let fixture = Cli::try_parse_from([
            "crucible",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
            "/tmp/worked-network",
        ])
        .expect("offline worked-network fixture arguments");
        assert!(matches!(
            fixture.command,
            Commands::Campaign(CampaignArgs {
                socket: None,
                principal: None,
                command: CampaignCommand::Fixture(CampaignFixtureArgs {
                    fixture: CampaignFixtureCommand::WorkedNetwork(
                        CampaignWorkedNetworkFixtureArgs { ref output },
                    ),
                }),
            }) if output == &PathBuf::from("/tmp/worked-network")
        ));

        let validate = Cli::try_parse_from([
            "crucible",
            "campaign",
            "validate-import",
            "/tmp/campaign-import.toml",
        ])
        .expect("offline campaign import validation arguments");
        assert!(matches!(
            validate.command,
            Commands::Campaign(CampaignArgs {
                socket: None,
                principal: None,
                command: CampaignCommand::ValidateImport(CampaignValidateImportArgs {
                    ref manifests,
                }),
            }) if manifests == &[PathBuf::from("/tmp/campaign-import.toml")]
        ));

        let missing_connection = Cli::try_parse_from(["crucible", "campaign", "status", "example"])
            .expect("connected campaign arguments are checked before dispatch");
        let Commands::Campaign(missing_connection_args) = &missing_connection.command else {
            panic!("campaign command");
        };
        assert!(
            run_campaign_invocation(&missing_connection, missing_connection_args)
                .expect_err("connected command requires a socket")
                .to_string()
                .contains("require --socket")
        );

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

        let left_snapshot = snapshot("left").to_string();
        let right_snapshot = snapshot("right").to_string();
        let snapshot_command = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "snapshot",
            "example",
            "--snapshot",
            &left_snapshot,
        ])
        .expect("campaign snapshot arguments");
        assert!(matches!(
            snapshot_command.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Snapshot(_),
                ..
            })
        ));
        let compare_command = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "compare",
            "example",
            "--left",
            &left_snapshot,
            "--right",
            &right_snapshot,
        ])
        .expect("campaign compare arguments");
        assert!(matches!(
            compare_command.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Compare(_),
                ..
            })
        ));
        let explanation_request = branch_request("explanation-parser");
        let explanation_request_id = explanation_request
            .id()
            .expect("explanation request ID")
            .to_string();
        let explanation_opportunity = explanation_request.opportunity().to_string();
        let explain_command = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "explain",
            "example",
            "--snapshot",
            &left_snapshot,
            "--opportunity",
            &explanation_opportunity,
            "--request",
            &explanation_request_id,
        ])
        .expect("campaign explanation arguments");
        assert!(matches!(
            explain_command.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Explain(_),
                ..
            })
        ));
        let finding = FindingId::parse(&format!(
            "crucible.campaign.finding@{}",
            ContentId::for_bytes(ObjectKind::Finding, 1, b"finding-explanation-parser").encode()
        ))
        .expect("finding explanation ID")
        .to_string();
        let explain_finding = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "explain-finding",
            "example",
            "--snapshot",
            &left_snapshot,
            "--finding",
            &finding,
        ])
        .expect("campaign finding explanation arguments");
        assert!(matches!(
            explain_finding.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::ExplainFinding(_),
                ..
            })
        ));
        let attempt = AttemptId::parse(&format!(
            "crucible.campaign.attempt@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"attempt-explanation-parser")
                .encode()
        ))
        .expect("attempt explanation ID")
        .to_string();
        let explain_attempt = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "explain-attempt",
            "example",
            "--snapshot",
            &left_snapshot,
            "--attempt",
            &attempt,
        ])
        .expect("campaign attempt explanation arguments");
        assert!(matches!(
            explain_attempt.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::ExplainAttempt(_),
                ..
            })
        ));

        for operation in ["graph", "choices", "frontier", "findings"] {
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
                        | CampaignCommand::Frontier(CampaignPageArgs { limit: 3, .. })
                        | CampaignCommand::Findings(CampaignPageArgs { limit: 3, .. }),
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
            object_branch
                .opportunity
                .as_deref()
                .expect("object opportunity"),
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

        let create_start = hash("create-start").to_hex();
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
            "--start-command",
            &create_start,
        ])
        .expect("campaign create arguments");
        assert!(matches!(
            create.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Create(CampaignCreateArgs {
                    ref name,
                    ref start_command,
                    ..
                }),
                ..
            }) if name == "created" && start_command.as_deref() == Some(create_start.as_str())
        ));

        let start = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "start",
            "created",
            "--expected",
            &snapshot("created").to_string(),
            "--command",
            &hash("start").to_hex(),
        ])
        .expect("campaign start arguments");
        assert!(matches!(
            start.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Start(_),
                ..
            })
        ));

        let planner_step = PlannerStepId::parse(&format!(
            "crucible.campaign.planner-step@{}",
            ContentId::for_bytes(
                CampaignRecordKind::PlannerStep.object_kind(),
                CampaignRecordKind::PlannerStep.schema_version(),
                b"planner ranking step",
            )
        ))
        .expect("planner step ID");
        let branch_point = BranchPointId::from_hash(hash("planner-ranking-branch-point"));
        let source = BranchRequestId::parse(&format!(
            "crucible.campaign.branch-request@{}",
            ContentId::for_bytes(
                CampaignRecordKind::BranchRequest.object_kind(),
                CampaignRecordKind::BranchRequest.schema_version(),
                b"planner ranking source",
            )
        ))
        .expect("branch request ID");
        let rankings = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "rankings",
            "created",
            "--snapshot",
            &snapshot("created").to_string(),
            "--step",
            &planner_step.to_string(),
            "--pages",
            "4",
            "--policy-groups",
            "--branch-point",
            &branch_point.to_string(),
            "--source",
            &source.to_string(),
            "--top",
            "2",
        ])
        .expect("campaign rankings arguments");
        assert!(matches!(
            rankings.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Rankings(CampaignRankingsArgs {
                    pages: 4,
                    policy_groups: true,
                    branch_point: Some(_),
                    source: Some(_),
                    top: Some(2),
                    ..
                }),
                ..
            })
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
            branch.command.as_deref().expect("operator command"),
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--opportunity",
            branch.opportunity.as_deref().expect("branch opportunity"),
            "--domain",
            branch.domain.as_deref().expect("branch domain"),
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
        let generated_branch = Cli::try_parse_from([
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
            branch.command.as_deref().expect("operator command"),
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--opportunity",
            branch.opportunity.as_deref().expect("branch opportunity"),
            "--domain",
            branch.domain.as_deref().expect("branch domain"),
            "--generator",
            &format!(
                "crucible.campaign.candidate-generator-spec@{}",
                ContentId::for_bytes(ObjectKind::Policy, 1, b"parser-generator").encode()
            ),
            "--proposals",
            "8",
            "--attempts",
            "2",
        ])
        .expect("campaign generated branch arguments");
        assert!(matches!(
            generated_branch.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Branch(CampaignBranchArgs {
                    values,
                    generator: Some(_),
                    proposals: Some(8),
                    attempts: 2,
                    ..
                }),
                ..
            }) if values.is_empty()
        ));
        let all_branch = Cli::try_parse_from([
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
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--opportunity",
            branch.opportunity.as_deref().expect("branch opportunity"),
            "--domain",
            branch.domain.as_deref().expect("branch domain"),
            "--all",
            "--attempts",
            "2",
        ])
        .expect("campaign exhaustive branch arguments");
        assert!(matches!(
            all_branch.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Branch(CampaignBranchArgs {
                    all: true,
                    values,
                    generator: None,
                    proposals: None,
                    attempts: 2,
                    ..
                }),
                ..
            }) if values.is_empty()
        ));
        let selector_branch = Cli::try_parse_from([
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
            branch.command.as_deref().expect("operator command"),
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--selector",
            "tag:network",
            "--selector",
            "name:product.network.retry",
            "--instance",
            "network-retry",
            "--selector-scan-limit",
            "32",
            "--value",
            "true",
        ])
        .expect("campaign selector branch arguments");
        assert!(matches!(
            selector_branch.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Branch(CampaignBranchArgs {
                    opportunity: None,
                    domain: None,
                    selector: ref selectors,
                    instance: Some(ref instance),
                    selector_scan_limit: 32,
                    ..
                }),
                ..
            }) if selectors
                == &[
                    String::from("tag:network"),
                    String::from("name:product.network.retry"),
                ]
                && instance == "network-retry"
        ));
        assert!(
            Cli::try_parse_from([
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
                branch.command.as_deref().expect("operator command"),
                "--branch-point",
                &branch.branch_point,
                "--parent",
                &branch.parent,
                "--opportunity",
                branch.opportunity.as_deref().expect("branch opportunity"),
                "--domain",
                branch.domain.as_deref().expect("branch domain"),
                "--all",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
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
                "--branch-point",
                &branch.branch_point,
                "--parent",
                &branch.parent,
                "--opportunity",
                branch.opportunity.as_deref().expect("branch opportunity"),
                "--domain",
                branch.domain.as_deref().expect("branch domain"),
                "--value",
                "false",
            ])
            .is_err()
        );

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

        let configuration = ConfigurationId::from_hash(hash("pin-configuration")).to_string();
        let pin = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "pin",
            "example",
            "--expected",
            &expected,
            "--command",
            &hash("pin").to_hex(),
            &configuration,
            "--tier",
            "exact",
            "--reason",
            "retain reproducer",
        ])
        .expect("campaign pin arguments");
        assert!(matches!(
            pin.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Pin(CampaignPinArgs {
                    tier: CampaignPinRetentionArg::Exact,
                    ref reason,
                    ..
                }),
                ..
            }) if reason == "retain reproducer"
        ));

        let unpin = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "unpin",
            "example",
            "--expected",
            &expected,
            "--command",
            &hash("unpin").to_hex(),
            &configuration,
            "--reason",
            "resolved",
        ])
        .expect("campaign unpin arguments");
        assert!(matches!(
            unpin.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Unpin(CampaignUnpinArgs { ref reason, .. }),
                ..
            }) if reason == "resolved"
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

    fn pin_over_loopback(command: &CampaignCommand) -> CampaignMutationReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign pin mutation");
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report = apply_campaign_pin(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            command,
        )
        .expect("checked campaign pin mutation");
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

    fn accept_start_over_loopback(
        request: CreateCampaignRequest,
        command: CampaignCommandId,
    ) -> CampaignAcceptanceReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            for _operation in 0..2 {
                serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                    .expect("serve create-and-start operation");
            }
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report = apply_campaign_acceptance(
            &client,
            PreparedCampaignCommand::CreateAndStart(request, command),
        )
        .expect("checked create-and-start acceptance");
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
            command: Some(
                CampaignCommandId::from_hash(hash(&format!("{label}-command"))).to_string(),
            ),
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
            opportunity: Some(
                ChoiceOpportunityId::parse(&format!(
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
            ),
            domain: Some(
                ChoiceDomainId::parse(&format!(
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
            ),
            selector: Vec::new(),
            instance: None,
            selector_scan_limit: 256,
            values: vec!["false".to_owned(), "true".to_owned()],
            generator: None,
            all: false,
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

    fn graph_page_service() -> (GraphPageService, CampaignSnapshotId, CampaignSnapshotId) {
        let backend = Arc::new(MemoryBlobBackend::new("cli-graph-page", u64::MAX));
        let map = MerkleMap::new(backend);
        let mut root = map.empty().expect("empty graph root");
        let empty = root.content_id();
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
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.network.retry",
            ChoiceSource::Workload {
                producer: "network-product".to_owned(),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
                .expect("choice class"),
            BTreeSet::from(["network".to_owned()]),
            true,
        )
        .expect("selectable declaration");
        let opportunity = ChoiceOpportunity::new(
            configuration.scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: hash("explanation-scheduler"),
                producer: hash("explanation-producer"),
            },
            "network-retry",
            None,
        )
        .expect("choice opportunity");
        let opportunity_id = opportunity.id().expect("choice opportunity ID");
        let domain_id = domain.id().expect("choice domain ID");
        root = map
            .insert(
                root.content_id(),
                CampaignChoiceEntry::new(opportunity_id).graph_key(),
                opportunity_id.content_id(),
            )
            .expect("choice opportunity graph insertion");
        let choice_index = map
            .insert(
                empty,
                CampaignChoiceEntry::new(opportunity_id).index_key(),
                opportunity_id.content_id(),
            )
            .expect("choice opportunity index insertion");
        root = map
            .insert(
                root.content_id(),
                CampaignChoiceEntry::index_anchor_key(),
                choice_index.content_id(),
            )
            .expect("choice opportunity index anchor");
        let branch_request = BranchRequest::new(
            opportunity.branch_point_id(configuration.configuration()),
            configuration.id().expect("configuration artifact ID"),
            opportunity_id,
            domain_id,
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("finite explanation source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("explanation-command"))),
            BranchBudget::new(1, 1).expect("explanation branch budget"),
            StopCondition::NextChoice,
        )
        .expect("explanation branch request");
        let request_id = branch_request.id().expect("explanation request ID");
        let frontier_projection = ContinuationProjection::new(
            request_id,
            branch_request.branch_point(),
            ContinuationState::Ready,
        );
        let frontier_index = map
            .insert(
                empty,
                CampaignHash::from_bytes(request_id.content_id().digest()),
                frontier_projection
                    .id()
                    .expect("frontier projection ID")
                    .content_id(),
            )
            .expect("frontier explanation index");
        let exploration = map
            .insert(
                empty,
                CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
                frontier_index.content_id(),
            )
            .expect("frontier explanation anchor");
        let selection = Selection::new_campaign_branch(
            &opportunity,
            &domain,
            ChoiceValue::Boolean(true),
            branch_request.branch_point(),
        )
        .expect("attempt explanation selection");
        let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
            unreachable!("campaign branch constructor returned another origin")
        };
        let path = BranchPath::new(vec![BranchPathSegment::new(
            branch_request.branch_point(),
            edge,
        )])
        .expect("attempt explanation path");
        let proposal = Proposal::new(
            branch_request.branch_point(),
            request_id,
            domain_id,
            ChoiceValue::Boolean(true),
            policy("next-policy"),
            None,
            1,
            CampaignViewId::parse(&format!(
                "crucible.campaign.planning-view@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"attempt-guidance-view",)
                    .encode()
            ))
            .expect("attempt guidance view ID"),
        )
        .expect("attempt explanation proposal");
        let proposal_id = proposal.id().expect("attempt explanation proposal ID");
        let exploration = map
            .insert(
                exploration.content_id(),
                content_index_key("exploration.proposal", proposal_id.content_id()),
                proposal_id.content_id(),
            )
            .expect("attempt explanation proposal insertion");
        let attempt = Attempt::new(
            AttemptStart::Branch {
                edge,
                parent: configuration.id().expect("attempt parent artifact ID"),
                selection: selection.id().expect("attempt selection ID"),
            },
            path.id().expect("attempt path ID"),
            StopCondition::NextChoice,
        )
        .expect("attempt explanation attempt");
        let attempt_id = attempt.id().expect("attempt explanation attempt ID");
        let admission = AttemptAdmission::new(
            attempt_id,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal_id),
                cause: branch_request.cause(),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        );
        let accounting = map
            .insert(
                empty,
                content_index_key("accounting.attempt", attempt_id.content_id()),
                attempt_id.content_id(),
            )
            .expect("attempt explanation accounting insertion");
        let accounting = map
            .insert(
                accounting.content_id(),
                content_index_key(
                    "accounting.attempt-execution-basis",
                    attempt_id.content_id(),
                ),
                admission
                    .id()
                    .expect("attempt explanation admission ID")
                    .content_id(),
            )
            .expect("attempt explanation admission insertion");
        let finding_observation = Observation::new(
            attempt_id,
            configuration.configuration(),
            configuration.id().expect("finding child artifact ID"),
            path.id().expect("finding path ID"),
            StopOutcome::ModeledTimeout("execution".to_owned()),
            MeasurementSetId::parse(&format!(
                "crucible.campaign.measurement-set@{}",
                ContentId::for_bytes(ObjectKind::Observation, 1, b"cli-finding-measurements")
                    .encode()
            ))
            .expect("finding measurement ID"),
            PropertyVerdictSetId::parse(&format!(
                "crucible.campaign.property-verdict-set@{}",
                ContentId::for_bytes(ObjectKind::Observation, 1, b"cli-finding-properties")
                    .encode()
            ))
            .expect("finding property ID"),
            CoverageProjectionId::parse(&format!(
                "crucible.campaign.coverage-projection@{}",
                ContentId::for_bytes(ObjectKind::Projection, 1, b"cli-finding-coverage").encode()
            ))
            .expect("finding coverage ID"),
            BTreeSet::new(),
        )
        .expect("finding observation");
        let finding_observation_id = finding_observation.id().expect("finding observation ID");
        let observations = map
            .insert(
                empty,
                content_index_key("observations.attempt", attempt_id.content_id()),
                finding_observation_id.content_id(),
            )
            .expect("attempt explanation observation insertion");
        let finding_reproduction = ReproductionArtifact::new(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration
                .id()
                .expect("finding configuration artifact ID"),
            hash("finding-fingerprint"),
            1,
            b"reproduce-timeout".to_vec(),
        )
        .expect("finding reproduction");
        let finding = Finding::new(
            FindingSignature::new(
                FindingKind::Timeout,
                hash("finding-fingerprint"),
                None,
                "timeout.execution".to_owned(),
                None,
                BTreeSet::new(),
            )
            .expect("finding signature"),
            finding_observation_id,
            finding_reproduction.id().expect("finding reproduction ID"),
            snapshot("finding-first-seen"),
            FindingOccurrenceSet::new(empty, 3, finding_observation_id)
                .expect("finding occurrences"),
            None,
            BTreeSet::new(),
        )
        .expect("finding");
        let finding_root = map
            .insert(
                empty,
                finding_index_key(finding.signature().cluster_key()),
                finding.id().expect("finding ID").content_id(),
            )
            .expect("finding index");
        let roots = CampaignRoots {
            graph: root.content_id(),
            exploration: exploration.content_id(),
            observations: observations.content_id(),
            corpus: empty,
            coverage: empty,
            findings: finding_root.content_id(),
            pins: empty,
            accounting: accounting.content_id(),
            coordination: empty,
        };
        let historical = CampaignSnapshot::genesis(lineage("lineage"), policy("policy"), roots)
            .expect("historical graph snapshot");
        let historical_id = historical.id().expect("historical graph snapshot ID");
        let transition = CampaignFactId::parse(&format!(
            "crucible.campaign.fact@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 2, b"cli-graph-transition").encode()
        ))
        .expect("transition fact ID");
        let snapshot = CampaignSnapshot::successor(
            historical_id,
            lineage("lineage"),
            policy("next-policy"),
            roots,
            transition,
        )
        .expect("current graph snapshot");
        let snapshot_id = snapshot.id().expect("current graph snapshot ID");
        let snapshots =
            BTreeMap::from([(historical_id, historical), (snapshot_id, snapshot.clone())]);
        (
            GraphPageService {
                map,
                root: root.content_id(),
                snapshot,
                snapshots,
                object_key,
                object,
                declaration,
                domain,
                opportunity,
                additional_choices: Vec::new(),
                branch_request,
                frontier_projection,
                finding,
                finding_root: finding_root.content_id(),
                finding_observation,
                finding_reproduction,
                attempt,
                attempt_admission: admission,
                attempt_path: path,
                attempt_selection: selection,
                attempt_proposal: proposal,
            },
            snapshot_id,
            historical_id,
        )
    }

    fn add_ambiguous_selector_choice(
        mut service: GraphPageService,
    ) -> (GraphPageService, CampaignSnapshotId) {
        let opportunity = ChoiceOpportunity::new(
            service.opportunity.scenario(),
            &service.declaration,
            &service.domain,
            ChoiceCoordinate {
                scheduler: hash("second-selector-scheduler"),
                producer: hash("second-selector-producer"),
            },
            "network-retry-secondary",
            None,
        )
        .expect("second selector opportunity");
        let opportunity_id = opportunity.id().expect("second selector opportunity ID");
        let old_graph = service.snapshot.roots().graph;
        let choice_index = service
            .map
            .get(old_graph, CampaignChoiceEntry::index_anchor_key())
            .expect("choice index lookup")
            .expect("choice index root");
        let choice_index = service
            .map
            .insert(
                choice_index,
                CampaignChoiceEntry::new(opportunity_id).index_key(),
                opportunity_id.content_id(),
            )
            .expect("second selector index insertion");
        let graph = service
            .map
            .insert(
                old_graph,
                CampaignChoiceEntry::new(opportunity_id).graph_key(),
                opportunity_id.content_id(),
            )
            .expect("second selector graph insertion");
        let graph = service
            .map
            .insert(
                graph.content_id(),
                CampaignChoiceEntry::index_anchor_key(),
                choice_index.content_id(),
            )
            .expect("second selector index anchor");
        let mut roots = service.snapshot.roots();
        roots.graph = graph.content_id();
        let parent = service.snapshot.id().expect("selector parent snapshot ID");
        let transition = CampaignFactId::parse(&format!(
            "crucible.campaign.fact@{}",
            ContentId::for_bytes(
                ObjectKind::CampaignFact,
                2,
                b"cli-selector-ambiguity-transition",
            )
            .encode()
        ))
        .expect("selector transition fact ID");
        let snapshot = CampaignSnapshot::successor(
            parent,
            service.snapshot.lineage(),
            service.snapshot.active_policy(),
            roots,
            transition,
        )
        .expect("selector ambiguity snapshot");
        let snapshot_id = snapshot.id().expect("selector ambiguity snapshot ID");
        service.root = graph.content_id();
        service.snapshot = snapshot.clone();
        service.snapshots.insert(snapshot_id, snapshot);
        service.additional_choices.push((
            opportunity,
            service.declaration.clone(),
            service.domain.clone(),
        ));
        (service, snapshot_id)
    }

    fn finding_index_key(cluster: CampaignHash) -> CampaignHash {
        let namespace = "findings.signature";
        let mut bytes = Vec::with_capacity(namespace.len() + 40);
        bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        bytes.extend_from_slice(namespace.as_bytes());
        bytes.extend_from_slice(&cluster.as_bytes());
        CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
    }

    fn content_index_key(namespace: &str, id: ContentId) -> CampaignHash {
        let encoded = id.encode();
        let mut bytes = Vec::with_capacity(namespace.len() + encoded.len() + 16);
        bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        bytes.extend_from_slice(namespace.as_bytes());
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(encoded.as_bytes());
        CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
    }

    fn mismatch_explanation_frontier(
        mut service: GraphPageService,
    ) -> (GraphPageService, CampaignSnapshotId) {
        let foreign_opportunity = ChoiceOpportunityId::parse(&format!(
            "crucible.campaign.choice-opportunity@{}",
            ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"foreign-explanation-opportunity",
            )
            .encode()
        ))
        .expect("foreign explanation opportunity ID");
        let prior = &service.branch_request;
        let branch_request = BranchRequest::new(
            prior.branch_point(),
            prior.parent(),
            foreign_opportunity,
            prior.domain(),
            prior.source().clone(),
            prior.cause(),
            prior.budget(),
            prior.stop().clone(),
        )
        .expect("mismatched explanation branch request");
        let request_id = branch_request.id().expect("mismatched request ID");
        let frontier_projection = ContinuationProjection::new(
            request_id,
            branch_request.branch_point(),
            ContinuationState::Ready,
        );
        let empty = service
            .map
            .empty()
            .expect("empty mismatch root")
            .content_id();
        let frontier_index = service
            .map
            .insert(
                empty,
                CampaignHash::from_bytes(request_id.content_id().digest()),
                frontier_projection
                    .id()
                    .expect("mismatched projection ID")
                    .content_id(),
            )
            .expect("mismatched frontier index");
        let exploration = service
            .map
            .insert(
                empty,
                CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
                frontier_index.content_id(),
            )
            .expect("mismatched frontier anchor");
        let mut roots = service.snapshot.roots();
        roots.exploration = exploration.content_id();
        let snapshot = CampaignSnapshot::genesis(
            service.snapshot.lineage(),
            service.snapshot.active_policy(),
            roots,
        )
        .expect("mismatched explanation snapshot");
        let snapshot_id = snapshot.id().expect("mismatched explanation snapshot ID");
        service.snapshot = snapshot.clone();
        service.snapshots = BTreeMap::from([(snapshot_id, snapshot)]);
        service.branch_request = branch_request;
        service.frontier_projection = frontier_projection;
        (service, snapshot_id)
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

    #[test]
    fn planner_attempt_explanations_render_guidance_and_accounting() {
        macro_rules! stored_id {
            ($type:ident, $tag:literal, $kind:expr, $version:expr, $label:literal) => {
                $type::parse(&format!(
                    concat!($tag, "@{}"),
                    ContentId::for_bytes($kind, $version, $label.as_bytes()).encode()
                ))
                .expect(concat!("valid ", $tag))
            };
        }

        let selected = PlanningScanPosition::new(
            BranchPointId::from_hash(hash("planner-explanation-branch-point")),
            stored_id!(
                BranchRequestId,
                "crucible.campaign.branch-request",
                ObjectKind::CampaignFact,
                1,
                "planner-explanation-request"
            ),
        );
        let step = PlannerStep::new(
            None,
            stored_id!(
                PlannerInvocationId,
                "crucible.campaign.planner-invocation",
                ObjectKind::Policy,
                2,
                "planner-explanation-invocation"
            ),
            stored_id!(
                RetainedPlannerRequestId,
                "crucible.campaign.retained-planner-request",
                ObjectKind::Policy,
                1,
                "planner-explanation-retained-request"
            ),
            hash("planner-explanation-request-digest"),
            policy("planner-explanation-policy"),
            stored_id!(
                PlannerEngineId,
                "crucible.campaign.planner-engine",
                ObjectKind::Policy,
                1,
                "planner-explanation-engine"
            ),
            stored_id!(
                PolicyArtifactId,
                "crucible.campaign.policy-artifact",
                ObjectKind::Policy,
                1,
                "planner-explanation-policy-artifact"
            ),
            stored_id!(
                CampaignViewId,
                "crucible.campaign.planning-view",
                ObjectKind::CampaignFact,
                1,
                "planner-explanation-view"
            ),
            PlannerDisposition::Issue {
                selected,
                issued_branch_requests: Vec::new(),
                issued_proposals: vec![stored_id!(
                    ProposalId,
                    "crucible.campaign.proposal",
                    ObjectKind::CampaignFact,
                    1,
                    "planner-explanation-proposal"
                )],
            },
            stored_id!(
                PlannerStateId,
                "crucible.campaign.planner-state",
                ObjectKind::Policy,
                1,
                "planner-explanation-state"
            ),
            PlanningUsage {
                branch_requests: 0,
                proposals: 1,
                input_objects: 12,
                input_bytes: 34_567,
                fuel: 890,
            },
            PlanningAccounting {
                branch_requests: 0,
                proposals: 1,
                attempts: 1,
                deduplicated: 0,
                input_objects: 12,
                input_bytes: 34_567,
                fuel: 890,
            },
            GuidanceEvidence::new(BTreeMap::from([
                (String::from("exploration"), 125_000),
                (String::from("novelty"), 750_000),
            ]))
            .expect("valid planner guidance evidence"),
        )
        .expect("valid planner explanation step");

        let explained =
            explain::explained_planner_decision(&step).expect("authenticated planner explanation");
        let value = serde_json::to_value(explained).expect("planner explanation JSON");

        assert_eq!(
            value["selected_branch_point"],
            selected.branch_point().to_string()
        );
        assert_eq!(value["selected_source"], selected.source().to_string());
        assert_eq!(value["guidance_terms_micros"]["exploration"], 125_000);
        assert_eq!(value["guidance_terms_micros"]["novelty"], 750_000);
        assert_eq!(value["accounting"]["attempts"], 1);
        assert_eq!(value["accounting"]["input_bytes"], 34_567);
        assert_eq!(value["accounting"]["fuel"], 890);
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
