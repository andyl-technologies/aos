//! Thin local client for authenticated lazy-campaign inspection and control.

use super::cli_campaign_import::{
    CampaignImportValidationReport, validate_campaign_import_manifests,
};
use super::*;

#[path = "campaign/acceptance.rs"]
mod acceptance;
#[path = "campaign/authoring.rs"]
mod authoring;
#[path = "campaign/configuration.rs"]
mod configuration;
#[path = "campaign/explain.rs"]
mod explain;
#[path = "campaign/fixture.rs"]
mod fixture;
#[path = "campaign/lineage.rs"]
mod lineage;
#[path = "campaign/object.rs"]
mod object;
#[path = "campaign/policy.rs"]
mod policy;
#[path = "campaign/ranking.rs"]
mod ranking;
#[path = "campaign/scenario.rs"]
mod scenario;
#[path = "campaign/schedule.rs"]
mod schedule;
#[path = "campaign/snapshot.rs"]
mod snapshot;
#[path = "campaign/validation.rs"]
mod validation;

use acceptance::CampaignBranchAcceptanceSummaryReport;
use configuration::{compile_campaign_configuration, render_campaign_configuration_compilation};
use explain::{
    query_campaign_attempt_explanation, query_campaign_explanation,
    query_campaign_finding_explanation, render_campaign_attempt_explanation,
    render_campaign_explanation, render_campaign_finding_explanation,
    validate_campaign_attempt_explain_command, validate_campaign_explain_command,
    validate_campaign_finding_explain_command,
};
use fixture::{generate_worked_network_fixture, render_worked_network_fixture};
use lineage::{compile_campaign_lineage, render_campaign_lineage_compilation};
use object::{query_campaign_object, render_campaign_object, validate_campaign_object_basis};
use policy::{compile_campaign_policy, render_campaign_policy_compilation};
use ranking::{
    query_campaign_rankings, render_campaign_rankings, validate_campaign_rankings_command,
};
use scenario::{compile_campaign_scenario, render_campaign_scenario_compilation};
use schedule::{compile_campaign_schedule, render_campaign_schedule_compilation};
use snapshot::{
    query_campaign_snapshot, render_campaign_snapshot, validate_campaign_snapshot_command,
};
use validation::{
    query_campaign_validation, render_campaign_validation, validate_campaign_policy_file,
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
    GetCampaignRequest, GetCampaignStatusRequest, IntegerValue, ListCampaignsRequest,
    MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_LIST_PAGE_ITEMS,
    MAX_CAMPAIGN_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES, PinCampaignRequest,
    PinChange, PinRequest, PinRetention, QueryCampaignChoicesRequest, QueryCampaignFindingsRequest,
    QueryCampaignFrontierRequest, QueryCampaignGraphRequest,
    STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION, SelectableDeclaration, SelectableId,
    StopCondition, SubmitCampaignBranchRequest, WatchCampaignRequest,
};
use crucible_daemon::{
    AttachCampaignRuntimeRequest, CampaignRuntimeAttachmentDisposition, LoopbackCampaignService,
};
use serde::Serialize;

const CAMPAIGN_HEAD_REPORT_SCHEMA: &str = "crucible.cli.campaign-head.v1";
const CAMPAIGN_STATUS_REPORT_SCHEMA: &str = "crucible.cli.campaign-head.v2";
const CAMPAIGN_LIST_REPORT_SCHEMA: &str = "crucible.cli.campaign-list.v1";
const CAMPAIGN_MUTATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-mutation.v1";
const CAMPAIGN_PAGE_REPORT_SCHEMA: &str = "crucible.cli.campaign-page.v2";
const CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA: &str = "crucible.cli.campaign-acceptance.v3";
const CAMPAIGN_RUNTIME_ATTACHMENT_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-runtime-attachment.v1";
const MAX_CAMPAIGN_SELECTOR_SCAN_ITEMS: u32 = 4_096;
const MAX_CAMPAIGN_SELECTOR_PREDICATES: usize = 16;
const MAX_CAMPAIGN_PAGE_FOLLOW_PAGES: u32 = 256;
const MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES: usize = 65_536;
const MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic: Option<CampaignSemanticStatusReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operational: Option<CampaignOperationalStatusReport>,
}

#[derive(Serialize)]
struct CampaignSemanticStatusReport {
    latent_or_open_continuations: u64,
    ready_continuations: u64,
    waiting_for_feedback_continuations: u64,
    open_continuations: u64,
    exhausted_continuations: u64,
    closed_continuations: u64,
    admitted_attempts: u64,
    stored_graph_nodes: u64,
    continuation_records_scanned: u64,
    continuation_bytes_scanned: u64,
}

#[derive(Serialize)]
#[serde(tag = "availability", rename_all = "kebab-case")]
enum CampaignOperationalStatusReport {
    Unavailable,
    Observed {
        daemon_epoch: String,
        inventory_generation: String,
        preparing_worlds: u64,
        running_worlds: u64,
        checkpointing_worlds: u64,
        publishing_worlds: u64,
        canceling_worlds: u64,
        paused_worlds: u64,
        retained_checkpoint_roots: u64,
        materialized_checkpoints: u64,
    },
}

#[derive(Serialize)]
struct CampaignListReport {
    schema: &'static str,
    operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_after: Option<String>,
    page_limit: u32,
    page_budget: u32,
    pages_scanned: u32,
    response_bytes: u64,
    complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after: Option<String>,
    entries: Vec<CampaignListReportEntry>,
}

#[derive(Serialize)]
struct CampaignListReportEntry {
    campaign: String,
    snapshot: String,
    lineage: String,
    policy: String,
    state: &'static str,
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
struct CampaignRuntimeAttachmentReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    request_digest: String,
    disposition: &'static str,
    attached_runtime_count: u32,
}

#[derive(Serialize)]
struct CampaignPageReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_after: Option<String>,
    page_limit: u32,
    page_budget: u32,
    pages_scanned: u32,
    response_bytes: u64,
    complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after: Option<String>,
    entries: Vec<CampaignPageEntry>,
}

struct CampaignPageBatch<C> {
    entries: Vec<CampaignPageEntry>,
    next_after: Option<C>,
    response_bytes: usize,
}

struct CampaignPageAggregation {
    start_after: Option<String>,
    pages_scanned: u32,
    response_bytes: u64,
    complete: bool,
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
    Attach(AttachCampaignRuntimeRequest),
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
        #[serde(flatten)]
        summary: CampaignBranchAcceptanceSummaryReport,
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
    if let CampaignCommand::Validate(validate) = &args.command
        && let Some(policy) = validate.policy.as_deref()
    {
        let report = validate_campaign_policy_file(policy)?;
        println!(
            "{}",
            render_campaign_validation(&report, cli.output_format())?
        );
        return Ok(());
    }
    if let CampaignCommand::Scenario(scenario) = &args.command {
        let report = match &scenario.command {
            CampaignScenarioCommand::Compile(compile) => {
                compile_campaign_scenario(&compile.input, &compile.output)?
            }
        };
        println!(
            "{}",
            render_campaign_scenario_compilation(&report, cli.output_format())?
        );
        return Ok(());
    }
    if let CampaignCommand::Configuration(configuration) = &args.command {
        let report = match &configuration.command {
            CampaignConfigurationCommand::Compile(compile) => compile_campaign_configuration(
                &compile.scenario,
                &compile.schedule,
                &compile.output,
            )?,
        };
        println!(
            "{}",
            render_campaign_configuration_compilation(&report, cli.output_format())?
        );
        return Ok(());
    }
    if let CampaignCommand::Schedule(schedule) = &args.command {
        let report = match &schedule.command {
            CampaignScheduleCommand::Compile(compile) => {
                compile_campaign_schedule(&compile.input, &compile.output)?
            }
        };
        println!(
            "{}",
            render_campaign_schedule_compilation(&report, cli.output_format())?
        );
        return Ok(());
    }
    if let CampaignCommand::Policy(policy) = &args.command {
        let report = match &policy.command {
            CampaignPolicyCommand::Compile(compile) => compile_campaign_policy(
                &compile.input,
                compile.scenario.as_deref(),
                &compile.output,
            )?,
        };
        println!(
            "{}",
            render_campaign_policy_compilation(&report, cli.output_format())?
        );
        return Ok(());
    }
    if let CampaignCommand::Lineage(lineage) = &args.command {
        let report = match &lineage.command {
            CampaignLineageCommand::Compile(compile) => {
                compile_campaign_lineage(&compile.input, &compile.output)?
            }
        };
        println!(
            "{}",
            render_campaign_lineage_compilation(&report, cli.output_format())?
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
    let mut prepared = prepare_campaign_command(&args.command, &principal)?;
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
    if matches!(args.command, CampaignCommand::Attach(_)) {
        let Some(PreparedCampaignCommand::Attach(request)) = prepared.take() else {
            return Err(backend_error(
                "campaign runtime attachment was not prepared before connection",
            ));
        };
        let response = service.attach_campaign_runtime(&request).map_err(|error| {
            backend_error(format!("campaign runtime attachment failed: {error}"))
        })?;
        let report = CampaignRuntimeAttachmentReport {
            schema: CAMPAIGN_RUNTIME_ATTACHMENT_REPORT_SCHEMA,
            operation: "attach-runtime",
            campaign: response.campaign().as_str().to_owned(),
            request_digest: response.request_digest().to_hex(),
            disposition: match response.disposition() {
                CampaignRuntimeAttachmentDisposition::Attached => "attached",
                CampaignRuntimeAttachmentDisposition::Replayed => "replayed",
            },
            attached_runtime_count: response.attached_runtime_count(),
        };
        println!(
            "{}",
            render_campaign_runtime_attachment(&report, cli.output_format())?
        );
        return Ok(());
    }
    let client = CampaignClient::new(service);
    let rendered = match &args.command {
        CampaignCommand::ValidateImport(_) => {
            return Err(backend_error(
                "offline campaign import validation reached the connected dispatch path",
            ));
        }
        CampaignCommand::Validate(validate) => {
            let report = query_campaign_validation(&client, principal, validate)?;
            render_campaign_validation(&report, cli.output_format())?
        }
        CampaignCommand::Fixture(_) => {
            return Err(backend_error(
                "offline campaign fixture generation reached the connected dispatch path",
            ));
        }
        CampaignCommand::Scenario(_)
        | CampaignCommand::Configuration(_)
        | CampaignCommand::Schedule(_)
        | CampaignCommand::Policy(_)
        | CampaignCommand::Lineage(_) => {
            return Err(backend_error(
                "offline campaign authoring reached the connected dispatch path",
            ));
        }
        CampaignCommand::Create(_) | CampaignCommand::Derive(_) => {
            let prepared = prepared.ok_or_else(|| {
                backend_error("campaign acceptance command was not prepared before connection")
            })?;
            let report = apply_campaign_acceptance(&client, prepared)?;
            render_campaign_acceptance(&report, cli.output_format())?
        }
        CampaignCommand::List(list) => {
            let report = query_campaign_list(&client, principal, list)?;
            render_campaign_list(&report, cli.output_format())?
        }
        CampaignCommand::Attach(_) => {
            return Err(backend_error(
                "campaign runtime attachment reached semantic campaign dispatch",
            ));
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
        CampaignCommand::Validate(_) => Ok(None),
        CampaignCommand::Scenario(_) => Ok(None),
        CampaignCommand::Configuration(_) => Ok(None),
        CampaignCommand::Schedule(_) => Ok(None),
        CampaignCommand::Policy(_) => Ok(None),
        CampaignCommand::Lineage(_) => Ok(None),
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
        CampaignCommand::List(list) => {
            validate_campaign_list(list)?;
            Ok(None)
        }
        CampaignCommand::Attach(attach) => {
            let request = AttachCampaignRuntimeRequest::new(
                principal.clone(),
                campaign_name(&attach.name)?,
                attach.executor_socket.clone(),
            )
            .map_err(|error| {
                usage_error(format!("invalid campaign runtime attachment: {error}"))
            })?;
            Ok(Some(PreparedCampaignCommand::Attach(request)))
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
    validate_campaign_page_aggregation(page, kind)
}

fn validate_campaign_page_aggregation(page: &CampaignPageArgs, kind: &str) -> Result<(), CliError> {
    if page.pages == 0 || page.pages > MAX_CAMPAIGN_PAGE_FOLLOW_PAGES {
        return Err(usage_error(format!(
            "campaign {kind} page budget must be between 1 and {MAX_CAMPAIGN_PAGE_FOLLOW_PAGES}"
        )));
    }
    let aggregate_entries = usize::try_from(page.limit)
        .ok()
        .and_then(|limit| {
            usize::try_from(page.pages)
                .ok()
                .and_then(|pages| limit.checked_mul(pages))
        })
        .ok_or_else(|| usage_error("campaign page aggregate entry count overflows"))?;
    if aggregate_entries > MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES {
        return Err(usage_error(format!(
            "campaign {kind} page request exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES}-entry aggregate bound"
        )));
    }
    Ok(())
}

fn validate_campaign_list(list: &CampaignListArgs) -> Result<(), CliError> {
    if let Some(after) = list.after.as_deref() {
        campaign_name(after)?;
    }
    if list.limit == 0 || list.limit > MAX_CAMPAIGN_LIST_PAGE_ITEMS {
        return Err(usage_error(format!(
            "campaign list page limit must be between 1 and {MAX_CAMPAIGN_LIST_PAGE_ITEMS}"
        )));
    }
    if list.pages == 0 || list.pages > MAX_CAMPAIGN_PAGE_FOLLOW_PAGES {
        return Err(usage_error(format!(
            "campaign list page budget must be between 1 and {MAX_CAMPAIGN_PAGE_FOLLOW_PAGES}"
        )));
    }
    let entries = usize::try_from(list.limit)
        .ok()
        .and_then(|limit| {
            usize::try_from(list.pages)
                .ok()
                .and_then(|pages| limit.checked_mul(pages))
        })
        .ok_or_else(|| usage_error("campaign list aggregate entry count overflows"))?;
    if entries > MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES {
        return Err(usage_error(format!(
            "campaign list request exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES}-entry aggregate bound"
        )));
    }
    Ok(())
}

fn query_campaign_list<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    list: &CampaignListArgs,
) -> Result<CampaignListReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    validate_campaign_list(list)?;
    let start_after = list.after.clone();
    let mut after = list.after.as_deref().map(campaign_name).transpose()?;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    let mut pages_scanned = 0_u32;
    let mut response_bytes = 0_u64;
    let mut complete = false;

    for _ in 0..list.pages {
        let request = ListCampaignsRequest::new(principal.clone(), after.clone(), list.limit)
            .map_err(|error| usage_error(format!("invalid campaign list request: {error}")))?;
        let response = client
            .list_campaigns(&request)
            .map_err(|error| backend_error(format!("campaign list failed: {error}")))?;
        pages_scanned = pages_scanned
            .checked_add(1)
            .ok_or_else(|| backend_error("campaign list page count overflowed"))?;
        response_bytes = response_bytes
            .checked_add(
                u64::try_from(response.canonical_bytes().len())
                    .map_err(|_| backend_error("campaign list response size overflowed"))?,
            )
            .ok_or_else(|| backend_error("campaign list response bytes overflowed"))?;
        if response_bytes > MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES {
            return Err(backend_error(format!(
                "campaign list responses exceed the {MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES}-byte aggregate bound"
            )));
        }
        for entry in response.entries() {
            if entries.len() >= MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES {
                return Err(backend_error(format!(
                    "campaign list exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES}-entry aggregate bound"
                )));
            }
            entries.push(CampaignListReportEntry {
                campaign: entry.name().as_str().to_owned(),
                snapshot: entry.snapshot().to_string(),
                lineage: entry.lineage().to_string(),
                policy: entry.policy().to_string(),
                state: campaign_state_label(entry.state()),
            });
        }
        match response.next_after().cloned() {
            Some(next) => {
                if !seen.insert(next.clone()) {
                    return Err(backend_error("campaign list cursor cycle detected"));
                }
                after = Some(next);
            }
            None => {
                after = None;
                complete = true;
                break;
            }
        }
    }

    Ok(CampaignListReport {
        schema: CAMPAIGN_LIST_REPORT_SCHEMA,
        operation: "list",
        start_after,
        page_limit: list.limit,
        page_budget: list.pages,
        pages_scanned,
        response_bytes,
        complete,
        next_after: after.map(|name| name.as_str().to_owned()),
        entries,
    })
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
            let status_request = GetCampaignStatusRequest::new(
                request.principal().clone(),
                campaign.clone(),
                response.snapshot(),
            )
            .map_err(|error| usage_error(format!("invalid campaign status request: {error}")))?;
            let status_response = client
                .get_campaign_status(&status_request)
                .map_err(|error| backend_error(format!("campaign status failed: {error}")))?;
            let status_summary = status_response.status();
            let semantic = status_summary.semantic();
            let continuations = semantic.continuations();
            let semantic = CampaignSemanticStatusReport {
                latent_or_open_continuations: continuations.latent_or_open().map_err(|error| {
                    backend_error(format!("campaign status is invalid: {error}"))
                })?,
                ready_continuations: continuations.ready(),
                waiting_for_feedback_continuations: continuations.waiting_for_feedback(),
                open_continuations: continuations.open(),
                exhausted_continuations: continuations.exhausted(),
                closed_continuations: continuations.closed(),
                admitted_attempts: semantic.admitted_attempts(),
                stored_graph_nodes: semantic.stored_graph_nodes(),
                continuation_records_scanned: semantic.continuation_records_scanned(),
                continuation_bytes_scanned: semantic.continuation_bytes_scanned(),
            };
            let operational = match status_summary.operational() {
                crucible_campaign::CampaignOperationalStatus::Unavailable => {
                    CampaignOperationalStatusReport::Unavailable
                }
                crucible_campaign::CampaignOperationalStatus::Observed(evidence) => {
                    let worlds = evidence.worlds();
                    CampaignOperationalStatusReport::Observed {
                        daemon_epoch: format!(
                            "{:032x}",
                            u128::from_be_bytes(evidence.daemon_epoch().as_bytes())
                        ),
                        inventory_generation: evidence.inventory_generation().to_hex(),
                        preparing_worlds: worlds.preparing(),
                        running_worlds: worlds.running(),
                        checkpointing_worlds: worlds.checkpointing(),
                        publishing_worlds: worlds.publishing(),
                        canceling_worlds: worlds.canceling(),
                        paused_worlds: worlds.paused(),
                        retained_checkpoint_roots: evidence.retained_checkpoint_roots(),
                        materialized_checkpoints: evidence.materialized_checkpoints(),
                    }
                }
            };
            Ok(CampaignHeadReport {
                schema: CAMPAIGN_STATUS_REPORT_SCHEMA,
                operation: "status",
                campaign: campaign.as_str().to_owned(),
                snapshot: response.snapshot().to_string(),
                lineage: response.lineage().to_string(),
                policy: response.policy().to_string(),
                state: campaign_state_label(response.state()),
                advanced: None,
                semantic: Some(semantic),
                operational: Some(operational),
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
                semantic: None,
                operational: None,
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
            let aggregation = collect_campaign_pages(
                page,
                "graph",
                after,
                |cursor| cursor.to_hex(),
                |cursor| {
                    let request = QueryCampaignGraphRequest::new(
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        cursor,
                        page.limit,
                    )
                    .map_err(|error| {
                        usage_error(format!("invalid campaign graph query: {error}"))
                    })?;
                    let response = client.query_campaign_graph(&request).map_err(|error| {
                        backend_error(format!("campaign graph query failed: {error}"))
                    })?;
                    Ok(CampaignPageBatch {
                        response_bytes: response.canonical_bytes().len(),
                        next_after: response.next_after(),
                        entries: response
                            .entries()
                            .iter()
                            .map(|entry| CampaignPageEntry::Graph {
                                key: entry.key().to_hex(),
                                object: entry.object().to_string(),
                            })
                            .collect(),
                    })
                },
            )?;
            Ok(campaign_page_report(
                "graph",
                &campaign,
                snapshot,
                page,
                aggregation,
            ))
        }
        CampaignCommand::Choices(page) => {
            let (campaign, snapshot) = campaign_page_basis(page)?;
            let after = page
                .after
                .as_deref()
                .map(ChoiceOpportunityId::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign choice cursor: {error}")))?;
            let aggregation =
                collect_campaign_pages(page, "choice", after, ToString::to_string, |cursor| {
                    let request = QueryCampaignChoicesRequest::new(
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        cursor,
                        page.limit,
                    )
                    .map_err(|error| {
                        usage_error(format!("invalid campaign choices query: {error}"))
                    })?;
                    let response = client.query_campaign_choices(&request).map_err(|error| {
                        backend_error(format!("campaign choices query failed: {error}"))
                    })?;
                    Ok(CampaignPageBatch {
                        response_bytes: response.canonical_bytes().len(),
                        next_after: response.next_after(),
                        entries: response
                            .entries()
                            .iter()
                            .map(|entry| CampaignPageEntry::Choice {
                                opportunity: entry.opportunity().to_string(),
                            })
                            .collect(),
                    })
                })?;
            Ok(campaign_page_report(
                "choices",
                &campaign,
                snapshot,
                page,
                aggregation,
            ))
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
            let aggregation =
                collect_campaign_pages(page, "frontier", after, ToString::to_string, |cursor| {
                    let request = QueryCampaignFrontierRequest::new(
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        cursor,
                        page.limit,
                    )
                    .map_err(|error| {
                        usage_error(format!("invalid campaign frontier query: {error}"))
                    })?;
                    let response = client.query_campaign_frontier(&request).map_err(|error| {
                        backend_error(format!("campaign frontier query failed: {error}"))
                    })?;
                    Ok(CampaignPageBatch {
                        response_bytes: response.canonical_bytes().len(),
                        next_after: response.next_after(),
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
                })?;
            Ok(campaign_page_report(
                "frontier",
                &campaign,
                snapshot,
                page,
                aggregation,
            ))
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
            let aggregation = collect_campaign_pages(
                page,
                "finding",
                after,
                |cursor| cursor.to_hex(),
                |cursor| {
                    let request = QueryCampaignFindingsRequest::new(
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        cursor,
                        page.limit,
                    )
                    .map_err(|error| {
                        usage_error(format!("invalid campaign findings query: {error}"))
                    })?;
                    let response = client.query_campaign_findings(&request).map_err(|error| {
                        backend_error(format!("campaign findings query failed: {error}"))
                    })?;
                    let entries = response
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
                        .collect::<Result<Vec<_>, CliError>>()?;
                    Ok(CampaignPageBatch {
                        response_bytes: response.canonical_bytes().len(),
                        next_after: response.next_after(),
                        entries,
                    })
                },
            )?;
            Ok(campaign_page_report(
                "findings",
                &campaign,
                snapshot,
                page,
                aggregation,
            ))
        }
        _ => Err(backend_error(
            "non-page campaign command reached the page query path",
        )),
    }
}

fn collect_campaign_pages<C, E, F>(
    page: &CampaignPageArgs,
    kind: &str,
    initial_after: Option<C>,
    encode_cursor: E,
    mut fetch: F,
) -> Result<CampaignPageAggregation, CliError>
where
    C: Clone,
    E: Fn(&C) -> String,
    F: FnMut(Option<C>) -> Result<CampaignPageBatch<C>, CliError>,
{
    validate_campaign_page_aggregation(page, kind)?;

    let start_after = initial_after.as_ref().map(&encode_cursor);
    let mut seen = BTreeSet::new();
    if let Some(cursor) = &start_after {
        seen.insert(cursor.clone());
    }
    let mut cursor = initial_after;
    let mut pages_scanned = 0_u32;
    let mut response_bytes = 0_u64;
    let mut entries = Vec::new();

    for _ in 0..page.pages {
        let mut batch = fetch(cursor.clone())?;
        pages_scanned = pages_scanned
            .checked_add(1)
            .ok_or_else(|| backend_error("campaign page counter overflow"))?;
        let batch_bytes = u64::try_from(batch.response_bytes)
            .map_err(|_| backend_error("campaign page response byte count overflows"))?;
        response_bytes = response_bytes
            .checked_add(batch_bytes)
            .ok_or_else(|| backend_error("campaign page response byte count overflows"))?;
        if response_bytes > MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES {
            return Err(backend_error(format!(
                "campaign {kind} scan exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES}-byte aggregate response bound"
            )));
        }
        let next_entry_count = entries
            .len()
            .checked_add(batch.entries.len())
            .ok_or_else(|| backend_error("campaign page aggregate entry count overflows"))?;
        if next_entry_count > MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES {
            return Err(backend_error(format!(
                "campaign {kind} scan exceeds the {MAX_CAMPAIGN_PAGE_AGGREGATE_ENTRIES}-entry aggregate bound"
            )));
        }
        entries.append(&mut batch.entries);

        let next = batch.next_after;
        if let Some(encoded) = next.as_ref().map(&encode_cursor)
            && !seen.insert(encoded)
        {
            return Err(backend_error(format!(
                "campaign {kind} scan returned a repeated cursor"
            )));
        }
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }

    Ok(CampaignPageAggregation {
        start_after,
        pages_scanned,
        response_bytes,
        complete: cursor.is_none(),
        next_after: cursor.as_ref().map(encode_cursor),
        entries,
    })
}

fn campaign_page_report(
    operation: &'static str,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    page: &CampaignPageArgs,
    aggregation: CampaignPageAggregation,
) -> CampaignPageReport {
    CampaignPageReport {
        schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
        operation,
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        start_after: aggregation.start_after,
        page_limit: page.limit,
        page_budget: page.pages,
        pages_scanned: aggregation.pages_scanned,
        response_bytes: aggregation.response_bytes,
        complete: aggregation.complete,
        next_after: aggregation.next_after,
        entries: aggregation.entries,
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
                summary: CampaignBranchAcceptanceSummaryReport::new(
                    response.summary(),
                    response.summary_recorded(),
                ),
                replayed: response.replayed(),
            })
        }
        PreparedCampaignCommand::Attach(_) => Err(backend_error(
            "campaign runtime attachment reached semantic acceptance dispatch",
        )),
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
        | CampaignCommand::Validate(_)
        | CampaignCommand::Fixture(_)
        | CampaignCommand::Scenario(_)
        | CampaignCommand::Configuration(_)
        | CampaignCommand::Schedule(_)
        | CampaignCommand::Policy(_)
        | CampaignCommand::Lineage(_)
        | CampaignCommand::Create(_)
        | CampaignCommand::List(_)
        | CampaignCommand::Attach(_)
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

fn render_campaign_list(
    report: &CampaignListReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => {
            let mut lines = vec![
                format!(
                    "{:<12} {}",
                    "start_after",
                    report.start_after.as_deref().unwrap_or("-")
                ),
                format!("{:<12} {}", "page_limit", report.page_limit),
                format!("{:<12} {}", "page_budget", report.page_budget),
                format!("{:<12} {}", "pages", report.pages_scanned),
                format!("{:<12} {}", "bytes", report.response_bytes),
                format!("{:<12} {}", "complete", report.complete),
                format!(
                    "{:<12} {}",
                    "next_after",
                    report.next_after.as_deref().unwrap_or("-")
                ),
                format!("{:<12} {}", "entries", report.entries.len()),
                String::new(),
                String::from("campaign\tsnapshot\tlineage\tpolicy\tstate"),
            ];
            lines.extend(report.entries.iter().map(|entry| {
                format!(
                    "{}\t{}\t{}\t{}\t{}",
                    entry.campaign, entry.snapshot, entry.lineage, entry.policy, entry.state
                )
            }));
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut output = format!(
                "| Field | Value |\n| --- | --- |\n| start_after | {} |\n| page_limit | {} |\n| page_budget | {} |\n| pages | {} |\n| response_bytes | {} |\n| complete | {} |\n| next_after | {} |\n| entries | {} |\n\n| Campaign | Snapshot | Lineage | Policy | State |\n| --- | --- | --- | --- | --- |\n",
                report.start_after.as_deref().unwrap_or("-"),
                report.page_limit,
                report.page_budget,
                report.pages_scanned,
                report.response_bytes,
                report.complete,
                report.next_after.as_deref().unwrap_or("-"),
                report.entries.len(),
            );
            for entry in &report.entries {
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    entry.campaign, entry.snapshot, entry.lineage, entry.policy, entry.state
                ));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn render_campaign_runtime_attachment(
    report: &CampaignRuntimeAttachmentReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!(
                "campaign runtime-attachment JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!(
                "campaign runtime-attachment JSON encoding failed: {error}"
            ))
        }),
        OutputFormat::Table => Ok([
            format!("{:<18} {}", "campaign", report.campaign),
            format!("{:<18} {}", "operation", report.operation),
            format!("{:<18} {}", "request_digest", report.request_digest),
            format!("{:<18} {}", "disposition", report.disposition),
            format!(
                "{:<18} {}",
                "attached_runtimes", report.attached_runtime_count
            ),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| operation | {} |\n| request_digest | {} |\n| disposition | {} |\n| attached_runtimes | {} |",
            report.campaign,
            report.operation,
            report.request_digest,
            report.disposition,
            report.attached_runtime_count,
        )),
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
        OutputFormat::Table => Ok(campaign_head_rows(report)
            .into_iter()
            .map(|(field, value)| format!("{field:<10} {value}"))
            .collect::<Vec<_>>()
            .join("\n")),
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in campaign_head_rows(report) {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

fn campaign_head_rows(report: &CampaignHeadReport) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("campaign", report.campaign.clone()),
        ("snapshot", report.snapshot.clone()),
        ("lineage", report.lineage.clone()),
        ("policy", report.policy.clone()),
        ("state", report.state.to_owned()),
    ];
    if let Some(advanced) = report.advanced {
        rows.push(("advanced", advanced.to_string()));
    }
    if let Some(semantic) = &report.semantic {
        rows.extend([
            (
                "latent_or_open_continuations",
                semantic.latent_or_open_continuations.to_string(),
            ),
            (
                "ready_continuations",
                semantic.ready_continuations.to_string(),
            ),
            (
                "waiting_for_feedback_continuations",
                semantic.waiting_for_feedback_continuations.to_string(),
            ),
            (
                "open_continuations",
                semantic.open_continuations.to_string(),
            ),
            (
                "exhausted_continuations",
                semantic.exhausted_continuations.to_string(),
            ),
            (
                "closed_continuations",
                semantic.closed_continuations.to_string(),
            ),
            ("admitted_attempts", semantic.admitted_attempts.to_string()),
            (
                "stored_graph_nodes",
                semantic.stored_graph_nodes.to_string(),
            ),
            (
                "continuation_records_scanned",
                semantic.continuation_records_scanned.to_string(),
            ),
            (
                "continuation_bytes_scanned",
                semantic.continuation_bytes_scanned.to_string(),
            ),
        ]);
    }
    match report.operational.as_ref() {
        None => {}
        Some(CampaignOperationalStatusReport::Unavailable) => {
            rows.push(("operational", String::from("unavailable")));
        }
        Some(CampaignOperationalStatusReport::Observed {
            daemon_epoch,
            inventory_generation,
            preparing_worlds,
            running_worlds,
            checkpointing_worlds,
            publishing_worlds,
            canceling_worlds,
            paused_worlds,
            retained_checkpoint_roots,
            materialized_checkpoints,
        }) => rows.extend([
            ("operational", String::from("observed")),
            ("daemon_epoch", daemon_epoch.clone()),
            ("inventory_generation", inventory_generation.clone()),
            ("preparing_worlds", preparing_worlds.to_string()),
            ("running_worlds", running_worlds.to_string()),
            ("checkpointing_worlds", checkpointing_worlds.to_string()),
            ("publishing_worlds", publishing_worlds.to_string()),
            ("canceling_worlds", canceling_worlds.to_string()),
            ("paused_worlds", paused_worlds.to_string()),
            (
                "retained_checkpoint_roots",
                retained_checkpoint_roots.to_string(),
            ),
            (
                "materialized_checkpoints",
                materialized_checkpoints.to_string(),
            ),
        ]),
    }
    rows
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

fn campaign_acceptance_fields(report: &CampaignAcceptanceReport) -> Vec<(&'static str, String)> {
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
                ("operation", "create".to_owned()),
                ("campaign", campaign.clone()),
                ("snapshot", snapshot.clone()),
                ("lineage", lineage.clone()),
                ("active_policy", active_policy.clone()),
                ("replayed", replayed.to_string()),
            ];
            if let Some(start) = start {
                fields.extend([
                    ("start_command", start.command.clone()),
                    ("start_prior_snapshot", start.prior_snapshot.clone()),
                    ("start_snapshot", start.new_snapshot.clone()),
                    ("start_replayed", start.replayed.to_string()),
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
            ("operation", "derive".to_owned()),
            ("source_campaign", source_campaign.clone()),
            ("source_snapshot", source_snapshot.clone()),
            ("campaign", campaign.clone()),
            ("new_snapshot", new_snapshot.clone()),
            ("active_policy", active_policy.clone()),
            ("replayed", replayed.to_string()),
        ],
        CampaignAcceptanceReport::Branch {
            campaign,
            request,
            prior_snapshot,
            new_snapshot,
            summary,
            replayed,
            ..
        } => {
            let mut fields = vec![
                ("operation", "branch".to_owned()),
                ("campaign", campaign.clone()),
                ("request", request.clone()),
                ("prior_snapshot", prior_snapshot.clone()),
                ("new_snapshot", new_snapshot.clone()),
            ];
            fields.extend(summary.human_fields());
            fields.push(("replayed", replayed.to_string()));
            fields
        }
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
            "start_after",
            report.start_after.as_deref().unwrap_or("-")
        ),
        format!("{:<11} {}", "page_limit", report.page_limit),
        format!("{:<11} {}", "page_budget", report.page_budget),
        format!("{:<11} {}", "pages", report.pages_scanned),
        format!("{:<11} {}", "bytes", report.response_bytes),
        format!("{:<11} {}", "complete", report.complete),
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
        "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| snapshot | {} |\n| start_after | {} |\n| page_limit | {} |\n| page_budget | {} |\n| pages | {} |\n| response_bytes | {} |\n| complete | {} |\n| next_after | {} |\n| entries | {} |\n\n",
        report.campaign,
        report.snapshot,
        report.start_after.as_deref().unwrap_or("-"),
        report.page_limit,
        report.page_budget,
        report.pages_scanned,
        report.response_bytes,
        report.complete,
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
#[path = "campaign/tests.rs"]
mod tests;
