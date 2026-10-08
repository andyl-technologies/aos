//! Private canonical choice execution from an authenticated executable finding bundle.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crucible_campaign::{
    Attempt, AttemptStart, BranchBudget, BranchPath, BranchPathSegment, BranchRequest,
    BranchRequestCause, BudgetGrant, CampaignArchivePolicy, CampaignCommandId,
    CampaignControlAction, CampaignHash, CampaignPrincipal, CampaignService, CampaignState,
    CandidateSource, ChoiceDomain, ChoiceValue, ControlRequest, DebugSessionId,
    ExplainCampaignAttemptRequest, Proposal, RepositoryCampaignService, Selection, SelectionOrigin,
    StopCondition,
};
use crucible_daemon::UnixPeerCampaignPolicy;
use serde::Serialize;

use super::*;

const BRANCH_NAME: &str = "imported-finding-branch";
const PRINCIPAL: &str = "private-branch";
const MAX_BRANCH_TIMEOUT_SECONDS: u64 = 3600;

#[derive(Serialize)]
struct FindingBundleBranchReport {
    schema: &'static str,
    operation: &'static str,
    branch_classification: &'static str,
    output: String,
    archive_manifest: String,
    finding: String,
    source_snapshot: String,
    branch_snapshot: String,
    request: String,
    attempt: String,
    observation: String,
    selected_value: String,
    stop: String,
    original_archive_unchanged: bool,
}

/// Executes one legal alternate value at the finding's first declared choice.
///
/// # Errors
///
/// Returns an error for unauthenticated or incomplete bundle evidence, an
/// illegal or unchanged choice, failed private QEMU execution, or missing
/// authenticated completion provenance.
pub(crate) fn run_finding_bundle_branch(
    cli: &Cli,
    args: &CampaignFindingBundleBranchArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    if args.timeout_seconds == 0 || args.timeout_seconds > MAX_BRANCH_TIMEOUT_SECONDS {
        return Err(usage_error(
            "branch timeout must be between 1 and 3600 seconds",
        ));
    }
    let supervision = ArchiveBundleAdmission::open(
        args.archive_policy.as_deref(),
        crucible_api::host_operational::HostOperationClass::Transfer,
        Some(
            args.host_transfer_timeout_ms
                .min(args.timeout_seconds * 1000),
        ),
        Some(&args.input),
        Some(&args.output),
    )?;
    let mut boundary = || supervision.boundary();
    let FindingSourceAuthentication {
        owner,
        deployment: guarded,
        qemu,
        plugin,
        workspace,
        decoding,
        ..
    } = FindingSourceAuthentication::open(cli, supervision.input_path(&args.input))?;
    let _decoding_scope = decoding.enter();
    let _archive_scope = supervision.input_scope()?;
    let bundle = load_authenticated_bundle_in_workspace(
        supervision.input_path(&args.input),
        &workspace,
        &supervision,
        &mut boundary,
    )?;
    let finding =
        bundle.evidence.finding.id().map_err(|error| {
            backend_error(format!("verified finding identity is invalid: {error}"))
        })?;
    let inspection = bundle
        .archive
        .inspect_campaign_archive_with_boundary(bundle.archive_id, &mut boundary)
        .map_err(|error| backend_error(format!("finding archive is invalid: {error}")))?;
    if inspection.manifest().policy() != CampaignArchivePolicy::Executable {
        return Err(usage_error("branch requires an executable finding archive"));
    }
    let source_snapshot = inspection.manifest().source_snapshot();
    let output_parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty());
    let output_parent = fs::canonicalize(output_parent.unwrap_or_else(|| Path::new(".")))?;
    let output_name = args
        .output
        .file_name()
        .ok_or_else(|| usage_error("branch output must name a new directory"))?;
    let output = output_parent.join(output_name);
    if output_parent.starts_with(fs::canonicalize(&args.input)?) {
        return Err(usage_error(
            "branch output must be outside the input bundle",
        ));
    }
    match fs::symlink_metadata(&output) {
        Ok(_) => return Err(usage_error("branch output path already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CliError::Io(error)),
    }
    supervision.publication_boundary()?;
    let private = tempfile::Builder::new()
        .prefix(".crucible-finding-branch-")
        .tempdir_in(&output_parent)?;
    supervision.prepare_output_directory(private.path())?;
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))?;
    let capture = crucible_daemon::load_archived_finding_production_capture(
        &bundle.archive,
        bundle.archive_id,
        finding,
        crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal,
    )
    .map_err(|error| backend_error(format!("archived QEMU capture is invalid: {error}")))?;
    if guarded.resources.maximum_execution_quanta() < capture.recipe().lifecycle_quantum_budget {
        return Err(backend_error(
            "local host cannot admit captured branch budget",
        ));
    }
    let guests = retain_materialized_guest_assets(
        crucible_daemon::materialize_finding_replay_guest_assets(
            capture.deployment(),
            &qemu,
            &plugin,
            &workspace,
        )
        .map_err(|error| backend_error(format!("finding guest assets are invalid: {error}")))?,
    )?;
    let lifecycle = exact::lifecycle_config(
        &qemu,
        &plugin,
        &guests,
        &workspace.join("branch"),
        capture.recipe(),
        exact::load_lifecycle_objects(&capture)?,
    )?;
    let model = crucible::ReproductionArtifact::from_compact_binary(capture.model_reproduction())
        .map_err(|error| backend_error(format!("finding model is invalid: {error}")))?;
    let owner = owner
        .with_imported_lifecycle(lifecycle)
        .and_then(|owner| owner.with_imported_guest_assets(Arc::clone(&guests)))
        .map_err(branch_error)?;
    let published = owner
        .import_finding_midpoint(
            &bundle.archive,
            bundle.archive_id,
            finding,
            model.scenario_form(),
        )
        .map_err(branch_error)?;
    let imported = published.repository();
    let source_name = published.campaign().as_str();
    let session = DebugSessionId::from_hash(CampaignHash::derive(
        "crucible.finding-bundle-private-branch-session.v1",
        output.as_os_str().as_encoded_bytes(),
    ));
    let imported_inspection = imported
        .inspect_campaign_archive_with_boundary(bundle.archive_id, &mut boundary)
        .map_err(branch_error)?;
    if imported_inspection != inspection {
        return Err(backend_error(
            "private archive copy differs from verified bundle",
        ));
    }
    let retained_finding = imported
        .inspect_archived_finding_with_boundary(bundle.archive_id, finding, &mut boundary)
        .map_err(branch_error)?;
    if retained_finding != bundle.evidence.finding || retained_finding.exact_pins().is_empty() {
        return Err(backend_error(
            "receiver finding or retained exact pins differ",
        ));
    }

    let reproduction = imported
        .load_reproduction_artifact(retained_finding.reproduction())
        .map_err(branch_error)?;
    let model = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .map_err(|error| backend_error(format!("finding reproduction is invalid: {error}")))?;
    let original = model
        .schedule()
        .decisions()
        .iter()
        .find_map(|decision| match decision {
            crucible::Decision::Selection(selection) => Some(selection.selection()),
            _ => None,
        })
        .ok_or_else(|| usage_error("finding has no retained declared choice"))?
        .map_err(|error| backend_error(format!("finding choice is invalid: {error}")))?;
    let opportunity = imported
        .load_choice_opportunity(original.opportunity())
        .map_err(branch_error)?;
    let domain = imported
        .load_choice_domain(original.domain())
        .map_err(branch_error)?;
    let alternate = match &domain {
        ChoiceDomain::Discrete(discrete) if !args.value.contains(':') => discrete
            .alternatives()
            .iter()
            .find_map(|(id, value)| {
                (value.label() == args.value).then_some(ChoiceValue::Discrete(*id))
            })
            .map(Ok)
            .unwrap_or_else(|| super::super::parse_campaign_choice_value(&args.value))?,
        _ => super::super::parse_campaign_choice_value(&args.value)?,
    };
    if !domain.contains(&alternate) || original.value() == &alternate {
        return Err(usage_error(
            "alternate value must be legal and differ from the finding choice",
        ));
    }

    let imported_head = imported.head(source_name).map_err(branch_error)?;
    let lineage = imported
        .load_lineage(imported_head.snapshot().lineage())
        .map_err(branch_error)?;
    let branch_point = opportunity.branch_point_id(lineage.genesis());
    let derived = imported
        .derive_campaign(source_name, source_snapshot, BRANCH_NAME, None)
        .map_err(branch_error)?;
    let mut branch_snapshot = derived.new_snapshot;
    if imported.state(BRANCH_NAME).map_err(branch_error)? == CampaignState::Sealed {
        branch_snapshot = imported
            .apply_control(
                BRANCH_NAME,
                &ControlRequest {
                    command: private_command(session, "unseal"),
                    expected_snapshot: branch_snapshot,
                    action: CampaignControlAction::Unseal,
                },
            )
            .map_err(branch_error)?
            .new_snapshot;
    }
    if imported.state(BRANCH_NAME).map_err(branch_error)? != CampaignState::Running {
        branch_snapshot = imported
            .apply_control(
                BRANCH_NAME,
                &ControlRequest {
                    command: private_command(session, "resume"),
                    expected_snapshot: branch_snapshot,
                    action: CampaignControlAction::Resume,
                },
            )
            .map_err(branch_error)?
            .new_snapshot;
    }
    let budget = imported
        .budget_projection(BRANCH_NAME)
        .map_err(branch_error)?;
    let needed_proposals = u64::from(budget.remaining_proposals() == 0);
    let needed_attempts = u64::from(budget.remaining_attempts() == 0);
    if needed_proposals != 0 || needed_attempts != 0 {
        imported
            .apply_control(
                BRANCH_NAME,
                &ControlRequest {
                    command: private_command(session, "grant-budget"),
                    expected_snapshot: branch_snapshot,
                    action: CampaignControlAction::GrantBudget(
                        BudgetGrant::new(needed_proposals, needed_attempts)
                            .map_err(branch_error)?,
                    ),
                },
            )
            .map_err(branch_error)?;
    }

    let request = BranchRequest::new(
        BranchRequest::identity(
            branch_point,
            lineage.genesis_content(),
            opportunity.id().map_err(branch_error)?,
            domain.id().map_err(branch_error)?,
        ),
        CandidateSource::finite(BTreeSet::from([alternate
            .clone_admitted()
            .map_err(branch_error)?]))
        .map_err(branch_error)?,
        BranchRequestCause::Debugger(session),
        BranchBudget::new(1, 1).map_err(branch_error)?,
        StopCondition::NextChoice,
    )
    .map_err(branch_error)?;
    let campaign = CampaignName::new(BRANCH_NAME).map_err(branch_error)?;
    let accepted = owner
        .authorize_branch_request(&campaign, session, request.clone())
        .map_err(branch_error)?;
    let (_, policy) = imported
        .head_with_policy(BRANCH_NAME)
        .map_err(branch_error)?;
    let proposal = Proposal::new_for_request(
        request.branch_point(),
        request.id().map_err(branch_error)?,
        request.domain(),
        alternate.clone_admitted().map_err(branch_error)?,
        policy.id().map_err(branch_error)?,
        None,
        1,
        accepted
            .snapshot
            .planning_view()
            .id()
            .map_err(branch_error)?,
        &request,
    )
    .map_err(branch_error)?;
    let proposed = imported
        .issue_proposal(BRANCH_NAME, accepted.new_snapshot, &proposal)
        .map_err(branch_error)?;
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        alternate.clone_admitted().map_err(branch_error)?,
        branch_point,
    )
    .map_err(branch_error)?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err(backend_error(
            "alternate choice did not produce a canonical edge",
        ));
    };
    let path =
        BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)]).map_err(branch_error)?;
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id().map_err(branch_error)?,
        },
        path.id().map_err(branch_error)?,
        request.stop().clone_admitted().map_err(branch_error)?,
    )
    .map_err(branch_error)?;
    let admitted = imported
        .admit_proposal(
            BRANCH_NAME,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .map_err(branch_error)?;
    if admitted.attempt != attempt.id().map_err(branch_error)? {
        return Err(backend_error(
            "private branch admission changed attempt identity",
        ));
    }
    if imported
        .head(source_name)
        .map_err(branch_error)?
        .snapshot_id()
        != source_snapshot
    {
        return Err(backend_error(
            "imported source head changed during branch admission",
        ));
    }

    let private_policy = private_policy()?;
    let principal = CampaignPrincipal::new(PRINCIPAL).map_err(branch_error)?;
    let attempt_id = attempt.id().map_err(branch_error)?;
    let service = RepositoryCampaignService::new(imported.as_ref(), private_policy);
    let mut execution_boundary = || boundary().map_err(std::io::Error::other);
    let observation = owner
        .run_admitted_branch(
            &campaign,
            attempt_id,
            crucible_daemon::ExecutionCancellation::default(),
            supervision.original_operation()?.supervisor(),
            &mut execution_boundary,
        )
        .map_err(branch_error)?;
    let branch_snapshot = imported
        .head(BRANCH_NAME)
        .map_err(branch_error)?
        .snapshot_id();
    let final_query =
        ExplainCampaignAttemptRequest::new(principal, campaign, branch_snapshot, attempt_id)
            .map_err(branch_error)?;
    let final_explanation = service
        .explain_campaign_attempt(&final_query)
        .map_err(branch_error)?;
    final_explanation
        .validate_for(&final_query)
        .map_err(branch_error)?;
    if final_explanation.observation() != Some(&observation)
        || final_explanation.selection() != Some(&selection)
        || final_explanation.proposal() != Some(&proposal)
    {
        return Err(backend_error(
            "final branch head lost executed choice provenance",
        ));
    }
    if imported
        .head(source_name)
        .map_err(branch_error)?
        .snapshot_id()
        != source_snapshot
        || imported
            .inspect_archived_finding_with_boundary(bundle.archive_id, finding, &mut boundary)
            .map_err(branch_error)?
            != retained_finding
        || bundle
            .archive
            .inspect_archived_finding_with_boundary(bundle.archive_id, finding, &mut boundary)
            .map_err(branch_error)?
            != retained_finding
        || bundle
            .archive
            .inspect_campaign_archive_with_boundary(bundle.archive_id, &mut boundary)
            .map_err(branch_error)?
            != inspection
    {
        return Err(backend_error(
            "original finding archive changed during branch execution",
        ));
    }
    let report = FindingBundleBranchReport {
        schema: "crucible.cli.campaign-finding-bundle-branch.v1",
        operation: "execute-finding-branch",
        branch_classification: "canonical",
        output: output.display().to_string(),
        archive_manifest: bundle.archive_id.to_string(),
        finding: finding.to_string(),
        source_snapshot: source_snapshot.to_string(),
        branch_snapshot: branch_snapshot.to_string(),
        request: request.id().map_err(branch_error)?.to_string(),
        attempt: attempt_id.to_string(),
        observation: observation.id().map_err(branch_error)?.to_string(),
        selected_value: super::super::object::campaign_choice_value_label(&alternate),
        stop: format!("{:?}", observation.stop()),
        original_archive_unchanged: true,
    };
    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| backend_error(format!("branch report encoding failed: {error}")))?;
    supervision.publication_boundary()?;
    write_private_file(&private.path().join("branch-report.json"), json.as_bytes())?;
    supervision.publication_boundary()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        private.path(),
        rustix::fs::CWD,
        &output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    File::open(&output_parent)?.sync_all()?;
    supervision.complete()?;
    render_branch_report(&report, format)
}

fn branch_error(error: impl std::fmt::Display) -> CliError {
    backend_error(format!("private finding branch failed: {error}"))
}

fn private_policy() -> Result<UnixPeerCampaignPolicy, CliError> {
    let policy = format!(
        "schema = \"crucible.campaign-local-policy\"\nversion = 1\n\n[[bindings]]\nuser_id = {}\ngroup_id = {}\nprincipal = \"{PRINCIPAL}\"\n\n[[grants]]\nprincipal = \"{PRINCIPAL}\"\noperation = \"explain-campaign-attempt\"\ncampaign = \"{BRANCH_NAME}\"\n",
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    UnixPeerCampaignPolicy::from_toml_bytes(policy.as_bytes()).map_err(branch_error)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn private_command(session: DebugSessionId, label: &str) -> CampaignCommandId {
    let mut bytes = session.to_string().into_bytes();
    bytes.extend_from_slice(label.as_bytes());
    CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.finding-bundle-private-command.v1",
        &bytes,
    ))
}

fn render_branch_report(
    report: &FindingBundleBranchReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("branch report encoding failed: {error}"))),
        OutputFormat::Table => Ok(format!(
            "branch-classification=canonical output={} source={} branch={} request={} attempt={} observation={} value={} stop={} original-archive-unchanged=true",
            report.output,
            report.source_snapshot,
            report.branch_snapshot,
            report.request,
            report.attempt,
            report.observation,
            report.selected_value,
            report.stop,
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| branch classification | canonical |\n| output | `{}` |\n| source snapshot | `{}` |\n| branch snapshot | `{}` |\n| request | `{}` |\n| attempt | `{}` |\n| observation | `{}` |\n| alternate value | `{}` |\n| stop | `{}` |\n| original archive unchanged | true |",
            report.output,
            report.source_snapshot,
            report.branch_snapshot,
            report.request,
            report.attempt,
            report.observation,
            report.selected_value,
            report.stop,
        )),
    }
}
