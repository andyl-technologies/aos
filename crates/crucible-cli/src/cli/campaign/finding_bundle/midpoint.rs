//! Private read-only exact midpoint and retained evidence from one bundle.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use crucible_campaign::{AttemptResourceLimits, ChoiceDomain, ChoiceValue};
use crucible_daemon::finding_production_replay::FindingProductionReplaySelectedSide;
use serde_json::{Value, json};

use super::*;

/// Opens a private QEMU restore and exposes one read-only local GDB relay.
///
/// # Errors
///
/// Returns an error for unauthenticated archive evidence, a missing exact pin,
/// mismatched packaged runtime, failed guarded restore, or relay failure.
pub(crate) fn run_finding_bundle_midpoint(
    cli: &Cli,
    args: &CampaignFindingBundleMidpointArgs,
) -> Result<(), CliError> {
    let listen: SocketAddr = args
        .gdb_listen
        .parse()
        .map_err(|error| usage_error(format!("invalid midpoint GDB address: {error}")))?;
    if !listen.ip().is_loopback() || args.node.is_empty() {
        return Err(usage_error(
            "midpoint requires a loopback GDB address and nonempty node",
        ));
    }

    let bundle = load_authenticated_bundle(&args.input)?;
    let finding =
        bundle.evidence.finding.id().map_err(|error| {
            backend_error(format!("verified finding identity is invalid: {error}"))
        })?;
    let objects: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "finding-bundle-midpoint",
        args.input.join("archive/objects"),
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(objects, args.maximum_checkpoint_bytes).map_err(|error| {
            backend_error(format!("finding checkpoint store is invalid: {error}"))
        })?,
    );
    let midpoint = crucible_daemon::prepare_archived_finding_debug_midpoint(
        &bundle.archive,
        bundle.archive_id,
        finding,
        &checkpoints,
    )
    .map_err(|error| backend_error(format!("finding midpoint is invalid: {error}")))?;
    let capture = crucible_daemon::load_archived_finding_production_capture(
        &bundle.archive,
        bundle.archive_id,
        finding,
        args.role.campaign_role(),
    )
    .map_err(|error| backend_error(format!("archived production replay is invalid: {error}")))?;
    let (qemu, plugin, _) = exact::resolve_immutable_qemu(cli)?;
    let private = tempfile::tempdir().map_err(CliError::Io)?;
    let guests = crucible_daemon::materialize_finding_replay_guest_assets(
        capture.deployment(),
        &qemu,
        &plugin,
        private.path(),
    )
    .map_err(|error| backend_error(format!("finding guest assets are invalid: {error}")))?;
    let lifecycle_objects = exact::load_lifecycle_objects(&capture)?;
    let mut lifecycle = exact::lifecycle_config(
        &qemu,
        &plugin,
        &guests,
        &private.path().join("midpoint"),
        capture.recipe(),
        lifecycle_objects,
    )?;
    let model =
        crucible::ReproductionArtifact::from_compact_binary(capture.model_reproduction())
            .map_err(|error| backend_error(format!("finding model replay is invalid: {error}")))?;
    let selected_index = match capture.selected_side() {
        FindingProductionReplaySelectedSide::Observed
        | FindingProductionReplaySelectedSide::Expected => 0,
        FindingProductionReplaySelectedSide::Reproduced => 1,
    };
    let selected = capture
        .sides()
        .get(selected_index)
        .ok_or_else(|| backend_error("finding capture has no selected replay side"))?;
    let fault_trace = selected
        .resolved_effect_trace()
        .map(|bytes| {
            crucible::ResolvedEffectTrace::from_canonical_bytes(
                bytes,
                model
                    .scenario_form()
                    .plan()
                    .fault_signals()
                    .resource_limits(),
            )
            .map_err(|error| backend_error(format!("finding effect trace is invalid: {error}")))
        })
        .transpose()?;
    if let Some(trace) = &fault_trace {
        lifecycle = lifecycle.with_fault_replay(trace.clone());
    }
    let deployment = crate::cli_verify_serve::load_guarded_campaign_deployment(
        cli.campaign_deployment.as_deref(),
    )?;
    let recipe = capture.recipe();
    if deployment.resources.maximum_execution_quanta() < recipe.lifecycle_quantum_budget {
        return Err(backend_error(
            "local host deployment cannot admit captured midpoint budget",
        ));
    }
    let resources = AttemptResourceLimits::new(
        deployment.resources.maximum_vcpus(),
        deployment.resources.maximum_resident_bytes(),
        deployment.resources.maximum_disk_bytes(),
        recipe.lifecycle_quantum_budget,
    )
    .map_err(|error| backend_error(format!("finding midpoint resources are invalid: {error}")))?;

    let report = midpoint_report(&bundle, &midpoint, &capture, selected, fault_trace.as_ref())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let session = midpoint
            .admit_guarded_read_only_session(checkpoints, lifecycle, deployment.host, resources)
            .await
            .map_err(|error| backend_error(format!("finding midpoint restore failed: {error}")))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(CliError::Io)?;
        let address = listener.local_addr().map_err(CliError::Io)?;
        let mut policy = DebugAuthorizationPolicy::deny_all();
        policy.grant_trusted_unauthenticated_role(DebugRole::new([
            DebugCapability::Observe,
            DebugCapability::Control,
        ]));
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(
            serve_shared_lifecycle_http2_with_debug_policy_until_shutdown(
                listener,
                session.shared_control_plane(),
                LifecycleServerMode::read_write(),
                policy,
                async move {
                    let _ = stopped.await;
                },
            ),
        );
        let client = RpcControlClient::new(RpcEndpoint::http2(format!("http://{address}")))
            .map_err(control_client_error)?;
        print_midpoint_report(&report, cli.output_format())?;
        let relay = crate::cli_triage_debug::run_debug_relay_with_client_async(
            &client,
            session.session(),
            crucible::NodeId {
                name: args.node.clone(),
            },
            listen,
        )
        .await;
        let _ = shutdown.send(());
        server
            .await
            .map_err(|error| backend_error(format!("finding midpoint relay task failed: {error}")))?
            .map_err(CliError::Io)?;
        relay
    })
}

fn midpoint_report(
    bundle: &AuthenticatedFindingBundle,
    midpoint: &crucible_daemon::ArchivedFindingDebugMidpoint,
    capture: &crucible_daemon::FindingProductionReplayCapture,
    selected: &crucible_daemon::FindingProductionReplayExecutionSide,
    fault_trace: Option<&crucible::ResolvedEffectTrace>,
) -> Result<Value, CliError> {
    let mut selections = Vec::new();
    for decision in bundle
        .evidence
        .report
        .finding
        .artifact
        .schedule()
        .decisions()
    {
        let crucible::Decision::Selection(decision) = decision else {
            continue;
        };
        let selection = decision.selection().map_err(|error| {
            backend_error(format!("finding choice selection is invalid: {error}"))
        })?;
        let resolved = bundle
            .archive
            .resolve_selection(selection.id().map_err(|error| {
                backend_error(format!("finding choice identity is invalid: {error}"))
            })?)
            .map_err(|error| backend_error(format!("finding choice is unavailable: {error}")))?;
        let label = match (resolved.domain(), selection.value()) {
            (ChoiceDomain::Discrete(domain), ChoiceValue::Discrete(id)) => domain
                .alternatives()
                .get(id)
                .map(|alternative| alternative.label().to_owned())
                .ok_or_else(|| backend_error("finding choice alternative is absent"))?,
            (_, value) => format!("{value:?}"),
        };
        selections.push(label);
    }
    let measurements = bundle
        .archive
        .load_measurement_set(bundle.evidence.observation.measurements())
        .map_err(|error| backend_error(format!("finding metrics are unavailable: {error}")))?;
    let evaluation = measurements.evaluation();
    let failure_detail = match &bundle.evidence.report.failure {
        crucible_model::FailureClusterReportFailure::Property(property) => {
            property.violation.detail.clone()
        }
        failure => format!("{failure:?}"),
    };
    let finding =
        bundle.evidence.finding.id().map_err(|error| {
            backend_error(format!("verified finding identity is invalid: {error}"))
        })?;
    Ok(json!({
        "schema": "crucible.cli.campaign-finding-bundle-midpoint.v1",
        "operation": "open-finding-bundle-midpoint",
        "archive_manifest": bundle.archive_id.to_string(),
        "finding": finding.to_string(),
        "checkpoint": midpoint.checkpoint().to_text(),
        "checkpoint_role": format!("{:?}", midpoint.role()),
        "configuration": midpoint.configuration().id().to_hex(),
        "restore_bytes": midpoint.restore_bytes(),
        "read_only": true,
        "branch_classification": "canonical",
        "capture_role": format!("{:?}", capture.selected_side()),
        "selection_sequence": selections.join(","),
        "selections": selections,
        "failure_detail": failure_detail,
        "observation_stop": format!("{:?}", bundle.evidence.observation.stop()),
        "causal_entries": bundle.evidence.report.causal_entries,
        "events": selected.event_log(),
        "signal_effects": fault_trace,
        "metrics": {
            "payload_schema": evaluation.payload_schema(),
            "payload_hex": lower_hex(evaluation.payload()),
            "evidence": evaluation.evidence().iter().map(ToString::to_string).collect::<Vec<_>>(),
        },
    }))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn print_midpoint_report(report: &Value, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(report).map_err(|error| {
                    backend_error(format!("finding midpoint report encoding failed: {error}"))
                })?
            );
        }
        OutputFormat::Table | OutputFormat::Markdown => {
            println!(
                "finding-midpoint checkpoint={} role={} configuration={} read-only=true branch=canonical selection={} failure={}",
                report["checkpoint"],
                report["checkpoint_role"],
                report["configuration"],
                report["selection_sequence"],
                report["failure_detail"],
            );
        }
    }
    std::io::stdout().flush().map_err(CliError::Io)
}
