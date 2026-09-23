//! Private read-only exact midpoint and retained evidence from one bundle.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use crucible_campaign::{AttemptResourceLimits, ChoiceDomain, ChoiceValue};
use crucible_daemon::finding_production_replay::FindingProductionReplaySelectedSide;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
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
    if args.node.is_empty() {
        return Err(usage_error("midpoint requires a nonempty node"));
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
    let private = private_bundle_tempdir()?;
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
        let transport = private_midpoint_transport(private.path())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(CliError::Io)?;
        let address = listener.local_addr().map_err(CliError::Io)?;
        let mut policy = DebugAuthorizationPolicy::deny_all();
        policy
            .grant_certificate_role(
                transport.client_identity.certificate_sha256(),
                DebugRole::new([DebugCapability::Observe, DebugCapability::Control]),
            )
            .map_err(|error| backend_error(format!("midpoint client role is invalid: {error}")))?;
        let client = RpcControlClient::new_mtls(
            RpcEndpoint::http2(format!("https://{address}")),
            RpcMutualTlsConfig::from_pem(transport.ca_pem, transport.client_identity_pem),
        )
        .map_err(control_client_error)?;
        let session = midpoint
            .admit_guarded_read_only_session(checkpoints, lifecycle, deployment.host, resources)
            .await
            .map_err(|error| backend_error(format!("finding midpoint restore failed: {error}")))?;
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_shared_lifecycle_http2_mtls_with_mode_until_shutdown(
            listener,
            session.shared_control_plane(),
            // Relay setup uses control verbs; the admitted actor is still ReadOnlyDebug.
            LifecycleServerMode::read_write(),
            transport.acceptor,
            policy,
            async move {
                let _ = stopped.await;
            },
        ));
        let relay = async {
            print_midpoint_report(&report, cli.output_format())?;
            crate::cli_triage_debug::run_private_unix_debug_relay_with_client_async(
                &client,
                session.session(),
                crucible::NodeId {
                    name: args.node.clone(),
                },
                &private.path().join("gdb.sock"),
            )
            .await
        }
        .await;
        let destroyed = session
            .in_process_client()
            .destroy_session(
                DestroySessionRequest::new(session.session())
                    .with_expected_epoch(session.session().epoch),
            )
            .await
            .map_err(control_client_error);
        drop(client);
        let _ = shutdown.send(());
        let served =
            match tokio::time::timeout(std::time::Duration::from_secs(10), &mut server).await {
                Ok(result) => result
                    .map_err(|error| {
                        backend_error(format!("finding midpoint relay task failed: {error}"))
                    })?
                    .map_err(CliError::Io),
                Err(_) => {
                    server.abort();
                    let _ = server.await;
                    Err(backend_error("finding midpoint relay shutdown timed out"))
                }
            };
        destroyed?;
        served?;
        relay
    })
}

struct PrivateMidpointTransport {
    acceptor: tokio_rustls::TlsAcceptor,
    ca_pem: String,
    client_identity_pem: String,
    client_identity: crucible_api::DebugTransportIdentity,
}

fn private_midpoint_transport(directory: &Path) -> Result<PrivateMidpointTransport, CliError> {
    // Both rustls providers are present in the workspace dependency closure;
    // the first installed process provider is shared with the RPC client.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| backend_error(format!("midpoint CA is invalid: {error}")))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(
        ca_params,
        KeyPair::generate()
            .map_err(|error| backend_error(format!("midpoint CA key failed: {error}")))?,
    )
    .map_err(|error| backend_error(format!("midpoint CA signing failed: {error}")))?;

    let mut server_params = CertificateParams::new(vec![String::from("127.0.0.1")])
        .map_err(|error| backend_error(format!("midpoint server identity is invalid: {error}")))?;
    server_params.is_ca = IsCa::ExplicitNoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()
        .map_err(|error| backend_error(format!("midpoint server key failed: {error}")))?;
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .map_err(|error| backend_error(format!("midpoint server signing failed: {error}")))?;

    let mut client_params = CertificateParams::new(vec![String::from("finding-bundle-client")])
        .map_err(|error| backend_error(format!("midpoint client identity is invalid: {error}")))?;
    client_params.is_ca = IsCa::ExplicitNoCa;
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate()
        .map_err(|error| backend_error(format!("midpoint client key failed: {error}")))?;
    let client_cert = client_params
        .signed_by(&client_key, &ca)
        .map_err(|error| backend_error(format!("midpoint client signing failed: {error}")))?;

    // The private temporary directory is owner-only, and no TLS key survives
    // this command. The server API reads its identity from these PEM files.
    let ca_path = directory.join("midpoint-ca.pem");
    let server_cert_path = directory.join("midpoint-server.pem");
    let server_key_path = directory.join("midpoint-server-key.pem");
    std::fs::write(&ca_path, ca.pem()).map_err(CliError::Io)?;
    std::fs::write(&server_cert_path, server_cert.pem()).map_err(CliError::Io)?;
    std::fs::write(&server_key_path, server_key.serialize_pem()).map_err(CliError::Io)?;
    let acceptor = mutual_tls_acceptor_from_pem(&server_cert_path, &server_key_path, &ca_path)
        .map_err(|error| backend_error(format!("midpoint TLS acceptor failed: {error}")))?;

    Ok(PrivateMidpointTransport {
        acceptor,
        ca_pem: ca.pem(),
        client_identity_pem: format!("{}{}", client_cert.pem(), client_key.serialize_pem()),
        client_identity: crucible_api::DebugTransportIdentity::from_leaf_certificate(
            client_cert.der().as_ref(),
        ),
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
        "branch_classification": "no-branch",
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
                "finding-midpoint checkpoint={} role={} configuration={} read-only=true branch=no-branch selection={} failure={}",
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn handshake_is_accepted(
        acceptor: tokio_rustls::TlsAcceptor,
        ca_pem: String,
        client_identity_pem: String,
    ) -> bool {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind private TLS test listener");
        let address = listener.local_addr().expect("private TLS test address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS test peer");
            acceptor.accept(stream).await.is_ok()
        });
        let client = RpcControlClient::new_mtls(
            RpcEndpoint::http2(format!("https://{address}")),
            RpcMutualTlsConfig::from_pem(ca_pem, client_identity_pem),
        )
        .expect("construct TLS test client");

        let _ = tokio::time::timeout(Duration::from_secs(5), client.list_sessions()).await;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("TLS handshake completed")
            .expect("TLS test server completed")
    }

    #[tokio::test]
    async fn private_midpoint_transport_denies_an_unrelated_local_certificate() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_bundle_tempdir().expect("private TLS directory");
        assert_eq!(
            std::fs::metadata(directory.path())
                .expect("private TLS directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let transport = private_midpoint_transport(directory.path()).expect("private TLS setup");
        let unrelated = rcgen::generate_simple_self_signed(vec![String::from("unrelated-client")])
            .expect("unrelated identity");

        assert!(
            handshake_is_accepted(
                transport.acceptor.clone(),
                transport.ca_pem.clone(),
                transport.client_identity_pem,
            )
            .await
        );
        assert!(
            !handshake_is_accepted(
                transport.acceptor,
                transport.ca_pem,
                format!(
                    "{}{}",
                    unrelated.cert.pem(),
                    unrelated.signing_key.serialize_pem()
                ),
            )
            .await
        );
    }
}
