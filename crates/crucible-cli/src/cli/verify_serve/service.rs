//! Private daemon service lifecycle, campaign attachments, and operational shutdown.
//!
//! Verification commands keep their canonical evidence logic in the parent
//! module. This module owns host service setup and cleanup, including the
//! packaged campaign executor and its separate operational watchdog.

use super::packaged_executor::prepare_cli_packaged_executor;
use super::*;
use crate::cli_campaign_import::apply_campaign_import_manifests;

const DEFAULT_CAMPAIGN_MAINTENANCE_WRITE_BACK_TRANSFERS: u32 = 64;
const DEFAULT_CAMPAIGN_MAINTENANCE_S3_NODES: u16 = 8;
const DEFAULT_CAMPAIGN_MAINTENANCE_S3_UPLOADS: u16 = 128;

pub(crate) fn run_serve_invocation(cli: &Cli, args: &ServeArgs) -> Result<(), CliError> {
    if cli.daemon.is_some() {
        return Err(usage_error(
            "serve hosts the daemon and cannot itself use --daemon",
        ));
    }
    validate_serve_invocation(args)?;
    let process =
        crucible_daemon::campaign_process::CampaignProcessOwner::admit().map_err(|error| {
            match error {
                crucible_daemon::campaign_process::CampaignProcessAdmissionError::Policy(
                    message,
                ) => serve_error(message),
                crucible_daemon::campaign_process::CampaignProcessAdmissionError::Io(source) => {
                    CliError::Io(source)
                }
                crucible_daemon::campaign_process::CampaignProcessAdmissionError::Store(source) => {
                    CliError::SqliteStartup(source)
                }
            }
        })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(process.worker_threads())
        .max_blocking_threads(process.blocking_threads())
        .thread_stack_size(process.thread_stack_bytes())
        .enable_all()
        .build()
        .map_err(|error| serve_error(format!("serve runtime error: {error}")))?;
    // A client can stop the daemon as soon as its socket appears.
    let shutdown = {
        let _runtime = runtime.enter();
        serve_shutdown_signal()?
    };
    if args.production_qemu {
        runtime.block_on(run_serve_with_process_heap_until_shutdown(
            cli,
            args,
            shutdown,
            process.heap(),
        ))
    } else {
        let decoding = crate::cli_input_resources::original_budget()?;
        let admitted = crucible_api::admit_future(
            run_serve_with_process_heap_until_shutdown(cli, args, shutdown, process.heap()),
            decoding,
        )
        .map_err(|source| CliError::LifecycleAdmission(Box::new(source)))?;
        runtime.block_on(admitted)
    }
}

async fn run_serve_with_process_heap_until_shutdown<S>(
    cli: &Cli,
    args: &ServeArgs,
    shutdown: S,
    process_heap: &crucible_daemon::campaign_store_composition::SqliteProcessHeap,
) -> Result<(), CliError>
where
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let debug_authorization = debug_authorization_policy(args)?;
    let tls_acceptor = match (&args.tls_cert, &args.tls_key, &args.client_ca) {
        (Some(certificate), Some(private_key), Some(client_ca)) => Some(
            mutual_tls_acceptor_from_pem(certificate, private_key, client_ca)
                .map_err(|error| serve_error(format!("serve mutual-TLS error: {error}")))?,
        ),
        _ => None,
    };
    let mut production_qemu_build_id = None;
    let mut production_config = if args.production_qemu {
        let backend = require_selftest_qemu_backend(cli)?;
        let qemu_build_id = match &backend {
            ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id,
            #[cfg(any(test, feature = "test-double"))]
            ResolvedLocalBackend::Double => {
                return Err(serve_error(
                    "production QEMU resolved a test-double backend",
                ));
            }
        };
        production_qemu_build_id = Some(qemu_build_id.clone());
        let mut config = production_qemu_lifecycle_config(&backend)?;
        if let Some(interval) = packaged_executor::production_rendezvous_interval(
            args.qemu_rendezvous_ticks,
            args.campaign_packaged_executor.is_some(),
        ) {
            config = config.with_rendezvous_interval_ticks(interval);
        }
        if let Some(budget) = args.qemu_quantum_budget {
            config = config.with_quantum_budget(budget);
        }
        Some(config)
    } else {
        None
    };
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .map_err(|error| serve_error(format!("serve bind error: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| serve_error(format!("serve bind error: {error}")))?;
    if !cli.quiet {
        let mode = if args.read_only {
            "read-only"
        } else {
            "read-write"
        };
        let scheme = if tls_acceptor.is_some() {
            "https"
        } else {
            "http"
        };
        println!("crucible: serving API daemon at {scheme}://{address} mode={mode}");
    }
    let mode = if args.read_only {
        LifecycleServerMode::read_only()
    } else {
        LifecycleServerMode::read_write()
    };
    if args.production_qemu {
        let campaign_config = production_config
            .take()
            .ok_or_else(|| serve_error("production QEMU configuration disappeared"))?;
        let config = production_session_lifecycle_config(campaign_config, &debug_authorization);
        let packaged_campaign_config = config;
        let observation_qemu_build_id = production_qemu_build_id
            .take()
            .ok_or_else(|| serve_error("production QEMU identity disappeared"))?;
        let observation_factory = Arc::new(std::sync::OnceLock::<
            crucible_daemon::qemu_campaign_lifecycle::RemoteObservationResumeFactory,
        >::new());
        let resume_factory = Arc::clone(&observation_factory);
        let mut control_plane = LifecycleControlPlane::new_with_fallible_source_factory(
            "crucible-cli-qemu-daemon",
            Vec::new(),
            move |_scenario, _source, _seed| -> Result<
                crucible_api::ProductionVmLifecycleLoop,
                crucible_api::LifecycleApiError,
            > {
                Err(crucible_api::LifecycleApiError::LoopFactory {
                    message: String::from(
                        "production QEMU daemon creates nodes only through guarded campaign attempts",
                    ),
                })
            },
        )
        .with_resume_observation_loop_factory(move |request, configuration, context| {
            resume_factory
                .get()
                .ok_or_else(|| crucible_api::LifecycleApiError::ResumeObservationSource {
                    message: String::from("observation resume requires an attached campaign owner"),
                })?
                .resume_loop(request, configuration, context)
        })
        .with_resume_replay_closure_validator(validate_remote_resume_replay_closure)
    .with_decode_budget(crate::cli_input_resources::original_budget()?);
        if let Some(max_sessions) = args.max_sessions {
            control_plane = control_plane.with_max_sessions(max_sessions);
        }
        let control_plane = Arc::new(tokio::sync::Mutex::new(control_plane));
        let lifecycle =
            InProcessLifecycleClient::from_shared_control_plane(Arc::clone(&control_plane));
        let campaign_debug_lifecycle: Arc<dyn crucible_daemon::CampaignDebugLifecycleAdmission> =
            Arc::new(CliCampaignDebugLifecycleAdmission {
                lifecycle,
                runtime: tokio::runtime::Handle::current(),
            });
        let campaign_service = open_local_campaign_service_with_heap(
            args,
            Some(packaged_campaign_config),
            Some(campaign_debug_lifecycle),
            None,
            Some(process_heap),
        )?;
        if let Some((owner, verify_findings)) = campaign_service
            .as_ref()
            .and_then(|service| service.guarded_owner.clone())
        {
            let factory =
                crucible_daemon::qemu_campaign_lifecycle::RemoteObservationResumeFactory::new(
                    env!("CARGO_PKG_VERSION"),
                    observation_qemu_build_id,
                    owner,
                    verify_findings,
                )
                .map_err(|error| serve_error(format!("observation resume owner error: {error}")))?;
            observation_factory
                .set(factory)
                .map_err(|_| serve_error("observation resume owner was already installed"))?;
        }
        if let Some(control) = campaign_service
            .as_ref()
            .and_then(|service| service.host_operational_control.clone())
        {
            control_plane
                .lock()
                .await
                .set_host_operational_control(control);
        }
        announce_campaign_service(cli, campaign_service.as_ref());
        return run_bound_daemon_services(
            listener,
            control_plane,
            mode,
            tls_acceptor,
            debug_authorization,
            shutdown,
            campaign_service,
        )
        .await;
    }
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-cli-daemon",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_replay_closure_validator(validate_remote_resume_replay_closure);
    if let Some(max_sessions) = args.max_sessions {
        control_plane = control_plane.with_max_sessions(max_sessions);
    }
    let control_plane = Arc::new(tokio::sync::Mutex::new(control_plane));
    let campaign_service =
        open_local_campaign_service_with_heap(args, None, None, None, Some(process_heap))?;
    announce_campaign_service(cli, campaign_service.as_ref());
    run_bound_daemon_services(
        listener,
        control_plane,
        mode,
        tls_acceptor,
        debug_authorization,
        shutdown,
        campaign_service,
    )
    .await
}

fn announce_campaign_service(cli: &Cli, service: Option<&PreparedLocalCampaignService>) {
    if !cli.quiet
        && let Some(service) = service
    {
        println!(
            "crucible: serving local campaign service at {}",
            service.socket_path().display()
        );
    }
}

pub(crate) fn production_session_lifecycle_config(
    campaign_config: crucible_api::ProductionVmLifecycleConfig,
    debug_authorization: &DebugAuthorizationPolicy,
) -> crucible_api::ProductionVmLifecycleConfig {
    campaign_config.with_authorized_debug_gdbstubs_for_all_nodes("127.0.0.1:0", debug_authorization)
}

pub(crate) struct PreparedLocalCampaignService {
    service: crucible_daemon::CampaignLocalService,
    socket_path: PathBuf,
    host_operational_control: Option<crucible_api::host_operational::SharedHostOperationalControl>,
    guarded_owner: Option<(
        crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignOwner,
        bool,
    )>,
}

struct CliCampaignDebugLifecycleAdmission<F> {
    lifecycle: InProcessLifecycleClient<crucible_api::ProductionVmLifecycleLoop, F>,
    runtime: tokio::runtime::Handle,
}

impl<F> crucible_daemon::CampaignDebugLifecycleAdmission for CliCampaignDebugLifecycleAdmission<F>
where
    F: Fn(
            &crucible::ScenarioDef,
            Option<&crucible::ScenarioDefForm>,
            crucible::Seed,
        )
            -> Result<crucible_api::ProductionVmLifecycleLoop, crucible_api::LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    fn admit(
        &self,
        request: crucible_daemon::PreparedCampaignDebugLifecycle,
    ) -> Result<crucible_api::ResumeSessionResponse, crucible_api::LifecycleApiError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            // Startup recovery runs while the daemon's multithreaded runtime is
            // active; campaign RPC workers call this outside that runtime.
            tokio::task::block_in_place(|| self.runtime.block_on(request.admit(&self.lifecycle)))
        } else {
            self.runtime.block_on(request.admit(&self.lifecycle))
        }
    }
}

impl PreparedLocalCampaignService {
    fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn open_local_campaign_service_with_heap(
    args: &ServeArgs,
    production_qemu: Option<crucible_api::ProductionVmLifecycleConfig>,
    campaign_debug_lifecycle: Option<Arc<dyn crucible_daemon::CampaignDebugLifecycleAdmission>>,
    private_target_attempt: Option<crucible_campaign::AttemptId>,
    process_heap: Option<&crucible_daemon::campaign_store_composition::SqliteProcessHeap>,
) -> Result<Option<PreparedLocalCampaignService>, CliError> {
    validate_campaign_runtime_attachments(args)?;
    let (Some(socket), Some(state), Some(policy)) = (
        args.campaign_socket.as_ref(),
        args.campaign_state.as_ref(),
        args.campaign_policy.as_ref(),
    ) else {
        return Ok(None);
    };
    let endpoint = crucible_daemon::CampaignLoopbackEndpointConfig::new(
        socket,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        args.campaign_socket_mode,
    )
    .map_err(|error| serve_error(format!("campaign endpoint configuration error: {error}")))?;
    let mut config = crucible_daemon::CampaignLocalServiceConfig::new(
        endpoint,
        state,
        policy,
        if args.read_only {
            crucible_daemon::CampaignLocalServiceMode::ReadOnly
        } else {
            crucible_daemon::CampaignLocalServiceMode::ReadWrite
        },
        crucible_daemon::CampaignLoopbackServerConfig::default(),
    )
    .map_err(|error| serve_error(format!("campaign service configuration error: {error}")))?;
    if let Some(path) = args.campaign_component_authority.as_ref() {
        config = config
            .with_component_authority_path(path)
            .map_err(|error| {
                serve_error(format!("campaign service configuration error: {error}"))
            })?;
    }
    let mut prepared = match args.campaign_store.as_deref() {
        Some(path) => config.prepare_with_store(
            crate::cli_campaign_store::load_campaign_repository_store_with_heap(
                path,
                process_heap,
            )?,
        ),
        None => config.prepare(process_heap.ok_or_else(|| {
            serve_error("builtin campaign storage requires the original process heap")
        })?),
    }
    .map_err(|error| serve_error(format!("campaign service bootstrap error: {error}")))?;
    if let Some(maintenance) = campaign_store_maintenance_config(args)? {
        prepared = prepared
            .with_store_maintenance(maintenance)
            .map_err(|error| serve_error(format!("campaign maintenance error: {error}")))?;
    }
    let runtime_control_planner = if args.campaign_component_authority.is_some() && !args.read_only
    {
        Some(
            crucible_daemon::CanonicalPlannerProcessConfig::for_current_executable(
                Duration::from_secs(30),
            )
            .map_err(|error| {
                serve_error(format!("campaign planner configuration error: {error}"))
            })?,
        )
    } else {
        None
    };
    apply_campaign_import_manifests(&prepared, &args.campaign_import_manifest)?;
    let selected_campaigns = if args.campaign_runtime_all {
        prepared
            .discover_packaged_campaigns()
            .map_err(|error| serve_error(format!("campaign runtime discovery error: {error}")))?
    } else {
        args.campaign_runtime
            .iter()
            .map(|campaign| {
                crucible_campaign::CampaignName::new(campaign)
                    .map_err(|error| serve_error(format!("campaign runtime name error: {error}")))
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
    };
    if private_target_attempt.is_some() && selected_campaigns.len() != 1 {
        return Err(serve_error(
            "private finding target requires exactly one campaign runtime",
        ));
    }
    let packaged_executor = match args.campaign_packaged_executor.as_deref() {
        Some(deployment) => {
            let executor_socket = args.campaign_executor_socket.first().ok_or_else(|| {
                usage_error("--campaign-packaged-executor requires one executor socket")
            })?;
            Some(prepare_cli_packaged_executor(
                &prepared,
                args,
                selected_campaigns.clone(),
                executor_socket,
                deployment,
                production_qemu.ok_or_else(|| {
                    serve_error("--campaign-packaged-executor requires --production-qemu")
                })?,
                process_heap.ok_or_else(|| {
                    serve_error("packaged catalog requires the original process heap")
                })?,
            )?)
        }
        None => None,
    };
    let runtime_targets = if packaged_executor.is_some() {
        let executor_socket = args.campaign_executor_socket.first().ok_or_else(|| {
            usage_error("--campaign-packaged-executor requires one executor socket")
        })?;
        selected_campaigns
            .iter()
            .cloned()
            .map(|campaign| (campaign, executor_socket.as_path()))
            .collect::<Vec<_>>()
    } else {
        args.campaign_runtime
            .iter()
            .zip(&args.campaign_executor_socket)
            .map(|(campaign, executor_socket)| {
                crucible_campaign::CampaignName::new(campaign)
                    .map(|campaign| (campaign, executor_socket.as_path()))
                    .map_err(|error| serve_error(format!("campaign runtime name error: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut runtimes = Vec::with_capacity(runtime_targets.len());
    for (index, (campaign, executor_socket)) in runtime_targets.into_iter().enumerate() {
        let endpoint = campaign_executor_endpoint(executor_socket)?;
        let planner = runtime_control_planner.clone().ok_or_else(|| {
            serve_error("campaign runtime attachment requires the planner control profile")
        })?;
        let runtime_config = match packaged_executor.as_ref() {
            Some(packaged) => packaged.runtime_config(campaign, planner)?,
            None => crucible_daemon::CanonicalCampaignRuntimeConfig::canonical_defaults(
                campaign, planner,
            )
            .map_err(|error| {
                serve_error(format!("campaign runtime configuration error: {error}"))
            })?,
        };
        let runtime_config = match private_target_attempt {
            Some(target) => runtime_config.for_private_finding_target(target),
            None => runtime_config,
        };
        runtimes.push(
            prepared
                .prepare_runtime_endpoint(endpoint, &runtime_config)
                .map_err(|error| {
                    serve_error(format!(
                        "campaign runtime {index} attachment error: {error}"
                    ))
                })?,
        );
    }
    let mut prepared = match runtime_control_planner {
        Some(planner) => prepared
            .with_runtime_control(planner)
            .map_err(|error| serve_error(format!("campaign runtime control error: {error}")))?,
        None => prepared,
    };
    if let Some(lifecycle) = campaign_debug_lifecycle {
        prepared = prepared.with_campaign_debug_lifecycle(lifecycle);
    }
    let guarded_owner = packaged_executor
        .as_ref()
        .map(|packaged| {
            prepared
                .guarded_campaign_owner(&packaged.executor)
                .map(|owner| (owner, packaged.verify_determinism_findings))
                .map_err(|error| serve_error(format!("guarded resume owner error: {error}")))
        })
        .transpose()?;
    let host_operational_control = if let Some(packaged) = packaged_executor.as_ref() {
        let registry = packaged.executor.host_operational_registry();
        for principal in &args.host_operator_certificate {
            registry.grant_principal(principal).map_err(|error| {
                serve_error(format!("host operational authorization error: {error}"))
            })?;
        }
        Some(Arc::new(registry) as crucible_api::host_operational::SharedHostOperationalControl)
    } else {
        None
    };
    let service = if let Some(packaged) = packaged_executor {
        prepared.bind_with_runtimes_and_executor(runtimes, packaged.executor)
    } else if runtimes.is_empty() {
        prepared.bind()
    } else {
        prepared.bind_with_runtimes(runtimes)
    }
    .map_err(|error| serve_error(format!("campaign service bind error: {error}")))?;
    Ok(Some(PreparedLocalCampaignService {
        service,
        socket_path: socket.clone(),
        host_operational_control,
        guarded_owner,
    }))
}

pub(crate) fn campaign_executor_endpoint(
    path: &Path,
) -> Result<crucible_daemon::ExecutorLoopbackEndpointConfig, CliError> {
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    let endpoint = crucible_daemon::ExecutorLoopbackEndpointConfig::new(
        path.to_owned(),
        user_id,
        group_id,
        0o600,
    )
    .map_err(|error| serve_error(format!("campaign executor endpoint error: {error}")))?;
    Ok(endpoint)
}

struct RunningLocalCampaignService {
    shutdown: crucible_daemon::CampaignLoopbackServerShutdown,
    thread: std::thread::JoinHandle<
        Result<
            crucible_daemon::CampaignLocalServiceReport,
            Box<crucible_daemon::CampaignLocalServiceError>,
        >,
    >,
    done: tokio::sync::oneshot::Receiver<Option<crucible_daemon::CampaignLocalServiceReport>>,
}

fn start_local_campaign_service(
    prepared: PreparedLocalCampaignService,
) -> Result<RunningLocalCampaignService, CliError> {
    let shutdown = prepared.service.shutdown_handle();
    let (done_sender, done) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name(String::from("crucible-campaign-service"))
        .spawn(move || {
            let result = prepared.service.serve().map_err(Box::new);
            let report = result.as_ref().ok().copied();
            let _ = done_sender.send(report);
            result
        })
        .map_err(|error| serve_error(format!("campaign service thread error: {error}")))?;
    Ok(RunningLocalCampaignService {
        shutdown,
        thread,
        done,
    })
}

async fn run_bound_daemon_services<L, F, S>(
    listener: tokio::net::TcpListener,
    control_plane: Arc<tokio::sync::Mutex<LifecycleControlPlane<L, F>>>,
    mode: LifecycleServerMode,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    debug_authorization: DebugAuthorizationPolicy,
    shutdown: S,
    campaign: Option<PreparedLocalCampaignService>,
) -> Result<(), CliError>
where
    L: crucible::QuantumLoop + Send + 'static,
    F: Fn(
            &crucible::ScenarioDef,
            Option<&crucible::ScenarioDefForm>,
            crucible::Seed,
        ) -> Result<L, crucible_api::LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let Some(campaign) = campaign else {
        return run_bound_lifecycle_server(
            listener,
            control_plane,
            mode,
            tls_acceptor,
            debug_authorization,
            shutdown,
        )
        .await;
    };
    let RunningLocalCampaignService {
        shutdown: campaign_shutdown,
        thread: campaign_thread,
        mut done,
    } = start_local_campaign_service(campaign)?;
    let wait_shutdown = campaign_shutdown.clone();
    let combined_shutdown = async move {
        match crate::host_boundary::first_completed(shutdown, &mut done).await {
            crate::host_boundary::HostRaceOutcome::First(result) => {
                wait_shutdown.shutdown();
                result
            }
            crate::host_boundary::HostRaceOutcome::Second(report) => {
                Err(campaign_service_stopped_error(report.ok().flatten()))
            }
        }
    };
    let lifecycle_result = run_bound_lifecycle_server(
        listener,
        control_plane,
        mode,
        tls_acceptor,
        debug_authorization,
        combined_shutdown,
    )
    .await;
    campaign_shutdown.shutdown();
    let campaign_result = match tokio::task::spawn_blocking(move || campaign_thread.join()).await {
        Err(error) => Err(serve_error(format!("campaign service join error: {error}"))),
        Ok(Err(_)) => Err(serve_error("campaign service thread panicked")),
        Ok(Ok(Err(error))) => Err(campaign_service_join_error(error.as_ref())),
        Ok(Ok(Ok(report))) => {
            emit_campaign_promotion_report(report);
            Ok(())
        }
    };
    combine_lifecycle_and_campaign_results(lifecycle_result, campaign_result)
}

fn emit_campaign_promotion_report(report: crucible_daemon::CampaignLocalServiceReport) {
    let Some(executor) = report.executor() else {
        return;
    };
    let pool = executor.pool();
    let phases = pool.promotion_failure_phases();
    let (activity_phase, activity_attempt) = match pool.last_promotion_activity() {
        Some((key, phase)) => (format!("{phase:?}"), key.attempt().to_string()),
        None => (String::from("none"), String::from("none")),
    };
    let failure = pool.last_promotion_failure();
    let (phase, attempt, detail, truncated) = match failure {
        Some(failure) => (
            format!("{:?}", failure.phase()),
            failure.key().attempt().to_string(),
            failure.detail().to_owned(),
            failure.detail_truncated(),
        ),
        None => (
            String::from("none"),
            String::from("none"),
            String::from("none"),
            false,
        ),
    };
    eprintln!(
        "CRUCIBLE-CHECKPOINT-PROMOTION-REPORT-V1 active={} queued={} retries={} reconciled={} discarded={} failures={} preparation_terminal={} publication_terminal_reverted={} last_activity_phase={} last_activity_attempt={} last_failure_phase={} last_failure_attempt={} last_failure_detail={:?} last_failure_detail_truncated={}",
        pool.promotions_active(),
        pool.promotions_queued(),
        pool.promotion_retries(),
        pool.promotions_reconciled(),
        pool.promotions_discarded(),
        pool.promotion_failures(),
        phases.preparation_terminal(),
        phases.publication_terminal_reverted(),
        activity_phase,
        activity_attempt,
        phase,
        attempt,
        detail,
        truncated,
    );
}

pub(crate) fn campaign_service_stopped_error(
    report: Option<crucible_daemon::CampaignLocalServiceReport>,
) -> CliError {
    let promotion_failures = report
        .and_then(crucible_daemon::CampaignLocalServiceReport::executor)
        .map(|executor| {
            let pool = executor.pool();
            let phases = pool.promotion_failure_phases();
            (
                pool.promotion_failures(),
                phases.preparation_terminal(),
                phases.publication_terminal_reverted(),
            )
        });
    campaign_service_stopped_error_with_promotion_failures(promotion_failures)
}

pub(crate) fn campaign_service_stopped_error_with_promotion_failures(
    promotion_failures: Option<(u64, u64, u64)>,
) -> CliError {
    let Some((total, preparation_terminal, publication_terminal_reverted)) = promotion_failures
    else {
        return serve_error("campaign service stopped unexpectedly");
    };

    serve_error(format!(
        "campaign service stopped unexpectedly; checkpoint promotions failed={} preparation_terminal={} publication_terminal_reverted={}",
        total, preparation_terminal, publication_terminal_reverted,
    ))
}

/// Converts a joined campaign service failure while retaining its typed cause chain.
pub(crate) fn campaign_service_join_error(error: &(dyn std::error::Error + 'static)) -> CliError {
    serve_error(format!(
        "campaign service error: {}",
        campaign_service_error_chain(error)
    ))
}

/// Renders a bounded campaign service error chain across the string-only CLI boundary.
fn campaign_service_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = String::new();
    let mut current = Some(error);
    for _ in 0..12 {
        let Some(error) = current else { break };
        if !message.is_empty() {
            message.push_str("; caused by: ");
        }
        message.extend(error.to_string().chars().take(1024));
        current = error.source();
    }
    if current.is_some() {
        message.push_str("; further causes omitted");
    }
    message
}

/// Combines the joined lifecycle and campaign service results without hiding either failure.
///
/// # Errors
///
/// Returns the sole service failure, or one serve error containing both causes
/// when both services failed while shutting each other down.
pub(crate) fn combine_lifecycle_and_campaign_results(
    lifecycle_result: Result<(), CliError>,
    campaign_result: Result<(), CliError>,
) -> Result<(), CliError> {
    match (lifecycle_result, campaign_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(lifecycle_error), Err(campaign_error)) => {
            Err(serve_error(format!("{lifecycle_error}; {campaign_error}")))
        }
    }
}

async fn run_bound_lifecycle_server<L, F, S>(
    listener: tokio::net::TcpListener,
    control_plane: Arc<tokio::sync::Mutex<LifecycleControlPlane<L, F>>>,
    mode: LifecycleServerMode,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    debug_authorization: DebugAuthorizationPolicy,
    shutdown: S,
) -> Result<(), CliError>
where
    L: crucible::QuantumLoop + Send + 'static,
    F: Fn(
            &crucible::ScenarioDef,
            Option<&crucible::ScenarioDefForm>,
            crucible::Seed,
        ) -> Result<L, crucible_api::LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server: Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>> =
        if let Some(tls_acceptor) = tls_acceptor {
            Box::pin(serve_shared_lifecycle_http2_mtls_with_mode_until_shutdown(
                listener,
                control_plane,
                mode,
                tls_acceptor,
                debug_authorization,
                async move {
                    let _ = shutdown_receiver.await;
                },
            ))
        } else {
            Box::pin(
                serve_shared_lifecycle_http2_with_debug_policy_until_shutdown(
                    listener,
                    control_plane,
                    mode,
                    debug_authorization,
                    async move {
                        let _ = shutdown_receiver.await;
                    },
                ),
            )
        };
    tokio::pin!(server);
    tokio::pin!(shutdown);
    match crate::host_boundary::first_completed(server.as_mut(), shutdown.as_mut()).await {
        crate::host_boundary::HostRaceOutcome::First(result) => {
            result.map_err(|error| serve_error(format!("serve backend error: {error}")))?;
            Ok(())
        }
        crate::host_boundary::HostRaceOutcome::Second(signal) => {
            signal?;
            let _ = shutdown_sender.send(());
            if let Ok(result) = tokio::time::timeout(SERVE_SHUTDOWN_DRAIN_TIMEOUT, server).await {
                result.map_err(|error| serve_error(format!("serve backend error: {error}")))?;
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(crate) fn serve_shutdown_signal() -> Result<impl Future<Output = Result<(), CliError>>, CliError>
{
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| serve_error(format!("serve shutdown signal error: {error}")))?;
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| serve_error(format!("serve shutdown signal error: {error}")))?;
    Ok(async move {
        let _ = crate::host_boundary::first_completed(interrupt.recv(), terminate.recv()).await;
        Ok(())
    })
}

#[cfg(not(unix))]
pub(crate) fn serve_shutdown_signal() -> Result<impl Future<Output = Result<(), CliError>>, CliError>
{
    Ok(async {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| serve_error(format!("serve shutdown signal error: {error}")))
    })
}

fn validate_listen_endpoint(listen: &str) -> Result<(), CliError> {
    let invalid = || serve_error("serve bind error: invalid listen host or port");
    let (host, port) = listen.rsplit_once(':').ok_or_else(invalid)?;
    port.parse::<u16>().map_err(|_| invalid())?;
    if host.is_empty() {
        return Err(invalid());
    }
    // Tokio retains its original host interpretation, including numeric IPv6
    // and scoped forms. This check performs no resolution, DNS or IO.
    Ok(())
}

pub(crate) fn validate_serve_invocation(args: &ServeArgs) -> Result<(), CliError> {
    if args.max_sessions == Some(0) {
        return Err(usage_error("--max-sessions must be greater than zero"));
    }
    if args.qemu_rendezvous_ticks == Some(0) {
        return Err(usage_error(
            "--qemu-rendezvous-ticks must be greater than zero",
        ));
    }
    if args.qemu_rendezvous_ticks.is_some() && !args.production_qemu {
        return Err(usage_error(
            "--qemu-rendezvous-ticks requires --production-qemu",
        ));
    }
    if args.qemu_quantum_budget == Some(0) {
        return Err(usage_error(
            "--qemu-quantum-budget must be greater than zero",
        ));
    }
    if args.qemu_quantum_budget.is_some() && !args.production_qemu {
        return Err(usage_error(
            "--qemu-quantum-budget requires --production-qemu",
        ));
    }
    let campaign_fields = [
        args.campaign_socket.is_some(),
        args.campaign_state.is_some(),
        args.campaign_policy.is_some(),
    ];
    let campaign_field_count = campaign_fields
        .into_iter()
        .filter(|present| *present)
        .count();
    if campaign_field_count != 0 && campaign_field_count != campaign_fields.len() {
        return Err(usage_error(
            "--campaign-socket, --campaign-state, and --campaign-policy must be provided together",
        ));
    }
    let _ = campaign_store_maintenance_config(args)?;
    validate_campaign_runtime_attachments(args)?;
    if args.campaign_packaged_executor.is_some() && !args.production_qemu {
        return Err(usage_error(
            "--campaign-packaged-executor requires --production-qemu",
        ));
    }
    if args.campaign_socket.is_some()
        && (args.campaign_socket_mode == 0
            || args.campaign_socket_mode & !0o777 != 0
            || args.campaign_socket_mode & 0o222 == 0)
    {
        return Err(usage_error(
            "--campaign-socket-mode must grant write access and contain only permission bits",
        ));
    }
    let tls_file_count = [
        args.tls_cert.is_some(),
        args.tls_key.is_some(),
        args.client_ca.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if tls_file_count != 0 && tls_file_count != 3 {
        return Err(usage_error(
            "--tls-cert, --tls-key, and --client-ca must be supplied together",
        ));
    }
    if tls_file_count == 3 && args.trusted_unauthenticated_bind {
        return Err(usage_error(
            "--trusted-unauthenticated-bind cannot be combined with mutual TLS",
        ));
    }
    if tls_file_count == 0 && !args.trusted_unauthenticated_bind {
        return Err(usage_error(
            "serve requires mutual TLS or explicit --trusted-unauthenticated-bind",
        ));
    }
    let _ = debug_authorization_policy(args)?;
    if !args.host_operator_certificate.is_empty() {
        if tls_file_count != 3 || args.campaign_packaged_executor.is_none() {
            return Err(usage_error(
                "--host-operator-certificate requires mutual TLS and a packaged campaign executor",
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for fingerprint in &args.host_operator_certificate {
            if fingerprint.len() != 64
                || !fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !unique.insert(fingerprint)
            {
                return Err(usage_error(
                    "host operator certificates must be unique lowercase 64-digit fingerprints",
                ));
            }
        }
    }
    // Preserve the original usage-error priority before checking bind syntax.
    validate_listen_endpoint(&args.listen)
}

fn campaign_store_maintenance_config(
    args: &ServeArgs,
) -> Result<Option<crucible_daemon::CampaignStoreMaintenanceConfig>, CliError> {
    let bounds_present = args.campaign_maintenance_write_back_transfers.is_some()
        || args.campaign_maintenance_s3_nodes.is_some()
        || args.campaign_maintenance_s3_uploads.is_some();
    let Some(interval_ms) = args.campaign_maintenance_interval_ms else {
        if bounds_present {
            return Err(usage_error(
                "campaign maintenance bounds require --campaign-maintenance-interval-ms",
            ));
        }
        return Ok(None);
    };
    if args.campaign_store.is_none() {
        return Err(usage_error(
            "--campaign-maintenance-interval-ms requires --campaign-store",
        ));
    }
    if args.read_only {
        return Err(usage_error(
            "--campaign-maintenance-interval-ms conflicts with --read-only",
        ));
    }
    crucible_daemon::CampaignStoreMaintenanceConfig::new(
        Duration::from_millis(interval_ms),
        args.campaign_maintenance_write_back_transfers
            .unwrap_or(DEFAULT_CAMPAIGN_MAINTENANCE_WRITE_BACK_TRANSFERS),
        args.campaign_maintenance_s3_nodes
            .unwrap_or(DEFAULT_CAMPAIGN_MAINTENANCE_S3_NODES),
        args.campaign_maintenance_s3_uploads
            .unwrap_or(DEFAULT_CAMPAIGN_MAINTENANCE_S3_UPLOADS),
    )
    .map(Some)
    .map_err(|error| usage_error(error.to_string()))
}

fn validate_campaign_runtime_attachments(args: &ServeArgs) -> Result<(), CliError> {
    let packaged = args.campaign_packaged_executor.is_some();
    if packaged {
        if args.campaign_executor_socket.is_empty()
            || args
                .campaign_executor_socket
                .windows(2)
                .any(|pair| pair[0] != pair[1])
        {
            return Err(usage_error(
                "--campaign-packaged-executor requires one shared executor socket value",
            ));
        }
    } else if args.campaign_runtime.len() != args.campaign_executor_socket.len() {
        return Err(usage_error(
            "--campaign-runtime and --campaign-executor-socket must be repeated the same number of times",
        ));
    }
    if args.campaign_runtime.len() > crucible_daemon::MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES {
        return Err(usage_error(format!(
            "--campaign-runtime exceeds the {}-runtime daemon ceiling",
            crucible_daemon::MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES
        )));
    }
    if args.campaign_runtime.is_empty() && !args.campaign_runtime_all {
        if packaged {
            return Err(usage_error(
                "--campaign-packaged-executor requires --campaign-runtime or --campaign-runtime-all",
            ));
        }
        if !args.campaign_executor_socket.is_empty() {
            return Err(usage_error(
                "--campaign-executor-socket requires a campaign runtime",
            ));
        }
        return Ok(());
    }
    if args.campaign_socket.is_none() || args.campaign_component_authority.is_none() {
        return Err(usage_error(
            "--campaign-runtime requires the complete campaign profile and --campaign-component-authority",
        ));
    }
    if args.read_only {
        return Err(usage_error(
            "--campaign-runtime cannot be combined with --read-only",
        ));
    }

    let mut campaigns = std::collections::BTreeSet::new();
    for campaign in &args.campaign_runtime {
        let campaign = crucible_campaign::CampaignName::new(campaign)
            .map_err(|error| usage_error(format!("--campaign-runtime is invalid: {error}")))?;
        if !campaigns.insert(campaign) {
            return Err(usage_error(
                "--campaign-runtime cannot attach the same campaign twice",
            ));
        }
    }
    Ok(())
}

pub(crate) fn debug_authorization_policy(
    args: &ServeArgs,
) -> Result<DebugAuthorizationPolicy, CliError> {
    let mut policy = DebugAuthorizationPolicy::deny_all();
    if args.trusted_unauthenticated_bind {
        policy.grant_trusted_unauthenticated_role(DebugRole::new([
            DebugCapability::Observe,
            DebugCapability::Control,
            DebugCapability::Mutate,
            DebugCapability::Shell,
            DebugCapability::Admin,
        ]));
    }
    for mapping in &args.debug_role {
        let (fingerprint, capabilities) = mapping
            .split_once('=')
            .ok_or_else(|| usage_error("--debug-role must use sha256=capability,... syntax"))?;
        let mut parsed = Vec::new();
        for capability in capabilities.split(',') {
            parsed.push(match capability {
                "observe" => DebugCapability::Observe,
                "control" => DebugCapability::Control,
                "mutate" => DebugCapability::Mutate,
                "shell" => DebugCapability::Shell,
                "admin" => DebugCapability::Admin,
                _ => {
                    return Err(usage_error(format!(
                        "unknown debugger capability `{capability}`"
                    )));
                }
            });
        }
        if parsed.is_empty() {
            return Err(usage_error(
                "--debug-role must grant at least one capability",
            ));
        }
        policy
            .grant_certificate_role(fingerprint, DebugRole::new(parsed))
            .map_err(|error| usage_error(error.to_string()))?;
    }
    Ok(policy)
}

#[cfg(test)]
pub(crate) async fn run_serve_invocation_until_shutdown<S>(
    cli: &Cli,
    args: &ServeArgs,
    shutdown: S,
) -> Result<(), CliError>
where
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let heap = crucible_cas::content_store::fixture_sqlite_heap()
        .map_err(|error| serve_error(format!("test process heap: {error}")))?;
    run_serve_with_process_heap_until_shutdown(cli, args, shutdown, &heap).await
}

#[cfg(test)]
pub(crate) fn open_local_campaign_service(
    args: &ServeArgs,
    production_qemu: Option<crucible_api::ProductionVmLifecycleConfig>,
    campaign_debug_lifecycle: Option<Arc<dyn crucible_daemon::CampaignDebugLifecycleAdmission>>,
    private_target_attempt: Option<crucible_campaign::AttemptId>,
) -> Result<Option<PreparedLocalCampaignService>, CliError> {
    let heap = crucible_cas::content_store::fixture_sqlite_heap()
        .map_err(|error| serve_error(format!("test process heap: {error}")))?;
    open_local_campaign_service_with_heap(
        args,
        production_qemu,
        campaign_debug_lifecycle,
        private_target_attempt,
        Some(&heap),
    )
}

#[cfg(test)]
mod listen_endpoint_tests {
    use super::validate_listen_endpoint;

    #[test]
    fn host_interpretation_remains_with_the_original_resolver() {
        for endpoint in [
            "localhost:0",
            "service.example:8443",
            "127.0.0.1:80",
            "[::1]:65535",
            "::1:80",
            "[fe80::1%2]:80",
            "fe80::1%2:80",
            "[invalid]:80",
        ] {
            assert!(validate_listen_endpoint(endpoint).is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn malformed_port_and_host_fail_without_bootstrap() {
        for endpoint in [
            "127.0.0.1:70000",
            "localhost:abc",
            ":80",
            "localhost:",
            "localhost",
        ] {
            let error = validate_listen_endpoint(endpoint).expect_err("invalid bind input");
            assert_eq!(error.exit_code(), 3);
            assert!(error.to_string().contains("serve bind error"));
        }
    }
}
