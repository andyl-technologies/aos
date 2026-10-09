//! Installed Controller activation and complete startup/serving recipes.
//!
//! The ordinary route retains its original locals; selected startup parks the
//! same originals in resident parent/worker slots before every later operation.
//! Configuration, credential reads, journal assembly, worker handoff, readiness
//! notification and serving remain ordered in these complete recipes. The
//! reconciliation loop, effect executor and resident fields remain in their
//! existing owners; this private module adds no admission or custody producer.

use std::io::IoSlice;

use aos_sandbox_linux::credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    sendmsg_addr, socket_with,
};

use super::worker::{WorkerEvent, controller_worker, retained_controller_worker};
use super::*;
use configuration::RuntimeConfiguration;

pub(super) mod configuration;

const NODE_ID_CREDENTIAL: &str = "node-id";
const CACHE_REPLAY_BUNDLE_CREDENTIAL: &str = "cache-replay-bundle";
const MAXIMUM_CACHE_REPLAY_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Runs the controller from systemd's protected runtime environment.
///
/// Positional arguments are the fixed decimal controller UID and GID. The
/// optional `--public-api` flag requires all four protected public TLS credentials
/// and enables the registered-client public endpoint at the fixed socket.
/// `--publisher-ingress` requires one protected service-scope credential and
/// PID 1's exact record-subject listener; it registers an execution only.
/// `--nix-start-admission` requires the original paired Nix startup capture and
/// twelve fixed public credentials. It admits pending Start operations only;
/// it does not enable a Nix worker, effect success, or readiness.
/// The exclusive `--issue-source-successor` mode derives and durably delivers
/// one fixed administrative approval from real completed generation-one owners.
/// It starts no listener or worker and sends no READY notification. After its
/// original resources are acquired, failure terminates with custody resident
/// instead of returning an ordinary runtime error.
/// The node identity is read from
/// `CREDENTIALS_DIRECTORY/node-id`; broker endpoints,
/// cgroups, journal location, and root-only diagnostic socket are fixed
/// production paths.
///
/// # Errors
///
/// Returns configuration or process-identity errors. A genuinely empty
/// NoRoot/NoNix continuation also returns ordinary state, socket, journal,
/// catalog, notification or server errors.
///
/// Original capture, selected Root/Nix startup and recipe admission failures
/// intentionally terminate instead of returning an error. Later ordinary
/// failures also terminate while the continuation remains armed or retains
/// Root, Nix selector or launch-image custody. Selected Publisher and partial
/// worker startup also retain returned originals through intentional
/// termination. Issue-only failures retain their original invocation.
pub fn run_from_environment<A: ControllerServerAssembly>() -> Result<(), ControllerRuntimeError> {
    let configuration = RuntimeConfiguration::from_process()?;
    configuration.validate_process_identity()?;
    let mut startup = startup::ControllerRuntimeStartupV1::new(
        configuration.publisher_ingress,
        configuration.nix_start_admission,
        configuration.issue_source_successor,
    );
    if !startup.capture_once() {
        startup.terminate_failed();
    }
    if configuration.issue_source_successor {
        return source_successor_issuance::run(&configuration, &mut startup);
    }

    match run_ordinary_controller::<A>(configuration, &mut startup) {
        Err(cause) if startup.must_retain_failure() => startup.fail_runtime(cause),
        result => result,
    }
}

fn run_ordinary_controller<A: ControllerServerAssembly>(
    configuration: RuntimeConfiguration,
    startup: &mut startup::ControllerRuntimeStartupV1,
) -> Result<(), ControllerRuntimeError> {
    // This independently selected profile is retained before opening any
    // journal. Root's concurrent startup is joined only on the original flight.
    if !startup.admit_root_once(configuration.uid, configuration.gid) {
        startup.terminate_failed();
    }
    let normal_root_profile = startup.profile_share();
    if configuration.create_q04_policy_subgate && normal_root_profile.is_none() {
        startup.fail_runtime(ControllerRuntimeError::InvalidCredential);
    }
    if !startup.require_source_delivery_absent() {
        if startup.must_retain_failure() {
            startup.terminate_failed();
        }
        // Genuine empty NoRoot/NoNix retains the old ordinary error exit.
        return Err(ControllerRuntimeError::InvalidCredential);
    }
    if !startup.bind_launch_in_place() {
        startup.terminate_failed();
    }
    let launch_image = startup.image_share();
    if startup.must_retain_failure() {
        return run_retained_controller::<A>(
            configuration,
            startup,
            normal_root_profile,
            launch_image,
        );
    }
    let publisher_descriptor = startup.take_publisher();
    let publisher_listener = publisher_descriptor
        .map(publisher_ingress::adopt_observed_listener)
        .transpose()
        .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
    let node_id = read_node_id()?;
    // Admission consumes the genuine original capture before any Controller
    // journal opens. The selected credentials grant no worker or floor owner.
    let nix_start = if configuration.nix_start_admission {
        if !startup.admit_nix_once(
            configuration.uid,
            configuration.gid,
            NodeId::from_bytes(node_id),
        ) {
            startup.terminate_failed();
        }
        startup.selector_share()
    } else {
        None
    };
    let source_genesis_input =
        ProvisionedControllerSourceGenesisInputV1::from_systemd_credentials_optional()?;
    let publisher_registration = if let Some(listener) = publisher_listener {
        let scope = publisher_ingress::PublisherServiceScopeV1::from_process_credential(
            NodeId::from_bytes(node_id),
        )
        .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
        Some(
            publisher_ingress::PublisherRegistrationOwnerV1::new(listener, scope)
                .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?,
        )
    } else {
        None
    };
    if let Some(bundle) = read_cache_replay_bundle()? {
        CacheReplayControllerBootstrapOwnerV1::import_fixed_bundle_for_uid(
            configuration.uid,
            &bundle,
        )
        .map_err(ControllerRuntimeError::CacheReplaySource)?;
    }
    let ownership = ControllerOwnershipConfigurationV1::from_process_credentials_optional()
        .map_err(|_| ControllerRuntimeError::InvalidOwnershipCredential)?;
    let attach_credentials = ControllerAttachCredentialsV1::from_process_credentials_optional()
        .map_err(|_| ControllerRuntimeError::InvalidAttachCredential)?;
    let attach_plan_signer = ControllerBrokerPlanSignerV1::from_process_credentials_optional()
        .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential)?;
    let guest_root_pins = load_guest_root_template_pins_optional()
        .map_err(|_| ControllerRuntimeError::InvalidGuestRootCredential)?;
    let listener = A::bind_socket(&configuration.diagnostic_socket, configuration.uid, 0o660)?;
    let sessions = Arc::new(Mutex::new(ControllerBrokerSessions {
        launch_image,
        nix_generation_enabled: configuration.nix_storage_generation_prepare,
        #[cfg(feature = "online-nix")]
        nix_existing_outputs: configuration.nix_existing_outputs,
        ..ControllerBrokerSessions::default()
    }));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ControllerRuntimeError::Runtime)?;
    let attachment_host = match runtime.block_on(attachment_target::observe_host_service_identity())
    {
        Ok(identity) => Some(identity),
        Err(error) => {
            // Unrelated controller work continues; attachment effects retain no target.
            eprintln!("aos-sandboxd: Host attachment identity unavailable: {error}");
            None
        }
    };
    let attachment_mount =
        match runtime.block_on(attachment_target::observe_mount_service_identity()) {
            Ok(identity) => Some(identity),
            Err(error) => {
                eprintln!("aos-sandboxd: Mount attachment identity unavailable: {error}");
                None
            }
        };
    let mut controller = open_controller(
        &configuration,
        node_id,
        Arc::clone(&sessions),
        attachment_host,
        attachment_mount,
        nix_start,
        None,
    )?;
    let replay_genesis = source_genesis_input
        .as_ref()
        .map(|input| controller.has_retained_provisioned_source_genesis_v1(input))
        .transpose()?
        .unwrap_or(false);
    if replay_genesis {
        // Historical owner recovery must not wait behind an expired or updated
        // unrelated publisher bootstrap credential. This selector grants no
        // authority: the coordinator still rejoins the actual original attempt.
        complete_configured_source_genesis(
            &mut controller,
            source_genesis_input.as_ref(),
            normal_root_profile.as_deref(),
        )?;
    }
    if let Some(scope) = publisher_registration
        .as_ref()
        .map(|owner| owner.service_scope())
    {
        publisher_policy_source::install_from_process_credentials(&mut controller, scope)
            .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
    }
    if !replay_genesis {
        complete_configured_source_genesis(
            &mut controller,
            source_genesis_input.as_ref(),
            normal_root_profile.as_deref(),
        )?;
    }
    let listener = runtime.block_on(A::diagnostic_listener(listener))?;
    let public_listener = if configuration.public_api {
        Some(runtime.block_on(A::public_listener(configuration.uid))?)
    } else {
        None
    };
    let capabilities = Arc::new(Mutex::new(CapabilityState::starting(node_id)));
    let (events_tx, events_rx) = mpsc::channel();
    let (commands_tx, commands_rx) = mpsc::sync_channel(CONTROLLER_COMMAND_CAPACITY);
    let worker_capabilities = Arc::clone(&capabilities);
    let worker_normal_root_profile = normal_root_profile.clone();

    std::thread::Builder::new()
        .name("aos-sandboxd-reconciler".to_owned())
        .spawn(move || {
            controller_worker(
                controller,
                worker_normal_root_profile,
                node_id,
                ownership,
                attach_credentials,
                attach_plan_signer,
                guest_root_pins,
                source_genesis_input,
                publisher_registration,
                worker_capabilities,
                sessions,
                commands_rx,
                events_tx,
            )
        })
        .map_err(ControllerRuntimeError::WorkerSpawn)?;

    startup.complete_worker_handoff();

    wait_for_initial_readiness(&events_rx)?;
    if let Some(profile) = &normal_root_profile {
        profile
            .recheck()
            .map_err(ControllerRuntimeError::NormalRootProfile)?;
    }
    SystemdReadyNotifier::from_environment()?.notify_ready()?;

    let public_service = Arc::new(CapabilityService {
        capabilities: Arc::clone(&capabilities),
        commands: commands_tx.clone(),
        endpoint: ControllerEndpoint::RegisteredPublic,
    });
    let diagnostic_service = Arc::new(CapabilityService {
        capabilities,
        commands: commands_tx,
        endpoint: ControllerEndpoint::RootDiagnostic,
    });
    let (public_application, application) =
        A::applications(public_service, diagnostic_service);
    let result = runtime.block_on(serve_until_worker_failure::<A>(
        listener,
        application,
        public_listener,
        public_application,
        events_rx,
    ));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

fn run_retained_controller<A: ControllerServerAssembly>(
    configuration: RuntimeConfiguration,
    startup: &mut startup::ControllerRuntimeStartupV1,
    profile: Option<Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>>,
    launch: Option<aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1>,
) -> ! {
    let mut parent = ControllerParentCustodyV1::<A>::new(profile, launch);
    let worker = Arc::clone(&parent.worker);
    let Ok(mut originals) = worker.originals.lock() else {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller owner lock poisoned"));
    };
    let _unwind = AbortControllerCustodyUnwindV1;

    originals.git_coverage_enabled = configuration.git_coverage;

    // Local propagation only: success is assigned immediately into an already
    // prepared field. No helper consumes an original or supplies authority.
    macro_rules! checked {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(cause) => worker.terminate(ControllerResidentCauseV1::Runtime(cause)),
            }
        };
    }

    macro_rules! required {
        ($value:expr) => {
            match $value {
                Some(value) => value,
                None => worker.terminate(ControllerResidentCauseV1::Closed(
                    "Controller partial destination unavailable",
                )),
            }
        };
    }

    macro_rules! begin {
        ($step:ident) => {
            if worker.ended.load(Ordering::Acquire)
                || !parent.stage.begin(ControllerParentStepV1::$step)
            {
                worker.terminate(ControllerResidentCauseV1::Closed("Controller step reentered"));
            }
        };
    }

    macro_rules! complete {
        ($step:ident) => {
            if worker.ended.load(Ordering::Acquire)
                || !parent.stage.complete(ControllerParentStepV1::$step)
            {
                worker.terminate(ControllerResidentCauseV1::Closed("Controller step incomplete"));
            }
        };
    }

    begin!(Publisher);
    // Prepare the destination before the same actual FIRST6 role handoff.
    originals.publisher_attempt = startup
        .take_publisher()
        .map(publisher_ingress::PublisherStartupAttemptV1::from_original_listener);
    if let Some(attempt) = &mut originals.publisher_attempt {
        if attempt.admit_listener_once().is_err() {
            worker.terminate(ControllerResidentCauseV1::Publisher);
        }
    }
    complete!(Publisher);

    begin!(Node);
    originals.node = Some(checked!(read_node_id()));
    let node_id = required!(originals.node);
    complete!(Node);

    begin!(Nix);
    if configuration.nix_start_admission {
        if !startup.admit_nix_once(
            configuration.uid,
            configuration.gid,
            NodeId::from_bytes(node_id),
        ) {
            worker.close(ControllerResidentCauseV1::Closed(
                "resident original Nix admission failed",
            ));
            startup.terminate_failed();
        }
        originals.nix_selector = Some(startup.selector_share());
    } else {
        originals.nix_selector = Some(None);
    }
    complete!(Nix);

    begin!(GenesisInput);
    originals.genesis = Some(checked!(
        ProvisionedControllerSourceGenesisInputV1::from_systemd_credentials_optional()
            .map_err(ControllerRuntimeError::from)
    ));
    complete!(GenesisInput);

    begin!(PublisherRegistration);
    originals.publisher_registration = Some(None);
    if let Some(attempt) = &mut originals.publisher_attempt {
        if attempt
            .construct_registration_once(NodeId::from_bytes(node_id))
            .is_err()
        {
            worker.terminate(ControllerResidentCauseV1::Publisher);
        }
        originals.publisher_registration = Some(Some(required!(
            attempt.take_completed_registration()
        )));
    }
    complete!(PublisherRegistration);

    begin!(Cache);
    if configuration.git_upload_bootstrap {
        // ExistingResident never imports or creates its own Source authority.
        originals.cache_bundle = Some(None);
    } else {
        originals.cache_bundle = Some(checked!(read_cache_replay_bundle()));
        if let Some(bundle) = required!(originals.cache_bundle.as_ref()) {
            checked!(
                CacheReplayControllerBootstrapOwnerV1::import_fixed_bundle_for_uid(
                    configuration.uid,
                    bundle,
                )
                .map_err(ControllerRuntimeError::CacheReplaySource)
            );
        }
    }
    complete!(Cache);

    begin!(Ownership);
    originals.snapshot_ownership = Some(Arc::new(OnceLock::new()));
    let ownership = checked!(
        ControllerOwnershipConfigurationV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidOwnershipCredential)
    );
    originals.ownership = Some(match ownership {
        None => None,
        Some(configuration) => {
            let donation = required!(originals.snapshot_ownership.as_ref());
            // The shared allocation precedes admission. The actual returned
            // owner parks without allocating/copying its secret afterward.
            if let Err(configuration) = donation.set(configuration) {
                originals.snapshot_ownership_refused = Some(configuration);
                worker.terminate(ControllerResidentCauseV1::Closed(
                    "Snapshot ownership donation was already occupied",
                ));
            }
            Some(Arc::clone(donation))
        }
    });
    complete!(Ownership);

    begin!(Attach);
    originals.attach = Some(checked!(
        ControllerAttachCredentialsV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidAttachCredential)
    ));
    complete!(Attach);

    begin!(Signer);
    originals.signer = Some(checked!(
        ControllerBrokerPlanSignerV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential)
    ));
    complete!(Signer);

    begin!(Pins);
    originals.pins = Some(checked!(
        load_guest_root_template_pins_optional()
            .map_err(|_| ControllerRuntimeError::InvalidGuestRootCredential)
    ));
    complete!(Pins);

    begin!(Diagnostic);
    parent.diagnostic_registration = Some(tokio::net::UnixListenerRegistrationAttempt::new(
        checked!(A::bind_socket(&configuration.diagnostic_socket, configuration.uid, 0o660)),
    ));
    complete!(Diagnostic);

    begin!(Sessions);
    originals.sessions = Some(Arc::new(Mutex::new(ControllerBrokerSessions {
        launch_image: required!(parent.launch.take()),
        storage_terminal: Some(Arc::downgrade(&worker)),
        nix_generation_enabled: configuration.nix_storage_generation_prepare,
        #[cfg(feature = "online-nix")]
        nix_existing_outputs: configuration.nix_existing_outputs,
        ..ControllerBrokerSessions::default()
    })));
    complete!(Sessions);

    begin!(Runtime);
    parent.runtime = Some(checked!(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ControllerRuntimeError::Runtime)
    ));
    complete!(Runtime);

    begin!(Host);
    parent.host = Some(match required!(parent.runtime.as_ref())
        .block_on(attachment_target::observe_host_service_identity())
    {
        Ok(identity) => Some(identity),
        Err(error) => {
            eprintln!("aos-sandboxd: Host attachment identity unavailable: {error}");
            None
        }
    });
    complete!(Host);

    begin!(Mount);
    parent.mount = Some(match required!(parent.runtime.as_ref())
        .block_on(attachment_target::observe_mount_service_identity())
    {
        Ok(identity) => Some(identity),
        Err(error) => {
            eprintln!("aos-sandboxd: Mount attachment identity unavailable: {error}");
            None
        }
    });
    complete!(Mount);

    begin!(Controller);
    // The actual selected capture transfers its originals into an already
    // prepared parent before either attachment identity can leave custody.
    parent.resource_opening = startup.take_resource_opening();
    if let Some(opening) = parent.resource_opening.as_mut() {
        let profile = required!(required!(originals.profile.as_ref()).as_deref());
        if opening.admit_preopen_once(profile).is_err() {
            worker.terminate(ControllerResidentCauseV1::Closed("original bootstrap preopening refused"));
        }
        {
            let loan = match opening.borrow_preopen(profile) {
                Ok(loan) => loan,
                Err(_) => worker.terminate(ControllerResidentCauseV1::Closed("original bootstrap loan unavailable")),
            };
            parent.construction = Some((|| {
                parent.controller_journal.open_once(
                    &loan, &configuration.state_directory, configuration.uid, node_id,
                ).map_err(|_| ControllerRuntimeError::Journal(JournalError::ProtectedBoundary))?;
                let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))?;
                let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)?;
                parent.executor_signer = Some(ControllerBrokerPlanSignerV1::from_process_credentials_optional()
                    .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential));
                let signer = parent.executor_signer.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ControllerRuntimeError::InvalidBrokerPlanCredential)?;
                validate_process_cache_readback_credentials_v1(
                    signer.as_ref().map(ControllerBrokerPlanSignerV1::verifying_key_bytes),
                ).map_err(|_| ControllerRuntimeError::InvalidCacheReadbackCredential)?;
                validate_process_controller_hold_credentials_v1(
                    signer.as_ref().map(ControllerBrokerPlanSignerV1::verifying_key_bytes),
                ).map_err(|_| ControllerRuntimeError::InvalidControllerHoldCredential)?;
                parent.source_journal.open_once(&loan, configuration.uid)
                    .map_err(|_| ControllerRuntimeError::Journal(JournalError::ProtectedBoundary))?;
                let source = parent.source_journal.source_mut()
                    .ok_or(ControllerRuntimeError::Journal(JournalError::ProtectedBoundary))?;
                // The old semantic engines and their borrowing owners remain
                // unchanged. This milestone does not retain their internal
                // unreturned credential/Root/recovery prefixes.
                parent.lifecycle_replay = Some(match aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(source) {
                    Ok(owner) => owner.replay().map_err(ControllerRuntimeError::from),
                    Err(cause) => Err(ControllerRuntimeError::from(cause)),
                });
                if !matches!(parent.lifecycle_replay, Some(Ok(_))) {
                    return Err(ControllerRuntimeError::Journal(JournalError::ProtectedBoundary));
                }
                let journal = parent.controller_journal.journal_mut()
                    .ok_or(ControllerRuntimeError::Journal(JournalError::ProtectedBoundary))?;
                parent.project_recovery = Some(crate::controller_service::project_admission::recover_source_project_admission_v1(
                    journal, source, scope,
                ));
                if !matches!(parent.project_recovery, Some(Ok(()))) {
                    return Err(ControllerRuntimeError::Journal(JournalError::ProtectedBoundary));
                }
                Ok((scope, limits))
            })());
            // These two independently available posts are attempted even
            // after a constructor action Err. The original action fields are
            // never replaced by the later negative dispositions.
            let source_post = parent.source_journal.finish_posts(&loan);
            let controller_post = parent.controller_journal.finish_posts(&loan);
            if !matches!(parent.construction, Some(Ok(_)))
                || source_post.is_err() || controller_post.is_err()
            {
                let _first = parent.controller_journal.primary_failure()
                    .or_else(|| parent.executor_signer.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| parent.source_journal.primary_failure())
                    .or_else(|| parent.lifecycle_replay.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| parent.project_recovery.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| parent.construction.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| parent.source_journal.postcheck_debt())
                    .or_else(|| parent.controller_journal.postcheck_debt());
                worker.terminate(ControllerResidentCauseV1::Closed("resident Controller construction refused"));
            }
        }
        // The short pre-opening borrow has ended. Native enrollment now uses
        // the SAME staged writer and still-resident original PID1 pair.
        let journal = required!(parent.controller_journal.journal_mut());
        if opening.open_once(journal, profile, node_id).is_err() {
            worker.terminate(ControllerResidentCauseV1::Closed("resident native bootstrap enrollment refused"));
        }
        // Transfer the same enrolled original into the prearmed shared slot;
        // its uncertainty and pair remain alive with the worker and executor.
        originals.resource_bank = parent
            .resource_opening
            .take()
            .map(|opening| Arc::new(Mutex::new(opening)));

        let (scope, limits) = match parent.construction.as_ref() {
            Some(Ok(parts)) => *parts,
            _ => worker.terminate(ControllerResidentCauseV1::Closed("Controller assembly unavailable")),
        };
        // The unchanged process-start observation occurs while both staged
        // writers and the signer still reside in the parent destinations.
        let process_start = current_boot_and_boottime();
        let signer = match parent.executor_signer.take() {
            Some(Ok(signer)) => signer,
            _ => worker.terminate(ControllerResidentCauseV1::Closed("Controller signer unavailable")),
        };
        let source = required!(parent.source_journal.take_source());
        let mut executor = ProductionEffectExecutor::from_retained_source(
            Arc::clone(required!(originals.sessions.as_ref())), scope, signer,
            required!(parent.host.take()), required!(parent.mount.take()), source,
            configuration.uid, NodeId::from_bytes(node_id), process_start,
        );
        executor.resource_bank = originals.resource_bank.as_ref().map(Arc::clone);
        executor.snapshot_ownership = Some(Arc::clone(required!(originals.snapshot_ownership.as_ref())))
            .filter(|donation| donation.get().is_some());
        let nix_start = required!(originals.nix_selector.as_ref()).clone();
        #[cfg(feature = "online-nix")]
        {
            executor.nix_generation_enabled = configuration.nix_storage_generation_prepare;
            if executor.nix_generation_enabled {
                executor.nix_generation_profile = Some(Arc::clone(
                    required!(required!(originals.profile.as_ref()).as_ref()),
                ));
            }
            if let Some(selector) = nix_start.as_ref() {
                executor.nix_start = Some(Arc::clone(selector));
            }
        }
        let compiler = match nix_start {
            Some(selector) => ProductionOperationCompilerV1::with_nix_start(selector),
            None => ProductionOperationCompilerV1::new(),
        };
        let journal = required!(parent.controller_journal.take_journal());
        originals.controller = Some(NodeController::new(scope, limits, compiler, Reconciler::new(journal, executor)));
    } else {
        // Ordinary construction keeps its original consuming boundaries.
        // Lower nested recovery owners are not rescued by this milestone.
        originals.controller = Some(checked!(open_controller(
            &configuration,
            node_id,
            Arc::clone(required!(originals.sessions.as_ref())),
            required!(parent.host.take()),
            required!(parent.mount.take()),
            required!(originals.nix_selector.as_ref()).clone(),
            Some(Arc::clone(required!(originals.snapshot_ownership.as_ref()))),
        )));
    }
    complete!(Controller);

    begin!(ControllerStartup);
    {
        let ControllerWorkerOriginalsV1 {
            controller,
            genesis,
            profile,
            publisher_registration,
            publisher_policy_bootstrap,
            resource_bank,
            ..
        } = &mut *originals;
        let controller = required!(controller.as_mut());
        let genesis = required!(genesis.as_ref()).as_ref();
        let profile = required!(profile.as_ref()).as_deref();
        if configuration.git_coverage && genesis.is_some() {
            worker.terminate(ControllerResidentCauseV1::Closed(
                "exclusive Git cohort cannot create or reconstruct Source genesis",
            ));
        }
        let first_global_prefix_selection = resource_bank.as_ref().map(|bank| {
            bank.lock().map(|bank| bank.selects_first_global_prefix())
        });
        let first_global_prefix_selected = match &first_global_prefix_selection {
            Some(Ok(selected)) => *selected,
            Some(Err(_)) => worker.terminate(ControllerResidentCauseV1::Closed(
                "FirstGlobal original bank lock failure retained",
            )),
            None => false,
        };
        if first_global_prefix_selected {
            let Some(profile) = profile else {
                worker.terminate(ControllerResidentCauseV1::Closed("FirstGlobal original profile is absent"));
            };
            // The entered executor parks its actual prefix before either
            // selector can replay, allocate, sign or connect. The outward
            // status does not carry or manufacture a spending loan.
            let prepared = controller.prepare_first_global_prefix_v1(profile);
            if prepared.is_err() {
                worker.terminate(ControllerResidentCauseV1::Closed("FirstGlobal prefix original failure retained"));
            }
        }
        // Only the selected image-bank startup consults this additional family
        // selector. Budgetless ordinary startup retains its old observation order.
        let resource_global_result = if resource_bank.is_some() {
            genesis.map(|input| controller.configured_resource_global_selection_v2(input)).transpose()
        } else { Ok(None) };
        let resource_global = match &resource_global_result {
            Ok(selected) => selected == &Some(true),
            Err(_) => worker.terminate(ControllerResidentCauseV1::Closed("original resource Global family selection failed")),
        };
        let configured_selection_result = genesis
            .map(|input| controller.configured_project_startup_selection_v3(input))
            .transpose();
        let configured_selection = match &configured_selection_result {
            Ok(selection) => *selection,
            Err(_) => worker.terminate(ControllerResidentCauseV1::Closed(
                "configured project history comparison failed",
            )),
        };
        // The same stored prefix remains charged, but its unused rows cannot
        // pay a different coordinator or an absent-input continuation.
        let refuse_skipped_first_global = |reason| -> ! {
            let closed = profile.map(|original| original.close_first_global_prefix_v1());
            let _original_close = &closed;
            worker.terminate(ControllerResidentCauseV1::Closed(reason))
        };
        if first_global_prefix_selected
            && (!resource_global
                || configured_selection == Some(aos_sandbox::controller::ConfiguredProjectStartupSelectionV3::MixedProject))
        {
            refuse_skipped_first_global("FirstGlobal prefix cannot enter an unrelated startup purpose");
        }
        let (replay_genesis, selected_genesis) = if configured_selection == Some(aos_sandbox::controller::ConfiguredProjectStartupSelectionV3::MixedProject) {
            let Some(input) = genesis else { worker.terminate(ControllerResidentCauseV1::Closed("configured mixed pair is absent")); };
            let Some(profile) = profile else { worker.terminate(ControllerResidentCauseV1::Closed("configured mixed startup requires the original Root profile")); };
            {
                // The whole predecessor loan ends before B is parked. Global A
                // keeps its actual global history and independent current floor.
                let returned = controller.coordinate_predecessor_successor_v3(input, profile);
                if let Err(failed) = &returned {
                    let _first_cause = failed.first_cause();
                    worker.terminate(ControllerResidentCauseV1::Closed("mixed original predecessor flight failed"));
                }
            }
            let selected_result = controller.retained_project_successor_selection_v3(input);
            let selected = match &selected_result {
                Ok(selected) => *selected,
                Err(_) => worker.terminate(ControllerResidentCauseV1::Closed("selected project history comparison failed")),
            };
            if selected == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
                let returned = controller.coordinate_project_successor_v3(profile, input.project());
                if let Err(failed) = &returned {
                    let _first_cause = failed.first_cause();
                    worker.terminate(ControllerResidentCauseV1::Closed("selected original successor flight failed"));
                }
            } else {
                let returned = controller.coordinate_configured_project_genesis_v3(input, profile);
                if let Err(failed) = &returned {
                    let _first_cause = failed.first_cause();
                    worker.terminate(ControllerResidentCauseV1::Closed("configured original project genesis failed"));
                }
            }
            (true, true)
        } else {
        // Inspect the genuine retained singleton before legacy genesis or any
        // publisher/public startup. Selection DATA is not mutation authority.
        let successor_project_result = controller.retained_first_source_successor_project_v2();
        let successor_project = match &successor_project_result {
            Ok(project) => *project,
            Err(_) => worker.terminate(ControllerResidentCauseV1::Closed(
                "retained first Source successor selection failed",
            )),
        };
        if first_global_prefix_selected && successor_project.is_some() {
            refuse_skipped_first_global("FirstGlobal prefix cannot enter a retained Source successor");
        }
        let selected_genesis = match (successor_project, genesis) {
            (Some(project), Some(input)) if input.project() == project => {
                // This compares actual configured credentials with the retained
                // Controller acceptance only; it never invokes gen1 Source replay.
                let configured = controller.has_retained_provisioned_source_genesis_v1(input);
                if !matches!(configured, Ok(true)) {
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "configured predecessor does not match retained Source genesis",
                    ));
                }
                true
            }
            (Some(_), Some(_)) => worker.terminate(ControllerResidentCauseV1::Closed(
                "a different configured genesis project is closed after the first Source successor",
            )),
            _ => false,
        };
        if successor_project.is_some() {
            let Some(profile) = profile else {
                worker.terminate(ControllerResidentCauseV1::Closed(
                    "retained first Source successor requires the original Root profile",
                ));
            };
            let returned = controller.coordinate_retained_first_source_successor_v2(profile);
            if let Err(failed) = &returned {
                // The whole returned failed loan and both writers stay named
                // here across terminal worker failure; no reborrow or retry.
                let _first_cause = failed.first_cause();
                worker.terminate(ControllerResidentCauseV1::Closed(
                    "original first Source successor flight failed",
                ));
            }
        }
        let replay_genesis = if selected_genesis {
            // The populated consumer completed the SAME configured predecessor
            // project. It must not be reinterpreted by the strict gen1 reader.
            true
        } else {
            checked!(
                genesis
                    .map(|input| controller.has_retained_provisioned_source_genesis_v1(input))
                    .transpose()
                    .map_err(ControllerRuntimeError::from)
            )
            .unwrap_or(false)
        };
        if replay_genesis && !selected_genesis {
            if resource_global {
                let Some(input) = genesis else {
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "resource Global original pair is absent",
                    ));
                };
                let Some(profile) = profile else {
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "resource Global original Root profile is absent",
                    ));
                };
                let returned = controller.coordinate_configured_global_genesis_v2(input, profile);
                if let Err(failed) = &returned {
                    let _first_cause = failed.first_cause();
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "retained resource Global genesis failed",
                    ));
                }
            } else {
                checked!(
                    complete_configured_source_genesis(controller, genesis, profile)
                        .map_err(ControllerRuntimeError::from)
                );
            }
        }
            (replay_genesis, selected_genesis)
        };
        if configuration.git_upload_bootstrap
            && required!(publisher_registration.as_ref()).is_none()
        {
            worker.terminate(ControllerResidentCauseV1::Closed(
                "Git bootstrap original publisher registration is absent",
            ));
        }
        if let Some(scope) = required!(publisher_registration.as_ref())
            .as_ref()
            .map(|owner| owner.service_scope())
        {
            if configuration.git_upload_bootstrap {
                // Park the empty fixed destination before capture or parsing.
                *publisher_policy_bootstrap = Some(
                    publisher_policy_source::PublisherPolicyBootstrapAttemptV1::new(),
                );
                let attempt = required!(publisher_policy_bootstrap.as_mut());
                let installed = if configuration.git_coverage {
                    attempt.install_coverage_bootstrap_once(controller, scope)
                } else {
                    attempt.install_bootstrap_once(controller, scope)
                };
                if installed.is_err() {
                    worker.terminate(ControllerResidentCauseV1::PublisherPolicyBootstrap);
                }
            } else {
                checked!(
                    publisher_policy_source::install_from_process_credentials(controller, scope)
                        .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))
                );
            }
        }
        if !replay_genesis {
            if resource_global {
                let Some(input) = genesis else {
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "resource Global original pair is absent",
                    ));
                };
                let Some(profile) = profile else {
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "resource Global original Root profile is absent",
                    ));
                };
                let returned = controller.coordinate_configured_global_genesis_v2(input, profile);
                if let Err(failed) = &returned {
                    let _first_cause = failed.first_cause();
                    worker.terminate(ControllerResidentCauseV1::Closed(
                        "retained resource Global genesis failed",
                    ));
                }
            } else {
                checked!(
                    complete_configured_source_genesis(controller, genesis, profile)
                        .map_err(ControllerRuntimeError::from)
                );
            }
        }
        if let Some(bootstrap) = publisher_policy_bootstrap.as_mut().filter(|_| !configuration.git_coverage) {
            if cache_usage::selected_bookend(controller, bootstrap).is_err() {
                worker.terminate(ControllerResidentCauseV1::CacheUsage);
            }
        }
    }
    complete!(ControllerStartup);

    if configuration.create_q04_policy_subgate {
        // The SAME admitted profile and whole Controller remain parked in the
        // existing worker before selected Cache opens or the first cycle.
        let ControllerWorkerOriginalsV1 { controller, profile, .. } = &mut *originals;
        let profile = required!(required!(profile.as_ref()).as_ref());
        if required!(controller.as_mut())
            .select_original_create_q04_policy_subgate_v1(Arc::clone(profile)).is_err()
        {
            worker.terminate(ControllerResidentCauseV1::Closed("original Q04 selection failed"));
        }
    }

    begin!(AsyncDiagnostic);
    {
        let ControllerParentCustodyV1 {
            runtime,
            diagnostic_registration,
            diagnostic,
            ..
        } = &mut parent;
        let runtime = required!(runtime.as_ref());
        let attempt = required!(diagnostic_registration.as_mut());
        runtime.block_on(async {
            A::register_diagnostic(attempt, diagnostic, worker.as_ref());
        });
    }
    complete!(AsyncDiagnostic);

    begin!(Public);
    if configuration.public_api {
        let ControllerParentCustodyV1 {
            runtime,
            public_startup,
            public,
            ..
        } = &mut parent;
        required!(runtime.as_ref()).block_on(async {
            A::bind_public_retained(
                configuration.uid,
                public_startup,
                public,
                worker.as_ref(),
            );
        });
    } else {
        parent.public = Some(None);
    }
    complete!(Public);

    if let Some(gateway) = configuration.git_read_inspection {
        parent.git_read.bind(configuration.uid, configuration.gid, gateway, &worker);
        let Some(Some(public)) = parent.public.as_ref() else {
            worker.terminate(ControllerResidentCauseV1::GitRead);
        };
        originals.git_read = Some(git_read_inspection::GitReadWorkerInputsV1::new(
            A::git_read_acceptor(public),
            required!(parent.runtime.as_ref()).handle().clone(),
        ));
    }

    begin!(Capabilities);
    originals.capabilities = Some(Arc::new(Mutex::new(CapabilityState::starting(node_id))));
    complete!(Capabilities);

    begin!(Events);
    // Both target guards are acquired BEFORE the tuple producer returns either
    // original end. The receiver never enters a consuming monitor closure.
    {
        let Ok(mut receiver) = worker.receiver.lock() else {
            worker.terminate(ControllerResidentCauseV1::Closed("Controller receiver lock poisoned"));
        };
        if receiver.is_some() || originals.events.is_some() {
            worker.terminate(ControllerResidentCauseV1::Closed("Controller event targets occupied"));
        }
        let (sender, received) = mpsc::channel();
        originals.events = Some(sender);
        *receiver = Some(received);
    }
    complete!(Events);

    begin!(Commands);
    let (commands_tx, commands_rx) = mpsc::sync_channel(CONTROLLER_COMMAND_CAPACITY);
    parent.commands = Some(commands_tx);
    if configuration.git_read_inspection.is_some() {
        parent.git_read_commands = Some(required!(parent.commands.as_ref()).clone());
    }
    originals.commands = Some(commands_rx);
    complete!(Commands);
    if !originals.complete_worker_inputs(&parent.stage) {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller worker fields incomplete"));
    }
    let capabilities = Arc::clone(required!(originals.capabilities.as_ref()));

    begin!(Spawn);
    drop(originals);
    let thread_worker = Arc::clone(&worker);
    parent.thread = Some(checked!(
        std::thread::Builder::new()
            .name("aos-sandboxd-reconciler".to_owned())
            .spawn(move || retained_controller_worker(&thread_worker))
            .map_err(ControllerRuntimeError::WorkerSpawn)
    ));
    complete!(Spawn);
    // No acquisition of the long owner loan after a successful spawn.
    startup.complete_worker_handoff();

    begin!(Readiness);
    match worker.receive() {
        ControllerMonitorOutcomeV1::Event(WorkerEvent::Ready)
            if !worker.ended.load(Ordering::Acquire) => {}
        ControllerMonitorOutcomeV1::Event(WorkerEvent::Fatal(message)) => {
            worker.terminate(ControllerResidentCauseV1::Worker(message))
        }
        _ => worker.terminate(ControllerResidentCauseV1::Closed(
            "resident Controller worker stopped before readiness",
        )),
    }
    complete!(Readiness);
    begin!(Profile);
    if let Some(profile) = startup.profile() {
        checked!(profile.recheck().map_err(ControllerRuntimeError::NormalRootProfile));
    }
    complete!(Profile);
    begin!(Notifier);
    parent.notifier = Some(checked!(SystemdReadyNotifier::from_environment()));
    complete!(Notifier);
    begin!(Notify);
    checked!(required!(parent.notifier.as_ref()).notify_ready());
    complete!(Notify);

    // These are the same routers and service sharing points as Legacy.
    begin!(Applications);
    let public_service = Arc::new(CapabilityService {
        capabilities: Arc::clone(&capabilities),
        commands: required!(parent.commands.as_ref()).clone(),
        endpoint: ControllerEndpoint::RegisteredPublic,
    });
    let diagnostic_service = Arc::new(CapabilityService {
        capabilities,
        commands: required!(parent.commands.take()),
        endpoint: ControllerEndpoint::RootDiagnostic,
    });
    let (public_application, application) =
        A::applications(public_service, diagnostic_service);
    complete!(Applications);

    // Future construction is an infallible ownership park. Axum's unchanged
    // IntoFuture boxing happens during poll, an excluded provider boundary.
    let public = std::pin::pin!(A::serve_public(
        required!(parent.public.take()),
        public_application,
    ));
    let _public_unwind = AbortControllerCustodyUnwindV1;
    let diagnostic_listener = required!(parent.diagnostic.take());
    let _diagnostic_input_unwind = AbortControllerCustodyUnwindV1;
    let diagnostic = std::pin::pin!(async move {
        A::serve_diagnostic(diagnostic_listener, application).await
    });
    let _diagnostic_unwind = AbortControllerCustodyUnwindV1;

    let git_read = std::pin::pin!(parent.git_read.serve(
        parent.git_read_commands.as_ref(),
        worker.as_ref(),
    ));
    let _git_read_unwind = AbortControllerCustodyUnwindV1;

    // Only the concrete listener/router enters that future. Runtime remains
    // in the parent, and the receiver stays in its independent original slot.
    begin!(Monitor);
    let monitor_worker = Arc::clone(&worker);
    parent.monitor = Some(
        required!(parent.runtime.as_ref()).spawn_blocking(move || monitor_worker.receive()),
    );
    complete!(Monitor);
    let _serve_unwind = AbortControllerCustodyUnwindV1;
    let runtime = required!(parent.runtime.as_ref());
    let monitor = required!(parent.monitor.as_mut());
    let _stopped: () = runtime.block_on(async {
        let mut public = public;
        let mut diagnostic = diagnostic;
        let mut git_read = git_read;
        tokio::select! {
            () = &mut git_read => worker.terminate(ControllerResidentCauseV1::GitRead),
            result = &mut public => {
                let cause = match result {
                    Err(cause) => ControllerResidentCauseV1::Runtime(cause),
                    Ok(()) => ControllerResidentCauseV1::Closed("Controller public server completed"),
                };
                worker.terminate(cause)
            }
            result = &mut diagnostic => {
                let cause = match result {
                    Err(cause) => ControllerResidentCauseV1::Runtime(cause),
                    Ok(()) => ControllerResidentCauseV1::Closed("Controller diagnostic server completed"),
                };
                worker.terminate(cause)
            }
            result = monitor => {
                let cause = match result {
                    Err(cause) => ControllerResidentCauseV1::Runtime(
                        ControllerRuntimeError::WorkerJoin(cause),
                    ),
                    Ok(ControllerMonitorOutcomeV1::Event(WorkerEvent::Fatal(message))) => {
                        ControllerResidentCauseV1::Worker(message)
                    }
                    Ok(_) => ControllerResidentCauseV1::Closed("Controller worker monitor ended"),
                };
                worker.terminate(cause)
            }
        }
    });
    worker.terminate(ControllerResidentCauseV1::Closed(
        "Controller server monitor returned unexpectedly",
    ))
}

fn complete_configured_source_genesis(
    controller: &mut ProductionController,
    input: Option<&ProvisionedControllerSourceGenesisInputV1>,
    profile: Option<&aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
) -> Result<(), ControllerSourceGenesisInputErrorV1> {
    let Some(input) = input else {
        return Ok(());
    };
    let profile = profile.ok_or(ControllerSourceGenesisInputErrorV1::Owner(
        aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1::AdmissionClosed,
    ))?;
    // Configured genesis is a real startup obligation, not an advisory
    // inspection. Failure keeps readiness closed; restarting rejoins the
    // exact original pair and protected rows through final Root Finish.
    controller.coordinate_provisioned_source_genesis_v1(input, profile)?;
    Ok(())
}

async fn serve_until_worker_failure<A: ControllerServerAssembly>(
    listener: A::DiagnosticListener,
    application: A::Application,
    public_listener: Option<A::PublicListener>,
    public_application: A::Application,
    events: mpsc::Receiver<WorkerEvent>,
) -> Result<(), ControllerRuntimeError> {
    let worker = tokio::task::spawn_blocking(move || events.recv());
    tokio::select! {
        result = A::serve_public(public_listener, public_application) => result,
        result = A::serve_diagnostic(listener, application) => result,
        result = worker => {
            match result.map_err(ControllerRuntimeError::WorkerJoin)? {
                Ok(WorkerEvent::Fatal(message)) => Err(ControllerRuntimeError::Worker(message)),
                Ok(WorkerEvent::Ready) => Err(ControllerRuntimeError::Worker(
                    "controller worker emitted duplicate readiness".to_owned(),
                )),
                Ok(WorkerEvent::ResidentFailure) => Err(ControllerRuntimeError::Worker(
                    "controller worker retained its original failure".to_owned(),
                )),
                Err(_) => Err(ControllerRuntimeError::Worker(
                    "controller worker exited without a terminal status".to_owned(),
                )),
            }
        }
    }
}

fn open_controller(
    configuration: &RuntimeConfiguration,
    node_id: [u8; 16],
    sessions: SharedControllerBrokerSessions,
    attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    nix_start: Option<Arc<ControllerNixStartRecipeSelectorV2>>,
    snapshot_ownership: Option<SnapshotOwnershipDonationV3>,
) -> Result<ProductionController, ControllerRuntimeError> {
    let (journal, _) = Journal::open_protected_at_for_uid(
        &configuration.state_directory,
        JOURNAL_NAME,
        production_journal_limits(),
        configuration.uid,
    )?;

    controller_from_journal(
        journal,
        node_id,
        sessions,
        configuration.uid,
        attachment_host,
        attachment_mount,
        nix_start,
        configuration.nix_storage_generation_prepare,
        snapshot_ownership,
    )
}

fn controller_from_journal(
    mut journal: Journal,
    node_id: [u8; 16],
    sessions: SharedControllerBrokerSessions,
    controller_uid: u32,
    attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    nix_start: Option<Arc<ControllerNixStartRecipeSelectorV2>>,
    nix_generation_enabled: bool,
    snapshot_ownership: Option<SnapshotOwnershipDonationV3>,
) -> Result<ProductionController, ControllerRuntimeError> {
    validate_controller_journal(&mut journal, node_id)?;
    let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))?;
    let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)?;
    let mut executor = ProductionEffectExecutor::open(
        &mut journal,
        sessions,
        scope,
        controller_uid,
        NodeId::from_bytes(node_id),
        attachment_host,
        attachment_mount,
    )?;
    executor.snapshot_ownership = snapshot_ownership.filter(|donation| donation.get().is_some());
    #[cfg(feature = "online-nix")]
    {
        executor.nix_generation_enabled = nix_generation_enabled;
    }
    #[cfg(feature = "online-nix")]
    if let Some(selector) = nix_start.as_ref() {
        // Share only the already admitted original. None keeps the old
        // constructor allocation/check/drop intervals and creates no loan.
        executor.nix_start = Some(Arc::clone(selector));
    }
    let compiler = match nix_start {
        Some(selector) => ProductionOperationCompilerV1::with_nix_start(selector),
        None => ProductionOperationCompilerV1::new(),
    };
    Ok(NodeController::new(
        scope,
        limits,
        compiler,
        Reconciler::new(journal, executor),
    ))
}

/// Reads the original process node identity credential as DATA.
///
/// # Errors
///
/// Returns the original credential-read error or rejects absent, malformed or
/// zero node identity bytes.
pub(super) fn read_node_id() -> Result<[u8; 16], ControllerRuntimeError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ControllerRuntimeError::InvalidCredential)?;
    let bytes = std::fs::read(Path::new(&directory).join(NODE_ID_CREDENTIAL))
        .map_err(ControllerRuntimeError::CredentialRead)?;
    let node_id: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ControllerRuntimeError::InvalidCredential)?;
    if node_id == [0; 16] {
        return Err(ControllerRuntimeError::InvalidCredential);
    }
    Ok(node_id)
}

fn read_cache_replay_bundle() -> Result<Option<Vec<u8>>, ControllerRuntimeError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ControllerRuntimeError::InvalidCacheReplayBundle)?;
    read_optional_bounded_role_credential_v1(
        Path::new(&directory),
        CACHE_REPLAY_BUNDLE_CREDENTIAL,
        1,
        MAXIMUM_CACHE_REPLAY_BUNDLE_BYTES,
        true,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| ControllerRuntimeError::InvalidCacheReplayBundle)
}

fn wait_for_initial_readiness(
    events: &mpsc::Receiver<WorkerEvent>,
) -> Result<(), ControllerRuntimeError> {
    match events.recv() {
        Ok(WorkerEvent::Ready) => Ok(()),
        Ok(WorkerEvent::Fatal(message)) => Err(ControllerRuntimeError::Worker(message)),
        Ok(WorkerEvent::ResidentFailure) => Err(ControllerRuntimeError::Worker(
            "controller worker retained its original failure".to_owned(),
        )),
        Err(_) => Err(ControllerRuntimeError::Worker(
            "controller worker exited before readiness".to_owned(),
        )),
    }
}

/// Retains the original systemd notification socket and address.
pub(super) struct SystemdReadyNotifier {
    socket: std::os::fd::OwnedFd,
    address: SocketAddrUnix,
}

impl SystemdReadyNotifier {
    fn from_environment() -> Result<Self, ControllerRuntimeError> {
        let value =
            std::env::var_os("NOTIFY_SOCKET").ok_or(ControllerRuntimeError::InvalidNotifySocket)?;
        let value = value
            .to_str()
            .filter(|value| !value.is_empty())
            .ok_or(ControllerRuntimeError::InvalidNotifySocket)?;
        let address = if let Some(name) = value.strip_prefix('@') {
            if name.is_empty() {
                return Err(ControllerRuntimeError::InvalidNotifySocket);
            }
            SocketAddrUnix::new_abstract_name(name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .map_err(ControllerRuntimeError::Notify)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(ControllerRuntimeError::Notify)?;
        Ok(Self { socket, address })
    }

    fn notify_ready(&self) -> Result<(), ControllerRuntimeError> {
        let payload = b"READY=1";
        let written = sendmsg_addr(
            &self.socket,
            &self.address,
            &[IoSlice::new(payload)],
            &mut SendAncillaryBuffer::default(),
            SendFlags::NOSIGNAL,
        )
        .map_err(ControllerRuntimeError::Notify)?;
        if written != payload.len() {
            return Err(ControllerRuntimeError::PartialNotification);
        }
        Ok(())
    }
}
