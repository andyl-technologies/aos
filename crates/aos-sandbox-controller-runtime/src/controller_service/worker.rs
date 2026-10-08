//! Complete private Controller reconciliation and broker-inventory worker.
//!
//! Both installed worker entries borrow the same reconciliation loop. Pending
//! history recovery, exact session acquisition, physical readback, catalog
//! publication and retry classification retain their original ordering. The
//! parent keeps the concrete effect executor and authenticated session slots;
//! this module adds no admission, detached loan or readiness producer.

use super::*;

#[cfg(test)]
mod tests;

/// Runs the original consuming worker frame through the sole borrowed loop.
pub(super) fn controller_worker(
    mut controller: ProductionController,
    normal_root_profile: Option<
        Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    >,
    node_id: [u8; 16],
    ownership: Option<ControllerOwnershipConfigurationV1>,
    attach_credentials: Option<ControllerAttachCredentialsV1>,
    attach_plan_signer: Option<ControllerBrokerPlanSignerV1>,
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    source_genesis_input: Option<ProvisionedControllerSourceGenesisInputV1>,
    mut publisher_registration: Option<publisher_ingress::PublisherRegistrationOwnerV1>,
    capabilities: Arc<Mutex<CapabilityState>>,
    sessions: SharedControllerBrokerSessions,
    commands: mpsc::Receiver<ControllerCommand>,
    events: mpsc::Sender<WorkerEvent>,
) {
    controller_worker_loop(
        ControllerWorkerLoanV1 {
            controller: &mut controller,
            profile: normal_root_profile.as_deref(),
            node: node_id,
            ownership: ownership.as_ref(),
            attach: attach_credentials.as_ref(),
            signer: attach_plan_signer.as_ref(),
            pins: guest_root_pins,
            genesis: source_genesis_input.as_ref(),
            publisher: publisher_registration.as_mut(),
            cache_bootstrap: None,
            git_coverage_enabled: false,
            git_read: None,
            capabilities: &capabilities,
            sessions: &sessions,
            commands: &commands,
            events: &events,
        },
        None,
    );
}

/// Borrows the resident worker's original slots without detaching their custody.
pub(super) fn retained_controller_worker(worker: &ControllerWorkerCustodyV1) {
    let Ok(mut originals) = worker.originals.lock() else {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller owner lock poisoned"));
    };
    let _unwind = AbortControllerCustodyUnwindV1;
    if worker.ended.load(Ordering::Acquire) {
        return;
    }
    let Some(loan) = originals.ready_loan() else {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller worker fields incomplete"));
    };
    controller_worker_loop(loan, Some(worker));
}

// The only loop is borrowed by both the literal consuming Legacy wrapper and
// the selected resident owner. No stored reference or duplicate reducer exists.
fn controller_worker_loop(
    loan: ControllerWorkerLoanV1<'_>,
    custody: Option<&ControllerWorkerCustodyV1>,
) {
    let ControllerWorkerLoanV1 {
        controller,
        profile: normal_root_profile,
        node: node_id,
        ownership,
        attach: attach_credentials,
        signer: attach_plan_signer,
        pins: guest_root_pins,
        genesis: source_genesis_input,
        publisher: mut publisher_registration,
        mut cache_bootstrap,
        git_coverage_enabled,
        mut git_read,
        capabilities,
        sessions,
        commands,
        events,
    } = loan;
    #[cfg(target_os = "linux")]
    let mut coverage = if git_coverage_enabled {
        let (Some(profile), Some(bootstrap), Some(terminal)) =
            (normal_root_profile, cache_bootstrap.as_deref_mut(), custody)
        else {
            std::process::abort();
        };
        let mut owner = git_coverage::GitCoverageWorkerV1::new(profile);
        let Ok(mut original_sessions) = sessions.lock() else {
            terminal.terminate(ControllerResidentCauseV1::GitCoverage);
        };
        if owner.install_once(controller, bootstrap, &mut original_sessions, node_id).is_err() {
            terminal.terminate(ControllerResidentCauseV1::GitCoverage);
        }
        Some(owner)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    if git_coverage_enabled {
        std::process::abort();
    }

    let mut ready = false;
    let mut next_cycle = Instant::now();
    let mut next_attach_poll = Instant::now();
    let mut attach_poll_cursor = 0;
    loop {
        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        if Instant::now() >= next_cycle {
            if let Some(input) = &source_genesis_input {
                if let Err(error) = input.recheck() {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Runtime(
                            ControllerRuntimeError::SourceGenesisInput(error),
                        ),
                    );
                    return;
                }
            }

            // Retain this same original profile in the actual worker lifecycle;
            // no Root readiness or genesis authority follows from this check.
            if let Some(profile) = &normal_root_profile {
                if let Err(error) = profile.recheck() {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Runtime(
                            ControllerRuntimeError::NormalRootProfile(error),
                        ),
                    );
                    return;
                }
            }
            if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
                return;
            }
            if let Some(bootstrap) = cache_bootstrap.as_mut() {
                #[cfg(target_os = "linux")]
                let checked = match coverage.as_mut() {
                    Some(owner) => owner.bookend(controller, bootstrap),
                    None => cache_usage::selected_bookend(controller, bootstrap),
                };
                #[cfg(not(target_os = "linux"))]
                let checked = cache_usage::selected_bookend(controller, bootstrap);
                if checked.is_err() {
                    report_controller_worker_failure(events, custody, ControllerResidentCauseV1::CacheUsage);
                    return;
                }
            }
            match run_controller_cycle(
                controller,
                node_id,
                sessions,
                !ready,
                guest_root_pins,
                attach_plan_signer,
            ) {
                Ok(catalog) => {
                    if let Some(bootstrap) = cache_bootstrap.as_mut() {
                        #[cfg(target_os = "linux")]
                        let checked = match coverage.as_mut() {
                            Some(owner) => owner.bookend(controller, bootstrap),
                            None => cache_usage::selected_bookend(controller, bootstrap),
                        };
                        #[cfg(not(target_os = "linux"))]
                        let checked = cache_usage::selected_bookend(controller, bootstrap);
                        if checked.is_err() {
                            report_controller_worker_failure(events, custody, ControllerResidentCauseV1::CacheUsage);
                            return;
                        }
                    }
                    if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
                        return;
                    }
                    let update = capabilities
                        .lock()
                        .map_err(|_| "capability status lock is poisoned".to_owned())
                        .map(|mut state| state.record_success(catalog.generation, catalog.digest));
                    if let Err(message) = update {
                        report_controller_worker_failure(
                            events,
                            custody,
                            ControllerResidentCauseV1::Worker(message),
                        );
                        return;
                    }
                    if !ready {
                        if let Err(cause) = events.send(WorkerEvent::Ready) {
                            if let Some(owner) = custody {
                                owner.close(ControllerResidentCauseV1::ReadySend(cause));
                            }
                            return;
                        }
                        ready = true;
                    }
                }
                Err(CycleFailure::Retryable(message)) => {
                    if let Ok(mut state) = capabilities.lock() {
                        state.record_retryable_failure(message.clone());
                    } else {
                        report_controller_worker_failure(
                            events,
                            custody,
                            ControllerResidentCauseV1::Worker(
                                "capability status lock is poisoned".to_owned(),
                            ),
                        );
                        return;
                    }
                    eprintln!("aos-sandboxd: reconciliation pending: {message}");
                }
                Err(CycleFailure::Fatal(message)) => {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Worker(message),
                    );
                    return;
                }
            }
            next_cycle = Instant::now() + RECONCILIATION_INTERVAL;
        }

        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        if Instant::now() >= next_attach_poll {
            original_attach::poll_one(
                controller,
                NodeId::from_bytes(node_id),
                sessions,
                attach_plan_signer,
                &mut attach_poll_cursor,
            );
            next_attach_poll = Instant::now() + ORIGINAL_ATTACH_POLL_INTERVAL;
        }

        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        if let Some(owner) = publisher_registration.as_mut() {
            if let Err(message) = owner.try_register(controller) {
                report_controller_worker_failure(
                    events,
                    custody,
                    ControllerResidentCauseV1::Worker(message),
                );
                return;
            }
        }

        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        let mut wait = next_cycle
            .min(next_attach_poll)
            .saturating_duration_since(Instant::now());
        if publisher_registration
            .as_ref()
            .is_some_and(|owner| owner.needs_registration())
        {
            wait = wait.min(Duration::from_millis(250));
        }
        match commands.recv_timeout(wait) {
            Ok(ControllerCommand::InspectGitRead { original, index, reply }) => {
                // Move the genuine returned owner into its destination before
                // any ended check, currentness gate or evaluator can fail.
                let (Some(inputs), Some(bootstrap), Some(terminal)) =
                    (git_read.as_mut(), cache_bootstrap.as_mut(), custody)
                else {
                    std::process::abort();
                };
                inputs.inspect(
                    controller, bootstrap,
                    #[cfg(target_os = "linux")]
                    coverage.as_mut(),
                    original, index, reply, terminal,
                );
            }
            #[cfg(target_os = "linux")]
            Ok(ControllerCommand::BootstrapPublicCapability { peer, idempotency_key, expires_at, reply })
                if coverage.is_some() =>
            {
                let (Some(owner), Some(bootstrap), Some(terminal)) =
                    (coverage.as_mut(), cache_bootstrap.as_deref_mut(), custody)
                else {
                    std::process::abort();
                };
                if owner.bootstrap_public_capability(
                    controller, bootstrap, peer, idempotency_key, expires_at, reply,
                ).is_err() {
                    terminal.terminate(ControllerResidentCauseV1::GitCoverage);
                }
            }
            Ok(command) => {
                if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
                    return;
                }
                if let Err(message) = handle_controller_command(
                    controller,
                    ownership,
                    attach_credentials,
                    attach_plan_signer,
                    NodeId::from_bytes(node_id),
                    sessions,
                    command,
                ) {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Worker(message),
                    );
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                report_controller_worker_failure(
                    events,
                    custody,
                    ControllerResidentCauseV1::Worker(
                        "controller command channel disconnected".to_owned(),
                    ),
                );
                return;
            }
        }
    }
}

fn run_controller_cycle(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &SharedControllerBrokerSessions,
    cold_start: bool,
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    guest_root_signer: Option<&ControllerBrokerPlanSignerV1>,
) -> Result<CatalogStatus, CycleFailure> {
    let pending_snapshot = {
        let mut sessions = sessions
            .lock()
            .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
        ensure_controller_broker_sessions(node_id, &mut sessions)?;
        if let Some(reservation) = resume_pending_guest_root(&mut sessions)? {
            let storage = authenticated_storage_inventory(controller, node_id, &mut sessions)?;
            if !controller
                .verify_guest_root_publication_readback(&storage, &reservation)
                .map_err(classify_guest_root_publication)?
            {
                return Err(CycleFailure::Retryable(
                    "Storage guest-root effect lacks fresh physical readback".to_owned(),
                ));
            }
        }
        if cold_start {
            audit_pending_atomic_snapshot_sources(controller, &mut sessions, true)?;
            let pending = controller
                .pending_atomic_snapshot_sources()
                .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
            if pending.len() > 1 {
                return Err(CycleFailure::Fatal(
                    "multiple Storage snapshot sources are pending".to_owned(),
                ));
            }
            pending.first().map(|(operation, _)| *operation)
        } else {
            None
        }
    };
    if let Some(operation) = pending_snapshot {
        controller
            .reconcile_operation_once(operation)
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        if !controller
            .pending_atomic_snapshot_sources()
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?
            .is_empty()
        {
            return Err(CycleFailure::Retryable(
                "original Storage snapshot source awaits terminal recovery".to_owned(),
            ));
        }
    }
    let mut state = (controller, sessions);
    pending_first_reconciliation_cycle(
        &mut state,
        |(controller, _)| {
            controller
                .pending_host_catalog()
                .map_err(|error| CycleFailure::Fatal(error.to_string()))
        },
        |(controller, sessions), pending| {
            let mut sessions = sessions
                .lock()
                .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
            publish_pending(controller, pending, node_id, &mut sessions).map(|_| ())
        },
        |(controller, _)| {
            controller
                .reconcile_quantum()
                .map(|_| ())
                .map_err(|error| CycleFailure::Fatal(error.to_string()))
        },
        |(controller, sessions)| {
            let mut sessions = sessions
                .lock()
                .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
            audit_pending_atomic_snapshot_sources(controller, &mut sessions, false)?;
            refresh_catalog(
                controller,
                node_id,
                &mut sessions,
                guest_root_pins,
                guest_root_signer,
            )
        },
    )
}

fn audit_pending_atomic_snapshot_sources(
    controller: &mut ProductionController,
    sessions: &mut ControllerBrokerSessions,
    before_reconciliation: bool,
) -> Result<(), CycleFailure> {
    // Historical group success may recover from a fresh read-only status only
    // when Storage attests the original protected post-head is still current.
    // An absent or incomplete group has no such authority.
    let completed = if before_reconciliation {
        controller
            .completed_atomic_snapshot_source_request_ids()
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?
    } else {
        Vec::new()
    };
    let pending = controller
        .pending_atomic_snapshot_sources()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    if pending.is_empty() && completed.is_empty() {
        return Ok(());
    }
    if pending.iter().any(|(_, source)| matches!(source,
        aos_sandbox::lifecycle::LifecycleAtomicSnapshotSourceRecoveryV1::OriginalPrerequisite { .. }))
    {
        return Err(CycleFailure::Fatal(
            "Snapshot derived original retains signing/dispatch debt; cold replacement is forbidden".to_owned(),
        ));
    }
    let storage = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Retryable("protected Storage session is unavailable".to_owned())
    })?;
    for request_id in completed {
        storage
            .retire_atomic_snapshot_archive(request_id)
            .map_err(|error| CycleFailure::Retryable(format!("{error:?}")))?;
    }
    for (_, source) in pending {
        let aos_sandbox::lifecycle::LifecycleAtomicSnapshotSourceRecoveryV1::Pending {
            request_id,
            request_packet,
            predecessor_packet,
            session,
            checkpoint,
        } = source
        else {
            return Err(CycleFailure::Fatal(
                "pending Storage source scan returned a terminal record".to_owned(),
            ));
        };
        let history = storage
            .recover_verified_atomic_snapshot_history(
                request_id,
                request_packet,
                predecessor_packet,
                session,
                checkpoint,
            )
            .map_err(|error| CycleFailure::Retryable(format!("{error:?}")))?;
        if !matches!(
            history.view(),
            HistoricalAtomicStorageHistoryDataV1::Complete { .. }
                | HistoricalAtomicStorageHistoryDataV1::GroupCommitted { .. }
        ) {
            return Err(CycleFailure::Retryable(
                "pending Storage source lacks a verified group result".to_owned(),
            ));
        }
        storage
            .archive_verified_atomic_snapshot_history(
                request_id,
                request_packet,
                predecessor_packet,
                session,
                checkpoint,
            )
            .map_err(|error| CycleFailure::Retryable(format!("{error:?}")))?;
        if !before_reconciliation {
            return Err(CycleFailure::Retryable(
                "verified Storage source awaits lifecycle completion".to_owned(),
            ));
        }
    }
    // Reconciliation completes the source before catalog refresh can install
    // a new Storage request and roll this old terminal history forward.
    Ok(())
}

fn pending_first_reconciliation_cycle<State, Pending, Status, Error>(
    state: &mut State,
    recover: impl FnOnce(&mut State) -> Result<Option<Pending>, Error>,
    publish: impl FnOnce(&mut State, Pending) -> Result<(), Error>,
    reconcile: impl FnOnce(&mut State) -> Result<(), Error>,
    continue_cycle: impl FnOnce(&mut State) -> Result<Status, Error>,
) -> Result<Status, Error> {
    if let Some(pending) = recover(state)? {
        publish(state, pending)?;
    }

    reconcile(state)?;
    continue_cycle(state)
}

fn ensure_controller_broker_sessions(
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<(), CycleFailure> {
    // Reconnect must not release the original terminal and append/post results.
    if sessions.host.as_ref().is_some_and(ControllerHostPublication::has_execution_publication_debt) {
        if let Some(worker) = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade) {
            worker.close(ControllerResidentCauseV1::Closed("original execution publication remains occupied"));
        }
        return Err(CycleFailure::Fatal("original execution publication remains occupied".to_owned()));
    }
    if sessions.storage.as_ref().is_some_and(|storage| storage.has_pending_capture_candidate()
        || (storage.has_capture_candidate() && sessions.storage_root.requires_reconnect()))
    {
        if let Some(worker) = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade) {
            worker.close(ControllerResidentCauseV1::CaptureCandidate);
        }
        return Err(CycleFailure::Fatal("original capture candidate Session remains occupied".to_owned()));
    }
    if sessions.storage.as_ref().is_some_and(|storage| storage.has_pending_nix_generation()) {
        #[cfg(feature = "online-nix")]
        if let Some(worker) = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade) {
            worker.close(ControllerResidentCauseV1::NixGeneration);
        }
        return Err(CycleFailure::Fatal("original Nix generation Session remains occupied".to_owned()));
    }
    if sessions.storage.as_ref().is_some_and(|storage| storage.has_pending_output_registration()) {
        if let Some(worker) = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade) {
            worker.close(ControllerResidentCauseV1::OutputRegistration);
        }
        return Err(CycleFailure::Fatal(
            "resident original output registration is closed".to_owned(),
        ));
    }
    // Required failure closes before reconnect can release either the old
    // Storage session or the original guest-root exchange. No replacement
    // owner may overtake a failed/unfinished verified cold flight.
    if sessions
        .storage_cold
        .as_ref()
        .is_some_and(aos_sandbox_broker_session_security::controller_composition::RetainedStorageColdOpenV1::is_failed)
    {
        if let Some(worker) = sessions
            .storage_terminal
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            worker.close(ControllerResidentCauseV1::StorageCold);
        }
        return Err(CycleFailure::Fatal(
            "resident Storage cold admission is closed".to_owned(),
        ));
    }
    if sessions.storage_root.requires_reconnect() {
        sessions.storage = None;
        sessions.storage_root = guest_root::ControllerGuestRootExchangeV1::default();
    }
    if sessions
        .host
        .as_ref()
        .is_some_and(ControllerHostPublication::requires_reconnect)
    {
        sessions.host = None;
    }
    if sessions.host.is_none() {
        sessions.host = Some(ControllerHostPublication::new(connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            node_id,
        )?));
    }
    if sessions.mount.is_none() {
        sessions.mount = Some(
            crate::DormantMountLifecycleInventoryOwnerV1::from_protected_session(
                connect_controller_session(
                    crate::ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
                    node_id,
                )?,
            ),
        );
    }
    if sessions.storage.is_none() {
        if let Some(image) = sessions.launch_image.as_ref() {
            // A genuine Required image selects the SAME parent-held worker
            // destination, including when no Publisher was supplied.
            let worker = sessions
                .storage_terminal
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .ok_or_else(|| {
                    CycleFailure::Fatal(
                        "Required Storage has no resident Controller destination".to_owned(),
                    )
                })?;
            let session = connect_retained_controller_storage(
                node_id,
                image,
                &mut sessions.storage_cold,
                &worker,
                sessions.nix_generation_enabled,
            )?;
            sessions.storage = Some(
                crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(session),
            );
        } else {
            sessions.storage = Some(
                crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(
                    connect_controller_storage_session(
                        crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
                        node_id,
                        sessions.launch_image.as_ref(),
                    )?,
                ),
            );
        }
    }
    if sessions.network.is_none() {
        sessions.network = Some(
            crate::DormantNetworkLifecycleInventoryOwnerV1::from_protected_session(
                connect_controller_session(
                    crate::ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
                    node_id,
                )?,
            ),
        );
    }
    Ok(())
}

/// Borrows the actual fixed image and resident destination for one cold flight.
fn connect_retained_controller_storage(
    node_id: [u8; 16],
    image: &aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1,
    cold: &mut Option<aos_sandbox_broker_session_security::controller_composition::RetainedStorageColdOpenV1>,
    worker: &ControllerWorkerCustodyV1,
    nix_generation: bool,
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
        crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
    )
    .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let custody = custody
        .retain_launch_image(Some(image.clone()))
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let deadline = aos_sandbox_broker_session_security::controller_composition::OriginalBrokerColdDeadlineV1::controller()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;

    let result = if nix_generation {
        custody.connect_retained_nix_generation_storage_session(deadline, cold, node_id)
    } else {
        custody.connect_retained_output_storage_session(deadline, cold, node_id)
    };
    match result {
        Ok(session) => Ok(session),
        Err(error) if cold.is_some() => {
            worker.close(ControllerResidentCauseV1::StorageCold);
            // Diagnostic projection only: the typed cause, packets, writers,
            // physical owners and debt remain in the SAME cold slot.
            let diagnostic = cold.as_ref()
                .and_then(aos_sandbox_broker_session_security::controller_composition::RetainedStorageColdOpenV1::output_failure)
                .map(|cause| cause.to_string())
                .unwrap_or_else(|| error.to_string());
            Err(CycleFailure::Fatal(diagnostic))
        }
        Err(error) => Err(classify_protected_handshake_error(error)),
    }
}

/// Connects the original fixed Controller endpoint and validates its node.
///
/// # Errors
///
/// Returns the original protected handshake or node-validation classification.
pub(super) fn connect_controller_session(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    node_id: [u8; 16],
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    connect_controller_storage_session(endpoint, node_id, None)
}

fn connect_controller_storage_session(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    node_id: [u8; 16],
    launch_image: Option<&aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1>,
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(endpoint)
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let custody = custody
        .retain_launch_image(launch_image.cloned())
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let deadline = crate::production_deadline_after(Duration::from_secs(10))
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let mut session = if endpoint == crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient {
        custody.connect_output_client_session(deadline)
    } else {
        custody.connect_production_client_session(deadline)
    }.map_err(classify_protected_handshake_error)?;
    session
        .require_current_node(node_id)
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    Ok(session)
}

fn refresh_catalog(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    guest_root_signer: Option<&ControllerBrokerPlanSignerV1>,
) -> Result<CatalogStatus, CycleFailure> {
    // Mount and destination state participate in the controller-state digest
    // captured by Storage and Network, so acquire them first.
    let (mounts, destinations) = authenticated_mount_inventories(controller, node_id, sessions)?;
    let storage = authenticated_storage_inventory(controller, node_id, sessions)?;
    let storage = publish_guest_roots(
        controller,
        node_id,
        sessions,
        storage,
        guest_root_pins,
        guest_root_signer,
    )?;
    let network = authenticated_network_inventory(controller, node_id, sessions)?;

    match controller
        .prepare_host_catalog(storage, network, mounts, destinations)
        .map_err(classify_catalog_error)?
    {
        HostCatalogReconciliationV1::Current(current) => Ok(CatalogStatus {
            generation: current.generation(),
            digest: current.catalog_digest(),
        }),
        HostCatalogReconciliationV1::Publish(pending) => {
            publish_pending(controller, pending, node_id, sessions)
        }
    }
}

fn resume_pending_guest_root(
    sessions: &mut ControllerBrokerSessions,
) -> Result<
    Option<aos_sandbox::guest_root_publication::GuestRootPublicationReservationV1>,
    CycleFailure,
> {
    let Some(reservation) = sessions.storage_root.pending_reservation() else {
        return Ok(None);
    };
    let owner = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Retryable("retained Storage session is unavailable".to_owned())
    })?;
    let session = owner
        .guest_root_session()
        .map_err(classify_guest_root_effect)?;
    sessions
        .storage_root
        .resume(session)
        .map_err(classify_guest_root_effect)?
        .ok_or_else(|| {
            CycleFailure::Fatal("guest-root exchange lost retained effect".to_owned())
        })?;
    Ok(Some(reservation))
}

fn publish_guest_roots(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
    storage: aos_sandbox::DurableStorageResourceInventorySnapshotV1,
    pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    signer: Option<&ControllerBrokerPlanSignerV1>,
) -> Result<aos_sandbox::DurableStorageResourceInventorySnapshotV1, CycleFailure> {
    let Some(pins) = pins else {
        if storage.inventory().workspaces().is_empty() {
            return Ok(storage);
        }
        return Err(CycleFailure::Retryable(
            "pinned guest-root template credentials are unavailable".to_owned(),
        ));
    };
    let Some(reservation) = controller
        .reserve_guest_root_publication(&storage, NodeId::from_bytes(node_id), pins)
        .map_err(classify_guest_root_publication)?
    else {
        return Ok(storage);
    };
    let signer = signer.ok_or_else(|| {
        CycleFailure::Retryable("Storage guest-root plan signer is unavailable".to_owned())
    })?;
    let now = sample_ownership_clock()
        .map_err(|_| CycleFailure::Retryable("guest-root clock is unavailable".to_owned()))?
        .wall_seconds();
    let (plan, lease, lease_signature) = controller
        .prepare_guest_root_publication_plan(&reservation, NodeId::from_bytes(node_id), now)
        .map_err(classify_guest_root_publication)?
        .into_parts();
    let signed_plan = signer.sign_plan(plan, now).map_err(|_| {
        CycleFailure::Retryable("fresh Storage guest-root plan could not be signed".to_owned())
    })?;
    let owner = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Retryable("retained Storage session is unavailable".to_owned())
    })?;
    let session = owner
        .guest_root_session()
        .map_err(classify_guest_root_effect)?;
    sessions
        .storage_root
        .apply(session, reservation, &signed_plan, lease, lease_signature)
        .map_err(classify_guest_root_effect)?;

    // The response is not a readiness claim. Storage must independently
    // read back its workspace and report the exact physical proof again.
    let observed = authenticated_storage_inventory(controller, node_id, sessions)?;
    if !controller
        .verify_guest_root_publication_readback(&observed, &reservation)
        .map_err(classify_guest_root_publication)?
    {
        return Err(CycleFailure::Retryable(
            "Storage guest-root effect lacks fresh physical readback".to_owned(),
        ));
    }
    if controller
        .reserve_guest_root_publication(&observed, NodeId::from_bytes(node_id), pins)
        .map_err(classify_guest_root_publication)?
        .is_some()
    {
        return Err(CycleFailure::Retryable(
            "another workspace still needs guest-root publication".to_owned(),
        ));
    }
    Ok(observed)
}

fn classify_guest_root_effect(error: EffectFailure) -> CycleFailure {
    match error {
        EffectFailure::Retryable(message) => CycleFailure::Retryable(message),
        EffectFailure::Permanent(message) => CycleFailure::Fatal(message),
    }
}

fn classify_guest_root_publication(
    error: aos_sandbox::guest_root_publication::GuestRootPublicationErrorV1,
) -> CycleFailure {
    match error {
        aos_sandbox::guest_root_publication::GuestRootPublicationErrorV1::Unavailable => {
            CycleFailure::Retryable(error.to_string())
        }
        _ => CycleFailure::Fatal(error.to_string()),
    }
}

fn publish_pending(
    controller: &mut ProductionController,
    pending: aos_sandbox::DurablePendingHostCatalogV1,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<CatalogStatus, CycleFailure> {
    if sessions.host.is_none() {
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            node_id,
        )?;
        sessions.host = Some(ControllerHostPublication::new(session));
    }
    let publisher = sessions
        .host
        .as_mut()
        .ok_or_else(|| CycleFailure::Fatal("protected Host session was not retained".to_owned()))?;
    let draft = HostCatalogPublicationDraftV1::new(
        pending.canonical_catalog().to_vec(),
        pending.generation(),
    )
    .map_err(classify_publication_error)?;
    let outcome = publisher
        .publish(&draft)
        .map_err(classify_protected_publication_error)?;
    let current = controller
        .complete_authenticated_host_catalog_publication(pending, &outcome)
        .map_err(classify_catalog_error)?;
    Ok(CatalogStatus {
        generation: current.generation(),
        digest: current.catalog_digest(),
    })
}

fn authenticated_mount_inventories(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<
    (
        aos_sandbox::DurableMountInventorySnapshotV1,
        aos_sandbox::DurableDestinationSlotInventorySnapshotV1,
    ),
    CycleFailure,
> {
    if sessions.mount.is_none() {
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
            node_id,
        )?;
        sessions.mount =
            Some(crate::DormantMountLifecycleInventoryOwnerV1::from_protected_session(session));
    }
    let inventory = sessions.mount.as_mut().ok_or_else(|| {
        CycleFailure::Fatal("protected Mount session was not retained".to_owned())
    })?;
    let mount_fence = controller
        .begin_authenticated_mount_inventory()
        .map_err(classify_mount_error)?;
    let mounts = inventory
        .current_inventory_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let mounts = controller
        .complete_authenticated_mount_inventory(mount_fence, &mounts)
        .map_err(classify_mount_error)?;

    // The Mount snapshot commit precedes the destination observation's fence.
    let destination_fence = controller
        .begin_authenticated_destination_slot_inventory()
        .map_err(classify_mount_error)?;
    let destinations = inventory
        .current_destination_slot_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let destinations = controller
        .complete_authenticated_destination_slot_inventory(destination_fence, &destinations)
        .map_err(classify_mount_error)?;
    Ok((mounts, destinations))
}

fn authenticated_storage_inventory(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<aos_sandbox::DurableStorageResourceInventorySnapshotV1, CycleFailure> {
    if sessions.storage.is_none() {
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            node_id,
        )?;
        sessions.storage =
            Some(crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(session));
    }
    let inventory = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Fatal("protected Storage session was not retained".to_owned())
    })?;
    let fence = controller
        .begin_authenticated_storage_inventory()
        .map_err(classify_resource_error)?;
    let outcome = inventory
        .current_inventory_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;

    controller
        .complete_authenticated_storage_inventory(fence, &outcome)
        .map_err(classify_resource_error)
}

fn authenticated_network_inventory(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<aos_sandbox::DurableNetworkResourceInventorySnapshotV1, CycleFailure> {
    if sessions.network.is_none() {
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
            node_id,
        )?;
        sessions.network =
            Some(crate::DormantNetworkLifecycleInventoryOwnerV1::from_protected_session(session));
    }
    let inventory = sessions.network.as_mut().ok_or_else(|| {
        CycleFailure::Fatal("protected Network session was not retained".to_owned())
    })?;
    let fence = controller
        .begin_authenticated_network_inventory()
        .map_err(classify_resource_error)?;
    let outcome = inventory
        .current_inventory_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;

    controller
        .complete_authenticated_network_inventory(fence, &outcome)
        .map_err(classify_resource_error)
}

fn classify_protected_publication_error(error: ControllerHostPublicationError) -> CycleFailure {
    // Only explicit retained recovery permits another cycle. A deadline or
    // protocol failure must not become permission to mint a new request.
    classified_failure(
        matches!(error, ControllerHostPublicationError::RecoveryPending),
        error,
    )
}

fn classify_mount_error(error: MountAttemptError) -> CycleFailure {
    let retryable = match &error {
        MountAttemptError::BrokerRejected { retryable, .. } => *retryable,
        MountAttemptError::Preparation(preparation) => retryable_mount_preparation(preparation),
        MountAttemptError::Transport(transport) => retryable_transport(transport),
        MountAttemptError::Kernel(kernel) => retryable_kernel(kernel),
        MountAttemptError::CorruptState
        | MountAttemptError::Conflict
        | MountAttemptError::Capacity
        | MountAttemptError::Deadline
        | MountAttemptError::MountIdentity
        | MountAttemptError::Protocol(_)
        | MountAttemptError::Current(_)
        | MountAttemptError::NamespaceTarget(_)
        | MountAttemptError::Journal(_) => false,
    };

    classified_failure(retryable, error)
}

fn classify_protected_handshake_error(
    error: crate::DormantBrokerSessionHandshakeErrorV1,
) -> CycleFailure {
    use crate::DormantBrokerSessionHandshakeErrorV1 as HandshakeError;

    let retryable = match &error {
        HandshakeError::Transport | HandshakeError::Deadline => true,
        HandshakeError::EndpointRole
        | HandshakeError::Protected(_)
        | HandshakeError::RemoteInvalid
        | HandshakeError::KernelEvidence => false,
    };
    classified_failure(retryable, error)
}

fn classify_resource_error(error: ResourceInventoryError) -> CycleFailure {
    let retryable = match &error {
        ResourceInventoryError::Deadline => true,
        ResourceInventoryError::Kernel(kernel) => retryable_kernel(kernel),
        ResourceInventoryError::BrokerRejected { retryable, .. } => *retryable,
        ResourceInventoryError::Transport(transport) => retryable_transport(transport),
        ResourceInventoryError::CorruptState
        | ResourceInventoryError::Conflict
        | ResourceInventoryError::Capacity
        | ResourceInventoryError::EntropyUnavailable
        | ResourceInventoryError::ServiceIdentity
        | ResourceInventoryError::Protocol(_)
        | ResourceInventoryError::Journal(_)
        | ResourceInventoryError::Io(_) => false,
    };

    classified_failure(retryable, error)
}

fn classify_catalog_error(error: HostCatalogReconciliationError) -> CycleFailure {
    if let HostCatalogReconciliationError::Publication(publication) = error {
        return classify_publication_error(publication);
    }

    let retryable = matches!(
        error,
        HostCatalogReconciliationError::InventoryConflict
            | HostCatalogReconciliationError::IncompleteResources
    );
    classified_failure(retryable, error)
}

fn classify_publication_error(error: HostCatalogPublicationError) -> CycleFailure {
    let retryable = match &error {
        HostCatalogPublicationError::Deadline => true,
        HostCatalogPublicationError::Kernel(kernel) => retryable_kernel(kernel),
        HostCatalogPublicationError::BrokerRejected { retryable, .. } => *retryable,
        HostCatalogPublicationError::Transport(transport) => retryable_transport(transport),
        HostCatalogPublicationError::InvalidDraft
        | HostCatalogPublicationError::EntropyUnavailable
        | HostCatalogPublicationError::HostIdentity
        | HostCatalogPublicationError::ReceiptMismatch
        | HostCatalogPublicationError::Protocol(_)
        | HostCatalogPublicationError::CatalogFile(_)
        | HostCatalogPublicationError::Io(_) => false,
    };

    classified_failure(retryable, error)
}

fn retryable_mount_preparation(error: &MountCatalogPreparationError) -> bool {
    match error {
        MountCatalogPreparationError::Deadline => true,
        MountCatalogPreparationError::Kernel(kernel) => retryable_kernel(kernel),
        MountCatalogPreparationError::Transport(transport) => retryable_transport(transport),
        MountCatalogPreparationError::InvalidIntent
        | MountCatalogPreparationError::EntropyUnavailable
        | MountCatalogPreparationError::MountIdentity
        | MountCatalogPreparationError::ReplayMismatch
        | MountCatalogPreparationError::HostAuthority(_)
        | MountCatalogPreparationError::CurrentTarget(_)
        | MountCatalogPreparationError::Semantics(_)
        | MountCatalogPreparationError::DispatchTemplate(_)
        | MountCatalogPreparationError::Protocol(_)
        | MountCatalogPreparationError::Io(_) => false,
    }
}

fn retryable_transport(error: &SeqpacketError) -> bool {
    matches!(
        error,
        SeqpacketError::WouldBlock | SeqpacketError::Interrupted | SeqpacketError::Closed
    ) || matches!(error, SeqpacketError::Kernel(kernel) if retryable_kernel(kernel))
}

fn retryable_kernel(error: &LinuxError) -> bool {
    matches!(
        error,
        LinuxError::Syscall { .. } | LinuxError::DeadlineExceeded { .. }
    )
}

fn classified_failure(error_is_retryable: bool, error: impl ToString) -> CycleFailure {
    if error_is_retryable {
        CycleFailure::Retryable(error.to_string())
    } else {
        CycleFailure::Fatal(error.to_string())
    }
}

#[derive(Clone, Copy)]
struct CatalogStatus {
    generation: u64,
    digest: ObjectDigest,
}

/// Classifies the original reconciliation refusal without granting readiness.
pub(super) enum CycleFailure {
    Retryable(String),
    Fatal(String),
}

/// Carries the original worker readiness or negative terminal notification.
pub(super) enum WorkerEvent {
    Ready,
    Fatal(String),
    ResidentFailure,
}
