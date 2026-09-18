//! Guardian-first broker lifecycle and recovery tests.

use super::*;
use crate::state::transition::{CompositeStopPhase, CompositeStopTarget};

fn configured_broker(
    fixture: &AuthorityFixture,
    credentials: &Path,
    store: GuardianRecordingStore,
    worker: GuardianWorker,
) -> HostBroker<FixedCatalog, GuardianRecordingStore, GuardianWorker> {
    HostBroker::open(
        FixedCatalog,
        store,
        worker,
        Some(nspawn()),
        fixture.protected_authority(credentials),
    )
    .unwrap()
    .with_guardian(GuardianConfig::for_tests().unwrap())
}

fn completed_guardian_state(
    fixture: &AuthorityFixture,
    authority: &HostAuthorityV1,
) -> (HostState, Vec<u8>, ValidatedUntrustedAuthorizationArtifacts) {
    let (request_bytes, artifacts) = fixture.guardian_request_and_artifacts(61);
    let request =
        decode_runtime_request(&request_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
            .unwrap();
    let request_id = *request.header().request_id();
    let request_digest: [u8; 32] = Sha256::digest(&request_bytes).into();
    let admitted = authority
        .admit(
            &artifacts,
            &request,
            &request_bytes,
            ProtocolVersion::new(1, 0),
            &clock(),
            None,
        )
        .unwrap();
    let context = ExecutionContext {
        action: HostAction::Launch,
        request_id,
        request_digest,
        sandbox_id: *request.fence().sandbox_id(),
        incarnation_id: *request.fence().incarnation_id(),
        assignment_epoch: request.fence().assignment_epoch(),
        desired_generation: request.fence().desired_generation(),
        assignment_digest: *request.fence().assignment_digest(),
        receipt_present: false,
    };
    let execution = DurableExecution::guardian_fixture(context);
    let sealed_fence = authority
        .seal_fence(request.fence().sandbox_id(), &admitted.fence)
        .unwrap();
    let sealed_effect = authority
        .seal_effect(&request_id, &admitted.effect)
        .unwrap();
    let mut state = HostState::default();
    state
        .admit_guardian(
            request.fence(),
            request_id,
            request_digest,
            execution,
            sealed_fence,
            &admitted,
            sealed_effect,
            authority,
        )
        .unwrap();
    state
        .set_guardian_phase(
            &request_id,
            GuardianLaunchPhase::Complete {
                guardian_invocation: [62; 16],
                payload_invocation: [63; 16],
                observation_sequence: 1,
                worker_proof: GuardianWorker::runtime_proof(),
            },
            authority,
        )
        .unwrap();
    let receipt = vec![61];
    let completed = admitted.effect.complete(receipt.clone()).unwrap();
    let sealed_completed = authority.seal_effect(&request_id, &completed).unwrap();
    state
        .complete(request_id, request_digest, sealed_completed, receipt)
        .unwrap();
    state.validate_authenticated(authority).unwrap();
    (state, request_bytes, artifacts)
}

fn lifecycle_request(
    request_id: u8,
    generation: u64,
    digest: u8,
    action: RuntimeAction,
) -> Vec<u8> {
    request_with_action(request_id, generation, digest, action)
}

fn composite_stop_request(request_id: u8, generation: u64, digest: u8) -> Vec<u8> {
    let mut request = ApplyRuntimeRequest::decode_from_slice(&request_at_protocol(
        request_id,
        2,
        ProtocolVersion::new(1, 0),
    ))
    .unwrap();
    let fence = request.fence.get_or_insert_default();
    fence.desired_generation = generation;
    fence.assignment_digest = vec![digest; 32];
    request.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
    request.launch_plan = None.into();
    request.encode_to_vec()
}

fn assert_absent_receipt(receipt: &[u8]) {
    let observation = RuntimeObservation::decode_from_slice(receipt).unwrap();
    assert_eq!(
        observation.state.as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
}

fn live_guardian_worker(store: GuardianRecordingStore, binding: [u8; 32]) -> GuardianWorker {
    let worker = GuardianWorker::new(store);
    *worker.binding.lock().unwrap() = Some(binding);
    worker.guardian_alive.store(true, Ordering::SeqCst);
    worker.payload_started.store(true, Ordering::SeqCst);
    worker
}

#[test]
fn pending_guardian_lineage_rejects_even_when_runtime_pins_are_retained() {
    assert!(matches!(
        select_completed_guardian_scope(GuardianLineage::Shadowed, true),
        Err(HostError::UnknownHandle)
    ));
}

#[tokio::test]
async fn retained_payload_scope_sandwich_rejects_guardian_death_and_replacement() {
    let fixture = AuthorityFixture::new();
    let authority = fixture.authority();
    let (state, request, _) = completed_guardian_state(&fixture, &authority);
    let GuardianLineage::Complete(lineage) = state
        .completed_guardian_lineage(&[2; 16], &[3; 16], &authority)
        .unwrap()
    else {
        panic!("completed Guardian launch lost its lineage");
    };
    let worker = live_guardian_worker(GuardianRecordingStore::default(), lineage.binding);
    let identity = runtime_identity(&request);

    guard_payload_scope_refresh(&worker, &identity, Some(lineage), || async {
        worker.ordering_events.lock().unwrap().push("refresh_scope");
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(
        worker.ordering_events.lock().unwrap().as_slice(),
        ["observe_guardian", "refresh_scope", "observe_guardian"]
    );

    worker.ordering_events.lock().unwrap().clear();
    worker.guardian_alive.store(false, Ordering::SeqCst);
    let refreshed = AtomicBool::new(false);
    assert!(
        guard_payload_scope_refresh(&worker, &identity, Some(lineage), || async {
            refreshed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .is_err()
    );
    assert!(!refreshed.load(Ordering::SeqCst));

    worker.guardian_alive.store(true, Ordering::SeqCst);
    *worker.binding.lock().unwrap() = Some([129; 32]);
    assert!(
        guard_payload_scope_refresh(&worker, &identity, Some(lineage), || async { Ok(()) })
            .await
            .is_err()
    );

    *worker.binding.lock().unwrap() = Some(lineage.binding);
    assert!(
        guard_payload_scope_refresh(&worker, &identity, Some(lineage), || async {
            worker.guardian_alive.store(false, Ordering::SeqCst);
            Ok(())
        })
        .await
        .is_err()
    );

    // A runtime without completed Guardian lineage uses the payload-only
    // live-pin rule and does not invoke the Guardian observer.
    worker.ordering_events.lock().unwrap().clear();
    guard_payload_scope_refresh(&worker, &identity, None, || async { Ok(()) })
        .await
        .unwrap();
    assert!(worker.ordering_events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn completed_freeze_restart_reaches_exact_payload_scope_recovery() {
    let fixture = AuthorityFixture::new();
    let authority = fixture.authority();
    let (state, _, _) = completed_guardian_state(&fixture, &authority);
    let GuardianLineage::Complete(lineage) = state
        .completed_guardian_lineage(&[2; 16], &[3; 16], &authority)
        .unwrap()
    else {
        panic!("completed Guardian launch lost its lineage");
    };
    let store = GuardianRecordingStore::default();
    *store.state.lock().unwrap() = state;
    let worker = live_guardian_worker(store.clone(), lineage.binding);
    let mut broker = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        authority,
    )
    .unwrap();
    let freeze = lifecycle_request(62, 2, 5, RuntimeAction::RUNTIME_ACTION_FREEZE);
    apply(&mut broker, &fixture, &freeze).await.unwrap();
    drop(broker);

    worker.ordering_events.lock().unwrap().clear();
    let mut reopened = HostBroker::open(
        FixedCatalog,
        store,
        worker.clone(),
        Some(nspawn()),
        fixture.authority(),
    )
    .unwrap();
    let error = reopened
        .recover_completed_runtime_scope(runtime_identity(&freeze))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("completed runtime recovery omitted retained payload pins")
    );
    assert!(
        worker
            .ordering_events
            .lock()
            .unwrap()
            .starts_with(&["recover_payload", "observe_guardian"])
    );
}

async fn run_freeze_thaw_composite_stop(reopen_before_stop: bool) {
    let fixture = AuthorityFixture::new();
    let authority = fixture.authority();
    let (state, _, _) = completed_guardian_state(&fixture, &authority);
    let GuardianLineage::Complete(lineage) = state
        .completed_guardian_lineage(&[2; 16], &[3; 16], &authority)
        .unwrap()
    else {
        panic!("completed Guardian launch lost its lineage");
    };
    let store = GuardianRecordingStore::default();
    *store.state.lock().unwrap() = state;
    let worker = live_guardian_worker(store.clone(), lineage.binding);
    let guardian = GuardianConfig::for_tests().unwrap();
    let mut broker = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian.clone());
    let freeze = lifecycle_request(62, 2, 5, RuntimeAction::RUNTIME_ACTION_FREEZE);
    let thaw = lifecycle_request(63, 3, 6, RuntimeAction::RUNTIME_ACTION_THAW);
    apply(&mut broker, &fixture, &freeze).await.unwrap();
    apply(&mut broker, &fixture, &thaw).await.unwrap();

    if reopen_before_stop {
        drop(broker);
        broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap()
        .with_guardian(guardian);
    }

    let stop = composite_stop_request(64, 4, 7);
    let receipt = apply_protocol(&mut broker, &fixture, &stop, ProtocolVersion::new(1, 0))
        .await
        .unwrap();
    assert_absent_receipt(&receipt);
    assert_eq!(
        worker.stop_roles.lock().unwrap().as_slice(),
        [ExactUnitRole::Payload, ExactUnitRole::Guardian]
    );
    let completed = store.load().unwrap();
    let record = completed.composite_stop_execution(&[64; 16]).unwrap();
    let CompositeStopTarget::GuardianComposite {
        source_launch_request_id,
        launch_binding,
        ..
    } = record.target
    else {
        panic!("composite Stop lost its Guardian launch lineage");
    };
    assert_eq!(source_launch_request_id, [61; 16]);
    assert_eq!(launch_binding, lineage.binding);
    assert!(matches!(record.phase, CompositeStopPhase::Complete { .. }));
}

#[tokio::test]
async fn freeze_thaw_composite_stop_uses_launch_lineage_before_and_after_reopen() {
    run_freeze_thaw_composite_stop(false).await;
    run_freeze_thaw_composite_stop(true).await;
}

#[tokio::test]
async fn completed_kill_shadows_payload_scope_recovery() {
    for (request_id, action) in [(63, RuntimeAction::RUNTIME_ACTION_KILL)] {
        let fixture = AuthorityFixture::new();
        let authority = fixture.authority();
        let (state, _, _) = completed_guardian_state(&fixture, &authority);
        let GuardianLineage::Complete(lineage) = state
            .completed_guardian_lineage(&[2; 16], &[3; 16], &authority)
            .unwrap()
        else {
            panic!("completed Guardian launch lost its lineage");
        };
        let store = GuardianRecordingStore::default();
        *store.state.lock().unwrap() = state;
        let worker = live_guardian_worker(store.clone(), lineage.binding);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker.clone(),
            Some(nspawn()),
            authority,
        )
        .unwrap();
        let terminal = lifecycle_request(request_id, 2, 5, action);
        apply(&mut broker, &fixture, &terminal).await.unwrap();
        drop(broker);

        worker.ordering_events.lock().unwrap().clear();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store,
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(matches!(
            reopened
                .recover_completed_runtime_scope(runtime_identity(&terminal))
                .await,
            Err(HostError::UnknownHandle)
        ));
        assert!(worker.ordering_events.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn guardian_reducer_failed_absent_start_completes_durable_compensation() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    worker.guardian_start_mode.store(1, Ordering::SeqCst);
    let starts = Arc::clone(&worker.starts);
    let payload_effects = Arc::clone(&worker.payload_effects);
    let stop_roles = Arc::clone(&worker.stop_roles);
    let mut broker = configured_broker(&fixture, credentials.path(), store.clone(), worker);
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

    let receipt = broker
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();

    assert_absent_receipt(&receipt);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 0);
    assert!(stop_roles.lock().unwrap().is_empty());
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
}

#[tokio::test]
async fn composite_stop_accepts_an_exactly_absent_compensated_launch() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    worker.guardian_start_mode.store(1, Ordering::SeqCst);
    let mut broker = configured_broker(&fixture, credentials.path(), store.clone(), worker);
    let (launch, launch_artifacts) = fixture.guardian_request_and_artifacts(61);
    broker
        .apply_runtime(
            &launch,
            &launch_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();

    let mut stop = ApplyRuntimeRequest::decode_from_slice(&request_at_protocol(
        62,
        2,
        ProtocolVersion::new(1, 0),
    ))
    .unwrap();
    stop.fence.get_or_insert_default().desired_generation = 2;
    stop.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
    stop.launch_plan = None.into();
    let stop = stop.encode_to_vec();
    let stop_artifacts = fixture.artifacts(&stop, 1);

    let receipt = broker
        .apply_runtime(
            &stop,
            &stop_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();
    assert_absent_receipt(&receipt);
    let stopped = store.load().unwrap();
    let stop_record = stopped.composite_stop_execution(&[62; 16]).unwrap();
    assert_eq!(stop_record.target, CompositeStopTarget::Absent);
    assert!(matches!(
        stop_record.phase,
        CompositeStopPhase::Complete { .. }
    ));
}

#[tokio::test]
async fn guardian_reducer_ambiguous_absent_start_expires_on_replay() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    worker.guardian_start_mode.store(3, Ordering::SeqCst);
    let starts = Arc::clone(&worker.starts);
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);
    let mut interrupted =
        configured_broker(&fixture, credentials.path(), store.clone(), worker.clone());

    assert!(matches!(
        interrupted
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await,
        Err(HostError::Worker(_))
    ));
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::GuardianStartIssued
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    drop(interrupted);

    let mut recovered = configured_broker(&fixture, credentials.path(), store.clone(), worker);
    let receipt = recovered
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock_at(301, TEST_BOOTTIME_NANOSECONDS + 151_000_000_000)),
        )
        .await
        .unwrap();

    assert_absent_receipt(&receipt);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
}

#[tokio::test]
async fn guardian_reducer_terminal_start_persists_cleanup_before_replay_stop() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    worker.guardian_start_mode.store(2, Ordering::SeqCst);
    worker.fail_stop_once.store(true, Ordering::SeqCst);
    let starts = Arc::clone(&worker.starts);
    let stop_roles = Arc::clone(&worker.stop_roles);
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);
    let mut interrupted =
        configured_broker(&fixture, credentials.path(), store.clone(), worker.clone());

    assert!(matches!(
        interrupted
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await,
        Err(HostError::Worker(_))
    ));
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::CleanupIssued { .. }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert!(stop_roles.lock().unwrap().is_empty());
    drop(interrupted);

    worker.residual_stop_once.store(true, Ordering::SeqCst);
    let mut recovered = configured_broker(&fixture, credentials.path(), store.clone(), worker);
    let receipt = recovered
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();

    assert_absent_receipt(&receipt);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        stop_roles.lock().unwrap().as_slice(),
        [ExactUnitRole::Guardian]
    );
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
}

#[tokio::test]
async fn guardian_reducer_post_payload_expiry_or_death_enters_exact_cleanup() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    for guardian_dies in [false, true] {
        let fixture = AuthorityFixture::new();
        let credentials = tempfile::tempdir().unwrap();
        let store = GuardianRecordingStore::default();
        let worker = GuardianWorker::new(store.clone());
        worker
            .kill_guardian_after_payload_start
            .store(guardian_dies, Ordering::SeqCst);
        let payload_effects = Arc::clone(&worker.payload_effects);
        let stop_roles = Arc::clone(&worker.stop_roles);
        let mut broker = configured_broker(&fixture, credentials.path(), store.clone(), worker);
        let (request, artifacts) = fixture.guardian_request_and_artifacts(61);
        let clock_calls = AtomicUsize::new(0);

        let receipt = broker
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || {
                    let call = clock_calls.fetch_add(1, Ordering::SeqCst) + 1;
                    if !guardian_dies && call >= 7 {
                        Ok(clock_at(301, TEST_BOOTTIME_NANOSECONDS + 151_000_000_000))
                    } else {
                        Ok(clock())
                    }
                },
            )
            .await
            .unwrap();

        assert_absent_receipt(&receipt);
        assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
        let roles = stop_roles.lock().unwrap();
        assert_eq!(roles.first(), Some(&ExactUnitRole::Payload));
        if guardian_dies {
            assert_eq!(roles.as_slice(), [ExactUnitRole::Payload]);
        } else {
            assert_eq!(
                roles.as_slice(),
                [ExactUnitRole::Payload, ExactUnitRole::Guardian]
            );
        }
        assert!(matches!(
            store
                .load()
                .unwrap()
                .guardian_attempt(&[61; 16])
                .unwrap()
                .phase,
            GuardianLaunchPhase::Compensated { .. }
        ));
    }
}

#[tokio::test]
async fn guardian_reducer_failed_payload_with_both_units_absent_completes() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    worker.fail_payload_start.store(true, Ordering::SeqCst);
    worker
        .disappear_after_payload_start
        .store(true, Ordering::SeqCst);
    worker
        .kill_guardian_after_payload_start
        .store(true, Ordering::SeqCst);
    let stop_roles = Arc::clone(&worker.stop_roles);
    let mut broker = configured_broker(&fixture, credentials.path(), store.clone(), worker);
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

    let receipt = broker
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();

    assert_absent_receipt(&receipt);
    assert!(stop_roles.lock().unwrap().is_empty());
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
}

#[tokio::test]
async fn root_guardian_apply_completes_bound_payload_and_replays_receipt() {
    if !rustix::process::geteuid().is_root() {
        eprintln!(
            "SKIP root_guardian_apply_completes_bound_payload_and_replays_receipt: root required"
        );
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let authority = fixture.protected_authority(credentials.path());
    let guardian = GuardianConfig::for_tests().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    let starts = worker.starts.clone();
    let payload_effects = worker.payload_effects.clone();
    let stop_roles = worker.stop_roles.clone();
    let mut broker = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian.clone());
    assert!(broker.launch_available());

    let (guardian_request, artifacts) = fixture.guardian_request_and_artifacts(61);
    let receipt = broker
        .apply_runtime(
            &guardian_request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    {
        let phases = store.phases.lock().unwrap();
        assert_eq!(phases.len(), 6);
        assert!(matches!(phases[0], GuardianLaunchPhase::Authorized));
        assert!(matches!(
            phases[1],
            GuardianLaunchPhase::GuardianStartIssued
        ));
        assert!(matches!(
            phases[2],
            GuardianLaunchPhase::GuardianReady { .. }
        ));
        assert!(matches!(
            phases[3],
            GuardianLaunchPhase::PayloadStartIssued { .. }
        ));
        assert!(matches!(
            phases[4],
            GuardianLaunchPhase::PayloadVerified { .. }
        ));
        assert!(matches!(phases[5], GuardianLaunchPhase::Complete { .. }));
    }
    let request_digest: [u8; 32] = Sha256::digest(&guardian_request).into();
    assert_eq!(
        store
            .load()
            .unwrap()
            .query_effect(&[61; 16], request_digest)
            .unwrap(),
        RuntimeEffectQuery::Complete(receipt.clone())
    );

    assert_eq!(
        broker
            .apply_runtime(
                &guardian_request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);

    let mut stop = ApplyRuntimeRequest::decode_from_slice(&request_at_protocol(
        62,
        2,
        ProtocolVersion::new(1, 0),
    ))
    .unwrap();
    stop.fence.get_or_insert_default().desired_generation = 2;
    stop.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
    stop.launch_plan = None.into();
    let stop_request = stop.encode_to_vec();
    let stop_artifacts = fixture.artifacts(&stop_request, 1);
    let stop_receipt = broker
        .apply_runtime(
            &stop_request,
            &stop_artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();
    let stopped = RuntimeObservation::decode_from_slice(&stop_receipt).unwrap();
    assert_eq!(
        stopped.state.as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    assert_eq!(
        stop_roles.lock().unwrap().as_slice(),
        [ExactUnitRole::Payload, ExactUnitRole::Guardian]
    );
    assert_eq!(
        broker
            .apply_runtime(
                &stop_request,
                &stop_artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
            .unwrap(),
        stop_receipt
    );
    assert_eq!(stop_roles.lock().unwrap().len(), 2);

    println!("AOS_GUARDIAN_BROKER_ROOT_INTEGRATION_OK");
}

#[tokio::test]
async fn guardian_completion_does_not_commit_before_runtime_retention_succeeds() {
    if !rustix::process::geteuid().is_root() {
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);
    let mut broker = configured_broker(&fixture, credentials.path(), store.clone(), worker);
    broker.fail_runtime_retention = true;

    assert!(matches!(
        broker
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await,
        Err(HostError::Worker(message)) if message == "injected runtime retention failure"
    ));
    let interrupted = store.load().unwrap();
    assert!(matches!(
        interrupted.guardian_attempt(&[61; 16]).unwrap().phase,
        GuardianLaunchPhase::PayloadVerified { .. }
    ));
    assert!(matches!(
        interrupted
            .query_effect(&[61; 16], Sha256::digest(&request).into())
            .unwrap(),
        RuntimeEffectQuery::Pending
    ));

    let receipt = broker
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();
    assert_eq!(
        RuntimeObservation::decode_from_slice(&receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_READY)
    );
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Complete { .. }
    ));
}

#[tokio::test]
async fn root_guardian_recovers_payload_start_from_observation_only_proof() {
    if !rustix::process::geteuid().is_root() {
        eprintln!(
            "SKIP root_guardian_recovers_payload_start_from_observation_only_proof: root required"
        );
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let guardian = GuardianConfig::for_tests().unwrap();
    let store = GuardianRecordingStore::default();
    store
        .fail_payload_verified_commit
        .store(true, Ordering::SeqCst);
    let worker = GuardianWorker::new(store.clone());
    let payload_effects = worker.payload_effects.clone();
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

    let mut interrupted = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        fixture.protected_authority(credentials.path()),
    )
    .unwrap()
    .with_guardian(guardian.clone());
    assert!(matches!(
        interrupted
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await,
        Err(HostError::State(_))
    ));
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::PayloadStartIssued { .. }
    ));
    drop(interrupted);

    worker.ordering_events.lock().unwrap().clear();
    let ordering_events = Arc::clone(&worker.ordering_events);
    let clock_events = Arc::clone(&ordering_events);
    let authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let mut recovered = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker,
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);
    let receipt = recovered
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || {
                clock_events.lock().unwrap().push("clock");
                Ok(clock())
            },
        )
        .await
        .unwrap();

    let events = ordering_events.lock().unwrap();
    assert_eq!(
        events.as_slice(),
        [
            "clock",
            "prove_payload",
            "observe_guardian",
            "clock",
            "prove_payload",
            "observe_guardian",
            "clock",
        ],
        "recovery must retain admission and both observation/freshness phases"
    );
    drop(events);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        RuntimeObservation::decode_from_slice(&receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_READY)
    );
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Complete { .. }
    ));
    println!("AOS_GUARDIAN_RECOVERED_PROOF_ROOT_OK");
}

#[tokio::test]
async fn root_guardian_recovered_proof_cannot_complete_after_lease_expiry() {
    if !rustix::process::geteuid().is_root() {
        eprintln!(
            "SKIP root_guardian_recovered_proof_cannot_complete_after_lease_expiry: root required"
        );
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let guardian = GuardianConfig::for_tests().unwrap();
    let store = GuardianRecordingStore::default();
    store
        .fail_payload_verified_commit
        .store(true, Ordering::SeqCst);
    let worker = GuardianWorker::new(store.clone());
    let payload_effects = worker.payload_effects.clone();
    let stop_roles = worker.stop_roles.clone();
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

    let mut interrupted = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        fixture.protected_authority(credentials.path()),
    )
    .unwrap()
    .with_guardian(guardian.clone());
    assert!(matches!(
        interrupted
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await,
        Err(HostError::State(_))
    ));
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::PayloadStartIssued { .. }
    ));
    drop(interrupted);

    worker.ordering_events.lock().unwrap().clear();
    let ordering_events = Arc::clone(&worker.ordering_events);
    let clock_events = Arc::clone(&ordering_events);
    let authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let mut recovered = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker,
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);
    let receipt = recovered
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || {
                clock_events.lock().unwrap().push("clock");
                Ok(clock_at(301, TEST_BOOTTIME_NANOSECONDS + 151_000_000_000))
            },
        )
        .await
        .unwrap();

    let events = ordering_events.lock().unwrap();
    assert_eq!(
        events.get(..4),
        Some(["clock", "prove_payload", "observe_guardian", "clock"].as_slice()),
        "recovery must admit before the observation/freshness phase: {events:?}"
    );
    drop(events);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        RuntimeObservation::decode_from_slice(&receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    assert_eq!(
        stop_roles.lock().unwrap().as_slice(),
        [ExactUnitRole::Payload, ExactUnitRole::Guardian]
    );
    let phases = store.phases.lock().unwrap();
    assert!(
        !phases
            .iter()
            .any(|phase| matches!(phase, GuardianLaunchPhase::Complete { .. }))
    );
    assert!(matches!(
        phases.last(),
        Some(GuardianLaunchPhase::Compensated { .. })
    ));
    println!("AOS_GUARDIAN_RECOVERED_EXPIRED_ROOT_OK");
}

#[tokio::test]
async fn root_guardian_recovery_commits_compensation_when_both_units_are_absent() {
    if !rustix::process::geteuid().is_root() {
        eprintln!(
            "SKIP root_guardian_recovery_commits_compensation_when_both_units_are_absent: root required"
        );
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let guardian = GuardianConfig::for_tests().unwrap();
    let store = GuardianRecordingStore::default();
    store
        .fail_payload_verified_commit
        .store(true, Ordering::SeqCst);
    let worker = GuardianWorker::new(store.clone());
    let starts = worker.starts.clone();
    let payload_effects = worker.payload_effects.clone();
    let stop_roles = worker.stop_roles.clone();
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

    let mut interrupted = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        fixture.protected_authority(credentials.path()),
    )
    .unwrap()
    .with_guardian(guardian.clone());
    assert!(matches!(
        interrupted
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await,
        Err(HostError::State(_))
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::PayloadStartIssued { .. }
    ));
    drop(interrupted);

    worker.payload_started.store(false, Ordering::SeqCst);
    worker.guardian_alive.store(false, Ordering::SeqCst);
    let authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let mut recovered = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker,
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);
    let receipt = recovered
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();

    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert!(stop_roles.lock().unwrap().is_empty());
    assert_eq!(
        RuntimeObservation::decode_from_slice(&receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    assert!(matches!(
        store
            .load()
            .unwrap()
            .guardian_attempt(&[61; 16])
            .unwrap()
            .phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
    println!("AOS_GUARDIAN_BOTH_ABSENT_RECOVERY_ROOT_OK");
}

#[tokio::test]
async fn root_guardian_recovery_never_restarts_payload_that_disappears_during_proof() {
    if !rustix::process::geteuid().is_root() {
        eprintln!(
            "SKIP root_guardian_recovery_never_restarts_payload_that_disappears_during_proof: root required"
        );
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let guardian = GuardianConfig::for_tests().unwrap();
    let store = GuardianRecordingStore::default();
    store
        .fail_payload_verified_commit
        .store(true, Ordering::SeqCst);
    let worker = GuardianWorker::new(store.clone());
    let payload_effects = worker.payload_effects.clone();
    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

    let mut interrupted = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker.clone(),
        Some(nspawn()),
        fixture.protected_authority(credentials.path()),
    )
    .unwrap()
    .with_guardian(guardian.clone());
    assert!(
        interrupted
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
            .is_err()
    );
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    drop(interrupted);

    worker
        .disappear_during_payload_proof
        .store(true, Ordering::SeqCst);
    let authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
    let mut recovered = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker,
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);
    let receipt = recovered
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock_at(301, TEST_BOOTTIME_NANOSECONDS + 151_000_000_000)),
        )
        .await
        .unwrap();

    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        RuntimeObservation::decode_from_slice(&receipt)
            .unwrap()
            .state
            .as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    let phases = store.phases.lock().unwrap();
    assert!(
        !phases
            .iter()
            .any(|phase| matches!(phase, GuardianLaunchPhase::Complete { .. }))
    );
    assert!(matches!(
        phases.last(),
        Some(GuardianLaunchPhase::Compensated { .. })
    ));
    println!("AOS_GUARDIAN_RECOVERY_RACE_ROOT_OK");
}

#[tokio::test]
async fn root_payload_verified_recovery_requires_live_fresh_guardian_pair() {
    if !rustix::process::geteuid().is_root() {
        eprintln!(
            "SKIP root_payload_verified_recovery_requires_live_fresh_guardian_pair: root required"
        );
        return;
    }

    for (guardian_disappears, expired) in [(true, false), (false, true)] {
        let fixture = AuthorityFixture::new();
        let credentials = tempfile::tempdir().unwrap();
        let guardian = GuardianConfig::for_tests().unwrap();
        let store = GuardianRecordingStore::default();
        store.fail_complete_commit.store(true, Ordering::SeqCst);
        let worker = GuardianWorker::new(store.clone());
        let payload_effects = worker.payload_effects.clone();
        let (request, artifacts) = fixture.guardian_request_and_artifacts(61);

        let mut interrupted = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker.clone(),
            Some(nspawn()),
            fixture.protected_authority(credentials.path()),
        )
        .unwrap()
        .with_guardian(guardian.clone());
        assert!(
            interrupted
                .apply_runtime(
                    &request,
                    &artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert!(matches!(
            store
                .load()
                .unwrap()
                .guardian_attempt(&[61; 16])
                .unwrap()
                .phase,
            GuardianLaunchPhase::PayloadVerified { .. }
        ));
        assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
        drop(interrupted);

        if guardian_disappears {
            worker.guardian_alive.store(false, Ordering::SeqCst);
        }
        worker.ordering_events.lock().unwrap().clear();
        let ordering_events = Arc::clone(&worker.ordering_events);
        let clock_events = Arc::clone(&ordering_events);
        let authority = HostAuthorityV1::from_protected_directory(credentials.path()).unwrap();
        let mut recovered = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            authority,
        )
        .unwrap()
        .with_guardian(guardian);
        let receipt = recovered
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || {
                    clock_events.lock().unwrap().push("clock");
                    if expired {
                        Ok(clock_at(301, TEST_BOOTTIME_NANOSECONDS + 151_000_000_000))
                    } else {
                        Ok(clock())
                    }
                },
            )
            .await
            .unwrap();

        let events = ordering_events.lock().unwrap();
        assert_eq!(
            events.get(..4),
            Some(["clock", "prove_payload", "observe_guardian", "clock"].as_slice()),
            "recovery must admit before the observation/freshness phase: {events:?}"
        );
        drop(events);
        assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
        assert_eq!(
            RuntimeObservation::decode_from_slice(&receipt)
                .unwrap()
                .state
                .as_known(),
            Some(RuntimeState::RUNTIME_STATE_ABSENT)
        );
        let phases = store.phases.lock().unwrap();
        assert!(
            !phases
                .iter()
                .any(|phase| matches!(phase, GuardianLaunchPhase::Complete { .. }))
        );
        assert!(matches!(
            phases.last(),
            Some(GuardianLaunchPhase::Compensated { .. })
        ));
    }
    println!("AOS_GUARDIAN_VERIFIED_PAIR_RECOVERY_ROOT_OK");
}

#[tokio::test]
async fn root_guardian_payload_failure_completes_exact_compensation() {
    if !rustix::process::geteuid().is_root() {
        eprintln!("SKIP root_guardian_payload_failure_completes_exact_compensation: root required");
        return;
    }

    let fixture = AuthorityFixture::new();
    let credentials = tempfile::tempdir().unwrap();
    let authority = fixture.protected_authority(credentials.path());
    let guardian = GuardianConfig::for_tests().unwrap();
    let store = GuardianRecordingStore::default();
    let worker = GuardianWorker::new(store.clone());
    worker.fail_payload_start.store(true, Ordering::SeqCst);
    let starts = worker.starts.clone();
    let payload_effects = worker.payload_effects.clone();
    let stop_roles = worker.stop_roles.clone();
    let mut broker = HostBroker::open(
        FixedCatalog,
        store.clone(),
        worker,
        Some(nspawn()),
        authority,
    )
    .unwrap()
    .with_guardian(guardian);

    let (request, artifacts) = fixture.guardian_request_and_artifacts(61);
    let receipt = broker
        .apply_runtime(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            policy(),
            || Ok(clock()),
        )
        .await
        .unwrap();
    let observation = RuntimeObservation::decode_from_slice(&receipt).unwrap();
    assert_eq!(
        observation.state.as_known(),
        Some(RuntimeState::RUNTIME_STATE_ABSENT)
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        stop_roles.lock().unwrap().as_slice(),
        [ExactUnitRole::Payload, ExactUnitRole::Guardian]
    );

    let durable = store.load().unwrap();
    assert!(matches!(
        durable.guardian_attempt(&[61; 16]).unwrap().phase,
        GuardianLaunchPhase::Compensated { .. }
    ));
    let request_digest: [u8; 32] = Sha256::digest(&request).into();
    assert_eq!(
        durable.query_effect(&[61; 16], request_digest).unwrap(),
        RuntimeEffectQuery::Complete(receipt.clone())
    );

    assert_eq!(
        broker
            .apply_runtime(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(payload_effects.load(Ordering::SeqCst), 1);
    assert_eq!(stop_roles.lock().unwrap().len(), 2);

    println!("AOS_GUARDIAN_COMPENSATION_ROOT_INTEGRATION_OK");
}
