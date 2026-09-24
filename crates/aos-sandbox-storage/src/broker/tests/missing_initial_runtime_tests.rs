//! Public-runtime coverage for missing-initial workspace-pin repair.

#![allow(clippy::unwrap_used)]

use super::*;

use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptedEffectFailure {
    None,
    BeforeMutation,
    AfterMutation,
}

#[derive(Default)]
struct ScriptedPinState {
    pin_present: bool,
    admission_observations: usize,
    repair_observations: usize,
    catalog_observations: usize,
    executions: usize,
    attempts: Vec<WorkspacePinAttemptV1>,
    catalogs: Vec<ResolvedCatalogCommitmentV1>,
}

struct ScriptedPinRuntimeIo {
    authority: crate::authorization::StorageAuthorityV1,
    state_key: StorageStateKey,
    contract: ZfsHelperContract,
    host_scope: WorkspacePinHostScopeV1,
    custody: crate::observation_protocol::WorkspaceCatalogCustodyBindingV1,
    dataset_name: &'static str,
    dataset_guid: u64,
    failure: ScriptedEffectFailure,
    state: Arc<Mutex<ScriptedPinState>>,
}

struct ScriptedPinRuntimeSpec {
    dataset_name: &'static str,
    dataset_guid: u64,
    failure: ScriptedEffectFailure,
    state: Arc<Mutex<ScriptedPinState>>,
}

fn scripted_pin(
    dataset_name: &'static str,
    dataset_guid: u64,
    failure: ScriptedEffectFailure,
    state: &Arc<Mutex<ScriptedPinState>>,
) -> ScriptedPinRuntimeSpec {
    ScriptedPinRuntimeSpec {
        dataset_name,
        dataset_guid,
        failure,
        state: Arc::clone(state),
    }
}

fn scripted_io_counts(state: &Arc<Mutex<ScriptedPinState>>) -> (usize, usize, usize, usize) {
    let state = state.lock().unwrap();
    (
        state.admission_observations,
        state.repair_observations,
        state.catalog_observations,
        state.executions,
    )
}

impl ScriptedPinRuntimeIo {
    fn pin_result(
        &self,
        attempt_id: [u8; 16],
        observation_digest: ObjectDigest,
    ) -> crate::pin_worker::WorkspacePinWorkerResultV1 {
        let state = self.state.lock().unwrap();
        let pin = if state.pin_present {
            crate::workspace_pin::WorkspacePinObservationV1::Present(workspace_pin_proof(
                state
                    .attempts
                    .last()
                    .map_or([8; 32], WorkspacePinAttemptV1::workspace_handle),
                self.dataset_name,
                self.dataset_guid,
            ))
        } else {
            crate::workspace_pin::WorkspacePinObservationV1::Absent
        };
        crate::pin_worker::WorkspacePinWorkerResultV1::new(
            attempt_id,
            crate::workspace_pin::WorkspaceDatasetObservationV1::Exact {
                name: self.dataset_name.to_owned(),
                guid: self.dataset_guid,
            },
            pin,
            observation_digest,
        )
    }
}

impl crate::pin_worker_runtime::WorkspacePinRuntimeIo for ScriptedPinRuntimeIo {
    fn recover_quiescence(&mut self) -> Result<(), crate::ZfsWorkerError> {
        Ok(())
    }

    fn host_scope(&self) -> Result<WorkspacePinHostScopeV1, crate::ZfsWorkerError> {
        Ok(self.host_scope)
    }

    fn catalog_binding(
        &self,
    ) -> Result<crate::observation_protocol::WorkspaceCatalogCustodyBindingV1, crate::ZfsWorkerError>
    {
        Ok(self.custody)
    }

    fn execute(
        &mut self,
        request: &[u8],
        expected_attempt: &WorkspacePinAttemptV1,
    ) -> Result<crate::pin_worker::WorkspacePinWorkerResultV1, crate::ZfsWorkerError> {
        let authenticated = crate::workspace_repair_worker::authenticate_request(
            &self.authority,
            &self.state_key,
            &self.contract,
            crate::workspace_repair_worker::decode_request(request)?,
        )?;
        if authenticated.attempt() != expected_attempt {
            return Err(crate::ZfsWorkerError::Authority);
        }
        let mut state = self.state.lock().unwrap();
        state.executions += 1;
        state.attempts.push(authenticated.attempt().clone());
        state.catalogs.push(authenticated.catalog().clone());
        drop(state);
        if self.failure == ScriptedEffectFailure::BeforeMutation {
            return Err(crate::ZfsWorkerError::Protocol(
                "scripted failure before pin mutation",
            ));
        }
        self.state.lock().unwrap().pin_present = true;
        if self.failure == ScriptedEffectFailure::AfterMutation {
            return Err(crate::ZfsWorkerError::Protocol(
                "scripted failure after pin mutation",
            ));
        }
        Ok(self.pin_result(
            expected_attempt.attempt_id(),
            ObjectDigest::from_bytes([0xa1; 32]),
        ))
    }

    fn observe(
        &mut self,
        _request: &[u8],
        _attempt: &WorkspacePinAttemptV1,
    ) -> Result<crate::pin_worker::WorkspacePinWorkerResultV1, crate::ZfsWorkerError> {
        Err(crate::ZfsWorkerError::Protocol(
            "unexpected ordinary pin observation",
        ))
    }

    fn observe_repair(
        &mut self,
        request: &[u8],
        attempt_id: [u8; 16],
        probe_digest: ObjectDigest,
    ) -> Result<WorkspacePinRepairObserverResultV1, crate::ZfsWorkerError> {
        let authenticated = crate::workspace_repair_observer::authenticate_request(
            &self.state_key,
            &self.contract,
            crate::workspace_repair_observer::decode_request(request)?,
            self.host_scope,
        )?;
        if authenticated.probe().digest() != probe_digest {
            return Err(crate::ZfsWorkerError::Authority);
        }
        self.state.lock().unwrap().repair_observations += 1;
        Ok(WorkspacePinRepairObserverResultV1::new(
            probe_digest,
            self.pin_result(attempt_id, ObjectDigest::from_bytes([0xa2; 32])),
        ))
    }

    fn observe_repair_admission(
        &mut self,
        request: &[u8],
        probe: &WorkspacePinRepairAdmissionProbeV1,
    ) -> Result<
        crate::pin_worker_runtime::FreshWorkspacePinRepairObservationV1,
        crate::ZfsWorkerError,
    > {
        let authenticated = crate::workspace_repair_admission::authenticate_request(
            &self.state_key,
            &self.contract,
            crate::workspace_repair_admission::decode_request(request)?,
            self.host_scope,
        )?;
        if authenticated.probe().digest() != probe.digest() {
            return Err(crate::ZfsWorkerError::Authority);
        }
        self.state.lock().unwrap().admission_observations += 1;
        let result = crate::workspace_repair_admission::WorkspacePinRepairAdmissionResultV1::new(
            probe.digest(),
            self.pin_result(
                probe.latest_attempt_id(),
                ObjectDigest::from_bytes([0xa3; 32]),
            ),
        );
        let validated =
            crate::workspace_repair_admission::ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
                probe,
                result,
            )?;
        Ok(
            crate::pin_worker_runtime::FreshWorkspacePinRepairObservationV1::new_for_test(
                validated,
            ),
        )
    }

    fn observe_catalog(
        &mut self,
        request_bytes: &[u8],
        request: &crate::observation_protocol::WorkspaceCatalogObservationRequestV1,
        _worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<crate::pin_worker_runtime::FreshWorkspaceCatalogObservationV1, crate::ZfsWorkerError>
    {
        let decoded = crate::observation_protocol::decode_request(request_bytes)?;
        if &decoded != request
            || crate::observation_protocol::encode_request(&decoded)? != request_bytes
        {
            return Err(crate::ZfsWorkerError::Authority);
        }
        self.state.lock().unwrap().catalog_observations += 1;
        let zfs_digest = ObjectDigest::from_bytes([0xa4; 32]);
        let pin_digest = ObjectDigest::from_bytes([0xa5; 32]);
        let result = crate::observation_protocol::WorkspaceCatalogObservationResultV1::matched(
            request, zfs_digest, pin_digest, pin_digest, zfs_digest,
        )?;
        Ok(crate::pin_worker_runtime::FreshWorkspaceCatalogObservationV1::new_for_test(result))
    }

    fn export_catalog_root(
        &mut self,
        _request_bytes: &[u8],
        _request: &crate::observation_protocol::WorkspaceCatalogObservationRequestV1,
        _worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<
        (
            crate::pin_worker_runtime::FreshWorkspaceCatalogObservationV1,
            std::os::fd::OwnedFd,
        ),
        crate::ZfsWorkerError,
    > {
        Err(crate::ZfsWorkerError::Protocol(
            "scripted pin runtime cannot export a detached root",
        ))
    }
}

struct StrictNoCallZfsBackend;

impl crate::helper::ZfsProcessBackend for StrictNoCallZfsBackend {
    fn observe_preconditions(
        &mut self,
        _program: &crate::helper::SealedZfsProgram<'_>,
        _expected: &[crate::ZfsPrecondition],
    ) -> Result<Vec<crate::ZfsPrecondition>, ZfsHelperError> {
        Err(ZfsHelperError::Backend(crate::ZfsWorkerError::Protocol(
            "unexpected ZFS precondition observation",
        )))
    }

    fn execute_once(
        &mut self,
        _program: &crate::helper::SealedZfsProgram<'_>,
    ) -> Result<crate::helper::ZfsProcessOutput, ZfsHelperError> {
        Err(ZfsHelperError::Backend(crate::ZfsWorkerError::Protocol(
            "unexpected ZFS execution",
        )))
    }

    fn observe_postcondition(
        &mut self,
        _program: &crate::helper::SealedZfsProgram<'_>,
        _expected: &crate::PostconditionPolicyV1,
        _expected_ancestor: Option<&ProjectAncestorPolicyV1>,
    ) -> Result<Option<crate::helper::ZfsPostconditionObservation>, ZfsHelperError> {
        Err(ZfsHelperError::Backend(crate::ZfsWorkerError::Protocol(
            "unexpected ZFS postcondition observation",
        )))
    }
}

fn open_scripted_runtime(
    coordinator: StorageAdmissionCoordinator,
    workspace_directory: &TempDir,
    fixture: &Fixture,
    contract: ZfsHelperContract,
    scripted: ScriptedPinRuntimeSpec,
) -> crate::StorageBrokerRuntime {
    let identity_pool = crate::StorageIdentityPoolV1::new(65_536, 65_536 * 4).unwrap();
    let host_scope = WorkspacePinHostScopeV1::new([50; 16], 51, 52).unwrap();
    let custody = crate::observation_protocol::WorkspaceCatalogCustodyBindingV1::new(
        [50; 16], 51, 52, 53, 54, 55,
    )
    .unwrap();
    let pin_io = ScriptedPinRuntimeIo {
        authority: fixture.authority(),
        state_key: StorageStateKey::new([51; 16], [52; 32]).unwrap(),
        contract: contract.clone(),
        host_scope,
        custody,
        dataset_name: scripted.dataset_name,
        dataset_guid: scripted.dataset_guid,
        failure: scripted.failure,
        state: scripted.state,
    };
    let helper = StorageMutationHelper::new(
        contract.clone(),
        Box::new(StrictNoCallZfsBackend) as Box<dyn crate::helper::ZfsProcessBackend + Send>,
    );
    crate::StorageBrokerRuntime::from_runtime_interfaces_for_test(
        coordinator,
        || {
            crate::workspace_catalog::PendingStorageWorkspaceCatalogV1::open_for_test(
                workspace_directory.path(),
                identity_pool,
            )
            .map_err(Into::into)
        },
        &mut || Ok(clock()),
        crate::runtime::runtime_configuration_binding(
            fixture.protected_authority_binding(),
            identity_pool,
        ),
        contract,
        Box::new(pin_io),
        helper,
    )
    .unwrap()
}

#[test]
fn public_runtime_missing_initial_create_runs_real_startup_admission_worker_and_catalog() {
    let transaction_directory = TempDir::new().unwrap();
    let workspace_directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (initial_coordinator, creation) =
        committed_workspace_without_pin(&transaction_directory, &fixture);
    let state = Arc::new(Mutex::new(ScriptedPinState::default()));
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let mut runtime = open_scripted_runtime(
        initial_coordinator,
        &workspace_directory,
        &fixture,
        contract.clone(),
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    assert!(matches!(
        runtime.readiness(),
        crate::StorageRuntimeReadiness::RecoveryPending { .. }
    ));
    assert_eq!(state.lock().unwrap().executions, 0);

    let workspace_handle = creation.storage_handle().unwrap();
    let manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, workspace_handle, 6, manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    assert_eq!(
        runtime
            .repair_workspace_pin(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &mut || Ok(clock()),
            )
            .unwrap(),
        crate::runtime::WorkspacePinRepairExecutionOutcomeV1::Satisfied
    );
    assert!(matches!(
        runtime.readiness(),
        crate::StorageRuntimeReadiness::Ready
    ));
    let after = state.lock().unwrap();
    assert_eq!(after.admission_observations, 1);
    assert_eq!(after.executions, 1);
    assert_eq!(after.catalog_observations, 1);
    assert_eq!(after.attempts[0].attempt_ordinal(), 1);
    assert!(matches!(
        after.catalogs[0].plan(),
        CatalogPlanV1::CreateWorkspace { .. }
    ));
    drop(after);

    let sequence = runtime
        .coordinator_for_test()
        .transactions
        .journal_sequence_for_test();
    let calls = scripted_io_counts(&state);
    assert_eq!(
        runtime
            .repair_workspace_pin(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &mut || Ok(clock()),
            )
            .unwrap(),
        crate::runtime::WorkspacePinRepairExecutionOutcomeV1::ObservationRequired
    );
    assert_eq!(
        runtime
            .coordinator_for_test()
            .transactions
            .journal_sequence_for_test(),
        sequence
    );
    assert_eq!(scripted_io_counts(&state), calls);

    let (locked_coordinator, locked_workspaces) = runtime.into_journals_for_test();
    drop(locked_workspaces);
    drop(locked_coordinator);
    let reopened = open_scripted_runtime(
        coordinator(&transaction_directory, &fixture),
        &workspace_directory,
        &fixture,
        contract,
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    assert!(matches!(
        reopened.readiness(),
        crate::StorageRuntimeReadiness::Ready
    ));
    assert_eq!(state.lock().unwrap().executions, 1);
    reopened
        .coordinator_for_test()
        .workspace_catalog_activation_plan()
        .unwrap();
}

#[test]
fn public_runtime_missing_initial_clone_binds_exact_source_and_root_policy() {
    let transaction_directory = TempDir::new().unwrap();
    let workspace_directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (coordinator, creation) = committed_clone_without_pin(&transaction_directory, &fixture);
    let state = Arc::new(Mutex::new(ScriptedPinState::default()));
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let mut runtime = open_scripted_runtime(
        coordinator,
        &workspace_directory,
        &fixture,
        contract,
        scripted_pin(
            "tank/aos/project/clone",
            13,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    let handle = creation.storage_handle().unwrap();
    let manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(80, 81, handle, 6, manifest.digest());
    let artifacts = fixture.repair_artifacts(&request);
    assert_eq!(
        runtime
            .repair_workspace_pin(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &mut || Ok(clock()),
            )
            .unwrap(),
        crate::runtime::WorkspacePinRepairExecutionOutcomeV1::Satisfied
    );
    let state = state.lock().unwrap();
    assert_eq!(state.executions, 1);
    assert_eq!(state.attempts[0].attempt_ordinal(), 1);
    assert_eq!(
        state.catalogs[0].root_policy(),
        Some(state.attempts[0].root_policy())
    );
    let CatalogPlanV1::Clone {
        source,
        origin_hold,
        ..
    } = state.catalogs[0].plan()
    else {
        panic!("runtime repair worker lost Clone semantics")
    };
    assert_eq!(source.guid(), 12);
    assert_eq!(source.version_handle(), [32; 32]);
    assert_eq!(origin_hold.snapshot_guid(), 12);
    assert_eq!(origin_hold.hold_id().as_bytes(), [33; 16]);
}

#[test]
fn public_runtime_uncertain_repair_admission_never_dispatches_worker() {
    let transaction_directory = TempDir::new().unwrap();
    let workspace_directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (initial_coordinator, creation) =
        committed_workspace_without_pin(&transaction_directory, &fixture);
    let state = Arc::new(Mutex::new(ScriptedPinState::default()));
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let mut runtime = open_scripted_runtime(
        initial_coordinator,
        &workspace_directory,
        &fixture,
        contract.clone(),
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    runtime.fail_after_next_transaction_journal_commit_for_test();
    let manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(
        80,
        81,
        creation.storage_handle().unwrap(),
        6,
        manifest.digest(),
    );
    let artifacts = fixture.repair_artifacts(&request);

    assert!(matches!(
        runtime.repair_workspace_pin(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &mut || Ok(clock()),
        ),
        Err(crate::StorageRuntimeError::ReopenRequired)
    ));
    assert_eq!(state.lock().unwrap().admission_observations, 1);
    assert_eq!(state.lock().unwrap().executions, 0);

    let (locked_coordinator, locked_workspaces) = runtime.into_journals_for_test();
    drop(locked_workspaces);
    drop(locked_coordinator);
    let reopened = open_scripted_runtime(
        coordinator(&transaction_directory, &fixture),
        &workspace_directory,
        &fixture,
        contract,
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    assert!(matches!(
        reopened.readiness(),
        crate::StorageRuntimeReadiness::RecoveryPending { .. }
    ));
    assert_eq!(state.lock().unwrap().repair_observations, 1);
    assert_eq!(state.lock().unwrap().executions, 0);
}

#[test]
fn public_runtime_worker_failures_reopen_by_observing_the_effect_boundary() {
    for (failure, pin_present_after_failure, expected_ready_after_reopen) in [
        (ScriptedEffectFailure::BeforeMutation, false, false),
        (ScriptedEffectFailure::AfterMutation, true, true),
    ] {
        let transaction_directory = TempDir::new().unwrap();
        let workspace_directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let (initial_coordinator, creation) =
            committed_workspace_without_pin(&transaction_directory, &fixture);
        let state = Arc::new(Mutex::new(ScriptedPinState::default()));
        let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        let mut runtime = open_scripted_runtime(
            initial_coordinator,
            &workspace_directory,
            &fixture,
            contract.clone(),
            scripted_pin("tank/aos/project/work", 11, failure, &state),
        );
        let manifest = assignment_manifest_at(&sandbox_spec(72), 6);
        let request = repair_request(
            80,
            81,
            creation.storage_handle().unwrap(),
            6,
            manifest.digest(),
        );
        let artifacts = fixture.repair_artifacts(&request);

        assert!(matches!(
            runtime.repair_workspace_pin(
                &request,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                peer_policy(),
                &mut || Ok(clock()),
            ),
            Err(crate::StorageRuntimeError::Recovery)
        ));
        assert_eq!(state.lock().unwrap().pin_present, pin_present_after_failure);
        assert_eq!(state.lock().unwrap().executions, 1);

        let (locked_coordinator, locked_workspaces) = runtime.into_journals_for_test();
        drop(locked_workspaces);
        drop(locked_coordinator);
        let mut reopened = open_scripted_runtime(
            coordinator(&transaction_directory, &fixture),
            &workspace_directory,
            &fixture,
            contract,
            scripted_pin(
                "tank/aos/project/work",
                11,
                ScriptedEffectFailure::None,
                &state,
            ),
        );
        assert_eq!(
            matches!(reopened.readiness(), crate::StorageRuntimeReadiness::Ready),
            expected_ready_after_reopen
        );
        assert_eq!(state.lock().unwrap().repair_observations, 1);
        assert_eq!(state.lock().unwrap().executions, 1);

        let io_counts = scripted_io_counts(&state);
        let replay = reopened.repair_workspace_pin(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &mut || Ok(clock()),
        );
        assert_eq!(
            replay.unwrap(),
            crate::runtime::WorkspacePinRepairExecutionOutcomeV1::ObservationRequired
        );
        assert_eq!(scripted_io_counts(&state), io_counts);
    }
}

#[test]
fn public_runtime_uncertain_catalog_commit_reopens_without_worker_redispatch() {
    let transaction_directory = TempDir::new().unwrap();
    let workspace_directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (initial_coordinator, creation) =
        committed_workspace_without_pin(&transaction_directory, &fixture);
    let state = Arc::new(Mutex::new(ScriptedPinState::default()));
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let mut runtime = open_scripted_runtime(
        initial_coordinator,
        &workspace_directory,
        &fixture,
        contract.clone(),
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    assert!(runtime.fail_after_next_workspace_catalog_commit_for_test());
    let manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(
        80,
        81,
        creation.storage_handle().unwrap(),
        6,
        manifest.digest(),
    );
    let artifacts = fixture.repair_artifacts(&request);

    assert!(matches!(
        runtime.repair_workspace_pin(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &mut || Ok(clock()),
        ),
        Err(crate::StorageRuntimeError::ReopenRequired)
    ));
    assert!(state.lock().unwrap().pin_present);
    assert_eq!(state.lock().unwrap().executions, 1);

    let (locked_coordinator, locked_workspaces) = runtime.into_reopen_components_for_test();
    drop(locked_workspaces);
    drop(locked_coordinator);
    let reopened = open_scripted_runtime(
        coordinator(&transaction_directory, &fixture),
        &workspace_directory,
        &fixture,
        contract,
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    assert!(matches!(
        reopened.readiness(),
        crate::StorageRuntimeReadiness::Ready
    ));
    assert_eq!(state.lock().unwrap().executions, 1);
}

#[test]
fn public_runtime_uncertain_completion_commit_reopens_without_worker_redispatch() {
    let transaction_directory = TempDir::new().unwrap();
    let workspace_directory = TempDir::new().unwrap();
    let fixture = Fixture::new();
    let (initial_coordinator, creation) =
        committed_workspace_without_pin(&transaction_directory, &fixture);
    let state = Arc::new(Mutex::new(ScriptedPinState::default()));
    let contract = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
    let mut runtime = open_scripted_runtime(
        initial_coordinator,
        &workspace_directory,
        &fixture,
        contract.clone(),
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    runtime.fail_after_next_repair_completion_commit_for_test();
    let manifest = assignment_manifest_at(&sandbox_spec(72), 6);
    let request = repair_request(
        80,
        81,
        creation.storage_handle().unwrap(),
        6,
        manifest.digest(),
    );
    let artifacts = fixture.repair_artifacts(&request);

    assert!(matches!(
        runtime.repair_workspace_pin(
            &request,
            &artifacts,
            ProtocolVersion::new(1, 0),
            peer(),
            peer_policy(),
            &mut || Ok(clock()),
        ),
        Err(crate::StorageRuntimeError::ReopenRequired)
    ));
    assert!(state.lock().unwrap().pin_present);
    assert_eq!(state.lock().unwrap().executions, 1);

    let (locked_coordinator, locked_workspaces) = runtime.into_journals_for_test();
    drop(locked_workspaces);
    drop(locked_coordinator);
    let reopened = open_scripted_runtime(
        coordinator(&transaction_directory, &fixture),
        &workspace_directory,
        &fixture,
        contract,
        scripted_pin(
            "tank/aos/project/work",
            11,
            ScriptedEffectFailure::None,
            &state,
        ),
    );
    assert!(matches!(
        reopened.readiness(),
        crate::StorageRuntimeReadiness::Ready
    ));
    assert_eq!(state.lock().unwrap().repair_observations, 0);
    assert_eq!(state.lock().unwrap().executions, 1);
}
