//! Actual installed conditional replay through the ordinary observation worker.
//!
//! The native recording test calls this only after original native reclamation
//! and deletion of its signed transcript archive namespace.

// crucible-lint: allow panic-shortcut -- The real observation worker must retain its original native source and durable outcome.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "production_faults.rs"]
mod faults;

pub(super) use faults::drive_store_failures;

use crate::supervision::ProcessDeadline;
use crucible_campaign::{
    CampaignRepository,
    executor_node_capabilities::NodeMaterializationStrategy,
    observed_node_attempt::{
        ConditionalReplayScope, ObservedAttemptAdmission, ObservedAttemptBackend,
        ObservedAttemptRequest, ObservedAttemptState, ObservedAttemptWorker,
    },
};

use super::*;

pub(super) fn drive_original_recipe(
    prepared: InstalledConditionalReplay,
    execution: ExecutionId,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    repository: Arc<CampaignRepository>,
) -> crucible_campaign::CampaignHash {
    assert_eq!(
        prepared.world.graph.world_repeatability(),
        crucible_node_contract::Repeatability::Nondeterministic
    );
    let context = super::super::super::backend::input_context_bytes(
        &prepared.world.scenario,
        &prepared.configuration,
    )
    .unwrap();
    let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
    assert!(
        blobs
            .put_if_absent(inputs, &BlobHandle::from_bytes(context))
            .unwrap()
            .is_durable()
    );
    let publisher = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs,
        RefName::new(format!(
            "node-world-activations/production-original-replay-{}",
            execution_text(execution)
        ))
        .unwrap(),
    )
    .unwrap();
    let mut backend =
        NodeObservedBackend::from_conditional_replay(prepared, publisher, blobs, inputs, execution)
            .unwrap();
    let scenario = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .unwrap();
    let configuration = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    assert!(request.conditional_scope().is_some());
    assert!(
        crucible_campaign::observed_node_attempt::ObservedAttemptRequest::new(
            execution,
            request.capabilities().clone(),
            request.inputs(),
        )
        .is_err()
    );
    assert_eq!(
        crucible_campaign::observed_node_attempt::ObservedAttemptRequest::from_canonical_bytes(
            &request.canonical_bytes(),
        )
        .unwrap(),
        request
    );
    assert_eq!(
        request.capabilities().materialization(),
        &std::collections::BTreeSet::from([
            NodeMaterializationStrategy::ConditionalTranscriptReplay
        ])
    );
    assert!(!request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let original = request.conditional_scope().unwrap();
    let changed = ConditionalReplayScope::new(
        original.original_world(),
        crucible_campaign::CampaignHash::parse(&"ff".repeat(32)).unwrap(),
        original.sources().clone(),
    )
    .unwrap();
    let counterfeit = ObservedAttemptRequest::conditional_replay(
        execution,
        request.capabilities().clone(),
        request.inputs(),
        changed,
    )
    .unwrap();
    // The public declaration is valid data; the installed recipe still refuses
    // its changed context before durable dispatch or any response consumption.
    assert!(backend.validate_realization(&counterfeit).is_err());
    assert!(
        admission
            .authenticate(
                &counterfeit,
                backend.scenario_artifact(),
                backend.configuration_artifact(),
            )
            .is_err()
    );

    let mut worker = ObservedAttemptWorker::new(repository, backend, 1).unwrap();
    worker
        .submit("installed-original-replay", &request, &admission)
        .unwrap();
    let deadline = ProcessDeadline::after(Duration::from_secs(10)).unwrap();
    loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(_) => break,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("installed original replay was contained: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(!deadline.expired(), "installed original replay stalled");
    }
    request.plan_digest()
}

/// Supplies original signed source custody to the real owning service fixture.
pub(super) struct ServiceReplayFixture {
    pub(super) archive: crucible::node_adapters::transcript::TranscriptArchive,
    pub(super) sources: BTreeMap<Id, ContentRef>,
    pub(super) executable: PathBuf,
    pub(super) private_root: PathBuf,
    pub(super) configuration: NodeRunConfiguration,
    pub(super) repository: Arc<CampaignRepository>,
    pub(super) blobs: Arc<dyn ImmutableBlobBackend>,
    pub(super) refs: Arc<dyn MutableRefBackend>,
}

pub(super) fn drive_service_original(fixture: ServiceReplayFixture) {
    use super::super::super::{NodeObservationService, NodeObservationServiceConfig};

    let ServiceReplayFixture {
        archive,
        sources,
        executable,
        private_root,
        configuration,
        repository,
        blobs,
        refs,
    } = fixture;
    let service = NodeObservationService::start_with_transcript_archive(
        NodeObservationServiceConfig {
            installed_artifacts: Vec::new(),
            expected_device: measure_executable(&executable).unwrap(),
            device_executable: executable,
            socket_parent: private_root,
            control_timeout: Duration::from_secs(5),
            maximum_worlds: 2,
            maximum_pending_requests: 2,
        },
        archive,
        repository,
        blobs,
        refs,
    )
    .unwrap();
    let retention = service.retention_owner();
    let execution = ExecutionId::from_bytes([101; 16]).unwrap();
    let mut changed = configuration.clone();
    changed.horizon_ps = U64::new(100);
    assert!(
        service
            .submit_conditional_replay(
                "service-conditional-original".into(),
                execution,
                sources.clone(),
                canonical::canonical_json(&serde_json::to_value(&changed).unwrap()).unwrap(),
            )
            .is_err()
    );
    assert!(service.state(execution).is_err());

    let bytes = canonical::canonical_json(&serde_json::to_value(&configuration).unwrap()).unwrap();
    let original = service
        .submit_conditional_replay(
            "service-conditional-original".into(),
            execution,
            sources.clone(),
            bytes.clone(),
        )
        .unwrap();
    assert!(original.request().conditional_scope().is_some());
    assert!(!original.request().capabilities().roster().is_repeatable());
    let retry = service.submit_conditional_replay(
        "service-conditional-original".into(),
        execution,
        sources.clone(),
        bytes.clone(),
    );
    // A current owner returns its cached original state. If the worker already
    // retired, historical state is readable but cannot allocate a new cursor.
    if let Ok(retry) = retry {
        assert_eq!(retry.request(), original.request());
    }
    let deadline = ProcessDeadline::after(Duration::from_secs(10)).unwrap();
    loop {
        match service.state(execution).unwrap() {
            ObservedAttemptState::Completed(result) => {
                assert_eq!(result.request(), original.request());
                break;
            }
            ObservedAttemptState::Quarantined { reason, .. } => panic!("{reason}"),
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(!deadline.expired(), "conditional owning actor stalled");
        deadline.pause(Duration::from_millis(1));
    }
    drop(service);
    while !retention.is_retired() {
        assert!(
            !deadline.expired(),
            "conditional owning actor abandoned custody"
        );
        deadline.pause(Duration::from_millis(1));
    }
    // Native worlds have retired, while durable original admission history
    // remains independently rooted and cannot become a replacement dispatch.
    assert!(!retention.retention_roots().unwrap().is_empty());
}

// The public socket consumes the same operator-owned signer capability as the
// actor; request bytes cannot enroll a source path, key or replay qualification.
pub(super) fn drive_control_original(fixture: ServiceReplayFixture) {
    use crate::node_control::{
        NodeConditionalReplayRequest, NodeControlCommand, NodeControlDaemon, NodeControlRequest,
        NodeControlResult, NodeDaemonPolicy, decode_conditional_preparation, decode_node_state,
        request_node_control,
    };
    use crate::node_observed_executor::ConditionalPreparationState;
    use crucible_campaign::observed_node_attempt::ObservedAttemptRequest;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicBool, Ordering},
    };

    let ServiceReplayFixture {
        archive,
        sources,
        executable,
        private_root,
        configuration,
        ..
    } = fixture;
    let state_directory = private_root.join("conditional-control");
    std::fs::create_dir(&state_directory).unwrap();
    std::fs::set_permissions(&state_directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state_directory.join("control.sock");
    let policy = NodeDaemonPolicy {
        format: "crucible.node-daemon-policy".into(),
        version: 1,
        state_directory,
        socket: socket.clone(),
        expected_device: measure_executable(&executable).unwrap(),
        device_executable: executable,
        control_timeout_ms: 5000,
        maximum_worlds: 2,
        maximum_pending_requests: 2,
        maximum_host_state_worlds: None,
        maximum_native_state_requests: None,
        immutable_artifacts: Vec::new(),
    };
    let mut daemon = NodeControlDaemon::start_with_conditional_archive(policy, archive).unwrap();
    let retention = daemon.retention_owner();
    let stopping = Arc::new(AtomicBool::new(false));
    let serving_stop = stopping.clone();
    let serving = std::thread::spawn(move || {
        daemon.serve(&serving_stop).unwrap();
        assert!(
            retention.is_retired(),
            "complete original runtime custody was not reclaimed"
        );
        assert!(
            !daemon.retention_roots().unwrap().is_empty(),
            "durable admission receipts lost their GC owner"
        );
    });
    let configuration_bytes =
        canonical::canonical_json(&serde_json::to_value(&configuration).unwrap()).unwrap();
    let original = NodeConditionalReplayRequest::new(
        "socket-original-replay".into(),
        "67676767676767676767676767676767".into(),
        sources.clone(),
        configuration_bytes.clone(),
    )
    .unwrap();
    let deadline = ProcessDeadline::after(Duration::from_secs(15)).unwrap();

    // Syntax can reserve admission, but counterfactual source scope cannot become Ready.
    let mut changed_configuration = configuration.clone();
    changed_configuration.horizon_ps = U64::new(100);
    let changed = NodeConditionalReplayRequest::new(
        "changed-context".into(),
        "66666666666666666666666666666666".into(),
        sources.clone(),
        canonical::canonical_json(&serde_json::to_value(&changed_configuration).unwrap()).unwrap(),
    )
    .unwrap();
    let changed_request =
        NodeControlRequest::conditional_replay("changed-horizon", changed).unwrap();
    let changed_receipt =
        decode_conditional_preparation(&request_node_control(&socket, &changed_request).unwrap())
            .unwrap();
    let changed_terminal = await_conditional_receipt(&socket, &changed_receipt, &deadline);
    assert!(matches!(
        changed_terminal.outcome,
        ConditionalPreparationState::Unavailable { .. }
    ));
    let missing = NodeControlRequest::new(
        "missing-before-admission",
        NodeControlCommand::Status {
            execution: changed_receipt.execution.clone(),
        },
    )
    .unwrap();
    assert!(matches!(
        request_node_control(&socket, &missing).unwrap().result,
        NodeControlResult::Refused { .. }
    ));

    let request =
        NodeControlRequest::conditional_replay("original-admission", original.clone()).unwrap();
    let pending =
        decode_conditional_preparation(&request_node_control(&socket, &request).unwrap()).unwrap();
    let repeated =
        decode_conditional_preparation(&request_node_control(&socket, &request).unwrap()).unwrap();
    assert_eq!(pending.request, repeated.request);
    let mut changed_retry = original;
    changed_retry.configuration = crucible_node_contract::Bytes::new(
        configuration_bytes.iter().copied().chain(*b" ").collect(),
    );
    let changed_retry =
        NodeControlRequest::conditional_replay("altered-exact-original-bytes", changed_retry)
            .unwrap();
    assert!(matches!(
        request_node_control(&socket, &changed_retry)
            .unwrap()
            .result,
        NodeControlResult::Refused { .. }
    ));
    let ready = await_conditional_receipt(&socket, &pending, &deadline);
    let ConditionalPreparationState::Admitted { observed_request } = ready.outcome else {
        panic!("original source admission did not finish");
    };
    let original_request =
        ObservedAttemptRequest::from_canonical_bytes(observed_request.as_slice()).unwrap();
    assert!(original_request.conditional_scope().is_some());
    assert!(!original_request.capabilities().roster().is_repeatable());
    let status = NodeControlRequest::new(
        "original-status",
        NodeControlCommand::Status {
            execution: pending.execution,
        },
    )
    .unwrap();
    loop {
        let state = decode_node_state(&request_node_control(&socket, &status).unwrap()).unwrap();
        assert_eq!(state.request(), &original_request);
        match state {
            ObservedAttemptState::Completed(_) => break,
            ObservedAttemptState::Quarantined { reason, .. } => panic!("socket replay: {reason}"),
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(!deadline.expired(), "socket conditional replay stalled");
        deadline.pause(Duration::from_millis(1));
    }

    if let Some(cli) = std::env::var_os("CRUCIBLE_TEST_CLI") {
        let sources_path = private_root.join("conditional-original-sources.json");
        let configuration_path = private_root.join("conditional-original-configuration.json");
        std::fs::write(
            &sources_path,
            canonical::canonical_json(&serde_json::to_value(&sources).unwrap()).unwrap(),
        )
        .unwrap();
        std::fs::write(&configuration_path, &configuration_bytes).unwrap();
        let cli_execution = "68686868686868686868686868686868";
        let output = std::process::Command::new(&cli)
            .args(["node", "conditional-replay", "--socket"])
            .arg(&socket)
            .args([
                "--ledger",
                "socket-original-replay",
                "--execution",
                cli_execution,
                "--sources",
            ])
            .arg(&sources_path)
            .arg("--configuration")
            .arg(&configuration_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "conditional CLI: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["materialization"], "conditional_transcript_replay");
        assert_eq!(value["repeatable"], false);
        let read = NodeControlRequest::conditional_replay_status(
            "cli-preparation-status",
            cli_execution.to_owned(),
        )
        .unwrap();
        let pending =
            decode_conditional_preparation(&request_node_control(&socket, &read).unwrap()).unwrap();
        let ready = await_conditional_receipt(&socket, &pending, &deadline);
        assert!(matches!(
            ready.outcome,
            ConditionalPreparationState::Admitted { .. }
        ));
        let cli_status = std::process::Command::new(&cli)
            .args(["node", "conditional-replay-status", "--socket"])
            .arg(&socket)
            .args(["--execution", cli_execution])
            .output()
            .unwrap();
        assert!(
            cli_status.status.success(),
            "conditional status CLI: {}",
            String::from_utf8_lossy(&cli_status.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&cli_status.stdout).unwrap();
        assert_eq!(value["admission"], "admitted");
        assert_eq!(value["source_authenticated"], true);
        let status = NodeControlRequest::new(
            "cli-completion",
            NodeControlCommand::Status {
                execution: cli_execution.into(),
            },
        )
        .unwrap();
        loop {
            match decode_node_state(&request_node_control(&socket, &status).unwrap()).unwrap() {
                ObservedAttemptState::Completed(result) => {
                    assert_eq!(
                        result.request().plan_digest(),
                        original_request.plan_digest()
                    );
                    break;
                }
                ObservedAttemptState::Quarantined { reason, .. } => {
                    panic!("conditional CLI: {reason}")
                }
                ObservedAttemptState::Reserved(_) => {}
            }
            assert!(!deadline.expired(), "conditional CLI did not finish");
            deadline.pause(Duration::from_millis(1));
        }
        let mut changed_sources = sources;
        let producer = changed_sources
            .remove(&Id::new("producer").unwrap())
            .unwrap();
        changed_sources.insert(Id::new("counterfactual-producer").unwrap(), producer);
        std::fs::write(
            &sources_path,
            canonical::canonical_json(&serde_json::to_value(changed_sources).unwrap()).unwrap(),
        )
        .unwrap();
        let changed_execution = "69696969696969696969696969696969";
        let output = std::process::Command::new(&cli)
            .args(["node", "conditional-replay", "--socket"])
            .arg(&socket)
            .args([
                "--ledger",
                "changed-source-actor",
                "--execution",
                changed_execution,
                "--sources",
            ])
            .arg(&sources_path)
            .arg("--configuration")
            .arg(&configuration_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "syntax-only pending receipt was unavailable"
        );
        let read = NodeControlRequest::conditional_replay_status(
            "changed-source-status",
            changed_execution.into(),
        )
        .unwrap();
        let pending =
            decode_conditional_preparation(&request_node_control(&socket, &read).unwrap()).unwrap();
        assert!(matches!(
            await_conditional_receipt(&socket, &pending, &deadline).outcome,
            ConditionalPreparationState::Unavailable { .. }
        ));
        let absent = NodeControlRequest::new(
            "counterfactual-source-status",
            NodeControlCommand::Status {
                execution: changed_execution.into(),
            },
        )
        .unwrap();
        assert!(matches!(
            request_node_control(&socket, &absent).unwrap().result,
            NodeControlResult::Refused { .. }
        ));
    }
    stopping.store(true, Ordering::Release);
    serving.join().unwrap();
}

fn await_conditional_receipt(
    socket: &std::path::Path,
    original: &crate::node_observed_executor::ConditionalPreparationRecord,
    deadline: &ProcessDeadline,
) -> crate::node_observed_executor::ConditionalPreparationRecord {
    use crate::node_observed_executor::ConditionalPreparationState;
    let request = crate::node_control::NodeControlRequest::conditional_replay_status(
        "original-preparation-status",
        original.execution.clone(),
    )
    .unwrap();
    loop {
        let record = crate::node_control::decode_conditional_preparation(
            &crate::node_control::request_node_control(socket, &request).unwrap(),
        )
        .unwrap();
        assert_eq!(record.request, original.request);
        assert_eq!(record.execution, original.execution);
        if !matches!(
            record.outcome,
            ConditionalPreparationState::AwaitingAdmission { .. }
        ) {
            return record;
        }
        assert!(
            !deadline.expired(),
            "original conditional admission stalled"
        );
        deadline.pause(Duration::from_millis(1));
    }
}
