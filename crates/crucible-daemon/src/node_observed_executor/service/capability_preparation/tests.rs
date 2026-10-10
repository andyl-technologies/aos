//! Checks data-only original custody; these synthetic refs qualify no native model.

// crucible-lint: allow panic-shortcut -- Model-only request custody and finite-credit assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_cas::content_store::{
    BlobHandle, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
    RefName,
};
use crucible_node_contract::{
    CaptureScope, Continuation, FacetSelection, OperatingMode, Repeatability,
};
use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};

fn request() -> CapabilityPreparationRequest {
    use crucible::node_admission::*;
    let model = canonical::content_ref(
        b"model-only policy body, no native authority",
        "application/json",
    )
    .unwrap();
    let demands = CapabilityRequirements {
        format: CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: vec![NodeCapabilityRequirement {
            node: Id::new("clock").unwrap(),
            roles: vec![],
            timing: TimingRequirement {
                mode: OperatingMode::Exact,
                resolution_ps: Some(1.into()),
                phase_ps: Some(0.into()),
                policy_ref: model.clone(),
            },
            operations: vec![OperationRequirement {
                operation: Id::new("exact_run").unwrap(),
                facet: FacetSelection {
                    id: Id::new("model-only").unwrap(),
                    version: 1,
                    configuration_ref: model.clone(),
                    guarantees_ref: model,
                    extensions: Default::default(),
                },
            }],
            guarantees: GuaranteeRequirement {
                repeatability: Repeatability::Qualified,
                capture_scope: CaptureScope::CompleteModel,
                continuation: Continuation::Exact,
                durable_restart: false,
                isolated_fork: false,
                conditional_replay: false,
            },
            compute: None,
            extensions: vec![],
        }],
    };
    CapabilityPreparationRequest {
        format: "crucible.capability-preparation-request".into(),
        version: 1,
        ledger: "model-original".into(),
        execution: "81818181818181818181818181818181".into(),
        requirements: Bytes::new([
            b" \n".as_slice(),
            encode(&demands).unwrap().as_slice()
        ].concat()),
        candidates: vec![CapabilityCandidateRecipe {
            id: Id::new("model-clock").unwrap(),
            selections: vec![InstalledNodeSelection {
                node: Id::new("clock").unwrap(),
                owner: Id::new("owner").unwrap(),
                kind: crate::node_observed_executor::InstalledNodeKind::HostClock
            }]
        }],
        configuration: Bytes::new(
            br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"10","maximum_rounds":"8"}"#.to_vec()
        ),
        action: CapabilityPreparationAction::Observe {}
    }
}

fn storage(
    directory: &std::path::Path,
) -> (Arc<dyn ImmutableBlobBackend>, Arc<dyn MutableRefBackend>) {
    (
        Arc::new(DirectoryBlobBackend::new(
            "capability-model",
            directory.join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.join("refs"))),
    )
}

#[test]
fn original_raw_custody_survives_restart_and_changed_context_never_dispatches() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::CapabilityPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = request();
    let first = ledger.reserve(&original).unwrap();
    assert!(first.original_dispatch);
    let identity = ContentId::parse(&first.record.request).unwrap();
    assert!(ledger.retention_roots().unwrap().contains(&identity));
    let body = blobs
        .read(identity, None)
        .unwrap()
        .read_all(4 * 1024 * 1024)
        .unwrap();
    let raw: CapabilityPreparationRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(raw.requirements, original.requirements);

    let restarted = ledger::CapabilityPreparationLedger::new(blobs, refs).unwrap();
    let same = restarted.reserve(&original).unwrap();
    assert!(!same.original_dispatch);
    assert_eq!(
        encode(&first.record).unwrap(),
        encode(&same.record).unwrap()
    );
    assert!(restarted.owns(&original.execution).unwrap());
    assert!(
        restarted
            .complete(
                &same,
                CapabilityPreparationState::Unavailable {
                    reason: "test refusal".into()
                }
            )
            .is_err()
    );

    let mut changed = original.clone();
    changed.requirements = Bytes::new([original.requirements.as_slice(), b" "].concat());
    assert!(restarted.reserve(&changed).is_err());
    assert_eq!(
        encode(&restarted.state(&original.execution).unwrap()).unwrap(),
        encode(&first.record).unwrap()
    );
}

#[test]
fn pending_status_and_exact_retry_do_not_wait_for_actor_and_full_queue_keeps_original() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let capabilities =
        ledger::CapabilityPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let (commands, receiver) = mpsc::sync_channel(1);
    let service = super::super::NodeObservationService {
        commands,
        stopping: Arc::new(AtomicBool::new(false)),
        roots: Arc::new(Mutex::new(Default::default())),
        retired: Arc::new(AtomicBool::new(false)),
        preparations: None,
        capabilities: capabilities.clone(),
        debug: super::super::debug::DebugLedger::new(blobs.clone(), refs.clone()).unwrap(),
        preserving_debug: super::super::debug_preserving::Ledger::new(blobs.clone(), refs.clone())
            .unwrap(),
        root_preparations: super::super::root_preparation::ledger::RootPreparationLedger::new(
            blobs, refs,
        )
        .unwrap(),
    };
    let original = request();
    let first = service
        .submit_capability_preparation(original.clone())
        .unwrap();
    assert!(matches!(
        first.outcome,
        CapabilityPreparationState::AwaitingAdmission {}
    ));
    assert_eq!(
        encode(&first).unwrap(),
        encode(
            &service
                .capability_preparation_status(&original.execution)
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        encode(&first).unwrap(),
        encode(
            &service
                .submit_capability_preparation(original.clone())
                .unwrap()
        )
        .unwrap()
    );

    let mut excess = original;
    excess.execution = "82828282828282828282828282828282".into();
    let unavailable = service
        .submit_capability_preparation(excess.clone())
        .unwrap();
    assert!(matches!(
        unavailable.outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    assert_eq!(
        encode(&unavailable).unwrap(),
        encode(&service.submit_capability_preparation(excess).unwrap()).unwrap()
    );

    let command = receiver.try_recv().unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    super::super::reply_refusal(command, NodeObservationServiceError::Unavailable);
    assert!(matches!(
        capabilities.state(&first.execution).unwrap().outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
}

#[test]
fn exhausted_persistent_credit_refuses_before_request_placement() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let bytes = encode(&serde_json::json!({
        "format": "crucible.capability-preparation-quota",
        "version": 1,
        "consumed": 4096
    }))
    .unwrap();
    let quota = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    assert!(
        blobs
            .put_if_absent(quota, &BlobHandle::from_bytes(bytes))
            .unwrap()
            .is_durable()
    );
    refs.compare_exchange(
        &RefName::new("node-capability-preparation-quota/records").unwrap(),
        None,
        quota,
    )
    .unwrap();

    let ledger = ledger::CapabilityPreparationLedger::new(blobs.clone(), refs).unwrap();
    let request = request();
    let body = ContentId::for_bytes(ObjectKind::Trace, 1, &encode(&request).unwrap());
    assert!(ledger.reserve(&request).is_err());
    assert!(!blobs.contains(body).unwrap());
    assert!(!ledger.owns(&request.execution).unwrap());
}

#[test]
fn wrong_edition_unknown_fields_and_mandatory_nullable_context_fail_closed() {
    let original_request = request();
    let control = crate::node_control::NodeControlRequest::capability_preparation(
        "model-test",
        original_request.clone(),
    )
    .unwrap();
    let mut wrong = serde_json::to_value(control).unwrap();
    wrong["version"] = serde_json::json!(1);
    let bytes = encode(&wrong).unwrap();
    // Public constructor validates the corresponding original nonce; decoding
    // unknown/duplicate authored fields never permits imported resolved state.
    let mut original = serde_json::to_value(original_request).unwrap();
    original["resolved_authority"] = serde_json::json!(true);
    assert!(CapabilityPreparationRequest::from_json(&encode(&original).unwrap()).is_err());
    let mut invalid = request();
    let mut demands: serde_json::Value =
        serde_json::from_slice(invalid.requirements.as_slice()).unwrap();
    demands["nodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("compute");
    invalid.requirements = Bytes::new(encode(&demands).unwrap());
    assert!(invalid.validate().is_err());
    assert!(
        crate::node_control::NodeControlRequest::capability_preparation_status(
            "model-test",
            "0".repeat(32)
        )
        .is_err()
    );
    let value: crate::node_control::NodeControlRequest = serde_json::from_slice(&bytes).unwrap();
    assert!(matches!(
        crate::node_control::request_node_control(
            std::path::Path::new("/nonexistent-capability-socket"),
            &value
        ),
        Err(crate::node_control::NodeControlError::Refused(_))
    ));
}

#[test]
fn complete_portable_receipt_credit_accounts_for_the_control_wrapper() {
    // This is data-only credit arithmetic, not a native qualification fixture.
    let oversized = Bytes::new(vec![0; super::MAX_RECEIPT_SCENARIO_BYTES + 1]);
    assert!(super::validate_scenario_credit(&oversized).is_err());
    let boundary = Bytes::new(vec![0; super::MAX_RECEIPT_SCENARIO_BYTES]);
    assert!(super::validate_scenario_credit(&boundary).is_ok());

    let record = Bytes::new(vec![0; super::MAX_RECEIPT_BYTES]);
    let wrapped = crate::node_control::NodeControlReply {
        format: "crucible.node-control-reply".into(),
        version: 7,
        request_id: Id::new("credit/boundary").unwrap(),
        result: crate::node_control::NodeControlResult::CapabilityPreparation { record },
    };
    let bytes = serde_json::to_vec(&wrapped).unwrap();
    assert!(bytes.len() < crate::node_control::MAX_NODE_CONTROL_BYTES);
}

#[test]
fn capability_and_conditional_pending_callers_cannot_both_reserve_one_nonce() {
    use super::super::conditional_preparation::{
        ConditionalPreparationRequest, ledger::ConditionalPreparationLedger,
    };
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let capability = ledger::CapabilityPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let conditional = ConditionalPreparationLedger::new(blobs, refs).unwrap();
    let original = request();
    let source =
        canonical::content_ref(b"model source, no native authority", "application/json").unwrap();
    let conditional_request = ConditionalPreparationRequest {
        ledger: original.ledger.clone(),
        execution: original.execution.clone(),
        sources: [
            (Id::new("first").unwrap(), source.clone()),
            (Id::new("second").unwrap(), source),
        ]
        .into_iter()
        .collect(),
        configuration: original.configuration.clone(),
    };
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let first_barrier = barrier.clone();
    let second_barrier = barrier.clone();
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        capability
            .reserve(&original)
            .map(|value| value.original_dispatch)
    });
    let second = std::thread::spawn(move || {
        second_barrier.wait();
        conditional
            .reserve(&conditional_request)
            .map(|value| value.original_dispatch)
    });

    barrier.wait();
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Ok(true)))
            .count(),
        1
    );
    assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
}

#[test]
fn retained_claim_without_own_admission_record_cannot_redispatch() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let original = request();
    let claims =
        super::super::original_claim::OriginalClaims::new(blobs.clone(), refs.clone()).unwrap();
    assert_eq!(
        claims
            .reserve(
                &original.execution,
                super::super::original_claim::Route::Capability,
                &encode(&original).unwrap()
            )
            .unwrap(),
        super::super::original_claim::Reservation::Original
    );
    let ledger = ledger::CapabilityPreparationLedger::new(blobs, refs).unwrap();

    assert!(ledger.reserve(&original).is_err());
    assert!(ledger.state(&original.execution).is_err());
    assert_eq!(
        ledger.retention_roots().unwrap(),
        claims.retention_roots().unwrap()
    );
}
