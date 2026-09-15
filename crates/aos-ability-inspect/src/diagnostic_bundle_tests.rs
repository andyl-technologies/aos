//! Tests for diagnostic bundle construction.

use aos_ability_model::{
    DecisionAlternative, DecisionNode, DecisionPredicate, DecisionSelector, DependencyEdge,
    DependencyKind, LocalKey, OperationResultReference, ResultProducerKey, ScopePath,
    ScopedOperationKey, TransactionId,
};
use aos_ability_validate::test_support::{
    checked_effect_plan, checked_lifecycle_effect_plan, plan_fixture,
};

use super::*;

#[test]
fn redacted_bundle_keeps_timeline_and_artifact_identity_without_private_values()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let bundle_digest = bundle.digest()?;
    let checked = bundle.check(Some(bundle_digest))?;
    let operation = OperationId {
        plan: plan.id(),
        operation: plan.document().operations[0].key.clone(),
    };
    let operation_node = PlanNodeKey::Operation {
        key: operation.operation.clone(),
    };
    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("private-transaction")?),
        &plan,
        PendingStateAvailability::RetainedClaims,
        vec![PendingOperationInput {
            operation: operation.clone(),
            blocking_dependencies: 1,
        }],
        vec![
            TimelineEventInput {
                sequence: 1,
                kind: TimelineEventKind::TransactionPlanned,
                node: None,
                attempt: None,
                selected_alternative: None,
                timing: TimelineTiming::Unavailable,
            },
            TimelineEventInput {
                sequence: 2,
                kind: TimelineEventKind::OperationAdmitted,
                node: Some(operation_node),
                attempt: NonZeroU32::new(1),
                selected_alternative: None,
                timing: TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 5 },
            },
        ],
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    )?;
    let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;

    assert_eq!(
        diagnostic.offline_replay(),
        ReplayAvailability::InputsRedacted
    );
    assert!(matches!(diagnostic.inputs(), ProtectedValue::Redacted));
    assert_eq!(diagnostic.timeline().events()[1].node_ordinal(), Some(0));
    assert_eq!(diagnostic.timeline().events().len(), 2);
    assert!(matches!(
        diagnostic.timeline().events()[1].node(),
        Some(ProtectedValue::Redacted)
    ));
    assert!(
        diagnostic
            .artifacts()
            .iter()
            .all(|artifact| matches!(artifact.store_path, ProtectedValue::Redacted))
    );
    assert_eq!(
        diagnostic.limitations(),
        &[
            DiagnosticLimitation::CommitmentCorrelationRetained,
            DiagnosticLimitation::NormalizedInputsRedacted,
            DiagnosticLimitation::ExecutionTopologyRedacted,
            DiagnosticLimitation::ArtifactLocationsRedacted,
            DiagnosticLimitation::ExecutionEvidenceRedacted,
            DiagnosticLimitation::NativeExecutionQualificationNotIncluded,
            DiagnosticLimitation::ExecutionRecordProvenanceUnverified,
            DiagnosticLimitation::JournalAuthenticationNotVerified,
            DiagnosticLimitation::RetainedRecordsNotLiveObservation,
            DiagnosticLimitation::OfflineReplayInputsRedacted,
        ]
    );

    let bytes = diagnostic.canonical_bytes()?;
    for private_value in ["private-transaction", "\"observe\"", "/nix/store/"] {
        assert!(
            !bytes
                .windows(private_value.len())
                .any(|window| window == private_value.as_bytes())
        );
    }
    Ok(())
}

#[test]
fn deployment_bundle_retains_inputs_but_never_runtime_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let bundle_digest = bundle.digest()?;
    let checked = bundle.check(Some(bundle_digest))?;
    let operation = OperationId {
        plan: plan.id(),
        operation: plan.document().operations[0].key.clone(),
    };
    let operation_node = PlanNodeKey::Operation {
        key: operation.operation.clone(),
    };
    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("transaction")?),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        vec![TimelineEventInput {
            sequence: 1,
            kind: TimelineEventKind::EffectCompleted,
            node: Some(operation_node),
            attempt: NonZeroU32::new(1),
            selected_alternative: None,
            timing: TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 8 },
        }],
        TimelineProvenance::CallerAssertedJournalAnchor {
            journal: Sha256Digest::of_bytes("journal"),
        },
        DiagnosticBundleAudience::Deployment,
    )?;
    let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;

    assert_eq!(diagnostic.offline_replay(), ReplayAvailability::Available);
    assert!(matches!(
        diagnostic.inputs(),
        ProtectedValue::Disclosed { .. }
    ));
    assert_eq!(
        diagnostic.limitations(),
        &[
            DiagnosticLimitation::ExecutionEvidenceRedacted,
            DiagnosticLimitation::NativeExecutionQualificationNotIncluded,
            DiagnosticLimitation::PendingDependencyStateUnavailable,
            DiagnosticLimitation::JournalAuthenticationNotVerified,
            DiagnosticLimitation::RetainedRecordsNotLiveObservation,
        ]
    );
    Ok(())
}

#[test]
fn timeline_rejects_foreign_operations_scope_errors_and_reordered_events()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let operation = OperationId {
        plan: plan.id(),
        operation: plan.document().operations[0].key.clone(),
    };
    let operation_node = PlanNodeKey::Operation {
        key: operation.operation.clone(),
    };
    let transaction = TransactionId(LocalKey::new("transaction")?);

    let foreign_pending = ExecutionTimeline::from_records(
        transaction.clone(),
        &plan,
        PendingStateAvailability::RetainedClaims,
        vec![PendingOperationInput {
            operation: OperationId {
                plan: PlanId(Sha256Digest::of_bytes("foreign-plan")),
                operation: operation.operation.clone(),
            },
            blocking_dependencies: 1,
        }],
        Vec::new(),
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    );
    assert!(matches!(
        foreign_pending,
        Err(DiagnosticBundleError::UnknownOperation)
    ));

    let reordered = ExecutionTimeline::from_records(
        transaction.clone(),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        vec![
            TimelineEventInput {
                sequence: 2,
                kind: TimelineEventKind::TransactionPlanned,
                node: None,
                attempt: None,
                selected_alternative: None,
                timing: TimelineTiming::Unavailable,
            },
            TimelineEventInput {
                sequence: 1,
                kind: TimelineEventKind::EffectStarted,
                node: Some(operation_node),
                attempt: NonZeroU32::new(1),
                selected_alternative: None,
                timing: TimelineTiming::Unavailable,
            },
        ],
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    );
    assert!(matches!(
        reordered,
        Err(DiagnosticBundleError::NoncanonicalEventOrder)
    ));

    let invalid_scope = ExecutionTimeline::from_records(
        transaction,
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        vec![TimelineEventInput {
            sequence: 1,
            kind: TimelineEventKind::EffectStarted,
            node: None,
            attempt: NonZeroU32::new(1),
            selected_alternative: None,
            timing: TimelineTiming::Unavailable,
        }],
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    );
    assert!(matches!(
        invalid_scope,
        Err(DiagnosticBundleError::InvalidEventScope)
    ));
    Ok(())
}

#[test]
fn timeline_enforces_event_timing_shape_and_rejects_operation_recovery_regression()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let operation_node = PlanNodeKey::Operation {
        key: plan.document().operations[0].key.clone(),
    };
    let transaction = TransactionId(LocalKey::new("transaction")?);
    let event = |sequence, kind, timing| TimelineEventInput {
        sequence,
        kind,
        node: Some(operation_node.clone()),
        attempt: NonZeroU32::new(1),
        selected_alternative: None,
        timing,
    };

    let missing_operation_timing = ExecutionTimeline::from_records(
        transaction.clone(),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        vec![event(
            1,
            TimelineEventKind::EffectStarted,
            TimelineTiming::Unavailable,
        )],
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    );
    assert!(matches!(
        missing_operation_timing,
        Err(DiagnosticBundleError::InvalidEventTiming)
    ));

    let backwards = ExecutionTimeline::from_records(
        transaction,
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        vec![
            event(
                1,
                TimelineEventKind::OperationAdmitted,
                TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 9 },
            ),
            event(
                2,
                TimelineEventKind::EffectStarted,
                TimelineTiming::OperationRecoveryElapsed { elapsed_millis: 1 },
            ),
        ],
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    );
    assert!(matches!(
        backwards,
        Err(DiagnosticBundleError::NoncanonicalElapsedTime)
    ));
    Ok(())
}

#[test]
fn timeline_tracks_recovery_elapsed_per_operation_across_interleaved_retries()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = plan_fixture();
    let mut second_operation = fixture.effect_plan.operations[0].clone();
    second_operation.key.key = LocalKey::new("observe-second")?;
    fixture.effect_plan.operations.push(second_operation);
    let plan = fixture.validate()?;
    let first = PlanNodeKey::Operation {
        key: plan.document().operations[0].key.clone(),
    };
    let second = PlanNodeKey::Operation {
        key: plan.document().operations[1].key.clone(),
    };
    let event = |sequence, node, elapsed_millis| TimelineEventInput {
        sequence,
        kind: TimelineEventKind::RetryScheduled,
        node: Some(node),
        attempt: NonZeroU32::new(1),
        selected_alternative: None,
        timing: TimelineTiming::OperationRecoveryElapsed { elapsed_millis },
    };

    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("transaction")?),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        vec![
            event(1, first.clone(), 9),
            event(2, second, 1),
            event(3, first, 10),
        ],
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    )?;

    assert_eq!(timeline.events().len(), 3);
    assert_eq!(timeline.events()[0].node_ordinal(), Some(0));
    assert_eq!(timeline.events()[1].node_ordinal(), Some(1));
    Ok(())
}

#[test]
fn branch_selection_retains_a_checked_ordinal_and_protects_its_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_branch_plan()?;
    let decision = &plan.document().decisions[0];
    let transaction = TransactionId(LocalKey::new("transaction")?);
    let event = |selected_alternative, audience| {
        ExecutionTimeline::from_records(
            transaction.clone(),
            &plan,
            PendingStateAvailability::Unavailable,
            Vec::new(),
            vec![TimelineEventInput {
                sequence: 1,
                kind: TimelineEventKind::BranchSelected,
                node: Some(PlanNodeKey::Decision {
                    key: decision.key.clone(),
                }),
                attempt: None,
                selected_alternative: Some(selected_alternative),
                timing: TimelineTiming::Unavailable,
            }],
            TimelineProvenance::UnverifiedRetainedRecords,
            audience,
        )
    };

    let redacted = event(
        decision.alternatives[1].key.clone(),
        DiagnosticBundleAudience::Redacted,
    )?;
    assert_eq!(redacted.events()[0].selected_alternative_ordinal(), Some(1));
    assert!(matches!(
        redacted.events()[0].selected_alternative(),
        Some(ProtectedValue::Redacted)
    ));

    let unknown = event(
        LocalKey::new("unknown-alternative")?,
        DiagnosticBundleAudience::Deployment,
    );
    assert!(matches!(
        unknown,
        Err(DiagnosticBundleError::InvalidBranchSelection)
    ));
    Ok(())
}

#[test]
fn deployment_bundle_round_trips_and_reconstructs_checked_replay_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let checked = bundle.clone().check(Some(bundle.digest()?))?;
    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("transaction")?),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        Vec::new(),
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Deployment,
    )?;
    let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;

    let bytes = diagnostic.canonical_bytes()?;
    let decoded = DiagnosticBundle::decode(&bytes)?;
    let replay = decoded.replay_inputs()?;

    assert_eq!(decoded, diagnostic);
    assert_eq!(replay.digest(), checked.digest());
    assert_eq!(replay.plan().id(), checked.plan().id());
    Ok(())
}

#[test]
fn redacted_bundle_decodes_but_reports_that_replay_inputs_are_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let checked = bundle.clone().check(Some(bundle.digest()?))?;
    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("transaction")?),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        Vec::new(),
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    )?;
    let bytes = DiagnosticBundle::from_checked(&checked, timeline)?.canonical_bytes()?;

    let decoded = DiagnosticBundle::decode(&bytes)?;
    assert!(matches!(
        decoded.replay_inputs(),
        Err(DiagnosticBundleError::ReplayInputsRedacted)
    ));
    Ok(())
}

#[test]
fn diagnostic_decode_rejects_noncanonical_json() -> Result<(), Box<dyn std::error::Error>> {
    let plan = checked_effect_plan();
    let bundle = InspectionBundle::from_checked(&plan)?;
    let checked = bundle.clone().check(Some(bundle.digest()?))?;
    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("transaction")?),
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        Vec::new(),
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    )?;
    let mut bytes = DiagnosticBundle::from_checked(&checked, timeline)?.canonical_bytes()?;
    bytes.push(b'\n');

    assert!(matches!(
        DiagnosticBundle::decode(&bytes),
        Err(DiagnosticBundleError::NoncanonicalEncoding)
    ));
    Ok(())
}

#[test]
fn bundle_rejects_a_timeline_from_another_checked_plan() -> Result<(), Box<dyn std::error::Error>> {
    let timeline_plan = checked_effect_plan();
    let timeline = ExecutionTimeline::from_records(
        TransactionId(LocalKey::new("transaction")?),
        &timeline_plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        Vec::new(),
        TimelineProvenance::UnverifiedRetainedRecords,
        DiagnosticBundleAudience::Redacted,
    )?;
    let other_plan = checked_lifecycle_effect_plan();
    let other_bundle = InspectionBundle::from_checked(&other_plan)?;
    let other_checked = other_bundle.check(None)?;

    assert!(matches!(
        DiagnosticBundle::from_checked(&other_checked, timeline),
        Err(DiagnosticBundleError::PlanMismatch)
    ));
    Ok(())
}

fn checked_branch_plan() -> Result<CheckedEffectPlan, Box<dyn std::error::Error>> {
    let mut fixture = plan_fixture();
    let operation = fixture.effect_plan.operations[0].key.clone();
    let decision = ScopedOperationKey {
        scope: ScopePath::root(),
        key: LocalKey::new("select-ready")?,
    };
    fixture.effect_plan.decisions = vec![DecisionNode {
        key: decision.clone(),
        branch_context: Vec::new(),
        selector: DecisionSelector {
            result: OperationResultReference {
                producer: ResultProducerKey::Operation {
                    key: operation.clone(),
                },
                output: LocalKey::new("ready")?,
            },
            tag_field: None,
        },
        alternatives: vec![
            DecisionAlternative {
                key: LocalKey::new("false")?,
                predicate: DecisionPredicate::Boolean { value: false },
            },
            DecisionAlternative {
                key: LocalKey::new("true")?,
                predicate: DecisionPredicate::Boolean { value: true },
            },
        ],
    }];
    fixture.effect_plan.edges = vec![DependencyEdge {
        from: PlanNodeKey::Operation { key: operation },
        to: PlanNodeKey::Decision { key: decision },
        kind: DependencyKind::Data,
    }];
    Ok(fixture.validate()?)
}
