//! Storage-fault evidence and journal tests.

use super::*;

fn storage_evidence_action() -> ResolvedBindingAction {
    ResolvedBindingAction {
        kind: crucible::model::BindingActionKind::Apply,
        binding: FaultObjectId::parse(String::from("storage-evidence-binding"))
            .unwrap_or_else(|error| panic!("test binding should parse: {error}")),
        target: ResolvedFaultTarget::BlockDevice {
            device: ContentHash::from_bytes(b"storage-evidence-device"),
        },
        phase: FaultPhase::Complete,
        effect: Arc::new(
            crucible::model::EffectRequest::new(
                crucible::model::EFFECT_SEMANTIC_VERSION,
                crucible::model::EffectLifetime::Persistent,
                EffectSpecification::Storage(StorageEffectSpecification::Availability {
                    state: crucible::model::StorageAvailabilityState::Online,
                    reconnect_policy: crucible::model::StorageTransitionPolicy::Preserve,
                }),
            )
            .unwrap_or_else(|error| panic!("test effect should validate: {error}")),
        ),
        mapping_output: Arc::new(crucible::model::ResolvedMappingOutput::Activation {
            active: true,
        }),
        mapped_digest: ContentHash::from_bytes(b"storage-evidence-mapping"),
        transition_sequence: 1,
        opportunity: Some(ContentHash::from_bytes(b"storage-evidence-opportunity")),
        coordinate: FaultCoordinate {
            virtual_nanos: 17,
            retired_instructions: None,
        },
        cause: crucible::model::BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn observation(evidence: &'static [u8]) -> FaultObservation {
    observation_at(0, evidence)
}

fn observation_at(nanos: u64, evidence: &'static [u8]) -> FaultObservation {
    FaultObservation {
        semantic_version: FAULT_RUNTIME_STATE_VERSION,
        kind: FaultObservationKind::EffectApplied,
        coordinate: FaultCoordinate {
            virtual_nanos: nanos,
            retired_instructions: None,
        },
        binding: None,
        target: None,
        opportunity: None,
        evidence: ContentHash::from_bytes(evidence),
    }
}

#[test]
fn ninep_result_evidence_excludes_locked_replay_authorization() {
    let action = storage_evidence_action();
    let mut locked = action.clone();
    locked.expected_precondition = Some(ContentHash::from_bytes(b"recorded-storage-state"));
    let request = NinepRequestOpportunity {
        identity: crucible_device::NinepRequestIdentity {
            request_icount: 19,
            transport_sequence: 3,
            tag: 7,
            digest: *blake3::hash(b"ninep-request").as_bytes(),
        },
        request_icount: 19,
        operation: NinepOperation::Read,
        frame: Vec::new(),
    };
    let response = LiveNinepResponseEvidence {
        completion_icount: 23,
        transport_sequence: 3,
        status: crucible_device::ResponseStatus::Ok,
        payload_len: 4,
        payload_digest: *blake3::hash(b"ninep-response").as_bytes(),
    };

    assert_ne!(action.id(), locked.id());
    assert_eq!(action.committed_state_id(), locked.committed_state_id());
    assert_eq!(
        ninep_result_evidence(&action, &request, &NinepResultDirective::Normal, response),
        ninep_result_evidence(&locked, &request, &NinepResultDirective::Normal, response),
    );
}

#[test]
fn observation_journal_drains_batches_in_global_sequence_order() {
    let earlier = observation(b"authorizing-evaluation");
    let same_sequence = observation(b"authorized-mutation");
    let later = observation(b"later");
    let mut journal = ProductionFaultObservationJournal::default();

    journal
        .append(9, vec![later.clone()])
        .unwrap_or_else(|error| panic!("later observation should append: {error}"));
    journal
        .append(3, vec![earlier.clone()])
        .unwrap_or_else(|error| panic!("earlier observations should append: {error}"));
    journal
        .append(3, vec![same_sequence.clone()])
        .unwrap_or_else(|error| panic!("same-sequence mutation should append: {error}"));

    assert_eq!(journal.snapshot(), vec![earlier, same_sequence, later]);
    let drained = journal.drain_ready(u64::MAX);
    assert_eq!(drained.len(), 3);
    assert!(journal.snapshot().is_empty());
}

#[test]
fn observation_journal_rolls_back_one_boundary_sequence_exactly() {
    let retained = observation(b"retained-before-boundary");
    let evaluation = observation(b"rolled-back-evaluation");
    let mutation = observation(b"rolled-back-mutation");
    let mut journal = ProductionFaultObservationJournal::default();
    journal
        .append(4, vec![retained.clone()])
        .unwrap_or_else(|error| panic!("prior observation should append: {error}"));
    journal
        .append(5, vec![evaluation, mutation])
        .unwrap_or_else(|error| panic!("boundary observations should append: {error}"));

    journal
        .rollback_sequence(5)
        .unwrap_or_else(|error| panic!("boundary sequence should roll back: {error}"));

    assert_eq!(journal.snapshot(), vec![retained]);
    assert!(!journal.contains_sequence(5));
}

#[test]
fn observation_journal_retains_future_batches_across_frontiers() {
    let earlier = observation_at(4, b"earlier");
    let future = observation_at(9, b"future");
    let same_time_later_sequence = observation_at(4, b"same-time-later-sequence");
    let mut journal = ProductionFaultObservationJournal::default();
    journal
        .append(7, vec![future.clone()])
        .unwrap_or_else(|error| panic!("future observation should append: {error}"));
    journal
        .append(2, vec![earlier.clone()])
        .unwrap_or_else(|error| panic!("earlier observation should append: {error}"));
    journal
        .append(5, vec![same_time_later_sequence.clone()])
        .unwrap_or_else(|error| panic!("same-time observation should append: {error}"));

    assert!(!journal.validate(7));
    assert_eq!(
        journal.drain_ready(4),
        vec![earlier, same_time_later_sequence]
    );
    assert_eq!(journal.snapshot(), vec![future.clone()]);
    assert!(journal.validate(8));
    assert_eq!(journal.drain_ready(9), vec![future]);
    assert!(journal.snapshot().is_empty());
    assert!(journal.validate(8));
}
