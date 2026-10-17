//! Exercises portable epoch data without native certificates or live authority.

// These bounded data-only fixtures intentionally panic on lineage regressions.
// crucible-lint: allow panic-shortcut -- These data-only tests deliberately panic on invalid fixtures or failed finite lineage invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_scheduling::{SavedBound, SavedOwner, SavedPermission};
use crucible_node_contract::{HashRef, Phase};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position(time: u64) -> Position {
    Position::new(time.into(), 0.into(), Phase::BoundaryControl)
}

fn payload(bytes: &[u8], media: &str) -> InputPayload {
    InputPayload {
        reference: canonical::content_ref(bytes, media).unwrap(),
        bytes: bytes.to_vec(),
    }
}

fn snapshot() -> SchedulingSnapshot {
    SchedulingSnapshot {
        schema_version: 1,
        original_epochs: None,
        ordering_profile: "superdense-v1".into(),
        world_binding_hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.world-binding.v1".into(),
            digest: "1".repeat(64),
        },
        source_activation_id: id("source/activation"),
        source_generation: 1.into(),
        source_boundary: position(0),
        capture_cut: position(10),
        capture_ordinal: 17.into(),
        source_owners: vec![SavedOwner {
            owner: id("owner/cpu"),
            incarnation: id("source/cpu"),
            generation: 1.into(),
        }],
        maximum_microsteps: 1_000_000.into(),
        positions: vec![SavedPosition {
            owner: id("owner/cpu"),
            position: position(0),
        }],
        producers: vec![SavedProducer {
            node: id("cpu"),
            bound: SavedBound::Unknown,
            closed_prefix: position(0),
            next_sequence: Some(0.into()),
        }],
        native_sequences: vec![],
        external_closed_prefixes: vec![],
        payload_objects: vec![],
        pending_deliveries: vec![],
        used_operations: vec![id("original/run")],
        reservations: vec![SavedReservation {
            operation: id("original/run"),
            node: id("cpu"),
            owner: id("owner/cpu"),
            permission: SavedPermission::ExactRun {
                start: position(0),
                limit: position(1_000_000),
                input_blocked_park: false,
            },
            input_batch: None,
        }],
        input_batches: vec![],
        used_input_batches: vec![],
    }
}

fn row(source: &SchedulingSnapshot) -> SavedSchedulingEpoch {
    let reference = payload(b"{}", "application/json").reference;
    SavedSchedulingEpoch {
        schema_version: 1,
        coordinator: reference.clone(),
        scheduler: reference.clone(),
        runtime: reference,
        policy: closed_scheduling_epoch_policy().unwrap(),
        source_generation: 1.into(),
        reservations: vec![SavedEpochReservation {
            reservation: source.reservations[0].clone(),
            position: source.positions[0].clone(),
            producer: source.producers[0].clone(),
        }],
    }
}

fn fresh_snapshot(source: &SchedulingSnapshot, row: SavedSchedulingEpoch) -> SchedulingSnapshot {
    let mut snapshot = source.clone();
    snapshot.schema_version = 2;
    snapshot.source_generation = 2.into();
    snapshot.source_boundary = position(10);
    snapshot.source_activation_id = id("fresh/activation");
    snapshot.source_owners[0].incarnation = id("fresh/cpu");
    snapshot.source_owners[0].generation = 2.into();
    snapshot.original_epochs = Some(vec![row]);
    snapshot
}

#[test]
fn legacy_bytes_and_hash_domain_have_no_epoch_marker() {
    let snapshot = snapshot();
    let value = serde_json::to_value(&snapshot).unwrap();
    assert!(value.get("original_epochs").is_none());
    assert_eq!(
        snapshot.continuation_hash().unwrap(),
        canonical::json_hash("cnp.scheduler-continuation.v1", &snapshot).unwrap()
    );

    let epoch = row(&snapshot);
    let current = fresh_snapshot(&snapshot, epoch);
    assert_eq!(
        current.continuation_hash().unwrap(),
        canonical::json_hash("cnp.scheduler-continuation.v2", &current).unwrap()
    );
    assert_ne!(
        snapshot.continuation_hash().unwrap().domain,
        current.continuation_hash().unwrap().domain
    );
}

#[test]
fn inherited_row_cannot_change_the_original_grant_input_or_cursor() {
    let source = snapshot();
    let original = row(&source);
    let current = fresh_snapshot(&source, original.clone());
    assert!(original.validate_row(&current).is_ok());

    let mut changed = original.clone();
    changed.reservations[0].reservation.permission = SavedPermission::ExactRun {
        start: position(0),
        limit: position(2_000_000),
        input_blocked_park: false,
    };
    assert!(changed.validate_row(&current).is_err());
    let mut changed = original.clone();
    changed.reservations[0].reservation.input_batch = Some(id("invented/input"));
    assert!(changed.validate_row(&current).is_err());
    let mut changed = original;
    changed.reservations[0].position.position = position(1);
    assert!(changed.validate_row(&current).is_err());
}

#[test]
fn fault_three_keeps_legacy_one_and_original_epoch_two_as_distinct_grammars() {
    use crate::node_contract::FaultMutationRequest;

    let legacy = snapshot();
    let inherited = fresh_snapshot(&legacy, row(&legacy));
    for original in [&legacy, &inherited] {
        crate::node_scheduling::scheduler::validate_snapshot_structure(original).unwrap();
        let bytes = canonical::canonical_json(&serde_json::to_value(original).unwrap()).unwrap();
        let decoded: SchedulingSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(&decoded, original);
        assert_eq!(
            decoded.continuation_hash().unwrap(),
            original.continuation_hash().unwrap()
        );
    }

    let mut fault = legacy.clone();
    fault.schema_version = 3;
    fault.reservations[0].permission = SavedPermission::FaultInjectionV1 {
        request: Box::new(FaultMutationRequest {
            version: 1,
            facet_profile: id("host/fault-injection-v1"),
            program: payload(b"installed-controller", "application/json").reference,
            decision: 0.into(),
            at: position(0),
        }),
    };
    crate::node_scheduling::scheduler::validate_snapshot_structure(&fault).unwrap();
    assert_eq!(
        fault.continuation_hash().unwrap().domain,
        "cnp.scheduler-continuation.v3"
    );

    for edition in [1, 2] {
        let mut incorrectly_labeled = fault.clone();
        incorrectly_labeled.schema_version = edition;
        assert!(
            crate::node_scheduling::scheduler::validate_snapshot_structure(&incorrectly_labeled)
                .is_err()
        );
    }
    let mut combined = fault.clone();
    combined.original_epochs = inherited.original_epochs.clone();
    assert!(crate::node_scheduling::scheduler::validate_snapshot_structure(&combined).is_err());
    let mut mislabeled_epoch = inherited;
    mislabeled_epoch.schema_version = 3;
    assert!(
        crate::node_scheduling::scheduler::validate_snapshot_structure(&mislabeled_epoch).is_err()
    );
}

#[test]
fn discharged_or_forward_epoch_is_not_a_lower_cursor_exception() {
    let source = snapshot();
    let original = row(&source);
    let mut current = fresh_snapshot(&source, original.clone());
    current.reservations.clear();
    assert!(original.validate_row(&current).is_err());

    let current = fresh_snapshot(&source, original.clone());
    let mut forward = original;
    forward.source_generation = current.source_generation;
    assert!(forward.validate_row(&current).is_err());
}

#[test]
fn body_credits_and_full_typed_aliases_are_checked_independently() {
    let policy = payload(b"installed-policy", "text/plain");
    let first = payload(b"{}", "application/json");
    let second = payload(b"{}", "application/vnd.crucible.original-scheduler+json");
    assert_eq!(first.reference.hash, second.reference.hash);
    let evidence = SchedulingEpochEvidence {
        policy,
        rows: vec![],
        objects: vec![first.clone(), second],
    };
    assert!(validate_evidence(&evidence).is_ok());

    let mut ambiguous = evidence.clone();
    ambiguous.objects.push(first);
    assert!(validate_evidence(&ambiguous).is_err());
    let mut changed = evidence.clone();
    changed.objects[0].bytes.push(b' ');
    assert!(validate_evidence(&changed).is_err());
    let mut exhausted = evidence;
    exhausted.objects = vec![payload(
        &vec![0; MAXIMUM_SCHEDULING_EPOCH_BYTES],
        "application/octet-stream",
    )];
    assert!(validate_evidence(&exhausted).is_err());
}

#[test]
fn legacy_native_verifier_refuses_epoch_two_without_invoking_native_continuation() {
    use crate::node_contract::{
        ActivationRecord, NativeRuntimeContinuationEvidence, NativeRuntimeContinuationVerifier,
        OwnerIdentity, RuntimeError, RuntimeSnapshot, SavedRuntimeActivation,
    };

    struct LegacyVerifier {
        native_calls: usize,
    }
    impl NativeRuntimeContinuationVerifier for LegacyVerifier {
        fn verify_runtime_continuation(
            &mut self,
            _: &RuntimeSnapshot,
            _: &SchedulingSnapshot,
            _: &ActivationRecord,
        ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
            self.native_calls += 1;
            Err(RuntimeError::InvalidReceipt)
        }
    }

    let source = snapshot();
    let target = ActivationRecord {
        generation: 2.into(),
        activation_id: id("fresh/activation"),
        world_binding_hash: source.world_binding_hash.clone(),
        owners: vec![OwnerIdentity {
            owner: id("owner/cpu"),
            incarnation: id("fresh/cpu"),
            generation: 2.into(),
        }],
        boundary: source.capture_cut,
    };
    let runtime = RuntimeSnapshot {
        schema_version: 1,
        source_activation: SavedRuntimeActivation {
            generation: source.source_generation,
            activation_id: source.source_activation_id.clone(),
            world_binding_hash: source.world_binding_hash.clone(),
            owners: vec![],
            boundary: source.source_boundary,
        },
        capture_cut: source.capture_cut,
        capture_ordinal: source.capture_ordinal,
        owners: vec![],
        operations: vec![],
        inputs: vec![],
        terminal: None,
        condition_stop: None,
    };
    let mut legacy = LegacyVerifier { native_calls: 0 };
    assert!(
        legacy
            .preserve_scheduling_epochs(&runtime, &source, &target)
            .unwrap()
            .is_none()
    );
    let current = fresh_snapshot(&source, row(&source));
    assert!(
        legacy
            .preserve_scheduling_epochs(&runtime, &current, &target)
            .is_err()
    );
    assert_eq!(legacy.native_calls, 0);
}

#[test]
fn continuation_hash_preserves_old_domains_and_separates_condition_four() {
    let mut source = snapshot();
    let mut identities = std::collections::BTreeSet::new();
    for (edition, domain) in [
        (1, "cnp.scheduler-continuation.v1"),
        (2, "cnp.scheduler-continuation.v2"),
        (3, "cnp.scheduler-continuation.v3"),
        (4, "cnp.scheduler-continuation.v4"),
    ] {
        source.schema_version = edition;
        let original = canonical::canonical_json(&serde_json::to_value(&source).unwrap()).unwrap();
        let expected = canonical::hash(domain, &original).unwrap();
        assert_eq!(source.continuation_hash().unwrap(), expected);
        assert!(identities.insert(expected));
    }
    source.schema_version = 5;
    assert!(source.continuation_hash().is_err());
}
