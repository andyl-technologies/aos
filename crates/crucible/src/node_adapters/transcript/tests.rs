//! Adversarial data, preallocation and authenticated replay-cursor model checks.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test failures deliberately panic.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crucible_node_contract::{ContentRef, Id, Phase, Position, Repeatability, U64, canonical};

use crate::{node_contract::*, node_scheduling::InputPayload};

use super::{capture::CaptureSession, codec::encode, control::*, replay::ReplayCursor, *};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "crucible-transcript-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn position(time: u64) -> Position {
    Position::new(time.into(), 0.into(), Phase::BoundaryControl)
}
fn object(bytes: &[u8]) -> InputPayload {
    InputPayload {
        reference: canonical::content_ref(bytes, "application/json").unwrap(),
        bytes: bytes.to_vec(),
    }
}
fn limits() -> TranscriptLimits {
    TranscriptLimits {
        maximum_records: 16.into(),
        maximum_record_bytes: 100_000.into(),
        maximum_total_bytes: 2_000_000.into(),
    }
}

fn origin() -> TranscriptOrigin {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let node = graph.node_ids().next().unwrap();
    let binding = graph.binding(node).unwrap();
    let owner = OwnerIdentity {
        owner: binding.compatibility.execution_owner.id.clone(),
        incarnation: binding.authority.incarnation_id.clone(),
        generation: binding.authority.owner_generation,
    };
    let source = object(&encode(binding).unwrap());
    TranscriptOrigin {
        attempt: id("source/actual-attempt"),
        activation: SavedRuntimeActivation {
            generation: 1.into(),
            activation_id: id("source/activation"),
            world_binding_hash: graph.world_binding_hash().clone(),
            owners: vec![owner.clone()],
            boundary: position(0),
        },
        route: NodeRoute {
            node: node.clone(),
            owners: vec![owner],
        },
        source_binding: source.reference.clone(),
        context: vec![source, object(b"{\"clock\":\"fixed\",\"faults\":[]}")],
        repeatability: Repeatability::Nondeterministic,
    }
}

pub(super) fn capture() -> CapturedTranscript {
    // This is a pure model fixture. Production seals are minted only by the
    // actual RecordingNode after original source validation and native ACK.
    let mut capture = CaptureSession::new(origin(), limits()).unwrap();
    let reservation = capture.reserve().unwrap();
    let body = ControlRequest::Acknowledge {
        operation: id("original/operation"),
        outputs: vec![id("original/output")],
    };
    let request = request(
        TranscriptAction::Acknowledge,
        id("original/operation"),
        position(0),
        capture.context().unwrap(),
        &body,
    )
    .unwrap();
    capture
        .retain(
            reservation,
            request,
            encode(&ControlResponse::Acknowledged).unwrap(),
            vec![object(b"{\"original_proof\":1}")],
            vec![position(50)],
            PhysicalTimingUncertainty::Unbounded,
        )
        .unwrap();
    capture.finish().unwrap()
}

pub(super) fn cursor(source: AuthenticatedTranscript) -> ReplayCursor {
    let route = source.transcript().origin.route.clone();
    ReplayCursor {
        qualification: ReplayQualification {
            proof: object(b"{\"model_only\":true}"),
            source_context: context_commitment(&source.transcript().origin).unwrap(),
            target_world: source
                .transcript()
                .origin
                .activation
                .world_binding_hash
                .clone(),
            target_binding: source.transcript().origin.source_binding.clone(),
            target_route: route,
        },
        source,
        next: 0,
        diverged: false,
    }
}

#[test]
fn complete_raw_bytes_and_origin_uncertainty_survive_source_independent_archive() {
    let directory = Directory::new();
    let archive = TranscriptArchive::open(&directory.0, limits()).unwrap();
    let saved = archive.persist(capture()).unwrap();
    let reference = saved.reference().clone();
    let bytes = saved.bytes().to_vec();
    drop(saved);
    drop(archive);

    let archive = TranscriptArchive::open(&directory.0, limits()).unwrap();
    let source = archive.load(&reference).unwrap();
    assert_eq!(source.bytes(), bytes);
    assert_eq!(
        source.transcript().origin.repeatability,
        Repeatability::Nondeterministic
    );
    assert_eq!(
        source.transcript().records[0].physical_uncertainty,
        PhysicalTimingUncertainty::Unbounded
    );
    assert_eq!(
        BoundaryTranscript::from_canonical_bytes(&bytes).unwrap(),
        *source.transcript()
    );
}

#[test]
fn changed_request_and_reordered_request_diverge_before_any_response() {
    for changed in ["bytes", "identity", "position", "context", "action"] {
        let directory = Directory::new();
        let archive = TranscriptArchive::open(&directory.0, limits()).unwrap();
        let source = archive.persist(capture()).unwrap();
        let mut request = source.transcript().records[0].request.clone();
        let original = request.clone();
        match changed {
            "bytes" => {
                request.bytes.push(b' ');
                request.content =
                    canonical::content_ref(&request.bytes, "application/json").unwrap();
            }
            "identity" => request.identity = id("changed/operation"),
            "position" => request.boundary = position(1),
            "context" => request.context = object(b"changed clocks/faults").reference,
            "action" => request.action = TranscriptAction::Begin,
            _ => unreachable!(),
        }
        let mut cursor = cursor(source);
        assert!(
            matches!(
                cursor.replay(&request),
                Err(TranscriptError::Divergence { .. })
            ),
            "{changed}"
        );
        assert_eq!(cursor.snapshot().next_record, U64::new(0));
        assert!(cursor.snapshot().diverged);
        assert!(
            cursor.replay(&original).is_err(),
            "a later retry cannot revive a counterfactual branch"
        );
    }
}

#[test]
fn unrecorded_future_is_not_simulated_or_resampled() {
    let directory = Directory::new();
    let archive = TranscriptArchive::open(&directory.0, limits()).unwrap();
    let source = archive.persist(capture()).unwrap();
    let request = source.transcript().records[0].request.clone();
    let expected = source.transcript().records[0].response_bytes.clone();
    let mut cursor = cursor(source);

    assert_eq!(cursor.replay(&request).unwrap().response_bytes, expected);
    assert!(cursor.replay(&request).is_err());
    assert_eq!(cursor.snapshot().next_record, U64::new(1));
    assert!(cursor.snapshot().diverged);
}

#[test]
fn public_hashes_cannot_replace_original_source_authentication() {
    let first = Directory::new();
    let second = Directory::new();
    let archive = TranscriptArchive::open(&first.0, limits()).unwrap();
    let source = archive.persist(capture()).unwrap();
    let name = format!("transcript-{}", source.reference().hash.digest);
    let other = TranscriptArchive::open(&second.0, limits()).unwrap();
    fs::copy(first.0.join(&name), second.0.join(&name)).unwrap();
    assert!(matches!(
        other.load(source.reference()),
        Err(TranscriptError::Unqualified(_))
    ));

    let path = first.0.join(&name);
    let mut bytes = fs::read(&path).unwrap();
    bytes[48 + 10] ^= 1;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, bytes).unwrap();
    assert!(archive.load(source.reference()).is_err());
}

#[test]
fn full_reservation_is_required_before_another_effect_can_begin() {
    let mut capture = CaptureSession::new(
        origin(),
        TranscriptLimits {
            maximum_records: 1.into(),
            maximum_record_bytes: 100_000.into(),
            maximum_total_bytes: 200_000.into(),
        },
    )
    .unwrap();
    let _first = capture.reserve().unwrap();
    assert_eq!(capture.reserve().err(), Some(TranscriptError::CaptureLimit));
    assert!(
        capture.finish().is_err(),
        "overflow cannot silently export a replayable prefix"
    );
}

#[test]
fn lost_original_response_and_post_effect_truncation_invalidate_capture() {
    let mut lost = CaptureSession::new(origin(), limits()).unwrap();
    let _reservation = lost.reserve().unwrap();
    assert!(lost.finish().is_err());

    let mut capture = CaptureSession::new(
        origin(),
        TranscriptLimits {
            maximum_records: 2.into(),
            maximum_record_bytes: 20_000.into(),
            maximum_total_bytes: 100_000.into(),
        },
    )
    .unwrap();
    let reservation = capture.reserve().unwrap();
    let body = ControlRequest::Acknowledge {
        operation: id("original/operation"),
        outputs: vec![],
    };
    let request = request(
        TranscriptAction::Acknowledge,
        id("original/operation"),
        position(0),
        capture.context().unwrap(),
        &body,
    )
    .unwrap();
    assert!(
        capture
            .retain(
                reservation,
                request,
                vec![b'a'; 30_000],
                Vec::new(),
                Vec::new(),
                PhysicalTimingUncertainty::Unbounded
            )
            .is_err()
    );
    assert!(capture.finish().is_err());
}

#[test]
fn source_lineage_sequence_and_missing_raw_objects_are_checked() {
    let source = capture();
    let mut data = source.transcript().clone();
    data.records[0].sequence = 1.into();
    assert!(data.canonical_bytes().is_err());
    data = source.transcript().clone();
    data.origin.context.clear();
    assert!(data.canonical_bytes().is_err());
    data = source.transcript().clone();
    data.records[0].response_bytes.clear();
    assert!(data.canonical_bytes().is_err());
    data = source.transcript().clone();
    data.origin.route.owners[0].generation = 99.into();
    assert!(data.canonical_bytes().is_err());
}

#[test]
fn absent_physical_measurement_bytes_cannot_claim_a_bounded_interval() {
    let source = capture();
    let mut data = source.transcript().clone();
    let reference: ContentRef = object(b"{\"actual_clock\":true}").reference;
    data.records[0].physical_uncertainty = PhysicalTimingUncertainty::ObservedInterval {
        earliest_ns: 1.into(),
        latest_ns: 2.into(),
        evidence: reference,
    };
    assert!(data.canonical_bytes().is_err());
}

#[test]
fn producer_proof_inventory_requires_original_scope_and_complete_raw_dependencies() {
    let mut data = capture().transcript().clone();
    let root = object(b"{\"native_root\":1}");
    let dependency = object(b"{\"native_dependency\":2}");
    let proof = super::proof::RecordedProofClosure::capture(
        &data.origin,
        root.reference.clone(),
        vec![dependency.reference.clone()],
    )
    .unwrap();
    data.records[0].evidence = vec![root.clone(), dependency.clone(), proof.clone()];
    assert!(data.canonical_bytes().is_ok());

    let mut missing = data.clone();
    missing.records[0]
        .evidence
        .retain(|object| object.reference != dependency.reference);
    assert!(missing.canonical_bytes().is_err());

    let mut duplicated = data.clone();
    duplicated.records[0].evidence[2] = super::proof::RecordedProofClosure::capture(
        &data.origin,
        root.reference.clone(),
        vec![dependency.reference.clone(), dependency.reference],
    )
    .unwrap();
    assert!(duplicated.canonical_bytes().is_err());

    let mut foreign_origin = data.origin.clone();
    foreign_origin.route.node = id("other/source");
    let mut foreign = data;
    foreign.records[0].evidence[2] =
        super::proof::RecordedProofClosure::capture(&foreign_origin, root.reference, vec![])
            .unwrap();
    assert!(foreign.canonical_bytes().is_err());
}

#[test]
fn original_bytes_can_fill_two_distinct_typed_content_roles() {
    let mut data = capture().transcript().clone();
    let json = object(b"{\"original_native_custody\":true}");
    let binary = InputPayload {
        reference: canonical::content_ref(&json.bytes, "application/octet-stream").unwrap(),
        bytes: json.bytes.clone(),
    };
    assert_eq!(json.reference.hash, binary.reference.hash);
    assert_ne!(json.reference, binary.reference);

    let proof = super::proof::RecordedProofClosure::capture(
        &data.origin,
        json.reference.clone(),
        vec![binary.reference.clone()],
    )
    .unwrap();
    data.records[0].evidence = vec![json.clone(), binary.clone(), proof];
    data.records[0].physical_uncertainty = PhysicalTimingUncertainty::ObservedInterval {
        earliest_ns: 1.into(),
        latest_ns: 2.into(),
        evidence: binary.reference.clone(),
    };

    let encoded = data.canonical_bytes().unwrap();
    let restored = BoundaryTranscript::from_canonical_bytes(&encoded).unwrap();
    assert_eq!(restored, data);
    assert_eq!(restored.records[0].evidence[0], json);
    assert_eq!(restored.records[0].evidence[1], binary);
}

#[test]
fn typed_roles_do_not_authorize_changed_bytes_or_unretained_roles() {
    let mut data = capture().transcript().clone();
    let json = object(b"{\"original_native_custody\":true}");
    let binary = InputPayload {
        reference: canonical::content_ref(&json.bytes, "application/octet-stream").unwrap(),
        bytes: json.bytes.clone(),
    };
    let proof = super::proof::RecordedProofClosure::capture(
        &data.origin,
        json.reference.clone(),
        vec![binary.reference.clone()],
    )
    .unwrap();
    data.records[0].evidence = vec![json, binary, proof];
    assert!(data.canonical_bytes().is_ok());

    let mut changed_bytes = data.clone();
    changed_bytes.records[0].evidence[1].bytes.push(b' ');
    assert!(changed_bytes.canonical_bytes().is_err());

    let mut changed_role = data.clone();
    changed_role.records[0].evidence[1].reference.media_type = "application/other".into();
    assert!(changed_role.canonical_bytes().is_err());

    let mut changed_enrollment_role = data.clone();
    let source_binding = changed_enrollment_role.origin.source_binding.clone();
    let enrolled = changed_enrollment_role
        .origin
        .context
        .iter_mut()
        .find(|object| object.reference == source_binding)
        .unwrap();
    enrolled.reference.media_type = "application/unenrolled-binding".into();
    assert!(changed_enrollment_role.canonical_bytes().is_err());

    let mut changed_measurement_role = data;
    let mut evidence = changed_measurement_role.records[0].evidence[1]
        .reference
        .clone();
    evidence.media_type = "application/unenrolled-measurement".into();
    changed_measurement_role.records[0].physical_uncertainty =
        PhysicalTimingUncertainty::ObservedInterval {
            earliest_ns: 1.into(),
            latest_ns: 2.into(),
            evidence,
        };
    assert!(changed_measurement_role.canonical_bytes().is_err());
}

#[test]
fn simultaneous_reservations_charge_complete_envelope_separators_before_effects() {
    let source = capture();
    let prototype = source.transcript().records[0].clone();
    let maximum_record_bytes = encode(&prototype).unwrap().len() as u64;
    let mut empty = source.transcript().clone();
    empty.records.clear();
    empty.limits.maximum_records = 2.into();
    empty.limits.maximum_record_bytes = maximum_record_bytes.into();
    // Solve the envelope extent including the encoded decimal ceiling itself.
    for _ in 0..10 {
        let total = encode(&empty).unwrap().len() as u64 + 2 * maximum_record_bytes + 1;
        if empty.limits.maximum_total_bytes.get() == total {
            break;
        }
        empty.limits.maximum_total_bytes = total.into();
    }
    let mut tight = CaptureSession::new(empty.origin.clone(), empty.limits.clone()).unwrap();
    let _first = tight.reserve().unwrap();
    assert_eq!(tight.reserve().err(), Some(TranscriptError::CaptureLimit));

    empty.limits.maximum_total_bytes = (empty.limits.maximum_total_bytes.get() + 1).into();
    let admitted_total = empty.limits.maximum_total_bytes.get();
    let mut fitting = CaptureSession::new(empty.origin, empty.limits).unwrap();
    let first = fitting.reserve().unwrap();
    let second = fitting.reserve().unwrap();
    for reservation in [first, second] {
        fitting
            .retain(
                reservation,
                prototype.request.clone(),
                prototype.response_bytes.clone(),
                prototype.evidence.clone(),
                prototype.assigned_positions.clone(),
                prototype.physical_uncertainty.clone(),
            )
            .unwrap();
    }
    let complete = fitting.finish().unwrap();
    assert!(complete.bytes().len() as u64 <= admitted_total);
}

#[test]
fn native_publication_payload_is_an_explicit_readable_recorded_object() {
    let payload = object(b"{\"actual_output\":17}");
    let proof = object(b"{\"actual_receipt\":19}");
    let publication = crate::node_scheduling::NativePublication {
        publication_id: id("native/output"),
        endpoint: crucible_node_contract::Endpoint {
            node_id: id("source"),
            port_id: id("output"),
            lane_id: id("bytes"),
        },
        native_sequence: 0.into(),
        publication: Position::new(50.into(), 0.into(), Phase::Publication),
        evaluation: None,
        causal_parents: Vec::new(),
        payload: payload.reference.clone(),
        payload_bytes: payload.bytes.clone(),
    };
    let observation = crate::node_scheduling::NativeSchedulingObservation {
        node: id("source"),
        owners: Vec::new(),
        reached: position(50),
        closed_prefix: position(50),
        bounds: Vec::new(),
        publications: vec![publication],
        input_progress: None,
        external_inputs: Vec::new(),
        proof_ref: proof.reference,
    };
    let outcome = OperationOutcome {
        operation: id("native/operation"),
        node: id("source"),
        owners: Vec::new(),
        progress: ProgressEvidence::Administrative,
        retained_outputs: vec![id("native/output")],
        scheduling: Some(observation.clone()),
    };
    assert!(outcome_references(&outcome).contains(&payload.reference));
    assert!(observation_references(&observation).contains(&payload.reference));
    assert!(!observation_proof_references(&observation).contains(&payload.reference));
}
