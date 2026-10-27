//! Measurement replay-evidence format and verifier regressions.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;

use crucible_engine::model::{Aggregation, MeasurementDefinition, MetricSource, UnitId};
use crucible_engine::{EventLog, MarkerId, NodeTemplate, ReadyPoint, WhiteBoxPolicy};

use crate::attempt_event_log::MemorySegmentStore;

fn campaign_leaf(
    label: &[u8],
    entries: Vec<SchedulerEventLogEntry>,
    terminal_at: u64,
) -> (CrucibleMeasurementReplayEvidence, MemorySegmentStore) {
    let (scenario, configuration) = identities(label);
    let mut store = MemorySegmentStore::default();
    let log = store.sealed_log(entries).expect("sealed log");
    let leaf = CrucibleMeasurementReplayEvidence {
        scenario,
        configuration,
        definitions: CampaignHash::derive("test.definitions", b"none"),
        log: ReplayLog::Segmented(log),
        terminal: MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: terminal_at },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: false,
        },
        stop: CrucibleMeasurementStopEvidence::Campaign,
    };
    (leaf, store)
}

#[test]
fn assertion_boundary_replays_exact_trace_and_rejects_forged_fields() {
    let unrelated = SchedulerEventLogEntry::assertion_state_observation(
        0,
        VirtualTime { ticks: 1 },
        crucible_engine::AssertionId::from_name("unrelated"),
        AssertionPhase::Violated,
    );
    let failed = SchedulerEventLogEntry::assertion_state_observation(
        1,
        VirtualTime { ticks: 2 },
        crucible_engine::AssertionId::from_name("target"),
        AssertionPhase::Violated,
    );
    let entries = vec![unrelated, failed.clone()];
    let (leaf, store) = campaign_leaf(b"assertion-boundary", entries.clone(), 2);
    let hash = CampaignHash::from_bytes(failed.content_hash().bytes);
    let digest = observation_event_prefix_digest(&entries);
    let witness = |prefix_digest, transition_hash, property: &str| {
        FindingAssertionFailureBoundary::new(
            leaf.id().expect("trace ID"),
            prefix_digest,
            2,
            1,
            1,
            transition_hash,
            property.to_owned(),
        )
        .expect("witness")
    };

    assert!(verify_assertion_failure_boundary(
        &leaf,
        &store,
        &witness(digest, hash, "target")
    ));
    assert!(!verify_assertion_failure_boundary(
        &leaf,
        &store,
        &witness(CampaignHash::derive("forged", b"prefix"), hash, "target")
    ));
    assert!(!verify_assertion_failure_boundary(
        &leaf,
        &store,
        &witness(
            digest,
            CampaignHash::derive("forged", b"transition"),
            "target"
        )
    ));
    assert!(!verify_assertion_failure_boundary(
        &leaf,
        &store,
        &witness(digest, hash, "unrelated")
    ));
    assert!(!verify_assertion_failure_boundary(
        &leaf,
        &MemorySegmentStore::default(),
        &witness(digest, hash, "target")
    ));

    let duplicate = SchedulerEventLogEntry::assertion_state_observation(
        2,
        VirtualTime { ticks: 2 },
        crucible_engine::AssertionId::from_name("target"),
        AssertionPhase::Violated,
    );
    let mut duplicated_entries = entries;
    duplicated_entries.push(duplicate);
    let (duplicate_leaf, duplicate_store) =
        campaign_leaf(b"assertion-boundary", duplicated_entries.clone(), 2);
    let duplicate_witness = FindingAssertionFailureBoundary::new(
        duplicate_leaf.id().expect("duplicate trace ID"),
        observation_event_prefix_digest(&duplicated_entries),
        3,
        1,
        1,
        hash,
        String::from("target"),
    )
    .expect("duplicate witness");
    assert!(!verify_assertion_failure_boundary(
        &duplicate_leaf,
        &duplicate_store,
        &duplicate_witness
    ));
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn identities(label: &[u8]) -> (ScenarioDefId, ConfigurationId) {
    (
        ScenarioDefId::from_hash(CampaignHash::derive("test-scenario", label)),
        ConfigurationId::from_hash(CampaignHash::derive("test-configuration", label)),
    )
}

fn definitions() -> MeasurementDefinitions {
    let worker = node("worker");
    let world = crucible_engine::World::from_nodes(vec![crucible_engine::WorldNode {
        id: worker.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "measurement-evidence-test".to_owned(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("world");
    MeasurementDefinitions::new(
        &world,
        &crucible_engine::Plan::empty(),
        &crucible_engine::Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("request").expect("measurement ID"),
            begin: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("begin"),
                instance: Some(MeasurementInstanceKey::parse("request-1").expect("instance ID")),
            },
            end: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("end"),
                instance: Some(MeasurementInstanceKey::parse("request-1").expect("instance ID")),
            },
            timeout: None,
            cohort: CohortPolicy::All(vec![worker]),
            metrics: vec![
                MetricDefinition {
                    id: MetricId::parse("guest-value").expect("metric ID"),
                    value_type: MetricValueType::UnsignedInteger,
                    unit: UnitId::parse("samples").expect("unit"),
                    source: MetricSource::Guest,
                    aggregation: Aggregation::Sum,
                },
                MetricDefinition {
                    id: MetricId::parse("virtual-time").expect("metric ID"),
                    value_type: MetricValueType::UnsignedInteger,
                    unit: UnitId::parse("virtual_ticks").expect("unit"),
                    source: MetricSource::VirtualTime,
                    aggregation: Aggregation::Max,
                },
            ],
        }],
    )
    .expect("definitions")
}

fn entries() -> Vec<SchedulerEventLogEntry> {
    let worker = node("worker");
    vec![
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            0,
            Icount { retired: 1 },
            worker.clone(),
            "begin".to_owned(),
            "request-1".to_owned(),
            Vec::new(),
        ),
        SchedulerEventLogEntry::guest_measurement_observation(
            1,
            Icount { retired: 2 },
            worker.clone(),
            GuestMeasurementEvent::Begin {
                measurement: "request".to_owned(),
                instance: "request-1".to_owned(),
            },
        ),
        SchedulerEventLogEntry::guest_measurement_observation(
            2,
            Icount { retired: 3 },
            worker.clone(),
            GuestMeasurementEvent::Sample {
                measurement: "request".to_owned(),
                instance: "request-1".to_owned(),
                metric: "guest-value".to_owned(),
                value: GuestMeasurementValue::Unsigned(7),
            },
        ),
        SchedulerEventLogEntry::guest_measurement_observation(
            3,
            Icount { retired: 4 },
            worker.clone(),
            GuestMeasurementEvent::End {
                measurement: "request".to_owned(),
                instance: "request-1".to_owned(),
            },
        ),
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            4,
            Icount { retired: 5 },
            worker,
            "end".to_owned(),
            "request-1".to_owned(),
            Vec::new(),
        ),
    ]
}

fn terminal() -> MeasurementTerminalState {
    MeasurementTerminalState {
        scenario_ready_at: Some(VirtualTime { ticks: 1 }),
        at: VirtualTime { ticks: 5 },
        node_icounts: BTreeMap::from([(node("worker"), Icount { retired: 5 })]),
        scheduler_quiescent: true,
    }
}

struct Published {
    publication: CrucibleMeasurementPublication,
    store: MemorySegmentStore,
}

fn publish(
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
    entries: Vec<SchedulerEventLogEntry>,
    terminal: MeasurementTerminalState,
    maximum_bytes: usize,
) -> Result<Published, CrucibleMeasurementError> {
    let mut store = MemorySegmentStore::default();
    let log = store.sealed_log(entries)?;
    let publication = evaluate_crucible_measurement_publication(
        scenario,
        configuration,
        definitions,
        log,
        &store,
        terminal,
        maximum_bytes,
    )?;
    Ok(Published { publication, store })
}

fn empty_evidence(label: &[u8]) -> CrucibleMeasurementReplayEvidence {
    let definitions = MeasurementDefinitions::empty();
    let (scenario, configuration) = identities(label);

    publish(
        scenario,
        configuration,
        &definitions,
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 0 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("empty evidence")
    .publication
    .evidence
}

/// Builds a version 2 leaf, which embeds its entries, for compatibility tests.
fn inline_v2_evidence(
    label: &[u8],
    entries: Vec<SchedulerEventLogEntry>,
    terminal: MeasurementTerminalState,
) -> CrucibleMeasurementReplayEvidence {
    let (scenario, configuration) = identities(label);
    CrucibleMeasurementReplayEvidence {
        scenario,
        configuration,
        definitions: campaign_hash(definitions().content_hash()),
        log: ReplayLog::Inline(entries),
        terminal,
        stop: CrucibleMeasurementStopEvidence::Campaign,
    }
}

fn replace_empty_container_length(bytes: &[u8], field: &str, major: u8, declared: u32) -> Vec<u8> {
    let field_bytes = field.as_bytes();
    let field_start = bytes
        .windows(field_bytes.len())
        .position(|window| window == field_bytes)
        .expect("CBOR field name");
    let value_offset = field_start + field_bytes.len();
    assert!(matches!(bytes.get(value_offset), Some(0x80 | 0xa0)));

    let mut mutated = Vec::with_capacity(bytes.len() + 4);
    mutated.extend_from_slice(&bytes[..value_offset]);
    mutated.push(major);
    mutated.extend_from_slice(&declared.to_be_bytes());
    mutated.extend_from_slice(&bytes[value_offset + 1..]);
    mutated
}

fn evidence_encoding_reason(
    result: Result<CrucibleMeasurementReplayEvidence, CrucibleMeasurementError>,
) -> String {
    match result {
        Err(CrucibleMeasurementError::EvidenceEncoding { reason }) => reason,
        other => panic!("expected evidence encoding error, got {other:?}"),
    }
}

fn invalid_guest_sample(sequence: u64) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::guest_measurement_observation(
        sequence,
        Icount { retired: 2 },
        node("worker"),
        GuestMeasurementEvent::Sample {
            measurement: "request".to_owned(),
            instance: "request-1".to_owned(),
            metric: "guest-value".to_owned(),
            value: GuestMeasurementValue::Unsigned(7),
        },
    )
}

fn with_forged_hash(entry: &SchedulerEventLogEntry) -> SchedulerEventLogEntry {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(entry, &mut encoded).expect("entry CBOR");
    let mut value: ciborium::Value =
        ciborium::de::from_reader(encoded.as_slice()).expect("entry value");
    let ciborium::Value::Map(fields) = &mut value else {
        panic!("entry must serialize as a map");
    };
    let retained_hash = fields
        .iter_mut()
        .find(|(key, _)| key == &ciborium::Value::Text("content_hash".to_owned()))
        .map(|(_, value)| value)
        .expect("content hash field");
    let mut forged_hash = Vec::new();
    ciborium::ser::into_writer(
        &crucible_engine::ContentHash::from_bytes(b"forged"),
        &mut forged_hash,
    )
    .expect("forged hash CBOR");
    *retained_hash = ciborium::de::from_reader(forged_hash.as_slice()).expect("forged hash value");

    encoded.clear();
    ciborium::ser::into_writer(&value, &mut encoded).expect("forged entry CBOR");
    ciborium::de::from_reader(encoded.as_slice()).expect("forged entry")
}

#[test]
fn v3_publication_round_trips_and_rederives_guest_and_model_samples() {
    let definitions = definitions();
    let (scenario, configuration) = identities(b"bound");
    let samples = derive_crucible_measurement_samples(&definitions, &entries())
        .expect("derived guest and model samples");
    assert!(
        samples
            .iter()
            .any(|sample| sample.metric().as_str() == "guest-value")
    );
    assert!(
        samples
            .iter()
            .any(|sample| sample.metric().as_str() == "virtual-time")
    );

    let Published { publication, store } = publish(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("v3 publication");
    assert_eq!(
        publication.evidence().schema_version(),
        CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3
    );
    assert_eq!(
        publication.evidence().stop(),
        CrucibleMeasurementStopEvidence::Campaign
    );
    assert_eq!(publication.evidence().entry_count(), entries().len() as u64);
    assert!(!publication.evidence().segments().is_empty());
    assert_eq!(
        publication.measurement_set().evaluation().evidence(),
        &publication.evidence().evidence_ids().expect("evidence IDs")
    );

    let evidence_bytes = publication
        .evidence()
        .canonical_bytes()
        .expect("canonical evidence");
    let decoded = CrucibleMeasurementReplayEvidence::from_canonical_bytes(&evidence_bytes)
        .expect("decoded evidence");
    assert_eq!(&decoded, publication.evidence());

    let verified = verify_crucible_measurement_publication(
        publication.measurement_set(),
        &decoded,
        &store,
        scenario,
        configuration,
        &definitions,
    )
    .expect("raw-evidence verification");
    assert_eq!(
        publication.measurement_set().evaluation().payload(),
        verified.canonical_bytes()
    );
    assert_eq!(
        publication.measurement_set().evaluation().payload_schema(),
        CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3
    );

    // Verification streams segments, so a source missing them fails closed.
    assert!(matches!(
        verify_crucible_measurement_publication(
            publication.measurement_set(),
            &decoded,
            &MemorySegmentStore::default(),
            scenario,
            configuration,
            &definitions,
        ),
        Err(CrucibleMeasurementError::EventLog(_))
    ));
}

#[test]
fn v2_leaves_remain_readable_and_replay_identically() {
    let definitions = definitions();
    let (scenario, configuration) = identities(b"v2");
    let leaf = inline_v2_evidence(b"v2", entries(), terminal());
    let bytes = leaf.canonical_bytes().expect("canonical v2 evidence");
    let decoded =
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes).expect("decoded v2");

    assert_eq!(decoded, leaf);
    assert_eq!(
        decoded.schema_version(),
        CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2
    );
    assert!(decoded.segments().is_empty());

    let inline = decoded
        .replay(
            &MemorySegmentStore::default(),
            scenario,
            configuration,
            &definitions,
        )
        .expect("v2 replay");
    let Published { publication, store } = publish(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("v3 publication");
    let segmented = publication
        .evidence()
        .replay(&store, scenario, configuration, &definitions)
        .expect("v3 replay");
    assert_eq!(inline, segmented);
}

#[test]
fn observation_boundary_evidence_round_trips_exact_coordinates() {
    let definitions = definitions();
    let (scenario, configuration) = identities(b"observation-boundary");
    let entries = entries();
    let mut log = EventLog::new();
    let append = log
        .append_entries(entries.clone())
        .expect("observation event segment");
    let boundary = CrucibleObservationBoundaryEvidence::new(
        VirtualTime { ticks: 5 },
        7,
        8,
        0,
        append.offset,
        true,
    )
    .expect("observation boundary");

    let mut store = MemorySegmentStore::default();
    let manifest = store.sealed_log(entries).expect("sealed log");
    let publication = evaluate_crucible_observation_measurement_publication(
        scenario,
        configuration,
        &definitions,
        manifest,
        &store,
        terminal(),
        boundary,
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("observation publication");
    assert_eq!(
        publication.evidence().stop(),
        CrucibleMeasurementStopEvidence::Observation(boundary)
    );
    assert_eq!(
        publication
            .evidence()
            .id()
            .expect("evidence ID")
            .schema_version(),
        CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3
    );

    let bytes = publication
        .evidence()
        .canonical_bytes()
        .expect("canonical evidence");
    let decoded =
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes).expect("decoded evidence");
    assert_eq!(decoded, *publication.evidence());
}

#[test]
fn verifier_rejects_missing_or_wrong_binding() {
    let definitions = definitions();
    let (scenario, configuration) = identities(b"bound");
    let Published { publication, store } = publish(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("publication");
    let retained = publication.measurement_set().evaluation();
    let with_evidence = |evidence| {
        MeasurementSet::from_evaluation(
            retained.definitions(),
            retained.payload_schema(),
            retained.evaluation(),
            retained.payload().to_vec(),
            evidence,
        )
        .expect("measurement set")
    };

    let leaf_only = with_evidence(BTreeSet::from([publication
        .evidence()
        .id()
        .expect("trace ID")]));
    assert!(matches!(
        verify_crucible_measurement_publication(
            &leaf_only,
            publication.evidence(),
            &store,
            scenario,
            configuration,
            &definitions,
        ),
        Err(CrucibleMeasurementError::ReplayEvidenceSetMismatch {
            actual_count: 1,
            ..
        })
    ));

    let mut extra = publication.evidence().evidence_ids().expect("evidence IDs");
    let owned = extra.len();
    extra.insert(ContentId::for_bytes(
        ObjectKind::Trace,
        1,
        b"unowned-extra-evidence",
    ));
    let with_extra_edge = with_evidence(extra);
    assert!(matches!(
        verify_crucible_measurement_publication(
            &with_extra_edge,
            publication.evidence(),
            &store,
            scenario,
            configuration,
            &definitions,
        ),
        Err(CrucibleMeasurementError::ReplayEvidenceSetMismatch { actual_count, .. })
            if actual_count == owned + 1
    ));

    let (wrong_scenario, _) = identities(b"wrong");
    assert!(matches!(
        verify_crucible_measurement_publication(
            publication.measurement_set(),
            publication.evidence(),
            &store,
            wrong_scenario,
            configuration,
            &definitions,
        ),
        Err(CrucibleMeasurementError::EvidenceBindingMismatch {
            binding: "scenario"
        })
    ));
}

#[test]
fn evidence_decode_rejects_noncanonical_unknown_and_unsupported_input() {
    let definitions = definitions();
    let (scenario, configuration) = identities(b"decode");
    let evidence = publish(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("evidence")
    .publication
    .evidence;
    let bytes = evidence.canonical_bytes().expect("canonical bytes");

    let mut trailing_space = bytes.clone();
    trailing_space.push(b' ');
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&trailing_space),
        Err(CrucibleMeasurementError::NonCanonicalEvidence)
    ));

    type CborFields = Vec<(ciborium::Value, ciborium::Value)>;
    let mutated = |edit: &dyn Fn(&mut CborFields)| {
        let mut value: ciborium::Value =
            ciborium::de::from_reader(bytes.as_slice()).expect("decoded CBOR value");
        let ciborium::Value::Map(fields) = &mut value else {
            panic!("evidence root must be a map");
        };
        edit(fields);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).expect("mutated CBOR");
        encoded
    };

    let unknown = mutated(&|fields| {
        fields.push((
            ciborium::Value::Text("unknown".to_owned()),
            ciborium::Value::Integer(0.into()),
        ));
    });
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&unknown),
        Err(CrucibleMeasurementError::EvidenceEncoding { .. })
    ));

    let unsupported = mutated(&|fields| {
        let schema = fields
            .iter_mut()
            .find(|(key, _)| key == &ciborium::Value::Text("schema_version".to_owned()))
            .map(|(_, value)| value)
            .expect("schema field");
        *schema = ciborium::Value::Integer(4.into());
    });
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&unsupported),
        Err(CrucibleMeasurementError::UnsupportedEvidenceSchema {
            actual: 4,
            expected: CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3,
        })
    ));

    // A manifest whose recorded chain differs from its segments is rejected
    // before any segment is read.
    let forged_chain = mutated(&|fields| {
        let log = fields
            .iter_mut()
            .find(|(key, _)| key == &ciborium::Value::Text("log".to_owned()))
            .map(|(_, value)| value)
            .expect("log field");
        let ciborium::Value::Map(log) = log else {
            panic!("log must be a map");
        };
        let count = log
            .iter_mut()
            .find(|(key, _)| key == &ciborium::Value::Text("entry_count".to_owned()))
            .map(|(_, value)| value)
            .expect("entry count field");
        *count = ciborium::Value::Integer(1.into());
    });
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&forged_chain),
        Err(CrucibleMeasurementError::EventLog(
            crate::attempt_event_log::AttemptEventLogError::InvalidManifest { .. }
        ))
    ));
}

#[test]
fn evidence_decode_rejects_oversized_declared_container_lengths() {
    let bytes = empty_evidence(b"declared-container-bounds")
        .canonical_bytes()
        .expect("canonical bytes");

    let oversized_segments = replace_empty_container_length(
        &bytes,
        "segments",
        0x9a,
        u32::try_from(MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS + 1).expect("segment bound fits u32"),
    );
    let reason = evidence_encoding_reason(CrucibleMeasurementReplayEvidence::from_canonical_bytes(
        &oversized_segments,
    ));
    assert!(
        reason.contains("at most 4095 attempt-log segments"),
        "unexpected rejection: {reason}"
    );

    let oversized_nodes = replace_empty_container_length(
        &bytes,
        "node_icounts",
        0xba,
        u32::try_from(MAX_MEASUREMENT_TERMINAL_NODES + 1).expect("node bound fits u32"),
    );
    let reason = evidence_encoding_reason(CrucibleMeasurementReplayEvidence::from_canonical_bytes(
        &oversized_nodes,
    ));
    assert!(
        reason.contains("at most 65536 terminal node counters"),
        "unexpected rejection: {reason}"
    );

    let v2_bytes = inline_v2_evidence(
        b"declared-container-bounds",
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 0 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
    )
    .canonical_bytes()
    .expect("canonical v2 bytes");
    let oversized_entries = replace_empty_container_length(
        &v2_bytes,
        "entries",
        0x9a,
        u32::try_from(MAX_MEASUREMENT_EVENT_ENTRIES + 1).expect("entry bound fits u32"),
    );
    let reason = evidence_encoding_reason(CrucibleMeasurementReplayEvidence::from_canonical_bytes(
        &oversized_entries,
    ));
    assert!(
        reason.contains("at most 1000000 scheduler entries"),
        "unexpected rejection: {reason}"
    );
}

#[test]
fn campaign_stop_is_explicit_and_round_trips() {
    let evidence = empty_evidence(b"canonical-golden");
    let bytes = evidence.canonical_bytes().expect("canonical bytes");
    let decoded = CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes)
        .expect("decode current terminal evidence");

    assert_eq!(decoded, evidence);
    assert_eq!(
        evidence.id().expect("content ID").schema_version(),
        CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3
    );
}

#[test]
fn effective_byte_limit_precedes_segment_reads() {
    let definitions = MeasurementDefinitions::empty();
    let (scenario, configuration) = identities(b"budget");
    let manifest = MemorySegmentStore::default()
        .sealed_log(entries())
        .expect("sealed log");
    let absent = MemorySegmentStore::default();
    let publish_with_limit = |maximum_bytes| {
        evaluate_crucible_measurement_publication(
            scenario,
            configuration,
            &definitions,
            manifest.clone(),
            &absent,
            terminal(),
            maximum_bytes,
        )
    };

    assert!(matches!(
        publish_with_limit(MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES),
        Err(CrucibleMeasurementError::EventLog(
            crate::attempt_event_log::AttemptEventLogError::Store { .. }
        ))
    ));
    assert!(matches!(
        publish_with_limit(1),
        Err(CrucibleMeasurementError::EvidenceTooLarge { maximum: 1, .. })
    ));
}

#[test]
fn authenticated_log_validation_precedes_guest_normalization() {
    let definitions = definitions();
    let valid_entries = entries();
    let non_dense = vec![invalid_guest_sample(0), valid_entries[2].clone()];
    let non_dense_result = derive_crucible_measurement_samples(&definitions, &non_dense);
    assert!(
        matches!(
            non_dense_result,
            Err(CrucibleMeasurementError::Evaluation(
                crucible_engine::model::MeasurementEvaluationError::NonDenseEventLog {
                    previous: 0,
                    actual: 2,
                }
            ))
        ),
        "unexpected result: {non_dense_result:?}"
    );

    let forged = vec![with_forged_hash(&invalid_guest_sample(0))];
    assert!(matches!(
        derive_crucible_measurement_samples(&definitions, &forged),
        Err(CrucibleMeasurementError::Evaluation(
            crucible_engine::model::MeasurementEvaluationError::InvalidEventHash { sequence: 0 }
        ))
    ));
}

#[test]
fn guest_vector_protocol_limit_is_checked_before_normalization() {
    let metric = MetricDefinition {
        id: MetricId::parse("vector").expect("metric ID"),
        value_type: MetricValueType::IntegerVector {
            signed: false,
            maximum_elements: 65_536,
        },
        unit: UnitId::parse("samples").expect("unit"),
        source: MetricSource::Guest,
        aggregation: Aggregation::Last,
    };
    let oversized = GuestMeasurementValue::UnsignedVector(vec![
        0;
        WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
            + 1
    ]);
    assert!(validate_guest_measurement_value(&oversized, &metric).is_err());
}
