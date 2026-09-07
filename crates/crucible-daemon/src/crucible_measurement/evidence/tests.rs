//! Measurement replay-evidence format and verifier regressions.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;

use crucible::model::{Aggregation, MeasurementDefinition, MetricSource, UnitId};
use crucible::{MarkerId, NodeTemplate, ReadyPoint, WhiteBoxPolicy};

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
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: worker.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "measurement-evidence-test".to_owned(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("world");
    MeasurementDefinitions::new(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
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
                    unit: UnitId::parse("virtual_nanoseconds").expect("unit"),
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

fn empty_evidence(label: &[u8]) -> CrucibleMeasurementReplayEvidence {
    let definitions = MeasurementDefinitions::empty();
    let (scenario, configuration) = identities(label);

    CrucibleMeasurementReplayEvidence::new(
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
        &crucible::ContentHash::from_bytes(b"forged"),
        &mut forged_hash,
    )
    .expect("forged hash CBOR");
    *retained_hash = ciborium::de::from_reader(forged_hash.as_slice()).expect("forged hash value");

    encoded.clear();
    ciborium::ser::into_writer(&value, &mut encoded).expect("forged entry CBOR");
    ciborium::de::from_reader(encoded.as_slice()).expect("forged entry")
}

#[test]
fn v2_publication_round_trips_and_rederives_guest_and_model_samples() {
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

    let publication = evaluate_crucible_measurement_publication(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("v2 publication");
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
        scenario,
        configuration,
        &definitions,
    )
    .expect("raw-evidence verification");
    assert_eq!(
        publication
            .measurement_set()
            .evaluation()
            .expect("evaluation")
            .payload(),
        verified.canonical_bytes()
    );
    assert_eq!(
        publication
            .measurement_set()
            .evaluation()
            .expect("evaluation")
            .payload_schema(),
        CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2
    );
}

#[test]
fn v2_verifier_rejects_legacy_verifier_and_missing_or_wrong_binding() {
    let definitions = definitions();
    let (scenario, configuration) = identities(b"bound");
    let publication = evaluate_crucible_measurement_publication(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("v2 publication");
    assert!(matches!(
        super::super::verify_crucible_measurement_set(
            publication.measurement_set(),
            &definitions,
            publication.evidence().entries(),
            Vec::new(),
            publication.evidence().terminal(),
        ),
        Err(CrucibleMeasurementError::UnsupportedPayloadSchema {
            actual: CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2,
            expected: super::super::CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1,
        })
    ));

    let retained = publication
        .measurement_set()
        .evaluation()
        .expect("evaluation");
    let missing_edge = MeasurementSet::from_evaluation(
        retained.definitions(),
        retained.payload_schema(),
        retained.evaluation(),
        retained.payload().to_vec(),
        BTreeSet::new(),
    )
    .expect("measurement set without trace edge");
    assert!(matches!(
        verify_crucible_measurement_publication(
            &missing_edge,
            publication.evidence(),
            scenario,
            configuration,
            &definitions,
        ),
        Err(CrucibleMeasurementError::ReplayEvidenceSetMismatch {
            actual_count: 0,
            ..
        })
    ));

    let extra_edge = ContentId::for_bytes(ObjectKind::Trace, 1, b"unowned-extra-evidence");
    let with_extra_edge = MeasurementSet::from_evaluation(
        retained.definitions(),
        retained.payload_schema(),
        retained.evaluation(),
        retained.payload().to_vec(),
        BTreeSet::from([publication.evidence().id().expect("trace ID"), extra_edge]),
    )
    .expect("measurement set with extra edge");
    assert!(matches!(
        verify_crucible_measurement_publication(
            &with_extra_edge,
            publication.evidence(),
            scenario,
            configuration,
            &definitions,
        ),
        Err(CrucibleMeasurementError::ReplayEvidenceSetMismatch {
            actual_count: 2,
            ..
        })
    ));

    let (wrong_scenario, _) = identities(b"wrong");
    assert!(matches!(
        verify_crucible_measurement_publication(
            publication.measurement_set(),
            publication.evidence(),
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
    let evidence = CrucibleMeasurementReplayEvidence::new(
        scenario,
        configuration,
        &definitions,
        entries(),
        terminal(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .expect("evidence");
    let bytes = evidence.canonical_bytes().expect("canonical bytes");

    let mut trailing_space = bytes.clone();
    trailing_space.push(b' ');
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&trailing_space),
        Err(CrucibleMeasurementError::NonCanonicalEvidence)
    ));

    let mut unknown_value: ciborium::Value =
        ciborium::de::from_reader(bytes.as_slice()).expect("decoded CBOR value");
    let ciborium::Value::Map(unknown_fields) = &mut unknown_value else {
        panic!("evidence root must be a map");
    };
    unknown_fields.push((
        ciborium::Value::Text("unknown".to_owned()),
        ciborium::Value::Integer(0.into()),
    ));
    let mut unknown = Vec::new();
    ciborium::ser::into_writer(&unknown_value, &mut unknown).expect("unknown-field CBOR");
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&unknown),
        Err(CrucibleMeasurementError::EvidenceEncoding { .. })
    ));

    let mut unsupported_value: ciborium::Value =
        ciborium::de::from_reader(bytes.as_slice()).expect("decoded CBOR value");
    let ciborium::Value::Map(unsupported_fields) = &mut unsupported_value else {
        panic!("evidence root must be a map");
    };
    let schema = unsupported_fields
        .iter_mut()
        .find(|(key, _)| key == &ciborium::Value::Text("schema_version".to_owned()))
        .map(|(_, value)| value)
        .expect("schema field");
    *schema = ciborium::Value::Integer(2.into());
    let mut unsupported = Vec::new();
    ciborium::ser::into_writer(&unsupported_value, &mut unsupported)
        .expect("unsupported-schema CBOR");
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::from_canonical_bytes(&unsupported),
        Err(CrucibleMeasurementError::UnsupportedEvidenceSchema {
            actual: 2,
            expected: CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1,
        })
    ));
}

#[test]
fn evidence_decode_rejects_oversized_declared_container_lengths() {
    let bytes = empty_evidence(b"declared-container-bounds")
        .canonical_bytes()
        .expect("canonical bytes");

    let oversized_entries = replace_empty_container_length(
        &bytes,
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

    let maximum_entries = replace_empty_container_length(
        &bytes,
        "entries",
        0x9a,
        u32::try_from(MAX_MEASUREMENT_EVENT_ENTRIES).expect("entry bound fits u32"),
    );
    let reason = evidence_encoding_reason(CrucibleMeasurementReplayEvidence::from_canonical_bytes(
        &maximum_entries,
    ));
    assert!(
        !reason.contains("at most 1000000 scheduler entries"),
        "exact limit must pass the count check: {reason}"
    );
}

#[test]
fn empty_evidence_canonical_bytes_and_content_id_are_stable() {
    let evidence = empty_evidence(b"canonical-golden");
    let bytes = evidence.canonical_bytes().expect("canonical bytes");
    let encoded = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        encoded,
        concat!(
            "a66e736368656d615f76657273696f6e01687363656e6172696f784032376430",
            "3832366635353537303262343832316361363262653863646663663436313464",
            "346532633566386663353239303832633133313266646234366166396d636f6e",
            "66696775726174696f6e78403164343536323366366334326532373032663039",
            "3364653365633863333033373135643433393737323233366537643163643664",
            "6565346563333136633638616b646566696e6974696f6e737840343330373132",
            "3534346235616165393565373030393730363066393764353534386535373433",
            "393536646562633533663138366232356662306335656566643967656e747269",
            "657380687465726d696e616ca4717363656e6172696f5f72656164795f6174f6",
            "626174a1657469636b73006c6e6f64655f69636f756e7473a073736368656475",
            "6c65725f717569657363656e74f5",
        )
    );
    assert_eq!(
        evidence.id().expect("content ID").encode(),
        "trace.1.2d75c4db7fc44f07b71fabe14c56d93f8831cb44558e4a34f44150c1826068c3"
    );
}

#[test]
fn effective_byte_limit_precedes_event_log_replay() {
    let definitions = MeasurementDefinitions::empty();
    let (scenario, configuration) = identities(b"budget");
    let valid_entries = entries();
    let invalid_sequence = vec![valid_entries[0].clone(), valid_entries[2].clone()];
    let terminal = terminal();
    let unconstrained = CrucibleMeasurementReplayEvidence::new(
        scenario,
        configuration,
        &definitions,
        invalid_sequence.clone(),
        terminal.clone(),
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    );
    assert!(
        matches!(
            unconstrained,
            Err(CrucibleMeasurementError::Evaluation(
                crucible::model::MeasurementEvaluationError::NonDenseEventLog {
                    previous: 0,
                    actual: 2,
                }
            ))
        ),
        "unexpected result: {unconstrained:?}"
    );
    assert!(matches!(
        CrucibleMeasurementReplayEvidence::new(
            scenario,
            configuration,
            &definitions,
            invalid_sequence,
            terminal,
            1,
        ),
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
                crucible::model::MeasurementEvaluationError::NonDenseEventLog {
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
            crucible::model::MeasurementEvaluationError::InvalidEventHash { sequence: 0 }
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
