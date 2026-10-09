//! Exercises normative CNP/1 vectors and hostile portable contract inputs.

#![allow(clippy::unwrap_used)]
#![forbid(unsafe_code)]

use crucible_node_contract::{canonical, *};
use serde_json::{Value, json};

#[test]
fn normative_positive_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../docs/rfcs/0025-crucible-node-contract/reference/cnp-v1-vectors.json"
    ))
    .unwrap();

    for vector in vectors["positive"].as_array().unwrap() {
        let domain = vector["domain"].as_str().unwrap();
        let payload = hex::decode(vector["payload_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(canonical::frame(domain, &payload).unwrap()),
            vector["framed_input_hex"].as_str().unwrap()
        );
        assert_eq!(
            canonical::hash(domain, &payload).unwrap().digest,
            vector["digest_hex"].as_str().unwrap()
        );

        if let Some(source) = vector["source_json"].as_str() {
            let parsed = canonical::parse_json(source.as_bytes(), 4096).unwrap();
            assert_eq!(canonical::canonical_json(&parsed).unwrap(), payload);
            assert_eq!(
                canonical::json_hash(domain, &parsed).unwrap().digest,
                vector["digest_hex"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn normative_negative_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../docs/rfcs/0025-crucible-node-contract/reference/cnp-v1-vectors.json"
    ))
    .unwrap();

    for vector in vectors["negative"].as_array().unwrap() {
        match vector["type"].as_str().unwrap() {
            "json" => assert!(
                canonical::parse_json(vector["input"].as_str().unwrap().as_bytes(), 4096).is_err()
            ),
            "json-utf8" => assert!(
                canonical::parse_json(
                    &hex::decode(vector["input_hex"].as_str().unwrap()).unwrap(),
                    4096
                )
                .is_err()
            ),
            "uint64-decimal-string" => {
                if let Some(input) = vector["input"].as_str() {
                    assert!(input.parse::<U64>().is_err());
                } else {
                    assert!(
                        serde_json::from_str::<U64>(vector["input_json"].as_str().unwrap())
                            .is_err()
                    );
                }
            }
            "signed-offset-decimal-string" => {
                assert!(vector["input"].as_str().unwrap().parse::<I64>().is_err())
            }
            unknown => panic!("unhandled normative vector type: {unknown}"),
        }
    }
}

#[test]
fn canonicalization_uses_ecmascript_numbers_and_utf16_keys() {
    // RFC 8785 numeric example; serde_json's ordinary serializer differs.
    let parsed = canonical::parse_json(
        br#"[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,-0.0]"#,
        4096,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(canonical::canonical_json(&parsed).unwrap()).unwrap(),
        "[333333333.3333333,1e+30,4.5,0.002,1e-27,0]"
    );

    // U+1F600 starts with a UTF-16 surrogate below U+E000, despite UTF-8 order.
    let value = json!({"\u{e000}": 1, "😀": 2, "e\u{301}": "é"});
    assert_eq!(
        String::from_utf8(canonical::canonical_json(&value).unwrap()).unwrap(),
        "{\"é\":\"é\",\"😀\":2,\"\u{e000}\":1}"
    );
}

#[test]
fn accurate_contract_numbers_do_not_change_legacy_json_parsing() {
    let source = b"333333333.33333329";
    let legacy: Value = serde_json::from_slice(source).unwrap();
    let contract = canonical::parse_json(source, 4096).unwrap();

    // Keep the existing engine's parsing behavior while CNP uses correctly
    // rounded numbers. A unified float_roundtrip feature would fail this check.
    assert_eq!(
        legacy.as_f64().unwrap().to_bits(),
        333333333.33333325_f64.to_bits()
    );
    assert_eq!(
        contract.as_f64().unwrap().to_bits(),
        333333333.3333333_f64.to_bits()
    );
}

#[test]
fn identifiers_and_integer_ranges_are_not_normalized() {
    for invalid in ["", "_node", "é", "node name", "node@host"] {
        assert!(Id::new(invalid).is_err());
    }
    assert!(Id::new("a".repeat(128)).is_ok());
    assert!(Id::new("a".repeat(129)).is_err());

    assert_eq!(
        "18446744073709551615".parse::<U64>().unwrap().get(),
        u64::MAX
    );
    assert_eq!(
        "-9223372036854775808".parse::<I64>().unwrap().get(),
        i64::MIN
    );
    for invalid in ["+1", " 1", "-0", "00", "1.0"] {
        assert!(invalid.parse::<I64>().is_err());
    }
    assert!("9223372036854775808".parse::<I64>().is_err());
    assert!(U64::new(u64::MAX).checked_add(U64::new(1)).is_err());
    assert!(U64::new(0).checked_offset(I64::new(-1)).is_err());
    assert_eq!(
        U64::new(10).checked_offset(I64::new(-5)).unwrap(),
        U64::new(5)
    );
    assert!(U64::new(u64::MAX).checked_offset(I64::new(1)).is_err());
    assert_eq!(
        serde_json::to_string(&U64::new(u64::MAX)).unwrap(),
        "\"18446744073709551615\""
    );
}

#[test]
fn grid_boundaries_never_round_or_saturate() {
    let grid = QuantumGrid::new(U64::new(100), U64::new(25)).unwrap();
    assert_eq!(grid.boundary(U64::new(2)).unwrap(), U64::new(225));
    assert_eq!(grid.predecessor(U64::new(250)).unwrap(), U64::new(225));
    assert_eq!(grid.successor(U64::new(250)).unwrap(), U64::new(325));
    assert_eq!(grid.successor(U64::new(0)).unwrap(), U64::new(25));
    assert!(grid.predecessor(U64::new(0)).is_err());
    assert!(grid.contains(U64::new(225)));
    assert!(!grid.contains(U64::new(226)));
    assert!(grid.boundary(U64::new(u64::MAX)).is_err());
    assert!(
        QuantumGrid::new(U64::new(2), U64::new(0))
            .unwrap()
            .successor(U64::new(u64::MAX))
            .is_err()
    );
    assert!(QuantumGrid::new(U64::new(0), U64::new(0)).is_err());
    assert!(QuantumGrid::new(U64::new(100), U64::new(100)).is_err());
}

#[test]
fn causal_publication_advances_microstep_without_time() {
    let source = Position::new(U64::new(100), U64::new(2), Phase::Reaction);
    let publication = source.reaction_publication(U64::new(4)).unwrap();
    assert_eq!(
        publication,
        Position::new(U64::new(100), U64::new(3), Phase::Publication)
    );
    assert!(source.reaction_publication(U64::new(3)).is_err());
    assert!(
        Position::new(U64::new(0), U64::new(u64::MAX), Phase::Reaction)
            .reaction_publication(U64::new(u64::MAX))
            .is_err()
    );
    assert!(
        serde_json::from_str::<Position>(r#"{"time_ps":"1","microstep":"0","phase":4}"#).is_err()
    );

    let id = |value| Id::new(value).unwrap();
    let mut events = [
        EventKey {
            position: publication,
            consumer_node_id: id("a"),
            producer_node_id: id("b"),
            source_sequence: U64::new(2),
        },
        EventKey {
            position: source,
            consumer_node_id: id("a"),
            producer_node_id: id("a"),
            source_sequence: U64::new(3),
        },
        EventKey {
            position: publication,
            consumer_node_id: id("a"),
            producer_node_id: id("b"),
            source_sequence: U64::new(1),
        },
    ];
    events.sort();
    assert_eq!(events[0].position, source);
    assert_eq!(events[1].source_sequence, U64::new(1));
}

#[test]
fn strict_json_rejects_nested_duplicate_keys_and_byte_limits() {
    assert!(canonical::parse_json(br#"{"extensions":{"vendor":{"x":1,"x":2}}}"#, 4096).is_err());
    assert!(canonical::parse_json(br#"{"a":1}"#, 6).is_err());
    assert!(canonical::parse_json(br#"{"a":"\ud800"}"#, 4096).is_err());
    assert!(canonical::parse_json(b"1e999", 4096).is_err());

    let oversized = format!("[{}]", vec!["0"; MAX_ARRAY_ELEMENTS + 1].join(","));
    assert!(canonical::parse_json(oversized.as_bytes(), oversized.len()).is_err());
}

#[test]
fn isolated_parser_rejects_invalid_json_grammar() {
    for invalid in [
        "01",
        "-01",
        "+1",
        "1.",
        ".1",
        "1e",
        "1e+",
        "--1",
        "[1,]",
        "[,1]",
        "{\"x\":1,}",
        "{\"x\" 1}",
        "truefalse",
        "null 0",
        "\"\\x\"",
        "\"line\nfeed\"",
    ] {
        assert!(
            canonical::parse_json(invalid.as_bytes(), 4096).is_err(),
            "accepted {invalid:?}"
        );
    }
    for valid in [
        "0",
        "-0",
        "-10",
        "1e+30",
        "1E-3",
        "[ 1 , null ]",
        "{\"x\":\"\\\"\\\\\"}",
    ] {
        assert!(
            canonical::parse_json(valid.as_bytes(), 4096).is_ok(),
            "rejected {valid:?}"
        );
    }
}

#[test]
fn inbound_and_outbound_json_enforce_container_depth() {
    let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    assert!(canonical::parse_json(nested(64).as_bytes(), 4096).is_ok());
    assert!(canonical::parse_json(nested(65).as_bytes(), 4096).is_err());
    assert!(canonical::parse_json_with_depth(nested(4).as_bytes(), 4096, 4).is_ok());
    assert!(canonical::parse_json_with_depth(nested(5).as_bytes(), 4096, 4).is_err());
    assert!(canonical::parse_json_with_depth(b"0", 4096, 65).is_err());

    let mut value = json!(0);
    for _ in 0..64 {
        value = Value::Array(vec![value]);
    }
    assert!(canonical::canonical_json(&value).is_ok());
    value = Value::Array(vec![value]);
    assert!(canonical::canonical_json(&value).is_err());
}

#[test]
fn opaque_bytes_require_canonical_unpadded_base64() {
    assert_eq!(
        serde_json::to_string(&Bytes::new(vec![0, 255])).unwrap(),
        "\"AP8\""
    );
    assert_eq!(
        serde_json::from_str::<Bytes>("\"AP8\"").unwrap().as_slice(),
        &[0, 255]
    );
    for invalid in ["AP8=", "AP9", "AP8\n", "AP+"] {
        assert!(serde_json::from_value::<Bytes>(json!(invalid)).is_err());
    }
}

#[test]
fn bounds_require_explicit_nulls_and_matching_evidence() {
    let unknown = br#"{"kind":"unknown","position":null,"evidence":null}"#;
    assert!(canonical::decode::<Bound>(unknown, 4096).is_ok());
    assert!(canonical::decode::<Bound>(br#"{"kind":"unknown","position":null}"#, 4096).is_err());
    assert!(canonical::decode::<Bound>(br#"{"kind":"unknown","evidence":null}"#, 4096).is_err());
    assert!(
        canonical::decode::<Bound>(br#"{"kind":"after","position":null,"evidence":null}"#, 4096)
            .is_err()
    );

    let proof = canonical::content_ref(b"qualified-proof", "application/json").unwrap();
    assert!(
        Bound {
            kind: BoundKind::NoneUntilActivation,
            position: None,
            evidence: Some(proof.clone())
        }
        .validate()
        .is_ok()
    );
    assert!(
        Bound {
            kind: BoundKind::Unknown,
            position: None,
            evidence: Some(proof)
        }
        .validate()
        .is_err()
    );
}

fn operating_contract() -> OperatingContract {
    OperatingContract {
        schema_version: 1,
        mode: OperatingMode::Exact,
        scheduling_role: SchedulingRole::Active,
        ordering_profile: "superdense-v1".to_owned(),
        policy_ref: canonical::content_ref(b"policy", "application/json").unwrap(),
        resolution_ps: Some(U64::new(50)),
        phase_ps: Some(U64::new(0)),
        facets: Vec::new(),
        extensions: Extensions::new(),
    }
}

#[test]
fn timing_contract_requires_nullable_fields_and_qualified_policy_reference() {
    let mut value = serde_json::to_value(operating_contract()).unwrap();
    assert!(
        canonical::decode::<OperatingContract>(&serde_json::to_vec(&value).unwrap(), 4096).is_ok()
    );
    value.as_object_mut().unwrap().remove("phase_ps");
    assert!(
        canonical::decode::<OperatingContract>(&serde_json::to_vec(&value).unwrap(), 4096).is_err()
    );

    let mut contract = operating_contract();
    contract.resolution_ps = Some(U64::new(0));
    assert!(contract.validate().is_err());
    contract.resolution_ps = None;
    assert!(contract.validate().is_err());
    contract.phase_ps = None;
    assert!(contract.validate().is_ok());
    contract.ordering_profile = "unqualified-order".to_owned();
    assert!(contract.validate().is_err());
}

#[test]
fn content_references_do_not_accept_typed_object_hashes() {
    let mut reference = canonical::content_ref(b"bytes", "application/octet-stream").unwrap();
    assert!(reference.verify(b"bytes").is_ok());
    assert!(reference.verify(b"other").is_err());
    assert!(reference.verify(b"shorter").is_err());
    reference.hash.domain = "cnp.node-descriptor.v1".to_owned();
    assert!(reference.validate().is_err());
    assert!(canonical::content_ref(b"bytes", "text/\nplain").is_err());
    assert!(canonical::hash("", b"bytes").is_err());
    assert!(canonical::hash(&"a".repeat(129), b"bytes").is_err());
}

#[test]
fn node_binding_identity_excludes_live_authority_and_wrapper_extensions() {
    let id = |value| Id::new(value).unwrap();
    let reference = canonical::content_ref(b"definition", "application/json").unwrap();
    let owner = OwnerRef {
        id: id("owner"),
        participant_ids: vec![id("node")],
        state_domain_ids: vec![id("cpu")],
    };
    let compatibility = BindingCompatibility {
        schema_version: 1,
        node_id: id("node"),
        descriptor_hash: canonical::json_hash("cnp.node-descriptor.v1", &json!({"id": "node"}))
            .unwrap(),
        implementation: ImplementationIdentity {
            schema_version: 1,
            implementation_id: id("model/1"),
            artifacts: Vec::new(),
            model_definitions: Vec::new(),
            formats: Vec::new(),
            extensions: Extensions::new(),
        },
        profile_ref: reference.clone(),
        configuration_ref: reference.clone(),
        operating_contract: operating_contract(),
        execution_owner: owner.clone(),
        capture_owner: owner,
        capabilities_ref: reference.clone(),
        guarantees_ref: reference.clone(),
        qualification_refs: Vec::new(),
        extensions: Extensions::new(),
    };
    let mut binding = NodeBinding {
        compatibility,
        authority: LiveAuthority {
            schema_version: 1,
            session_id: id("session"),
            incarnation_id: id("incarnation/1"),
            realization_id: id("realization"),
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: U64::new(1),
            input_epoch: id("epoch"),
            host_receipt: reference,
            extensions: Extensions::new(),
        },
        extensions: Extensions::new(),
    };
    let initial = binding.identity().unwrap();
    binding.authority.incarnation_id = id("incarnation/2");
    binding
        .extensions
        .insert("vendor.runtime".to_owned(), json!("different"));
    assert_eq!(initial, binding.identity().unwrap());
    binding
        .compatibility
        .extensions
        .insert("vendor.semantic".to_owned(), json!("different"));
    assert_ne!(initial, binding.identity().unwrap());

    let mut value = serde_json::to_value(&binding.authority).unwrap();
    value.as_object_mut().unwrap().remove("activation_id");
    assert!(
        canonical::decode::<LiveAuthority>(&serde_json::to_vec(&value).unwrap(), 4096).is_err()
    );
    binding.authority.owner_generation = U64::new(0);
    assert!(binding.validate().is_err());
}

#[test]
fn descriptor_identity_covers_extensions_and_refuses_duplicate_ports() {
    let reference = canonical::content_ref(b"definition", "application/json").unwrap();
    let mut descriptor = NodeDescriptor {
        schema_version: 1,
        id: Id::new("node").unwrap(),
        roles: vec![Id::new("clock").unwrap()],
        model_ref: reference.clone(),
        configuration_ref: reference.clone(),
        initialization_ref: reference.clone(),
        ports: Vec::new(),
        extensions: Extensions::new(),
    };
    let first = descriptor.identity().unwrap();
    descriptor
        .extensions
        .insert("vendor.example".to_owned(), json!({"parameter": "1"}));
    assert_ne!(first, descriptor.identity().unwrap());

    let port = PortDescriptor {
        id: Id::new("port").unwrap(),
        lanes: Vec::new(),
        interface_id: Id::new("core.clock/1").unwrap(),
        features: Vec::new(),
        configuration_ref: reference,
        extensions: Extensions::new(),
    };
    descriptor.ports = vec![port.clone(), port];
    assert!(descriptor.identity().is_err());
    descriptor.ports.clear();
    let mut value = serde_json::to_value(descriptor).unwrap();
    value["host_pointer"] = json!("123");
    assert!(
        canonical::decode::<NodeDescriptor>(&serde_json::to_vec(&value).unwrap(), 4096).is_err()
    );
}

#[test]
fn capability_axes_do_not_imply_each_other() {
    let profile = GuaranteeProfile {
        schema_version: 1,
        repeatability: Repeatability::Nondeterministic,
        capture_scope: CaptureScope::Architectural,
        continuation: Continuation::Exact,
        durable_restart: true,
        isolated_fork: false,
        conditional_replay: false,
        limitations_ref: canonical::content_ref(b"physical restrictions", "text/plain").unwrap(),
        extensions: Extensions::new(),
    };
    assert!(profile.validate().is_ok());
    assert_eq!(profile.repeatability, Repeatability::Nondeterministic);
    assert!(!profile.isolated_fork);
}

fn event(sequence: u64) -> Event {
    let id = |value: &str| Id::new(value).unwrap();
    let reference = canonical::content_ref(b"payload", "application/json").unwrap();
    let publication = Position::new(U64::new(100), U64::new(0), Phase::Publication);
    Event {
        schema_version: 1,
        id: id(&format!("event/{sequence}")),
        source: Endpoint {
            node_id: id("producer"),
            port_id: id("port"),
            lane_id: id("output"),
        },
        destination: Endpoint {
            node_id: id("consumer"),
            port_id: id("port"),
            lane_id: id("input"),
        },
        position: publication,
        stage: EventStage::Publication,
        publication_position: publication,
        delivery_position: None,
        source_sequence: U64::new(sequence),
        causal_parent_ids: Vec::new(),
        payload: reference.clone(),
        provenance_ref: reference,
        extensions: Extensions::new(),
    }
}

#[test]
fn event_stages_retain_publication_and_require_explicit_delivery_coordinates() {
    let mut produced = event(1);
    assert!(produced.validate().is_ok());
    let publication = produced.publication_position;
    produced.stage = EventStage::Delivery;
    assert!(produced.validate().is_err());
    produced.position = Position {
        phase: Phase::Delivery,
        ..publication
    };
    produced.delivery_position = Some(produced.position);
    assert!(produced.validate().is_ok());
    assert_eq!(produced.publication_position, publication);
    produced.publication_position.phase = Phase::Reaction;
    assert!(produced.validate().is_err());

    let mut value = serde_json::to_value(event(2)).unwrap();
    value.as_object_mut().unwrap().remove("delivery_position");
    assert!(canonical::decode::<Event>(&serde_json::to_vec(&value).unwrap(), 4096).is_err());
}

#[test]
fn input_batch_identity_preserves_semantic_event_order() {
    let delivered = |sequence| {
        let mut event = event(sequence);
        event.stage = EventStage::Delivery;
        event.position.phase = Phase::Delivery;
        event.delivery_position = Some(event.position);
        event
    };
    let mut batch = InputBatch {
        schema_version: 1,
        execution_owner_id: Id::new("owner").unwrap(),
        input_epoch: Id::new("epoch").unwrap(),
        batch_id: Id::new("batch").unwrap(),
        batch_sequence: U64::new(1),
        events: vec![delivered(1), delivered(2)],
        extensions: Extensions::new(),
    };
    let first = batch.identity().unwrap();
    batch.events.reverse();
    assert_ne!(first, batch.identity().unwrap());
    batch.events = vec![event(1)];
    assert!(batch.validate().is_err());
    batch.events = vec![delivered(1), delivered(1)];
    assert!(batch.validate().is_err());
}

#[test]
fn capture_representations_require_one_matching_state_source() {
    let reference = canonical::content_ref(b"state", "application/octet-stream").unwrap();
    let mut captured = CapturedOwner {
        capture_owner_id: Id::new("owner").unwrap(),
        participant_ids: vec![Id::new("node").unwrap()],
        state_domain_ids: vec![Id::new("cpu").unwrap()],
        binding_hashes: Vec::new(),
        state_schema: SchemaRef {
            id: Id::new("model.state/1").unwrap(),
            version: 1,
            definition: reference.clone(),
            extensions: Extensions::new(),
        },
        representation: CaptureRepresentation::Durable,
        state_ref: Some(reference.clone()),
        retained_source_ref: None,
        dependencies: Vec::new(),
        capture_receipt: reference.clone(),
        extensions: Extensions::new(),
    };
    assert!(captured.validate().is_ok());
    captured.retained_source_ref = Some(reference);
    assert!(captured.validate().is_err());
    captured.state_ref = None;
    assert!(captured.validate().is_err());
    captured.representation = CaptureRepresentation::RetainedSource;
    assert!(captured.validate().is_ok());

    let mut value = serde_json::to_value(captured).unwrap();
    value.as_object_mut().unwrap().remove("state_ref");
    assert!(
        canonical::decode::<CapturedOwner>(&serde_json::to_vec(&value).unwrap(), 4096).is_err()
    );
}

#[test]
fn cleanup_quarantine_requires_explicit_supervisor_custody() {
    let reference = canonical::content_ref(b"resources", "application/json").unwrap();
    let mut cleanup = CleanupRecord {
        schema_version: 1,
        owner_ids: vec![Id::new("owner").unwrap()],
        resource_inventory_ref: reference.clone(),
        disposition: CleanupDisposition::Quarantined,
        supervisor_receipt: None,
        evidence_refs: Vec::new(),
        extensions: Extensions::new(),
    };
    assert!(cleanup.validate().is_err());
    cleanup.supervisor_receipt = Some(reference);
    assert!(cleanup.validate().is_ok());
    let mut value = serde_json::to_value(cleanup).unwrap();
    value.as_object_mut().unwrap().remove("supervisor_receipt");
    assert!(
        canonical::decode::<CleanupRecord>(&serde_json::to_vec(&value).unwrap(), 4096).is_err()
    );
}
