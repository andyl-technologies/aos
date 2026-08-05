use super::*;
use crate::model::{
    MAX_REPRODUCTION_SCENARIO_BLOB_BYTES, MAX_SCENARIO_BINARY_BLOB_BYTES, Plan,
    ScenarioBinaryReader, ScenarioBinaryWriter, World,
};

fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("invalid test signal ID: {error}"))
}

fn program(value: bool) -> SignalProgram {
    let output = signal_id(if value { "true-output" } else { "false-output" });
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(value),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test program: {error}"))
}

fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value).unwrap_or_else(|error| panic!("invalid test object ID: {error}"))
}

fn binding(program: &SignalProgram) -> FaultBinding {
    binding_with_sampling(program, BindingSampling::AtBoundary)
}

fn binding_with_sampling(program: &SignalProgram, sampling: BindingSampling) -> FaultBinding {
    let target = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("invalid test target: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid test effect: {error}"));
    FaultBinding::new(
        object_id("binding-a"),
        program.exported_outputs().to_vec(),
        sampling,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target),
        [FaultPhase::Admit].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"))
}

fn u64_program(value: u64) -> SignalProgram {
    let output = signal_id("u64-output");
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("invalid u64 shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::U64(value),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid u64 program: {error}"))
}

#[test]
fn program_order_is_canonical_and_duplicates_fail_closed() {
    let first = program(false);
    let second = program(true);
    let plan = FaultSignalPlan::new(vec![second.clone(), first.clone()], Vec::new())
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    assert!(
        plan.programs()
            .windows(2)
            .all(|pair| pair[0].id() < pair[1].id())
    );
    assert!(matches!(
        FaultSignalPlan::new(vec![first.clone(), first], Vec::new()),
        Err(FaultSignalPlanError::DuplicateProgram)
    ));
    assert_ne!(plan.id(), FaultSignalPlan::empty().id());
}

#[test]
fn outer_plan_identity_commits_to_the_complete_fault_layer() {
    let program = program(true);
    let faults = FaultSignalPlan::new(vec![program], Vec::new())
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let baseline = Plan::empty();
    let plan = baseline.clone().with_fault_signals(faults.clone());

    assert_eq!(plan.fault_signals(), &faults);
    assert_ne!(plan.content_hash(), baseline.content_hash());
    assert!(
        String::from_utf8(plan.canonical_bytes())
            .unwrap_or_else(|error| panic!("canonical material is not UTF-8: {error}"))
            .ends_with(&format!("fault-signal-plan={}", faults.id().to_hex()))
    );
}

#[test]
fn plan_toml_round_trips_an_admitted_signal_program() {
    let program = program(true);
    let faults = FaultSignalPlan::new(vec![program], Vec::new())
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let plan = Plan::empty().with_fault_signals(faults);
    let encoded = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode fault signal plan: {error}"));
    let decoded = Plan::from_canonical_toml_for_world(
        &World::from_content_hash(ContentHash::default()),
        &encoded,
    )
    .unwrap_or_else(|error| panic!("decode fault signal plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.contains("[[signal_program]]"));
    assert!(encoded.contains("fault_signal_semantic_version = 1"));

    let without_version = encoded.replace("fault_signal_semantic_version = 1\n", "");
    assert!(
        Plan::from_canonical_toml_for_world(
            &World::from_content_hash(ContentHash::default()),
            &without_version,
        )
        .is_err()
    );
}

#[test]
fn plan_toml_round_trips_a_complete_binding_contract() {
    let program = program(true);
    let binding = binding(&program);
    let faults = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let plan = Plan::empty().with_fault_signals(faults);
    let encoded = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode fault signal plan: {error}"));
    let decoded = Plan::from_canonical_toml_for_world(
        &World::from_content_hash(ContentHash::default()),
        &encoded,
    )
    .unwrap_or_else(|error| panic!("decode fault signal plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.contains("[[fault_binding]]"));
}

#[test]
fn plan_binary_round_trips_a_complete_binding_contract() {
    let program = program(true);
    let binding = binding(&program);
    let faults = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let plan = Plan::empty().with_fault_signals(faults);
    let encoded = plan.to_compact_binary();
    let decoded = Plan::from_compact_binary_for_world(
        &World::from_content_hash(ContentHash::default()),
        &encoded,
    )
    .unwrap_or_else(|error| panic!("decode fault signal plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.starts_with(b"crucible.plan.v3\0"));
    let mut old_magic = encoded.clone();
    old_magic[..b"crucible.plan.v3\0".len()].copy_from_slice(b"crucible.plan.v2\0");
    assert!(
        Plan::from_compact_binary_for_world(
            &World::from_content_hash(ContentHash::default()),
            &old_magic,
        )
        .is_err()
    );
}

#[test]
fn wire_decode_reenters_identity_scalar_and_selector_validation() {
    assert!(serde_json::from_str::<SignalId>(r#""Not-Canonical""#).is_err());
    assert!(serde_json::from_str::<FaultObjectId>(r#""Not-Canonical""#).is_err());
    assert!(serde_json::from_str::<ProbabilityMillionths>("1000001").is_err());
    assert!(serde_json::from_str::<PositiveU64>("0").is_err());
    assert!(serde_json::from_str::<OperationSet>("[]").is_err());

    let valid = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("valid selector: {error}"));
    let mut value =
        serde_json::to_value(valid).unwrap_or_else(|error| panic!("encode selector JSON: {error}"));
    value["targets"] = serde_json::Value::Array(Vec::new());
    assert!(serde_json::from_value::<ResolvedTargetSet>(value).is_err());
}

#[test]
fn wire_admission_rejects_versions_missing_programs_and_duplicate_contracts() {
    let program = program(true);
    let binding = binding(&program);
    let plan = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));

    let mut wrong_version = FaultSignalPlanWire::from_plan(&plan);
    wrong_version.semantic_version += 1;
    assert!(matches!(
        wrong_version.admit(),
        Err(FaultSignalWireError::Version { .. })
    ));

    let mut missing_program = FaultSignalPlanWire::from_plan(&plan);
    missing_program.fault_binding[0].program = ContentHash::from_bytes(b"missing-program");
    assert!(matches!(
        missing_program.admit(),
        Err(FaultSignalWireError::MissingProgram { .. })
    ));

    let mut duplicate_program = FaultSignalPlanWire::from_plan(&plan);
    duplicate_program
        .signal_program
        .push(duplicate_program.signal_program[0].clone());
    assert!(matches!(
        duplicate_program.admit(),
        Err(FaultSignalWireError::Plan(
            FaultSignalPlanError::DuplicateProgram
        ))
    ));

    let mut unexpected_declaration = FaultSignalPlanWire::from_plan(&plan);
    unexpected_declaration.fault_binding[0].service_declaration = Some(ServiceProfileDeclaration {
        id: object_id("unused-service"),
        semantic_version: 1,
        effect: EffectKind::NetworkAvailability,
        inputs: vec![
            SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("service input shape: {error}")),
        ],
        parameters: vec![MappedEffectParameter::UnsignedCount],
    });
    assert!(matches!(
        unexpected_declaration.admit(),
        Err(FaultSignalWireError::UnexpectedMappingDeclaration { .. })
    ));

    let mut missing_declaration = FaultSignalPlanWire::from_plan(&plan);
    missing_declaration.fault_binding[0].mapping = BindingMapping::StateTransition {
        transition_table: object_id("missing-transition-table"),
    };
    assert!(matches!(
        missing_declaration.admit(),
        Err(FaultSignalWireError::MissingMappingDeclaration { .. })
    ));
}

#[test]
fn wire_encoding_is_bounded_and_empty_encoding_is_canonical() {
    let empty = FaultSignalPlan::empty();
    let decoded = FaultSignalPlan::from_wire_bytes(empty.wire_bytes())
        .unwrap_or_else(|error| panic!("decode empty plan: {error}"));
    assert_eq!(decoded, empty);

    let error = encode_wire_bounded(&vec![0_u8; 32], 8)
        .expect_err("bounded encoder must reject oversized output");
    assert!(error.is_io());
}

#[test]
fn reproduction_scenario_envelope_contains_a_maximum_fault_wire_layer() {
    assert_eq!(
        MAX_REPRODUCTION_SCENARIO_BLOB_BYTES,
        MAX_SCENARIO_BINARY_BLOB_BYTES + HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
    );

    let magic = b"blob-boundary-test\0";
    let mut writer = ScenarioBinaryWriter::new(magic);
    writer.write_count(MAX_SCENARIO_BINARY_BLOB_BYTES + 1);
    let bytes = writer.finish();

    let mut ordinary = ScenarioBinaryReader::new(&bytes, magic)
        .unwrap_or_else(|error| panic!("ordinary reader: {error}"));
    let ordinary_error = ordinary
        .read_binary_blob("ordinary")
        .expect_err("ordinary blobs stop at their original limit");
    assert!(ordinary_error.to_string().contains("blob limit"));

    let mut enclosing = ScenarioBinaryReader::new(&bytes, magic)
        .unwrap_or_else(|error| panic!("enclosing reader: {error}"));
    let enclosing_error = enclosing
        .read_binary_blob_bounded("scenario", MAX_REPRODUCTION_SCENARIO_BLOB_BYTES)
        .expect_err("the synthetic blob has no payload");
    assert!(!enclosing_error.to_string().contains("blob limit"));
}

#[test]
fn toml_round_trips_full_range_u64_values_without_narrowing() {
    let numeric_program = u64_program(u64::MAX);
    let numeric_plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![numeric_program], Vec::new())
            .unwrap_or_else(|error| panic!("numeric plan: {error}")),
    );
    let numeric_toml = numeric_plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode u64::MAX signal: {error}"));
    assert!(numeric_toml.contains("u64:18446744073709551615"));
    assert_eq!(
        Plan::from_canonical_toml_for_world(
            &World::from_content_hash(ContentHash::default()),
            &numeric_toml,
        )
        .unwrap_or_else(|error| panic!("decode u64::MAX signal: {error}")),
        numeric_plan,
    );

    let program = program(true);
    let binding = binding_with_sampling(
        &program,
        BindingSampling::CadenceNanos(
            PositiveU64::new("cadence_nanos", u64::MAX)
                .unwrap_or_else(|error| panic!("max cadence: {error}")),
        ),
    );
    let cadence_plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("cadence plan: {error}")),
    );
    let cadence_toml = cadence_plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode max cadence: {error}"));
    assert_eq!(
        Plan::from_canonical_toml_for_world(
            &World::from_content_hash(ContentHash::default()),
            &cadence_toml,
        )
        .unwrap_or_else(|error| panic!("decode max cadence: {error}")),
        cadence_plan,
    );
}
