//! Binding admission and canonical-contract tests.
use super::*;

fn object_id(value: &str) -> FaultObjectId {
    match FaultObjectId::parse(value) {
        Ok(id) => id,
        Err(error) => panic!("test object ID must be valid: {error}"),
    }
}

fn signal_id(value: &str) -> SignalId {
    match SignalId::parse(value) {
        Ok(id) => id,
        Err(error) => panic!("test signal ID must be valid: {error}"),
    }
}

fn boolean_program() -> SignalProgram {
    let id = signal_id("active");
    let shape = match SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0) {
        Ok(value) => value,
        Err(error) => panic!("test shape must be valid: {error}"),
    };
    match SignalProgram::new(
        vec![SignalNode {
            id: id.clone(),
            domain: SignalDomain::VirtualTime,
            output: shape,
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(true),
            },
        }],
        vec![id],
        SignalResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test program must be valid: {error}"),
    }
}

#[test]
fn selectors_are_canonical_and_homogeneous() {
    let first = ResolvedFaultTarget::Node {
        node: object_id("node-a"),
    };
    let second = ResolvedFaultTarget::Node {
        node: object_id("node-b"),
    };
    let set = match ResolvedTargetSet::new(vec![second.clone(), first.clone()], false) {
        Ok(value) => value,
        Err(error) => panic!("test selector must be valid: {error}"),
    };
    assert_eq!(set.targets(), &[first, second]);

    let network = ResolvedFaultTarget::NetworkForwarder {
        forwarder: object_id("switch-a"),
    };
    assert!(ResolvedTargetSet::new(vec![network, set.targets()[0].clone()], false).is_err());
}

#[test]
fn search_candidates_are_finite_unique_and_canonical() {
    let mut candidates = vec![object_id("transition-b"), object_id("transition-a")];
    candidates.sort();
    assert!(validate_candidates(&candidates).is_ok());
    assert_eq!(
        candidates,
        vec![object_id("transition-a"), object_id("transition-b")]
    );
    assert!(validate_candidates(&[SignalValue::U64(1), SignalValue::U64(1)]).is_err());
}

#[test]
fn empty_dynamic_path_cannot_hide_a_storage_effect() {
    let targets = match ResolvedTargetSet::new(Vec::new(), true) {
        Ok(value) => value,
        Err(error) => panic!("explicit empty selector must be valid: {error}"),
    };
    let effect = match EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Storage(StorageEffectSpecification::Availability {
            state: StorageAvailabilityState::Offline,
            reconnect_policy: StorageTransitionPolicy::Fail,
        }),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test effect must be valid: {error}"),
    };
    let result = FaultBinding::new(
        object_id("bad-dynamic-path"),
        vec![signal_id("active")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::DynamicPath {
            path: object_id("path-a"),
            initial: targets,
            membership_semantic_version: 1,
        },
        [FaultPhase::Admit].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: false,
        },
        &boolean_program(),
    );
    assert_eq!(result, Err(BindingError::DynamicSelectorAdapter));
}

#[test]
fn mapped_field_must_belong_to_the_effect() {
    let shape = SignalShape {
        value_type: SignalValueType::ProbabilityMillionths,
        unit: SignalUnit::ProbabilityMillionths,
        scale_decimal_exponent: 0,
    };
    assert_eq!(
        validate_mapping(
            &BindingMapping::MapParameter {
                parameter: MappedEffectParameter::Probability,
            },
            &[&shape],
            EffectKind::NetworkAvailability,
            EffectLifetime::Persistent,
        ),
        Err(BindingError::MappingShape)
    );
}

#[test]
fn binding_contract_codec_is_golden_and_covers_every_top_level_field() {
    let program = boolean_program();
    let target = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("test target must be valid: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect must be valid: {error}"));
    let binding = FaultBinding::new(
        object_id("binding-golden"),
        vec![signal_id("active")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target),
        [FaultPhase::Admit].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: false,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("test binding must be valid: {error}"));
    let golden = binding
        .contract_digest()
        .unwrap_or_else(|error| panic!("binding encoding must succeed: {error}"));
    assert_eq!(
        golden.to_hex(),
        "c72f522b8fc2e39d01f57a1547765eb7a5062545a33482e5940b778bd73e2d09"
    );

    let mut mutations = Vec::new();
    let mut changed = binding.clone();
    changed.id = object_id("binding-changed");
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.program = ContentHash::from_bytes(b"changed-program");
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.signals.push(signal_id("other-signal"));
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.sampling = BindingSampling::AtChange;
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.mapping = BindingMapping::ActiveWhenTrue { invert: true };
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.selector = TargetSelector::TargetSet(changed.selector.resolved().clone());
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.phases.insert(FaultPhase::Resolve);
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::ReceiveOnly,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("changed effect must be valid: {error}"));
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.opportunity_filter = Some(OpportunityFilter {
        adapter: FaultAdapter::Network,
        operations: OperationSet::new(vec![FaultOperation::NetworkTransmit])
            .unwrap_or_else(|error| panic!("operation set must be valid: {error}")),
        phases: [FaultPhase::Admit].into_iter().collect(),
        target_kinds: BTreeSet::new(),
    });
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.search = BindingSearchPolicy::BranchOutcome {
        maximum_branches: PositiveU64::new("maximum_branches", 2)
            .unwrap_or_else(|error| panic!("search bound must be valid: {error}")),
    };
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.observability.record_inactive_opportunities = true;
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.transition_declaration = Some(StateTransitionTableDeclaration {
        id: object_id("transition-table"),
        semantic_version: 1,
        input: SignalValueType::Event(signal_id("transition-request")),
        effect: EffectKind::NetworkAvailability,
        transitions: [(SignalValue::Bool(true), object_id("transition-a"))]
            .into_iter()
            .collect(),
        default_transition: object_id("transition-default"),
    });
    mutations.push(changed);
    let mut changed = binding.clone();
    changed.service_declaration = Some(ServiceProfileDeclaration {
        id: object_id("service-profile"),
        semantic_version: 1,
        effect: EffectKind::NetworkAvailability,
        inputs: vec![ServiceProfileInput {
            role: object_id("service-input"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("service input must be valid: {error}")),
        }],
        parameters: vec![MappedEffectParameter::UnsignedCount],
    });
    mutations.push(changed);

    for changed in mutations {
        let changed_digest = changed
            .contract_digest()
            .unwrap_or_else(|error| panic!("changed binding must encode: {error}"));
        assert_ne!(changed_digest, golden);
    }
}
