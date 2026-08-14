use super::*;

struct NoArtifacts;

#[derive(Default)]
struct AcceptActions {
    prepared: Option<PreparedActionBatch>,
}

struct RejectActions;

#[derive(Default)]
struct MismatchedActions {
    prepared: bool,
    aborted: bool,
}

#[derive(Default)]
struct CountingActions {
    prepares: u64,
    commits: u64,
    prepared: Option<PreparedActionBatch>,
}

fn prepared_actions(actions: &[ResolvedBindingAction]) -> PreparedActionBatch {
    PreparedActionBatch {
        transaction: ContentHash::from_bytes(b"prepared-transaction"),
        results: actions
            .iter()
            .map(|action| PreparedActionResult {
                action: action.id(),
                precondition: None,
                observation: FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: match action.kind {
                        BindingActionKind::UpsertPersistent => {
                            FaultObservationKind::BindingActivation
                        }
                        BindingActionKind::RemovePersistent => {
                            FaultObservationKind::BindingDeactivation
                        }
                        BindingActionKind::Apply => FaultObservationKind::EffectApplied,
                    },
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence: ContentHash::from_bytes(b"adapter-evidence"),
                },
            })
            .collect(),
    }
}

impl FaultActionSink for AcceptActions {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        let prepared = prepared_actions(actions);
        self.prepared = Some(prepared.clone());
        Ok(prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        self.prepared
            .take()
            .filter(|prepared| prepared.transaction == transaction)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ))
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        Ok(())
    }
}

impl FaultActionSink for CountingActions {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        self.prepares += 1;
        let prepared = prepared_actions(actions);
        self.prepared = Some(prepared.clone());
        Ok(prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        self.commits += 1;
        self.prepared
            .take()
            .filter(|prepared| prepared.transaction == transaction)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ))
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        Ok(())
    }
}

impl FaultActionSink for RejectActions {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        let action = actions
            .first()
            .unwrap_or_else(|| panic!("rejection test requires an action"));
        Err(Box::new(RejectedActionBatch {
            error: FaultRuntimeError::InvalidContributionKey,
            observations: vec![FaultObservation {
                semantic_version: FAULT_RUNTIME_STATE_VERSION,
                kind: FaultObservationKind::EffectRejected,
                coordinate: action.coordinate,
                binding: Some(action.binding.clone()),
                target: Some(action.target.clone()),
                opportunity: action.opportunity,
                evidence: ContentHash::from_bytes(b"rejection-evidence"),
            }],
            rejected_action: Some(action.id()),
        }))
    }

    fn commit_batch(
        &mut self,
        _transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::UnknownAdapterTransaction,
        ))
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        Ok(())
    }
}

#[test]
fn network_control_opportunities_only_match_their_typed_transform_contract() {
    let transform = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Opportunity,
        EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
            technology: object_id("network-routing-v1"),
            operations: OperationSet::new(vec![FaultOperation::NetworkRoute])
                .unwrap_or_else(|error| panic!("control operation set: {error}")),
            kind: NetworkControlResultKind::Drop,
            result: None,
        }),
    )
    .unwrap_or_else(|error| panic!("control transform: {error}"));
    let target = ResolvedFaultTarget::NetworkPath {
        path_version: object_id("route-a"),
        direction: FaultDirection::AToB,
    };
    let control = FaultOpportunity::new(
        target.clone(),
        FaultOperation::NetworkRoute,
        FaultPhase::Resolve,
        coordinate(1),
        0,
        None,
        OpportunityPayload::NetworkControl {
            technology: object_id("network-routing-v1"),
            event_sequence: 0,
            request_digest: ContentHash::from_bytes(b"request"),
            result_schema: object_id("network-route-id-v1"),
            result_digest: ContentHash::from_bytes(b"route-b"),
        },
    )
    .unwrap_or_else(|error| panic!("control opportunity: {error}"));
    assert!(control_opportunity_matches(&transform, Some(&control)));
    assert!(!control_opportunity_matches(
        &availability_effect(),
        Some(&control)
    ));

    let wrong_technology = FaultOpportunity::new(
        target,
        FaultOperation::NetworkRoute,
        FaultPhase::Resolve,
        coordinate(1),
        1,
        None,
        OpportunityPayload::NetworkControl {
            technology: object_id("network-contact-v1"),
            event_sequence: 1,
            request_digest: ContentHash::from_bytes(b"request"),
            result_schema: object_id("network-route-id-v1"),
            result_digest: ContentHash::from_bytes(b"route-b"),
        },
    )
    .unwrap_or_else(|error| panic!("wrong-technology opportunity: {error}"));
    assert!(!control_opportunity_matches(
        &transform,
        Some(&wrong_technology)
    ));
}

impl FaultActionSink for MismatchedActions {
    fn prepare_batch(
        &mut self,
        _actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        self.prepared = true;
        Ok(PreparedActionBatch {
            transaction: ContentHash::from_bytes(b"malformed-transaction"),
            results: Vec::new(),
        })
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        self.prepared = false;
        Ok(PreparedActionBatch {
            transaction,
            results: Vec::new(),
        })
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        self.prepared = false;
        self.aborted = true;
        Ok(())
    }
}

impl SignalArtifactProvider for NoArtifacts {
    fn inverse_cdf_table(
        &self,
        _content: &ContentHash,
    ) -> Result<InverseCdfTable, SignalEvaluationError> {
        Err(SignalEvaluationError::ArtifactContentMismatch(
            ContentHash::default(),
        ))
    }

    fn evaluate_artifact_source(
        &self,
        node: &SignalNode,
        _source: &SignalSourceSpecification,
        _coordinate: &SignalCoordinate,
        _same_coordinate_sequence: u64,
        _choice: &SignalChoiceContext,
        _inputs: &[EvaluatedSignal],
        _resource_limits: FaultResourceLimits,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        Err(SignalEvaluationError::ArtifactSourceRequired(
            node.id.clone(),
        ))
    }
}

fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value).unwrap_or_else(|error| panic!("invalid test object ID: {error}"))
}

fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("invalid test signal ID: {error}"))
}

fn constant_program(value: SignalValue, shape: SignalShape) -> SignalProgram {
    let output = signal_id("output");
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: shape,
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant { value },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test signal program: {error}"))
}

fn event_program(schema: &str, payload: Vec<u8>, nanos: u64) -> SignalProgram {
    let output = signal_id("output");
    let schema = signal_id(schema);
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::Event,
            output: SignalShape::new(
                SignalValueType::Event(schema.clone()),
                SignalUnit::Dimensionless,
                0,
            )
            .unwrap_or_else(|error| panic!("invalid event test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: vec![SignalPoint {
                    coordinate: SignalCoordinate::Event {
                        parent: Box::new(SignalCoordinate::VirtualTime { nanos }),
                        sequence: 0,
                    },
                    sequence: 0,
                    value: SignalValue::Event { schema, payload },
                }],
            }),
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid event test program: {error}"))
}

fn target_set() -> ResolvedTargetSet {
    network_target_set("segment-a")
}

fn network_target_set(segment: &str) -> ResolvedTargetSet {
    ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: object_id(segment),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("invalid test target: {error}"))
}

fn observability() -> BindingObservabilityPolicy {
    BindingObservabilityPolicy {
        samples: SampleObservation::ChangesAndEffects,
        record_inactive_opportunities: false,
        retain_mapped_values: true,
    }
}

fn availability_effect() -> EffectRequest {
    EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid test effect: {error}"))
}

fn forwarder_lifecycle_effect(lifetime: EffectLifetime) -> EffectRequest {
    EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        lifetime,
        EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
            transition: NetworkForwarderTransition::Restart,
            downtime_nanos: PositiveU64::new("downtime_nanos", 1)
                .unwrap_or_else(|error| panic!("invalid downtime: {error}")),
            queue_policy: NetworkStatePolicy::Preserve,
            table_policy: NetworkStatePolicy::Preserve,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid lifecycle effect: {error}"))
}

fn coordinate(nanos: u64) -> FaultCoordinate {
    FaultCoordinate {
        virtual_nanos: nanos,
        retired_instructions: None,
    }
}

fn threshold_binding(
    program: &SignalProgram,
    comparison: ThresholdComparison,
    threshold: u64,
    clear_threshold: Option<u64>,
    residence_nanos: u64,
) -> FaultBinding {
    FaultBinding::new(
        object_id("binding-threshold"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::Threshold {
            comparison,
            threshold: SignalValue::U64(threshold),
            clear_threshold: clear_threshold.map(SignalValue::U64),
            residence_nanos,
        },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        program,
    )
    .unwrap_or_else(|error| panic!("invalid threshold binding: {error}"))
}

#[test]
fn persistent_activation_is_installed_once_and_retains_values() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-a"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));

    let first = runtime
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("first evaluation failed: {error}"));
    assert!(!first.actions.is_empty());
    assert!(
        first
            .actions
            .iter()
            .all(|action| action.kind == BindingActionKind::UpsertPersistent)
    );
    assert_eq!(first.actions.len(), 1);
    assert_eq!(first.actions[0].phase, FaultPhase::Admit);
    let second = runtime
        .evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("second evaluation failed: {error}"));
    assert!(second.actions.is_empty());
    assert!(
        runtime
            .active()
            .entries()
            .values()
            .all(|contribution| contribution.mapping_output.as_ref()
                == &ResolvedMappingOutput::Activation { active: true })
    );
}

#[test]
fn piecewise_parameter_actions_carry_the_transferred_value() {
    let program = constant_program(
        SignalValue::U64(5),
        SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(
                PositiveU64::new("delay_nanos", 1)
                    .unwrap_or_else(|error| panic!("invalid delay: {error}")),
            ),
            distance_velocity_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid test effect: {error}"));
    let binding = FaultBinding::new(
        object_id("binding-piecewise"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: MappedEffectParameter::DurationNanos,
            points: vec![
                BindingMapPoint {
                    input: SignalValue::U64(0),
                    output: SignalValue::DurationNanos(10),
                },
                BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(30),
                },
            ],
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));

    let evaluation = runtime
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    assert_eq!(
        evaluation.actions[0].mapping_output.as_ref(),
        &ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::DurationNanos,
            value: SignalValue::DurationNanos(20),
        }
    );
}

#[test]
fn initially_inactive_binding_does_not_emit_removal_actions() {
    let program = constant_program(
        SignalValue::Bool(false),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-inactive"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));

    let evaluation = runtime
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    assert!(evaluation.actions.is_empty());
    assert!(runtime.active().entries().is_empty());
}

#[test]
fn finite_binding_search_choices_replay_once_and_reject_unused_overrides() {
    let program = constant_program(
        SignalValue::U64(5),
        SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(
                PositiveU64::new("delay_nanos", 1)
                    .unwrap_or_else(|error| panic!("invalid delay: {error}")),
            ),
            distance_velocity_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid test effect: {error}"));
    let binding = FaultBinding::new(
        object_id("binding-search-outcome"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: MappedEffectParameter::DurationNanos,
            points: vec![
                BindingMapPoint {
                    input: SignalValue::U64(0),
                    output: SignalValue::DurationNanos(10),
                },
                BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(30),
                },
            ],
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::BranchParameter {
            parameter: MappedEffectParameter::DurationNanos,
            candidates: vec![
                SignalValue::DurationNanos(10),
                SignalValue::DurationNanos(20),
            ],
        },
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid search binding: {error}"));
    let seed = ContentHash::from_bytes(b"finite-binding-search");
    let mut discovery = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid discovery runtime: {error}"));
    let discovered = discovery
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("search discovery failed: {error}"));
    let choice = discovered
        .search_choices
        .first()
        .unwrap_or_else(|| panic!("branching binding must expose a finite choice"));
    assert_eq!(choice.candidate_count, 2);
    assert_eq!(choice.selected_index, Some(1));
    assert!(!choice.overridden);

    let overrides: BTreeMap<SearchChoiceId, SearchOverride> = [(
        choice.id,
        SearchOverride {
            candidate_index: 0,
            candidates_digest: choice.candidates_digest,
            parent_branch: Some(ContentHash::from_bytes(b"search-parent")),
        },
    )]
    .into_iter()
    .collect();
    let mut replay = FaultBindingRuntime::new_with_search_overrides(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
        overrides.clone(),
    )
    .unwrap_or_else(|error| panic!("invalid replay runtime: {error}"));
    let replayed = replay
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("search replay failed: {error}"));
    assert_eq!(replayed.actions.len(), 1);
    assert_eq!(
        replayed.actions[0].mapping_output.as_ref(),
        &ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::DurationNanos,
            value: SignalValue::DurationNanos(10),
        }
    );
    assert_eq!(replayed.search_choices[0].selected_index, Some(0));
    assert!(replayed.search_choices[0].overridden);
    assert!(replay.verify_search_overrides_consumed().is_ok());
    let consumed_checkpoint = replay
        .checkpoint()
        .unwrap_or_else(|error| panic!("consumed search state should checkpoint: {error}"));
    let restored = FaultBindingRuntime::restore(
        &program,
        vec![binding],
        &NoArtifacts,
        seed,
        FaultResourceLimits::default(),
        &consumed_checkpoint,
    )
    .unwrap_or_else(|error| panic!("consumed search state should restore: {error}"));
    assert!(restored.verify_search_overrides_consumed().is_ok());

    let unused = FaultBindingRuntime::new_with_search_overrides(
        &program,
        Vec::new(),
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
        overrides,
    )
    .unwrap_or_else(|error| panic!("invalid unused-override runtime: {error}"));
    assert!(matches!(
        unused.verify_search_overrides_consumed(),
        Err(BindingRuntimeError::UnusedSearchOverride)
    ));
}

#[test]
fn dynamic_membership_reconciles_active_adapter_contributions() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding_id = object_id("binding-dynamic");
    let binding = FaultBinding::new(
        binding_id.clone(),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::DynamicPath {
            path: object_id("path-a"),
            initial: network_target_set("segment-a"),
            membership_semantic_version: 1,
        },
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));
    runtime
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("activation failed: {error}"));

    let evaluation = runtime
        .update_dynamic_targets(
            &binding_id,
            DynamicMembershipTransition {
                path: object_id("path-a"),
                semantic_version: 1,
                sequence: 1,
                evidence: ContentHash::from_bytes(b"route-change"),
                targets: network_target_set("segment-b"),
            },
            coordinate(1),
            0,
            &mut AcceptActions::default(),
        )
        .unwrap_or_else(|error| panic!("membership update failed: {error}"));
    assert!(
        evaluation
            .actions
            .iter()
            .any(|action| action.kind == BindingActionKind::RemovePersistent)
    );
    assert!(
        evaluation
            .actions
            .iter()
            .any(|action| action.kind == BindingActionKind::UpsertPersistent)
    );
    assert!(runtime.active().entries().keys().all(|key| matches!(
        &key.target,
        ResolvedFaultTarget::NetworkSegment { segment, .. }
            if segment == &object_id("segment-b")
    )));
}

#[test]
fn dynamic_membership_computes_wakeup_before_adapter_prepare() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let dynamic_id = object_id("binding-dynamic-terminal");
    let dynamic = FaultBinding::new(
        dynamic_id.clone(),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::DynamicPath {
            path: object_id("path-terminal"),
            initial: network_target_set("segment-a"),
            membership_semantic_version: 1,
        },
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid dynamic binding: {error}"));
    let cadence = FaultBinding::new(
        object_id("binding-terminal-cadence"),
        vec![signal_id("output")],
        BindingSampling::CadenceNanos(
            PositiveU64::new("cadence_nanos", 1)
                .unwrap_or_else(|error| panic!("invalid cadence: {error}")),
        ),
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid cadence binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![dynamic, cadence],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid terminal runtime: {error}"));
    runtime
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("activation failed: {error}"));
    let mut sink = CountingActions::default();

    assert!(matches!(
        runtime.update_dynamic_targets(
            &dynamic_id,
            DynamicMembershipTransition {
                path: object_id("path-terminal"),
                semantic_version: 1,
                sequence: 1,
                evidence: ContentHash::from_bytes(b"terminal-route-change"),
                targets: network_target_set("segment-b"),
            },
            coordinate(u64::MAX),
            0,
            &mut sink,
        ),
        Err(BindingRuntimeError::WakeupOverflow)
    ));
    assert_eq!(sink.prepares, 0);
    assert_eq!(sink.commits, 0);
    assert!(runtime.active().entries().keys().any(|key| matches!(
        &key.target,
        ResolvedFaultTarget::NetworkSegment { segment, .. }
            if segment == &object_id("segment-a")
    )));
}

#[test]
fn adapter_rejection_rolls_back_the_entire_boundary() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-rollback"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));

    assert!(matches!(
        runtime.evaluate_boundary(coordinate(0), 0, &mut RejectActions),
        Err(BindingRuntimeError::AdapterRejected(_))
    ));
    assert!(runtime.active().entries().is_empty());
    assert!(runtime.states().values().all(|state| !state.active));
    let accepted = runtime
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("retry after rollback failed: {error}"));
    assert!(!accepted.actions.is_empty());
}

#[test]
fn malformed_adapter_success_rolls_back_the_entire_boundary() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-result-mismatch"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));

    let mut sink = MismatchedActions::default();
    let result = runtime.evaluate_boundary(coordinate(0), 0, &mut sink);
    assert!(!sink.aborted);
    assert!(matches!(
        result,
        Err(BindingRuntimeError::AdapterCommit(
            FaultRuntimeError::IncompleteAdapterState
        ))
    ));
    assert!(matches!(
        runtime.evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default()),
        Err(BindingRuntimeError::Poisoned)
    ));
    assert!(!sink.prepared);
    assert!(runtime.active().entries().is_empty());
    assert!(runtime.states().values().all(|state| !state.active));
}

#[test]
fn event_parent_drives_exactly_one_impulse() {
    let program = event_program("link-event", vec![1, 2, 3], 7);
    let binding = FaultBinding::new(
        object_id("binding-event"),
        vec![signal_id("output")],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set()),
        [FaultPhase::Boundary].into_iter().collect(),
        forwarder_lifecycle_effect(EffectLifetime::Impulse),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid event binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid event runtime: {error}"));

    let evaluation = runtime
        .evaluate_boundary(coordinate(7), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("event evaluation failed: {error}"));
    assert_eq!(evaluation.actions.len(), 1);
    assert_eq!(evaluation.actions[0].kind, BindingActionKind::Apply);
    assert!(matches!(
        evaluation.actions[0].mapping_output.as_ref(),
        ResolvedMappingOutput::Impulse { .. }
    ));
    let duplicate = runtime
        .evaluate_boundary(coordinate(7), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("duplicate event evaluation failed: {error}"));
    assert!(duplicate.actions.is_empty());
}

#[test]
fn sampled_inactive_event_checkpoint_restores_before_event() {
    let program = event_program("future-event", vec![1], 7);
    let binding = FaultBinding::new(
        object_id("binding-future-event"),
        vec![signal_id("output")],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set()),
        [FaultPhase::Boundary].into_iter().collect(),
        forwarder_lifecycle_effect(EffectLifetime::Impulse),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid future event binding: {error}"));
    let seed = ContentHash::from_bytes(b"future-event-seed");
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid future event runtime: {error}"));

    let before_event = runtime
        .evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("inactive event sample failed: {error}"));
    assert!(before_event.actions.is_empty());
    let checkpoint = runtime
        .checkpoint()
        .unwrap_or_else(|error| panic!("inactive event checkpoint failed: {error}"));

    let restored = FaultBindingRuntime::restore(
        &program,
        vec![binding],
        &NoArtifacts,
        seed,
        FaultResourceLimits::default(),
        &checkpoint,
    )
    .unwrap_or_else(|error| panic!("inactive event checkpoint should restore: {error}"));
    assert_eq!(restored.states(), runtime.states());
    assert_eq!(restored.active(), runtime.active());
}

#[test]
fn state_transition_uses_the_exhaustive_default_for_an_unknown_request() {
    let request = SignalValue::Event {
        schema: signal_id("link-event"),
        payload: vec![9],
    };
    let program = event_program("link-event", vec![9], 4);
    let transition_table = object_id("link-transition-table");
    let selected_transition = object_id("reject-unknown-transition");
    let known_request = SignalValue::Event {
        schema: signal_id("link-event"),
        payload: vec![8],
    };
    let registry = BindingMappingRegistry::new(
        vec![StateTransitionTableDeclaration {
            id: transition_table.clone(),
            semantic_version: 1,
            input: SignalValueType::Event(signal_id("link-event")),
            effect: EffectKind::NetworkForwarderLifecycle,
            transitions: [(known_request, object_id("restart-forwarder"))]
                .into_iter()
                .collect(),
            default_transition: selected_transition.clone(),
        }],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("invalid mapping registry: {error}"));
    let binding = FaultBinding::new_with_registry(
        object_id("binding-transition"),
        vec![signal_id("output")],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::StateTransition {
            transition_table: transition_table.clone(),
        },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Boundary].into_iter().collect(),
        forwarder_lifecycle_effect(EffectLifetime::StateMachine),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
        &registry,
    )
    .unwrap_or_else(|error| panic!("invalid transition binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid transition runtime: {error}"));

    let evaluation = runtime
        .evaluate_boundary(coordinate(4), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("transition evaluation failed: {error}"));
    assert_eq!(evaluation.actions.len(), 1);
    assert_eq!(
        evaluation.actions[0].mapping_output.as_ref(),
        &ResolvedMappingOutput::StateTransition {
            transition_table,
            request,
            selected_transition,
        }
    );
}

#[test]
fn scheduler_rejects_a_backward_boundary() {
    let program = constant_program(
        SignalValue::Bool(false),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-monotone"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid monotone binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid monotone runtime: {error}"));
    runtime
        .evaluate_boundary(coordinate(2), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("first boundary failed: {error}"));
    assert!(matches!(
        runtime.evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default()),
        Err(BindingRuntimeError::NonMonotoneBoundary)
    ));
}

#[test]
fn opportunity_before_boundary_is_rejected() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-boundary-after-opportunity"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid boundary binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid boundary runtime: {error}"));
    let opportunity = FaultOpportunity::new(
        target_set().targets()[0].clone(),
        FaultOperation::NetworkTransmit,
        FaultPhase::Admit,
        coordinate(3),
        0,
        Some(FaultDirection::AToB),
        OpportunityPayload::None,
    )
    .unwrap_or_else(|error| panic!("invalid test opportunity: {error}"));

    assert!(matches!(
        runtime.evaluate_opportunity(&opportunity, 0, &mut AcceptActions::default()),
        Err(BindingRuntimeError::OpportunityBeforeBoundary)
    ));
    let boundary_evaluation = runtime
        .evaluate_boundary(coordinate(3), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("boundary evaluation failed: {error}"));
    assert_eq!(boundary_evaluation.actions.len(), 1);
    assert!(runtime.states().values().all(|state| state.active));
    let opportunity_evaluation = runtime
        .evaluate_opportunity(&opportunity, 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("ordered opportunity evaluation failed: {error}"));
    assert!(opportunity_evaluation.actions.is_empty());
}

#[test]
fn opportunity_after_latest_completed_boundary_is_accepted() {
    let program = constant_program(
        SignalValue::ProbabilityMillionths(1_000_000),
        SignalShape::new(
            SignalValueType::ProbabilityMillionths,
            SignalUnit::ProbabilityMillionths,
            0,
        )
        .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Opportunity,
        EffectSpecification::Network(NetworkEffectSpecification::Jitter {
            maximum_nanos: PositiveU64::new("maximum_nanos", 5)
                .unwrap_or_else(|error| panic!("invalid jitter bound: {error}")),
            distribution: NetworkDistribution::Uniform,
            distribution_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid opportunity effect: {error}"));
    let binding = FaultBinding::new(
        object_id("binding-in-quantum-opportunity"),
        vec![signal_id("output")],
        BindingSampling::AtOpportunity,
        BindingMapping::Hazard,
        TargetSelector::Exact(target_set()),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        Some(OpportunityFilter {
            adapter: FaultAdapter::Network,
            operations: OperationSet::new(vec![FaultOperation::NetworkTraverse])
                .unwrap_or_else(|error| panic!("invalid opportunity operations: {error}")),
            phases: [FaultPhase::Resolve].into_iter().collect(),
            target_kinds: [FaultTargetKind::NetworkSegment].into_iter().collect(),
        }),
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid opportunity binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid opportunity runtime: {error}"));
    runtime
        .evaluate_boundary(coordinate(3), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("boundary evaluation failed: {error}"));
    let opportunity = FaultOpportunity::new(
        target_set().targets()[0].clone(),
        FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        coordinate(4),
        0,
        Some(FaultDirection::AToB),
        OpportunityPayload::None,
    )
    .unwrap_or_else(|error| panic!("invalid test opportunity: {error}"));

    let evaluation = runtime
        .evaluate_opportunity(&opportunity, 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("in-quantum opportunity should be ordered: {error}"));
    assert_eq!(evaluation.actions.len(), 1);
}

#[test]
fn undeclared_opportunity_sampling_does_not_advance_the_global_cursor() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("boundary-only-binding"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid boundary binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid boundary runtime: {error}"));
    runtime
        .evaluate_boundary(coordinate(3), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("initial boundary failed: {error}"));
    let opportunity = FaultOpportunity::new(
        target_set().targets()[0].clone(),
        FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        coordinate(9),
        0,
        Some(FaultDirection::AToB),
        OpportunityPayload::None,
    )
    .unwrap_or_else(|error| panic!("invalid irrelevant opportunity: {error}"));

    let evaluation = runtime
        .evaluate_opportunity(&opportunity, 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("irrelevant opportunity should be inert: {error}"));
    assert_eq!(evaluation, BindingEvaluation::default());
    runtime
        .evaluate_boundary(coordinate(4), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("later global boundary should remain monotone: {error}"));
}

#[test]
fn hysteresis_clearing_respects_all_inclusive_boundaries() {
    let program = constant_program(
        SignalValue::U64(0),
        SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let cases = [
        (ThresholdComparison::LessThan, 10, 20, 19, 20),
        (ThresholdComparison::LessThanOrEqual, 10, 20, 20, 21),
        (ThresholdComparison::GreaterThan, 10, 5, 6, 5),
        (ThresholdComparison::GreaterThanOrEqual, 10, 5, 5, 4),
    ];
    for (comparison, threshold, clear, retained, cleared) in cases {
        let binding = threshold_binding(&program, comparison, threshold, Some(clear), 0);
        let mut state = BindingRuntimeState {
            active: true,
            ..BindingRuntimeState::default()
        };
        let retained_decision = map_binding(
            &binding,
            &[SignalValue::U64(retained)],
            &mut state,
            0,
            None,
            ContentHash::default(),
        )
        .unwrap_or_else(|error| panic!("retained decision failed: {error}"));
        assert_eq!(retained_decision, MappingDecision::NoAction);
        let cleared_decision = map_binding(
            &binding,
            &[SignalValue::U64(cleared)],
            &mut state,
            0,
            None,
            ContentHash::default(),
        )
        .unwrap_or_else(|error| panic!("clearing decision failed: {error}"));
        assert_eq!(cleared_decision, MappingDecision::Persistent(false));
    }
}

#[test]
fn threshold_residence_matures_only_at_the_declared_boundary() {
    let program = constant_program(
        SignalValue::U64(12),
        SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = threshold_binding(
        &program,
        ThresholdComparison::GreaterThanOrEqual,
        10,
        None,
        5,
    );
    let mut state = BindingRuntimeState::default();
    for now in [0, 4] {
        let decision = map_binding(
            &binding,
            &[SignalValue::U64(12)],
            &mut state,
            now,
            None,
            ContentHash::default(),
        )
        .unwrap_or_else(|error| panic!("residence decision failed: {error}"));
        assert_eq!(decision, MappingDecision::NoAction);
    }
    let decision = map_binding(
        &binding,
        &[SignalValue::U64(12)],
        &mut state,
        5,
        None,
        ContentHash::default(),
    )
    .unwrap_or_else(|error| panic!("mature decision failed: {error}"));
    assert_eq!(decision, MappingDecision::Persistent(true));
}

#[test]
fn fat_checkpoint_restore_matches_uninterrupted_continuation() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-checkpoint"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut uninterrupted = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));
    uninterrupted
        .evaluate_boundary(coordinate(0), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("activation failed: {error}"));
    let checkpoint = uninterrupted
        .checkpoint()
        .unwrap_or_else(|error| panic!("checkpoint failed: {error}"));
    assert!(matches!(
        FaultBindingRuntime::restore(
            &program,
            vec![binding.clone()],
            &NoArtifacts,
            ContentHash::from_bytes(b"different-seed"),
            FaultResourceLimits::default(),
            &checkpoint,
        ),
        Err(BindingRuntimeError::CheckpointIdentity)
    ));
    let mut tampered = checkpoint.clone();
    tampered
        .bindings
        .get_mut(&object_id("binding-checkpoint"))
        .unwrap_or_else(|| panic!("checkpoint must contain binding state"))
        .mapping_output = Some(ResolvedMappingOutput::Activation { active: false });
    assert!(matches!(
        FaultBindingRuntime::restore(
            &program,
            vec![binding.clone()],
            &NoArtifacts,
            ContentHash::from_bytes(b"seed"),
            FaultResourceLimits::default(),
            &tampered,
        ),
        Err(BindingRuntimeError::CheckpointState)
    ));
    let mut future = checkpoint.clone();
    future
        .bindings
        .get_mut(&object_id("binding-checkpoint"))
        .unwrap_or_else(|| panic!("checkpoint must contain binding state"))
        .last_sample_nanos = Some(u64::MAX);
    assert!(matches!(
        FaultBindingRuntime::restore(
            &program,
            vec![binding.clone()],
            &NoArtifacts,
            ContentHash::from_bytes(b"seed"),
            FaultResourceLimits::default(),
            &future,
        ),
        Err(BindingRuntimeError::CheckpointState)
    ));
    let mut restored = FaultBindingRuntime::restore(
        &program,
        vec![binding],
        &NoArtifacts,
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
        &checkpoint,
    )
    .unwrap_or_else(|error| panic!("restore failed: {error}"));

    let expected = uninterrupted
        .evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("uninterrupted continuation failed: {error}"));
    let actual = restored
        .evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default())
        .unwrap_or_else(|error| panic!("restored continuation failed: {error}"));
    assert_eq!(actual, expected);
    assert_eq!(restored.states(), uninterrupted.states());
    assert_eq!(restored.active(), uninterrupted.active());
}

#[test]
fn service_profile_identity_includes_named_physical_input_contracts() {
    let value = SignalValue::U64(42);
    let distance = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("physical-input-profile"),
        input_contracts: vec![ServiceProfileInput {
            role: object_id("distance"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Millimetres, 0)
                .unwrap_or_else(|error| panic!("distance shape: {error}")),
        }],
        inputs: vec![value.clone()],
    };
    let count = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("physical-input-profile"),
        input_contracts: vec![ServiceProfileInput {
            role: object_id("count"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("count shape: {error}")),
        }],
        inputs: vec![value],
    };
    let range = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("physical-input-profile"),
        input_contracts: vec![ServiceProfileInput {
            role: object_id("range"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Millimetres, 0)
                .unwrap_or_else(|error| panic!("range shape: {error}")),
        }],
        inputs: vec![SignalValue::U64(42)],
    };

    let distance_digest = resolved_mapping_output_digest(&distance, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("distance digest: {error}"));
    assert_ne!(
        distance_digest,
        resolved_mapping_output_digest(&count, FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("count digest: {error}")),
    );
    assert_ne!(
        distance_digest,
        resolved_mapping_output_digest(&range, FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("range digest: {error}")),
    );
}
