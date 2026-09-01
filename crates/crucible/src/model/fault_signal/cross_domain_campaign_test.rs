//! Cross-domain fleet search, minimization, and ordinary locked-replay proof.

use std::collections::{BTreeMap, BTreeSet};

use super::test_support::*;
use super::*;
use crate::model::{
    Configuration, Decision, EngineError, FindingDiscoveryPath, FindingReproductionArtifact,
    MinimizationConfig, RngDecision, RngStreamId, Schedule, Seed,
};

const CAMPAIGN_COORDINATE: u64 = 10;
const EVIDENCE_PATH_ENV: &str = "CRUCIBLE_CROSS_DOMAIN_FLEET_EVIDENCE";

#[path = "cross_domain_campaign_test/fixture.rs"]
mod fixture;
use fixture::*;

#[test]
fn cross_domain_fleet_search_minimizes_and_locked_replays_without_explorer() {
    let plan = cross_domain_plan();
    let scenario = campaign_scenario();
    let base = Configuration {
        def: scenario.scenario_def(),
        schedule: Schedule::empty(),
    };
    let seed = ContentHash::from_bytes(b"cross-domain-fleet-campaign-seed");

    let mut discovery = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("cross-domain search discovery runtime: {error}"));
    let discovered = evaluate_campaign_boundary(&mut discovery)
        .unwrap_or_else(|error| panic!("cross-domain search discovery boundary: {error}"));
    let choice = discovered
        .search_choices
        .iter()
        .find(|choice| choice.candidate_count == 2)
        .unwrap_or_else(|| panic!("routed-network transition must expose two finite candidates"));
    let candidate_decisions = choice.override_decisions(base.id());
    assert_eq!(candidate_decisions.len(), 2);

    let mut failing_decisions = candidate_decisions
        .iter()
        .filter_map(|decision| {
            let schedule = Schedule::from_decisions([Decision::Override(decision.clone())]);
            campaign_failure_fingerprint(&plan, &schedule, seed)
                .unwrap_or_else(|error| panic!("cross-domain search candidate: {error}"))
                .map(|fingerprint| (decision.clone(), fingerprint))
        })
        .collect::<Vec<_>>();
    assert_eq!(failing_decisions.len(), 1);
    let (failing_decision, target_fingerprint) = failing_decisions
        .pop()
        .unwrap_or_else(|| panic!("one routed-network candidate must preserve the failure"));

    let original_schedule = Schedule::from_decisions([
        noise_override("fleet-search-guard-left"),
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fleet-search-noise"),
            value: 7,
        }),
        Decision::Override(failing_decision.clone()),
        noise_override("fleet-search-guard-right"),
    ]);
    let original_configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: original_schedule,
    };
    let original = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        target_fingerprint,
        &scenario,
        &original_configuration,
    )
    .unwrap_or_else(|error| panic!("cross-domain finding artifact: {error}"));
    let minimized = original
        .minimize(
            MinimizationConfig::new(Seed::from_u64(0x0014_f1ee7)),
            |candidate| {
                let _ = candidate.artifact.replay()?;
                campaign_failure_fingerprint(&plan, candidate.artifact.schedule(), seed)
            },
        )
        .unwrap_or_else(|error| panic!("cross-domain failure minimization: {error}"));

    assert!(minimized.shrank());
    assert_eq!(minimized.original.artifact.schedule().len(), 4);
    assert_eq!(minimized.minimized.artifact.schedule().len(), 1);
    assert_eq!(minimized.accepted_attempts(), 1);
    assert!(minimized.attempts.iter().any(|attempt| !attempt.accepted));
    assert_eq!(
        minimized.minimized.artifact.schedule().decisions(),
        &[Decision::Override(failing_decision)]
    );

    let artifacts = NoArtifacts;
    let minimized_overrides =
        search_overrides_from_schedule(minimized.minimized.artifact.schedule(), Some(base.id()))
            .unwrap_or_else(|error| panic!("decode minimized signal-fault override: {error}"));
    assert_eq!(minimized_overrides.len(), 1);
    let mut recorder = FaultExecutionRuntime::new_with_search_overrides(
        &plan,
        &artifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
        minimized_overrides.clone(),
    )
    .unwrap_or_else(|error| panic!("minimized cross-domain runtime: {error}"));
    let recorded = evaluate_campaign_boundary(&mut recorder)
        .unwrap_or_else(|error| panic!("minimized cross-domain boundary: {error}"));
    assert_campaign_actions(&recorded);
    recorder
        .verify_search_overrides_consumed()
        .unwrap_or_else(|error| panic!("minimized override consumption: {error}"));
    let trace = recorder
        .recorded_trace(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("cross-domain locked trace: {error}"));
    assert_eq!(trace.work_items.len(), 1);
    assert_eq!(trace.work_items[0].records.len(), expected_effects().len());
    let expected_work_items = trace.work_items.clone();

    // The minimized ordinary schedule selected the exact effect retained in
    // the locked trace. This fresh runtime receives only that trace: no
    // explorer, search override, or search callback runs during reproduction.
    let mut replay = FaultExecutionRuntime::new(
        &plan,
        &artifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("ordinary cross-domain replay runtime: {error}"));
    replay
        .install_replay(trace)
        .unwrap_or_else(|error| panic!("install cross-domain locked replay: {error}"));
    let replayed = evaluate_campaign_boundary(&mut replay)
        .unwrap_or_else(|error| panic!("ordinary cross-domain locked replay: {error}"));
    assert_campaign_actions(&replayed);
    replay
        .verify_replay_exhausted()
        .unwrap_or_else(|error| panic!("cross-domain replay exhaustion: {error}"));
    assert_eq!(
        replay
            .recorded_trace(FaultReplayMode::LockedEffect)
            .unwrap_or_else(|error| panic!("replayed cross-domain trace: {error}"))
            .work_items,
        expected_work_items
    );

    write_campaign_evidence(expected_work_items[0].records.len());
}

fn campaign_failure_fingerprint(
    plan: &FaultSignalPlan,
    schedule: &Schedule,
    seed: ContentHash,
) -> Result<Option<ContentHash>, EngineError> {
    let overrides = search_overrides_from_schedule(schedule, None)?;
    if overrides.is_empty() {
        return Ok(None);
    }
    let mut runtime = FaultExecutionRuntime::new_with_search_overrides(
        plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
        overrides,
    )
    .map_err(|error| campaign_error("construct candidate runtime", error))?;
    let evaluation = evaluate_campaign_boundary(&mut runtime)
        .map_err(|error| campaign_error("evaluate candidate boundary", error))?;
    runtime
        .verify_search_overrides_consumed()
        .map_err(|error| campaign_error("consume candidate override", error))?;
    if !is_campaign_failure(&evaluation) {
        return Ok(None);
    }

    let material = evaluation
        .actions
        .iter()
        .map(|action| format!("{}={}", action.effect.kind().as_str(), action.id().to_hex()))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Some(ContentHash::from_canonical_material(
        "crucible.cross-domain-fleet-failure.v1",
        &material,
    )))
}

fn evaluate_campaign_boundary(
    runtime: &mut FaultExecutionRuntime<'_>,
) -> Result<BindingEvaluation, FaultExecutionError> {
    let mut backend = CampaignBackend::default();
    runtime.evaluate_boundary_with_backend(campaign_coordinate(), 0, &mut backend)
}

fn search_overrides_from_schedule(
    schedule: &Schedule,
    expected_parent: Option<ContentHash>,
) -> Result<BTreeMap<SearchChoiceId, SearchOverride>, EngineError> {
    let mut overrides = BTreeMap::new();
    for decision in schedule.decisions() {
        let Decision::Override(decision) = decision else {
            continue;
        };
        if !decision.point.key.starts_with("signal-fault/") {
            continue;
        }
        let (id, search_override) = SearchOverride::from_override_decision(decision)
            .ok_or_else(|| campaign_error("decode signal-fault override", "malformed decision"))?;
        if expected_parent.is_some_and(|parent| search_override.parent_branch != Some(parent)) {
            return Err(campaign_error(
                "decode signal-fault override",
                "wrong parent configuration",
            ));
        }
        if overrides.insert(id, search_override).is_some() {
            return Err(campaign_error(
                "decode signal-fault override",
                "duplicate search choice",
            ));
        }
    }
    Ok(overrides)
}

fn is_campaign_failure(evaluation: &BindingEvaluation) -> bool {
    let effects = evaluation
        .actions
        .iter()
        .map(|action| action.effect.kind())
        .collect::<BTreeSet<_>>();
    let failure_route = object_id("routed-network-failure");
    effects == expected_effects()
        && evaluation.actions.iter().any(|action| {
            action.binding == object_id("interference-routed-network")
                && matches!(
                    action.mapping_output.as_ref(),
                    ResolvedMappingOutput::StateTransition {
                        selected_transition,
                        ..
                    } if selected_transition == &failure_route
                )
        })
}

fn assert_campaign_actions(evaluation: &BindingEvaluation) {
    assert!(is_campaign_failure(evaluation));
    assert_eq!(evaluation.actions.len(), expected_effects().len());
    assert_eq!(
        evaluation
            .actions
            .iter()
            .map(|action| action.target.kind())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            FaultTargetKind::NetworkPath,
            FaultTargetKind::NetworkContact,
            FaultTargetKind::BlockDevice,
            FaultTargetKind::Node,
            FaultTargetKind::MemoryRange,
            FaultTargetKind::Interrupt,
            FaultTargetKind::ClockSource,
        ])
    );
}

fn expected_effects() -> BTreeSet<EffectKind> {
    BTreeSet::from([
        EffectKind::NetworkRouteTransition,
        EffectKind::NetworkContact,
        EffectKind::StorageVolatileCacheLoss,
        EffectKind::CpuService,
        EffectKind::MemoryMutation,
        EffectKind::InterruptDisposition,
        EffectKind::ClockTransform,
    ])
}

fn cross_domain_plan() -> FaultSignalPlan {
    let schema = signal_id("fleet-physical-event");
    let shared_power = signal_id("shared-power");
    let vibration = signal_id("vibration");
    let movement = signal_id("movement");
    let interference = signal_id("interference");
    let satellite_contact = signal_id("satellite-contact");
    let program = SignalProgram::new(
        vec![
            event_node(&shared_power, &schema, 1),
            SignalNode {
                id: vibration.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                    .unwrap_or_else(|error| panic!("vibration shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            },
            event_node(&movement, &schema, 2),
            event_node(&interference, &schema, 3),
            event_node(&satellite_contact, &schema, 4),
        ],
        vec![
            shared_power.clone(),
            vibration.clone(),
            movement.clone(),
            interference.clone(),
            satellite_contact.clone(),
        ],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("cross-domain signal program: {error}"));

    assert_eq!(
        program
            .exported_outputs()
            .iter()
            .map(SignalId::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "shared-power",
            "vibration",
            "movement",
            "interference",
            "satellite-contact",
        ])
    );

    let route_table = object_id("routed-network-transition-table");
    let contact_table = object_id("satellite-contact-transition-table");
    let interrupt_table = object_id("interference-interrupt-transition-table");
    let route_failure = object_id("routed-network-failure");
    let registry = BindingMappingRegistry::new(
        vec![
            transition_declaration(
                route_table.clone(),
                &schema,
                EffectKind::NetworkRouteTransition,
                event_value(&schema, 3),
                route_failure,
                object_id("routed-network-degraded"),
            ),
            transition_declaration(
                contact_table.clone(),
                &schema,
                EffectKind::NetworkContact,
                event_value(&schema, 4),
                object_id("satellite-contact-acquired"),
                object_id("satellite-contact-unavailable"),
            ),
            transition_declaration(
                interrupt_table.clone(),
                &schema,
                EffectKind::InterruptDisposition,
                event_value(&schema, 3),
                object_id("interrupt-dropped"),
                object_id("interrupt-delivered"),
            ),
        ],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("cross-domain mapping registry: {error}"));

    let node = object_id("fleet-node-a");
    let clock = object_id("fleet-clock-tsc");
    let device = ContentHash::from_bytes(b"fleet-durable-block-device");
    let bindings = vec![
        transition_binding(
            "interference-routed-network",
            &interference,
            ResolvedFaultTarget::NetworkPath {
                path_version: object_id("routed-network-primary-path"),
                direction: FaultDirection::AToB,
            },
            FaultPhase::Boundary,
            EffectSpecification::Network(NetworkEffectSpecification::RouteTransition {
                old_route: object_id("routed-network-primary"),
                new_route: object_id("routed-network-failure"),
                convergence_events: object_id("routed-network-convergence"),
                in_flight_policy: NetworkInFlightPolicy::Reevaluate,
            }),
            route_table,
            BindingSearchPolicy::BranchTransition {
                candidates: vec![
                    object_id("routed-network-degraded"),
                    object_id("routed-network-failure"),
                ],
            },
            &program,
            &registry,
        ),
        transition_binding(
            "satellite-contact-availability",
            &satellite_contact,
            ResolvedFaultTarget::NetworkContact {
                plan: object_id("fleet-contact-plan"),
                endpoint_a: object_id("fleet-ground-station"),
                endpoint_b: object_id("fleet-satellite"),
                contact: object_id("fleet-contact-window"),
            },
            FaultPhase::Boundary,
            EffectSpecification::Network(NetworkEffectSpecification::Contact {
                intervals: object_id("fleet-contact-intervals"),
                range_delay_lookup: object_id("fleet-range-delay"),
                beams: object_set(["fleet-beam-a", "fleet-beam-b"]),
                gateways: object_set(["fleet-gateway-a"]),
            }),
            contact_table,
            BindingSearchPolicy::Fixed,
            &program,
            &registry,
        ),
        impulse_binding(
            "shared-power-storage-durability",
            &shared_power,
            ResolvedFaultTarget::BlockDevice { device },
            FaultPhase::Boundary,
            EffectSpecification::Storage(StorageEffectSpecification::VolatileCacheLoss {
                selector: StorageVolatileCacheLossSelector::All,
                loss: StorageVolatileCacheLossKind::PowerLoss,
            }),
            &program,
        ),
        persistent_binding(
            "vibration-cpu-service",
            &vibration,
            ResolvedFaultTarget::Node { node: node.clone() },
            FaultPhase::Run,
            EffectSpecification::Node(NodeEffectSpecification::CpuService {
                vcpus: vec![0, 1],
                capacity: ExactRatio::new(1, 2)
                    .unwrap_or_else(|error| panic!("CPU capacity: {error}")),
                quantum_instructions: PositiveU64::new("quantum_instructions", 64)
                    .unwrap_or_else(|error| panic!("CPU quantum: {error}")),
                service_rule: CpuServiceDiscipline::StrictCap,
            }),
            &program,
        ),
        impulse_binding(
            "movement-memory-mutation",
            &movement,
            ResolvedFaultTarget::MemoryRange {
                node: node.clone(),
                address_space: object_id("gpa"),
                guest_address: 0x1000,
                vcpu: None,
                length_bytes: 1,
            },
            FaultPhase::Boundary,
            EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
                address_space: MemoryAddressSpace::GuestPhysical,
                range: ByteRange::new(0x1000, 1)
                    .unwrap_or_else(|error| panic!("memory range: {error}")),
                mutation: MemoryMutationKind::BitFlip {
                    mask: HexBytes::parse("01", 1)
                        .unwrap_or_else(|error| panic!("memory mask: {error}")),
                },
                atomicity: MemoryMutationAtomicity::AllOrNothing,
            }),
            &program,
        ),
        transition_binding(
            "interference-interrupt-disposition",
            &interference,
            ResolvedFaultTarget::Interrupt {
                node: node.clone(),
                controller: object_id("fleet-apic"),
                source: object_id("fleet-network-irq"),
                target_vcpu: 0,
                vector: 81,
            },
            FaultPhase::Route,
            EffectSpecification::Node(NodeEffectSpecification::InterruptDisposition {
                mutation: InterruptMutation::Drop,
            }),
            interrupt_table,
            BindingSearchPolicy::Fixed,
            &program,
            &registry,
        ),
        impulse_binding(
            "shared-power-clock-transform",
            &shared_power,
            ResolvedFaultTarget::ClockSource {
                node,
                source: clock.clone(),
            },
            FaultPhase::ClockRead,
            EffectSpecification::Node(NodeEffectSpecification::ClockTransform {
                source: clock,
                mutation: ClockMutation::Offset {
                    offset_nanos: 1_000_000,
                },
                monotonicity: ClockMonotonicityPolicy::ClampMonotonic,
                overdue_timer_policy: ClockOverdueTimerPolicy::FireAtBoundary,
            }),
            &program,
        ),
    ];
    FaultSignalPlan::new(vec![program], bindings, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("cross-domain fleet plan: {error}"))
}

fn event_node(id: &SignalId, schema: &SignalId, payload: u8) -> SignalNode {
    SignalNode {
        id: id.clone(),
        domain: SignalDomain::Event,
        output: SignalShape::new(
            SignalValueType::Event(schema.clone()),
            SignalUnit::Dimensionless,
            0,
        )
        .unwrap_or_else(|error| panic!("fleet event shape: {error}")),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
            events: vec![SignalPoint {
                coordinate: SignalCoordinate::Event {
                    parent: Box::new(SignalCoordinate::VirtualTime {
                        nanos: CAMPAIGN_COORDINATE,
                    }),
                    sequence: 0,
                },
                sequence: 0,
                value: event_value(schema, payload),
            }],
        }),
    }
}

fn event_value(schema: &SignalId, payload: u8) -> SignalValue {
    SignalValue::Event {
        schema: schema.clone(),
        payload: vec![payload],
    }
}

fn transition_declaration(
    id: FaultObjectId,
    schema: &SignalId,
    effect: EffectKind,
    request: SignalValue,
    transition: FaultObjectId,
    default_transition: FaultObjectId,
) -> StateTransitionTableDeclaration {
    StateTransitionTableDeclaration {
        id,
        semantic_version: 1,
        input: SignalValueType::Event(schema.clone()),
        effect,
        transitions: [(request, transition)].into_iter().collect(),
        default_transition,
    }
}
