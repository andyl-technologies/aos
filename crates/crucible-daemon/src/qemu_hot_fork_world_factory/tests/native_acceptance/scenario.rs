//! Representative traffic and host-I/O scenario for native whole-world forks.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;

use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementDefinitions,
    MeasurementId, MeasurementInstanceKey, MetricDefinition, MetricId, MetricSource,
    MetricValueType, UnitId, WorldNodeDef,
};
use crucible::model::{
    BindingEventParent, BindingMapping, BindingObservabilityPolicy, BindingSampling,
    BindingSearchPolicy, DagStore, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    EffectSpecification, FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits,
    FaultSignalPlan, NodeBootPolicy, NodeEffectSpecification, NodeLifecycleTransition,
    NodeStatePolicy, ResolvedFaultTarget, ResolvedTargetSet, SignalCoordinate, SignalDomain,
    SignalId, SignalNode, SignalNodeKind, SignalPoint, SignalResourceLimits, SignalShape,
    SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType, TargetSelector,
};
use crucible::{
    AssertionDef, AssertionId, MarkerId, NodeId, Plan, Properties, Property, ScenarioDefForm,
    ScenarioSelectableLimits, ScenarioSelectables, Seed, World,
};
use crucible_campaign::{
    ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue, ExactRational, IntegerDomain,
    IntegerRepresentation, IntegerValue, SelectableDeclaration,
};

const PERMANENT_FAILURE_NANOS: u64 = 30_000_000_000;

/// Builds the native acceptance scenario from the reviewed three-node fixture.
pub(super) fn build(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let base = ScenarioDefForm::from_canonical_toml(fixture)?;
    let world = base.world().clone();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-receives-http-200"),
                "Curl receives an HTTP 200 response",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-block-read-complete"),
                "Curl reads the block continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("io-probe-complete"),
                "The I/O probe reads the 9p continuation",
            ),
            AssertionDef {
                id: AssertionId::from_name("traffic-nodes-remain-running"),
                message: String::from("Nginx and Curl remain available"),
                property: Property::Always {
                    predicate: crucible::Predicate::not(crucible::Predicate::any_of(vec![
                        crucible::Predicate::node_state(
                            node_id("nginx"),
                            crucible::NodeLifecycle::Crashed,
                        ),
                        crucible::Predicate::node_state(
                            node_id("curl"),
                            crucible::NodeLifecycle::Crashed,
                        ),
                    ])),
                },
            },
        ],
    )?;
    let plan = Plan::empty().with_fault_signals_for_world(&world, permanent_failure_plan()?)?;
    let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0x000a_701c),
        0,
    )?;

    Ok((source, artifacts))
}

/// Builds the representative scenario with a pending typed choice and measurement window.
pub(super) fn build_equivalence(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let base = ScenarioDefForm::from_canonical_toml(fixture)?;
    let world = base.world().clone();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-receives-http-200"),
                "Curl receives an HTTP 200 response",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-block-read-complete"),
                "Curl reads the block continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("io-probe-complete"),
                "The I/O probe reads the 9p continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("hot-fork-continuation-complete"),
                "The selected continuation completes",
            ),
            AssertionDef {
                id: AssertionId::from_name("traffic-nodes-remain-running"),
                message: String::from("Nginx and Curl remain available"),
                property: Property::Always {
                    predicate: crucible::Predicate::not(crucible::Predicate::any_of(vec![
                        crucible::Predicate::node_state(
                            node_id("nginx"),
                            crucible::NodeLifecycle::Crashed,
                        ),
                        crucible::Predicate::node_state(
                            node_id("curl"),
                            crucible::NodeLifecycle::Crashed,
                        ),
                    ])),
                },
            },
        ],
    )?;
    let plan = Plan::empty().with_fault_signals_for_world(&world, permanent_failure_plan()?)?;
    let measurements = equivalence_measurements(&world, &plan, &properties)?;
    let selectables = equivalence_selectables(&world)?;
    let source = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(0x000a_701c),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

/// Builds a one-VM production fixture with both block and 9p continuations.
pub(super) fn build_single_node_equivalence(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let base = ScenarioDefForm::from_canonical_toml(fixture)?;
    let mut node = base
        .world()
        .vm_nodes()
        .iter()
        .find(|node| node.id.name == "curl")
        .cloned()
        .ok_or("representative fixture has no curl VM")?;
    node.cmdline = String::from("console=ttyS0 crucible.workload=hot-fork-single");
    let owner = node.id.clone();
    let mut nodes = vec![WorldNodeDef::Vm(node)];
    nodes.extend(base.world().io_nodes().cloned().map(|mut io| {
        io.owner = owner.clone();
        WorldNodeDef::Io(io)
    }));
    let world = World::from_node_defs_and_links(nodes, Vec::new())?;
    let plan = Plan::empty();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef::guest_sometimes(
            AssertionId::from_name("hot-fork-continuation-complete"),
            "The selected continuation completes",
        )],
    )?;
    let measurements = equivalence_measurements(&world, &plan, &properties)?;
    let selectables = equivalence_selectables(&world)?;
    let source = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(0x000a_701d),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

fn equivalence_measurements(
    world: &World,
    plan: &Plan,
    properties: &Properties,
) -> Result<MeasurementDefinitions, Box<dyn Error>> {
    Ok(MeasurementDefinitions::new(
        world,
        plan,
        properties,
        vec![MeasurementDefinition {
            id: MeasurementId::parse("hot-fork-window")?,
            begin: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("hot-fork-window-begin"),
                instance: Some(MeasurementInstanceKey::parse("instance-1")?),
            },
            end: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("hot-fork-window-end"),
                instance: Some(MeasurementInstanceKey::parse("instance-1")?),
            },
            timeout: None,
            cohort: CohortPolicy::All(vec![node_id("curl")]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("selected-retry")?,
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("samples")?,
                source: MetricSource::Guest,
                aggregation: Aggregation::Last,
            }],
        }],
    )?)
}

fn equivalence_selectables(world: &World) -> Result<ScenarioSelectables, Box<dyn Error>> {
    let retry_domain = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(1),
        IntegerValue::Unsigned(9),
        2,
        Some(String::from("quanta")),
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?);
    let declaration = SelectableDeclaration::new(
        "hot-fork.retry-quanta",
        ChoiceSource::Guest {
            node: String::from("curl"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        retry_domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(3)),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::from([String::from("hot-fork-equivalence")]),
        true,
    )?;
    Ok(ScenarioSelectables::new(
        world,
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?)
}

fn permanent_failure_plan() -> Result<FaultSignalPlan, Box<dyn Error>> {
    let signal = signal_id("permanent-failure")?;
    let schema = signal_id("permanent-failure-v1")?;
    let node = SignalNode {
        id: signal.clone(),
        domain: SignalDomain::Event,
        output: SignalShape::new(
            SignalValueType::Event(schema.clone()),
            SignalUnit::Dimensionless,
            0,
        )?,
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
            events: vec![SignalPoint {
                coordinate: SignalCoordinate::Event {
                    parent: Box::new(SignalCoordinate::VirtualTime {
                        nanos: PERMANENT_FAILURE_NANOS,
                    }),
                    sequence: 0,
                },
                sequence: 0,
                value: SignalValue::Event {
                    schema,
                    payload: b"permanent-failure".to_vec(),
                },
            }],
        }),
    };
    let program = crucible::model::SignalProgram::new(
        vec![node],
        vec![signal.clone()],
        SignalResourceLimits::default(),
    )?;
    let binding = FaultBinding::new(
        object_id("permanently-fail-io-probe")?,
        vec![signal],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::Node {
                node: object_id("io-probe")?,
            }],
            false,
        )?),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: NodeLifecycleTransition::PermanentFailure,
                downtime_nanos: 0,
                boot_policy: NodeBootPolicy::Immediate,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
        )?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &program,
    )?;

    Ok(FaultSignalPlan::new(
        vec![program],
        vec![binding],
        FaultResourceLimits::default(),
    )?)
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn signal_id(name: &str) -> Result<SignalId, Box<dyn Error>> {
    Ok(SignalId::parse(name)?)
}

fn object_id(name: &str) -> Result<FaultObjectId, Box<dyn Error>> {
    Ok(FaultObjectId::parse(name)?)
}
