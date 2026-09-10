//! Representative traffic and host-I/O scenario for native whole-world forks.

use std::error::Error;
use std::sync::Arc;

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
    AssertionDef, AssertionId, NodeId, Plan, Properties, Property, ScenarioDefForm, Seed,
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
        Seed::from_u64(0xa70_1c),
        0,
    )?;

    Ok((source, artifacts))
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
