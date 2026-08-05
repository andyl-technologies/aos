use super::*;
use crate::model::Plan;

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
