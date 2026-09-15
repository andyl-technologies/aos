//! Tests deployment resource-capacity enforcement.

use super::*;

#[test]
fn guarded_campaign_route_uses_the_deployment_quanta_ceiling() {
    let insufficient = AttemptResourceLimits::new(1, 1, 1, PRODUCTION_CLI_QUANTUM_BUDGET - 1)
        .or_panic("nonzero limits");
    assert!(guarded_run_resources(insufficient, None).is_err());

    let sufficient = AttemptResourceLimits::new(
        2,
        1024 * 1024 * 1024,
        2 * 1024 * 1024 * 1024,
        PRODUCTION_CLI_QUANTUM_BUDGET,
    )
    .or_panic("guarded capacity");
    let resources = guarded_run_resources(sufficient, None).or_panic("default run resources");
    assert_eq!(
        resources.maximum_execution_quanta(),
        PRODUCTION_CLI_QUANTUM_BUDGET
    );

    let larger = AttemptResourceLimits::new(
        2,
        1024 * 1024 * 1024,
        2 * 1024 * 1024 * 1024,
        PRODUCTION_CLI_QUANTUM_BUDGET + 10,
    )
    .or_panic("larger guarded capacity");
    let resources = guarded_run_resources(larger, Some(PRODUCTION_CLI_QUANTUM_BUDGET + 10))
        .or_panic("requested run resources");
    assert_eq!(
        resources.maximum_execution_quanta(),
        PRODUCTION_CLI_QUANTUM_BUDGET + 10
    );
    assert!(guarded_run_resources(larger, Some(PRODUCTION_CLI_QUANTUM_BUDGET + 11)).is_err());
}
