//! Ordered branch-configuration validation for lifecycle construction.

use super::*;

pub(super) fn configured_branches(
    config: &ProductionVmLifecycleConfig,
) -> impl Iterator<Item = &ProductionVmBranchConfig> {
    config
        .branch
        .iter()
        .chain(config.continuation_branches.iter())
}

pub(super) fn first_configured_branch(
    config: &ProductionVmLifecycleConfig,
) -> Option<&ProductionVmBranchConfig> {
    configured_branches(config).next()
}

pub(in crate::vm_lifecycle) fn validate_configured_branch_sequence(
    scenario: &ScenarioDef,
    branches: &[ProductionVmBranchConfig],
) -> Result<(), LifecycleApiError> {
    if branches
        .iter()
        .any(|branch| branch.base.def.id() != scenario.id())
    {
        return Err(loop_factory_error(
            "production branch sequence names a different scenario",
        ));
    }
    for pair in branches.windows(2) {
        let [previous, next] = pair else {
            continue;
        };
        if next.frontier < previous.frontier {
            return Err(loop_factory_error(
                "production branch sequence moves backward in virtual time",
            ));
        }
        let previous_prefix = next
            .base
            .schedule
            .prefix(previous.base.schedule.len())
            .map_err(|_| {
                loop_factory_error(
                    "production branch sequence moves backward in configuration history",
                )
            })?;
        if previous_prefix != previous.base.schedule {
            return Err(loop_factory_error(
                "production branch sequence has divergent configuration history",
            ));
        }
    }
    Ok(())
}
