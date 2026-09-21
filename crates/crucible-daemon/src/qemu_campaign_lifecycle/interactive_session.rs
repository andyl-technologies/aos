//! Guarded fresh production-QEMU sessions for interactive execution.
//!
//! Interactive replay owns the returned production lifecycle directly. This
//! constructor performs all immutable source and resource admission before it
//! opens the Linux process and storage allocator, then transfers the composed
//! attempt guard into the lifecycle node launcher.

use crucible::{ScenarioDef, ScenarioDefForm};
use crucible_api::{ProductionVmLifecycleConfig, ProductionVmLifecycleLoop};
use crucible_campaign::{AttemptResourceLimits, ExecutionRetentionIntent};
use crucible_qemu::{LinuxQemuAttemptHostConfig, QemuVmRealizationError};
use thiserror::Error;

use super::{
    QemuAttemptProductionVmLifecycleError, QemuAttemptProductionVmLifecycleFactory,
    QemuFreshScenarioResourceError, validate_fresh_qemu_scenario_resources,
};
use crate::{
    AttemptExecutionContext, ComposedQemuAttemptResourceGuardFactory, ExecutionCancellation,
    ExecutionCheckpointRequest, LinuxQemuAttemptHostResourceFactory,
    MAX_QEMU_ATTEMPT_GENERATION_NODES,
};

/// Failure to construct a guarded fresh production-QEMU interactive session.
#[derive(Debug, Error)]
pub enum InteractiveQemuSessionError {
    /// The serialized scenario form reconstructs a different semantic identity.
    #[error("interactive QEMU scenario form does not match the supplied scenario")]
    ScenarioIdentityMismatch,
    /// The scenario cannot fit within one attempt generation owner.
    #[error(
        "interactive QEMU scenario node count {0} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
    )]
    InvalidNodeCount(usize),
    /// The admitted aggregate resources cannot launch the complete fresh world.
    #[error("interactive QEMU scenario resources are invalid: {0}")]
    ScenarioResources(#[source] QemuFreshScenarioResourceError),
    /// The exact Linux process and storage allocator could not be opened.
    #[error("open interactive QEMU host resources: {0}")]
    Host(#[source] QemuVmRealizationError),
    /// The guarded production lifecycle rejected construction.
    #[error("build interactive QEMU lifecycle: {0}")]
    Lifecycle(#[source] QemuAttemptProductionVmLifecycleError),
}

/// Builds one fresh production-QEMU lifecycle for an interactive session.
///
/// Source identity, node cardinality, and the world's fixed aggregate launch
/// baseline are checked before Linux host resources are opened. The returned
/// lifecycle owns the composed process, writable-storage, cancellation, and
/// scheduler-quantum guards and must be shut down by its interactive owner.
///
/// # Errors
///
/// Returns [`InteractiveQemuSessionError`] when the scenario identity or fixed
/// resource baseline is invalid, the Linux host allocator cannot be opened, or
/// the guarded production lifecycle cannot be constructed.
pub fn build_guarded_interactive_qemu_session(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    lifecycle_config: ProductionVmLifecycleConfig,
    host_config: LinuxQemuAttemptHostConfig,
    resources: AttemptResourceLimits,
) -> Result<ProductionVmLifecycleLoop, InteractiveQemuSessionError> {
    validate_source(scenario, source)?;
    validate_fresh_qemu_scenario_resources(source, resources)
        .map_err(InteractiveQemuSessionError::ScenarioResources)?;

    let host = LinuxQemuAttemptHostResourceFactory::open(host_config)
        .map_err(InteractiveQemuSessionError::Host)?;
    let resource_guards = ComposedQemuAttemptResourceGuardFactory::new(host);
    let context = AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    );
    let mut factory =
        QemuAttemptProductionVmLifecycleFactory::new(lifecycle_config, resource_guards);

    factory
        .begin_fresh(scenario, source, &context)
        .map_err(InteractiveQemuSessionError::Lifecycle)
}

fn validate_source(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
) -> Result<(), InteractiveQemuSessionError> {
    if source.scenario_def() != *scenario {
        return Err(InteractiveQemuSessionError::ScenarioIdentityMismatch);
    }

    let node_count = source.world().vm_nodes().len();
    if node_count == 0 || node_count > MAX_QEMU_ATTEMPT_GENERATION_NODES {
        return Err(InteractiveQemuSessionError::InvalidNodeCount(node_count));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use std::time::Duration;

    use crucible::{
        Icount, NodeId, NodeTemplate, Plan, Properties, ReadyPoint, Seed, WhiteBoxPolicy, World,
        WorldNode,
    };

    use super::*;

    #[test]
    fn wrong_scenario_identity_fails_before_host_open() {
        let source = scenario_form();
        let wrong_scenario = ScenarioDef::from_canonical_material(
            "crucible.test.interactive.wrong-scenario",
            "identity=wrong",
        );

        let result = build_guarded_interactive_qemu_session(
            &wrong_scenario,
            &source,
            lifecycle_config(),
            unopened_host_config(),
            sufficient_resources(),
        );
        let Err(error) = result else {
            panic!("mismatched identity must fail before opening the nonexistent host roots");
        };

        assert!(matches!(
            error,
            InteractiveQemuSessionError::ScenarioIdentityMismatch
        ));
    }

    #[test]
    fn insufficient_resources_fail_before_host_open() {
        let source = scenario_form();
        let scenario = source.scenario_def();
        let resources = test_value(
            AttemptResourceLimits::new(1, 1, 0, 1),
            "nonzero semantic resource limits",
        );

        let result = build_guarded_interactive_qemu_session(
            &scenario,
            &source,
            lifecycle_config(),
            unopened_host_config(),
            resources,
        );
        let Err(error) = result else {
            panic!("insufficient resources must fail before opening the nonexistent host roots");
        };

        assert!(matches!(
            error,
            InteractiveQemuSessionError::ScenarioResources(
                QemuFreshScenarioResourceError::Capacity {
                    field: "resident bytes",
                    ..
                }
            )
        ));
    }

    fn scenario_form() -> ScenarioDefForm {
        let world = World::from_nodes(vec![WorldNode {
            id: NodeId {
                name: String::from("interactive-node"),
            },
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::from("interactive-session-test"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let world = test_value(world, "interactive test world");

        test_value(
            ScenarioDefForm::from_components(
                &world,
                &Plan::empty(),
                &Properties::empty(),
                Seed::from_u64(0x696e_7465_7261_6374),
            ),
            "interactive test scenario",
        )
    }

    fn lifecycle_config() -> ProductionVmLifecycleConfig {
        ProductionVmLifecycleConfig::new(
            "unopened-qemu",
            "unopened-plugin",
            "unopened-kernel",
            "unopened-root-image",
            "unopened-run-state",
        )
    }

    fn unopened_host_config() -> LinuxQemuAttemptHostConfig {
        test_value(
            LinuxQemuAttemptHostConfig::new(
                "/does-not-exist/interactive-cgroup",
                "/does-not-exist/interactive-runs",
                "interactive-session-test",
                1,
                1,
                65_527,
                65_527,
                16,
                1_024,
                Duration::from_secs(1),
            ),
            "syntactically valid unopened host configuration",
        )
    }

    fn sufficient_resources() -> AttemptResourceLimits {
        test_value(
            AttemptResourceLimits::new(1, 512 * 1024 * 1024, 1024 * 1024 * 1024, 16),
            "sufficient interactive resources",
        )
    }

    fn test_value<T, E>(result: Result<T, E>, context: &str) -> T
    where
        E: Display,
    {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }
}
