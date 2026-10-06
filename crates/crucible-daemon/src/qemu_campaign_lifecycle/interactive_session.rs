//! Fresh interactive native worlds on the original guarded campaign actor.
//!
//! Each session admits an independent complete Service before native startup.
//! The lifecycle retains that Service until its node and directory borrowers
//! close; an uncertain final cleanup preserves the original capacity charge.

use crucible::{ScenarioDef, ScenarioDefForm};
use crucible_api::ProductionVmLifecycleLoop;
use crucible_campaign::AttemptResourceLimits;
use crucible_linux_resource::host_supervision::HostOperationClass;
use thiserror::Error;

use super::{
    GuardedCampaignOwner, QemuAttemptProductionVmLifecycleError,
    QemuAttemptProductionVmLifecycleFactory, QemuFreshScenarioResourceError,
    validate_fresh_qemu_scenario_resources,
};
use crate::{
    ComposedQemuAttemptResourceGuardFactory, ExecutionCancellation,
    MAX_QEMU_ATTEMPT_GENERATION_NODES,
};

/// Refusal to admit a fresh interactive native session on its original owner.
#[derive(Debug, Error)]
pub enum InteractiveQemuSessionError {
    /// The serialized source reconstructs another scenario.
    #[error("interactive QEMU scenario form does not match the supplied scenario")]
    ScenarioIdentityMismatch,
    /// The world cannot fit within one generation owner.
    #[error("interactive QEMU node count {0} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}")]
    InvalidNodeCount(usize),
    /// The accepted semantic limits cannot launch the complete world.
    #[error("interactive QEMU scenario resources: {0}")]
    ScenarioResources(#[source] QemuFreshScenarioResourceError),
    /// The original storage owner could not lend metadata capacity.
    #[error("interactive QEMU metadata resources: {0}")]
    Metadata(#[source] crucible_cas::content_store::StoreError),
    /// A model copy could not retain its original metadata credit.
    #[error("interactive QEMU model admission: {0}")]
    Decoding(#[source] crucible::owned_decode::DecodeAdmissionError),
    /// The original actor refused independent complete Service admission.
    #[error("interactive QEMU Service admission: {0}")]
    Admission(#[source] Box<crate::PackagedQemuExecutorError>),
    /// Configured or live owner authority is unavailable.
    #[error("interactive QEMU authority: {0}")]
    Authority(#[source] crucible_api::host_operational::HostOperationalError),
    /// The original startup operation expired or was canceled.
    #[error("interactive QEMU supervision: {0}")]
    Supervision(#[source] crucible_linux_resource::host_supervision::HostSupervisionError),
    /// Native construction rejected the admitted source or retained cleanup.
    #[error("build interactive QEMU lifecycle: {0}")]
    Lifecycle(#[source] Box<QemuAttemptProductionVmLifecycleError>),
}

// The final field retains both model copies and the structural admission loan
// until the Service has checked its original native cleanup ledger.
struct InteractiveSessionCustody {
    _service: crate::packaged_qemu_executor::RetainedTemplateService,
    _metadata: crucible::owned_decode::DecodeCustody,
}

impl GuardedCampaignOwner {
    /// Admits a fresh interactive native world on this owner's original actor.
    ///
    /// The deployment's semantic limits and complete physical Service ceiling
    /// remain distinct. Each invocation reserves a fresh Service with the
    /// authored operation roster and original cancellation authority. The
    /// returned lifecycle retains that Service after its native borrowers; a
    /// failed reap, source join or final close conservatively retains capacity.
    /// No campaign execution row or process-local execution identity is invented.
    ///
    /// # Errors
    /// Refuses a mismatched source, insufficient semantic or complete physical
    /// capacity, unavailable storage credit, original expiry/cancellation, or
    /// failed native startup. Uncertain startup cleanup remains charged.
    pub fn begin_interactive_session(
        &self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Result<ProductionVmLifecycleLoop, InteractiveQemuSessionError> {
        let decoding = crucible::owned_decode::DecodeBudget::for_store(
            self.repository_metadata_resources()
                .map_err(InteractiveQemuSessionError::Metadata)?,
        )
        .map_err(InteractiveQemuSessionError::Decoding)?;
        let _scope = decoding.enter();
        let resources =
            self.inner
                .config
                .assignment_limits()
                .ok_or(InteractiveQemuSessionError::Authority(
                    crucible_api::host_operational::HostOperationalError::Unavailable,
                ))?;
        validate_interactive_source(scenario, source, resources)?;

        decoding
            .charge_array::<InteractiveSessionCustody>(1)
            .map_err(InteractiveQemuSessionError::Decoding)?;
        // A fresh lifecycle's first external owner uses at most the four-slot
        // minimum Vec capacity for boxed pointers in the pinned toolchain.
        decoding
            .charge_array::<Box<dyn Send>>(4)
            .map_err(InteractiveQemuSessionError::Decoding)?;

        let service = self
            .replay_services()
            .map_err(InteractiveQemuSessionError::Authority)?
            .start_for_interactive_session(source, cancellation)
            .map_err(|error| InteractiveQemuSessionError::Admission(Box::new(error)))?;
        // Projection copies modeled limits only. The genuine fresh Service's
        // original host cap, allocator, watchdog and full vector remain intact.
        let context = service.context().clone().with_service_resources(resources);
        let operation = context
            .host_operation_supervisor()
            .ok_or(InteractiveQemuSessionError::Authority(
                crucible_api::host_operational::HostOperationalError::Unavailable,
            ))?
            .begin(HostOperationClass::Preparation)
            .map_err(InteractiveQemuSessionError::Supervision)?;
        operation
            .wait_slice()
            .map_err(InteractiveQemuSessionError::Supervision)?;
        let lifecycle_config = self.inner.config.guarded_inputs().ok_or(
            InteractiveQemuSessionError::Authority(
                crucible_api::host_operational::HostOperationalError::Unavailable,
            ),
        )?.0;
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            lifecycle_config,
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        );
        let lifecycle = factory
            .begin_fresh(scenario, source, &context)
            .map_err(|error| InteractiveQemuSessionError::Lifecycle(Box::new(error)))?;
        // Install custody before another fallible boundary can drop the world.
        let lifecycle = lifecycle.with_retained_resource_owner(InteractiveSessionCustody {
            _service: service,
            _metadata: decoding.custody(),
        });
        operation
            .complete()
            .map_err(InteractiveQemuSessionError::Supervision)?;
        Ok(lifecycle)
    }
}

fn validate_interactive_source(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    resources: AttemptResourceLimits,
) -> Result<(), InteractiveQemuSessionError> {
    if source.scenario_def() != *scenario {
        return Err(InteractiveQemuSessionError::ScenarioIdentityMismatch);
    }
    let node_count = source.world().vm_nodes().len();
    if node_count == 0 || node_count > MAX_QEMU_ATTEMPT_GENERATION_NODES {
        return Err(InteractiveQemuSessionError::InvalidNodeCount(node_count));
    }
    validate_fresh_qemu_scenario_resources(source, resources)
        .map_err(InteractiveQemuSessionError::ScenarioResources)
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use crucible::{
        Icount, NodeId, NodeTemplate, Plan, Properties, ReadyPoint, Seed, WhiteBoxPolicy, World,
        WorldNode,
    };

    use super::*;

    #[test]
    fn wrong_scenario_identity_refuses_session_admission() {
        let source = scenario_form();
        let wrong_scenario = ScenarioDef::from_canonical_material(
            "crucible.test.interactive.wrong-scenario",
            "identity=wrong",
        );

        let result = validate_interactive_source(&wrong_scenario, &source, sufficient_resources());
        let Err(error) = result else {
            panic!("mismatched identity must fail immutable admission");
        };

        assert!(matches!(
            error,
            InteractiveQemuSessionError::ScenarioIdentityMismatch
        ));
    }

    #[test]
    fn insufficient_semantic_resources_refuse_session_admission() {
        let source = scenario_form();
        let scenario = source.scenario_def();
        let resources = test_value(
            AttemptResourceLimits::new(1, 1, 0, 1),
            "nonzero semantic resource limits",
        );

        let result = validate_interactive_source(&scenario, &source, resources);
        let Err(error) = result else {
            panic!("insufficient resources must fail immutable admission");
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
