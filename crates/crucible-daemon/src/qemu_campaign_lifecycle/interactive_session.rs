//! Fresh interactive native worlds on the original guarded campaign actor.
//!
//! Each session admits an independent complete Service before native startup.
//! The lifecycle retains that Service until its node and directory borrowers
//! close; an uncertain final cleanup preserves the original capacity charge.

use std::sync::Arc;

use crate::{ProductionVmLifecycleConfig, ProductionVmLifecycleLoop};
use crucible::{ScenarioDef, ScenarioDefForm};
use crucible_campaign::AttemptResourceLimits;
use crucible_linux_resource::host_supervision::HostOperationClass;
use thiserror::Error;

use super::{
    GuardedCampaignOwner, QemuAttemptProductionVmLifecycleError, QemuFreshScenarioResourceError,
    validate_fresh_qemu_scenario_resources,
};
use crate::{ExecutionCancellation, MAX_QEMU_ATTEMPT_GENERATION_NODES};

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
    /// A replay projection changes the admitted executable or plugin.
    #[error("interactive QEMU replay changes the admitted native identity")]
    NativeIdentityMismatch,
    /// Requested modeled limits exceed the original deployed semantic ceiling.
    #[error("interactive QEMU replay limits exceed the original admission")]
    ExecutionLimitsExceedAdmission,
    /// An active lifecycle projection could not retain its original credit.
    #[error("interactive QEMU lifecycle projection: {0}")]
    ConfigurationCopy(#[source] crate::vm_lifecycle::ProductionVmLifecycleConfigCloneError),
    /// The same Main retains the actual failed Service or Source construction.
    #[error("interactive QEMU preparation: {first}")]
    Prepared {
        /// Same-role report projecting its actual retained first cause.
        #[source]
        first: crate::lifecycle_cleanup::PreparedSourceFailure,
        /// Independent actual receiver return refusal, if that return refused.
        receiver_return: Option<crate::lifecycle_cleanup::PreparedSourceFailure>,
    },
    /// Configured or live owner authority is unavailable.
    #[error("interactive QEMU authority: {0}")]
    Authority(#[source] crucible_api::host_operational::HostOperationalError),
    /// The actual startup Original refused while the same Main kept custody.
    #[error("interactive QEMU supervision: {source}")]
    PreparedSupervision {
        /// Actual initiating Original refusal, independent of physical cleanup.
        #[source]
        source: crucible_linux_resource::host_supervision::HostSupervisionError,
        /// Original prepared role and retained native first cause.
        custody: crate::lifecycle_cleanup::PreparedSourceFailure,
        /// Independent actual receiver return refusal, if any.
        receiver_return: Option<crate::lifecycle_cleanup::PreparedSourceFailure>,
    },
    /// Native construction refused while its original Main retained the body.
    #[error("build interactive QEMU lifecycle: {source}")]
    PreparedLifecycle {
        /// Actual lifecycle refusal; uses the existing boxed report allocation.
        #[source]
        source: Box<QemuAttemptProductionVmLifecycleError>,
        /// Original prepared role, retained independently of the diagnostic.
        custody: crate::lifecycle_cleanup::PreparedSourceFailure,
        /// Independent actual receiver return refusal, if any.
        receiver_return: Option<crate::lifecycle_cleanup::PreparedSourceFailure>,
    },
    /// Native construction rejected the admitted source or retained cleanup.
    #[error("build interactive QEMU lifecycle: {0}")]
    Lifecycle(#[source] Box<QemuAttemptProductionVmLifecycleError>),
}

// The protected scope has an exhaustive error vocabulary. Receiver return
// cannot encounter an unrelated preflight error or discard either raw cause.
enum InteractivePreparationFailure {
    Prepared {
        first: crate::lifecycle_cleanup::PreparedSourceFailure,
    },
    PreparedSupervision {
        source: crucible_linux_resource::host_supervision::HostSupervisionError,
        custody: crate::lifecycle_cleanup::PreparedSourceFailure,
    },
    PreparedLifecycle {
        source: Box<QemuAttemptProductionVmLifecycleError>,
        custody: crate::lifecycle_cleanup::PreparedSourceFailure,
    },
}

impl InteractivePreparationFailure {
    fn into_session_error(
        self,
        receiver_return: Option<crate::lifecycle_cleanup::PreparedSourceFailure>,
    ) -> InteractiveQemuSessionError {
        match self {
            Self::Prepared { first } => InteractiveQemuSessionError::Prepared {
                first,
                receiver_return,
            },
            Self::PreparedSupervision { source, custody } => {
                InteractiveQemuSessionError::PreparedSupervision {
                    source,
                    custody,
                    receiver_return,
                }
            }
            Self::PreparedLifecycle { source, custody } => {
                InteractiveQemuSessionError::PreparedLifecycle {
                    source,
                    custody,
                    receiver_return,
                }
            }
        }
    }
}

// Metadata custody remains with the lifecycle. The actual Service stays in
// Main; no success-only external owner or Service observer is constructed.
struct InteractiveSessionCustody {
    _metadata: crucible::owned_decode::DecodeCustody,
}

impl GuardedCampaignOwner {
    /// Admits an interactive world with narrower modeled execution limits.
    ///
    /// The original actor, lifecycle configuration, physical Service ceiling,
    /// and operation roster are reused. Only the requested semantic bounds
    /// may narrow the deployment's accepted limits.
    ///
    /// # Errors
    /// Refuses limits exceeding the original admission or any source, resource,
    /// supervision, or native startup failure reported by the session builder.
    pub fn begin_interactive_session_with_limits(
        &self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<ProductionVmLifecycleLoop, InteractiveQemuSessionError> {
        let (lifecycle, _, _) =
            self.inner
                .config
                .guarded_inputs()
                .ok_or(InteractiveQemuSessionError::Authority(
                    crucible_api::host_operational::HostOperationalError::Unavailable,
                ))?;
        self.begin_interactive_session_with_lifecycle(
            scenario,
            source,
            cancellation,
            lifecycle,
            resources,
        )
    }

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
        let (lifecycle, _, resources) =
            self.inner
                .config
                .guarded_inputs()
                .ok_or(InteractiveQemuSessionError::Authority(
                    crucible_api::host_operational::HostOperationalError::Unavailable,
                ))?;
        self.begin_interactive_session_with_lifecycle(
            scenario,
            source,
            cancellation,
            lifecycle,
            resources,
        )
    }

    /// Admits an interactive replay projection under this owner's original account.
    ///
    /// The supplied lifecycle may change replay traces and quantum policy. Its
    /// executable and plugin must match admission; its paths and catalog provider
    /// are rebound to the original namespace before native construction. Modeled
    /// limits may only narrow the immutable deployment ceiling. The fresh Service
    /// retains the same actor, full physical vector and original operation roster.
    ///
    /// # Errors
    /// Refuses a changed native identity, wider modeled limits, unavailable
    /// original metadata or Service authority, expiry, or native startup failure.
    pub fn begin_interactive_session_with_lifecycle(
        &self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
        lifecycle: impl Into<Arc<ProductionVmLifecycleConfig>>,
        resources: AttemptResourceLimits,
    ) -> Result<ProductionVmLifecycleLoop, InteractiveQemuSessionError> {
        let decoding = crucible::owned_decode::DecodeBudget::for_store(
            self.repository_metadata_resources()
                .map_err(InteractiveQemuSessionError::Metadata)?,
        )
        .map_err(InteractiveQemuSessionError::Decoding)?;
        let _scope = decoding.enter();
        let (admitted, _, ceiling) =
            self.inner
                .config
                .guarded_inputs()
                .ok_or(InteractiveQemuSessionError::Authority(
                    crucible_api::host_operational::HostOperationalError::Unavailable,
                ))?;
        validate_interactive_limits(resources, ceiling)?;
        validate_interactive_source(scenario, source, resources)?;
        let lifecycle = lifecycle.into();
        if lifecycle.executable() != admitted.executable()
            || lifecycle.plugin() != admitted.plugin()
        {
            return Err(InteractiveQemuSessionError::NativeIdentityMismatch);
        }
        let provider = admitted.ram_catalog_provider().cloned().ok_or(
            InteractiveQemuSessionError::Authority(
                crucible_api::host_operational::HostOperationalError::Unavailable,
            ),
        )?;
        decoding
            .charge_array::<u8>(admitted.run_state_root().as_os_str().len())
            .map_err(InteractiveQemuSessionError::Decoding)?;
        let lifecycle_config = Arc::new(
            lifecycle
                .try_clone_admitted()
                .map_err(InteractiveQemuSessionError::ConfigurationCopy)?
                .with_run_state_root(admitted.run_state_root())
                .with_ram_catalog_provider(provider),
        );

        decoding
            .charge_array::<InteractiveSessionCustody>(1)
            .map_err(InteractiveQemuSessionError::Decoding)?;
        // A fresh lifecycle's first external owner uses at most the four-slot
        // minimum Vec capacity for boxed pointers in the pinned toolchain.
        decoding
            .charge_array::<Box<dyn Send>>(4)
            .map_err(InteractiveQemuSessionError::Decoding)?;

        let services = self
            .replay_services()
            .map_err(InteractiveQemuSessionError::Authority)?;
        let mut source_owner = self
            .prepare_service_source(lifecycle_config)
            .map_err(|error| InteractiveQemuSessionError::Lifecycle(Box::new(error)))?;
        source_owner
            .start("admit interactive Service", |phase| {
                services.start_for_interactive_session(phase, source, cancellation)
            })
            .map_err(|first| InteractiveQemuSessionError::Prepared {
                first,
                receiver_return: None,
            })?;
        let receiver = source_owner
            .retain_receiver("retain interactive startup receiver")
            .map_err(|first| InteractiveQemuSessionError::Prepared {
                first,
                receiver_return: None,
            })?;

        // Every local context/supervisor/Original alias is inside this scope.
        // Its Result cannot outlive these aliases on either success or failure.
        let result: Result<_, InteractivePreparationFailure> = (|| {
            let context = source_owner
                .with_ready("project interactive context", |service| {
                    service.context().clone().with_service_resources(resources)
                })
                .map_err(|first| InteractivePreparationFailure::Prepared { first })?;
            let supervisor = context.host_operation_supervisor().ok_or_else(|| {
                InteractivePreparationFailure::Prepared {
                    first: source_owner.failure("interactive supervision is absent"),
                }
            })?;
            let operation =
                supervisor
                    .begin(HostOperationClass::Preparation)
                    .map_err(|source| {
                        let (source, custody) = source_owner
                            .supervision_failure("enter interactive Preparation", source)
                            .into_parts();
                        InteractivePreparationFailure::PreparedSupervision { source, custody }
                    })?;
            operation.wait_slice().map_err(|source| {
                let (source, custody) = source_owner
                    .supervision_failure("check interactive Preparation", source)
                    .into_parts();
                InteractivePreparationFailure::PreparedSupervision { source, custody }
            })?;
            let lifecycle = source_owner
                .factory
                .begin_fresh(scenario, source, &context)
                .map_err(|error| InteractivePreparationFailure::PreparedLifecycle {
                    source: Box::new(error),
                    custody: source_owner.failure("build interactive World"),
                })?;
            let lifecycle = lifecycle.with_retained_resource_owner(InteractiveSessionCustody {
                _metadata: decoding.custody(),
            });
            operation.complete().map_err(|source| {
                let (source, custody) = source_owner
                    .supervision_failure("complete interactive Preparation", source)
                    .into_parts();
                InteractivePreparationFailure::PreparedSupervision { source, custody }
            })?;
            Ok(lifecycle)
        })();
        // This cut follows actual scope destruction, independently of ACKs or
        // World return. A refused counter return keeps its same lease in error.
        match receiver.return_after_alias_destruction() {
            Ok(()) => result.map_err(|first| first.into_session_error(None)),
            Err(receiver) => {
                let returned = receiver.into_failure("return interactive startup aliases");
                match result {
                    Ok(lifecycle) => {
                        drop(lifecycle);
                        Err(InteractiveQemuSessionError::Prepared {
                            first: returned,
                            receiver_return: None,
                        })
                    }
                    Err(first) => Err(first.into_session_error(Some(returned))),
                }
            }
        }
    }
}

fn validate_interactive_limits(
    requested: AttemptResourceLimits,
    ceiling: AttemptResourceLimits,
) -> Result<(), InteractiveQemuSessionError> {
    if requested.maximum_vcpus() > ceiling.maximum_vcpus()
        || requested.maximum_resident_bytes() > ceiling.maximum_resident_bytes()
        || requested.maximum_disk_bytes() > ceiling.maximum_disk_bytes()
        || requested.maximum_execution_quanta() > ceiling.maximum_execution_quanta()
    {
        return Err(InteractiveQemuSessionError::ExecutionLimitsExceedAdmission);
    }
    Ok(())
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

    #[test]
    fn replay_limits_refuse_each_dimension_above_original_admission() {
        let ceiling = test_value(AttemptResourceLimits::new(2, 2048, 4096, 16), "ceiling");
        let narrower = test_value(AttemptResourceLimits::new(1, 1024, 2048, 8), "narrower");
        assert!(validate_interactive_limits(narrower, ceiling).is_ok());
        assert!(validate_interactive_limits(ceiling, ceiling).is_ok());

        for values in [
            (3, 2048, 4096, 16),
            (2, 2049, 4096, 16),
            (2, 2048, 4097, 16),
            (2, 2048, 4096, 17),
        ] {
            let requested = test_value(
                AttemptResourceLimits::new(values.0, values.1, values.2, values.3),
                "wider requested limits",
            );
            assert!(matches!(
                validate_interactive_limits(requested, ceiling),
                Err(InteractiveQemuSessionError::ExecutionLimitsExceedAdmission)
            ));
        }
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
