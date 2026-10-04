//! Public production lifecycle discovery with a retained concurrent source.
//!
//! Scripted transports supply physical completions; the production lifecycle,
//! scheduler ownership, and campaign discovery paths execute unchanged.

use super::*;
use crucible::QuantumLoop;
use crucible_api::{
    LifecycleApiError, ProductionVmLifecycleConfig, ProductionVmNodeGeneration,
    ProductionVmNodeLaunch, ProductionVmNodeLaunchRequest, ProductionVmNodeLauncher,
    ProductionVmNodeLease, build_production_vm_lifecycle_loop_with_launcher,
};
use crucible_protocol::SelectableRegister;
use crucible_qemu::{
    QemuTestHotForkOutcome, QemuTestQuantumBoundary, scripted_hot_fork_source_with_script_for_test,
};
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ScriptedLease(ProductionVmNodeGeneration);

impl ProductionVmNodeLease for ScriptedLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.0
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        Err(LifecycleApiError::LoopFactory {
            message: String::from("scripted lease has no physical overlay"),
        })
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

struct HeldSourceLauncher {
    world: World,
}

impl ProductionVmNodeLauncher for HeldSourceLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        _qemu: &Path,
        _root: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        let build = || -> Result<_, Box<dyn std::error::Error>> {
            let plan = request.launch().selectable_catalog_plan().cloned();
            let (plan, pending) = if let Some(mut plan) = plan {
                let declaration = plan
                    .declarations()
                    .values()
                    .next()
                    .ok_or("declaration absent")?
                    .registration();
                let registration = SelectableRegister::new(
                    1,
                    declaration.selectable_id(),
                    declaration.domain().to_vec(),
                    declaration.default_value().to_vec(),
                    declaration.semantic_tags().to_vec(),
                )?;
                plan.apply_registration(&registration)?;
                plan.apply_freeze()?;
                let pending = SelectablePlanPendingRequest::new(
                    SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)?,
                    1,
                    50,
                    0,
                    0x1000,
                );
                (Some(plan), VecDeque::from([pending]))
            } else {
                (None, VecDeque::new())
            };
            let at = if plan.is_some() { 100 } else { 150 };
            let mut backend = scripted_hot_fork_source_with_script_for_test(
                QemuTestHotForkOutcome::Forked,
                Vec::new(),
                plan,
                pending,
                VecDeque::from([QemuTestQuantumBoundary::Paused {
                    at,
                    next_deadline: None,
                }]),
            )?;
            backend.bind_scripted_io_inventory_for_test(&self.world, request.node())?;
            let identity =
                ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
            Ok(ProductionVmNodeLaunch::new(
                request,
                backend,
                ScriptedLease(identity),
            )?)
        };
        build().map_err(|error| LifecycleApiError::LoopFactory {
            message: error.to_string(),
        })
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: crucible_api::ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(LifecycleApiError::LoopFactory {
            message: String::from("held-source fixture has no restore authority"),
        })
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(LifecycleApiError::LoopFactory {
            message: String::from("held-source fixture has no replay authority"),
        })
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

fn held_source_input() -> Result<CrucibleAttemptExecution, Box<dyn std::error::Error>> {
    let (input, source) = input_with_guest_selectable(StopCondition::NextChoice);
    let nodes = [source, node("router-b")]
        .into_iter()
        .map(|id| WorldNode {
            id,
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::from("held-source-test"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: 1,
            kernel: None,
            root_image: None,
            initrd: None,
        })
        .collect();
    let world = World::from_nodes(nodes)?;
    let selectables = ScenarioSelectables::new(
        &world,
        input.scenario().selectables().limits(),
        input
            .scenario()
            .selectables()
            .declarations()
            .values()
            .cloned()
            .collect(),
    )?;
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )?
    .with_selectables(selectables)?;
    Ok(input_for_scenario(source, StopCondition::NextChoice))
}

#[test]
fn committed_guest_source_is_discovered_before_global_peer_frontier() -> TestResult {
    let input = held_source_input()?;
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("root.img");
    std::fs::write(&root, b"scripted immutable root")?;
    let config = ProductionVmLifecycleConfig::new(
        "scripted-qemu",
        "scripted-plugin",
        "scripted-kernel",
        root,
        directory.path().join("runs"),
    )
    .with_run_ceiling_ticks(100_000)
    .with_quantum_budget(5_000)
    .with_maximum_host_workers(2);
    let mut owner = build_production_vm_lifecycle_loop_with_launcher(
        &input.scenario().scenario_def(),
        input.scenario(),
        &config,
        HeldSourceLauncher {
            world: input.scenario().world().clone(),
        },
    )?;
    let uncommitted = crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
        node("router-a"),
        SelectablePlanPendingRequest::new(
            SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)?,
            1,
            50,
            0,
            0x1000,
        ),
    );
    assert!(!owner.pending_selectable_request_is_committed_source(&uncommitted)?);

    let mut configuration = starting_configuration(&input);
    let mut outcome = QuantumLoop::drive_quantum(
        &mut owner,
        QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        },
    )?;
    configuration = outcome.configuration.clone();
    let pending = owner.drain_pending_selectable_requests()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0], uncommitted);
    assert_eq!(
        owner.pending_selectable_request_time(&pending[0])?,
        VirtualTime { ticks: 100 }
    );
    assert_eq!(outcome.frontier, VirtualTime { ticks: 0 });
    assert!(owner.pending_selectable_request_is_committed_source(&pending[0])?);

    let wrong_node = crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
        node("router-b"),
        pending[0].pending().clone(),
    );
    assert!(!owner.pending_selectable_request_is_committed_source(&wrong_node)?);
    for (sequence, trap_ps, address) in [(10, 50, 0x1000), (9, 50, 0x2000), (9, 5_000, 0x1000)] {
        let replaced = crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
            pending[0].node().clone(),
            SelectablePlanPendingRequest::new(
                SelectionRequest::new(sequence, "product.recovery", "routing-epoch-7", None, 256)?,
                1,
                trap_ps,
                0,
                address,
            ),
        );
        assert!(!owner.pending_selectable_request_is_committed_source(&replaced)?);
    }
    assert_eq!(owner.drain_pending_selectable_requests()?, pending);
    let expected_discovery = resolve_guest_selectable(
        input.lineage().scenario(),
        input.scenario(),
        pending[0].node(),
        pending[0].pending(),
    )?;

    let mut discoveries = RetainedChoiceDiscoveries::default();
    let result = {
        let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
        resolve_pending_guest_choices(
            &mut lifecycle,
            &input,
            &context(),
            &mut outcome,
            &mut discoveries,
        )
    };
    let blocked = QuantumLoop::drive_quantum(
        &mut owner,
        QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        },
    );
    QuantumLoop::shutdown(&mut owner)?;

    result.map_err(|error| format!("resolve original source: {error:?}"))?;
    let error = blocked
        .err()
        .ok_or("held source unexpectedly allowed another quantum")?;
    assert!(
        error
            .to_string()
            .contains("held physical RUNs must settle before queued network release")
    );
    assert_eq!(outcome.configuration, configuration);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 0 });
    assert_eq!(
        discoveries.discoveries.into_values().collect::<Vec<_>>(),
        vec![expected_discovery]
    );
    Ok(())
}
