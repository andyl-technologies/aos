//! Live patched-QEMU execution of the closed hardware variant matrix.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use crucible::NodeId;
use crucible::model::{
    BindingRuntimeError, ContentHash, FaultCoordinate, FaultExecutionError, FaultObservationKind,
    HostFaultAdapterManifests, SignalBoundarySnapshot,
};
use crucible_qemu::{
    ProductionFaultRuntime, ProductionFaultRuntimeError, QemuLiveNodeStepGateConfig, QemuNodeSet,
    launch_qemu_live_node,
};

use super::matrix_plan::{
    HardwareVariantCase, hardware_variant_case_plan, hardware_variant_cases,
    unsupported_clock_read_error_plan,
};
use super::support::error_chain;

/// Applies every closed clock and accelerator state variant to live QEMU.
pub(super) fn run_hardware_variant_matrix(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: &Path,
) -> Result<Vec<&'static str>, String> {
    fs::create_dir_all(run_directory)
        .map_err(|error| format!("create hardware matrix run directory: {error}"))?;

    let mut completed = Vec::with_capacity(hardware_variant_cases().len());
    for case in hardware_variant_cases() {
        eprintln!("hardware variant start: {}", case.name);
        run_hardware_variant_case(config, run_directory, *case)?;
        completed.push(case.name);
        eprintln!("hardware variant complete: {}", case.name);
    }
    run_hardware_rejection_control(config, run_directory)?;
    Ok(completed)
}

fn run_hardware_rejection_control(
    config: &QemuLiveNodeStepGateConfig,
    matrix_directory: &Path,
) -> Result<(), String> {
    let name = "clock-source-unsupported-read-error";
    let case_directory = matrix_directory.join(name);
    fs::create_dir_all(&case_directory)
        .map_err(|error| format!("create `{name}` run directory: {error}"))?;
    let matrix_config = config.clone().with_run_directory(&case_directory);
    let node_id = NodeId {
        name: String::from("fault-hardware-matrix-node"),
    };
    let mut node = launch_qemu_live_node(
        &matrix_config,
        &case_directory,
        &node_id.name,
        "fault-hardware-matrix-router",
        "fault-hardware-matrix-crash-detector",
    )
    .map_err(|error| error_chain(&error))?;
    let initial_icount = node
        .current_icount()
        .map_err(|error| format!("read `{name}` QEMU coordinate: {error}"))?
        .retired;
    let mut nodes = QemuNodeSet::new();
    if nodes.insert(node_id.clone(), node).is_some() {
        return Err(String::from("hardware rejection node identity collided"));
    }

    let result = evaluate_hardware_rejection_control(initial_icount, &mut nodes);
    let mut node = nodes
        .take(&node_id)
        .ok_or_else(|| String::from("hardware rejection QEMU node disappeared"))?;
    let shutdown = node
        .shutdown_child()
        .map_err(|error| format!("shut down `{name}` QEMU: {error}"))?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(format!("`{name}` QEMU child was not reaped"));
    }
    result
}

fn evaluate_hardware_rejection_control(
    initial_icount: u64,
    nodes: &mut QemuNodeSet,
) -> Result<(), String> {
    let plan = unsupported_clock_read_error_plan()?;
    let store: Arc<dyn crucible::model::DagStore> =
        Arc::new(crucible::model::MemoryDagStore::new());
    let artifacts: Arc<dyn crucible::model::SignalArtifactProvider> =
        Arc::new(crucible::model::OwnedDagSignalArtifactProvider::new(store));
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        Some(artifacts),
        SignalBoundarySnapshot::default(),
        ContentHash::from_canonical_material(
            "crucible.live-fault-hardware.rejection.v1",
            "clock-source-unsupported-read-error",
        ),
        HostFaultAdapterManifests::node_only()
            .map_err(|error| format!("build rejection node fault manifests: {error}"))?,
        nodes,
    )
    .map_err(|error| format!("admit hardware rejection control: {error}"))?;
    let rejected = match runtime.evaluate_boundary(
        FaultCoordinate {
            virtual_nanos: 1,
            retired_instructions: Some(initial_icount),
        },
        0,
        nodes,
    ) {
        Err(ProductionFaultRuntimeError::Execution(FaultExecutionError::Binding(
            BindingRuntimeError::AdapterRejected(rejected),
        ))) => rejected,
        Err(error) => {
            return Err(format!(
                "unsupported APIC read-error returned `{error}` instead of an authenticated adapter rejection"
            ));
        }
        Ok(_) => {
            return Err(String::from(
                "unsupported APIC read-error transition was unexpectedly committed",
            ));
        }
    };
    if rejected.observations.len() != 1
        || rejected.observations[0].kind != FaultObservationKind::EffectRejected
        || rejected.observations[0].evidence == ContentHash::default()
    {
        return Err(String::from(
            "unsupported APIC read-error omitted exact rejection evidence",
        ));
    }
    Ok(())
}

fn run_hardware_variant_case(
    config: &QemuLiveNodeStepGateConfig,
    matrix_directory: &Path,
    case: HardwareVariantCase,
) -> Result<(), String> {
    let case_directory = matrix_directory.join(case.name);
    fs::create_dir_all(&case_directory)
        .map_err(|error| format!("create `{}` run directory: {error}", case.name))?;
    let matrix_config = config.clone().with_run_directory(&case_directory);
    let node_id = NodeId {
        name: String::from("fault-hardware-matrix-node"),
    };
    let mut node = launch_qemu_live_node(
        &matrix_config,
        &case_directory,
        &node_id.name,
        "fault-hardware-matrix-router",
        "fault-hardware-matrix-crash-detector",
    )
    .map_err(|error| error_chain(&error))?;
    let initial_icount = node
        .current_icount()
        .map_err(|error| format!("read `{}` QEMU coordinate: {error}", case.name))?
        .retired;
    let mut nodes = QemuNodeSet::new();
    if nodes.insert(node_id.clone(), node).is_some() {
        return Err(String::from("hardware matrix node identity collided"));
    }

    let result = evaluate_hardware_variant_case(case, initial_icount, &mut nodes);
    let mut node = nodes
        .take(&node_id)
        .ok_or_else(|| String::from("hardware matrix QEMU node disappeared"))?;
    let shutdown = node
        .shutdown_child()
        .map_err(|error| format!("shut down `{}` QEMU: {error}", case.name))?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(format!("`{}` QEMU child was not reaped", case.name));
    }
    result
}

fn evaluate_hardware_variant_case(
    case: HardwareVariantCase,
    initial_icount: u64,
    nodes: &mut QemuNodeSet,
) -> Result<(), String> {
    let plan = hardware_variant_case_plan(case)?;
    let store: Arc<dyn crucible::model::DagStore> =
        Arc::new(crucible::model::MemoryDagStore::new());
    let artifacts: Arc<dyn crucible::model::SignalArtifactProvider> =
        Arc::new(crucible::model::OwnedDagSignalArtifactProvider::new(store));
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        Some(artifacts),
        SignalBoundarySnapshot::default(),
        ContentHash::from_canonical_material("crucible.live-fault-hardware.matrix.v1", case.name),
        HostFaultAdapterManifests::node_only()
            .map_err(|error| format!("build matrix node fault manifests: {error}"))?,
        nodes,
    )
    .map_err(|error| format!("admit hardware variant `{}`: {error}", case.name))?;
    let evaluation = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: case.coordinate,
                retired_instructions: Some(initial_icount),
            },
            0,
            nodes,
        )
        .map_err(|error| format!("apply hardware variant `{}`: {error}", case.name))?;
    let expected_binding = case.binding;
    if evaluation.actions.len() != 1 || evaluation.actions[0].binding.as_str() != expected_binding {
        let actual = evaluation
            .actions
            .iter()
            .map(|action| action.binding.as_str())
            .collect::<Vec<_>>();
        return Err(format!(
            "hardware variant `{}` produced action bindings {actual:?} instead of exactly `{expected_binding}`",
            case.name
        ));
    }
    if evaluation.observations.iter().any(|observation| {
        observation.kind == FaultObservationKind::EffectRejected
            && observation
                .binding
                .as_ref()
                .is_some_and(|binding| binding.as_str() == expected_binding)
    }) {
        return Err(format!(
            "hardware variant `{}` was rejected after live QEMU evaluation",
            case.name
        ));
    }
    if !evaluation.observations.iter().any(|observation| {
        matches!(
            observation.kind,
            FaultObservationKind::EffectCommitted | FaultObservationKind::BindingActivation
        ) && observation
            .binding
            .as_ref()
            .is_some_and(|binding| binding.as_str() == expected_binding)
    }) {
        return Err(format!(
            "hardware variant `{}` omitted its committed or activated production observation",
            case.name
        ));
    }
    Ok(())
}
