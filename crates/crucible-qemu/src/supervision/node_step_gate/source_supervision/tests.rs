//! Checks real supervisor projection without native or child authority.

use super::*;
use crucible_linux_resource::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass,
};
use crucible_protocol::ram_control::{
    RamControlOuterState, decode_ram_control_budgets, decode_ram_control_outer,
};
use std::time::Duration;

fn record(arguments: &str, name: &str) -> Vec<u8> {
    let encoded = arguments
        .split(',')
        .filter_map(|field| field.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap();
    hex::decode(encoded).unwrap()
}

#[test]
fn resident_projection_preserves_real_class_totals_without_entering_an_operation() {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::FingerprintUpdate as usize] =
        HostOperationBudget::finite(Duration::from_millis(77));
    let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();
    let before = supervisor.outer_cap_binding().unwrap();
    let plugin = publish(
        QemuLaunchPluginConfig::new("fixture-plugin", 0),
        &supervisor,
    )
    .unwrap();

    let arguments = plugin.plugin_args_raw();
    let observed = decode_ram_control_budgets(&record(&arguments, "ram_initial_budgets")).unwrap();
    let outer = decode_ram_control_outer(&record(&arguments, "ram_outer_cap")).unwrap();
    assert_eq!(
        observed,
        crate::ram_control::budgets_to_wire(budgets).unwrap()
    );
    assert_eq!(outer.cap_id, before.cap_id);
    assert_eq!(outer.original_monotonic_ns, before.original_monotonic_ns);
    assert_eq!(outer.allowance_ns, None);
    assert!(plugin.ram_control().is_none());
    assert!(!arguments.contains("ram_spill_"));
    assert!(supervisor.operation_statuses().unwrap().is_empty());
}

#[test]
fn later_projection_retains_original_anchor_and_actual_cancellation() {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(3)),
    )
    .unwrap();
    let first = publish(
        QemuLaunchPluginConfig::new("fixture-plugin", 0),
        &supervisor,
    )
    .unwrap();
    let first =
        decode_ram_control_outer(&record(&first.plugin_args_raw(), "ram_outer_cap")).unwrap();
    supervisor.cancel().unwrap();

    let later = publish(
        QemuLaunchPluginConfig::new("fixture-plugin", 0),
        &supervisor,
    )
    .unwrap();
    let later =
        decode_ram_control_outer(&record(&later.plugin_args_raw(), "ram_outer_cap")).unwrap();
    assert_eq!(later.cap_id, first.cap_id);
    assert_eq!(later.original_monotonic_ns, first.original_monotonic_ns);
    assert_eq!(later.allowance_ns, first.allowance_ns);
    assert_eq!(later.state, RamControlOuterState::Canceled);
    assert!(supervisor.operation_statuses().unwrap().is_empty());
}

#[test]
fn resident_source_publishes_submillisecond_totals_without_rounding() {
    for total in [Duration::from_nanos(1), Duration::from_micros(500)] {
        let mut budgets = HostOperationBudgets::default();
        budgets.classes[HostOperationClass::FingerprintUpdate as usize] =
            HostOperationBudget::finite(total);
        let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();

        let plugin = publish(
            QemuLaunchPluginConfig::new("fixture-plugin", 0),
            &supervisor,
        )
        .unwrap();
        let observed =
            decode_ram_control_budgets(&record(&plugin.plugin_args_raw(), "ram_initial_budgets"))
                .unwrap();
        assert_eq!(
            observed[HostOperationClass::FingerprintUpdate as usize].total_ns,
            Some(total.as_nanos() as u64),
        );
        assert!(plugin.ram_control().is_none());
        assert!(supervisor.operation_statuses().unwrap().is_empty());
    }
}

#[test]
fn unrepresentable_source_timing_refuses_before_emitting_launch_arguments() {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::FingerprintUpdate as usize] = HostOperationBudget::finite(
        Duration::from_nanos(crucible_protocol::ram_control::RAM_CONTROL_MAX_ALLOWANCE_NS + 1),
    );
    let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();

    assert!(
        publish(
            QemuLaunchPluginConfig::new("fixture-plugin", 0),
            &supervisor
        )
        .is_err()
    );
    assert!(supervisor.operation_statuses().unwrap().is_empty());
}
