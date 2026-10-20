//! Actual original-child containment probes for native source refusals.
//!
//! Each case preserves original preparation and endpoint custody, requires the
//! actual child exit and reaping, and never projects failure into NoEffects.

use std::error::Error;

use super::run_original_construction;

#[test]
#[ignore = "requires actual timer-free containment launcher and matching GPL plugin"]
fn actual_fixed_microvm_timer_free_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "free",
            "fixed original timer teardown",
            "actual-source-BQL-and-HOLD",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual timer-deinit containment launcher and matching GPL plugin"]
fn actual_fixed_microvm_timer_deinit_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "deinit",
            "fixed original timer teardown",
            "actual-source-BQL-and-HOLD",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual CPU throttle containment launcher and matching GPL plugin"]
fn actual_fixed_microvm_cpu_throttle_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "throttle",
            "refuses CPU throttle activation",
            "actual-source-BQL-and-HOLD",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual dormant timer arm containment launcher and matching GPL plugin"]
fn actual_fixed_microvm_dormant_arm_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "dormant-arm",
            "nonvirtual root timer armed",
            "actual-source-BQL-and-HOLD",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original IRQ delivery containment launcher and GPL plugin"]
fn actual_fixed_microvm_irq_delivery_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "delivery",
            "Crucible original IRQ lifetime refused: IRQ delivery has no original source effect cut",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original GPIO relink containment launcher and GPL plugin"]
fn actual_fixed_microvm_gpio_relink_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "link",
            "Crucible original IRQ lifetime refused: IRQ allocation, release, or connection changed",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original GPIO output release containment launcher and GPL plugin"]
fn actual_fixed_microvm_gpio_output_release_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "release-output",
            "Crucible original IRQ lifetime refused: IRQ allocation, release, or connection changed",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original GPIO input release containment launcher and GPL plugin"]
fn actual_fixed_microvm_gpio_input_release_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "release-input",
            "Crucible original IRQ lifetime refused: IRQ allocation, release, or connection changed",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original empty IRQ release containment launcher and GPL plugin"]
fn actual_fixed_microvm_gpio_empty_release_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "release-empty",
            "Crucible original IRQ lifetime refused: IRQ allocation, release, or connection changed",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

/// Checks only the original diagnostic suffix written by this exact child.
#[test]
#[ignore = "requires actual pre-seal foreign IRQ thread containment launcher and GPL plugin"]
fn actual_fixed_microvm_foreign_irq_thread_retains_unissued_preparation_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "foreign-thread-delivery",
            "Crucible original IRQ lifetime refused: IRQ delivery has no original source effect cut",
            "same-original-process=1 actual-BQL=held before-native-seal=1 effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_monitor_retains_original_unknown_custody() -> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "monitor",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_character_device_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "character",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_qtest_allocation_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "qtest-object",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_qtest_input_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "qtest-input",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_iothread_retains_original_unknown_custody() -> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "iothread",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_anonymous_block_node_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "block-node",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_unattached_block_backend_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "block-backend",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_network_client_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "network",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original endpoint source guard launcher and GPL plugin"]
fn actual_fixed_microvm_fdset_input_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "fdset",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual transient endpoint history source guard launcher and GPL plugin"]
fn actual_fixed_microvm_transient_character_history_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "history-character",
            "Crucible original endpoint lifetime refused: input or allocation has no original source effect cut",
            "actual-source-BQL-and-HOLD original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original CPU writer source guard launcher and GPL plugin"]
fn actual_fixed_microvm_cpu_irq_set_retains_original_unknown_custody() -> Result<(), Box<dyn Error>>
{
    run_original_construction(
        true,
        Some((
            "cpu-irq-set",
            "Crucible original CPU source refused: CPU IRQ set; no original source effect cut",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original CPU writer source guard launcher and GPL plugin"]
fn actual_fixed_microvm_cpu_irq_clear_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "cpu-irq-clear",
            "Crucible original CPU source refused: CPU IRQ clear; no original source effect cut",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original CPU writer source guard launcher and GPL plugin"]
fn actual_fixed_microvm_cpu_reset_retains_original_unknown_custody() -> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "cpu-reset",
            "Crucible original CPU source refused: CPU reset; no original source effect cut",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual original CPU writer source guard launcher and GPL plugin"]
fn actual_fixed_microvm_cpu_reset_hold_retains_original_unknown_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "cpu-reset-hold",
            "Crucible original CPU source refused: CPU reset hold; no original source effect cut",
            "original-held-census=valid original-init-unacknowledged effect-permission=absent",
        )),
        false,
    )
}

#[test]
#[ignore = "requires actual post-install RR foreign-thread fixture and matching GPL plugin"]
fn actual_fixed_microvm_foreign_irq_thread_after_install_retains_unissued_preparation_custody()
-> Result<(), Box<dyn Error>> {
    run_original_construction(
        true,
        Some((
            "foreign-thread-post-install",
            "Crucible original IRQ lifetime refused: IRQ delivery has no original source effect cut",
            "actual-post-install-RR-cut-held=",
        )),
        false,
    )
}
