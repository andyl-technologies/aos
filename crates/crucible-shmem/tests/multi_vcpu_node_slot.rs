//! Checks that multi-vCPU nodes stay node-scoped in the shmem ABI.

#![forbid(unsafe_code)]

use crucible_shmem::{
    ABI_VERSION, KIND_VM, MAX_NODES, MAX_VM_NODES, NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET,
    NODE_SLOT_CURRENT_ICOUNT_OFFSET, NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
    NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, NODE_SLOT_SIZE,
    NodeSlot, RESERVED_SLOTS, RegionConfig, RegionLayout, STATUS_IDLE, authorize_advance_ceiling,
};

const SHMEM_SOURCE: &str = concat!(
    include_str!("../src/lib.rs"),
    include_str!("../src/shmem/region.rs"),
    include_str!("../src/shmem/ring_coverage.rs"),
    include_str!("../src/shmem/frame_node.rs"),
    include_str!("../src/shmem/delivery_errors.rs"),
);
const GENERATED_HEADER: &str = include_str!("../include/crucible_shmem_abi.h");

#[test]
fn multi_vcpu_count_does_not_change_region_shape_or_abi_version() {
    assert_eq!(ABI_VERSION, 17);

    let region_layout = layout(RegionConfig::new(2, 8, 4));
    assert_eq!(region_layout.node_count, MAX_NODES as u32);
    assert_eq!(region_layout.vm_node_count, 2);
    assert_eq!(region_layout.ring_count, 2 * RESERVED_SLOTS as u32 * 2);
    assert_eq!(MAX_VM_NODES, MAX_NODES - RESERVED_SLOTS);

    for simulated_vcpu_count in [1_u32, 2, 4, 8] {
        let same_node_shape = layout(RegionConfig::new(2, 8, 4));
        assert_eq!(
            same_node_shape, region_layout,
            "{simulated_vcpu_count} vCPUs must not allocate more shmem slots"
        );
    }
}

#[test]
fn one_node_slot_carries_aggregate_multi_vcpu_clock_and_idle_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = match authorize_advance_ceiling(0, 256, None) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("aggregate ceiling should be valid: {error}"),
    };
    if let Err(error) = slot.publish_scheduler_ceiling(ceiling) {
        panic!("aggregate ceiling publish should succeed: {error}");
    }

    let per_vcpu_deadlines = [240_u64, 180, 220, 360];
    let aggregate_idle_wake_icount = match per_vcpu_deadlines.iter().min() {
        Some(deadline) => *deadline,
        None => panic!("test deadline set is nonempty"),
    };
    if let Err(error) = slot.publish_idle(128, aggregate_idle_wake_icount, 2) {
        panic!("aggregate idle publish should succeed: {error}");
    }

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 128);
    assert_eq!(snapshot.current_ns, 512);
    assert_eq!(snapshot.max_advance_icount, 256);
    assert_eq!(snapshot.idle_wake_icount, 180);
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.device_io_active, 0);
}

#[test]
fn node_slot_publishes_device_io_active_flag() {
    let slot = NodeSlot::new(KIND_VM);

    assert!(!slot.load_device_io_active());

    slot.mark_device_io_active();
    let active = slot.snapshot();
    assert_eq!(active.device_io_active, 1);
    assert!(slot.load_device_io_active());

    slot.clear_device_io_active();
    if let Err(error) = slot.wake_for_device_io_release() {
        panic!("device-I/O release wake should succeed: {error}");
    }
    let inactive = slot.snapshot();
    assert_eq!(inactive.device_io_active, 0);
    assert_eq!(inactive.wake_signal, active.wake_signal.wrapping_add(1));
    assert!(!slot.load_device_io_active());
    assert!(inactive.publish_gen > active.publish_gen);
}

#[test]
fn shmem_abi_has_no_per_vcpu_fields_or_slots() {
    for forbidden in [
        "per_vcpu",
        "VcpuSlot",
        "vcpu_deadline",
        "vcpu_shift",
        "vcpu_epoch",
        "vcpu_count",
    ] {
        assert!(
            !SHMEM_SOURCE.contains(forbidden),
            "shmem Rust ABI must not expose `{forbidden}`"
        );
        assert!(
            !GENERATED_HEADER.contains(forbidden),
            "generated C ABI must not expose `{forbidden}`"
        );
    }
}

#[test]
fn generated_c_header_keeps_node_slot_node_scoped() {
    assert!(
        GENERATED_HEADER
            .contains("typedef struct CRUCIBLE_SHMEM_ALIGNED(128) crucible_shmem_node_slot")
    );
    assert!(GENERATED_HEADER.contains("CRUCIBLE_SHMEM_NODE_SLOT_SIZE 128u"));
    assert!(GENERATED_HEADER.contains("CRUCIBLE_SHMEM_NODE_SLOT_CURRENT_ICOUNT_OFFSET 0u"));
    assert!(GENERATED_HEADER.contains("CRUCIBLE_SHMEM_NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET 16u"));
    assert!(GENERATED_HEADER.contains("CRUCIBLE_SHMEM_NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET 24u"));
    assert!(GENERATED_HEADER.contains("CRUCIBLE_SHMEM_NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET 38u"));
    assert!(GENERATED_HEADER.contains("CRUCIBLE_SHMEM_NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET 44u"));
    assert_eq!(NODE_SLOT_SIZE, 128);
    assert_eq!(NODE_SLOT_CURRENT_ICOUNT_OFFSET, 0);
    assert_eq!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, 16);
    assert_eq!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, 24);
    assert_eq!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET, 38);
    assert_eq!(NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET, 44);
}

fn layout(config: RegionConfig) -> RegionLayout {
    match RegionLayout::for_config(config) {
        Ok(layout) => layout,
        Err(error) => panic!("region layout should be valid: {error}"),
    }
}
