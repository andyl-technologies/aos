//! Conservation controls for pure process-family partition arithmetic.

// crucible-lint: allow panic-shortcut -- fixed accounting fixtures panic only on invalid modeled setup or the deliberate caught-unwind control; they grant no native resources.

use super::*;

fn envelope() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 512 * 1024 * 1024,
        backing_peak_bytes: 1024 * 1024 * 1024,
        metadata_bytes: 16 * 1024 * 1024,
        staging_bytes: 8 * 1024 * 1024,
        paging_io_slots: 2,
        cpu_slots: 1,
        task_slots: 64,
        file_descriptors: 128,
    }
}

fn floor() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 128 * 1024 * 1024,
        backing_peak_bytes: 256 * 1024 * 1024,
        metadata_bytes: 4 * 1024 * 1024,
        staging_bytes: 2 * 1024 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 8,
        file_descriptors: 32,
    }
}

#[test]
fn initial_allowance_excludes_the_stage_before_first_launch() {
    let partition = HostRamProcessFamilyPartition::with_staged(envelope(), floor(), floor())
        .unwrap_or_else(|error| panic!("modeled family partition: {error}"));
    let initial = partition.initial();
    let staged = partition
        .staged()
        .unwrap_or_else(|| panic!("missing modeled stage"));
    assert_eq!(
        initial.resident_peak_bytes + staged.resident_peak_bytes,
        512 * 1024 * 1024
    );
    assert_eq!(
        initial.backing_peak_bytes + staged.backing_peak_bytes,
        envelope().backing_peak_bytes
    );
    assert_eq!(
        initial.metadata_bytes + staged.metadata_bytes,
        envelope().metadata_bytes
    );
    assert_eq!(
        initial.staging_bytes + staged.staging_bytes,
        envelope().staging_bytes
    );
    assert_eq!(initial.file_descriptors + staged.file_descriptors, 128);
    assert_eq!(initial.task_slots + staged.task_slots, 64);
    assert_eq!(initial.paging_io_slots + staged.paging_io_slots, 2);
    assert_eq!(initial.cpu_slots, 1);
    assert_eq!(staged.cpu_slots, 1);
    assert!(!envelope().fits(initial));
}

#[test]
fn every_additive_axis_refuses_before_a_partition_exists() {
    macro_rules! insufficient {
        ($($axis:ident),+ $(,)?) => {$(
            let mut capacity = envelope();
            capacity.$axis = floor().$axis.checked_mul(2).unwrap_or(u64::MAX) - 1;
            assert!(HostRamProcessFamilyPartition::with_staged(capacity, floor(), floor()).is_err(),
                "accepted insufficient {}", stringify!($axis));
        )+};
    }
    insufficient!(
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        paging_io_slots,
        task_slots,
        file_descriptors
    );
}

#[test]
fn a_parked_cpu_does_not_discount_live_paging_io_or_duplicate_descriptor_limits() {
    let mut child = floor();
    child.file_descriptors = 128;
    assert!(HostRamProcessFamilyPartition::with_staged(envelope(), floor(), child).is_err());

    let mut capacity = envelope();
    capacity.paging_io_slots = 1;
    assert!(HostRamProcessFamilyPartition::with_staged(capacity, floor(), floor()).is_err());
}

#[test]
fn overflowing_floor_combinations_and_invalid_subsets_refuse() {
    let mut initial = floor();
    initial.resident_peak_bytes = u64::MAX;
    let mut capacity = envelope();
    capacity.resident_peak_bytes = u64::MAX;
    assert!(HostRamProcessFamilyPartition::with_staged(capacity, initial, floor()).is_err());

    let mut invalid = floor();
    invalid.metadata_bytes = u64::MAX;
    assert!(HostRamProcessFamilyPartition::single(invalid).is_err());
    invalid = floor();
    invalid.staging_bytes = invalid.backing_peak_bytes + 1;
    assert!(HostRamProcessFamilyPartition::single(invalid).is_err());
}

#[test]
fn actual_ledger_reserves_all_staged_axes_without_a_second_cpu_grant() {
    use crucible_linux_resource::ram_policy::{HostRamTarget, HostResourceLedger};

    let partition = HostRamProcessFamilyPartition::with_staged(envelope(), floor(), floor())
        .unwrap_or_else(|error| panic!("modeled family partition: {error}"));
    let initial = HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    let staged = HostRamTarget {
        owner_generation: 2,
        arena_generation: 2,
        ..initial
    };
    let mut ledger = HostResourceLedger::new(partition.envelope());
    assert!(ledger.admit(initial, partition.initial()).is_ok());
    assert!(ledger.admit(staged, floor()).is_err());
    assert_eq!(ledger.reserved(), partition.initial());

    let escrow = partition
        .staged_escrow()
        .unwrap_or_else(|| panic!("missing modeled staged escrow"));
    assert_eq!(escrow.cpu_slots, 0);
    assert_eq!(escrow.paging_io_slots, floor().paging_io_slots);
    assert!(ledger.admit(staged, escrow).is_ok());
    assert_eq!(ledger.reserved(), partition.envelope());
    assert!(
        ledger
            .admit(
                HostRamTarget {
                    arena_generation: 3,
                    ..staged
                },
                escrow
            )
            .is_err()
    );
    assert_eq!(ledger.reserved(), partition.envelope());
}
