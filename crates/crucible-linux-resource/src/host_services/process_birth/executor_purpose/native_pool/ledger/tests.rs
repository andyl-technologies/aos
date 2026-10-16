//! Pure accounting refusals, not authenticated Main/Source issuance controls.

// SPDX-License-Identifier: Apache-2.0

use super::*;

fn ceiling() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 1000,
        backing_peak_bytes: 1000,
        metadata_bytes: 200,
        staging_bytes: 100,
        cpu_slots: 4,
        task_slots: 20,
        file_descriptors: 64,
        paging_io_slots: 10,
    }
}

fn requests() -> [NativeNodeReservation; 2] {
    [
        NativeNodeReservation {
            node: [1; 32],
            source_host_descriptors: 5,
            target_host_descriptors: 7,
            resources: HostResourceVector {
                resident_peak_bytes: 100,
                backing_peak_bytes: 200,
                metadata_bytes: 30,
                staging_bytes: 10,
                cpu_slots: 1,
                task_slots: 3,
                file_descriptors: 8,
                paging_io_slots: 2,
            },
        },
        NativeNodeReservation {
            node: [2; 32],
            source_host_descriptors: 6,
            target_host_descriptors: 8,
            resources: HostResourceVector {
                resident_peak_bytes: 150,
                backing_peak_bytes: 300,
                metadata_bytes: 50,
                staging_bytes: 20,
                cpu_slots: 2,
                task_slots: 4,
                file_descriptors: 12,
                paging_io_slots: 3,
            },
        },
    ]
}

#[test]
fn distinct_node_payloads_and_controls_conserve_all_axes() {
    let controls = HostResourceVector {
        resident_peak_bytes: 8,
        metadata_bytes: 8,
        ..HostResourceVector::default()
    };
    let (sum, windows) = checked_selection(ceiling(), controls, &requests()).unwrap();

    assert_eq!(
        sum,
        HostResourceVector {
            resident_peak_bytes: 258,
            backing_peak_bytes: 500,
            metadata_bytes: 88,
            staging_bytes: 30,
            cpu_slots: 3,
            task_slots: 7,
            file_descriptors: 46,
            paging_io_slots: 5,
        }
    );
    assert_eq!(windows, 26);
}

#[test]
fn one_short_on_any_aggregate_axis_refuses_the_whole_selection() {
    let (sum, _) =
        checked_selection(ceiling(), HostResourceVector::default(), &requests()).unwrap();
    macro_rules! short {
        ($($axis:ident),+ $(,)?) => {$(
            let mut limit = ceiling();
            limit.$axis = sum.$axis - 1;
            assert!(checked_selection(limit, HostResourceVector::default(), &requests()).is_err(), stringify!($axis));
        )+};
    }
    short!(
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        cpu_slots,
        task_slots,
        file_descriptors,
        paging_io_slots
    );
}

#[test]
fn duplicate_or_unordered_nodes_and_unfunded_landings_refuse() {
    let mut nodes = requests();
    nodes[1].node = nodes[0].node;
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());

    let mut nodes = requests();
    nodes.swap(0, 1);
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());

    let mut nodes = requests();
    nodes[0].target_host_descriptors = 0;
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());
}

#[test]
fn overflow_never_becomes_an_additional_pool_allowance() {
    let used = HostResourceVector {
        resident_peak_bytes: u64::MAX,
        ..HostResourceVector::default()
    };
    assert!(checked_selection(ceiling(), used, &requests()).is_err());

    let mut nodes = requests();
    nodes[0].source_host_descriptors = u64::MAX;
    assert!(checked_selection(ceiling(), HostResourceVector::default(), &nodes).is_err());
}

#[test]
fn concurrent_world_template_and_replay_selections_share_one_ceiling() {
    let mut limit = ceiling();
    limit.cpu_slots = 3;
    let request = [requests()[0]];
    let initial = HostResourceVector::default();
    let (world, _) = checked_selection(limit, initial, &request).unwrap();
    let (template, _) = checked_selection(limit, world, &request).unwrap();
    let (replay, _) = checked_selection(limit, template, &request).unwrap();

    assert_eq!(replay.cpu_slots, 3);
    assert_eq!(replay.resident_peak_bytes, 300);
    assert_eq!(replay.file_descriptors, 60);
    assert!(checked_selection(limit, replay, &request).is_err());
}

#[test]
fn node_count_is_not_the_private_four_worker_roster_width() {
    let mut limit = ceiling();
    limit.cpu_slots = 6;
    limit.file_descriptors = 120;
    limit.paging_io_slots = 12;
    let nodes: [_; 6] = std::array::from_fn(|index| {
        let mut request = requests()[0];
        request.node = [u8::try_from(index + 1).unwrap(); 32];
        request.resources.backing_peak_bytes = 100;
        request
    });
    let (sum, peak) = checked_selection(limit, HostResourceVector::default(), &nodes).unwrap();

    assert_eq!(sum.cpu_slots, 6);
    assert_eq!(sum.file_descriptors, 120);
    assert_eq!(peak, 72);
}

#[test]
fn containing_control_geometry_refuses_before_root_publication() {
    let mut limit = ceiling();
    limit.resident_peak_bytes = u64::MAX;
    limit.metadata_bytes = u64::MAX;
    assert!(super::super::checked_layout(limit, u64::MAX, 1).is_err());

    limit.metadata_bytes = 1;
    assert!(super::super::checked_layout(limit, 0, 1).is_err());
}

#[test]
fn shared_and_node_landings_share_the_same_descriptor_ceiling() {
    let shared = HostResourceVector {
        file_descriptors: 19,
        ..HostResourceVector::default()
    };
    // 19 shared + 20 native tables + 26 Main landings is one over 64.
    assert!(checked_selection(ceiling(), shared, &requests()).is_err());
    let fitting = HostResourceVector {
        file_descriptors: 18,
        ..shared
    };
    let (used, _) = checked_selection(ceiling(), fitting, &requests()).unwrap();
    assert_eq!(used.file_descriptors, 64);
}

#[test]
fn simultaneous_world_containing_bodies_share_the_same_bank() {
    let limit = ceiling();
    let used = charge_world_controls(limit, HostResourceVector::default(), 100).unwrap();
    let used = charge_world_controls(limit, used, 100).unwrap();

    assert_eq!(used.resident_peak_bytes, 200);
    assert_eq!(used.metadata_bytes, 200);
    assert!(charge_world_controls(limit, used, 1).is_err());
    assert_eq!(
        subtract(
            used,
            HostResourceVector {
                resident_peak_bytes: 100,
                metadata_bytes: 100,
                ..HostResourceVector::default()
            }
        )
        .unwrap(),
        charge_world_controls(limit, HostResourceVector::default(), 100).unwrap()
    );
}

#[test]
fn permanent_worker_controls_compete_with_every_world_without_a_second_bank() {
    let mut ledger = PoolLedger::new(ceiling(), 2, 8, 3).unwrap();
    let initial = ledger.used;
    assert!(ledger.reserve_worker_controls(0).is_err());
    assert_eq!(ledger.used, initial);
    assert!(ledger.reserve_worker_controls(201).is_err());
    assert_eq!(ledger.used, initial);
    ledger.reserve_worker_controls(112).unwrap();
    assert_eq!(ledger.used.metadata_bytes, 120);
    assert_eq!(ledger.used.resident_peak_bytes, 120);
    assert_eq!(ledger.used.file_descriptors, 3);
    let (whole, _) = checked_selection(ceiling(), ledger.used, &requests()).unwrap();
    assert_eq!(whole.metadata_bytes, 200);
    assert!(charge_world_controls(ceiling(), whole, 1).is_err());
    let used = ledger.used;
    assert!(ledger.reserve_worker_controls(1).is_err());
    assert_eq!(ledger.used, used);
}
