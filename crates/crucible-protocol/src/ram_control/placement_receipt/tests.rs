//! Strict completion framing, historical-cut semantics, and hostile receipts.

use super::*;
use crate::ram_control::{
    RamControlConvergence, RamControlDisposition, RamControlFrame, RamControlInventoryReport,
    RamControlMessage, RamControlOwnerInventory, RamControlTarget, decode_ram_control,
    encode_ram_control,
};

fn resident_receipt() -> RamControlPlacementReceipt {
    RamControlPlacementReceipt {
        mode: RamControlMode::ResidentRequired,
        policy_revision: 1,
        topology_generation: 11,
        placement_epoch: 3,
        locked_bytes: 8192,
        disk_preserved_logical_pages: 0,
        disk_preserved_logical_bytes: 0,
        ram_write_generation_at_cut: 0,
    }
}

fn disk_receipt() -> RamControlPlacementReceipt {
    RamControlPlacementReceipt {
        mode: RamControlMode::DiskOriented,
        locked_bytes: 0,
        disk_preserved_logical_pages: 2,
        disk_preserved_logical_bytes: 8192,
        ram_write_generation_at_cut: 19,
        ..resident_receipt()
    }
}

fn frame(receipt: RamControlPlacementReceipt) -> RamControlFrame {
    let state = RamControlReply {
        performance: None,
        placement_receipt: Some(receipt),
        operation_failure: None,
        fault_actor: None,
        kernel_probe: None,
        activity: None,
        disposition: RamControlDisposition::Accepted,
        logical_ram_bytes: 8192,
        inventory: Some(RamControlInventoryReport {
            topology_generation: 11,
            logical_bytes: 8192,
            region_count: 2,
            native_metadata_bytes: 4096,
            native_scratch_bytes: 4096,
            owner_resources: RamControlOwnerInventory {
                existing_tasks: 4,
                existing_file_descriptors: 10,
                registered_service_tasks: 1,
                prospective_tasks: 0,
                prospective_file_descriptors: 0,
            },
            granted: true,
        }),
        inventory_region: None,
        requested_policy_revision: 2,
        applied_policy_revision: 1,
        reservation_revision: 5,
        observation_sequence: 8,
        effective_resident_target_bytes: 8192,
        effective_floor_bytes: 8192,
        limitation_reasons: 0,
        measurements_available: false,
        private_resident_bytes: 0,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 0,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        convergence: RamControlConvergence::Applying,
    };
    RamControlFrame {
        session: [1; 32],
        sequence: 2,
        target: RamControlTarget {
            daemon_epoch: [2; 32],
            owner_id: [3; 32],
            node_id: [4; 32],
            owner_generation: 7,
            arena_generation: 9,
            retained_template: false,
        },
        message: RamControlMessage::Reply {
            request_digest: [5; 32],
            state,
        },
    }
}

#[test]
fn pending_transition_retains_original_applied_receipt() {
    for receipt in [resident_receipt(), disk_receipt()] {
        let original = frame(receipt);
        let encoded = encode_ram_control(&original)
            .unwrap_or_else(|error| panic!("valid applied receipt: {error}"));

        assert_eq!(
            decode_ram_control(&encoded)
                .unwrap_or_else(|error| panic!("decode applied receipt: {error}")),
            original
        );
    }
}

#[test]
fn strict_receipts_reject_pending_revision_topology_and_cross_mode_counters() {
    let resident = resident_receipt();
    let disk = disk_receipt();
    for invalid in [
        RamControlPlacementReceipt {
            policy_revision: 0,
            ..resident
        },
        RamControlPlacementReceipt {
            policy_revision: 2,
            ..resident
        },
        RamControlPlacementReceipt {
            topology_generation: 12,
            ..resident
        },
        RamControlPlacementReceipt {
            placement_epoch: 0,
            ..resident
        },
        RamControlPlacementReceipt {
            mode: RamControlMode::Managed,
            ..resident
        },
        RamControlPlacementReceipt {
            locked_bytes: 0,
            ..resident
        },
        RamControlPlacementReceipt {
            locked_bytes: 8191,
            ..resident
        },
        RamControlPlacementReceipt {
            disk_preserved_logical_pages: 1,
            ..resident
        },
        RamControlPlacementReceipt {
            disk_preserved_logical_bytes: 1,
            ..resident
        },
        RamControlPlacementReceipt {
            ram_write_generation_at_cut: 1,
            ..resident
        },
        RamControlPlacementReceipt {
            locked_bytes: 4096,
            ..disk
        },
        RamControlPlacementReceipt {
            disk_preserved_logical_pages: 1,
            ..disk
        },
        RamControlPlacementReceipt {
            disk_preserved_logical_pages: 4,
            ..disk
        },
        RamControlPlacementReceipt {
            disk_preserved_logical_bytes: 8191,
            ..disk
        },
    ] {
        assert!(
            encode_ram_control(&frame(invalid)).is_err(),
            "accepted {invalid:?}"
        );
    }

    for change in 0..3 {
        let mut observation = frame(resident);
        let RamControlMessage::Reply { state, .. } = &mut observation.message else {
            panic!("receipt fixture must be a reply");
        };
        match change {
            0 => state.inventory = None,
            1 => {
                if let Some(inventory) = &mut state.inventory {
                    inventory.granted = false;
                }
            }
            _ => state.logical_ram_bytes = 8191,
        }
        assert!(encode_ram_control(&observation).is_err());
    }
}

#[test]
fn disk_receipt_preserves_a_historical_cut_without_claiming_write_through() {
    let original = frame(disk_receipt());
    let RamControlMessage::Reply { state, .. } = original.message else {
        panic!("receipt fixture must be a reply");
    };
    let receipt = state
        .placement_receipt
        .unwrap_or_else(|| panic!("preserved cut receipt must exist"));

    // The physical owner verifies the exact regional sum. The wire admits
    // partial trailing pages without inferring topology from a byte total.
    let rounded = RamControlPlacementReceipt {
        disk_preserved_logical_pages: 3,
        ..receipt
    };
    assert!(encode_ram_control(&frame(rounded)).is_ok());
    let untouched = RamControlPlacementReceipt {
        ram_write_generation_at_cut: 0,
        ..receipt
    };
    assert!(encode_ram_control(&frame(untouched)).is_ok());
    assert_eq!(receipt.ram_write_generation_at_cut, 19);
}

#[test]
fn strict_receipt_decoder_rejects_truncation_unknown_tags_and_predecessor_schema() {
    let canonical = encode_ram_control(&frame(resident_receipt()))
        .unwrap_or_else(|error| panic!("valid strict receipt: {error}"));
    for length in 0..canonical.len() {
        assert!(decode_ram_control(&canonical[..length]).is_err());
    }

    for (offset, value) in [(canonical.len() - 58, 2), (canonical.len() - 57, 0), (3, 3)] {
        let mut malformed = canonical.clone();
        malformed[offset] = value;
        assert!(decode_ram_control(&malformed).is_err());
    }
    let mut malformed = canonical;
    malformed.push(0);
    assert!(decode_ram_control(&malformed).is_err());
}
