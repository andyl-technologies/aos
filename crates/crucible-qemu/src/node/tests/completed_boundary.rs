//! Exercises the production node driver and cached original clamp evidence.

use super::*;
use std::io::Read;

fn fixture<T>(value: Result<T, impl std::fmt::Debug>) -> T {
    value.unwrap_or_else(|error| panic!("node completed-boundary fixture failed: {error:?}"))
}

#[test]
fn logical_time_calibration_checks_scaled_raw_retirement() {
    let calibration = QemuLogicalTimeCalibration {
        logical_icount: 2_107,
        raw_icount: 42,
    };
    assert!(matches!(calibration.offset(), Ok(7)));

    let underflow = QemuLogicalTimeCalibration {
        logical_icount: 2_099,
        raw_icount: 42,
    };
    assert!(underflow.offset().is_err());

    let overflow = QemuLogicalTimeCalibration {
        logical_icount: u64::MAX,
        raw_icount: u64::MAX,
    };
    assert!(overflow.offset().is_err());
}

#[test]
fn node_returns_original_mapped_completion_while_live_getter_observes_later_wake() {
    let mapped =
        crate::supervision::host_io_runtime::tests::completed_boundary::MappedCompletion::new();
    let mut node = fixture(scripted_node(shared_log(), false, false, false));
    node.channels.shmem_hot_path = Box::new(mapped.channel);
    node.host_io_runtime = Box::new(mapped.runtime);
    node.async_policy = crate::QemuAsyncDriverPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    assert!(node.completed_quantum_boundary().is_none());
    let producer = mapped.producer;
    let mut notifications = mapped.notifications;
    let slot = fixture(producer.node_slot(0));

    let node = std::thread::scope(|scope| {
        let host = scope.spawn(move || {
            let result = Backend::advance_to_horizon(
                &mut node,
                ExecutionHorizon {
                    icount: Icount { retired: 100 },
                },
            );
            (node, result)
        });
        let mut wake = [0_u8; 8];
        // The live await first probes the advance, then independently revokes
        // dispatch with its mandatory completed-quantum clamp. Service both
        // genuine requests, preserving their original even/odd incarnation.
        for generation in [2, 4] {
            loop {
                fixture(notifications.read_exact(&mut wake));
                if slot.snapshot().control_boundary_ack == generation {
                    break;
                }
            }
            fixture(slot.publish_reached_icount(100));
            fixture(slot.publish_control_boundary(100, 1));
            slot.acknowledge_control_boundary();
            slot.mark_running();
        }

        let (node, result) = fixture(host.join());
        assert_eq!(fixture(result), AdvanceOutcome::ReachedHorizon);
        node
    });
    let original = node
        .completed_quantum_boundary()
        .unwrap_or_else(|| panic!("production node discarded its original clamp record"));
    assert_eq!(
        original.calibration(),
        QemuLogicalTimeCalibration {
            logical_icount: 100,
            raw_icount: 1
        }
    );
    assert_eq!(
        original.idle_state().next_deadline,
        Some(Icount { retired: 100 })
    );
    fixture(slot.publish_idle(100, 200));
    let mut node = node;

    assert_eq!(
        fixture(node.idle_state()).next_deadline,
        Some(Icount { retired: 200 })
    );
    assert_eq!(node.completed_quantum_boundary(), Some(original));
    fixture(node.shutdown_child());
}

#[test]
fn modeled_node_retains_absent_native_completion_evidence() {
    let mut node = fixture(scripted_node(shared_log(), false, false, false));

    fixture(Backend::advance_to_horizon(
        &mut node,
        ExecutionHorizon {
            icount: Icount { retired: 19 },
        },
    ));

    assert!(node.completed_quantum_boundary().is_none());
    fixture(node.shutdown_child());
}
