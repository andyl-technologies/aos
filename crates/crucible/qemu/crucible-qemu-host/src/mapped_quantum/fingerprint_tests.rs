//! Black-box execution-fingerprint regressions.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::unwrap_used)]

use crucible_qemu_shmem::{FingerprintSample, FingerprintSampleVcpu};

use super::*;

fn sample() -> FingerprintSample {
    let mut sample = FingerprintSample {
        sample_icount: 41,
        vcpu_count: 1,
        rr_current_vcpu: 0,
        rr_position_in_quantum: 41,
        rr_switch_quantum: 4096,
        component_failures: 0,
        ram_bytes: 4096,
        ram_digest: [0x11; 32],
        device_state_bytes: 512,
        device_state_sections: 17,
        device_state_digest: [0x22; 32],
        device_state_schema_digest: [0x33; 32],
        ..FingerprintSample::default()
    };
    sample.vcpus[0] = FingerprintSampleVcpu {
        register_digest: [0x44; 32],
        register_file_bytes: 256,
        retired_instruction_count: 0,
    };
    sample
}

#[test]
fn black_box_fingerprint_covers_live_register_ram_and_device_state() {
    let node = crucible_engine::NodeId {
        name: String::from("vm-a"),
    };
    let baseline = black_box_execution_fingerprint(&node, &sample()).unwrap();

    let mut changed = sample();
    changed.vcpus[0].register_digest[0] ^= 1;
    assert_ne!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
    changed = sample();
    changed.ram_digest[0] ^= 1;
    assert_ne!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
    changed = sample();
    changed.device_state_digest[0] ^= 1;
    assert_ne!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
}

#[test]
fn black_box_fingerprint_excludes_unused_vcpu_slots() {
    let node = crucible_engine::NodeId {
        name: String::from("vm-a"),
    };
    let baseline = black_box_execution_fingerprint(&node, &sample()).unwrap();
    let mut changed = sample();
    changed.vcpus[1].register_digest = [0xff; 32];
    assert_eq!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
}

#[test]
fn black_box_fingerprint_rejects_incomplete_samples() {
    let node = crucible_engine::NodeId {
        name: String::from("vm-a"),
    };
    let mut failed = sample();
    failed.component_failures = 1;
    assert!(black_box_execution_fingerprint(&node, &failed).is_err());

    let mut empty = sample();
    empty.vcpu_count = 0;
    assert!(black_box_execution_fingerprint(&node, &empty).is_err());
}

struct RejectFingerprintNetworkSends;

impl crucible_engine::SchedulerSendAuthorizer for RejectFingerprintNetworkSends {
    fn authorize_cross_node_send(
        &self,
        _producer: &crucible_engine::SchedulerNodeId,
        _consumer: &crucible_engine::SchedulerNodeId,
    ) -> Result<crucible_engine::SchedulerSendAuthorization, crucible_engine::SchedulerError> {
        panic!("fingerprint observation must not authorize a network send");
    }
}

fn mapped_fingerprint_channel()
-> Result<(QemuMappedQuantumShmemHotPath, MappedSetupRegion), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    use crucible_qemu_shmem::{RegionAllocation, RegionConfig, mmap_setup_region};

    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
    shmem.write_all(&allocation.setup_region_bytes()?)?;
    let producer = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let region = mmap_setup_region(shmem.as_fd(), layout.region_size)?;
    let config = QemuQuantumShmemConfig::new(
        crucible_engine::NodeId {
            name: String::from("fingerprint-node"),
        },
        0,
    );
    let channel =
        QemuMappedQuantumShmemHotPath::new(config, region, RejectFingerprintNetworkSends)?;
    Ok((channel, producer))
}

#[test]
fn mapped_snapshot_borrows_existing_configuration_without_allocating()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let (mut channel, producer) = mapped_fingerprint_channel()?;
    let expected = producer.node_slot(0)?.snapshot();

    let (snapshot, counts) = TestAllocationObserver::count(|| {
        channel.with_hot_path("observe fingerprint boundary", |hot_path| {
            Ok(hot_path.node_snapshot())
        })
    });

    assert_eq!(snapshot?, expected);
    assert_eq!(counts.allocations, 0, "{counts:?}");
    assert_eq!(counts.reallocations, 0, "{counts:?}");
    assert!(!counts.overflow);
    Ok(())
}

#[test]
fn mapped_fingerprint_boundary_refusal_retains_coordinates_without_allocating()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let (mut channel, producer) = mapped_fingerprint_channel()?;
    let current = 4096 * crucible_qemu_shmem::TICKS_PER_INSTRUCTION;
    producer.node_slot(0)?.publish_pause_quiesced(current, 0)?;

    for (sample_icount, relation, retryable) in [
        (current - 1, "behind", true),
        (current + 1, "ahead of", false),
    ] {
        let sample = FingerprintSample {
            sample_icount,
            ..sample()
        };
        producer.fingerprint_sample(0)?.publish(&sample)?;
        let expected = format!(
            "execution_fingerprint failed: black-box fingerprint sample at icount {sample_icount} is {relation} current boundary {current}"
        );

        let (result, counts) = TestAllocationObserver::count(|| {
            QemuShmemHotPathChannel::execution_fingerprint(&mut channel)
        });

        let error = result.expect_err("a different boundary cannot supply this fingerprint");
        assert_eq!(counts.allocations, 0, "{counts:?}");
        assert_eq!(counts.reallocations, 0, "{counts:?}");
        assert!(!counts.overflow);
        assert_eq!(error.to_string(), expected);
        let expected_source = if retryable {
            crate::QemuFingerprintSampleError::BehindBoundary {
                sample_icount,
                current_icount: current,
            }
        } else {
            crate::QemuFingerprintSampleError::AheadOfBoundary {
                sample_icount,
                current_icount: current,
            }
        };
        assert_eq!(error.fingerprint_sample_source(), Some(expected_source));
        assert_eq!(error.is_retryable(), retryable);
        assert!(error.bounded_timeout().is_none());
        assert_eq!(producer.fingerprint_sample(0)?.snapshot(), Some(sample));
        assert_eq!(
            producer.fingerprint_sample(0)?.pending_capture_request_v1(),
            None
        );
    }
    Ok(())
}
