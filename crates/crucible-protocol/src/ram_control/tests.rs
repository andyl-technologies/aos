//! Golden framing and hostile authority/size cases for the independent channel.

use super::*;
use std::io::Cursor;

fn target() -> RamControlTarget {
    RamControlTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 7,
        arena_generation: 9,
        retained_template: false,
    }
}

fn frame(sequence: u64, request: RamControlRequest) -> RamControlFrame {
    RamControlFrame {
        session: [4; 32],
        sequence,
        target: target(),
        message: RamControlMessage::Request(request),
    }
}

fn state() -> RamControlReply {
    RamControlReply {
        performance: None,
        placement_receipt: None,
        operation_failure: None,
        fault_actor: None,
        kernel_probe: None,
        activity: None,
        disposition: RamControlDisposition::Accepted,
        logical_ram_bytes: 8192,
        inventory: None,
        inventory_region: None,
        limitation_reasons: RAM_LIMIT_COMPULSORY_FLOOR,
        measurements_available: true,
        requested_policy_revision: 2,
        applied_policy_revision: 1,
        reservation_revision: 3,
        observation_sequence: 4,
        effective_resident_target_bytes: 4096,
        effective_floor_bytes: 8192,
        private_resident_bytes: 4096,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 16384,
        private_dirty_bytes: 4096,
        writeback_pending_bytes: 4096,
        convergence: RamControlConvergence::Evicting,
    }
}

fn policy() -> RamControlPolicy {
    RamControlPolicy {
        mode: RamControlMode::DiskOriented,
        resident_target_bytes: 0,
        eviction_preference: 100,
        writeback_bytes_per_second: 4096,
        maximum_paging_io_in_flight: 2,
        prefetch_on_increase: false,
        budgets: [RamControlBudget {
            poll_ms: 10,
            progress_ms: Some(5000),
            total_ms: Some(60_000),
        }; RAM_CONTROL_BUDGET_COUNT],
    }
}

#[test]
fn ram_control_golden_hello_and_all_closed_messages_roundtrip() {
    let hello = frame(1, RamControlRequest::Hello);
    let mut golden = vec![0, 0, 0, 6, 0];
    golden.extend_from_slice(&[4; 32]);
    golden.extend_from_slice(&1_u64.to_be_bytes());
    golden.extend_from_slice(&[1; 32]);
    golden.extend_from_slice(&[2; 32]);
    golden.extend_from_slice(&[3; 32]);
    golden.extend_from_slice(&7_u64.to_be_bytes());
    golden.extend_from_slice(&9_u64.to_be_bytes());
    golden.push(0);

    assert_eq!(golden.len(), 158);
    assert_eq!(
        encode_ram_control(&hello).unwrap_or_else(|_| panic!("valid test fixture must succeed")),
        golden
    );
    for request in [
        RamControlRequest::Hello,
        RamControlRequest::Status,
        RamControlRequest::Cancel {
            operation_generation: 99,
        },
        RamControlRequest::Apply {
            expected_revision: 1,
            policy_revision: 2,
            reservation_revision: 3,
            resources: RamControlResources::default(),
            policy: policy(),
        },
    ] {
        let expected = frame(1, request);
        let encoded = encode_ram_control(&expected)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        assert_eq!(
            decode_ram_control(&encoded)
                .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
            expected
        );
        let reply = RamControlFrame {
            message: RamControlMessage::Reply {
                request_digest: ram_control_request_digest(&expected)
                    .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
                state: state(),
            },
            ..expected
        };
        assert_eq!(
            decode_ram_control(
                &encode_ram_control(&reply)
                    .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
            )
            .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
            reply
        );
    }
}

#[test]
fn ram_control_rejects_truncation_trailing_unknown_and_overflow_before_dispatch() {
    let canonical = encode_ram_control(&frame(1, RamControlRequest::Hello))
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    for size in 0..canonical.len() {
        assert!(
            decode_ram_control(&canonical[..size]).is_err(),
            "accepted truncated size {size}"
        );
    }
    let mut malformed = canonical.clone();
    malformed.push(0);
    assert!(decode_ram_control(&malformed).is_err());
    malformed = canonical.clone();
    malformed[4] = 127;
    assert!(decode_ram_control(&malformed).is_err());
    malformed = canonical;
    malformed[3] = 2;
    assert!(matches!(
        decode_ram_control(&malformed),
        Err(RamControlError::UnsupportedVersion(2))
    ));
    let mut huge = Cursor::new(u32::MAX.to_be_bytes());
    assert!(matches!(
        read_ram_control(&mut huge),
        Err(RamControlError::TooLarge)
    ));
    assert_eq!(huge.position(), 4);
    let mut partial_header = Cursor::new(vec![0, 0]);
    assert!(read_ram_control(&mut partial_header).is_err());
    assert!(
        read_ram_control(&mut Cursor::new(Vec::<u8>::new()))
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
            .is_none()
    );
}

#[test]
fn ram_control_rejects_invalid_scalars_and_noncanonical_optional_durations() {
    let mut invalid = policy();
    invalid.eviction_preference = 101;
    for policy in [
        invalid,
        RamControlPolicy {
            maximum_paging_io_in_flight: 0,
            ..policy()
        },
        RamControlPolicy {
            writeback_bytes_per_second: 0,
            ..policy()
        },
    ] {
        assert!(
            encode_ram_control(&frame(
                1,
                RamControlRequest::Apply {
                    expected_revision: 1,
                    policy_revision: 2,
                    reservation_revision: 3,
                    resources: RamControlResources::default(),
                    policy
                }
            ))
            .is_err()
        );
    }
    let mut policy = policy();
    policy.budgets[0].progress_ms = Some(0);
    assert!(
        encode_ram_control(&frame(
            1,
            RamControlRequest::Apply {
                expected_revision: 1,
                policy_revision: 2,
                reservation_revision: 3,
                resources: RamControlResources::default(),
                policy
            }
        ))
        .is_err()
    );
    assert!(
        encode_ram_control(&frame(
            1,
            RamControlRequest::Apply {
                expected_revision: u64::MAX,
                policy_revision: 0,
                reservation_revision: 3,
                resources: RamControlResources::default(),
                policy
            }
        ))
        .is_err()
    );
    assert!(
        encode_ram_control(&frame(
            1,
            RamControlRequest::Cancel {
                operation_generation: 0
            }
        ))
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn ram_control_independent_socket_services_status_while_guest_is_stalled() {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    let guest_replay_lock = Arc::new(Mutex::new(()));
    let (held, held_rx) = mpsc::sync_channel(0);
    let (release, release_rx) = mpsc::sync_channel(0);
    let guest_lock = Arc::clone(&guest_replay_lock);
    let guest = thread::spawn(move || {
        let _guard = guest_lock
            .lock()
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        held.send(())
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        release_rx
            .recv()
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    });
    held_rx
        .recv()
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    let (mut host, mut pager) =
        UnixStream::pair().unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    host.set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    let worker =
        thread::spawn(move || serve_ram_control(&mut pager, [4; 32], target(), |_| state()));

    for (sequence, request) in [
        (1, RamControlRequest::Hello),
        (2, RamControlRequest::Status),
        (
            3,
            RamControlRequest::Cancel {
                operation_generation: 99,
            },
        ),
    ] {
        let request = frame(sequence, request);
        write_ram_control(&mut host, &request)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        let reply = read_ram_control(&mut host)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
            .unwrap_or_else(|| panic!("test peer must send a frame"));
        assert_eq!(reply.sequence, sequence);
        assert_eq!(
            reply.message,
            RamControlMessage::Reply {
                request_digest: ram_control_request_digest(&request)
                    .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
                state: state()
            }
        );
    }
    host.shutdown(std::net::Shutdown::Both)
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    worker
        .join()
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    release
        .send(())
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    guest
        .join()
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
}

#[cfg(unix)]
#[test]
fn ram_control_stale_session_target_and_replayed_sequence_never_mutate() {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    for alteration in 0..4 {
        let (mut host, mut pager) =
            UnixStream::pair().unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        let mutations = Arc::new(AtomicUsize::new(0));
        let worker_mutations = Arc::clone(&mutations);
        let worker = thread::spawn(move || {
            serve_ram_control(&mut pager, [4; 32], target(), |request| {
                if matches!(request, RamControlRequest::Apply { .. }) {
                    worker_mutations.fetch_add(1, Ordering::SeqCst);
                }
                state()
            })
        });
        let hello = frame(1, RamControlRequest::Hello);
        write_ram_control(&mut host, &hello)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        read_ram_control(&mut host)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
            .unwrap_or_else(|| panic!("test peer must send a frame"));
        let mut request = frame(
            2,
            RamControlRequest::Apply {
                expected_revision: 1,
                policy_revision: 2,
                reservation_revision: 3,
                resources: RamControlResources::default(),
                policy: policy(),
            },
        );
        match alteration {
            0 => request.session = [5; 32],
            1 => request.target.owner_generation += 1,
            2 => request.target.arena_generation += 1,
            _ => request.sequence = 1,
        }
        write_ram_control(&mut host, &request)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
        assert!(matches!(
            worker
                .join()
                .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
            Err(RamControlError::AuthorityMismatch)
        ));
        assert_eq!(mutations.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn control_cutover_accepts_current_golden_and_refuses_predecessor_handshake() {
    use crate::{
        CONTROL_PROTOCOL_VERSION, GOLDEN_CONTROL_VECTORS, HandshakeError, HostHandshakeConfig,
        PluginMsg, control_decode_plugin_msg, host_negotiate_handshake,
    };

    let config = HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: 1,
        slot_index: 7,
        node_count: 32,
    };
    let current = control_decode_plugin_msg(GOLDEN_CONTROL_VECTORS[0].frame)
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    assert!(host_negotiate_handshake(current, config).is_ok());
    let predecessor = PluginMsg::Hello {
        proto_version: 3,
        abi_version: 1,
    };
    assert!(matches!(
        host_negotiate_handshake(predecessor, config),
        Err(HandshakeError::ProtocolVersionMismatch { .. })
    ));
}

#[test]
fn ram_control_unavailable_counters_cannot_masquerade_as_zero_measurements() {
    let request = frame(1, RamControlRequest::Status);
    let unavailable = RamControlReply {
        performance: None,
        measurements_available: false,
        private_resident_bytes: 0,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 0,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        ..state()
    };
    let response = |state| RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&request)
                .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
            state,
        },
        ..request
    };
    let valid = response(unavailable);
    assert_eq!(
        decode_ram_control(
            &encode_ram_control(&valid)
                .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
        )
        .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
        valid
    );
    assert!(
        encode_ram_control(&response(RamControlReply {
            preserved_backing_bytes: 4096,
            ..unavailable
        }))
        .is_err()
    );
    assert!(
        encode_ram_control(&response(RamControlReply {
            limitation_reasons: 64,
            ..unavailable
        }))
        .is_err()
    );
}

#[test]
fn actual_inventory_records_bind_geometry_generation_and_canonical_identity() {
    let request = frame(1, RamControlRequest::Status);
    let response = |state| RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&request)
                .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
            state,
        },
        ..request
    };
    let report = RamControlInventoryReport {
        topology_generation: 9,
        logical_bytes: 8192,
        region_count: 2,
        native_metadata_bytes: 4096,
        native_scratch_bytes: 16384,
        owner_resources: RamControlOwnerInventory {
            existing_tasks: 5,
            existing_file_descriptors: 14,
            registered_service_tasks: 1,
            prospective_tasks: 1,
            prospective_file_descriptors: 4,
        },
        granted: false,
    };
    let region = RamControlInventoryRegion::new(1, 4096, 2, "device/vram")
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    let mut observation = state();
    observation.inventory = Some(report);
    observation.inventory_region = Some(region);
    let original = response(observation);
    let bytes =
        encode_ram_control(&original).unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    assert_eq!(
        decode_ram_control(&bytes).unwrap_or_else(|_| panic!("valid test fixture must succeed")),
        original
    );
    for length in 0..bytes.len() {
        assert!(decode_ram_control(&bytes[..length]).is_err());
    }

    for invalid in [
        RamControlInventoryRegion {
            ordinal: 2,
            ..region
        },
        RamControlInventoryRegion {
            logical_length: 8193,
            ..region
        },
        RamControlInventoryRegion { class: 5, ..region },
        RamControlInventoryRegion {
            identity_length: 0,
            ..region
        },
    ] {
        observation.inventory_region = Some(invalid);
        assert!(encode_ram_control(&response(observation)).is_err());
    }
    let mut padding = region;
    padding.identity[254] = 1;
    observation.inventory_region = Some(padding);
    assert!(encode_ram_control(&response(observation)).is_err());
    observation.inventory = None;
    observation.inventory_region = Some(region);
    assert!(encode_ram_control(&response(observation)).is_err());
}

#[test]
fn initial_roster_and_exact_grants_have_one_bounded_encoding() {
    let budgets = policy().budgets;
    let bytes = encode_ram_control_budgets(&budgets)
        .unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    assert!(bytes.len() <= RAM_CONTROL_BUDGET_ROSTER_MAX_BYTES);
    assert_eq!(
        decode_ram_control_budgets(&bytes)
            .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
        budgets
    );
    for length in 0..bytes.len() {
        assert!(decode_ram_control_budgets(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_ram_control_budgets(&trailing).is_err());
    let mut unknown = bytes;
    unknown[3] = 2;
    assert!(decode_ram_control_budgets(&unknown).is_err());

    let grant = frame(
        2,
        RamControlRequest::GrantInventory {
            topology_generation: 9,
            spill_quota_bytes: 1 << 30,
            resources: RamControlResources {
                resident_peak_bytes: 1 << 30,
                backing_peak_bytes: 4 << 30,
                metadata_bytes: 32 << 20,
                staging_bytes: 4 << 20,
                paging_io_slots: 2,
                cpu_slots: 4,
                task_slots: 12,
                file_descriptors: 30,
            },
        },
    );
    let bytes =
        encode_ram_control(&grant).unwrap_or_else(|_| panic!("valid test fixture must succeed"));
    assert_eq!(
        decode_ram_control(&bytes).unwrap_or_else(|_| panic!("valid test fixture must succeed")),
        grant
    );
    let request = frame(
        3,
        RamControlRequest::InventoryRegion {
            topology_generation: 9,
            ordinal: 4095,
        },
    );
    assert_eq!(
        decode_ram_control(
            &encode_ram_control(&request)
                .unwrap_or_else(|_| panic!("valid test fixture must succeed"))
        )
        .unwrap_or_else(|_| panic!("valid test fixture must succeed")),
        request
    );
    for request in [
        RamControlRequest::InventoryRegion {
            topology_generation: 0,
            ordinal: 0,
        },
        RamControlRequest::InventoryRegion {
            topology_generation: 9,
            ordinal: 4096,
        },
        RamControlRequest::GrantInventory {
            topology_generation: 0,
            spill_quota_bytes: 0,
            resources: RamControlResources::default(),
        },
    ] {
        assert!(encode_ram_control(&frame(2, request)).is_err());
    }
}

#[test]
fn operational_activity_is_independent_of_rss_and_rejects_incomplete_or_unknown_tail() {
    let request = frame(1, RamControlRequest::Status);
    let activity = RamControlActivity {
        successful_missing_installs: 1,
        successful_missing_read_installs: 2,
        successful_missing_write_installs: 3,
        write_protect_transitions: 4,
        preservation_reads: 5,
        preservation_writes: 6,
        physical_discards: 7,
        prefetched_pages: u64::MAX,
    };
    let response = RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&request)
                .unwrap_or_else(|_| panic!("valid activity request must encode")),
            state: RamControlReply {
                performance: None,
                activity: Some(activity),
                measurements_available: false,
                private_resident_bytes: 0,
                shared_resident_bytes_observed: 0,
                preserved_backing_bytes: 0,
                private_dirty_bytes: 0,
                writeback_pending_bytes: 0,
                ..state()
            },
        },
        ..request
    };
    let encoded = encode_ram_control(&response)
        .unwrap_or_else(|_| panic!("valid operational activity must encode"));
    assert_eq!(
        decode_ram_control(&encoded)
            .unwrap_or_else(|_| panic!("valid operational activity must decode")),
        response
    );

    // Activity is followed by absent performance, probe and actor tags.
    let tail = encoded.len() - 68;
    assert_eq!(encoded[tail], 1);
    for (index, value) in [1_u64, 2, 3, 4, 5, 6, 7, u64::MAX].into_iter().enumerate() {
        let start = tail + 1 + index * 8;
        assert_eq!(&encoded[start..start + 8], &value.to_be_bytes());
    }
    for length in tail..encoded.len() {
        assert!(decode_ram_control(&encoded[..length]).is_err());
    }
    let mut unknown = encoded;
    unknown[tail] = 2;
    assert!(decode_ram_control(&unknown).is_err());
}

#[test]
fn native_probe_has_one_bounded_encoding_and_refuses_user_only_or_empty_features() {
    let request = frame(1, RamControlRequest::Status);
    let probe = RamControlKernelProbe {
        effective_uid: 65534,
        effective_gid: 65533,
        features: u64::MAX,
        mode: RamControlKernelProbeMode::FullKernel,
    };
    let reply = RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&request)
                .unwrap_or_else(|error| panic!("encode probe request: {error}")),
            state: RamControlReply {
                performance: None,
                kernel_probe: Some(probe),
                ..state()
            },
        },
        ..request
    };
    let encoded = encode_ram_control(&reply)
        .unwrap_or_else(|error| panic!("encode authenticated probe facts: {error}"));
    assert_eq!(
        decode_ram_control(&encoded)
            .unwrap_or_else(|error| panic!("decode authenticated probe facts: {error}")),
        reply
    );
    let tail = encoded.len() - 19;
    assert_eq!(&encoded[tail..tail + 2], &[1, 1]);
    assert_eq!(
        &encoded[tail + 2..tail + 6],
        &probe.effective_uid.to_be_bytes()
    );
    assert_eq!(
        &encoded[tail + 6..tail + 10],
        &probe.effective_gid.to_be_bytes()
    );
    assert_eq!(
        &encoded[tail + 10..tail + 18],
        &probe.features.to_be_bytes()
    );
    assert_eq!(encoded[tail + 18], 0);
    for length in tail..encoded.len() {
        assert!(decode_ram_control(&encoded[..length]).is_err());
    }
    for (offset, invalid) in [(tail, 2), (tail + 1, 0), (tail + 1, 2)] {
        let mut unsupported = encoded.clone();
        unsupported[offset] = invalid;
        assert!(decode_ram_control(&unsupported).is_err());
    }
    let mut empty = encoded;
    empty[tail + 10..tail + 18].fill(0);
    assert!(decode_ram_control(&empty).is_err());
}

fn actor_response(state: RamControlReply) -> RamControlFrame {
    RamControlFrame {
        session: [4; 32],
        sequence: 2,
        target: target(),
        message: RamControlMessage::Reply {
            request_digest: [8; 32],
            state,
        },
    }
}

#[test]
fn fault_actor_test_request_is_bounded_and_requires_explicit_identity() {
    let request = frame(
        2,
        RamControlRequest::TestFaultActor {
            entitlement: [9; 32],
            worker_generation: 7,
            action: RamControlFaultActorAction::RequestExit,
        },
    );
    let bytes = encode_ram_control(&request).unwrap_or_else(|error| panic!("test frame: {error}"));
    assert!(bytes.len() < RAM_CONTROL_MAX_BYTES);
    assert_eq!(
        decode_ram_control(&bytes).unwrap_or_else(|error| panic!("test decode: {error}")),
        request
    );
    for (entitlement, worker_generation) in [([0; 32], 7), ([9; 32], 0)] {
        assert!(
            encode_ram_control(&frame(
                2,
                RamControlRequest::TestFaultActor {
                    entitlement,
                    worker_generation,
                    action: RamControlFaultActorAction::RequestExit,
                }
            ))
            .is_err()
        );
    }
}

#[test]
fn fault_actor_report_distinguishes_request_failure_and_role_release() {
    let mut reply = state();
    let mut report = RamControlFaultActorReport {
        worker_generation: 7,
        thread_id: 123,
        exit_requested: true,
        failure: None,
        membership_released: false,
    };
    for failure in [
        None,
        Some(RamControlFaultActorFailure::RequestedExit),
        Some(RamControlFaultActorFailure::Io { errno: 5 }),
    ] {
        report.failure = failure;
        report.membership_released = failure.is_some();
        reply.fault_actor = Some(report);
        let message = actor_response(reply);
        let bytes =
            encode_ram_control(&message).unwrap_or_else(|error| panic!("actor report: {error}"));
        assert_eq!(
            decode_ram_control(&bytes).unwrap_or_else(|error| panic!("actor decode: {error}")),
            message
        );
    }
    report.failure = None;
    report.membership_released = true;
    reply.fault_actor = Some(report);
    assert!(encode_ram_control(&actor_response(reply)).is_err());
    report.membership_released = false;
    report.thread_id = 0;
    reply.fault_actor = Some(report);
    assert!(encode_ram_control(&actor_response(reply)).is_err());
}

#[test]
fn original_operation_failure_preserves_the_cut_and_rejects_invalid_scalar_causes() {
    let failure = RamControlOperationFailure {
        operation: RamControlFailureOperation::Writeback,
        policy_revision: 31,
        topology_generation: 47,
        cause: RamControlFailureCause::Io { errno: 5 },
    };
    for cause in [
        failure.cause,
        RamControlFailureCause::Native { status: -5 },
        RamControlFailureCause::Supervision {
            kind: RamControlSupervisionFailure::Canceled,
        },
        RamControlFailureCause::Other,
    ] {
        let message = actor_response(RamControlReply {
            performance: None,
            operation_failure: Some(RamControlOperationFailure { cause, ..failure }),
            ..state()
        });
        let bytes = encode_ram_control(&message)
            .unwrap_or_else(|error| panic!("original operation report: {error}"));
        assert!(bytes.len() < RAM_CONTROL_MAX_BYTES);
        assert_eq!(
            decode_ram_control(&bytes)
                .unwrap_or_else(|error| panic!("original operation decode: {error}")),
            message
        );
        assert!(decode_ram_control(&bytes[..bytes.len() - 1]).is_err());
    }
    for cause in [
        RamControlFailureCause::Io { errno: -5 },
        RamControlFailureCause::Native { status: 0 },
    ] {
        let message = actor_response(RamControlReply {
            performance: None,
            operation_failure: Some(RamControlOperationFailure { cause, ..failure }),
            ..state()
        });
        assert!(encode_ram_control(&message).is_err());
    }
}

#[test]
fn performance_actions_and_exact_partial_work_roundtrip() {
    for action in [
        RamControlPerformanceAction::Start,
        RamControlPerformanceAction::Observe,
        RamControlPerformanceAction::Stop,
    ] {
        let request = frame(1, RamControlRequest::Performance { action });
        let encoded = encode_ram_control(&request).unwrap();
        assert_eq!(decode_ram_control(&encoded).unwrap(), request);
        let mut predecessor = encoded.clone();
        predecessor[..4].copy_from_slice(&5u32.to_be_bytes());
        assert!(matches!(
            decode_ram_control(&predecessor),
            Err(RamControlError::UnsupportedVersion(5))
        ));
        let mut invalid_action = encoded;
        *invalid_action.last_mut().unwrap() = 3;
        assert!(decode_ram_control(&invalid_action).is_err());
    }
    let mut report = RamControlPerformance {
        generation: 1,
        active: false,
        complete: true,
        pending_operations: 0,
        io: [RamControlIoMeasurement::default(); RAM_PERFORMANCE_IO_CLASSES],
    };
    report.io[RamControlIoClass::PageRead as usize] = RamControlIoMeasurement {
        operations: 2,
        completed: 1,
        failed: 1,
        syscalls: 4,
        transferred_bytes: 17 + 7,
        elapsed_ns: 900,
        maximum_elapsed_ns: 700,
    };
    let mut reply = state();
    reply.performance = Some(report);
    let response = RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: [9; 32],
            state: reply,
        },
        ..frame(2, RamControlRequest::Status)
    };
    assert_eq!(
        decode_ram_control(&encode_ram_control(&response).unwrap()).unwrap(),
        response
    );
    for invalid in 0..4 {
        let mut report = report;
        match invalid {
            0 => report.generation = 0,
            1 => report.io[0].operations += 1,
            2 => report.io[0].maximum_elapsed_ns = 901,
            _ => report.io[RamControlIoClass::Sync as usize].transferred_bytes = 1,
        }
        let mut response = response;
        if let RamControlMessage::Reply { state, .. } = &mut response.message {
            state.performance = Some(report);
        }
        assert!(encode_ram_control(&response).is_err());
    }
}
