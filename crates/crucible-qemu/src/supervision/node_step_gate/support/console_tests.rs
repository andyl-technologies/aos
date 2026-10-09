//! Real priming-loop custody with explicit modeled UART and CLOSED-RR providers.
//!
//! The original loop, publishers, clamp, request claim and prefix consumer run
//! unchanged host implementations. These providers do not establish native
//! dispatch, phase authority or an actual translated UART stop.

use super::*;
use crate::QemuHostIoRuntime;
use crate::native_console_owner::ConsoleOwnerError;
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};
use crucible_protocol::native_console::{
    NativeConsoleAuthorization, NativeConsoleFrontier, NativeConsoleOrigin, NativeConsoleRecord,
};
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

fn stage_modeled_uart(
    region: &crucible_shmem::MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    emitted_ps: u64,
    count: usize,
    byte: u8,
) -> Result<(), FixtureError> {
    let segment = region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?;
    let records: Vec<_> = (0..count)
        .map(|index| NativeConsoleRecord {
            owner: authorization.owner,
            origin: NativeConsoleOrigin {
                stream: 1,
                logical_generation: authorization.logical_generation,
                node_sequence: authorization.prior_sequence + index as u64 + 1,
                stream_sequence: authorization.prior_sequence + index as u64 + 1,
                logical_ps: emitted_ps + index as u64,
                raw_prefix: 0,
                vcpu: 0,
                byte,
            },
            authorization_advance: authorization.advance,
            phase: authorization.phase,
        })
        .collect();
    segment
        .ring
        .stage_native_console(segment.records, &records)?;
    Ok(())
}

fn complete_modeled_native_clamp(
    fixture: &LaunchFixture,
    region: &crucible_shmem::MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    ps: u64,
    notifications: &mut UnixStream,
) -> Result<(), FixtureError> {
    read_clamp_wake(notifications)?;
    publish_modeled_native_frontier(fixture, region, authorization, ps)
}

fn read_clamp_wake(notifications: &mut UnixStream) -> Result<(), FixtureError> {
    let mut wake = [0; 8];
    notifications.read_exact(&mut wake)?;
    assert_eq!(u64::from_ne_bytes(wake), 1);
    Ok(())
}

fn publish_modeled_native_frontier(
    fixture: &LaunchFixture,
    region: &crucible_shmem::MappedSetupRegion,
    authorization: NativeConsoleAuthorization,
    ps: u64,
) -> Result<(), FixtureError> {
    let segment = region
        .native_console_segment(0)
        .map_err(ConsoleOwnerError::from)?;
    let paired = segment.clamp.snapshot()?;
    assert_eq!(paired.last_issued, Some(authorization));
    let ring_end = segment.ring.write_index();
    segment.frontier.store(NativeConsoleFrontier {
        sequence: authorization.prior_sequence + ring_end - authorization.prior_ring_end,
        ring_end,
        logical_ps: ps,
        raw_prefix: u64::from(ps >= 50),
        owner: authorization.owner,
        accepted_advance: paired.advance,
        logical_generation: authorization.logical_generation,
        request: paired.request,
        plan_hash: fixture.plan_hash()?,
    })?;
    let slot = region.node_slot(0)?;
    slot.publish_control_boundary(ps, u64::from(ps >= 50))?;
    slot.acknowledge_control_boundary();
    Ok(())
}

fn enqueue_block_request(
    region: &mut crucible_shmem::MappedSetupRegion,
    current: u64,
    payload: &[u8],
) -> Result<(), FixtureError> {
    let frame = crucible_shmem::FrameEntry::new(current, 0, 7, payload)?;
    let pair = region.node_directed_ring_pair_mut(
        0,
        0,
        crucible_shmem::SLOT_BLK_IO as u32,
        crucible_shmem::SLOT_BLK_IO as u32,
        0,
    )?;
    pair.first.header.enqueue(pair.first.entries, &frame)?;
    Ok(())
}

fn dequeue_block_response(
    region: &mut crucible_shmem::MappedSetupRegion,
) -> Result<crucible_shmem::FrameEntry, FixtureError> {
    let pair = region.node_directed_ring_pair_mut(
        0,
        0,
        crucible_shmem::SLOT_BLK_IO as u32,
        crucible_shmem::SLOT_BLK_IO as u32,
        0,
    )?;
    pair.second
        .header
        .dequeue(pair.second.entries)?
        .ok_or(FixtureError::Peer(
            "original block response was absent".into(),
        ))
}

/// Waits on the original real eventfd, under one bounded provider deadline.
fn wait_for_real_regrant(
    fixture: &LaunchFixture,
    wake: &mut File,
    previous: NativeConsoleAuthorization,
) -> Result<NativeConsoleAuthorization, FixtureError> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let deadline = HostSupervisionDeadline::start(Duration::from_secs(1));
    while let Some(remaining) = deadline
        .remaining()
        .filter(|remaining| !remaining.is_zero())
    {
        let timeout = Timespec::try_from(remaining)
            .map_err(|error| FixtureError::Peer(format!("provider timeout: {error}")))?;
        let mut descriptors = [PollFd::new(&*wake, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(std::io::Error::from(error).into()),
            Ok(_) if !descriptors[0].revents().contains(PollFlags::IN) => continue,
            Ok(_) => {}
        }
        let mut counter = [0; 8];
        wake.read_exact(&mut counter)?;
        let current = fixture.authorization()?;
        if current.owner.authorization != previous.owner.authorization {
            return Ok(current);
        }
    }
    Err(FixtureError::Peer(
        "original priming loop did not publish a regrant".into(),
    ))
}

#[test]
fn original_prime_loop_accepts_early_prefix_before_regrant_and_retains_more_than_one_ring()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold_with_allowance(1, 4096)?;
    let mut region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let mut hot_path = fixture.hot_path()?;
    let horizon = crucible::ExecutionHorizon {
        icount: Icount { retired: 10_000 },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        horizon,
        crate::QemuQuantumStopCondition::Ceiling,
    )?;
    let original = fixture.authorization()?;
    stage_modeled_uart(&region, original, 1000, 2048, b'a')?;
    region.node_slot(0)?.publish_idle(4000, 4000)?;

    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    let mut plugin_wake = File::from(fixture.setup.wake_as_fd().try_clone_to_owned()?);
    let deadline = HostSupervisionDeadline::start(Duration::from_secs(1));
    let mut block = QemuLiveBlockIoServicer::from_shmem_fd_with_base_and_latency(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
        0,
        BaseImage::new(vec![0x5a; 4096]),
        BlockLatency::new(0, 0, 0, 0, 0),
    )?;
    let setup = &fixture.setup;
    let (mut runtime, host_result, provider_result) = std::thread::scope(|scope| {
        let provider = scope.spawn(|| -> Result<(), FixtureError> {
            // A real post-stop request arrives after the original clamp wake.
            // The sole borrowed priming servicer must DELIVER it before the
            // modeled native callback can settle the hold and acknowledge.
            read_clamp_wake(&mut notifications)?;
            region.node_slot(0)?.mark_device_io_active();
            let request = crucible_device::block::BlockRequest::read(7, 0, 8).encode()?;
            enqueue_block_request(&mut region, 4000, &request)?;
            read_clamp_wake(&mut notifications)?;
            let reply = dequeue_block_response(&mut region)?;
            assert_eq!(reply.delivery_icount, 4000);
            assert_eq!(reply.src_node, crucible_shmem::SLOT_BLK_IO as u32);
            let response = crucible_device::block::BlockResponse::decode(reply.payload()?)?;
            assert_eq!(response.request_id, 7);
            assert_eq!(response.data, vec![0x5a; 8]);
            assert!(fixture.pending_origins()?.is_empty());
            assert_eq!(
                region
                    .native_console_segment(0)
                    .map_err(ConsoleOwnerError::from)?
                    .ring
                    .read_index(),
                0
            );
            region.node_slot(0)?.clear_device_io_active();
            publish_modeled_native_frontier(&fixture, &region, original, 4000)?;
            let second = wait_for_real_regrant(&fixture, &mut plugin_wake, original)?;
            assert_eq!(second.prior_sequence, 2048);
            assert_eq!(second.prior_ring_end, 2048);
            assert_eq!(
                region
                    .native_console_segment(0)
                    .map_err(ConsoleOwnerError::from)?
                    .ring
                    .read_index(),
                2048
            );
            assert_eq!(fixture.pending_origins()?.len(), 2048);
            stage_modeled_uart(&region, second, 5000, 2049, b'b')?;
            region.node_slot(0)?.publish_idle(8000, 8000)?;
            complete_modeled_native_clamp(&fixture, &region, second, 8000, &mut notifications)?;
            let final_body = wait_for_real_regrant(&fixture, &mut plugin_wake, second)?;
            assert_eq!(final_body.prior_sequence, 4097);
            assert_eq!(final_body.prior_ring_end, 4097);
            region.node_slot(0)?.publish_reached_icount(10_000)?;
            Ok(())
        });
        // The original opaque pending token stays on its owning host thread.
        let result = poll_mapped_prime_chain(
            setup,
            &deadline,
            &mut hot_path,
            pending,
            10_000,
            PrimeDeviceServicers {
                block: Some(&mut block),
                ninep: None,
                runtime: &mut runtime,
            },
            false,
        );
        // Reap the provider even when the original host waiter refuses.
        let provider = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
        Ok::<_, FixtureError>((runtime, result, provider))
    })?;
    provider_result?;
    assert_eq!(block.frames_processed(), 1);
    assert_eq!(block.frames_delivered(), 1);
    assert!(
        host_result
            .map_err(|source| FixtureError::Priming {
                source: Box::new(source)
            })?
            .is_empty()
    );

    // Final-ceiling completion still passes through the original handoff; the
    // early-loop clamps did not duplicate that final request or invent a grant.
    let final_body = fixture.authorization()?;
    let host = std::thread::spawn(move || {
        let result = runtime.fence_priming_handoff(Duration::from_secs(1));
        (runtime, result)
    });
    let provider =
        complete_modeled_native_clamp(&fixture, &region, final_body, 10_000, &mut notifications);
    let (runtime, result) = host.join().map_err(|_| FixtureError::PeerPanicked)?;
    provider?;
    result?;
    assert_eq!(
        runtime
            .completed_quantum_boundary()
            .ok_or(ConsoleOwnerError::Storage)?
            .calibration()
            .logical_icount,
        10_000
    );
    fixture.assert_issued_advances(&[])?;
    let origins = fixture.pending_origins()?;
    assert_eq!(origins.len(), 4097);
    assert_eq!((origins[0].emitted_ps, origins[0].byte), (1000, b'a'));
    assert_eq!((origins[2047].emitted_ps, origins[2047].byte), (3047, b'a'));
    assert_eq!((origins[2048].emitted_ps, origins[2048].byte), (5000, b'b'));
    assert_eq!((origins[4096].emitted_ps, origins[4096].byte), (7048, b'b'));
    assert!(
        origins
            .iter()
            .all(|origin| origin.logical_generation == 0 && origin.raw_prefix == 0)
    );
    assert_eq!(origins[4096].node_sequence, 4097);
    fixture.finish()
}

#[test]
fn expired_or_changed_prime_completion_does_not_publish_a_clamp() -> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let mut hot_path = fixture.hot_path()?;
    QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        crucible::ExecutionHorizon {
            icount: Icount { retired: 100 },
        },
        crate::QemuQuantumStopCondition::Ceiling,
    )?;
    let region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    region.node_slot(0)?.publish_reached_icount(50)?;
    let before = region.node_slot(0)?.snapshot();
    let (notifications, wake) = UnixStream::pair()?;
    notifications.set_nonblocking(true)?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    assert!(
        runtime
            .fence_priming_console_completion(
                Icount { retired: 50 },
                &HostSupervisionDeadline::start(Duration::ZERO),
                None,
                None
            )
            .is_err()
    );
    assert!(
        runtime
            .fence_priming_console_completion(
                Icount { retired: 49 },
                &HostSupervisionDeadline::start(Duration::from_secs(1)),
                None,
                None
            )
            .is_err()
    );
    assert_eq!(region.node_slot(0)?.try_snapshot(), Some(before));
    fixture.assert_issued_advances(&[2])?;
    let mut counter = [0; 8];
    assert!(
        (&notifications)
            .read(&mut counter)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
    );
    fixture.finish()
}

#[test]
fn ordinary_prime_completion_does_not_read_or_wake_console_state() -> Result<(), FixtureError> {
    let mut fixture = LaunchFixture::cold(1)?;
    fixture.setup.console_custody = None;
    use std::os::unix::fs::FileExt;
    let file = File::from(fixture.setup.shmem_as_fd().try_clone_to_owned()?);
    let layout = crucible_shmem::RegionLayout::for_config(crucible_shmem::RegionConfig::new(1, 4))?;
    let offset = layout.node_slots_off + crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64;
    file.write_all_at(&1_u32.to_ne_bytes(), offset)?;
    let (notifications, wake) = UnixStream::pair()?;
    notifications.set_nonblocking(true)?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.fence_priming_console_completion(
        Icount { retired: u64::MAX },
        &HostSupervisionDeadline::start(Duration::ZERO),
        None,
        None,
    )?;
    let mut publication = [0; 4];
    file.read_exact_at(&mut publication, offset)?;
    assert_eq!(u32::from_ne_bytes(publication), 1);
    let mut counter = [0; 8];
    assert!(
        (&notifications)
            .read(&mut counter)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
    );
    file.write_all_at(&2_u32.to_ne_bytes(), offset)?;
    fixture.finish()
}

#[test]
fn post_stop_device_refusal_retains_prefix_and_prevents_a_prime_regrant() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::cold(1)?;
    let mut region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let mut hot_path = fixture.hot_path()?;
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        crucible::ExecutionHorizon {
            icount: Icount { retired: 100 },
        },
        crate::QemuQuantumStopCondition::Ceiling,
    )?;
    let original = fixture.authorization()?;
    stage_modeled_uart(&region, original, 10, 1, b'x')?;
    region.node_slot(0)?.publish_idle(50, 50)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    let mut block = QemuLiveBlockIoServicer::from_shmem_fd_with_base_and_latency(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
        0,
        BaseImage::new(vec![0x5a; 4096]),
        BlockLatency::new(0, 0, 0, 0, 0),
    )?;
    let setup = &fixture.setup;
    let deadline = HostSupervisionDeadline::start(Duration::from_secs(1));
    let (result, provider) = std::thread::scope(|scope| {
        let provider = scope.spawn(|| -> Result<(), FixtureError> {
            read_clamp_wake(&mut notifications)?;
            region.node_slot(0)?.mark_device_io_active();
            // An actual malformed request reaches the sole real initialization
            // servicer after the stop; no synthetic service-error callback.
            enqueue_block_request(&mut region, 50, &[0xff])?;
            Ok(())
        });
        let result = poll_mapped_prime_chain(
            setup,
            &deadline,
            &mut hot_path,
            pending,
            100,
            PrimeDeviceServicers {
                block: Some(&mut block),
                ninep: None,
                runtime: &mut runtime,
            },
            false,
        );
        let provider = provider.join().map_err(|_| FixtureError::PeerPanicked)?;
        Ok::<_, FixtureError>((result, provider))
    })?;
    provider?;
    assert!(matches!(
        result,
        Err(QemuLiveNodeStepGateError::PrimeHandoff { .. })
    ));
    assert_eq!(fixture.authorization()?, original);
    fixture.assert_issued_advances(&[2])?;
    assert_eq!(
        region.node_slot(0)?.snapshot().advance_publication_sequence,
        4
    );
    assert!(fixture.pending_origins()?.is_empty());
    assert_eq!(
        region
            .native_console_segment(0)
            .map_err(ConsoleOwnerError::from)?
            .ring
            .read_index(),
        0
    );
    fixture.finish()
}

#[test]
fn actual_canary_completion_is_accepted_before_the_continuation_grant() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::cold(2)?;
    let mut region = mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let identity = QemuLiveNodeIdentity::new("vm", "router", "crash");
    let payload = b"retained boot canary";
    let prepared = prepare_guest_prime(
        &fixture.setup,
        Duration::from_secs(1),
        identity,
        QemuLaunchPluginSwitch::Off,
        Some(payload),
    )
    .map_err(|source| FixtureError::Priming {
        source: Box::new(source),
    })?;
    let original = fixture.authorization()?;
    {
        let router = SLOT_NET_ROUTER as u32;
        let pair = region.node_directed_ring_pair_mut(0, 0, router, router, 0)?;
        let canary = pair
            .second
            .header
            .peek(pair.second.entries)?
            .ok_or(FixtureError::Peer(
                "original injected canary was absent".into(),
            ))?;
        assert_eq!(canary.delivery_icount, 1);
        assert_eq!(canary.src_node, router);
        assert_eq!(canary.seq, 0);
        assert_eq!(canary.payload()?, payload);

        // This explicit modeled native delivery provider retains the original
        // live head under backpressure; it neither drops nor dequeues the frame.
        let index = pair.second.header.read_index() & (pair.second.entries.len() as u64 - 1);
        let entry = &pair.second.entries[index as usize];
        assert_eq!(
            entry.record_delivery_attempt(1, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)?,
            1
        );
        entry.mark_delivery_retained()?;
    }
    region.node_slot(0)?.publish_reached_icount(1)?;
    let (mut notifications, wake) = UnixStream::pair()?;
    notifications.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        fixture.setup.shmem_as_fd(),
        wake.as_fd(),
        fixture.setup.region().region_len,
        0,
    )?;
    runtime.retain_console_launch(&fixture.setup)?;
    let primed = complete_guest_prime(
        &fixture.setup,
        prepared,
        None,
        None,
        &mut runtime,
        Some(payload),
    )
    .map_err(|source| FixtureError::Priming {
        source: Box::new(source),
    })?;
    let initial_network = primed.retained_network.ok_or(FixtureError::Peer(
        "original canary transport was absent".into(),
    ))?;
    let mut plugin_wake = File::from(fixture.setup.wake_as_fd().try_clone_to_owned()?);
    let setup = &fixture.setup;
    let (result, provider) = std::thread::scope(|scope| {
        let host = scope.spawn(move || {
            continue_boot_network_backpressure_capture(
                setup,
                Duration::from_secs(1),
                identity,
                QemuLaunchPluginSwitch::Off,
                BootNetworkBackpressureContinuation {
                    block: None,
                    ninep: None,
                    runtime: &mut runtime,
                    payload,
                    capture_icount: 100,
                    initial_network,
                    emitted_frames: primed.emitted_frames,
                    observable_events: primed.observable_events,
                },
            )
        });
        let provider = (|| -> Result<(), FixtureError> {
            complete_modeled_native_clamp(&fixture, &region, original, 1, &mut notifications)?;
            let continued = wait_for_real_regrant(&fixture, &mut plugin_wake, original)?;
            assert_eq!(continued.prior_sequence, 0);
            assert_eq!(continued.prior_ring_end, 0);
            // The canary's two original issuances have been retired before this
            // new continuation issuance reuses the configured inventory.
            fixture.assert_issued_advances(&[continued.advance])?;
            region.node_slot(0)?.publish_reached_icount(100)?;
            Ok(())
        })();
        let result = host.join().map_err(|_| FixtureError::PeerPanicked)?;
        Ok::<_, FixtureError>((result, provider))
    })?;
    provider?;
    let outcome = result.map_err(|source| FixtureError::Priming {
        source: Box::new(source),
    })?;
    assert!(outcome.retained_network.is_some());
    assert!(fixture.pending_origins()?.is_empty());
    fixture.finish()
}
