//! Real shared mappings with controlled original-publication/ACK providers.
//!
//! These tests exercise transport and ordering, not native UART/TCG ownership.
//! The publication/ACK atomics are explicit test providers. The future adapter
//! must join them to the genuine original NodeSlot writer and accepted boundary.

use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Barrier};

use crucible_protocol::native_console::*;

use super::*;
use crate::{MappedSetupRegion, RegionAllocation, RegionConfig, RingHeader, mmap_setup_region};

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Layout(#[from] crate::RegionLayoutError),
    #[error(transparent)]
    Serialization(#[from] crate::RegionSerializationError),
    #[error(transparent)]
    Mapping(#[from] crate::SetupRegionMapError),
    #[error(transparent)]
    Shape(#[from] NativeConsoleError),
    #[error(transparent)]
    Ring(#[from] NativeConsoleRingError),
}

#[test]
fn native_console_generated_portable_header_matches_the_committed_draft() {
    assert_eq!(
        generated_native_console_c_header(),
        include_str!("../../include/crucible_native_console_draft.h")
    );
}

fn fixture() -> Result<
    (
        std::fs::File,
        MappedSetupRegion,
        MappedSetupRegion,
        NativeConsoleSegmentLayout,
    ),
    FixtureError,
> {
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "crucible-console-wire-{}-{}",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::fs::remove_file(path)?;
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4))?;
    let image = allocation.setup_region_bytes()?;
    let region = allocation.layout();
    let layout = NativeConsoleSegmentLayout::new(region.native_console_off as usize, image.len())?;
    file.set_len(image.len() as u64)?;
    file.write_all_at(&image, 0)?;
    let producer = mmap_setup_region(file.as_fd(), image.len() as u64)?;
    let consumer = mmap_setup_region(file.as_fd(), image.len() as u64)?;
    Ok((file, producer, consumer, layout))
}

fn plan() -> NativeConsolePlan {
    NativeConsolePlan {
        slot: 0,
        logical_generation: 3,
        node_sequence_base: 0,
        streams: vec![NativeConsoleStream {
            stream: 7,
            device: NativeConsoleDevice::Serial16550,
            device_identity: [9; 32],
            owner_mask: 1,
            sequence_base: 0,
        }],
    }
}

fn grant() -> NativeConsoleAuthorization {
    NativeConsoleAuthorization {
        publication: 2,
        owner: NativeConsoleOwner {
            slot: 0,
            region: [4; 16],
            process: 8,
            authorization: 10,
        },
        logical_generation: 3,
        advance: 12,
        prior_sequence: 0,
        prior_ring_end: 0,
        allowance: 2,
        phase_token: 1,
        phase: NativeConsolePhase::Grant,
    }
}

fn record(sequence: u64) -> NativeConsoleRecord {
    NativeConsoleRecord {
        owner: grant().owner,
        authorization_advance: 12,
        phase: NativeConsolePhase::Grant,
        origin: NativeConsoleOrigin {
            stream: 7,
            logical_generation: 3,
            node_sequence: sequence,
            stream_sequence: sequence,
            logical_ps: sequence * 50,
            raw_prefix: sequence,
            vcpu: 0,
            byte: sequence as u8,
        },
    }
}

fn frontier() -> Result<NativeConsoleFrontier, NativeConsoleError> {
    Ok(NativeConsoleFrontier {
        sequence: 2,
        ring_end: 2,
        logical_ps: 100,
        raw_prefix: 2,
        owner: grant().owner,
        accepted_advance: 14,
        logical_generation: 3,
        request: 2,
        plan_hash: plan().digest()?,
    })
}

#[test]
fn native_console_mapped_prefix_stays_staged_until_complete_joined_frontier()
-> Result<(), FixtureError> {
    let (_file, producer, consumer, _layout) = fixture()?;
    let source = producer.native_console_segment(0)?;
    let target = consumer.native_console_segment(0)?;
    let capability = NativeConsoleCapability {
        slot: grant().owner.slot,
        region: grant().owner.region,
        process: grant().owner.process,
        plan_hash: plan().digest()?,
        resolved_streams: [6; 32],
    };
    assert!(target.capability.copy().is_err());
    source.capability.publish(capability)?;
    // The actual setup ACK is an external adapter obligation; this only
    // exercises the mapped shape copy after the controlled producer returns.
    assert_eq!(target.capability.copy()?, capability);
    source.authorization.publish(grant())?;
    assert_eq!(target.authorization.snapshot()?, grant());
    source
        .ring
        .stage_native_console(source.records, &[record(1), record(2)])?;
    assert!(target.frontier.copy().is_err());
    assert_eq!(target.ring.read_idx.load(Ordering::Acquire), 0);

    // Explicit provider brackets the same atomic frontier fields that the
    // native adapter must place inside its original publication interval.
    let publication = Arc::new(AtomicU32::new(1));
    let ack = Arc::new(AtomicU32::new(2));
    let written = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let expected_frontier = frontier()?;
    let (unpublished, stored) = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let stored = source.frontier.store(expected_frontier);
            written.wait();
            release.wait();
            if stored.is_ok() {
                publication.store(2, Ordering::Release);
                ack.store(3, Ordering::Release);
            }
            stored
        });
        written.wait();
        let observed = (
            ack.load(Ordering::Acquire),
            publication.load(Ordering::Acquire),
            target.ring.read_idx.load(Ordering::Acquire),
        );
        release.wait();
        (observed, writer.join())
    });
    stored.map_err(|_| std::io::Error::other("publication provider panicked"))??;
    assert_eq!(unpublished, (2, 1, 0));
    assert_eq!(ack.load(Ordering::Acquire), 3);
    let before = publication.load(Ordering::Acquire);
    let accepted = target.frontier.copy()?;
    assert_eq!(publication.load(Ordering::Acquire), before);
    assert_eq!(before & 1, 0);
    let prefix = target.ring.prepare_native_console_prefix(
        target.records,
        &plan(),
        target.authorization.snapshot()?,
        accepted,
        0,
        &[0],
    )?;
    assert_eq!(prefix.records(), &[record(1), record(2)]);
    assert_eq!(prefix.node_sequence(), 2);
    assert_eq!(prefix.stream_sequences(), &[2]);
    assert_eq!(target.ring.read_idx.load(Ordering::Acquire), 0);
    // This represents the host's evidence commit; acknowledgement follows it.
    let evidence = prefix.records().to_vec();
    target.ring.acknowledge_native_console_prefix(prefix)?;
    assert_eq!(evidence, vec![record(1), record(2)]);
    assert_eq!(source.ring.read_idx.load(Ordering::Acquire), 2);
    Ok(())
}

#[test]
fn native_console_mapped_refusals_preserve_prior_indices_and_evidence() -> Result<(), FixtureError>
{
    let (_file, producer, consumer, _layout) = fixture()?;
    let source = producer.native_console_segment(0)?;
    let target = consumer.native_console_segment(0)?;
    source
        .ring
        .stage_native_console(source.records, &[record(1), record(2)])?;
    let evidence: Vec<NativeConsoleRecord> = Vec::new();
    for changed in [
        NativeConsoleFrontier {
            ring_end: 3,
            ..frontier()?
        },
        NativeConsoleFrontier {
            sequence: 3,
            ..frontier()?
        },
        NativeConsoleFrontier {
            logical_ps: 99,
            ..frontier()?
        },
        NativeConsoleFrontier {
            raw_prefix: 1,
            ..frontier()?
        },
        NativeConsoleFrontier {
            owner: NativeConsoleOwner {
                process: 9,
                ..grant().owner
            },
            ..frontier()?
        },
        NativeConsoleFrontier {
            plan_hash: [1; 32],
            ..frontier()?
        },
    ] {
        assert!(
            target
                .ring
                .prepare_native_console_prefix(target.records, &plan(), grant(), changed, 0, &[0])
                .is_err()
        );
        assert_eq!(target.ring.read_idx.load(Ordering::Acquire), 0);
        assert!(evidence.is_empty());
    }
    for changed in [
        NativeConsoleRecord {
            owner: NativeConsoleOwner {
                region: [5; 16],
                ..grant().owner
            },
            ..record(2)
        },
        NativeConsoleRecord {
            authorization_advance: 14,
            ..record(2)
        },
        NativeConsoleRecord {
            origin: NativeConsoleOrigin {
                stream_sequence: 3,
                ..record(2).origin
            },
            ..record(2)
        },
        NativeConsoleRecord {
            origin: NativeConsoleOrigin {
                vcpu: 1,
                ..record(2).origin
            },
            ..record(2)
        },
    ] {
        source.records[1].store(&changed.encode()?);
        assert!(
            target
                .ring
                .prepare_native_console_prefix(
                    target.records,
                    &plan(),
                    grant(),
                    frontier()?,
                    0,
                    &[0]
                )
                .is_err()
        );
        assert_eq!(target.ring.read_idx.load(Ordering::Acquire), 0);
    }
    source.records[1].store(&record(2).encode()?);
    let mut malformed = record(2).encode()?;
    malformed[127] = 1;
    source.records[1].store(&malformed);
    assert!(
        target
            .ring
            .prepare_native_console_prefix(target.records, &plan(), grant(), frontier()?, 0, &[0])
            .is_err()
    );
    Ok(())
}

#[test]
fn native_console_mapped_admission_capacity_and_ring_binding_refuse_atomically()
-> Result<(), FixtureError> {
    let (_file, producer, consumer, _layout) = fixture()?;
    let source = producer.native_console_segment(0)?;
    let target = consumer.native_console_segment(0)?;
    let _ = source.ring.hold_hot_fork_producers();
    assert!(
        source
            .ring
            .stage_native_console(source.records, &[record(1)])
            .is_err()
    );
    assert_eq!(source.ring.write_idx.load(Ordering::Acquire), 0);
    let _ = source.ring.release_hot_fork_producers();
    let large = vec![record(1); NATIVE_CONSOLE_CAPACITY as usize + 1];
    assert!(
        source
            .ring
            .stage_native_console(source.records, &large)
            .is_err()
    );
    assert_eq!(source.records[0].load(), [0; 128]);
    source
        .ring
        .stage_native_console(source.records, &[record(1), record(2)])?;
    let _ = target.ring.hold_hot_fork_consumers();
    assert!(
        target
            .ring
            .prepare_native_console_prefix(target.records, &plan(), grant(), frontier()?, 0, &[0])
            .is_err()
    );
    let _ = target.ring.release_hot_fork_consumers();
    let prefix = target.ring.prepare_native_console_prefix(
        target.records,
        &plan(),
        grant(),
        frontier()?,
        0,
        &[0],
    )?;
    let foreign = RingHeader::new();
    assert!(foreign.acknowledge_native_console_prefix(prefix).is_err());
    assert_eq!(target.ring.read_idx.load(Ordering::Acquire), 0);
    source.ring.write_idx.store(u64::MAX, Ordering::Release);
    source.ring.read_idx.store(u64::MAX, Ordering::Release);
    assert!(
        source
            .ring
            .stage_native_console(source.records, &[record(1)])
            .is_err()
    );
    assert_eq!(source.ring.write_idx.load(Ordering::Acquire), u64::MAX);
    Ok(())
}

#[test]
fn native_console_mapping_refuses_old_versions_and_forged_geometry() -> Result<(), FixtureError> {
    assert_eq!(crate::ABI_VERSION, NATIVE_CONSOLE_REQUIRED_SHMEM_ABI);
    assert_eq!(
        crucible_protocol::CONTROL_PROTOCOL_VERSION,
        NATIVE_CONSOLE_REQUIRED_CONTROL_VERSION
    );
    assert_eq!(
        crucible_protocol::plugin_setup_plan::PLUGIN_SETUP_PLAN_VERSION,
        NATIVE_CONSOLE_REQUIRED_SETUP_SCHEMA
    );
    let (file, producer, _consumer, layout) = fixture()?;
    file.write_all_at(&30_u32.to_le_bytes(), 8)?;
    assert!(producer.native_console_segment(0).is_err());

    file.write_all_at(&crate::ABI_VERSION.to_le_bytes(), 8)?;
    file.write_all_at(&((layout.end - 1) as u64).to_le_bytes(), 48)?;
    assert!(producer.native_console_segment(0).is_err());
    assert!(NativeConsoleSegmentLayout::new(layout.capability + 1, layout.end).is_err());
    assert!(NativeConsoleSegmentLayout::new(layout.capability, layout.end - 1).is_err());
    assert!(NativeConsoleSegmentLayout::new(usize::MAX & !127, usize::MAX).is_err());
    Ok(())
}

#[test]
fn accounted_operation_stop_table_is_visible_only_after_its_same_node_writer_closes()
-> Result<(), FixtureError> {
    let (_file, producer, consumer, _) = fixture()?;
    let writer = producer
        .node_slot(0)
        .map_err(|_| NativeConsoleError::Binding)?;
    let observer = consumer
        .node_slot(0)
        .map_err(|_| NativeConsoleError::Binding)?;
    let table = producer
        .native_console_segment(0)
        .map_err(|_| NativeConsoleError::Binding)?
        .operation_stop;
    assert_eq!(table.try_snapshot()?, None);
    writer
        .publish_pause_quiesced_with_effect(100, 1, |publication| {
            let row = NativeConsoleOperationStop {
                publication: 2,
                ring_end: 1,
                node_sequence: 1,
                logical_ps: publication.logical(),
                raw_prefix: publication.raw(),
                owner: grant().owner,
                authorization_advance: 12,
                logical_generation: 3,
                vcpu: 0,
                closed_generation: publication.closed_generation(),
                control_boundary_ack: writer.control_boundary_token(),
                stopped_advance: 0,
            };
            table.store(row)?;
            assert!(observer.try_snapshot().is_none());
            Ok::<_, NativeConsoleError>(())
        })
        .map_err(|_| NativeConsoleError::Binding)?;
    let row = table.snapshot()?;
    assert_eq!(row.closed_generation, observer.snapshot().publish_gen);
    assert_eq!(row.raw_prefix, 1);
    assert_eq!(row.logical_ps, 100);
    let bytes = row.encode()?;
    assert_eq!(&bytes[104..108], &row.closed_generation.to_le_bytes());
    assert_eq!(NativeConsoleOperationStop::decode(&bytes)?, row);
    let mut reserved = bytes;
    reserved[127] = 1;
    assert!(NativeConsoleOperationStop::decode(&reserved).is_err());
    Ok(())
}

#[test]
fn accounted_operation_stop_refuses_stale_or_invalid_rows_without_replacing_body()
-> Result<(), FixtureError> {
    let (_file, producer, _consumer, _) = fixture()?;
    let table = producer
        .native_console_segment(0)
        .map_err(|_| NativeConsoleError::Binding)?
        .operation_stop;
    let row = NativeConsoleOperationStop {
        publication: 2,
        ring_end: 1,
        node_sequence: 1,
        logical_ps: 100,
        raw_prefix: 1,
        owner: grant().owner,
        authorization_advance: 12,
        logical_generation: 3,
        vcpu: 0,
        closed_generation: 0,
        control_boundary_ack: 1,
        stopped_advance: 0,
    };
    table.store(row)?;
    let mut invalid = row;
    invalid.publication = 4;
    invalid.closed_generation = 1;
    assert!(table.store(invalid).is_err());
    assert_eq!(table.snapshot()?, row);
    assert!(table.store(row).is_err());
    assert_eq!(table.snapshot()?, row);
    Ok(())
}
