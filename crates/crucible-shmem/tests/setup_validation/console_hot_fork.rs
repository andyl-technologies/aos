//! Real mapped console admission and sparse child-image controls.
//!
//! Records and permission-table bytes are explicit test providers. These
//! storage controls do not stand in for native child resource or Restore owners.

use super::*;
use crucible_protocol::native_console::{
    NativeConsoleOrigin, NativeConsoleOwner, NativeConsolePhase, NativeConsoleRecord,
};
use crucible_shmem::native_console::{NativeConsoleRingError, NativeConsoleSegmentLayout};
use std::os::unix::fs::FileExt;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn mapping(bytes: &[u8]) -> TestResult<(std::fs::File, MappedSetupRegion)> {
    let mut file = temp_region_file();
    file.set_len(bytes.len() as u64)?;
    file.write_all(bytes)?;
    let mapped = mmap_setup_region(file.as_fd(), bytes.len() as u64)?;

    Ok((file, mapped))
}

fn record(slot: u32) -> NativeConsoleRecord {
    NativeConsoleRecord {
        owner: NativeConsoleOwner {
            slot,
            region: [4; 16],
            process: 8,
            authorization: 10,
        },
        authorization_advance: 12,
        phase: NativeConsolePhase::ColdSetup,
        origin: NativeConsoleOrigin {
            stream: 1,
            logical_generation: 0,
            node_sequence: 1,
            stream_sequence: 1,
            logical_ps: 50,
            raw_prefix: 1,
            vcpu: 0,
            byte: b'A' + slot as u8,
        },
    }
}

fn segment(layout: RegionLayout, slot: u32) -> TestResult<NativeConsoleSegmentLayout> {
    let base = layout.native_console_off + u64::from(slot) * layout.native_console_stride;
    Ok(NativeConsoleSegmentLayout::new(
        base as usize,
        layout.region_size as usize,
    )?)
}

fn read_mapping(file: &std::fs::File, length: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, 0)?;

    Ok(bytes)
}

#[test]
fn console_hot_fork_barrier_holds_both_endpoints_at_every_node_stride() -> TestResult<()> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(2, 4))?;
    let mapped = mapped_region_from_allocation(&allocation);
    for slot in 0..2 {
        let console = mapped.native_console_segment(slot)?;
        console
            .ring
            .stage_native_console(console.records, &[record(slot)])?;
    }

    let held = mapped.hold_hot_fork_ring_io()?;
    assert!(held.quiescent());
    assert_eq!(mapped.hot_fork_ring_io_snapshot()?, held);
    for slot in 0..2 {
        let console = mapped.native_console_segment(slot)?;
        assert!(console.ring.producer_barrier_snapshot().held());
        assert!(console.ring.consumer_barrier_snapshot().held());
        assert!(matches!(
            console
                .ring
                .stage_native_console(console.records, &[record(slot)]),
            Err(NativeConsoleRingError::Ring(
                SpscRingError::ProducerBarrierHeld
            ))
        ));
        assert!(matches!(
            console
                .ring
                .peek_native_console_operation_tail(console.records, 1),
            Err(NativeConsoleRingError::Ring(
                SpscRingError::ConsumerBarrierHeld
            ))
        ));
    }

    let released = mapped.release_hot_fork_ring_io()?;
    assert_eq!(released.ring_count(), held.ring_count());
    assert_eq!(released.held_rings(), 0);
    for slot in 0..2 {
        let console = mapped.native_console_segment(slot)?;
        assert_eq!(
            console
                .ring
                .peek_native_console_operation_tail(console.records, 1)?,
            Some(record(slot))
        );
    }

    Ok(())
}

#[test]
fn console_hot_fork_image_retains_held_queues_without_physical_permission_tables() -> TestResult<()>
{
    let allocation = RegionAllocation::new_model(RegionConfig::new(2, 4))?;
    let layout = allocation.layout();
    let fresh = allocation.setup_region_bytes()?;
    let mut source_bytes = fresh.clone();
    for slot in 0..2 {
        let console = segment(layout, slot)?;
        // Deliberately non-authoritative bytes make accidental table copying
        // visible, without minting a capability, AUTH, frontier or stop receipt.
        source_bytes[console.capability..console.ring_header].fill(0x45);
        source_bytes[console.frontier..console.end].fill(0x76);
    }
    let (_source_file, source) = mapping(&source_bytes)?;
    let (destination_file, mut destination) = mapping(&fresh)?;
    for slot in 0..2 {
        let console = source.native_console_segment(slot)?;
        console
            .ring
            .stage_native_console(console.records, &[record(slot)])?;
    }
    source.hold_hot_fork_ring_io()?;
    destination.hold_hot_fork_ring_io()?;

    let image = source.capture_hot_fork_ring_image(usize::MAX)?;
    let canonical = image.canonical_bytes()?;
    assert_eq!(&canonical[..8], b"CRHFRI03");
    let decoded = HotForkRingImage::from_canonical_bytes(&canonical, canonical.len())?;
    destination.restore_hot_fork_ring_image(&decoded)?;

    let restored = read_mapping(&destination_file, fresh.len())?;
    for slot in 0..2 {
        let offsets = segment(layout, slot)?;
        assert_eq!(
            &restored[offsets.capability..offsets.ring_header],
            &fresh[offsets.capability..offsets.ring_header]
        );
        assert_eq!(
            &restored[offsets.frontier..offsets.end],
            &fresh[offsets.frontier..offsets.end]
        );
        let console = destination.native_console_segment(slot)?;
        assert_eq!(
            read_u64(&restored, offsets.ring_header + RING_HEADER_READ_IDX_OFFSET),
            0
        );
        assert_eq!(
            read_u64(
                &restored,
                offsets.ring_header + RING_HEADER_WRITE_IDX_OFFSET
            ),
            1
        );
        assert!(console.ring.producer_barrier_snapshot().held());
        assert!(console.ring.consumer_barrier_snapshot().held());
    }
    assert_eq!(
        destination.capture_hot_fork_ring_image(canonical.len())?,
        image
    );

    // Only this modeled storage test releases admission. Production release
    // additionally requires the genuine native child resource/Restore owner.
    destination.release_hot_fork_ring_io()?;
    for slot in 0..2 {
        let console = destination.native_console_segment(slot)?;
        assert_eq!(
            console
                .ring
                .peek_native_console_operation_tail(console.records, 1)?,
            Some(record(slot))
        );
    }

    let mut legacy = canonical;
    legacy[..8].copy_from_slice(b"CRHFRI02");
    legacy[8..12].copy_from_slice(&2_u32.to_le_bytes());
    assert!(matches!(
        HotForkRingImage::from_canonical_bytes(&legacy, legacy.len()),
        Err(HotForkRingImageError::InvalidCanonicalImage {
            reason: "hot-fork-ring-image-magic"
        })
    ));

    Ok(())
}

#[test]
fn console_hot_fork_image_refuses_one_open_endpoint_before_destination_effects() -> TestResult<()> {
    let allocation = RegionAllocation::new_model(RegionConfig::new(2, 4))?;
    let fresh = allocation.setup_region_bytes()?;
    let (_source_file, source) = mapping(&fresh)?;
    let (destination_file, mut destination) = mapping(&fresh)?;
    source.hold_hot_fork_ring_io()?;
    destination.hold_hot_fork_ring_io()?;
    let image = source.capture_hot_fork_ring_image(usize::MAX)?;

    let _released_consumer = source
        .native_console_segment(1)?
        .ring
        .release_hot_fork_consumers();
    assert!(matches!(
        source.capture_hot_fork_ring_image(usize::MAX),
        Err(HotForkRingImageError::BarrierNotQuiescent { .. })
    ));
    let _released_producer = destination
        .native_console_segment(1)?
        .ring
        .release_hot_fork_producers();
    let before = read_mapping(&destination_file, fresh.len())?;
    assert!(matches!(
        destination.restore_hot_fork_ring_image(&image),
        Err(HotForkRingImageError::BarrierNotQuiescent { .. })
    ));
    assert_eq!(read_mapping(&destination_file, fresh.len())?, before);

    Ok(())
}
