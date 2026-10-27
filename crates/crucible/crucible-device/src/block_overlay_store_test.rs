//! Equivalence of the disk-backed overlay with an in-memory page map.
//!
//! The reference model below is the former heap overlay: a `BTreeMap` of full
//! 4 KiB pages plus a dirty set. Every test drives the same deterministic
//! operation stream through the reference, a heap-backed [`CowOverlay`], and
//! a file-backed one, and requires byte-identical reads, images, dirty sets,
//! snapshot encodings, restores, and forks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::sync::Arc;

use super::test_support::*;
use super::*;
use crate::DeviceError;
use crate::subnode::IoCore;

/// A device spanning three chunks with an unaligned tail page.
const DEVICE_LENGTH: usize = 2 * OVERLAY_CHUNK_BYTES as usize + 5 * PAGE_SIZE + 123;

#[derive(Clone, Default)]
struct ReferenceOverlay {
    pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
    dirty: BTreeSet<u64>,
}

impl ReferenceOverlay {
    fn write(&mut self, base: &BaseImage, offset: u64, data: &[u8]) {
        for (index, byte) in data.iter().enumerate() {
            let position = offset + index as u64;
            let page_base = position - position % PAGE_SIZE as u64;
            let page = self.pages.entry(page_base).or_insert_with(|| {
                let mut page = [0; PAGE_SIZE];
                let start = page_base as usize;
                let end = (start + PAGE_SIZE).min(base.bytes().len());
                page[..end - start].copy_from_slice(&base.bytes()[start..end]);
                page
            });
            page[(position - page_base) as usize] = *byte;
            self.dirty.insert(page_base);
        }
    }

    fn image(&self, base: &BaseImage) -> Vec<u8> {
        let mut image = base.bytes().to_vec();
        for (page_base, page) in &self.pages {
            let start = *page_base as usize;
            let span = (image.len() - start).min(PAGE_SIZE);
            image[start..start + span].copy_from_slice(&page[..span]);
        }
        image
    }
}

/// A small deterministic generator; tests must not depend on host entropy.
struct Stream(u64);

impl Stream {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn write(&mut self, length: usize) -> (u64, Vec<u8>) {
        // Mix tiny, page-straddling, and chunk-straddling writes, including
        // all-zero payloads that must stay present rather than vanish.
        let size = match self.next() % 4 {
            0 => 1 + (self.next() % 16) as usize,
            1 => PAGE_SIZE + (self.next() % 300) as usize,
            2 => 3 * PAGE_SIZE,
            _ => (self.next() % 64) as usize,
        }
        .min(length);
        let near_chunk = self.next().is_multiple_of(3);
        let offset = if near_chunk {
            let chunk = 1 + self.next() % 2;
            (chunk * OVERLAY_CHUNK_BYTES).saturating_sub(self.next() % (2 * PAGE_SIZE as u64))
        } else {
            self.next() % length as u64
        }
        .min((length - size) as u64);
        let fill = if self.next().is_multiple_of(5) {
            0
        } else {
            self.next() as u8
        };
        (offset, vec![fill; size])
    }
}

fn file_store(directory: &tempfile::TempDir) -> BlockPageStore {
    let file = ok(tempfile::tempfile_in(directory.path()));
    ok(BlockPageStore::from_unnamed_file(file))
}

fn assert_matches(reference: &ReferenceOverlay, overlay: &CowOverlay, base: &BaseImage) {
    assert_eq!(overlay_image(overlay, base), reference.image(base));
    assert_eq!(
        overlay.present_pages().collect::<Vec<_>>(),
        reference.pages.keys().copied().collect::<Vec<_>>()
    );
    assert_eq!(
        overlay.dirty_pages().collect::<Vec<_>>(),
        reference.dirty.iter().copied().collect::<Vec<_>>()
    );
    assert_eq!(overlay.page_count(), reference.pages.len());
}

#[test]
fn disk_overlay_matches_heap_overlay_and_reference_across_writes_forks_and_restores() {
    let directory = ok(tempfile::tempdir());
    let base = ramp_base(DEVICE_LENGTH);
    let mut stream = Stream(0x9e37_79b9_7f4a_7c15);
    let mut reference = ReferenceOverlay::default();
    let mut heap = CowOverlay::new();
    let mut disk = CowOverlay::with_store(file_store(&directory));
    let mut forks = Vec::new();

    for step in 0..400 {
        let (offset, data) = stream.write(DEVICE_LENGTH);
        reference.write(&base, offset, &data);
        ok(heap.write(&base, offset, &data));
        ok(disk.write(&base, offset, &data));

        let (offset, data) = stream.write(DEVICE_LENGTH);
        let read_length = data.len() as u64;
        assert_eq!(
            ok(disk.read(&base, offset, read_length)),
            ok(heap.read(&base, offset, read_length))
        );

        if step % 37 == 0 {
            // Fork: the clone shares pages; later writes on either side must
            // not leak into the other.
            forks.push((reference.clone(), disk.clone()));
        }
        if step % 53 == 0 {
            reference.dirty.clear();
            heap.clear_dirty();
            disk.clear_dirty();
        }
        if step % 61 == 0 {
            // A staged transaction that is discarded leaves no trace.
            let mut staged = disk.clone();
            let (offset, data) = stream.write(DEVICE_LENGTH);
            ok(staged.write(&base, offset, &data));
            drop(staged);
        }
        if step % 71 == 0 {
            let image = disk.freeze(base.len());
            assert_eq!(image, heap.freeze(base.len()));
            let restored = ok(image.materialize_into(&file_store(&directory)));
            assert_matches(&reference, &restored, &base);
        }
    }

    assert_matches(&reference, &heap, &base);
    assert_matches(&reference, &disk, &base);
    assert_eq!(heap, disk);
    for (fork_reference, fork) in &forks {
        assert_matches(fork_reference, fork, &base);
    }
}

#[test]
fn snapshot_encoding_is_identical_for_heap_and_disk_devices() {
    let directory = ok(tempfile::tempdir());
    let base_len = DEVICE_LENGTH;
    let heap_device = |store| {
        let core = ok(IoCore::new(crucible_qemu_shmem::SLOT_BLK_IO as u32, 16, 16));
        BlockDevice::new_with_store(core, ramp_base(base_len), BlockLatency::default(), store)
    };
    let mut heap = heap_device(mem());
    let mut disk = heap_device(file_store(&directory));
    let mut stream = Stream(7);
    let mut tick = 0;
    let mut checkpoints = Vec::new();

    for request_id in 0..120_u32 {
        let request = if request_id % 3 == 0 {
            let (offset, _) = stream.write(base_len);
            BlockRequest::read(
                request_id,
                offset,
                512.min((base_len as u64 - offset) as u32),
            )
        } else {
            let (offset, data) = stream.write(base_len);
            let data = data[..data.len().min(160)].to_vec();
            BlockRequest::write(request_id, offset, data)
        };
        let responses = [&mut heap, &mut disk].map(|device| {
            ok(device.submit(tick, &request));
            let limit = device.core().next_exact_local_event().unwrap_or(tick);
            ok(device.advance_to(limit));
            let mut responses = Vec::new();
            while let Some(pending) = ok(device.core_mut().pop_response()) {
                responses.push((pending.delivery_icount(), pending.response.payload));
            }
            (limit, responses)
        });
        assert_eq!(responses[0], responses[1]);
        tick = responses[0].0;

        if request_id % 17 == 0 {
            let heap_snapshot = heap.snapshot();
            let disk_snapshot = disk.snapshot();
            assert_eq!(
                ok(heap_snapshot.to_canonical_bytes()),
                ok(disk_snapshot.to_canonical_bytes()),
                "checkpoint bytes must not depend on the page store"
            );
            checkpoints.push((disk_snapshot, image(&disk)));
            heap.checkpoint_boundary();
            disk.checkpoint_boundary();
        }
    }
    assert_eq!(image(&heap), image(&disk));

    // Every earlier checkpoint still restores exactly, both from the frozen
    // image and through the encoded snapshot plus its chunk objects.
    for (snapshot, expected) in &checkpoints {
        let frozen = ok(BlockDevice::restore(
            snapshot,
            ramp_base(base_len),
            &file_store(&directory),
        ));
        assert_eq!(&image(&frozen), expected);
        let decoded = encoded_round_trip(snapshot);
        assert_eq!(&decoded, snapshot);
        ok(BlockDevice::validate_restore(
            &decoded,
            &ramp_base(base_len),
        ));
        let restored = ok(BlockDevice::restore(
            &decoded,
            ramp_base(base_len),
            &file_store(&directory),
        ));
        assert_eq!(&image(&restored), expected);
        assert_eq!(
            ok(restored.snapshot().to_canonical_bytes()),
            ok(snapshot.to_canonical_bytes())
        );
    }
}

#[test]
fn restored_devices_continue_identically_to_the_uninterrupted_run() {
    let directory = ok(tempfile::tempdir());
    let core = ok(IoCore::new(crucible_qemu_shmem::SLOT_BLK_IO as u32, 16, 16));
    let mut original = BlockDevice::new_with_store(
        core,
        ramp_base(DEVICE_LENGTH),
        BlockLatency::default(),
        file_store(&directory),
    );
    drive(&mut original, &mut Stream(11), 0, 0, 40);
    let snapshot = original.snapshot();
    let resume_tick = original.core().current_icount();
    let continuation = drive(&mut original, &mut Stream(23), 40, resume_tick, 40);

    // A fork restored from the frozen image shares pages with the original.
    let mut fork = ok(BlockDevice::restore(
        &snapshot,
        ramp_base(DEVICE_LENGTH),
        original.page_store(),
    ));
    assert_eq!(
        drive(&mut fork, &mut Stream(23), 40, resume_tick, 40),
        continuation
    );
    assert_eq!(image(&fork), image(&original));

    // A restore through the persisted form continues identically too.
    let mut restored = ok(BlockDevice::restore(
        &encoded_round_trip(&snapshot),
        ramp_base(DEVICE_LENGTH),
        &file_store(&directory),
    ));
    assert_eq!(
        drive(&mut restored, &mut Stream(23), 40, resume_tick, 40),
        continuation
    );
    assert_eq!(image(&restored), image(&original));
    assert_eq!(restored.snapshot(), original.snapshot());
}

/// Drives write-then-read pairs and returns every delivered response.
fn drive(
    device: &mut BlockDevice,
    stream: &mut Stream,
    first_request: u32,
    start_tick: u64,
    count: u32,
) -> Vec<(u64, Vec<u8>)> {
    let mut tick = start_tick;
    let mut trace = Vec::new();
    for request_id in first_request..first_request + count {
        let (offset, data) = stream.write(DEVICE_LENGTH);
        let data = data[..data.len().min(160)].to_vec();
        ok(device.submit(tick, &BlockRequest::write(request_id, offset, data)));
        ok(device.submit(tick, &BlockRequest::read(request_id + 10_000, offset, 64)));
        let limit = device.core().next_exact_local_event().unwrap_or(tick);
        ok(device.advance_to(limit));
        while let Some(pending) = ok(device.core_mut().pop_response()) {
            trace.push((pending.delivery_icount(), pending.response.payload));
        }
        tick = limit.max(tick);
    }
    trace
}

#[test]
fn file_store_reuses_released_slots() {
    let directory = ok(tempfile::tempdir());
    let store = file_store(&directory);
    let base = ramp_base(8 * PAGE_SIZE);
    let mut overlay = CowOverlay::with_store(store.clone());
    ok(overlay.write(&base, 0, &[1; 4 * PAGE_SIZE]));
    assert_eq!(store.live_file_slots(), 4);

    // Sole holder: patched in place, no new slot.
    ok(overlay.write(&base, 0, &[2; PAGE_SIZE]));
    assert_eq!(store.live_file_slots(), 4);

    // Shared with a snapshot: the write copies one page.
    let snapshot = overlay.freeze(base.len());
    ok(overlay.write(&base, 0, &[3; PAGE_SIZE]));
    assert_eq!(store.live_file_slots(), 5);
    drop(snapshot);
    assert_eq!(store.live_file_slots(), 4);
    drop(overlay);
    assert_eq!(store.live_file_slots(), 0);
}

#[test]
fn page_store_rejects_a_nonempty_file() {
    let directory = ok(tempfile::tempdir());
    let path = directory.path().join("used");
    ok(std::fs::write(&path, b"x"));
    assert!(BlockPageStore::from_unnamed_file(ok(File::open(&path))).is_err());
}

/// Mutates one stored chunk object before it is served.
type ChunkEdit = Box<dyn Fn(&mut Vec<u8>)>;

fn tampered_source(
    snapshot: &BlockSnapshot,
    edit: impl Fn(&mut Vec<u8>),
) -> Arc<dyn BlockOverlayChunkSource> {
    let mut objects = BTreeMap::new();
    let mut buffer = Vec::new();
    for chunk in ok(snapshot.overlay.chunks()) {
        if let Some(identity) = ok(snapshot.overlay.read_chunk(chunk.index, &mut buffer)) {
            let mut bytes = buffer.clone();
            edit(&mut bytes);
            objects.insert(identity, bytes);
        }
    }
    Arc::new(objects)
}

#[test]
fn restore_authenticates_every_stored_chunk() {
    let mut device = device(3 * PAGE_SIZE);
    ok(device.submit(0, &BlockRequest::write(1, 10, vec![0x5a; 32])));
    let limit = device.core().next_exact_local_event().unwrap_or(0);
    ok(device.advance_to(limit));
    let snapshot = device.snapshot();
    let bytes = ok(snapshot.to_canonical_bytes());
    let decoded = || ok(BlockSnapshot::from_canonical_bytes(&bytes));

    // No source bound: the chunk cannot be read.
    let unbound = decoded();
    assert!(!unbound.overlay.is_readable());
    assert!(matches!(
        BlockDevice::restore(&unbound, ramp_base(3 * PAGE_SIZE), &mem()),
        Err(DeviceError::BlockOverlayImage { .. })
    ));

    let cases: [(&str, ChunkEdit); 3] = [
        ("flipped byte", Box::new(|bytes| bytes[10] ^= 1)),
        ("truncated", Box::new(|bytes| bytes.truncate(100))),
        (
            "bytes in an absent page",
            Box::new(|bytes| bytes[2 * PAGE_SIZE] = 1),
        ),
    ];
    for (name, edit) in cases {
        let mut tampered = decoded();
        tampered.bind_overlay_source(tampered_source(&snapshot, edit));
        assert!(
            matches!(
                BlockDevice::validate_restore(&tampered, &ramp_base(3 * PAGE_SIZE)),
                Err(DeviceError::BlockOverlayImage { .. })
            ),
            "{name} chunk must be refused"
        );
        assert!(
            BlockDevice::restore(&tampered, ramp_base(3 * PAGE_SIZE), &mem()).is_err(),
            "{name} chunk must not restore"
        );
    }
}

#[test]
fn zero_pages_stay_present_without_a_chunk_object() {
    let base = ramp_base(2 * PAGE_SIZE);
    let mut overlay = CowOverlay::new();
    ok(overlay.write(&base, 0, &[0; PAGE_SIZE]));
    let image = overlay.freeze(base.len());
    let chunks = ok(image.chunks());
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].identity, None, "an all-zero chunk has no object");

    // Restore needs no source, and the zero page still shadows the base.
    let restored = ok(image.materialize_into(&mem()));
    assert_eq!(
        ok(restored.read(&base, 0, PAGE_SIZE as u64)),
        vec![0; PAGE_SIZE]
    );
    assert_eq!(restored.page_count(), 1);
}

#[test]
fn decoded_records_must_respect_device_geometry() {
    let length = OVERLAY_CHUNK_BYTES + 2 * PAGE_SIZE as u64;
    let mut present = ChunkPageBits::default();
    present.insert(0);
    let record = |index, present, dirty| BlockOverlayChunk {
        index,
        identity: None,
        present,
        dirty,
    };
    assert!(BlockOverlayImage::from_chunks(length, [record(1, present, present)]).is_ok());

    let mut beyond = ChunkPageBits::default();
    beyond.insert(2);
    let mut dirty_only = ChunkPageBits::default();
    dirty_only.insert(1);
    for records in [
        vec![record(2, present, present)],
        vec![record(1, beyond, ChunkPageBits::default())],
        vec![record(
            0,
            ChunkPageBits::default(),
            ChunkPageBits::default(),
        )],
        vec![record(0, present, dirty_only)],
        vec![record(1, present, present), record(0, present, present)],
    ] {
        assert!(matches!(
            BlockOverlayImage::from_chunks(length, records),
            Err(DeviceError::BlockOverlayImage { .. })
        ));
    }
}
