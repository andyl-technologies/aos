//! Checks T-IO-2 deterministic block sub-node base+overlay behavior.

#![forbid(unsafe_code)]

use crucible::{
    BLOCK_OVERLAY_PAGE_SIZE, BlockBaseImage, BlockOverlayError, BlockSubNodeOverlay,
    ContentAddressedBlobRef, ContentHash,
};

#[test]
fn reads_resolve_overlay_pages_before_immutable_base() {
    let original_base = patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2 + 8);
    let base = BlockBaseImage::from_bytes(original_base.clone()).expect("base should build");
    let base_hash = base.content_hash();
    let mut overlay = BlockSubNodeOverlay::new(base.clone());

    overlay
        .write((BLOCK_OVERLAY_PAGE_SIZE - 2) as u64, b"abcd")
        .expect("cross-page write should succeed");

    let read = overlay
        .read((BLOCK_OVERLAY_PAGE_SIZE - 4) as u64, 8)
        .expect("cross-page read should succeed");

    assert_eq!(
        read,
        vec![
            original_base[BLOCK_OVERLAY_PAGE_SIZE - 4],
            original_base[BLOCK_OVERLAY_PAGE_SIZE - 3],
            b'a',
            b'b',
            b'c',
            b'd',
            original_base[BLOCK_OVERLAY_PAGE_SIZE + 2],
            original_base[BLOCK_OVERLAY_PAGE_SIZE + 3],
        ]
    );
    assert_eq!(base.bytes(), original_base.as_slice());
    assert_eq!(base.content_hash(), base_hash);
    assert_eq!(overlay.base().content_hash(), base_hash);
}

#[test]
fn partial_write_faults_in_a_whole_page_and_dirties_only_that_page() {
    let original_base = patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2);
    let base = BlockBaseImage::from_bytes(original_base.clone()).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());

    overlay
        .write(10, b"xyz")
        .expect("partial write should succeed");

    assert_eq!(overlay.overlay_page_count(), 1);
    assert_eq!(overlay.dirty_pages(), vec![0]);

    let delta = overlay.capture_dirty_delta();
    assert_eq!(delta.base, base.content_ref());
    assert_eq!(delta.pages.len(), 1);
    assert_eq!(delta.pages[0].page_base, 0);
    assert_eq!(delta.pages[0].bytes.len(), BLOCK_OVERLAY_PAGE_SIZE);
    assert_eq!(&delta.pages[0].bytes[..10], &original_base[..10]);
    assert_eq!(&delta.pages[0].bytes[10..13], b"xyz");
    assert_eq!(
        &delta.pages[0].bytes[13..],
        &original_base[13..BLOCK_OVERLAY_PAGE_SIZE]
    );
    assert_eq!(overlay.dirty_page_count(), 0);
    assert_eq!(base.bytes(), original_base.as_slice());
}

#[test]
fn dirty_delta_is_sorted_unique_and_cleared_after_capture() {
    let base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 4))
        .expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base);

    overlay
        .write((BLOCK_OVERLAY_PAGE_SIZE * 2 + 3) as u64, b"third")
        .expect("third page write should succeed");
    overlay
        .write(7, b"first")
        .expect("first page write should succeed");
    overlay
        .write((BLOCK_OVERLAY_PAGE_SIZE + 11) as u64, b"second")
        .expect("second page write should succeed");
    overlay
        .write(9, b"again")
        .expect("second write to first page should succeed");

    let delta = overlay.capture_dirty_delta();
    let dirty_pages = delta
        .pages
        .iter()
        .map(|page| page.page_base)
        .collect::<Vec<_>>();

    assert_eq!(
        dirty_pages,
        vec![
            0,
            BLOCK_OVERLAY_PAGE_SIZE as u64,
            (BLOCK_OVERLAY_PAGE_SIZE * 2) as u64,
        ]
    );
    assert!(overlay.capture_dirty_delta().is_empty());

    overlay
        .write((BLOCK_OVERLAY_PAGE_SIZE + 1) as u64, b"checkpoint")
        .expect("post-checkpoint dirty page should succeed");
    let next_delta = overlay.capture_dirty_delta();
    assert_eq!(next_delta.pages.len(), 1);
    assert_eq!(
        next_delta.pages[0].page_base,
        BLOCK_OVERLAY_PAGE_SIZE as u64
    );
}

#[test]
fn ranges_past_the_base_length_fail_without_extending_the_device() {
    let base = BlockBaseImage::from_bytes(patterned_base(17)).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());

    assert_eq!(
        overlay.read(16, 1).expect("last byte read should succeed"),
        vec![base.bytes()[16]]
    );
    assert!(
        overlay
            .read(17, 0)
            .expect("empty EOF read should succeed")
            .is_empty()
    );

    let read_error = overlay
        .read(16, 2)
        .expect_err("range extending past the base should fail");
    assert!(matches!(
        read_error,
        BlockOverlayError::RangeOutOfBounds {
            offset: 16,
            count: 2,
            length: 17,
        }
    ));

    let write_error = overlay
        .write(17, b"x")
        .expect_err("write extending past the base should fail");
    assert!(matches!(
        write_error,
        BlockOverlayError::RangeOutOfBounds {
            offset: 17,
            count: 1,
            length: 17,
        }
    ));

    assert_eq!(overlay.get_length(), 17);
    assert_eq!(overlay.overlay_page_count(), 0);
    assert_eq!(base.bytes().len(), 17);
}

#[test]
fn final_partial_page_delta_is_zero_filled_beyond_device_length() {
    let base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE + 3))
        .expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base);

    overlay
        .write(BLOCK_OVERLAY_PAGE_SIZE as u64, b"abc")
        .expect("final page write should succeed");

    let delta = overlay.capture_dirty_delta();
    assert_eq!(delta.pages.len(), 1);
    assert_eq!(delta.pages[0].page_base, BLOCK_OVERLAY_PAGE_SIZE as u64);
    assert_eq!(&delta.pages[0].bytes[..3], b"abc");
    assert!(delta.pages[0].bytes[3..].iter().all(|byte| *byte == 0));
}

#[test]
fn flush_is_a_noop_success_and_get_length_reports_base_size() {
    let original_base = patterned_base(128);
    let base = BlockBaseImage::from_bytes(original_base.clone()).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());

    overlay.write(4, b"data").expect("write should succeed");
    let before_pages = overlay.overlay_pages();
    overlay.flush().expect("flush should be a no-op success");

    assert_eq!(overlay.get_length(), 128);
    assert_eq!(overlay.overlay_pages(), before_pages);
    assert_eq!(base.bytes(), original_base.as_slice());
}

#[test]
fn base_image_constructor_rejects_mismatched_content_address() {
    let bytes = patterned_base(64);
    let wrong_hash = ContentHash::from_bytes(b"different base image");
    let wrong_ref = ContentAddressedBlobRef::from_hash(wrong_hash);

    let error = BlockBaseImage::from_content_ref(wrong_ref, bytes)
        .expect_err("wrong content-addressed base should fail");

    assert!(matches!(
        error,
        BlockOverlayError::ContentHashMismatch { expected, actual }
            if expected == wrong_hash && actual != wrong_hash
    ));
}

#[test]
fn overflowing_ranges_fail_before_any_overlay_mutation() {
    let base = BlockBaseImage::from_bytes(patterned_base(64)).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base);

    let read_error = overlay
        .read(u64::MAX, 1)
        .expect_err("overflowing read should fail");
    assert!(matches!(
        read_error,
        BlockOverlayError::RangeOverflow {
            offset: u64::MAX,
            count: 1,
        }
    ));

    let write_error = overlay
        .write(u64::MAX, b"x")
        .expect_err("overflowing write should fail");
    assert!(matches!(
        write_error,
        BlockOverlayError::RangeOverflow {
            offset: u64::MAX,
            count: 1,
        }
    ));
    assert_eq!(overlay.overlay_page_count(), 0);
}

fn patterned_base(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}
