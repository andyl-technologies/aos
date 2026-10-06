//! White-box availability observations, geometry errors, and SPSC publication.

use super::*;

#[test]
fn whitebox_availability_matches_peek_without_consuming() {
    let ring = RingHeader::new();

    for capacity in [0, 1, 2, 3, 4] {
        let entries = vec![WhiteboxMarkerEntry::default(); capacity];
        for head in [0, u64::from(u32::MAX), u64::MAX] {
            for count in [0, 1, 2, 4, 5] {
                let tail = head.wrapping_add(count);
                ring.read_idx.store(head, Ordering::Relaxed);
                ring.write_idx.store(tail, Ordering::Release);

                assert_eq!(
                    ring.has_whitebox_marker(&entries),
                    ring.peek_whitebox_marker(&entries)
                        .map(|entry| entry.is_some()),
                    "capacity={capacity}, head={head}, count={count}",
                );
                assert_eq!(ring.read_index(), head);
                assert_eq!(ring.write_index(), tail);
            }
        }
    }
}

#[test]
fn whitebox_availability_is_advisory_across_publication_and_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let ring = RingHeader::new();
    let mut entries = vec![WhiteboxMarkerEntry::default()];
    let entry = WhiteboxMarkerEntry::new(50, 0, 7, b"reply")?;

    assert!(!ring.has_whitebox_marker(&entries)?);
    ring.enqueue_whitebox_marker(&mut entries, entry)?;
    assert!(ring.has_whitebox_marker(&entries)?);
    assert_eq!(ring.dequeue_whitebox_marker(&entries)?, Some(entry));
    assert_eq!(ring.peek_whitebox_marker(&entries)?, None);
    assert!(!ring.has_whitebox_marker(&entries)?);
    Ok(())
}

#[test]
fn whitebox_availability_does_not_validate_payloads() -> Result<(), Box<dyn std::error::Error>> {
    let ring = RingHeader::new();
    let mut entries = vec![WhiteboxMarkerEntry::default()];
    entries[0]._reserved[0] = 1;
    ring.write_idx.store(1, Ordering::Release);

    assert!(ring.has_whitebox_marker(&entries)?);
    assert!(ring.peek_whitebox_marker(&entries)?.is_some());
    assert!(entries[0].validate().is_err());
    assert_eq!(ring.read_index(), 0);
    Ok(())
}

#[test]
fn whitebox_availability_preserves_peek_without_consumer_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let ring = RingHeader::new();
    let mut entries = vec![WhiteboxMarkerEntry::default()];
    let entry = WhiteboxMarkerEntry::new(50, 0, 7, b"reply")?;
    assert!(ring.hold_hot_fork_consumers().quiescent());

    assert!(!ring.has_whitebox_marker(&entries)?);
    assert_eq!(ring.peek_whitebox_marker(&entries)?, None);
    ring.enqueue_whitebox_marker(&mut entries, entry)?;
    assert!(ring.has_whitebox_marker(&entries)?);
    assert_eq!(ring.peek_whitebox_marker(&entries)?, Some(entry));
    assert_eq!(
        ring.dequeue_whitebox_marker(&entries),
        Err(SpscRingError::ConsumerBarrierHeld),
    );
    assert_eq!(ring.read_index(), 0);
    Ok(())
}
