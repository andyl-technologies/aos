//! Independent byte construction for cohort and physical-return boundaries.

use super::*;

fn word32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn word64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn publication_bytes() -> [u8; 1536] {
    let mut bytes = [0; 1536];
    for (offset, value) in [(0, 2), (8, 3), (16, 5), (24, 1), (32, 8), (40, 1)] {
        word64(&mut bytes, offset, value);
    }
    for (offset, value) in [(48, 128), (52, 896), (56, 1024), (60, 128)] {
        word32(&mut bytes, offset, value);
    }

    let cohort = &mut bytes[128..1024];
    cohort[..8].copy_from_slice(b"CRUCACT2");
    word32(cohort, 8, 2);
    word32(cohort, 12, 896);
    cohort[16..48].fill(1);
    cohort[48..80].fill(2);
    word64(cohort, 80, 3);
    word64(cohort, 88, 4);
    word64(cohort, 104, 0x1122_3344_5566_7788);
    word64(cohort, 112, 2);
    word32(cohort, 120, 0x0001_0101);
    word32(cohort, 124, 1);

    let row = &mut cohort[128..320];
    row[..32].fill(7);
    // Root owner zero is a canonical identity; the operation and inventory exist.
    word64(row, 40, 9);
    word32(row, 48, 1);
    word64(row, 72, 100);
    word64(row, 80, 110);
    word64(row, 88, 110);
    word64(row, 128, 1);
    word64(row, 144, 1);
    bytes[1024..1152].copy_from_slice(&vector::<128>(COMMAND));

    bytes
}

fn return_bytes() -> [u8; 504] {
    let mut bytes = [0; 504];
    for (offset, value) in [
        (0, 6),
        (8, 5),
        (16, 3),
        (24, 2),
        (32, 7),
        (64, u64::MAX),
        (72, 9),
        (80, 11),
    ] {
        word64(&mut bytes, offset, value);
    }
    for (offset, value) in [
        (40, (-5i32) as u32),
        (44, i32::MIN as u32),
        (48, 1),
        (52, 0x41),
        (56, 2),
        (60, 1),
    ] {
        word32(&mut bytes, offset, value);
    }

    bytes
}

fn terminal_bytes() -> [u8; 512] {
    let mut bytes = [0; 512];
    for (offset, value) in [(0, 8), (8, 5), (16, 3), (24, 2), (32, 6), (56, 13)] {
        word64(&mut bytes, offset, value);
    }
    for (offset, value) in [
        (40, (-5i32) as u32),
        (44, i32::MIN as u32),
        (48, 1),
        (52, 3),
    ] {
        word32(&mut bytes, offset, value);
    }

    bytes
}

#[test]
fn publication_accepts_independent_class_one_root_owner_vector() -> Result<(), PublisherDecodeError>
{
    let bytes = publication_bytes();
    let publication = PublisherPublication::decode(&bytes)?;

    assert_eq!(publication.sequence, 2);
    assert_eq!(publication.offer_generation, 3);
    assert_eq!(publication.ticket_serial, 5);
    assert_eq!(publication.standing_sequence, 8);
    assert_eq!(publication.command, Some(command()));
    assert_eq!(publication.cohort.parents[0].budget_owner, 0);
    assert_eq!(publication.cohort.parents[0].required, 1);
    assert_eq!(publication.encode()?, bytes);

    for permission in [
        PublisherPermission::Borrowable,
        PublisherPermission::Revoked,
        PublisherPermission::Terminal,
    ] {
        let value = PublisherPublication {
            permission,
            ..publication
        };
        assert_eq!(PublisherPublication::decode(&value.encode()?)?, value);
    }

    Ok(())
}

#[test]
fn publication_refuses_each_reserved_byte_and_changed_geometry() {
    let original = publication_bytes();

    for offset in (48..128).chain(1152..1536) {
        let mut bytes = original;
        bytes[offset] ^= 1;
        assert_eq!(
            PublisherPublication::decode(&bytes),
            Err(PublisherDecodeError),
            "offset {offset}"
        );
    }
    for length in 0..1536 {
        assert_eq!(
            PublisherPublication::decode(&original[..length]),
            Err(PublisherDecodeError)
        );
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_eq!(
        PublisherPublication::decode(&trailing),
        Err(PublisherDecodeError)
    );
}

#[test]
fn publication_checks_correlation_inventory_and_command_domains() -> Result<(), PublisherDecodeError>
{
    let original = publication_bytes();

    for (offset, invalid) in [
        (0, 0),
        (0, 1),
        (0, u64::MAX),
        (8, 0),
        (8, u64::MAX),
        (16, 0),
        (16, PUBLISHER_TICKET_MAX_SERIAL + 1),
        (24, 0),
        (24, 4),
        (32, 0),
        (32, 1),
        (32, u64::MAX),
        (40, 2),
        (128 + 112, 10),
        (128 + 128 + 40, 0),
        (128 + 128 + 144, 0),
        (1024 + 64, 0),
    ] {
        let mut bytes = original;
        word64(&mut bytes, offset, invalid);
        assert_eq!(
            PublisherPublication::decode(&bytes),
            Err(PublisherDecodeError),
            "offset {offset}, value {invalid}"
        );
    }
    let mut bytes = original;
    bytes[128..136].copy_from_slice(b"CRUCPRK1");
    assert_eq!(
        PublisherPublication::decode(&bytes),
        Err(PublisherDecodeError)
    );

    // A non-Quantum cohort retains its own class and has no command at all.
    let mut value = PublisherPublication::decode(&original)?;
    value.command = None;
    assert_eq!(value.encode(), Err(PublisherDecodeError));
    value.cohort.parents[0].class = 3;
    value.cohort.parents[0].total_end_ns = 200;
    let bytes = value.encode()?;
    assert!(bytes[1024..1152].iter().all(|byte| *byte == 0));
    assert_eq!(PublisherPublication::decode(&bytes)?, value);
    let mut invalid = bytes;
    invalid[1024] = 1;
    assert_eq!(
        PublisherPublication::decode(&invalid),
        Err(PublisherDecodeError)
    );
    value.command = Some(command());
    assert_eq!(value.encode(), Err(PublisherDecodeError));

    Ok(())
}

#[test]
fn publication_preserves_four_distinct_born_and_partially_projected_rows()
-> Result<(), PublisherDecodeError> {
    let mut value = PublisherPublication::decode(&publication_bytes())?;
    value.cohort.row_count = 4;
    value.cohort.borrowed_mask = 15;
    value.cohort.projected_mask = 9;
    value.cohort.cohort_current = false;
    value.cohort.parents[0].preparation = 4;
    value.cohort.parents[3] = crate::boundary_action::ActionParent {
        class: 12,
        role: 1,
        total_end_ns: 200,
        preparation: 0,
        ..value.cohort.parents[0]
    };

    let bytes = value.encode()?;
    let decoded = PublisherPublication::decode(&bytes)?;
    assert_eq!(decoded, value);
    assert_eq!(decoded.cohort.borrowed_mask, 15);
    assert_eq!(decoded.cohort.projected_mask, 9);
    assert_eq!(
        decoded.cohort.parents[0].operation,
        decoded.cohort.parents[3].operation
    );
    assert!(bytes[448..832].iter().all(|byte| *byte == 0));

    value.cohort.cohort_current = true;
    assert_eq!(value.encode(), Err(PublisherDecodeError));

    Ok(())
}

#[test]
fn receiver_return_preserves_negative_post_actual_unit_and_partial_masks()
-> Result<(), PublisherDecodeError> {
    let bytes = return_bytes();
    let value = PublisherReturn::decode(&bytes)?;

    assert_eq!(value.first, -5);
    assert_eq!(value.post, i32::MIN);
    assert_eq!(value.returned_view_mask, 1);
    assert_eq!(value.physical_child_mask, 0x41);
    assert_eq!(value.final_raw_icount, u64::MAX);
    assert_eq!(
        value.outcome,
        PublisherOutcome::NextIdle {
            completion_generation: 9,
            work_unit_serial: 11,
        }
    );
    assert_eq!(value.encode()?, bytes);

    for outcome in [
        PublisherOutcome::None,
        PublisherOutcome::RetiredCeiling {
            work_unit_serial: u64::MAX - 1,
        },
        PublisherOutcome::NextIdle {
            completion_generation: u64::MAX - 1,
            work_unit_serial: 1,
        },
    ] {
        let record = PublisherReturn {
            outcome,
            returned_view_mask: 0,
            physical_child_mask: 0,
            ..value
        };
        assert_eq!(PublisherReturn::decode(&record.encode()?)?, record);
    }

    Ok(())
}

#[test]
fn receiver_return_checks_identity_status_masks_and_unit_shape() {
    let original = return_bytes();

    for (offset, invalid) in [
        (0, 0),
        (0, 1),
        (8, 0),
        (8, PUBLISHER_TICKET_MAX_SERIAL + 1),
        (16, 0),
        (16, u64::MAX),
        (24, 0),
        (24, 1),
        (32, 0),
        (32, u64::MAX),
        (72, 0),
        (72, u64::MAX),
        (80, 0),
        (80, u64::MAX),
    ] {
        let mut bytes = original;
        word64(&mut bytes, offset, invalid);
        assert_eq!(PublisherReturn::decode(&bytes), Err(PublisherDecodeError));
    }
    for (offset, invalid) in [
        (40, 1),
        (44, 1),
        (48, 16),
        (52, 128),
        (56, 0),
        (56, 3),
        (60, 0),
        (60, 2),
    ] {
        let mut bytes = original;
        word32(&mut bytes, offset, invalid);
        assert_eq!(PublisherReturn::decode(&bytes), Err(PublisherDecodeError));
    }
    for offset in 88..504 {
        let mut bytes = original;
        bytes[offset] = 1;
        assert_eq!(PublisherReturn::decode(&bytes), Err(PublisherDecodeError));
    }
    for length in 0..504 {
        assert_eq!(
            PublisherReturn::decode(&original[..length]),
            Err(PublisherDecodeError)
        );
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_eq!(
        PublisherReturn::decode(&trailing),
        Err(PublisherDecodeError)
    );
}

#[test]
fn terminal_preserves_incomplete_consumption_and_negative_post() -> Result<(), PublisherDecodeError>
{
    let bytes = terminal_bytes();
    let value = PublisherTerminal::decode(&bytes)?;

    assert_eq!(value.first, -5);
    assert_eq!(value.post, i32::MIN);
    assert_eq!(value.consumed_mask, 1);
    assert_eq!(value.born_mask, 3);
    assert_eq!(value.command_consumption_generation, 13);
    assert_eq!(value.encode()?, bytes);

    for consumed_mask in [0, 1, 2, 3] {
        for command_consumption_generation in [0, 1, u64::MAX - 1] {
            let record = PublisherTerminal {
                consumed_mask,
                command_consumption_generation,
                ..value
            };
            assert_eq!(PublisherTerminal::decode(&record.encode()?)?, record);
        }
    }

    Ok(())
}

#[test]
fn terminal_checks_identity_status_born_subset_and_padding() {
    let original = terminal_bytes();

    for (offset, invalid) in [
        (0, 0),
        (0, 1),
        (8, 0),
        (8, PUBLISHER_TICKET_MAX_SERIAL + 1),
        (16, 0),
        (16, u64::MAX),
        (24, 0),
        (24, 1),
        (32, 0),
        (32, 1),
        (56, u64::MAX),
    ] {
        let mut bytes = original;
        word64(&mut bytes, offset, invalid);
        assert_eq!(PublisherTerminal::decode(&bytes), Err(PublisherDecodeError));
    }
    for (offset, invalid) in [(40, 1), (44, 1), (48, 4), (52, 0), (52, 16)] {
        let mut bytes = original;
        word32(&mut bytes, offset, invalid);
        assert_eq!(PublisherTerminal::decode(&bytes), Err(PublisherDecodeError));
    }
    for offset in 64..512 {
        let mut bytes = original;
        bytes[offset] = 1;
        assert_eq!(PublisherTerminal::decode(&bytes), Err(PublisherDecodeError));
    }
    for length in 0..512 {
        assert_eq!(
            PublisherTerminal::decode(&original[..length]),
            Err(PublisherDecodeError)
        );
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_eq!(
        PublisherTerminal::decode(&trailing),
        Err(PublisherDecodeError)
    );
}
