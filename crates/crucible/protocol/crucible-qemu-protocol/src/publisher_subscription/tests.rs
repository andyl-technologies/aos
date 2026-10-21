//! Independent canonical vectors and adversarial subscription syntax checks.

use super::*;

mod records;
mod purpose;

const HEADER: &str = "
43525543504c4d31000000010000100000000000000000030000000000000000
000000000000000500000000000000070102030405060708090a0b0c0d0e0f10
1112131415161718191a1b1c1d1e1f20a1a2a3a4a5a6a7a8a9aaabacadaeafb0
b1b2b3b4b5b6b7b8b9babbbcbdbebfc000000002000000040000010000000600
0000070000000200000009000000020000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000";

const COMMAND: &str = "
4352554351434d3100000001000000800102030405060708fffffffffffffff0
ffffffffffffffff0000000000000000ffffffffffffffff0000000200000000
1122334455667788000000000000000900000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000";

fn vector<const N: usize>(text: &str) -> [u8; N] {
    let digits: Vec<_> = text.chars().filter_map(|c| c.to_digit(16)).collect();
    assert_eq!(digits.len(), N * 2);

    core::array::from_fn(|index| ((digits[index * 2] << 4) | digits[index * 2 + 1]) as u8)
}

fn header() -> PublisherHeader {
    PublisherHeader {
        lender_generation: 3,
        account_generation: 5,
        process_generation: 7,
        capability: core::array::from_fn(|index| index as u8 + 1),
        reservation: core::array::from_fn(|index| index as u8 + 161),
        node_index: 2,
        node_count: 4,
    }
}

fn command() -> PublisherCommand {
    PublisherCommand {
        scheduler_generation: 0x0102_0304_0506_0708,
        initial_raw_icount: u64::MAX - 15,
        maximum_raw_icount: u64::MAX,
        logical_tick_ceiling: 0,
        native_monotonic_ns_ceiling: u64::MAX,
        stop: PublisherStopMode::NextIdle {
            target_generation: 9,
        },
        frontier: 0x1122_3344_5566_7788,
    }
}

#[test]
fn immutable_header_matches_independent_big_endian_vector() -> Result<(), PublisherDecodeError> {
    let bytes = vector::<256>(HEADER);

    assert_eq!(PublisherHeader::decode(&bytes)?, header());
    assert_eq!(header().encode()?, bytes);

    Ok(())
}

#[test]
fn header_refuses_each_changed_geometry_and_reserved_byte() {
    let original = vector::<256>(HEADER);

    for offset in (0..16).chain(24..32).chain(120..256) {
        let mut bytes = original;
        bytes[offset] ^= 1;

        assert_eq!(
            PublisherHeader::decode(&bytes),
            Err(PublisherDecodeError),
            "offset {offset}"
        );
    }
    for length in 0..256 {
        assert_eq!(
            PublisherHeader::decode(&original[..length]),
            Err(PublisherDecodeError)
        );
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_eq!(
        PublisherHeader::decode(&trailing),
        Err(PublisherDecodeError)
    );
}

#[test]
fn header_checks_each_identity_and_node_boundary() -> Result<(), PublisherDecodeError> {
    for invalid in [0, u64::MAX] {
        for field in 0..3 {
            let mut value = header();
            match field {
                0 => value.lender_generation = invalid,
                1 => value.account_generation = invalid,
                _ => value.process_generation = invalid,
            }
            assert_eq!(value.encode(), Err(PublisherDecodeError));

            let mut bytes = vector::<256>(HEADER);
            let offset = [16, 32, 40][field];
            bytes[offset..offset + 8].copy_from_slice(&invalid.to_be_bytes());
            assert_eq!(PublisherHeader::decode(&bytes), Err(PublisherDecodeError));
        }
    }
    for (start, end) in [(48, 80), (80, 112)] {
        let mut bytes = vector::<256>(HEADER);
        bytes[start..end].fill(0);
        assert_eq!(PublisherHeader::decode(&bytes), Err(PublisherDecodeError));
    }
    for (node_index, node_count, valid) in [
        (0, 0, false),
        (0, 1, true),
        (1, 1, false),
        (31, 32, true),
        (32, 32, false),
        (0, 33, false),
        (u32::MAX, u32::MAX, false),
    ] {
        let value = PublisherHeader {
            node_index,
            node_count,
            ..header()
        };
        assert_eq!(value.encode().is_ok(), valid);
        if valid {
            assert_eq!(PublisherHeader::decode(&value.encode()?)?, value);
        }
    }

    Ok(())
}

#[test]
fn command_matches_independent_vector_with_distinct_clock_domains()
-> Result<(), PublisherDecodeError> {
    let bytes = vector::<128>(COMMAND);

    assert_eq!(PublisherCommand::decode(&bytes)?, command());
    assert_eq!(command().encode()?, bytes);

    for (initial, maximum) in [(0, 0), (0, u64::MAX), (u64::MAX, u64::MAX)] {
        for (logical, native) in [(0, u64::MAX), (u64::MAX, 0), (0, 0)] {
            let value = PublisherCommand {
                initial_raw_icount: initial,
                maximum_raw_icount: maximum,
                logical_tick_ceiling: logical,
                native_monotonic_ns_ceiling: native,
                stop: PublisherStopMode::RetiredCeiling,
                frontier: 0,
                ..command()
            };
            assert_eq!(PublisherCommand::decode(&value.encode()?)?, value);
        }
    }

    Ok(())
}

#[test]
fn command_rejects_changed_geometry_outcomes_and_decreasing_icount() {
    let original = vector::<128>(COMMAND);

    for offset in (0..16).chain(60..64).chain(80..128) {
        let mut bytes = original;
        bytes[offset] ^= 1;
        assert_eq!(
            PublisherCommand::decode(&bytes),
            Err(PublisherDecodeError),
            "offset {offset}"
        );
    }
    for length in 0..128 {
        assert_eq!(
            PublisherCommand::decode(&original[..length]),
            Err(PublisherDecodeError)
        );
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_eq!(
        PublisherCommand::decode(&trailing),
        Err(PublisherDecodeError)
    );

    for invalid in [0, 1, 3, u64::MAX] {
        let mut bytes = original;
        bytes[16..24].copy_from_slice(&invalid.to_be_bytes());
        assert_eq!(PublisherCommand::decode(&bytes), Err(PublisherDecodeError));
    }
    let value = PublisherCommand {
        initial_raw_icount: 1,
        maximum_raw_icount: 0,
        ..command()
    };
    assert_eq!(value.encode(), Err(PublisherDecodeError));
    let mut bytes = original;
    bytes[32..40].fill(0);
    assert_eq!(PublisherCommand::decode(&bytes), Err(PublisherDecodeError));
}

#[test]
fn command_stop_modes_preserve_their_exact_target_rules() -> Result<(), PublisherDecodeError> {
    for mode in [0u32, 1, 2, 3, u32::MAX] {
        for target in [0u64, 1, u64::MAX - 1, u64::MAX] {
            let mut bytes = vector::<128>(COMMAND);
            bytes[56..60].copy_from_slice(&mode.to_be_bytes());
            bytes[72..80].copy_from_slice(&target.to_be_bytes());
            let valid =
                (mode == 1 && target == 0) || (mode == 2 && target != 0 && target != u64::MAX);

            assert_eq!(PublisherCommand::decode(&bytes).is_ok(), valid);
            if valid {
                assert_eq!(PublisherCommand::decode(&bytes)?.encode()?, bytes);
            }
        }
    }
    for target_generation in [0, u64::MAX] {
        let value = PublisherCommand {
            stop: PublisherStopMode::NextIdle { target_generation },
            ..command()
        };
        assert_eq!(value.encode(), Err(PublisherDecodeError));
    }

    Ok(())
}

#[test]
fn ticket_words_preserve_all_phases_and_serial_boundaries() -> Result<(), PublisherDecodeError> {
    let phases = [
        PublisherTicketPhase::Issued,
        PublisherTicketPhase::Acquired,
        PublisherTicketPhase::ReturnRequested,
        PublisherTicketPhase::Consumed,
        PublisherTicketPhase::Closed,
        PublisherTicketPhase::Withdrawn,
    ];
    for serial in [1, 0x0102_0304_0506_0708, PUBLISHER_TICKET_MAX_SERIAL] {
        for (index, phase) in phases.into_iter().enumerate() {
            let expected = (serial << 3) | (index as u64 + 1);
            let ticket = PublisherTicket { serial, phase };

            assert_eq!(ticket.encode()?, expected);
            assert_eq!(PublisherTicket::decode(expected)?, ticket);
        }
        for phase in [0, 7] {
            assert_eq!(
                PublisherTicket::decode((serial << 3) | phase),
                Err(PublisherDecodeError)
            );
        }
    }
    for word in 0..8 {
        assert_eq!(PublisherTicket::decode(word), Err(PublisherDecodeError));
    }
    for serial in [0, PUBLISHER_TICKET_MAX_SERIAL + 1, u64::MAX] {
        let ticket = PublisherTicket {
            serial,
            phase: PublisherTicketPhase::Issued,
        };
        assert_eq!(ticket.encode(), Err(PublisherDecodeError));
    }

    Ok(())
}
