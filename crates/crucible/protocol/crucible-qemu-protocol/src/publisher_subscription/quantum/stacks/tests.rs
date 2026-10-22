//! Checks independent literal stack records, edition refusal and checked sums.
//!
//! All records here are syntax fixtures; they issue no stack or cleanup holder.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publisher_subscription::{PublisherHeader, PublisherPurpose, PublisherSetup};

pub(crate) fn purpose() -> QuantumStackPurpose {
    QuantumStackPurpose {
        grant_set_generation: 17,
        process_generation: 7,
        account_generation: 5,
        lender_generation: 3,
        capability: [2; 32],
        reservation: [4; 32],
        main: QuantumStackReservation {
            loan_generation: 11,
            usable_bytes: 8193,
            mapping_bytes: 12288,
            thread_control_bytes: 256,
            loader_tls_bytes: 512,
            page_bytes: 4096,
            profile_digest: [9; 32],
            cleanup_generation: 31,
        },
        rr: QuantumStackReservation {
            loan_generation: 13,
            usable_bytes: 32768,
            mapping_bytes: 40960,
            thread_control_bytes: 512,
            loader_tls_bytes: 1024,
            page_bytes: 4096,
            profile_digest: [10; 32],
            cleanup_generation: 37,
        },
    }
}

#[test]
fn stack_purpose_matches_independent_literal_header_and_both_role_records() {
    let value = purpose();
    let mut literal = [0; 576];
    literal[..24].copy_from_slice(b"CRUCSTK1\0\0\0\x01\0\0\0\x40\0\0\x02\x40\0\0\0\x02");
    for (offset, number) in [(24, 17_u64), (32, 7), (40, 5), (48, 3)] {
        literal[offset..offset + 8].copy_from_slice(&number.to_be_bytes());
    }
    for (base, role, values, profile) in [
        (
            64,
            1_u32,
            [11_u64, 8193, 0, 12288, 256, 512, 4096, 8193, 8193, 31],
            9,
        ),
        (
            320,
            2,
            [13, 32768, 8192, 40960, 512, 1024, 4096, 0, 0, 37],
            10,
        ),
    ] {
        literal[base..base + 4].copy_from_slice(&role.to_be_bytes());
        for (offset, number) in [
            (8, values[0]),
            (16, 5),
            (24, 7),
            (96, values[1]),
            (104, values[2]),
            (112, values[3]),
            (120, values[4]),
            (128, values[5]),
            (136, values[6]),
            (144, values[7]),
            (152, values[8]),
            (192, values[9]),
            (200, 1),
            (208, 1),
            (216, 1),
        ] {
            literal[base + offset..base + offset + 8].copy_from_slice(&number.to_be_bytes());
        }
        literal[base + 32..base + 64].fill(2);
        literal[base + 64..base + 96].fill(4);
        literal[base + 160..base + 192].fill(profile);
    }

    assert_eq!(value.encode().unwrap(), literal);
    assert_eq!(QuantumStackPurpose::decode(&literal), Ok(value));
    assert_eq!(value.reserved_bytes(), Ok(55_552));
}

#[test]
fn stack_purpose_refuses_every_short_record_and_each_fixed_or_repeated_field() {
    let bytes = purpose().encode().unwrap();
    for length in 0..bytes.len() {
        assert!(QuantumStackPurpose::decode(&bytes[..length]).is_err());
    }
    assert!(QuantumStackPurpose::decode(&[bytes.as_slice(), &[0]].concat()).is_err());

    let fixed = (0..24)
        .chain(56..64)
        .chain([64, 320].into_iter().flat_map(|base| {
            (base..base + 8)
                .chain(base + 16..base + 96)
                .chain(base + 104..base + 120)
                .chain(base + 144..base + 160)
                .chain(base + 200..base + 256)
        }));
    for offset in fixed {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            QuantumStackPurpose::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn stack_geometry_refuses_exhaustion_rounding_and_inventory_overflow() {
    let original = purpose();
    for bad in [0, u64::MAX] {
        for field in 0..8 {
            let mut value = original;
            match field {
                0 => value.grant_set_generation = bad,
                1 => value.process_generation = bad,
                2 => value.account_generation = bad,
                3 => value.lender_generation = bad,
                4 => value.main.loan_generation = bad,
                5 => value.rr.loan_generation = bad,
                6 => value.main.cleanup_generation = bad,
                _ => value.rr.cleanup_generation = bad,
            }
            assert!(value.encode().is_err());
        }
    }
    for field in 0..10 {
        let mut value = original;
        match field {
            0 => value.main.usable_bytes = u64::MAX - 1,
            1 => value.rr.usable_bytes += 1,
            2 => value.rr.page_bytes = 0,
            3 => value.main.mapping_bytes += 1,
            4 => value.main.profile_digest = [0; 32],
            5 => value.capability = [0; 32],
            6 => value.reservation = [0; 32],
            7 => value.main.thread_control_bytes = u64::MAX,
            8 => value.rr.loader_tls_bytes = u64::MAX,
            _ => value.rr.page_bytes *= 2,
        }
        assert!(value.encode().is_err(), "field {field}");
    }
    let mut aggregate = original;
    aggregate.main.thread_control_bytes = u64::MAX - aggregate.main.reserved_bytes().unwrap();
    assert!(aggregate.main.reserved_bytes().is_ok());
    assert!(aggregate.reserved_bytes().is_err());
    assert!(aggregate.encode().is_err());

    for page in [4096_u64, 16384, 65536] {
        let mut value = original;
        value.main.page_bytes = page;
        value.main.usable_bytes = page + 1;
        value.main.mapping_bytes = 2 * page;
        value.rr.page_bytes = page;
        value.rr.usable_bytes = 8 * page;
        value.rr.mapping_bytes = 10 * page;
        assert_eq!(
            QuantumStackPurpose::decode(&value.encode().unwrap()),
            Ok(value)
        );
    }
}

fn observations() -> (
    QuantumStackPublisherSetup,
    QuantumPublisherPurpose,
    QuantumPublisherHeader,
) {
    let value = purpose();
    let session = PublisherPurpose {
        lender_generation: value.lender_generation,
        account_generation: value.account_generation,
        process_generation: value.process_generation,
        capability: value.capability,
        reservation: value.reservation,
        device: 0,
        inode: 0,
        producer_event: 11,
        receiver_event: 13,
        backing_bytes: 65536,
    };
    let publisher = QuantumPublisherSetup {
        transport: PublisherSetup {
            region_len: 8192,
            process_generation: session.process_generation,
            device_digest_workspace: None,
            lender_generation: session.lender_generation,
            device: session.device,
            inode: session.inode,
            producer_event: session.producer_event,
            receiver_event: session.receiver_event,
        },
    };
    let header = QuantumPublisherHeader {
        identity: PublisherHeader {
            lender_generation: session.lender_generation,
            account_generation: session.account_generation,
            process_generation: session.process_generation,
            capability: session.capability,
            reservation: session.reservation,
            node_index: 0,
            node_count: 1,
        },
    };
    (
        QuantumStackPublisherSetup {
            publisher,
            grant_set_generation: value.grant_set_generation,
        },
        QuantumPublisherPurpose { session },
        header,
    )
}

#[test]
fn setup_eight_has_literal_extension_and_mutually_refuses_prior_editions() {
    let (setup, publisher, header) = observations();
    let bytes = setup.encode().unwrap();
    assert_eq!(&bytes[..5], &[0, 0, 0, 121, 0x18]);
    assert_eq!(&bytes[117..], &17_u64.to_be_bytes());
    assert_eq!(QuantumStackPublisherSetup::decode(&bytes), Ok(setup));
    assert!(QuantumPublisherSetup::decode(&bytes).is_err());
    assert!(PublisherSetup::decode(&bytes).is_err());
    assert!(QuantumStackPublisherSetup::decode(&setup.publisher.encode().unwrap()).is_err());
    assert!(
        QuantumStackPublisherSetup::decode(&setup.publisher.transport.encode().unwrap()).is_err()
    );
    purpose()
        .validate_correspondence(&setup, &publisher, &header)
        .unwrap();
    for length in 0..bytes.len() {
        assert!(QuantumStackPublisherSetup::decode(&bytes[..length]).is_err());
    }
    assert!(QuantumStackPublisherSetup::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    for offset in [0, 4, 109, 113] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(QuantumStackPublisherSetup::decode(&changed).is_err());
    }
    for bad in [0_u64, u64::MAX] {
        let mut changed = bytes;
        changed[117..].copy_from_slice(&bad.to_be_bytes());
        assert!(QuantumStackPublisherSetup::decode(&changed).is_err());
    }
}

#[test]
fn stack_correspondence_refuses_every_changed_parent_coordinate() {
    let (setup, publisher, header) = observations();
    for field in 0..6 {
        let mut value = purpose();
        match field {
            0 => value.grant_set_generation += 1,
            1 => value.process_generation += 1,
            2 => value.account_generation += 1,
            3 => value.lender_generation += 1,
            4 => value.capability[0] ^= 1,
            _ => value.reservation[0] ^= 1,
        }
        assert!(value.encode().is_ok());
        assert!(
            value
                .validate_correspondence(&setup, &publisher, &header)
                .is_err()
        );
    }
    let mut changed = header;
    changed.identity.reservation[0] ^= 1;
    assert!(
        purpose()
            .validate_correspondence(&setup, &publisher, &changed)
            .is_err()
    );
}

#[test]
fn stack_purpose_refuses_non_power_of_two_pages_even_when_all_geometry_matches() {
    for page in [3_u64, 6144, 12288] {
        let mut value = purpose();
        value.main.page_bytes = page;
        value.main.usable_bytes = page + 1;
        value.main.mapping_bytes = 2 * page;
        value.rr.page_bytes = page;
        value.rr.usable_bytes = 8 * page;
        value.rr.mapping_bytes = 10 * page;

        let mut wire = purpose().encode().unwrap();
        for (offset, number) in [
            (64 + 96, page + 1),
            (64 + 112, 2 * page),
            (64 + 136, page),
            (64 + 144, page + 1),
            (64 + 152, page + 1),
            (320 + 96, 8 * page),
            (320 + 104, 2 * page),
            (320 + 112, 10 * page),
            (320 + 136, page),
        ] {
            wire[offset..offset + 8].copy_from_slice(&number.to_be_bytes());
        }

        assert!(
            QuantumStackPurpose::decode(&wire).is_err(),
            "decode page {page}"
        );
        assert!(value.encode().is_err(), "encode page {page}");
    }
}
