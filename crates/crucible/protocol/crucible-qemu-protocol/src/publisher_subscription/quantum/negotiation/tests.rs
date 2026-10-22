//! Checks exact negotiation editions and changed physical observations.
//!
//! These syntax fixtures issue no sealed carrier, operation or Source owner.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publisher_subscription::PublisherHeader;

fn observations() -> (
    QuantumPublisherPurpose,
    QuantumPublisherSetup,
    QuantumPublisherHeader,
) {
    let purpose = PublisherPurpose {
        lender_generation: 3,
        account_generation: 5,
        process_generation: 7,
        capability: [2; 32],
        reservation: [4; 32],
        device: 0,
        inode: 0,
        producer_event: 11,
        receiver_event: 13,
        backing_bytes: 65_536,
    };
    let setup = PublisherSetup {
        region_len: 8192,
        process_generation: purpose.process_generation,
        device_digest_workspace: None,
        lender_generation: purpose.lender_generation,
        device: purpose.device,
        inode: purpose.inode,
        producer_event: purpose.producer_event,
        receiver_event: purpose.receiver_event,
    };
    let header = PublisherHeader {
        lender_generation: purpose.lender_generation,
        account_generation: purpose.account_generation,
        process_generation: purpose.process_generation,
        capability: purpose.capability,
        reservation: purpose.reservation,
        node_index: 0,
        node_count: 1,
    };
    (
        QuantumPublisherPurpose { session: purpose },
        QuantumPublisherSetup { transport: setup },
        QuantumPublisherHeader { identity: header },
    )
}

#[test]
fn negotiation_literals_preserve_physical_inventory_and_select_distinct_editions() {
    let (purpose, setup, header) = observations();
    let sealed = purpose.encode().unwrap();
    let frame = setup.encode().unwrap();

    assert_eq!(&sealed[..16], b"CRUCPSP2\0\0\0\x02\0\0\0\xe0");
    assert_eq!(
        &sealed[192..],
        &[
            0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]
    );
    assert_eq!(&frame[..5], &[0, 0, 0, 121, 0x17]);
    assert_eq!(
        &frame[109..],
        &[0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        &sealed[16..192],
        &purpose.session.encode().unwrap()[16..192]
    );
    assert_eq!(&frame[5..109], &setup.transport.encode().unwrap()[5..109]);
    assert_eq!(QuantumPublisherPurpose::decode(&sealed), Ok(purpose));
    assert_eq!(QuantumPublisherSetup::decode(&frame), Ok(setup));
    assert!(purpose.validate_correspondence(&setup, &header).is_ok());

    assert!(PublisherPurpose::decode(&sealed).is_err());
    assert!(PublisherSetup::decode(&frame).is_err());
    assert!(QuantumPublisherPurpose::decode(&purpose.session.encode().unwrap()).is_err());
    assert!(QuantumPublisherSetup::decode(&setup.transport.encode().unwrap()).is_err());
}

#[test]
fn negotiation_refuses_every_truncation_and_changed_contract_or_reserved_byte() {
    let (purpose, setup, _) = observations();
    let sealed = purpose.encode().unwrap();
    let frame = setup.encode().unwrap();

    for length in 0..sealed.len() {
        assert!(QuantumPublisherPurpose::decode(&sealed[..length]).is_err());
    }
    for length in 0..frame.len() {
        assert!(QuantumPublisherSetup::decode(&frame[..length]).is_err());
    }
    assert!(QuantumPublisherPurpose::decode(&[sealed.as_slice(), &[0]].concat()).is_err());
    assert!(QuantumPublisherSetup::decode(&[frame.as_slice(), &[0]].concat()).is_err());

    for offset in (0..16).chain(120..128).chain(152..224) {
        let mut changed = sealed;
        changed[offset] ^= 1;
        assert!(
            QuantumPublisherPurpose::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    for offset in (0..5).chain(69..77).chain(109..125) {
        let mut changed = frame;
        changed[offset] ^= 1;
        assert!(
            QuantumPublisherSetup::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn correspondence_refuses_individually_valid_foreign_source_file_and_events() {
    let (purpose, setup, header) = observations();
    let bytes = purpose.encode().unwrap();

    for offset in [16, 24, 32, 40, 72, 104, 112, 128, 136] {
        let mut changed = bytes;
        changed[offset + 7] ^= 1;
        let foreign = QuantumPublisherPurpose::decode(&changed).unwrap();
        assert!(
            foreign.validate_correspondence(&setup, &header).is_err(),
            "offset {offset}"
        );
    }
}
