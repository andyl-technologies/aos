//! Real datagram/credit controls with explicitly modeled consumed native facts.
//!
//! These tests exercise framing and retained publication only. The constructed
//! records issue no source RootSeal, acquired epoch, consumed native ACK or Ready.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::native_node_control::administrative_mailbox::{
    NativeAdministrativeClass, NativeAdministrativeReceive,
};
use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NativeChannel, NativeControlEdition, NativeInitializationReceipt, NativeInitializationStatus,
};

fn facts() -> Result<NativePrefixPreparationFacts, NativeCommandError> {
    let mut bytes = [0; 640];
    for (offset, value) in [
        (0, 1u32),
        (4, 640),
        (8, 1),
        (12, 328),
        (312, 2),
        (316, 7),
        (320, 1),
        (324, 1),
        (328, 64),
        (632, 1),
        (636, 1),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    for (offset, value) in [
        (272, 65536u64),
        (280, 32 * 1024 * 1024),
        (296, 1024),
        (304, 64),
        (552, 1),
        (568, 2),
        (576, 50),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    for (offset, value) in [
        (16, 1u8),
        (48, 2),
        (80, 3),
        (112, 4),
        (144, 5),
        (176, 6),
        (208, 7),
        (240, 8),
        (520, 10),
    ] {
        bytes[offset..offset + 32].fill(value);
    }
    let initialization = NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 3,
        sequence: U64::new(1),
        hold_generation: U64::new(1),
        prepared_scope_hash: [1; 32],
        initialization_commitment: [5; 32],
        original_cut_digest: [9; 32],
        realize_request_digest: [3; 32],
    };
    bytes[336..496].copy_from_slice(&initialization.encode()?);
    NativePrefixPreparationFacts::decode(&bytes)
}

#[test]
fn original_initial_query_keeps_its_real_credit_and_identical_cached_body()
-> Result<(), Box<dyn std::error::Error>> {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::PrefixEffect)?;
    let mut endpoint = Some(native);
    let actor =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)?;
    let query = NativeFrame::QueryPrefixPreparation {
        scope: [1; 32],
        prefix_preparation: [10; 32],
    };
    assert!(host.send(&query)?);
    assert_eq!(
        actor.receive_one()?,
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::ReadOriginal)
    );
    let original_bytes = actor.original(1)?;
    let credit = actor.reserve_construction_reply(1)?;
    actor.validate_unpublished_credit(&credit)?;
    let reply = NativeFrame::PrefixPreparationFacts(Box::new(facts()?));
    let mut original = Original {
        frame: query.clone(),
        cursor: 1,
        credit: Some(credit),
        reply: Some(reply.clone()),
        retained: false,
        published: false,
        repeated: None,
    };

    original.publish(&actor)?;
    assert!(original.retained && original.published);
    assert_eq!(host.receive()?, Some(reply.clone()));
    original.published = false;
    original.publish(&actor)?;
    assert_eq!(host.receive()?, Some(reply));
    assert_eq!(actor.original_frame(1)?, query);
    assert_eq!(actor.original(1)?, original_bytes);
    assert!(original.credit.is_none());
    Ok(())
}

#[test]
fn modeled_consumed_initial_ack_must_match_all_original_reply_correlations()
-> Result<(), Box<dyn std::error::Error>> {
    let offered = NativePrefixPreparationAcknowledgement {
        scope: [1; 32],
        prefix_preparation: [2; 32],
        facts_digest: [3; 32],
        initialization_cut: [4; 32],
        initialization_sequence: U64::new(1),
        epoch_incarnation: U64::new(2),
        acknowledgement_sequence: U64::new(1),
    };
    for field in 0..7 {
        let (host, native) =
            NativeChannel::supervised_pair_for_edition(NativeControlEdition::PrefixEffect)?;
        let mut endpoint = Some(native);
        let actor = NativeAdministrativeInbox::from_pinned_endpoint(
            &mut endpoint,
            [1; 32],
            false,
            8,
            65536,
        )?;
        let frame = NativeFrame::AcknowledgePrefixPreparation(offered.clone());
        assert!(host.send(&frame)?);
        assert_eq!(
            actor.receive_one()?,
            NativeAdministrativeReceive::Retained(
                1,
                NativeAdministrativeClass::AcknowledgeOriginal
            )
        );
        let body = actor.original(1)?;
        let mut credit = Some(actor.reserve_construction_reply(1)?);
        let mut consumed = offered.clone();
        match field {
            0 => consumed.scope[0] ^= 1,
            1 => consumed.prefix_preparation[0] ^= 1,
            2 => consumed.facts_digest[0] ^= 1,
            3 => consumed.initialization_cut[0] ^= 1,
            4 => consumed.initialization_sequence = U64::new(2),
            5 => consumed.epoch_incarnation = U64::new(3),
            _ => consumed.acknowledgement_sequence = U64::new(2),
        }

        assert!(
            actor
                .retain_construction_reply(
                    &mut credit,
                    &NativeFrame::PrefixPreparationAcknowledged(consumed)
                )
                .is_err()
        );
        assert_eq!(actor.original(1)?, body);
        assert_eq!(actor.original_frame(1)?, frame);
        assert!(host.receive()?.is_none());
    }
    Ok(())
}

#[test]
fn native_preparation_storage_has_exact_extent_alignment_and_scalar_conversion() {
    assert_eq!(std::mem::size_of::<NativeStorage<640>>(), 640);
    assert_eq!(std::mem::align_of::<NativeStorage<640>>(), 8);
    assert_eq!(std::mem::size_of::<NativeStorage<160>>(), 160);
    let mut native = [0; 640];
    for offset in [
        0, 4, 8, 12, 312, 316, 320, 324, 328, 332, 336, 340, 344, 348, 512, 516, 624, 628, 632, 636,
    ] {
        native[offset..offset + 4].copy_from_slice(&0x01020304u32.to_ne_bytes());
    }
    for offset in [
        272, 280, 288, 296, 304, 352, 360, 496, 504, 552, 560, 568, 576, 584, 592, 600, 608, 616,
    ] {
        native[offset..offset + 8].copy_from_slice(&0x0102030405060708u64.to_ne_bytes());
    }
    native[520..552].fill(0x55);

    let canonical = canonical_facts(native);

    assert_eq!(&canonical[..8], &[1, 2, 3, 4, 1, 2, 3, 4]);
    assert_eq!(&canonical[352..360], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        &canonical[624..640],
        &[1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]
    );
    assert_eq!(&canonical[520..552], &[0x55; 32]);
}

#[test]
fn equal_initial_query_uses_each_actual_datagram_credit_without_replacing_history()
-> Result<(), Box<dyn std::error::Error>> {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::PrefixEffect)?;
    let mut endpoint = Some(native);
    let actor =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)?;
    let query = NativeFrame::QueryPrefixPreparation {
        scope: [1; 32],
        prefix_preparation: [10; 32],
    };
    assert!(host.send(&query)?);
    assert_eq!(
        actor.receive_one()?,
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::ReadOriginal)
    );
    let mut original = Original {
        frame: query.clone(),
        cursor: 1,
        credit: Some(actor.reserve_construction_reply(1)?),
        reply: Some(NativeFrame::PrefixPreparationFacts(Box::new(facts()?))),
        retained: false,
        published: false,
        repeated: None,
    };
    original.publish(&actor)?;
    let first = host.receive()?.ok_or(NativeCommandError::Conflict)?;

    for cursor in [2, 3] {
        assert!(host.send(&query)?);
        assert_eq!(
            actor.receive_one()?,
            NativeAdministrativeReceive::Retained(cursor, NativeAdministrativeClass::ReadOriginal)
        );
        assert!(original.admit_repeated(&actor, cursor, &actor.original_frame(cursor)?)?);
        original.publish(&actor)?;
        assert_eq!(host.receive()?, Some(first.clone()));
        assert_eq!(actor.original_frame(cursor)?, query);
        assert_eq!(original.cursor, 1);
        assert_eq!(original.frame, query);
        assert!(original.credit.is_none());
    }
    let changed = NativeFrame::QueryPrefixPreparation {
        scope: [1; 32],
        prefix_preparation: [11; 32],
    };
    assert!(host.send(&changed)?);
    assert_eq!(
        actor.receive_one()?,
        NativeAdministrativeReceive::Retained(4, NativeAdministrativeClass::ReadOriginal)
    );
    assert!(
        original
            .admit_repeated(&actor, 4, &actor.original_frame(4)?)
            .is_err()
    );
    assert_eq!(original.cursor, 1);
    assert_eq!(original.frame, query);
    Ok(())
}

#[test]
fn equal_consumed_initial_ack_recovers_only_the_retained_native_response()
-> Result<(), Box<dyn std::error::Error>> {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::PrefixEffect)?;
    let mut endpoint = Some(native);
    let actor =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)?;
    let ack = NativePrefixPreparationAcknowledgement {
        scope: [1; 32],
        prefix_preparation: [2; 32],
        facts_digest: [3; 32],
        initialization_cut: [4; 32],
        initialization_sequence: U64::new(1),
        epoch_incarnation: U64::new(2),
        acknowledgement_sequence: U64::new(1),
    };
    let frame = NativeFrame::AcknowledgePrefixPreparation(ack.clone());
    assert!(host.send(&frame)?);
    assert_eq!(
        actor.receive_one()?,
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::AcknowledgeOriginal)
    );
    let mut original = Original {
        frame: frame.clone(),
        cursor: 1,
        credit: Some(actor.reserve_construction_reply(1)?),
        reply: None,
        retained: false,
        published: false,
        repeated: None,
    };
    assert!(host.send(&frame)?);
    assert_eq!(
        actor.receive_one()?,
        NativeAdministrativeReceive::Retained(2, NativeAdministrativeClass::AcknowledgeOriginal)
    );
    assert!(!original.admit_repeated(&actor, 2, &frame)?);
    assert!(original.repeated.is_none());
    original.reply = Some(NativeFrame::PrefixPreparationAcknowledged(ack.clone()));
    original.publish(&actor)?;
    assert_eq!(
        host.receive()?,
        Some(NativeFrame::PrefixPreparationAcknowledged(ack.clone()))
    );
    assert!(original.admit_repeated(&actor, 2, &frame)?);
    original.publish(&actor)?;
    assert_eq!(
        host.receive()?,
        Some(NativeFrame::PrefixPreparationAcknowledged(ack))
    );
    assert_eq!(original.cursor, 1);
    assert!(original.credit.is_none());
    Ok(())
}
