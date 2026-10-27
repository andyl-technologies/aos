//! Checks Cache proof framing, receipt equality and observed clock DATA.
//!
//! Returned receipt and packet slices remain borrowed from the supplied bytes.
//! These comparisons do not authenticate their transport or construct a Root,
//! Cache, Source, signer, paid role or current protected original.

use std::mem::size_of;

use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    current_proofs::{CurrentProofsDataV1, CurrentProofsChallengeDataV1},
    ready::{ReadyBundleDataV1, InputsReadyNativeReceiptDataV1},
    root_open::RootHelloDataV1,
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1},
    use_authorized::CURRENT_PROOFS_PAYLOAD_BYTES_V1,
    use_reserved::{UseCurrentProofsDataV1, USE_CURRENT_PROOFS_BYTES_V1,
        UseReservedNativeReceiptDataV1},
};

/// Holds the exact initial CurrentProofs frame width.
pub const PROOFS_FRAME_BYTES: usize = FRAME_HEADER_BYTES + CURRENT_PROOFS_PAYLOAD_BYTES_V1;

/// Holds the exact reserved-use CurrentProofs frame width.
pub const USE_PROOFS_FRAME_BYTES: usize = FRAME_HEADER_BYTES + USE_CURRENT_PROOFS_BYTES_V1;

/// Decodes the initial proofs at the exact next Phase4 sequence.
///
/// # Errors
/// Preserves original extent, digest, sequence, frame-coordinate and payload errors.
pub fn received_proofs_v1<'frame>(frame: &'frame [u8], hello: RootHelloDataV1<'_>,
    index: aos_sandbox_protocol::domain_ledger::create_storage_history::transport::TransferIndexV1)
    -> Result<CurrentProofsDataV1<'frame>, HistoryErrorV1>
{
    if frame.len() != PROOFS_FRAME_BYTES || index.digest() != hello.body.open.ready {
        return Err(HistoryErrorV1::Correlation);
    }
    let sequence = 4_u64.checked_add(u64::from(index.count())).ok_or(HistoryErrorV1::Extent)?;
    let frame = FrameEnvelopeV1::decode(frame, FrameCoordinatesV1 {
        kind: FrameKindV1::CurrentProofs, lane: hello.body.open.lane, sequence,
        root_nonce: hello.body.root_nonce, controller_nonce: hello.body.open.controller_nonce,
    })?;
    CurrentProofsDataV1::decode(frame.payload(), hello.body.open.lane)
}

/// Decodes reserved-use proofs at their exact next sequence.
///
/// # Errors
/// Preserves original extent, digest, sequence, frame-coordinate and payload errors.
pub fn received_use_proofs_v1<'frame>(frame: &'frame [u8], hello: RootHelloDataV1<'_>,
    index: aos_sandbox_protocol::domain_ledger::create_storage_history::transport::TransferIndexV1)
    -> Result<UseCurrentProofsDataV1<'frame>, HistoryErrorV1>
{
    if frame.len() != USE_PROOFS_FRAME_BYTES || index.digest() != hello.body.open.ready {
        return Err(HistoryErrorV1::Correlation);
    }
    let sequence = 8_u64.checked_add(u64::from(index.count())).ok_or(HistoryErrorV1::Extent)?;
    let frame = FrameEnvelopeV1::decode(frame, FrameCoordinatesV1 {
        kind: FrameKindV1::UseCurrentProofs, lane: hello.body.open.lane, sequence,
        root_nonce: hello.body.root_nonce, controller_nonce: hello.body.open.controller_nonce,
    })?;
    UseCurrentProofsDataV1::decode(frame.payload(), hello.body.open.lane)
}

/// Compares every retained reserved receipt field for exact equality.
///
/// # Errors
/// Returns a correlation error for different record, head, names or native positions.
pub fn require_same_reserved_receipt_v1(actual: UseReservedNativeReceiptDataV1<'_>,
    expected: UseReservedNativeReceiptDataV1<'_>) -> Result<(), HistoryErrorV1>
{
    if actual.record != expected.record || actual.latest_head != expected.latest_head
        || actual.names != expected.names || actual.after_next != expected.after_next
        || actual.after_end != expected.after_end
    { return Err(HistoryErrorV1::Correlation); }
    Ok(())
}

/// Checks that a signed sample lies within both Root observation samples.
///
/// # Errors
/// Returns a correlation error for a different boot or an out-of-interval clock field.
pub fn require_observed_clock(signed: RawPairedClockSample, before: RawPairedClockSample, after: RawPairedClockSample)
    -> Result<(), HistoryErrorV1>
{
    if signed.host_boot_id() != before.host_boot_id() || signed.host_boot_id() != after.host_boot_id()
        || signed.boottime_nanoseconds() < before.boottime_nanoseconds()
        || signed.boottime_nanoseconds() > after.boottime_nanoseconds()
        || signed.wall_seconds() < before.wall_seconds() || signed.wall_seconds() > after.wall_seconds()
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

/// Quotes the two original fixed Cache framing carriers.
#[must_use]
pub const fn fixed_framing_receiving_bytes_v1() -> Option<usize> {
    size_of::<FixedCacheFramingV1>().checked_mul(2)
}

/// Names the added passive roster supplier and its caller's interface controls.
///
/// The checked-multiply result, supplier return and added checked-sum result
/// each retain their actual Option plane. Separate usize pairs name the new
/// callee multiplication and the caller's interface addition. This constant
/// introduces no additional runtime quote helper or native resource identity.
pub const FRAMING_INTERFACE_CONTROL_BYTES_V1: usize =
    9 * size_of::<Option<usize>>() + 6 * size_of::<(usize, usize)>();

#[allow(dead_code)]
struct FixedCacheFramingV1 {
    bundles: [ReadyBundleDataV1<'static>; 2],
    frames: [FrameEnvelopeV1<'static>; 4],
    coordinates: [FrameCoordinatesV1; 4],
    hellos: [RootHelloDataV1<'static>; 4],
    proofs: [CurrentProofsDataV1<'static>; 4],
    invitations: [CurrentProofsChallengeDataV1; 2],
    receipts: [InputsReadyNativeReceiptDataV1<'static>; 4],
    readers: [aos_sandbox_model::bounded_codec::BoundedReader<'static, HistoryErrorV1>; 8],
    hashers: [sha2::Sha256; 2],
    clock_samples: [RawPairedClockSample; 4],
    cutoff: [u64; 4],
}

#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::
    ROOT_HELLO_FRAME_BYTES_V1 as HELLO_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
        association::AcceptedAssociationDataV1,
        ready::InputsReadyBodyDataV1,
        root_open::RootOpenBodyDataV1,
        transport::{OpenQueryV1, TransferIndexV1},
    };
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

    fn sample(provenance: u8, boot: u8, wall: i64, ticks: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([provenance; 16]).unwrap(), [boot; 16], wall, ticks,
        ).unwrap()
    }

    #[test]
    fn second_proof_requires_the_exact_reserved_record_names_and_native_positions() {
        // Equality DATA only. The production path decodes the authenticated
        // frame first and gets expected bytes only from Root's completed replay.
        // This fixture cannot construct a Root receiver, native loan or U.
        let record = [7; 1904];
        let changed_record = [8; 1904];
        let expected = UseReservedNativeReceiptDataV1 {
            record: &record, latest_head: [9; 40],
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            after_next: 41, after_end: 4096,
        };
        assert!(require_same_reserved_receipt_v1(expected, expected).is_ok());
        for changed in [
            UseReservedNativeReceiptDataV1 { record: &changed_record, ..expected },
            UseReservedNativeReceiptDataV1 { latest_head: [10; 40], ..expected },
            UseReservedNativeReceiptDataV1 {
                names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 7)),
                ..expected
            },
            UseReservedNativeReceiptDataV1 { after_next: expected.after_next + 1, ..expected },
            UseReservedNativeReceiptDataV1 { after_end: expected.after_end + 1, ..expected },
        ] {
            assert_eq!(require_same_reserved_receipt_v1(changed, expected),
                Err(HistoryErrorV1::Correlation));
        }
    }

    #[test]
    fn independently_observed_cache_clock_must_lie_inside_both_root_samples() {
        let before = sample(1, 2, 30, 40);
        let after = sample(1, 2, 32, 42);
        let signed = sample(3, 2, 31, 41);

        assert!(require_observed_clock(signed, before, after).is_ok());
        assert!(require_observed_clock(sample(3, 4, 31, 41), before, after).is_err());
        assert!(require_observed_clock(sample(3, 2, 31, 39), before, after).is_err());
        assert!(require_observed_clock(sample(3, 2, 31, 43), before, after).is_err());
        assert!(require_observed_clock(sample(3, 2, 29, 41), before, after).is_err());
        assert!(require_observed_clock(sample(3, 2, 33, 41), before, after).is_err());
    }

    #[test]
    fn phase_four_requires_the_actual_next_sequence_and_retains_exact_packet_slice() {
        // These are codec DATA fixtures. They do not construct a Root R,
        // Controller writer, Cache signature, authenticated peer or purpose.
        let open = OpenQueryV1 {
            controller_nonce: [1; 16], lane: [2; 16], seed: [3; 32], ready: [4; 32],
        };
        let body = RootOpenBodyDataV1 {
            open, root_nonce: [5; 16], boot: [6; 16], started: 100, cutoff: 200,
            authority_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
            authority_next: 11, policy_next: 1, root_profile: [12; 32],
            root_recipient: [13; 16], root_producer: [14; 16], root_pid: 15,
            controller_pid: 16, controller_uid: 17, controller_gid: 18,
        };
        let mut record = [0; 500];
        RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(open.lane, OwnerV1::Root, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 1).unwrap(),
            predecessor: [0; 32], correlation: open.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let mut hello_bytes = [0; HELLO_BYTES];
        hello_bytes[..FRAME_HEADER_BYTES].copy_from_slice(&FrameCoordinatesV1 {
            kind: FrameKindV1::Hello, lane: open.lane, sequence: 1,
            root_nonce: body.root_nonce, controller_nonce: open.controller_nonce,
        }.encode_header(&record).unwrap());
        hello_bytes[FRAME_HEADER_BYTES..].copy_from_slice(&record);
        let hello = RootHelloDataV1::decode(&hello_bytes, open).unwrap();
        let index = TransferIndexV1::new(1, open.ready).unwrap();
        let inputs = InputsReadyBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [2; 16], project: [3; 16], sandbox: [4; 16],
                accepted_request: [5; 32], coissuance_binding: [6; 32], seed: open.seed,
                controller_nonce: open.controller_nonce, boot: body.boot,
                started: 100, cutoff: 200,
            },
            assignment_planned: [12; 32], ready: open.ready, bundle_bytes: 14,
        };
        let mut inputs_record = [0; 412];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(open.lane, OwnerV1::Controller, 3).unwrap(),
            phase: PhaseV1::new(OwnerV1::Controller, 2).unwrap(),
            predecessor: inputs.assignment_planned, correlation: open.seed,
        }, &inputs.encode().unwrap(), &mut inputs_record).unwrap();
        let receipt = InputsReadyNativeReceiptDataV1 {
            record: &inputs_record,
            latest_head: LatestHeadV1::new(3, checksum).unwrap().encode(),
            names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
            after_next: 15, after_end: 16,
        };
        let packet = [42; 1064];
        let proofs = CurrentProofsDataV1 { controller: receipt, cache_packet: &packet };
        let mut payload = [0; CURRENT_PROOFS_PAYLOAD_BYTES_V1];
        proofs.encode_into(open.lane, &mut payload).unwrap();
        let mut coordinates = FrameCoordinatesV1 {
            kind: FrameKindV1::CurrentProofs, lane: open.lane, sequence: 5,
            root_nonce: body.root_nonce, controller_nonce: open.controller_nonce,
        };
        let mut frame = Vec::from(coordinates.encode_header(&payload).unwrap());
        frame.extend_from_slice(&payload);

        let accepted = received_proofs_v1(&frame, hello, index).unwrap();
        assert_eq!(accepted.cache_packet, packet);
        assert_eq!(accepted.cache_packet.as_ptr(), frame[FRAME_HEADER_BYTES + 532..].as_ptr());

        coordinates.sequence -= 1;
        frame[..FRAME_HEADER_BYTES].copy_from_slice(&coordinates.encode_header(&payload).unwrap());
        assert!(received_proofs_v1(&frame, hello, index).is_err());
        coordinates.sequence += 2;
        frame[..FRAME_HEADER_BYTES].copy_from_slice(&coordinates.encode_header(&payload).unwrap());
        assert!(received_proofs_v1(&frame, hello, index).is_err());
    }
}
