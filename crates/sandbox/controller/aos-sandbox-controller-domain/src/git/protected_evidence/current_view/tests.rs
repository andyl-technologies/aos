//! Inert codec, bound and failed-latch vectors; no genuine owner is fabricated.

use super::*;
use sha2::{Digest as _, Sha256};

fn coordinates() -> Coordinates {
    Coordinates { client: [1; 16], root: [2; 16], cutoff: 123 }
}

#[test]
fn bootstrap_has_exact_width_coordinates_and_closed_nonzero_bindings() {
    let expected = coordinates();
    let bytes = expected.encode_bootstrap();

    assert_eq!(&bytes[..8], b"AOSGQV01");
    assert_eq!(&bytes[8..24], &[1; 16]);
    assert_eq!(&bytes[24..], &123_u64.to_be_bytes());
    let decoded = Coordinates::bootstrap(&bytes).unwrap();
    assert_eq!(decoded.client, expected.client);
    assert_eq!(decoded.cutoff, expected.cutoff);
    assert_eq!(decoded.root, [0; 16]);

    let mut changed = bytes;
    changed[0] ^= 1;
    assert!(Coordinates::bootstrap(&changed).is_err());
    changed = bytes;
    changed[8..24].fill(0);
    assert!(Coordinates::bootstrap(&changed).is_err());
    changed = bytes;
    changed[24..].fill(0);
    assert!(Coordinates::bootstrap(&changed).is_err());
}

#[test]
fn header_offsets_are_exact_and_no_truncation_or_trailing_bytes_are_accepted() {
    let expected = coordinates();
    let bytes = expected.header(Phase::Checked, 7, 32).unwrap();

    assert_eq!(bytes.len(), 72);
    assert_eq!(&bytes[..8], b"AOSGVF01");
    assert_eq!(&bytes[8..11], &[0, 1, 4]);
    assert_eq!(&bytes[11..16], &[0; 5]);
    assert_eq!(&bytes[16..32], &[1; 16]);
    assert_eq!(&bytes[32..48], &[2; 16]);
    assert_eq!(&bytes[48..56], &123_u64.to_be_bytes());
    assert_eq!(&bytes[56..60], &7_u32.to_be_bytes());
    assert_eq!(&bytes[60..64], &32_u32.to_be_bytes());
    assert_eq!(&bytes[64..], &[0; 8]);
    assert_eq!(expected.decode_header(&bytes, false).unwrap(), (Phase::Checked, 7, 32, [2; 16]));

    for length in 0..HEADER_BYTES {
        assert!(expected.decode_header(&bytes[..length], false).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(expected.decode_header(&trailing, false).is_err());
    assert!(take::<8>(&bytes, usize::MAX).is_err());
}

#[test]
fn every_reserved_version_phase_and_coordinate_mutation_refuses() {
    let expected = coordinates();
    let bytes = expected.header(Phase::Checked, 1, 32).unwrap();

    for offset in [0, 8, 9, 11, 15, 16, 32, 48, 64, 71] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(expected.decode_header(&changed, false).is_err(), "offset {offset}");
    }
    for code in [0, 8, 255] {
        let mut changed = bytes;
        changed[10] = code;
        assert!(expected.decode_header(&changed, false).is_err());
    }
    let mut zero_root = bytes;
    zero_root[32..48].fill(0);
    assert!(expected.decode_header(&zero_root, false).is_err());
}

#[test]
fn root_nonce_adoption_is_confined_to_the_first_closed_hello() {
    let expected = coordinates();
    let first = Coordinates { root: [0; 16], ..expected };
    let hello = expected.header(Phase::Hello, 0, 16).unwrap();

    assert_eq!(first.decode_header(&hello, true).unwrap().3, [2; 16]);
    assert!(first.decode_header(&hello, false).is_err());
    assert!(expected.decode_header(&hello, true).is_err());
    let record = expected.header(Phase::Record, 0, 152).unwrap();
    assert!(first.decode_header(&record, true).is_err());
}

#[test]
fn sequences_and_all_phase_payload_widths_remain_closed() {
    let expected = coordinates();

    for phase in [Phase::Hello, Phase::Record] {
        assert!(require_sequence(phase, 0).is_ok());
        assert!(require_sequence(phase, 1).is_err());
    }
    for phase in [Phase::Check, Phase::Checked] {
        assert!(require_sequence(phase, 0).is_err());
        assert!(require_sequence(phase, 16).is_ok());
        assert!(require_sequence(phase, 17).is_err());
    }
    for phase in [Phase::Release, Phase::Released, Phase::Terminal] {
        assert!(require_sequence(phase, 0).is_err());
        assert!(require_sequence(phase, 17).is_ok());
        assert!(require_sequence(phase, 18).is_err());
        assert!(expected.header(phase, 1, 31).is_err());
        assert!(expected.header(phase, 1, 32).is_ok());
        assert!(expected.header(phase, 1, 33).is_err());
    }
    assert!(expected.header(Phase::Hello, 0, 15).is_err());
    assert!(expected.header(Phase::Hello, 0, 17).is_err());
    assert!(expected.header(Phase::Check, 1, 0).is_ok());
    assert!(expected.header(Phase::Check, 1, 1).is_err());
}

#[test]
fn record_bound_is_derived_from_the_existing_general_decoder_limits() {
    let maximum = git_evidence_journal_limits().maximum_record_bytes;

    assert_eq!(super::super::FIXED_PREFIX_BYTES, 120);
    assert_eq!(maximum, 33_554_584);
    assert!(Phase::Record.require_length(151).is_err());
    assert!(Phase::Record.require_length(152).is_ok());
    assert!(Phase::Record.require_length(maximum).is_ok());
    assert!(Phase::Record.require_length(maximum + 1).is_err());
    assert!(Phase::Record.require_length(usize::MAX).is_err());
}

#[test]
fn first_typed_cause_is_resident_and_a_later_refusal_cannot_replace_it() {
    let mut carrier = RetainedCarrier::empty();
    let mut latch = Latch::new();
    latch.begin(State::New).unwrap();
    latch.finish(Err(Failure::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied))),
        State::Active, &mut carrier);
    let first = latch.first.as_ref().unwrap() as *const Failure;

    assert!(latch.begin(State::New).is_err());
    latch.finish(Err(Failure::Protocol), State::Active, &mut carrier);
    assert_eq!(latch.first.as_ref().unwrap() as *const Failure, first);
    assert!(matches!(latch.first, Some(Failure::Io(_))));
    assert!(latch.state == State::Failed);
    assert!(latch.error(&carrier).shutdown_failure().is_none());
}

#[test]
fn unfinished_method_cannot_resume_or_fabricate_an_io_cause() {
    let mut latch = Latch::new();
    let carrier = RetainedCarrier::empty();
    latch.begin(State::New).unwrap();

    assert!(latch.state == State::Unfinished);
    assert!(latch.begin(State::New).is_err());
    assert!(latch.begin(State::Active).is_err());
    assert!(latch.first.is_none());
    assert!(matches!(latch.error(&carrier).first, Failure::Unfinished));
}

#[test]
fn metadata_comparison_uses_the_unchanged_canonical_decoder_without_a_claim() {
    // A pure record fixture, not a protected journal, clock, peer or owner.
    let mut bytes = vec![0; super::super::FIXED_PREFIX_BYTES];
    bytes[..8].copy_from_slice(b"AOSGITE1");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..48].fill(1);
    bytes[48..80].fill(2);
    bytes[80..88].copy_from_slice(&100_u64.to_be_bytes());
    bytes[88..96].copy_from_slice(&7_u64.to_be_bytes());
    bytes[96..104].copy_from_slice(&8_u64.to_be_bytes());
    let digest: [u8; 32] = Sha256::new().chain_update(super::super::EVIDENCE_DOMAIN)
        .chain_update(&bytes).finalize().into();
    bytes.extend_from_slice(&digest);
    let decoded = decode_evidence(&bytes).unwrap();
    let metadata = GitRootEvidenceMetadataV1 { bytes: &bytes, decoded: &decoded };

    assert!(std::ptr::eq(metadata.encoded_record().as_ptr(), bytes.as_ptr()));
    assert_eq!(metadata.recorded_times(), (100, 7, 8));
    assert_eq!(metadata.commitments().2.as_bytes(), &digest);
    assert!(metadata.accepted_sets().0.is_empty());
    assert!(metadata.accepted_sets().1.is_empty());
    assert!(metadata.accepted_sets().2.is_empty());
    assert!(metadata.accepted_sets().3.is_empty());

    bytes[16] ^= 1;
    assert!(decode_evidence(&bytes).is_err());
}
