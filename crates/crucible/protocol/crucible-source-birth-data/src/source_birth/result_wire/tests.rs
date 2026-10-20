//! Exercises real fixed headers, captured bytes, CNP hashes and framing refusals.

use super::*;

fn identity() -> Identity {
    Identity {
        task_digest: [0x31; 32],
        input_digest: [0x72; 32],
    }
}
fn limits() -> WireLimits {
    WireLimits {
        maximum_frame_bytes: 4096,
        maximum_diagnostic_bytes: 1024,
    }
}
fn success_frame() -> Vec<u8> {
    let source = b"{\"source\":1}";
    let registration = b"{\"registration\":2}";
    let header = ResultHeader::success(identity(), source, registration).unwrap();
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(source);
    frame.extend_from_slice(registration);
    frame
}

fn error_frame() -> Vec<u8> {
    let diagnostic = "actual input stream failed: 雪";
    let header = ResultHeader::failure(
        identity(),
        FailureInfo::operational(OperationalReason::InputIo),
        diagnostic,
        1024,
    )
    .unwrap();
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(diagnostic.as_bytes());
    frame
}

#[test]
fn fixed_header_has_explicit_offsets_and_matches_existing_cnp_blob_identity() {
    let source = b"source";
    let registration = b"registration";
    let header = ResultHeader::success(identity(), source, registration).unwrap();
    let bytes = header.encode();

    assert_eq!(bytes.len(), 240);
    assert_eq!(&bytes[..16], b"CSBR0001\0\0\0\0\0\0\0\0");
    assert_eq!(&bytes[16..48], &[0x31; 32]);
    assert_eq!(&bytes[48..80], &[0x72; 32]);
    assert_eq!(&bytes[80..88], &[0, 0, 0, 0, 0, 0, 0, 6]);
    assert_eq!(&bytes[120..128], &[0, 0, 0, 0, 0, 0, 0, 12]);
    assert_eq!(&bytes[160..], &[0; 80]);
    let canonical = crucible_node_format::canonical::hash("cnp.blob.v1", source).unwrap();
    assert_eq!(
        blake3::Hash::from(header.payload_digests()[0])
            .to_hex()
            .to_string(),
        canonical.digest
    );
    assert_eq!(ResultHeader::decode(&bytes).unwrap(), header);
}

#[test]
fn actual_stdout_requires_every_byte_and_exact_eof() {
    for frame in [success_frame(), error_frame()] {
        assert!(verify_stdout(&frame, identity(), limits()).is_ok());
        for length in 0..frame.len() {
            assert_eq!(
                verify_stdout(&frame[..length], identity(), limits()).unwrap_err(),
                WireError::Truncated
            );
        }
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(
            verify_stdout(&trailing, identity(), limits()).unwrap_err(),
            WireError::Trailing
        );
    }
}

#[test]
fn actual_payload_mutation_reordering_and_foreign_job_fail_closed() {
    let frame = success_frame();
    let header = ResultHeader::decode(frame[..HEADER_BYTES].try_into().unwrap()).unwrap();
    let source_len = usize::try_from(header.payload_lengths()[0]).unwrap();
    for (offset, expected) in [
        (HEADER_BYTES, PayloadKind::Source),
        (HEADER_BYTES + source_len, PayloadKind::Registration),
    ] {
        let mut changed = frame.clone();
        changed[offset] ^= 1;
        assert_eq!(
            verify_stdout(&changed, identity(), limits()).unwrap_err(),
            WireError::DigestMismatch(expected)
        );
    }
    let mut swapped = frame[..HEADER_BYTES].to_vec();
    swapped.extend_from_slice(&frame[HEADER_BYTES + source_len..]);
    swapped.extend_from_slice(&frame[HEADER_BYTES..HEADER_BYTES + source_len]);
    assert_eq!(
        verify_stdout(&swapped, identity(), limits()).unwrap_err(),
        WireError::DigestMismatch(PayloadKind::Source)
    );
    for expected in [
        Identity {
            task_digest: [0; 32],
            ..identity()
        },
        Identity {
            input_digest: [0; 32],
            ..identity()
        },
    ] {
        assert_eq!(
            verify_stdout(&frame, expected, limits()).unwrap_err(),
            WireError::ForeignIdentity
        );
    }
}

#[test]
fn unknown_tags_reserved_fields_and_contradictory_status_are_rejected() {
    let frame = success_frame();
    let original: [u8; HEADER_BYTES] = frame[..HEADER_BYTES].try_into().unwrap();
    for (offset, tag) in [
        (8, TagField::Status),
        (9, TagField::Stage),
        (10, TagField::Cause),
        (11, TagField::CoordinateBasis),
    ] {
        let mut bytes = original;
        bytes[offset] = 255;
        assert_eq!(
            ResultHeader::decode(&bytes),
            Err(WireError::UnknownTag(tag, 255))
        );
    }
    for offset in [13, 14, 15, 216, 239] {
        let mut bytes = original;
        bytes[offset] = 1;
        assert_eq!(ResultHeader::decode(&bytes), Err(WireError::Reserved));
    }
    let mut bytes = original;
    bytes[0] ^= 1;
    assert_eq!(ResultHeader::decode(&bytes), Err(WireError::BadMagic));
    for offset in [9, 10, 12, 200, 208] {
        let mut bytes = original;
        bytes[offset] = 1;
        assert!(ResultHeader::decode(&bytes).is_err());
    }
    let mut bytes = original;
    bytes[8] = 1;
    assert_eq!(ResultHeader::decode(&bytes), Err(WireError::InvalidShape));
}

#[test]
fn real_lengths_obey_exact_one_short_and_overflow_limits_before_payloads() {
    let frame = success_frame();
    let exact = WireLimits {
        maximum_frame_bytes: frame.len(),
        maximum_diagnostic_bytes: 0,
    };
    assert!(verify_stdout(&frame, identity(), exact).is_ok());
    assert_eq!(
        verify_stdout(
            &frame,
            identity(),
            WireLimits {
                maximum_frame_bytes: frame.len() - 1,
                ..exact
            }
        )
        .unwrap_err(),
        WireError::FrameLimit
    );
    let mut bytes: [u8; HEADER_BYTES] = frame[..HEADER_BYTES].try_into().unwrap();
    bytes[80..88].copy_from_slice(&u64::MAX.to_be_bytes());
    let header = ResultHeader::decode(&bytes).unwrap();
    assert_eq!(
        header.checked_frame_length(WireLimits {
            maximum_frame_bytes: usize::MAX,
            maximum_diagnostic_bytes: usize::MAX
        }),
        Err(WireError::LengthOverflow)
    );
}

#[test]
fn error_payloads_are_complete_utf8_with_no_banks_or_truncated_diagnostics() {
    let frame = error_frame();
    let verified = verify_stdout(&frame, identity(), limits()).unwrap();
    assert_eq!(verified.header().status(), Status::OperationalFailure);
    assert!(verified.source_bytes().is_empty());
    assert!(verified.registration_bytes().is_empty());
    assert_eq!(verified.diagnostic(), "actual input stream failed: 雪");
    let length = verified.diagnostic().len();
    assert!(
        verify_stdout(
            &frame,
            identity(),
            WireLimits {
                maximum_diagnostic_bytes: length,
                ..limits()
            }
        )
        .is_ok()
    );
    assert_eq!(
        verify_stdout(
            &frame,
            identity(),
            WireLimits {
                maximum_diagnostic_bytes: length - 1,
                ..limits()
            }
        )
        .unwrap_err(),
        WireError::DiagnosticLimit
    );
    assert_eq!(
        ResultHeader::failure(
            identity(),
            FailureInfo::operational(OperationalReason::DiagnosticLimit),
            "whole diagnostic",
            1
        ),
        Err(WireError::DiagnosticLimit)
    );

    let mut changed = frame.clone();
    changed[HEADER_BYTES] ^= 1;
    assert_eq!(
        verify_stdout(&changed, identity(), limits()).unwrap_err(),
        WireError::DigestMismatch(PayloadKind::Diagnostic)
    );
    let mut malformed = frame;
    malformed[HEADER_BYTES] = 255;
    let mut hasher =
        PayloadHasher::diagnostic(u64::try_from(malformed.len() - HEADER_BYTES).unwrap());
    hasher.update(&malformed[HEADER_BYTES..]).unwrap();
    malformed[168..200].copy_from_slice(&hasher.finish().unwrap());
    assert_eq!(
        verify_stdout(&malformed, identity(), limits()).unwrap_err(),
        WireError::InvalidUtf8
    );
    malformed[80..88].copy_from_slice(&1u64.to_be_bytes());
    assert_eq!(
        ResultHeader::decode(malformed[..HEADER_BYTES].try_into().unwrap()),
        Err(WireError::InvalidShape)
    );
}

#[test]
fn streaming_hash_enforces_length_and_domain_without_weakening_actual_bytes() {
    let payload = b"source\0literal";
    let mut split = PayloadHasher::bank(u64::try_from(payload.len()).unwrap());
    split.update(&payload[..3]).unwrap();
    assert_eq!(split.update(payload), Err(WireError::HashLength));
    split.update(&payload[3..]).unwrap();
    let bank = split.finish().unwrap();
    let canonical = crucible_node_format::canonical::hash("cnp.blob.v1", payload).unwrap();
    assert_eq!(
        blake3::Hash::from(bank).to_hex().to_string(),
        canonical.digest
    );
    let mut diagnostic = PayloadHasher::diagnostic(u64::try_from(payload.len()).unwrap());
    diagnostic.update(payload).unwrap();
    assert_ne!(bank, diagnostic.finish().unwrap());
    assert_eq!(PayloadHasher::bank(1).finish(), Err(WireError::HashLength));
}
