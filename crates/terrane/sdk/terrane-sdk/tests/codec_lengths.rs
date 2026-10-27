//! Checks bounded encoded lengths without treating frame metadata as verification.

#![cfg(feature = "std")]

use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_sdk::codec::{self, FrameError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn measured_raw_length_remains_bounded() -> TestResult {
    assert_eq!(codec::encoded_plaintext_len(&[0, 1, 2, 3], 3)?, 3);
    assert!(codec::encoded_plaintext_len(&[0, 1, 2, 3], 2).is_err());
    assert!(codec::encoded_plaintext_len(&[], 3).is_err());
    Ok(())
}

#[test]
fn compressed_length_rejects_truncation_concatenation_and_allocation_overflow() -> TestResult {
    let plaintext = vec![0x5a; 262_144];
    let encoded = codec::encode_chunk(&plaintext, plaintext.len(), 3, None)?;
    assert_ne!(encoded[0], 0);
    assert_eq!(
        codec::encoded_plaintext_len(&encoded, plaintext.len())?,
        plaintext.len()
    );
    assert!(codec::encoded_plaintext_len(&encoded, plaintext.len() - 1).is_err());
    assert!(codec::encoded_plaintext_len(&encoded[..encoded.len() - 1], plaintext.len()).is_err());

    let mut concatenated = encoded.clone();
    concatenated.extend_from_slice(&encoded[1..]);
    assert!(codec::encoded_plaintext_len(&concatenated, plaintext.len()).is_err());
    Ok(())
}

#[test]
fn inspected_dictionary_length_does_not_verify_content_or_supply_dictionary() -> TestResult {
    let profile = ChunkProfile::cdc_1m([7; 32]);
    let dictionary = vec![0x71; 4096];
    let plaintext = vec![0x71; 8192];
    let encoded = codec::encode_chunk(&plaintext, profile.maximum(), 3, Some(&dictionary))?;
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;

    assert_eq!(
        codec::encoded_plaintext_len(&encoded, profile.maximum())?,
        plaintext.len()
    );
    assert!(matches!(
        codec::decode_verified(&encoded, plaintext.len(), &profile, true, &identity, None),
        Err(FrameError::MissingDictionary)
    ));
    assert!(
        codec::decode_verified(
            &encoded,
            plaintext.len(),
            &profile,
            true,
            &identity,
            Some(&dictionary)
        )
        .is_ok()
    );
    let wrong_identity = TERRANE_V1.calculate(IdentityKind::Chunk, b"different original bytes")?;
    assert!(
        codec::decode_verified(
            &encoded,
            plaintext.len(),
            &profile,
            true,
            &wrong_identity,
            Some(&dictionary)
        )
        .is_err()
    );
    Ok(())
}
