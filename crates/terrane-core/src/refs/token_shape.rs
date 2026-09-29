//! Checks the canonical token shape embedded in commit provenance.
//!
//! This module enforces the closed CDDL fields before a commit is hashed.
//! Signature and authorization checks belong to the token verifier.

use super::{Locality, RecordError, read_key};
use crate::cbor::Decoder;

const MAX_TOKEN_BLOCKS: usize = 16;
const MAX_GRANTS: usize = 256;

pub(super) fn validate_token(bytes: &[u8]) -> Result<(), RecordError> {
    let mut decoder = Decoder::new(bytes);
    let blocks = decoder.array(MAX_TOKEN_BLOCKS)?;
    if blocks == 0 {
        return Err(RecordError::Schema);
    }
    authority_block(&mut decoder)?;
    for _ in 1..blocks {
        attenuation_block(&mut decoder)?;
    }
    decoder.finish()?;
    Ok(())
}

fn authority_block(decoder: &mut Decoder<'_>) -> Result<(), RecordError> {
    let fields = decoder.map(12)?;
    let mut previous = 0;
    let mut seen = 0u16;
    for _ in 0..fields {
        let key = read_key(decoder, &mut previous, 12)?;
        seen |= 1 << key;
        match key {
            1..=3 | 10 => {
                decoder.text(decoder.remaining().len())?;
            }
            4 => {
                if !(1..=3).contains(&decoder.uint()?) {
                    return Err(RecordError::Schema);
                }
            }
            5 => {
                let groups = decoder.array(decoder.remaining().len())?;
                for _ in 0..groups {
                    decoder.text(decoder.remaining().len())?;
                }
            }
            6 | 7 => {
                decoder.uint()?;
            }
            8 => exact_bytes(decoder, 16)?,
            9 => grants(decoder)?,
            11 => exact_bytes(decoder, 32)?,
            12 => exact_bytes(decoder, 64)?,
            _ => return Err(RecordError::Schema),
        }
    }

    require_fields(seen, &[1, 2, 3, 4, 5, 6, 8, 9, 11, 12])
}

fn attenuation_block(decoder: &mut Decoder<'_>) -> Result<(), RecordError> {
    let fields = decoder.map(6)?;
    let mut previous = 0;
    let mut seen = 0u16;
    for _ in 0..fields {
        let key = read_key(decoder, &mut previous, 6)?;
        seen |= 1 << key;
        match key {
            1 | 2 => {
                decoder.uint()?;
            }
            3 => grants(decoder)?,
            4 => {
                let count = decoder.array(decoder.remaining().len())?;
                if count == 0 {
                    return Err(RecordError::Schema);
                }
                for _ in 0..count {
                    caveat(decoder)?;
                }
            }
            5 => exact_bytes(decoder, 32)?,
            6 => exact_bytes(decoder, 64)?,
            _ => return Err(RecordError::Schema),
        }
    }

    require_fields(seen, &[5, 6])
}

fn grants(decoder: &mut Decoder<'_>) -> Result<(), RecordError> {
    let count = decoder.array(MAX_GRANTS)?;
    if count == 0 {
        return Err(RecordError::Schema);
    }
    for _ in 0..count {
        if decoder.array(2)? != 2 {
            return Err(RecordError::Schema);
        }
        decoder.text(decoder.remaining().len())?;
        decoder.uint()?;
    }
    Ok(())
}

fn caveat(decoder: &mut Decoder<'_>) -> Result<(), RecordError> {
    let fields = decoder.array(3)?;
    let kind = decoder.text(16)?;
    match (kind, fields) {
        ("before" | "after" | "verb", 2) => {
            decoder.uint()?;
        }
        ("ref" | "root" | "domain" | "surface", 2) => {
            decoder.text(decoder.remaining().len())?;
        }
        ("locality", 2) => {
            Locality::decode_from(decoder)?;
        }
        ("epoch", 3) => {
            decoder.text(decoder.remaining().len())?;
            decoder.uint()?;
        }
        _ => return Err(RecordError::Schema),
    }
    Ok(())
}

fn exact_bytes(decoder: &mut Decoder<'_>, length: usize) -> Result<(), RecordError> {
    if decoder.bytes(length)?.len() == length {
        Ok(())
    } else {
        Err(RecordError::Schema)
    }
}

fn require_fields(seen: u16, required: &[u8]) -> Result<(), RecordError> {
    if required.iter().all(|key| seen & (1 << *key) != 0) {
        Ok(())
    } else {
        Err(RecordError::Schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use alloc::vec::Vec;

    fn authority_and_caveat(issuer: &str) -> Vec<u8> {
        let mut token = Vec::new();
        cbor::write_array(&mut token, 2);
        cbor::write_map(&mut token, 10);
        for (key, value) in [(1, issuer), (2, "key"), (3, "subject")] {
            cbor::write_uint(&mut token, key);
            cbor::write_text(&mut token, value);
        }
        cbor::write_uint(&mut token, 4);
        cbor::write_uint(&mut token, 2);
        cbor::write_uint(&mut token, 5);
        cbor::write_array(&mut token, 0);
        cbor::write_uint(&mut token, 6);
        cbor::write_uint(&mut token, 100);
        cbor::write_uint(&mut token, 8);
        cbor::write_bytes(&mut token, &[1; 16]);
        cbor::write_uint(&mut token, 9);
        cbor::write_array(&mut token, 1);
        cbor::write_array(&mut token, 2);
        cbor::write_text(&mut token, "refs/heads/tenant/main");
        cbor::write_uint(&mut token, 4);
        cbor::write_uint(&mut token, 11);
        cbor::write_bytes(&mut token, &[2; 32]);
        cbor::write_uint(&mut token, 12);
        cbor::write_bytes(&mut token, &[3; 64]);

        cbor::write_map(&mut token, 3);
        cbor::write_uint(&mut token, 4);
        cbor::write_array(&mut token, 1);
        cbor::write_array(&mut token, 2);
        cbor::write_text(&mut token, "before");
        cbor::write_uint(&mut token, 99);
        cbor::write_uint(&mut token, 5);
        cbor::write_bytes(&mut token, &[4; 32]);
        cbor::write_uint(&mut token, 6);
        cbor::write_bytes(&mut token, &[5; 64]);

        token
    }

    #[test]
    fn embedded_token_accepts_well_formed_authority_and_caveat() {
        assert_eq!(validate_token(&authority_and_caveat("issuer")), Ok(()));
    }

    #[test]
    fn embedded_token_accepts_unbounded_issuer_text() {
        let token = authority_and_caveat(&"i".repeat((1 << 20) + 1));

        assert_eq!(validate_token(&token), Ok(()));
    }

    #[test]
    fn embedded_token_rejects_non_block_values() {
        assert!(validate_token(&[0x81, 0xf6]).is_err());
        assert!(validate_token(&[0x81, 0xa0]).is_err());
        assert!(validate_token(&[0x80]).is_err());
    }
}
