//! Selects original encoded chunk ranges from already verified pack bytes.
//!
//! The native caller retains and rechecks the actual pack and dictionary sources.
//! This format helper supplies neither native custody nor content verification;
//! it moves a selected envelope within the existing bounded payload allocation.

use super::{dictionaries::pack_body, files::invalid, verification::bounded_pack};
use std::io;
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::host::cache::HostReadLimits;

/// Selects a checked record without allocating a second encoded payload window.
pub(super) fn select(
    mut bytes: Vec<u8>,
    identity: &Identity,
    limits: HostReadLimits,
) -> io::Result<(Descriptor, Vec<u8>)> {
    if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packed chunk selection requires the configured chunk identity",
        ));
    }
    if bytes.capacity() > limits.max_allocation_bytes {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "packed chunk buffer exceeds its allocation policy",
        ));
    }
    let digest = identity.terrane_v1_digest().map_err(invalid)?;
    let pack = bounded_pack(&bytes, limits)?;
    let (range, length) = pack_body(&pack, &bytes, &digest, limits.max_allocation_bytes)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "verified pack chunk absent"))?;
    let descriptor = Descriptor::from_wire(
        &TERRANE_V1,
        TERRANE_V1.algorithm(),
        TERRANE_V1.domain(IdentityKind::Chunk).map_err(invalid)?,
        &digest,
        u64::try_from(length).map_err(invalid)?,
    )
    .map_err(invalid)?;

    // Keep the original pack allocation so extraction does not overlap a second
    // full payload. Canonical admission still receives the exact offered bytes.
    let encoded_length = range.len();
    bytes.copy_within(range, 0);
    bytes.truncate(encoded_length);
    Ok((descriptor, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use terrane_format::{chunking::ChunkProfile, codec::Codec};
    use terrane_sdk::pack::{EntryKind, NativeBodyDecoder, PackClass, PackId, PackWriter};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn original_raw_and_nested_envelopes_keep_the_single_payload_allocation() -> TestResult {
        // These are format inputs; no native inspection or admission is fabricated.
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let terminal = b"packed terminal vocabulary ".repeat(16);
        let middle = b"packed terminal vocabulary intermediate ".repeat(64);
        let root = b"packed terminal vocabulary intermediate content ".repeat(128);
        let terminal_id = TERRANE_V1.calculate(IdentityKind::Chunk, &terminal)?;
        let middle_id = TERRANE_V1.calculate(IdentityKind::Chunk, &middle)?;
        let root_id = TERRANE_V1.calculate(IdentityKind::Chunk, &root)?;
        let middle_encoded =
            terrane_sdk::codec::encode_chunk(&middle, profile.maximum(), 3, Some(&terminal))?;
        let root_encoded =
            terrane_sdk::codec::encode_chunk(&root, profile.maximum(), 3, Some(&middle))?;
        assert_eq!(
            terrane_format::codec::parse_envelope(&root_encoded)?.codec,
            Codec::ZstdDictionary(middle_id.terrane_v1_digest()?)
        );
        let dictionaries = BTreeMap::from([
            (terminal_id.terrane_v1_digest()?, terminal.clone()),
            (middle_id.terrane_v1_digest()?, middle.clone()),
        ]);
        let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
        let mut writer =
            PackWriter::new(PackId::from_random_bytes([49; 16]), PackClass::Data, true);
        writer.append_raw(EntryKind::Chunk, &terminal)?;
        writer.append_chunk(
            middle_id.terrane_v1_digest()?,
            &middle_encoded,
            u32::try_from(middle.len())?,
            0,
            &decoder,
        )?;
        writer.append_chunk(
            root_id.terrane_v1_digest()?,
            &root_encoded,
            u32::try_from(root.len())?,
            0,
            &decoder,
        )?;
        let sealed = writer.seal()?;
        let terminal_encoded =
            terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
                codec: Codec::Raw,
                body: &terminal,
            });

        for (identity, plaintext, expected) in [
            (&terminal_id, &terminal, &terminal_encoded),
            (&middle_id, &middle, &middle_encoded),
            (&root_id, &root, &root_encoded),
        ] {
            let bytes = sealed.bytes().to_vec();
            let pointer = bytes.as_ptr();
            let capacity = bytes.capacity();
            let limits = HostReadLimits {
                max_allocation_bytes: capacity.max(root.len()),
            };

            let (descriptor, encoded) = select(bytes, identity, limits)?;

            assert_eq!(encoded, *expected);
            assert_eq!(encoded.as_ptr(), pointer);
            assert_eq!(encoded.capacity(), capacity);
            assert_eq!(descriptor.size(), plaintext.len() as u64);
            assert_eq!(
                descriptor.verify_bytes(&TERRANE_V1, IdentityKind::Chunk, plaintext)?,
                *identity
            );
        }
        Ok(())
    }

    #[test]
    fn selection_refuses_missing_wrong_kind_and_changed_codec_records() -> TestResult {
        let mut writer =
            PackWriter::new(PackId::from_random_bytes([50; 16]), PackClass::Data, false);
        let digest = writer.append_raw(EntryKind::Chunk, b"original packed chunk")?;
        let sealed = writer.seal()?;
        let identity = TERRANE_V1.from_digest(IdentityKind::Chunk, &digest)?;
        let limits = HostReadLimits {
            max_allocation_bytes: 4096,
        };
        let absent = TERRANE_V1.calculate(IdentityKind::Chunk, b"absent")?;
        let wrong_kind = TERRANE_V1.from_digest(IdentityKind::Manifest, &digest)?;

        let absent_error = select(sealed.bytes().to_vec(), &absent, limits)
            .err()
            .ok_or("missing chunk was selected")?;
        let kind_error = select(sealed.bytes().to_vec(), &wrong_kind, limits)
            .err()
            .ok_or("metadata identity selected a chunk")?;

        assert_eq!(absent_error.kind(), io::ErrorKind::NotFound);
        assert_eq!(kind_error.kind(), io::ErrorKind::InvalidInput);

        let reader = bounded_pack(sealed.bytes(), limits)?;
        let offset = usize::try_from(reader.entries()[0].offset())?;
        let mut changed = sealed.bytes().to_vec();
        changed[offset] = 1;
        assert!(select(changed, &identity, limits).is_err());
        Ok(())
    }

    #[test]
    fn selection_checks_buffer_capacity_and_decoded_length_independently() -> TestResult {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let plaintext = b"packed compressed window ".repeat(1024);
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
        let encoded = terrane_sdk::codec::encode_chunk(&plaintext, profile.maximum(), 3, None)?;
        let dictionaries = BTreeMap::new();
        let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
        let mut writer =
            PackWriter::new(PackId::from_random_bytes([51; 16]), PackClass::Data, true);
        writer.append_chunk(
            identity.terrane_v1_digest()?,
            &encoded,
            u32::try_from(plaintext.len())?,
            0,
            &decoder,
        )?;
        let sealed = writer.seal()?;
        assert!(sealed.bytes().len() < plaintext.len());
        let bytes = sealed.bytes().to_vec();
        let limits = HostReadLimits {
            max_allocation_bytes: bytes.capacity(),
        };

        let plaintext_error = select(bytes, &identity, limits)
            .err()
            .ok_or("oversized plaintext declaration was selected")?;

        assert_eq!(plaintext_error.kind(), io::ErrorKind::OutOfMemory);

        let mut spare = sealed.bytes().to_vec();
        spare.try_reserve_exact(4096)?;
        let capacity_error = select(spare, &identity, limits)
            .err()
            .ok_or("oversized backing allocation was selected")?;

        assert_eq!(capacity_error.kind(), io::ErrorKind::OutOfMemory);
        Ok(())
    }
}
