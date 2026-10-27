//! Verifies closed data-pack graphs and decodes original positioned body reads.
//!
//! This format layer grants no native authority. Its caller binds every read to
//! an original admitted pack/index pair and verifies both complete native files.
//! External dictionary custody requires a separate owner transfer path.

use crate::host_cache::recovery_inspection::bounded_pack;
use std::{collections::BTreeMap, io, ops::Range};
use terrane_format::{
    chunking::ChunkProfile,
    codec::Codec,
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    host::cache::{HostReadLimits, reconstruct_pack_index},
    pack::{EntryKind, IndexEntry, PackClass, PackId, PackReader},
    repository::MetadataValidator,
};

/// Verifies a complete data pair whose dictionary graph stays inside the pack.
///
/// # Errors
/// Refuses another class or key, damaged bodies or indexes, external or cyclic
/// dictionaries, exceeded member/allocation bounds and invalid chunk content.
pub(in crate::host_cache::owner) fn verify(
    bytes: &[u8],
    index: &[u8],
    id: PackId,
    profile: &ChunkProfile,
    limits: HostReadLimits,
    max_entries: usize,
) -> io::Result<Vec<String>> {
    let reader = inspect(bytes, limits, max_entries)?;
    if reader.header().id() != id {
        return Err(invalid("data pack differs from its canonical key"));
    }
    let mut dictionaries = BTreeMap::new();
    let mut retained_bytes = 0_usize;
    for entry in reader.entries() {
        let encoded = bytes
            .get(range(entry)?)
            .ok_or_else(|| invalid("data body absent"))?;
        if let Codec::ZstdDictionary(digest) = codec(entry, encoded)?
            && let std::collections::btree_map::Entry::Vacant(slot) = dictionaries.entry(digest)
        {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(invalid)?;
            let plaintext = decode(bytes, &identity, profile, limits, max_entries, |range| {
                bytes
                    .get(range)
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| invalid("data dictionary range absent"))
            })?;
            retained_bytes = retained_bytes
                .checked_add(plaintext.capacity())
                .ok_or_else(|| invalid("data dictionary memory overflow"))?;
            if retained_bytes > limits.max_allocation_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "data dictionaries exceed aggregate allocation policy",
                ));
            }
            slot.insert(plaintext);
        }
    }
    let verified = reconstruct_pack_index(
        bytes,
        id,
        profile,
        &MetadataValidator::new(profile.clone()),
        &dictionaries,
        limits,
    )
    .map_err(invalid)?;
    if verified.bytes() != index {
        return Err(invalid(
            "detached data index differs from the verified pack",
        ));
    }
    let mut hashes = Vec::new();
    hashes
        .try_reserve_exact(
            reader
                .entries()
                .len()
                .checked_add(1)
                .ok_or_else(|| invalid("data identity count overflow"))?,
        )
        .map_err(invalid)?;
    hashes.push(super::state::hex(verified.pack_identity().digest()));
    hashes.extend(
        reader
            .entries()
            .iter()
            .map(|entry| super::state::hex(entry.hash())),
    );
    Ok(hashes)
}

/// Decodes an actual body chain using a caller's bounded original range reads.
///
/// Discovery stores only record metadata. Reverse verification rereads every
/// envelope, retaining the immediate plaintext dictionary and current payload.
/// Expected pack bytes select records; they never supply returned native data.
///
/// # Errors
/// Refuses foreign identities, unavailable/cyclic dictionaries, changed codecs,
/// invalid content or framing, failed reads and exceeded finite resource bounds.
pub(super) fn decode(
    bytes: &[u8],
    identity: &Identity,
    profile: &ChunkProfile,
    limits: HostReadLimits,
    max_entries: usize,
    mut read: impl FnMut(Range<usize>) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "data read requires a configured chunk identity",
        ));
    }
    let reader = inspect(bytes, limits, max_entries)?;
    let mut digest = identity.terrane_v1_digest().map_err(invalid)?;
    let mut chain: Vec<&IndexEntry> = Vec::new();
    loop {
        if chain.len() >= max_entries || chain.iter().any(|entry| entry.hash() == &digest) {
            return Err(invalid("data dictionary cycle or member bound exceeded"));
        }
        let entry = reader
            .entries()
            .iter()
            .find(|entry| entry.hash() == &digest)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "data pack requires separately registered external dictionary custody",
                )
            })?;
        check_length(entry.plaintext_len() as usize, limits)?;
        let encoded = read(range(entry)?)?;
        check_length(encoded.capacity(), limits)?;
        let actual_codec = codec(entry, &encoded)?;
        chain.try_reserve_exact(1).map_err(invalid)?;
        chain.push(entry);
        match actual_codec {
            Codec::ZstdDictionary(next) => digest = next,
            _ => break,
        }
    }

    let mut plaintext: Option<Vec<u8>> = None;
    let mut dictionary: Option<Digest> = None;
    for entry in chain.into_iter().rev() {
        let encoded = read(range(entry)?)?;
        check_length(encoded.capacity(), limits)?;
        let actual_codec = codec(entry, &encoded)?;
        if matches!(actual_codec, Codec::ZstdDictionary(digest) if Some(digest) != dictionary) {
            return Err(invalid("data dictionary edge changed during native read"));
        }
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, entry.hash())
            .map_err(invalid)?;
        let verified = terrane_sdk::codec::decode_verified(
            &encoded,
            entry.plaintext_len() as usize,
            profile,
            true,
            &identity,
            plaintext.as_deref(),
        )
        .map_err(invalid)?;
        plaintext = Some(verified.plaintext().to_vec());
        dictionary = Some(*entry.hash());
    }
    plaintext.ok_or_else(|| invalid("data chunk chain is empty"))
}

fn inspect(bytes: &[u8], limits: HostReadLimits, max_entries: usize) -> io::Result<PackReader<'_>> {
    let reader = bounded_pack(bytes, limits)?;
    if reader.header().class() != PackClass::Data
        || reader
            .entries()
            .iter()
            .any(|entry| entry.kind() != EntryKind::Chunk)
    {
        return Err(invalid("data admission requires a data-class chunk pack"));
    }
    if reader.entries().len() > max_entries
        || max_entries
            .checked_mul(std::mem::size_of::<&IndexEntry>())
            .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "data pack exceeds its configured member bound",
        ));
    }
    Ok(reader)
}

fn codec(entry: &IndexEntry, encoded: &[u8]) -> io::Result<Codec> {
    if encoded.len() != entry.body_len() as usize
        || encoded.first().copied().map(u32::from) != Some(entry.codec() as u32)
    {
        return Err(invalid(
            "original data envelope differs from its verified record",
        ));
    }
    terrane_format::codec::parse_envelope(encoded)
        .map(|envelope| envelope.codec)
        .map_err(invalid)
}

fn range(entry: &IndexEntry) -> io::Result<Range<usize>> {
    let start = usize::try_from(entry.offset()).map_err(invalid)?;
    let end = start
        .checked_add(entry.body_len() as usize)
        .ok_or_else(|| invalid("data body range overflow"))?;
    Ok(start..end)
}

fn check_length(length: usize, limits: HostReadLimits) -> io::Result<()> {
    if length > limits.max_allocation_bytes {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "data body exceeds allocation policy",
        ));
    }
    Ok(())
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane_sdk::pack::{NativeBodyDecoder, PackWriter, SealedPack};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        pair: SealedPack,
        profile: ChunkProfile,
        identity: Identity,
        plaintext: Vec<u8>,
    }

    fn fixture() -> TestResult<Fixture> {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let base = b"closed pack native vocabulary ".repeat(32);
        let middle = b"closed pack native vocabulary selected middle ".repeat(64);
        let plaintext = b"closed pack native vocabulary selected middle root ".repeat(128);
        let base_id = TERRANE_V1.calculate(IdentityKind::Chunk, &base)?;
        let middle_id = TERRANE_V1.calculate(IdentityKind::Chunk, &middle)?;
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
        let dictionaries = BTreeMap::from([
            (base_id.terrane_v1_digest()?, base.clone()),
            (middle_id.terrane_v1_digest()?, middle.clone()),
        ]);
        let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
        let mut writer =
            PackWriter::new(PackId::from_random_bytes([62; 16]), PackClass::Data, true);
        writer.append_raw(EntryKind::Chunk, &base)?;
        for (id, bytes, dictionary) in [
            (&middle_id, &middle, &base),
            (&identity, &plaintext, &middle),
        ] {
            let encoded =
                terrane_sdk::codec::encode_chunk(bytes, profile.maximum(), 3, Some(dictionary))?;
            assert!(matches!(
                terrane_format::codec::parse_envelope(&encoded)?.codec,
                Codec::ZstdDictionary(_)
            ));
            writer.append_chunk(
                id.terrane_v1_digest()?,
                &encoded,
                u32::try_from(bytes.len())?,
                0,
                &decoder,
            )?;
        }
        Ok(Fixture {
            pair: writer.seal()?,
            profile,
            identity,
            plaintext,
        })
    }

    #[test]
    fn closed_pack_verification_and_range_decoding_follow_the_original_nested_graph() -> TestResult
    {
        // This is a real format fixture, not fabricated native owner custody.
        let fixture = fixture()?;
        let limits = HostReadLimits {
            max_allocation_bytes: 1024 * 1024,
        };
        let reader = PackReader::open(fixture.pair.bytes())?;
        let hashes = verify(
            fixture.pair.bytes(),
            fixture.pair.index_object(),
            reader.header().id(),
            &fixture.profile,
            limits,
            3,
        )?;
        assert_eq!(hashes.len(), 4);
        let mut reads = Vec::new();

        let plaintext = decode(
            fixture.pair.bytes(),
            &fixture.identity,
            &fixture.profile,
            limits,
            3,
            |range| {
                reads.push(range.clone());
                Ok(fixture.pair.bytes()[range].to_vec())
            },
        )?;

        assert_eq!(plaintext, fixture.plaintext);
        assert_eq!(reads.len(), 6);
        assert_eq!(
            &reads[..3],
            reads[3..].iter().rev().cloned().collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn external_and_self_dependent_data_dictionaries_remain_unavailable() -> TestResult {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let plaintext = b"unavailable closed pack dictionary vocabulary ".repeat(256);
        let external = b"unavailable closed pack dictionary vocabulary different ".repeat(128);
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
        let limits = HostReadLimits {
            max_allocation_bytes: 1024 * 1024,
        };
        for dictionary in [&external, &plaintext] {
            let dictionary_id = TERRANE_V1.calculate(IdentityKind::Chunk, dictionary)?;
            let dictionaries =
                BTreeMap::from([(dictionary_id.terrane_v1_digest()?, dictionary.clone())]);
            let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
            let encoded = terrane_sdk::codec::encode_chunk(
                &plaintext,
                profile.maximum(),
                3,
                Some(dictionary),
            )?;
            let id = PackId::from_random_bytes([63; 16]);
            let mut writer = PackWriter::new(id, PackClass::Data, true);
            writer.append_chunk(
                identity.terrane_v1_digest()?,
                &encoded,
                u32::try_from(plaintext.len())?,
                0,
                &decoder,
            )?;
            let pair = writer.seal()?;

            let error = verify(pair.bytes(), pair.index_object(), id, &profile, limits, 3)
                .err()
                .ok_or("unavailable dictionary was accepted")?;

            assert_eq!(
                error.kind(),
                if dictionary == &plaintext {
                    io::ErrorKind::InvalidData
                } else {
                    io::ErrorKind::Unsupported
                }
            );
        }
        Ok(())
    }

    #[test]
    fn native_range_candidates_cannot_bypass_content_codec_or_resource_checks() -> TestResult {
        let fixture = fixture()?;
        let limits = HostReadLimits {
            max_allocation_bytes: 1024 * 1024,
        };
        let reader = PackReader::open(fixture.pair.bytes())?;
        let error = decode(
            fixture.pair.bytes(),
            &fixture.identity,
            &fixture.profile,
            limits,
            3,
            |range| {
                let mut bytes = fixture.pair.bytes()[range].to_vec();
                bytes[0] ^= 0xff;
                Ok(bytes)
            },
        )
        .err()
        .ok_or("changed original codec was accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = decode(
            fixture.pair.bytes(),
            &fixture.identity,
            &fixture.profile,
            limits,
            2,
            |range| Ok(fixture.pair.bytes()[range].to_vec()),
        )
        .err()
        .ok_or("member bound was ignored")?;
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);

        let small = HostReadLimits {
            max_allocation_bytes: fixture.pair.bytes().len(),
        };
        assert!(fixture.plaintext.len() > small.max_allocation_bytes);
        let error = decode(
            fixture.pair.bytes(),
            &fixture.identity,
            &fixture.profile,
            small,
            3,
            |range| Ok(fixture.pair.bytes()[range].to_vec()),
        )
        .err()
        .ok_or("plaintext allocation bound was ignored")?;
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);

        let mut changed_index = fixture.pair.index_object().to_vec();
        let final_byte = changed_index.last_mut().ok_or("index absent")?;
        *final_byte ^= 1;
        assert!(
            verify(
                fixture.pair.bytes(),
                &changed_index,
                reader.header().id(),
                &fixture.profile,
                limits,
                3
            )
            .is_err()
        );
        Ok(())
    }
}
