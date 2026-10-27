//! Resolves bounded dictionary chains while retaining their original native sources.
//!
//! Discovery retains descriptors and body ranges, then rereads those same files
//! in dependency order. Encoded chain bodies never accumulate in memory, and
//! verified observations still grant no admission or serving authority.

use super::{
    NativeRecoveryInspector,
    files::{CanonicalName, RetainedFile, invalid},
    verification::{VerifiedDependency, bounded_pack, bounded_standalone_length},
};
use std::{borrow::Cow, io, ops::Range, os::unix::fs::MetadataExt};
use terrane_format::{
    codec::Codec,
    identity::{Digest, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    host::cache::maximum_encoded_chunk_bytes,
    pack::{EntryKind, PackId, PackReader},
};

type CurrentPack<'a> = Option<(&'a PackReader<'a>, &'a [u8])>;

/// Retains a body location in an original descriptor, or in the enclosing pack.
struct Member {
    digest: Digest,
    length: usize,
    source: Option<usize>,
    range: Range<usize>,
}

/// Verifies every dependency before returning the requested dictionary plaintext.
pub(super) fn resolve(
    context: &NativeRecoveryInspector,
    digest: &Digest,
    current_pack: CurrentPack<'_>,
    packs: &[PackId],
    dependencies: &mut Vec<VerifiedDependency>,
    plaintext_budget: usize,
) -> io::Result<Vec<u8>> {
    let plaintext_budget = plaintext_budget.min(context.reads.max_allocation_bytes);
    context
        .max_candidates
        .checked_mul(std::mem::size_of::<Member>())
        .ok_or_else(|| invalid("dictionary walk allocation overflow"))?;
    let mut members: Vec<Member> = Vec::new();
    let mut next = *digest;
    loop {
        if members.len() >= context.max_candidates {
            return Err(invalid(
                "dictionary chain exceeds recovery inventory budget",
            ));
        }
        if members.iter().any(|member| member.digest == next) {
            return Err(invalid("recovered dictionary dependency cycle"));
        }
        let (member, bytes) = candidate(
            context,
            &next,
            current_pack,
            packs,
            dependencies,
            if members.is_empty() {
                plaintext_budget
            } else {
                context.reads.max_allocation_bytes
            },
        )?;
        let codec = terrane_format::codec::parse_envelope(
            bytes
                .get(member.range.clone())
                .ok_or_else(|| invalid("dictionary body range absent"))?,
        )
        .map_err(invalid)?
        .codec;
        members.try_reserve_exact(1).map_err(io::Error::other)?;
        members.push(member);
        match codec {
            Codec::ZstdDictionary(digest) => next = digest,
            _ => break,
        }
    }

    let profile = context.layout.layout().chunk_profile();
    let mut plaintext = None;
    for member in members.iter().rev() {
        let bytes = match member.source {
            Some(index) => {
                let dependency = dependencies
                    .get(index)
                    .ok_or_else(|| invalid("dictionary source disappeared"))?;
                dependency.check_current()?;
                let bytes = dependency.source.read(context.reads.max_allocation_bytes)?;
                if blake3::hash(&bytes) != dependency.encoded_hash {
                    return Err(invalid("dictionary source changed during recovery"));
                }
                Cow::Owned(bytes)
            }
            None => Cow::Borrowed(
                current_pack
                    .ok_or_else(|| invalid("enclosing pack absent"))?
                    .1,
            ),
        };
        let encoded = bytes
            .get(member.range.clone())
            .ok_or_else(|| invalid("dictionary body range changed"))?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, &member.digest)
            .map_err(invalid)?;
        let verified = terrane_sdk::codec::decode_verified(
            encoded,
            member.length,
            profile,
            true,
            &identity,
            plaintext.as_deref(),
        )
        .map_err(invalid)?;
        plaintext = Some(verified.plaintext().to_vec());
        if let Some(index) = member.source {
            dependencies[index].check_current()?;
        }
    }
    plaintext.ok_or_else(|| invalid("dictionary chain is empty"))
}

/// Selects original domain-bound bytes, preserving the canonical lookup order.
fn candidate<'a>(
    context: &NativeRecoveryInspector,
    digest: &Digest,
    current_pack: CurrentPack<'a>,
    packs: &[PackId],
    dependencies: &mut Vec<VerifiedDependency>,
    plaintext_budget: usize,
) -> io::Result<(Member, Cow<'a, [u8]>)> {
    if let Some((pack, bytes)) = current_pack
        && let Some((range, length)) = pack_body(pack, bytes, digest, plaintext_budget)?
    {
        return Ok((
            Member {
                digest: *digest,
                length,
                source: None,
                range,
            },
            Cow::Borrowed(bytes),
        ));
    }
    let profile = context.layout.layout().chunk_profile();
    for codec in 0..=2 {
        let source = match RetainedFile::open(
            context,
            CanonicalName::Chunk {
                digest: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
                codec,
            },
        ) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let encoded = source.read(
            maximum_encoded_chunk_bytes(profile)
                .map_err(invalid)?
                .min(context.reads.max_allocation_bytes),
        )?;
        if encoded.first().copied().map(u32::from) != Some(codec) {
            return Err(invalid(
                "dictionary source codec differs from canonical key",
            ));
        }
        let length = bounded_standalone_length(&encoded, profile, plaintext_budget)?;
        let range = 0..encoded.len();
        let index = retain(source, &encoded, dependencies, context.max_candidates)?;
        return Ok((
            Member {
                digest: *digest,
                length,
                source: Some(index),
                range,
            },
            Cow::Owned(encoded),
        ));
    }
    for id in packs {
        let source = match RetainedFile::open(
            context,
            CanonicalName::Pack {
                id: *id,
                index: false,
            },
        ) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let encoded = source.read(context.reads.max_allocation_bytes)?;
        let pack = bounded_pack(&encoded, context.reads)?;
        if pack.header().id() != *id {
            return Err(invalid("dictionary pack header differs from canonical key"));
        }
        if let Some((range, length)) = pack_body(&pack, &encoded, digest, plaintext_budget)? {
            let index = retain(source, &encoded, dependencies, context.max_candidates)?;
            return Ok((
                Member {
                    digest: *digest,
                    length,
                    source: Some(index),
                    range,
                },
                Cow::Owned(encoded),
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "actual domain-bound dictionary is unavailable",
    ))
}

/// Captures complete original-file bytes, including a pack's enclosing structure.
fn retain(
    source: RetainedFile,
    bytes: &[u8],
    dependencies: &mut Vec<VerifiedDependency>,
    maximum: usize,
) -> io::Result<usize> {
    source.recheck()?;
    let metadata = source.file().metadata()?;
    let encoded_hash = blake3::hash(bytes);
    for (index, dependency) in dependencies.iter().enumerate() {
        let original = dependency.source.file().metadata()?;
        if (metadata.dev(), metadata.ino()) == (original.dev(), original.ino()) {
            dependency.source.matches(source.file())?;
            dependency.check_current()?;
            if encoded_hash != dependency.encoded_hash {
                return Err(invalid("shared dictionary source changed during recovery"));
            }
            return Ok(index);
        }
    }
    if dependencies.len() >= maximum {
        return Err(invalid("dictionary descriptor budget exceeded"));
    }
    dependencies
        .try_reserve_exact(1)
        .map_err(io::Error::other)?;
    let index = dependencies.len();
    dependencies.push(VerifiedDependency {
        source,
        encoded_hash,
    });
    Ok(index)
}

/// Checks an indexed encoded body and its declared plaintext before decoding.
fn pack_body(
    pack: &PackReader<'_>,
    bytes: &[u8],
    digest: &Digest,
    plaintext_budget: usize,
) -> io::Result<Option<(Range<usize>, usize)>> {
    let Some(entry) = pack
        .entries()
        .iter()
        .find(|entry| entry.kind() == EntryKind::Chunk && entry.hash() == digest)
    else {
        return Ok(None);
    };
    let length = entry.plaintext_len() as usize;
    if length > plaintext_budget {
        return Err(invalid(
            "decoded dictionary exceeds recovery allocation budget",
        ));
    }
    let start = usize::try_from(entry.offset()).map_err(invalid)?;
    let end = start
        .checked_add(entry.body_len() as usize)
        .ok_or_else(|| invalid("dictionary pack range overflow"))?;
    let encoded = bytes
        .get(start..end)
        .ok_or_else(|| invalid("dictionary pack range absent"))?;
    if encoded.first().copied().map(u32::from) != Some(entry.codec() as u32) {
        return Err(invalid("dictionary envelope differs from pack index codec"));
    }
    Ok(Some((start..end, length)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use terrane_format::chunking::ChunkProfile;
    use terrane_sdk::pack::{NativeBodyDecoder, PackClass, PackWriter};

    #[test]
    fn packed_dictionary_discovery_preserves_nested_envelope_and_plaintext_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        // Format discovery does not fabricate native recovery or admission custody.
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let terminal = b"terminal dictionary vocabulary ".repeat(32);
        let middle = b"terminal dictionary vocabulary intermediate ".repeat(64);
        let terminal_digest = TERRANE_V1
            .calculate(IdentityKind::Chunk, &terminal)?
            .terrane_v1_digest()?;
        let middle_digest = TERRANE_V1
            .calculate(IdentityKind::Chunk, &middle)?
            .terrane_v1_digest()?;
        let encoded =
            terrane_sdk::codec::encode_chunk(&middle, profile.maximum(), 3, Some(&terminal))?;
        assert_eq!(
            terrane_format::codec::parse_envelope(&encoded)?.codec,
            Codec::ZstdDictionary(terminal_digest)
        );
        let dictionaries = BTreeMap::from([(terminal_digest, terminal)]);
        let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
        let mut writer =
            PackWriter::new(PackId::from_random_bytes([48; 16]), PackClass::Data, true);
        writer.append_chunk(middle_digest, &encoded, middle.len() as u32, 0, &decoder)?;
        let sealed = writer.seal()?;
        let reader = PackReader::recover(sealed.bytes())?;

        let (range, length) = pack_body(&reader, sealed.bytes(), &middle_digest, middle.len())?
            .ok_or("dictionary body missing")?;

        assert_eq!(&sealed.bytes()[range], encoded);
        assert_eq!(length, middle.len());
        assert!(pack_body(&reader, sealed.bytes(), &middle_digest, middle.len() - 1).is_err());
        assert!(pack_body(&reader, sealed.bytes(), &terminal_digest, middle.len())?.is_none());
        Ok(())
    }
}
