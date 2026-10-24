//! Retains independently verified standalone chunks across exhaustive recovery.
//!
//! These observations grant neither admission nor serving authority. Every source
//! retains its original native inode and dependencies; a fresh inventory must
//! describe that same complete set before the owner can acknowledge recovery.

use super::recovery_candidates::{self, RecoveryCase};
use crate::host_cache::{NativeRecoveryInspection, VerifiedEncodedBody, VerifiedStandaloneChunk};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::unix::fs::MetadataExt,
    sync::Arc,
};
use terrane_format::codec::Codec;
use terrane_sdk::host::cache::ResidenceRecord;

/// Selects genuine verified chunks after classifying the entire inventory.
///
/// # Errors
/// Refuses unresolved inventory, multiple encodings of one identity and
/// dictionaries without a separately verified standalone source.
pub(super) fn select(
    inventory: &NativeRecoveryInspection,
) -> io::Result<Vec<Arc<VerifiedStandaloneChunk>>> {
    recovery_candidates::preflight(inventory)?;
    let mut chunks = Vec::new();
    let mut identities = BTreeMap::new();
    for candidate in inventory.candidates() {
        if !matches!(
            recovery_candidates::classify(candidate)?,
            RecoveryCase::Chunk
        ) {
            continue;
        }
        let Some(VerifiedEncodedBody::Chunk(chunk)) = candidate.verified() else {
            return Err(invalid("standalone candidate lost verified native custody"));
        };
        if identities
            .insert(chunk.identity().digest().to_vec(), chunk.codec())
            .is_some()
        {
            return Err(invalid(
                "multiple standalone encodings of one recovered identity",
            ));
        }
        chunks.push(Arc::clone(chunk));
    }
    // Import relies on actual completed one-hop admission jobs. A dictionary
    // present only inside a metadata pack needs a separate transfer path.
    for chunk in &chunks {
        let bytes = chunk.encoded()?;
        if let Codec::ZstdDictionary(digest) = terrane_format::codec::parse_envelope(&bytes)
            .map_err(io::Error::other)?
            .codec
            && identities
                .get(digest.as_slice())
                .is_none_or(|codec| *codec == 2)
        {
            return Err(invalid("recovery requires a standalone one-hop dictionary"));
        }
    }
    // Raw and plain Zstd dictionaries enter the actual owner before dependents.
    chunks.sort_by(|left, right| {
        (left.codec() == 2)
            .cmp(&(right.codec() == 2))
            .then_with(|| left.identity().digest().cmp(right.identity().digest()))
    });
    Ok(chunks)
}

/// Checks the exact original encoded sources against a fresh complete inventory.
///
/// # Errors
/// Refuses changed bytes, keys, inodes, roots, source sets or sealed residences.
pub(super) fn check(
    inventory: &NativeRecoveryInspection,
    original: &[Arc<VerifiedStandaloneChunk>],
    residences: &[ResidenceRecord],
) -> io::Result<()> {
    let current = select(inventory)?;
    if current.len() != original.len() {
        return Err(invalid("standalone recovery inventory changed"));
    }
    let sealed: BTreeSet<&str> = residences.iter().map(|row| row.chunk.as_str()).collect();
    for (before, after) in original.iter().zip(&current) {
        before.check_current()?;
        after.check_current()?;
        let before_inode = before.file().metadata()?;
        let after_inode = after.file().metadata()?;
        if before.descriptor() != after.descriptor()
            || before.codec() != after.codec()
            || !Arc::ptr_eq(before.layout(), after.layout())
            || (before_inode.dev(), before_inode.ino()) != (after_inode.dev(), after_inode.ino())
            || sealed.contains(hex(before.identity().digest()).as_str())
        {
            return Err(invalid(
                "standalone recovery source changed or duplicates a sealed residence",
            ));
        }
    }
    Ok(())
}

/// Derives cold-pin comparison hashes from actual independently verified chunks.
pub(super) fn hashes(chunks: &[Arc<VerifiedStandaloneChunk>]) -> Vec<String> {
    chunks
        .iter()
        .map(|chunk| hex(chunk.identity().digest()))
        .collect()
}

/// Selects sealed ranges whose chunks have no verified standalone residence.
///
/// Re-extraction removes the durable range before publishing its replacement
/// chunk. A crash can therefore leave both the original sealed body and the
/// replacement encoding. The complete native inventory, rather than either
/// filename alone, determines which source owns the chunk. Original cold rows
/// still have to reconcile separately; this never clears an old assertion.
///
/// # Errors
/// Refuses overflowing ranges or a plaintext length conflicting with the actual
/// independently verified standalone descriptor.
pub(super) fn sealed_residences(
    records: impl IntoIterator<Item = ResidenceRecord>,
    chunks: &[Arc<VerifiedStandaloneChunk>],
) -> io::Result<Vec<ResidenceRecord>> {
    let standalone = chunks
        .iter()
        .map(|chunk| (hex(chunk.identity().digest()), chunk.descriptor().size()))
        .collect();
    select_residences(records, &standalone)
}

fn select_residences(
    records: impl IntoIterator<Item = ResidenceRecord>,
    standalone: &BTreeMap<String, u64>,
) -> io::Result<Vec<ResidenceRecord>> {
    let mut selected = Vec::new();
    for record in records {
        record
            .offset
            .checked_add(record.length)
            .ok_or_else(|| invalid("recovered residence range overflows"))?;
        match standalone.get(&record.chunk) {
            Some(length) if *length != record.length => {
                return Err(invalid(
                    "sealed range conflicts with verified standalone plaintext length",
                ));
            }
            Some(_) => {}
            None => selected.push(record),
        }
    }
    Ok(selected)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn range(chunk: &str, offset: u64, length: u64) -> ResidenceRecord {
        ResidenceRecord {
            chunk: chunk.into(),
            object: "sealed-body".into(),
            offset,
            length,
        }
    }

    #[test]
    fn extraction_crash_selection_keeps_one_residence_and_checks_both_lengths() {
        // Pure selection data supplies no adoption, recovery or read capability.
        let standalone = BTreeMap::from([("shared".into(), 3)]);
        let selected = select_residences(
            [range("shared", 7, 3), range("unextracted", 10, 5)],
            &standalone,
        )
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].chunk, "unextracted");
        assert!(select_residences([range("shared", 7, 4)], &standalone).is_err());
        assert!(select_residences([range("shared", u64::MAX, 3)], &standalone).is_err());
    }

    #[test]
    fn before_canonical_publish_the_verified_original_range_remains_selected() {
        let selected = select_residences([range("shared", 7, 3)], &BTreeMap::new()).unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].offset, 7);
    }
}
