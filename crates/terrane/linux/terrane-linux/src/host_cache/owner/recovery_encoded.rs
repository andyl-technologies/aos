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
        {
            if identities
                .get(digest.as_slice())
                .is_none_or(|codec| *codec == 2)
            {
                return Err(invalid("recovery requires a standalone one-hop dictionary"));
            }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
