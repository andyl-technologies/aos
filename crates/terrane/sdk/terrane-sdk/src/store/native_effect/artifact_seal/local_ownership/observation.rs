//! Checks neutral local-v1 creator associations against actual native descriptors.

use super::*;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Derives the registered neutral container binding from checked inventory.
pub(super) fn binding(inventory: &PackInventoryEntry, index: bool) -> ArtifactBinding {
    if index {
        ArtifactBinding::Index {
            digest: inventory.index_hash,
            size: inventory.index_size,
        }
    } else {
        ArtifactBinding::Pack {
            digest: inventory.pack_hash,
            size: inventory.pack_size,
        }
    }
}

/// Checks canonical Committed data and its exact registered association.
///
/// # Errors
/// Refuses unknown, malformed or mismatched creator journals.
pub(super) fn committed(
    bytes: &[u8],
    key: &str,
    expected: &ArtifactBinding,
) -> io::Result<CreationJournal> {
    let record =
        CreationJournal::decode(bytes).map_err(|_| unknown("unknown native creation journal"))?;
    if record.encode().map_err(io::Error::other)? != bytes || record.key != key {
        return Err(unknown(
            "native journal is not exactly canonical or associated",
        ));
    }
    match &record.state {
        JournalState::Committed {
            binding,
            file_identity,
        } if binding == expected && file_identity.len() == 16 => Ok(record),
        _ => Err(unknown(
            "native pair journal is not current Committed evidence",
        )),
    }
}

/// Encodes the actual descriptor identity in the existing local-v1 domain.
pub(super) fn native_identity(observation: Observation) -> [u8; 16] {
    let mut result = [0; 16];
    result[..8].copy_from_slice(&observation.stamp.identity.0.to_be_bytes());
    result[8..].copy_from_slice(&observation.stamp.identity.1.to_be_bytes());
    result
}

/// Compares protected Committed evidence with the actual opened descriptor.
///
/// # Errors
/// Refuses another incarnation or a noncommitted creator journal.
pub(super) fn compare_journal(
    record: &CreationJournal,
    observation: Observation,
) -> io::Result<()> {
    let JournalState::Committed { file_identity, .. } = &record.state else {
        return Err(unknown("native pair has no Committed journal"));
    };
    if file_identity.as_slice() != native_identity(observation).as_slice() {
        return Err(unknown(
            "native pair journal does not match actual descriptor",
        ));
    }
    Ok(())
}

/// Checks the bounded detached index identity and every container association.
///
/// # Errors
/// Refuses malformed, oversized, misidentified or out-of-bounds index data.
pub(super) fn verify_index(
    inventory: &PackInventoryEntry,
    bytes: &[u8],
    expected: &PackIndexSnapshot,
) -> io::Result<()> {
    if u64::try_from(bytes.len()).map_err(io::Error::other)? != inventory.index_size {
        return Err(unknown("native index differs from inventory length"));
    }
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Index, &inventory.index_hash)
        .map_err(io::Error::other)?;
    TERRANE_V1
        .verify(&identity, bytes)
        .map_err(io::Error::other)?;
    let decoded =
        PackIndexSnapshot::decode(bytes, expected.generation()).map_err(io::Error::other)?;
    let body_end = inventory
        .pack_size
        .checked_sub(inventory.index_size)
        .and_then(|size| size.checked_add(terrane_format::pack_format::HEADER_SIZE as u64))
        .and_then(|size| size.checked_sub(terrane_format::pack_format::FOOTER_SIZE as u64))
        .ok_or_else(|| unknown("native container body bound overflow"))?;
    if decoded != *expected
        || decoded.header().id().as_bytes() != &inventory.pack_id
        || decoded.entries().iter().any(|entry| {
            entry
                .offset()
                .checked_add(u64::from(entry.body_len()))
                .is_none_or(|end| end > body_end)
        })
    {
        return Err(unknown("native detached index association differs"));
    }
    Ok(())
}
