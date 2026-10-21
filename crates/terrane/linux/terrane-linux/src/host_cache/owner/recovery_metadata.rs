//! Retains verified metadata admitted before its sealed object was published.
//!
//! Actual matched pack/index sources enter the acknowledged running registry
//! before cold inventory descriptors can disappear. Selection grants no serving
//! authority; every import still funds and synchronizes its actual owner job.

use super::recovery_candidates::{self, RecoveryCase};
use crate::host_cache::{DerivedIndexRepair, NativeRecoveryInspection, VerifiedEncodedBody};
use std::{io, os::unix::fs::MetadataExt, sync::Arc};
use terrane_sdk::pack::PackReader;

/// Selects independently verified metadata pairs from the complete inventory.
///
/// # Errors
/// Refuses unresolved candidates, data packs and changed or unbounded pairs.
pub(super) fn select(
    inventory: &NativeRecoveryInspection,
) -> io::Result<Vec<Arc<DerivedIndexRepair>>> {
    recovery_candidates::preflight(inventory)?;
    let mut sources = Vec::new();
    for candidate in inventory.candidates() {
        if !matches!(
            recovery_candidates::classify(candidate)?,
            RecoveryCase::Pack
        ) {
            continue;
        }
        let Some(VerifiedEncodedBody::Pack(source)) = candidate.verified() else {
            return Err(io::Error::other(
                "metadata candidate lost verified native custody",
            ));
        };
        source.metadata_bytes()?;
        sources.push(Arc::clone(source));
    }
    Ok(sources)
}

/// Checks exact original verified metadata against a fresh complete inventory.
///
/// # Errors
/// Refuses a changed source set, root, pack identity or actual pair incarnation.
pub(super) fn check(
    inventory: &NativeRecoveryInspection,
    original: &[Arc<DerivedIndexRepair>],
) -> io::Result<()> {
    let current = select(inventory)?;
    if current.len() != original.len() {
        return Err(io::Error::other("metadata recovery inventory changed"));
    }
    for (before, after) in original.iter().zip(&current) {
        before.check_current()?;
        after.check_current()?;
        if before.pack_id() != after.pack_id()
            || before.pack_identity() != after.pack_identity()
            || !Arc::ptr_eq(before.layout(), after.layout())
        {
            return Err(io::Error::other("metadata recovery source changed"));
        }
        for (left, right) in [
            (before.pack_file(), after.pack_file()),
            (index(before)?, index(after)?),
        ] {
            let left = left.metadata()?;
            let right = right.metadata()?;
            if (left.dev(), left.ino()) != (right.dev(), right.ino()) {
                return Err(io::Error::other("metadata recovery inode changed"));
            }
        }
    }
    Ok(())
}

/// Derives comparison hashes from the actual fully verified metadata bytes.
///
/// # Errors
/// Refuses changed original sources, invalid pack parsing or bounded reads.
pub(super) fn hashes(sources: &[Arc<DerivedIndexRepair>]) -> io::Result<Vec<String>> {
    let mut hashes = Vec::new();
    for source in sources {
        let (bytes, _) = source.metadata_bytes()?;
        let pack = PackReader::open(&bytes).map_err(io::Error::other)?;
        hashes.push(hex(source.pack_identity().digest()));
        hashes.extend(pack.entries().iter().map(|entry| hex(entry.hash())));
    }
    Ok(hashes)
}

fn index(source: &DerivedIndexRepair) -> io::Result<&std::fs::File> {
    source
        .present_index_file()
        .ok_or_else(|| io::Error::other("verified metadata index absent"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
