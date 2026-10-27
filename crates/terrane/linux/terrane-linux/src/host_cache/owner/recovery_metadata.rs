//! Retains verified native pack pairs across cold recovery and owner import.
//!
//! Actual matched pack/index sources enter the acknowledged running registry
//! before cold inventory descriptors can disappear. Selection grants no serving
//! authority; every import still funds and synchronizes its actual owner job.

use super::recovery_candidates::{self, RecoveryCase};
use crate::host_cache::{DerivedIndexRepair, NativeRecoveryInspection, VerifiedEncodedBody};
use std::{io, os::unix::fs::MetadataExt, sync::Arc};
use terrane_sdk::pack::PackReader;

/// Selects verified pairs whose external dictionaries have standalone cold custody.
///
/// # Errors
/// Refuses unresolved candidates, unavailable standalone dictionaries and changed
/// or unbounded pairs. Inspection never substitutes for running admission custody.
pub(super) fn select(
    inventory: &NativeRecoveryInspection,
    referenced: &[Arc<crate::host_cache::NativeManifestSource>],
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
        if let Some(retained) = referenced
            .iter()
            .find(|retained| retained.pack_id() == source.pack_id())
        {
            retained.recheck()?;
            source.check_current()?;
            if !Arc::ptr_eq(retained.layout(), source.layout())
                || retained.pack_identity() != source.pack_identity()
            {
                return Err(io::Error::other(
                    "referenced metadata differs from verified recovery source",
                ));
            }
            for (left, right) in [
                (retained.files().0, source.pack_file()),
                (retained.files().1, index(source)?),
            ] {
                let left = left.metadata()?;
                let right = right.metadata()?;
                if (left.dev(), left.ino()) != (right.dev(), right.ino()) {
                    return Err(io::Error::other(
                        "referenced metadata changed its original pair",
                    ));
                }
            }
            continue;
        }
        let (bytes, index) = source.pair_bytes()?;
        let pack = PackReader::open(&bytes).map_err(io::Error::other)?;
        if pack.header().class() == terrane_sdk::pack::PackClass::Data {
            let (limits, max_entries) = source.read_policy();
            let external =
                super::admission::packed_body::external_dictionaries(&bytes, limits, max_entries)?;
            if external.is_empty() {
                super::admission::packed_body::verify(
                    &bytes,
                    &index,
                    source.pack_id(),
                    source.layout().layout().chunk_profile(),
                    limits,
                    max_entries,
                )?;
            } else {
                // DerivedIndexRepair already verified every original body and
                // retained dictionary inode. Require genuine complete standalone
                // candidates here; Resume must import them before this pair.
                for digest in external {
                    let dictionary = inventory
                        .candidates()
                        .iter()
                        .find_map(|candidate| match candidate.verified() {
                            Some(VerifiedEncodedBody::Chunk(chunk))
                                if chunk.identity().digest() == digest =>
                            {
                                Some(chunk)
                            }
                            _ => None,
                        })
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::Unsupported,
                                "data recovery requires original standalone dictionary custody",
                            )
                        })?;
                    dictionary.check_current()?;
                }
            }
        }
        sources.push(Arc::clone(source));
    }
    Ok(sources)
}

/// Selects actual external edges to import before the original data pair.
///
/// # Errors
/// Refuses changed native pairs, malformed data or exceeded inspection bounds.
pub(super) fn external_dictionaries(
    source: &DerivedIndexRepair,
) -> io::Result<Vec<terrane_format::identity::Digest>> {
    let (bytes, _) = source.pair_bytes()?;
    let pack = PackReader::open(&bytes).map_err(io::Error::other)?;
    if pack.header().class() != terrane_sdk::pack::PackClass::Data {
        return Ok(Vec::new());
    }
    let (limits, max_entries) = source.read_policy();
    super::admission::packed_body::external_dictionaries(&bytes, limits, max_entries)
}

/// Checks exact original verified metadata against a fresh complete inventory.
///
/// # Errors
/// Refuses a changed source set, root, pack identity or actual pair incarnation.
pub(super) fn check(
    inventory: &NativeRecoveryInspection,
    original: &[Arc<DerivedIndexRepair>],
    referenced: &[Arc<crate::host_cache::NativeManifestSource>],
) -> io::Result<()> {
    let current = select(inventory, referenced)?;
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
        let (bytes, _) = source.pair_bytes()?;
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
