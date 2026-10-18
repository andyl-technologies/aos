//! Validates retained retirement metadata without granting a deadline or body.

use super::{NativeInventory, invalid, source};
use std::{io, os::unix::fs::MetadataExt};
use terrane::host::publication::RetirementRecordCandidate;
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};

/// Checks a retained record against its real device and registered key shape.
///
/// # Errors
/// Rejects malformed metadata, another device, or an unknown typed key.
pub(super) fn validate(inventory: &NativeInventory, name: &str, bytes: &[u8]) -> io::Result<()> {
    let candidate = RetirementRecordCandidate::parse(inventory.location.domain(), name, bytes)?;
    if candidate.device() != inventory.root.metadata()?.dev() {
        return Err(invalid("retirement record belongs to another device"));
    }
    validate_key(candidate.key())
}

/// Checks the existing sealed, chunk, and pack-member lease key encodings.
///
/// # Errors
/// Rejects malformed descriptors, wrong kinds, codecs, or member classes.
pub(super) fn validate_key(key: &[u8]) -> io::Result<()> {
    match key {
        [1, codec, descriptor @ .., 0] if *codec <= 2 => {
            let descriptor = Descriptor::decode(&TERRANE_V1, descriptor).map_err(source)?;
            if TERRANE_V1.kind(descriptor.domain()).map_err(source)? != IdentityKind::Chunk {
                return Err(invalid("encoded retirement key has a non-chunk descriptor"));
            }
        }
        [2, pack_id @ .., member] if pack_id.len() == 16 && *member <= 1 => {}
        _ => {
            let descriptor = Descriptor::decode(&TERRANE_V1, key).map_err(source)?;
            if !matches!(
                TERRANE_V1.kind(descriptor.domain()).map_err(source)?,
                IdentityKind::Chunk | IdentityKind::Manifest
            ) {
                return Err(invalid(
                    "sealed retirement key has a non-content descriptor",
                ));
            }
        }
    }
    Ok(())
}
