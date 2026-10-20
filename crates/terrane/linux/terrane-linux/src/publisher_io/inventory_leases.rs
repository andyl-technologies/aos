//! Validates retained retirement metadata without granting a deadline or body.

use super::{NativeInventory, invalid, source};
use std::io;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::publication::RetirementRecordCandidate;

/// Checks retained metadata against its domain, name and registered key shape.
///
/// # Errors
/// Rejects malformed metadata or an unknown typed key. The caller separately
/// checks the retained record inode against the actual filesystem custody.
pub(super) fn validate(inventory: &NativeInventory, name: &str, bytes: &[u8]) -> io::Result<()> {
    let candidate = RetirementRecordCandidate::parse(inventory.location.domain(), name, bytes)?;
    // A historical device number can change after a reboot or remount. It
    // grants no current inode or deadline authority; actual pending-inode use
    // still goes through the existing conservative lease reconstruction.
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
