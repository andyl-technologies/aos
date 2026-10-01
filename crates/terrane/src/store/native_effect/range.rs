//! Verifies a fixed range against its captured complete physical preimage.
//!
//! A private publication factory selects the path and bytes. This reader binds
//! the actual nofollow descriptor to that preimage before seeking or reading;
//! its successful result establishes no publication or collector authority.

use super::{ExactRead, MetadataStamp, check_opened_name, open_native};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Verifies the actual range read against its complete retained preimage.
///
/// # Errors
/// Refuses absent or mismatched preimages, changed physical metadata or names,
/// incorrect range bytes, offset overflow and unavailable reads.
pub(super) fn verify(
    path: &Path,
    start: u64,
    expected: &[u8],
    preimages: &[ExactRead],
) -> io::Result<()> {
    let preimage = preimages
        .iter()
        .find(|read| read.path == path)
        .ok_or_else(|| io::Error::other("range probe lacks its complete physical preimage"))?;
    let captured = preimage
        .metadata
        .ok_or_else(|| io::Error::other("range probe lacks captured file metadata"))?;
    let body = preimage
        .expected
        .as_deref()
        .ok_or_else(|| io::Error::other("range probe requires a present complete body"))?;
    let offset = usize::try_from(start).map_err(io::Error::other)?;
    let end = offset
        .checked_add(expected.len())
        .ok_or_else(|| io::Error::other("range probe offset overflows"))?;
    if body.get(offset..end) != Some(expected) || preimage.identity != Some(captured.identity) {
        return Err(io::Error::other(
            "range probe differs from its captured preimage",
        ));
    }

    let mut file = open_native(path, false)?;
    let opened = MetadataStamp::checked(&file.metadata()?)?;
    preimage.policy.validate(opened)?;
    if !opened.same_incarnation(captured) {
        return Err(io::Error::other(
            "range probe opened a different file incarnation",
        ));
    }
    check_opened_name(&file, path, false)?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected.len())
        .map_err(io::Error::other)?;
    bytes.resize(expected.len(), 0);
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut bytes)?;

    let after = MetadataStamp::checked(&file.metadata()?)?;
    preimage.policy.validate(after)?;
    if !after.same_incarnation(captured) || bytes != expected {
        return Err(io::Error::other("range probe metadata or bytes changed"));
    }
    check_opened_name(&file, path, false)?;
    preimage.check()
}
