//! Complete checked sources in the existing Directory staging transaction.
//!
//! Whole-only sources retain their own paid output instead of acquiring an
//! unsupported owning reader. Every publication still authenticates the entire
//! returned body, and both original accounts remain live through staging.

use super::*;

#[cfg(test)]
mod tests;

/// Copies one authenticated Whole body under both retained original accounts.
///
/// # Errors
/// Returns the first checked-read, length, identity, original-account or staging
/// write refusal. It does not accept a publication receipt or renew an account.
pub(super) fn copy(
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    sink: &mut dyn Write,
    path: &Path,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let bytes = source.read_all_with_boundary(original, source.logical_length(), check)?;
    let payer = bytes.original_account().clone();
    checked_reader::check_pair(original, &payer, check)?;
    validate_bytes(id, &bytes)?;
    checked_reader::check_pair(original, &payer, check)?;

    for chunk in bytes.chunks(64 * 1024) {
        let mut written = 0;
        while written < chunk.len() {
            checked_reader::check_pair(original, &payer, check)?;
            match sink.write(&chunk[written..]) {
                Ok(0) => {
                    return Err(io_error(
                        "write-object-staging",
                        path,
                        io::Error::from(io::ErrorKind::WriteZero),
                    ));
                }
                Ok(count) => written += count,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(io_error("write-object-staging", path, source)),
            }
            checked_reader::check_pair(original, &payer, check)?;
        }
    }

    // The returned body closes before its credit and the final success cut.
    drop(bytes);
    checked_reader::check_pair(original, &payer, check)
}
