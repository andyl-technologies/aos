//! Content-hash line validation for invocation planning.

use super::*;

/// Validates a raw fixed-width content-hash field.
///
/// # Errors
///
/// Returns [`CliError`] when the value is not exactly 64 hexadecimal digits.
pub(crate) fn validate_content_hash_hex_line(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<(), CliError> {
    let bytes = parse_hex_bytes(line_index, tag, value)?;
    if bytes.len() == 32 {
        Ok(())
    } else {
        Err(artifact_line_error(
            line_index,
            tag,
            &format!("content hash must be 32 bytes, got {}", bytes.len()),
        ))
    }
}
