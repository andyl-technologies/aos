//! Validates authoritative coordinator descriptors without selecting or rewriting DATA.
//!
//! Shared local generation and the separately selected transport owner both
//! pass protoc's complete original bytes to the generator after validation.

use buffa::Message;
use buffa_codegen::generated::descriptor::FileDescriptorSet;

/// Names the shared schema relative to the proto include root.
pub(super) const COORDINATOR_FILE: &str = "aos/sandbox/coordinator/v1/coordinator.proto";

/// Names the unchanged package shared by local DATA and optional transport.
pub(super) const COORDINATOR_PACKAGE: &str = "aos.sandbox.coordinator.v1";

/// Validates the named coordinator file in a complete code-generation descriptor.
///
/// # Errors
///
/// Returns an error for invalid descriptor bytes, invalid tooling decode limits,
/// a missing or duplicate coordinator file, a mismatched package, or an
/// oversized encoded descriptor.
pub(super) fn validate_descriptor(
    original: &[u8],
    expected_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let options = buffa_codegen::tooling_decode_options().map_err(std::io::Error::other)?;
    let descriptor = options.decode_from_slice::<FileDescriptorSet>(original)?;
    let mut coordinator_files = descriptor
        .file
        .iter()
        .filter(|file| file.name.as_deref() == Some(expected_file));
    let coordinator = coordinator_files.next().ok_or_else(|| {
        std::io::Error::other("code-generation descriptor is missing the coordinator file")
    })?;
    if coordinator_files.next().is_some() {
        return Err(std::io::Error::other(
            "code-generation descriptor contains duplicate coordinator files",
        )
        .into());
    }
    if coordinator.package.as_deref() != Some(COORDINATOR_PACKAGE) {
        return Err(std::io::Error::other(
            "code-generation descriptor has an unexpected coordinator package",
        )
        .into());
    }

    // Preserve the encoder bound without replacing the original descriptor bytes.
    descriptor.try_encode_to_vec()?;
    Ok(())
}

/// Computes the complete comment-free schema compatibility fingerprint.
pub(super) fn complete_schema_fingerprint(source: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut fingerprint = FNV_OFFSET;
    let mut first = true;
    for declaration in source
        .lines()
        .filter_map(|line| line.split("//").next())
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if !first {
            fingerprint ^= u64::from(b'\n');
            fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
        }
        for byte in declaration.bytes() {
            fingerprint ^= u64::from(byte);
            fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
        }
        first = false;
    }
    fingerprint
}
