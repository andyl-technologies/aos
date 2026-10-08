//! Selects coordinator RPC generation without changing persistence DATA.
//!
//! The complete schema remains compatibility-owned. Only its descriptor's
//! coordinator service declarations are omitted from default code generation;
//! messages, enums, options, source information, and unknown fields survive.

use buffa::Message;
use buffa_codegen::generated::descriptor::FileDescriptorSet;

/// Names the authoritative coordinator schema relative to the proto include root.
pub(super) const COORDINATOR_FILE: &str = "aos/sandbox/coordinator/v1/coordinator.proto";

/// Names the unchanged module package shared by local DATA and optional RPCs.
pub(super) const COORDINATOR_PACKAGE: &str = "aos.sandbox.coordinator.v1";

/// Selects the code-generation descriptor after validating its coordinator file.
///
/// # Errors
///
/// Returns an error for invalid descriptor bytes, invalid tooling decode limits,
/// a missing or duplicate coordinator file, a mismatched package, or an
/// oversized encoded descriptor.
pub(super) fn select_descriptor(
    original: &[u8],
    multi_node: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let options = buffa_codegen::tooling_decode_options().map_err(std::io::Error::other)?;
    let mut descriptor = options.decode_from_slice::<FileDescriptorSet>(original)?;
    let mut coordinator_files = descriptor
        .file
        .iter_mut()
        .filter(|file| file.name.as_deref() == Some(COORDINATOR_FILE));
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

    // The opt-in path passes protoc's original bytes to the existing generator.
    // Default generation changes just this vector; buffa's descriptor model
    // retains unknown fields, unlike a reduced/manual descriptor projection.
    if multi_node {
        return Ok(original.to_vec());
    }
    coordinator.service.clear();
    Ok(descriptor.try_encode_to_vec()?)
}
