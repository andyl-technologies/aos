//! Joins decoded private Birth DATA to its defining key and original launch.
//!
//! Import18 preserves the genuine private Birth constructor and its version5
//! identity derivation. Matching these bytes creates no Birth, Source purpose,
//! executable measurement, full Recipe or native admission.

use super::*;

// This is the unchanged domain used by OriginalAckPeerBirth. The new wrapper
// must not silently change the identity of the original retained private Birth.
const ORIGINAL_PRIVATE_BIRTH_DOMAIN: &str = "source-owned.packet-canonical-ack-birth/5";

/// Checks the key-derived Birth ID and complete original Host reference.
///
/// The caller separately authenticates the prefix/key, original channel and
/// current cut, and admits this check's actual hashing and comparison controls.
///
/// # Errors
/// Refuses another key-derived Birth ID or a different launch Host reference.
pub(super) fn authenticate_data(
    boot: &PacketNativeImport18PrivateBootWireData,
    launch: &PacketNative5SourceLaunch,
    actual_key: &[u8; 32],
) -> Result<(), ProviderError> {
    let mut hasher = blake3::Hasher::new_derive_key(ORIGINAL_PRIVATE_BIRTH_DOMAIN);
    hasher.update(actual_key);
    let birth = hasher.finalize();
    if boot.birth_id.as_slice() != birth.as_bytes()
        || boot.host_executable != launch.controller_executable
    {
        return Err(ProviderError::Correlation(
            "original import18 private Birth DATA",
        ));
    }
    Ok(())
}

/// Names the actual derivation and borrowed full-reference comparison controls.
pub(super) fn counter_scratch_data() -> usize {
    // The surrounding physical prefix row separately admits the shared BLAKE3
    // primitive. These are this check's own live state and comparison operands.
    size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<&[u8; 32]>()
        + size_of::<&[u8]>() * 2
        + size_of::<&PacketNativeImport18PrivateBootWireData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&ContentRef>() * 2
        + size_of::<&crucible_node_format::HashRef>() * 2
        + size_of::<&String>() * 6
        + size_of::<&U64>() * 2
        + size_of::<u64>() * 2
        + size_of::<bool>()
        + size_of::<Result<(), ProviderError>>()
}
