//! Versioned execution-fingerprint definition.
//!
//! This module fixes the authenticated request boundary and state set for the
//! first Crucible execution fingerprint. The definition digest is folded into
//! every stream so two runs cannot be compared under different request or state
//! coverage contracts.

use super::hasher::FingerprintHasher;

/// The version tag folded into every execution-fingerprint definition digest.
pub const EXECUTION_FINGERPRINT_DEFINITION_VERSION: &str = "crucible-execution-fingerprint-v2";

/// The stable hash algorithm tag used by the fingerprint combiner.
pub const FINGERPRINT_HASH_ALGORITHM: &str = "crucible-stable-fingerprint-hash-v1";

/// The register sub-digest algorithm expected from host observation.
pub const REGISTER_DIGEST_ALGORITHM: &str = "host-observed-architectural-register-digest-v1";

/// The memory sub-digest algorithm expected from host observation.
pub const MEMORY_DIGEST_ALGORITHM: &str = "host-observed-full-guest-memory-digest-v1";

/// The device-state sub-digest algorithm expected from host observation.
pub const DEVICE_DIGEST_ALGORITHM: &str = "host-observed-device-state-digest-v1";

/// A deterministic 256-bit digest represented as canonical bytes.
pub type FingerprintDigest = Vec<u8>;

/// The byte length of every execution-fingerprint digest.
pub const FINGERPRINT_DIGEST_BYTES: usize = 32;

/// The content-addressed execution-fingerprint definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintDefinition {
    include_device_state: bool,
    include_rr_scheduler_state: bool,
}

impl FingerprintDefinition {
    /// Builds the fixed Contract A fingerprint definition.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            include_device_state: true,
            include_rr_scheduler_state: true,
        }
    }

    /// Returns the fixed fingerprint-definition version tag.
    #[must_use]
    pub fn version(&self) -> &'static str {
        EXECUTION_FINGERPRINT_DEFINITION_VERSION
    }

    /// Returns the stable fingerprint hash algorithm tag.
    #[must_use]
    pub fn hash_algorithm(&self) -> &'static str {
        FINGERPRINT_HASH_ALGORITHM
    }

    /// Returns the expected register sub-digest algorithm tag.
    #[must_use]
    pub fn register_digest_algorithm(&self) -> &'static str {
        REGISTER_DIGEST_ALGORITHM
    }

    /// Returns the expected memory sub-digest algorithm tag.
    #[must_use]
    pub fn memory_digest_algorithm(&self) -> &'static str {
        MEMORY_DIGEST_ALGORITHM
    }

    /// Returns the expected device-state sub-digest algorithm tag.
    #[must_use]
    pub fn device_digest_algorithm(&self) -> &'static str {
        DEVICE_DIGEST_ALGORITHM
    }

    /// Returns whether device state is included in each sample.
    #[must_use]
    pub fn include_device_state(&self) -> bool {
        self.include_device_state
    }

    /// Returns whether RR-scheduler state is included in each sample.
    #[must_use]
    pub fn include_rr_scheduler_state(&self) -> bool {
        self.include_rr_scheduler_state
    }

    /// Computes the stable content digest for this definition.
    #[must_use]
    pub fn digest(&self) -> FingerprintDigest {
        let mut hasher = FingerprintHasher::new();
        hasher.write_tag("fingerprint-definition");
        hasher.write_bytes(self.version().as_bytes());
        hasher.write_bytes(self.hash_algorithm().as_bytes());
        hasher.write_bytes(self.register_digest_algorithm().as_bytes());
        hasher.write_bytes(self.memory_digest_algorithm().as_bytes());
        hasher.write_bytes(self.device_digest_algorithm().as_bytes());
        hasher.write_u64(FINGERPRINT_DIGEST_BYTES as u64);
        hasher.write_tag("authenticated-on-demand");
        hasher.write_tag("full-guest-memory");
        hasher.write_bool(self.include_device_state);
        hasher.write_bool(self.include_rr_scheduler_state);
        hasher.finish()
    }
}
