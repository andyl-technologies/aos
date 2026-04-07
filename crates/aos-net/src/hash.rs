//! Streaming SHA-256 verification helpers.
//!
//! Provides a wrapper for incrementally hashing byte streams as they are
//! downloaded or uploaded, then producing `"sha256:<hex>"` format strings
//! for comparison against narinfo/bundle hashes.

use sha2::{Digest, Sha256};

/// Streaming SHA-256 hasher that accumulates bytes incrementally.
///
/// Wraps `sha2::Sha256` with convenience methods for producing the
/// `"sha256:<hex>"` format used throughout AOS.
pub struct StreamingHash {
    hasher: Sha256,
}

impl StreamingHash {
    /// Create a new streaming hasher.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Feed bytes into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash as `"sha256:<hex>"`.
    pub fn finalize_hex(self) -> String {
        let digest = self.hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    }

    /// Finalize and return just the raw hex string (without `sha256:` prefix).
    pub fn finalize_raw_hex(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl Default for StreamingHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the SHA-256 hash of a byte slice, returning `"sha256:<hex>"`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("sha256:{}", hex::encode(digest))
}

/// Compute the SHA-256 hash of a byte slice, returning just the raw hex.
pub fn sha256_raw_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Verify that `actual_hash` matches `expected_hash`.
///
/// Both should be in `"sha256:<hex>"` format.
pub fn verify_hash(expected: &str, actual: &str) -> bool {
    expected == actual
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_hash_matches_oneshot() {
        let data = b"hello world";
        let mut hasher = StreamingHash::new();
        hasher.update(data);
        let streaming = hasher.finalize_hex();
        let oneshot = sha256_hex(data);
        assert_eq!(streaming, oneshot);
    }

    #[test]
    fn streaming_hash_incremental() {
        let mut hasher = StreamingHash::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finalize_hex();
        let oneshot = sha256_hex(b"hello world");
        assert_eq!(incremental, oneshot);
    }

    #[test]
    fn sha256_hex_format() {
        let hash = sha256_hex(b"test");
        assert!(hash.starts_with("sha256:"));
        // SHA-256 produces 64 hex chars
        assert_eq!(hash.len(), 7 + 64);
    }

    #[test]
    fn sha256_raw_hex_format() {
        let hash = sha256_raw_hex(b"test");
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains(':'));
    }

    #[test]
    fn verify_hash_match() {
        let hash = sha256_hex(b"test");
        assert!(verify_hash(&hash, &hash));
    }

    #[test]
    fn verify_hash_mismatch() {
        let h1 = sha256_hex(b"hello");
        let h2 = sha256_hex(b"world");
        assert!(!verify_hash(&h1, &h2));
    }
}
