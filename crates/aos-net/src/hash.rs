//! Streaming hash verification during transfers.
//!
//! Computes a hash incrementally as data is received, then verifies
//! against an expected value at the end.

use digest::Digest;
use sha2::{Sha256, Sha512};

use crate::types::HashAlgorithm;

/// A streaming hasher that can be fed chunks of data and finalized.
///
/// Used by the transfer engine to verify downloads chunk-by-chunk as
/// they arrive, without buffering the full body.
///
/// # Examples
///
/// ```no_run
/// use aos_net::StreamingHasher;
/// use aos_net::types::HashAlgorithm;
///
/// let mut hasher = StreamingHasher::new(HashAlgorithm::Sha256);
/// hasher.update(b"hel");
/// hasher.update(b"lo");
/// let result = hasher.finalize();
/// println!("sha256 = {}", result.hex);
/// ```
pub struct StreamingHasher {
    state: HasherState,
    expected: Option<String>,
}

/// Algorithm-specific digest state behind [`StreamingHasher`].
enum HasherState {
    Sha256(Sha256),
    Sha512(Sha512),
}

/// The result of finalizing a streaming hash.
#[derive(Debug, Clone)]
pub struct HashResult {
    /// The computed hash as a hex string.
    pub hex: String,
    /// Whether the hash matched the expected value.
    /// `None` if no expected hash was provided, `Some(bool)` if checked.
    pub matched: Option<bool>,
}

impl StreamingHasher {
    /// Create a new streaming hasher without an expected value.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let state = match algorithm {
            HashAlgorithm::Sha256 => HasherState::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => HasherState::Sha512(Sha512::new()),
        };
        Self {
            state,
            expected: None,
        }
    }

    /// Create a new streaming hasher with an expected hash value.
    ///
    /// The expected value may be bare hex (`"2cf2..."`) or carry a
    /// `"sha256:"` / `"sha512:"` prefix; the prefix is stripped before
    /// comparison in [`finalize`](StreamingHasher::finalize).
    pub fn with_expected(algorithm: HashAlgorithm, expected: &str) -> Self {
        let state = match algorithm {
            HashAlgorithm::Sha256 => HasherState::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => HasherState::Sha512(Sha512::new()),
        };
        Self {
            state,
            expected: Some(expected.to_string()),
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            HasherState::Sha256(h) => h.update(data),
            HasherState::Sha512(h) => h.update(data),
        }
    }

    /// Finalize the hash and return the result.
    ///
    /// The comparison against the expected value (if any) is
    /// case-insensitive, and a `"sha256:"` or `"sha512:"` prefix on the
    /// expected string is ignored.
    pub fn finalize(self) -> HashResult {
        let hex = match self.state {
            HasherState::Sha256(h) => hex::encode(h.finalize()),
            HasherState::Sha512(h) => hex::encode(h.finalize()),
        };

        let matched = self.expected.as_ref().map(|expected| {
            // Support both bare hex and prefixed formats like "sha256:abc..."
            let expected_hex = expected
                .strip_prefix("sha256:")
                .or_else(|| expected.strip_prefix("sha512:"))
                .unwrap_or(expected);
            hex.eq_ignore_ascii_case(expected_hex)
        });

        HashResult { hex, matched }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hasher = StreamingHasher::new(HashAlgorithm::Sha256);
        let result = hasher.finalize();
        assert_eq!(
            result.hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(result.matched, None);
    }

    #[test]
    fn test_sha256_hello() {
        let mut hasher = StreamingHasher::new(HashAlgorithm::Sha256);
        hasher.update(b"hello");
        let result = hasher.finalize();
        assert_eq!(
            result.hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_streaming() {
        let mut hasher = StreamingHasher::new(HashAlgorithm::Sha256);
        hasher.update(b"hel");
        hasher.update(b"lo");
        let result = hasher.finalize();
        assert_eq!(
            result.hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_with_expected_match() {
        let mut hasher = StreamingHasher::with_expected(
            HashAlgorithm::Sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
        hasher.update(b"hello");
        let result = hasher.finalize();
        assert_eq!(result.matched, Some(true));
    }

    #[test]
    fn test_sha256_with_expected_mismatch() {
        let mut hasher = StreamingHasher::with_expected(HashAlgorithm::Sha256, "0000000000000000");
        hasher.update(b"hello");
        let result = hasher.finalize();
        assert_eq!(result.matched, Some(false));
    }

    #[test]
    fn test_sha256_with_prefixed_expected() {
        let mut hasher = StreamingHasher::with_expected(
            HashAlgorithm::Sha256,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
        hasher.update(b"hello");
        let result = hasher.finalize();
        assert_eq!(result.matched, Some(true));
    }

    #[test]
    fn test_sha512() {
        let mut hasher = StreamingHasher::new(HashAlgorithm::Sha512);
        hasher.update(b"hello");
        let result = hasher.finalize();
        assert_eq!(result.hex.len(), 128); // SHA-512 produces 64 bytes = 128 hex chars
    }
}
