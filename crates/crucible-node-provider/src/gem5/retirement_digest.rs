//! Verifies bounded original operational bodies directly from actual borrowed custody.
//!
//! This streaming writer checks the complete CNP/1 identity and media type. It
//! neither buffers a second full native/ACK body nor interprets hashes as native
//! authority. Its callers must separately hold the original capsule and proof.
//!
//! ```text
//! CNP/1 || 00 || domain length || domain || original body length || actual body
//! ```

use std::io::Write;

use crucible_node_contract::{ContentRef, Validate};

use super::ProviderError;

pub(super) struct OriginalBodyDigest<'a> {
    expected: &'a ContentRef,
    remaining: u64,
    hasher: blake3::Hasher,
    failed: bool,
}

impl<'a> OriginalBodyDigest<'a> {
    pub(super) fn new(
        expected: &'a ContentRef,
        media: &str,
        maximum: u64,
    ) -> Result<Self, ProviderError> {
        expected.validate()?;
        if expected.hash.algorithm != "blake3-256"
            || expected.hash.domain != "cnp.blob.v1"
            || expected.media_type != media
            || expected.length.get() > maximum
        {
            return Err(ProviderError::Correlation(
                "original retirement body grammar differs",
            ));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CNP/1\0");
        hasher.update(&(expected.hash.domain.len() as u32).to_be_bytes());
        hasher.update(expected.hash.domain.as_bytes());
        hasher.update(&expected.length.get().to_be_bytes());
        Ok(Self {
            expected,
            remaining: expected.length.get(),
            hasher,
            failed: false,
        })
    }

    pub(super) fn finish(self) -> Result<(), ProviderError> {
        if self.failed
            || self.remaining != 0
            || self.hasher.finalize().to_hex().as_str() != self.expected.hash.digest
        {
            return Err(ProviderError::Correlation(
                "actual original retirement body differs",
            ));
        }
        Ok(())
    }
}

impl Write for OriginalBodyDigest<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.failed {
            return Err(std::io::Error::other(
                "original body verification already refused",
            ));
        }
        let Some(remaining) = self.remaining.checked_sub(bytes.len() as u64) else {
            self.failed = true;
            return Err(std::io::Error::other(
                "actual original body exceeds its exact extent",
            ));
        };
        self.remaining = remaining;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These inert framing controls panic on unexpected hashing or refusal behavior.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_contract::canonical;

    #[test]
    fn exact_original_body_accepts_only_full_identity_media_and_credit() {
        let body = b"original-partial-ack";
        let original = canonical::content_ref(body, "application/octet-stream").unwrap();
        let mut accepted =
            OriginalBodyDigest::new(&original, "application/octet-stream", body.len() as u64)
                .unwrap();
        accepted.write_all(body).unwrap();
        accepted.finish().unwrap();

        assert!(OriginalBodyDigest::new(&original, "application/json", body.len() as u64).is_err());
        assert!(
            OriginalBodyDigest::new(&original, "application/octet-stream", body.len() as u64 - 1)
                .is_err()
        );
        let mut changed =
            OriginalBodyDigest::new(&original, "application/octet-stream", body.len() as u64)
                .unwrap();
        changed.write_all(b"changed--partial-ack").unwrap();
        assert!(changed.finish().is_err());
    }

    #[test]
    fn short_or_overlong_attempt_remains_refused_after_full_expected_prefix() {
        let original = canonical::content_ref(b"first", "application/octet-stream").unwrap();
        let mut short = OriginalBodyDigest::new(&original, "application/octet-stream", 5).unwrap();
        short.write_all(b"firs").unwrap();
        assert!(short.finish().is_err());

        let mut extra = OriginalBodyDigest::new(&original, "application/octet-stream", 5).unwrap();
        extra.write_all(b"first").unwrap();
        assert!(extra.write_all(b"extra").is_err());
        assert!(extra.finish().is_err());
    }
}
