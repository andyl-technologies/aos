//! Canonical SHA-256 content digests.
//!
//! RFC-0019 deliberately accepts only this exact wire form:
//!
//! ```text
//! sha256:<64 lowercase hexadecimal digits>
//! ```
//!
//! There is no normalize-and-accept path for uppercase hex, alternate
//! algorithms, percent encoding, or surrounding whitespace.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

const PREFIX: &str = "sha256:";
const ENCODED_BYTES: usize = 64;

/// A canonical `sha256:` OCI digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Computes the SHA-256 digest of `content`.
    #[must_use]
    pub fn digest(content: &[u8]) -> Self {
        Self(Sha256::digest(content).into())
    }

    /// Constructs a digest from its exact 32 hash bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses the exact RFC-0019 digest spelling.
    ///
    /// # Errors
    ///
    /// Returns an error unless `value` is `sha256:` followed by exactly 64
    /// lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != PREFIX.len() + ENCODED_BYTES {
            return Err(Error::InvalidDigest {
                reason: "expected 'sha256:' followed by exactly 64 lowercase hex digits",
            });
        }
        let Some(encoded) = value.strip_prefix(PREFIX) else {
            return Err(Error::InvalidDigest {
                reason: "SHA-256 is the only accepted algorithm",
            });
        };
        if !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::InvalidDigest {
                reason: "encoded digest must use lowercase hexadecimal digits",
            });
        }

        let mut bytes = [0_u8; 32];
        for (output, pair) in bytes.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
            let high = decode_nibble(pair[0]);
            let low = decode_nibble(pair[1]);
            *output = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Returns the exact 32 hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verifies that `content` hashes to this digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DigestMismatch`] when the computed SHA-256 differs.
    pub fn verify(&self, content: &[u8]) -> Result<()> {
        let actual = Self::digest(content);
        if actual != *self {
            return Err(Error::DigestMismatch {
                expected: self.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(())
    }

    /// Returns the 64-character lowercase hexadecimal component.
    #[must_use]
    pub fn encoded(&self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(PREFIX)?;
        formatter.write_str(&encode_hex(&self.0))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for Sha256Digest {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        // `parse` proves every byte is lowercase hexadecimal before decoding.
        _ => 0,
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(ENCODED_BYTES);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies_the_empty_vector() {
        let digest = Sha256Digest::digest(b"");
        assert_eq!(
            digest.to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        digest.verify(b"").expect("empty digest verifies");
        assert!(digest.verify(b"different").is_err());
    }

    #[test]
    fn accepts_only_the_exact_canonical_wire_form() {
        let valid = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            Sha256Digest::parse(&valid).expect("valid").to_string(),
            valid
        );

        for invalid in [
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("SHA256:{}", "a".repeat(64)),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}%20", "a".repeat(61)),
            format!(" sha256:{}", "a".repeat(64)),
        ] {
            assert!(Sha256Digest::parse(&invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn serde_uses_a_json_string() {
        let digest = Sha256Digest::digest(b"serde");
        let json = serde_json::to_string(&digest).expect("serialize digest");
        let decoded: Sha256Digest = serde_json::from_str(&json).expect("deserialize digest");
        assert_eq!(decoded, digest);
    }
}
