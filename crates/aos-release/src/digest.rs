//! Typed SHA-256 identities and signature-domain separation.

use std::fmt;

use anyhow::{Context as _, Result, anyhow, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::canonical;

/// An exact SHA-256 content identity serialized as `sha256:<lower-hex>`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Constructs an identity from an already computed SHA-256 value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes the identity of exact bytes.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    /// Computes a domain-separated identity over exact bytes.
    #[must_use]
    pub fn separated(domain: &str, bytes: impl AsRef<[u8]>) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain.as_bytes());
        digest.update([0]);
        digest.update(bytes.as_ref());
        Self(digest.finalize().into())
    }

    /// Computes a domain-separated identity over canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the value cannot be encoded in the canonical AOS
    /// JSON dialect.
    pub fn of_canonical<T>(domain: &str, value: &T) -> Result<Self>
    where
        T: Serialize,
    {
        Ok(Self::separated(domain, canonical::to_vec(value)?))
    }

    /// Parses the exact external representation.
    ///
    /// # Errors
    ///
    /// Returns an error unless `value` is `sha256:` followed by exactly 64
    /// lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self> {
        let encoded = value
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("digest must start with sha256:"))?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("SHA-256 digest must contain exactly 64 lowercase hexadecimal digits");
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).context("decoding SHA-256 text")?;
            bytes[index] = u8::from_str_radix(pair, 16).context("decoding SHA-256 text")?;
        }
        Ok(Self(bytes))
    }

    /// Returns the raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns lowercase hexadecimal without the algorithm prefix.
    #[must_use]
    pub fn hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", encode_hex(&self.0))
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

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(*byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(*byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trips_strictly() {
        let digest = Sha256Digest::of_bytes("release");
        assert!(matches!(
            Sha256Digest::parse(&digest.to_string()),
            Ok(parsed) if parsed == digest
        ));
        assert!(Sha256Digest::parse(&digest.to_string().to_uppercase()).is_err());
        assert!(Sha256Digest::parse(&digest.hex()).is_err());
    }
}
