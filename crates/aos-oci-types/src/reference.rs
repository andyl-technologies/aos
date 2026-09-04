//! Canonical repository, tag, and manifest-reference parsing.
//!
//! Values are either accepted byte-for-byte or rejected. This module never
//! lowercases, trims, percent-decodes, collapses separators, or falls back from
//! one manifest-reference interpretation to another.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::limits::{MAX_REPOSITORY_BYTES, MAX_TAG_BYTES};

/// A canonical repository name local to one AOS registry authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepositoryName(String);

impl RepositoryName {
    /// Parses an exact lowercase slash-separated repository name.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong name, a non-ASCII or uppercase
    /// byte, a percent or backslash, an empty/dot component, or a component that
    /// violates the RFC-0019 separator grammar.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidRepository {
                reason: "repository must not be empty",
            });
        }
        if value.len() > MAX_REPOSITORY_BYTES {
            return Err(Error::InvalidRepository {
                reason: "repository exceeds 255 bytes",
            });
        }
        if !value.is_ascii() {
            return Err(Error::InvalidRepository {
                reason: "repository must be ASCII",
            });
        }
        if value.contains('%') {
            return Err(Error::InvalidRepository {
                reason: "percent-encoded octets are not accepted",
            });
        }
        if value.contains('\\') {
            return Err(Error::InvalidRepository {
                reason: "backslashes are not accepted",
            });
        }

        for component in value.split('/') {
            validate_repository_component(component)?;
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the canonical repository bytes as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the repository and returns its canonical spelling.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RepositoryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RepositoryName {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for RepositoryName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RepositoryName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A case-sensitive canonical OCI tag.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(String);

impl Tag {
    /// Parses a tag matching `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty, exceeds 128 bytes, contains
    /// percent encoding or non-ASCII bytes, or violates the tag grammar.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidTag {
                reason: "tag must not be empty",
            });
        }
        if value.len() > MAX_TAG_BYTES {
            return Err(Error::InvalidTag {
                reason: "tag exceeds 128 bytes",
            });
        }
        if !value.is_ascii() {
            return Err(Error::InvalidTag {
                reason: "tag must be ASCII",
            });
        }
        if value.contains('%') {
            return Err(Error::InvalidTag {
                reason: "percent-encoded octets are not accepted",
            });
        }
        let mut bytes = value.bytes();
        let Some(first) = bytes.next() else {
            return Err(Error::InvalidTag {
                reason: "tag must not be empty",
            });
        };
        if !first.is_ascii_alphanumeric() && first != b'_' {
            return Err(Error::InvalidTag {
                reason: "first byte must be alphanumeric or underscore",
            });
        }
        if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')) {
            return Err(Error::InvalidTag {
                reason: "tag contains a byte outside [A-Za-z0-9_.-]",
            });
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the exact case-sensitive tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the tag and returns its exact spelling.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Tag {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A `/manifests/<reference>` value interpreted exactly once as a tag or digest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManifestReference {
    /// A mutable or release-bound tag.
    Tag(Tag),
    /// An immutable SHA-256 digest.
    Digest(Sha256Digest),
}

impl ManifestReference {
    /// Parses a canonical tag or digest without fallback interpretation.
    ///
    /// Any value containing `:` is treated as a digest attempt. This ensures an
    /// unsupported algorithm or malformed `sha256:` value cannot be reinterpreted
    /// under a future tag grammar.
    ///
    /// # Errors
    ///
    /// Returns the corresponding tag or digest error when the exact value is not
    /// canonical.
    pub fn parse(value: &str) -> Result<Self> {
        if value.contains(':') {
            Sha256Digest::parse(value).map(Self::Digest)
        } else {
            Tag::parse(value).map(Self::Tag)
        }
    }

    /// Returns whether this reference is immutable.
    #[must_use]
    pub const fn is_digest(&self) -> bool {
        matches!(self, Self::Digest(_))
    }
}

impl fmt::Display for ManifestReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tag(tag) => tag.fmt(formatter),
            Self::Digest(digest) => digest.fmt(formatter),
        }
    }
}

impl FromStr for ManifestReference {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for ManifestReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ManifestReference {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

fn validate_repository_component(component: &str) -> Result<()> {
    if component.is_empty() {
        return Err(Error::InvalidRepository {
            reason: "repository contains an empty component",
        });
    }
    if matches!(component, "." | "..") {
        return Err(Error::InvalidRepository {
            reason: "dot components are not accepted",
        });
    }

    let bytes = component.as_bytes();
    if !is_lower_alphanumeric(bytes[0]) || !is_lower_alphanumeric(bytes[bytes.len() - 1]) {
        return Err(Error::InvalidRepository {
            reason: "each component must start and end with [a-z0-9]",
        });
    }

    let mut cursor = 0;
    while cursor < bytes.len() {
        if is_lower_alphanumeric(bytes[cursor]) {
            cursor += 1;
            continue;
        }

        cursor = match bytes[cursor] {
            b'.' => cursor + 1,
            b'_' if bytes.get(cursor + 1) == Some(&b'_') => cursor + 2,
            b'_' => cursor + 1,
            b'-' => {
                let mut next = cursor + 1;
                while bytes.get(next) == Some(&b'-') {
                    next += 1;
                }
                next
            }
            _ => {
                return Err(Error::InvalidRepository {
                    reason: "component contains a byte outside the lowercase grammar",
                });
            }
        };

        if bytes
            .get(cursor)
            .is_none_or(|byte| !is_lower_alphanumeric(*byte))
        {
            return Err(Error::InvalidRepository {
                reason: "component separators must be followed by [a-z0-9]",
            });
        }
    }
    Ok(())
}

const fn is_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn repository_parser_accepts_each_canonical_separator() {
        for valid in [
            "a",
            "a/b",
            "team/image.v1",
            "team/image_v1",
            "team/image__v1",
            "team/image---v1",
            "0/9",
        ] {
            assert_eq!(RepositoryName::parse(valid).expect("valid").as_str(), valid);
        }
    }

    #[test]
    fn repository_parser_rejects_noncanonical_inputs() {
        let overlong = "a".repeat(MAX_REPOSITORY_BYTES + 1);
        for invalid in [
            "", "/a", "a/", "a//b", "a/./b", "a/../b", "Upper", "a%2fb", "a\\b", "a..b", "a___b",
            "a.-b", "a_-b", "a-", &overlong,
        ] {
            assert!(
                RepositoryName::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn tag_parser_is_case_sensitive_and_bounded() {
        for valid in [
            "latest",
            "V1.2-rc_3",
            "_internal",
            &"a".repeat(MAX_TAG_BYTES),
        ] {
            assert_eq!(Tag::parse(valid).expect("valid").as_str(), valid);
        }
        for invalid in [
            "",
            ".latest",
            "-bad",
            "with/slash",
            "x%2fy",
            &"a".repeat(129),
        ] {
            assert!(Tag::parse(invalid).is_err(), "accepted {invalid}");
        }
        assert_ne!(
            Tag::parse("Release").expect("tag"),
            Tag::parse("release").expect("tag")
        );
    }

    #[test]
    fn manifest_reference_never_falls_back_from_digest_syntax() {
        assert!(matches!(
            ManifestReference::parse("latest").expect("tag"),
            ManifestReference::Tag(_)
        ));
        let digest = Sha256Digest::digest(b"manifest").to_string();
        assert!(matches!(
            ManifestReference::parse(&digest).expect("digest"),
            ManifestReference::Digest(_)
        ));
        assert!(ManifestReference::parse("sha256:not-a-digest").is_err());
        assert!(ManifestReference::parse("sha512:deadbeef").is_err());
    }
}
