//! Bounded names, normalized artifact paths, and durable blob identities.

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const MAX_LOCAL_KEY_BYTES: usize = 128;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;

/// Reports why an ability identity component is invalid.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    /// A required identity component was empty.
    #[error("{kind} must not be empty")]
    Empty { kind: &'static str },
    /// An identity component exceeded its format bound byte limit.
    #[error("{kind} exceeds its {limit} byte limit")]
    TooLong { kind: &'static str, limit: usize },
    /// A local key used a character outside the closed grammar.
    #[error("local key contains a character outside [A-Za-z0-9._-]")]
    InvalidLocalKey,
    /// An artifact-relative path was empty, absolute, or non-normalized.
    #[error("relative path must be a nonempty normalized path of at most {limit} bytes")]
    InvalidRelativePath { limit: usize },
}

/// Identifies one bounded local name inside an authenticated parent scope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalKey(String);

impl LocalKey {
    /// Constructs a local key from the version-1 key grammar.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty, exceeds 128 bytes, is not
    /// ASCII, or contains a character outside `[A-Za-z0-9._-]`.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        validate_local_key(&value)?;
        Ok(Self(value))
    }

    /// Returns the serialized key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for LocalKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for LocalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for LocalKey {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for LocalKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LocalKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identifies a normalized file below an authenticated artifact root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativePath(String);

impl RelativePath {
    /// Constructs an artifact-relative path without `.` or `..` components.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty, absolute, exceeds 4,096 bytes,
    /// contains a NUL byte, or is not lexically normalized.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_RELATIVE_PATH_BYTES
            && !value.starts_with('/')
            && !value.contains('\0')
            && value
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..");
        if !valid {
            return Err(IdentityError::InvalidRelativePath {
                limit: MAX_RELATIVE_PATH_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Returns the serialized artifact-relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RelativePath {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for RelativePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identifies one durable controller allocation for a plan execution.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TransactionId(pub LocalKey);

fn validate_local_key(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { kind: "local key" });
    }
    if value.len() > MAX_LOCAL_KEY_BYTES {
        return Err(IdentityError::TooLong {
            kind: "local key",
            limit: MAX_LOCAL_KEY_BYTES,
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(IdentityError::InvalidLocalKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_keys_enforce_the_closed_grammar() {
        assert!(LocalKey::new("edge.v1_0-main").is_ok());
        for key in ["", "host/path", "é", &"x".repeat(129)] {
            assert!(LocalKey::new(key).is_err());
        }
    }

    #[test]
    fn relative_paths_stay_below_the_authenticated_artifact_root() {
        assert!(RelativePath::new("module/options.json").is_ok());
        for path in ["", "/absolute", "../parent", "a/../b", "a//b", "a/./b"] {
            assert!(RelativePath::new(path).is_err());
        }
    }
}
