//! Normalized artifact-relative paths and durable module transaction identities.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use aos_core::identity::{IdentityError, LocalKey};

const MAX_RELATIVE_PATH_BYTES: usize = 4_096;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_stay_below_the_authenticated_artifact_root() {
        assert!(RelativePath::new("module/options.json").is_ok());
        for path in ["", "/absolute", "../parent", "a/../b", "a//b", "a/./b"] {
            assert!(RelativePath::new(path).is_err());
        }
    }
}
