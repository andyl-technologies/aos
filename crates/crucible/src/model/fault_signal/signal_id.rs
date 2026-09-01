//! Stable signal identifiers and their allocation-aware wire admission.

use std::fmt;

use super::{SignalProgramError, fallible_decode};

/// Stable author-supplied identifier used by signal nodes and exported outputs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SignalId(String);

impl SignalId {
    /// Parses a canonical signal identifier.
    ///
    /// Identifiers contain 1 through 96 ASCII bytes. They begin with a lower
    /// case letter and otherwise contain lower case letters, digits, or single
    /// hyphens separating non-empty components.
    ///
    /// # Errors
    ///
    /// Returns [`SignalProgramError::InvalidId`] when `value` is not canonical.
    pub fn parse(value: impl Into<String>) -> Result<Self, SignalProgramError> {
        let value = value.into();
        if !valid_signal_id(&value) {
            return Err(SignalProgramError::InvalidId { value });
        }
        Ok(Self(value))
    }

    /// Returns the canonical identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for SignalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = fallible_decode::deserialize_string(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SignalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_signal_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 96 || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        let hyphen = *byte == b'-';
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || hyphen)
            || (hyphen && previous_hyphen)
        {
            return false;
        }
        previous_hyphen = hyphen;
    }
    true
}
