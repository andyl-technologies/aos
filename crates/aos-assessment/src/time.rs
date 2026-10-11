//! Explicit whole-second UTC timestamps for portable assessment inputs.
//!
//! This profile accepts `"2026-10-09T12:00:00Z"`, without offsets, fractions,
//! leap seconds, or implicit wall-clock reads. Older Unix-second contracts are
//! translated explicitly by the effect layer.

use std::fmt;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// Preserves a validated whole-second UTC timestamp and its comparison value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Timestamp {
    encoded: String,
    unix_seconds: u64,
}

impl Timestamp {
    /// Parses the closed assessment timestamp profile.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid dates, offsets, fractions, leap seconds,
    /// timestamps before the Unix epoch, or incompatible encodings.
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != 20
            || !value.is_ascii()
            || !value.ends_with('Z')
            || value.as_bytes()[10] != b'T'
            || value.get(17..19) == Some("60")
        {
            bail!("assessment timestamp requires whole-second UTC without leap seconds");
        }

        let parsed = humantime::parse_rfc3339(value).context("invalid assessment timestamp")?;
        let unix_seconds = parsed
            .duration_since(UNIX_EPOCH)
            .context("assessment timestamp predates the Unix epoch")?
            .as_secs();
        let canonical = humantime::format_rfc3339_seconds(parsed).to_string();
        if canonical != value {
            bail!("assessment timestamp is not canonical UTC");
        }

        Ok(Self {
            encoded: canonical,
            unix_seconds,
        })
    }

    /// Constructs an exact timestamp from a legacy Unix-second value.
    ///
    /// # Errors
    ///
    /// Returns an error when the timestamp exceeds the four-digit year profile
    /// or cannot be represented on the target platform.
    pub fn from_unix_seconds(seconds: u64) -> Result<Self> {
        if seconds > 253_402_300_799 {
            bail!("assessment timestamp exceeds year 9999");
        }

        let parsed = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .context("assessment timestamp is outside the platform range")?;
        Self::parse(&humantime::format_rfc3339_seconds(parsed).to_string())
    }

    /// Returns the exact legacy Unix-second representation.
    #[must_use]
    pub const fn unix_seconds(&self) -> u64 {
        self.unix_seconds
    }

    /// Returns the canonical RFC3339 representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Computes elapsed seconds without accepting future evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when `earlier` is later than this timestamp.
    pub fn elapsed_since(&self, earlier: &Self) -> Result<u64> {
        self.unix_seconds
            .checked_sub(earlier.unix_seconds)
            .context("assessment evidence has a future timestamp")
    }
}

impl TryFrom<String> for Timestamp {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<Timestamp> for String {
    fn from(value: Timestamp) -> Self {
        value.encoded
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_profile_rejects_noncanonical_or_ambiguous_times() {
        for invalid in [
            "2026-10-09T12:00:00+00:00",
            "2026-10-09T12:00:00.1Z",
            "2026-10-09T12:00:60Z",
            "2026-02-30T12:00:00Z",
            "2026-10-09 12:00:00Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert!(Timestamp::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn timestamps_translate_without_rounding_or_ambient_time() -> Result<()> {
        let parsed = Timestamp::parse("2026-08-29T12:34:56Z")?;
        assert_eq!(parsed.unix_seconds(), 1_788_006_896);
        assert_eq!(Timestamp::from_unix_seconds(parsed.unix_seconds())?, parsed);
        assert_eq!(serde_json::to_string(&parsed)?, "\"2026-08-29T12:34:56Z\"");
        assert!(Timestamp::from_unix_seconds(u64::MAX).is_err());
        assert!(
            Timestamp::from_unix_seconds(0)?
                .elapsed_since(&parsed)
                .is_err()
        );
        Ok(())
    }
}
