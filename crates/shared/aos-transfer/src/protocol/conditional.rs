//! Conditional-write (compare-and-swap) semantics shared by the protocols.
//!
//! A `PUT` request becomes conditional when it carries exactly one of the
//! standard HTTP precondition headers:
//!
//! ```text
//! If-None-Match: *          write only if the object does not exist
//! If-Match: <version>       write only if the current version equals <version>
//! ```
//!
//! Every protocol answers a conditional `PUT` with a [`TransferResult`]
//! rather than an error when the precondition is simply not met:
//!
//! | Outcome              | `status` | `ETag` response header                     |
//! |----------------------|----------|--------------------------------------------|
//! | written              | `200`    | version of the bytes just written          |
//! | precondition failed  | `412`    | current version where the protocol knows it |
//!
//! Version tokens are opaque. S3 uses the object's `ETag` verbatim, quotes
//! included. The filesystem and SFTP protocols use [`content_version`], the
//! lowercase hex SHA-256 of the stored bytes, and evaluate the precondition
//! under an exclusive sibling lock file named by [`lock_file_name`]. HTTP
//! forwards the headers to the server unchanged.
//!
//! Requests without either header keep their unconditional behavior.

use std::time::Duration;

use anyhow::Result;
use sha2::{Digest as _, Sha256};

use crate::types::TransferResult;

/// Request header that makes a write conditional on the current version.
pub const IF_MATCH: &str = "If-Match";

/// Request header that makes a write conditional on the object being absent
/// when its value is `*`.
pub const IF_NONE_MATCH: &str = "If-None-Match";

/// Response header that carries an object's opaque version token.
pub const ETAG: &str = "ETag";

/// Status of a conditional write whose precondition was not met.
pub const PRECONDITION_FAILED: u16 = 412;

/// How long the filesystem and SFTP protocols wait for a contended
/// conditional-write lock before failing.
///
/// Locks are held only for one small read and write, so a longer wait
/// almost always means a stale lock. The transfer engine may retry the
/// failed attempt, multiplying the total wait by its attempt count.
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(5);

/// Delay between attempts to acquire a contended conditional-write lock.
pub(crate) const LOCK_POLL: Duration = Duration::from_millis(100);

/// Returns how many lock acquisition attempts, spaced by [`LOCK_POLL`], fit
/// in `wait`, and at least one.
///
/// Counting attempts rather than comparing clock readings keeps host
/// monotonic time out of the protocol, as the workspace lints require.
pub(crate) fn lock_attempts(wait: Duration) -> u32 {
    let attempts = wait.as_millis().div_ceil(LOCK_POLL.as_millis()).max(1);
    u32::try_from(attempts).unwrap_or(u32::MAX)
}

/// The precondition a conditional `PUT` must satisfy before it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritePrecondition {
    /// The object must not exist (`If-None-Match: *`).
    Absent,
    /// The object must exist with exactly this version (`If-Match`).
    Matches(String),
}

impl WritePrecondition {
    /// Parses the precondition carried by request `headers`.
    ///
    /// Header names match case-insensitively. Returns `Ok(None)` for an
    /// unconditional request.
    ///
    /// # Errors
    ///
    /// Returns an error when both headers are present, when a header is
    /// repeated, when `If-None-Match` is anything other than `*`, or when
    /// `If-Match` is empty or `*` (existence-only matching is not supported).
    pub fn from_headers(headers: &[(String, String)]) -> Result<Option<Self>> {
        let mut precondition = None;

        for (name, value) in headers {
            let parsed = if name.eq_ignore_ascii_case(IF_NONE_MATCH) {
                if value.trim() != "*" {
                    anyhow::bail!(
                        "conditional write supports only `If-None-Match: *`, got {value:?}"
                    );
                }
                Self::Absent
            } else if name.eq_ignore_ascii_case(IF_MATCH) {
                let version = value.trim();
                if version.is_empty() || version == "*" {
                    anyhow::bail!(
                        "conditional write requires an exact `If-Match` version, got {value:?}"
                    );
                }
                Self::Matches(version.to_string())
            } else {
                continue;
            };

            if precondition.replace(parsed).is_some() {
                anyhow::bail!("conditional write accepts exactly one of If-Match or If-None-Match");
            }
        }

        Ok(precondition)
    }

    /// Returns whether an object whose current version is `current`
    /// (`None` when absent) satisfies this precondition.
    pub fn is_satisfied_by(&self, current: Option<&str>) -> bool {
        match (self, current) {
            (Self::Absent, None) => true,
            (Self::Matches(expected), Some(current)) => expected == current,
            _ => false,
        }
    }
}

/// Returns the version token the filesystem and SFTP protocols assign to
/// stored bytes: the lowercase hex SHA-256 of `bytes`.
///
/// # Examples
///
/// ```
/// let version = aos_transfer::protocol::conditional::content_version(b"");
/// assert_eq!(
///     version,
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
/// );
/// ```
pub fn content_version(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Returns the name of the exclusive lock file that guards conditional
/// writes of the sibling file `target_name` (`.<target_name>.lock`).
///
/// # Examples
///
/// ```
/// use aos_transfer::protocol::conditional::lock_file_name;
///
/// assert_eq!(lock_file_name("generation"), ".generation.lock");
/// ```
pub fn lock_file_name(target_name: &str) -> String {
    format!(".{target_name}.lock")
}

/// Contents written into a lock file so an operator can identify a stale
/// lock left behind by a crashed writer.
pub(crate) fn lock_file_contents() -> String {
    format!(
        "aos conditional-write lock held by pid {}\n",
        std::process::id()
    )
}

/// Error message for a lock that stayed held past [`LOCK_WAIT`].
pub(crate) fn lock_timeout_error(lock: &str, waited: Duration) -> anyhow::Error {
    anyhow::anyhow!(
        "timed out after {waited:?} waiting for conditional-write lock {lock}; another writer \
         holds it, or a crashed writer left it behind (remove it only after confirming that no \
         writer is active)"
    )
}

/// Builds the result of a conditional write that stored `byte_count` bytes
/// as `version`.
pub(crate) fn written_result(version: String, byte_count: u64) -> TransferResult {
    TransferResult {
        status: 200,
        headers: vec![(ETAG.to_string(), version)],
        bytes_transferred: byte_count,
        content_length: Some(byte_count),
        body: None,
        hash: None,
        resumed: false,
    }
}

/// Builds the result of a conditional write that was refused because the
/// object's version is `current` (`None` when absent or unknown).
pub(crate) fn precondition_failed_result(current: Option<String>) -> TransferResult {
    TransferResult {
        status: PRECONDITION_FAILED,
        headers: current
            .map(|version| vec![(ETAG.to_string(), version)])
            .unwrap_or_default(),
        bytes_transferred: 0,
        content_length: None,
        body: None,
        hash: None,
        resumed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn unconditional_requests_have_no_precondition() {
        let parsed = WritePrecondition::from_headers(&headers(&[("Content-Type", "text/plain")]));

        assert_eq!(parsed.unwrap(), None);
    }

    #[test]
    fn parses_both_precondition_forms_case_insensitively() {
        let absent = WritePrecondition::from_headers(&headers(&[("if-none-match", "*")]));
        let matches = WritePrecondition::from_headers(&headers(&[("IF-MATCH", "\"abc\"")]));

        assert_eq!(absent.unwrap(), Some(WritePrecondition::Absent));
        assert_eq!(
            matches.unwrap(),
            Some(WritePrecondition::Matches("\"abc\"".to_string()))
        );
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_preconditions() {
        for invalid in [
            headers(&[("If-Match", "a"), ("If-None-Match", "*")]),
            headers(&[("If-Match", "a"), ("If-Match", "b")]),
            headers(&[("If-None-Match", "\"abc\"")]),
            headers(&[("If-Match", "*")]),
            headers(&[("If-Match", " ")]),
        ] {
            assert!(
                WritePrecondition::from_headers(&invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn evaluates_preconditions_against_current_versions() {
        let absent = WritePrecondition::Absent;
        let matches = WritePrecondition::Matches("v1".to_string());

        assert!(absent.is_satisfied_by(None));
        assert!(!absent.is_satisfied_by(Some("v1")));
        assert!(matches.is_satisfied_by(Some("v1")));
        assert!(!matches.is_satisfied_by(Some("v2")));
        assert!(!matches.is_satisfied_by(None));
    }

    #[test]
    fn lock_attempts_cover_the_wait_and_never_drop_to_zero() {
        assert_eq!(lock_attempts(Duration::ZERO), 1);
        assert_eq!(lock_attempts(Duration::from_millis(150)), 2);
        assert_eq!(lock_attempts(LOCK_WAIT), 50);
    }

    #[test]
    fn precondition_failed_result_reports_known_current_version() {
        let known = precondition_failed_result(Some("v2".to_string()));
        let unknown = precondition_failed_result(None);

        assert_eq!(known.status, PRECONDITION_FAILED);
        assert_eq!(known.header(ETAG), Some("v2"));
        assert_eq!(unknown.header(ETAG), None);
    }
}
