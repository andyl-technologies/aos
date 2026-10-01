//! Compare-and-swap writes of small mutable static objects.
//!
//! Static release surfaces keep a few small mutable records, such as a
//! channel generation record, beside their immutable payloads. A release
//! tool advances such a record with a read / compare-and-swap loop built on
//! [`CacheBackend::get_static_object`] and
//! [`CacheBackend::put_static_file_conditional`]:
//!
//! [`CacheBackend::get_static_object`]: super::CacheBackend::get_static_object
//! [`CacheBackend::put_static_file_conditional`]: super::CacheBackend::put_static_file_conditional
//!
//! ```no_run
//! use aos_cache::CacheBackend;
//! use aos_cache::backend::{ConditionalOutcome, Expectation, MUTABLE_CACHE_CONTROL};
//!
//! async fn advance(backend: &dyn CacheBackend, next: &std::path::Path) -> anyhow::Result<()> {
//!     let path = "channels/edge/generation";
//!     let expect = match backend.get_static_object(path, 64 * 1024).await? {
//!         Some((_current_bytes, version)) => Expectation::Version(version),
//!         None => Expectation::Absent,
//!     };
//!
//!     let outcome = backend
//!         .put_static_file_conditional(
//!             path,
//!             next,
//!             Some("application/json"),
//!             Some(MUTABLE_CACHE_CONTROL),
//!             expect,
//!         )
//!         .await?;
//!     match outcome {
//!         ConditionalOutcome::Written(version) => println!("committed {version}"),
//!         ConditionalOutcome::PreconditionFailed { current } => {
//!             anyhow::bail!("another writer advanced {path} to {current:?}")
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Backend semantics
//!
//! | Backend  | [`ObjectVersion`]                 | Compare and swap                                            |
//! |----------|-----------------------------------|-------------------------------------------------------------|
//! | `file`   | hex SHA-256 of the stored bytes   | compare under a `.<name>.lock` created with `O_EXCL`, then temp file + `rename` |
//! | `s3`     | the object's `ETag`, verbatim     | `PutObject` with `If-Match` or `If-None-Match: *`, evaluated by the service |
//! | `sftp`   | hex SHA-256 of the stored bytes   | compare under a `.<name>.lock` created with `CREATE \| EXCL`, then temp file + rename |
//! | `http`   | unsupported                       | unsupported (read-only)                                     |
//!
//! The lock-file backends serialize conditional writers only; unconditional
//! writes to the same path do not take the lock. A lock left behind by a
//! crashed writer makes later conditional writes fail with an error naming
//! it, never succeed silently.
//!
//! # Retried writes
//!
//! The transfer engine retries transient transport failures. If an S3
//! write committed but its response was lost, the retry reports
//! [`ConditionalOutcome::PreconditionFailed`] with the version the lost
//! attempt created. Callers that must distinguish "someone else won" from
//! "I already won" read the object back and compare its bytes.

use std::fmt;

use anyhow::{Context, Result};

use aos_net::protocol::conditional::{ETAG, IF_MATCH, IF_NONE_MATCH, PRECONDITION_FAILED};
use aos_net::{TransferEngine, TransferRequest, TransferResult};

use super::add_static_metadata_headers;

/// Opaque version token of a stored object: the `ETag` for S3, and the
/// lowercase hex SHA-256 of the content for the filesystem and SFTP.
///
/// Tokens are only meaningful to the backend that produced them; compare
/// them for equality and pass them back in [`Expectation::Version`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectVersion(pub String);

impl ObjectVersion {
    /// Returns the token as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The state an object must be in for a conditional write to proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expectation {
    /// No object exists at the path.
    Absent,
    /// The object exists and its current version equals this one.
    Version(ObjectVersion),
}

/// Result of a conditional write whose precondition was evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalOutcome {
    /// The object now holds the new bytes, with this version.
    Written(ObjectVersion),
    /// The expectation did not hold and nothing was written.
    PreconditionFailed {
        /// The object's version when the write was refused, or `None` when
        /// it does not exist.
        current: Option<ObjectVersion>,
    },
}

/// Error returned by backends that cannot read or write static objects
/// conditionally.
///
/// Callers can detect it with `anyhow::Error::downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalWriteUnsupported {
    operation: &'static str,
}

impl ConditionalWriteUnsupported {
    /// Creates the error for the named trait operation.
    pub(crate) const fn new(operation: &'static str) -> Self {
        Self { operation }
    }

    /// Returns the name of the unsupported
    /// [`CacheBackend`](super::CacheBackend) operation.
    pub fn operation(&self) -> &'static str {
        self.operation
    }
}

impl fmt::Display for ConditionalWriteUnsupported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "conditional writes are unsupported by this backend ({} needs a file://, s3://, or \
             sftp:// backend)",
            self.operation
        )
    }
}

impl std::error::Error for ConditionalWriteUnsupported {}

/// Rejects paths that are not normalized and relative to the backend root.
///
/// Conditional writes target small records by exact path, so absolute
/// paths, empty components, and `.` or `..` components are refused rather
/// than resolved.
pub(crate) fn validate_relative_path(relative_path: &str) -> Result<()> {
    let normalized = !relative_path.is_empty()
        && !relative_path.contains('\0')
        && relative_path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."));

    if !normalized {
        anyhow::bail!("static object path {relative_path:?} is not a normalized relative path");
    }
    Ok(())
}

/// A small object read in full, with the `ETag` the transport reported.
pub(crate) struct SmallObject {
    pub(crate) bytes: Vec<u8>,
    pub(crate) etag: Option<String>,
}

/// Reads the object at `url` if it exists, refusing more than `max_bytes`.
///
/// Existence is checked with a `HEAD` first because a `GET` of a missing
/// object is an error on every transport. An object deleted between the two
/// requests therefore surfaces as a read error, not as absence.
pub(crate) async fn read_small_object(
    engine: &TransferEngine,
    url: &str,
    max_bytes: usize,
) -> Result<Option<SmallObject>> {
    let limit = u64::try_from(max_bytes).context("static object size limit overflows u64")?;

    let head = engine
        .head(url)
        .await
        .with_context(|| format!("checking {url}"))?;
    if head.status == 404 {
        return Ok(None);
    }
    if let Some(length) = head.content_length
        && length > limit
    {
        anyhow::bail!("{url} holds {length} bytes, more than the {max_bytes} byte limit");
    }

    let result = engine
        .execute(TransferRequest::get(url).with_maximum_bytes(limit))
        .await
        .with_context(|| format!("reading {url}"))?;
    let etag = result.header(ETAG).map(str::to_string);
    let bytes = result.body.unwrap_or_default();

    // The engine enforces the limit while streaming; this re-check keeps the
    // contract independent of each protocol's length reporting.
    if bytes.len() > max_bytes {
        anyhow::bail!("{url} exceeds the {max_bytes} byte limit");
    }
    Ok(Some(SmallObject { bytes, etag }))
}

/// A conditional write's raw result, before backend-specific version
/// handling.
pub(crate) enum ConditionalResponse {
    /// The write committed; the transport's `ETag` for the new bytes.
    Written(Option<String>),
    /// The precondition failed; the current `ETag` where the transport
    /// reports it.
    Refused(Option<String>),
}

/// Uploads `source` to `url` only if `expect` holds.
pub(crate) async fn send_conditional_put(
    engine: &TransferEngine,
    url: &str,
    source: &std::path::Path,
    content_type: Option<&str>,
    cache_control: Option<&str>,
    expect: &Expectation,
) -> Result<ConditionalResponse> {
    let mut request = TransferRequest::put_file(url, source.to_path_buf());
    add_static_metadata_headers(&mut request, content_type, cache_control, None, None);
    let (name, value) = match expect {
        Expectation::Absent => (IF_NONE_MATCH, "*".to_string()),
        Expectation::Version(version) => (IF_MATCH, version.0.clone()),
    };
    request.headers.push((name.to_string(), value));

    let result = engine
        .execute(request)
        .await
        .with_context(|| format!("conditionally writing {url}"))?;
    classify_conditional_result(url, &result)
}

/// Maps a conditional `PUT` result onto [`ConditionalResponse`], rejecting
/// statuses that are neither success nor a precondition failure.
fn classify_conditional_result(url: &str, result: &TransferResult) -> Result<ConditionalResponse> {
    let etag = result.header(ETAG).map(str::to_string);

    match result.status {
        200..=299 => Ok(ConditionalResponse::Written(etag)),
        PRECONDITION_FAILED => Ok(ConditionalResponse::Refused(etag)),
        status => anyhow::bail!("conditional write of {url} returned unexpected status {status}"),
    }
}

/// Builds the outcome for backends whose transport reports the version of
/// both the written bytes and a refusing object (filesystem and SFTP).
pub(crate) fn outcome_with_reported_versions(
    url: &str,
    response: ConditionalResponse,
) -> Result<ConditionalOutcome> {
    match response {
        ConditionalResponse::Written(Some(etag)) => {
            Ok(ConditionalOutcome::Written(ObjectVersion(etag)))
        }
        ConditionalResponse::Written(None) => {
            anyhow::bail!("conditional write of {url} committed but reported no version")
        }
        ConditionalResponse::Refused(current) => Ok(ConditionalOutcome::PreconditionFailed {
            current: current.map(ObjectVersion),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: u16, etag: Option<&str>) -> TransferResult {
        TransferResult {
            status,
            headers: etag
                .map(|etag| vec![("ETag".to_string(), etag.to_string())])
                .unwrap_or_default(),
            bytes_transferred: 0,
            content_length: None,
            body: None,
            hash: None,
            resumed: false,
        }
    }

    #[test]
    fn accepts_only_normalized_relative_paths() {
        for valid in ["generation", "channels/edge/generation", ".aos-surface"] {
            assert!(validate_relative_path(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "/channels/edge",
            "channels//edge",
            "channels/edge/",
            "channels/./edge",
            "channels/../edge",
            "nul\0byte",
        ] {
            assert!(validate_relative_path(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn classifies_conditional_statuses() {
        let written = classify_conditional_result("u", &result(200, Some("v1"))).unwrap();
        let refused = classify_conditional_result("u", &result(412, None)).unwrap();

        assert!(matches!(written, ConditionalResponse::Written(Some(ref v)) if v == "v1"));
        assert!(matches!(refused, ConditionalResponse::Refused(None)));
        assert!(classify_conditional_result("u", &result(404, None)).is_err());
    }

    #[test]
    fn reported_versions_become_outcomes() {
        let written =
            outcome_with_reported_versions("u", ConditionalResponse::Written(Some("v".into())));
        let refused = outcome_with_reported_versions("u", ConditionalResponse::Refused(None));

        assert_eq!(
            written.unwrap(),
            ConditionalOutcome::Written(ObjectVersion("v".into()))
        );
        assert_eq!(
            refused.unwrap(),
            ConditionalOutcome::PreconditionFailed { current: None }
        );
        assert!(outcome_with_reported_versions("u", ConditionalResponse::Written(None)).is_err());
    }

    #[test]
    fn unsupported_error_is_downcastable() {
        let error = anyhow::Error::from(ConditionalWriteUnsupported::new("get_static_object"));

        let unsupported = error.downcast_ref::<ConditionalWriteUnsupported>();

        assert_eq!(
            unsupported.map(ConditionalWriteUnsupported::operation),
            Some("get_static_object")
        );
    }
}
