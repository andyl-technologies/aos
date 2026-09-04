//! Transport-neutral HTTP planning for immutable OCI objects.
//!
//! Blob, manifest, and index bytes share the same exact-digest validators,
//! single-range semantics, and private/public cache policy in native Hub and
//! Worker deployments. This adapter intentionally omits disk-image attachment
//! headers and derives the Distribution-specific digest header separately.

use std::collections::BTreeMap;

use anyhow::{bail, Result};

use crate::delivery_http::{
    evaluate_verified_representation, ContentMutability, DeliveryMethod, EntityTag,
    EntityTagCondition, HttpTimestamp, IfRangeCondition, RequestDecision, RequestPreconditions,
    SingleByteRange, VerifiedRepresentation,
};

/// Authorization visibility of the resolved repository object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciAccess {
    /// Anonymous pulls may be stored by shared caches.
    Public,
    /// Pulls depend on a repository bearer and must not be cached publicly.
    Private,
}

/// Exact immutable identity required to serve one OCI object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciHttpMetadata {
    /// Exact allowlisted response media type.
    pub media_type: String,
    /// Exact immutable object byte length.
    pub byte_size: u64,
    /// Canonical `sha256:` Distribution digest.
    pub digest: String,
}

/// Borrowed request headers admitted by OCI delivery.
#[derive(Debug, Clone, Copy)]
pub struct OciHttpRequest<'a> {
    /// Exact GET or HEAD method.
    pub method: DeliveryMethod,
    /// Raw `Range` bytes.
    pub range: Option<&'a [u8]>,
    /// Raw `If-Match` bytes.
    pub if_match: Option<&'a [u8]>,
    /// Raw `If-Unmodified-Since` bytes.
    pub if_unmodified_since: Option<&'a [u8]>,
    /// Raw `If-None-Match` bytes.
    pub if_none_match: Option<&'a [u8]>,
    /// Raw `If-Modified-Since` bytes.
    pub if_modified_since: Option<&'a [u8]>,
    /// Raw `If-Range` bytes.
    pub if_range: Option<&'a [u8]>,
    /// Current time used for obsolete HTTP-date disambiguation.
    pub now: HttpTimestamp,
}

/// Inclusive body interval selected from one OCI object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciByteRange {
    /// Inclusive first byte.
    pub start: u64,
    /// Inclusive last byte.
    pub end: u64,
}

impl OciByteRange {
    /// Returns the number of selected bytes.
    #[must_use]
    pub const fn len(self) -> u64 {
        if self.is_empty() {
            0
        } else {
            self.end - self.start + 1
        }
    }

    /// Returns whether the interval is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end < self.start
    }
}

/// Complete response plan before a placement stream is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciResponsePlan {
    /// HTTP status code.
    pub status: u16,
    /// Exact common and Distribution response headers.
    pub headers: BTreeMap<String, String>,
    /// Storage range to open, absent for HEAD and terminal responses.
    pub body_range: Option<OciByteRange>,
}

/// Plans one immutable OCI GET or HEAD response.
///
/// # Errors
///
/// Returns an error for malformed digest metadata, entity-tag conditions,
/// dates, or range syntax. An unsatisfiable valid range yields a 416 plan.
pub fn plan_oci_response(
    object: &OciHttpMetadata,
    access: OciAccess,
    request: OciHttpRequest<'_>,
) -> Result<OciResponsePlan> {
    validate_digest(&object.digest)?;
    let etag = EntityTag::parse(&format!("\"{}\"", object.digest))?;
    let representation = VerifiedRepresentation::new(
        object.byte_size,
        etag,
        None,
        object.media_type.clone(),
        ContentMutability::Immutable,
    )?;
    let if_match = request
        .if_match
        .map(EntityTagCondition::parse_bytes)
        .transpose()?;
    let if_none_match = request
        .if_none_match
        .map(EntityTagCondition::parse_bytes)
        .transpose()?;
    let if_unmodified_since = parse_optional_http_date(request.if_unmodified_since, request.now);
    let if_modified_since = parse_optional_http_date(request.if_modified_since, request.now);
    let (if_range, if_range_valid) = parse_if_range(request.if_range, request.now);
    let preconditions = RequestPreconditions::new(
        if_match,
        if_unmodified_since,
        if_none_match,
        if_modified_since,
        if_range,
    )?;
    let range = request
        .range
        .map(|value| {
            std::str::from_utf8(value)
                .map_err(|_| anyhow::anyhow!("OCI Range is not ASCII"))
                .and_then(|value| SingleByteRange::parse(value).map_err(Into::into))
        })
        .transpose()?;
    let effective_range = if if_range_valid { range } else { None };
    let decision = evaluate_verified_representation(
        request.method,
        &preconditions,
        effective_range,
        &representation,
    );
    response_plan(object, access, decision)
}

fn response_plan(
    object: &OciHttpMetadata,
    access: OciAccess,
    decision: RequestDecision,
) -> Result<OciResponsePlan> {
    let status = decision.status_code();
    match decision {
        RequestDecision::ServeFull { method } => {
            let mut headers = immutable_headers(object, access)?;
            headers.insert("content-length".into(), object.byte_size.to_string());
            Ok(OciResponsePlan {
                status,
                headers,
                body_range: (method == DeliveryMethod::Get && object.byte_size > 0).then_some(
                    OciByteRange {
                        start: 0,
                        end: object.byte_size - 1,
                    },
                ),
            })
        }
        RequestDecision::ServePartial { range } => {
            let selected = OciByteRange {
                start: range.start(),
                end: range.end(),
            };
            let mut headers = immutable_headers(object, access)?;
            headers.insert(
                "content-range".into(),
                format!(
                    "bytes {}-{}/{}",
                    selected.start, selected.end, object.byte_size
                ),
            );
            headers.insert("content-length".into(), selected.len().to_string());
            Ok(OciResponsePlan {
                status,
                headers,
                body_range: Some(selected),
            })
        }
        RequestDecision::NotModified => Ok(OciResponsePlan {
            status,
            headers: immutable_headers(object, access)?,
            body_range: None,
        }),
        RequestDecision::PreconditionFailed => Ok(OciResponsePlan {
            status,
            headers: terminal_headers(access),
            body_range: None,
        }),
        RequestDecision::RangeNotSatisfiable { complete_length } => {
            let mut headers = terminal_headers(access);
            headers.insert("accept-ranges".into(), "bytes".into());
            headers.insert("content-range".into(), format!("bytes */{complete_length}"));
            headers.insert("content-length".into(), "0".into());
            Ok(OciResponsePlan {
                status,
                headers,
                body_range: None,
            })
        }
        RequestDecision::NotFound => bail!("OCI response evaluation lost a present object"),
    }
}

fn immutable_headers(
    object: &OciHttpMetadata,
    access: OciAccess,
) -> Result<BTreeMap<String, String>> {
    validate_digest(&object.digest)?;
    let mut headers = BTreeMap::from([
        ("accept-ranges".into(), "bytes".into()),
        (
            "cache-control".into(),
            match access {
                OciAccess::Public => crate::delivery_http::PUBLIC_IMMUTABLE_CACHE_CONTROL,
                OciAccess::Private => crate::delivery_http::PRIVATE_CACHE_CONTROL,
            }
            .into(),
        ),
        ("content-type".into(), object.media_type.clone()),
        ("docker-content-digest".into(), object.digest.clone()),
        ("etag".into(), format!("\"{}\"", object.digest)),
        ("x-content-type-options".into(), "nosniff".into()),
        (
            "docker-distribution-api-version".into(),
            crate::oci::DISTRIBUTION_API_VERSION.into(),
        ),
    ]);
    if access == OciAccess::Private {
        headers.insert("vary".into(), "Authorization".into());
    }
    Ok(headers)
}

fn terminal_headers(access: OciAccess) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::from([
        (
            "cache-control".into(),
            match access {
                OciAccess::Public => "no-store",
                OciAccess::Private => crate::delivery_http::PRIVATE_CACHE_CONTROL,
            }
            .into(),
        ),
        ("content-length".into(), "0".into()),
        (
            "docker-distribution-api-version".into(),
            crate::oci::DISTRIBUTION_API_VERSION.into(),
        ),
        ("x-content-type-options".into(), "nosniff".into()),
    ]);
    if access == OciAccess::Private {
        headers.insert("vary".into(), "Authorization".into());
    }
    headers
}

fn validate_digest(value: &str) -> Result<()> {
    aos_oci_types::Sha256Digest::parse(value)
        .map(|_| ())
        .map_err(Into::into)
}

fn parse_optional_http_date(value: Option<&[u8]>, now: HttpTimestamp) -> Option<HttpTimestamp> {
    value
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| HttpTimestamp::parse_http_date(value, now).ok())
}

fn parse_if_range(value: Option<&[u8]>, now: HttpTimestamp) -> (Option<IfRangeCondition>, bool) {
    let Some(value) = value else {
        return (None, true);
    };
    if let Ok(tag) = EntityTag::parse_bytes(value) {
        return (Some(IfRangeCondition::EntityTag(tag)), true);
    }
    if let Ok(value) = std::str::from_utf8(value) {
        if let Ok(date) = HttpTimestamp::parse_http_date(value, now) {
            return (Some(IfRangeCondition::Date(date)), true);
        }
    }
    (None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> OciHttpMetadata {
        OciHttpMetadata {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            byte_size: 10,
            digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    fn request(method: DeliveryMethod, range: Option<&[u8]>) -> OciHttpRequest<'_> {
        OciHttpRequest {
            method,
            range,
            if_match: None,
            if_unmodified_since: None,
            if_none_match: None,
            if_modified_since: None,
            if_range: None,
            now: HttpTimestamp::from_unix_seconds(1_700_000_000).unwrap(),
        }
    }

    #[test]
    fn full_head_and_range_share_digest_identity() {
        let full = plan_oci_response(
            &object(),
            OciAccess::Public,
            request(DeliveryMethod::Get, None),
        )
        .unwrap();
        assert_eq!(full.status, 200);
        assert_eq!(full.headers["docker-content-digest"], object().digest);
        assert_eq!(full.body_range.unwrap().len(), 10);

        let head = plan_oci_response(
            &object(),
            OciAccess::Private,
            request(DeliveryMethod::Head, None),
        )
        .unwrap();
        assert_eq!(head.status, 200);
        assert!(head.body_range.is_none());
        assert_eq!(head.headers["cache-control"], "private, no-store");
        assert_eq!(head.headers["vary"], "Authorization");

        let partial = plan_oci_response(
            &object(),
            OciAccess::Public,
            request(DeliveryMethod::Get, Some(b"bytes=2-5")),
        )
        .unwrap();
        assert_eq!(partial.status, 206);
        assert_eq!(partial.headers["content-range"], "bytes 2-5/10");
    }

    #[test]
    fn conditional_and_unsatisfiable_responses_have_no_body() {
        let mut conditional = request(DeliveryMethod::Get, None);
        let tag = format!("\"{}\"", object().digest);
        conditional.if_none_match = Some(tag.as_bytes());
        let not_modified = plan_oci_response(&object(), OciAccess::Public, conditional).unwrap();
        assert_eq!(not_modified.status, 304);
        assert!(not_modified.body_range.is_none());

        let unsatisfied = plan_oci_response(
            &object(),
            OciAccess::Private,
            request(DeliveryMethod::Get, Some(b"bytes=20-30")),
        )
        .unwrap();
        assert_eq!(unsatisfied.status, 416);
        assert_eq!(unsatisfied.headers["content-range"], "bytes */10");
    }

    #[test]
    fn invalid_ranges_are_empty_without_unsigned_underflow() {
        assert_eq!(OciByteRange { start: 2, end: 1 }.len(), 0);
    }
}
