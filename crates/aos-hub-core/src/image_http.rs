//! Transport-neutral HTTP semantics for immutable disk-image delivery.
//!
//! Native Axum and Cloudflare Worker adapters use this module to produce the
//! same preconditions, status, range, and integrity headers while streaming
//! bytes from their placement-specific storage readers.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use base64::Engine as _;

use crate::delivery_http::{
    evaluate_verified_representation, ContentMutability, DeliveryMethod, EntityTag,
    EntityTagCondition, HttpTimestamp, IfRangeCondition, RequestDecision, RequestPreconditions,
    SingleByteRange, VerifiedRepresentation,
};

/// Authorization visibility of the resolved registry image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageAccess {
    /// Anonymous delivery may be stored by shared caches and CDNs.
    Public,
    /// Delivery required authorization and must remain in private caches.
    Private,
}

/// Signed metadata required to serve one immutable image-related object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHttpMetadata {
    /// Portable attachment filename.
    pub filename: String,
    /// Exact response media type.
    pub media_type: String,
    /// Exact immutable object byte length.
    pub byte_size: u64,
    /// Lowercase hexadecimal SHA-256 of the response bytes.
    pub sha256: String,
}

/// Borrowed client request metadata admitted by signed-image delivery.
#[derive(Debug, Clone, Copy)]
pub struct ImageHttpRequest<'a> {
    /// Exact admitted method.
    pub method: DeliveryMethod,
    /// Raw `Range` field bytes.
    pub range: Option<&'a [u8]>,
    /// Raw `If-Match` field bytes.
    pub if_match: Option<&'a [u8]>,
    /// Raw `If-Unmodified-Since` field bytes.
    pub if_unmodified_since: Option<&'a [u8]>,
    /// Raw `If-None-Match` field bytes.
    pub if_none_match: Option<&'a [u8]>,
    /// Raw `If-Modified-Since` field bytes.
    pub if_modified_since: Option<&'a [u8]>,
    /// Raw `If-Range` field bytes.
    pub if_range: Option<&'a [u8]>,
    /// Current time used only for obsolete HTTP-date year disambiguation.
    pub now: HttpTimestamp,
}

/// Inclusive byte interval selected from one immutable object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageByteRange {
    /// Inclusive first byte.
    pub start: u64,
    /// Inclusive last byte.
    pub end: u64,
}

impl ImageByteRange {
    /// Returns the exact number of bytes in the interval.
    #[must_use]
    pub fn len(self) -> u64 {
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

/// Complete transport-neutral response plan for one image request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageResponsePlan {
    /// HTTP status (`200`, `206`, `304`, `412`, or `416`).
    pub status: u16,
    /// Response headers shared by native and Worker adapters.
    pub headers: BTreeMap<String, String>,
    /// Storage interval to read; absent for HEAD and every terminal response.
    pub body_range: Option<ImageByteRange>,
}

/// Plans a GET or HEAD response for one signed image record.
///
/// Only a single RFC 9110 byte range is accepted. Multipart ranges are
/// rejected so native and Worker deployments retain identical semantics.
///
/// # Errors
///
/// Returns an error for malformed entity-tag conditions or malformed/multiple
/// range syntax. Invalid HTTP dates are ignored as required by HTTP semantics;
/// syntactically valid but unsatisfiable ranges return a `416` plan.
pub fn plan_image_response(
    image: &ImageHttpMetadata,
    access: ImageAccess,
    request: ImageHttpRequest<'_>,
) -> Result<ImageResponsePlan> {
    if image.byte_size == 0 {
        bail!("signed image size must be non-zero");
    }
    validate_download_filename(&image.filename)?;
    let etag = EntityTag::parse(&format!("\"sha256:{}\"", image.sha256))?;
    let representation = VerifiedRepresentation::new(
        image.byte_size,
        etag,
        None,
        image.media_type.clone(),
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
                .map_err(|_| anyhow::anyhow!("image Range is not ASCII"))
                .and_then(|value| SingleByteRange::parse(value).map_err(Into::into))
        })
        .transpose()?;
    // RFC 9110 requires an invalid If-Range to make the Range field ineffective.
    let effective_range = if if_range_valid { range } else { None };
    let decision = evaluate_verified_representation(
        request.method,
        &preconditions,
        effective_range,
        &representation,
    );
    response_plan(image, access, decision)
}

fn response_plan(
    image: &ImageHttpMetadata,
    access: ImageAccess,
    decision: RequestDecision,
) -> Result<ImageResponsePlan> {
    let status = decision.status_code();
    match decision {
        RequestDecision::ServeFull { method } => {
            let mut headers = immutable_headers(image, access)?;
            headers.insert("content-length".into(), image.byte_size.to_string());
            Ok(ImageResponsePlan {
                status,
                headers,
                body_range: (method == DeliveryMethod::Get).then_some(ImageByteRange {
                    start: 0,
                    end: image.byte_size - 1,
                }),
            })
        }
        RequestDecision::ServePartial { range } => {
            let selected = ImageByteRange {
                start: range.start(),
                end: range.end(),
            };
            let mut headers = immutable_headers(image, access)?;
            headers.insert(
                "content-range".into(),
                format!(
                    "bytes {}-{}/{}",
                    selected.start, selected.end, image.byte_size
                ),
            );
            headers.insert("content-length".into(), selected.len().to_string());
            Ok(ImageResponsePlan {
                status,
                headers,
                body_range: Some(selected),
            })
        }
        RequestDecision::NotModified => Ok(ImageResponsePlan {
            status,
            headers: immutable_headers(image, access)?,
            body_range: None,
        }),
        RequestDecision::PreconditionFailed => Ok(ImageResponsePlan {
            status,
            headers: terminal_headers(access),
            body_range: None,
        }),
        RequestDecision::RangeNotSatisfiable { complete_length } => {
            let mut headers = terminal_headers(access);
            headers.insert("accept-ranges".into(), "bytes".into());
            headers.insert("content-range".into(), format!("bytes */{complete_length}"));
            headers.insert("content-length".into(), "0".into());
            Ok(ImageResponsePlan {
                status,
                headers,
                body_range: None,
            })
        }
        RequestDecision::NotFound => {
            bail!("image response evaluation unexpectedly lost a present representation")
        }
    }
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

fn terminal_headers(access: ImageAccess) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "cache-control".into(),
            match access {
                ImageAccess::Public => "no-store",
                ImageAccess::Private => "private, no-store",
            }
            .into(),
        ),
        ("content-length".into(), "0".into()),
        ("x-content-type-options".into(), "nosniff".into()),
    ])
}

fn immutable_headers(
    image: &ImageHttpMetadata,
    access: ImageAccess,
) -> Result<BTreeMap<String, String>> {
    if image.sha256.len() != 64
        || !image
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid image SHA-256");
    }
    let digest =
        hex::decode(&image.sha256).map_err(|_| anyhow::anyhow!("invalid image SHA-256"))?;
    Ok(BTreeMap::from([
        ("accept-ranges".into(), "bytes".into()),
        (
            "cache-control".into(),
            match access {
                ImageAccess::Public => crate::delivery_http::PUBLIC_IMMUTABLE_CACHE_CONTROL,
                ImageAccess::Private => "private, no-store",
            }
            .into(),
        ),
        ("content-type".into(), image.media_type.clone()),
        (
            "content-disposition".into(),
            format!("attachment; filename=\"{}\"", image.filename),
        ),
        ("etag".into(), format!("\"sha256:{}\"", image.sha256)),
        (
            "repr-digest".into(),
            format!(
                "sha-256=:{}:",
                base64::engine::general_purpose::STANDARD.encode(digest)
            ),
        ),
        ("x-aos-sha256".into(), image.sha256.clone()),
        ("x-content-type-options".into(), "nosniff".into()),
    ]))
}

fn validate_download_filename(filename: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > 128
        || !filename.is_ascii()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !filename
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || filename.contains("..")
    {
        bail!("image filename is unsafe for Content-Disposition");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> ImageHttpMetadata {
        ImageHttpMetadata {
            filename: "aos-server.qcow2".into(),
            media_type: "application/vnd.aos.disk-image.qcow2".into(),
            byte_size: 10,
            sha256: "a".repeat(64),
        }
    }

    fn request(method: DeliveryMethod, range: Option<&[u8]>) -> ImageHttpRequest<'_> {
        ImageHttpRequest {
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
    fn get_head_and_ranges_share_immutable_integrity_headers() {
        let image = image();
        let full = plan_image_response(
            &image,
            ImageAccess::Public,
            request(DeliveryMethod::Get, None),
        )
        .unwrap();
        assert_eq!(full.status, 200);
        assert_eq!(full.body_range, Some(ImageByteRange { start: 0, end: 9 }));
        assert_eq!(full.headers["content-length"], "10");
        assert_eq!(full.headers["etag"], format!("\"sha256:{}\"", image.sha256));
        assert!(full.headers["repr-digest"].starts_with("sha-256=:"));
        assert!(!full.headers.contains_key("content-digest"));

        let head = plan_image_response(
            &image,
            ImageAccess::Private,
            request(DeliveryMethod::Head, Some(b"bytes=2-5")),
        )
        .unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.body_range, None);
        assert!(!head.headers.contains_key("content-range"));
        assert_eq!(head.headers["content-length"], "10");
        assert_eq!(head.headers["cache-control"], "private, no-store");

        let suffix = plan_image_response(
            &image,
            ImageAccess::Public,
            request(DeliveryMethod::Get, Some(b"bytes=-3")),
        )
        .unwrap();
        assert_eq!(suffix.body_range, Some(ImageByteRange { start: 7, end: 9 }));
    }

    #[test]
    fn entity_tag_preconditions_and_if_range_use_the_shared_kernel() {
        let image = image();
        let current = format!("\"sha256:{}\"", image.sha256);

        let mut not_modified = request(DeliveryMethod::Get, None);
        not_modified.if_none_match = Some(current.as_bytes());
        let not_modified = plan_image_response(&image, ImageAccess::Public, not_modified).unwrap();
        assert_eq!(not_modified.status, 304);
        assert_eq!(not_modified.body_range, None);

        let mut failed = request(DeliveryMethod::Get, None);
        failed.if_match = Some(b"\"different\"");
        let failed = plan_image_response(&image, ImageAccess::Public, failed).unwrap();
        assert_eq!(failed.status, 412);
        assert_eq!(failed.headers["cache-control"], "no-store");

        let mut matching_range = request(DeliveryMethod::Get, Some(b"bytes=2-5"));
        matching_range.if_range = Some(current.as_bytes());
        let matching_range =
            plan_image_response(&image, ImageAccess::Public, matching_range).unwrap();
        assert_eq!(matching_range.status, 206);

        let mut stale_range = request(DeliveryMethod::Get, Some(b"bytes=2-5"));
        stale_range.if_range = Some(b"\"different\"");
        let stale_range = plan_image_response(&image, ImageAccess::Public, stale_range).unwrap();
        assert_eq!(stale_range.status, 200);
        assert_eq!(
            stale_range.body_range,
            Some(ImageByteRange { start: 0, end: 9 })
        );

        let mut malformed_if_range = request(DeliveryMethod::Get, Some(b"bytes=2-5"));
        malformed_if_range.if_range = Some(b"not-a-validator");
        let malformed_if_range =
            plan_image_response(&image, ImageAccess::Public, malformed_if_range).unwrap();
        assert_eq!(malformed_if_range.status, 200);
    }

    #[test]
    fn unsatisfiable_and_multiple_ranges_fail_deterministically() {
        let image = image();
        let unsatisfied = plan_image_response(
            &image,
            ImageAccess::Public,
            request(DeliveryMethod::Get, Some(b"bytes=10-")),
        )
        .unwrap();
        assert_eq!(unsatisfied.status, 416);
        assert_eq!(unsatisfied.headers["content-range"], "bytes */10");
        assert!(plan_image_response(
            &image,
            ImageAccess::Public,
            request(DeliveryMethod::Get, Some(b"bytes=0-1,3-4")),
        )
        .is_err());
    }
}
