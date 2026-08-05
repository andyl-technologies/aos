//! Transport-neutral HTTP semantics for immutable disk-image delivery.
//!
//! Native Axum and Cloudflare Worker adapters use this module to produce the
//! same status, range, and integrity headers while streaming bytes from their
//! placement-specific storage readers.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use base64::Engine as _;

/// Request method relevant to immutable image delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageMethod {
    /// Return headers without a response body.
    Head,
    /// Return the selected bytes.
    Get,
}

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
    /// HTTP status (`200`, `206`, or `416`).
    pub status: u16,
    /// Response headers shared by native and Worker adapters.
    pub headers: BTreeMap<String, String>,
    /// Storage interval to read; absent for HEAD and unsatisfiable ranges.
    pub body_range: Option<ImageByteRange>,
}

/// Plans a GET or HEAD response for one signed image record.
///
/// Only a single RFC 9110 byte range is accepted. Multipart ranges are
/// rejected so native and Worker deployments retain identical semantics.
///
/// # Errors
///
/// Returns an error for malformed or multiple range syntax. Syntactically
/// valid but unsatisfiable ranges return a `416` plan.
pub fn plan_image_response(
    image: &ImageHttpMetadata,
    method: ImageMethod,
    access: ImageAccess,
    range_header: Option<&str>,
) -> Result<ImageResponsePlan> {
    if image.byte_size == 0 {
        bail!("signed image size must be non-zero");
    }
    validate_download_filename(&image.filename)?;
    let mut headers = immutable_headers(image, access)?;
    let selected = match range_header {
        Some(value) => match parse_range(value, image.byte_size)? {
            Some(range) => {
                headers.insert(
                    "content-range".into(),
                    format!("bytes {}-{}/{}", range.start, range.end, image.byte_size),
                );
                headers.insert("content-length".into(), range.len().to_string());
                return Ok(ImageResponsePlan {
                    status: 206,
                    headers,
                    body_range: (method == ImageMethod::Get).then_some(range),
                });
            }
            None => {
                headers.insert(
                    "content-range".into(),
                    format!("bytes */{}", image.byte_size),
                );
                headers.insert("content-length".into(), "0".into());
                return Ok(ImageResponsePlan {
                    status: 416,
                    headers,
                    body_range: None,
                });
            }
        },
        None => ImageByteRange {
            start: 0,
            end: image.byte_size - 1,
        },
    };
    headers.insert("content-length".into(), image.byte_size.to_string());
    Ok(ImageResponsePlan {
        status: 200,
        headers,
        body_range: (method == ImageMethod::Get).then_some(selected),
    })
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
                ImageAccess::Public => "public, max-age=31536000, immutable",
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

    #[test]
    fn get_head_and_ranges_share_immutable_integrity_headers() {
        let image = image();
        let full =
            plan_image_response(&image, ImageMethod::Get, ImageAccess::Public, None).unwrap();
        assert_eq!(full.status, 200);
        assert_eq!(full.body_range, Some(ImageByteRange { start: 0, end: 9 }));
        assert_eq!(full.headers["content-length"], "10");
        assert_eq!(full.headers["etag"], format!("\"sha256:{}\"", image.sha256));
        assert!(full.headers["repr-digest"].starts_with("sha-256=:"));
        assert!(!full.headers.contains_key("content-digest"));

        let head = plan_image_response(
            &image,
            ImageMethod::Head,
            ImageAccess::Private,
            Some("bytes=2-5"),
        )
        .unwrap();
        assert_eq!(head.status, 206);
        assert_eq!(head.body_range, None);
        assert_eq!(head.headers["content-range"], "bytes 2-5/10");
        assert_eq!(head.headers["content-length"], "4");
        assert_eq!(head.headers["cache-control"], "private, no-store");

        let suffix = plan_image_response(
            &image,
            ImageMethod::Get,
            ImageAccess::Public,
            Some("bytes=-3"),
        )
        .unwrap();
        assert_eq!(suffix.body_range, Some(ImageByteRange { start: 7, end: 9 }));
    }

    #[test]
    fn unsatisfiable_and_multiple_ranges_fail_deterministically() {
        let image = image();
        let unsatisfied = plan_image_response(
            &image,
            ImageMethod::Get,
            ImageAccess::Public,
            Some("bytes=10-"),
        )
        .unwrap();
        assert_eq!(unsatisfied.status, 416);
        assert_eq!(unsatisfied.headers["content-range"], "bytes */10");
        assert!(plan_image_response(
            &image,
            ImageMethod::Get,
            ImageAccess::Public,
            Some("bytes=0-1,3-4"),
        )
        .is_err());
    }
}

fn parse_range(value: &str, size: u64) -> Result<Option<ImageByteRange>> {
    if size == 0 {
        return Ok(None);
    }
    let Some(spec) = value.strip_prefix("bytes=") else {
        bail!("image Range must use the bytes unit");
    };
    if spec.contains(',') {
        bail!("multiple image byte ranges are not supported");
    }
    let Some((start, end)) = spec.split_once('-') else {
        bail!("malformed image byte range");
    };
    if start.is_empty() {
        let suffix: u64 = end
            .parse()
            .map_err(|_| anyhow::anyhow!("malformed suffix range"))?;
        if suffix == 0 {
            return Ok(None);
        }
        let length = suffix.min(size);
        return Ok(Some(ImageByteRange {
            start: size - length,
            end: size - 1,
        }));
    }
    let start: u64 = start
        .parse()
        .map_err(|_| anyhow::anyhow!("malformed range start"))?;
    if start >= size {
        return Ok(None);
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("malformed range end"))?
            .min(size - 1)
    };
    if end < start {
        return Ok(None);
    }
    Ok(Some(ImageByteRange { start, end }))
}
