//! Typed bounded direct UploadPart, server copy and ListParts capabilities.

use anyhow::{ensure, Result};

use crate::direct_upload::{
    valid_direct_digest, DirectPart, DirectRequiredHeader, MAX_DIRECT_GRANT_URL_BYTES,
    MAX_DIRECT_OBJECT_BYTES, MAX_DIRECT_PARTS, MAX_DIRECT_PART_BYTES,
};

use super::{presign_url_with_headers, uri_encode, PresignParams};

/// Exact signed provider request; bearer URL and header values are Debug-redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectSignedProviderRequest {
    /// Exact original request URL; clients must preserve these bytes.
    pub url: String,
    /// Explicit required headers, excluding automatically supplied Host.
    pub required_headers: Vec<DirectRequiredHeader>,
}

impl std::fmt::Debug for DirectSignedProviderRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectSignedProviderRequest")
            .field("url", &"[REDACTED]")
            .field("required_headers", &"[REDACTED]")
            .finish()
    }
}

/// Signs one exact private-stage UploadPart with length and provider checksum.
///
/// The caller supplies its reviewed lifetime ceiling; this signer qualifies
/// neither provider policy nor grant-tail settlement. No unrelated headers,
/// operations or query fields can be selected through this API.
///
/// # Errors
/// Returns a value-free error for invalid coordinates, part declarations,
/// missing checksum, excessive lifetime or URL size, or signing failure.
pub fn presign_direct_upload_part(
    p: &PresignParams<'_>,
    upload_id: &str,
    part: &DirectPart,
    maximum_expires_secs: u32,
) -> Result<DirectSignedProviderRequest> {
    validate(p, Some(upload_id), maximum_expires_secs)?;
    ensure!(
        (1..=MAX_DIRECT_PARTS).contains(&part.part_number)
            && part.byte_size.get() > 0
            && part.byte_size.get() <= MAX_DIRECT_PART_BYTES
            && part
                .offset
                .get()
                .checked_add(part.byte_size.get())
                .is_some_and(|end| end <= MAX_DIRECT_OBJECT_BYTES),
        "invalid direct provider part geometry"
    );
    ensure!(
        valid_direct_digest(&part.sha256),
        "invalid direct provider part digest"
    );
    let checksum = part
        .checksum
        .decoded()
        .map_err(|_| anyhow::anyhow!("invalid direct provider checksum"))?;
    ensure!(
        part.checksum.algorithm != crate::direct_upload::DirectChecksumAlgorithm::Sha256
            || hex::encode(checksum) == part.sha256,
        "direct provider checksum mismatch"
    );
    let headers = [
        ("content-length", part.byte_size.get().to_string()),
        (part.checksum.header_name(), part.checksum.value.clone()),
    ];
    signed(
        p,
        "PUT",
        &[
            ("partNumber", part.part_number.to_string()),
            ("uploadId", upload_id.to_owned()),
        ],
        &headers,
    )
}

/// Immutable source coordinates for one server-owned UploadPartCopy operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPartCopySource<'a> {
    /// Exact admitted source bucket, never an arbitrary URL.
    pub bucket: &'a str,
    /// Exact completed private-stage key.
    pub full_key: &'a str,
    /// Inclusive source start offset.
    pub first_byte: u64,
    /// Inclusive source end offset.
    pub last_byte: u64,
}

/// Signs a server-only exact UploadPartCopy with source and range headers.
///
/// This API has no unsupported conditional source headers. Its caller must
/// establish an immutable positively closed stage under the physical guard;
/// an UploadId, HEAD or expired capability alone does not establish that fact.
///
/// # Errors
/// Returns a value-free error for malformed source/destination, range, lifetime,
/// encoded URL bounds or signing failure.
pub fn presign_direct_upload_part_copy(
    p: &PresignParams<'_>,
    upload_id: &str,
    part_number: u32,
    source: &DirectPartCopySource<'_>,
    maximum_expires_secs: u32,
) -> Result<DirectSignedProviderRequest> {
    validate(p, Some(upload_id), maximum_expires_secs)?;
    ensure!(
        (1..=MAX_DIRECT_PARTS).contains(&part_number)
            && bucket(source.bucket)
            && key(source.full_key)
            && source.first_byte <= source.last_byte
            && source.last_byte < MAX_DIRECT_OBJECT_BYTES
            && source
                .last_byte
                .checked_sub(source.first_byte)
                .and_then(|n| n.checked_add(1))
                .is_some_and(|n| n <= MAX_DIRECT_PART_BYTES),
        "invalid direct copy source"
    );
    let headers = [
        (
            "x-amz-copy-source",
            uri_encode(&format!("/{}/{}", source.bucket, source.full_key), false),
        ),
        (
            "x-amz-copy-source-range",
            format!("bytes={}-{}", source.first_byte, source.last_byte),
        ),
    ];
    signed(
        p,
        "PUT",
        &[
            ("partNumber", part_number.to_string()),
            ("uploadId", upload_id.to_owned()),
        ],
        &headers,
    )
}

/// Signs one bounded exact ListParts page owned by the server.
///
/// # Errors
/// Returns an error for invalid upload ID, marker, page size or lifetime.
pub fn presign_direct_list_parts(
    p: &PresignParams<'_>,
    upload_id: &str,
    after_part: u32,
    maximum_parts: u32,
    maximum_expires_secs: u32,
) -> Result<DirectSignedProviderRequest> {
    validate(p, Some(upload_id), maximum_expires_secs)?;
    ensure!(
        after_part < MAX_DIRECT_PARTS && (1..=1000).contains(&maximum_parts),
        "invalid direct ListParts page"
    );
    signed(
        p,
        "GET",
        &[
            ("uploadId", upload_id.to_owned()),
            ("part-number-marker", after_part.to_string()),
            ("max-parts", maximum_parts.to_string()),
        ],
        &[],
    )
}

/// Signs server-owned staging creation with its exact checksum negotiation.
///
/// SHA-256 part checksums require an explicitly selected SHA256 multipart
/// algorithm; Content-MD5 parts use the provider's normal multipart creation.
/// This does not qualify either checksum algorithm on a provider deployment.
///
/// # Errors
/// Returns an error for invalid coordinates, algorithm lifetime or signing.
pub fn presign_direct_create_multipart(
    p: &PresignParams<'_>,
    checksum: crate::direct_upload::DirectChecksumAlgorithm,
    maximum_expires_secs: u32,
) -> Result<DirectSignedProviderRequest> {
    validate(p, None, maximum_expires_secs)?;
    let headers = match checksum {
        crate::direct_upload::DirectChecksumAlgorithm::Md5 => Vec::new(),
        crate::direct_upload::DirectChecksumAlgorithm::Sha256 => {
            vec![("x-amz-checksum-algorithm", "SHA256".to_owned())]
        }
    };
    signed(p, "POST", &[("uploads", String::new())], &headers)
}

fn validate(
    p: &PresignParams<'_>,
    upload_id: Option<&str>,
    maximum_expires_secs: u32,
) -> Result<()> {
    ensure!(
        p.scheme == "https"
            && p.service == "s3"
            && !p.access_key.is_empty()
            && p.access_key.len() <= 255
            && !p.access_key.chars().any(|c| c.is_control() || c == '/')
            && !p.secret_key.is_empty()
            && !p.region.is_empty()
            && p.region.len() <= 64
            && p.region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && p.path.starts_with('/')
            && key(&p.path[1..])
            && upload_id.is_none_or(|id| !id.is_empty()
                && id.len() <= 2048
                && !id.chars().any(char::is_control))
            && (1..=604800).contains(&maximum_expires_secs)
            && p.expires_secs > 0
            && p.expires_secs <= maximum_expires_secs,
        "invalid direct provider signing inputs"
    );
    Ok(())
}

fn signed(
    p: &PresignParams<'_>,
    method: &str,
    query: &[(&str, String)],
    headers: &[(&str, String)],
) -> Result<DirectSignedProviderRequest> {
    let url = presign_url_with_headers(method, p, query, headers)
        .map_err(|_| anyhow::anyhow!("direct provider signing failed"))?;
    ensure!(
        url.len() <= MAX_DIRECT_GRANT_URL_BYTES,
        "direct provider URL exceeds limit"
    );
    Ok(DirectSignedProviderRequest {
        url,
        required_headers: headers
            .iter()
            .map(|(name, value)| DirectRequiredHeader {
                name: (*name).to_owned(),
                value: value.clone(),
            })
            .collect(),
    })
}

fn key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.trim() == value
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
}

fn bucket(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        && !value.contains("..")
}

#[cfg(test)]
mod tests;
