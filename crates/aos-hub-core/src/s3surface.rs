//! Resolving an S3-compatible binding into per-object signed URLs.
//!
//! A binding of kind `s3` or `r2` points a registry's (or cache's)
//! surface at an **external, S3-compatible object store** — Amazon S3, Cloudflare
//! R2 (via its S3 API), MinIO, Backblaze B2, and so on. The hub never holds the
//! bytes; it reaches the origin over plain HTTP using short-lived presigned URLs
//! that the shared [`sigv4`](crate::sigv4) signer mints. Because the signing is
//! pure (HMAC-SHA256 + SHA-256, no `ring`/C) and the only per-runtime part is the
//! HTTP request itself, the native hub (`reqwest`) and the Cloudflare Worker
//! (`worker::Fetch`) drive the *identical* signed-URL code path.
//!
//! # Binding wire form
//!
//! An S3/R2 binding row carries a typed origin and access policy:
//!
//! ```text
//! kind            = "s3" | "r2"
//! object_bucket      = bucket name
//! object_prefix      = binding-owned prefix within the bucket
//! access_mode        = "private" | "public"
//! endpoint_scheme    = "https"
//! endpoint_host_*    = canonical typed DNS/IP host
//! endpoint_port      = explicit origin port
//! ```
//!
//! The object key for a logical surface path `P` under a resource whose prefix is
//! `RP` is `{bucket}/{binding-prefix}/{RP}/{P}`; path-style addressing is used,
//! which both R2's S3 API and AWS S3 accept.
//!
//! # Access modes
//!
//! - **private** — the caller supplies a purpose- and generation-resolved
//!   credential capability, and every request is a SigV4-presigned URL.
//! - **public** — a credential-less read-only mirror: reads are a direct
//!   unsigned `GET` of the public origin URL; writes are refused (there is
//!   nothing to sign with).

use crate::db::BindingRecord;

/// Maximum in-memory S3 object read used by metadata/indexing operations.
/// Large machine objects use [`crate::fetch::SurfaceFetch::fetch_stream`].
pub const MAX_S3_BUFFERED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum XML body accepted from one ListObjectsV2 page.
pub const MAX_S3_LIST_PAGE_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum one S3 listing response may occupy in a Worker isolate.
pub const WORKER_MAX_S3_LIST_PAGE_BYTES: u64 = 512 * 1024;
/// Maximum pages accepted for one complete S3 inventory walk.
pub const MAX_S3_LIST_PAGES: usize = 10_000;
/// Maximum keys accepted for one complete S3 inventory walk.
pub const MAX_S3_LIST_KEYS: usize = 1_000_000;
/// Maximum aggregate XML bytes accepted for one complete S3 inventory walk.
pub const MAX_S3_LIST_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// How long a minted presigned URL stays valid. The hub uses each URL
/// immediately for a single proxied request, so a short window is ample and
/// bounds the blast radius if one were ever logged.
const PRESIGN_TTL_SECS: u32 = 300;

/// An HTTP method a surface operation maps to.
///
/// Each is signed into the presigned URL (the method is part of the SigV4
/// canonical request), so a `Get` URL cannot be replayed as a `Put`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Read an object's bytes.
    Get,
    /// Read an object's metadata (size/existence) without its body.
    Head,
    /// Write (create or overwrite) an object.
    Put,
    /// Remove an object.
    Delete,
}

impl Method {
    /// The HTTP method token for transport (`"GET"`, `"HEAD"`, `"PUT"`,
    /// `"DELETE"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }

    /// Whether this method mutates the object store (`Put`/`Delete`).
    ///
    /// A public (credential-less) binding refuses mutating methods.
    fn is_write(self) -> bool {
        matches!(self, Method::Put | Method::Delete)
    }
}

/// SigV4 credentials for a private S3/R2 origin.
struct S3Creds {
    region: String,
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

/// A resolved S3-compatible origin scoped to one resource's key prefix.
///
/// Built by [`S3Surface::from_binding`] from a binding row and the per-resource
/// sub-prefix; [`S3Surface::object_url`] then mints a signed (or, for a public
/// binding, direct) URL for one object operation.
pub struct S3Surface {
    /// URL scheme of the origin (`https`, or `http` for a local test endpoint).
    scheme: String,
    /// Origin host (URL authority), e.g. `bucket.s3.amazonaws.com` or the R2
    /// account host.
    host: String,
    /// The object-key prefix this surface is scoped to: `bucket[/sub]/RP` with no
    /// leading or trailing slash. A logical path is appended to it.
    key_prefix: String,
    /// SigV4 credentials, or `None` for a public read-only binding.
    creds: Option<S3Creds>,
}

impl S3Surface {
    /// Resolve a binding into an S3 surface scoped to `sub_prefix`, or `Ok(None)`
    /// when the binding is not an S3-compatible object store.
    ///
    /// `sub_prefix` is the per-resource key segment. For a private binding,
    /// `resolved_credential` is an already-authorized
    /// `access_key:secret_key:region` capability; the secret may contain `:`.
    ///
    /// # Errors
    ///
    /// Returns an error for an incomplete typed origin or a missing/malformed
    /// private credential capability. A non-object-store kind yields `Ok(None)`.
    pub fn from_binding(
        binding: &BindingRecord,
        sub_prefix: &str,
        resolved_credential: Option<&str>,
    ) -> Result<Option<S3Surface>> {
        match binding.kind.as_str() {
            "s3" | "r2" => {}
            _ => return Ok(None),
        }
        let scheme = binding
            .endpoint_scheme
            .as_deref()
            .context("object-store binding has no typed endpoint scheme")?;
        let host_bytes = binding
            .endpoint_host_bytes
            .as_deref()
            .context("object-store binding has no typed endpoint host")?;
        let host = match binding.endpoint_host_kind.as_deref() {
            Some("dns") => std::str::from_utf8(host_bytes)
                .context("object-store DNS host is not UTF-8")?
                .to_string(),
            Some("ipv4") if host_bytes.len() == 4 => {
                std::net::Ipv4Addr::new(host_bytes[0], host_bytes[1], host_bytes[2], host_bytes[3])
                    .to_string()
            }
            Some("ipv6") if host_bytes.len() == 16 => {
                let bytes: [u8; 16] = host_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid IPv6 endpoint bytes"))?;
                format!("[{}]", std::net::Ipv6Addr::from(bytes))
            }
            _ => bail!("object-store binding has an invalid typed endpoint host"),
        };
        let host = match binding.endpoint_port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        if host.is_empty() {
            bail!("binding '{}' has an empty endpoint host", binding.name);
        }

        let bucket = binding
            .object_bucket
            .as_deref()
            .context("object-store binding has no bucket")?
            .trim_matches('/');
        let binding_prefix = binding
            .object_prefix
            .as_deref()
            .unwrap_or("")
            .trim_matches('/');
        let sub = sub_prefix.trim_matches('/');
        let key_prefix = [bucket, binding_prefix, sub]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/");

        let creds = match binding.access_mode.as_deref() {
            Some("private") => {
                let plaintext = resolved_credential
                    .context("private binding requires a resolved credential-version capability")?;
                let (access_key, rest) = plaintext
                    .split_once(':')
                    .context("storage credential must be access_key:secret_key:region")?;
                let (secret_key, region) = rest
                    .rsplit_once(':')
                    .context("storage credential must be access_key:secret_key:region")?;
                anyhow::ensure!(
                    !access_key.is_empty() && !secret_key.is_empty() && !region.is_empty(),
                    "storage credential fields must not be empty"
                );
                Some(S3Creds {
                    region: region.to_string(),
                    access_key: Zeroizing::new(access_key.to_string()),
                    secret_key: Zeroizing::new(secret_key.to_string()),
                })
            }
            Some("public") => {
                anyhow::ensure!(
                    resolved_credential.is_none(),
                    "public bindings must not resolve credentials"
                );
                None
            }
            _ => bail!("object-store binding has invalid access mode"),
        };

        Ok(Some(S3Surface {
            scheme: scheme.to_string(),
            host,
            key_prefix,
            creds,
        }))
    }

    /// Whether this surface can be written to (a private, credentialed binding).
    pub fn is_writable(&self) -> bool {
        self.creds.is_some()
    }

    /// A short human description of the origin, for logs and error messages
    /// (never includes the secret key).
    pub fn describe(&self) -> String {
        format!("s3://{}/{}", self.host, self.key_prefix)
    }

    /// Mint a URL for `method` on the object at logical surface `path`, signed
    /// when the binding is private.
    ///
    /// `now` is the current Unix time in seconds (the signing timestamp); the URL
    /// is valid for [`PRESIGN_TTL_SECS`]. A public binding returns an unsigned
    /// direct `GET` URL and refuses mutating methods.
    ///
    /// # Errors
    ///
    /// Returns an error when `path` is not a safe relative surface path (absolute,
    /// or containing `..`/`.`/empty/control segments — which on a path-normalizing
    /// origin could escape this resource's key prefix into another tenant's keys
    /// in a shared bucket), when a mutating method is requested on a public
    /// (read-only) binding, or when the SigV4 signer rejects the inputs (a
    /// malformed host or date).
    pub fn object_url(&self, method: Method, path: &str, now: i64) -> Result<String> {
        // Guard the logical path BEFORE composing the object key, so a crafted
        // `..` can never sign (or directly request) an object outside this
        // resource's prefix — the same containment the filesystem and R2 writers
        // enforce, applied here before the key reaches the origin.
        crate::url_guard::validate_http_surface_path(path)?;
        // Avoid a doubled slash when `key_prefix` is empty (a binding whose root
        // and sub-prefix are both empty) or carries a trailing slash — an
        // `s3://host/bucket//key` URL is rejected (R2 returns 400).
        let key = if self.key_prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}/{}", self.key_prefix.trim_end_matches('/'), path)
        };
        let object_path = format!("/{key}");
        match &self.creds {
            Some(creds) => {
                let params = crate::sigv4::PresignParams {
                    access_key: &creds.access_key,
                    secret_key: &creds.secret_key,
                    region: &creds.region,
                    service: "s3",
                    scheme: &self.scheme,
                    host: &self.host,
                    path: &object_path,
                    expires_secs: PRESIGN_TTL_SECS,
                    amz_date: &crate::sigv4::amz_date_from_unix(now),
                };
                match method {
                    Method::Get => crate::sigv4::presign_get_url(&params),
                    Method::Head => crate::sigv4::presign_head_url(&params),
                    Method::Put => crate::sigv4::presign_put_url(&params),
                    Method::Delete => crate::sigv4::presign_delete_url(&params),
                }
            }
            None => {
                if method.is_write() {
                    bail!("public binding is read-only");
                }
                // A public origin needs no signature; the object is world-readable
                // at its direct URL.
                Ok(format!("{}://{}{}", self.scheme, self.host, object_path))
            }
        }
    }

    /// Mints the four presigned URLs used by the S3 multipart protocol.
    ///
    /// `operation` is `create`, `part`, `complete`, or `abort`. Part requires
    /// both `upload_id` and a positive `part_number`; complete/abort require an
    /// upload id; create requires neither.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, public binding, invalid operation
    /// arguments, or SigV4 signing failure.
    pub fn multipart_url(
        &self,
        operation: &str,
        path: &str,
        upload_id: Option<&str>,
        part_number: Option<u32>,
        now: i64,
    ) -> Result<String> {
        crate::url_guard::validate_http_surface_path(path)?;
        let creds = self.creds.as_ref().context("public binding is read-only")?;
        let key = if self.key_prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}/{}", self.key_prefix.trim_end_matches('/'), path)
        };
        let object_path = format!("/{key}");
        let amz_date = crate::sigv4::amz_date_from_unix(now);
        let params = crate::sigv4::PresignParams {
            access_key: &creds.access_key,
            secret_key: &creds.secret_key,
            region: &creds.region,
            service: "s3",
            scheme: &self.scheme,
            host: &self.host,
            path: &object_path,
            expires_secs: PRESIGN_TTL_SECS,
            amz_date: &amz_date,
        };
        let (method, query) = match (operation, upload_id, part_number) {
            ("create", None, None) => ("POST", vec![("uploads", String::new())]),
            ("part", Some(id), Some(number)) if number > 0 && !id.is_empty() => (
                "PUT",
                vec![
                    ("partNumber", number.to_string()),
                    ("uploadId", id.to_string()),
                ],
            ),
            ("complete", Some(id), None) if !id.is_empty() => {
                ("POST", vec![("uploadId", id.to_string())])
            }
            ("abort", Some(id), None) if !id.is_empty() => {
                ("DELETE", vec![("uploadId", id.to_string())])
            }
            _ => bail!("invalid S3 multipart operation arguments"),
        };
        crate::sigv4::presign_multipart_url(&params, method, &query)
    }

    /// Mints a bounded ListMultipartUploads URL for one exact probe object key.
    ///
    /// The exact key prefix and `max-uploads=1000` make recovery closed and
    /// bounded. A truncated response is rejected by
    /// [`parse_exact_multipart_uploads`](Self::parse_exact_multipart_uploads)
    /// rather than leaving an unenumerated upload behind.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, public binding, or signing failure.
    pub fn list_multipart_uploads_url(&self, path: &str, now: i64) -> Result<String> {
        crate::url_guard::validate_http_surface_path(path)?;
        let creds = self
            .creds
            .as_ref()
            .context("public binding cannot list multipart uploads")?;
        let key = if self.key_prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}/{}", self.key_prefix.trim_end_matches('/'), path)
        };
        let (bucket, _) = self.bucket_split();
        let bucket_path = format!("/{bucket}");
        let amz_date = crate::sigv4::amz_date_from_unix(now);
        let params = crate::sigv4::PresignParams {
            access_key: &creds.access_key,
            secret_key: &creds.secret_key,
            region: &creds.region,
            service: "s3",
            scheme: &self.scheme,
            host: &self.host,
            path: &bucket_path,
            expires_secs: PRESIGN_TTL_SECS,
            amz_date: &amz_date,
        };
        crate::sigv4::presign_multipart_url(
            &params,
            "GET",
            &[
                ("uploads", String::new()),
                ("prefix", key),
                ("max-uploads", "1000".to_string()),
            ],
        )
    }

    /// Parses and validates incomplete multipart uploads for one exact key.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/truncated XML, more than 1000 uploads,
    /// or any upload whose key is not exactly the requested probe identity.
    pub fn parse_exact_multipart_uploads(&self, path: &str, xml: &str) -> Result<Vec<String>> {
        crate::url_guard::validate_http_surface_path(path)?;
        anyhow::ensure!(
            xml.matches("<ListMultipartUploadsResult").count() == 1
                && xml.matches("</ListMultipartUploadsResult>").count() == 1
                && xml.trim_end().ends_with("</ListMultipartUploadsResult>"),
            "multipart upload listing is incomplete"
        );
        anyhow::ensure!(
            xml.matches("<Upload>").count() == xml.matches("</Upload>").count()
                && xml.matches("<Upload>").count() <= 1000,
            "multipart upload listing has invalid upload cardinality"
        );
        let truncated = extract_unique_tag(xml, "IsTruncated")?
            .context("multipart upload listing has no IsTruncated")?;
        anyhow::ensure!(
            truncated.trim() == "false",
            "multipart upload listing is truncated"
        );
        let expected_key = if self.key_prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}/{}", self.key_prefix.trim_end_matches('/'), path)
        };
        let mut uploads = Vec::new();
        let mut rest = xml;
        while let Some(start) = rest.find("<Upload>") {
            let after = &rest[start + "<Upload>".len()..];
            let end = after
                .find("</Upload>")
                .context("multipart upload listing has an unterminated Upload")?;
            let upload = &after[..end];
            let key = extract_unique_tag(upload, "Key")?.context("multipart upload has no Key")?;
            let upload_id = extract_unique_tag(upload, "UploadId")?
                .context("multipart upload has no UploadId")?;
            anyhow::ensure!(
                xml_unescape(key.trim())? == expected_key,
                "multipart upload listing returned a foreign key"
            );
            let upload_id = xml_unescape(upload_id.trim())?;
            anyhow::ensure!(
                !upload_id.is_empty()
                    && upload_id.len() <= 2048
                    && !upload_id.chars().any(char::is_control),
                "multipart upload listing returned an invalid upload id"
            );
            uploads.push(upload_id);
            anyhow::ensure!(
                uploads.len() <= 1000,
                "multipart upload listing exceeds cap"
            );
            rest = &after[end + "</Upload>".len()..];
        }
        Ok(uploads)
    }

    /// Split `key_prefix` (`bucket[/sub]/RP`) into `(bucket, in-bucket prefix)`.
    ///
    /// The bucket is the canonical-URI path for a bucket-level S3 op; the
    /// in-bucket prefix is what `ListObjectsV2`'s `prefix` is relative to.
    fn bucket_split(&self) -> (&str, &str) {
        match self.key_prefix.split_once('/') {
            Some((bucket, rest)) => (bucket, rest),
            None => (self.key_prefix.as_str(), ""),
        }
    }

    /// Build a presigned `ListObjectsV2` URL scoped to this surface's prefix.
    ///
    /// A `GET` on `/{bucket}` with `prefix` = this surface's in-bucket prefix,
    /// optionally continuing from `continuation` and returning at most
    /// `max_keys` keys. The walk that storage
    /// migration / re-scan run when a surface lives on an external binding pages
    /// through these. Credential-less (public) bindings cannot be listed.
    ///
    /// # Errors
    ///
    /// [`bail`]s for a public binding (no anonymous list); otherwise propagates
    /// a signing error.
    pub fn list_url(
        &self,
        continuation: Option<&str>,
        max_keys: usize,
        now: i64,
    ) -> Result<String> {
        let Some(creds) = &self.creds else {
            bail!("cannot list a public (credential-less) binding");
        };
        let (bucket, in_bucket) = self.bucket_split();
        let list_prefix = if in_bucket.is_empty() {
            String::new()
        } else {
            format!("{in_bucket}/")
        };
        let bucket_path = format!("/{bucket}");
        let params = crate::sigv4::PresignParams {
            access_key: &creds.access_key,
            secret_key: &creds.secret_key,
            region: &creds.region,
            service: "s3",
            scheme: &self.scheme,
            host: &self.host,
            path: &bucket_path,
            expires_secs: PRESIGN_TTL_SECS,
            amz_date: &crate::sigv4::amz_date_from_unix(now),
        };
        crate::sigv4::presign_list_url(&params, &list_prefix, continuation, max_keys)
    }

    /// Recover the surface-relative path from a `ListObjectsV2` `<Key>`.
    ///
    /// `<Key>` values are bucket-relative (`{in-bucket prefix}/{path}`); this
    /// strips the in-bucket prefix to the logical path the surface ports speak,
    /// or `None` when the key is not under this surface's prefix.
    #[must_use]
    pub fn relative_from_key(&self, key: &str) -> Option<String> {
        let (_, in_bucket) = self.bucket_split();
        crate::keymap::relative_key(in_bucket, key)
    }
}

/// Parses an S3 `ListObjectsV2` XML response into keys and pagination state.
///
/// The returned boolean is the authoritative `IsTruncated` value. A truncated
/// page must carry one non-empty continuation token, while a terminal page
/// must not carry one. The parser deliberately recognizes only the fixed S3
/// response fields needed by inventory so malformed or partial XML cannot be
/// mistaken for a complete listing on the wasm Worker.
///
/// # Errors
///
/// Returns an error when the document is incomplete, a required pagination
/// field is missing or duplicated, a key is unterminated, or an XML entity is
/// malformed.
pub fn parse_list_objects_v2(xml: &str) -> Result<(Vec<String>, Option<String>, bool)> {
    let mut keys = Vec::new();
    let (next, truncated) = visit_list_objects_v2(xml, |key| {
        keys.push(key);
        Ok(())
    })?;
    Ok((keys, next, truncated))
}

/// Visits each key in an S3 `ListObjectsV2` XML response while parsing it.
///
/// This adapter-oriented form avoids constructing a second page-sized key
/// vector before an inventory sink can enforce its aggregate object and byte
/// limits. Pagination has the same strict validation as
/// [`parse_list_objects_v2`].
///
/// # Errors
///
/// Returns an error when the document or pagination fields are malformed, an
/// XML entity cannot be decoded, or `visit` rejects a decoded key.
pub fn visit_list_objects_v2(
    xml: &str,
    mut visit: impl FnMut(String) -> Result<()>,
) -> Result<(Option<String>, bool)> {
    let root_close = "</ListBucketResult>";
    anyhow::ensure!(
        xml.matches("<ListBucketResult").count() == 1 && xml.matches(root_close).count() == 1,
        "S3 list response is not a complete ListBucketResult document"
    );
    let root_end = xml
        .find(root_close)
        .context("S3 list response is missing its root close")?
        + root_close.len();
    anyhow::ensure!(
        xml[root_end..].trim().is_empty(),
        "S3 list response has data after its root element"
    );
    let mut rest = xml;
    while let Some(start) = rest.find("<Key>") {
        let after = &rest[start + "<Key>".len()..];
        let end = after
            .find("</Key>")
            .context("S3 list response contains an unterminated Key")?;
        visit(xml_unescape(&after[..end])?)?;
        rest = &after[end + "</Key>".len()..];
    }
    anyhow::ensure!(
        xml.matches("<Key>").count() == xml.matches("</Key>").count(),
        "S3 list response contains mismatched Key elements"
    );
    let truncated = match extract_unique_tag(xml, "IsTruncated")?
        .context("S3 list response is missing IsTruncated")?
        .trim()
    {
        "true" => true,
        "false" => false,
        _ => anyhow::bail!("S3 list response has invalid IsTruncated"),
    };
    let next = extract_unique_tag(xml, "NextContinuationToken")?
        .map(|value| xml_unescape(value.trim()))
        .transpose()?;
    if truncated {
        anyhow::ensure!(
            next.as_deref().is_some_and(|token| !token.is_empty()),
            "truncated S3 list response has no continuation token"
        );
    } else {
        anyhow::ensure!(
            next.is_none(),
            "terminal S3 list response unexpectedly has a continuation token"
        );
    }
    Ok((next, truncated))
}

/// Parses the opaque upload id from a bounded CreateMultipartUpload response.
///
/// # Errors
///
/// Returns an error when the response does not contain exactly one non-empty,
/// well-formed `UploadId` element.
pub fn parse_multipart_upload_id(xml: &str) -> Result<String> {
    let upload_id =
        extract_unique_tag(xml, "UploadId")?.context("S3 multipart response has no UploadId")?;
    let upload_id = xml_unescape(upload_id.trim())?;
    anyhow::ensure!(
        !upload_id.is_empty()
            && upload_id.len() <= 2048
            && !upload_id.chars().any(char::is_control),
        "S3 multipart response has an invalid UploadId"
    );
    Ok(upload_id)
}

/// Renders the bounded CompleteMultipartUpload XML request body.
///
/// # Errors
///
/// Returns an error for an empty, non-contiguous part set or unsafe ETag.
pub fn complete_multipart_xml(parts: &[crate::surface_write::PartTag]) -> Result<String> {
    anyhow::ensure!(
        !parts.is_empty() && parts.len() <= 10_000,
        "invalid multipart part count"
    );
    let mut ordered = parts.to_vec();
    ordered.sort_by_key(|part| part.part_number);
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (index, part) in ordered.iter().enumerate() {
        anyhow::ensure!(
            part.part_number == u32::try_from(index + 1).unwrap_or(u32::MAX),
            "multipart parts must be contiguous"
        );
        anyhow::ensure!(
            !part.etag.is_empty()
                && part.etag.len() <= 1024
                && !part.etag.chars().any(|character| character.is_control() || matches!(character, '<' | '>' | '&')),
            "multipart part ETag is invalid"
        );
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            part.part_number, part.etag
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    Ok(xml)
}

/// Validates the bounded body returned by `CompleteMultipartUpload`.
///
/// S3-compatible services may return HTTP 200 and encode a failed completion
/// as an XML `Error` document. An empty body is accepted for implementations
/// that report success only in the status code.
///
/// # Errors
///
/// Returns an error when a non-empty response is an `Error` document or is not
/// a complete `CompleteMultipartUploadResult` document.
pub fn validate_complete_multipart_response(xml: &str) -> Result<()> {
    let xml = xml.trim();
    if xml.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        !xml.contains("<Error>") && !xml.contains("<Error "),
        "S3 reported an error while completing the multipart upload"
    );
    anyhow::ensure!(
        xml.matches("<CompleteMultipartUploadResult").count() == 1
            && xml.matches("</CompleteMultipartUploadResult>").count() == 1
            && xml.ends_with("</CompleteMultipartUploadResult>"),
        "S3 multipart completion response is malformed"
    );
    Ok(())
}

/// Returns the strong ETag from a successful multipart-completion document.
pub fn complete_multipart_etag(xml: &str) -> Result<String> {
    validate_complete_multipart_response(xml)?;
    let etag = extract_unique_tag(xml.trim(), "ETag")?
        .context("S3 multipart completion response omitted ETag")?;
    crate::surface_write::strong_if_match_etag(etag)
}

/// Returns the unique `<tag>…</tag>` body, if present.
fn extract_unique_tag<'a>(xml: &'a str, tag: &str) -> Result<Option<&'a str>> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let open_count = xml.matches(&open).count();
    let close_count = xml.matches(&close).count();
    anyhow::ensure!(
        open_count == close_count && open_count <= 1,
        "S3 list response has malformed or duplicate {tag} elements"
    );
    let Some(start) = xml.find(&open).map(|start| start + open.len()) else {
        return Ok(None);
    };
    let end = xml[start..]
        .find(&close)
        .map(|end| start + end)
        .context("S3 list response has an unterminated element")?;
    Ok(Some(&xml[start..end]))
}

/// Strictly decodes predefined and numeric XML entities.
fn xml_unescape(value: &str) -> Result<String> {
    anyhow::ensure!(
        !value.contains('<'),
        "XML element contains an unescaped '<'"
    );
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        decoded.push_str(&rest[..index]);
        let entity_and_rest = &rest[index + 1..];
        let end = entity_and_rest
            .find(';')
            .context("XML entity is missing a semicolon")?;
        let entity = &entity_and_rest[..end];
        match entity {
            "amp" => decoded.push('&'),
            "lt" => decoded.push('<'),
            "gt" => decoded.push('>'),
            "quot" => decoded.push('"'),
            "apos" => decoded.push('\''),
            numeric if numeric.starts_with("#x") => {
                let codepoint = u32::from_str_radix(&numeric[2..], 16)
                    .context("XML hexadecimal character reference is invalid")?;
                decoded.push(char::from_u32(codepoint).context("XML character is invalid")?);
            }
            numeric if numeric.starts_with('#') => {
                let codepoint = numeric[1..]
                    .parse::<u32>()
                    .context("XML decimal character reference is invalid")?;
                decoded.push(char::from_u32(codepoint).context("XML character is invalid")?);
            }
            _ => anyhow::bail!("XML response contains an unknown entity"),
        }
        rest = &entity_and_rest[end + 1..];
    }
    decoded.push_str(rest);
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_surface() -> S3Surface {
        S3Surface {
            scheme: "https".into(),
            host: "objects.example".into(),
            key_prefix: "bucket/tenant".into(),
            creds: Some(S3Creds {
                region: "us-east-1".into(),
                access_key: Zeroizing::new("access".into()),
                secret_key: Zeroizing::new("secret".into()),
            }),
        }
    }

    #[test]
    fn multipart_probe_recovery_accepts_only_exact_complete_inventory() {
        let surface = probe_surface();
        let empty = "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>";
        // Crash after abort: recovery observes no incomplete upload and may
        // safely start one fresh create+abort cycle.
        assert!(surface
            .parse_exact_multipart_uploads(".aos/credential-probes/write/1/token", empty,)
            .unwrap()
            .is_empty());
        let xml = "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>bucket/tenant/.aos/credential-probes/write/1/token</Key><UploadId>first</UploadId></Upload><Upload><Key>bucket/tenant/.aos/credential-probes/write/1/token</Key><UploadId>second</UploadId></Upload></ListMultipartUploadsResult>";
        // Crashes before the create response and after parsing the upload id
        // have the same recovery surface: every exact-key upload is enumerated
        // and aborted before a fresh probe starts.
        assert_eq!(
            surface
                .parse_exact_multipart_uploads(".aos/credential-probes/write/1/token", xml,)
                .unwrap(),
            vec!["first", "second"]
        );
        assert!(surface
            .parse_exact_multipart_uploads(
                ".aos/credential-probes/write/1/token",
                &xml.replace("bucket/tenant/.aos", "bucket/foreign/.aos"),
            )
            .is_err());
        assert!(surface
            .parse_exact_multipart_uploads(
                ".aos/credential-probes/write/1/token",
                &xml.replace("<IsTruncated>false", "<IsTruncated>true"),
            )
            .is_err());
    }

    #[test]
    fn multipart_response_and_completion_are_strict() {
        assert_eq!(
            parse_multipart_upload_id(
                "<InitiateMultipartUploadResult><UploadId>opaque&amp;id</UploadId></InitiateMultipartUploadResult>"
            )
            .unwrap(),
            "opaque&id"
        );
        assert!(parse_multipart_upload_id("<UploadId></UploadId>").is_err());
        assert!(
            parse_multipart_upload_id("<UploadId>one</UploadId><UploadId>two</UploadId>").is_err()
        );
        let xml = complete_multipart_xml(&[
            crate::surface_write::PartTag {
                part_number: 2,
                etag: "\"two\"".into(),
            },
            crate::surface_write::PartTag {
                part_number: 1,
                etag: "\"one\"".into(),
            },
        ])
        .unwrap();
        assert!(xml.find("<PartNumber>1").unwrap() < xml.find("<PartNumber>2").unwrap());
        assert!(validate_complete_multipart_response("").is_ok());
        assert!(validate_complete_multipart_response(
            "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>"
        )
        .is_ok());
        assert!(
            validate_complete_multipart_response("<Error><Code>InternalError</Code></Error>")
                .is_err()
        );
    }

    fn binding(kind: &str, access: &str, endpoint: Option<&str>) -> BindingRecord {
        let endpoint = endpoint.map(|value| url::Url::parse(value).unwrap());
        BindingRecord {
            id: 1,
            org_id: Some(1),
            name: "store".into(),
            kind: kind.into(),
            local_root_path: (kind == "local_fs").then(|| "/srv/store".into()),
            object_bucket: (kind != "local_fs").then(|| "my-bucket".into()),
            object_prefix: (kind != "local_fs").then(String::new),
            endpoint_scheme: endpoint.as_ref().map(|url| url.scheme().to_string()),
            endpoint_host_kind: endpoint.as_ref().map(|_| "dns".into()),
            endpoint_host_bytes: endpoint
                .as_ref()
                .and_then(|url| url.host_str())
                .map(|host| host.as_bytes().to_vec()),
            endpoint_port: endpoint
                .as_ref()
                .and_then(url::Url::port_or_known_default)
                .map(i64::from),
            signing_region: (kind != "local_fs").then(|| "auto".into()),
            access_mode: (kind != "local_fs").then(|| access.into()),
            is_instance_default: false,
            created_at: 0,
            ..BindingRecord::default()
        }
    }

    #[test]
    fn parse_list_objects_v2_extracts_keys_and_token() {
        let xml = "<?xml version=\"1.0\"?><ListBucketResult>\
            <Contents><Key>reg/HEAD</Key><Size>20</Size></Contents>\
            <Contents><Key>reg/objects/ab&amp;cd</Key></Contents>\
            <IsTruncated>true</IsTruncated>\
            <NextContinuationToken>tok/123</NextContinuationToken>\
            </ListBucketResult>";
        let (keys, next, truncated) = parse_list_objects_v2(xml).unwrap();
        assert_eq!(
            keys,
            vec!["reg/HEAD".to_string(), "reg/objects/ab&cd".to_string()]
        );
        assert_eq!(next.as_deref(), Some("tok/123"));
        assert!(truncated);

        // Not truncated: no continuation, even if a token tag is present.
        let done = "<ListBucketResult><Contents><Key>reg/x</Key></Contents>\
            <IsTruncated>false</IsTruncated></ListBucketResult>";
        let (keys, next, truncated) = parse_list_objects_v2(done).unwrap();
        assert_eq!(keys, vec!["reg/x".to_string()]);
        assert_eq!(next, None);
        assert!(!truncated);

        let mut visited = 0_usize;
        let error = visit_list_objects_v2(xml, |_| {
            visited += 1;
            anyhow::ensure!(visited <= 1, "inventory budget exhausted");
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("inventory budget exhausted"));
        assert_eq!(visited, 2);
        assert!(parse_list_objects_v2(
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>"
        )
        .is_err());
        assert!(parse_list_objects_v2(
            "<ListBucketResult><Contents><Key>x&amp</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>"
        )
        .is_err());
    }

    #[test]
    fn relative_from_key_strips_in_bucket_prefix() {
        // root "my-bucket", reg "andyl/demo" -> key_prefix "my-bucket/andyl/demo".
        let b = binding("s3", "private", Some("https://s3.example.com"));
        let surface = S3Surface::from_binding(&b, "andyl/demo", Some("AKID:sec:auto"))
            .unwrap()
            .unwrap();
        assert_eq!(
            surface.relative_from_key("andyl/demo/HEAD").as_deref(),
            Some("HEAD")
        );
        assert_eq!(
            surface
                .relative_from_key("andyl/demo/objects/ab/cd")
                .as_deref(),
            Some("objects/ab/cd")
        );
        assert_eq!(surface.relative_from_key("other/x"), None);
        // And a presigned list URL carries the in-bucket prefix + signature.
        let url = surface.list_url(None, 256, 1_700_000_000).unwrap();
        assert!(
            url.contains("/my-bucket?") || url.contains("/my-bucket&"),
            "{url}"
        );
        assert!(url.contains("prefix=andyl%2Fdemo%2F"), "{url}");
        assert!(
            url.contains("list-type=2") && url.contains("X-Amz-Signature="),
            "{url}"
        );
    }

    #[test]
    fn non_object_store_kinds_resolve_to_none() {
        let b = binding("local_fs", "private", None);
        assert!(S3Surface::from_binding(&b, "reg", None).unwrap().is_none());
    }

    #[test]
    fn private_binding_signs_each_method_distinctly() {
        let b = binding(
            "r2",
            "private",
            Some("https://acct.r2.cloudflarestorage.com"),
        );
        let surface = S3Surface::from_binding(&b, "andyl/demo", Some("AKIDEXAMPLE:secretkey:auto"))
            .unwrap()
            .unwrap();
        assert!(surface.is_writable());
        let get = surface
            .object_url(Method::Get, "info/refs", 1_700_000_000)
            .unwrap();
        let put = surface
            .object_url(Method::Put, "info/refs", 1_700_000_000)
            .unwrap();
        // Path-style key includes bucket + resource prefix + logical path.
        assert!(get.contains("/my-bucket/andyl/demo/info/refs?"), "{get}");
        assert!(get.contains("X-Amz-Signature="));
        assert_ne!(get, put, "method is signed, so GET and PUT differ");
        // The secret never leaks into a URL.
        assert!(!get.contains("secretkey"));
    }

    #[test]
    fn traversal_paths_are_rejected_before_signing() {
        let b = binding("s3", "private", Some("https://s3.example.com"));
        let surface = S3Surface::from_binding(&b, "andyl/demo", Some("AKID:sec:auto"))
            .unwrap()
            .unwrap();
        // `..` toward another tenant's prefix, an absolute path, and a doubled
        // slash are all refused — never signed.
        assert!(surface
            .object_url(Method::Get, "../other/info/refs", 1)
            .is_err());
        assert!(surface.object_url(Method::Get, "/etc/passwd", 1).is_err());
        assert!(surface.object_url(Method::Put, "a//b", 1).is_err());
    }

    #[test]
    fn public_binding_is_read_only_and_unsigned() {
        let b = binding("s3", "public", Some("https://cdn.example.com"));
        let surface = S3Surface::from_binding(&b, "reg", None).unwrap().unwrap();
        assert!(!surface.is_writable());
        let get = surface.object_url(Method::Get, "info/refs", 1).unwrap();
        assert_eq!(get, "https://cdn.example.com:443/my-bucket/reg/info/refs");
        assert!(surface.object_url(Method::Put, "info/refs", 1).is_err());
    }

    #[test]
    fn missing_endpoint_is_an_error() {
        let b = binding("s3", "public", None);
        assert!(S3Surface::from_binding(&b, "reg", None).is_err());
    }

    #[test]
    fn private_without_credentials_is_an_error() {
        let b = binding("s3", "private", Some("https://s3.example.com"));
        assert!(S3Surface::from_binding(&b, "reg", None).is_err());
    }
}
