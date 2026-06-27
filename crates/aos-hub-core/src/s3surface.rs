//! Resolving an S3-compatible storage binding into per-object signed URLs.
//!
//! A storage binding of kind `s3` or `r2` points a registry's (or cache's)
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
//! An S3/R2 binding row carries its origin and credentials in the columns the
//! authenticated-origin cache path already defined:
//!
//! ```text
//! kind            = "s3" | "r2"
//! root            = bucket name, optionally "bucket/sub-prefix"
//! access          = "private" | "public"
//! endpoint        = S3/R2 API endpoint the hub writes/presigns against, e.g.
//!                     https://<account>.r2.cloudflarestorage.com   (R2)
//!                     https://s3.us-east-1.amazonaws.com            (S3)
//! credential_ref  = sealed "access_key:secret_key:region"  (private only)
//! ```
//!
//! The object key for a logical surface path `P` under a resource whose prefix is
//! `RP` is `{root}/{RP}/{P}`; path-style addressing (`{endpoint}/{key}`) is used,
//! which both R2's S3 API and AWS S3 accept.
//!
//! # Access modes
//!
//! - **private** — the common case: the binding carries credentials, and every
//!   request (read *and* write) is a SigV4-presigned URL. Full read/write.
//! - **public** — a credential-less read-only mirror: reads are a direct
//!   unsigned `GET` of the public origin URL; writes are refused (there is
//!   nothing to sign with).

use crate::auth::seal::SecretSealer;
use crate::db::StorageBindingRecord;
use anyhow::{bail, Context, Result};

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
#[derive(Clone)]
struct S3Creds {
    region: String,
    access_key: String,
    secret_key: String,
}

/// A resolved S3-compatible origin scoped to one resource's key prefix.
///
/// Built by [`S3Surface::from_binding`] from a binding row and the per-resource
/// sub-prefix; [`S3Surface::object_url`] then mints a signed (or, for a public
/// binding, direct) URL for one object operation.
#[derive(Clone)]
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
    /// `sub_prefix` is the per-resource key segment (a registry's or cache's
    /// `prefix`); the surface's full key prefix is `{binding.root}/{sub_prefix}`.
    /// For a `private` binding the sealed `credential_ref` is unsealed here (it is
    /// `access_key:secret_key:region`; the secret may itself contain `:`, so only
    /// the first and last separators are split on). For a `public` binding no
    /// credentials are loaded and the surface serves read-only.
    ///
    /// # Errors
    ///
    /// Returns an error when an `s3`/`r2` binding is missing its
    /// `endpoint`, when a `private` binding is missing or has a malformed
    /// `credential_ref`, or when unsealing fails. A binding kind that is not an
    /// object store yields `Ok(None)`, not an error.
    pub fn from_binding(
        binding: &StorageBindingRecord,
        sub_prefix: &str,
        sealer: &dyn SecretSealer,
    ) -> Result<Option<S3Surface>> {
        match binding.kind.as_str() {
            "s3" | "r2" => {}
            _ => return Ok(None),
        }
        let endpoint = binding
            .endpoint
            .as_deref()
            .filter(|u| !u.is_empty())
            .with_context(|| {
                format!(
                    "storage binding '{}' (kind {}) has no endpoint",
                    binding.name, binding.kind
                )
            })?;
        let scheme = if endpoint.starts_with("http://") {
            "http"
        } else {
            "https"
        };
        let host = endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        if host.is_empty() {
            bail!(
                "storage binding '{}' has an empty endpoint host",
                binding.name
            );
        }

        let bucket = binding.root.trim_matches('/');
        let sub = sub_prefix.trim_matches('/');
        let key_prefix = if sub.is_empty() {
            bucket.to_string()
        } else {
            format!("{bucket}/{sub}")
        };

        let creds = match binding.access.as_str() {
            "private" => {
                let sealed = binding.credential_ref.as_deref().with_context(|| {
                    format!(
                        "private storage binding '{}' has no sealed credentials",
                        binding.name
                    )
                })?;
                let plain = sealer.unseal(sealed).with_context(|| {
                    format!("unsealing credentials for binding '{}'", binding.name)
                })?;
                let (access_key, rest) = plain
                    .split_once(':')
                    .context("credential_ref must be access_key:secret_key:region")?;
                let (secret_key, region) = rest
                    .rsplit_once(':')
                    .context("credential_ref must be access_key:secret_key:region")?;
                Some(S3Creds {
                    region: region.to_string(),
                    access_key: access_key.to_string(),
                    secret_key: secret_key.to_string(),
                })
            }
            _ => None,
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
                    bail!("public storage binding is read-only");
                }
                // A public origin needs no signature; the object is world-readable
                // at its direct URL.
                Ok(format!("{}://{}{}", self.scheme, self.host, object_path))
            }
        }
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
    /// optionally continuing from `continuation`. The walk that storage
    /// migration / re-scan run when a surface lives on an external binding pages
    /// through these. Credential-less (public) bindings cannot be listed.
    ///
    /// # Errors
    ///
    /// [`bail`]s for a public binding (no anonymous list); otherwise propagates
    /// a signing error.
    pub fn list_url(&self, continuation: Option<&str>, now: i64) -> Result<String> {
        let Some(creds) = &self.creds else {
            bail!("cannot list a public (credential-less) storage binding");
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
        crate::sigv4::presign_list_url(&params, &list_prefix, continuation)
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

/// Parse an S3 `ListObjectsV2` XML response into `(keys, next_continuation)`.
///
/// Extracts every `<Key>` (XML-unescaped) and, when `<IsTruncated>true`, the
/// `<NextContinuationToken>` to page from. Deliberately minimal — the response
/// shape is fixed and small — so it needs no XML dependency on the wasm Worker.
#[must_use]
pub fn parse_list_objects_v2(xml: &str) -> (Vec<String>, Option<String>) {
    let mut keys = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Key>") {
        let after = &rest[start + "<Key>".len()..];
        let Some(end) = after.find("</Key>") else {
            break;
        };
        keys.push(xml_unescape(&after[..end]));
        rest = &after[end + "</Key>".len()..];
    }
    let truncated = extract_tag(xml, "IsTruncated").as_deref() == Some("true");
    let next = if truncated {
        extract_tag(xml, "NextContinuationToken").map(|s| xml_unescape(&s))
    } else {
        None
    };
    (keys, next)
}

/// First `<tag>…</tag>` body in `xml`, or `None`.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Unescape the five predefined XML entities (sufficient for object keys).
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::seal::AesGcmSealer;

    fn binding(
        kind: &str,
        access: &str,
        cred: Option<&str>,
        endpoint: Option<&str>,
    ) -> StorageBindingRecord {
        StorageBindingRecord {
            id: 1,
            org_id: Some(1),
            name: "store".into(),
            kind: kind.into(),
            root: "my-bucket".into(),
            access: access.into(),
            endpoint: endpoint.map(str::to_string),
            credential_ref: cred.map(str::to_string),
            is_instance_default: false,
            created_at: 0,
        }
    }

    fn sealer() -> AesGcmSealer {
        AesGcmSealer::new(&[7u8; 32]).unwrap()
    }

    #[test]
    fn parse_list_objects_v2_extracts_keys_and_token() {
        let xml = "<?xml version=\"1.0\"?><ListBucketResult>\
            <Contents><Key>reg/HEAD</Key><Size>20</Size></Contents>\
            <Contents><Key>reg/objects/ab&amp;cd</Key></Contents>\
            <IsTruncated>true</IsTruncated>\
            <NextContinuationToken>tok/123</NextContinuationToken>\
            </ListBucketResult>";
        let (keys, next) = parse_list_objects_v2(xml);
        assert_eq!(
            keys,
            vec!["reg/HEAD".to_string(), "reg/objects/ab&cd".to_string()]
        );
        assert_eq!(next.as_deref(), Some("tok/123"));

        // Not truncated: no continuation, even if a token tag is present.
        let done = "<ListBucketResult><Contents><Key>reg/x</Key></Contents>\
            <IsTruncated>false</IsTruncated></ListBucketResult>";
        let (keys, next) = parse_list_objects_v2(done);
        assert_eq!(keys, vec!["reg/x".to_string()]);
        assert_eq!(next, None);
    }

    #[test]
    fn relative_from_key_strips_in_bucket_prefix() {
        let s = sealer();
        let sealed = s.seal("AKID:sec:auto").unwrap();
        // root "my-bucket", reg "andyl/demo" -> key_prefix "my-bucket/andyl/demo".
        let b = binding(
            "s3",
            "private",
            Some(&sealed),
            Some("https://s3.example.com"),
        );
        let surface = S3Surface::from_binding(&b, "andyl/demo", &s)
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
        let url = surface.list_url(None, 1_700_000_000).unwrap();
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
        let s = sealer();
        let b = binding("local_fs", "private", None, None);
        assert!(S3Surface::from_binding(&b, "reg", &s).unwrap().is_none());
    }

    #[test]
    fn private_binding_signs_each_method_distinctly() {
        let s = sealer();
        let sealed = s.seal("AKIDEXAMPLE:secretkey:auto").unwrap();
        let b = binding(
            "r2",
            "private",
            Some(&sealed),
            Some("https://acct.r2.cloudflarestorage.com"),
        );
        let surface = S3Surface::from_binding(&b, "andyl/demo", &s)
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
        let s = sealer();
        let sealed = s.seal("AKID:sec:auto").unwrap();
        let b = binding(
            "s3",
            "private",
            Some(&sealed),
            Some("https://s3.example.com"),
        );
        let surface = S3Surface::from_binding(&b, "andyl/demo", &s)
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
        let s = sealer();
        let b = binding("s3", "public", None, Some("https://cdn.example.com"));
        let surface = S3Surface::from_binding(&b, "reg", &s).unwrap().unwrap();
        assert!(!surface.is_writable());
        let get = surface.object_url(Method::Get, "info/refs", 1).unwrap();
        assert_eq!(get, "https://cdn.example.com/my-bucket/reg/info/refs");
        assert!(surface.object_url(Method::Put, "info/refs", 1).is_err());
    }

    #[test]
    fn missing_endpoint_is_an_error() {
        let s = sealer();
        let b = binding("s3", "public", None, None);
        assert!(S3Surface::from_binding(&b, "reg", &s).is_err());
    }

    #[test]
    fn private_without_credentials_is_an_error() {
        let s = sealer();
        let b = binding("s3", "private", None, Some("https://s3.example.com"));
        assert!(S3Surface::from_binding(&b, "reg", &s).is_err());
    }
}
