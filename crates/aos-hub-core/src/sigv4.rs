//! AWS Signature Version 4 presigned-URL signing for authenticated-origin
//! cache proxying (RFC-0004 "11-caches": proxy to an authenticated origin).
//!
//! When a managed cache's binding is a **private** external S3/R2
//! bucket, the hub never hands the bucket's bare URL to a consumer. Instead it
//! either streams the object through its proxied facade or — for a direct-style
//! read — mints a short-lived **presigned GET URL** the client fetches itself
//! (`presigned GET → 302`). This module computes that URL.
//!
//! It is pure and `wasm32`-clean: HMAC-SHA256 + SHA-256 over the `hmac`/`sha2`
//! crates (the same primitives the HS256 JWT path uses — no `ring`, no C), so it
//! runs identically on the native hub and the Worker.
//!
//! # Algorithm
//!
//! The [query-string presigned form] of SigV4:
//!
//! ```text
//! canonical request = METHOD \n URI \n canonical-query \n
//!                     canonical-headers \n signed-headers \n UNSIGNED-PAYLOAD
//! string to sign    = "AWS4-HMAC-SHA256" \n amz-date \n
//!                     <date>/<region>/<service>/aws4_request \n
//!                     hex(sha256(canonical-request))
//! signing key       = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
//! signature         = hex(HMAC(signing-key, string-to-sign))
//! ```
//!
//! [query-string presigned form]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Credentials and target coordinates for presigning one request.
#[derive(Debug, Clone)]
pub struct PresignParams<'a> {
    /// The access key id (e.g. an AWS/R2 access key).
    pub access_key: &'a str,
    /// The secret access key — never logged, never placed in the URL.
    pub secret_key: &'a str,
    /// The signing region (e.g. `us-east-1`; R2 uses `auto`).
    pub region: &'a str,
    /// The service (`s3` for object storage).
    pub service: &'a str,
    /// The URL scheme (`https` for real S3/R2; `http` only for a plaintext
    /// origin, e.g. a local test/dev endpoint). SigV4 signs the host and path
    /// but **not** the scheme, so this affects only the emitted URL, never the
    /// signature.
    pub scheme: &'a str,
    /// The request host (the value of the `Host` header / URL authority).
    pub host: &'a str,
    /// The object path, leading-slash absolute (e.g. `/test.txt`). Each segment
    /// is URI-encoded; `/` separators are preserved.
    pub path: &'a str,
    /// Validity window in seconds (`X-Amz-Expires`).
    pub expires_secs: u32,
    /// The signing timestamp in ISO-8601 *basic* UTC (`YYYYMMDDTHHMMSSZ`).
    /// Passed in (not read from a clock) so the result is deterministic and the
    /// signer is `wasm`-clean.
    pub amz_date: &'a str,
}

/// Format a Unix timestamp (seconds) as SigV4's ISO-8601 *basic* UTC
/// `YYYYMMDDTHHMMSSZ`.
///
/// Pure and `wasm`-clean (no `chrono`/`time`): converts days-since-epoch to a
/// civil date with Howard Hinnant's algorithm. Negative timestamps (pre-1970)
/// are clamped to the epoch — the signer only ever sees "now".
#[must_use]
pub fn amz_date_from_unix(secs: i64) -> String {
    let secs = secs.max(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 -> civil (y, m, d). Shift epoch to 0000-03-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}T{hour:02}{min:02}{sec:02}Z")
}

/// HMAC-SHA256 of `data` under `key`.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Lowercase hex of SHA-256(`data`).
fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// RFC-3986 percent-encoding per the SigV4 rules.
///
/// Unreserved characters (`A-Z a-z 0-9 - _ . ~`) pass through; everything else
/// is `%XX` with uppercase hex. When `encode_slash` is false, `/` is left as-is
/// (used for the canonical URI path); when true, `/` is encoded (query values).
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (byte == b'/' && !encode_slash);
        if keep {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// Build a presigned `GET` URL valid for [`PresignParams::expires_secs`].
///
/// The returned `https://…` URL carries the `X-Amz-*` query parameters and the
/// computed `X-Amz-Signature`; a client may `GET` it directly with no further
/// credentials until it expires. The secret key never appears in the output.
///
/// Only `host` is signed, matching what a browser/`curl`/`nix` client sends;
/// `UNSIGNED-PAYLOAD` is used so the body need not be hashed.
///
/// # Errors
///
/// Returns an error when `amz_date` is not exactly `YYYYMMDDTHHMMSSZ` (16 ASCII
/// chars: 8 digits, `T`, 6 digits, `Z`) or when `host` contains a control,
/// whitespace, or URL-structural character (`/ ? # @`) — guards against a
/// confidently-wrong signature from a malformed date and against CRLF/authority
/// injection into the signed canonical request, since both inputs are caller-
/// supplied.
pub fn presign_get_url(p: &PresignParams<'_>) -> Result<String> {
    presign_url("GET", p, &[], None)
}

/// Build a presigned S3 `ListObjectsV2` URL valid for
/// [`PresignParams::expires_secs`].
///
/// A `GET` on the bucket (`p.path` = `/{bucket}`) carrying `list-type=2`, the
/// in-bucket `prefix`, bounded `max-keys`, and an optional continuation token -
/// all folded into the signed canonical query alongside the `X-Amz-*` params, so the
/// returned URL can be fetched directly to page through every key under
/// `prefix`. This is the enumeration storage migration walks when a surface
/// lives on an external S3/R2 binding.
///
/// # Errors
///
/// Same as [`presign_get_url`].
pub fn presign_list_url(
    p: &PresignParams<'_>,
    prefix: &str,
    continuation: Option<&str>,
    max_keys: usize,
) -> Result<String> {
    anyhow::ensure!(max_keys > 0 && max_keys <= 1_000, "invalid S3 max-keys");
    let mut extra = vec![
        ("list-type", "2".to_string()),
        ("max-keys", max_keys.to_string()),
        ("prefix", prefix.to_string()),
    ];
    if let Some(token) = continuation {
        extra.push(("continuation-token", token.to_string()));
    }
    presign_url("GET", p, &extra, None)
}

/// Build a presigned `PUT` URL valid for [`PresignParams::expires_secs`].
///
/// The upload sibling of [`presign_get_url`]: a client may `PUT` the object's
/// bytes directly to this URL (the `presign` mode of `CreateCacheObjectUploads`)
/// with no further credentials until it expires. Same signing rules; only the
/// HTTP method in the canonical request differs.
///
/// # Errors
///
/// Same as [`presign_get_url`].
pub fn presign_put_url(p: &PresignParams<'_>) -> Result<String> {
    presign_url("PUT", p, &[], None)
}

/// Builds a presigned `PUT` whose signature requires one exact Content-Length.
///
/// The uploader must send the returned URL with a `Content-Length` header equal
/// to `content_length`; S3/R2 rejects any under- or over-declared body before it
/// can consume bytes outside the quota reservation.
///
/// # Errors
///
/// Same as [`presign_get_url`].
pub fn presign_put_url_with_content_length(
    p: &PresignParams<'_>,
    content_length: u64,
) -> Result<String> {
    presign_url("PUT", p, &[], Some(content_length))
}

/// Build a presigned `HEAD` URL valid for [`PresignParams::expires_secs`].
///
/// The metadata sibling of [`presign_get_url`]: a client may `HEAD` it to read
/// an object's size/existence (`Content-Length`) without transferring the body.
/// Because the HTTP method is part of the signed canonical request, a `HEAD`
/// presign differs from the `GET`/`PUT` presigns of the same object.
///
/// # Errors
///
/// Same as [`presign_get_url`].
pub fn presign_head_url(p: &PresignParams<'_>) -> Result<String> {
    presign_url("HEAD", p, &[], None)
}

/// Build a presigned `DELETE` URL valid for [`PresignParams::expires_secs`].
///
/// The removal sibling of [`presign_put_url`]: a client may `DELETE` it to
/// remove the object with no further credentials until it expires.
///
/// # Errors
///
/// Same as [`presign_get_url`].
pub fn presign_delete_url(p: &PresignParams<'_>) -> Result<String> {
    presign_url("DELETE", p, &[], None)
}

/// Builds a presigned S3 multipart-operation URL.
///
/// `method` is restricted to `POST`, `PUT`, or `DELETE`; `query` is the exact
/// operation query (`uploads`, `uploadId`, and optionally `partNumber`) folded
/// into the signature.
///
/// # Errors
///
/// Returns an error for an unsupported method, malformed multipart query, or
/// any error documented by [`presign_get_url`].
pub fn presign_multipart_url(
    p: &PresignParams<'_>,
    method: &str,
    query: &[(&str, String)],
) -> Result<String> {
    anyhow::ensure!(
        matches!(method, "POST" | "PUT" | "DELETE"),
        "invalid S3 multipart method"
    );
    let upload_id = query
        .iter()
        .find(|(key, _)| *key == "uploadId")
        .map(|(_, value)| value.as_str());
    let part_number = query
        .iter()
        .find(|(key, _)| *key == "partNumber")
        .and_then(|(_, value)| value.parse::<u32>().ok());
    let valid = match method {
        "POST" => {
            (query.len() == 1 && query[0].0 == "uploads" && query[0].1.is_empty())
                || (query.len() == 1 && upload_id.is_some_and(|id| !id.is_empty()))
        }
        "PUT" => {
            query.len() == 2
                && upload_id.is_some_and(|id| !id.is_empty())
                && part_number.is_some_and(|number| (1..=10_000).contains(&number))
        }
        "DELETE" => query.len() == 1 && upload_id.is_some_and(|id| !id.is_empty()),
        _ => false,
    };
    anyhow::ensure!(valid, "invalid S3 multipart query");
    presign_url(method, p, query, None)
}

/// Build a presigned URL for `method` (`GET`/`PUT`/`HEAD`/`DELETE`). The shared
/// signer behind [`presign_get_url`]/[`presign_put_url`]/[`presign_head_url`]/
/// [`presign_delete_url`].
fn presign_url(
    method: &str,
    p: &PresignParams<'_>,
    extra: &[(&str, String)],
    content_length: Option<u64>,
) -> Result<String> {
    validate_amz_date(p.amz_date)?;
    validate_host(p.host)?;
    // `amz_date` is `YYYYMMDDTHHMMSSZ` (validated above); the credential-scope
    // date is its 8-char date part. `get` never panics on a bad boundary.
    let date_stamp = p.amz_date.get(..8).unwrap_or(p.amz_date);
    let scope = format!("{date_stamp}/{}/{}/aws4_request", p.region, p.service);
    let credential = format!("{}/{scope}", p.access_key);

    // Canonical query string: the X-Amz-* params, each key+value URI-encoded
    // (values encode `/`), sorted by encoded key. `X-Amz-Signature` is appended
    // *after* signing and is not part of the canonical request.
    let signed_headers = if content_length.is_some() {
        "content-length;host"
    } else {
        "host"
    };
    let params = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential.clone()),
        ("X-Amz-Date", p.amz_date.to_string()),
        ("X-Amz-Expires", p.expires_secs.to_string()),
        ("X-Amz-SignedHeaders", signed_headers.to_string()),
    ];
    // The X-Amz-* presign params plus any operation params (e.g. ListObjectsV2's
    // `list-type`/`prefix`/`continuation-token`) all belong in the canonical
    // query, each key+value URI-encoded (values encode `/`) and sorted by
    // encoded key.
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .chain(
            extra
                .iter()
                .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true))),
        )
        .collect();
    encoded.sort();
    let canonical_query = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_uri = uri_encode(p.path, false);
    let canonical_headers = content_length.map_or_else(
        || format!("host:{}\n", p.host),
        |length| format!("content-length:{length}\nhost:{}\n", p.host),
    );
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        p.amz_date,
        sha256_hex(canonical_request.as_bytes())
    );

    // Derive the signing key and sign.
    let seed = Zeroizing::new(format!("AWS4{}", p.secret_key));
    let k_date = Zeroizing::new(hmac(seed.as_bytes(), date_stamp.as_bytes()));
    let k_region = Zeroizing::new(hmac(&k_date[..], p.region.as_bytes()));
    let k_service = Zeroizing::new(hmac(&k_region[..], p.service.as_bytes()));
    let k_signing = Zeroizing::new(hmac(&k_service[..], b"aws4_request"));
    let signature = hex::encode(hmac(&k_signing[..], string_to_sign.as_bytes()));

    // Emit the *encoded* path (the one that was signed), so the client requests
    // exactly the URI the signature covers.
    Ok(format!(
        "{}://{}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
        p.scheme, p.host
    ))
}

/// Validate an `X-Amz-Date` is exactly `YYYYMMDDTHHMMSSZ`.
fn validate_amz_date(amz_date: &str) -> Result<()> {
    let bytes = amz_date.as_bytes();
    let well_formed = bytes.len() == 16
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..15].iter().all(u8::is_ascii_digit);
    if !well_formed {
        bail!("X-Amz-Date must be YYYYMMDDTHHMMSSZ, got '{amz_date}'");
    }
    Ok(())
}

/// Validate a request `host` is a clean authority — no control, whitespace, or
/// URL-structural characters that could inject into the signed canonical
/// request or the emitted URL authority.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("host must not be empty");
    }
    if host.bytes().any(|b| {
        b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'/' | b'?' | b'#' | b'@')
    }) {
        bail!("host '{host}' contains an invalid character");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's documented presigned-URL example (S3 dev guide, "GET Object"):
    /// the canonical case the algorithm must reproduce bit-for-bit.
    /// <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html>
    #[test]
    fn matches_aws_documented_example() {
        let p = PresignParams {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
            scheme: "https",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            expires_secs: 86400,
            amz_date: "20130524T000000Z",
        };
        let url = presign_get_url(&p).unwrap();
        // The expected signature from the AWS worked example.
        assert!(
            url.ends_with(
                "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "presigned URL signature mismatch: {url}"
        );
        // Sanity: the secret never leaks into the URL.
        assert!(!url.contains("wJalr"), "secret key leaked: {url}");
        assert!(url.contains(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        ));
        assert!(url.contains("X-Amz-Expires=86400"));
    }

    #[test]
    fn amz_date_formats_unix_seconds() {
        // 2013-05-24T00:00:00Z (the AWS example's date) = 1369353600.
        assert_eq!(amz_date_from_unix(1369353600), "20130524T000000Z");
        // Epoch and a time-of-day case.
        assert_eq!(amz_date_from_unix(0), "19700101T000000Z");
        assert_eq!(amz_date_from_unix(1369353600 + 3661), "20130524T010101Z");
        // The output always satisfies the signer's own validator.
        assert!(validate_amz_date(&amz_date_from_unix(1700000000)).is_ok());
        // Negative clamps to the epoch.
        assert_eq!(amz_date_from_unix(-5), "19700101T000000Z");
    }

    #[test]
    fn put_presign_differs_from_get_and_is_well_formed() {
        let p = PresignParams {
            access_key: "AKIDEXAMPLE",
            secret_key: "secret",
            region: "us-east-1",
            service: "s3",
            scheme: "https",
            host: "bucket.s3.amazonaws.com",
            path: "/upload.nar",
            expires_secs: 300,
            amz_date: "20240101T000000Z",
        };
        let get = presign_get_url(&p).unwrap();
        let put = presign_put_url(&p).unwrap();
        assert!(put.contains("&X-Amz-Signature="));
        assert!(put.contains("/upload.nar?"));
        // The method is part of the signed canonical request, so GET and PUT
        // over the same object produce different signatures.
        assert_ne!(get, put, "PUT and GET presign to different signatures");
    }

    #[test]
    fn exact_length_put_signs_content_length() {
        let p = PresignParams {
            access_key: "AKIDEXAMPLE",
            secret_key: "secret",
            region: "us-east-1",
            service: "s3",
            scheme: "https",
            host: "bucket.s3.amazonaws.com",
            path: "/upload.nar",
            expires_secs: 300,
            amz_date: "20240101T000000Z",
        };
        let exact = presign_put_url_with_content_length(&p, 4096).unwrap();
        let other = presign_put_url_with_content_length(&p, 4097).unwrap();

        assert!(
            exact.contains("X-Amz-SignedHeaders=content-length%3Bhost"),
            "{exact}"
        );
        assert_ne!(exact, other, "Content-Length must change the signature");
        assert_ne!(exact, presign_put_url(&p).unwrap());
    }

    #[test]
    fn multipart_operation_and_identifiers_are_signed() {
        let p = params("bucket.example", "20240101T000000Z");
        let create = presign_multipart_url(&p, "POST", &[("uploads", String::new())]).unwrap();
        let part_one = presign_multipart_url(
            &p,
            "PUT",
            &[("partNumber", "1".into()), ("uploadId", "upload-a".into())],
        )
        .unwrap();
        let part_two = presign_multipart_url(
            &p,
            "PUT",
            &[("partNumber", "2".into()), ("uploadId", "upload-a".into())],
        )
        .unwrap();
        assert!(create.contains("uploads="));
        assert!(part_one.contains("uploadId=upload-a"));
        assert_ne!(create, part_one);
        assert_ne!(part_one, part_two);
    }

    #[test]
    fn uri_encode_follows_sigv4_rules() {
        assert_eq!(uri_encode("a/b c", false), "a/b%20c");
        assert_eq!(uri_encode("a/b c", true), "a%2Fb%20c");
        assert_eq!(uri_encode("-_.~", true), "-_.~");
        assert_eq!(uri_encode("/", false), "/");
    }

    #[test]
    fn path_segments_are_encoded_but_slashes_preserved() {
        let p = PresignParams {
            access_key: "AKIDEXAMPLE",
            secret_key: "secret",
            region: "auto",
            service: "s3",
            scheme: "https",
            host: "bucket.example.com",
            path: "/cache-prefix/nar/ab cd.nar.zst",
            expires_secs: 300,
            amz_date: "20240101T000000Z",
        };
        let url = presign_get_url(&p).unwrap();
        assert!(url.contains("/cache-prefix/nar/ab%20cd.nar.zst"), "{url}");
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("&X-Amz-Signature="));
    }

    fn params<'a>(host: &'a str, amz_date: &'a str) -> PresignParams<'a> {
        PresignParams {
            access_key: "AKIDEXAMPLE",
            secret_key: "secret",
            region: "auto",
            service: "s3",
            scheme: "https",
            host,
            path: "/x",
            expires_secs: 300,
            amz_date,
        }
    }

    #[test]
    fn rejects_malformed_amz_date() {
        // Too short, wrong shape, and a non-char-boundary multibyte input that
        // would have panicked a naive `[..8]` byte slice.
        assert!(presign_get_url(&params("h.example", "2013")).is_err());
        assert!(presign_get_url(&params("h.example", "20130524-000000Z")).is_err());
        assert!(presign_get_url(&params("h.example", "2013052\u{e9}2013")).is_err());
        // The canonical good form is accepted.
        assert!(presign_get_url(&params("h.example", "20130524T000000Z")).is_ok());
    }

    #[test]
    fn presign_list_signs_operation_query_params() {
        let p = params("bucket.example", "20130524T000000Z");
        let sig = |u: &str| {
            u.split("X-Amz-Signature=")
                .nth(1)
                .unwrap_or_default()
                .to_string()
        };

        let url = presign_list_url(&p, "demo/sub/", None, 256).unwrap();
        // The operation params are present, with `/` encoded in query values.
        assert!(url.contains("list-type=2"), "{url}");
        assert!(url.contains("max-keys=256"), "{url}");
        assert!(url.contains("prefix=demo%2Fsub%2F"), "{url}");
        assert!(url.contains("&X-Amz-Signature="), "{url}");
        // Deterministic for fixed inputs.
        assert_eq!(url, presign_list_url(&p, "demo/sub/", None, 256).unwrap());
        // Because the operation params are part of the signed canonical query,
        // the list signature differs from a plain GET of the same path.
        assert_ne!(sig(&url), sig(&presign_get_url(&p).unwrap()));
        // A continuation token is signed in too.
        let next = presign_list_url(&p, "demo/sub/", Some("tok123"), 256).unwrap();
        assert!(next.contains("continuation-token=tok123"), "{next}");
        assert_ne!(sig(&next), sig(&url));
    }

    #[test]
    fn rejects_host_with_injection_or_structural_chars() {
        assert!(presign_get_url(&params("h.example\nx-evil:1", "20130524T000000Z")).is_err());
        assert!(presign_get_url(&params("h.example/path", "20130524T000000Z")).is_err());
        assert!(presign_get_url(&params("h.example?q=1", "20130524T000000Z")).is_err());
        assert!(presign_get_url(&params("has space", "20130524T000000Z")).is_err());
        assert!(presign_get_url(&params("", "20130524T000000Z")).is_err());
        assert!(presign_get_url(&params("ok.example.com", "20130524T000000Z")).is_ok());
    }
}
