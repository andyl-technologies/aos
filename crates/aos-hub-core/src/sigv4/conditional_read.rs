//! Closed version-and-condition signing for bounded external copy source ranges.

use anyhow::{ensure, Result};

use crate::direct_upload::{DirectRequiredHeader, MAX_DIRECT_PART_BYTES};
use crate::storage_authority::external_object::copy::CopySourceObject;

use super::{presign_url_with_headers, DirectSignedProviderRequest, PresignParams};

/// Signs one exact immutable version, strong condition and bounded source range.
///
/// Both `If-Match` and `Range` are required signed headers. Provider support and
/// current read authority are separate prerequisites; a signed URL alone proves
/// neither source immutability nor range response correctness.
///
/// # Errors
/// Returns an error for missing source version, weak tag, invalid or overflowing
/// range, excessive length/lifetime, malformed coordinates or signing failure.
pub fn presign_versioned_conditional_range(
    parameters: &PresignParams<'_>,
    source: &CopySourceObject,
    offset: u64,
    bytes: u64,
    maximum_ttl: u32,
) -> Result<DirectSignedProviderRequest> {
    source.validate()?;
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| anyhow::anyhow!("conditional source range overflow"))?;
    ensure!(
        bytes > 0
            && bytes <= MAX_DIRECT_PART_BYTES
            && end <= source.bytes.get() as u64
            && (1..=604800).contains(&maximum_ttl)
            && parameters.expires_secs > 0
            && parameters.expires_secs <= maximum_ttl,
        "conditional source range or lifetime exceeds bound"
    );
    let range = format!("bytes={offset}-{}", end - 1);
    let headers = [("if-match", source.etag.clone()), ("range", range)];
    let url = presign_url_with_headers(
        "GET",
        parameters,
        &[("versionId", source.provider_version.clone())],
        &headers,
    )?;
    Ok(DirectSignedProviderRequest {
        url,
        required_headers: headers
            .into_iter()
            .map(|(name, value)| DirectRequiredHeader {
                name: name.into(),
                value,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_authority::lease::LeaseInteger;

    fn parameters() -> PresignParams<'static> {
        PresignParams {
            access_key: "fixture-access",
            secret_key: "fixture-secret",
            region: "fixture-region",
            service: "s3",
            scheme: "https",
            host: "provider.invalid",
            path: "/bucket/source/key",
            expires_secs: 30,
            amz_date: "20261001T000000Z",
        }
    }

    fn source() -> CopySourceObject {
        CopySourceObject {
            provider_version: "version/one+".into(),
            etag: "\"actual-source-tag\"".into(),
            bytes: LeaseInteger::new(12).unwrap(),
        }
    }

    #[test]
    fn source_version_condition_and_range_are_all_authenticated() {
        let parameters = parameters();
        let source = source();
        let signed = presign_versioned_conditional_range(&parameters, &source, 2, 5, 30).unwrap();
        assert!(signed.url.contains("versionId=version%2Fone%2B"));
        assert!(signed
            .url
            .contains("X-Amz-SignedHeaders=host%3Bif-match%3Brange"));
        assert_eq!(signed.required_headers[0].value, source.etag);
        assert_eq!(signed.required_headers[1].value, "bytes=2-6");
        let signature = |request: DirectSignedProviderRequest| {
            request
                .url
                .split("X-Amz-Signature=")
                .nth(1)
                .unwrap()
                .to_owned()
        };
        let original = signature(signed);

        let mut changed = source.clone();
        changed.provider_version = "another-real-version".into();
        assert_ne!(
            original,
            signature(
                presign_versioned_conditional_range(&parameters, &changed, 2, 5, 30).unwrap()
            )
        );
        changed = source.clone();
        changed.etag = "\"another-real-tag\"".into();
        assert_ne!(
            original,
            signature(
                presign_versioned_conditional_range(&parameters, &changed, 2, 5, 30).unwrap()
            )
        );
        assert_ne!(
            original,
            signature(presign_versioned_conditional_range(&parameters, &source, 3, 5, 30).unwrap())
        );
    }

    #[test]
    fn versionless_overflow_out_of_bounds_and_unreviewed_lifetime_refuse() {
        let parameters = parameters();
        let mut source = source();
        source.provider_version = "null".into();
        assert!(presign_versioned_conditional_range(&parameters, &source, 0, 5, 30).is_err());
        source.provider_version = "actual-version".into();
        assert!(
            presign_versioned_conditional_range(&parameters, &source, u64::MAX, 5, 30).is_err()
        );
        assert!(presign_versioned_conditional_range(&parameters, &source, 10, 5, 30).is_err());
        assert!(presign_versioned_conditional_range(&parameters, &source, 0, 0, 30).is_err());
        assert!(presign_versioned_conditional_range(&parameters, &source, 0, 5, 29).is_err());
    }
}
