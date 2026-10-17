//! Strong conditional full-object signing for an acknowledged private stage.

use anyhow::{ensure, Result};

use super::{presign_url_with_headers, DirectSignedProviderRequest, PresignParams};
use crate::direct_upload::DirectRequiredHeader;

/// Signs a full-object GET with the original strong ETag and actual optional version.
///
/// The caller independently establishes the retained closure and current read
/// permission. A versionless request addresses the condition-selected current
/// object; it does not establish historical version addressability.
///
/// # Errors
/// Returns an error for a weak or malformed ETag, an invented null or malformed
/// version, excessive lifetime, invalid coordinates, or signing failure.
pub fn presign_closed_stage_read(
    parameters: &PresignParams<'_>,
    etag: &str,
    provider_version: Option<&str>,
    maximum_ttl: u32,
) -> Result<DirectSignedProviderRequest> {
    ensure!(
        crate::direct_upload::valid_direct_etag(etag),
        "closed source ETag malformed"
    );
    let etag = crate::surface_write::strong_if_match_etag(etag)?;
    ensure!(
        (1..=604800).contains(&maximum_ttl)
            && parameters.expires_secs > 0
            && parameters.expires_secs <= maximum_ttl,
        "closed source lifetime exceeds bound"
    );
    let query = match provider_version {
        Some(version) => {
            ensure!(
                crate::storage_work::valid_provider_version(version) && version != "null",
                "closed source version malformed"
            );
            vec![("versionId", version.to_owned())]
        }
        None => Vec::new(),
    };
    let headers = [("if-match", etag.clone())];
    let url = presign_url_with_headers("GET", parameters, &query, &headers)?;
    Ok(DirectSignedProviderRequest {
        url,
        required_headers: vec![DirectRequiredHeader {
            name: "if-match".into(),
            value: etag,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters() -> PresignParams<'static> {
        PresignParams {
            access_key: "fixture-access",
            secret_key: "fixture-secret",
            region: "fixture-region",
            service: "s3",
            scheme: "https",
            host: "provider.invalid",
            path: "/bucket/private-stage",
            expires_secs: 30,
            amz_date: "20261001T000000Z",
        }
    }

    #[test]
    fn full_read_binds_condition_and_only_an_actual_supplied_version() {
        let versionless = presign_closed_stage_read(&parameters(), "\"closed\"", None, 30).unwrap();
        assert!(versionless
            .url
            .contains("X-Amz-SignedHeaders=host%3Bif-match"));
        assert!(!versionless.url.contains("versionId="));
        assert_eq!(versionless.required_headers.len(), 1);
        assert_eq!(versionless.required_headers[0].value, "\"closed\"");

        let versioned =
            presign_closed_stage_read(&parameters(), "\"closed\"", Some("actual/v1+"), 30).unwrap();
        assert!(versioned.url.contains("versionId=actual%2Fv1%2B"));
        let signature = |request: &DirectSignedProviderRequest| {
            request
                .url
                .split("X-Amz-Signature=")
                .nth(1)
                .unwrap()
                .to_owned()
        };
        assert_ne!(signature(&versionless), signature(&versioned));
        for changed in [
            presign_closed_stage_read(&parameters(), "\"changed\"", Some("actual/v1+"), 30)
                .unwrap(),
            presign_closed_stage_read(&parameters(), "\"closed\"", Some("actual/v2"), 30).unwrap(),
        ] {
            assert_ne!(signature(&versioned), signature(&changed));
        }
    }

    #[test]
    fn weak_tags_false_versions_and_unbounded_lifetimes_refuse() {
        for tag in ["W/\"weak\"", "*", "\"one\",\"two\"", ""] {
            assert!(presign_closed_stage_read(&parameters(), tag, None, 30).is_err());
        }
        for version in ["", "null", "bad\nversion", &"a".repeat(513)] {
            assert!(
                presign_closed_stage_read(&parameters(), "\"closed\"", Some(version), 30).is_err()
            );
        }
        assert!(presign_closed_stage_read(&parameters(), "\"closed\"", None, 29).is_err());
        assert!(presign_closed_stage_read(&parameters(), "\"closed\"", None, 0).is_err());
    }
}
