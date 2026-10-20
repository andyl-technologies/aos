//! Closed bucket metadata requests for read-only operator observations.
//!
//! These selectors reuse the ordinary SigV4 canonical signer. They do not
//! validate permission, issue a storage lease, or establish writer exclusion.

use anyhow::{ensure, Result};

use super::PresignParams;

/// A read-only bucket subresource selected by an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketReadback {
    /// The bucket's CORS configuration.
    Cors,
    /// The bucket's lifecycle configuration.
    Lifecycle,
    /// The bucket's location.
    Location,
    /// The bucket's versioning configuration.
    Versioning,
    /// The bucket's resource policy, when readable by the selected identity.
    Policy,
}

impl BucketReadback {
    fn query(self) -> &'static str {
        match self {
            Self::Cors => "cors",
            Self::Lifecycle => "lifecycle",
            Self::Location => "location",
            Self::Versioning => "versioning",
            Self::Policy => "policy",
        }
    }
}

/// Signs one HTTPS GET of a closed bucket metadata subresource.
///
/// The path must be exactly one bucket segment. An object path, arbitrary
/// query, mutating method, or non-S3 service cannot enter this interface.
/// Existing credentials are used only for the selected request; no permission
/// or closure claim follows from signing it.
///
/// # Errors
///
/// Returns an error for invalid bucket coordinates, an excessive validity
/// interval, or an error from the existing canonical SigV4 signer.
pub fn presign_bucket_readback(
    params: &PresignParams<'_>,
    operation: BucketReadback,
) -> Result<String> {
    let bucket = params.path.strip_prefix('/').unwrap_or_default();
    ensure!(
        params.scheme == "https"
            && params.service == "s3"
            && (3..=63).contains(&bucket.len())
            && bucket.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-'))
            && (1..=300).contains(&params.expires_secs),
        "read-only bucket coordinates are invalid"
    );
    super::presign_url("GET", params, &[(operation.query(), String::new())], None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> PresignParams<'static> {
        PresignParams {
            access_key: "fixture-access-key",
            secret_key: "fixture-secret-key",
            region: "auto",
            service: "s3",
            scheme: "https",
            host: "storage.example",
            path: "/fixture-bucket",
            expires_secs: 30,
            amz_date: "20260101T000000Z",
        }
    }

    #[test]
    fn closed_bucket_reads_reuse_exact_canonical_signatures() {
        for operation in [
            BucketReadback::Cors,
            BucketReadback::Lifecycle,
            BucketReadback::Location,
            BucketReadback::Versioning,
            BucketReadback::Policy,
        ] {
            let selected = params();
            let actual = presign_bucket_readback(&selected, operation).unwrap();
            let expected = super::super::presign_url(
                "GET",
                &selected,
                &[(operation.query(), String::new())],
                None,
            )
            .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn object_paths_and_non_read_coordinates_refuse() {
        for path in ["/fixture-bucket/key", "/../key", "/bucket?cors", "/a"] {
            let mut selected = params();
            selected.path = path;
            assert!(presign_bucket_readback(&selected, BucketReadback::Cors).is_err());
        }
        let mut selected = params();
        selected.scheme = "http";
        assert!(presign_bucket_readback(&selected, BucketReadback::Cors).is_err());
        selected.scheme = "https";
        selected.expires_secs = 301;
        assert!(presign_bucket_readback(&selected, BucketReadback::Cors).is_err());
    }
}
