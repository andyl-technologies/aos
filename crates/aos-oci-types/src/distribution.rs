//! OCI Distribution error response vocabulary.
//!
//! ```text
//! {
//!   "errors": [
//!     { "code": "MANIFEST_UNKNOWN", "message": "manifest unknown" }
//!   ]
//! }
//! ```
//!
//! AOS-specific diagnostics belong in the bounded `message` and `detail`
//! fields. Servers do not invent private error-code strings because standard
//! clients already understand this closed vocabulary.

use serde::{Deserialize, Serialize};

use crate::canonical::{parse_bounded, to_canonical_json};
use crate::error::{Error, Result};

/// A standard OCI Distribution error code admitted by RFC-0019.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DistributionErrorCode {
    /// A referenced blob is unknown to the repository.
    #[serde(rename = "BLOB_UNKNOWN")]
    BlobUnknown,
    /// An upload request or byte range is invalid.
    #[serde(rename = "BLOB_UPLOAD_INVALID")]
    BlobUploadInvalid,
    /// An upload session is unknown or expired.
    #[serde(rename = "BLOB_UPLOAD_UNKNOWN")]
    BlobUploadUnknown,
    /// A digest spelling or content verification is invalid.
    #[serde(rename = "DIGEST_INVALID")]
    DigestInvalid,
    /// A manifest references a blob not linked to the repository.
    #[serde(rename = "MANIFEST_BLOB_UNKNOWN")]
    ManifestBlobUnknown,
    /// A manifest body fails syntax or semantic admission.
    #[serde(rename = "MANIFEST_INVALID")]
    ManifestInvalid,
    /// A requested manifest is unknown.
    #[serde(rename = "MANIFEST_UNKNOWN")]
    ManifestUnknown,
    /// A repository name is not canonical.
    #[serde(rename = "NAME_INVALID")]
    NameInvalid,
    /// A requested repository is unknown.
    #[serde(rename = "NAME_UNKNOWN")]
    NameUnknown,
    /// A declared or observed size is invalid.
    #[serde(rename = "SIZE_INVALID")]
    SizeInvalid,
    /// A tag is not canonical.
    #[serde(rename = "TAG_INVALID")]
    TagInvalid,
    /// Authentication is missing or invalid.
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,
    /// The authenticated identity lacks permission.
    #[serde(rename = "DENIED")]
    Denied,
    /// The requested operation or media type is unsupported.
    #[serde(rename = "UNSUPPORTED")]
    Unsupported,
    /// The caller exceeded a request-rate limit.
    #[serde(rename = "TOOMANYREQUESTS")]
    TooManyRequests,
}

/// One standard Distribution error entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionError {
    /// Standard machine-readable error code.
    pub code: DistributionErrorCode,
    /// Bounded human-readable diagnostic.
    pub message: String,
    /// Optional structured AOS or protocol detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Top-level Distribution error response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionErrorEnvelope {
    /// One or more errors explaining the failed request.
    pub errors: Vec<DistributionError>,
}

impl DistributionErrorEnvelope {
    /// Parses and validates one Distribution error body within the 4 MiB cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is oversized or malformed, the error list
    /// is empty, a message contains a NUL byte, or a detail contains a
    /// floating-point value that cannot be canonically serialized.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = parse_bounded(bytes, "Distribution error")?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates error presence, messages, detail shape, and the body-size cap.
    ///
    /// # Errors
    ///
    /// Returns an error when there are no errors, a message contains a NUL byte,
    /// detail contains floating point, or canonical JSON exceeds 4 MiB.
    pub fn validate(&self) -> Result<()> {
        if self.errors.is_empty() {
            return Err(Error::invalid(
                "Distribution errors",
                "at least one error entry is required",
            ));
        }
        for error in &self.errors {
            if error.message.contains('\0') {
                return Err(Error::invalid(
                    "Distribution error message",
                    "message contains a NUL byte",
                ));
            }
        }
        to_canonical_json(self).map(|_| ())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_frozen_code() {
        let codes = [
            DistributionErrorCode::BlobUnknown,
            DistributionErrorCode::BlobUploadInvalid,
            DistributionErrorCode::BlobUploadUnknown,
            DistributionErrorCode::DigestInvalid,
            DistributionErrorCode::ManifestBlobUnknown,
            DistributionErrorCode::ManifestInvalid,
            DistributionErrorCode::ManifestUnknown,
            DistributionErrorCode::NameInvalid,
            DistributionErrorCode::NameUnknown,
            DistributionErrorCode::SizeInvalid,
            DistributionErrorCode::TagInvalid,
            DistributionErrorCode::Unauthorized,
            DistributionErrorCode::Denied,
            DistributionErrorCode::Unsupported,
            DistributionErrorCode::TooManyRequests,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).expect("serialize code");
            assert_eq!(
                serde_json::from_str::<DistributionErrorCode>(&json).expect("deserialize code"),
                code
            );
        }
    }

    #[test]
    fn rejects_unknown_codes_empty_envelopes_and_float_detail() {
        assert!(serde_json::from_str::<DistributionErrorCode>(r#""AOS_PRIVATE""#).is_err());
        assert!(
            DistributionErrorEnvelope { errors: Vec::new() }
                .validate()
                .is_err()
        );

        let envelope = DistributionErrorEnvelope {
            errors: vec![DistributionError {
                code: DistributionErrorCode::ManifestInvalid,
                message: "bad manifest".to_string(),
                detail: Some(serde_json::json!({"ratio": 1.5})),
            }],
        };
        assert_eq!(envelope.validate(), Err(Error::FloatingPointNotCanonical));
    }
}
