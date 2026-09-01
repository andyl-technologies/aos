//! Content descriptors and platform requirements.
//!
//! ```text
//! {
//!   "mediaType": "application/vnd.oci.image.manifest.v1+json",
//!   "digest": "sha256:...",
//!   "size": 7682,
//!   "platform": { "architecture": "amd64", "os": "linux" }
//! }
//! ```

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{validate_canonical_size, validate_printable_ascii};
use crate::annotations::Annotations;
use crate::canonical::parse_bounded;
use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::limits::MAX_JSON_BYTES;
use crate::media_type::MediaType;

/// Minimum runtime platform requirements attached to an index descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    /// Go-style CPU architecture, such as `amd64` or `arm64`.
    pub architecture: String,
    /// Go-style operating system, such as `linux`.
    pub os: String,
    /// Optional operating-system version requirement.
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
    /// Optional mandatory operating-system features.
    #[serde(rename = "os.features", default, skip_serializing_if = "Vec::is_empty")]
    pub os_features: Vec<String>,
    /// Optional CPU architecture variant, such as `v8`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Reserved future OCI platform features.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

impl Platform {
    /// Validates the v1 platform projection.
    ///
    /// # Errors
    ///
    /// Returns an error when `architecture` or `os` is not a lowercase ASCII
    /// token, an optional field contains control or non-ASCII bytes, or the
    /// reserved `features` field is non-empty.
    pub fn validate(&self) -> Result<()> {
        validate_platform_token(&self.architecture, "platform architecture")?;
        validate_platform_token(&self.os, "platform OS")?;
        if let Some(version) = &self.os_version {
            validate_printable_ascii(version, "platform OS version", false)?;
        }
        for feature in &self.os_features {
            validate_printable_ascii(feature, "platform OS feature", false)?;
        }
        if let Some(variant) = &self.variant {
            validate_printable_ascii(variant, "platform variant", false)?;
        }
        if !self.features.is_empty() {
            return Err(Error::invalid(
                "platform features",
                "the OCI v1 field is reserved and must be empty",
            ));
        }
        Ok(())
    }

    /// Returns a canonical Linux/amd64 platform.
    #[must_use]
    pub fn linux_amd64() -> Self {
        Self {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            os_version: None,
            os_features: Vec::new(),
            variant: None,
            features: Vec::new(),
        }
    }

    /// Returns a canonical Linux/arm64 platform.
    #[must_use]
    pub fn linux_arm64() -> Self {
        Self {
            architecture: "arm64".to_string(),
            os: "linux".to_string(),
            os_version: None,
            os_features: Vec::new(),
            variant: None,
            features: Vec::new(),
        }
    }
}

/// An OCI content descriptor with AOS-admitted media and digest types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// Exact media type of the referenced bytes.
    pub media_type: MediaType,
    /// SHA-256 content digest of the referenced bytes.
    pub digest: Sha256Digest,
    /// Exact byte length of the referenced bytes.
    pub size: u64,
    /// External retrieval URLs, rejected by RFC-0017 admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Unknown and standard descriptor annotations retained in key order.
    #[serde(default, skip_serializing_if = "Annotations::is_empty")]
    pub annotations: Annotations,
    /// Optional RFC 4648 base64-encoded embedded content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Optional type of an artifact manifest targeted by this descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<MediaType>,
    /// Optional platform requirements when the descriptor appears in an index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

impl Descriptor {
    /// Parses and validates one descriptor JSON object within the frozen body cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON exceeds 4 MiB, cannot be decoded, or the
    /// descriptor violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let descriptor: Self = parse_bounded(bytes, "OCI descriptor")?;
        descriptor.validate()?;
        validate_canonical_size(&descriptor)?;
        Ok(descriptor)
    }

    /// Returns the canonical descriptor for the two-byte empty JSON object.
    #[must_use]
    pub fn canonical_empty() -> Self {
        Self {
            media_type: MediaType::OciEmptyJson,
            digest: Sha256Digest::digest(b"{}"),
            size: 2,
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    /// Returns whether this is the canonical empty JSON descriptor.
    #[must_use]
    pub fn is_canonical_empty(&self) -> bool {
        let data_is_empty_json = self.data.as_deref().is_none_or(|data| data == "e30=");
        self.media_type == MediaType::OciEmptyJson
            && self.digest == Sha256Digest::digest(b"{}")
            && self.size == 2
            && self.urls.is_empty()
            && self.annotations.is_empty()
            && data_is_empty_json
            && self.artifact_type.is_none()
            && self.platform.is_none()
    }

    /// Validates descriptor structure, extensions, and optional embedded bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a size outside signed OCI `int64`, external URLs,
    /// invalid annotations or platform data, a non-artifact `artifactType`, or
    /// embedded data whose base64, size, or digest is invalid.
    pub fn validate(&self) -> Result<()> {
        if self.size > i64::MAX as u64 {
            return Err(Error::invalid(
                "descriptor size",
                "size exceeds the OCI signed int64 maximum",
            ));
        }
        if !self.urls.is_empty() {
            return Err(Error::invalid(
                "descriptor urls",
                "external descriptor URLs are not admitted in RFC-0017 v1",
            ));
        }
        self.annotations.validate()?;
        if let Some(artifact_type) = self.artifact_type
            && !artifact_type.is_artifact_payload()
        {
            return Err(Error::invalid(
                "descriptor artifactType",
                "value is not in the AOS JSON artifact allowlist",
            ));
        }
        if let Some(platform) = &self.platform {
            platform.validate()?;
        }
        if let Some(data) = &self.data {
            if data.len() > MAX_JSON_BYTES {
                return Err(Error::JsonTooLarge {
                    document: "embedded descriptor data",
                    limit: MAX_JSON_BYTES,
                    actual: data.len(),
                });
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|error| Error::invalid("descriptor data", error.to_string()))?;
            self.verify(&decoded)?;
        }
        Ok(())
    }

    /// Verifies exact content size and SHA-256 against this descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SizeMismatch`] or [`Error::DigestMismatch`] when the
    /// bytes do not match the descriptor.
    pub fn verify(&self, content: &[u8]) -> Result<()> {
        let actual = u64::try_from(content.len())
            .map_err(|error| Error::invalid("content size", error.to_string()))?;
        if actual != self.size {
            return Err(Error::SizeMismatch {
                expected: self.size,
                actual,
            });
        }
        self.digest.verify(content)
    }
}

fn validate_platform_token(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(Error::invalid(
            field,
            "value must be a lowercase ASCII platform token",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_content_and_embedded_data() {
        let content = b"{}";
        let mut descriptor = Descriptor::canonical_empty();
        descriptor.data = Some("e30=".to_string());
        descriptor.validate().expect("embedded empty JSON");
        descriptor.verify(content).expect("descriptor bytes");

        descriptor.data = Some("e30K".to_string());
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn rejects_external_urls_and_nonartifact_type_extensions() {
        let mut descriptor = Descriptor::canonical_empty();
        descriptor
            .urls
            .push("https://example.invalid/blob".to_string());
        assert!(descriptor.validate().is_err());

        descriptor.urls.clear();
        descriptor.artifact_type = Some(MediaType::OciImageConfig);
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn validates_platform_tokens_and_reserved_features() {
        Platform::linux_amd64().validate().expect("linux/amd64");
        let mut invalid = Platform::linux_arm64();
        invalid.architecture = "ARM64".to_string();
        assert!(invalid.validate().is_err());

        let mut reserved = Platform::linux_arm64();
        reserved.features.push("future".to_string());
        assert!(reserved.validate().is_err());
    }
}
