//! Signed AOS container-release sidecar contracts.
//!
//! A verified registry release may contain one strict sidecar at
//! `containers/v1/index.json`. The signed document binds AOS release identity,
//! the exact OCI index and platform-manifest descriptors, the Nix definition
//! and realized output, and every required evidence referrer:
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "mediaType": "application/vnd.aos.container-release.v1+json",
//!   "identity": {
//!     "release": "1.0.0",
//!     "package": "aos",
//!     "packageVersion": "0.1.0",
//!     "image": "aos"
//!   },
//!   "oci": {
//!     "index": { "mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:...", "size": 512 },
//!     "platformManifests": [
//!       { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:...", "size": 768, "platform": { "architecture": "amd64", "os": "linux" } }
//!     ]
//!   },
//!   "nix": {
//!     "definition": { "attribute": "containerImages.aos", "derivationPath": "/nix/store/...-aos-container.drv" },
//!     "output": { "name": "out", "storePath": "/nix/store/...-aos-container" },
//!     "closure": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.aos.nix-closure.v1+json", "digest": "sha256:...", "size": 640 }
//!   },
//!   "evidence": {
//!     "sbom": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/spdx+json", "digest": "sha256:...", "size": 640 },
//!     "source": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.aos.source-closure.v1+json", "digest": "sha256:...", "size": 640 },
//!     "license": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.aos.license-report.v1+json", "digest": "sha256:...", "size": 640 },
//!     "provenance": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.in-toto+json", "digest": "sha256:...", "size": 640 },
//!     "signature": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.dsse.envelope.v1+json", "digest": "sha256:...", "size": 640 }
//!   }
//! }
//! ```
//!
//! Unlike generic OCI projections, this AOS-owned signed schema rejects
//! unknown fields at every nested object. Descriptors still retain standard
//! OCI annotations, but no unmodelled field may influence signed-release
//! admission without a versioned schema change.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::annotations::Annotations;
use crate::canonical::{parse_bounded, to_canonical_json};
use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::limits::{
    MAX_CONTAINER_RELEASE_IDENTITY_BYTES, MAX_JSON_BYTES, MAX_NIX_DEFINITION_ATTRIBUTE_BYTES,
    MAX_NIX_OUTPUT_NAME_BYTES, MAX_NIX_STORE_PATH_BYTES, MAX_PLATFORMS_PER_INDEX,
};
use crate::media_type::MediaType;
use crate::model::{Descriptor, Platform};

/// Stable registry-relative location of the first container-release sidecar.
pub const CONTAINER_RELEASE_SIDECAR_PATH: &str = "containers/v1/index.json";

/// Schema version carried by [`ContainerRelease`].
pub const CONTAINER_RELEASE_SCHEMA_VERSION: u32 = 1;

/// One strict signed AOS container-release sidecar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerRelease {
    /// Required AOS sidecar schema version, currently `1`.
    pub schema_version: u32,
    /// Required exact AOS container-release media type.
    pub media_type: MediaType,
    /// Signed registry release, package, and logical image identity.
    pub identity: ContainerReleaseIdentity,
    /// Exact OCI index and per-platform manifest roots.
    pub oci: ContainerOciRelease,
    /// Nix definition, realized output, and closure-manifest identity.
    pub nix: ContainerNixProvenance,
    /// Required source, compliance, provenance, and signature evidence.
    pub evidence: ContainerReleaseEvidence,
}

impl ContainerRelease {
    /// Parses and validates one strict signed sidecar within the 4 MiB JSON cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is oversized or malformed, contains
    /// an unknown field, or violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let release: Self = parse_bounded(bytes, "AOS container release")?;
        release.validate()?;
        Ok(release)
    }

    /// Validates every identity, OCI root, Nix output, and evidence role.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema or media type, invalid or
    /// overlong identities, malformed descriptors, duplicate platforms,
    /// invalid Nix paths, or a missing/mistyped evidence role.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTAINER_RELEASE_SCHEMA_VERSION {
            return Err(Error::invalid(
                "container release schemaVersion",
                format!(
                    "expected {CONTAINER_RELEASE_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            ));
        }
        if self.media_type != MediaType::AosContainerRelease {
            return Err(Error::invalid(
                "container release mediaType",
                format!(
                    "expected {}, got {}",
                    MediaType::AosContainerRelease,
                    self.media_type
                ),
            ));
        }

        self.identity.validate()?;
        self.oci.validate()?;
        self.nix.validate()?;
        self.evidence.validate()?;
        validate_unique_release_descriptors(self)?;
        to_canonical_json(self).map(|_| ())
    }
}

/// Signed AOS identities associated with one immutable container release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerReleaseIdentity {
    /// Signed registry release version containing the sidecar.
    pub release: String,
    /// AOS package whose runtime is represented by the image.
    pub package: String,
    /// Exact AOS package version represented by the image.
    pub package_version: String,
    /// Logical container definition name, initially `aos`.
    pub image: String,
}

impl ContainerReleaseIdentity {
    /// Validates the release, package, package-version, and image identities.
    ///
    /// # Errors
    ///
    /// Returns an error when a field is empty, exceeds 255 bytes, is not
    /// printable ASCII, or a package/image name violates its safe-name syntax.
    pub fn validate(&self) -> Result<()> {
        validate_version_identity(&self.release, "container release identity release")?;
        validate_package_name(&self.package)?;
        validate_version_identity(
            &self.package_version,
            "container release identity packageVersion",
        )?;
        validate_image_name(&self.image)
    }
}

/// Exact OCI roots bound by a signed AOS container release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerOciRelease {
    /// Descriptor of the publishable multi-platform OCI image index.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub index: Descriptor,
    /// Ordered descriptors of every platform manifest named by the index.
    #[serde(deserialize_with = "deserialize_strict_descriptors")]
    pub platform_manifests: Vec<Descriptor>,
}

impl ContainerOciRelease {
    /// Validates index and platform-manifest roles, sizes, and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error unless the index is an OCI index descriptor, one to
    /// 256 OCI manifest descriptors carry valid distinct platforms, manifest
    /// digests are unique, and every JSON descriptor is within 4 MiB.
    pub fn validate(&self) -> Result<()> {
        validate_document_descriptor(
            &self.index,
            "container release OCI index",
            MediaType::OciImageIndex,
            PlatformRequirement::Forbidden,
        )?;

        if self.platform_manifests.is_empty() {
            return Err(Error::invalid(
                "container release platformManifests",
                "at least one platform manifest is required",
            ));
        }
        if self.platform_manifests.len() > MAX_PLATFORMS_PER_INDEX {
            return Err(Error::TooManyItems {
                field: "container release platformManifests",
                limit: MAX_PLATFORMS_PER_INDEX,
                actual: self.platform_manifests.len(),
            });
        }

        let mut manifest_digests = BTreeSet::new();
        for manifest in &self.platform_manifests {
            validate_document_descriptor(
                manifest,
                "container release platform manifest",
                MediaType::OciImageManifest,
                PlatformRequirement::Required,
            )?;
            if !manifest_digests.insert(manifest.digest) {
                return Err(Error::invalid(
                    "container release platformManifests",
                    format!("manifest digest {} is duplicated", manifest.digest),
                ));
            }
        }

        for (index, platform) in self.platform_manifests.iter().enumerate() {
            if self.platform_manifests[..index]
                .iter()
                .any(|candidate| candidate.platform == platform.platform)
            {
                let platform = platform
                    .platform
                    .as_ref()
                    .ok_or_else(|| Error::invalid("container release platform", "missing"))?;
                return Err(Error::invalid(
                    "container release platformManifests",
                    format!("platform {} is duplicated", platform_label(platform)),
                ));
            }
        }
        Ok(())
    }
}

/// Nix definition and realized-output provenance for a container image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerNixProvenance {
    /// Nix attribute and derivation that defined the image.
    pub definition: NixDefinitionIdentity,
    /// Named realized Nix output containing the self-contained OCI image.
    pub output: NixOutputIdentity,
    /// OCI referrer manifest for the realized Nix closure inventory.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub closure: Descriptor,
}

impl ContainerNixProvenance {
    /// Validates Nix definition/output identity and the closure referrer role.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid attribute, derivation, output name,
    /// output store path, or closure referrer descriptor.
    pub fn validate(&self) -> Result<()> {
        self.definition.validate()?;
        self.output.validate()?;
        validate_evidence_descriptor(
            &self.closure,
            "container release closure",
            MediaType::AosNixClosure,
        )
    }
}

/// Evaluated Nix definition identity for a container image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NixDefinitionIdentity {
    /// Canonical dotted Nix attribute, such as `containerImages.aos`.
    pub attribute: String,
    /// Exact realized derivation store path that defined the image output.
    pub derivation_path: String,
}

impl NixDefinitionIdentity {
    /// Validates the dotted attribute and derivation store path.
    ///
    /// # Errors
    ///
    /// Returns an error when the attribute is empty, overlong, or contains an
    /// unsafe segment, or when the derivation is not a bounded `.drv` store
    /// path below `/nix/store`.
    pub fn validate(&self) -> Result<()> {
        validate_nix_attribute(&self.attribute)?;
        validate_store_path(
            &self.derivation_path,
            "container release Nix definition derivationPath",
            true,
        )
    }
}

/// Realized Nix output identity for a container image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NixOutputIdentity {
    /// Selected Nix output name, normally `out`.
    pub name: String,
    /// Exact realized store path of the self-contained OCI image output.
    pub store_path: String,
}

impl NixOutputIdentity {
    /// Validates the output name and realized store path.
    ///
    /// # Errors
    ///
    /// Returns an error when the output name is empty, overlong, or unsafe, or
    /// when the output is not a bounded non-derivation path below `/nix/store`.
    pub fn validate(&self) -> Result<()> {
        validate_nix_output_name(&self.name)?;
        validate_store_path(
            &self.store_path,
            "container release Nix output storePath",
            false,
        )
    }
}

/// Required evidence referrers for a signed AOS container release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerReleaseEvidence {
    /// OCI referrer manifest for the SPDX 2.3 JSON software bill of materials.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub sbom: Descriptor,
    /// OCI referrer manifest for the corresponding-source closure.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub source: Descriptor,
    /// OCI referrer manifest for the full-closure license report.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub license: Descriptor,
    /// OCI referrer manifest for the versioned AOS in-toto provenance statement.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub provenance: Descriptor,
    /// OCI referrer manifest for the DSSE signature envelope.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub signature: Descriptor,
}

impl ContainerReleaseEvidence {
    /// Validates all mandatory evidence descriptor roles.
    ///
    /// # Errors
    ///
    /// Returns an error unless every field is an OCI referrer-manifest
    /// descriptor whose `artifactType` exactly matches its required role.
    pub fn validate(&self) -> Result<()> {
        validate_evidence_descriptor(&self.sbom, "container release SBOM", MediaType::SpdxJson)?;
        validate_evidence_descriptor(
            &self.source,
            "container release source",
            MediaType::AosSourceClosure,
        )?;
        validate_evidence_descriptor(
            &self.license,
            "container release license",
            MediaType::AosLicenseReport,
        )?;
        validate_evidence_descriptor(
            &self.provenance,
            "container release provenance",
            MediaType::InTotoJson,
        )?;
        validate_evidence_descriptor(
            &self.signature,
            "container release signature",
            MediaType::DsseEnvelope,
        )
    }
}

#[derive(Clone, Copy)]
enum PlatformRequirement {
    Forbidden,
    Required,
}

fn validate_document_descriptor(
    descriptor: &Descriptor,
    field: &'static str,
    media_type: MediaType,
    platform_requirement: PlatformRequirement,
) -> Result<()> {
    descriptor.validate()?;
    if descriptor.media_type != media_type {
        return Err(Error::invalid(
            field,
            format!(
                "expected mediaType {media_type}, got {}",
                descriptor.media_type
            ),
        ));
    }
    if descriptor.artifact_type.is_some() {
        return Err(Error::invalid(
            field,
            "runnable index and manifest descriptors must not declare artifactType",
        ));
    }
    if descriptor.data.is_some() {
        return Err(Error::invalid(
            field,
            "signed release descriptors must not embed data",
        ));
    }
    match (platform_requirement, descriptor.platform.as_ref()) {
        (PlatformRequirement::Forbidden, Some(_)) => {
            return Err(Error::invalid(
                field,
                "the OCI index descriptor must not declare a platform",
            ));
        }
        (PlatformRequirement::Required, None) => {
            return Err(Error::invalid(
                field,
                "a platform manifest descriptor must declare a platform",
            ));
        }
        (PlatformRequirement::Forbidden, None) | (PlatformRequirement::Required, Some(_)) => {}
    }
    validate_descriptor_json_size(descriptor, field)
}

fn validate_evidence_descriptor(
    descriptor: &Descriptor,
    field: &'static str,
    artifact_type: MediaType,
) -> Result<()> {
    descriptor.validate()?;
    if descriptor.media_type != MediaType::OciImageManifest {
        return Err(Error::invalid(
            field,
            format!(
                "evidence referrer must use mediaType {}, got {}",
                MediaType::OciImageManifest,
                descriptor.media_type
            ),
        ));
    }
    if descriptor.artifact_type != Some(artifact_type) {
        let actual = descriptor
            .artifact_type
            .map_or_else(|| "missing".to_string(), |value| value.to_string());
        return Err(Error::invalid(
            field,
            format!("expected artifactType {artifact_type}, got {actual}"),
        ));
    }
    if descriptor.platform.is_some() {
        return Err(Error::invalid(
            field,
            "evidence referrer descriptors must not declare a platform",
        ));
    }
    if descriptor.data.is_some() {
        return Err(Error::invalid(
            field,
            "signed release descriptors must not embed data",
        ));
    }
    validate_descriptor_json_size(descriptor, field)
}

fn validate_descriptor_json_size(descriptor: &Descriptor, field: &'static str) -> Result<()> {
    if descriptor.size == 0 {
        return Err(Error::invalid(
            field,
            "JSON document descriptor size must be greater than zero",
        ));
    }
    let limit =
        u64::try_from(MAX_JSON_BYTES).map_err(|error| Error::invalid(field, error.to_string()))?;
    if descriptor.size > limit {
        return Err(Error::invalid(
            field,
            format!(
                "descriptor size {} exceeds the {MAX_JSON_BYTES}-byte JSON limit",
                descriptor.size
            ),
        ));
    }
    Ok(())
}

fn validate_unique_release_descriptors(release: &ContainerRelease) -> Result<()> {
    let descriptors = [
        (&release.oci.index, "OCI index"),
        (&release.nix.closure, "closure"),
        (&release.evidence.sbom, "SBOM"),
        (&release.evidence.source, "source"),
        (&release.evidence.license, "license"),
        (&release.evidence.provenance, "provenance"),
        (&release.evidence.signature, "signature"),
    ];
    let mut digests = BTreeSet::new();
    for (descriptor, role) in descriptors {
        if !digests.insert(descriptor.digest) {
            return Err(Error::invalid(
                "container release descriptors",
                format!("{role} reuses descriptor digest {}", descriptor.digest),
            ));
        }
    }
    for descriptor in &release.oci.platform_manifests {
        if !digests.insert(descriptor.digest) {
            return Err(Error::invalid(
                "container release descriptors",
                format!(
                    "platform manifest reuses descriptor digest {}",
                    descriptor.digest
                ),
            ));
        }
    }
    Ok(())
}

fn validate_package_name(value: &str) -> Result<()> {
    validate_identity_length(value, "container release identity package")?;
    let valid_start = value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let valid_bytes = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'_' | b'=' | b'-')
    });
    if !valid_start || !valid_bytes {
        return Err(Error::invalid(
            "container release identity package",
            "use only ASCII letters, digits, '+', '.', '_', '=' and '-', starting with a letter or digit",
        ));
    }
    Ok(())
}

fn validate_image_name(value: &str) -> Result<()> {
    validate_identity_length(value, "container release identity image")?;
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
    }) || value.ends_with('-')
    {
        return Err(Error::invalid(
            "container release identity image",
            "value must match [a-z0-9][a-z0-9-]*",
        ));
    }
    Ok(())
}

fn validate_version_identity(value: &str, field: &'static str) -> Result<()> {
    validate_identity_length(value, field)?;
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(Error::invalid(
            field,
            "value must contain non-space printable ASCII only",
        ));
    }
    Ok(())
}

fn validate_identity_length(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > MAX_CONTAINER_RELEASE_IDENTITY_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_CONTAINER_RELEASE_IDENTITY_BYTES}",
                value.len()
            ),
        ));
    }
    Ok(())
}

fn validate_nix_attribute(value: &str) -> Result<()> {
    let field = "container release Nix definition attribute";
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > MAX_NIX_DEFINITION_ATTRIBUTE_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_NIX_DEFINITION_ATTRIBUTE_BYTES}",
                value.len()
            ),
        ));
    }
    if value.split('.').any(|segment| {
        segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
    }) {
        return Err(Error::invalid(
            field,
            "value must be dot-separated non-empty ASCII attribute segments",
        ));
    }
    Ok(())
}

fn validate_nix_output_name(value: &str) -> Result<()> {
    let field = "container release Nix output name";
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > MAX_NIX_OUTPUT_NAME_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_NIX_OUTPUT_NAME_BYTES}",
                value.len()
            ),
        ));
    }
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
    {
        return Err(Error::invalid(
            field,
            "value must contain ASCII letters, digits, '_', '+' or '-', starting with a letter or digit",
        ));
    }
    Ok(())
}

fn validate_store_path(value: &str, field: &'static str, derivation: bool) -> Result<()> {
    if value.len() > MAX_NIX_STORE_PATH_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_NIX_STORE_PATH_BYTES}",
                value.len()
            ),
        ));
    }
    let Some(name) = value.strip_prefix("/nix/store/") else {
        return Err(Error::invalid(field, "value must be below /nix/store"));
    };
    let Some((store_hash, store_name)) = name.split_once('-') else {
        return Err(Error::invalid(
            field,
            "value must contain a canonical Nix store hash and name",
        ));
    };
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    if store_hash.len() != 32 || !store_hash.bytes().all(|byte| NIX_BASE32.contains(&byte)) {
        return Err(Error::invalid(
            field,
            "store hash must contain exactly 32 lowercase Nix base32 characters",
        ));
    }
    if store_name.is_empty()
        || store_name.contains('/')
        || !store_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'_' | b'?' | b'=' | b'-')
        })
    {
        return Err(Error::invalid(
            field,
            "value must contain one safe Nix store basename",
        ));
    }
    if derivation != store_name.ends_with(".drv") {
        let reason = if derivation {
            "derivation path must end in .drv"
        } else {
            "output store path must not end in .drv"
        };
        return Err(Error::invalid(field, reason));
    }
    Ok(())
}

fn platform_label(platform: &Platform) -> String {
    platform.variant.as_ref().map_or_else(
        || format!("{}/{}", platform.os, platform.architecture),
        |variant| format!("{}/{}/{}", platform.os, platform.architecture, variant),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StrictDescriptor {
    media_type: MediaType,
    digest: Sha256Digest,
    size: u64,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    annotations: Annotations,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    artifact_type: Option<MediaType>,
    #[serde(default)]
    platform: Option<StrictPlatform>,
}

impl From<StrictDescriptor> for Descriptor {
    fn from(value: StrictDescriptor) -> Self {
        Self {
            media_type: value.media_type,
            digest: value.digest,
            size: value.size,
            urls: value.urls,
            annotations: value.annotations,
            data: value.data,
            artifact_type: value.artifact_type,
            platform: value.platform.map(Platform::from),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StrictPlatform {
    architecture: String,
    os: String,
    #[serde(rename = "os.version", default)]
    os_version: Option<String>,
    #[serde(rename = "os.features", default)]
    os_features: Vec<String>,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    features: Vec<String>,
}

impl From<StrictPlatform> for Platform {
    fn from(value: StrictPlatform) -> Self {
        Self {
            architecture: value.architecture,
            os: value.os,
            os_version: value.os_version,
            os_features: value.os_features,
            variant: value.variant,
            features: value.features,
        }
    }
}

fn deserialize_strict_descriptor<'de, D>(
    deserializer: D,
) -> std::result::Result<Descriptor, D::Error>
where
    D: Deserializer<'de>,
{
    StrictDescriptor::deserialize(deserializer).map(Descriptor::from)
}

fn deserialize_strict_descriptors<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<Descriptor>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<StrictDescriptor>::deserialize(deserializer)
        .map(|descriptors| descriptors.into_iter().map(Descriptor::from).collect())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: u64::try_from(label.len()).expect("fixture size"),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    fn release_fixture() -> ContainerRelease {
        let mut platform_manifest = descriptor(MediaType::OciImageManifest, "amd64-manifest");
        platform_manifest.platform = Some(Platform::linux_amd64());
        ContainerRelease {
            schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
            media_type: MediaType::AosContainerRelease,
            identity: ContainerReleaseIdentity {
                release: "1.0.0".to_string(),
                package: "aos".to_string(),
                package_version: "0.1.0".to_string(),
                image: "aos".to_string(),
            },
            oci: ContainerOciRelease {
                index: descriptor(MediaType::OciImageIndex, "index"),
                platform_manifests: vec![platform_manifest],
            },
            nix: ContainerNixProvenance {
                definition: NixDefinitionIdentity {
                    attribute: "containerImages.aos".to_string(),
                    derivation_path:
                        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv".to_string(),
                },
                output: NixOutputIdentity {
                    name: "out".to_string(),
                    store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container"
                        .to_string(),
                },
                closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
            },
            evidence: ContainerReleaseEvidence {
                sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
                source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
                license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
                provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
                signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
            },
        }
    }

    #[test]
    fn accepts_and_round_trips_the_complete_required_contract() {
        let release = release_fixture();
        release.validate().expect("valid release");
        let bytes = to_canonical_json(&release).expect("canonical release");
        assert_eq!(
            ContainerRelease::from_json(&bytes).expect("strict release"),
            release
        );
    }

    #[test]
    fn rejects_unknown_fields_at_every_signed_schema_boundary() {
        let release = release_fixture();
        let mut value = serde_json::to_value(&release).expect("release JSON");
        value
            .as_object_mut()
            .expect("release object")
            .insert("future".to_string(), serde_json::json!(true));
        let bytes = serde_json::to_vec(&value).expect("release bytes");
        assert!(matches!(
            ContainerRelease::from_json(&bytes),
            Err(Error::Json {
                document: "AOS container release",
                ..
            })
        ));

        let mut value = serde_json::to_value(release_fixture()).expect("release JSON");
        value["oci"]["platformManifests"][0]["platform"]["future"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).expect("release bytes");
        assert!(ContainerRelease::from_json(&bytes).is_err());

        let mut value = serde_json::to_value(release_fixture()).expect("release JSON");
        value["evidence"]["sbom"]["future"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).expect("release bytes");
        assert!(ContainerRelease::from_json(&bytes).is_err());
    }

    #[test]
    fn reports_exact_schema_identity_and_media_errors() {
        let mut release = release_fixture();
        release.schema_version = 2;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release schemaVersion",
                reason: "expected 1, got 2".to_string(),
            })
        );

        let mut release = release_fixture();
        release.media_type = MediaType::OciImageIndex;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release mediaType",
                reason: format!(
                    "expected {}, got {}",
                    MediaType::AosContainerRelease,
                    MediaType::OciImageIndex
                ),
            })
        );
    }

    #[test]
    fn enforces_identity_and_nix_provenance_bounds() {
        let mut release = release_fixture();
        release.identity.package = "x".repeat(MAX_CONTAINER_RELEASE_IDENTITY_BYTES + 1);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release identity package",
                reason: format!(
                    "value is {} bytes; the limit is {MAX_CONTAINER_RELEASE_IDENTITY_BYTES}",
                    MAX_CONTAINER_RELEASE_IDENTITY_BYTES + 1
                ),
            })
        );

        let mut release = release_fixture();
        release.nix.definition.attribute = "containerImages..aos".to_string();
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release Nix definition attribute",
                reason: "value must be dot-separated non-empty ASCII attribute segments"
                    .to_string(),
            })
        );

        let mut release = release_fixture();
        release.nix.output.store_path = "/tmp/not-a-store-output".to_string();
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release Nix output storePath",
                reason: "value must be below /nix/store".to_string(),
            })
        );
    }

    #[test]
    fn requires_exact_oci_index_and_platform_manifest_roles() {
        let mut release = release_fixture();
        release.oci.index.media_type = MediaType::OciImageManifest;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release OCI index",
                reason: format!(
                    "expected mediaType {}, got {}",
                    MediaType::OciImageIndex,
                    MediaType::OciImageManifest
                ),
            })
        );

        let mut release = release_fixture();
        release.oci.platform_manifests[0].platform = None;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platform manifest",
                reason: "a platform manifest descriptor must declare a platform".to_string(),
            })
        );

        let mut release = release_fixture();
        let duplicate = release.oci.platform_manifests[0].clone();
        release.oci.platform_manifests.push(duplicate);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platformManifests",
                reason: format!(
                    "manifest digest {} is duplicated",
                    release.oci.platform_manifests[0].digest
                ),
            })
        );

        let mut release = release_fixture();
        let mut duplicate_platform = release.oci.platform_manifests[0].clone();
        duplicate_platform.digest = Sha256Digest::digest(b"second-manifest");
        release.oci.platform_manifests.push(duplicate_platform);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platformManifests",
                reason: "platform linux/amd64 is duplicated".to_string(),
            })
        );
    }

    #[test]
    fn requires_every_evidence_referrer_media_role() {
        let mut release = release_fixture();
        release.evidence.sbom.artifact_type = Some(MediaType::AosLicenseReport);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release SBOM",
                reason: format!(
                    "expected artifactType {}, got {}",
                    MediaType::SpdxJson,
                    MediaType::AosLicenseReport
                ),
            })
        );

        let mut release = release_fixture();
        release.nix.closure.media_type = MediaType::AosNixClosure;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release closure",
                reason: format!(
                    "evidence referrer must use mediaType {}, got {}",
                    MediaType::OciImageManifest,
                    MediaType::AosNixClosure
                ),
            })
        );
    }

    #[test]
    fn bounds_platform_collections_and_json_descriptor_sizes() {
        let mut release = release_fixture();
        release.oci.platform_manifests.clear();
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platformManifests",
                reason: "at least one platform manifest is required".to_string(),
            })
        );

        let mut release = release_fixture();
        let template = release.oci.platform_manifests[0].clone();
        release.oci.platform_manifests = (0..=MAX_PLATFORMS_PER_INDEX)
            .map(|index| Descriptor {
                digest: Sha256Digest::digest(index.to_string().as_bytes()),
                ..template.clone()
            })
            .collect();
        assert_eq!(
            release.validate(),
            Err(Error::TooManyItems {
                field: "container release platformManifests",
                limit: MAX_PLATFORMS_PER_INDEX,
                actual: MAX_PLATFORMS_PER_INDEX + 1,
            })
        );

        let mut release = release_fixture();
        release.oci.index.size = u64::try_from(MAX_JSON_BYTES + 1).expect("fixture size");
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release OCI index",
                reason: format!(
                    "descriptor size {} exceeds the {MAX_JSON_BYTES}-byte JSON limit",
                    MAX_JSON_BYTES + 1
                ),
            })
        );
    }
}
