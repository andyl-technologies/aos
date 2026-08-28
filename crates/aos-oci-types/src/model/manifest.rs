//! OCI image manifests and multi-platform indexes.
//!
//! ```text
//! manifest = schemaVersion + config descriptor + ordered layer descriptors
//! index    = schemaVersion + ordered manifest descriptors and platforms
//! artifact = OCI manifest + artifactType + subject + empty config + payload layers
//! ```

use serde::{Deserialize, Serialize};

use super::{Descriptor, validate_canonical_size};
use crate::annotations::Annotations;
use crate::canonical::parse_bounded;
use crate::error::{Error, Result};
use crate::limits::{
    MAX_DESCRIPTORS_PER_OBJECT, MAX_JSON_BYTES, MAX_LAYERS_PER_IMAGE, MAX_PLATFORMS_PER_INDEX,
    SCHEMA_VERSION,
};
use crate::media_type::MediaType;

/// An OCI image manifest or Docker schema 2 manifest projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    /// Required schema version, always `2` for accepted documents.
    pub schema_version: u32,
    /// Optional outer document media type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
    /// Required artifact type for an RFC-0015 artifact manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<MediaType>,
    /// Descriptor of the image or empty artifact configuration.
    pub config: Descriptor,
    /// Ordered filesystem layers or type-specific artifact payload descriptors.
    pub layers: Vec<Descriptor>,
    /// Optional referred manifest; required for RFC-0015 artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    /// Unknown and standard annotations retained in key order.
    #[serde(default, skip_serializing_if = "Annotations::is_empty")]
    pub annotations: Annotations,
}

impl ImageManifest {
    /// Parses and validates one manifest within the frozen 4 MiB body cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is oversized or malformed, or when the
    /// decoded manifest violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = parse_bounded(bytes, "OCI manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates schema, descriptors, media compatibility, and artifact shape.
    ///
    /// # Errors
    ///
    /// Returns an error for a schema other than 2, too many descriptors or
    /// runnable layers, invalid nested descriptors, incompatible OCI/Docker
    /// media families, or an artifact that lacks its exact empty-config,
    /// subject, and type-specific payload shape.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::invalid(
                "manifest schemaVersion",
                format!("expected {SCHEMA_VERSION}, got {}", self.schema_version),
            ));
        }
        if self.layers.is_empty() {
            return Err(Error::invalid(
                "manifest layers",
                "at least one descriptor is required",
            ));
        }
        let descriptor_count = 1_usize
            .checked_add(self.layers.len())
            .and_then(|count| count.checked_add(usize::from(self.subject.is_some())))
            .ok_or_else(|| Error::invalid("manifest descriptors", "count overflow"))?;
        ensure_count(
            "manifest descriptors",
            descriptor_count,
            MAX_DESCRIPTORS_PER_OBJECT,
        )?;

        self.config.validate()?;
        for layer in &self.layers {
            layer.validate()?;
        }
        if let Some(subject) = &self.subject {
            subject.validate()?;
            if !subject.media_type.is_image_manifest() && !subject.media_type.is_image_index() {
                return Err(Error::invalid(
                    "manifest subject",
                    "subject must identify an allowlisted manifest or index",
                ));
            }
        }
        self.annotations.validate()?;

        if let Some(artifact_type) = self.artifact_type {
            self.validate_artifact(artifact_type)?;
        } else {
            self.validate_runnable()?;
        }
        validate_canonical_size(self)
    }

    fn validate_runnable(&self) -> Result<()> {
        ensure_count(
            "runnable image layers",
            self.layers.len(),
            MAX_LAYERS_PER_IMAGE,
        )?;

        match self.config.media_type {
            MediaType::OciImageConfig => {
                if self.media_type == Some(MediaType::DockerImageManifest) {
                    return Err(Error::invalid(
                        "manifest mediaType",
                        "Docker manifest cannot reference an OCI image config",
                    ));
                }
                if self
                    .layers
                    .iter()
                    .any(|layer| !layer.media_type.is_oci_layer())
                {
                    return Err(Error::invalid(
                        "manifest layers",
                        "OCI image config requires OCI distributable layer media types",
                    ));
                }
            }
            MediaType::DockerImageConfig => {
                if self.media_type == Some(MediaType::OciImageManifest) {
                    return Err(Error::invalid(
                        "manifest mediaType",
                        "OCI manifest cannot reference a Docker image config",
                    ));
                }
                if self
                    .layers
                    .iter()
                    .any(|layer| !layer.media_type.is_docker_layer())
                {
                    return Err(Error::invalid(
                        "manifest layers",
                        "Docker image config requires Docker schema 2 layer media types",
                    ));
                }
            }
            _ => {
                return Err(Error::invalid(
                    "manifest config",
                    "runnable image requires an OCI or Docker image config",
                ));
            }
        }
        if self
            .media_type
            .is_some_and(|media_type| !media_type.is_image_manifest())
        {
            return Err(Error::invalid(
                "manifest mediaType",
                "outer media type must identify an OCI or Docker schema 2 manifest",
            ));
        }
        Ok(())
    }

    fn validate_artifact(&self, artifact_type: MediaType) -> Result<()> {
        if self.media_type != Some(MediaType::OciImageManifest) {
            return Err(Error::invalid(
                "artifact manifest mediaType",
                "artifact manifests require the explicit OCI image manifest media type",
            ));
        }
        if !artifact_type.is_artifact_payload() {
            return Err(Error::invalid(
                "artifactType",
                "value is not in the AOS JSON artifact allowlist",
            ));
        }
        if !self.config.is_canonical_empty() {
            return Err(Error::invalid(
                "artifact config",
                "artifact manifests require the canonical empty JSON descriptor",
            ));
        }
        if self.subject.is_none() {
            return Err(Error::invalid(
                "artifact subject",
                "artifact manifests require a subject descriptor",
            ));
        }
        let json_payload = match artifact_type {
            MediaType::AosSourceClosure => {
                if self.layers.len() != 2
                    || self.layers[0].media_type != MediaType::AosSourceClosure
                    || self.layers[1].media_type != MediaType::AosSourceArchive
                {
                    return Err(Error::invalid(
                        "artifact layers",
                        "source-closure artifacts require ordered JSON inventory and source archive descriptors",
                    ));
                }
                &self.layers[0]
            }
            _ => {
                if self.layers.len() != 1 || self.layers[0].media_type != artifact_type {
                    return Err(Error::invalid(
                        "artifact layers",
                        "JSON artifacts require exactly one payload matching artifactType",
                    ));
                }
                &self.layers[0]
            }
        };
        let maximum_payload_size = u64::try_from(MAX_JSON_BYTES)
            .map_err(|error| Error::invalid("artifact layer size", error.to_string()))?;
        if json_payload.size > maximum_payload_size {
            return Err(Error::invalid(
                "artifact layer size",
                format!("JSON payload exceeds the {MAX_JSON_BYTES}-byte limit"),
            ));
        }
        Ok(())
    }
}

/// An OCI image index or Docker schema 2 manifest-list projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    /// Required schema version, always `2` for accepted documents.
    pub schema_version: u32,
    /// Optional outer document media type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MediaType>,
    /// Reserved artifact type, not admitted on indexes in RFC-0015 v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<MediaType>,
    /// Ordered descriptors of platform manifests or nested indexes.
    pub manifests: Vec<Descriptor>,
    /// Optional referred manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    /// Unknown and standard annotations retained in key order.
    #[serde(default, skip_serializing_if = "Annotations::is_empty")]
    pub annotations: Annotations,
}

impl ImageIndex {
    /// Parses and validates one index within the frozen 4 MiB body cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is oversized or malformed, or when the
    /// decoded index violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let index: Self = parse_bounded(bytes, "OCI index")?;
        index.validate()?;
        Ok(index)
    }

    /// Validates schema, descriptor media, platforms, annotations, and bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for a schema other than 2, a non-index outer media type,
    /// an index artifact type, invalid nested descriptors, more than 1,024
    /// descriptors, or more than 256 platform-bearing entries.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::invalid(
                "index schemaVersion",
                format!("expected {SCHEMA_VERSION}, got {}", self.schema_version),
            ));
        }
        if self
            .media_type
            .is_some_and(|media_type| !media_type.is_image_index())
        {
            return Err(Error::invalid(
                "index mediaType",
                "outer media type must identify an OCI index or Docker manifest list",
            ));
        }
        if self.artifact_type.is_some() {
            return Err(Error::invalid(
                "index artifactType",
                "artifact indexes are not admitted in RFC-0015 v1",
            ));
        }
        let descriptor_count = self
            .manifests
            .len()
            .checked_add(usize::from(self.subject.is_some()))
            .ok_or_else(|| Error::invalid("index descriptors", "count overflow"))?;
        ensure_count(
            "index descriptors",
            descriptor_count,
            MAX_DESCRIPTORS_PER_OBJECT,
        )?;
        let platform_count = self
            .manifests
            .iter()
            .filter(|descriptor| descriptor.platform.is_some())
            .count();
        ensure_count("index platforms", platform_count, MAX_PLATFORMS_PER_INDEX)?;

        for descriptor in &self.manifests {
            descriptor.validate()?;
            if !descriptor.media_type.is_image_manifest() && !descriptor.media_type.is_image_index()
            {
                return Err(Error::invalid(
                    "index manifest descriptor",
                    "descriptor must identify an allowlisted manifest or index",
                ));
            }
        }
        if let Some(subject) = &self.subject {
            subject.validate()?;
            if !subject.media_type.is_image_manifest() && !subject.media_type.is_image_index() {
                return Err(Error::invalid(
                    "index subject",
                    "subject must identify an allowlisted manifest or index",
                ));
            }
        }
        self.annotations.validate()?;
        validate_canonical_size(self)
    }
}

fn ensure_count(field: &'static str, actual: usize, limit: usize) -> Result<()> {
    if actual > limit {
        return Err(Error::TooManyItems {
            field,
            limit,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::digest::Sha256Digest;
    use crate::model::Platform;

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

    fn runnable_manifest() -> ImageManifest {
        ImageManifest {
            schema_version: SCHEMA_VERSION,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: None,
            config: descriptor(MediaType::OciImageConfig, "config"),
            layers: vec![descriptor(MediaType::OciLayerGzip, "layer")],
            subject: None,
            annotations: Annotations::new(),
        }
    }

    #[test]
    fn accepts_runnable_and_artifact_manifest_shapes() {
        runnable_manifest().validate().expect("runnable manifest");

        let payload = descriptor(MediaType::SpdxJson, "spdx");
        let artifact = ImageManifest {
            schema_version: SCHEMA_VERSION,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: Some(MediaType::SpdxJson),
            config: Descriptor::canonical_empty(),
            layers: vec![payload],
            subject: Some(descriptor(MediaType::OciImageManifest, "subject")),
            annotations: Annotations::new(),
        };
        artifact.validate().expect("artifact manifest");

        let source_artifact = ImageManifest {
            schema_version: SCHEMA_VERSION,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: Some(MediaType::AosSourceClosure),
            config: Descriptor::canonical_empty(),
            layers: vec![
                descriptor(MediaType::AosSourceClosure, "source-inventory"),
                descriptor(MediaType::AosSourceArchive, "source-archive"),
            ],
            subject: Some(descriptor(MediaType::OciImageIndex, "subject-index")),
            annotations: Annotations::new(),
        };
        source_artifact
            .validate()
            .expect("source artifact manifest");
    }

    #[test]
    fn rejects_mixed_media_families_and_malformed_artifacts() {
        let mut mixed = runnable_manifest();
        mixed.layers[0].media_type = MediaType::DockerLayerGzip;
        assert!(mixed.validate().is_err());

        let mut artifact = runnable_manifest();
        artifact.artifact_type = Some(MediaType::SpdxJson);
        assert!(artifact.validate().is_err());

        let mut oversized = ImageManifest {
            schema_version: SCHEMA_VERSION,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: Some(MediaType::SpdxJson),
            config: Descriptor::canonical_empty(),
            layers: vec![descriptor(MediaType::SpdxJson, "payload")],
            subject: Some(descriptor(MediaType::OciImageManifest, "subject")),
            annotations: Annotations::new(),
        };
        oversized.layers[0].size = u64::try_from(MAX_JSON_BYTES + 1).expect("fixture size");
        assert!(oversized.validate().is_err());

        let mut source = ImageManifest {
            schema_version: SCHEMA_VERSION,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: Some(MediaType::AosSourceClosure),
            config: Descriptor::canonical_empty(),
            layers: vec![
                descriptor(MediaType::AosSourceClosure, "source-inventory"),
                descriptor(MediaType::AosSourceArchive, "source-archive"),
            ],
            subject: Some(descriptor(MediaType::OciImageIndex, "subject-index")),
            annotations: Annotations::new(),
        };
        source.layers.swap(0, 1);
        assert!(source.validate().is_err());

        let mut non_source = source;
        non_source.layers.swap(0, 1);
        non_source.artifact_type = Some(MediaType::SpdxJson);
        assert!(non_source.validate().is_err());
    }

    #[test]
    fn enforces_layer_descriptor_and_platform_counts() {
        let mut manifest = runnable_manifest();
        manifest.layers = (0..=MAX_LAYERS_PER_IMAGE)
            .map(|index| descriptor(MediaType::OciLayerGzip, &format!("layer-{index}")))
            .collect();
        assert!(manifest.validate().is_err());

        let mut manifest_descriptors = runnable_manifest();
        manifest_descriptors.artifact_type = Some(MediaType::SpdxJson);
        manifest_descriptors.layers = (0..MAX_DESCRIPTORS_PER_OBJECT)
            .map(|index| descriptor(MediaType::SpdxJson, &format!("artifact-{index}")))
            .collect();
        manifest_descriptors.subject = Some(descriptor(MediaType::OciImageManifest, "subject"));
        assert!(manifest_descriptors.validate().is_err());

        let manifests = (0..=MAX_PLATFORMS_PER_INDEX)
            .map(|index| {
                let mut entry = descriptor(MediaType::OciImageManifest, &format!("m-{index}"));
                entry.platform = Some(Platform::linux_amd64());
                entry
            })
            .collect();
        let index = ImageIndex {
            schema_version: SCHEMA_VERSION,
            media_type: Some(MediaType::OciImageIndex),
            artifact_type: None,
            manifests,
            subject: None,
            annotations: Annotations::new(),
        };
        assert!(index.validate().is_err());
    }

    #[test]
    fn rejects_schema_one_before_graph_use() {
        let mut manifest = runnable_manifest();
        manifest.schema_version = 1;
        assert!(manifest.validate().is_err());
    }
}
