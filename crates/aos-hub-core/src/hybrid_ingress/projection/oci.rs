//! Closed OCI parse results produced beside object storage.
//!
//! Source identities describe the original bytes. A semantic projection is not
//! a reconstructed config file and cannot replace its source digest or bytes.

use anyhow::{ensure, Context as _, Result};
use aos_oci_types::{
    Annotations, Descriptor, ImageConfig, ImageIndex, ImageManifest, MediaType, Platform,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};

/// Encoded inner OCI projection budget, reserving space in its 64 KiB envelope.
pub const MAX_HYBRID_OCI_PROJECTION_BYTES: usize = 60 * 1024;

/// Closed root document parsed from an exact manifest or index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "document",
    rename_all = "snake_case",
    deny_unknown_fields,
    try_from = "ClosedDocument"
)]
pub enum HybridOciDocumentProjection {
    /// Validated OCI or Docker manifest, retaining descriptor metadata.
    Manifest(ImageManifest),
    /// Validated OCI or Docker index, retaining ordered child descriptors.
    Index(ImageIndex),
}

/// Original root identity and validated descriptor graph declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridOciManifestProjection {
    /// Closed projection format, currently one.
    pub version: u8,
    /// Lowercase SHA-256 of the original root document bytes.
    pub source_sha256: String,
    /// Original root document byte length, independently from encoded projection.
    pub source_size: u32,
    /// Admitted media type of the original document.
    pub media_type: MediaType,
    /// Parsed root graph declaration; config bytes remain at storage.
    pub document: HybridOciDocumentProjection,
}

impl HybridOciManifestProjection {
    /// Parses the full original root document into a bounded semantic result.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or oversized original documents, unsupported
    /// media types or an encoded semantic projection outside its reserved budget.
    pub fn from_bytes(media_type: MediaType, bytes: &[u8]) -> Result<Self> {
        let document = if media_type.is_image_manifest() {
            HybridOciDocumentProjection::Manifest(ImageManifest::from_json(bytes)?)
        } else {
            ensure!(
                media_type.is_image_index(),
                "OCI root media type is unsupported"
            );
            HybridOciDocumentProjection::Index(ImageIndex::from_json(bytes)?)
        };
        let projection = Self {
            version: 1,
            source_sha256: Sha256Digest::digest(bytes).encoded(),
            source_size: u32::try_from(bytes.len()).context("OCI root size exceeds u32")?,
            media_type,
            document,
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Validates the closed format, source identity and descriptor declaration.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, source bounds, media mismatch,
    /// invalid nested documents or an excessive encoded projection.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "OCI root projection version is unsupported"
        );
        validate_source_identity(&self.source_sha256, self.source_size)?;
        match &self.document {
            HybridOciDocumentProjection::Manifest(document) => {
                ensure!(
                    self.media_type.is_image_manifest(),
                    "OCI root projection media mismatch"
                );
                document.validate()?;
                validate_projected_document(&self.document)?;
                ensure!(
                    document
                        .media_type
                        .is_none_or(|media| media == self.media_type),
                    "OCI root document media mismatch"
                );
            }
            HybridOciDocumentProjection::Index(document) => {
                ensure!(
                    self.media_type.is_image_index(),
                    "OCI root projection media mismatch"
                );
                document.validate()?;
                validate_projected_document(&self.document)?;
                ensure!(
                    document
                        .media_type
                        .is_none_or(|media| media == self.media_type),
                    "OCI root document media mismatch"
                );
            }
        }
        validate_encoded_budget(self)
    }
}

/// Minimal content-addressed descriptor required by config inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciInspectionDescriptor {
    /// Digest of the original content, selecting its canonical OCI blob key.
    pub digest: Sha256Digest,
    /// Exact byte count admitted in the repository catalog.
    pub size: u64,
    /// Media type determining parsing or measurement semantics.
    pub media_type: MediaType,
}

impl From<&Descriptor> for OciInspectionDescriptor {
    fn from(descriptor: &Descriptor) -> Self {
        Self {
            digest: descriptor.digest,
            size: descriptor.size,
            media_type: descriptor.media_type,
        }
    }
}

/// Existing metadata interpretation of one layer's uncompressed size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciLayerSizeMeasurement {
    /// Plain tar bytes equal the declared compressed byte count.
    PlainBytes,
    /// Gzip footer ISIZE, modulo 2^32; not full decompression verification.
    GzipIsize32,
    /// Content size explicitly encoded in a zstd frame header.
    ZstdContentSize,
}

/// One ordered layer identity and its independently measured metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciImageConfigLayerSemantics {
    /// Exact repository-admitted layer descriptor identity.
    pub descriptor: OciInspectionDescriptor,
    /// Config's ordered uncompressed content digest.
    pub diff_id: Sha256Digest,
    /// Byte count interpreted under the explicit measurement method.
    pub unpacked_byte_size: u64,
    /// Measurement interpretation; never implies a full layer-content digest.
    pub measurement: OciLayerSizeMeasurement,
}

/// Validated config semantics with a separate original-byte source identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciImageConfigSemanticsV1 {
    /// Closed parser/projection format, currently one.
    pub version: u8,
    /// SHA-256 of the full original config, including omitted runtime/history fields.
    pub source_sha256: String,
    /// Exact original UTF-8 config byte count.
    pub source_size: u32,
    /// Original config media family, independently bound to the request descriptor.
    pub source_media_type: MediaType,
    /// Config-derived target platform.
    #[serde(deserialize_with = "deserialize_closed_platform")]
    pub platform: Platform,
    /// Ordered DiffIDs and descriptor-bound legacy size measurements.
    pub layers: Vec<OciImageConfigLayerSemantics>,
}

impl OciImageConfigSemanticsV1 {
    /// Parses the complete config and retains only graph-admission semantics.
    ///
    /// The caller supplies measurements in exact descriptor order. This parser
    /// validates omitted runtime and history fields before producing a result.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed config, source identity mismatch, invalid
    /// layer count/order/measurements or an excessive encoded projection.
    pub fn from_config_bytes(
        bytes: &[u8],
        config: &OciInspectionDescriptor,
        layers: &[OciInspectionDescriptor],
        measurements: &[u64],
    ) -> Result<Self> {
        validate_config_inspection_request(config, layers)?;
        ensure!(
            bytes.len() as u64 == config.size && Sha256Digest::digest(bytes) == config.digest,
            "OCI config source identity mismatch"
        );
        let parsed = ImageConfig::from_json(bytes)?;
        ensure!(
            parsed.rootfs.diff_ids.len() == layers.len() && measurements.len() == layers.len(),
            "OCI config layer count mismatch"
        );
        let measured_layers = layers
            .iter()
            .zip(&parsed.rootfs.diff_ids)
            .zip(measurements)
            .map(|((descriptor, diff_id), size)| {
                Ok(OciImageConfigLayerSemantics {
                    descriptor: descriptor.clone(),
                    diff_id: *diff_id,
                    unpacked_byte_size: *size,
                    measurement: layer_measurement(descriptor.media_type)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let projection = Self {
            version: 1,
            source_sha256: config.digest.encoded(),
            source_size: u32::try_from(bytes.len()).context("OCI config size exceeds u32")?,
            source_media_type: config.media_type,
            platform: parsed.platform(),
            layers: measured_layers,
        };
        projection.validate_for(config, layers)?;
        Ok(projection)
    }

    /// Validates a persisted closed summary without asserting producer authenticity.
    ///
    /// This checks format and self-consistency only. Admission separately binds
    /// the complete authenticated request and repository/placement evidence.
    /// Historical capture does not refresh or manufacture those proofs.
    ///
    /// # Errors
    ///
    /// Returns an error for source syntax, unsupported format/media, invalid
    /// platform/layer measurements or an excessive encoded semantic result.
    pub fn validate(&self) -> Result<()> {
        let config = OciInspectionDescriptor {
            digest: Sha256Digest::parse(&format!("sha256:{}", self.source_sha256))?,
            size: u64::from(self.source_size),
            media_type: self.source_media_type,
        };
        let layers = self
            .layers
            .iter()
            .map(|layer| layer.descriptor.clone())
            .collect::<Vec<_>>();
        self.validate_for(&config, &layers)
    }

    /// Validates a semantic result against the complete exact inspection request.
    ///
    /// # Errors
    ///
    /// Returns an error for format/source/platform mismatch, changed descriptor
    /// order or measurements, excessive cardinality or encoded size.
    pub fn validate_for(
        &self,
        config: &OciInspectionDescriptor,
        layers: &[OciInspectionDescriptor],
    ) -> Result<()> {
        validate_config_inspection_request(config, layers)?;
        ensure!(
            self.version == 1,
            "OCI config projection version is unsupported"
        );
        validate_source_identity(&self.source_sha256, self.source_size)?;
        ensure!(
            self.source_sha256 == config.digest.encoded()
                && u64::from(self.source_size) == config.size
                && self.source_media_type == config.media_type,
            "OCI config projection source mismatch"
        );
        self.platform.validate()?;
        ensure!(
            self.layers.len() == layers.len(),
            "OCI config projection layer count mismatch"
        );
        for (layer, expected) in self.layers.iter().zip(layers) {
            ensure!(
                &layer.descriptor == expected
                    && layer.measurement == layer_measurement(expected.media_type)?,
                "OCI config projection layer identity mismatch"
            );
            match layer.measurement {
                OciLayerSizeMeasurement::PlainBytes => ensure!(
                    layer.unpacked_byte_size == expected.size,
                    "plain OCI layer size mismatch"
                ),
                OciLayerSizeMeasurement::GzipIsize32 => ensure!(
                    u32::try_from(layer.unpacked_byte_size).is_ok(),
                    "gzip OCI layer ISIZE exceeds u32"
                ),
                OciLayerSizeMeasurement::ZstdContentSize => {}
            }
        }
        validate_encoded_budget(self)
    }

    /// Derives the canonical AOS/Nix selector from the config platform.
    #[must_use]
    pub fn aos_system(&self) -> String {
        aos_system(&self.platform)
    }
}

/// Validates the closed config-and-layer declaration before any provider read.
///
/// # Errors
///
/// Returns an error for unsupported media, source bounds or layer cardinality.
pub fn validate_config_inspection_request(
    config: &OciInspectionDescriptor,
    layers: &[OciInspectionDescriptor],
) -> Result<()> {
    ensure!(
        config.media_type.is_image_config()
            && config.size > 0
            && config.size <= aos_oci_types::limits::MAX_JSON_BYTES as u64,
        "OCI config inspection source is invalid"
    );
    ensure!(
        !layers.is_empty() && layers.len() <= aos_oci_types::limits::MAX_LAYERS_PER_IMAGE,
        "OCI config inspection layer count is invalid"
    );
    for layer in layers {
        let measurement = layer_measurement(layer.media_type)?;
        ensure!(
            layer.size <= crate::storage_work::MAX_OCI_COMPOSE_BYTES,
            "OCI layer inspection size is invalid"
        );
        ensure!(
            measurement != OciLayerSizeMeasurement::GzipIsize32 || layer.size >= 4,
            "gzip OCI layer is truncated"
        );
        ensure!(
            config.media_type == MediaType::OciImageConfig && layer.media_type.is_oci_layer()
                || config.media_type == MediaType::DockerImageConfig
                    && layer.media_type.is_docker_layer(),
            "OCI config and layer media families conflict"
        );
    }
    Ok(())
}

/// Returns the canonical AOS/Nix selector of a validated platform.
#[must_use]
pub fn aos_system(platform: &Platform) -> String {
    match (platform.os.as_str(), platform.architecture.as_str()) {
        ("linux", "amd64") => "x86_64-linux".to_string(),
        ("linux", "arm64") => "aarch64-linux".to_string(),
        (os, architecture) => format!("{architecture}-{os}"),
    }
}

fn layer_measurement(media_type: MediaType) -> Result<OciLayerSizeMeasurement> {
    match media_type {
        MediaType::OciLayerTar | MediaType::DockerLayerTar => {
            Ok(OciLayerSizeMeasurement::PlainBytes)
        }
        MediaType::OciLayerGzip | MediaType::DockerLayerGzip => {
            Ok(OciLayerSizeMeasurement::GzipIsize32)
        }
        MediaType::OciLayerZstd => Ok(OciLayerSizeMeasurement::ZstdContentSize),
        _ => anyhow::bail!("OCI layer measurement media type is unsupported"),
    }
}

fn validate_source_identity(digest: &str, size: u32) -> Result<()> {
    ensure!(
        super::valid_sha256(digest)
            && size > 0
            && size as usize <= aos_oci_types::limits::MAX_JSON_BYTES,
        "OCI projection source identity is invalid"
    );
    Ok(())
}

fn validate_encoded_budget(value: &impl Serialize) -> Result<()> {
    // Stream into a capped sink; never allocate an unbounded encoded projection.
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_HYBRID_OCI_PROJECTION_BYTES)
                .ok_or_else(|| {
                    std::io::Error::other("OCI projection exceeds its encoded budget")
                })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(0), value).context("OCI projection exceeds its encoded budget")
}

#[cfg(test)]
mod tests;

fn validate_projected_document(document: &HybridOciDocumentProjection) -> Result<()> {
    let (annotations, descriptors): (_, Vec<&Descriptor>) = match document {
        HybridOciDocumentProjection::Manifest(document) => (
            &document.annotations,
            std::iter::once(&document.config)
                .chain(document.layers.iter())
                .chain(document.subject.iter())
                .collect(),
        ),
        HybridOciDocumentProjection::Index(document) => (
            &document.annotations,
            document
                .manifests
                .iter()
                .chain(document.subject.iter())
                .collect(),
        ),
    };
    validate_projection_annotations(annotations)?;
    for descriptor in descriptors {
        validate_projection_annotations(&descriptor.annotations)?;
        ensure!(
            descriptor.urls.is_empty() && descriptor.data.is_none(),
            "OCI projection does not admit opaque descriptor content"
        );
    }
    Ok(())
}

// Closed wire wrappers preserve duplicate/unknown-field rejection without
// replacing the shared OCI semantic parser used on original storage bytes.
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "document",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ClosedDocument {
    Manifest(ClosedManifest),
    Index(ClosedIndex),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClosedManifest {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<MediaType>,
    #[serde(default)]
    artifact_type: Option<MediaType>,
    config: ClosedDescriptor,
    layers: Vec<ClosedDescriptor>,
    #[serde(default)]
    subject: Option<ClosedDescriptor>,
    #[serde(default)]
    annotations: Annotations,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClosedIndex {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<MediaType>,
    #[serde(default)]
    artifact_type: Option<MediaType>,
    manifests: Vec<ClosedDescriptor>,
    #[serde(default)]
    subject: Option<ClosedDescriptor>,
    #[serde(default)]
    annotations: Annotations,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClosedDescriptor {
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
    platform: Option<ClosedPlatform>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClosedPlatform {
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

impl TryFrom<ClosedDocument> for HybridOciDocumentProjection {
    type Error = anyhow::Error;

    fn try_from(document: ClosedDocument) -> Result<Self> {
        let document = match document {
            ClosedDocument::Manifest(document) => Self::Manifest(ImageManifest {
                schema_version: document.schema_version,
                media_type: document.media_type,
                artifact_type: document.artifact_type,
                config: document.config.into(),
                layers: document.layers.into_iter().map(Descriptor::from).collect(),
                subject: document.subject.map(Descriptor::from),
                annotations: document.annotations,
            }),
            ClosedDocument::Index(document) => Self::Index(ImageIndex {
                schema_version: document.schema_version,
                media_type: document.media_type,
                artifact_type: document.artifact_type,
                manifests: document
                    .manifests
                    .into_iter()
                    .map(Descriptor::from)
                    .collect(),
                subject: document.subject.map(Descriptor::from),
                annotations: document.annotations,
            }),
        };
        validate_projected_document(&document)?;
        Ok(document)
    }
}

impl From<ClosedDescriptor> for Descriptor {
    fn from(descriptor: ClosedDescriptor) -> Self {
        Self {
            media_type: descriptor.media_type,
            digest: descriptor.digest,
            size: descriptor.size,
            urls: descriptor.urls,
            annotations: descriptor.annotations,
            data: descriptor.data,
            artifact_type: descriptor.artifact_type,
            platform: descriptor.platform.map(Platform::from),
        }
    }
}

impl From<ClosedPlatform> for Platform {
    fn from(platform: ClosedPlatform) -> Self {
        Self {
            architecture: platform.architecture,
            os: platform.os,
            os_version: platform.os_version,
            os_features: platform.os_features,
            variant: platform.variant,
            features: platform.features,
        }
    }
}

fn deserialize_closed_platform<'de, D>(deserializer: D) -> std::result::Result<Platform, D::Error>
where
    D: serde::Deserializer<'de>,
{
    ClosedPlatform::deserialize(deserializer).map(Platform::from)
}

fn validate_projection_annotations(annotations: &Annotations) -> Result<()> {
    annotations.validate()?;
    const KEYS: &[&str] = &[
        "org.opencontainers.image.created",
        "org.opencontainers.image.authors",
        "org.opencontainers.image.url",
        "org.opencontainers.image.documentation",
        "org.opencontainers.image.source",
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.vendor",
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.ref.name",
        "org.opencontainers.image.title",
        "org.opencontainers.image.description",
        "org.opencontainers.image.base.digest",
        "org.opencontainers.image.base.name",
        "dev.andyl.aos.release.name",
        "dev.andyl.aos.release.version",
        "dev.andyl.aos.state-version",
        "dev.andyl.aos.module-abi",
        "dev.andyl.aos.release.tier",
        "dev.andyl.aos.registry",
        "dev.andyl.aos.channel",
        "dev.andyl.aos.registry-root-epoch",
        "dev.andyl.aos.system",
    ];
    ensure!(
        annotations
            .iter()
            .all(|(key, _)| KEYS.contains(&key.as_str())),
        "OCI projection annotation key is unsupported"
    );
    Ok(())
}

/// Parses the existing zstd content-size metadata without decompressing a layer.
///
/// Returns `None` for a truncated header, unsupported magic or an absent content
/// size. This result does not verify a layer content digest or complete frame.
pub fn parse_oci_zstd_content_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 5 || bytes[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return None;
    }
    let descriptor = bytes[4];
    let single_segment = descriptor & 0x20 != 0;
    let dictionary_size = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let size_flag = descriptor >> 6;
    let size_length = match (size_flag, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    if size_length == 0 {
        return None;
    }
    let offset = 5 + usize::from(!single_segment) + dictionary_size;
    let field = bytes.get(offset..offset + size_length)?;
    let mut encoded = [0_u8; 8];
    encoded[..size_length].copy_from_slice(field);
    let size = u64::from_le_bytes(encoded);
    Some(if size_length == 2 { size + 256 } else { size })
}

/// Measures one layer using only its exact admitted header/footer metadata.
///
/// # Errors
///
/// Returns an error for a wrong metadata length, unsupported media or an absent
/// zstd content size. Gzip results remain modulo-2^32 footer ISIZE values.
pub fn measure_oci_layer_metadata(
    descriptor: &OciInspectionDescriptor,
    bytes: &[u8],
) -> Result<u64> {
    match layer_measurement(descriptor.media_type)? {
        OciLayerSizeMeasurement::PlainBytes => {
            ensure!(
                bytes.is_empty(),
                "plain OCI layer does not require metadata bytes"
            );
            Ok(descriptor.size)
        }
        OciLayerSizeMeasurement::GzipIsize32 => {
            ensure!(descriptor.size >= 4, "gzip OCI layer is truncated");
            let footer: [u8; 4] = bytes
                .try_into()
                .context("gzip OCI footer length is invalid")?;
            Ok(u64::from(u32::from_le_bytes(footer)))
        }
        OciLayerSizeMeasurement::ZstdContentSize => {
            ensure!(
                bytes.len() as u64 == descriptor.size.min(18),
                "zstd OCI metadata length is invalid"
            );
            parse_oci_zstd_content_size(bytes).context("zstd OCI layer omits its content size")
        }
    }
}
