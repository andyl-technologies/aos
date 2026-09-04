//! Fail-closed OCI layout verification and platform selection.
//!
//! Verification walks from `index.json` through one selected manifest, its
//! config, and every ordered layer. Descriptor size and compressed digest are
//! checked before parsing. Layer streams are then decompressed and compared to
//! the config's ordered DiffIDs, so inspection detects corruption on either
//! side of the compression boundary.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek as _, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use aos_oci_types::limits::MAX_JSON_BYTES;
use aos_oci_types::{
    Annotations, Descriptor, ImageConfig, ImageIndex, ImageManifest, MediaType, Platform,
    Sha256Digest,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::reference::PlatformSelector;

const LAYOUT_VERSION: &str = "1.0.0";
const MAX_INDEX_DEPTH: usize = 8;

struct SecureLayout {
    root: File,
    blobs: File,
}

impl SecureLayout {
    fn open(root: &Path) -> Result<Self> {
        let canonical = fs::canonicalize(root)
            .with_context(|| format!("resolving OCI layout root {}", root.display()))?;
        let root = File::from(
            rustix::fs::open(
                &canonical,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .with_context(|| format!("opening OCI layout root {}", canonical.display()))?,
        );
        let blobs = open_directory_at(&root, "blobs")?;
        let blobs = open_directory_at(&blobs, "sha256")?;
        Ok(Self { root, blobs })
    }

    fn open_root_file(&self, name: &str) -> Result<File> {
        open_regular_at(&self.root, name)
    }

    fn open_blob(&self, digest: &Sha256Digest) -> Result<File> {
        open_regular_at(&self.blobs, &digest.encoded())
    }
}

fn open_directory_at(directory: &File, name: &str) -> Result<File> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening OCI layout directory {name}"))?;
    Ok(File::from(descriptor))
}

fn open_regular_at(directory: &File, name: &str) -> Result<File> {
    ensure!(
        !name.is_empty() && !name.contains('/'),
        "OCI layout file name must be one component"
    );
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening OCI layout file {name}"))?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "OCI layout entry is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "OCI layout files must not be hard-linked"
        );
    }
    Ok(file)
}

/// The verified, selected runnable image projection of an OCI layout.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedImage {
    /// Stable result schema for CLI and tests.
    pub schema: &'static str,
    /// Digest of the exact root `index.json` bytes.
    pub index_digest: Sha256Digest,
    /// Root-index annotations retained in canonical key order.
    pub index_annotations: Annotations,
    /// Descriptor selecting the runnable manifest.
    pub manifest: Descriptor,
    /// Exact selected target platform.
    pub platform: Platform,
    /// Descriptor of the image configuration.
    pub config: Descriptor,
    /// Parsed and validated image configuration.
    pub image_config: ImageConfig,
    /// Ordered compressed layer descriptors.
    pub layers: Vec<Descriptor>,
    /// Total bytes covered by the config and compressed layer descriptors.
    pub compressed_bytes: u64,
    /// Total uncompressed layer-tar bytes verified against DiffIDs.
    pub uncompressed_bytes: u64,
}

/// Verifies an OCI image layout and selects one runnable platform.
///
/// When `platform` is absent the root index must resolve unambiguously to one
/// runnable manifest. Multi-platform indexes require an explicit selector.
///
/// # Errors
///
/// Returns an error for an invalid layout marker, malformed or oversized JSON,
/// unsafe blob paths, descriptor size/digest mismatch, cycles or excessive
/// nested-index depth, ambiguous/missing platforms, config/platform mismatch,
/// unsupported compression, or DiffID mismatch.
pub fn verify_layout(root: &Path, platform: Option<&PlatformSelector>) -> Result<VerifiedImage> {
    let layout = SecureLayout::open(root)?;
    verify_layout_marker(&layout)?;

    let index_bytes = read_root_json(&layout, "index.json", "OCI index")?;
    let index_digest = Sha256Digest::digest(&index_bytes);
    let index = ImageIndex::from_json(&index_bytes).context("validating root OCI index")?;

    let mut visited = BTreeSet::new();
    let selected = select_manifest(&layout, &index, platform, &mut visited, 0)?;
    let manifest_bytes = read_descriptor_bytes(&layout, &selected.descriptor, "image manifest")?;
    let manifest =
        ImageManifest::from_json(&manifest_bytes).context("validating image manifest")?;
    ensure!(
        manifest.artifact_type.is_none(),
        "selected descriptor is an artifact manifest, not a runnable image"
    );

    let config_bytes = read_descriptor_bytes(&layout, &manifest.config, "image config")?;
    let config = ImageConfig::from_json(&config_bytes).context("validating image config")?;
    ensure!(
        config.os == selected.platform.os
            && config.architecture == selected.platform.architecture
            && config.variant == selected.platform.variant,
        "image config platform does not match the selected index descriptor"
    );
    ensure!(
        manifest.layers.len() == config.rootfs.diff_ids.len(),
        "manifest layer count does not match image-config DiffID count"
    );

    let mut compressed_bytes = manifest.config.size;
    let mut uncompressed_bytes = 0_u64;
    for (layer, expected_diff_id) in manifest.layers.iter().zip(&config.rootfs.diff_ids) {
        let mut layer_file = layout.open_blob(&layer.digest)?;
        verify_file_descriptor(&mut layer_file, layer)
            .with_context(|| format!("verifying layer {}", layer.digest))?;
        layer_file.seek(SeekFrom::Start(0))?;
        let (actual_diff_id, size) = uncompressed_digest(layer_file, layer.media_type)
            .with_context(|| format!("decompressing layer {}", layer.digest))?;
        ensure!(
            &actual_diff_id == expected_diff_id,
            "layer {} DiffID mismatch: expected {}, got {}",
            layer.digest,
            expected_diff_id,
            actual_diff_id
        );
        compressed_bytes = compressed_bytes
            .checked_add(layer.size)
            .context("compressed image byte total overflow")?;
        uncompressed_bytes = uncompressed_bytes
            .checked_add(size)
            .context("uncompressed image byte total overflow")?;
    }

    Ok(VerifiedImage {
        schema: "aos.oci.inspect/v1",
        index_digest,
        index_annotations: index.annotations,
        manifest: selected.descriptor,
        platform: selected.platform,
        config: manifest.config,
        image_config: config,
        layers: manifest.layers,
        compressed_bytes,
        uncompressed_bytes,
    })
}

/// Reads the exact root index only when it still matches a verified digest.
///
/// # Errors
///
/// Returns an error when the root path is unsafe, the index is malformed or
/// oversized, or its current bytes no longer match `expected`.
pub fn read_verified_index(root: &Path, expected: &Sha256Digest) -> Result<Vec<u8>> {
    let layout = SecureLayout::open(root)?;
    let bytes = read_root_json(&layout, "index.json", "OCI index")?;
    ensure!(
        Sha256Digest::digest(&bytes) == *expected,
        "OCI index changed after verification"
    );
    ImageIndex::from_json(&bytes).context("validating exact OCI index")?;
    Ok(bytes)
}

#[derive(Clone)]
struct SelectedManifest {
    descriptor: Descriptor,
    platform: Platform,
}

fn select_manifest(
    layout: &SecureLayout,
    index: &ImageIndex,
    selector: Option<&PlatformSelector>,
    visited: &mut BTreeSet<Sha256Digest>,
    depth: usize,
) -> Result<SelectedManifest> {
    let mut results = collect_manifests(layout, index, selector, visited, depth)?;

    if results.is_empty() {
        let requested =
            selector.map_or_else(|| "an unambiguous image".to_string(), ToString::to_string);
        bail!("OCI index does not contain {requested}");
    }
    ensure!(
        results.len() == 1,
        "OCI index resolves to multiple runnable manifests for the selected platform"
    );
    results.pop().context("selected OCI manifest disappeared")
}

fn collect_manifests(
    layout: &SecureLayout,
    index: &ImageIndex,
    selector: Option<&PlatformSelector>,
    visited: &mut BTreeSet<Sha256Digest>,
    depth: usize,
) -> Result<Vec<SelectedManifest>> {
    ensure!(
        depth <= MAX_INDEX_DEPTH,
        "OCI index nesting exceeds {MAX_INDEX_DEPTH}"
    );
    let mut results = Vec::new();
    for descriptor in &index.manifests {
        if descriptor.media_type.is_image_manifest() {
            let matches = match (selector, descriptor.platform.as_ref()) {
                (Some(selector), Some(platform)) => selector.matches(platform),
                (Some(_), None) => false,
                (None, _) => true,
            };
            if matches {
                let platform = descriptor
                    .platform
                    .clone()
                    .or_else(|| selector.map(selector_platform))
                    .context("runnable manifest descriptor lacks a platform")?;
                results.push(SelectedManifest {
                    descriptor: descriptor.clone(),
                    platform,
                });
            }
            continue;
        }
        ensure!(
            descriptor.media_type.is_image_index(),
            "index contains a non-manifest descriptor"
        );
        if let (Some(selector), Some(platform)) = (selector, descriptor.platform.as_ref())
            && !selector.matches(platform)
        {
            continue;
        }
        ensure!(
            visited.insert(descriptor.digest),
            "OCI index graph contains a cycle at {}",
            descriptor.digest
        );
        let nested_bytes = read_descriptor_bytes(layout, descriptor, "nested image index")?;
        let nested = ImageIndex::from_json(&nested_bytes).context("validating nested OCI index")?;
        results.extend(collect_manifests(
            layout,
            &nested,
            selector,
            visited,
            depth + 1,
        )?);
        visited.remove(&descriptor.digest);
    }
    Ok(results)
}

fn selector_platform(selector: &PlatformSelector) -> Platform {
    Platform {
        architecture: selector.architecture.clone(),
        os: selector.os.clone(),
        os_version: None,
        os_features: Vec::new(),
        variant: selector.variant.clone(),
        features: Vec::new(),
    }
}

fn verify_layout_marker(layout: &SecureLayout) -> Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Marker {
        image_layout_version: String,
    }

    let bytes = read_root_json(layout, "oci-layout", "OCI layout marker")?;
    let marker: Marker = serde_json::from_slice(&bytes).context("decoding OCI layout marker")?;
    ensure!(
        marker.image_layout_version == LAYOUT_VERSION,
        "unsupported OCI layout version {}",
        marker.image_layout_version
    );
    Ok(())
}

fn read_descriptor_bytes(
    layout: &SecureLayout,
    descriptor: &Descriptor,
    label: &str,
) -> Result<Vec<u8>> {
    ensure!(
        descriptor.size <= u64::try_from(MAX_JSON_BYTES).context("JSON limit conversion")?,
        "{label} exceeds the {MAX_JSON_BYTES}-byte JSON limit"
    );
    let mut file = layout.open_blob(&descriptor.digest)?;
    let bytes = read_limited_file(&mut file, label, MAX_JSON_BYTES)?;
    descriptor
        .verify(&bytes)
        .with_context(|| format!("verifying {label} descriptor"))?;
    Ok(bytes)
}

fn read_root_json(layout: &SecureLayout, name: &str, label: &str) -> Result<Vec<u8>> {
    let mut file = layout.open_root_file(name)?;
    read_limited_file(&mut file, label, MAX_JSON_BYTES)
}

fn read_limited_file(file: &mut File, label: &str, limit: usize) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.len() <= u64::try_from(limit).context("file limit conversion")?,
        "{label} exceeds the {limit}-byte limit"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    ensure!(bytes.len() <= limit, "{label} changed or exceeds its limit");
    Ok(bytes)
}

#[cfg(test)]
fn blob_path(root: &Path, digest: &Sha256Digest) -> Result<std::path::PathBuf> {
    let digest = digest.to_string();
    let hex = digest
        .strip_prefix("sha256:")
        .context("AOS OCI digest lost its sha256 prefix")?;
    ensure!(
        hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid SHA-256 blob path"
    );
    Ok(root.join("blobs").join("sha256").join(hex))
}

fn verify_file_descriptor(file: &mut File, descriptor: &Descriptor) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.len() == descriptor.size,
        "descriptor size mismatch: expected {}, got {}",
        descriptor.size,
        metadata.len()
    );
    file.seek(SeekFrom::Start(0))?;
    let (digest, size) = digest_reader(BufReader::new(file))?;
    ensure!(
        size == descriptor.size,
        "descriptor size changed while reading"
    );
    ensure!(
        digest == descriptor.digest,
        "descriptor digest mismatch: expected {}, got {}",
        descriptor.digest,
        digest
    );
    Ok(())
}

fn uncompressed_digest(file: File, media_type: MediaType) -> Result<(Sha256Digest, u64)> {
    let file = BufReader::new(file);
    match media_type {
        MediaType::OciLayerTar | MediaType::DockerLayerTar => digest_reader(file),
        MediaType::OciLayerGzip | MediaType::DockerLayerGzip => {
            digest_reader(flate2::read::MultiGzDecoder::new(file))
        }
        MediaType::OciLayerZstd => {
            let decoder = zstd::stream::read::Decoder::new(file).context("opening zstd layer")?;
            digest_reader(decoder)
        }
        _ => bail!("unsupported runnable layer media type {media_type}"),
    }
}

fn digest_reader(mut reader: impl Read) -> Result<(Sha256Digest, u64)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = reader.read(&mut buffer).context("reading OCI content")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        size = size
            .checked_add(u64::try_from(count).context("read size conversion")?)
            .context("OCI content size overflow")?;
    }
    let digest = Sha256Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))?;
    Ok((digest, size))
}

/// Streams one compressed layer into an uncompressed tar writer.
///
/// This crate-private helper is shared with Docker archive export.
pub(crate) fn copy_uncompressed_layer(
    file: File,
    media_type: MediaType,
    writer: &mut impl io::Write,
) -> Result<u64> {
    let file = BufReader::new(file);
    let size = match media_type {
        MediaType::OciLayerTar | MediaType::DockerLayerTar => {
            io::copy(&mut file.take(u64::MAX), writer)
        }
        MediaType::OciLayerGzip | MediaType::DockerLayerGzip => {
            io::copy(&mut flate2::read::MultiGzDecoder::new(file), writer)
        }
        MediaType::OciLayerZstd => {
            let mut decoder =
                zstd::stream::read::Decoder::new(file).context("opening zstd layer")?;
            io::copy(&mut decoder, writer)
        }
        _ => bail!("unsupported runnable layer media type {media_type}"),
    }
    .context("decompressing OCI layer")?;
    Ok(size)
}

/// Opens one descriptor blob through retained no-follow directory handles.
pub(crate) fn open_verified_blob(root: &Path, descriptor: &Descriptor) -> Result<File> {
    let layout = SecureLayout::open(root)?;
    let mut file = layout.open_blob(&descriptor.digest)?;
    verify_file_descriptor(&mut file, descriptor)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Reads one bounded descriptor blob after exact verification.
pub(crate) fn read_verified_blob(root: &Path, descriptor: &Descriptor) -> Result<Vec<u8>> {
    ensure!(
        descriptor.size <= u64::try_from(MAX_JSON_BYTES).context("JSON limit conversion")?,
        "descriptor exceeds the JSON limit"
    );
    let mut file = open_verified_blob(root, descriptor)?;
    read_limited_file(&mut file, "OCI descriptor blob", MAX_JSON_BYTES)
}

/// Reads one root layout file through the retained root descriptor.
pub(crate) fn read_root_file(root: &Path, name: &str) -> Result<Vec<u8>> {
    let layout = SecureLayout::open(root)?;
    let mut file = layout.open_root_file(name)?;
    read_limited_file(&mut file, name, MAX_JSON_BYTES)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn selector_platform_preserves_variant() {
        let selector = PlatformSelector::parse("linux/arm64/v8").expect("selector");
        let platform = selector_platform(&selector);
        assert_eq!(platform.architecture, "arm64");
        assert_eq!(platform.variant.as_deref(), Some("v8"));
    }

    #[test]
    fn blob_paths_never_use_digest_separators() {
        let digest = Sha256Digest::digest(b"blob");
        let path = blob_path(Path::new("layout"), &digest).expect("blob path");
        assert!(path.starts_with("layout/blobs/sha256"));
        assert_eq!(
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::len),
            Some(64)
        );
    }

    #[test]
    fn gzip_layers_consume_every_member_and_reject_trailing_garbage() {
        fn member(bytes: &[u8]) -> Vec<u8> {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
            encoder.write_all(bytes).expect("gzip member");
            encoder.finish().expect("finish gzip member")
        }

        let mut encoded = member(b"first");
        encoded.extend_from_slice(&member(b"second"));
        let mut file = tempfile::NamedTempFile::new().expect("gzip fixture");
        file.write_all(&encoded).expect("write gzip fixture");
        let mut output = Vec::new();
        copy_uncompressed_layer(
            file.reopen().expect("reopen gzip fixture"),
            MediaType::OciLayerGzip,
            &mut output,
        )
        .expect("decode every gzip member");
        assert_eq!(output, b"firstsecond");

        file.write_all(b"garbage").expect("append garbage");
        assert!(
            copy_uncompressed_layer(
                file.reopen().expect("reopen malformed fixture"),
                MediaType::OciLayerGzip,
                &mut Vec::new(),
            )
            .is_err()
        );
    }
}
