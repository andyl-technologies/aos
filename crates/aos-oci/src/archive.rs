//! Safe OCI archive ingestion and deterministic OCI/Docker archive export.
//!
//! OCI archives are treated as transport envelopes: extraction accepts only
//! regular files and directories beneath the temporary layout root. Symlinks,
//! hard links, devices, duplicate paths, absolute paths, and parent traversal
//! are rejected before any entry is unpacked.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_oci_types::{ImageIndex, MediaType, RepositoryName, Tag, to_canonical_json};
use serde::Serialize;
use tar::{Builder, EntryType, Header};
use tempfile::{NamedTempFile, TempDir};

use crate::layout::{
    VerifiedImage, copy_uncompressed_layer, open_verified_blob, read_verified_blob,
};
use crate::reference::PlatformSelector;
use crate::verify_layout;

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const NORMALIZED_MTIME: u64 = 1;
const OCI_LAYOUT_MARKER: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;

/// A directory-backed OCI layout, optionally owned by a temporary extraction.
pub struct PreparedLayout {
    root: PathBuf,
    _temporary: Option<TempDir>,
}

impl PreparedLayout {
    /// Returns the directory containing `oci-layout`, `index.json`, and blobs.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Opens a directory layout or safely extracts an OCI archive into a temporary layout.
///
/// The top-level source may be a symlink, matching the conventional Nix
/// result-link workflow. Directory entries and archive members remain subject
/// to the stricter no-link traversal policy.
///
/// # Errors
///
/// Returns an error when the source is neither a directory nor a regular file,
/// the tar stream is malformed, an entry is unsafe or duplicated, or the
/// bounded entry/byte totals are exceeded.
pub fn prepare_layout(source: &Path) -> Result<PreparedLayout> {
    let metadata = fs::metadata(source)
        .with_context(|| format!("reading OCI source metadata at {}", source.display()))?;
    if metadata.is_dir() {
        let root = if source.join("oci-layout").is_file() {
            source.to_path_buf()
        } else if source.join("layout/oci-layout").is_file() {
            source.join("layout")
        } else {
            source.to_path_buf()
        };
        return Ok(PreparedLayout {
            root,
            _temporary: None,
        });
    }
    ensure!(
        metadata.file_type().is_file(),
        "OCI source must be a directory or regular tar file"
    );

    let temporary = tempfile::tempdir().context("creating OCI archive extraction directory")?;
    let file = File::open(source).with_context(|| format!("opening {}", source.display()))?;
    let mut archive = tar::Archive::new(BufReader::new(file));
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);

    let mut paths = BTreeSet::new();
    let mut count = 0_usize;
    let mut total = 0_u64;
    for entry in archive.entries().context("reading OCI archive entries")? {
        let mut entry = entry.context("reading OCI archive entry")?;
        count = count
            .checked_add(1)
            .context("OCI archive entry count overflow")?;
        ensure!(
            count <= MAX_ARCHIVE_ENTRIES,
            "OCI archive exceeds {MAX_ARCHIVE_ENTRIES} entries"
        );

        let entry_type = entry.header().entry_type();
        ensure!(
            matches!(entry_type, EntryType::Regular | EntryType::Directory),
            "OCI archive contains a link or special entry"
        );
        let path = entry
            .path()
            .context("decoding OCI archive path")?
            .into_owned();
        validate_relative_path(&path)?;
        ensure!(
            paths.insert(path.clone()),
            "OCI archive contains duplicate path {}",
            path.display()
        );

        if entry_type == EntryType::Regular {
            total = total
                .checked_add(entry.size())
                .context("OCI archive byte total overflow")?;
            ensure!(
                total <= MAX_ARCHIVE_BYTES,
                "OCI archive exceeds the 64 GiB extraction limit"
            );
        }
        ensure!(
            entry
                .unpack_in(temporary.path())
                .context("unpacking OCI archive entry")?,
            "OCI archive entry escaped the extraction root"
        );
    }

    Ok(PreparedLayout {
        root: temporary.path().to_path_buf(),
        _temporary: Some(temporary),
    })
}

/// Writes a deterministic uncompressed OCI-layout tar archive.
///
/// # Errors
///
/// Returns an error when layout traversal encounters a link or special file,
/// an input changes while being archived, the destination parent is absent, or
/// the temporary archive cannot be atomically persisted.
pub fn write_oci_archive(root: &Path, output: &Path) -> Result<()> {
    let verified = verify_layout(root, None)?;
    let index = selected_index_bytes(&verified)?;
    let mut descriptors = vec![verified.manifest.clone(), verified.config.clone()];
    descriptors.extend(verified.layers.clone());
    descriptors.sort_by_key(|descriptor| descriptor.digest);
    descriptors.dedup_by_key(|descriptor| descriptor.digest);

    atomic_tar(output, |builder| {
        append_directory(builder, Path::new("blobs"))?;
        append_directory(builder, Path::new("blobs/sha256"))?;
        for descriptor in &descriptors {
            let mut file = open_verified_blob(root, descriptor)?;
            let path = PathBuf::from("blobs/sha256").join(descriptor.digest.encoded());
            append_reader(builder, &path, &mut file, descriptor.size, 0o644)?;
        }
        append_bytes(builder, Path::new("index.json"), &index, 0o644)?;
        append_bytes(builder, Path::new("oci-layout"), OCI_LAYOUT_MARKER, 0o644)?;
        Ok(())
    })
}

/// Copies one verified, reachable image graph into a clean OCI layout directory.
///
/// The destination must already exist and be empty. Only the selected index,
/// manifest, config, and ordered layers are copied, so resumable-state debris
/// and stale blobs can never enter the published layout.
///
/// # Errors
///
/// Returns an error when verification fails, the destination is not an empty
/// directory, a source changes, or any output cannot be created exclusively.
pub fn write_oci_layout(root: &Path, output: &Path) -> Result<VerifiedImage> {
    let verified = verify_layout(root, None)?;
    ensure!(output.is_dir(), "OCI layout destination is not a directory");
    ensure!(
        fs::read_dir(output)
            .context("reading OCI layout destination")?
            .next()
            .is_none(),
        "OCI layout destination is not empty"
    );
    let blob_directory = output.join("blobs/sha256");
    fs::create_dir_all(&blob_directory).context("creating OCI blob destination")?;

    write_new_file(&output.join("oci-layout"), OCI_LAYOUT_MARKER)?;
    write_new_file(
        &output.join("index.json"),
        &selected_index_bytes(&verified)?,
    )?;
    let mut descriptors = vec![verified.manifest.clone(), verified.config.clone()];
    descriptors.extend(verified.layers.clone());
    descriptors.sort_by_key(|descriptor| descriptor.digest);
    descriptors.dedup_by_key(|descriptor| descriptor.digest);
    for descriptor in descriptors {
        let mut source = open_verified_blob(root, &descriptor)?;
        let path = blob_directory.join(descriptor.digest.encoded());
        let mut destination = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating OCI blob {}", path.display()))?;
        let copied = std::io::copy(&mut source, &mut destination)?;
        ensure!(copied == descriptor.size, "OCI blob changed while copying");
        destination.sync_all()?;
    }
    verify_layout(output, None)
}

fn selected_index_bytes(verified: &VerifiedImage) -> Result<Vec<u8>> {
    let mut manifest = verified.manifest.clone();
    manifest.platform = Some(verified.platform.clone());
    let index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![manifest],
        subject: None,
        annotations: verified.index_annotations.clone(),
    };
    index.validate()?;
    to_canonical_json(&index).map_err(Into::into)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Writes a deterministic Docker-load archive for one verified platform.
///
/// Layers are decompressed to Docker `layer.tar` members and named by their
/// already-verified DiffIDs. The config bytes are preserved exactly. No Docker
/// or Podman daemon is invoked.
///
/// # Errors
///
/// Returns an error when layout verification fails, a layer cannot be
/// decompressed, a descriptor blob is unavailable, the repository tag is
/// malformed for Docker archive JSON, or the output cannot be persisted.
pub fn write_docker_archive(
    root: &Path,
    output: &Path,
    platform: Option<&PlatformSelector>,
    repository_tags: &[String],
) -> Result<VerifiedImage> {
    for repository_tag in repository_tags {
        validate_docker_repository_tag(repository_tag)?;
    }
    let verified = verify_layout(root, platform)?;
    let parent = output_parent(output);
    ensure!(
        parent.is_dir(),
        "Docker archive output parent does not exist"
    );

    let config_hex = digest_hex(&verified.config.digest)?;
    let config_name = format!("{config_hex}.json");
    let config_bytes = read_verified_blob(root, &verified.config)?;

    let mut layer_files = Vec::new();
    let mut layer_names = Vec::new();
    for ((descriptor, diff_id), index) in verified
        .layers
        .iter()
        .zip(&verified.image_config.rootfs.diff_ids)
        .zip(0_usize..)
    {
        let diff_hex = digest_hex(diff_id)?;
        let layer_name = format!("{diff_hex}/layer.tar");
        let mut temporary = NamedTempFile::new_in(parent)
            .with_context(|| format!("creating temporary Docker layer {index}"))?;
        let source = open_verified_blob(root, descriptor)?;
        let size = copy_uncompressed_layer(source, descriptor.media_type, temporary.as_file_mut())?;
        temporary
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .context("rewinding temporary Docker layer")?;
        layer_files.push((diff_hex, temporary, size));
        layer_names.push(layer_name);
    }

    #[derive(Serialize)]
    struct DockerManifest<'a> {
        #[serde(rename = "Config")]
        config: &'a str,
        #[serde(rename = "RepoTags")]
        repo_tags: &'a [String],
        #[serde(rename = "Layers")]
        layers: &'a [String],
    }
    let manifest = serde_json::to_vec(&[DockerManifest {
        config: &config_name,
        repo_tags: repository_tags,
        layers: &layer_names,
    }])
    .context("encoding Docker archive manifest")?;

    atomic_tar(output, |builder| {
        for (diff_hex, temporary, size) in &mut layer_files {
            append_directory(builder, Path::new(diff_hex))?;
            let layer_name = PathBuf::from(diff_hex.as_str()).join("layer.tar");
            append_reader(builder, &layer_name, temporary.as_file_mut(), *size, 0o644)?;
        }
        append_bytes(builder, Path::new(&config_name), &config_bytes, 0o644)?;
        append_bytes(builder, Path::new("manifest.json"), &manifest, 0o644)?;
        Ok(())
    })?;

    Ok(verified)
}

fn validate_docker_repository_tag(value: &str) -> Result<()> {
    ensure!(
        !value.contains('@'),
        "Docker archive RepoTags must not contain a digest"
    );
    let final_slash = value.rfind('/').map_or(0, |index| index + 1);
    let tag_offset = value[final_slash..]
        .rfind(':')
        .context("Docker archive RepoTag must include a tag")?;
    let split = final_slash + tag_offset;
    let name = &value[..split];
    let tag = &value[split + 1..];
    Tag::parse(tag)?;

    let first = name.split('/').next().unwrap_or_default();
    if name.contains('/')
        && (first.contains('.') || first.contains(':') || first.eq_ignore_ascii_case("localhost"))
    {
        crate::RegistryReference::parse(value)?;
    } else {
        RepositoryName::parse(name)?;
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty(),
        "OCI archive contains an empty path"
    );
    ensure!(!path.is_absolute(), "OCI archive contains an absolute path");
    for component in path.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "OCI archive path contains parent, root, or dot components"
        );
    }
    Ok(())
}

fn atomic_tar(
    output: &Path,
    populate: impl FnOnce(&mut Builder<&mut File>) -> Result<()>,
) -> Result<()> {
    let parent = output_parent(output);
    ensure!(parent.is_dir(), "archive output parent does not exist");
    let mut temporary = NamedTempFile::new_in(parent).context("creating temporary archive")?;
    {
        let mut builder = Builder::new(temporary.as_file_mut());
        builder.mode(tar::HeaderMode::Deterministic);
        populate(&mut builder)?;
        builder.finish().context("finishing tar archive")?;
    }
    temporary
        .as_file_mut()
        .sync_all()
        .context("syncing tar archive")?;
    temporary
        .persist(output)
        .map_err(|error| error.error)
        .with_context(|| format!("persisting archive to {}", output.display()))?;
    Ok(())
}

fn append_directory(builder: &mut Builder<&mut File>, path: &Path) -> Result<()> {
    let mut header = normalized_header(0, 0o755, EntryType::Directory)?;
    builder
        .append_data(&mut header, path, std::io::empty())
        .with_context(|| format!("archiving directory {}", path.display()))
}

fn append_bytes(
    builder: &mut Builder<&mut File>,
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let size = u64::try_from(bytes.len()).context("archive byte length conversion")?;
    append_reader(builder, path, &mut &bytes[..], size, mode)
}

fn append_reader(
    builder: &mut Builder<&mut File>,
    path: &Path,
    reader: &mut impl std::io::Read,
    size: u64,
    mode: u32,
) -> Result<()> {
    let mut header = normalized_header(size, mode, EntryType::Regular)?;
    builder
        .append_data(&mut header, path, reader)
        .with_context(|| format!("archiving {}", path.display()))
}

fn normalized_header(size: u64, mode: u32, entry_type: EntryType) -> Result<Header> {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(NORMALIZED_MTIME);
    header.set_entry_type(entry_type);
    header
        .set_username("")
        .context("setting empty tar username")?;
    header
        .set_groupname("")
        .context("setting empty tar group name")?;
    header.set_cksum();
    Ok(header)
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn digest_hex(digest: &aos_oci_types::Sha256Digest) -> Result<String> {
    digest
        .to_string()
        .strip_prefix("sha256:")
        .map(str::to_owned)
        .context("SHA-256 digest lost its algorithm prefix")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn archive_path_validation_rejects_every_escape_shape() {
        assert!(validate_relative_path(Path::new("blobs/sha256/abc")).is_ok());
        for path in [
            "",
            ".",
            "../index.json",
            "/index.json",
            "blobs/../index.json",
        ] {
            assert!(validate_relative_path(Path::new(path)).is_err(), "{path}");
        }
    }
}
