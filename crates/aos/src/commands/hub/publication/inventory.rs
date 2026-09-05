//! Inventories and pins publication files while validating paths, hashes, and size limits.

use anyhow::{Context as _, Result};
use aos_remote::hub_types;

/// Keeps the admitted publication manifest with its pinned root directory handle.
pub(super) struct PinnedPublication {
    /// Admitted manifest used to begin the staged publication.
    pub(super) request: hub_types::BeginRegistryPublicationRequest,
    /// Directory handle used to open objects beneath the admitted root.
    pub(super) root: std::os::fd::OwnedFd,
}

// A complete package origin includes immutable Git/index objects and paired
// narinfo/NAR cache objects. The supported catalog exceeds twenty thousand
// files, so keep admission bounded at a capacity that leaves useful headroom
// for catalog and history growth between releases.
/// Bounds the number of objects admitted into one publication.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) const MAX_PUBLICATION_OBJECTS: usize = 50_000;

const MAX_PUBLICATION_ENTRIES: usize = 50_000;

const MAX_PUBLICATION_PATH_BYTES: usize = 512;

const MAX_PUBLICATION_DIRECTORY_DEPTH: usize = 32;

/// Inventories a publication root and validates the complete object set.
///
/// # Errors
///
/// Returns an error if files cannot be read or violate publication path, size, or hash rules.
pub(super) fn publication_from_root(
    root: &std::path::Path,
    registry: &str,
) -> Result<PinnedPublication> {
    use sha2::{Digest as _, Sha256};

    let mut objects = std::collections::BTreeMap::new();
    let mut entries = 0;
    let root = open_publication_root(root)?;
    collect_publication_objects(&root, "", 0, &mut entries, &mut objects)?;
    validate_publication_pack_indexes(&root, &objects)?;
    validate_publication_nar_urls(&root, &objects)?;
    let refs_object = objects
        .get("info/refs")
        .context("publication surface has no info/refs")?;
    anyhow::ensure!(
        refs_object.byte_size <= 4 * 1024 * 1024,
        "publication info/refs exceeds its 4194304 byte limit"
    );
    let refs_file = snapshot_publication_object(&root, refs_object)?;
    let refs = read_pinned_publication_file(refs_file, "info/refs", 4 * 1024 * 1024)?;
    let refs_digest = format!("{:x}", Sha256::digest(&refs));
    let head_object = objects
        .get("HEAD")
        .context("publication surface has no HEAD")?;
    anyhow::ensure!(
        head_object.byte_size <= 4096,
        "publication HEAD exceeds its 4096 byte limit"
    );
    let head_file = snapshot_publication_object(&root, head_object)?;
    let head = read_pinned_publication_file(head_file, "HEAD", 4096)?;
    let default_commit = publication_default_commit(&head, &refs)?;
    let objects = publication_inputs(&objects)?;
    let generation = publication_generation(&objects)?;

    Ok(PinnedPublication {
        request: hub_types::BeginRegistryPublicationRequest {
            registry: registry.into(),
            generation,
            refs_digest,
            default_commit,
            parent_publication_id: String::new(),
            objects,
        },
        root,
    })
}

fn validate_publication_pack_indexes(
    root: &std::os::fd::OwnedFd,
    objects: &std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<()> {
    for path in objects
        .keys()
        .filter(|path| aos_package::registry::surface_keymap::is_git_pack_index_path(path))
    {
        let companion = aos_package::registry::pack_index::companion_pack_path(path)
            .with_context(|| format!("deriving companion pack path for {path}"))?;
        anyhow::ensure!(
            objects.contains_key(&companion),
            "publication pack index has no companion pack: {path}"
        );
        let index_file = snapshot_publication_object(root, &objects[path])?;
        let index = read_pinned_publication_file(
            index_file,
            path,
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES,
        )?;
        let pack_object = &objects[&companion];
        let pack_file = snapshot_publication_object(root, pack_object)?;
        let pack = read_pinned_publication_file(
            pack_file,
            &companion,
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_BYTES,
        )?;
        aos_package::registry::pack_index::validate_against_pack(path, &index, &pack)
            .with_context(|| format!("validating publication pack/index pair {path}"))?;
    }
    Ok(())
}

fn validate_publication_nar_urls(
    root: &std::os::fd::OwnedFd,
    objects: &std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<()> {
    for (path, object) in objects
        .iter()
        .filter(|(path, _)| path.ends_with(".narinfo"))
    {
        anyhow::ensure!(
            object.byte_size <= 1024 * 1024,
            "publication narinfo exceeds its 1048576 byte limit: {path}"
        );
        let file = snapshot_publication_object(root, object)?;
        let bytes = read_pinned_publication_file(file, path, 1024 * 1024)?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("publication narinfo is not UTF-8: {path}"))?;
        let narinfo = aos_core::nar::info::parse(text)
            .with_context(|| format!("parsing publication narinfo {path}"))?;
        let file_hash = narinfo
            .file_hash
            .as_deref()
            .with_context(|| format!("publication narinfo has no FileHash: {path}"))?;
        let compression = match narinfo.compression.as_str() {
            "none" => aos_core::nar::cache::NarCompression::None,
            "zstd" => aos_core::nar::cache::NarCompression::Zstd,
            "xz" => aos_core::nar::cache::NarCompression::Xz,
            value => {
                anyhow::bail!("publication narinfo uses unsupported compression '{value}': {path}")
            }
        };
        let expected_url =
            aos_core::nar::cache::nar_url(&narinfo.store_path, file_hash, compression)
                .with_context(|| format!("publication narinfo FileHash is not SHA-256: {path}"))?;
        anyhow::ensure!(
            narinfo.url == expected_url,
            "publication narinfo URL does not identify its compressed FileHash: {path}"
        );
        let nar_object = objects.get(&expected_url).with_context(|| {
            format!("publication narinfo names missing NAR object {expected_url}: {path}")
        })?;
        let expected_sha256 = aos_core::nar::cache::canonical_sha256_hex(file_hash)
            .with_context(|| format!("publication narinfo FileHash is not SHA-256: {path}"))?;
        let expected_size = i64::try_from(
            narinfo
                .file_size
                .with_context(|| format!("publication narinfo has no FileSize: {path}"))?,
        )
        .with_context(|| format!("publication narinfo FileSize is too large: {path}"))?;
        anyhow::ensure!(
            nar_object.sha256 == expected_sha256 && nar_object.byte_size == expected_size,
            "publication NAR object does not match narinfo FileHash/FileSize: {path}"
        );
    }
    Ok(())
}

fn collect_publication_objects(
    directory: &std::os::fd::OwnedFd,
    relative_directory: &str,
    depth: usize,
    entries: &mut usize,
    objects: &mut std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<()> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .context("publication path is not valid UTF-8")?
            .to_string();
        if name != "." && name != ".." {
            *entries = entries
                .checked_add(1)
                .context("publication entry count overflowed")?;
            anyhow::ensure!(
                *entries <= MAX_PUBLICATION_ENTRIES,
                "publication surface exceeds the {MAX_PUBLICATION_ENTRIES} entry limit"
            );
            names.push(name);
        }
    }
    names.sort();
    for name in names {
        let descriptor = rustix::fs::openat(
            directory,
            name.as_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("opening publication path {name} without following links"))?;
        let file = std::fs::File::from(descriptor);
        let metadata = file
            .metadata()
            .with_context(|| format!("reading publication metadata {name}"))?;
        let relative = if relative_directory.is_empty() {
            name.clone()
        } else {
            format!("{relative_directory}/{name}")
        };
        anyhow::ensure!(
            relative.len() <= MAX_PUBLICATION_PATH_BYTES,
            "publication path exceeds the {MAX_PUBLICATION_PATH_BYTES} byte limit: {relative}"
        );
        if metadata.is_dir() {
            anyhow::ensure!(
                depth < MAX_PUBLICATION_DIRECTORY_DEPTH,
                "publication surface exceeds the {MAX_PUBLICATION_DIRECTORY_DEPTH} directory depth limit"
            );
            let descriptor = file.into();
            collect_publication_objects(&descriptor, &relative, depth + 1, entries, objects)?;
            continue;
        }
        anyhow::ensure!(
            metadata.is_file(),
            "publication surface contains non-file {relative}"
        );
        anyhow::ensure!(
            aos_package::registry::surface_keymap::is_machine_path(&relative),
            "publication surface contains unsupported path {relative}"
        );
        anyhow::ensure!(
            objects.len() < MAX_PUBLICATION_OBJECTS,
            "publication surface exceeds the {MAX_PUBLICATION_OBJECTS} object limit"
        );
        anyhow::ensure!(
            objects
                .insert(relative.clone(), publication_input(&relative, file)?)
                .is_none(),
            "publication surface contains duplicate path {relative}"
        );
    }
    Ok(())
}

fn open_publication_root(path: &std::path::Path) -> Result<std::os::fd::OwnedFd> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| {
        format!(
            "opening publication root {} without following links",
            path.display()
        )
    })?;
    let metadata = std::fs::File::from(descriptor.try_clone()?).metadata()?;
    anyhow::ensure!(metadata.is_dir(), "publication root is not a directory");
    Ok(descriptor)
}

fn publication_inputs(
    objects: &std::collections::BTreeMap<String, hub_types::RegistryPublicationObjectInput>,
) -> Result<Vec<hub_types::RegistryPublicationObjectInput>> {
    anyhow::ensure!(!objects.is_empty(), "publication surface is empty");
    Ok(objects.values().cloned().collect())
}

fn publication_input(
    relative: &str,
    mut file: std::fs::File,
) -> Result<hub_types::RegistryPublicationObjectInput> {
    use std::io::{Seek as _, SeekFrom};

    let metadata = file
        .metadata()
        .with_context(|| format!("reading pinned publication object {relative}"))?;
    if aos_package::registry::surface_keymap::is_loose_git_object_path(relative) {
        anyhow::ensure!(
            metadata.len() <= aos_package::registry::MAX_PUBLISHED_LOOSE_OBJECT_BYTES,
            "loose Git object {relative} exceeds the {}-byte publication limit",
            aos_package::registry::MAX_PUBLISHED_LOOSE_OBJECT_BYTES
        );
    }
    if aos_package::registry::surface_keymap::is_git_pack_index_path(relative) {
        let bytes = read_pinned_publication_file(
            file.try_clone()?,
            relative,
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES,
        )?;
        aos_package::registry::pack_index::validate(relative, &bytes)
            .with_context(|| format!("validating publication pack index {relative}"))?;
    }
    if aos_package::registry::surface_keymap::is_git_pack_path(relative) {
        anyhow::ensure!(
            metadata.len() <= aos_package::registry::pack_index::MAX_PUBLISHED_PACK_BYTES,
            "Git pack {relative} exceeds the {}-byte publication limit",
            aos_package::registry::pack_index::MAX_PUBLISHED_PACK_BYTES
        );
    }
    file.seek(SeekFrom::Start(0))?;
    let digest = copy_and_hash_exact(&mut file, &mut std::io::sink(), metadata.len(), relative)?;
    let after = file
        .metadata()
        .with_context(|| format!("rechecking pinned publication object {relative}"))?;
    anyhow::ensure!(
        metadata.len() == after.len() && metadata.modified().ok() == after.modified().ok(),
        "publication object changed while it was hashed: {relative}"
    );
    Ok(hub_types::RegistryPublicationObjectInput {
        path: relative.to_string(),
        sha256: digest,
        byte_size: i64::try_from(metadata.len()).context("publication object is too large")?,
        kind: if aos_package::registry::surface_keymap::cache_control(relative)
            == aos_package::registry::surface_keymap::MUTABLE_CACHE_CONTROL
        {
            "mutable_pointer"
        } else {
            "immutable"
        }
        .into(),
        media_type: aos_package::registry::surface_keymap::content_type(relative).into(),
    })
}

fn publication_generation(objects: &[hub_types::RegistryPublicationObjectInput]) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

/// Checks a supplied manifest against the pinned publication inventory.
///
/// # Errors
///
/// Returns an error if inventory validation fails or the supplied manifest differs.
pub(super) fn pinned_publication_from_root(
    root: &std::path::Path,
    mut request: hub_types::BeginRegistryPublicationRequest,
) -> Result<PinnedPublication> {
    let mut objects = std::collections::BTreeMap::new();
    let mut entries = 0;
    let root = open_publication_root(root)?;
    collect_publication_objects(&root, "", 0, &mut entries, &mut objects)?;
    let actual = publication_inputs(&objects)?;
    request
        .objects
        .sort_by(|left, right| left.path.cmp(&right.path));
    anyhow::ensure!(
        request
            .objects
            .windows(2)
            .all(|objects| objects[0].path != objects[1].path),
        "publication manifest contains duplicate paths"
    );
    let declared = serde_json::to_vec(&request.objects)?;
    let actual = serde_json::to_vec(&actual)?;
    anyhow::ensure!(
        declared == actual,
        "publication manifest does not exactly match the pinned surface"
    );
    Ok(PinnedPublication { request, root })
}

fn read_pinned_publication_file(
    mut file: std::fs::File,
    label: &str,
    maximum_size: u64,
) -> Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let size = file.metadata()?.len();
    anyhow::ensure!(
        size <= maximum_size,
        "publication control object exceeds its {maximum_size} byte limit: {label}"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0_u8; usize::try_from(size)?];
    file.read_exact(&mut bytes)
        .with_context(|| format!("reading pinned publication object {label}"))?;
    let mut excess = [0_u8; 1];
    anyhow::ensure!(
        file.read(&mut excess)? == 0,
        "publication control object grew while it was read: {label}"
    );
    Ok(bytes)
}

fn open_publication_object(root: &std::os::fd::OwnedFd, relative: &str) -> Result<std::fs::File> {
    let mut directory = root.try_clone()?;
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        anyhow::ensure!(
            !component.is_empty() && component != "." && component != "..",
            "publication path is not a portable relative path: {relative}"
        );
        let mut flags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
        if components.peek().is_some() {
            flags |= rustix::fs::OFlags::DIRECTORY;
        }
        let descriptor =
            rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty())
                .with_context(|| {
                    format!("opening publication path {relative} without following links")
                })?;
        if components.peek().is_some() {
            directory = descriptor;
        } else {
            let file = std::fs::File::from(descriptor);
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "publication object is not a file"
            );
            return Ok(file);
        }
    }
    anyhow::bail!("publication object path is empty")
}

/// Copies and hashes an admitted object into a bounded upload snapshot.
///
/// # Errors
///
/// Returns an error if the file cannot be copied or differs from its admitted size or hash.
pub(super) fn snapshot_publication_object(
    root: &std::os::fd::OwnedFd,
    expected: &hub_types::RegistryPublicationObjectInput,
) -> Result<std::fs::File> {
    use std::io::{Seek as _, SeekFrom};

    let mut source = open_publication_object(root, &expected.path)?;
    let mut snapshot = tempfile::tempfile().context("creating publication object snapshot")?;
    let expected_size = u64::try_from(expected.byte_size)
        .context("publication object has a negative declared size")?;
    let digest = copy_and_hash_exact(&mut source, &mut snapshot, expected_size, &expected.path)?;
    anyhow::ensure!(
        digest == expected.sha256,
        "publication object changed after inventory: {}",
        expected.path
    );
    snapshot.seek(SeekFrom::Start(0))?;
    Ok(snapshot)
}

fn copy_and_hash_exact(
    source: &mut impl std::io::Read,
    destination: &mut impl std::io::Write,
    expected_size: u64,
    label: &str,
) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    let mut remaining = expected_size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))?;
        let count = source
            .read(&mut buffer[..limit])
            .with_context(|| format!("reading publication object {label}"))?;
        anyhow::ensure!(
            count != 0,
            "publication object is shorter than its declared size: {label}"
        );
        destination
            .write_all(&buffer[..count])
            .with_context(|| format!("copying publication object {label}"))?;
        digest.update(&buffer[..count]);
        remaining -= u64::try_from(count)?;
    }
    anyhow::ensure!(
        source
            .read(&mut buffer[..1])
            .with_context(|| format!("checking publication object size {label}"))?
            == 0,
        "publication object is longer than its declared size: {label}"
    );
    Ok(format!("{:x}", digest.finalize()))
}

fn publication_default_commit(head: &[u8], refs: &[u8]) -> Result<String> {
    let head = std::str::from_utf8(head)
        .context("HEAD is not UTF-8")?
        .trim();
    let commit = if let Some(reference) = head.strip_prefix("ref: ") {
        let refs = std::str::from_utf8(refs).context("info/refs is not UTF-8")?;
        refs.lines()
            .filter_map(|line| line.split_once('\t'))
            .find_map(|(oid, name)| (name == reference).then_some(oid))
            .with_context(|| format!("HEAD reference {reference} is absent from info/refs"))?
    } else {
        head
    };
    anyhow::ensure!(
        commit.len() == 64
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "publication HEAD does not resolve to a lowercase SHA-256 commit"
    );
    Ok(commit.into())
}

/// Loads a publication manifest and binds it to the requested registry.
///
/// # Errors
///
/// Returns an error if the manifest cannot be read or decoded.
pub(super) fn publication_manifest_request(
    manifest: &std::path::Path,
    registry: &str,
) -> Result<hub_types::BeginRegistryPublicationRequest> {
    let bytes = std::fs::read(manifest)
        .with_context(|| format!("reading publication manifest {}", manifest.display()))?;
    let mut request: hub_types::BeginRegistryPublicationRequest =
        serde_json::from_slice(&bytes).context("decoding publication manifest")?;
    if !request.registry.is_empty() && request.registry != registry {
        anyhow::bail!("manifest registry does not match the command registry");
    }
    request.registry = registry.to_string();
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::hub::publication::publication_objects_in_upload_order;

    #[test]
    fn publication_surface_derives_a_complete_stable_request() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/aa")).unwrap();
        std::fs::create_dir_all(root.join("channels/stable")).unwrap();
        let commit = "a".repeat(64);
        std::fs::write(root.join("HEAD"), "ref: refs/heads/stable\n").unwrap();
        std::fs::write(
            root.join("info/refs"),
            format!("{commit}\trefs/heads/stable\n"),
        )
        .unwrap();
        std::fs::write(root.join("objects/aa/object"), b"object").unwrap();
        std::fs::write(root.join("channels/stable/00"), b"pointer").unwrap();

        let pinned = publication_from_root(root, "andyl/main").unwrap();
        let first_generation = pinned.request.generation.clone();
        let first_refs_digest = pinned.request.refs_digest.clone();
        let request = pinned.request;
        assert_eq!(request.registry, "andyl/main");
        assert_eq!(request.default_commit, commit);
        assert_ne!(request.generation, request.refs_digest);
        assert_eq!(request.generation.len(), 64);
        assert_eq!(request.objects.len(), 4);
        assert_eq!(request.objects[0].path, "HEAD");
        assert_eq!(request.objects[0].kind, "mutable_pointer");
        assert_eq!(request.objects[2].path, "info/refs");
        assert_eq!(request.objects[2].kind, "mutable_pointer");
        assert_eq!(request.objects[3].path, "objects/aa/object");
        assert_eq!(request.objects[3].kind, "immutable");

        std::fs::write(root.join("objects/aa/object"), b"replacement object").unwrap();
        let replacement = publication_from_root(root, "andyl/main").unwrap();
        assert_eq!(replacement.request.refs_digest, first_refs_digest);
        assert_ne!(replacement.request.generation, first_generation);
    }

    #[test]
    fn publication_object_contract_matches_delivery_path_contract() {
        use sha2::Digest as _;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/info")).unwrap();
        std::fs::create_dir_all(root.join("web/packages")).unwrap();
        std::fs::create_dir_all(root.join("nar")).unwrap();
        let commit = "e".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        for path in [
            "nix-cache-info",
            "index.html",
            "objects/info/packs",
            "web/config.json",
            "web/index.json",
            "web/packages/aos.json",
        ] {
            std::fs::write(root.join(path), path.as_bytes()).unwrap();
        }
        let nar = b"compressed-nar";
        let file_hash = format!("sha256:{:x}", sha2::Sha256::digest(nar));
        let nar_url = aos_core::nar::cache::nar_url(
            "/nix/store/hash-package",
            &file_hash,
            aos_core::nar::cache::NarCompression::Zstd,
        )
        .unwrap();
        std::fs::write(root.join(&nar_url), nar).unwrap();
        std::fs::write(
            root.join("hash.narinfo"),
            format!(
                "StorePath: /nix/store/hash-package\nURL: {nar_url}\nCompression: zstd\nFileHash: {file_hash}\nFileSize: {}\nNarHash: sha256:nar\nNarSize: 99\n",
                nar.len()
            ),
        )
        .unwrap();

        let pinned = publication_from_root(root, "andyl/main").unwrap();
        for object in &pinned.request.objects {
            let expected = if aos_package::registry::surface_keymap::cache_control(&object.path)
                == aos_package::registry::surface_keymap::MUTABLE_CACHE_CONTROL
            {
                "mutable_pointer"
            } else {
                "immutable"
            };
            assert_eq!(object.kind, expected, "{}", object.path);
            assert_eq!(
                object.media_type,
                aos_package::registry::surface_keymap::content_type(&object.path),
                "{}",
                object.path
            );
        }
        assert_eq!(
            pinned
                .request
                .objects
                .iter()
                .find(|object| object.path == "hash.narinfo")
                .unwrap()
                .kind,
            "mutable_pointer"
        );
    }

    #[test]
    fn publication_rejects_nar_urls_that_do_not_identify_file_hash() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/aa")).unwrap();
        std::fs::create_dir_all(root.join("nar")).unwrap();
        let commit = "a".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        std::fs::write(root.join("objects/aa/object"), b"object").unwrap();
        std::fs::write(root.join("nar/hash-sha256-nar.nar.zst"), b"payload").unwrap();
        std::fs::write(
            root.join("hash.narinfo"),
            "StorePath: /nix/store/hash-package\nURL: nar/hash-sha256-nar.nar.zst\nCompression: zstd\nFileHash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nFileSize: 7\nNarHash: sha256:nar\nNarSize: 9\n",
        )
        .unwrap();

        let error = publication_from_root(root, "andyl/main").err().unwrap();
        assert!(
            error
                .to_string()
                .contains("does not identify its compressed FileHash")
        );
    }

    #[test]
    fn publication_uploads_immutable_objects_before_pointers() {
        let object = |path: &str, kind: &str| hub_types::RegistryPublicationObject {
            path: path.into(),
            kind: kind.into(),
            ..Default::default()
        };
        let publication = hub_types::RegistryPublication {
            objects: vec![
                object("HEAD", "mutable_pointer"),
                object("objects/aa/object", "immutable"),
                object("info/refs", "mutable_pointer"),
                object("nar/package.nar.zst", "immutable"),
            ],
            ..Default::default()
        };

        let paths = publication_objects_in_upload_order(&publication)
            .into_iter()
            .map(|object| object.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "objects/aa/object",
                "nar/package.nar.zst",
                "HEAD",
                "info/refs"
            ]
        );
    }

    #[test]
    fn publication_upload_snapshot_rejects_post_inventory_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        let commit = "c".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        std::fs::write(root.join("index.html"), b"reviewed").unwrap();
        let pinned = publication_from_root(root, "andyl/main").unwrap();
        let expected = pinned
            .request
            .objects
            .iter()
            .find(|object| object.path == "index.html")
            .unwrap();

        std::fs::write(root.join("index.html"), b"changed").unwrap();

        assert!(snapshot_publication_object(&pinned.root, expected).is_err());
    }

    #[test]
    fn publication_copy_is_bounded_by_the_declared_size() {
        let mut excess = std::io::Cursor::new(b"reviewed-extra");
        assert!(copy_and_hash_exact(&mut excess, &mut std::io::sink(), 8, "excess").is_err());

        let mut short = std::io::Cursor::new(b"short");
        assert!(copy_and_hash_exact(&mut short, &mut std::io::sink(), 8, "short").is_err());
    }

    #[test]
    fn publication_surface_rejects_excessive_directory_depth() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        let commit = "d".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();

        let mut directory = root.join("web");
        for _ in 0..=MAX_PUBLICATION_DIRECTORY_DEPTH {
            directory.push("nested");
        }
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("index.html"), b"too deep").unwrap();

        assert!(publication_from_root(root, "andyl/main").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn publication_surface_rejects_symlinks_and_unknown_paths() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("info")).unwrap();
        let commit = "b".repeat(64);
        std::fs::write(root.join("HEAD"), format!("{commit}\n")).unwrap();
        std::fs::write(root.join("info/refs"), b"").unwrap();
        std::fs::write(root.join("operator-notes"), b"private").unwrap();
        assert!(publication_from_root(root, "andyl/main").is_err());

        std::fs::remove_file(root.join("operator-notes")).unwrap();
        symlink(root.join("HEAD"), root.join("index.html")).unwrap();
        assert!(publication_from_root(root, "andyl/main").is_err());
    }
}
