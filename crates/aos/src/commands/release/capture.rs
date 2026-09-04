//! Descriptor-relative, no-follow capture of an immutable bundle snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail};
use aos_release::artifact::BundlePath;
use aos_release::digest::Sha256Digest;
use aos_release::verify::CapturedFile;
use rustix::fs::{Dir, Mode, OFlags, open, openat};
use sha2::{Digest as _, Sha256};

const MAX_DEPTH: usize = 32;
const MAX_ENTRIES: usize = 65_536;
const MAX_CONTROL_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn of(file: &File) -> Result<Self> {
        let metadata = file.metadata().context("reading captured file metadata")?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: Identity,
    size: u64,
    mode: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileSnapshot {
    fn of(file: &File) -> Result<Self> {
        let metadata = file.metadata().context("reading captured file metadata")?;
        Ok(Self {
            identity: Identity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            size: metadata.len(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

/// Immutable identities and bounded control bytes captured from one bundle.
pub(super) struct CapturedBundle {
    pub(super) plan_bytes: Vec<u8>,
    pub(super) manifest_bytes: Vec<u8>,
    pub(super) files: Vec<CapturedFile>,
}

/// Captures a release tree without following links or loading large artifacts.
pub(super) fn bundle(path: &Path) -> Result<CapturedBundle> {
    let root = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening release bundle {}", path.display()))?;
    let root_file = File::from(root.try_clone()?);
    let root_identity = Identity::of(&root_file)?;

    let mut state = CaptureState::default();
    capture_directory(&root, "", 0, &mut state)?;
    assert_directory_entries(&root, &state.root_entries)?;

    let reopened = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("reopening release bundle root")?;
    if Identity::of(&File::from(reopened))? != root_identity {
        bail!("release bundle root changed during capture");
    }

    let plan_bytes = state
        .control_files
        .remove("release-plan.json")
        .ok_or_else(|| anyhow!("release bundle lacks release-plan.json"))?;
    let manifest_bytes = state
        .control_files
        .remove("release-manifest.json")
        .ok_or_else(|| anyhow!("release bundle lacks release-manifest.json"))?;
    if !state.control_files.is_empty() {
        bail!("unexpected internal control-file capture state");
    }
    state
        .files
        .retain(|file| file.path.as_str() != "release-manifest.json");
    Ok(CapturedBundle {
        plan_bytes,
        manifest_bytes,
        files: state.files,
    })
}

/// Reads one no-follow, single-link regular control file with a strict bound.
pub(super) fn control_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let handle = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label} {}", path.display()))?;
    let mut file = File::from(handle);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("{label} must be a single-link regular file");
    }
    if metadata.len() > MAX_CONTROL_FILE_BYTES {
        bail!("{label} exceeds {MAX_CONTROL_FILE_BYTES} bytes");
    }
    let snapshot = FileSnapshot::of(&file)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    std::io::Read::by_ref(&mut file)
        .take(MAX_CONTROL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? != metadata.len() || FileSnapshot::of(&file)? != snapshot {
        bail!("{label} changed during capture");
    }
    Ok(bytes)
}

/// Copies a no-follow payload tree into a new private destination.
///
/// Every source file is held open while it is copied, hashed, and checked for
/// metadata changes. Directory membership and the root identity are rechecked
/// after traversal. Release control filenames are reserved for the caller.
///
/// # Errors
///
/// Returns an error for links, aliases, special files, unstable input,
/// reserved control paths, excessive depth/count, or destination collisions.
pub(super) fn copy_payload_tree(source: &Path, destination: &Path) -> Result<Vec<CapturedFile>> {
    copy_tree(source, destination, true)
}

/// Copies a publication surface without following links or accepting aliases.
///
/// # Errors
///
/// Returns an error for links, aliases, special files, unstable input,
/// excessive depth/count, or destination collisions.
pub(super) fn copy_surface_tree(source: &Path, destination: &Path) -> Result<Vec<CapturedFile>> {
    copy_tree(source, destination, false)
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    reserve_release_controls: bool,
) -> Result<Vec<CapturedFile>> {
    let root = open(
        source,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening release payload tree {}", source.display()))?;
    let root_identity = Identity::of(&File::from(root.try_clone()?))?;
    fs::create_dir(destination).with_context(|| {
        format!(
            "creating release payload destination {}",
            destination.display()
        )
    })?;

    let mut state = CaptureState::default();
    copy_payload_directory(
        &root,
        "",
        0,
        &mut state,
        destination,
        reserve_release_controls,
    )?;
    let reopened = open(
        source,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if Identity::of(&File::from(reopened))? != root_identity {
        bail!("release payload root changed during capture");
    }
    Ok(state.files)
}

fn copy_payload_directory(
    directory: &OwnedFd,
    relative: &str,
    depth: usize,
    state: &mut CaptureState,
    destination: &Path,
    reserve_release_controls: bool,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("release payload exceeds maximum depth of {MAX_DEPTH}");
    }
    let names = directory_entries(directory)?;
    for name in &names {
        state.entries = state
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("release payload entry count overflow"))?;
        if state.entries > MAX_ENTRIES {
            bail!("release payload exceeds maximum entry count of {MAX_ENTRIES}");
        }
        let child = openat(
            directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let child_file = File::from(child.try_clone()?);
        let metadata = child_file.metadata()?;
        let identity = Identity::of(&child_file)?;
        let child_path = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if reserve_release_controls
            && matches!(
                child_path.as_str(),
                "release-plan.json" | "release-manifest.json"
            )
        {
            bail!("release payload uses reserved control path {child_path}");
        }
        let target = destination.join(&child_path);
        if metadata.is_dir() {
            fs::create_dir(&target)?;
            copy_payload_directory(
                &child,
                &child_path,
                depth + 1,
                state,
                destination,
                reserve_release_controls,
            )?;
        } else if metadata.is_file() {
            copy_payload_regular(child, &child_path, &target, state)?;
        } else {
            bail!("release payload contains a symlink or special file: {child_path}");
        }
        let reopened = openat(
            directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if Identity::of(&File::from(reopened))? != identity {
            bail!("release payload member changed during capture: {child_path}");
        }
    }
    assert_directory_entries(directory, &names)
}

fn copy_payload_regular(
    handle: OwnedFd,
    relative: &str,
    target: &Path,
    state: &mut CaptureState,
) -> Result<()> {
    let mut source = File::from(handle);
    let snapshot = FileSnapshot::of(&source)?;
    if snapshot.links != 1 || !state.identities.insert(snapshot.identity) {
        bail!("release payload contains a linked or aliased file: {relative}");
    }
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    let mut digest = Sha256::new();
    let copied = std::io::copy(
        &mut source,
        &mut CopyDigestWriter {
            destination: &mut destination,
            digest: &mut digest,
        },
    )?;
    destination.sync_all()?;
    if copied != snapshot.size || FileSnapshot::of(&source)? != snapshot {
        bail!("release payload file changed during copy: {relative}");
    }
    state.files.push(CapturedFile {
        path: BundlePath::parse(relative)?,
        size_bytes: snapshot.size,
        sha256: Sha256Digest::parse(&format!("sha256:{:x}", digest.finalize()))?,
    });
    Ok(())
}

struct CopyDigestWriter<'a> {
    destination: &'a mut File,
    digest: &'a mut Sha256,
}

impl std::io::Write for CopyDigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.destination.write(bytes)?;
        self.digest.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.destination.flush()
    }
}

#[derive(Default)]
struct CaptureState {
    entries: usize,
    identities: BTreeSet<Identity>,
    files: Vec<CapturedFile>,
    control_files: BTreeMap<String, Vec<u8>>,
    root_entries: Vec<String>,
}

fn capture_directory(
    directory: &OwnedFd,
    relative: &str,
    depth: usize,
    state: &mut CaptureState,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("release bundle exceeds maximum depth of {MAX_DEPTH}");
    }
    let names = directory_entries(directory)?;
    if relative.is_empty() {
        state.root_entries.clone_from(&names);
    }
    for name in &names {
        state.entries = state
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("release bundle entry count overflow"))?;
        if state.entries > MAX_ENTRIES {
            bail!("release bundle exceeds maximum entry count of {MAX_ENTRIES}");
        }
        let child = openat(
            directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening bundle member {name}"))?;
        let child_file = File::from(child.try_clone()?);
        let metadata = child_file.metadata()?;
        let child_identity = Identity::of(&child_file)?;
        let child_path = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if metadata.is_dir() {
            capture_directory(&child, &child_path, depth + 1, state)?;
        } else if metadata.is_file() {
            capture_regular(child, &child_path, state)?;
        } else {
            bail!("bundle contains a symlink or special file: {child_path}");
        }
        let reopened = openat(
            directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("reopening bundle member {child_path}"))?;
        if Identity::of(&File::from(reopened))? != child_identity {
            bail!("bundle member changed during capture: {child_path}");
        }
    }
    assert_directory_entries(directory, &names)
}

fn capture_regular(handle: OwnedFd, relative: &str, state: &mut CaptureState) -> Result<()> {
    let mut file = File::from(handle);
    let metadata = file.metadata()?;
    if metadata.nlink() != 1 {
        bail!("bundle regular file must have one link: {relative}");
    }
    let snapshot = FileSnapshot::of(&file)?;
    if !state.identities.insert(snapshot.identity) {
        bail!("bundle aliases one file through multiple paths: {relative}");
    }

    let mut digest = Sha256::new();
    let copied = std::io::copy(&mut file, &mut DigestWriter(&mut digest))?;
    if copied != snapshot.size || FileSnapshot::of(&file)? != snapshot {
        bail!("bundle file changed during capture: {relative}");
    }
    let sha256 = Sha256Digest::parse(&format!("sha256:{:x}", digest.finalize()))?;
    if matches!(relative, "release-plan.json" | "release-manifest.json") {
        if snapshot.size > MAX_CONTROL_FILE_BYTES {
            bail!("release control file exceeds {MAX_CONTROL_FILE_BYTES} bytes");
        }
        let mut control = file.try_clone()?;
        use std::io::Seek as _;
        control.rewind()?;
        let mut bytes = Vec::with_capacity(usize::try_from(snapshot.size)?);
        control.read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len())? != snapshot.size || FileSnapshot::of(&control)? != snapshot {
            bail!("release control file changed during capture: {relative}");
        }
        if Sha256Digest::of_bytes(&bytes) != sha256 {
            bail!("release control file bytes changed during capture: {relative}");
        }
        state.control_files.insert(relative.to_owned(), bytes);
    }
    state.files.push(CapturedFile {
        path: BundlePath::parse(relative)?,
        size_bytes: snapshot.size,
        sha256,
    });
    Ok(())
}

struct DigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn directory_entries(directory: &OwnedFd) -> Result<Vec<String>> {
    let fresh = openat(
        directory,
        CStr::from_bytes_with_nul(b".\0")?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut names = Vec::new();
    for entry in Dir::read_from(&fresh)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| anyhow!("bundle path is not UTF-8"))?;
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn assert_directory_entries(directory: &OwnedFd, expected: &[String]) -> Result<()> {
    if directory_entries(directory)? != expected {
        bail!("release bundle directory changed during capture");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::{bundle, copy_payload_tree, copy_surface_tree};

    fn control_files(root: &Path) -> Result<()> {
        fs::write(root.join("release-plan.json"), b"{}")?;
        fs::write(root.join("release-manifest.json"), b"{}")?;
        Ok(())
    }

    use std::path::Path;

    use anyhow::Result;

    #[test]
    fn capture_streams_payload_identities_and_control_bytes() -> Result<()> {
        let temporary = tempdir()?;
        control_files(temporary.path())?;
        fs::create_dir(temporary.path().join("packages"))?;
        fs::write(temporary.path().join("packages/example.nar"), b"nar")?;

        let captured = bundle(temporary.path())?;
        assert_eq!(captured.plan_bytes, b"{}");
        assert_eq!(captured.manifest_bytes, b"{}");
        assert_eq!(captured.files.len(), 2);
        assert!(
            captured
                .files
                .iter()
                .all(|file| file.path.as_str() != "release-manifest.json")
        );
        Ok(())
    }

    #[test]
    fn capture_rejects_links() -> Result<()> {
        let temporary = tempdir()?;
        control_files(temporary.path())?;
        symlink("release-plan.json", temporary.path().join("alias"))?;
        assert!(bundle(temporary.path()).is_err());

        fs::remove_file(temporary.path().join("alias"))?;
        fs::hard_link(
            temporary.path().join("release-plan.json"),
            temporary.path().join("alias"),
        )?;
        assert!(bundle(temporary.path()).is_err());
        Ok(())
    }

    #[test]
    fn payload_copy_recreates_exact_regular_file_closure() -> Result<()> {
        let source = tempdir()?;
        let parent = tempdir()?;
        fs::create_dir(source.path().join("nested"))?;
        fs::write(source.path().join("nested/artifact"), b"payload")?;

        let destination = parent.path().join("bundle");
        let files = copy_payload_tree(source.path(), &destination)?;

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path.as_str(), "nested/artifact");
        assert_eq!(fs::read(destination.join("nested/artifact"))?, b"payload");
        Ok(())
    }

    #[test]
    fn payload_copy_rejects_reserved_controls_and_links() -> Result<()> {
        let source = tempdir()?;
        let parent = tempdir()?;
        fs::write(source.path().join("release-manifest.json"), b"{}")?;
        assert!(copy_payload_tree(source.path(), &parent.path().join("reserved")).is_err());

        fs::remove_file(source.path().join("release-manifest.json"))?;
        fs::write(source.path().join("artifact"), b"payload")?;
        symlink("artifact", source.path().join("alias"))?;
        assert!(copy_payload_tree(source.path(), &parent.path().join("linked")).is_err());
        Ok(())
    }

    #[test]
    fn surface_copy_accepts_controls_but_still_rejects_links() -> Result<()> {
        let source = tempdir()?;
        let parent = tempdir()?;
        fs::write(source.path().join("release-manifest.json"), b"{}")?;

        let copied = parent.path().join("copied");
        copy_surface_tree(source.path(), &copied)?;
        assert_eq!(fs::read(copied.join("release-manifest.json"))?, b"{}");

        fs::write(source.path().join("artifact"), b"payload")?;
        symlink("artifact", source.path().join("alias"))?;
        assert!(copy_surface_tree(source.path(), &parent.path().join("linked")).is_err());
        Ok(())
    }
}
