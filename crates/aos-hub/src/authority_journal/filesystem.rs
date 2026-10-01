//! Private per-authority file coordinates and rollback-journal namespace checks.

use std::fs::{self, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context as _, Result};

use super::HubDataBoundary;

/// Pinned open-file identity; no journal contents or current head are cached.
#[derive(Debug, Clone)]
pub(super) struct PrivateFile {
    pub(super) path: PathBuf,
    device: u64,
    inode: u64,
    parent_device: u64,
    parent_inode: u64,
}

impl PrivateFile {
    pub(super) fn recovery_identity(&self) -> super::recovery::ClockRecoveryFile {
        super::recovery::ClockRecoveryFile {
            device: self.device.to_string(),
            inode: self.inode.to_string(),
            parent_device: self.parent_device.to_string(),
            parent_inode: self.parent_inode.to_string(),
        }
    }

    // The open descriptor owns the flock until the clock/service or explicit
    // operator operation ends. No sidecar or path-only lock can substitute.
    pub(super) fn lock_exclusive(&self) -> Result<std::fs::File> {
        self.validate_current()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)?;
        let metadata = file.metadata()?;
        private_regular_file(&metadata)?;
        ensure!(
            metadata.dev() == self.device && metadata.ino() == self.inode,
            "issuer journal lock file was replaced"
        );
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .context("unresolved clock session: issuer or operator holds the journal inode lock")?;
        self.validate_current()?;
        Ok(file)
    }

    pub(super) fn create_new(path: &Path, boundary: &HubDataBoundary) -> Result<Self> {
        validate_location(path, boundary)?;
        validate_namespace(path, true)?;
        validate_sidecars(path, true)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .context("creating new private issuer journal")?;
        file.sync_all()?;
        Self::capture(path)
    }

    pub(super) fn existing(path: &Path, boundary: &HubDataBoundary) -> Result<Self> {
        validate_location(path, boundary)?;
        Self::capture(path)
    }

    fn capture(path: &Path) -> Result<Self> {
        let parent = path.parent().context("issuer journal requires a parent")?;
        let metadata = fs::symlink_metadata(path).context("opening existing issuer journal")?;
        private_regular_file(&metadata)?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        private_directory(&parent_metadata)?;
        validate_namespace(path, false)?;
        validate_sidecars(path, false)?;
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
        })
    }

    pub(super) fn validate_current(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path)?;
        private_regular_file(&metadata)?;
        ensure!(
            metadata.dev() == self.device && metadata.ino() == self.inode,
            "issuer journal file was replaced"
        );
        let parent = self
            .path
            .parent()
            .context("issuer journal requires a parent")?;
        ensure!(
            fs::canonicalize(parent)? == parent,
            "issuer journal ancestry changed or traverses symlinks"
        );
        let metadata = fs::symlink_metadata(parent)?;
        private_directory(&metadata)?;
        ensure!(
            metadata.dev() == self.parent_device && metadata.ino() == self.parent_inode,
            "issuer journal directory was replaced"
        );
        validate_namespace(&self.path, false)?;
        validate_sidecars(&self.path, false)
    }

    pub(super) fn sync_installation(&self) -> Result<()> {
        self.validate_current()?;
        OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)?
            .sync_all()?;
        OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32,
            )
            .open(
                self.path
                    .parent()
                    .context("issuer journal requires parent")?,
            )?
            .sync_all()?;
        self.validate_current()
    }
}

fn validate_location(path: &Path, boundary: &HubDataBoundary) -> Result<()> {
    absolute_normal(path)?;
    absolute_normal(&boundary.hub_root)?;
    let parent = path.parent().context("issuer journal requires parent")?;
    ensure!(
        fs::canonicalize(parent)? == parent,
        "issuer journal directory must not traverse symlinks"
    );
    private_directory(&fs::symlink_metadata(parent)?)?;
    let hub_root = resolved_boundary(&boundary.hub_root)?;
    ensure!(
        !path.starts_with(&hub_root),
        "issuer journal must be outside Hub data root"
    );
    if let Some(sqlite_file) = &boundary.hub_sqlite_file {
        absolute_normal(sqlite_file)?;
        ensure!(
            path != resolved_boundary(sqlite_file)?,
            "issuer journal must not be Hub SQL"
        );
    }
    Ok(())
}

fn absolute_normal(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.file_name().is_some()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "issuer paths must be explicit absolute normalized paths"
    );
    Ok(())
}

// A separate authority process need not mount Hub data; resolve any existing
// ancestor without creating or opening the excluded Hub file/database.
fn resolved_boundary(path: &Path) -> Result<PathBuf> {
    let mut ancestor = path;
    let mut suffix = Vec::new();
    while !ancestor.try_exists()? {
        suffix.push(
            ancestor
                .file_name()
                .context("missing boundary ancestor")?
                .to_owned(),
        );
        ancestor = ancestor.parent().context("missing boundary parent")?;
    }
    let mut resolved = fs::canonicalize(ancestor)?;
    for part in suffix.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

fn private_directory(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7777 == 0o700,
        "issuer journal parent must be owner-private directory"
    );
    Ok(())
}

fn private_regular_file(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1,
        "issuer journal must be owner-private unlinked regular file"
    );
    Ok(())
}

fn validate_sidecars(path: &Path, initializing: bool) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => {
                ensure!(
                    !initializing && suffix == "-journal",
                    "unexpected issuer journal sidecar"
                );
                private_regular_file(&metadata)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

// One authority owns the entire parent directory. This prevents a second
// installation from using another authority's reserved SQLite sidecar name.
fn validate_namespace(path: &Path, initializing: bool) -> Result<()> {
    let parent = path.parent().context("issuer journal requires parent")?;
    let filename = path
        .file_name()
        .context("issuer journal requires filename")?;
    let mut rollback = filename.to_owned();
    rollback.push("-journal");
    for entry in fs::read_dir(parent)? {
        let name = entry?.file_name();
        ensure!(
            !initializing && (name == filename || name == rollback),
            "issuer journal requires a dedicated private directory"
        );
    }
    Ok(())
}
