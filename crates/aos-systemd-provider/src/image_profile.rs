//! Owns durable image-payload paths outside the firmware partition.
//!
//! Staged UKIs and rollout backups remain in the image profile. Only selectable
//! boot entries need ESP space; keeping their authenticated sources here also
//! lets selection replay preserve or explicitly reset consumed boot counts.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};

/// Names the durable image profile shared by staging and boot selection.
pub(crate) const IMAGE_PROFILE: &str = "/var/lib/profiles/image";

/// Names the firmware partition containing selectable boot entries.
pub(crate) const BOOT_ROOT: &str = "/boot";

/// Distinguishes selectable ESP entries from durable staged profile sources.
pub(crate) enum PayloadSource {
    /// Resolves an installed firmware entry relative to the ESP.
    Installed(PathBuf),
    /// Resolves an authenticated staged payload relative to the image profile.
    Staged(PathBuf),
}

impl PayloadSource {
    /// Parses a canonical source in one of the two owned payload namespaces.
    ///
    /// # Errors
    /// Returns an error for aliases, another namespace, or an invalid name.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let parts = value.split('/').collect::<Vec<_>>();
        if let ["EFI", "Linux", name] = parts.as_slice() {
            ensure!(
                name.len() > 4 && name.ends_with(".efi"),
                "invalid installed UKI source"
            );
            return Ok(Self::Installed(PathBuf::from(value)));
        }
        Ok(Self::Staged(parse_candidate_path(value)?))
    }

    /// Resolves the source beneath its owning storage root.
    pub(crate) fn resolve(&self, boot_root: &Path, profile: &Path) -> PathBuf {
        match self {
            Self::Installed(path) => boot_root.join(path),
            Self::Staged(path) => profile.join(path),
        }
    }
}

/// Constructs the canonical profile-relative source for a staged generation.
///
/// # Errors
/// Returns an error when the generation is zero.
pub(crate) fn candidate_path(generation: u32) -> Result<PathBuf> {
    ensure!(generation > 0, "invalid staged generation");
    Ok(Path::new("candidates")
        .join(generation.to_string())
        .join("candidate.efi"))
}

/// Parses an exact profile-relative staged payload identity.
///
/// # Errors
/// Returns an error for an alias, a noncanonical generation, or another file.
pub(crate) fn parse_candidate_path(value: &str) -> Result<PathBuf> {
    let parts = value.split('/').collect::<Vec<_>>();
    ensure!(
        parts.len() == 3 && parts[0] == "candidates" && parts[2] == "candidate.efi",
        "invalid staged UKI source"
    );
    let generation: u32 = parts[1].parse()?;
    let path = candidate_path(generation)?;
    ensure!(
        path == Path::new(value) && generation.to_string() == parts[1],
        "invalid staged generation"
    );
    Ok(path)
}

/// Creates a private child directory and durably publishes its parent entry.
///
/// # Errors
/// Returns an error for aliased parents, conflicting objects, or failed I/O.
pub(crate) fn private_directory(parent: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        matches!(Path::new(name).components().collect::<Vec<_>>().as_slice(), [Component::Normal(component)] if *component == name),
        "image payload directory name is not one component"
    );
    ensure!(
        fs::canonicalize(parent)? == parent,
        "image payload parent traverses an alias"
    );
    let directory = parent.join(name);
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("creating image payload directory"),
    }
    ensure!(
        fs::symlink_metadata(&directory)?.is_dir(),
        "image payload directory is not a real directory"
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    File::open(&directory)?.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn private_payload_directories_reject_aliases_and_foreign_objects() {
        let root = tempfile::tempdir().unwrap();
        let foreign = root.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("marker"), b"unchanged").unwrap();
        symlink(&foreign, root.path().join("alias")).unwrap();

        assert!(private_directory(root.path(), "alias").is_err());
        assert!(private_directory(&root.path().join("alias"), "child").is_err());
        assert!(!foreign.join("child").exists());
        assert_eq!(fs::read(foreign.join("marker")).unwrap(), b"unchanged");

        fs::write(root.path().join("file"), b"not a directory").unwrap();
        assert!(private_directory(root.path(), "file").is_err());
        for name in ["..", "a/b", "a/"] {
            assert!(private_directory(root.path(), name).is_err());
        }

        let directory = private_directory(root.path(), "payloads").unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            private_directory(root.path(), "payloads").unwrap(),
            directory
        );
    }
}
