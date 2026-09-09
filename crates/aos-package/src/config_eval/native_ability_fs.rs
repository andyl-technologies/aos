//! Protected descriptor-relative storage for native ability adapters.
//!
//! Roots are opened by walking from `/` with `O_NOFOLLOW`. Every ancestor is
//! root-owned or owned by the selected trusted identity and prevents arbitrary
//! rename. Files remain addressed through retained directory descriptors, so a
//! later pathname substitution cannot redirect reads, replacements, or unlinks.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aos_ability_model::ArtifactReference;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Retains a protected directory descriptor and its trusted ownership policy.
#[derive(Clone, Debug)]
pub(super) struct RootedDirectory {
    directory: Arc<OwnedFd>,
    display: PathBuf,
    trusted_owner: u32,
}

impl RootedDirectory {
    /// Opens an existing canonical absolute directory through no-follow descriptors.
    ///
    /// Every ancestor must be root-owned or owned by `trusted_owner` and must
    /// prevent arbitrary rename. The selected directory must be owned by
    /// `trusted_owner` and deny group/world writes.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is noncanonical, a component is absent or
    /// is a symlink, or the ownership and mode invariants are not satisfied.
    pub(super) fn open(path: &Path, trusted_owner: u32, label: &str) -> Result<Self, io::Error> {
        let path_text = path
            .to_str()
            .ok_or_else(|| invalid(format!("{label} path is not UTF-8")))?;
        if !is_canonical_absolute(path_text) {
            return Err(invalid(format!("{label} is not a canonical absolute path")));
        }

        let mut directory =
            fs::openat(fs::CWD, "/", directory_flags(), Mode::empty()).map_err(io::Error::from)?;
        let test_namespace_root_owner = test_namespace_root_owner(&directory)?;
        validate_ancestor(&directory, test_namespace_root_owner, trusted_owner, label)?;
        for component in path.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            directory = fs::openat(&directory, component, directory_flags(), Mode::empty())
                .map_err(io::Error::from)?;
            validate_ancestor(&directory, test_namespace_root_owner, trusted_owner, label)?;
        }
        validate_directory(&directory, trusted_owner, label)?;

        Ok(Self {
            directory: Arc::new(directory),
            display: path.to_path_buf(),
            trusted_owner,
        })
    }

    /// Opens an existing protected child directory without following a symlink.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is invalid, the child cannot be opened, or
    /// it is not a directory owned solely by the trusted identity.
    pub(super) fn child_directory(&self, name: &str) -> Result<Self, io::Error> {
        validate_name(OsStr::new(name))?;
        let directory = fs::openat(&*self.directory, name, directory_flags(), Mode::empty())
            .map_err(io::Error::from)?;
        validate_directory(
            &directory,
            self.trusted_owner,
            "native ability private directory",
        )?;

        Ok(Self {
            directory: Arc::new(directory),
            display: self.display.join(name),
            trusted_owner: self.trusted_owner,
        })
    }

    /// Resolves a canonical relative file beneath existing protected parents.
    ///
    /// The final file may be absent. When present, it must already satisfy the
    /// trusted regular-file invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for an absolute or noncanonical path, a missing or
    /// unprotected parent, a symlink, or an unsafe existing target.
    pub(super) fn resolve(&self, relative: &Path) -> Result<RootedFile, io::Error> {
        let relative_text = relative
            .to_str()
            .ok_or_else(|| invalid("native ability relative path is not UTF-8"))?;
        if !is_canonical_relative(relative_text) {
            return Err(invalid(
                "native ability target is not a canonical relative path",
            ));
        }
        let name = relative
            .file_name()
            .ok_or_else(|| invalid("native ability target has no file name"))?
            .to_os_string();
        validate_name(&name)?;

        let mut parent = self.clone();
        if let Some(relative_parent) = relative.parent() {
            for component in relative_parent.components() {
                let Component::Normal(component) = component else {
                    return Err(invalid(
                        "native ability target contains a traversal component",
                    ));
                };
                let component = component
                    .to_str()
                    .ok_or_else(|| invalid("native ability path is not UTF-8"))?;
                parent = parent.child_directory(component)?;
            }
        }

        let target = RootedFile {
            directory: parent.directory,
            name,
            display: self.display.join(relative),
            trusted_owner: self.trusted_owner,
        };
        target.validate_optional_target()?;
        Ok(target)
    }

    /// Resolves a canonical relative file path beneath this directory.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::resolve`].
    pub(super) fn child(&self, name: String) -> Result<RootedFile, io::Error> {
        self.resolve(Path::new(&name))
    }

    pub(super) fn display(&self) -> &Path {
        &self.display
    }
}

/// Retains a protected parent descriptor and one validated relative file name.
#[derive(Clone, Debug)]
pub(super) struct RootedFile {
    directory: Arc<OwnedFd>,
    name: OsString,
    display: PathBuf,
    trusted_owner: u32,
}

impl RootedFile {
    fn validate_optional_target(&self) -> Result<(), io::Error> {
        match fs::openat(&*self.directory, &self.name, read_flags(), Mode::empty()) {
            Ok(descriptor) => validate_regular(&descriptor, self.trusted_owner),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    /// Reports whether the target is a trusted singly linked regular file.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be opened or violates its type,
    /// link-count, ownership, or mode invariants.
    pub(super) fn exists(&self) -> Result<bool, io::Error> {
        match fs::openat(&*self.directory, &self.name, read_flags(), Mode::empty()) {
            Ok(descriptor) => {
                validate_regular(&descriptor, self.trusted_owner)?;
                Ok(true)
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    /// Opens the validated target read-only without releasing its parent anchor.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is absent, is not a singly linked
    /// regular file owned by the trusted identity, or cannot be opened without
    /// following links.
    pub(super) fn open_read_only(&self) -> Result<File, io::Error> {
        let descriptor = fs::openat(&*self.directory, &self.name, read_flags(), Mode::empty())
            .map_err(io::Error::from)?;
        validate_regular(&descriptor, self.trusted_owner)?;
        Ok(File::from(descriptor))
    }

    /// Reads the bounded target when it exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unsafe, cannot be read, or exceeds
    /// `limit`.
    pub(super) fn read_optional(&self, limit: u64) -> Result<Option<Vec<u8>>, io::Error> {
        match self.read(limit) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Reads at most `limit` bytes from the trusted target.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is absent or unsafe, an I/O operation
    /// fails, or the file exceeds or grows beyond `limit`.
    pub(super) fn read(&self, limit: u64) -> Result<Vec<u8>, io::Error> {
        let descriptor = fs::openat(&*self.directory, &self.name, read_flags(), Mode::empty())
            .map_err(io::Error::from)?;
        validate_regular(&descriptor, self.trusted_owner)?;
        let metadata = fs::fstat(&descriptor).map_err(io::Error::from)?;
        if metadata.st_size < 0 || u64::try_from(metadata.st_size).unwrap_or(u64::MAX) > limit {
            return Err(invalid("native ability state exceeds its size bound"));
        }

        let mut bytes = Vec::with_capacity(metadata.st_size as usize);
        File::from(descriptor)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(invalid("native ability state grew beyond its size bound"));
        }
        Ok(bytes)
    }

    /// Returns the validated target's raw Unix mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be opened or violates the
    /// trusted regular-file invariants.
    pub(super) fn mode(&self) -> Result<u32, io::Error> {
        let descriptor = fs::openat(&*self.directory, &self.name, read_flags(), Mode::empty())
            .map_err(io::Error::from)?;
        validate_regular(&descriptor, self.trusted_owner)?;
        let metadata = fs::fstat(&descriptor).map_err(io::Error::from)?;
        Ok(metadata.st_mode)
    }

    /// Atomically replaces the target and makes its parent entry durable.
    ///
    /// The temporary file is written with mode 0600, synchronized, and renamed
    /// through the retained parent descriptor. When `immutable` is true, write
    /// permission is removed and synchronized before publication.
    ///
    /// # Errors
    ///
    /// Returns an error when creation, writing, permission change, syncing,
    /// rename, or parent-directory synchronization fails.
    pub(super) fn atomic_write(&self, bytes: &[u8], immutable: bool) -> Result<(), io::Error> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = OsString::from(format!(
            ".aos-ability-tmp-{}-{sequence}",
            std::process::id()
        ));
        let descriptor = fs::openat(
            &*self.directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)?;
        let result = (|| {
            let mut file = File::from(descriptor);
            file.write_all(bytes)?;
            file.sync_all()?;
            if immutable {
                fs::fchmod(&file, Mode::RUSR).map_err(io::Error::from)?;
                file.sync_all()?;
            }
            drop(file);
            fs::renameat(&*self.directory, &temporary, &*self.directory, &self.name)
                .map_err(io::Error::from)?;
            self.sync_parent()
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&*self.directory, &temporary, AtFlags::empty());
        }
        result
    }

    /// Removes the named target without following it; absence is successful.
    ///
    /// # Errors
    ///
    /// Returns an error when unlinking an existing target fails.
    pub(super) fn remove(&self) -> Result<(), io::Error> {
        match fs::unlinkat(&*self.directory, &self.name, AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    }

    /// Synchronizes the retained parent directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be synchronized.
    pub(super) fn sync_parent(&self) -> Result<(), io::Error> {
        fs::fsync(&*self.directory).map_err(io::Error::from)
    }

    pub(super) fn display(&self) -> &Path {
        &self.display
    }
}

/// Verifies that this process is the exact native executor selected by an artifact.
///
/// # Errors
///
/// Returns an error when the current executable cannot be resolved to the
/// artifact's exact Nix store path and entry point.
pub(super) fn authenticate_native_executor(
    artifact: &ArtifactReference,
    entry_point: &str,
    subject: &str,
) -> Result<(), io::Error> {
    let executable = std::env::current_exe()
        .map_err(|error| invalid(format!("resolving {subject} native executor path: {error}")))?;
    authenticate_native_executor_path(artifact, entry_point, subject, &executable)
}

/// Applies native-executor authentication to an explicit path for focused tests.
///
/// # Errors
///
/// Returns an error when `executable` is outside the Nix store or differs from
/// the artifact's exact store path and entry point.
pub(super) fn authenticate_native_executor_path(
    artifact: &ArtifactReference,
    entry_point: &str,
    subject: &str,
    executable: &Path,
) -> Result<(), io::Error> {
    let (root, suffix) = super::stock::store_root_and_suffix(executable).map_err(|error| {
        invalid(format!(
            "{subject} native executor is outside the Nix store: {error}"
        ))
    })?;
    if root.as_os_str() != OsStr::new(&artifact.store_path)
        || suffix.as_os_str() != OsStr::new(entry_point)
    {
        return Err(invalid(format!(
            "signed {subject} handler artifact does not identify the running package runtime"
        )));
    }
    Ok(())
}

fn is_canonical_absolute(path: &str) -> bool {
    path.starts_with('/')
        && (path == "/" || !path.ends_with('/'))
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn is_canonical_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

fn validate_directory(
    descriptor: &OwnedFd,
    trusted_owner: u32,
    label: &str,
) -> Result<(), io::Error> {
    let metadata = fs::fstat(descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != trusted_owner
        || metadata.st_mode & 0o022 != 0
    {
        return Err(invalid(format!(
            "{label} is not protected by the trusted owner"
        )));
    }
    Ok(())
}

fn validate_ancestor(
    descriptor: &OwnedFd,
    test_namespace_root_owner: Option<u32>,
    trusted_owner: u32,
    label: &str,
) -> Result<(), io::Error> {
    let metadata = fs::fstat(descriptor).map_err(io::Error::from)?;
    if !ancestor_is_protected(
        metadata.st_mode,
        metadata.st_uid,
        test_namespace_root_owner,
        trusted_owner,
    ) {
        return Err(invalid(format!(
            "{label} has an ancestor without trusted rename protection"
        )));
    }
    Ok(())
}

fn ancestor_is_protected(
    mode: u32,
    owner: u32,
    test_namespace_root_owner: Option<u32>,
    trusted_owner: u32,
) -> bool {
    let is_directory = FileType::from_raw_mode(mode) == FileType::Directory;
    let owner_is_trusted = owner_has_native_authority(owner, trusted_owner)
        || test_namespace_root_owner == Some(owner);
    let writable_by_others = mode & 0o022 != 0;
    let has_sticky_rename_protection = mode & 0o1000 != 0;
    is_directory && owner_is_trusted && (!writable_by_others || has_sticky_rename_protection)
}

fn owner_has_native_authority(owner: u32, trusted_owner: u32) -> bool {
    owner == 0 || owner == trusted_owner
}

#[cfg(not(test))]
fn test_namespace_root_owner(_descriptor: &OwnedFd) -> Result<Option<u32>, io::Error> {
    Ok(None)
}

#[cfg(test)]
fn test_namespace_root_owner(descriptor: &OwnedFd) -> Result<Option<u32>, io::Error> {
    // Nix test sandboxes map the namespace root owner to the overflow UID. This
    // exception exists only in test binaries; production always requires UID 0.
    let owner = fs::fstat(descriptor).map_err(io::Error::from)?.st_uid;
    Ok(Some(owner))
}

fn validate_regular(descriptor: &OwnedFd, trusted_owner: u32) -> Result<(), io::Error> {
    let metadata = fs::fstat(descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != trusted_owner
        || metadata.st_mode & 0o022 != 0
    {
        return Err(invalid(
            "native ability state is not a singly linked regular file",
        ));
    }
    Ok(())
}

fn validate_name(name: &OsStr) -> Result<(), io::Error> {
    if name.is_empty()
        || name == OsStr::new(".")
        || name == OsStr::new("..")
        || name.as_encoded_bytes().contains(&b'/')
    {
        return Err(invalid("native ability path has an invalid component"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn child_directory_rejects_multicomponent_names_before_lookup() {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = std::fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        std::fs::create_dir_all(root.path().join("target/child"))
            .expect("symlink target is created");
        std::fs::create_dir_all(root.path().join("a/b"))
            .expect("ordinary nested directory is created");
        symlink("target", root.path().join("symlink")).expect("directory symlink is created");

        let rooted =
            RootedDirectory::open(root.path(), owner, "test root").expect("test root is opened");
        for name in ["symlink/child", "a/b", "/", "symlink/", "symlink/.", "./"] {
            let error = rooted
                .child_directory(name)
                .expect_err("child name must be exactly one component");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}");
        }
    }

    #[test]
    fn ancestor_policy_rejects_an_untrusted_owner() {
        let directory = FileType::Directory.as_raw_mode();
        assert!(!ancestor_is_protected(directory | 0o755, 2000, None, 1000));
        assert!(ancestor_is_protected(directory | 0o755, 0, None, 1000));
        assert!(!ancestor_is_protected(directory | 0o755, 65534, None, 1000));
        assert!(ancestor_is_protected(
            directory | 0o755,
            65534,
            Some(65534),
            1000
        ));
        assert!(ancestor_is_protected(directory | 0o1755, 1000, None, 1000));
        assert!(!ancestor_is_protected(directory | 0o0777, 1000, None, 1000));
    }

    #[test]
    fn production_root_authority_requires_uid_zero() {
        assert!(owner_has_native_authority(0, 1000));
        assert!(owner_has_native_authority(1000, 1000));
        assert!(!owner_has_native_authority(65534, 1000));
    }
}
