//! Protected descriptor-relative storage for current activation authority.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};

use super::{
    CURRENT_ABILITY_AUTHORITY_MAX_BYTES, CurrentAbilityAuthorityDocument, CurrentAuthorityError,
    CurrentAuthorityPublication, CurrentAuthorityScope, build_publication, invalid, io_error,
};

static AUTHORITY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Atomically publishes current authority at a protected native path.
#[derive(Clone, Debug)]
pub struct CurrentAbilityAuthorityPublisher {
    path: PathBuf,
    trust_anchor: PathBuf,
    trusted_owner: u32,
}

impl CurrentAbilityAuthorityPublisher {
    /// Constructs the production publisher for one exact activation scope.
    #[must_use]
    pub fn system(scope: &CurrentAuthorityScope) -> Self {
        Self {
            path: scope.system_path(),
            trust_anchor: PathBuf::from("/"),
            trusted_owner: 0,
        }
    }

    /// Constructs a publisher for an explicitly selected protected path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            trust_anchor: PathBuf::from("/"),
            trusted_owner: 0,
        }
    }

    /// Rederives exact bindings from authenticated policy and atomically publishes them.
    ///
    /// The caller is the native root trust boundary: policy documents and live
    /// observations must already be authenticated independently from the plan.
    /// Resource revisions must come from authoritative probes, never desired
    /// resource specifications.
    ///
    /// # Errors
    ///
    /// Returns an error when policy does not independently issue every checked
    /// binding, observations are malformed, sequence monotonicity fails, or the
    /// protected file cannot be durably replaced.
    pub fn publish(
        &self,
        publication: CurrentAuthorityPublication<'_>,
    ) -> Result<CurrentAbilityAuthorityDocument, CurrentAuthorityError> {
        let document = build_publication(publication)?;
        document.validate(&document.required_features.iter().cloned().collect())?;
        publish_authority_file(
            &self.path,
            &self.trust_anchor,
            self.trusted_owner,
            &document,
        )?;
        Ok(document)
    }

    #[cfg(test)]
    pub(super) fn for_test(path: PathBuf, trust_anchor: PathBuf, trusted_owner: u32) -> Self {
        Self {
            path,
            trust_anchor,
            trusted_owner,
        }
    }
}

/// Loads the root-owned current-authority file without following a final symlink.
#[derive(Clone, Debug)]
pub struct RootOwnedCurrentAuthoritySource {
    path: PathBuf,
    trust_anchor: PathBuf,
    trusted_owner: u32,
}

impl RootOwnedCurrentAuthoritySource {
    /// Constructs the production source for one exact activation scope.
    #[must_use]
    pub fn system(scope: &CurrentAuthorityScope) -> Self {
        Self {
            path: scope.system_path(),
            trust_anchor: PathBuf::from("/"),
            trusted_owner: 0,
        }
    }

    /// Constructs a source for an explicitly selected protected path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            trust_anchor: PathBuf::from("/"),
            trusted_owner: 0,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(path: PathBuf, trust_anchor: PathBuf, trusted_owner: u32) -> Self {
        Self {
            path,
            trust_anchor,
            trusted_owner,
        }
    }
}

/// Reloads the latest native current-authority document.
pub trait CurrentAbilityAuthoritySource {
    /// Structured source failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Securely reloads one current authority publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected source is absent or cannot be read.
    fn load_current(&mut self) -> Result<CurrentAbilityAuthorityDocument, Self::Error>;
}

impl CurrentAbilityAuthoritySource for RootOwnedCurrentAuthoritySource {
    type Error = CurrentAuthorityError;

    fn load_current(&mut self) -> Result<CurrentAbilityAuthorityDocument, Self::Error> {
        let parent = open_authority_parent(&self.path, &self.trust_anchor, self.trusted_owner)?;
        read_authority_at(&parent)
    }
}

pub(super) fn publish_authority_file(
    path: &Path,
    trust_anchor: &Path,
    trusted_owner: u32,
    document: &CurrentAbilityAuthorityDocument,
) -> Result<(), CurrentAuthorityError> {
    let bytes = aos_contract::canonical::to_vec(document)
        .map_err(|error| invalid(format!("encoding current authority: {error}")))?;
    let parent = open_authority_parent(path, trust_anchor, trusted_owner)?;
    let lock_name = authority_sibling_name(&parent.name, ".lock")?;
    let lock = fs::openat(
        &parent.directory,
        &lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|source| {
        io_error(
            "opening current authority publication lock",
            &parent.display,
            source.into(),
        )
    })?;
    validate_protected_file(
        &lock,
        parent.trusted_owner,
        "current authority publication lock",
    )?;
    fs::flock(&lock, FlockOperation::LockExclusive).map_err(|source| {
        io_error(
            "locking current authority publication",
            &parent.display,
            source.into(),
        )
    })?;

    match read_authority_at(&parent) {
        Ok(previous) => {
            if previous == *document {
                return fs::fsync(&parent.directory).map_err(|source| {
                    io_error(
                        "syncing current authority directory",
                        &parent.display,
                        source.into(),
                    )
                });
            }
            if document.sequence <= previous.sequence {
                return Err(invalid(
                    "changed current authority did not advance its sequence",
                ));
            }
            if document.observed_at_restart_millis < previous.observed_at_restart_millis {
                return Err(invalid(
                    "changed current authority regressed its observation timestamp",
                ));
            }
        }
        Err(CurrentAuthorityError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let sequence = AUTHORITY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = parent
        .name
        .to_str()
        .ok_or_else(|| invalid("current authority path has no UTF-8 file name"))?;
    let temporary_name = OsString::from(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        sequence
    ));
    let descriptor = fs::openat(
        &parent.directory,
        &temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|source| io_error("creating current authority", &parent.display, source.into()))?;
    let mut file = File::from(descriptor);
    if let Err(source) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = fs::unlinkat(
            &parent.directory,
            &temporary_name,
            rustix::fs::AtFlags::empty(),
        );
        return Err(io_error(
            "writing current authority",
            &parent.display,
            source,
        ));
    }
    drop(file);
    if let Err(source) = fs::renameat(
        &parent.directory,
        &temporary_name,
        &parent.directory,
        &parent.name,
    ) {
        let _ = fs::unlinkat(
            &parent.directory,
            &temporary_name,
            rustix::fs::AtFlags::empty(),
        );
        return Err(io_error(
            "publishing current authority",
            &parent.display,
            source.into(),
        ));
    }
    fs::fsync(&parent.directory).map_err(|source| {
        io_error(
            "syncing current authority directory",
            &parent.display,
            source.into(),
        )
    })
}

struct AuthorityParent {
    directory: OwnedFd,
    name: OsString,
    display: PathBuf,
    trusted_owner: u32,
}

fn open_authority_parent(
    path: &Path,
    trust_anchor: &Path,
    trusted_owner: u32,
) -> Result<AuthorityParent, CurrentAuthorityError> {
    if !path.is_absolute() || !trust_anchor.is_absolute() {
        return Err(invalid(
            "current authority and trust anchor must be absolute",
        ));
    }
    let relative = path
        .strip_prefix(trust_anchor)
        .map_err(|_| invalid("current authority lies outside its trust anchor"))?;
    let name = relative
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| invalid("current authority path has no valid file name"))?
        .to_os_string();
    let relative_parent = relative
        .parent()
        .ok_or_else(|| invalid("current authority path has no parent directory"))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory =
        fs::openat(fs::CWD, trust_anchor, flags, Mode::empty()).map_err(|source| {
            io_error(
                "opening current authority trust anchor",
                trust_anchor,
                source.into(),
            )
        })?;
    validate_protected_directory(&directory, trusted_owner)?;
    for component in relative_parent.components() {
        let component = match component {
            Component::CurDir => continue,
            Component::Normal(component) => component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid(
                    "current authority path contains an invalid traversal component",
                ));
            }
        };
        directory = fs::openat(&directory, component, flags, Mode::empty()).map_err(|source| {
            io_error("walking current authority directory", path, source.into())
        })?;
        validate_protected_directory(&directory, trusted_owner)?;
    }
    Ok(AuthorityParent {
        directory,
        name,
        display: path.to_path_buf(),
        trusted_owner,
    })
}

fn validate_protected_directory(
    directory: &OwnedFd,
    trusted_owner: u32,
) -> Result<(), CurrentAuthorityError> {
    let metadata = fs::fstat(directory)
        .map_err(|error| invalid(format!("inspecting current authority directory: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != trusted_owner
        || metadata.st_mode & 0o022 != 0
    {
        return Err(invalid(
            "current authority directory is not protected by the trusted owner",
        ));
    }
    Ok(())
}

fn read_authority_at(
    parent: &AuthorityParent,
) -> Result<CurrentAbilityAuthorityDocument, CurrentAuthorityError> {
    let descriptor = fs::openat(
        &parent.directory,
        &parent.name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| io_error("opening current authority", &parent.display, source.into()))?;
    let metadata = fs::fstat(&descriptor).map_err(|source| {
        io_error(
            "inspecting current authority",
            &parent.display,
            source.into(),
        )
    })?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != parent.trusted_owner
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(invalid(
            "current authority is not a protected singly linked regular file",
        ));
    }
    if metadata.st_size < 0
        || u64::try_from(metadata.st_size).unwrap_or(u64::MAX)
            > CURRENT_ABILITY_AUTHORITY_MAX_BYTES as u64
    {
        return Err(invalid("current authority exceeds its byte limit"));
    }

    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(metadata.st_size as usize);
    Read::by_ref(&mut file)
        .take(CURRENT_ABILITY_AUTHORITY_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("reading current authority", &parent.display, source))?;
    if bytes.len() > CURRENT_ABILITY_AUTHORITY_MAX_BYTES {
        return Err(invalid("current authority grew beyond its byte limit"));
    }
    let document: CurrentAbilityAuthorityDocument =
        aos_contract::canonical::from_slice(&bytes, "current ability authority")
            .map_err(|error| invalid(format!("decoding current authority: {error}")))?;
    let canonical = aos_contract::canonical::to_vec(&document)
        .map_err(|error| invalid(format!("encoding current authority: {error}")))?;
    if canonical != bytes {
        return Err(invalid("current authority is not canonical"));
    }
    document.validate(&document.required_features.iter().cloned().collect())?;
    Ok(document)
}

fn validate_protected_file(
    file: &OwnedFd,
    trusted_owner: u32,
    label: &str,
) -> Result<(), CurrentAuthorityError> {
    let metadata =
        fs::fstat(file).map_err(|error| invalid(format!("inspecting {label}: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != trusted_owner
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(invalid(format!(
            "{label} is not a protected singly linked regular file"
        )));
    }
    Ok(())
}

fn authority_sibling_name(name: &OsStr, suffix: &str) -> Result<OsString, CurrentAuthorityError> {
    let name = name
        .to_str()
        .ok_or_else(|| invalid("current authority path has no UTF-8 file name"))?;
    Ok(OsString::from(format!(".{name}{suffix}")))
}
