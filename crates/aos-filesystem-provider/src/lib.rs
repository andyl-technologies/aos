//! Provider-owned storage allocation and filesystem view validation.
//!
//! The crate validates exact mutable storage paths, rejects overlapping claims,
//! and resolves child views without following symbolic links. The executable
//! handler owns durable realization through the shared provider protocol.

use std::fs;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

pub mod handler;

/// Reports why a requested storage path cannot be safely realized.
#[derive(Debug, Error)]
pub enum FilesystemPathError {
    /// The requested path violates normalization, ownership, or containment.
    #[error("invalid filesystem provider path: {0}")]
    InvalidPath(String),
    /// A filesystem observation needed for validation failed.
    #[error("cannot inspect {operation}: {message}")]
    Observation {
        /// Names the observation being attempted.
        operation: &'static str,
        /// Describes the operating-system failure.
        message: String,
    },
}

/// Validates one exact provider-owned requested storage path.
///
/// The filesystem provider may own children beneath `/run` and `/var/lib`.
/// The two mutable roots themselves remain shared platform resources.
///
/// # Errors
///
/// Returns an error for a relative or non-normalized path, a shared root, a
/// path outside the provider's mutable roots, or an existing symbolic-link
/// component.
pub fn validate_requested_storage_path(path: &Path) -> Result<(), FilesystemPathError> {
    validate_provider_owned_path(path, &[Path::new("/run"), Path::new("/var/lib")])
}

/// Validates a provider-owned path beneath one of the exact mutable roots.
///
/// # Errors
///
/// Returns an error when the path is malformed, names a shared root, falls
/// outside every supplied root, or crosses an existing symbolic link.
pub fn validate_provider_owned_path(
    path: &Path,
    roots: &[&Path],
) -> Result<(), FilesystemPathError> {
    checked_absolute_path(path, "requested storage")?;
    if roots.iter().any(|root| path == *root) {
        return Err(invalid(
            "requested storage cannot claim a shared mutable root",
        ));
    }
    if !roots.iter().any(|root| path.starts_with(root)) {
        return Err(invalid(
            "requested storage is outside the provider-owned mutable roots",
        ));
    }
    reject_existing_symlink_components(path, "requested storage")
}

/// Rejects overlapping exact storage claims.
///
/// # Errors
///
/// Returns an error when `candidate` contains or is contained by an existing
/// claim owned by another logical resource.
pub fn validate_storage_claim(
    candidate: &Path,
    existing: impl IntoIterator<Item = PathBuf>,
) -> Result<(), FilesystemPathError> {
    for claimed in existing {
        if candidate == claimed || candidate.starts_with(&claimed) || claimed.starts_with(candidate)
        {
            return Err(invalid("requested storage overlaps an existing claim"));
        }
    }
    Ok(())
}

/// Resolves one portable child view beneath an admitted storage root.
///
/// Existing path components must remain ordinary directories or the final
/// object. A missing suffix is retained lexically so providers can authorize a
/// socket or file before its owning service creates it.
///
/// # Errors
///
/// Returns an error for a non-directory root, an unsafe relative path, a
/// symbolic-link component, a non-directory ancestor, or canonical escape.
pub fn resolve_storage_view_path(
    root: &Path,
    relative_path: Option<&str>,
) -> Result<PathBuf, FilesystemPathError> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| encoding_error("storage view", format!("cannot resolve root: {error}")))?;
    if !canonical_root.is_dir() {
        return Err(invalid("storage view root is not a directory"));
    }
    let Some(relative_path) = relative_path else {
        return Ok(canonical_root);
    };
    let relative = checked_relative_path(relative_path, "storage view")?;
    let components = relative.components().collect::<Vec<_>>();
    let mut resolved = canonical_root.clone();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(invalid("storage view path is not normalized"));
        };
        resolved.push(component);
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(invalid("storage view traverses a symbolic link"));
                }
                if index + 1 < components.len() && !metadata.is_dir() {
                    return Err(invalid("storage view traverses a non-directory ancestor"));
                }
                let canonical = fs::canonicalize(&resolved).map_err(|error| {
                    encoding_error("storage view", format!("cannot resolve component: {error}"))
                })?;
                if !canonical.starts_with(&canonical_root) {
                    return Err(invalid("storage view escapes its admitted root"));
                }
                resolved = canonical;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                for suffix in &components[index + 1..] {
                    let Component::Normal(suffix) = suffix else {
                        return Err(invalid("storage view path is not normalized"));
                    };
                    resolved.push(suffix);
                }
                break;
            }
            Err(error) => {
                return Err(encoding_error(
                    "storage view",
                    format!("cannot inspect component: {error}"),
                ));
            }
        }
    }
    Ok(resolved)
}

fn checked_relative_path(path: &str, label: &'static str) -> Result<PathBuf, FilesystemPathError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "{label} path is not a portable relative path"
        )));
    }
    Ok(path.to_path_buf())
}

fn checked_absolute_path(path: &Path, label: &'static str) -> Result<(), FilesystemPathError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "{label} path is not normalized and absolute"
        )));
    }
    Ok(())
}

fn reject_existing_symlink_components(
    path: &Path,
    label: &'static str,
) -> Result<(), FilesystemPathError> {
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(component) = component else {
            return Err(invalid(format!("{label} path is not normalized")));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid(format!("{label} traverses a symbolic link")));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(encoding_error(
                    label,
                    format!("cannot inspect path component: {error}"),
                ));
            }
        }
    }
    Ok(())
}

fn encoding_error(operation: &'static str, message: impl Into<String>) -> FilesystemPathError {
    FilesystemPathError::Observation {
        operation,
        message: message.into(),
    }
}

fn invalid(message: impl Into<String>) -> FilesystemPathError {
    FilesystemPathError::InvalidPath(message.into())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn storage_child_view_rejects_symlinks_and_allows_an_absent_socket() {
        let temporary = tempdir().expect("temporary root exists");
        let root = temporary.path().join("storage");
        let outside = temporary.path().join("outside");
        fs::create_dir(&root).expect("storage root exists");
        fs::create_dir(&outside).expect("outside directory exists");
        symlink(&outside, root.join("escape")).expect("escape symlink exists");

        assert_eq!(
            resolve_storage_view_path(&root, Some("containerd.sock"))
                .expect("absent child remains authorized"),
            fs::canonicalize(&root)
                .expect("root canonicalizes")
                .join("containerd.sock")
        );
        assert!(
            resolve_storage_view_path(&root, Some("escape/socket"))
                .expect_err("symlink is rejected")
                .to_string()
                .contains("symbolic link")
        );
        assert!(resolve_storage_view_path(&root, Some("../foreign")).is_err());
    }

    #[test]
    fn storage_claims_reject_equal_parent_and_child_paths() {
        let candidate = Path::new("/var/lib/docker");
        for claimed in [
            PathBuf::from("/var/lib/docker"),
            PathBuf::from("/var/lib"),
            PathBuf::from("/var/lib/docker/volumes"),
        ] {
            assert!(
                validate_storage_claim(candidate, [claimed])
                    .expect_err("overlap is rejected")
                    .to_string()
                    .contains("overlaps")
            );
        }
        validate_storage_claim(candidate, [PathBuf::from("/var/lib/containerd")])
            .expect("siblings do not overlap");
    }
}
