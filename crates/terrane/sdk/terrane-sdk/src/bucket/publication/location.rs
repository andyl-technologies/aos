//! Fixes the configured external control location without filesystem effects.
//!
//! The default sibling name uses raw BLAKE3-256 over the exact normalized
//! absolute root bytes. Configuration describes a proposed location only;
//! actual protected ownership, identity and ancestry need separate verification.

use crate::bucket::FileBucketPublicationConfig;
use crate::store::{StoreErrorKind, StoreFailure};
use std::path::{Component, Path, PathBuf};

fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

/// Resolves the canonical configured owner and external control location.
///
/// # Errors
/// Refuses noncanonical or overlapping locations, and an unconfigured control
/// location on platforms without the native default naming representation.
pub(in crate::bucket) fn configured_location(
    root: &Path,
    config: &FileBucketPublicationConfig,
) -> Result<(u32, PathBuf), StoreFailure> {
    let unsupported = || StoreFailure::new(StoreErrorKind::Unsupported);
    if !normalized(root) {
        return Err(unsupported());
    }

    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStrExt;

        config.control.clone().unwrap_or_else(|| {
            let hash: String = blake3::hash(root.as_os_str().as_bytes())
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            root.with_file_name(format!(".terrane-control:{hash}"))
        })
    };
    #[cfg(not(unix))]
    let path = config.control.clone().ok_or_else(unsupported)?;

    if !normalized(&path) || path.starts_with(root) || root.starts_with(&path) {
        return Err(unsupported());
    }
    Ok((config.operator_uid, path))
}
