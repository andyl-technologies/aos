//! Erases complete native pack/index payloads using genuine retained checks.
//!
//! Physical enumeration discovers deletion targets only after the closed Guard
//! producer has qualified complete authoritative roots. It supplies no actor,
//! completeness-of-ref-inventory, original, or collector authority.

use std::path::{Path, PathBuf};

use super::{Plan, publication::contextual_frame};
use crate::bucket::{BucketBinding, publication::SelectedObservation};
use crate::selected_bridge::native_guard::GuardEffectContext;
use crate::store::{LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::bucket::BucketKey;

fn failure(error: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}

fn corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("domain-deletion".into()),
    ))
}

/// Enumerates checked physical payload leaves without deriving any authority.
async fn payloads<F: LocalFs + BucketBinding>(
    fs: &F,
    root: &Path,
) -> Result<Vec<PathBuf>, StoreFailure> {
    let mut pending = vec![root.join("objects/pack"), root.join("objects/index")];
    let mut result = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = match fs.symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(failure(error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(corrupt());
        }
        if metadata.is_dir() {
            for child in fs.read_dir(&path).await.map_err(failure)? {
                if child.parent() != Some(path.as_path()) {
                    return Err(corrupt());
                }
                pending.push(child);
            }
        } else if metadata.is_file() {
            let key = path
                .strip_prefix(root)
                .map_err(|_| corrupt())?
                .to_str()
                .ok_or_else(corrupt)?;
            let key = BucketKey::parse(key).map_err(|_| corrupt())?;
            if !(key.as_str().starts_with("objects/pack/")
                || key.as_str().starts_with("objects/index/"))
            {
                return Err(corrupt());
            }
            result.push(path);
        } else {
            return Err(corrupt());
        }
    }
    result.sort();
    Ok(result)
}

/// Removes every actual pack/index while source and signed pending audit remain held.
///
/// # Errors
/// Preserves changed protected/current whole-record inputs, actual native
/// descriptor refusal, unsafe payloads, expired authority and failed durability.
/// Partial or indeterminate failure leaves the independently signed intent pending.
pub(crate) async fn erase<F: LocalFs + BucketBinding>(
    fs: &F,
    source: &SelectedObservation<'_>,
    audit: &SelectedObservation<'_>,
    context: &GuardEffectContext,
) -> Result<(), StoreFailure> {
    let (mut frame, _) = contextual_frame(fs, audit, &[source], context).await?;
    let root = source.identity().root();
    let targets = payloads(fs, root).await?;
    for target in targets {
        frame
            .remove_domain_target(fs, root, &target, source.configured_operator_uid())
            .await?;
    }
    if !payloads(fs, root).await?.is_empty() {
        return Err(corrupt());
    }
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "tokio"))]
mod test_fault {
    use crate::store::{EffectFault, NativeFsEffect, StoreErrorKind, StoreFailure};
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };
    static FAULTS: OnceLock<Mutex<BTreeMap<PathBuf, PathBuf>>> = OnceLock::new();

    /// Arms one failure at the actual unlink parent sync.
    ///
    /// # Errors
    /// Returns an error for poisoned state or an already armed root.
    pub(crate) fn arm(root: &Path, parent: &Path) -> Result<(), StoreFailure> {
        let mut faults = FAULTS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }))?;
        if faults.contains_key(root) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        faults.insert(root.to_owned(), parent.to_owned());
        Ok(())
    }

    /// Attaches an armed parent-sync failure to the actual native effect.
    ///
    /// # Errors
    /// Returns an error when the fixture state is poisoned.
    pub(crate) fn inject(
        root: &Path,
        effect: NativeFsEffect,
    ) -> Result<NativeFsEffect, StoreFailure> {
        let fault = FAULTS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }))?
            .remove(root);
        Ok(match fault {
            Some(parent) => {
                effect.inject_test_faults(vec![EffectFault::BeforeDirectorySyncAt(parent)])
            }
            None => effect,
        })
    }
}

#[cfg(all(test, feature = "tokio"))]
pub(crate) use test_fault::arm as fail_next_parent_sync;

#[cfg(all(test, feature = "tokio"))]
pub(super) use test_fault::inject as inject_remove_fault;
