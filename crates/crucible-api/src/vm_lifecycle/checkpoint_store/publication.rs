//! Atomic closure publication and durability-state classification.

use super::*;
use crucible::model::FaultResourceLimitError;

/// Durable-store outcome relative to the closure manifest rename.
#[derive(Debug)]
pub(in crate::vm_lifecycle) enum PersistExactCheckpointError {
    /// The final closure directory is durably absent.
    Unpublished(SchedulerError),
    /// The final closure may be visible but its durability is uncertain.
    Indeterminate {
        /// Authenticated closure identity selected before the rename.
        identity: ContentHash,
        /// Count rollback or directory durability failure.
        source: SchedulerError,
    },
}

/// Prepared closure publication whose immutable objects are already durable.
///
/// A staged value owns the unpublished manifest directory. Dropping it removes
/// that directory, so the caller may release transient QMP snapshots before it
/// makes the authenticated closure visible.
#[must_use = "a prepared exact checkpoint must be published or deliberately abandoned"]
pub(in crate::vm_lifecycle) enum PreparedExactCheckpointPublication {
    /// An identical authenticated publication was already present.
    Existing {
        identity: ContentHash,
        closure_parent: PathBuf,
    },
    /// The manifest is durable in a private staging directory.
    Staged {
        identity: ContentHash,
        staging: tempfile::TempDir,
        destination: PathBuf,
        closure_parent: PathBuf,
        resource_limits: Box<FaultResourceLimits>,
    },
}

impl PreparedExactCheckpointPublication {
    /// Returns the authenticated closure identity selected during preparation.
    pub(in crate::vm_lifecycle) fn identity(&self) -> ContentHash {
        match self {
            Self::Existing { identity, .. } | Self::Staged { identity, .. } => *identity,
        }
    }

    /// Returns whether the closure was already visible before this transaction.
    pub(in crate::vm_lifecycle) fn was_already_published(&self) -> bool {
        matches!(self, Self::Existing { .. })
    }

    /// Makes the prepared manifest visible and synchronizes its parent.
    ///
    /// # Errors
    ///
    /// Returns [`PersistExactCheckpointError::Unpublished`] when publication is
    /// durably rolled back, or [`PersistExactCheckpointError::Indeterminate`]
    /// when manifest visibility or parent-directory durability is uncertain.
    pub(in crate::vm_lifecycle) fn publish(self) -> Result<(), PersistExactCheckpointError> {
        match self {
            Self::Existing {
                identity,
                closure_parent,
            } => sync_directory(&closure_parent)
                .map_err(|source| PersistExactCheckpointError::Indeterminate { identity, source }),
            Self::Staged {
                identity,
                staging,
                destination,
                closure_parent,
                resource_limits,
            } => {
                fs::rename(staging.path(), &destination).map_err(|error| {
                    store_error(format!(
                        "publish exact checkpoint closure {}: {error}",
                        destination.display()
                    ))
                })?;
                let count_result =
                    enforce_published_checkpoint_count(&closure_parent, *resource_limits);
                finalize_published_checkpoint(
                    identity,
                    count_result,
                    || {
                        fs::remove_dir_all(&destination).map_err(|cleanup| {
                            store_error(format!(
                                "roll back over-limit checkpoint publication {}: {cleanup}",
                                destination.display()
                            ))
                        })
                    },
                    || sync_directory(&closure_parent),
                )
            }
        }
    }
}

impl From<SchedulerError> for PersistExactCheckpointError {
    fn from(error: SchedulerError) -> Self {
        Self::Unpublished(error)
    }
}

pub(super) fn scheduler_resource_limit(error: FaultResourceLimitError) -> SchedulerError {
    match error {
        FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        }
        | FaultResourceLimitError::UsageOverflow {
            field,
            current,
            requested,
            configured,
            hard,
        } => SchedulerError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        error => store_error(error.to_string()),
    }
}

/// Admits one new closure against the currently published checkpoint count.
///
/// Transaction-staging directories do not consume the durable closure count.
/// Every directory entry and file type is inspected fail-closed before the
/// publication transaction begins.
///
/// # Errors
///
/// Returns an exact resource-limit error when the additional closure would
/// exceed the authored or compiled ceiling, or a store error when directory
/// inspection fails.
pub(super) fn admit_new_checkpoint_publication(
    parent: &Path,
    limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let count = published_checkpoint_count(parent)?;
    limits
        .reserve("checkpoint_count", count, 1)
        .map_err(scheduler_resource_limit)
}

/// Counts authenticated-name closure directories without discarding I/O errors.
///
/// # Errors
///
/// Returns an error for directory inspection or resource admission failures.
pub(super) fn enforce_published_checkpoint_count(
    parent: &Path,
    limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let count = published_checkpoint_count(parent)?;
    limits
        .reserve(
            "checkpoint_count",
            count.saturating_sub(1),
            u64::from(count != 0),
        )
        .map_err(scheduler_resource_limit)
}

fn published_checkpoint_count(parent: &Path) -> Result<u64, SchedulerError> {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(store_error(format!(
                "count published checkpoint closures: {error}"
            )));
        }
    };
    let mut count = 0_u64;
    for entry in entries {
        let entry = entry.map_err(|error| {
            store_error(format!("enumerate published checkpoint closures: {error}"))
        })?;
        let kind = entry.file_type().map_err(|error| {
            store_error(format!(
                "inspect published checkpoint closure type: {error}"
            ))
        })?;
        let is_identity = entry.file_name().to_str().is_some_and(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        });
        if kind.is_dir() && is_identity {
            count = count
                .checked_add(1)
                .ok_or_else(|| store_error("published checkpoint count is not representable"))?;
        }
    }
    Ok(count)
}

/// Finalizes count admission and parent durability after the manifest rename.
///
/// # Errors
///
/// Distinguishes a durably removed publication from an indeterminate outcome.
pub(super) fn finalize_published_checkpoint(
    identity: ContentHash,
    count_result: Result<(), SchedulerError>,
    mut remove_destination: impl FnMut() -> Result<(), SchedulerError>,
    mut sync_parent: impl FnMut() -> Result<(), SchedulerError>,
) -> Result<(), PersistExactCheckpointError> {
    if let Err(error) = count_result {
        let remove_result = remove_destination();
        let sync_result = sync_parent();
        return match (remove_result, sync_result) {
            (Ok(()), Ok(())) => Err(PersistExactCheckpointError::Unpublished(error)),
            (remove, sync) => Err(PersistExactCheckpointError::Indeterminate {
                identity,
                source: store_error(format!(
                    "checkpoint count admission failed ({error}); publication rollback was indeterminate (remove={remove:?}, sync={sync:?})"
                )),
            }),
        };
    }

    sync_parent().map_err(|source| PersistExactCheckpointError::Indeterminate { identity, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_checkpoint_count_ignores_transaction_staging_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join(".closure-incomplete"))?;
        fs::create_dir(root.path().join("not-a-checkpoint"))?;
        fs::create_dir(root.path().join("0".repeat(64)))?;
        let limits = FaultResourceLimits {
            checkpoint_count: 1,
            ..FaultResourceLimits::default()
        };

        enforce_published_checkpoint_count(root.path(), limits)?;

        fs::create_dir(root.path().join("1".repeat(64)))?;
        assert!(matches!(
            enforce_published_checkpoint_count(root.path(), limits),
            Err(SchedulerError::ResourceLimit {
                field: "checkpoint_count",
                current: 1,
                requested: 1,
                configured: 1,
                hard,
            }) if hard == FaultResourceLimits::compiled_maximum().checkpoint_count
        ));
        Ok(())
    }

    #[test]
    fn new_checkpoint_count_is_admitted_before_publication_with_exact_coordinates()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join(".closure-incomplete"))?;
        fs::create_dir(root.path().join("0".repeat(64)))?;
        let limits = FaultResourceLimits {
            checkpoint_count: 1,
            ..FaultResourceLimits::default()
        };

        let error = match admit_new_checkpoint_publication(root.path(), limits) {
            Ok(()) => return Err("a second publication succeeded before rename".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SchedulerError::ResourceLimit {
                field: "checkpoint_count",
                current: 1,
                requested: 1,
                configured: 1,
                hard,
            } if hard == FaultResourceLimits::compiled_maximum().checkpoint_count
        ));
        Ok(())
    }

    #[test]
    fn publication_commit_tail_distinguishes_rollback_from_durability_uncertainty() {
        let identity = ContentHash::from_bytes(b"published-checkpoint");
        let calls = std::cell::RefCell::new(Vec::new());
        let result = finalize_published_checkpoint(
            identity,
            Err(store_error("count limit")),
            || {
                calls.borrow_mut().push("remove");
                Ok(())
            },
            || {
                calls.borrow_mut().push("sync");
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(PersistExactCheckpointError::Unpublished(_))
        ));
        assert_eq!(*calls.borrow(), ["remove", "sync"]);

        let result = finalize_published_checkpoint(
            identity,
            Ok(()),
            || panic!("a successfully admitted publication must not be removed"),
            || Err(store_error("parent fsync")),
        );
        assert!(matches!(
            result,
            Err(PersistExactCheckpointError::Indeterminate {
                identity: observed,
                ..
            }) if observed == identity
        ));

        let calls = std::cell::RefCell::new(Vec::new());
        let result = finalize_published_checkpoint(
            identity,
            Err(store_error("count limit")),
            || {
                calls.borrow_mut().push("remove");
                Err(store_error("remove failed"))
            },
            || {
                calls.borrow_mut().push("sync");
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(PersistExactCheckpointError::Indeterminate {
                identity: observed,
                ..
            }) if observed == identity
        ));
        assert_eq!(*calls.borrow(), ["remove", "sync"]);
    }

    #[test]
    fn prepared_manifest_is_invisible_until_explicit_publication() {
        let root = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create publication fixture: {error}"));
        let closure_parent = root.path().join("checkpoint-closures");
        fs::create_dir(&closure_parent)
            .unwrap_or_else(|error| panic!("create closure parent: {error}"));
        let staging = tempfile::Builder::new()
            .prefix(".closure-")
            .tempdir_in(&closure_parent)
            .unwrap_or_else(|error| panic!("create private manifest staging: {error}"));
        fs::write(staging.path().join(MANIFEST_FILE), b"manifest")
            .unwrap_or_else(|error| panic!("write staged manifest: {error}"));
        let staging_path = staging.path().to_path_buf();
        let identity = ContentHash::from_bytes(b"prepared checkpoint");
        let destination = closure_parent.join(identity.to_hex());
        let prepared = PreparedExactCheckpointPublication::Staged {
            identity,
            staging,
            destination: destination.clone(),
            closure_parent,
            resource_limits: Box::new(FaultResourceLimits::default()),
        };

        assert!(staging_path.exists());
        assert!(!destination.exists());
        prepared
            .publish()
            .unwrap_or_else(|error| panic!("publish prepared manifest: {error:?}"));
        assert!(!staging_path.exists());
        assert_eq!(
            fs::read(destination.join(MANIFEST_FILE))
                .unwrap_or_else(|error| panic!("read published manifest: {error}")),
            b"manifest"
        );
    }

    #[test]
    fn abandoning_prepared_manifest_keeps_the_identity_unpublished() {
        let root = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create abandonment fixture: {error}"));
        let closure_parent = root.path().join("checkpoint-closures");
        fs::create_dir(&closure_parent)
            .unwrap_or_else(|error| panic!("create closure parent: {error}"));
        let staging = tempfile::Builder::new()
            .prefix(".closure-")
            .tempdir_in(&closure_parent)
            .unwrap_or_else(|error| panic!("create private manifest staging: {error}"));
        let staging_path = staging.path().to_path_buf();
        let identity = ContentHash::from_bytes(b"abandoned checkpoint");
        let destination = closure_parent.join(identity.to_hex());
        let prepared = PreparedExactCheckpointPublication::Staged {
            identity,
            staging,
            destination: destination.clone(),
            closure_parent,
            resource_limits: Box::new(FaultResourceLimits::default()),
        };

        drop(prepared);
        assert!(!staging_path.exists());
        assert!(!destination.exists());
    }
}
