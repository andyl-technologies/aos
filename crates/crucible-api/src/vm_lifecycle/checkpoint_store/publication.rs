//! Atomic closure publication and durability-state classification.

use super::*;
use crucible::model::FaultResourceLimitError;

/// Durable-store outcome relative to the closure manifest rename.
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

/// Counts authenticated-name closure directories without discarding I/O errors.
///
/// # Errors
///
/// Returns an error for directory inspection or resource admission failures.
pub(super) fn enforce_published_checkpoint_count(
    parent: &Path,
    limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(parent)
        .map_err(|error| store_error(format!("count published checkpoint closures: {error}")))?
    {
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
    let count = u64::try_from(count)
        .map_err(|_| store_error("published checkpoint count is not representable"))?;
    limits
        .reserve(
            "checkpoint_count",
            count.saturating_sub(1),
            u64::from(count != 0),
        )
        .map_err(scheduler_resource_limit)
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
    fn published_checkpoint_count_ignores_transaction_staging_directories() {
        let root = tempfile::tempdir().expect("create checkpoint count fixture");
        fs::create_dir(root.path().join(".closure-incomplete"))
            .expect("create transaction staging directory");
        fs::create_dir(root.path().join("not-a-checkpoint")).expect("create unrelated directory");
        fs::create_dir(root.path().join("0".repeat(64)))
            .expect("create one published checkpoint directory");
        let limits = FaultResourceLimits {
            checkpoint_count: 1,
            ..FaultResourceLimits::default()
        };

        enforce_published_checkpoint_count(root.path(), limits)
            .expect("only the published identity counts against the limit");

        fs::create_dir(root.path().join("1".repeat(64)))
            .expect("create a second published checkpoint directory");
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
}
