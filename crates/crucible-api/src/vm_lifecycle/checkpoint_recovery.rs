//! Fresh-process recovery for exact-checkpoint transaction artifacts.

use super::*;

const CAPTURE_STAGING_DIRECTORY: &str = ".exact-checkpoint-";
const CLOSURE_STAGING_DIRECTORY: &str = ".closure-";
const OBJECT_STAGING_DIRECTORY: &str = ".object-";

/// Recovers authenticated durable closure ownership for a new lifecycle.
///
/// # Errors
///
/// Returns an error when the published catalog is malformed or incomplete.
pub(super) fn recover_published_checkpoint_states(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
) -> Result<BTreeMap<ContentHash, quantum_loop::ExactCheckpointPublicationState>, LifecycleApiError>
{
    checkpoint_store::recover_published_checkpoint_catalog(run_state_root, scenario, source).map(
        |catalog| {
            catalog
                .into_iter()
                .map(|(configuration, identity)| {
                    (
                        configuration,
                        quantum_loop::ExactCheckpointPublicationState::Published(identity),
                    )
                })
                .collect()
        },
    )
}

/// Preserves typed resource coordinates from durable run-state operations.
pub(super) fn durable_run_state_api_error(error: DurableRunStateError) -> LifecycleApiError {
    match error {
        DurableRunStateError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        }),
        error => loop_factory_error(error.to_string()),
    }
}

/// Removes capture staging owned by a prior lifecycle that cannot still run.
///
/// The caller proves the run owner is gone before invoking this helper. Final
/// content-addressed closures are never stored below this per-run directory.
///
/// # Errors
///
/// Returns an error when the directory cannot be inspected, an unexpected
/// entry has the transaction prefix, or removal cannot be made durable.
pub(super) fn reconcile_abandoned_run_checkpoint_staging(
    run_directory: &Path,
) -> Result<(), LifecycleApiError> {
    remove_staging_directories(
        &run_directory.join("exact-checkpoints"),
        CAPTURE_STAGING_DIRECTORY,
        "exact checkpoint capture",
    )
}

/// Removes shared-store staging when no lifecycle for the scenario is alive.
///
/// Final closure and object names are content hashes and therefore cannot
/// collide with either transaction prefix.
///
/// # Errors
///
/// Returns an error when either store directory cannot be inspected or a
/// staging directory cannot be removed durably.
pub(super) fn reconcile_abandoned_checkpoint_store_staging(
    run_state_root: &Path,
    scenario: ContentHash,
) -> Result<(), LifecycleApiError> {
    let scenario_directory = run_state_root.join(scenario.to_hex());
    remove_staging_directories(
        &scenario_directory.join("checkpoint-closures"),
        CLOSURE_STAGING_DIRECTORY,
        "exact checkpoint closure",
    )?;
    remove_staging_directories(
        &scenario_directory.join("checkpoint-objects"),
        OBJECT_STAGING_DIRECTORY,
        "exact checkpoint object",
    )
}

fn remove_staging_directories(
    parent: &Path,
    prefix: &str,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(loop_factory_error(format!(
                "enumerate abandoned {role} staging in {}: {error}",
                parent.display()
            )));
        }
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|error| {
            loop_factory_error(format!(
                "read abandoned {role} staging entry in {}: {error}",
                parent.display()
            ))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(prefix) {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|error| {
                loop_factory_error(format!(
                    "inspect abandoned {role} staging {}: {error}",
                    entry.path().display()
                ))
            })?
            .is_dir()
        {
            return Err(loop_factory_error(format!(
                "abandoned {role} staging path {} is not a directory",
                entry.path().display()
            )));
        }
        fs::remove_dir_all(entry.path()).map_err(|error| {
            loop_factory_error(format!(
                "remove abandoned {role} staging {}: {error}",
                entry.path().display()
            ))
        })?;
        removed = true;
    }
    if removed {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                loop_factory_error(format!(
                    "flush reconciled {role} staging directory {}: {error}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- child-process fixtures need exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;
    use std::process::Command;

    const CHILD_ROOT: &str = "CRUCIBLE_CHECKPOINT_RECOVERY_CHILD_ROOT";
    const TEST_NAME: &str = "vm_lifecycle::checkpoint_recovery::tests::fresh_process_removes_only_abandoned_checkpoint_staging";

    #[test]
    fn fresh_process_removes_only_abandoned_checkpoint_staging() {
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let run_staging = root.join("prior-run/exact-checkpoints/.exact-checkpoint-owned");
            let closure_staging = root.join("store/checkpoint-closures/.closure-owned");
            let object_staging = root.join("store/checkpoint-objects/.object-owned");
            for path in [&run_staging, &closure_staging, &object_staging] {
                fs::create_dir_all(path).expect("create child-owned staging directory");
                fs::write(path.join("owned"), b"incomplete")
                    .expect("write child-owned staging artifact");
            }
            fs::create_dir_all(root.join("store/checkpoint-closures/final"))
                .expect("create final closure sentinel");
            std::process::exit(86);
        }

        let fixture = tempfile::tempdir().expect("create recovery fixture");
        let status = Command::new(std::env::current_exe().expect("locate test executable"))
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_ROOT, fixture.path())
            .status()
            .expect("launch abrupt prior controller");
        assert_eq!(status.code(), Some(86));

        reconcile_abandoned_run_checkpoint_staging(&fixture.path().join("prior-run"))
            .expect("remove prior-run capture staging");
        let store = fixture.path().join("store");
        remove_staging_directories(
            &store.join("checkpoint-closures"),
            CLOSURE_STAGING_DIRECTORY,
            "exact checkpoint closure",
        )
        .expect("remove closure staging");
        remove_staging_directories(
            &store.join("checkpoint-objects"),
            OBJECT_STAGING_DIRECTORY,
            "exact checkpoint object",
        )
        .expect("remove object staging");

        assert!(
            !fixture
                .path()
                .join("prior-run/exact-checkpoints/.exact-checkpoint-owned")
                .exists()
        );
        assert!(!store.join("checkpoint-closures/.closure-owned").exists());
        assert!(!store.join("checkpoint-objects/.object-owned").exists());
        assert!(store.join("checkpoint-closures/final").is_dir());
    }
}
