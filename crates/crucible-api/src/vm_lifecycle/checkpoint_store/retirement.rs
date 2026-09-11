//! Crash-safe retirement of attempt-local native checkpoint catalogs.

use super::*;

const RETIRED_CATALOG_PREFIX: &str = ".retired-checkpoint-catalog-";

/// Opaque authority to retire one attempt-local native checkpoint catalog.
///
/// The authority is minted only from a completely authenticated production
/// closure. It deliberately names the whole scenario catalog beneath one
/// attempt-owned run-state root: a semantic worker never shares that root with
/// another concurrent execution, so every native object becomes redundant
/// after the corresponding campaign-CAS root is durable.
#[derive(Clone, Debug)]
pub struct ProductionExactCheckpointRetirement {
    run_state_root: PathBuf,
    scenario: ContentHash,
}

impl ProductionExactCheckpointRetirement {
    pub(super) fn new(run_state_root: PathBuf, scenario: ContentHash) -> Self {
        Self {
            run_state_root,
            scenario,
        }
    }
}

/// Result of one idempotent native-catalog retirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointRetirementReport {
    scenario: ContentHash,
    retired: bool,
}

impl ProductionExactCheckpointRetirementReport {
    /// Returns the exact semantic scenario whose attempt-local catalog was retired.
    #[must_use]
    pub const fn scenario(self) -> ContentHash {
        self.scenario
    }

    /// Returns whether this call made a published catalog unreachable.
    #[must_use]
    pub const fn retired(self) -> bool {
        self.retired
    }
}

/// Failure to retire one attempt-local native checkpoint catalog.
#[derive(Debug, thiserror::Error)]
pub enum ProductionExactCheckpointRetirementError {
    /// The catalog namespace violates the exclusive-owner state machine.
    #[error("native checkpoint catalog has both active and retired generations")]
    ConflictingGeneration,
    /// A catalog path was replaced by a non-directory filesystem object.
    #[error("native checkpoint catalog path is not a directory: {path}")]
    InvalidPath {
        /// Path that violated the catalog namespace contract.
        path: PathBuf,
    },
    /// A filesystem operation failed before durability was established.
    #[error("{operation} native checkpoint catalog {path}: {source}")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Exact path involved in the failed operation.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
}

impl ProductionExactCheckpointRetirementError {
    /// Returns whether exact retry under the same exclusive owner may succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Io { .. })
    }
}

/// Retires every native closure and object in one attempt-owned scenario catalog.
///
/// The caller must own the run-state root exclusively and must have stopped the
/// lifecycle that produced the catalog. The operation first renames the whole
/// scenario directory to a deterministic retired generation and synchronizes
/// the parent. Only then does it recursively remove the retired generation.
/// A crash can therefore leave redundant bytes, but cannot expose a partially
/// deleted active catalog. Exact retry completes either phase idempotently.
///
/// # Errors
///
/// Returns [`ProductionExactCheckpointRetirementError`] when namespace state is
/// inconsistent, a path is not a real directory, or rename, removal, or parent
/// synchronization fails.
pub fn retire_production_exact_checkpoint_catalog(
    authority: &ProductionExactCheckpointRetirement,
) -> Result<ProductionExactCheckpointRetirementReport, ProductionExactCheckpointRetirementError> {
    retire_production_exact_checkpoint_catalog_with(authority, &ProductionRetirementFilesystem)
}

trait RetirementFilesystem {
    fn rename(&self, source: &Path, destination: &Path) -> std::io::Result<()>;

    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()>;

    fn sync_parent(&self, path: &Path) -> std::io::Result<()>;
}

struct ProductionRetirementFilesystem;

impl RetirementFilesystem for ProductionRetirementFilesystem {
    fn rename(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
        fs::rename(source, destination)
    }

    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        fs::remove_dir_all(path)
    }

    fn sync_parent(&self, path: &Path) -> std::io::Result<()> {
        match File::open(path) {
            Ok(directory) => directory.sync_all(),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source),
        }
    }
}

fn retire_production_exact_checkpoint_catalog_with<F>(
    authority: &ProductionExactCheckpointRetirement,
    filesystem: &F,
) -> Result<ProductionExactCheckpointRetirementReport, ProductionExactCheckpointRetirementError>
where
    F: RetirementFilesystem,
{
    let parent = &authority.run_state_root;
    let scenario_name = authority.scenario.to_hex();
    let active = parent.join(&scenario_name);
    let retired = parent.join(format!("{RETIRED_CATALOG_PREFIX}{scenario_name}"));

    let active_present = directory_presence(&active)?;
    let retired_present = directory_presence(&retired)?;
    if active_present && retired_present {
        return Err(ProductionExactCheckpointRetirementError::ConflictingGeneration);
    }

    if retired_present {
        remove_retired_catalog(filesystem, &retired, parent)?;
    }
    if !active_present {
        sync_catalog_parent(filesystem, parent)?;
        return Ok(ProductionExactCheckpointRetirementReport {
            scenario: authority.scenario,
            retired: false,
        });
    }

    filesystem.rename(&active, &retired).map_err(|source| {
        ProductionExactCheckpointRetirementError::Io {
            operation: "rename",
            path: active.clone(),
            source,
        }
    })?;
    sync_catalog_parent(filesystem, parent)?;
    remove_retired_catalog(filesystem, &retired, parent)?;

    Ok(ProductionExactCheckpointRetirementReport {
        scenario: authority.scenario,
        retired: true,
    })
}

fn directory_presence(path: &Path) -> Result<bool, ProductionExactCheckpointRetirementError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(ProductionExactCheckpointRetirementError::InvalidPath {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ProductionExactCheckpointRetirementError::Io {
            operation: "inspect",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_retired_catalog<F>(
    filesystem: &F,
    retired: &Path,
    parent: &Path,
) -> Result<(), ProductionExactCheckpointRetirementError>
where
    F: RetirementFilesystem,
{
    filesystem.remove_dir_all(retired).map_err(|source| {
        ProductionExactCheckpointRetirementError::Io {
            operation: "remove",
            path: retired.to_path_buf(),
            source,
        }
    })?;
    sync_catalog_parent(filesystem, parent)
}

fn sync_catalog_parent<F>(
    filesystem: &F,
    parent: &Path,
) -> Result<(), ProductionExactCheckpointRetirementError>
where
    F: RetirementFilesystem,
{
    filesystem
        .sync_parent(parent)
        .map_err(|source| ProductionExactCheckpointRetirementError::Io {
            operation: "synchronize parent",
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::cell::Cell;

    use super::*;

    struct InjectedRetirementFilesystem {
        fail_operation: &'static str,
        failed: Cell<bool>,
    }

    impl InjectedRetirementFilesystem {
        fn once(fail_operation: &'static str) -> Self {
            Self {
                fail_operation,
                failed: Cell::new(false),
            }
        }

        fn inject(&self, operation: &'static str) -> std::io::Result<()> {
            if operation == self.fail_operation && !self.failed.replace(true) {
                Err(std::io::Error::other(format!(
                    "injected {operation} failure"
                )))
            } else {
                Ok(())
            }
        }
    }

    impl RetirementFilesystem for InjectedRetirementFilesystem {
        fn rename(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
            self.inject("rename")?;
            fs::rename(source, destination)
        }

        fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
            self.inject("remove")?;
            fs::remove_dir_all(path)
        }

        fn sync_parent(&self, path: &Path) -> std::io::Result<()> {
            self.inject("synchronize")?;
            ProductionRetirementFilesystem.sync_parent(path)
        }
    }

    fn retirement_fixture() -> (
        tempfile::TempDir,
        ProductionExactCheckpointRetirement,
        PathBuf,
        PathBuf,
    ) {
        let root = tempfile::tempdir().expect("retirement test root");
        let scenario = ContentHash::from_bytes(b"injected native retirement");
        let scenario_name = scenario.to_hex();
        let active = root.path().join(&scenario_name);
        let retired = root
            .path()
            .join(format!("{RETIRED_CATALOG_PREFIX}{scenario_name}"));
        fs::create_dir(&active).expect("active native catalog");
        fs::write(active.join("catalog"), b"native").expect("native catalog sentinel");
        let authority =
            ProductionExactCheckpointRetirement::new(root.path().to_path_buf(), scenario);
        (root, authority, active, retired)
    }

    #[test]
    fn retirement_retries_injected_rename_failure_with_same_authority() {
        let (_root, authority, active, retired) = retirement_fixture();
        let filesystem = InjectedRetirementFilesystem::once("rename");

        let error = retire_production_exact_checkpoint_catalog_with(&authority, &filesystem)
            .expect_err("injected rename must fail");
        assert!(error.is_retryable());
        assert!(active.exists());
        assert!(!retired.exists());

        let report = retire_production_exact_checkpoint_catalog_with(&authority, &filesystem)
            .expect("retry injected rename");
        assert!(report.retired());
        assert!(!active.exists());
        assert!(!retired.exists());
    }

    #[test]
    fn retirement_retries_injected_remove_failure_from_renamed_generation() {
        let (_root, authority, active, retired) = retirement_fixture();
        let filesystem = InjectedRetirementFilesystem::once("remove");

        let error = retire_production_exact_checkpoint_catalog_with(&authority, &filesystem)
            .expect_err("injected remove must fail");
        assert!(error.is_retryable());
        assert!(!active.exists());
        assert!(retired.exists());

        let report = retire_production_exact_checkpoint_catalog_with(&authority, &filesystem)
            .expect("retry injected remove");
        assert!(!report.retired());
        assert!(!retired.exists());
    }

    #[test]
    fn retirement_retries_injected_parent_fsync_after_durable_rename() {
        let (_root, authority, active, retired) = retirement_fixture();
        let filesystem = InjectedRetirementFilesystem::once("synchronize");

        let error = retire_production_exact_checkpoint_catalog_with(&authority, &filesystem)
            .expect_err("injected parent synchronization must fail");
        assert!(error.is_retryable());
        assert!(!active.exists());
        assert!(retired.exists());

        let report = retire_production_exact_checkpoint_catalog_with(&authority, &filesystem)
            .expect("retry injected parent synchronization");
        assert!(!report.retired());
        assert!(!retired.exists());
    }

    #[test]
    fn terminal_namespace_rejection_keeps_authority_reusable() {
        let (_root, authority, active, _retired) = retirement_fixture();
        fs::remove_dir_all(&active).expect("remove active catalog directory");
        fs::write(&active, b"invalid catalog entry").expect("replace catalog with file");

        let error = retire_production_exact_checkpoint_catalog(&authority)
            .expect_err("non-directory catalog must fail terminally");
        assert!(!error.is_retryable());

        fs::remove_file(&active).expect("remove invalid catalog entry");
        fs::create_dir(&active).expect("repair active catalog directory");
        let report = retire_production_exact_checkpoint_catalog(&authority)
            .expect("reuse retained authority after repair");
        assert!(report.retired());
    }
}
