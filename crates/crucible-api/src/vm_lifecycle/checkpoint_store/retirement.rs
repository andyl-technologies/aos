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
        remove_retired_catalog(&retired, parent)?;
    }
    if !active_present {
        sync_catalog_parent(parent)?;
        return Ok(ProductionExactCheckpointRetirementReport {
            scenario: authority.scenario,
            retired: false,
        });
    }

    fs::rename(&active, &retired).map_err(|source| {
        ProductionExactCheckpointRetirementError::Io {
            operation: "rename",
            path: active.clone(),
            source,
        }
    })?;
    sync_catalog_parent(parent)?;
    remove_retired_catalog(&retired, parent)?;

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

fn remove_retired_catalog(
    retired: &Path,
    parent: &Path,
) -> Result<(), ProductionExactCheckpointRetirementError> {
    fs::remove_dir_all(retired).map_err(|source| ProductionExactCheckpointRetirementError::Io {
        operation: "remove",
        path: retired.to_path_buf(),
        source,
    })?;
    sync_catalog_parent(parent)
}

fn sync_catalog_parent(parent: &Path) -> Result<(), ProductionExactCheckpointRetirementError> {
    let directory = match File::open(parent) {
        Ok(directory) => directory,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ProductionExactCheckpointRetirementError::Io {
                operation: "open parent for synchronization",
                path: parent.to_path_buf(),
                source,
            });
        }
    };
    directory
        .sync_all()
        .map_err(|source| ProductionExactCheckpointRetirementError::Io {
            operation: "synchronize parent",
            path: parent.to_path_buf(),
            source,
        })
}
