//! Executes ordinary leaf reads and fixed physical read closures without authority.
//!
//! Parent validation remains with the caller. This recipe preserves ordinary
//! whole-body and absence semantics without protected owner or link policies.
//! A separate private recipe closes genuine retained publication inputs and
//! reports a physical observation alone; it performs no mutation or durability ACK.

use std::path::Path;
#[cfg(all(feature = "tokio", unix))]
use std::path::PathBuf;

/// Carries a fixed ordinary leaf recipe with privately constructed inputs.
///
/// Ordinary leaves carry no retained holder. The private projection recipe owns
/// already acquired exclusions and exact read data, without selected-state authority.
pub struct NativeOrdinaryRead {
    #[cfg(all(feature = "tokio", unix))]
    recipe: Recipe,
}

#[cfg(all(feature = "tokio", unix))]
enum Recipe {
    Leaf(PathBuf),
    Projection(super::native_effect::NativeReadProjection),
}

/// Holds whole ordinary read data or a sealed physical-layout rejection.
///
/// The result grants no publication or authorization authority.
pub struct NativeOrdinaryRecord {
    outcome: OrdinaryReadOutcome,
}

/// Separates caller-classified layout rejection from actual I/O errors.
pub(crate) enum OrdinaryReadOutcome {
    #[cfg(all(feature = "tokio", unix))]
    ProjectionChecked,
    #[cfg(all(feature = "tokio", unix))]
    Absent,
    #[cfg(all(feature = "tokio", unix))]
    Present(Vec<u8>, std::fs::Metadata),
    #[cfg(all(feature = "tokio", unix))]
    InvalidLayout,
}

impl NativeOrdinaryRead {
    /// Retains an actual leaf after its caller has validated every parent.
    #[cfg(all(feature = "tokio", unix))]
    pub(crate) fn for_leaf(path: &Path) -> Self {
        Self {
            recipe: Recipe::Leaf(path.to_owned()),
        }
    }

    /// Retains complete actual physical inputs for a read-only closing worker.
    #[cfg(all(feature = "tokio", unix))]
    pub(in crate::store) fn for_projection(
        projection: super::native_effect::NativeReadProjection,
    ) -> Self {
        Self {
            recipe: Recipe::Projection(projection),
        }
    }

    /// Names unsupported execution while preserving the scalar fallback.
    #[cfg(not(all(feature = "tokio", unix)))]
    pub(crate) fn for_leaf(_path: &Path) -> Self {
        Self {}
    }

    /// Executes the original ordinary leaf checks in their original order.
    ///
    /// # Errors
    /// Returns metadata, open, descriptor inspection and whole-read errors.
    /// NotFound during before metadata or body read is observed absence;
    /// NotFound after successful body reading remains an I/O error.
    #[cfg(all(feature = "tokio", unix))]
    pub(super) fn execute(self) -> std::io::Result<NativeOrdinaryRecord> {
        match self.recipe {
            Recipe::Leaf(path) => Self::execute_leaf(&path),
            Recipe::Projection(projection) => {
                projection.check()?;
                Ok(NativeOrdinaryRecord {
                    outcome: OrdinaryReadOutcome::ProjectionChecked,
                })
            }
        }
    }

    /// Preserves the ordinary leaf's ordered metadata and whole-body checks.
    #[cfg(all(feature = "tokio", unix))]
    fn execute_leaf(path: &Path) -> std::io::Result<NativeOrdinaryRecord> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let before = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                return Ok(NativeOrdinaryRecord {
                    outcome: OrdinaryReadOutcome::InvalidLayout,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(NativeOrdinaryRecord {
                    outcome: OrdinaryReadOutcome::Absent,
                });
            }
            Err(error) => return Err(error),
        };

        let body = (|| {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path is not a regular file",
                ));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        let bytes = match body {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(NativeOrdinaryRecord {
                    outcome: OrdinaryReadOutcome::Absent,
                });
            }
            Err(error) => return Err(error),
        };

        let after = std::fs::symlink_metadata(path)?;
        if !after.is_file()
            || after.file_type().is_symlink()
            || (before.dev(), before.ino()) != (after.dev(), after.ino())
        {
            return Ok(NativeOrdinaryRecord {
                outcome: OrdinaryReadOutcome::InvalidLayout,
            });
        }
        Ok(NativeOrdinaryRecord {
            outcome: OrdinaryReadOutcome::Present(bytes, after),
        })
    }
}

impl NativeOrdinaryRecord {
    /// Gives the backend actual data without choosing a bucket error identity.
    pub(crate) fn into_outcome(self) -> OrdinaryReadOutcome {
        self.outcome
    }
}
