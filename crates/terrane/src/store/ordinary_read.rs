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
    #[cfg(all(test, feature = "tokio", unix))]
    observation: Option<Box<dyn FnMut(TestStage) + Send>>,
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
            #[cfg(test)]
            observation: None,
        }
    }

    /// Retains complete actual physical inputs for a read-only closing worker.
    #[cfg(all(feature = "tokio", unix))]
    pub(in crate::store) fn for_projection(
        projection: super::native_effect::NativeReadProjection,
    ) -> Self {
        Self {
            recipe: Recipe::Projection(projection),
            #[cfg(test)]
            observation: None,
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
    ///
    /// # Panics
    /// In test builds, panics if a configured test observer panics.
    #[cfg(all(feature = "tokio", unix))]
    pub(super) fn execute(self) -> std::io::Result<NativeOrdinaryRecord> {
        let Self {
            recipe,
            #[cfg(test)]
            mut observation,
        } = self;
        match recipe {
            Recipe::Leaf(path) => Self::execute_leaf(
                &path,
                #[cfg(test)]
                &mut observation,
            ),
            Recipe::Projection(projection) => {
                // Entry runs inside the submitted worker, while it owns every
                // real exclusion; the observer never supplies a checked result.
                #[cfg(test)]
                Self::observe(&mut observation, TestStage::ProjectionEntered);

                projection.check()?;
                Ok(NativeOrdinaryRecord {
                    outcome: OrdinaryReadOutcome::ProjectionChecked,
                })
            }
        }
    }

    /// Preserves the ordinary leaf's ordered metadata and whole-body checks.
    #[cfg(all(feature = "tokio", unix))]
    fn execute_leaf(
        path: &Path,
        #[cfg(test)] observation: &mut Option<Box<dyn FnMut(TestStage) + Send>>,
    ) -> std::io::Result<NativeOrdinaryRecord> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        // This local diagnostic measures actual worker execution, separately
        // from caller dispatch and parent observations. It grants no evidence.
        #[cfg(test)]
        let trace = crate::ref_advance::NativeTrace::new(path, "ordinary-leaf-worker");

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

        #[cfg(test)]
        Self::observe(observation, TestStage::BeforeOpen);

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
            #[cfg(test)]
            Self::observe(observation, TestStage::BeforeBody);

            #[cfg(test)]
            trace.mark("descriptor-regular-before-whole-body");
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            #[cfg(test)]
            trace.mark("whole-body-returned");
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

        #[cfg(test)]
        Self::observe(observation, TestStage::AfterBody);

        let after = std::fs::symlink_metadata(path)?;
        if !after.is_file()
            || after.file_type().is_symlink()
            || (before.dev(), before.ino()) != (after.dev(), after.ino())
        {
            return Ok(NativeOrdinaryRecord {
                outcome: OrdinaryReadOutcome::InvalidLayout,
            });
        }
        #[cfg(test)]
        Self::observe(observation, TestStage::Finished);
        #[cfg(test)]
        trace.mark("named-after-incarnation-accepted");

        Ok(NativeOrdinaryRecord {
            outcome: OrdinaryReadOutcome::Present(bytes, after),
        })
    }
}

impl NativeOrdinaryRecord {
    /// Reports whether the native worker captured a present ordinary leaf body.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn has_present_body_for_test(&self) -> bool {
        matches!(&self.outcome, OrdinaryReadOutcome::Present(_, _))
    }

    /// Gives the backend actual data without choosing a bucket error identity.
    pub(crate) fn into_outcome(self) -> OrdinaryReadOutcome {
        self.outcome
    }
}

// Leaf observations change real filesystem nodes at their original boundaries.
// Projection entry observes the actual closing worker without a body path.
#[cfg(all(test, feature = "tokio", unix))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestStage {
    ProjectionEntered,
    BeforeOpen,
    BeforeBody,
    AfterBody,
    Finished,
}

#[cfg(all(test, feature = "tokio", unix))]
impl NativeOrdinaryRead {
    /// Borrows the actual leaf for operation-local physical test changes.
    ///
    /// Physical projections have several fixed inputs and no single leaf path.
    pub(crate) fn path_for_test(&self) -> Option<&Path> {
        match &self.recipe {
            Recipe::Leaf(path) => Some(path),
            Recipe::Projection(_) => None,
        }
    }

    /// Attaches one entry observer to a genuine native closing projection.
    ///
    /// The observer runs inside the existing native worker before the unchanged
    /// physical checks. It cannot replace the recipe or manufacture its result.
    ///
    /// # Errors
    /// Returns an invalid-input error for a leaf recipe or an existing observer.
    pub(crate) fn observe_projection_entry_for_test(
        &mut self,
        action: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<()> {
        if !matches!(&self.recipe, Recipe::Projection(_)) || self.observation.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "projection entry requires an unobserved closing recipe",
            ));
        }

        let mut action = Some(action);
        self.observation = Some(Box::new(move |stage| {
            if stage == TestStage::ProjectionEntered
                && let Some(action) = action.take()
            {
                action();
            }
        }));
        Ok(())
    }

    fn observe(observation: &mut Option<Box<dyn FnMut(TestStage) + Send>>, stage: TestStage) {
        if let Some(observation) = observation.as_mut() {
            observation(stage);
        }
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
