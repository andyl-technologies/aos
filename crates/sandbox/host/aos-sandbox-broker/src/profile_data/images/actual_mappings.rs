//! Retains the sole bounded self-maps reader and its full comparison outcome.
//!
//! The genuine caller pays this passive destination before construction/entry.
//! Files, required names and a positive comparison supply no process, startup,
//! Source, signing, journal or effect authority.

use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{MAXIMUM_MAPS_BYTES, NormalRootStartupErrorV1, RetainedImmutableFileV1};
use crate::profile_data::shared_read::BoundedFileReadOriginalV1;

/// Reports a refused comparison while the native reader and cause remain held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("actual executable maps comparison is incomplete or refused")]
pub struct ActualExecutableMappingsClosedV1;

/// Holds one actual self-maps file, reached bytes and the existing comparison.
#[must_use = "retain this whole destination through the caller's owed posts"]
pub struct ActualExecutableMappingsOriginalV1 {
    original: BoundedFileReadOriginalV1,
    comparison: Option<Result<(), NormalRootStartupErrorV1>>,
    entered: bool,
    reentered: bool,
    closed: ActualExecutableMappingsClosedV1,
}

impl ActualExecutableMappingsOriginalV1 {
    /// Creates empty inline custody without allocation or native observations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            original: BoundedFileReadOriginalV1::new(),
            comparison: None,
            entered: false,
            reentered: false,
            closed: ActualExecutableMappingsClosedV1,
        }
    }

    /// Quotes actual model carriers, bounded maps input and one native path.
    ///
    /// The exact retained file roster supplies the comparison scratch count.
    /// It supplies neither a role nor payment; the real Source must admit this
    /// complete quote before the destination or either comparison Vec grows.
    #[must_use]
    pub fn receiving_demand_v1(files: usize) -> Option<ResourceVector> {
        let maximum = usize::try_from(MAXIMUM_MAPS_BYTES).ok()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(BoundedFileReadOriginalV1::requested_bytes_v1(maximum)?)?
            .checked_add(files.checked_mul(std::mem::size_of::<(u64, u64, u64)>()
                .checked_add(std::mem::size_of::<bool>())?)?)?
            .checked_add(2_usize.checked_mul(std::mem::size_of::<Vec<usize>>())?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1)
            .with(D::MetadataEntries, 4)
            .with(D::OutputBytes, MAXIMUM_MAPS_BYTES.checked_add(1)?))
    }

    /// Runs the existing retained reader and canonical closure comparison once.
    ///
    /// # Errors
    /// Retains failed open/read/UTF8 and pure mapping comparison Results, and
    /// rejects reentry without opening another file or replacing an old cause.
    pub fn observe_once_v1(
        &mut self,
        files: &[RetainedImmutableFileV1],
        required: &[&str],
    ) -> Result<(), ActualExecutableMappingsClosedV1> {
        if self.entered {
            self.reentered = true;
            return Err(self.closed);
        }
        self.entered = true;
        self.comparison = Some(super::require_actual_mappings_retaining_v1(
            files, required, &mut self.original,
        ));
        if matches!(self.comparison, Some(Ok(()))) { Ok(()) } else { Err(self.closed) }
    }

    /// Borrows the actual first native or pure comparison error without IO.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
            .or_else(|| self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentered.then_some(&self.closed as &dyn Error))
    }
}
