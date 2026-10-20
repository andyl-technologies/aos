//! Retains the existing captured-prefix metadata post before tail handling.
//!
//! This comparison DATA owner invokes the same held-file metadata engine once.
//! It authenticates no role or pathname and supplies no receiving allowance.
//! A role prepays and parks it after its parser outcome, including on failure.

use std::error::Error;
use std::fs::{File, Metadata};
use std::io;

use super::{FileIdentity, ProtectedFailure};

/// Retains the actual independent held-file result and seven-field comparison.
pub struct CapturedReplayPrefixPostV1<E> {
    metadata: io::Result<Metadata>,
    comparison: Result<(), E>,
}

impl<E: ProtectedFailure> CapturedReplayPrefixPostV1<E> {
    /// Observes the same held file once against its original captured metadata.
    ///
    /// This returns an owned DATA destination on either outcome. Native errors
    /// remain in the exact raw result before their stale comparison projection.
    #[must_use]
    pub fn observe(file: &File, before: &Metadata) -> Self {
        let metadata = super::writer_witness::observe_metadata_once(
            file, super::writer_witness::OrdinaryMetadata,
        );
        let comparison = match &metadata {
            Ok(after) if FileIdentity::from_metadata(before) == FileIdentity::from_metadata(after) => {
                Ok(())
            }
            _ => Err(E::STALE_NAME),
        };
        Self { metadata, comparison }
    }

    /// Borrows the actual native Metadata result without reobserving the file.
    #[must_use]
    pub const fn metadata_result(&self) -> &io::Result<Metadata> {
        &self.metadata
    }

    /// Borrows the original seven-field comparison without changing it.
    #[must_use]
    pub const fn comparison_result(&self) -> &Result<(), E> {
        &self.comparison
    }

    /// Bounds this owner, native return and original comparison temporaries.
    #[must_use]
    pub fn receiving_memory_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<io::Result<Metadata>>())?
            .checked_add(std::mem::size_of::<Result<(), E>>())?
            .checked_add(std::mem::size_of::<FileIdentity>().checked_mul(2)?)
    }
}

impl<E: Error + 'static> CapturedReplayPrefixPostV1<E> {
    /// Borrows the native post error before its original typed comparison error.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.metadata.as_ref().err()
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.comparison.as_ref().err()
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}
