//! Bounded measurement and decoding of the actual inherited Root profile.
//!
//! This reservoir is DATA custody, never role or resource admission. Only the
//! genuine RootR or SourceF owner selects its own inherited original after
//! checking its fixed negative prefix.
//! The original immutable-file engine, derived schema and existing validator
//! remain shared with normal startup; no alternate profile format is added.

use std::error::Error;
use std::fs::File;
use std::os::fd::OwnedFd;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::immutable_image::{ImmutableImageErrorV1, PendingImmutableFileV1, RetainedImmutableFileV1};

use crate::profile_data::images;
use super::root_observation_error::RootImageObservationErrorV1 as ImageObservationErrorV1;
use crate::profile_data::schema::{
    bounded_profile_representation_bytes_v1, MAXIMUM_RUNTIME_FILES,
    NormalRootProfileV1, RootProfileDecodeAttemptV1,
};
use super::RootObservationErrorV1 as NormalRootStartupErrorV1;

/// Retains the actual inherited Root profile file, decoder and partial results.
///
/// This physical reservoir grants no role, payment or selected-startup authority.
#[derive(Default)]
pub struct RootProfileOriginalCaptureV1 {
    original: PendingImmutableFileV1,
    measurement: Option<Result<(), ImageObservationErrorV1>>,
    decode: RootProfileDecodeAttemptV1,
    completion: Option<Result<(), NormalRootStartupErrorV1>>,
    attempted: bool,
}

impl RootProfileOriginalCaptureV1 {
    /// Prices the fixed profile representation and actual construction carriers.
    ///
    /// The existing bounded representation, 32MiB fixed negative prefix and
    /// descriptor allowance are unchanged. The lower destination plus upper
    /// wrapper construction are both paid explicitly; the two new metadata
    /// terms name that wrapper and its native construction temporary.
    /// The explicit Cache signer GID adds its scalar cell and the extra owned
    /// decimal argv member used by the shared original-launch comparison.
    /// Returns `None` on unrepresentable arithmetic; this is not admission.
    #[must_use]
    pub fn fixed_demand() -> Option<ResourceVector> {
        let strings = MAXIMUM_RUNTIME_FILES.checked_mul(2)?.checked_add(9)?;
        let memory = bounded_profile_representation_bytes_v1()?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<String>() + 10)?
            .checked_add(32 * 1024 * 1024)?;
        let memory = u64::try_from(memory).ok()?;
        let cells = strings.checked_add(MAXIMUM_RUNTIME_FILES)?.checked_add(4)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, 32)
            .with(D::MetadataEntries, u64::try_from(cells).ok()?)
            .with(D::PublicationStagingBytes, memory)
            .with(D::LogBytes, 64 * 1024)
            .with(D::OutputBytes, memory)
            .with(D::ConcurrentOperations, 1))
    }

    /// Captures and decodes the original descriptor from its actual move slot.
    ///
    /// # Errors
    /// Retains original image/decoder causes and refuses absent files or reentry.
    pub fn receive_original_once(
        &mut self,
        original: &mut Option<OwnedFd>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.attempted {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        self.attempted = true;
        self.completion = Some((|| {
            let original = original.take().ok_or(NormalRootStartupErrorV1::Activation)?;
            self.original.park_original(File::from(original));
            self.measurement = Some(
                images::park_controller_profile(&mut self.original).map_err(Into::into),
            );
            if !matches!(self.measurement, Some(Ok(()))) {
                return Err(NormalRootStartupErrorV1::Profile);
            }
            self.decode.decode_once(self.original.bytes())?;
            if self.decode.profile().is_none() {
                return Err(NormalRootStartupErrorV1::Profile);
            }
            Ok(())
        })());
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Profile)
        }
    }

    /// Borrows the complete validated profile DATA without transferring custody.
    #[must_use]
    pub fn profile(&self) -> Option<&NormalRootProfileV1> {
        self.decode.profile()
    }

    /// Borrows the same actual immutable profile measurement.
    ///
    /// # Errors
    /// Returns the existing refusal when no completed measurement is available.
    pub fn measurement(
        &self,
    ) -> Result<&RetainedImmutableFileV1, ImmutableImageErrorV1> {
        self.original.measurement()
    }

    /// Revalidates this same measured profile for its existing Source consumer.
    ///
    /// # Errors
    /// Preserves the actual native cause on the retained immutable-file owner.
    pub fn recheck_source_original(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.original.revalidate().map_err(|_| NormalRootStartupErrorV1::Profile)
    }

    /// Moves the actual completed measurement and decoded model together.
    #[must_use]
    pub fn take_originals(
        &mut self,
    ) -> Option<(RetainedImmutableFileV1, NormalRootProfileV1)> {
        if self.failure().is_some() || self.profile().is_none() || self.measurement().is_err() {
            return None;
        }
        match (self.original.take_measurement(), self.decode.take_completed()) {
            (Some(file), Some(profile)) => Some((file, profile)),
            (file, profile) => {
                self.original.restore_measurement(file);
                if let Some(profile) = profile {
                    self.decode.restore_completed(profile);
                }
                None
            }
        }
    }

    /// Restores the same atomic-transfer destinations without granting authority.
    pub fn restore_originals(
        &mut self,
        originals: Option<(RetainedImmutableFileV1, NormalRootProfileV1)>,
    ) {
        if let Some((file, profile)) = originals {
            self.original.restore_measurement(Some(file));
            self.decode.restore_completed(profile);
        }
    }

    /// Borrows the native-first failure required by the existing Source adapter.
    #[must_use]
    pub fn source_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.native_failure().or_else(|| self.failure())
    }

    /// Borrows the first image, decoder or completion cause without reentry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.measurement.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.decode.failure())
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_original_keeps_first_cause_and_never_transfers_models() {
        let mut capture = RootProfileOriginalCaptureV1::default();
        let mut original = None;
        assert!(matches!(
            capture.receive_original_once(&mut original),
            Err(NormalRootStartupErrorV1::Profile),
        ));
        let cause = capture.failure().unwrap() as *const dyn Error;
        assert!(capture.failure().unwrap()
            .downcast_ref::<NormalRootStartupErrorV1>().is_some());
        assert!(capture.profile().is_none());
        assert!(capture.take_originals().is_none());

        assert!(matches!(
            capture.receive_original_once(&mut original),
            Err(NormalRootStartupErrorV1::Activation),
        ));
        assert!(std::ptr::eq(
            cause, capture.failure().unwrap() as *const dyn Error,
        ));
        assert!(capture.profile().is_none());
    }
}
