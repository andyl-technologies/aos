//! Retains both actual measured files during a fixed helper owed post.
//!
//! This destination neither opens an image nor establishes helper authority.
//! The genuine physical owner prepays it before the primary operation, retains
//! its measured executable and loader, and fences the whole owed continuation.

use std::error::Error;

use crate::immutable_image::ImmutableFileRevalidationOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{ImmutableImageErrorV1, MeasuredHelperImageV1};

/// Retains actual native image currentness observations without authority.
#[must_use = "retain reached native results through purpose disposition"]
pub struct HelperImageRevalidationOriginalV1 {
    executable: ImmutableFileRevalidationOriginalV1,
    executable_result: Option<Result<(), ImmutableImageErrorV1>>,
    loader: ImmutableFileRevalidationOriginalV1,
    loader_result: Option<Result<(), ImmutableImageErrorV1>>,
    result: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
    native_entered: [bool; 2],
}

impl HelperImageRevalidationOriginalV1 {
    /// Creates inert destinations without native IO.
    pub fn new() -> Self {
        Self {
            executable: ImmutableFileRevalidationOriginalV1::new(),
            executable_result: None,
            loader: ImmutableFileRevalidationOriginalV1::new(),
            loader_result: None,
            result: None,
            entered: false,
            native_entered: [false; 2],
        }
    }

    /// Describes both original samples and their simultaneous digest work.
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        let file = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let own_bytes = std::mem::size_of::<Self>().checked_sub(
            2_usize.checked_mul(std::mem::size_of::<ImmutableFileRevalidationOriginalV1>())?,
        )?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(own_bytes).ok()?)
            .with(D::MetadataEntries, 0);
        file.checked_add(file).ok()?.checked_add(own).ok()
    }

    /// Supplies both maximum bounded image reads for a separately owed post.
    ///
    /// This bound comes from the same fixed acquisition recipe. It includes
    /// both native destinations and each file's extra EOF byte.
    pub fn maximum_with_input_receiving_demand_v1() -> Option<ResourceVector> {
        let input = super::MAXIMUM_IMAGE_BYTES.checked_add(1)?.checked_mul(2)?;
        Some(Self::receiving_demand_v1()?.with(D::OutputBytes, input))
    }

    /// Borrows the earliest reached native or typed comparison cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.executable
            .failure()
            .or_else(|| failure(&self.executable_result))
            .or_else(|| self.loader.failure())
            .or_else(|| failure(&self.loader_result))
            .or_else(|| failure(&self.result))
    }

    /// Reports successful completion of both actual native comparisons.
    pub fn is_complete(&self) -> bool {
        self.executable.is_complete()
            && self.loader.is_complete()
            && matches!(self.result, Some(Ok(())))
    }
}

impl MeasuredHelperImageV1 {
    /// Supplies both same retained images' actual bounded hash inputs.
    pub fn revalidation_receiving_demand_v1(&self) -> Option<ResourceVector> {
        let input = self
            .executable
            .maximum_requested_read_bytes_v1()?
            .checked_add(self.loader.maximum_requested_read_bytes_v1()?)?;
        Some(HelperImageRevalidationOriginalV1::receiving_demand_v1()?.with(D::OutputBytes, input))
    }

    /// Preserves the healthy executable-then-loader comparison order.
    ///
    /// # Errors
    /// Retains native comparison failures and rejects repeated entry.
    pub fn revalidate_primary_retaining_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        if original.entered {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        original.entered = true;
        original.native_entered[0] = true;
        original.executable_result = Some(
            self.executable
                .revalidate_retaining(&mut original.executable)
                .map_err(Into::into),
        );
        if let Some(Err(cause)) = original.executable_result {
            original.result = Some(Err(cause));
            return Err(cause);
        }
        original.native_entered[1] = true;
        original.loader_result = Some(
            self.loader
                .revalidate_retaining(&mut original.loader)
                .map_err(Into::into),
        );
        original.result = Some(if original.failure().is_none() {
            Ok(())
        } else {
            Err(ImmutableImageErrorV1::Provisioning)
        });
        original
            .result
            .unwrap_or(Err(ImmutableImageErrorV1::Provisioning))
    }

    /// Observes both same held images once without reopening a healthy path.
    ///
    /// The loader post is independently owed even if the executable post fails.
    /// A completed comparison cannot authorize another operation or erase a
    /// primary failure; the enclosing genuine purpose owner keeps that state.
    ///
    /// # Errors
    /// Retains failures from either independently owed lane or repeated entry.
    pub fn revalidate_owed_retaining_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        if original.entered {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        original.entered = true;

        original.native_entered[0] = true;
        original.executable_result = Some(
            self.executable
                .revalidate_retaining(&mut original.executable)
                .map_err(Into::into),
        );
        original.native_entered[1] = true;
        original.loader_result = Some(
            self.loader
                .revalidate_retaining(&mut original.loader)
                .map_err(Into::into),
        );
        original.result = Some(if original.failure().is_some() {
            Err(ImmutableImageErrorV1::Provisioning)
        } else {
            Ok(())
        });

        match original.result {
            Some(Ok(())) => Ok(()),
            _ => Err(ImmutableImageErrorV1::Provisioning),
        }
    }

    /// Enters only unused owed image lanes after an enclosing caught unwind.
    ///
    /// Already entered originals are never replayed. This terminal negative
    /// observer cannot complete positively or restore an interrupted owner.
    ///
    /// # Errors
    /// Always refuses; remaining native lanes are retained for disposition.
    pub fn drain_owed_after_unwind_once_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        original.entered = true;
        original.result = Some(Err(ImmutableImageErrorV1::Provisioning));
        if !original.native_entered[0] {
            original.native_entered[0] = true;
            original.executable_result = Some(
                self.executable
                    .revalidate_retaining(&mut original.executable)
                    .map_err(Into::into),
            );
        }
        if !original.native_entered[1] {
            original.native_entered[1] = true;
            original.loader_result = Some(
                self.loader
                    .revalidate_retaining(&mut original.loader)
                    .map_err(Into::into),
            );
        }
        Err(ImmutableImageErrorV1::Provisioning)
    }
}

fn failure<E: Error + 'static>(slot: &Option<Result<(), E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as &dyn Error)
}

impl Default for HelperImageRevalidationOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl super::HelperImageAcquisitionOriginalV1 {
    /// Observes every available original after an incomplete acquisition.
    ///
    /// A complete retained pair uses the same two-image post. Otherwise each
    /// reached file is independently observed, including a metadata-only
    /// incomplete prefix. No measurement, pin read or transfer is repeated.
    ///
    /// # Errors
    /// Refuses incomplete acquisitions, changed originals and repeated entry.
    /// Native results from both reached lanes remain in the supplied owner.
    pub fn observe_available_held_once_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        let pair = self.image.as_ref().or_else(|| {
            self.returned
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
        });
        if let Some(image) = pair {
            return image.revalidate_owed_retaining_v1(original);
        }
        if original.entered {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        original.entered = true;

        original.native_entered[0] = true;
        original.executable_result = match self.executable.as_ref() {
            Some(file) => Some(file.revalidate_retaining(&mut original.executable)),
            None => self.files[0].observe_available_held_once_v1(&mut original.executable),
        };
        original.native_entered[1] = true;
        original.loader_result = match self.loader.as_ref() {
            Some(file) => Some(file.revalidate_retaining(&mut original.loader)),
            None => self.files[1].observe_available_held_once_v1(&mut original.loader),
        };
        // These observations preserve a failed prefix; they cannot complete a
        // pair that never reached the original positive measurement boundary.
        original.result = Some(Err(ImmutableImageErrorV1::Provisioning));
        Err(ImmutableImageErrorV1::Provisioning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_tpm_helper_image::HelperImageAcquisitionOriginalV1;

    #[test]
    fn failed_acquisition_posts_both_actual_held_prefixes_without_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let mut acquisition = HelperImageAcquisitionOriginalV1::new();
        for index in 0..2 {
            let path = directory.path().join(index.to_string());
            std::fs::write(&path, b"mutable file is not a helper image").unwrap();
            assert!(
                acquisition.files[index]
                    .measure_original_once(
                        path.clone(),
                        std::fs::File::open(&path).unwrap(),
                        None,
                        1024,
                        true
                    )
                    .is_err()
            );
            std::fs::remove_file(path).unwrap();
        }
        let first = acquisition.failure().unwrap() as *const dyn Error;
        let mut post = HelperImageRevalidationOriginalV1::new();

        assert!(
            acquisition
                .observe_available_held_once_v1(&mut post)
                .is_err()
        );

        assert!(matches!(post.executable_result, Some(Err(_))));
        assert!(matches!(post.loader_result, Some(Err(_))));
        assert_eq!(post.native_entered, [true, true]);
        assert!(std::ptr::addr_eq(acquisition.failure().unwrap(), first));
        assert!(!post.is_complete());
        assert!(
            acquisition
                .observe_available_held_once_v1(&mut post)
                .is_err()
        );
        assert!(acquisition.take_completed_once().is_none());
    }
}
