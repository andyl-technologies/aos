//! Retains both actual measured files during a fixed helper owed post.
//!
//! This destination neither opens an image nor establishes helper authority.
//! The genuine physical owner prepays it before the primary operation, retains
//! its measured executable and loader, and fences the whole owed continuation.

use std::error::Error;

use aos_sandbox_broker::immutable_image::ImmutableFileRevalidationOriginalV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::{FloorErrorV1, MeasuredHelperImageV1};

pub(crate) struct HelperImageRevalidationOriginalV1 {
    executable: ImmutableFileRevalidationOriginalV1,
    executable_result: Option<Result<(), FloorErrorV1>>,
    loader: ImmutableFileRevalidationOriginalV1,
    loader_result: Option<Result<(), FloorErrorV1>>,
    result: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    native_entered: [bool; 2],
}

impl HelperImageRevalidationOriginalV1 {
    pub(crate) fn new() -> Self {
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
    pub(crate) fn receiving_demand_v1() -> Option<ResourceVector> {
        let file = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let own_bytes = std::mem::size_of::<Self>().checked_sub(
            2_usize.checked_mul(std::mem::size_of::<ImmutableFileRevalidationOriginalV1>())?,
        )?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(own_bytes).ok()?)
            .with(D::MetadataEntries, 0);
        file.checked_add(file).ok()?.checked_add(own).ok()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.executable.failure()
            .or_else(|| failure(&self.executable_result))
            .or_else(|| self.loader.failure())
            .or_else(|| failure(&self.loader_result))
            .or_else(|| failure(&self.result))
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.executable.is_complete()
            && self.loader.is_complete()
            && matches!(self.result, Some(Ok(())))
    }
}

impl MeasuredHelperImageV1 {
    /// Supplies both same retained images' actual bounded hash inputs.
    pub(crate) fn revalidation_receiving_demand_v1(&self) -> Option<ResourceVector> {
        let input = self.executable.maximum_requested_read_bytes_v1()?
            .checked_add(self.loader.maximum_requested_read_bytes_v1()?)?;
        Some(HelperImageRevalidationOriginalV1::receiving_demand_v1()?
            .with(D::OutputBytes, input))
    }

    /// Preserves the healthy executable-then-loader comparison order.
    pub(crate) fn revalidate_primary_retaining_v1(
        &self, original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        if original.entered { return Err(FloorErrorV1::Provisioning); }
        original.entered = true;
        original.native_entered[0] = true;
        original.executable_result = Some(self.executable.revalidate_retaining(
            &mut original.executable,
        ).map_err(Into::into));
        if let Some(Err(cause)) = original.executable_result { original.result = Some(Err(cause)); return Err(cause); }
        original.native_entered[1] = true;
        original.loader_result = Some(self.loader.revalidate_retaining(
            &mut original.loader,
        ).map_err(Into::into));
        original.result = Some(if original.failure().is_none() { Ok(()) }
            else { Err(FloorErrorV1::Provisioning) });
        original.result.unwrap_or(Err(FloorErrorV1::Provisioning))
    }

    /// Observes both same held images once without reopening a healthy path.
    ///
    /// The loader post is independently owed even if the executable post fails.
    /// A completed comparison cannot authorize another operation or erase a
    /// primary failure; the enclosing genuine purpose owner keeps that state.
    pub(crate) fn revalidate_owed_retaining_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        if original.entered {
            return Err(FloorErrorV1::Provisioning);
        }
        original.entered = true;

        original.native_entered[0] = true;
        original.executable_result = Some(
            self.executable.revalidate_retaining(&mut original.executable).map_err(Into::into),
        );
        original.native_entered[1] = true;
        original.loader_result = Some(
            self.loader.revalidate_retaining(&mut original.loader).map_err(Into::into),
        );
        original.result = Some(if original.failure().is_some() {
            Err(FloorErrorV1::Provisioning)
        } else {
            Ok(())
        });

        match original.result {
            Some(Ok(())) => Ok(()),
            _ => Err(FloorErrorV1::Provisioning),
        }
    }

    /// Enters only unused owed image lanes after an enclosing caught unwind.
    ///
    /// Already entered originals are never replayed. This terminal negative
    /// observer cannot complete positively or restore an interrupted owner.
    pub(crate) fn drain_owed_after_unwind_once_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        original.entered = true;
        original.result = Some(Err(FloorErrorV1::Provisioning));
        if !original.native_entered[0] {
            original.native_entered[0] = true;
            original.executable_result = Some(
                self.executable.revalidate_retaining(&mut original.executable).map_err(Into::into),
            );
        }
        if !original.native_entered[1] {
            original.native_entered[1] = true;
            original.loader_result = Some(
                self.loader.revalidate_retaining(&mut original.loader).map_err(Into::into),
            );
        }
        Err(FloorErrorV1::Provisioning)
    }
}

fn failure<E: Error + 'static>(slot: &Option<Result<(), E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
}
