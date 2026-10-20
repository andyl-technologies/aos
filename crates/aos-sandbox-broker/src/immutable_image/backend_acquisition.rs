//! Retains the original PID1 file, backend pin and measurement acquisition.
//!
//! The existing compiled backend recipe alone selects the path and pin. This
//! DATA owner authenticates neither the supplied descriptor nor its caller.

use std::error::Error;

use super::*;

pub(super) struct BackendImageSlotsV1 {
    pub(super) path: Option<PathBuf>,
    pub(super) pin: ImmutableImagePinReadOriginalV1,
    pub(super) digest: Option<Result<[u8; 32], ImmutableImageErrorV1>>,
    pub(super) cloned: Option<std::io::Result<File>>,
    pub(super) flags: Option<Result<OFlags, rustix::io::Errno>>,
    pub(super) readonly: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) measurement: ImmutableFileAcquisitionOriginalV1,
    pub(super) measurement_entry: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    pub(super) clone_transferred: bool,
}

impl BackendImageSlotsV1 {
    fn new() -> Self {
        Self { path: None, pin: ImmutableImagePinReadOriginalV1::new(),
            digest: None, cloned: None, flags: None, readonly: None,
            measurement: ImmutableFileAcquisitionOriginalV1::new(), measurement_entry: None, clone_transferred: false }
    }
}

/// Retains every reached native prefix of the existing backend PID1 recipe.
///
/// The genuine caller supplies its own original launch File and independently
/// binds it to its actual role, profile and receiving admission. A measurement
/// or compiled path does not construct launch, TPM or service authority.
#[must_use = "retain actual failed backend originals with their same launch owner"]
pub struct BackendPid1ImageAcquisitionOriginalV1 {
    slots: BackendImageSlotsV1,
    returned: Option<Result<RetainedImmutableFileV1, ImmutableImageErrorV1>>,
    entered: bool,
    taken: bool,
    reentry: Option<ImmutableImageErrorV1>,
}

impl BackendPid1ImageAcquisitionOriginalV1 {
    /// Creates inert destinations without duplicating or observing the input.
    #[must_use]
    pub fn new() -> Self {
        Self { slots: BackendImageSlotsV1::new(), returned: None,
            entered: false, taken: false, reentry: None }
    }

    /// Measures once through the same compiled pin, clone, flags and image engine.
    ///
    /// # Errors
    /// Retains missing compiled selection, pin metadata/read/format refusal,
    /// clone or flag failure, initial native measurement and reentry errors.
    pub fn capture_once(&mut self, original: &File) -> Result<(), ImmutableImageErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(ImmutableImageErrorV1::Provisioning);
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.entered = true;
        self.returned = Some(retain_original_backend_pid1_recipe(original, Some(&mut self.slots)));
        match self.returned.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(cause)) => Err(currentness::projection(cause)),
            None => Err(ImmutableImageErrorV1::Unavailable),
        }
    }

    /// Moves only the actual completed measurement once, retaining all probes.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<RetainedImmutableFileV1> {
        if self.reentry.is_some() || self.taken { return None; }
        match self.returned.take() {
            Some(Ok(file)) => { self.taken = true; Some(file) }
            original => { self.returned = original; None }
        }
    }

    /// Disposes only a wholly positive pin leaf File at the typed success boundary.
    ///
    /// The measured original remains owned, either here or by the caller that
    /// took this actual completed measurement. That enclosing caller waits for
    /// its full typed/native success before requesting retirement. Failed pins,
    /// partial reads and comparison outcomes remain; no refund occurs.
    #[must_use]
    pub fn retire_completed_pin_file_once_v1(&mut self) -> bool {
        if self.reentry.is_some()
            || !(matches!(self.returned, Some(Ok(_))) || self.taken)
        {
            return false;
        }
        self.slots.pin.retire_completed_file_once_v1()
    }

    /// Observes an available original without retrying the backend acquisition.
    ///
    /// A completed measurement uses its same revalidation engine; an earlier
    /// clone receives only a retained metadata observation and stays incomplete.
    /// `None` denotes an unreached or already transferred image descriptor.
    ///
    /// # Errors
    /// A reached result retains native revalidation refusal, or refuses the
    /// incomplete metadata-only prefix and repeated entry into its sink.
    #[doc(hidden)]
    pub fn observe_available_held_once_v1(
        &self,
        original: &mut ImmutableFileRevalidationOriginalV1,
    ) -> Option<Result<(), ImmutableImageErrorV1>> {
        if let Some(Ok(file)) = self.returned.as_ref() {
            return Some(file.revalidate_retaining(original));
        }
        if let Some(result) = self.slots.measurement.observe_available_held_once_v1(original) {
            return Some(result);
        }
        match self.slots.cloned.as_ref() {
            Some(Ok(file)) => Some(original.observe_held_metadata_only_v1(file)),
            _ => None,
        }
    }

    /// Supplies actual backend owners and both native pin/image file peaks.
    ///
    /// The locator is derived from this same compiled recipe before native IO.
    /// Scalar/result controls occupy memory and create no namespace entries.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let path = option_env!("AOS_METHOD46_TPM_PID1")?;
        let pin = ImmutableImagePinReadOriginalV1::receiving_demand_v1(4096, 4096)?;
        let measurement = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(path.len())?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(path.len().checked_mul(2)?)?
            .checked_add(4097_usize.checked_mul(2)?)?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .checked_add(pin).ok()?.checked_add(measurement).ok()
    }

    /// Borrows the first actual pin, clone, flags or image native failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.slots.pin.failure().or_else(|| error(&self.slots.digest))
            .or_else(|| error(&self.slots.cloned)).or_else(|| error(&self.slots.flags))
            .or_else(|| error(&self.slots.readonly)).or_else(|| self.slots.measurement.failure())
            .or_else(|| error(&self.slots.measurement_entry))
            .or_else(|| error(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for BackendPid1ImageAcquisitionOriginalV1 {
    fn default() -> Self { Self::new() }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
