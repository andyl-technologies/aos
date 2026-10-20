//! Retains the actual immutable pin metadata and shared bounded leaf read.
//!
//! This passive DATA reader has no fixed role, launch or signer admission.
//! Its caller independently pays and retains the same complete purpose owner.

use std::error::Error;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;

use super::*;

pub(super) struct PinReadSlotsV1 {
    pub(super) path: Option<PathBuf>,
    pub(super) metadata: Option<std::io::Result<Metadata>>,
    pub(super) binding: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) reader: FixedRoleCredentialReadV1,
}

impl PinReadSlotsV1 {
    fn new() -> Self {
        Self { path: None, metadata: None, binding: None,
            reader: FixedRoleCredentialReadV1::prearmed() }
    }
}

/// Retains every reached native prefix of one existing immutable pin read.
///
/// Successful bytes are comparison DATA. They cannot establish their supplier,
/// select an executable or construct a role, original, payer or authority.
#[must_use = "retain actual failed pin observations with their same purpose owner"]
pub struct ImmutableImagePinReadOriginalV1 {
    slots: PinReadSlotsV1,
    returned: Option<Result<Vec<u8>, ImmutableImageErrorV1>>,
    entered: bool,
    taken: bool,
    reentry: Option<ImmutableImageErrorV1>,
}

impl ImmutableImagePinReadOriginalV1 {
    /// Creates inert destinations without opening, reading or allocating payload.
    #[must_use]
    pub fn new() -> Self {
        Self { slots: PinReadSlotsV1::new(), returned: None,
            entered: false, taken: false, reentry: None }
    }

    /// Reads once through the existing metadata and bounded credential engines.
    ///
    /// # Errors
    /// Retains unavailable native metadata/open/read results, unsafe metadata,
    /// invalid lengths, partial bounded bytes and repeated-entry refusal.
    pub fn read_once(&mut self, directory: &Path, name: &str, minimum: usize, maximum: usize)
        -> Result<(), ImmutableImageErrorV1>
    {
        if self.entered {
            self.reentry.get_or_insert(ImmutableImageErrorV1::Provisioning);
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.entered = true;
        self.returned = Some(read_immutable_image_pin_recipe(
            directory, name, minimum, maximum, Some(&mut self.slots),
        ));
        if matches!(self.returned, Some(Ok(_))) { Ok(()) }
        else { Err(ImmutableImageErrorV1::Provisioning) }
    }

    /// Borrows the actual complete bytes without moving any native original.
    #[must_use]
    pub fn completed_bytes(&self) -> Option<&[u8]> {
        if self.reentry.is_some() || self.taken { return None; }
        self.returned.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    /// Moves the actual complete bytes once, keeping native outcomes resident.
    #[must_use]
    pub fn take_completed_bytes_once(&mut self) -> Option<Vec<u8>> {
        self.completed_bytes()?;
        match self.returned.take() {
            Some(Ok(bytes)) => { self.taken = true; Some(bytes) }
            original => { self.returned = original; None }
        }
    }

    /// Disposes only a complete positive leaf File at the caller's typed boundary.
    ///
    /// The caller invokes this after its entire pin-dependent construction
    /// succeeded. Failed, absent and partial originals remain untouched. This
    /// releases no financial charge and establishes no role or currentness.
    #[must_use]
    pub fn retire_completed_file_once_v1(&mut self) -> bool {
        if self.reentry.is_some() || !matches!(self.returned, Some(Ok(_))) { return false; }
        self.slots.reader.retire_completed_file_once_v1()
    }

    /// Supplies actual compiled owners, bounded read/path backing and one File.
    ///
    /// The caller derives both widths from its actual selected pin recipe and
    /// prepays before construction. Native results and scalar controls occupy
    /// memory, rather than resident namespace metadata entries.
    #[must_use]
    pub fn receiving_demand_v1(locator_bytes: usize, maximum_bytes: usize)
        -> Option<aos_sandbox_core::ResourceVector>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(locator_bytes.checked_add(1)?.checked_mul(4)?)?
            .checked_add(maximum_bytes)?
            .checked_add(16_usize.checked_mul(std::mem::size_of::<usize>())?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 1))
    }

    /// Borrows the earliest reached native or typed pin-read cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.slots.metadata).or_else(|| error(&self.slots.binding))
            .or_else(|| self.slots.reader.failure())
            .or_else(|| error(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for ImmutableImagePinReadOriginalV1 {
    fn default() -> Self { Self::new() }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_pin_retains_its_actual_metadata_error_and_cannot_retry() {
        let directory = tempfile::tempdir().unwrap();
        let mut original = ImmutableImagePinReadOriginalV1::new();
        assert!(original.read_once(directory.path(), "missing-pin", 1, 65).is_err());
        let native = original.slots.metadata.as_ref().unwrap().as_ref().unwrap_err();
        let first = native as *const std::io::Error;
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        assert!(std::ptr::eq(original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(), first));
        assert!(original.slots.reader.view().open.is_none());
        std::fs::write(directory.path().join("missing-pin"), b"replacement").unwrap();
        assert!(original.read_once(directory.path(), "missing-pin", 1, 65).is_err());
        assert!(std::ptr::eq(original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(), first));
        assert!(original.completed_bytes().is_none());
        assert!(original.slots.reader.view().open.is_none());
    }
}
