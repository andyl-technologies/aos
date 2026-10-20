//! Retains the same sealed-file inspection and scoped mapping on refusal.
//!
//! These are native custody destinations, not specification or role authority.
//! The caller must pay their actual storage before transferring its descriptor.

use std::error::Error;
use std::os::fd::OwnedFd;
use std::marker::PhantomData;

use super::{ImmutableFileError, ImmutableFileIdentity, ObservedFile, ReadOnlyMapping};

#[derive(Default)]
pub(super) struct SealedInspectionV2 {
    pub(super) before: Option<ObservedFile>,
    pub(super) raw_before: Option<libc::stat>,
    pub(super) flags: Option<i32>,
    pub(super) seals: Option<i32>,
}

#[derive(Default)]
pub(super) struct MappingOriginalV2 {
    pub(super) mapping: Option<ReadOnlyMapping>,
    pub(super) after: Option<ObservedFile>,
    pub(super) raw_after: Option<libc::stat>,
}

/// Retains one original descriptor and every reached sealed-mapping owner.
///
/// No descriptor, mutable mapping, validated role or success constructor is
/// exposed. The same ordinary seal and mapping engines perform all checks.
#[derive(Default)]
pub struct SealedMemfdReadOriginalV2 {
    // Unmap before closing the same descriptor, matching ordinary local order.
    mapping: MappingOriginalV2,
    inspection: SealedInspectionV2,
    file: Option<OwnedFd>,
    returned: Option<Result<(), ImmutableFileError>>,
    entered: bool,
    retired: bool,
}

impl SealedMemfdReadOriginalV2 {
    /// Creates inert receiving storage without opening or adopting a file.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Captures the original before invoking the sole native admission engine.
    ///
    /// # Errors
    /// Reports refusal without losing the original file, mapping or native
    /// error. Reentry does no IO and cannot replace prior custody.
    pub fn prepare_once(
        &mut self, file: OwnedFd, expected_bytes: u64, maximum_bytes: u64,
    ) -> Result<(), SealedMemfdReadClosedV2> {
        if self.entered {
            // The supplied extra file remains in the returned owning refusal.
            return Err(SealedMemfdReadClosedV2 { _extra: Some(file) });
        }
        self.entered = true;
        self.file = Some(file);
        self.returned = Some((|| {
            let file = self.file.as_ref().ok_or(ImmutableFileError::AdmissionRace)?;
            let before = super::inspect_sealed_memfd(file, &mut self.inspection)?;
            super::prepare_mapping(file, before, expected_bytes, maximum_bytes, &mut self.mapping)
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(SealedMemfdReadClosedV2 { _extra: None }) }
    }

    /// Borrows only this original's complete immutable mapping for a callback.
    ///
    /// # Errors
    /// Refuses absent or failed admission. Callback output is DATA and grants
    /// no process, Session, currentness or output disposal permission.
    pub fn with_bytes<R, F>(&self, use_bytes: F) -> Result<R, SealedMemfdReadClosedV2>
    where F: for<'mapping> FnOnce(&'mapping [u8], ImmutableFileIdentity<'mapping>) -> R,
    {
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(SealedMemfdReadClosedV2 { _extra: None });
        }
        let mapping = self.mapping.mapping.as_ref()
            .ok_or(SealedMemfdReadClosedV2 { _extra: None })?;
        let before = self.inspection.before
            .ok_or(SealedMemfdReadClosedV2 { _extra: None })?;
        Ok(use_bytes(mapping.bytes(), ImmutableFileIdentity {
            device: before.device, inode: before.inode, bytes: before.bytes,
            mapping: PhantomData,
        }))
    }

    /// Closes a fully validated mapping and descriptor without rearming them.
    ///
    /// The original inspection, post-map metadata and successful Result remain.
    /// Failed or partial originals retain their files and mapping. This closes
    /// local input custody only; it grants no descriptor-copy or role claim.
    ///
    /// # Errors
    /// Refuses an absent, failed, or already retired original.
    pub fn retire_positive_mapping_v2(&mut self) -> Result<(), SealedMemfdReadClosedV2> {
        if self.retired || !matches!(self.returned, Some(Ok(())))
            || self.mapping.mapping.is_none() || self.file.is_none()
        {
            return Err(SealedMemfdReadClosedV2 { _extra: None });
        }
        // Match the ordinary mapping's physical unmap-before-close order.
        drop(self.mapping.mapping.take());
        drop(self.file.take());
        self.retired = true;
        Ok(())
    }

    /// Borrows the exact original seal, metadata, mapping or race error.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.returned.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    /// Bounds compiled native receiving and constructor representations.
    #[must_use]
    pub fn receiving_memory_bytes_v2() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<(), ImmutableFileError>>())?
            .checked_add(std::mem::size_of::<ObservedFile>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<libc::stat>().checked_mul(2)?)
    }
}

/// Reports a retained sealed-mapping refusal without projecting native custody.
#[derive(Debug, thiserror::Error)]
#[error("sealed mapping refused; actual original remains resident")]
pub struct SealedMemfdReadClosedV2 {
    _extra: Option<OwnedFd>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn refused_nonregular_input_retains_actual_file_and_observation() {
        let (reader, _writer) = rustix::pipe::pipe().unwrap();
        let mut original = SealedMemfdReadOriginalV2::new();
        assert!(original.prepare_once(reader, 1, 1).is_err());

        assert!(matches!(original.returned, Some(Err(ImmutableFileError::NotRegular))));
        assert!(original.inspection.before.is_some());
        assert!(rustix::fs::fstat(original.file.as_ref().unwrap()).is_ok());
        assert!(original.with_bytes(|bytes, _| bytes.len()).is_err());
    }

    #[test]
    fn complete_mapping_stays_on_same_original_for_following_validation() {
        let sealed = super::super::SealedReadOnlyCredential::create("capture-spec-test", b"spec", 4).unwrap();
        let descriptor = sealed.as_fd().try_clone_to_owned().unwrap();
        let mut original = SealedMemfdReadOriginalV2::new();
        original.prepare_once(descriptor, 4, 4).unwrap();

        assert_eq!(original.with_bytes(|bytes, _| bytes.to_vec()).unwrap(), b"spec");
        assert!(original.file.is_some());
        assert!(original.mapping.mapping.is_some());
        assert!(original.failure().is_none());

        original.retire_positive_mapping_v2().unwrap();
        assert!(original.file.is_none());
        assert!(original.mapping.mapping.is_none());
        assert!(original.inspection.before.is_some());
        assert!(matches!(original.returned, Some(Ok(()))));
        assert!(original.with_bytes(|bytes, _| bytes.len()).is_err());
        assert!(original.retire_positive_mapping_v2().is_err());
    }
}
