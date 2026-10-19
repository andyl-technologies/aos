//! Retains native capture outputs until their real queue acceptance.
//!
//! The callback's existing paid body contains this journal. A refused or
//! partially validated output never becomes a new operation or a closed file.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::mem::ManuallyDrop;
#[cfg(test)]
use std::os::fd::FromRawFd as _;

/// Owns one prequeue attempt, including outputs that cannot be validated.
///
/// The containing callback retains this value through refusal. Its material
/// fields deliberately have no implicit close path: Source's typed destruction
/// must first refuse outstanding local debt, and inherited copies remain inert.
pub(crate) struct CaptureAttempt {
    output: QemuFingerprintCaptureV2,
    #[cfg(not(test))]
    native_material: *mut crate::fingerprint_native::Material,
    native_status: Option<c_int>,
    attempted: bool,
    material: ManuallyDrop<Option<CapturedFingerprintMaterial>>,
    ready: ManuallyDrop<Option<CapturedFingerprintSample>>,
    first_failure: Option<FingerprintSamplerError>,
}

// SAFETY: native pointers are opaque process-local identity projections. Source
// retains every physical owner and authenticates the actual Main/worker thread
// before effects; Rust never dereferences these pointers or closes their FDs.
unsafe impl Send for CaptureAttempt {}

impl CaptureAttempt {
    pub(crate) fn new() -> Self {
        Self {
            output: QemuFingerprintCaptureV2::default(),
            #[cfg(not(test))]
            native_material: std::ptr::null_mut(),
            native_status: None,
            attempted: false,
            material: ManuallyDrop::new(None),
            ready: ManuallyDrop::new(None),
            first_failure: None,
        }
    }

    /// Borrows the actual pending owner; the queue takes it only on acceptance.
    pub(crate) fn pending(&mut self) -> &mut Option<CapturedFingerprintSample> {
        &mut self.ready
    }

    /// Clears only the record whose sole owner was moved to the actual queue.
    ///
    /// # Errors
    /// Refuses incomplete or inconsistent transfer without starting a new capture.
    pub(crate) fn transferred(&mut self) -> Result<(), FingerprintSamplerError> {
        if !self.attempted
            || self.native_status != Some(0)
            || self.first_failure.is_some()
            || self.ready.is_some()
            || self.material.is_some()
            || self.has_native_material()
        {
            return Err(self.refuse(FingerprintSamplerError::CaptureRetained));
        }
        *self = Self::new();
        Ok(())
    }

    /// Reports only a local objection to physical parent destruction/transfer.
    pub(crate) fn has_material_debt(&self) -> bool {
        self.output.device_fd >= 0
            || self.material.is_some()
            || self.ready.is_some()
            || self.has_native_material()
    }

    fn has_native_material(&self) -> bool {
        #[cfg(not(test))]
        {
            !self.native_material.is_null()
        }
        #[cfg(test)]
        {
            false
        }
    }

    /// Returns actual prequeue Material custody after Source closes admission.
    ///
    /// # Errors
    /// Retains unknown descriptor debt, unconsumed native Material or return failure.
    #[cfg(not(test))]
    pub(crate) fn retire_native_material(
        &mut self,
        id: u64,
        api: crate::fingerprint_native::Api,
    ) -> Result<(), FingerprintSamplerError> {
        let known_material =
            self.has_native_material() || self.material.is_some() || self.ready.is_some();
        if let Some(sample) = self.ready.as_mut() {
            sample.return_material(id, api)?;
        }
        if let Some(material) = self.material.as_mut() {
            let status = (api.material_return)(id, &mut material.native.owner);
            if material.native.owner.is_null() {
                material.native.descriptor = -1;
            }
            if status != 0 {
                return Err(FingerprintSamplerError::NativeMaterial { status });
            }
            if !material.native.owner.is_null() {
                return Err(FingerprintSamplerError::CaptureRetained);
            }
        }
        if !self.native_material.is_null() {
            let status = (api.material_return)(id, &mut self.native_material);
            if status != 0 {
                return Err(FingerprintSamplerError::NativeMaterial { status });
            }
            if !self.native_material.is_null() {
                return Err(FingerprintSamplerError::CaptureRetained);
            }
        }
        if self.output.device_fd >= 0 && !known_material {
            return Err(FingerprintSamplerError::CaptureRetained);
        }
        self.output.device_fd = -1;
        // SAFETY: all actual native owners have been returned, so these local
        // read transcripts contain no live FD or Material/worker borrow.
        unsafe {
            ManuallyDrop::drop(&mut self.material);
            ManuallyDrop::drop(&mut self.ready);
        }
        self.material = ManuallyDrop::new(None);
        self.ready = ManuallyDrop::new(None);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fixture_journal(&self) -> (QemuFingerprintCaptureV2, Option<c_int>) {
        (self.output, self.native_status)
    }

    fn refuse(&mut self, failure: FingerprintSamplerError) -> FingerprintSamplerError {
        self.first_failure.get_or_insert(failure).clone()
    }
}

impl PluginFingerprintSampling {
    /// Captures into the callback's retained attempt before interpreting status.
    ///
    /// # Errors
    /// Preserves the first introspection, signed capture or validation refusal.
    /// An attempted capture cannot be repeated until its actual queue acceptance.
    pub(crate) fn capture(
        &self,
        attempt: &mut CaptureAttempt,
        current_icount: u64,
        vcpu_count: u32,
    ) -> Result<(), FingerprintSamplerError> {
        if attempt.attempted {
            return Err(attempt.refuse(FingerprintSamplerError::CaptureRetained));
        }
        attempt.attempted = true;
        let inputs = self
            .introspector
            .read_nvcpu_fingerprint_inputs(vcpu_count)
            .map_err(|failure| attempt.refuse(FingerprintSamplerError::Introspection(failure)))?;

        // Native writes directly into the retained record. Its signed result is
        // saved before validation; a nonconforming negative FD stays raw unknown
        // debt, because the exporter transfers ownership only on success.
        #[cfg(test)]
        let status = (self.capture)(&mut attempt.output);
        #[cfg(not(test))]
        let status = (self.capture)(&mut attempt.output, &mut attempt.native_material);
        attempt.native_status = Some(status);
        if status != 0 {
            return Err(attempt.refuse(FingerprintSamplerError::Capture { status }));
        }
        #[cfg(test)]
        if attempt.output.device_fd >= 0 {
            // SAFETY: a successful export transfers its one device descriptor.
            let file = unsafe { File::from_raw_fd(attempt.output.device_fd) };
            *attempt.material = Some(CapturedFingerprintMaterial {
                file,
                material_length: attempt.output.device_material_length,
                progress: MaterialDigestProgress::default(),
            });
        }
        #[cfg(not(test))]
        if !attempt.native_material.is_null() && attempt.output.device_fd >= 0 {
            *attempt.material = Some(CapturedFingerprintMaterial {
                native: NativeCapturedMaterial {
                    owner: attempt.native_material,
                    descriptor: attempt.output.device_fd,
                },
                material_length: attempt.output.device_material_length,
                progress: MaterialDigestProgress::default(),
            });
            attempt.native_material = std::ptr::null_mut();
        }
        if let Err(failure) = validate_capture_evidence(&attempt.output) {
            return Err(attempt.refuse(failure));
        }
        let Some(material) = attempt.material.as_ref() else {
            return Err(
                attempt.refuse(FingerprintSamplerError::InvalidCaptureDescriptor {
                    component: "device state",
                }),
            );
        };
        if let Err(failure) = validate_capture_file(material, "device state") {
            return Err(attempt.refuse(failure));
        }
        let mut sample =
            sample_metadata(current_icount, &inputs, attempt.output.device_schema_digest)
                .map_err(|failure| attempt.refuse(failure))?;
        sample.ram_bytes = attempt.output.ram_bytes;
        sample.ram_digest = attempt.output.ram_digest;
        sample.device_state_bytes = attempt.output.device_bytes;
        sample.device_state_sections = attempt.output.device_schema_sections;
        sample
            .validate()
            .map_err(|failure| attempt.refuse(FingerprintSamplerError::Slot(failure)))?;
        let Some(device) = attempt.material.take() else {
            return Err(attempt.refuse(FingerprintSamplerError::CaptureRetained));
        };
        *attempt.ready = Some(CapturedFingerprintSample { sample, device });
        Ok(())
    }
}
