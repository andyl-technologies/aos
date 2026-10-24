//! Retains native capture outputs until their real queue acceptance.
//!
//! The callback's existing paid body contains this journal. A refused or
//! partially validated output never becomes a new operation or a closed file.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::mem::ManuallyDrop;
#[cfg(test)]
use std::os::fd::FromRawFd as _;

/// Keeps distinct prequeue transfer, actual return and Native diagnostic facts.
#[cfg(not(test))]
#[derive(Debug, Default)]
pub(crate) struct PrequeueReturnHistory {
    identity: crate::fingerprint_native::MaterialRef,
    return_status: Option<i32>,
    return_first_failure: Option<FingerprintSamplerError>,
    observation_status: Option<i32>,
    observation_first_failure: Option<i32>,
    pipeline: Option<crate::fingerprint_native::PipelineStatus>,
    job_transfer: Option<PaidJobTransfer>,
    native_return_consumed: bool,
}

/// Records an actual move into a retained paid job, including a negative post.
#[cfg(not(test))]
#[derive(Debug)]
struct PaidJobTransfer {
    material: crate::fingerprint_native::MaterialRef,
    work: crate::fingerprint_native::WorkRef,
    submit_status: i32,
}

/// Owns one prequeue attempt, including outputs that cannot be validated.
///
/// The containing callback retains this value through refusal. Its material
/// fields deliberately have no implicit close path: Source's typed destruction
/// must first refuse outstanding local debt, and inherited copies remain inert.
pub(crate) struct CaptureAttempt {
    output: QemuFingerprintCaptureV2,
    #[cfg(not(test))]
    native_material: crate::fingerprint_native::MaterialRef,
    #[cfg(not(test))]
    return_history: PrequeueReturnHistory,
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
            native_material: crate::fingerprint_native::MaterialRef::empty(),
            #[cfg(not(test))]
            return_history: PrequeueReturnHistory::default(),
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
        #[cfg(not(test))]
        {
            let valid_transfer =
                self.return_history
                    .job_transfer
                    .as_ref()
                    .is_some_and(|transfer| {
                        transfer.material == self.return_history.identity
                            && transfer.work.is_live()
                            && transfer.submit_status == 0
                    });
            if !valid_transfer || self.return_history.native_return_consumed {
                return Err(self.refuse(FingerprintSamplerError::CaptureRetained));
            }
        }
        *self = Self::new();
        Ok(())
    }

    /// Records real paid-job custody before propagating a signed submit refusal.
    ///
    /// # Errors
    /// Retains an inconsistent transfer without treating absent local fields as
    /// proof of either queue acceptance or physical Native return.
    #[cfg(not(test))]
    pub(crate) fn moved_to_native_job(
        &mut self,
        material: crate::fingerprint_native::MaterialRef,
        work: crate::fingerprint_native::WorkRef,
        submit_status: i32,
    ) -> Result<(), FingerprintSamplerError> {
        if !self.attempted
            || self.native_status != Some(0)
            || self.first_failure.is_some()
            || self.ready.is_some()
            || self.material.is_some()
            || self.has_native_material()
            || !material.is_live()
            || material != self.return_history.identity
            || work.is_empty()
            || self.return_history.job_transfer.is_some()
            || self.return_history.native_return_consumed
        {
            return Err(self.refuse(FingerprintSamplerError::CaptureRetained));
        }
        self.return_history.job_transfer = Some(PaidJobTransfer {
            material,
            work,
            submit_status,
        });
        // The job now owns this borrowed descriptor's Material. This records a
        // custody move, not a Native close or a consumed physical return.
        self.output.device_fd = -1;
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
            !self.native_material.is_empty()
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
        let known_material = self.return_history.identity.is_live();
        let returned = if let Some(sample) = self.ready.as_mut() {
            if sample.native_material().is_empty() {
                None
            } else {
                Some(sample.return_material(id, api))
            }
        } else if let Some(material) = self.material.as_mut() {
            if material.native.owner.is_empty() {
                None
            } else {
                let status = (api.material_return)(id, &mut material.native.owner);
                if material.native.owner.is_empty() {
                    material.native.descriptor = -1;
                }
                Some(if status == 0 {
                    Ok(())
                } else {
                    Err(FingerprintSamplerError::NativeMaterial { status })
                })
            }
        } else if !self.native_material.is_empty() {
            let status = (api.material_return)(id, &mut self.native_material);
            Some(if status == 0 {
                Ok(())
            } else {
                Err(FingerprintSamplerError::NativeMaterial { status })
            })
        } else {
            None
        };
        let attempted_return = returned.is_some();
        let mut first = None;
        if let Some(result) = returned {
            let status = match &result {
                Ok(()) => 0,
                Err(FingerprintSamplerError::NativeMaterial { status }) => *status,
                Err(_) => -libc::EPROTO,
            };
            self.return_history.return_status = Some(status);
            if let Err(source) = result {
                self.return_history
                    .return_first_failure
                    .get_or_insert(source.clone());
                first = Some(source);
            }
        }
        let outstanding = !self.native_material.is_empty()
            || self
                .material
                .as_ref()
                .is_some_and(|material| !material.native.owner.is_empty())
            || self
                .ready
                .as_ref()
                .is_some_and(|sample| !sample.native_material().is_empty());
        if known_material && attempted_return && !outstanding {
            // This actual return call consumed the owning output, independently
            // of its signed post. A prior move into a job is recorded separately.
            self.return_history.native_return_consumed = true;
            self.output.device_fd = -1;
        }
        if known_material {
            let mut receipt = crate::fingerprint_native::PipelineStatus::default();
            let status = (api.pipeline_observe)(id, &self.return_history.identity, &mut receipt);
            let status = if status == 0
                && (receipt.schema_version != 1
                    || receipt.struct_size as usize
                        != size_of::<crate::fingerprint_native::PipelineStatus>()
                    || receipt.material_serial != self.return_history.identity.serial)
            {
                -libc::EPROTO
            } else {
                status
            };
            self.return_history.observation_status = Some(status);
            if status == 0 {
                self.return_history.pipeline = Some(receipt);
            } else {
                self.return_history
                    .observation_first_failure
                    .get_or_insert(status);
                if first.is_none() {
                    first = Some(FingerprintSamplerError::NativeMaterial { status });
                }
            }
        }
        if outstanding || self.output.device_fd >= 0 {
            return Err(first.unwrap_or(FingerprintSamplerError::CaptureRetained));
        }
        // SAFETY: these prequeue fields hold no remaining native owner. Custody
        // either returned through the actual call or moved into the recorded paid
        // job, whose debt remains independently retained. Failures stay above.
        unsafe {
            ManuallyDrop::drop(&mut self.material);
            ManuallyDrop::drop(&mut self.ready);
        }
        self.material = ManuallyDrop::new(None);
        self.ready = ManuallyDrop::new(None);
        match first {
            Some(source) => Err(source),
            None => Ok(()),
        }
    }

    /// Borrows diagnostics only while the caller retains the real control owner.
    #[cfg(not(test))]
    pub(crate) fn native_return_history(&self) -> &PrequeueReturnHistory {
        &self.return_history
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
        #[cfg(not(test))]
        {
            attempt.return_history.identity = attempt.native_material;
        }
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
        if attempt.native_material.is_live() && attempt.output.device_fd >= 0 {
            *attempt.material = Some(CapturedFingerprintMaterial {
                native: NativeCapturedMaterial {
                    owner: attempt.native_material,
                    descriptor: attempt.output.device_fd,
                },
                material_length: attempt.output.device_material_length,
                progress: MaterialDigestProgress::default(),
            });
            attempt.native_material = crate::fingerprint_native::MaterialRef::empty();
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
