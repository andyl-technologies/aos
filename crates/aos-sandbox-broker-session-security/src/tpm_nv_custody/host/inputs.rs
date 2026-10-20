//! Retains normal Host input acquisition and same-Source currentness prefixes.
//!
//! The normal journal parks the inert admission original before calling the
//! only fixed-purpose entry. Each later comparison prepays its actual retained
//! destination from that same genuine Origins before allocation or native work.
//! Independent postchecks remain owed after a primary refusal.

use std::error::Error;

use aos_sandbox::{RuntimeDeploymentComparisonErrorV1, RuntimeDeploymentComparisonOriginsV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use zeroize::Zeroizing;

use crate::recovery::{
    HelperExecutedImageOriginalV1, HelperImageAcquisitionOriginalV1,
    HelperImageRevalidationOriginalV1, MeasuredHelperImageV1,
    ModeRevalidationOriginalV1,
};

use super::provisioning::{
    HostAuthReadOriginalV1, HostProvisioningAdmissionOriginalV1, HostProvisioningPinV1,
};
use super::{AdmittedHostTpmInputsV1, HostTpmAdmissionErrorV1};

/// Keeps the actual initial native input prefix until journal disposition.
pub(super) struct HostTpmInputAdmissionOriginalV1<'origin, 'startup> {
    payment: Option<Result<(), RuntimeDeploymentComparisonErrorV1>>,
    origins: Option<Result<(), RuntimeDeploymentComparisonErrorV1>>,
    provisioning: HostProvisioningAdmissionOriginalV1,
    provisioned: Option<HostProvisioningPinV1<'origin, 'startup>>,
    image: HelperImageAcquisitionOriginalV1,
    candidate: Option<AdmittedHostTpmInputsV1<'origin, 'startup>>,
    body: Option<Result<(), HostTpmAdmissionErrorV1>>,
    entered: bool,
    taken: bool,
}

impl<'origin, 'startup> HostTpmInputAdmissionOriginalV1<'origin, 'startup> {
    pub(super) fn new() -> Self {
        Self {
            payment: None,
            origins: None,
            provisioning: HostProvisioningAdmissionOriginalV1::new(),
            provisioned: None,
            image: HelperImageAcquisitionOriginalV1::new(),
            candidate: None,
            body: None,
            entered: false,
            taken: false,
        }
    }

    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .checked_add(HostProvisioningAdmissionOriginalV1::receiving_demand_v1()?).ok()?
            .checked_add(HelperImageAcquisitionOriginalV1::runtime_deployment_receiving_demand_v1()?).ok()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.payment).or_else(|| failure(&self.origins))
            .or_else(|| self.provisioning.failure())
            .or_else(|| self.image.failure())
            .or_else(|| self.candidate.as_ref().and_then(AdmittedHostTpmInputsV1::native_failure_v1))
            .or_else(|| failure(&self.body))
    }

    fn capture_once(
        &mut self,
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<(), HostTpmAdmissionErrorV1> {
        self.payment = Some(origins.admit_boot_publisher_representation_v1(Self::receiving_demand_v1()));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        self.origins = Some(origins.recheck());
        if !matches!(self.origins, Some(Ok(()))) {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }

        // The partially admitted pin remains in this original if helper
        // acquisition or the final whole-input comparison later refuses.
        self.provisioned = Some(self.provisioning.open_once(origins)?);
        let image = self.capture_image_once()?;
        let provisioning = self.provisioned.take().ok_or(HostTpmAdmissionErrorV1::Unusable)?;
        self.candidate = Some(AdmittedHostTpmInputsV1 {
            provisioning,
            image,
            usable: true,
            boot_currentness: Some(HostInputArchiveV1::new()),
        });
        self.candidate.as_mut().ok_or(HostTpmAdmissionErrorV1::Unusable)?.recheck()?;
        self.provisioning.auth.retire_positive_file();
        Ok(())
    }

    fn capture_image_once(&mut self) -> Result<MeasuredHelperImageV1, HostTpmAdmissionErrorV1> {
        self.image.capture_runtime_deployment_once().map_err(HostTpmAdmissionErrorV1::Image)?;
        self.image.take_completed_once().ok_or(HostTpmAdmissionErrorV1::Unusable)
    }
}

impl<'origin, 'startup> AdmittedHostTpmInputsV1<'origin, 'startup> {
    /// Admits only normal055 inputs into the journal's preexisting original.
    ///
    /// # Errors
    /// Rejects reentry, Source refusal, or any fixed native input comparison.
    /// All reached failures and partial owners remain in `original`.
    pub(super) fn admit_boot_retaining_once(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
        original: &mut HostTpmInputAdmissionOriginalV1<'origin, 'startup>,
    ) -> Result<Self, HostTpmAdmissionErrorV1> {
        if original.entered || original.taken {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        original.entered = true;
        original.body = Some(original.capture_once(origins));
        if !matches!(original.body, Some(Ok(()))) || original.failure().is_some() {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        let admitted = original.candidate.take().ok_or(HostTpmAdmissionErrorV1::Unusable)?;
        original.taken = true;
        Ok(admitted)
    }

    pub(super) fn native_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.boot_currentness.as_ref().and_then(HostInputArchiveV1::failure)
    }
}

/// Selects only an existing private input comparison; it grants no effect.
pub(super) enum HostInputOperationV1 {
    Recheck,
    Auth,
    Executed(u32),
}

pub(super) struct HostInputArchiveV1 {
    steps: Vec<Box<HostInputCheckOriginalV1>>,
    payment: Option<Result<(), RuntimeDeploymentComparisonErrorV1>>,
    allocation: Option<std::collections::TryReserveError>,
    refused: bool,
    pending_owed: Option<usize>,
    order: Option<HostTpmAdmissionErrorV1>,
    unwind_drained: bool,
}

impl HostInputArchiveV1 {
    fn new() -> Self {
        Self {
            steps: Vec::new(), payment: None, allocation: None, refused: false,
            pending_owed: None, order: None, unwind_drained: false,
        }
    }

    pub(super) fn run_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
        operation: HostInputOperationV1,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, HostTpmAdmissionErrorV1> {
        let index = self.reserve_step_once(provisioning, image, &operation)?;
        let step = self.steps.get_mut(index).ok_or(HostTpmAdmissionErrorV1::Unusable)?;
        step.observe_once(provisioning, image, operation);
        if step.failure().is_some() || !matches!(step.result, Some(Ok(()))) {
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        step.retire_positive_probes();
        Ok(step.auth.take_auth())
    }

    fn reserve_step_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
        operation: &HostInputOperationV1,
    ) -> Result<usize, HostTpmAdmissionErrorV1> {
        if self.refused || self.failure().is_some() {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        // The full old/new pointer backing is charged before reserve; existing
        // entries are separately paid retained originals, never rebuilt reads.
        let demand = self.steps.len().checked_add(1)
            .and_then(|slots| slots.checked_mul(2 * std::mem::size_of::<Box<HostInputCheckOriginalV1>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| HostInputCheckOriginalV1::receiving_demand_v1(operation, provisioning, image)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)).ok());
        self.payment = Some(provisioning.origins().admit_boot_publisher_representation_v1(demand));
        if !matches!(self.payment, Some(Ok(()))) {
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        if let Err(cause) = self.steps.try_reserve_exact(1) {
            self.allocation = Some(cause);
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        let index = self.steps.len();
        self.steps.push(Box::new(HostInputCheckOriginalV1::new()));
        Ok(index)
    }

    pub(super) fn prepare_owed_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
    ) -> Result<(), HostTpmAdmissionErrorV1> {
        if self.pending_owed.is_some() || self.unwind_drained {
            self.order.get_or_insert(HostTpmAdmissionErrorV1::Unusable);
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        let index = self.reserve_step_once(provisioning, image, &HostInputOperationV1::Recheck)?;
        self.steps.get_mut(index).ok_or(HostTpmAdmissionErrorV1::Unusable)?.owed = true;
        self.pending_owed = Some(index);
        Ok(())
    }

    pub(super) fn observe_owed_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
    ) -> Result<(), HostTpmAdmissionErrorV1> {
        let Some(index) = self.pending_owed else {
            self.order.get_or_insert(HostTpmAdmissionErrorV1::Unusable);
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        };
        let earlier_failure = self.refused || self.failure().is_some();
        let step = self.steps.get_mut(index).ok_or(HostTpmAdmissionErrorV1::Unusable)?;
        if step.result.is_some() {
            self.order.get_or_insert(HostTpmAdmissionErrorV1::Unusable);
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        // The parked index remains until every native lane returns. If an
        // unwind interrupts this pass, the terminal drain can enter only the
        // still-unused lanes on this same prepaid destination.
        step.observe_once(provisioning, image, HostInputOperationV1::Recheck);
        let complete = matches!(step.result, Some(Ok(()))) && step.failure().is_none();
        if complete && !earlier_failure {
            step.retire_positive_probes();
        }
        self.pending_owed = None;
        if earlier_failure || !complete {
            self.refused = true;
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        Ok(())
    }

    pub(super) fn drain_after_unwind_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
    ) -> Result<(), HostTpmAdmissionErrorV1> {
        if self.unwind_drained {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        self.unwind_drained = true;
        self.refused = true;
        let Some(index) = self.pending_owed else {
            return Ok(());
        };
        let step = self.steps.get_mut(index).ok_or(HostTpmAdmissionErrorV1::Unusable)?;
        step.interrupted.get_or_insert(HostTpmAdmissionErrorV1::Unusable);
        self.observe_owed_once(provisioning, image)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // Earlier native debt precedes a later representation refusal.
        self.steps.iter().find_map(|step| step.failure())
            .or_else(|| failure(&self.payment))
            .or_else(|| self.allocation.as_ref().map(|cause| cause as _))
            .or_else(|| self.order.as_ref().map(|cause| cause as _))
    }
}

struct HostInputCheckOriginalV1 {
    before: HostInputSampleOriginalV1,
    auth: HostAuthReadOriginalV1,
    auth_result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    executed: HelperExecutedImageOriginalV1,
    executed_result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    image_post: HelperImageRevalidationOriginalV1,
    image_post_result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    after: HostInputSampleOriginalV1,
    result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    interrupted: Option<HostTpmAdmissionErrorV1>,
    owed: bool,
}

impl HostInputCheckOriginalV1 {
    fn new() -> Self {
        Self {
            before: HostInputSampleOriginalV1::new(),
            auth: HostAuthReadOriginalV1::new(),
            auth_result: None,
            executed: HelperExecutedImageOriginalV1::new(),
            executed_result: None,
            image_post: HelperImageRevalidationOriginalV1::new(),
            image_post_result: None,
            after: HostInputSampleOriginalV1::new(),
            result: None,
            interrupted: None,
            owed: false,
        }
    }

    fn receiving_demand_v1(
        operation: &HostInputOperationV1,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
    ) -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        let sample = HostInputSampleOriginalV1::receiving_demand_v1(provisioning, image)?;
        let samples = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .checked_add(sample).ok()?.checked_add(sample).ok()?;
        match operation {
            HostInputOperationV1::Recheck => Some(samples),
            HostInputOperationV1::Auth => samples
                .checked_add(HostAuthReadOriginalV1::receiving_demand_v1()?).ok(),
            HostInputOperationV1::Executed(_) => samples
                .checked_add(HelperExecutedImageOriginalV1::receiving_with_input_demand_v1()?).ok()?
                .checked_add(image.revalidation_receiving_demand_v1()?).ok(),
        }
    }

    fn observe_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
        operation: HostInputOperationV1,
    ) {
        if self.interrupted.is_some() {
            self.before.drain_after_unwind_once(provisioning, image, self.owed);
        } else if self.owed {
            self.before.observe_owed_once(provisioning, image);
        } else {
            self.before.observe_once(provisioning, image);
        }
        if self.before.failure().is_none() {
            match operation {
                HostInputOperationV1::Recheck => {}
                HostInputOperationV1::Auth => {
                    self.auth_result = Some(provisioning.auth_retaining(&mut self.auth));
                }
                HostInputOperationV1::Executed(pid) => {
                    self.executed_result = Some(image.require_executed_retaining_v1(pid, &mut self.executed)
                        .map_err(HostTpmAdmissionErrorV1::Image));
                    // Both held-image posts are owed even if executable or maps
                    // refused. The same image engine observes both independently.
                    self.image_post_result = Some(image.revalidate_owed_retaining_v1(&mut self.image_post)
                        .map_err(HostTpmAdmissionErrorV1::Image));
                }
            }
        }
        if self.interrupted.is_some() {
            self.after.drain_after_unwind_once(provisioning, image, self.owed);
        } else if self.owed {
            self.after.observe_owed_once(provisioning, image);
        } else {
            self.after.observe_once(provisioning, image);
        }
        self.result = Some(if self.failure().is_none() { Ok(()) }
            else { Err(HostTpmAdmissionErrorV1::Unusable) });
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure().or_else(|| self.auth.failure())
            .or_else(|| failure(&self.auth_result))
            .or_else(|| self.executed.failure()).or_else(|| failure(&self.executed_result))
            .or_else(|| self.image_post.failure()).or_else(|| failure(&self.image_post_result))
            .or_else(|| self.interrupted.as_ref().map(|cause| cause as _))
            .or_else(|| self.after.failure()).or_else(|| failure(&self.result))
    }

    fn retire_positive_probes(&mut self) {
        self.before.auth.retire_positive_file();
        self.auth.retire_positive_file();
        self.after.auth.retire_positive_file();
        self.executed.retire_positive_probes_once_v1();
    }
}

struct HostInputSampleOriginalV1 {
    auth: HostAuthReadOriginalV1,
    auth_result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    mode: ModeRevalidationOriginalV1,
    mode_result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    image: HelperImageRevalidationOriginalV1,
    image_result: Option<Result<(), HostTpmAdmissionErrorV1>>,
    origins: Option<Result<(), HostTpmAdmissionErrorV1>>,
    entered: [bool; 4],
}

impl HostInputSampleOriginalV1 {
    fn new() -> Self {
        Self {
            auth: HostAuthReadOriginalV1::new(), auth_result: None,
            mode: ModeRevalidationOriginalV1::new(), mode_result: None,
            image: HelperImageRevalidationOriginalV1::new(), image_result: None,
            origins: None,
            entered: [false; 4],
        }
    }

    fn receiving_demand_v1(
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
    ) -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .checked_add(HostAuthReadOriginalV1::receiving_demand_v1()?).ok()?
            .checked_add(provisioning.mode_receiving_demand_v1()?).ok()?
            .checked_add(image.revalidation_receiving_demand_v1()?).ok()
    }

    fn observe_once(&mut self, provisioning: &HostProvisioningPinV1<'_, '_>, image: &MeasuredHelperImageV1) {
        self.observe_native_once(provisioning, image);
        if !self.entered[3] {
            self.entered[3] = true;
            self.origins = Some(provisioning.recheck_origins());
        }
    }

    fn observe_owed_once(&mut self, provisioning: &HostProvisioningPinV1<'_, '_>, image: &MeasuredHelperImageV1) {
        self.observe_native_once(provisioning, image);
        if !self.entered[3] {
            self.entered[3] = true;
            // Core's same-Original actual native post is separately prepaid
            // by the enclosing physical binding and always finished there.
            // This historical DATA check neither debits nor replaces it.
            self.origins = Some(provisioning.compare_retained_origins_data_v1());
        }
    }

    fn observe_native_once(&mut self, provisioning: &HostProvisioningPinV1<'_, '_>, image: &MeasuredHelperImageV1) {
        // Each guard is latched before native entry. A caught unwind never
        // repeats an entered native original, and cannot suppress the other
        // independently prepaid lanes during terminal drain.
        if !self.entered[0] {
            self.entered[0] = true;
            self.auth_result = Some(provisioning.auth_retaining(&mut self.auth));
        }
        if !self.entered[1] {
            self.entered[1] = true;
            self.mode_result = Some(provisioning.recheck_mode_retaining(&mut self.mode));
        }
        if !self.entered[2] {
            self.entered[2] = true;
            self.image_result = Some(image.revalidate_owed_retaining_v1(&mut self.image)
                .map_err(HostTpmAdmissionErrorV1::Image));
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.auth.failure().or_else(|| failure(&self.auth_result))
            .or_else(|| self.mode.failure()).or_else(|| failure(&self.mode_result))
            .or_else(|| self.image.failure()).or_else(|| failure(&self.image_result))
            .or_else(|| failure(&self.origins))
    }

    fn drain_after_unwind_once(
        &mut self,
        provisioning: &HostProvisioningPinV1<'_, '_>,
        image: &MeasuredHelperImageV1,
        owed: bool,
    ) {
        if self.entered[2] && self.image_result.is_none() {
            self.image_result = Some(image.drain_owed_after_unwind_once_v1(&mut self.image)
                .map_err(HostTpmAdmissionErrorV1::Image));
        }
        if owed {
            self.observe_owed_once(provisioning, image);
        } else {
            self.observe_once(provisioning, image);
        }
    }
}

pub(super) fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
