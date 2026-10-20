//! Binds the selected physical recipe to its actual paid Controller originals.
//!
//! The fixed destinations hold at most one primary and two independently owed
//! native comparisons. A failed comparison is never recycled; a completed
//! positive comparison releases only its temporary probes. No negative entry
//! sends a TPM command or reopens the healthy attachment phase.

mod currentness;
mod payment;

pub(super) use currentness::BrokerPhysicalCurrentnessOriginalV2;
pub(crate) use payment::BrokerPhysicalPaymentOriginalV2;

use super::*;
use aos_sandbox::Journal;

pub(super) fn prepare_samples_v1(attempt: &mut BrokerPhysicalAttemptV1)
    -> Result<(), PhysicalTpmFailureV1>
{
    attempt.payment.as_ref().ok_or(PhysicalTpmFailureV1::State)?.require_primary_program_v2()?;
    for (index, slot) in attempt.currentness.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(Box::new(attempt.payment.as_ref().ok_or(PhysicalTpmFailureV1::State)?
                .new_currentness_v2()?));
        }
        let sample = slot.as_mut().ok_or(PhysicalTpmFailureV1::State)?;
        if sample.is_entered() { continue; }
        let source = attempt.observations.as_ref().ok_or(PhysicalTpmFailureV1::State)?;
        let result = (|| {
            if attempt.identity_captured { sample.prepare_identity(source)?; }
            if attempt.context_captured { sample.prepare_context(source)?; }
            Ok::<(), FloorErrorV1>(())
        })();
        if let Err(cause) = result {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::Currentness(index, cause));
            return Err(cause.into());
        }
    }
    Ok(())
}

impl RetainedBrokerPhysicalTpmOwnerV1 {
    pub(crate) fn retain_funded_broker_v2(
        binding: BrokerPhysicalOpenV1<'_>, payment: BrokerPhysicalPaymentOriginalV2,
    ) -> Self {
        let mut owner = Self::retain_broker(binding);
        if let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &mut owner.binding {
            attempt.payment = Some(payment);
        }
        owner
    }

    pub(crate) fn admit_broker_with_controller_pair_v1(
        &mut self, main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        self.prepare_controller_request_v1(main, sidecar)?;
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Fresh)?;
        let result = operation.owner.admit_broker_inner();
        let result = operation.finish(result);
        self.finish_controller_primitive_v1(result)
    }
}

impl<'owner, 'origin, 'startup, H: PhysicalHostSlotV1<'owner, 'origin, 'startup>>
    RetainedPhysicalTpmOwnerV1<'owner, 'origin, 'startup, H>
{
    pub(super) fn require_broker_owner_retaining_v1(&mut self, profile: FloorProfileV1)
        -> Result<(), PhysicalTpmFailureV1>
    {
        if !self.has_controller_payment_v1() {
            return require_broker_floor_owner_v1(profile.endpoint()).map_err(Into::into);
        }
        let attempt = self.broker_mut()?;
        attempt.payment.as_ref().ok_or(PhysicalTpmFailureV1::State)?.require_primary_program_v2()?;
        let index = attempt.owner_samples.iter().position(Option::is_none)
            .ok_or(PhysicalTpmFailureV1::State)?;
        attempt.owner_samples[index] = Some(crate::recovery::OwnerConfinementOriginalV1::new());
        let result = attempt.owner_samples[index].as_mut().ok_or(PhysicalTpmFailureV1::State)?
            .capture_floor_owner_once_v2(profile);
        if let Err(cause) = result {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::OwnerConfinement(index, cause));
            return Err(cause.into());
        }
        drop(attempt.owner_samples[index].take());
        Ok(())
    }

    pub(super) fn require_broker_helper_preamble_retaining_v1(&mut self, profile: FloorProfileV1, pid: u32)
        -> Result<(), PhysicalTpmFailureV1>
    {
        if !self.has_controller_payment_v1() {
            return BrokerPhysicalOpenV1::require_helper_preamble(profile, pid).map_err(Into::into);
        }
        self.require_broker_owner_retaining_v1(profile)?;
        if pid == 0 || pid == std::process::id() { return Err(FloorErrorV1::Provisioning.into()); }
        Ok(())
    }

    pub(super) fn revalidate_initial_broker_image_v1(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        if !self.has_controller_payment_v1() { return self.broker_image_mut()?.revalidate().map_err(Into::into); }
        let RetainedPhysicalBindingV1::Broker { image: Some(image), attempt: Some(attempt), .. }
            = &mut self.binding else { return Err(PhysicalTpmFailureV1::State); };
        if attempt.initial_image_currentness.is_some() { return Err(PhysicalTpmFailureV1::State); }
        attempt.initial_image_currentness = Some(crate::recovery::HelperImageRevalidationOriginalV1::new());
        let original = attempt.initial_image_currentness.as_mut().ok_or(PhysicalTpmFailureV1::State)?;
        if let Err(cause) = image.revalidate_primary_retaining_v1(original) {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::InitialImageCurrentness(cause));
            return Err(cause.into());
        }
        drop(attempt.initial_image_currentness.take());
        Ok(())
    }

    pub(super) fn has_controller_payment_v1(&self) -> bool {
        matches!(&self.binding, RetainedPhysicalBindingV1::Broker {
            attempt: Some(attempt), ..
        } if attempt.payment.is_some())
    }

    fn prepare_controller_request_v1(&mut self, main: &Journal, sidecar: &Journal)
        -> Result<(), FloorErrorV1>
    {
        let attempt = self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?;
        attempt.after_entered = false;
        attempt.owed_physical_consumed = false;
        let payment = attempt.payment.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        if let Err(cause) = payment.prepare_request(main, sidecar) {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::Payment(cause));
            attempt.phase = BrokerPhysicalPhaseV1::Failed;
            return Err(cause);
        }
        Ok(())
    }

    pub(super) fn require_controller_spawn_stack_v1(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        if !self.has_controller_payment_v1() { return Ok(()); }
        let attempt = self.broker_mut()?;
        if let Err(cause) = attempt.payment.as_mut().ok_or(PhysicalTpmFailureV1::State)?
            .require_spawn_stack()
        {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::Payment(cause));
            return Err(cause.into());
        }
        Ok(())
    }

    pub(super) fn mark_controller_after_entered_v1(&mut self) {
        if let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &mut self.binding {
            if attempt.payment.is_some() { attempt.after_entered = true; }
        }
    }

    pub(super) fn require_controller_custody_v1(&mut self) -> Result<(), PhysicalTpmFailureV1> {
        let RetainedPhysicalBindingV1::Broker {
            image: Some(image), service: Some(service), profile,
            attempt: Some(attempt),
        } = &mut self.binding else { return Err(PhysicalTpmFailureV1::State); };
        prepare_samples_v1(attempt)?;
        let index = attempt.currentness.iter().position(|slot|
            slot.as_ref().is_some_and(|sample| !sample.is_entered()))
            .ok_or(PhysicalTpmFailureV1::State)?;
        let sample = attempt.currentness[index].as_mut().ok_or(PhysicalTpmFailureV1::State)?;
        let payment = attempt.payment.as_mut().ok_or(PhysicalTpmFailureV1::State)?;
        payment.consume_primary_policy_comparisons_v2(1)?;
        let result = sample.observe_primary(
            self.pidfd.as_ref().ok_or(PhysicalTpmFailureV1::State)?,
            self.child.as_mut().ok_or(PhysicalTpmFailureV1::State)?, self.identity,
            attempt.observations.as_mut().ok_or(PhysicalTpmFailureV1::State)?,
            image, service, *profile, self.poisoned, attempt.cold_deadline,
        );
        if let Err(cause) = result {
            payment.preserve_failed_shared_interval_v1();
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::Currentness(index, cause));
            return Err(cause.into());
        }
        if let Err(cause) = payment.retire_completed_shared_interval_v1() {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::Payment(cause));
            return Err(cause.into());
        }
        // All native predicates in this custody comparison completed. The
        // actual image/service/pidfd and healthy observation source stay held.
        drop(attempt.currentness[index].take());
        Ok(())
    }

    fn observe_controller_owed_v1(&mut self, floor_post: bool) -> Result<(), FloorErrorV1> {
        let RetainedPhysicalBindingV1::Broker { image, service, profile,
            attempt: Some(attempt) } = &mut self.binding
            else { return Err(FloorErrorV1::Unavailable); };
        let consumed = if floor_post { &mut attempt.owed_floor_consumed }
            else { &mut attempt.owed_physical_consumed };
        if *consumed || attempt.payment.is_none() { return Err(FloorErrorV1::Unavailable); }
        *consumed = true;
        // Destinations were allocated/prearmed while their real source was
        // healthy. Prefixes before process capture still use the same fixed
        // destination and observe every actual owner already reached.
        let index = attempt.currentness.iter().position(|slot|
            slot.as_ref().is_none_or(|sample| !sample.is_entered()))
            .ok_or(FloorErrorV1::Unavailable)?;
        if attempt.currentness[index].is_none() {
            attempt.currentness[index] = Some(Box::new(
                attempt.payment.as_ref().ok_or(FloorErrorV1::Unavailable)?.new_currentness_v2()?,
            ));
        }
        let sample = attempt.currentness[index].as_mut().ok_or(FloorErrorV1::Unavailable)?;
        if let Some(source) = attempt.observations.as_ref() {
            // The actual fixed duplicate/native bytes were paid before the
            // primary. This observes the same already-open partial OFDs even
            // when their first read closed healthy source readiness.
            sample.prepare_available_prefix_v1(source);
        }
        attempt.payment.as_mut().ok_or(FloorErrorV1::Unavailable)?.consume_policy_comparisons_v1(1)?;
        let result = sample.observe_negative(
            self.pidfd.as_ref(), self.child.as_mut(), image.as_ref(), service.as_mut(),
            attempt.service_opening.as_deref_mut(),
            attempt.launch_image.as_ref().ok_or(FloorErrorV1::Unavailable)?,
            *profile, attempt.cold_deadline,
        );
        if let Err(cause) = result {
            attempt.first_failure.get_or_insert(BrokerPhysicalFailureV1::Currentness(index, cause));
        }
        // A successful comparison is DATA only. Poison/ambiguity remains on
        // the same original owner and cannot turn this post into readiness.
        result
    }

    fn finish_controller_primitive_v1<T>(&mut self, result: Result<T, FloorErrorV1>)
        -> Result<T, FloorErrorV1>
    {
        if result.is_err() {
            if let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &self.binding {
                if let Some(payment) = &attempt.payment { payment.preserve_failed_shared_interval_v1(); }
            }
            let after_entered = self.broker().map(|attempt| attempt.after_entered).unwrap_or(true);
            if !after_entered { let _ = self.observe_controller_owed_v1(false); }
            if let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &mut self.binding {
                if let Some(payment) = &mut attempt.payment { payment.fence(); }
            }
            return if self.controller_physical_failure_v1().is_some() {
                Err(FloorErrorV1::RetainedControllerPhysical)
            } else { result };
        }
        let attempt = self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?;
        // A positive authenticated frame and both native bookends completed.
        // These raw temporary record owners are no longer identity anchors.
        drop(attempt.acknowledgment.take());
        drop(attempt.observation.take());
        attempt.request = None;
        attempt.payment.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .retire_request_after_disposal()?;
        result
    }

    pub(crate) fn read_with_controller_pair_v1(
        &mut self, index: u32, main: &Journal, sidecar: &Journal,
    ) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        if !self.has_controller_payment_v1() { return self.read(index); }
        self.prepare_controller_request_v1(main, sidecar)?;
        let profile = self.broker_profile()?;
        if index != profile.endpoint().nv_index() { return Err(FloorErrorV1::Provisioning); }
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Ready)?;
        let result = operation.owner.read_broker_inner(profile, index);
        let result = operation.finish(result);
        self.finish_controller_primitive_v1(result)
    }

    pub(crate) fn extend_with_controller_pair_v1(
        &mut self, index: u32, input: &[u8; 32], main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if !self.has_controller_payment_v1() { return self.extend(index, input); }
        self.prepare_controller_request_v1(main, sidecar)?;
        let profile = self.broker_profile()?;
        if index != profile.endpoint().nv_index() { return Err(FloorErrorV1::Provisioning); }
        let operation = BrokerPhysicalOperationV1::begin(self, BrokerPhysicalPhaseV1::Ready)?;
        let result = operation.owner.extend_broker_inner(profile, input);
        let result = operation.finish(result);
        self.finish_controller_primitive_v1(result)
    }

    pub(crate) fn controller_physical_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &self.binding
            else { return None; };
        attempt.payment.as_ref()?;
        attempt.native_failure()
    }

    pub(crate) fn controller_property_failure_view_v1(&self)
        -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>>
    {
        let RetainedPhysicalBindingV1::Broker { attempt: Some(attempt), .. } = &self.binding
            else { return None; };
        match attempt.first_failure.as_ref()? {
            BrokerPhysicalFailureV1::Currentness(index, _) => {
                let sample = attempt.currentness.get(*index)?.as_ref()?;
                let selected = std::ptr::from_ref(attempt.native_failure()?).cast::<()>();
                if sample.failure().is_some_and(|cause|
                    std::ptr::from_ref(cause).cast::<()>() == selected)
                { sample.property_failure_view_v1() } else { None }
            }
            BrokerPhysicalFailureV1::ServiceAcquisition(_) => attempt.service_opening.as_ref()?
                .property_failure_view_v1(),
            _ => None,
        }
    }

    pub(crate) fn observe_controller_floor_post_v1(&mut self) -> Result<(), FloorErrorV1> {
        // A caught unwind can leave the physical after frontier unentered.
        // Complete that already-paid post first, then the independent outer
        // floor post. Neither path restores phase or dispatches a TPM command.
        let physical_owed = self.broker().is_ok_and(|attempt|
            !attempt.after_entered && !attempt.owed_physical_consumed);
        if physical_owed { let _ = self.observe_controller_owed_v1(false); }
        self.observe_controller_owed_v1(true)
    }

    pub(crate) fn begin_storage_primitive_v2(&mut self,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
        main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        self.require_storage_program_disposition_v2()?;
        self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?.payment.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?.begin_storage_primitive_v2(receiving, main, sidecar)
    }

    fn require_storage_program_disposition_v2(&mut self) -> Result<(), FloorErrorV1> {
        if self.poisoned || self.child.is_none() || self.channel.is_none()
            || self.pidfd.is_none() || self.identity.is_none()
        { return Err(FloorErrorV1::Unavailable); }
        let attempt = self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?;
        if attempt.phase != BrokerPhysicalPhaseV1::Ready || attempt.first_failure.is_some()
            || !attempt.identity_captured || !attempt.context_captured || !attempt.after_entered
            || attempt.request.is_some() || attempt.acknowledgment.is_some() || attempt.observation.is_some()
            || attempt.currentness.iter().flatten().any(|sample| sample.is_entered() || sample.failure().is_some())
        { return Err(FloorErrorV1::Unavailable); }
        Ok(())
    }

    pub(crate) fn finish_storage_primitive_v2(&mut self,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
        main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        self.require_storage_program_disposition_v2()?;
        self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?.payment.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?.finish_storage_program_v2(receiving, main, sidecar)
    }

    pub(crate) fn finish_storage_initial_program_v2(&mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>, main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if self.poisoned || self.child.is_none() || self.channel.is_none()
            || self.pidfd.is_none() || self.identity.is_none()
        { return Err(FloorErrorV1::Unavailable); }
        let attempt = self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?;
        if attempt.phase != BrokerPhysicalPhaseV1::Ready || attempt.first_failure.is_some()
            || !attempt.identity_captured || !attempt.context_captured || !attempt.after_entered
            || attempt.request.is_some() || attempt.acknowledgment.is_some() || attempt.observation.is_some()
            || attempt.currentness.iter().flatten().any(|sample| sample.is_entered() || sample.failure().is_some())
        { return Err(FloorErrorV1::Unavailable); }
        attempt.payment.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .finish_storage_program_v2(receiving, main, sidecar)
    }

    pub(crate) fn finish_controller_initial_once_v1(&mut self) -> Result<(), FloorErrorV1> {
        self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?.payment.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?.finish_initial_once()
    }
}

impl RetainedBrokerPhysicalTpmOwnerV1 {
    /// Retires unused prearmed probes only at the completed whole Client take.
    pub(crate) fn retire_completed_initial_native_v1(
        &mut self,
        completed: &aos_sandbox::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &Journal,
        sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if self.poisoned || self.child.is_none() || self.channel.is_none()
            || self.pidfd.is_none() || self.identity.is_none()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        let attempt = self.broker_mut().map_err(PhysicalTpmFailureV1::broker_error)?;
        if attempt.phase != BrokerPhysicalPhaseV1::Ready || attempt.first_failure.is_some()
            || !attempt.identity_captured || !attempt.context_captured || !attempt.after_entered
            || attempt.request.is_some() || attempt.acknowledgment.is_some()
            || attempt.observation.is_some()
            || attempt.currentness.iter().flatten().any(|sample| sample.is_entered() || sample.failure().is_some())
        {
            return Err(FloorErrorV1::Unavailable);
        }
        attempt.payment.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .require_completed_initial_native_v1(completed, main, sidecar)?;
        // The actual original C post is already positive and the same held
        // main/sidecar remain borrowed. No outer initial debt can reach these
        // never-entered samples now. Future operations prearm fresh samples
        // through prepare_samples under their unchanged paid resident peak.
        for sample in &mut attempt.currentness { drop(sample.take()); }
        Ok(())
    }
}
