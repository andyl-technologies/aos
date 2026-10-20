//! Owns the actual Root enrollment and its closed fixed initial receiving lane.
//!
//! Profile/kernel payment and observations use the same private original pair,
//! fixed table and Root envelope. No vector, account, File, callback or successful
//! DATA argument admits this lane. The same native original also owns its
//! negative-lifetime fence; semantic stages and genuine purpose loans remain
//! in the upper role until their complete owner cut.

mod policy_flight;
mod q04_transport;
pub use q04_transport::{RootQ04InputCurrentLoanV1, RootQ04NativeStreamLoanV1, RootQ04TransportOriginalV1};
use policy_flight::RootPolicyFlightNativeDisposalV1;
pub(super) mod financial;
pub use financial::{RootFinancialClosedV1, RootJournalFinancialBorrowV1,
    RootJournalFinancialOriginalV1, RootPolicyFlightDisposalV2,
    RootPolicyFlightFinancialDisposalV1, RootUpperRefusalOriginalV1,
    RootUpperFailureParkingV1, RootUpperMutationGuardV1};
mod history_post;
pub use history_post::RootPrearmedHistoryServicePostV1;

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, NativeLayoutDemand};

use super::{
    ActivationNamesErrorV1, OriginalEnrollment, RootEnrollmentErrorV1,
    RootEnrollmentOriginalsV1, RootInitialActivationErrorV1, RootKernelOriginalCaptureV1,
    RootKernelStartupFieldsV1, RootKernelStartupPartsV1, RootObservationErrorV1,
    RootProfileOriginalCaptureV1,
};
use crate::profile_data::schema::NormalRootProfileV1;
use crate::immutable_image::RetainedImmutableFileV1;

/// Retains an actual native-stage admission failure before its role projection.
#[derive(Debug, thiserror::Error)]
pub enum RootNativeAdmissionErrorV1 {
    /// Preserves the closed native prerequisite or representation refusal.
    #[error(transparent)]
    Prerequisite(#[from] RootObservationErrorV1),
    /// Preserves the original resource arithmetic and failed dimension.
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_model::AccountingError),
}

/// Holds the original Root enrollment and the same fixed initial receiving lane.
///
/// The only constructor is inert. A positive native recipient join still grants
/// no semantic writer, accepted flight, RootOpen, Use or Q04 capability.
pub struct RootInitialReceivingOriginalV1 {
    // This is first so even direct native ownership aborts before any original
    // field release. The upper role's Drop forwards here at its old frontier.
    invocation: Option<super::root_invocation::RootInvocationOriginalV1>,
    enrollment: Option<RootEnrollmentOriginalsV1>,
    permanent: Option<Arc<super::root_permanent::RootPermanentNativeOriginalV1>>,
    financial: Option<financial::RootFinancialCustodyV1>,
    owner: Arc<()>,
    profile_prefix: Option<Result<ResourceVector, RootEnrollmentErrorV1>>,
    profile: Option<RootProfileOriginalCaptureV1>,
    kernel: Option<RootKernelOriginalCaptureV1>,
    completion: Option<Result<(), RootObservationErrorV1>>,
    recipient_binding: Option<Result<(), RootEnrollmentErrorV1>>,
    selected_admission: Option<Result<ResourceVector, RootNativeAdmissionErrorV1>>,
    currentness_admission: Option<Result<ResourceVector, RootNativeAdmissionErrorV1>>,
    currentness_refusal: Option<RootObservationErrorV1>,
    currentness: Option<super::RootServiceCurrentnessOriginalV1>,
    policy_flight_admission: Option<Result<ResourceVector, RootNativeAdmissionErrorV1>>,
    policy_flight: Option<Box<policy_flight::RootPolicyFlightNativeV1>>,
}

impl RootInitialReceivingOriginalV1 {
    fn native_enrollment(&self) -> Option<&RootEnrollmentOriginalsV1> {
        self.enrollment.as_ref().or_else(|| {
            self.permanent.as_ref().map(|original| original.enrollment())
        })
    }

    fn native_invocation(&self) -> Option<&super::root_invocation::RootInvocationOriginalV1> {
        self.invocation.as_ref().or_else(|| {
            self.permanent.as_ref().map(|original| original.invocation())
        })
    }

    /// Creates inert destinations using the real upper native parser layout.
    #[must_use]
    pub fn new(layout: NativeLayoutDemand) -> Self {
        Self {
            invocation: Some(super::root_invocation::RootInvocationOriginalV1::new()),
            enrollment: Some(RootEnrollmentOriginalsV1::new(layout)),
            permanent: None,
            financial: Some(financial::RootFinancialCustodyV1::new()),
            owner: Arc::new(()),
            profile_prefix: None,
            profile: None,
            kernel: None,
            completion: None,
            recipient_binding: None,
            selected_admission: None,
            currentness_admission: None,
            currentness_refusal: None,
            currentness: None,
            policy_flight_admission: None,
            policy_flight: None,
        }
    }

    /// Captures this process's original fixed Root descriptor table.
    ///
    /// # Errors
    /// Preserves actual native/names/role causes and refuses repeated entry.
    pub fn capture_once(&mut self) -> Result<(), RootInitialActivationErrorV1> {
        if self.permanent.is_some() {
            self.latch_root_refusal_v1();
            return Err(RootInitialActivationErrorV1::Conflict);
        }
        self.enrollment.as_mut().ok_or(RootInitialActivationErrorV1::Conflict)?.capture_once()
    }

    /// Authenticates only the same captured pair with the complete shared parser.
    ///
    /// # Errors
    /// Preserves actual pair/envelope errors and refuses absent or repeated input.
    pub fn authenticate_once(&mut self) -> Result<ResourceVector, RootEnrollmentErrorV1> {
        if self.permanent.is_some() {
            self.latch_root_refusal_v1();
            return Err(RootEnrollmentErrorV1::Conflict);
        }
        self.enrollment.as_mut().ok_or(RootEnrollmentErrorV1::Conflict)?.authenticate_once()
    }

    /// Prices the complete fixed native lane without granting admission.
    #[must_use]
    pub fn fixed_profile_prefix_demand_v1() -> Option<ResourceVector> {
        use aos_sandbox_model::ResourceDimension as D;

        let own = std::mem::size_of::<Self>().checked_mul(2)?;
        let transfer = std::mem::size_of::<RootInitialStartupPartsV1>().checked_mul(2)?;
        let fields = std::mem::size_of::<RootInitialStartupFieldsV1>().checked_mul(2)?;
        let restoration = std::mem::size_of::<Result<(), RootInitialRestoreFailureV1>>()
            .checked_mul(2)?;
        let conversion = std::mem::size_of::<Result<
            RootInitialStartupFieldsV1, RootInitialStartupPartsV1,
        >>().checked_mul(2)?;
        let linked_conversion = std::mem::size_of::<Result<
            (RootInitialStartupFieldsV1, Arc<()>), RootInitialStartupPartsV1,
        >>().checked_mul(2)?;
        let link = std::mem::size_of::<(usize, usize, ())>();
        let invocation = std::mem::size_of::<super::root_invocation::RootInvocationOriginalV1>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<(), RootObservationErrorV1>>().checked_mul(3)?)?;
        let permanent = super::root_permanent::RootPermanentNativeOriginalV1::construction_bytes_v1()?;
        let memory = own.checked_add(invocation)?.checked_add(permanent)?
            .checked_add(transfer)?.checked_add(fields)?
            .checked_add(std::mem::size_of::<OriginalEnrollment>())?
            .checked_add(restoration)?.checked_add(conversion)?
            .checked_add(linked_conversion)?.checked_add(link)?
            .checked_add(std::mem::size_of::<Arc<()>>())?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(22)?)?;
        let parent = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            // Seven parent fields; three opaque destinations and their
            // two-field profile tuple; three moved fields; three constructors;
            // take/restore tuples two; copied enrollment/Arc one each; and
            // restoration/conversion Result+return carriers two each; the
            // restoration error field/construction two; Arc clone carrier one.
            // Eight financial carriers conservatively name the three nested
            // supplier returns, parent, combined/returned total, envelope and
            // admitted demand. The sealed linked conversion adds its two-field
            // tuple and whole Result/return carriers four. No unnamed metadata
            // pool funds these destinations or native ownership links. The
            // selected admission and currentness admission/refusal/sampler
            // fields four, plus fourteen selected/currentness financial carriers,
            // are paid before those later headers or computations exist.
            // The native invocation adds one parent destination, three actual
            // fence fields in construction/destination, and three named Result
            // carriers (checked prerequisite, fence return, public return).
            .with(D::MetadataEntries,
                7 + 3 + 2 + 3 + 3 + 2 + 1 + 1 + 2 + 2 + 2 + 1 + 8 + 4 + 4 + 14
                    + 1 + 3 * 2 + 3);
        RootProfileOriginalCaptureV1::fixed_demand()?
            .checked_add(RootKernelOriginalCaptureV1::fixed_demand()?).ok()?
            .checked_add(RootEnrollmentOriginalsV1::additional_receiving_demand_v1()?).ok()?
            .checked_add(parent).ok()
            .and_then(|demand| demand.checked_add(Self::financial_fixed_construction_demand_v1()?).ok())
    }

    /// Runs the closed same-original fixed profile/kernel receiving lane once.
    ///
    /// # Errors
    /// Refuses reentry, invalid original shape, insufficient fixed R or failed
    /// native/profile/recipient observations. Every reached independent post
    /// runs before the earlier completion is projected; failed owners remain.
    pub fn receive_profile_once(&mut self) -> Result<(), RootEnrollmentErrorV1> {
        if self.permanent.is_some() {
            self.latch_root_refusal_v1();
            return Err(RootEnrollmentErrorV1::Conflict);
        }
        if self.profile_prefix.is_some() || self.profile.is_some()
            || self.process_id_v1() != std::process::id()
            || !matches!(self.root_shape_result_v1(), Some(Ok(())))
        {
            return Err(RootEnrollmentErrorV1::Conflict);
        }
        self.profile_prefix = Some((|| {
            let envelope = self.enrollment_v1()
                .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                .ok_or(RootEnrollmentErrorV1::Unavailable)?;
            let demand = Self::fixed_profile_prefix_demand_v1()
                .ok_or(RootEnrollmentErrorV1::Unavailable)?;
            envelope.checked_sub(demand).map_err(|_| RootEnrollmentErrorV1::Unavailable)?;
            Ok(demand)
        })());
        if !matches!(self.profile_prefix, Some(Ok(_))) {
            return Err(RootEnrollmentErrorV1::Unavailable);
        }

        let original = self.enrollment_v1().copied()
            .ok_or(RootEnrollmentErrorV1::Unavailable)?;
        let envelope = original.policy.bootstrap_provisions().root_receiving
            .ok_or(RootEnrollmentErrorV1::Unavailable)?;
        self.kernel = Some(RootKernelOriginalCaptureV1::new());
        self.profile = Some(RootProfileOriginalCaptureV1::default());
        let kernel = self.kernel.as_mut().ok_or(RootEnrollmentErrorV1::Unavailable)?;
        let profile = self.profile.as_mut().ok_or(RootEnrollmentErrorV1::Unavailable)?;

        self.completion = Some((|| {
            kernel.capture_fixed_once(envelope)?;
            let (pid1, profile_original) = self.enrollment.as_mut()
                .and_then(RootEnrollmentOriginalsV1::profile_originals_v1)
                .ok_or(RootObservationErrorV1::Activation)?;
            profile.receive_original_once(profile_original)?;
            kernel.observe_original_once(pid1, profile)?;
            Ok(())
        })());
        kernel.finish_once(profile);
        self.recipient_binding = Some((|| {
            if !matches!(self.completion, Some(Ok(()))) {
                return Err(RootEnrollmentErrorV1::Unavailable);
            }
            let (invocation, producer) = kernel.observed_pair()
                .ok_or(RootEnrollmentErrorV1::Unavailable)?;
            if original.recipient_invocation != invocation
                || original.identity.native_fields().invocation != producer
                || self.enrollment.as_ref().map(RootEnrollmentOriginalsV1::process_id_v1)
                    != Some(std::process::id())
            {
                return Err(RootEnrollmentErrorV1::Unavailable);
            }
            Ok(())
        })());
        if matches!(self.recipient_binding, Some(Ok(()))) {
            kernel.settle_selected_positive_once().map_err(|_| RootEnrollmentErrorV1::Unavailable)
        } else {
            Err(RootEnrollmentErrorV1::Unavailable)
        }
    }

    /// Captures the same process identity after its actual positive recipient join.
    ///
    /// # Errors
    /// Refuses an absent/failed join or repeated native identity capture.
    pub fn prepare_startup_identity_once(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.permanent.is_some() {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if !matches!(self.recipient_binding, Some(Ok(()))) {
            return Err(RootObservationErrorV1::Service);
        }
        self.kernel.as_mut().ok_or(RootObservationErrorV1::Service)?
            .prepare_startup_identity_once()
    }

    /// Borrows the same actual profile capture without a mutation or payer port.
    #[must_use]
    pub fn profile_capture_v1(&self) -> Option<&RootProfileOriginalCaptureV1> {
        self.profile.as_ref()
    }

    /// Borrows the same actual kernel controls without a mutation or payer port.
    #[must_use]
    pub fn kernel_capture_v1(&self) -> Option<&RootKernelOriginalCaptureV1> {
        self.kernel.as_ref().or_else(|| self.permanent.as_ref().map(|original| original.service.kernel()))
    }

    /// Begins the actual Controller history worker interval on this original.
    ///
    /// # Errors
    /// Refuses incomplete handoff, earlier refusal or an already active worker.
    pub fn enter_controller_history_worker_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        let original = self.permanent.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let mut invocation = original.enter_native()?;
        let returned = original.service.enter_worker_once_v1();
        if returned.is_err() { invocation.refuse(); }
        returned
    }

    /// Ends only the same already-entered Controller history worker interval.
    ///
    /// # Errors
    /// Refuses missing original custody or an unentered worker. The owed path
    /// can retain its disposition after refusal without admitting new work.
    pub fn finish_controller_history_worker_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        let original = self.permanent.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let mut invocation = original.enter_observation()?;
        let returned = original.service.finish_worker_once_v1();
        if returned.is_err() { invocation.refuse(); }
        returned
    }

    /// Compares the actual retained worker interval without renewing authority.
    #[must_use]
    pub fn controller_history_worker_idle_data_v1(&self) -> bool {
        self.permanent.as_ref().is_some_and(|original| {
            original.service.worker_idle_data_v1()
        })
    }

    // Only the same native owner prices and consumes this closed once stage.
    // A second selected wrapper cannot reuse its successful admission/header.
    pub(super) fn admit_selected_native_once_v1(
        &mut self,
    ) -> Result<ResourceVector, RootObservationErrorV1> {
        let invalid = || RootObservationErrorV1::Profile;
        if self.selected_admission.is_some() {
            return Err(invalid());
        }
        self.selected_admission = Some((|| {
            if self.failure().is_some() { return Err(invalid().into()); }
            let prefix = self.profile_prefix_result_v1()
                .and_then(|result| result.as_ref().ok()).copied().ok_or_else(invalid)?;
            let envelope = self.enrollment_v1()
                .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                .ok_or_else(invalid)?;
            let demand = prefix.checked_add(super::RootSelectedStartupOriginalV1::demand(self)?)?;
            envelope.checked_sub(demand)?;
            Ok(demand)
        })());
        self.selected_admission.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or_else(invalid)
    }

    /// Borrows the whole selected admission cause before its coarse return.
    #[must_use]
    pub fn selected_admission_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.selected_admission.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
    }

    /// Observes currentness only for this receiver's actual sealed startup.
    ///
    /// The expected pair and finite payment come from this SAME original
    /// enrollment and its privately retained selected prefix. No field DTO,
    /// copied account, vector or caller success marker can admit this method.
    ///
    /// # Errors
    /// Refuses foreign/incomplete startup, prior debt, insufficient fixed R or
    /// failed native/local bookends. Only a complete positive sampler disposes;
    /// a failed sample remains resident and cannot be reset by another call.
    pub fn observe_startup_currentness_once(
        &mut self,
        startup: &super::RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        let permanent = self.permanent.as_ref().map(Arc::clone);
        let mut observation = match permanent.as_ref() {
            Some(original) => Some(original.enter_observation()?),
            None => None,
        };
        let result = self.observe_startup_currentness_inner(startup);
        if result.is_err() {
            match observation.as_mut() {
                Some(guard) => guard.refuse(),
                None => self.latch_root_refusal_v1(),
            }
        }
        result
    }

    fn observe_startup_currentness_inner(
        &mut self,
        startup: &super::RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        let invalid = || RootObservationErrorV1::Service;
        if let Some(permanent) = &self.permanent {
            if !startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
                || self.process_id_v1() != std::process::id()
                || !matches!(self.recipient_binding, Some(Ok(())))
            {
                return Err(invalid());
            }
            let original = self.enrollment_v1().ok_or_else(invalid)?;
            return permanent.service.observe_prepaid_once_v1(startup, original.recipient_invocation,
                original.identity.native_fields().invocation);
        }
        if self.currentness_refusal.is_some()
            || !startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
            || self.process_id_v1() != std::process::id()
            || !matches!(self.recipient_binding, Some(Ok(())))
            || self.currentness.as_ref().is_some_and(|sample| !sample.is_positive())
        {
            self.currentness_refusal.get_or_insert_with(invalid);
            return Err(invalid());
        }
        if self.currentness_admission.is_none() {
            self.currentness_admission = Some((|| {
                let prefix = self.selected_admission.as_ref()
                    .and_then(|result| result.as_ref().ok()).copied().ok_or_else(invalid)?;
                let envelope = self.enrollment_v1()
                    .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                    .ok_or_else(invalid)?;
                let disposed_names = self.kernel.as_ref()
                    .and_then(|kernel| kernel.settled_named_descriptor_peak_v1())
                    .ok_or_else(invalid)?;
                let currentness = super::RootServiceCurrentnessOriginalV1::demand()
                    .ok_or_else(invalid)?;
                // The same original kernel really disposed these successful
                // name handles. Its complete prefix remains paid; only their
                // sequential FD peak is reused, as at the original upper gate.
                let currentness = currentness.with(
                    aos_sandbox_model::ResourceDimension::OpenFiles,
                    currentness.get(aos_sandbox_model::ResourceDimension::OpenFiles)
                        .saturating_sub(disposed_names),
                );
                let demand = prefix.checked_add(currentness)?;
                envelope.checked_sub(demand)?;
                Ok(demand)
            })());
        }
        if !matches!(self.currentness_admission, Some(Ok(_))) {
            return Err(invalid());
        }
        let original = self.enrollment_v1().copied().ok_or_else(invalid)?;
        let kernel = self.kernel.as_ref().ok_or_else(invalid)?;
        // This None disposes only a prior complete positive. Failure never
        // reaches it; the SAME native whole-service R remains continuously held.
        self.currentness = None;
        self.currentness = Some(super::RootServiceCurrentnessOriginalV1::new());
        let sample = self.currentness.as_mut().ok_or_else(invalid)?;
        sample.observe_once(startup, kernel, original.recipient_invocation,
            original.identity.native_fields().invocation);
        if sample.is_positive() { Ok(()) } else { Err(invalid()) }
    }

    /// Borrows the actual currentness cause ahead of its upper projection.
    #[must_use]
    pub fn currentness_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.currentness_admission.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.currentness.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| self.currentness_refusal.as_ref()
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.permanent.as_ref().and_then(|original| original.service.failure()))
    }

    /// Permanently latches a refusal from an actual upper Root continuation.
    ///
    /// This can only arm negative ownership. It releases no resource, admits no
    /// purpose and supplies no success or new receiving capability.
    pub fn latch_root_refusal_v1(&mut self) {
        if let Some(invocation) = self.native_invocation() {
            invocation.latch_refusal();
        }
    }

    /// Aborts at the original upper Drop frontier while native R remains armed.
    ///
    /// Actual role Drop calls this before any field release. The native owner
    /// repeats the same fence defensively as its own first field is destroyed.
    pub fn abort_if_root_armed_v1(&mut self) {
        match self.native_invocation() {
            Some(invocation) => invocation.abort_if_armed(),
            None => std::process::abort(),
        }
    }

    /// Settles only the actual same-original native startup handoff once.
    ///
    /// This disposition does not complete a semantic purpose, issue a RootOpen,
    /// accepted flight, Use or Q04 grant, or release/refund the permanent R. The
    /// role still owns those separate typed continuations and latches refusal
    /// before returning any later failed original.
    ///
    /// # Errors
    /// Retains and refuses foreign or incomplete startup, a failed same-owner
    /// native sample, any prior refusal, or a repeated handoff.
    pub fn settle_serving_startup_once_v1(
        &mut self,
        startup: &super::RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        let checked = if startup.initial_owner.as_ref()
            .is_some_and(|owner| self.same_owner_link(owner))
            && self.process_id_v1() == std::process::id()
            && matches!(self.completion, Some(Ok(())))
            && matches!(self.recipient_binding, Some(Ok(())))
            && matches!(self.selected_admission, Some(Ok(_)))
            && self.currentness.as_ref().is_some_and(|sample| sample.is_positive())
            && self.failure().is_none()
        {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        };
        // Both actual originals must still be local before a successful move.
        // No effect or allocation intervenes between this check and take.
        if self.permanent.is_some() || startup.selected_permanent.get().is_some()
            || self.enrollment.is_none() || self.invocation.is_none()
            || self.financial.is_none() || self.kernel.is_none() || self.currentness.is_none()
        {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.native_invocation().ok_or(RootObservationErrorV1::Service)?
            .settle_checked_startup_once(checked)?;
        let invocation = match self.invocation.take() {
            Some(invocation) => invocation,
            None => std::process::abort(),
        };
        let enrollment = match self.enrollment.take() {
            Some(enrollment) => enrollment,
            None => std::process::abort(),
        };
        let financial = match self.financial.take() {
            Some(financial) => financial,
            None => std::process::abort(),
        };
        let kernel = match self.kernel.take() {
            Some(kernel) => kernel,
            None => std::process::abort(),
        };
        let sampler = match self.currentness.take() {
            Some(sampler) => sampler,
            None => std::process::abort(),
        };
        let permanent = Arc::new(
            super::root_permanent::RootPermanentNativeOriginalV1::from_serving_originals(
                invocation, enrollment, Arc::clone(&self.owner), financial, kernel, sampler,
            ),
        );
        if startup.selected_permanent.set(Arc::clone(&permanent)).is_err() {
            std::process::abort();
        }
        self.permanent = Some(permanent);
        Ok(())
    }

    /// Borrows the native invocation's first refusal without disposing originals.
    #[must_use]
    pub fn invocation_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.native_invocation().and_then(|invocation| invocation.failure())
            .map(|cause| cause as &(dyn Error + 'static))
    }

    /// Moves both actual startup payloads together after the original join.
    #[must_use]
    pub fn take_startup_originals_v1(&mut self) -> Option<RootInitialStartupPartsV1> {
        if self.permanent.is_some() {
            self.latch_root_refusal_v1();
            return None;
        }
        if !matches!(self.recipient_binding, Some(Ok(()))) || self.failure().is_some() {
            return None;
        }
        let profile = self.profile.as_mut()?.take_originals();
        let kernel = self.kernel.as_mut()?.take_startup_originals();
        Some(RootInitialStartupPartsV1 {
            profile,
            kernel,
            owner: Arc::clone(&self.owner),
        })
    }

    pub(super) fn owner_link(&self) -> Arc<()> {
        Arc::clone(&self.owner)
    }

    pub(super) fn same_owner_link(&self, owner: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }

    /// Restores the same still-opaque payload on an incomplete outer tuple.
    ///
    /// # Errors
    /// Returns the WHOLE actual foreign payload when its owner differs or the
    /// receiving destinations are absent. It never drops failed restore input.
    pub fn restore_startup_originals_v1(
        &mut self,
        originals: Option<RootInitialStartupPartsV1>,
    ) -> Result<(), RootInitialRestoreFailureV1> {
        if self.permanent.is_some() {
            self.latch_root_refusal_v1();
            return Err(RootInitialRestoreFailureV1 { originals });
        }
        let Some(originals) = originals else {
            return Ok(());
        };
        if !Arc::ptr_eq(&self.owner, &originals.owner)
            || self.profile.is_none() || self.kernel.is_none()
        {
            return Err(RootInitialRestoreFailureV1 { originals: Some(originals) });
        }
        if let (Some(profile), Some(kernel)) = (&mut self.profile, &mut self.kernel) {
            profile.restore_originals(originals.profile);
            kernel.restore_startup_originals(originals.kernel);
        }
        Ok(())
    }

    /// Borrows nonauthorizing enrollment DATA from this same actual pair.
    #[must_use]
    pub fn enrollment_v1(&self) -> Option<&OriginalEnrollment> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::enrollment_v1)
    }

    /// Borrows the complete actual Root-envelope Result for role classification.
    #[must_use]
    pub fn root_shape_result_v1(&self) -> Option<&Result<(), bank::ResourceBankDataError>> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::root_shape_result_v1)
    }

    /// Borrows the process identity captured with the original table.
    #[must_use]
    pub fn process_id_v1(&self) -> u32 {
        self.native_enrollment().map_or(0, RootEnrollmentOriginalsV1::process_id_v1)
    }

    /// Reports physical table completion without granting role authority.
    #[must_use]
    pub fn is_captured_v1(&self) -> bool {
        self.native_enrollment().is_some_and(RootEnrollmentOriginalsV1::is_captured_v1)
    }

    /// Borrows the actual fixed-prefix Result for the role's cumulative adapter.
    #[must_use]
    pub fn profile_prefix_result_v1(&self) -> Option<&Result<ResourceVector, RootEnrollmentErrorV1>> {
        self.profile_prefix.as_ref()
    }

    /// Borrows the actual completion for the role's existing classification.
    #[must_use]
    pub fn completion_result_v1(&self) -> Option<&Result<(), RootObservationErrorV1>> {
        self.completion.as_ref()
    }

    /// Borrows the actual recipient join for the existing private role adapter.
    #[must_use]
    pub fn recipient_binding_result_v1(&self) -> Option<&Result<(), RootEnrollmentErrorV1>> {
        self.recipient_binding.as_ref()
    }

    /// Borrows the actual initial table failure without releasing custody.
    #[must_use]
    pub fn table_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::table_failure_v1)
    }

    /// Borrows the actual names refusal for the role classification adapter.
    #[must_use]
    pub fn names_failure_v1(&self) -> Option<&ActivationNamesErrorV1> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::names_failure_v1)
    }

    /// Borrows the actual role refusal for the existing role adapter.
    #[must_use]
    pub fn role_failure_v1(&self) -> Option<&RootInitialActivationErrorV1> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::role_failure_v1)
    }

    /// Borrows the original pair cause ahead of later role projections.
    #[must_use]
    pub fn pair_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::pair_failure_v1)
    }

    /// Borrows the earliest reached failure without changing the native owners.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native_enrollment().and_then(RootEnrollmentOriginalsV1::failure)
            .or_else(|| self.profile_prefix.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.profile.as_ref().and_then(|profile| profile.failure()))
            .or_else(|| self.kernel.as_ref().and_then(|kernel| kernel.failure()))
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.recipient_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.selected_admission.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.currentness_failure_v1())
            .or_else(|| self.policy_flight_failure_v1())
            .or_else(|| self.financial_failure_v1())
            .or_else(|| self.invocation_failure_v1())
    }
}

impl Drop for RootInitialReceivingOriginalV1 {
    fn drop(&mut self) {
        if let Some(permanent) = &self.permanent {
            permanent.end_initial();
        } else {
            self.abort_if_root_armed_v1();
        }
    }
}

/// Keeps both actual initial payloads sealed until the whole upper tuple succeeds.
pub struct RootInitialStartupPartsV1 {
    profile: Option<(RetainedImmutableFileV1, NormalRootProfileV1)>,
    kernel: Option<RootKernelStartupPartsV1>,
    owner: Arc<()>,
}

impl RootInitialStartupPartsV1 {
    /// Reports only completeness of this actual owned transfer tuple.
    ///
    /// This local DATA predicate grants no native, financial or role authority.
    #[must_use]
    pub fn is_complete_v1(&self) -> bool {
        self.profile.is_some() && self.kernel.is_some()
    }

    /// Moves complete native fields without cloning, IO or an authority grant.
    ///
    /// # Errors
    /// Returns the WHOLE same payload on an incomplete tuple, retaining every
    /// reached original rather than constructing fields from substitute DATA.
    pub fn into_startup_fields_v1(self) -> Result<RootInitialStartupFieldsV1, Self> {
        self.into_linked_startup_fields_v1().map(|(fields, _owner)| fields)
    }

    // The selected native constructor keeps this same private physical link.
    // It cannot be supplied by a caller or replaced with field DATA.
    pub(super) fn into_linked_startup_fields_v1(
        self,
    ) -> Result<(RootInitialStartupFieldsV1, Arc<()>), Self> {
        match (self.profile, self.kernel) {
            (Some((profile_file, profile)), Some(kernel)) => Ok((
                RootInitialStartupFieldsV1 {
                    profile_file,
                    profile,
                    kernel: kernel.into_startup_fields_v1(),
                },
                self.owner,
            )),
            (profile, kernel) => Err(Self { profile, kernel, owner: self.owner }),
        }
    }
}

/// Carries moved native fields and canonical profile DATA without role authority.
pub struct RootInitialStartupFieldsV1 {
    /// Same actual measured Root profile file.
    pub profile_file: RetainedImmutableFileV1,
    /// Same complete decoded canonical profile model.
    pub profile: NormalRootProfileV1,
    /// Same actual native manager/process/cgroup/unit fields.
    pub kernel: RootKernelStartupFieldsV1,
}

/// Retains the whole native payload when a same-owner restoration is refused.
///
/// The private payload is diagnostic custody, not a grant or a DATA constructor.
pub struct RootInitialRestoreFailureV1 {
    // A closed repeated restore may have no supplied payload. A supplied
    // actual payload remains owned here; no fresh original is manufactured.
    originals: Option<RootInitialStartupPartsV1>,
}

impl std::fmt::Debug for RootInitialRestoreFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.originals;
        formatter.debug_struct("RootInitialRestoreFailureV1")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootInitialRestoreFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original Root native restoration differs")
    }
}

impl Error for RootInitialRestoreFailureV1 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_partial_restore_keeps_the_actual_owner_link() {
        // Both inert fixtures contain the actual armed initial-table fence.
        let first = std::mem::ManuallyDrop::new(
            RootInitialReceivingOriginalV1::new(NativeLayoutDemand::new(1, 2)),
        );
        let mut second = std::mem::ManuallyDrop::new(
            RootInitialReceivingOriginalV1::new(NativeLayoutDemand::new(1, 2)),
        );
        let partial = RootInitialStartupPartsV1 {
            profile: None,
            kernel: None,
            owner: Arc::clone(&first.owner),
        };

        let failure = second.restore_startup_originals_v1(Some(partial)).unwrap_err();

        assert!(Arc::ptr_eq(&failure.originals.as_ref().unwrap().owner, &first.owner));
        assert!(!Arc::ptr_eq(&failure.originals.as_ref().unwrap().owner, &second.owner));
        assert!(second.profile_capture_v1().is_none());
        assert!(second.kernel_capture_v1().is_none());
    }

    #[test]
    fn incomplete_conversion_preserves_the_same_opaque_payload() {
        let owner = Arc::new(());
        let partial = RootInitialStartupPartsV1 {
            profile: None,
            kernel: None,
            owner: Arc::clone(&owner),
        };

        let returned = match partial.into_startup_fields_v1() {
            Err(returned) => returned,
            Ok(_) => panic!("an incomplete payload became complete"),
        };

        assert!(Arc::ptr_eq(&returned.owner, &owner));
        assert!(!returned.is_complete_v1());
    }

    #[test]
    fn layout_data_cannot_enter_unfunded_initial_receiving() {
        // Retain the original armed fence; changing it would weaken production.
        let mut original = std::mem::ManuallyDrop::new(
            RootInitialReceivingOriginalV1::new(NativeLayoutDemand::new(1, 2)),
        );
        assert!(matches!(original.receive_profile_once(), Err(RootEnrollmentErrorV1::Conflict)));
        assert!(original.profile_prefix_result_v1().is_none());
        assert!(original.completion_result_v1().is_none());
        assert!(original.recipient_binding_result_v1().is_none());
        assert!(original.profile_capture_v1().is_none());
        assert!(original.kernel_capture_v1().is_none());
        assert!(original.take_startup_originals_v1().is_none());
        assert!(original.failure().is_none());
    }

    #[test]
    fn transferred_restore_keeps_supplied_parts_and_repeated_none_refuses() {
        let mut original = std::mem::ManuallyDrop::new(
            RootInitialReceivingOriginalV1::new(NativeLayoutDemand::new(1, 2)),
        );
        // Only this private inert fixture sets the native phase; no real PID1
        // role or effect constructor is entered by these bookkeeping calls.
        let invocation = original.invocation.take().unwrap();
        invocation.settle_checked_startup_once(Ok(())).unwrap();
        let enrollment = original.enrollment.take().unwrap();
        let financial = original.financial.take().unwrap();
        original.permanent = Some(Arc::new(
            super::super::root_permanent::RootPermanentNativeOriginalV1::from_serving_originals(
                invocation, enrollment, Arc::clone(&original.owner), financial,
                RootKernelOriginalCaptureV1::new(), super::super::RootServiceCurrentnessOriginalV1::new(),
            ),
        ));
        let supplied_owner = Arc::new(());
        let parts = RootInitialStartupPartsV1 {
            profile: None, kernel: None, owner: Arc::clone(&supplied_owner),
        };

        let supplied = original.restore_startup_originals_v1(Some(parts)).unwrap_err();
        let cause = original.invocation_failure_v1().unwrap() as *const dyn Error;
        let absent = original.restore_startup_originals_v1(None).unwrap_err();
        let repeated = original.restore_startup_originals_v1(None).unwrap_err();

        assert!(Arc::ptr_eq(&supplied.originals.as_ref().unwrap().owner, &supplied_owner));
        assert!(absent.originals.is_none());
        assert!(repeated.originals.is_none());
        assert!(std::ptr::eq(cause, original.invocation_failure_v1().unwrap() as *const dyn Error));
    }

}

#[cfg(target_os = "linux")]
impl RootInitialReceivingOriginalV1 {
    fn take_fixed_writer_once(
        &mut self,
        recipe: super::root_writer::recipe::RootWriterRecipeV1,
    ) -> Result<super::RootWriterOpeningOriginalV1, super::RootWriterErrorV1> {
        let original = match self.permanent.as_ref() {
            Some(original) => Arc::clone(original),
            None => {
                self.latch_root_refusal_v1();
                return Err(super::RootWriterErrorV1::Closed);
            }
        };
        super::RootWriterOpeningOriginalV1::from_initial(original, recipe)
    }

    /// Claims the original startup authority writer after the permanent handoff.
    ///
    /// The trusted Root coordinator retains its fixed/native/semantic permits.
    /// This native port grants no policy or receiving-purpose success.
    ///
    /// # Errors
    /// Refuses incomplete startup, ended invocation or a repeated recipe claim.
    pub fn take_startup_authority_writer_once_v1(
        &mut self,
    ) -> Result<super::RootWriterOpeningOriginalV1, super::RootWriterErrorV1> {
        self.take_fixed_writer_once(super::root_writer::recipe::RootWriterRecipeV1::StartupAuthority)
    }

    /// Claims the existing current authority writer under this same invocation.
    ///
    /// # Errors
    /// Refuses incomplete startup, ended invocation or a repeated recipe claim.
    pub fn take_current_authority_writer_once_v1(
        &mut self,
    ) -> Result<super::RootWriterOpeningOriginalV1, super::RootWriterErrorV1> {
        self.take_fixed_writer_once(super::root_writer::recipe::RootWriterRecipeV1::CurrentAuthority)
    }

    /// Claims the compiler-state writer under this same original invocation.
    ///
    /// # Errors
    /// Refuses incomplete startup, ended invocation or a repeated recipe claim.
    pub fn take_current_policy_writer_once_v1(
        &mut self,
    ) -> Result<super::RootWriterOpeningOriginalV1, super::RootWriterErrorV1> {
        self.take_fixed_writer_once(super::root_writer::recipe::RootWriterRecipeV1::CurrentPolicy)
    }
}

impl RootInitialReceivingOriginalV1 {
    /// Ends serving on the original Root invocation before its owner releases.
    ///
    /// Journal custody may retain this same financial owner after startup ends.
    /// That custody cannot extend serving or observation permission: this waits
    /// for the actual native interval and closes every future writer borrow.
    /// Refused/poisoned destruction preserves the original abort fence.
    pub fn end_serving_journal_lifetime_v1(&self) {
        match &self.permanent {
            Some(original) => original.end_initial(),
            None => std::process::abort(),
        }
    }
}
