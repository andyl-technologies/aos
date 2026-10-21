//! Retains two independent observations for one actual paid Root listener flight.
//!
//! The genuine upper Root owner admits the complete cumulative partition before
//! arming these destinations. Native binding is still checked here against this
//! receiver's same original enrollment and startup. A failed primary observation
//! does not consume or suppress the separately prearmed owed observation.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{RootInitialReceivingOriginalV1, RootNativeAdmissionErrorV1, RootObservationErrorV1};
use crate::receiving::{RootServiceCurrentnessOriginalV1, RootStartupNativeOriginalV1};

pub(super) struct RootPolicyFlightNativeV1 {
    before: RootServiceCurrentnessOriginalV1,
    after: RootServiceCurrentnessOriginalV1,
    before_return: Option<Result<(), RootObservationErrorV1>>,
    after_return: Option<Result<(), RootObservationErrorV1>>,
    disposal_entered: bool,
    q04_origin_claimed: bool,
    initial_controller_entered: bool,
}

impl RootInitialReceivingOriginalV1 {
    // The financial exclusion already holds N. This comparison performs no
    // native entry, mutex acquisition, observation or diagnostic projection.
    pub(super) fn require_active_policy_flight_native_v1(&self)
        -> Result<(), RootObservationErrorV1>
    {
        if matches!(self.policy_flight_admission, Some(Ok(_)))
            && self.policy_flight.as_ref().is_some_and(|flight|
                !flight.disposal_entered && matches!(flight.before_return, Some(Ok(())))
                    && flight.before.is_positive() && flight.after_return.is_none())
        {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    /// Prices the two actual native destinations without granting admission.
    #[must_use]
    pub fn policy_flight_native_demand_v1() -> Option<ResourceVector> {
        let observation = RootServiceCurrentnessOriginalV1::demand()?;
        let construction = std::mem::size_of::<RootPolicyFlightNativeV1>().checked_mul(3)?
            .checked_add(std::mem::size_of::<RootPolicyFlightNativeDisposalV1<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<RootPolicyFlightNativeDisposalV1<'_>, RootObservationErrorV1>>().checked_mul(2)?)?;
        observation.checked_add(observation).ok()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(construction).ok()?),
        ).ok()
    }

    /// Arms the original listener's before and independent owed native samples.
    ///
    /// # Errors
    /// Refuses reentry, a foreign startup, an incomplete recipient or selected
    /// prefix, earlier refusal, or insufficient original Root R. No IO is made.
    pub fn arm_policy_flight_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        let invalid = || RootObservationErrorV1::Service;
        if self.policy_flight_admission.is_some() || self.policy_flight.is_some()
            || self.permanent.is_none()
            || self.failure().is_some()
            || !startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
            || !matches!(self.recipient_binding, Some(Ok(())))
            || self.process_id_v1() != std::process::id()
        {
            self.latch_root_refusal_v1();
            return Err(invalid());
        }
        self.require_financial_flight_consumed_v1().map_err(|_| invalid())?;
        self.policy_flight_admission = Some((|| {
            let prefix = self.selected_admission.as_ref()
                .and_then(|result| result.as_ref().ok()).copied().ok_or_else(invalid)?;
            let envelope = self.enrollment_v1()
                .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                .ok_or_else(invalid)?;
            let demand = Self::policy_flight_native_demand_v1().ok_or_else(invalid)?;
            let complete = prefix.checked_add(demand)?;
            envelope.checked_sub(complete)?;
            Ok(complete)
        })());
        if !matches!(self.policy_flight_admission, Some(Ok(_))) {
            self.latch_root_refusal_v1();
            return Err(invalid());
        }
        self.policy_flight = Some(Box::new(RootPolicyFlightNativeV1 {
            before: RootServiceCurrentnessOriginalV1::new(),
            after: RootServiceCurrentnessOriginalV1::new(),
            before_return: None,
            after_return: None,
            disposal_entered: false,
            q04_origin_claimed: false, initial_controller_entered: false,
        }));
        Ok(())
    }

    /// Runs the primary observation on the same actual startup and original.
    ///
    /// # Errors
    /// Retains the actual first sampler or binding failure. Reentry cannot
    /// replace the destination or make the separately owed sample disappear.
    pub fn observe_policy_flight_before_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        self.observe_policy_flight_v1(startup, false)
    }

    /// Runs the prepaid independent post even after a primary refusal.
    ///
    /// # Errors
    /// Refuses a missing arm, foreign startup, ended original or repeated post.
    /// The same invocation fence remains held through all actual native IO.
    pub fn observe_policy_flight_after_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        self.observe_policy_flight_v1(startup, true)
    }

    fn observe_policy_flight_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        after: bool,
    ) -> Result<(), RootObservationErrorV1> {
        let invalid = || RootObservationErrorV1::Service;
        let same = startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
            && self.process_id_v1() == std::process::id()
            && matches!(self.recipient_binding, Some(Ok(())));
        let original = self.enrollment_v1().copied();
        let permanent = self.permanent.as_ref().map(Arc::clone);
        let kernel = self.kernel.as_ref().or_else(|| permanent.as_ref().map(|original| original.service.kernel()));
        let flight = self.policy_flight.as_mut().ok_or_else(invalid)?;
        let (sample, returned) = if after {
            (&mut flight.after, &mut flight.after_return)
        } else {
            (&mut flight.before, &mut flight.before_return)
        };
        if returned.is_some() {
            self.latch_root_refusal_v1();
            return Err(invalid());
        }
        *returned = Some((|| {
            if !same { return Err(invalid()); }
            let original = original.ok_or_else(invalid)?;
            let kernel = kernel.ok_or_else(invalid)?;
            // Observation admission allows Refused but never Ended; it grants
            // no effect and cannot restore Serving after the earlier cause.
            let mut guard = permanent.as_ref().ok_or_else(invalid)?.enter_observation()?;
            sample.observe_once(startup, kernel, original.recipient_invocation,
                original.identity.native_fields().invocation);
            if sample.is_positive() { Ok(()) } else {
                guard.refuse();
                Err(invalid())
            }
        })());
        if matches!(returned, Some(Ok(()))) { Ok(()) } else {
            self.latch_root_refusal_v1();
            Err(invalid())
        }
    }

    /// Borrows the original listener sampler cause without another observation.
    #[must_use]
    pub fn policy_flight_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.policy_flight_before_failure_v1().or_else(|| self.policy_flight_after_failure_v1())
    }

    /// Borrows only the primary admission or observation cause.
    #[must_use]
    pub fn policy_flight_before_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.policy_flight_admission.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                let flight = self.policy_flight.as_ref()?;
                flight.before.failure()
                    .or_else(|| flight.before_return.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn Error + 'static)))
            })
    }

    /// Borrows only the independently owed observation cause.
    #[must_use]
    pub fn policy_flight_after_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let flight = self.policy_flight.as_ref()?;
        flight.after.failure()
            .or_else(|| flight.after_return.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}

/// Holds the same two completed native samples through upper disposal.
///
/// The genuine Initial owner alone constructs this token after its same-startup
/// checks. Forgetting it leaves the entered native slot resident and unavailable;
/// it neither ends Initial nor releases permanent Root writer ownership.
#[must_use]
pub(super) struct RootPolicyFlightNativeDisposalV1<'original> {
    flight: &'original mut Option<Box<RootPolicyFlightNativeV1>>,
    admission: &'original mut Option<Result<ResourceVector, RootNativeAdmissionErrorV1>>,
}

impl RootInitialReceivingOriginalV1 {
    pub(super) fn claim_q04_transport_origin_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        let same = startup
            .initial_owner
            .as_ref()
            .is_some_and(|owner| self.same_owner_link(owner))
            && self.process_id_v1() == std::process::id()
            && matches!(self.recipient_binding, Some(Ok(())));
        if !same || self.failure().is_some() || self.require_active_policy_flight_v1().is_err() {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let flight = self
            .policy_flight
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        if flight.q04_origin_claimed {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        flight.q04_origin_claimed = true;
        Ok(())
    }

    pub(super) fn require_q04_transport_native_posts_v1(
        &self,
    ) -> Result<(), RootObservationErrorV1> {
        if self.failure().is_some()
            || !self.policy_flight.as_ref().is_some_and(|flight| {
                flight.q04_origin_claimed
                    && !flight.disposal_entered
                    && matches!(flight.before_return, Some(Ok(())))
                    && matches!(flight.after_return, Some(Ok(())))
                    && flight.before.is_positive()
                    && flight.after.is_positive()
            })
        {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(())
    }

    /// Prepares disposal of the actual positive listener sample pair once.
    ///
    /// This performs no native IO or accounting mutation. The caller must keep
    /// the same Initial and startup borrowed while it disposes the corresponding
    /// accepted socket, peer and upper control owners, then consume the token.
    ///
    /// # Errors
    /// Refuses a failed or foreign startup, incomplete native samples, missing
    /// admission, prior preparation, ended lifetime or earlier original refusal.
    pub(super) fn prepare_policy_flight_disposal_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<RootPolicyFlightNativeDisposalV1<'_>, RootObservationErrorV1> {
        let same = startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
            && self.process_id_v1() == std::process::id()
            && matches!(self.recipient_binding, Some(Ok(())));
        let positive = self.policy_flight.as_ref().is_some_and(|flight| {
            !flight.disposal_entered
                && matches!(flight.before_return, Some(Ok(())))
                && matches!(flight.after_return, Some(Ok(())))
                && flight.before.is_positive()
                && flight.after.is_positive()
        });
        if !same || !positive || self.failure().is_some()
            || !matches!(self.policy_flight_admission, Some(Ok(_)))
            || !self.native_invocation().is_some_and(|invocation| invocation.is_serving())
        {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let flight = self.policy_flight.as_mut().ok_or(RootObservationErrorV1::Service)?;
        flight.disposal_entered = true;
        Ok(RootPolicyFlightNativeDisposalV1 {
            flight: &mut self.policy_flight,
            admission: &mut self.policy_flight_admission,
        })
    }
}

impl RootPolicyFlightNativeDisposalV1<'_> {
    /// Disposes these positive native samples after actual upper disposition.
    ///
    /// No check, allocation, native IO, refund or permanent lifetime transition
    /// follows this boundary. The next flight still needs actual fresh admission.
    pub fn complete_after_disposal_v1(self) {
        drop(self.flight.take());
        drop(self.admission.take());
    }
}

impl RootInitialReceivingOriginalV1 {
    /// Claims the existing initial-peer once frontier on this real policy flight.
    ///
    /// This negative-only latch grants no peer, finance or semantic purpose.
    /// Existing native flight disposal drops it with the same flight owner.
    ///
    /// # Errors
    /// Refuses unavailable, ended or repeated entry before Stage or native arm.
    pub fn claim_initial_controller_peer_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        self.require_active_policy_flight_native_v1()?;
        let flight = self.policy_flight.as_mut().ok_or(RootObservationErrorV1::Service)?;
        if flight.initial_controller_entered {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        flight.initial_controller_entered = true;
        Ok(())
    }

    /// Measures the concrete once-claim helper's fixed forwarding controls.
    #[must_use]
    pub fn initial_controller_claim_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<&mut Self>().checked_mul(3)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Option<&mut RootPolicyFlightNativeV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&mut RootPolicyFlightNativeV1, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)
    }
}
