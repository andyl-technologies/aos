//! Retains the actual NoApply purpose admission and every reached Stage/post.
//!
//! Only the completed native Policy listener's private factory may arm this
//! original. The mechanical Initial and startup are reborrowed at the original
//! short L/U intervals; no receiver lock is kept across Host or peer IO.

use std::error::Error;

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootPurposePeerPostV1, RootPurposePeerPostsOriginalV1, RootSelectedStartupBorrowV1,
};
use aos_sandbox_model::{
    ResourceVector,
    component_receiving::{operation_traffic_demand_v1, without_operation_traffic_v1},
};

use super::stages::{
    RootNoApplyReceivingErrorV2 as ReceivingError, RootNoApplyStageDataV2,
    RootNoApplyStagesOriginalV2,
};

pub(super) struct RootNoApplyPurposeAdmissionOriginalV2 {
    pub(super) entered: bool,
    pub(super) permit: Option<Result<ResourceVector, ReceivingError>>,
    pub(super) traffic: Option<Result<(), ReceivingError>>,
    pub(super) posts: RootPurposePeerPostsOriginalV1<RootObservationErrorV1>,
    pub(super) financial: Option<RootJournalFinancialOriginalV1>,
    pub(super) stages: RootNoApplyStagesOriginalV2,
}

impl RootNoApplyPurposeAdmissionOriginalV2 {
    // These are actual nested constructors, distinct from the inline field
    // bytes in the containing peer. The genuine first payer charges them
    // before invoking prepare and its Admission::new/Stages::default chain.
    pub(super) fn construction_control_bytes_v2() -> Option<usize> {
        use std::mem::size_of;

        size_of::<Self>().checked_mul(2)?
            .checked_add(RootNoApplyStagesOriginalV2::construction_control_bytes_v2()?)?
            .checked_add(RootPurposePeerPostsOriginalV1::<RootObservationErrorV1>::
                construction_control_bytes_v1()?)
    }

    // The completed-listener borrow is new to NoApply. Its actual loan and
    // returned Result are charged here, not inferred from the old prefix or
    // an unrelated earlier invocation of the same native listener methods.
    pub(super) fn listener_loan_control_bytes_v2() -> Option<usize> {
        use crate::native::{
            RootCompletedPolicyListenerBorrowV1 as Loan,
            RootCompletedPolicyListenerOriginalV1 as Listener,
        };
        use std::mem::size_of;

        size_of::<Listener>()
            .checked_mul(2)?
            .checked_add(size_of::<Loan<'static, 'static>>().checked_mul(2)?)?
            .checked_add(
                size_of::<Result<Loan<'static, 'static>, RootObservationErrorV1>>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<&Loan<'static, 'static>>().checked_mul(4)?)?
            .checked_add(size_of::<&Listener>().checked_mul(2)?)?
            .checked_add(size_of::<&mut RootInitialReceivingOriginalV1>().checked_mul(2)?)?
            .checked_add(
                size_of::<Result<ResourceVector, RootObservationErrorV1>>().checked_mul(2)?,
            )?
            .checked_add(size_of::<ResourceVector>().checked_mul(2)?)?
            .checked_add(size_of::<&RootJournalFinancialOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(2)?)
    }

    // Five mutable and six shared real Admission entry points are distinct
    // from Peer receivers. Closure tuples are the actual finite captures of
    // arm, traffic and stage computations, not callbacks or authority inputs.
    pub(super) fn operation_control_bytes_v2() -> Option<usize> {
        use crate::native::RootCompletedPolicyListenerOriginalV1 as Listener;
        use std::mem::size_of;

        size_of::<&mut Self>()
            .checked_mul(10)?
            .checked_add(size_of::<&Self>().checked_mul(12)?)?
            .checked_add(size_of::<&RootSelectedStartupBorrowV1<'static>>().checked_mul(4)?)?
            .checked_add(size_of::<&Listener>().checked_mul(2)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(8)?)?
            .checked_add(size_of::<RootNoApplyStageDataV2>().checked_mul(2)?)?
            .checked_add(size_of::<usize>().checked_mul(2)?)?
            .checked_add(size_of::<Result<ResourceVector, ReceivingError>>().checked_mul(4)?)?
            .checked_add(size_of::<Result<(), ReceivingError>>().checked_mul(4)?)?
            .checked_add(
                size_of::<(
                    &mut Self,
                    &mut RootInitialReceivingOriginalV1,
                    &RootSelectedStartupBorrowV1<'static>,
                    &Listener,
                    &ResourceVector,
                    &ResourceVector,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(
                    &mut RootInitialReceivingOriginalV1,
                    &ResourceVector,
                    &ResourceVector,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(
                    &Self,
                    &mut RootInitialReceivingOriginalV1,
                    &RootNoApplyStageDataV2,
                    &ResourceVector,
                    &ResourceVector,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(size_of::<&RootInitialReceivingOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<ReceivingError>().checked_mul(2)?)?
            .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(2)?)
    }

    // An inert destination grants nothing. The real listener factory must
    // enter once, derive/check/pay its actual cumulative prefix, retain the
    // same financial original, and arm every post before exposing the purpose.
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            permit: None,
            traffic: None,
            posts: Default::default(),
            financial: None,
            stages: Default::default(),
        }
    }

    // Only the concrete peer producer supplies native_minimum; it derives
    // that minimum from its own actual native fields and shared suppliers.
    // Upper geometry describes still-upper transport residency, never a
    // prefix, admission result, financial handle or lower allocation grant.
    pub(super) fn arm_once_v2(
        &mut self,
        listener: &crate::native::RootCompletedPolicyListenerOriginalV1,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        native_minimum: ResourceVector,
        upper_geometry: ResourceVector,
    ) -> Result<(), ReceivingError> {
        if self.entered {
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(ReceivingError::Conflict);
        }
        self.entered = true;
        let returned = (|| {
            // This real loan alone supplies the original completed prefix.
            let loan = listener.borrow_initial_v1(initial)?;
            let base = loan.completed_prefix_data_v1()?;
            if !startup.same_financial_original_data_v1(loan.financial_original_v1()) {
                return Err(ReceivingError::Conflict);
            }
            self.financial = Some(loan.financial_original_v1().clone());
            drop(loan);
            initial
                .require_active_policy_flight_v1()
                .map_err(|_| ReceivingError::Conflict)?;
            let complete = base
                .checked_add(without_operation_traffic_v1(native_minimum))?
                .checked_add(without_operation_traffic_v1(upper_geometry))?;
            initial
                .require_receiving_demand_v1(complete)
                .map_err(|_| financial_error(initial))?;
            Ok(complete)
        })();
        initial
            .upper_refusal_original_v1()
            .park_empty_result_v1(&mut self.permit, returned);
        if !matches!(self.permit, Some(Ok(_))) {
            return Err(ReceivingError::Conflict);
        }
        let returned = (|| {
            let traffic = operation_traffic_demand_v1(native_minimum)
                .checked_add(operation_traffic_demand_v1(upper_geometry))?;
            initial
                .debit_observer_traffic_v1(traffic)
                .map_err(|_| financial_error(initial))
        })();
        initial
            .upper_refusal_original_v1()
            .park_empty_result_v1(&mut self.traffic, returned);
        if !matches!(self.traffic, Some(Ok(()))) {
            return Err(ReceivingError::Conflict);
        }
        startup
            .arm_purpose_posts_once_v1(initial, &mut self.posts)
            .map_err(ReceivingError::from)
    }

    pub(super) fn require_armed_v2(&self) -> Result<(), ReceivingError> {
        if matches!(self.permit, Some(Ok(_)))
            && matches!(self.traffic, Some(Ok(())))
            && self.posts.require_armed_v1().is_ok()
            && self.financial.is_some()
        {
            Ok(())
        } else {
            Err(ReceivingError::Conflict)
        }
    }

    fn require_same_initial_v2(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<(), ReceivingError> {
        let actual = initial
            .financial_diagnostic_original_v1()
            .ok_or(ReceivingError::EnrollmentUnavailable)?;
        let original = self
            .financial
            .as_ref()
            .ok_or(ReceivingError::EnrollmentUnavailable)?;
        if !original.same_original_data_v1(&actual) {
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(ReceivingError::Conflict);
        }
        Ok(())
    }

    /// Rechecks the actual recipient-bound node at the old late frontier.
    ///
    /// The same outer L/U guard still owns this short observation. Its prior
    /// returned errors must already have denied the real native invocation.
    pub(super) fn enrolled_node_data_v2(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<[u8; 16], ReceivingError> {
        self.require_armed_v2()?;
        self.require_same_initial_v2(initial)?;
        if initial.failure().is_some()
            || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
        {
            return Err(ReceivingError::Conflict);
        }
        initial
            .enrollment_v1()
            .map(|original| original.identity.native_fields().node)
            .ok_or(ReceivingError::EnrollmentUnavailable)
    }

    /// Charges one actual reached stage without clearing any failed prefix.
    ///
    /// The genuine outer receiver holds its original L/U interval for this
    /// short mutation. No native IO or owning destructor occurs under N/M.
    pub(super) fn admit_stage_once_v2(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        stage: RootNoApplyStageDataV2,
        demand: ResourceVector,
        resident_baseline: ResourceVector,
    ) -> Result<(), ReceivingError> {
        let index = stage.index_v2();
        if self.stages.failure().is_some() || self.stages.requirements[index].is_some() {
            self.stages.closed.get_or_insert(ReceivingError::Conflict);
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(ReceivingError::Conflict);
        }
        let returned = (|| {
            self.require_same_initial_v2(initial)?;
            initial
                .require_active_policy_flight_v1()
                .map_err(|_| ReceivingError::Conflict)?;
            self.require_armed_v2()?;
            if !stage.prerequisites_positive_v2(&self.stages) {
                return Err(ReceivingError::Conflict);
            }
            let base = self
                .stages
                .complete
                .or_else(|| {
                    self.permit
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .copied()
                })
                .ok_or(ReceivingError::EnrollmentUnavailable)?;
            let complete = base
                .checked_add(without_operation_traffic_v1(demand))?
                .checked_add(without_operation_traffic_v1(resident_baseline))?;
            initial
                .require_receiving_demand_v1(complete)
                .map_err(|_| financial_error(initial))?;
            Ok(complete)
        })();
        initial
            .upper_refusal_original_v1()
            .park_empty_result_v1(&mut self.stages.requirements[index], returned);
        if let Some(Ok(complete)) = self.stages.requirements[index].as_ref() {
            self.stages.complete = Some(*complete);
        } else {
            self.stages.first = Some(index);
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(ReceivingError::Conflict);
        }
        let returned = initial
            .debit_observer_traffic_v1(operation_traffic_demand_v1(demand))
            .map_err(|_| financial_error(initial));
        initial
            .upper_refusal_original_v1()
            .park_empty_result_v1(&mut self.stages.traffic[index], returned);
        if !matches!(self.stages.traffic[index], Some(Ok(()))) {
            self.stages.first = Some(index);
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(ReceivingError::Conflict);
        }
        Ok(())
    }

    /// Observes the same already-paid native debt after either primary outcome.
    pub(super) fn observe_post_once_v2(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        post: RootPurposePeerPostV1,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_same_initial_v2(initial)
            .map_err(|_| RootObservationErrorV1::Service)?;
        startup.observe_purpose_post_once_v1(initial, &mut self.posts, post)
    }

    pub(super) fn is_positive_v2(&self, post: RootPurposePeerPostV1) -> bool {
        self.posts.is_positive_v1(post)
    }

    pub(super) fn settle_admission_positive_once_v2(&mut self) -> Result<(), ReceivingError> {
        self.posts
            .settle_admission_positive_once_v1()
            .map_err(|_| ReceivingError::Conflict)
    }

    pub(super) fn settle_final_positive_once_v2(&mut self) -> Result<(), ReceivingError> {
        self.posts
            .settle_final_positive_once_v1()
            .map_err(|_| ReceivingError::Conflict)
    }

    pub(super) fn admission_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.permit
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.traffic
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.posts.arming_failure_v1().map(|cause| cause as _))
    }

    pub(super) fn post_failure_v2(
        &self,
        post: RootPurposePeerPostV1,
    ) -> Option<&(dyn Error + 'static)> {
        self.posts.post_failure_v1(post)
    }
}

fn financial_error(initial: &RootInitialReceivingOriginalV1) -> ReceivingError {
    initial
        .financial_diagnostic_original_v1()
        .map(ReceivingError::Financial)
        .unwrap_or(ReceivingError::EnrollmentUnavailable)
}
