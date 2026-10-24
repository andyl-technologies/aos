//! Retains the same four prearmed Root posts for a genuine purpose owner.
//!
//! This mechanical aggregate grants no purpose, budget, listener completion,
//! peer, or effect. The real caller admits its complete fixed programme before
//! arming these existing samplers against the actual Initial and startup.

use std::error::Error;
use std::mem::size_of;

use super::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1, RootPrearmedHistoryServicePostV1,
    RootStartupNativeOriginalV1,
};

/// Selects one original independently owed observation without authorizing it.
#[derive(Clone, Copy)]
pub enum RootPurposePeerPostV1 {
    /// The original admission-before native observation.
    AdmissionBefore,
    /// The independently owed admission-after native observation.
    AdmissionAfter,
    /// The original final-before native observation.
    FinalBefore,
    /// The independently owed final-after native observation.
    FinalAfter,
}

impl RootPurposePeerPostV1 {
    fn index(self) -> usize {
        match self {
            Self::AdmissionBefore => 0,
            Self::AdmissionAfter => 1,
            Self::FinalBefore => 2,
            Self::FinalAfter => 3,
        }
    }
}

/// Projects only the caller's established observation and closed diagnostics.
///
/// This adapter supplies no observation, original, phase, or financial entry.
pub trait RootPurposePostErrorV1: Error + 'static {
    /// Returns the caller's existing closed-service refusal.
    fn closed() -> Self;

    /// Moves the actual native observation cause into its existing category.
    fn from_observation(error: RootObservationErrorV1) -> Self;
}

impl RootPurposePostErrorV1 for RootObservationErrorV1 {
    fn closed() -> Self {
        Self::Service
    }

    fn from_observation(error: RootObservationErrorV1) -> Self {
        error
    }
}

/// Owns four actual native debts and both distinct positive retirements.
pub struct RootPurposePeerPostsOriginalV1<E> {
    posts: [Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>; 4],
    returned: [Option<Result<(), E>>; 4],
    settled: [bool; 2],
}

impl<E> Default for RootPurposePeerPostsOriginalV1<E> {
    fn default() -> Self {
        Self {
            posts: std::array::from_fn(|_| None),
            returned: std::array::from_fn(|_| None),
            settled: [false; 2],
        }
    }
}

impl<E: RootPurposePostErrorV1> RootPurposePeerPostsOriginalV1<E> {
    /// Measures the two added inert aggregate constructor/return controls.
    ///
    /// The actual listener's fixed invoice pays these before a purpose's
    /// Default construction. Native samplers are not constructed here.
    #[must_use]
    pub fn construction_control_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)
    }

    /// Measures new typed observation forwarding controls without native IO.
    ///
    /// The actual purpose pays the existing two-plane observation controls
    /// for all four distinct posts before arming/observing. Native sampler
    /// demands and actual resident parent fields stay separate.
    #[must_use]
    pub fn operation_control_bytes_v1() -> Option<usize> {
        size_of::<Result<(), E>>()
            .checked_mul(2)?
            .checked_add(size_of::<&mut Self>().checked_mul(2)?)?
            .checked_add(size_of::<&mut RootInitialReceivingOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<&RootStartupNativeOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<RootPurposePeerPostV1>().checked_mul(2)?)?
            .checked_mul(4)
    }

    /// Arms all four same-Root native debts before primary work.
    ///
    /// # Errors
    /// Refuses reentry or any existing native arming failure. Every reached
    /// original is retained, and a failed arm does not suppress later arms.
    pub fn arm_once_v1(
        &mut self,
        initial: &RootInitialReceivingOriginalV1,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), E> {
        if self.posts.iter().any(Option::is_some) {
            initial.upper_refusal_original_v1().refuse_v1();
            return Err(E::closed());
        }
        for post in &mut self.posts {
            let returned = initial.arm_history_service_post_v1(startup);
            initial
                .upper_refusal_original_v1()
                .park_empty_result_v1(post, returned);
        }
        self.require_armed_v1()
    }

    /// Requires every original arming Result without observing native state.
    ///
    /// # Errors
    /// Refuses an absent or failed independently owed native destination.
    pub fn require_armed_v1(&self) -> Result<(), E> {
        if self.posts.iter().all(|post| matches!(post, Some(Ok(_)))) {
            Ok(())
        } else {
            Err(E::closed())
        }
    }

    /// Borrows the first actual native arming error in original slot order.
    #[must_use]
    pub fn arming_failure_v1(&self) -> Option<&RootObservationErrorV1> {
        self.posts
            .iter()
            .find_map(|post| post.as_ref()?.as_ref().err())
    }

    /// Executes one already-paid post on its same original after either outcome.
    ///
    /// # Errors
    /// Refuses an absent, repeated, foreign or failed observation. This owed
    /// path deliberately adds no healthy Stage or financial entry check.
    pub fn observe_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootStartupNativeOriginalV1,
        purpose: RootPurposePeerPostV1,
    ) -> Result<(), E> {
        let slot = purpose.index();
        if self.returned[slot].is_some() {
            return Err(E::closed());
        }
        let post = self.posts[slot]
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or_else(E::closed)?;
        let returned = initial
            .observe_history_service_post_once_v1(startup, post)
            .map_err(E::from_observation);
        initial
            .upper_refusal_original_v1()
            .park_empty_result_v1(&mut self.returned[slot], returned);
        if self.is_positive_v1(purpose) {
            Ok(())
        } else {
            Err(E::closed())
        }
    }

    /// Reports only the original slot's returned comparison Result.
    #[must_use]
    pub fn is_positive_v1(&self, purpose: RootPurposePeerPostV1) -> bool {
        matches!(self.returned[purpose.index()], Some(Ok(())))
    }

    /// Borrows the actual native sampler cause before its projected Result.
    #[must_use]
    pub fn post_failure_v1(
        &self,
        purpose: RootPurposePeerPostV1,
    ) -> Option<&(dyn Error + 'static)> {
        let slot = purpose.index();
        self.posts[slot]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(RootPrearmedHistoryServicePostV1::failure)
            .or_else(|| {
                self.returned[slot]
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    /// Retires only the two actually completed positive admission samplers.
    ///
    /// # Errors
    /// Refuses incomplete/failed originals or repeated positive retirement.
    pub fn settle_admission_positive_once_v1(&mut self) -> Result<(), E> {
        self.settle_pair_positive(0)
    }

    /// Retires only the two actually completed positive final samplers.
    ///
    /// # Errors
    /// Refuses incomplete/failed originals or repeated positive retirement.
    pub fn settle_final_positive_once_v1(&mut self) -> Result<(), E> {
        self.settle_pair_positive(1)
    }

    fn settle_pair_positive(&mut self, pair: usize) -> Result<(), E> {
        let first = pair * 2;
        if self.settled[pair]
            || self.posts[first..first + 2]
                .iter()
                .any(|post| !matches!(post, Some(Ok(_))))
            || self.returned[first..first + 2]
                .iter()
                .any(|returned| !matches!(returned, Some(Ok(()))))
        {
            return Err(E::closed());
        }
        for original in &mut self.posts[first..first + 2] {
            let original = original
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or_else(E::closed)?;
            if original.failure().is_some() {
                return Err(E::closed());
            }
        }
        for original in &mut self.posts[first..first + 2] {
            original
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or_else(E::closed)?
                .retire_positive_once_v1();
        }
        self.settled[pair] = true;
        Ok(())
    }
}
