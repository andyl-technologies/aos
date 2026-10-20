//! Arms actual pre-Bank Source construction and its independently owed C post.
//!
//! Only paired Startup creates this loan after the real construction lanes are
//! paid. Arming does not enter the Source body: Controller construction may
//! fail first, and the fixed Source post remains owed independently. The actual
//! trusted coordinator starts Source IO only after its real predecessor body.

use std::sync::Arc;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use super::{ControllerReceivingOriginalV1, ControllerReceivingErrorV1, ControllerOriginalObservationV1};
use super::profile::{ControllerSelfProfileOriginalV1, ControllerProfileErrorV1};
use super::construction::ControllerSourceConstructionReceivingV1;

/// Retains only the actual Source native owner's original financial association.
///
/// This inert, non-Clone association creates no writer, parser, receiving scope,
/// IO ability, semantic completion or Bank. The Source crate's private native
/// constructor still requires the genuine live construction loan itself.
pub struct ControllerSourceOriginalRefV1 {
    original: Arc<ControllerReceivingOriginalV1>,
}

impl ControllerSourceOriginalRefV1 {
    // Identity comparison only. The Source coordinator retains this association
    // from its genuine pre-Bank opening; no Arc or mutable original escapes.
    pub(crate) fn has_same_original_v1(&self, original: &Arc<ControllerReceivingOriginalV1>) -> bool {
        Arc::ptr_eq(&self.original, original)
    }

    /// Restricts representation DATA on this same fixed Source native owner.
    ///
    /// # Errors
    /// Retains no permit and refuses actual original/capacity/arithmetic error.
    /// The actual Source native owner stores this returned Result before growth.
    #[doc(hidden)]
    pub fn debit_complete_representation_v1(&self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.original.require_source_native_representation_v1(complete)
    }
}

/// Holds the actual pre-Bank Source interval and its fixed owed post.
///
/// There is no public constructor and no caller-supplied profile/original
/// tuple, amount, FD, success flag or callback can create this obligation.
#[must_use]
pub struct ControllerSourcePreBankConstructionLoanV1<'profile> {
    original: Arc<ControllerReceivingOriginalV1>,
    profile: &'profile ControllerSelfProfileOriginalV1,
    claim: Result<(), ControllerReceivingErrorV1>,
    receiving: Option<ControllerSourceConstructionReceivingV1<'profile>>,
    body_entry: Option<Result<(), ControllerReceivingErrorV1>>,
    body_post: Option<Result<(), ControllerProfileErrorV1>>,
    observation: ControllerOriginalObservationV1,
    post: Option<Result<(), ControllerProfileErrorV1>>,
    reference_taken: bool,
    finished: bool,
}

impl<'profile> ControllerSourcePreBankConstructionLoanV1<'profile> {
    pub(in crate::controller_receiving) fn from_paired_startup(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Self {
        let claim = original.claim_source_prebank_construction_v1(profile);
        Self {
            original, profile, claim, receiving: None, body_entry: None,
            body_post: None, observation: ControllerOriginalObservationV1::new(),
            post: None, reference_taken: false, finished: false,
        }
    }

    /// Describes actual loan/receiver/observation construction representation.
    ///
    /// # Errors
    /// Refuses checked representation arithmetic overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let invalid = || ControllerReceivingErrorV1::Conflict;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerSourceConstructionReceivingV1<'_>>().checked_mul(2)?))
            .ok_or_else(invalid)?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .checked_add(ControllerOriginalObservationV1::receiving_demand_v1().ok_or_else(invalid)?)
            .map_err(ControllerReceivingErrorV1::from)
    }

    /// Starts the actual fixed Source body interval before any protected IO.
    ///
    /// # Errors
    /// Retains failed claim/profile/original entry and refuses repeated entry.
    pub fn begin_native_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.claim.is_err() || self.body_entry.is_some() || self.finished {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.receiving = Some(ControllerSourceConstructionReceivingV1::begin(self.profile, &self.original));
        self.body_entry = Some(self.receiving.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?.require_active());
        self.require_active()
    }

    /// Requires only this same actually entered and still-live native interval.
    ///
    /// # Errors
    /// Refuses absent/failed/ended body or an already attempted independent post.
    pub fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        if self.claim.is_err() || !matches!(self.body_entry, Some(Ok(())))
            || self.body_post.is_some() || self.post.is_some() || self.finished
        { return Err(ControllerReceivingErrorV1::Conflict); }
        self.receiving.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?.require_active()
    }

    /// Returns the same admitted profile's fixed writer UID as comparison DATA.
    ///
    /// # Errors
    /// Refuses inactive interval before supplying selected recipe DATA.
    pub fn fixed_writer_uid_data_v1(&self) -> Result<u32, ControllerReceivingErrorV1> {
        self.require_active()?;
        Ok(self.profile.schema().identities[0])
    }

    /// Restricts the reached Source native representation before growth.
    ///
    /// No amount returns a grant, parser, writer, account or finish token.
    ///
    /// # Errors
    /// Retains arithmetic/original/capacity refusal in this same receiving owner.
    pub fn require_native_complete(&mut self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_active()?;
        self.receiving.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .require_native_complete(complete)
    }

    /// Moves the actual native owner's inert original association once.
    ///
    /// This is not semantic or native completion. Only a private Source native
    /// constructor holding this active loan may use it beside its actual writer.
    ///
    /// # Errors
    /// Refuses inactive entry or repeated association transfer.
    pub fn take_bound_source_original_once_v1(&mut self)
        -> Result<ControllerSourceOriginalRefV1, ControllerReceivingErrorV1>
    {
        self.require_active()?;
        if self.reference_taken { return Err(ControllerReceivingErrorV1::Conflict); }
        self.reference_taken = true;
        Ok(ControllerSourceOriginalRefV1 { original: Arc::clone(&self.original) })
    }

    /// Attempts the body bookend and independently armed fixed Source post.
    ///
    /// This runs even if the body was never entered because Controller failed.
    /// No upper body result is accepted or reinterpreted as Source success.
    ///
    /// # Errors
    /// Retains every actual profile/pair/native refusal and rejects reentry.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.post.is_some() || self.finished { return Err(ControllerReceivingErrorV1::Conflict); }
        if let Some(receiving) = self.receiving.as_mut() {
            self.body_post = Some(receiving.finish_native_once());
        }
        // This separate prepaid post remains owed after body/entry refusal.
        self.post = Some(self.profile.observe_source_construction_post_retaining_v1(
            &self.original, &mut self.observation,
        ));
        if self.failure().is_some() || !matches!(self.post, Some(Ok(())))
            || self.receiving.is_some() && !matches!(self.body_post, Some(Ok(())))
        { return Err(ControllerReceivingErrorV1::Conflict); }
        self.finished = true;
        Ok(())
    }

    /// Borrows the first actual claim/body/debit/profile/native refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.claim.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.body_entry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.receiving.as_ref().and_then(|receiving| receiving.failure()))
            .or_else(|| self.body_post.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.observation.failure())
            .or_else(|| self.post.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl Drop for ControllerSourcePreBankConstructionLoanV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Keep all same-original/native failures resident until termination.
            std::process::abort();
        }
    }
}
