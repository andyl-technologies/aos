//! Retains a prearmed same-Root service observation through an owed history post.
//!
//! This owner grants no phase, effect or payment. Only the actual Root original
//! arms it for its own sealed startup before primary work; observations retain
//! the same invocation fence after refusal and can never restore serving.

use std::error::Error;
use std::sync::Arc;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use super::RootInitialReceivingOriginalV1;
use crate::receiving::{RootObservationErrorV1 as E, RootServiceCurrentnessOriginalV1,
    RootStartupNativeOriginalV1};
use super::super::root_permanent::RootPermanentNativeOriginalV1;

/// Owns one independently owed observation, associated with the actual Root.
pub struct RootPrearmedHistoryServicePostV1 {
    original: Arc<RootPermanentNativeOriginalV1>,
    sample: Option<RootServiceCurrentnessOriginalV1>,
    returned: Option<Result<(), E>>,
    closed: bool,
}

impl RootPrearmedHistoryServicePostV1 {
    pub(in crate::receiving) fn matches_startup_original_v1(&self, startup: &RootStartupNativeOriginalV1) -> bool {
        startup.initial_owner.as_ref().is_some_and(|owner| self.original.has_identity(owner))
    }


    /// Describes the actual native sampler and constructor without funding it.
    #[must_use]
    pub fn demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(std::mem::size_of::<(&mut Self, &RootStartupNativeOriginalV1)>().checked_mul(9)?)?
            .checked_add(std::mem::size_of::<Result<(), E>>().checked_mul(15)?)?
            .checked_add(std::mem::size_of::<Arc<RootPermanentNativeOriginalV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<super::financial::RootHistoryUpperExclusionGuardV1<'_>>().checked_mul(12)?)?
            .checked_add(std::mem::size_of::<&RootPermanentNativeOriginalV1>().checked_mul(9)?)?
            .checked_add(std::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'_, ()>>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<std::sync::MutexGuard<'_, ()>>().checked_mul(6)?)?;
        RootServiceCurrentnessOriginalV1::demand()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)).ok()
    }

    /// Borrows the original sampler cause before its returned classification.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.sample.as_ref().and_then(|sample| sample.failure()).or_else(||
            self.returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    /// Reports complete native comparison DATA without granting a healthy role.
    #[must_use]
    pub fn is_positive_v1(&self) -> bool {
        !self.closed && matches!(self.returned, Some(Ok(()))) && self.failure().is_none()
    }

    pub(in crate::receiving) fn refuse_original_history_post_v1(&self) {
        self.original.invocation().latch_refusal();
    }

    pub(in crate::receiving) fn enter_original_history_worker_once_v1(&self) -> Result<(), E> {
        let _exclusion = self.original.enter_history_post_exclusion_v1();
        self.original.enter_history_worker_under_exclusion_v1()
    }

    pub(in crate::receiving) fn finish_original_history_worker_once_v1(&self) -> Result<(), E> {
        let _exclusion = self.original.enter_history_post_exclusion_v1();
        self.original.finish_history_worker_under_exclusion_v1()
    }

    pub(in crate::receiving) fn observe_owned_with_exclusion_once_v1(&mut self, startup: &RootStartupNativeOriginalV1) -> Result<(), E> {
        // The real Arc keeps the same L owner borrowed while this destination
        // is mutably sampled; cloning it creates neither an account nor a lease.
        let original = Arc::clone(&self.original);
        let _exclusion = original.enter_history_post_exclusion_v1();
        self.observe_once_on_original_v1(startup)
    }

    /// Observes the original prearmed post under its same already-held L.
    ///
    /// No healthy financial gate, new service traffic fee or second exclusion
    /// acquisition suppresses this independently owed observation after refusal.
    ///
    /// # Errors
    /// Retains a foreign guard, changed startup, repeated post, ended original
    /// or actual native sample refusal on the same owning post.
    pub(in crate::receiving) fn observe_under_upper_exclusion_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        exclusion: &super::RootUpperMutationGuardV1<'_>,
    ) -> Result<(), E> {
        if !exclusion.matches_permanent_original_v1(&self.original) {
            exclusion.refuse_v1();
            return Err(E::Service);
        }
        self.observe_once_on_original_v1(startup)
    }

    fn observe_once_on_original_v1(&mut self, startup: &RootStartupNativeOriginalV1) -> Result<(), E> {
        if self.returned.is_some() || self.closed { self.closed = true; return Err(E::Service); }
        self.returned = Some(self.observe_original_inner_v1(startup));
        if self.is_positive_v1() {
            Ok(())
        } else {
            self.original.invocation().latch_refusal();
            Err(E::Service)
        }
    }

    fn observe_original_inner_v1(&mut self, startup: &RootStartupNativeOriginalV1) -> Result<(), E> {
        if !self.matches_startup_original_v1(startup)
            || self.original.enrollment().process_id_v1() != std::process::id()
        { return Err(E::Service); }
        // This SAME Permanent physically received enrollment and kernel only
        // after positive recipient binding/startup settlement. Its prearmed
        // constructor rejoined that actual Initial; the binding is never reset.
        let original = self.original.enrollment().enrollment_v1().copied().ok_or(E::Service)?;
        let kernel = self.original.service.kernel();
        let mut guard = self.original.enter_observation()?;
        let sample = self.sample.as_mut().ok_or(E::Service)?;
        sample.observe_once(startup, kernel, original.recipient_invocation,
            original.identity.native_fields().invocation);
        if sample.is_positive() { Ok(()) } else { guard.refuse(); Err(E::Service) }
    }

    /// Disposes the positive sampler only after all enclosing independent posts.
    ///
    /// This retains its real original association and returned completion. A
    /// failed or incomplete sample remains owned and cannot be replaced.
    pub fn retire_positive_once_v1(&mut self) {
        if self.is_positive_v1() { drop(self.sample.take()); }
    }
}

impl RootInitialReceivingOriginalV1 {
    /// Arms an owed sampler for this actual startup before primary work.
    ///
    /// The genuine upper fixed stage pays its concrete native demand first.
    /// This method observes no native state and creates no role grant.
    ///
    /// # Errors
    /// Refuses an incomplete/foreign startup, prior refusal or absent original.
    pub fn arm_history_service_post_v1(&self, startup: &RootStartupNativeOriginalV1)
        -> Result<RootPrearmedHistoryServicePostV1, E>
    {
        if self.failure().is_some() || self.process_id_v1() != std::process::id()
            || !startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
            || !matches!(self.recipient_binding, Some(Ok(())))
        { return Err(E::Service); }
        let original = self.permanent.as_ref().map(Arc::clone).ok_or(E::Service)?;
        Ok(RootPrearmedHistoryServicePostV1 { original,
            sample: Some(RootServiceCurrentnessOriginalV1::new()), returned: None, closed: false })
    }

    /// Runs this prearmed observation on its same actual startup after refusal.
    ///
    /// # Errors
    /// Refuses foreign/ended originals or repeated observation and retains the
    /// actual sample/native cause. Earlier refusal is neither cleared nor waived.
    pub fn observe_history_service_post_once_v1(&mut self,
        startup: &RootStartupNativeOriginalV1, post: &mut RootPrearmedHistoryServicePostV1,
    ) -> Result<(), E> {
        if post.returned.is_some() || post.closed { post.closed = true; return Err(E::Service); }
        if !self.permanent.as_ref().is_some_and(|original| Arc::ptr_eq(original, &post.original))
            || !startup.initial_owner.as_ref().is_some_and(|owner| self.same_owner_link(owner))
            || self.process_id_v1() != std::process::id()
            || !matches!(self.recipient_binding, Some(Ok(())))
        {
            post.returned = Some(Err(E::Service));
            self.latch_root_refusal_v1();
            return Err(E::Service);
        }
        let returned = post.observe_once_on_original_v1(startup);
        if returned.is_err() { self.latch_root_refusal_v1(); }
        returned
    }
}
