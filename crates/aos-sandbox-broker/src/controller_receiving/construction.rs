//! Keeps the original C native interval live across one role constructor.
//!
//! The role's body and semantic completion remain above this mechanism. A
//! continuous loan starts the same profile/control interval, retains admission
//! and debit failures, and performs its independent native post before any
//! successful mechanical settlement. It accepts no body callback or result.

use std::sync::Arc;

use aos_sandbox_core::ResourceVector;

use super::budget::BaselineOwner;
use super::profile::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1};
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};

/// Selects only the two actual private construction observation recipes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum ControllerProfileConstructionPurposeV1 {
    Source,
    Cache,
    PublisherReadonly,
}

struct ConstructionReceiving<'profile> {
    original: Arc<ControllerReceivingOriginalV1>,
    profile: &'profile ControllerSelfProfileOriginalV1,
    purpose: ControllerProfileConstructionPurposeV1,
    entry: Result<(), ControllerProfileErrorV1>,
    debit_failure: Option<ControllerReceivingErrorV1>,
    completion: Option<Result<(), ControllerProfileErrorV1>>,
    settled: bool,
    same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<'profile> ConstructionReceiving<'profile> {
    fn begin(
        profile: &'profile ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: ControllerProfileConstructionPurposeV1,
    ) -> Self {
        let mut receiving = Self {
            original: Arc::clone(original),
            profile,
            purpose,
            entry: Err(ControllerProfileErrorV1::Service),
            debit_failure: None,
            completion: None,
            settled: false,
            same_thread: std::marker::PhantomData,
        };
        receiving.entry = profile.begin_original_construction_receiving_v1(original, purpose);
        receiving
    }

    fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        if self.entry.is_err() || self.debit_failure.is_some() || self.completion.is_some()
            || self.settled || !self.profile.has_same_baseline_original(&self.original)
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    fn require_complete(
        &mut self,
        owner: BaselineOwner,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_active()?;
        let result = self.original.raise_cache_complete(owner, complete);
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.debit_failure = Some(cause);
                Err(ControllerReceivingErrorV1::Conflict)
            }
        }
    }

    fn finish_native_once(&mut self) -> Result<(), ControllerProfileErrorV1> {
        if self.completion.is_some() || self.settled {
            return Err(ControllerProfileErrorV1::Service);
        }
        // This native post is owed independently after a role/body/debit
        // refusal. It receives no upper semantic completion to reinterpret.
        self.completion = Some(self.profile.finish_original_construction_receiving_v1(
            &self.original, self.purpose,
        ));
        if self.entry.is_err() || self.debit_failure.is_some()
            || !matches!(self.completion, Some(Ok(())))
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.settled = true;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.entry.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.debit_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

impl Drop for ConstructionReceiving<'_> {
    fn drop(&mut self) {
        if !self.settled {
            // A failed or abandoned loan cannot free its native originals or
            // let an upper caller mistake ordinary field Drop for settlement.
            std::process::abort();
        }
    }
}

/// Borrows the same C interval throughout the fixed Source constructor.
///
/// Successful settlement says only that this interval's native observations
/// completed. The upper Source constructor still owns its complete body Result,
/// writer, recovery outcome and startup phase transition.
#[must_use]
pub struct ControllerSourceConstructionReceivingV1<'profile> {
    receiving: ConstructionReceiving<'profile>,
}

impl<'profile> ControllerSourceConstructionReceivingV1<'profile> {
    /// Enters the original Source construction interval before its body grows.
    #[must_use]
    pub(in crate::controller_receiving) fn begin(
        profile: &'profile ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Self {
        Self {
            receiving: ConstructionReceiving::begin(
                profile, original, ControllerProfileConstructionPurposeV1::Source,
            ),
        }
    }

    /// Checks this same live interval without another observation or grant.
    ///
    /// # Errors
    /// Refuses failed entry, prior debit failure, settlement or a foreign profile.
    pub fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_active()
    }

    /// Restricts the same Source native owner's complete representation bound.
    ///
    /// This monotone DATA debit grants no IO, append, replay or Source authority.
    /// The actual Source owner separately enforces its closed native recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::SourceNative, complete)
    }

    /// Performs this interval's independent native post and mechanical disposal.
    ///
    /// # Errors
    /// Refuses repeated settlement or any retained entry, debit or native error.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerProfileErrorV1> {
        self.receiving.finish_native_once()
    }

    /// Borrows the first retained loan refusal without cloning its cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receiving.failure()
    }
}

/// Borrows the same C interval throughout one selected Cache constructor body.
///
/// Fixed native and representation lanes are charged to the existing original
/// highwaters. No account, provision, receiving grant or semantic completion
/// escapes this owner. The upper Cache initializer retains all body outcomes.
#[must_use]
pub struct ControllerCacheConstructionReceivingV1<'profile> {
    receiving: ConstructionReceiving<'profile>,
}

impl<'profile> ControllerCacheConstructionReceivingV1<'profile> {
    // Only the genuine fixed-writer/Bank/live-Launch conjunction calls this
    // after its own actual identity/currentness/financial checks. It remains
    // inaccessible outside the lower Controller original implementation.
    pub(in crate::controller_receiving) fn begin_from_paired_cache_import(
        profile: &'profile ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Self {
        Self::begin_from_conjunction(profile, original)
    }

    pub(in crate::controller_receiving) fn begin_from_conjunction(
        profile: &'profile ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Self {
        Self {
            receiving: ConstructionReceiving::begin(
                profile, original, ControllerProfileConstructionPurposeV1::Cache,
            ),
        }
    }

    /// Checks this live interval without manufacturing another receiving grant.
    ///
    /// # Errors
    /// Refuses failed entry, prior debit failure, settlement or a foreign profile.
    pub fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_active()
    }

    /// Restricts the same Controller Cache bootstrap native owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_bootstrap_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheBootstrapNative, complete)
    }

    /// Restricts the same Cache HOLD native owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_hold_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheHoldNative, complete)
    }

    /// Restricts the same Cache clock native owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_clock_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheClockNative, complete)
    }

    /// Restricts the same Cache Authority native owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_authority_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheAuthorityNative, complete)
    }

    /// Restricts the same Cache STATE native owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_state_native_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheStateNative, complete)
    }

    /// Restricts the same Cache import model owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_import_models_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::ImportModels, complete)
    }

    /// Restricts the same Cache Source model owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_source_models_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheSourceModels, complete)
    }

    /// Restricts the same Cache Authority model owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_authority_models_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CacheAuthorityModels, complete)
    }

    /// Restricts the same Cache physical owner's complete representation bound.
    ///
    /// This monotone DATA debit supplies no native or semantic authority.
    /// The role's private original still enforces its actual operation recipe.
    ///
    /// # Errors
    /// Retains the first arithmetic, capacity or original-interval refusal.
    pub fn require_physical_complete(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_complete(BaselineOwner::CachePhysical, complete)
    }

    /// Performs this interval's independent native post and mechanical disposal.
    ///
    /// # Errors
    /// Refuses repeated settlement or any retained entry, debit or native error.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerProfileErrorV1> {
        self.receiving.finish_native_once()
    }

    /// Borrows the first retained loan refusal without cloning its cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receiving.failure()
    }
}

/// Keeps the same paid C/profile scope around one Controller Publisher read.
///
/// Construction stays inside the actual fixed-writer/Bank/launch conjunction.
/// It has no native mutation, account, caller resource or semantic success port.
#[must_use]
pub(in crate::controller_receiving) struct ControllerPublisherReadReceivingV1<'profile> {
    receiving: ConstructionReceiving<'profile>,
}

impl<'profile> ControllerPublisherReadReceivingV1<'profile> {
    pub(in crate::controller_receiving) fn begin_from_conjunction(
        profile: &'profile ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Self {
        Self {
            receiving: ConstructionReceiving::begin(
                profile, original, ControllerProfileConstructionPurposeV1::PublisherReadonly,
            ),
        }
    }

    pub(in crate::controller_receiving) fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        self.receiving.require_active()
    }

    pub(in crate::controller_receiving) fn finish_native_once(&mut self) -> Result<(), ControllerProfileErrorV1> {
        self.receiving.finish_native_once()
    }

    pub(in crate::controller_receiving) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receiving.failure()
    }
}
