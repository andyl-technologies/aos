//! Holds the actual optional Cache import before Controller Bank enrollment.
//!
//! The paired Startup alone emits this loan after Source credential disposal.
//! Exactly two sequential intervals preserve initial import, physical disposal,
//! durable reopen and verify. This is distinct from the later confirmed-writer
//! Cache constructor. Neither interval can issue a Bank or launch authority.

use std::sync::Arc;

use aos_sandbox_core::ResourceVector;

use super::construction::ControllerCacheConstructionReceivingV1;
use super::profile::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1};
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};

/// Retains both finite pre-Bank Cache import intervals on the SAME original.
///
/// Its private constructor accepts neither a caller writer nor a launch result.
/// The actual Native importer keeps its complete semantic/body outcomes and
/// must dispose the first positive native stage before entering the second.
#[must_use]
pub struct ControllerCachePreBankImportLoanV1<'profile> {
    original: Arc<ControllerReceivingOriginalV1>,
    profile: &'profile ControllerSelfProfileOriginalV1,
    claim: Result<(), ControllerReceivingErrorV1>,
    phases: [Option<ControllerCacheConstructionReceivingV1<'profile>>; 2],
    posts: [Option<Result<(), ControllerProfileErrorV1>>; 2],
    entered: usize,
}

impl<'profile> ControllerCachePreBankImportLoanV1<'profile> {
    pub(super) fn from_paired_startup(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Self {
        let claim = original.claim_cache_prebank_import_once_v1(profile);
        Self { original, profile, claim, phases: [None, None], posts: [None, None], entered: 0 }
    }

    /// Prices only this actual resident and returned loan representation.
    ///
    /// # Errors
    /// Refuses checked byte overflow; profile/native growth has separate bounds.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerReceivingErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
    }

    /// Begins the next actual initial-import or durable-reopen interval.
    ///
    /// # Errors
    /// Refuses a third entry, failed prior post, wrong process or spent claim.
    pub fn begin_next_native_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.claim.is_err() || self.entered >= 2
            || (self.entered != 0 && !matches!(self.posts[self.entered - 1], Some(Ok(()))))
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let index = self.entered;
        self.entered += 1;
        self.phases[index] = Some(ControllerCacheConstructionReceivingV1::begin_from_paired_cache_import(
            self.profile, &self.original,
        ));
        self.require_active()
    }

    fn current(&self) -> Result<&ControllerCacheConstructionReceivingV1<'profile>, ControllerReceivingErrorV1> {
        self.entered.checked_sub(1).and_then(|index| self.phases[index].as_ref())
            .ok_or(ControllerReceivingErrorV1::Conflict)
    }

    fn current_mut(&mut self) -> Result<&mut ControllerCacheConstructionReceivingV1<'profile>, ControllerReceivingErrorV1> {
        self.entered.checked_sub(1).and_then(|index| self.phases[index].as_mut())
            .ok_or(ControllerReceivingErrorV1::Conflict)
    }

    /// Checks the same entered interval without admitting another operation.
    ///
    /// # Errors
    /// Refuses absent, completed or failed entry.
    pub fn require_active(&self) -> Result<(), ControllerReceivingErrorV1> {
        self.current()?.require_active()
    }

    /// Debits the actual Bootstrap fixed/captured-prefix representation only.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or same-interval refusal before growth.
    pub fn require_bootstrap_native_complete(&mut self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.current_mut()?.require_bootstrap_native_complete(complete)
    }

    /// Debits the actual import models before decode and after each open.
    ///
    /// # Errors
    /// Retains arithmetic, capacity or same-interval refusal before growth.
    pub fn require_import_models_complete(&mut self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.current_mut()?.require_import_models_complete(complete)
    }

    /// Finishes the already-entered interval independently of the body result.
    ///
    /// # Errors
    /// Retains the actual same-profile/control/native post; refuses repeats.
    pub fn finish_native_once(&mut self) -> Result<(), ControllerProfileErrorV1> {
        let index = self.entered.checked_sub(1).ok_or(ControllerProfileErrorV1::Service)?;
        if self.posts[index].is_some() { return Err(ControllerProfileErrorV1::Service); }
        self.posts[index] = Some(self.phases[index].as_mut()
            .ok_or(ControllerProfileErrorV1::Service)?.finish_native_once());
        if matches!(self.posts[index], Some(Ok(()))) { Ok(()) }
        else { Err(ControllerProfileErrorV1::Service) }
    }

    /// Borrows the earliest retained claim or interval cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.claim.as_ref().err().map(|cause| cause as _).or_else(|| {
            self.phases.iter().flatten().find_map(|phase| phase.failure())
        })
    }
}
