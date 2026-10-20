//! Retains the selected Root's actual service sampler after native handoff.
//!
//! The original enrolled kernel and settled sampler move into the existing
//! permanent allocation once. Currentness borrows that owner; copied policy,
//! financial or qualification DATA cannot construct a selected startup loan.

use std::error::Error;
use std::sync::{Arc, Mutex, OnceLock};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{
    RootKernelOriginalCaptureV1, RootObservationErrorV1 as Closed,
    RootServiceCurrentnessOriginalV1, RootStartupNativeOriginalV1,
};

pub(super) struct RootSelectedServiceOriginalV1 {
    kernel: RootKernelOriginalCaptureV1,
    state: Mutex<ServiceStateV1>,
    failed: OnceLock<RootServiceCurrentnessOriginalV1>,
    closed: OnceLock<Closed>,
    first: OnceLock<FailureSiteV1>,
}

#[derive(Clone, Copy)]
enum FailureSiteV1 {
    Financial,
    Sampler,
    Gate,
}

struct ServiceStateV1 {
    sampler: Option<RootServiceCurrentnessOriginalV1>,
    worker_active: bool,
}

impl RootSelectedServiceOriginalV1 {
    pub(super) fn from_settled_originals(
        kernel: RootKernelOriginalCaptureV1,
        sampler: RootServiceCurrentnessOriginalV1,
    ) -> Self {
        Self {
            kernel,
            state: Mutex::new(ServiceStateV1 {
                sampler: Some(sampler),
                worker_active: false,
            }),
            failed: OnceLock::new(),
            closed: OnceLock::new(),
            first: OnceLock::new(),
        }
    }

    pub(super) fn construction_bytes_v1() -> Option<usize> {
        type Guard<'a> = std::sync::MutexGuard<'a, ServiceStateV1>;
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<ServiceStateV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Guard<'_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::sync::LockResult<Guard<'_>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootSelectedStartupBorrowV1<'_>>().checked_mul(2)?)?
            .checked_add(
                std::mem::size_of::<Result<RootSelectedStartupBorrowV1<'_>, Closed>>()
                    .checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<(), Box<dyn std::any::Any + Send>>>().checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(4)?)?
            .checked_add(
                std::mem::size_of::<RootSelectedCurrentnessFailureOriginalV1>().checked_mul(2)?,
            )?
            .checked_add(
                std::mem::size_of::<Option<RootSelectedCurrentnessFailureOriginalV1>>()
                    .checked_mul(2)?,
            )
    }

    pub(super) fn kernel(&self) -> &RootKernelOriginalCaptureV1 {
        &self.kernel
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failed
            .get()
            .and_then(RootServiceCurrentnessOriginalV1::failure)
            .or_else(|| self.closed.get().map(|cause| cause as _))
    }

    pub(super) fn retain_financial_failure_v1(&self) {
        self.first.get_or_init(|| FailureSiteV1::Financial);
    }

    // Callers hold the genuine permanent invocation fence. This is the moved
    // original worker interval, not a copied idle qualification supplied by U.
    pub(super) fn require_worker_idle_v1(&self) -> Result<(), Closed> {
        let state = self.state.lock().map_err(|_| self.refuse())?;
        if state.worker_active || self.failure().is_some() {
            return Err(self.refuse());
        }
        Ok(())
    }

    pub(super) fn worker_idle_data_v1(&self) -> bool {
        self.state.lock().is_ok_and(|state| !state.worker_active)
    }

    pub(super) fn enter_worker_once_v1(&self) -> Result<(), Closed> {
        let mut state = self.state.lock().map_err(|_| self.refuse())?;
        if state.worker_active || self.failure().is_some() {
            return Err(self.refuse());
        }
        state.worker_active = true;
        Ok(())
    }

    pub(super) fn finish_worker_once_v1(&self) -> Result<(), Closed> {
        let mut state = self.state.lock().map_err(|_| self.refuse())?;
        if !state.worker_active {
            return Err(self.refuse());
        }
        state.worker_active = false;
        Ok(())
    }

    pub(super) fn observe_prepaid_once_v1(
        &self,
        startup: &RootStartupNativeOriginalV1,
        recipient: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), Closed> {
        let mut state = self.state.lock().map_err(|_| self.refuse())?;
        if state.worker_active
            || self.failure().is_some()
            || !state
                .sampler
                .as_ref()
                .is_some_and(|sampler| sampler.is_positive())
        {
            return Err(self.refuse());
        }
        // Only a fully settled positive predecessor is retired. Failed native
        // prefixes move intact to the immutable diagnostic slot below.
        drop(state.sampler.take());
        state.sampler = Some(RootServiceCurrentnessOriginalV1::new());
        let sampler = state.sampler.as_mut().ok_or_else(|| self.refuse())?;
        let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sampler.observe_once(startup, &self.kernel, recipient, producer);
        }));
        if returned.is_ok() && sampler.is_positive() {
            return Ok(());
        }
        self.first.get_or_init(|| FailureSiteV1::Sampler);
        if let Some(sampler) = state.sampler.take() {
            if let Err(_original) = self.failed.set(sampler) {
                std::process::abort();
            }
        }
        if let Err(payload) = returned {
            self.refuse();
            std::panic::resume_unwind(payload);
        }
        Err(self.refuse())
    }

    fn refuse(&self) -> Closed {
        self.first.get_or_init(|| FailureSiteV1::Gate);
        *self.closed.get_or_init(|| Closed::Service)
    }
}

/// Retains the actual first selected-currentness cause on the same Root.
///
/// This diagnostic owns only a reference to the existing permanent allocation.
/// It cannot admit a sampler, create a writer or revive a failed native phase.
pub struct RootSelectedCurrentnessFailureOriginalV1 {
    original: Arc<super::root_permanent::RootPermanentNativeOriginalV1>,
}

impl RootSelectedCurrentnessFailureOriginalV1 {
    fn cause(&self) -> Option<&(dyn Error + 'static)> {
        match self.original.service.first.get()? {
            FailureSiteV1::Financial => self.original.financial.failure(),
            FailureSiteV1::Sampler | FailureSiteV1::Gate => self.original.service.failure(),
        }
    }
}

impl std::fmt::Debug for RootSelectedCurrentnessFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("RootSelectedCurrentnessFailureOriginalV1")
            .field("cause", &self.cause())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootSelectedCurrentnessFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cause() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("original selected Root currentness is closed"),
        }
    }
}

impl Error for RootSelectedCurrentnessFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause()
    }
}

/// Borrows the genuine selected startup and its same permanent native owner.
///
/// Its factory requires the actual one-way native handoff. This loan holds no
/// financial or upper mutex across its consumer's later shared journal debit.
#[must_use = "retain the actual startup through the original native crossing"]
pub struct RootSelectedStartupBorrowV1<'startup> {
    startup: &'startup RootStartupNativeOriginalV1,
}

impl RootStartupNativeOriginalV1 {
    /// Retains the actual first service-currentness failure without admission.
    #[must_use]
    pub fn selected_currentness_failure_original_v1(
        &self,
    ) -> Option<RootSelectedCurrentnessFailureOriginalV1> {
        let original = self.selected_permanent.get()?;
        original.service.first.get()?;
        Some(RootSelectedCurrentnessFailureOriginalV1 {
            original: Arc::clone(original),
        })
    }

    /// Borrows the actual settled selected startup without a field adopter.
    ///
    /// # Errors
    /// Refuses an ordinary, foreign, failed, unfinished or ended startup.
    pub fn borrow_selected_startup_v1(&self) -> Result<RootSelectedStartupBorrowV1<'_>, Closed> {
        let original = self.selected_permanent.get().ok_or(Closed::Service)?;
        let mut invocation = original.enter_native()?;
        if !self
            .initial_owner
            .as_ref()
            .is_some_and(|identity| original.has_identity(identity))
            || original.enrollment().process_id_v1() != std::process::id()
            || original.service.failure().is_some()
            || original.financial.failure().is_some()
        {
            invocation.refuse();
            return Err(Closed::Service);
        }
        Ok(RootSelectedStartupBorrowV1 { startup: self })
    }
}

impl RootSelectedStartupBorrowV1<'_> {
    /// Retains its already-selected original failure without another admission.
    #[must_use]
    pub fn failure_original_v1(&self) -> Option<RootSelectedCurrentnessFailureOriginalV1> {
        self.startup.selected_currentness_failure_original_v1()
    }

    /// Repeats the same paid selected service read and all native bookends.
    ///
    /// # Errors
    /// Preserves the original payment, worker, native or retained sampler
    /// refusal. It neither retries a failed prefix nor renews an effect cutoff.
    pub fn recheck_v1(&self) -> Result<(), Closed> {
        let original = self
            .startup
            .selected_permanent
            .get()
            .ok_or(Closed::Service)?;
        original.recheck_selected_service_once_v1(self.startup)
    }

    /// Returns the actual configured identities as comparison DATA only.
    #[must_use]
    pub fn identities_data_v1(&self) -> [u32; 4] {
        self.startup.fields().profile.identities
    }
}

pub(super) fn service_traffic_demand_v1() -> Option<ResourceVector> {
    let demand = RootServiceCurrentnessOriginalV1::demand()?;
    Some(
        ResourceVector::ZERO
            .with(D::NetworkBytes, demand.get(D::NetworkBytes))
            .with(D::LogBytes, demand.get(D::LogBytes))
            .with(
                D::PublicationStagingBytes,
                demand.get(D::PublicationStagingBytes),
            )
            .with(D::OutputBytes, demand.get(D::OutputBytes)),
    )
}
