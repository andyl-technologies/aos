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
            .checked_add(std::mem::size_of::<(&super::root_permanent::RootPermanentNativeOriginalV1, &RootStartupNativeOriginalV1)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Closed>>().checked_mul(3)?)?
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

impl<'startup> RootSelectedStartupBorrowV1<'startup> {
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

    /// Rechecks the same selected owner while retaining its genuine held L.
    ///
    /// The finite native provision keeps this guard across its original quote,
    /// Stage mutation and returned service result. This entry neither reacquires
    /// L nor performs another service traffic debit beside the existing one.
    ///
    /// # Errors
    /// Refuses a foreign guard, failed/ended original, nonidle worker, failed
    /// existing traffic mutation or actual native selected-service observation.
    pub fn recheck_under_upper_exclusion_v1(
        &self,
        exclusion: &super::RootUpperMutationGuardV1<'_>,
    ) -> Result<(), Closed> {
        let original = self.startup.selected_permanent.get().ok_or(Closed::Service)?;
        original.recheck_selected_service_under_upper_exclusion_v1(self.startup, exclusion)
    }

    /// Arms one independently owed service post on this same actual Initial.
    ///
    /// The finite native receiving owner prepays the real post before this
    /// constructor. The hidden native startup is never supplied as field DATA.
    ///
    /// # Errors
    /// Refuses a failed, incomplete or foreign actual Initial/startup pair.
    pub fn arm_owed_service_post_once_v1(
        &self,
        initial: &mut super::RootInitialReceivingOriginalV1,
    ) -> Result<super::RootPrearmedHistoryServicePostV1, Closed> {
        initial.arm_history_service_post_v1(self.startup)
    }

    /// Observes the same owed post while retaining its genuine original L.
    ///
    /// No upper lock, healthy reentry or additional traffic fee is acquired.
    /// The actual prearmed post retains every reached native prefix even when
    /// an earlier body or primary service check already refused.
    ///
    /// # Errors
    /// Retains a foreign guard, repeated post, ended original or native refusal.
    pub fn observe_owed_service_post_under_upper_exclusion_v1(
        &self,
        exclusion: &super::RootUpperMutationGuardV1<'_>,
        post: &mut super::RootPrearmedHistoryServicePostV1,
    ) -> Result<(), Closed> {
        post.observe_under_upper_exclusion_once_v1(self.startup, exclusion)
    }

    /// Measures the new held-exclusion receiving and service call controls.
    ///
    /// The actual finite provision supplier consumes this before entry. This
    /// passive quote creates no financial account, guard or semantic role.
    #[must_use]
    pub fn held_exclusion_control_bytes_v1() -> Option<usize> {
        super::RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?
            .checked_add(Self::service_recheck_under_exclusion_control_bytes_v1()?)?
            .checked_add(Self::owed_service_arm_control_bytes_v1()?)?
            .checked_add(std::mem::size_of::<(
                &Self, &super::RootUpperMutationGuardV1<'_>, &mut super::RootPrearmedHistoryServicePostV1,
            )>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(
                &mut super::RootPrearmedHistoryServicePostV1, &RootStartupNativeOriginalV1,
                &super::RootUpperMutationGuardV1<'_>,
            )>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Closed>>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<(
                &super::RootUpperMutationGuardV1<'_>, &super::root_permanent::RootPermanentNativeOriginalV1,
            )>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<bool>().checked_mul(3)?)
    }

    /// Measures the existing selected-service recheck under its retained guard.
    ///
    /// This is the service portion of the complete held-exclusion quote. It
    /// grants no Stage or observation and does not include a second Stage fee.
    #[must_use]
    pub fn service_recheck_under_exclusion_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        size_of::<(&Self, &super::RootUpperMutationGuardV1<'_>)>()
            .checked_mul(3)?
            .checked_add(size_of::<(&super::root_permanent::RootPermanentNativeOriginalV1,
                &RootStartupNativeOriginalV1, &super::RootUpperMutationGuardV1<'_>)>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Result<(), Closed>>().checked_mul(6)?)?
            .checked_add(size_of::<(&super::RootUpperMutationGuardV1<'_>,
                &super::root_permanent::RootPermanentNativeOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)
    }

    /// Arms the already-funded purpose posts against this same native startup.
    ///
    /// # Errors
    /// Retains every reached arm and refuses reentry or actual native failure.
    pub fn arm_purpose_posts_once_v1<E: super::RootPurposePostErrorV1>(
        &self,
        initial: &mut super::RootInitialReceivingOriginalV1,
        posts: &mut super::RootPurposePeerPostsOriginalV1<E>,
    ) -> Result<(), E> {
        posts.arm_once_v1(initial, self.startup)
    }

    /// Runs one independently owed purpose post on its original startup.
    ///
    /// # Errors
    /// Retains an absent, repeated, foreign or failed native observation. This
    /// owed path remains available after the primary programme has refused.
    pub fn observe_purpose_post_once_v1<E: super::RootPurposePostErrorV1>(
        &self,
        initial: &mut super::RootInitialReceivingOriginalV1,
        posts: &mut super::RootPurposePeerPostsOriginalV1<E>,
        purpose: super::RootPurposePeerPostV1,
    ) -> Result<(), E> {
        posts.observe_once_v1(initial, self.startup, purpose)
    }

    /// Measures the added opaque-startup forwarding planes for purpose posts.
    ///
    /// One arm and four distinct observations each retain their constructor,
    /// ABI-return and caller planes. Native samplers and the aggregate remain
    /// separately invoiced by the actual purpose before these interfaces.
    #[must_use]
    pub fn purpose_post_forwarding_control_bytes_v1<E: super::RootPurposePostErrorV1>() -> Option<usize> {
        use std::mem::size_of;

        size_of::<(&Self, &mut super::RootInitialReceivingOriginalV1,
            &mut super::RootPurposePeerPostsOriginalV1<E>)>()
            .checked_mul(3)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(3)?)?
            .checked_add(size_of::<(&Self, &mut super::RootInitialReceivingOriginalV1,
                &mut super::RootPurposePeerPostsOriginalV1<E>, super::RootPurposePeerPostV1)>()
                .checked_mul(12)?)?
            .checked_add(size_of::<Result<(), E>>().checked_mul(12)?)
    }

    /// Bounds the actual prearmed-service factory's finite forwarding planes.
    ///
    /// This contains no Stage, service observation, native backing or traffic
    /// credit. A caller reaches it once per actual arm in its earlier pure
    /// construction quote; the real arm still requires genuine Initial/startup.
    #[must_use]
    pub fn owed_service_arm_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        size_of::<(&Self, &mut super::RootInitialReceivingOriginalV1)>()
            .checked_mul(3)?
            .checked_add(size_of::<Result<super::RootPrearmedHistoryServicePostV1, Closed>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<(&mut super::RootInitialReceivingOriginalV1,
                &RootStartupNativeOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    /// Compares the same held permanent allocation without observing it.
    ///
    /// This passive affinity establishes no health, service or role completion.
    #[must_use]
    pub fn same_financial_original_data_v1(
        &self,
        financial: &super::RootJournalFinancialOriginalV1,
    ) -> bool {
        financial.same_startup_allocation_data_v1(self.startup)
    }

    /// Constructs only the existing native peer observer for this real startup.
    ///
    /// Its genuine Policy producer separately pays and owns admission and posts;
    /// construction alone establishes no Controller or listener completion.
    #[must_use]
    pub fn new_controller_peer_original_v1(
        &self,
        lifetime: super::ObservationLifetimeV1,
    ) -> super::RootSelectedControllerPeerOriginalV1<'startup> {
        super::RootSelectedControllerPeerOriginalV1::new(self.startup, lifetime)
    }

    /// Pays and arms the original startup post on its same actual Initial.
    ///
    /// The Initial owns the shared once-resident payment; every named Policy
    /// purpose still derives its own true phase before calling this mechanism.
    ///
    /// # Errors
    /// Retains actual fixed/native/traffic denial or original arm refusal.
    pub fn arm_paid_startup_service_post_once_v1(
        &self,
        initial: &mut super::RootInitialReceivingOriginalV1,
        exclusion: &super::RootUpperMutationGuardV1<'_>,
    ) -> Result<super::RootPrearmedHistoryServicePostV1, super::RootStartupServicePostErrorV1> {
        initial.arm_paid_startup_service_post_once_v1(self.startup, exclusion)
    }

    /// Quotes the new passive association, native-peer and paid-arm forwarding.
    #[must_use]
    pub fn startup_provision_forwarding_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<(&Self, &super::RootJournalFinancialOriginalV1)>().checked_mul(3)?
            .checked_add(size_of::<(&super::RootJournalFinancialOriginalV1, &RootStartupNativeOriginalV1)>()
                .checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(6)?)?
            .checked_add(size_of::<(&Self, super::ObservationLifetimeV1)>().checked_mul(3)?)?
            .checked_add(size_of::<super::RootSelectedControllerPeerOriginalV1<'static>>())?
            .checked_add(size_of::<(&Self, &mut super::RootInitialReceivingOriginalV1,
                &super::RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<super::RootPrearmedHistoryServicePostV1,
                super::RootStartupServicePostErrorV1>>().checked_mul(3)?)
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

impl RootStartupNativeOriginalV1 {
    /// Borrows the same settled selected original without a healthy reentry.
    ///
    /// This association alone grants no currentness, service observation or
    /// stage admission. Each reached native operation retains its own actual
    /// gates. Independent owed posts can therefore run after primary refusal.
    ///
    /// # Errors
    /// Refuses missing settled custody, a foreign initial identity or another PID.
    pub fn borrow_selected_original_v1(&self) -> Result<RootSelectedStartupBorrowV1<'_>, Closed> {
        let original = self.selected_permanent.get().ok_or(Closed::Service)?;
        let identity = self.initial_owner.as_ref().ok_or(Closed::Service)?;
        if !original.has_identity(identity)
            || original.enrollment().process_id_v1() != std::process::id()
        {
            return Err(Closed::Service);
        }
        Ok(RootSelectedStartupBorrowV1 { startup: self })
    }
}

impl RootStartupNativeOriginalV1 {
    /// Measures the passive original-borrow helper's concrete control carriers.
    ///
    /// This inert geometry supplies no original, currentness or financial grant.
    #[must_use]
    pub fn selected_original_borrow_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<&Self>()
            .checked_mul(3)?
            .checked_add(size_of::<RootSelectedStartupBorrowV1<'_>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<RootSelectedStartupBorrowV1<'_>, Closed>>().checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Option<&Arc<super::root_permanent::RootPermanentNativeOriginalV1>>>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<Option<&Arc<()>>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&Arc<()>, Closed>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(6)?)
    }
}
