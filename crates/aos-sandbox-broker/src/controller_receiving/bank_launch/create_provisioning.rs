//! Keeps postterminal provisioning on the same Controller native interval.
//!
//! Actual completed Create, Session and Apply/publication semantics stay in
//! the trusted upper coordinator. Short same-writer reborrows allow its real
//! appends while this owner retains prearmed names and the existing private
//! profile destinations. Each complete Producer stays on its own real thread;
//! only the Send owning results/anchors cross an await. Identity and
//! representation DATA alone cannot construct it.

mod catalog_maintenance;
pub use catalog_maintenance::{ControllerCatalogMaintenanceIdentityV2, ControllerCatalogMaintenanceReceivingV2};
mod completion;
mod recovered_stop;
mod cleanup_association;
pub(in crate::controller_receiving) use cleanup_association::RecoveredStopCleanupAssociationOriginalV1;
mod network_endpoint;
pub use network_endpoint::ControllerStartResourceEndpointOriginalV2;
mod recover_session;
mod recovered_sessions;
pub use recovered_sessions::ControllerRecoveredOrdinarySessionsOriginalV2;
mod recovered_enrollment;
pub use recovered_enrollment::ControllerRecoveredEnrollmentReceivingV2;
pub(in crate::controller_receiving) use recovered_enrollment::RecoveredEnrollmentAssociationV1;
pub(in crate::controller_receiving) use recover_session::ControllerSessionRepresentationV3;
pub use recover_session::{ControllerReconciliationInventoryRoleV2, ControllerRecoverySessionRetentionV1,
    ControllerStopCleanupSessionRetentionV1, ControllerStopCleanupSourceAffinityV1};
pub use completion::ControllerCreateProvisioningCompletionDestinationV1;

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use crate::controller_receiving::profile::baseline::provisioning::ProvisioningProfileOriginalV1;
use crate::controller_receiving::profile::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1};
use crate::controller_receiving::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};
use crate::controller_receiving::original::ContinuationReceivingPurposeV1;
use super::coordinator::ControllerCoordinatorWriterV1;
use super::identity::ControllerWriterIdentityV1;
use super::launch::ControllerBankLaunchOriginalV1;
use super::writer::ControllerWriterNameSampleV1;
use super::ControllerBankLaunchErrorV1;

#[derive(Clone, Copy)]
enum First { Entry, Before, Profile, Representation, CleanupScope, SessionEntry, SessionFence, SessionGraph, After, ProfileAfter, Launch, Finish, Next }

/// Retains one genuine provisioning interval without borrowing an executor.
///
/// Every healthy entry rejoins the same physical writer, confirmed launch and
/// private profile owner. The upper owner retains its actual body and output;
/// native completion authenticates none of their semantic claims.
#[must_use = "retain failed native originals with their independent posts"]
pub struct ControllerCreateProvisioningReceivingV1 {
    purpose: ContinuationReceivingPurposeV1,
    recovered_stop: Option<Box<recovered_stop::RecoveredStopNativeFieldsV3>>,
    cleanup_session: Option<Arc<ControllerSessionRepresentationV3>>,
    cleanup_source_scope: Option<Arc<std::sync::atomic::AtomicBool>>,
    cleanup_source_scope_entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    cleanup_source_scope_reentry: Option<ControllerBankLaunchErrorV1>,
    cleanup_session_entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    cleanup_session_fence: Option<Result<(), ControllerReceivingErrorV1>>,
    cleanup_posts_complete: bool,
    cleanup_graph_retired: Option<Result<(), ControllerBankLaunchErrorV1>>,
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    turn_identity: Option<Arc<std::sync::atomic::AtomicBool>>,
    completion_claimed: bool,
    fixed: Result<ResourceVector, ControllerBankLaunchErrorV1>,
    initial_complete: ResourceVector,
    conjunction: Result<(), ControllerBankLaunchErrorV1>,
    entry: Result<ResourceVector, ControllerReceivingErrorV1>,
    arm: Option<Result<(), ControllerBankLaunchErrorV1>>,
    before: ControllerWriterNameSampleV1,
    before_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile: Option<ProvisioningProfileOriginalV1>,
    representation: Option<Result<ResourceVector, ControllerBankLaunchErrorV1>>,
    after: ControllerWriterNameSampleV1,
    after_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile_result: Option<Result<(), ControllerProfileErrorV1>>,
    launch_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    finish_result: Option<Result<(), ControllerReceivingErrorV1>>,
    next_entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    first: Option<First>,
    finished: bool,
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Describes this actual owner and its two retained name/witness samples.
    ///
    /// # Errors
    /// Refuses unrepresentable compiled-layout or native supplier arithmetic.
    pub fn receiving_demand_v1(profile: &ControllerSelfProfileOriginalV1) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<usize>()))
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let bytes = u64::try_from(bytes).map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(profile.provisioning_receiving_demand_v1()?)?)
    }

    fn begin<P>(writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Self {
        Self::begin_purpose_v1(writer, launch, profile, complete,
            ContinuationReceivingPurposeV1::CreateProvisioning)
    }

    fn begin_purpose_v1<P>(writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector, purpose: ContinuationReceivingPurposeV1,
    ) -> Self {
        Self::begin_purpose_with_predecessor_v2(writer, launch, profile, complete, purpose, None)
    }

    fn begin_purpose_with_predecessor_v2<P>(writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector, purpose: ContinuationReceivingPurposeV1,
        predecessor: Option<&Result<(), ControllerBankLaunchErrorV1>>,
    ) -> Self {
        let fixed = match purpose {
            ContinuationReceivingPurposeV1::CreateProvisioning
                | ContinuationReceivingPurposeV1::LifecycleStop => Self::receiving_demand_v1(profile),
            ContinuationReceivingPurposeV1::RecoveredLifecycleStop => Self::receiving_demand_v1(profile)
                .and_then(|demand| Ok(demand.checked_add(recovered_stop::RecoveredStopNativeFieldsV3::receiving_demand_v3()?)?)),
            ContinuationReceivingPurposeV1::OperatorRecover => ControllerOperatorRecoverReceivingV1::receiving_demand_v1(profile),
            ContinuationReceivingPurposeV1::CatalogMaintenance => ControllerCatalogMaintenanceReceivingV2::receiving_demand_v2(profile),
            ContinuationReceivingPurposeV1::RecoveredEnrollment => ControllerRecoveredEnrollmentReceivingV2::receiving_demand_v2(profile),
            ContinuationReceivingPurposeV1::RecoveredOrdinarySession(_) =>
                ControllerRecoveredOrdinarySessionsOriginalV2::role_native_demand_v2(profile),
        };
        let conjunction = (|| {
            if predecessor.is_some_and(Result::is_err) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            match purpose {
                ContinuationReceivingPurposeV1::CreateProvisioning
                    | ContinuationReceivingPurposeV1::LifecycleStop => launch.require_controller_baseline_precharge_v1(writer)?,
                ContinuationReceivingPurposeV1::OperatorRecover
                    | ContinuationReceivingPurposeV1::RecoveredLifecycleStop => launch.require_operator_recover_current_v1(writer)?,
                ContinuationReceivingPurposeV1::CatalogMaintenance => {
                    launch.require_controller_baseline_precharge_v1(writer)?;
                    writer.fixed.original().require_catalog_maintenance_context_v2()?;
                }
                ContinuationReceivingPurposeV1::RecoveredOrdinarySession(_) => {
                    launch.require_operator_recover_current_v1(writer)?;
                }
                ContinuationReceivingPurposeV1::RecoveredEnrollment => {
                    launch.require_operator_recover_current_v1(writer)?;
                    writer.fixed.original().require_recovered_intakes_funded_v2(profile)?;
                }
            }
            if !profile.has_same_baseline_original(writer.fixed.original()) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            Ok(())
        })();
        let entry = (|| {
            let fixed = *fixed.as_ref().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            conjunction.as_ref().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            let complete = fixed.checked_add(complete)?;
            if purpose == ContinuationReceivingPurposeV1::RecoveredLifecycleStop && predecessor.is_some() {
                writer.fixed.original().begin_recovered_stop_seed_continuation_v3(complete)
            } else {
                writer.fixed.original().begin_continuation_complete_v1(purpose, complete)
            }
        })();
        let first = entry.is_err().then_some(First::Entry);
        let mut owner = Self {
            purpose, recovered_stop: None, cleanup_session: None,
            cleanup_source_scope: None, cleanup_source_scope_entry: None, cleanup_source_scope_reentry: None,
            cleanup_session_entry: None, cleanup_session_fence: None, cleanup_posts_complete: false,
            cleanup_graph_retired: None,
            original: Arc::clone(writer.fixed.original()), identity: Arc::clone(writer.fixed.identity()),
            turn_identity: None, completion_claimed: false,
            fixed, initial_complete: complete, conjunction, entry, arm: None, before: ControllerWriterNameSampleV1::new(), before_result: None,
            profile: None, representation: None, after: ControllerWriterNameSampleV1::new(),
            after_result: None, profile_result: None, launch_result: None, finish_result: None,
            next_entry: None, first, finished: false,
        };
        if owner.entry.is_ok() {
            // The private native-turn identity is paid by the fixed demand
            // before this allocation and survives actual completion.
            owner.turn_identity = Some(Arc::new(std::sync::atomic::AtomicBool::new(false)));
            owner.profile = ProvisioningProfileOriginalV1::prepare(profile, &owner.original);
            if owner.profile.as_ref().is_none_or(|profile| profile.failure().is_some()) {
                owner.first = Some(First::Profile);
                return owner;
            }
            // Prearm the SAME physical writer's post before any primary IO.
            owner.arm = Some(writer.fixed.begin_name_sample(&mut owner.after));
            if !matches!(owner.arm, Some(Ok(()))) { owner.first = Some(First::Entry); }
            else {
                owner.before_result = Some((|| {
                    writer.fixed.begin_name_sample(&mut owner.before)?;
                    writer.fixed.finish_owed_name_sample(&mut owner.before)
                })());
                if !matches!(owner.before_result, Some(Ok(()))) { owner.first = Some(First::Before); }
                else {
                    let observed = owner.profile.as_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)
                        .and_then(|owner| owner.before_once(profile).map_err(Into::into));
                    if observed.is_err() { owner.first = Some(First::Profile); }
                }
            }
        }
        owner
    }

    fn same_writer<P>(&self, writer: &ControllerCoordinatorWriterV1<P>) -> bool {
        Arc::ptr_eq(&self.identity, writer.fixed.identity()) && writer.fixed.has_original(&self.original)
    }

    /// Rejoins actual owners before another healthy provisioning stage.
    ///
    /// # Errors
    /// Refuses foreign writer/profile/launch, prior failure or completed posts.
    pub fn require_current_v1<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.same_writer(writer) || self.first.is_some() || self.finished || self.after_result.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?.require_active(profile)?;
        launch.require_controller_baseline_precharge_v1(writer)
    }

    /// Rejoins a completed original without entering another native observation.
    ///
    /// Both actual Producer destinations and writer name samples must already
    /// be disposed. This only lends completed custody to the upper typed child
    /// comparison; it grants no append, fresh currentness or next-turn entry.
    ///
    /// # Errors
    /// Refuses incomplete, failed, undisposed or foreign original owners.
    pub fn require_completed_original_v1<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.finished || self.first.is_some() || !self.same_writer(writer)
            || self.fixed.is_err() || self.conjunction.is_err() || self.entry.is_err()
            || !matches!(self.arm, Some(Ok(())))
            || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
            || !matches!(self.profile_result, Some(Ok(())))
            || !matches!(self.launch_result, Some(Ok(())))
            || !matches!(self.finish_result, Some(Ok(())))
            || self.representation.as_ref().is_some_and(Result::is_err)
            || self.next_entry.is_some()
            || !self.before.has_disposed_complete_interval_v1()
            || !self.after.has_disposed_complete_interval_v1()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .require_completed_v1(profile)?;
        launch.require_controller_baseline_precharge_v1(writer)
    }

    /// Debits reached complete native/schema representation before actual growth.
    ///
    /// The upper requirement includes every earlier resident upper owner and
    /// this turn's cumulative traffic. The same C also retains all prior turns'
    /// spent traffic. This returns no capacity, IO permission or append port.
    ///
    /// # Errors
    /// Retains arithmetic, original-capacity or same-owner refusal.
    pub fn require_complete_representation_v1<P>(&mut self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if let Some(session) = self.cleanup_session.as_ref().map(Arc::clone) {
            return session.raise_upper_v1(self, writer, launch, profile, complete);
        }
        self.require_complete_representation_inner_v1(writer, launch, profile, complete)
    }

    fn require_complete_representation_inner_v1<P>(&mut self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v1(writer, launch, profile)?;
        self.representation = Some((|| {
            let fixed = *self.fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let base = *self.entry.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let complete = fixed.checked_add(complete)?;
            self.original.raise_continuation_complete_v1(self.purpose, base, complete)?;
            Ok(complete)
        })());
        if self.representation.as_ref().is_none_or(Result::is_err) {
            self.first.get_or_insert(First::Representation);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Runs every already-owed native post independently of the upper body.
    ///
    /// Same-owner checks run before borrowing poisoned files; healthy entry is
    /// deliberately not required for the prearmed name/profile continuation.
    /// Native completion establishes no Apply or publication semantic result.
    ///
    /// # Errors
    /// Retains first names/profile/launch/disposal failure and fences the writer.
    pub fn finish_native_once<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.after_result.is_some() || self.finished || !self.same_writer(writer)
            || self.profile.as_ref().is_some_and(|held| held.require_same_profile(profile).is_err())
        { return Err(ControllerBankLaunchErrorV1::Conflict); }

        if let Some(session) = self.cleanup_session.as_ref() {
            self.cleanup_session_fence = Some(session.fence_primary_v1());
            if !matches!(self.cleanup_session_fence, Some(Ok(()))) {
                self.first.get_or_insert(First::SessionFence);
            }
        }

        if matches!(self.arm, Some(Ok(()))) {
            self.after_result = Some(writer.fixed.finish_owed_name_sample(&mut self.after));
            if !matches!(self.after_result, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        }
        if let Some(held) = self.profile.as_mut() {
            self.profile_result = Some(held.after_once(profile));
            if !matches!(self.profile_result, Some(Ok(()))) { self.first.get_or_insert(First::ProfileAfter); }
        }
        self.launch_result = Some(launch.require_controller_baseline_precharge_v1(writer));
        if !matches!(self.launch_result, Some(Ok(()))) { self.first.get_or_insert(First::Launch); }
        if self.cleanup_source_scope.is_some() && self.first.is_none()
            && matches!(self.after_result, Some(Ok(())))
            && matches!(self.profile_result, Some(Ok(())))
            && matches!(self.launch_result, Some(Ok(())))
        {
            // Source22 keeps the SAME continuation and name-sample custody
            // while actual cold/SDK/model owners retire. This runs no new IO;
            // its separate closed disposer performs the positive transition.
            self.cleanup_posts_complete = true;
            return Ok(());
        }
        if self.first.is_none() && matches!(self.after_result, Some(Ok(())))
            && matches!(self.profile_result, Some(Ok(()))) && matches!(self.launch_result, Some(Ok(())))
        {
            return self.complete_native_disposal_v1(writer);
        }
        writer.fixed.fence();
        Err(ControllerBankLaunchErrorV1::Conflict)
    }

    fn complete_native_disposal_v1<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if self.first.is_some() || self.finished || self.finish_result.is_some()
            || !self.same_writer(writer) || !matches!(self.after_result, Some(Ok(())))
            || !matches!(self.profile_result, Some(Ok(())))
            || !matches!(self.launch_result, Some(Ok(())))
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.require_stop_cleanup_session_graph_retired_v1()?;
        self.finish_result = Some(match self.entry.as_ref() {
            Ok(base) => self.original.finish_continuation_native_v1(self.purpose, *base),
            Err(_) => Err(ControllerReceivingErrorV1::Conflict),
        });
        if !matches!(self.finish_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Finish);
            writer.fixed.fence();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.before.dispose_after_complete_interval();
        self.after.dispose_after_complete_interval();
        self.finished = true;
        Ok(())
    }

    /// Starts the next native turn only after this exact turn really disposed.
    ///
    /// All prior complete names/profile/control/Ended/launch posts must already
    /// be positive. Only their completed DATA slots are replaced; the actual
    /// C ledger, owner highwater and spent traffic remain unchanged. A refused
    /// predecessor or next entry stays resident and cannot rearm through here.
    /// `complete` includes all retained upper owners and current-turn traffic.
    ///
    /// # Errors
    /// Retains foreign/repeated association or next native/financial refusal.
    pub fn begin_next_native_turn_v1<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.finished || self.first.is_some() || self.next_entry.is_some()
            || self.cleanup_source_scope.is_some() || self.cleanup_session.is_some()
            || (self.completion_claimed && self.turn_identity.as_ref().is_none_or(|turn|
                !turn.load(std::sync::atomic::Ordering::Acquire))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.next_entry = Some((|| {
            if !self.same_writer(writer) { return Err(ControllerBankLaunchErrorV1::Conflict); }
            self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .require_same_profile(profile)?;
            launch.require_controller_baseline_precharge_v1(writer)
        })());
        if !matches!(self.next_entry, Some(Ok(()))) {
            self.first = Some(First::Next);
            self.finished = false;
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let purpose = self.purpose;
        if let Some(seed) = self.recovered_stop.as_ref() {
            seed.intake.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .require_recovered_entry_v2(writer, launch, profile)?;
        }
        // The actual seed stays owned through construction of the next native
        // Result-bearing destination; no fallible return crosses its local move.
        let seed = self.recovered_stop.take();
        let mut next = Self::begin_purpose_v1(writer, launch, profile, complete, purpose);
        next.recovered_stop = seed;
        let previous = std::mem::replace(self, next);
        drop(previous);
        if self.failure().is_some() { Err(ControllerBankLaunchErrorV1::Conflict) } else { Ok(()) }
    }

    /// Borrows the rich profile cause only when it is the actual first stage.
    #[must_use]
    pub fn profile_failure_view_v1(&self)
        -> Option<crate::controller_receiving::profile::ControllerProfileFailureViewV1<'_>>
    {
        if !matches!(self.first, Some(First::Profile | First::ProfileAfter)) { return None; }
        Some(crate::controller_receiving::profile::ControllerProfileFailureViewV1::from_baseline_v1(
            self.profile.as_ref()?.failure_view()?,
        ))
    }

    /// Borrows the original first native cause without cloning its owner.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Entry => error(&self.fixed).or_else(|| error(&self.conjunction)).or_else(|| error(&self.entry))
                .or_else(|| self.arm.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Before => self.before.failure()
                .or_else(|| self.before_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Profile | First::ProfileAfter => self.profile.as_ref()?.failure(),
            First::Representation => self.representation.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::CleanupScope => self.cleanup_source_scope_entry.as_ref()
                .and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.cleanup_source_scope_reentry.as_ref().map(|cause| cause as _)),
            First::SessionEntry => self.cleanup_session_entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SessionFence => self.cleanup_session_fence.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SessionGraph => self.cleanup_graph_retired.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::After => self.after.failure()
                .or_else(|| self.after_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Launch => self.launch_result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Finish => self.finish_result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Next => self.next_entry.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

impl Drop for ControllerCreateProvisioningReceivingV1 {
    fn drop(&mut self) {
        if !self.finished {
            // Match the existing closed C conjunction: abandonment must not
            // release actual failed native owners through ordinary field Drop.
            std::process::abort();
        }
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Enters this writer's fixed postterminal provisioning native interval.
    ///
    /// The actual upper Bank additionally requires its completed Create and
    /// same Session. This mechanism accepts no semantic receipt, caller files,
    /// substitute original or callback, and exports no writer or append port.
    #[must_use]
    pub fn begin_create_provisioning_receiving_v1(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> ControllerCreateProvisioningReceivingV1 {
        ControllerCreateProvisioningReceivingV1::begin(self, launch, profile, complete)
    }
}

/// Retains a separately paid OperatorRecover observation interval.
///
/// Only an authenticated current PID1 successor constructs this original. It
/// shares the fixed native engine and Producer reservoir while using its own
/// monotone residual liability. It adopts no interrupted Create/C23 owner and
/// grants no operation, Source mutation, lease, Root response or replay effect.
#[must_use = "retain the whole recovery original and finish its owed posts"]
pub struct ControllerOperatorRecoverReceivingV1 {
    native: ControllerCreateProvisioningReceivingV1,
    session: Option<Arc<ControllerSessionRepresentationV3>>,
    session_entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    session_reentry: Option<ControllerBankLaunchErrorV1>,
    session_entry_primary: bool,
    session_reentry_primary: bool,
    session_retired_before_posts: Option<Result<(), ControllerReceivingErrorV1>>,
}

impl ControllerOperatorRecoverReceivingV1 {
    /// Checks that this original prepaid its independently owed observations.
    ///
    /// This receipt does not admit body work or require later healthy posts.
    /// It remains usable after a subsequent refusal, while a failed initial
    /// admission cannot authorize native observation or allocation.
    ///
    /// # Errors
    /// Refuses an original whose fixed geometry, conjunction or entry failed.
    #[doc(hidden)]
    pub fn require_prepaid_owed_observation_v1(&self)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if self.native.fixed.is_err() || self.native.conjunction.is_err()
            || self.native.entry.is_err() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Prices this concrete fixed owner and the same two native Producers.
    ///
    /// # Errors
    /// Refuses unrepresentable actual native/profile supplier arithmetic.
    pub fn receiving_demand_v1(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let wrapper = u64::try_from(std::mem::size_of::<Self>())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        // The common body already prices its resident/constructor pair. The
        // distinct outer Recover return carrier also survives that crossing.
        Ok(ControllerCreateProvisioningReceivingV1::receiving_demand_v1(profile)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, wrapper))?)
    }

    /// Rejoins the same actual current recipient, writer and active profile.
    ///
    /// # Errors
    /// Refuses foreign custody, failed entry or already-finished posts.
    pub fn require_current_v1<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.session_reentry.is_some() || self.session_entry.as_ref().is_some_and(Result::is_err) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        launch.require_operator_recover_current_v1(writer)?;
        self.native.require_current_v1(writer, launch, profile)
    }

    /// Raises only the actual Recover owner's complete reached representation.
    ///
    /// # Errors
    /// Retains capacity/arithmetic failure on this same residual C ledger.
    pub fn require_complete_representation_v1<P>(&mut self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let session = self.session.as_ref().map(Arc::clone);
        match session {
            Some(session) => session.raise_upper_v1(&mut self.native, writer, launch, profile, complete),
            None => self.native.require_complete_representation_v1(writer, launch, profile, complete),
        }
    }

    /// Runs every prearmed native post even when the recovery body refused.
    ///
    /// # Errors
    /// Retains actual names, Producer, recipient or disposal refusal.
    pub fn finish_native_once<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.session_retired_before_posts.is_none() {
            let retired = self.require_cold_session_last_owner_v1();
            self.session_retired_before_posts = Some(match retired {
                Ok(()) => Ok(()),
                Err(cause) if self.session.as_ref().is_some_and(|session| session.is_stop_cleanup_v1()) => {
                    // Preserve the actual snapshot cause in the existing
                    // native finisher, before any owed posts. Its first-stage
                    // conjunction prevents continuation retirement and
                    // physical positive disposal while those posts still run.
                    self.native.finish_result = Some(Err(cause));
                    self.native.first.get_or_insert(First::Finish);
                    Err(ControllerReceivingErrorV1::Conflict)
                }
                Err(cause) => Err(cause),
            });
        }
        if let Some(session) = &self.session { session.end_primary_v1(); }
        self.native.finish_native_once(writer, launch, profile)
    }

    /// Requires the actual positive disposal, without granting recovery success.
    ///
    /// # Errors
    /// Refuses foreign or unfinished native custody.
    pub fn require_completed_original_v1<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.session_reentry.is_some() || self.session_entry.as_ref().is_some_and(Result::is_err) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        launch.require_operator_recover_current_v1(writer)?;
        self.native.require_completed_original_v1(writer, launch, profile)
    }

    /// Borrows the actual first native or financial cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.session_entry_primary { return self.session_entry.as_ref().and_then(error); }
        if self.session_reentry_primary {
            return self.session_reentry.as_ref().map(|cause| cause as _);
        }
        self.native.failure().or_else(|| self.session_entry.as_ref().and_then(error))
            .or_else(|| self.session_reentry.as_ref().map(|cause| cause as _))
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Begins the successor's separately charged, closed Recover observation.
    ///
    /// The trusted upper owner still requires actual capability authorization
    /// and exact protected target/evidence before any reconciliation. This
    /// mechanical factory lends no journal, grant or ordinary Create receipt.
    #[must_use]
    pub fn begin_operator_recover_receiving_v1(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> ControllerOperatorRecoverReceivingV1 {
        ControllerOperatorRecoverReceivingV1 {
            session: None, session_entry: None, session_reentry: None,
            session_entry_primary: false, session_reentry_primary: false,
            session_retired_before_posts: None,
            native: ControllerCreateProvisioningReceivingV1::begin_purpose_v1(self, launch, profile,
                complete, ContinuationReceivingPurposeV1::OperatorRecover),
        }
    }
}

fn error<T, E: Error + 'static>(result: &Result<T, E>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_provisioning_owner_can_cross_the_installed_async_handoff() {
        fn requires_send<T: Send>() {}
        requires_send::<ControllerCreateProvisioningReceivingV1>();
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    pub(crate) fn require_source_original_v1<P>(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v1(writer, launch, profile)?;
        if !source.has_same_original_v1(&self.original) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_completed_source_original_v1(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.finished || self.first.is_some()
            || !source.has_same_original_v1(&self.original) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }
}


impl ControllerCreateProvisioningReceivingV1 {
    /// Measures the completed native carrier after its probes were disposed.
    ///
    /// The same upper custody must independently rejoin its writer, profile
    /// and confirmed launch. Shared baseline/profile allocations remain owned
    /// by those originals and are not reconstructed by this passive supplier.
    ///
    /// # Errors
    /// Refuses incomplete, failed or undisposed native samples and overflow.
    pub fn completed_resident_receiving_demand_v1(&self)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1>
    {
        if !self.finished || self.first.is_some()
            || !self.before.has_disposed_complete_interval_v1()
            || !self.after.has_disposed_complete_interval_v1()
            || !matches!(self.finish_result, Some(Ok(())))
            || self.turn_identity.is_none()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        // This is the same actual carrier/Arc backing recipe paid at entry.
        // Both native name samples and Producer scopes are already disposed.
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<usize>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }
}

impl ControllerOperatorRecoverReceivingV1 {
    pub(crate) fn require_source_original_v1<P>(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        controller: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v1(controller, launch, profile)?;
        self.native.require_source_original_v1(source, controller, launch, profile)
    }

    pub(crate) fn require_completed_source_original_v1(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.native.require_completed_source_original_v1(source)
    }
}

impl ControllerOperatorRecoverReceivingV1 {
    /// Measures conservatively retained residents of this completed scope.
    ///
    /// This DATA disposes no field, returns no capacity and resets no traffic.
    ///
    /// # Errors
    /// Refuses unfinished, failed or foreign completed native custody.
    #[doc(hidden)]
    pub fn completed_resident_receiving_demand_v1<P>(
        &self,
        writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        self.require_completed_original_v1(writer, launch, profile)?;
        self.native.original.completed_operator_recover_resident_demand_v1().map_err(Into::into)
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Starts the closed native Stop interval on the same permanent C invoice.
    ///
    /// This is native receiving custody only. The actual Domain Stop owner
    /// must separately validate its accepted public Stop and protected Source
    /// operation before any business effect or terminal append. Other native
    /// purposes cannot be promoted to this purpose by representation DATA.
    ///
    /// # Errors
    /// Entry/native failures remain in the returned original; its before and
    /// independently prearmed after destinations must remain retained.
    pub fn begin_lifecycle_stop_receiving_v4(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> ControllerCreateProvisioningReceivingV1 {
        ControllerCreateProvisioningReceivingV1::begin_purpose_v1(self, launch, profile,
            complete, ContinuationReceivingPurposeV1::LifecycleStop)
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Checks only the actual native purpose before a Stop-specific borrower.
    ///
    /// No supplied context or amount can change this original's purpose.
    ///
    /// # Errors
    /// Refuses a Create, Start, Recover or foreign/incomplete native original.
    pub fn require_lifecycle_stop_current_v4<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !matches!(self.purpose, ContinuationReceivingPurposeV1::LifecycleStop
            | ContinuationReceivingPurposeV1::RecoveredLifecycleStop) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_current_v1(writer, launch, profile)
    }
}


impl ControllerCreateProvisioningReceivingV1 {
    /// Rejoins a completed Stop turn before another finite turn on the same C.
    ///
    /// # Errors
    /// Refuses another native purpose or any incomplete/foreign disposition.
    pub fn require_lifecycle_stop_completed_v4<P>(
        &self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !matches!(self.purpose, ContinuationReceivingPurposeV1::LifecycleStop
            | ContinuationReceivingPurposeV1::RecoveredLifecycleStop) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_completed_original_v1(writer, launch, profile)
    }
}
