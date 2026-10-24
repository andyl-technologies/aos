//! Admits one host query on the actual retained completed-Admit preparation.
//!
//! This action precedes node/runtime conversion. The installed ResourceLimits
//! policy observes its actual registered holder and Core observes the same
//! preparation, then admits the separately projected host query owners. No
//! native allocation report, restored graph or future whole grant is required
//! to issue this narrow host window.

use std::{
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

use crucible_node_format::Id;
use crucible_node_transport::{
    client::{CnpController, OriginalFreshRestoreQueryStorageData},
    connection::OriginalRetainedSupervisor,
    handshake::OriginalExtensionRegistryOwner,
};

use super::{InstalledConformancePlan, WeakInstalledConformancePlan};
use crate::{
    node_adapters::cnp::{
        CnpPreparationStorageScratch, CnpSemanticPreparation, PacketCompleteSemanticSource,
    },
    node_contract::RuntimeError,
};

/// Borrows the genuine installed plan and same pre-node host query owners.
///
/// Core alone constructs this scope; equality labels and decoded envelopes do
/// not construct one. Policy callbacks authenticate the actual registered
/// holder using raw identities, without renewing native or live graph state.
pub struct OriginalFreshRestoreHostScope<'a> {
    plan: &'a InstalledConformancePlan,
    preparation: &'a CnpSemanticPreparation,
    source: &'a Rc<PacketCompleteSemanticSource>,
    planned_id: &'a Id,
    registry: Option<&'a OriginalExtensionRegistryOwner>,
    supervisor: Option<&'a OriginalRetainedSupervisor>,
}

impl OriginalFreshRestoreHostScope<'_> {
    /// Borrows the actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the actual preparation before conversion to a node.
    pub fn preparation(&self) -> &CnpSemanticPreparation {
        self.preparation
    }

    /// Borrows the same concrete original Source allocation.
    pub fn source(&self) -> &Rc<PacketCompleteSemanticSource> {
        self.source
    }

    /// Borrows the caller's already retained one-shot request identifier.
    pub fn planned_id(&self) -> &Id {
        self.planned_id
    }

    /// Borrows the same retained concrete registry owner, when available.
    pub fn registry(&self) -> Option<&OriginalExtensionRegistryOwner> {
        self.registry
    }

    /// Borrows the same retained concrete supervisor owner, when available.
    pub fn supervisor(&self) -> Option<&OriginalRetainedSupervisor> {
        self.supervisor
    }

    /// Compares the actual preparation allocation without an owner callback.
    pub fn is_original_preparation(&self, preparation: &CnpSemanticPreparation) -> bool {
        std::ptr::eq(self.preparation, preparation)
    }

    /// Compares the actual installed plan allocation without reauthentication.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the actual retained policy object without its live callbacks.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Carries the installed host-query resource action and its observer allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalFreshRestoreHostPolicy {
    /// Bounds the holder, actual preparation and all added host query owners.
    pub maximum_requested_bytes: usize,
    /// Precredits actual holder observation and separately named fixed scratch.
    pub declared_observer_scratch_bytes: usize,
}

/// Observes the actual registered holder separately from its preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalFreshRestoreHostStorage {
    /// Counts actual holder/code/plan/authority/Host and other preparation roots.
    pub retained_holder_bytes: usize,
    /// Bounds the holder's complete simultaneous observation/construction phase.
    pub maximum_simultaneous_transient_bytes: usize,
}

/// Retains one admitted host query bound to its original preparation and Source.
///
/// No public constructor, Clone or serialization exists. This is host query
/// allocation authority only; it grants no native allocation, Prepare MAC,
/// activation, Ready, complete capture or whole restoration permission.
pub struct CompleteOriginalFreshRestoreHostWindow {
    process: u32,
    thread: ThreadId,
    source: Weak<PacketCompleteSemanticSource>,
    plan: WeakInstalledConformancePlan,
    // Used solely for equality with the actual original retained read owner.
    // This pointer is never dereferenced or exposed as authority to callers.
    original_owner: *const (),
    quote: OriginalFreshRestoreQueryStorageData,
    maximum_requested_bytes: usize,
    preparation_bytes: usize,
    current_validation_bytes: usize,
    registry: Option<*const ()>,
    supervisor: Option<*const ()>,
    rechecked: std::cell::Cell<bool>,
    spent: bool,
}

impl CompleteOriginalFreshRestoreHostWindow {
    /// Observes nested ticket backing while its containing holder counts inline storage.
    ///
    /// Shared owner headers are conservatively repeated; equal values receive
    /// no alias refund. This data sum does not renew the query occurrence.
    ///
    /// # Errors
    /// Refuses another creator/thread, unavailable quote backing or the bound.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        let maximum = maximum.min(self.maximum_requested_bytes);
        let facts = self
            .quote
            .original_retained_metadata_facts()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        let quote =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts, maximum,
            )?;
        let headers = crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
            PacketCompleteSemanticSource,
        >();
        checked_sum(
            [
                quote,
                headers,
                InstalledConformancePlan::original_report_startup_plan_header_storage_data(),
            ],
            maximum,
        )
    }

    /// Rechecks the same immutable preparation before mutable query dispatch.
    ///
    /// The registered holder calls this while its actual preparation slot is
    /// still immutably borrowed. The loan ends before mutable dispatch; policy
    /// callbacks that could reborrow that bank are not invoked under mutation.
    ///
    /// # Errors
    /// Refuses different original loans, a spent ticket or widened backing.
    pub fn recheck_original_preparation_data(
        &self,
        preparation: &CnpSemanticPreparation,
        source: &Rc<PacketCompleteSemanticSource>,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.rechecked.set(false);
        if self.spent {
            return Err(RuntimeError::DuplicateOperation);
        }
        let plan = self.authenticate_preparation(preparation, source)?;
        preparation.authenticate_original_fresh_query_plan_data(&plan)?;
        if preparation.original_fresh_query_current_storage_data(source)?
            > self.current_validation_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        if self.registry != registry.map(|value| std::ptr::from_ref(value).cast())
            || self.supervisor != supervisor.map(|value| std::ptr::from_ref(value).cast())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let observed = preparation
            .retained_requested_storage_precredit_data(
                scratch,
                registry,
                supervisor,
                self.maximum_requested_bytes,
            )?
            .complete_requested_bytes_precredit_data()?;
        if observed > self.preparation_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_holder_data(&plan, source)?;
        self.rechecked.set(true);
        Ok(())
    }

    pub(crate) fn authenticate_preparation(
        &self,
        preparation: &CnpSemanticPreparation,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<InstalledConformancePlan, RuntimeError> {
        self.origin()?;
        let original = self
            .source
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(&original, source)
            || self.original_owner
                != preparation.original_fresh_query_owner_identity_data(source)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    pub(crate) fn spend(&mut self) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.spent || !self.rechecked.replace(false) {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.spent = true;
        Ok(())
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }
}

impl InstalledConformancePlan {
    /// Quotes the fixed Core/Source/SDK headers before host observers run.
    ///
    /// Actual holder counters are added separately. Compiler and recursive SDK
    /// frames, allocator rounding and kernel memory are not certified here.
    ///
    /// # Errors
    /// Returns `ResourceLimit` if the checked fixed-layout sum overflows.
    pub fn original_fresh_restore_host_counter_scratch_data() -> Result<usize, RuntimeError> {
        checked_sum([
            CnpPreparationStorageScratch::requested_bytes(),
            PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(),
            PacketCompleteSemanticSource::original_fresh_query_invocation_counter_scratch_data()?,
            CnpController::original_restoration_host_metadata_counter_scratch_data(),
            CnpController::original_fresh_restore_query_counter_scratch_data(),
            crate::node_adapters::cnp::CnpSemanticSourceRead::original_fresh_query_call_scratch_data(),
            size_of::<OriginalFreshRestoreHostScope<'_>>(),
            size_of::<CompleteOriginalFreshRestoreHostWindow>(),
        ], usize::MAX)
    }

    pub(crate) fn is_same_original_plan_data(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Admits one query on the same preparation under the actual installed action.
    ///
    /// The holder retains `planned_id` before this call. The returned ticket is
    /// placed in its owning slot before mutable query dispatch. Any refusal or
    /// unwind after claiming the occurrence leaves it spent in the preparation.
    ///
    /// # Errors
    /// Refuses an unsupported policy, foreign/changed owner, repeated query,
    /// unknown backing, busy scratch or any complete requested-storage overrun.
    pub fn reserve_original_fresh_restore_host_window(
        &self,
        preparation: &CnpSemanticPreparation,
        source: &Rc<PacketCompleteSemanticSource>,
        planned_id: &Id,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
    ) -> Result<CompleteOriginalFreshRestoreHostWindow, RuntimeError> {
        preparation.authenticate_original_fresh_query_preparation_data(source)?;
        preparation.authenticate_original_fresh_query_plan_data(self)?;
        preparation.claim_original_fresh_query_window_data(source)?;
        let scope = OriginalFreshRestoreHostScope {
            plan: self,
            preparation,
            source,
            planned_id,
            registry,
            supervisor,
        };
        let policy = self
            .0
            .authority
            .original_fresh_restore_host_policy(self.evidence(), &scope)?;
        let fixed = Self::original_fresh_restore_host_counter_scratch_data()?;
        if fixed > policy.maximum_requested_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        if policy.declared_observer_scratch_bytes < fixed
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = self.0.authority.authenticate_original_fresh_restore_host(
            self.evidence(),
            &scope,
            &policy,
        )?;
        let preparation_bytes = observe(&scope, scratch, policy.maximum_requested_bytes)?;
        let current_validation_bytes =
            preparation.original_fresh_query_current_storage_data(source)?;
        let quote = preparation.quote_original_fresh_query_storage_data(source, planned_id)?;
        let ticket = CompleteOriginalFreshRestoreHostWindow {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: Rc::downgrade(source),
            plan: self.downgrade(),
            original_owner: preparation.original_fresh_query_owner_identity_data(source)?,
            quote,
            maximum_requested_bytes: policy.maximum_requested_bytes,
            preparation_bytes,
            current_validation_bytes,
            registry: registry.map(|value| std::ptr::from_ref(value).cast()),
            supervisor: supervisor.map(|value| std::ptr::from_ref(value).cast()),
            rechecked: std::cell::Cell::new(false),
            spent: false,
        };
        let retained_ticket = checked_sum(
            [
                size_of::<CompleteOriginalFreshRestoreHostWindow>(),
                ticket.retained_requested_storage_precredit_data(policy.maximum_requested_bytes)?,
            ],
            policy.maximum_requested_bytes,
        )?;
        let phase = checked_sum(
            [
                ticket.quote.maximum_simultaneous_transient_bytes(),
                current_validation_bytes,
                fixed,
                ticket.quote.declared_counter_scratch_bytes(),
            ],
            policy.maximum_requested_bytes,
        )?;
        let observation = checked_sum(
            [
                policy.declared_observer_scratch_bytes,
                storage.maximum_simultaneous_transient_bytes,
            ],
            policy.maximum_requested_bytes,
        )?;
        checked_sum(
            [
                storage.retained_holder_bytes,
                preparation_bytes,
                retained_ticket,
                ticket.quote.retained_growth_bytes(),
                phase.max(observation),
            ],
            policy.maximum_requested_bytes,
        )?;
        // Currency and all actual retained rows are rechecked after callbacks.
        let current_policy = self
            .0
            .authority
            .original_fresh_restore_host_policy(self.evidence(), &scope)?;
        let current_storage = self.0.authority.authenticate_original_fresh_restore_host(
            self.evidence(),
            &scope,
            &policy,
        )?;
        if current_policy != policy
            || current_storage.retained_holder_bytes > storage.retained_holder_bytes
            || current_storage.maximum_simultaneous_transient_bytes
                > storage.maximum_simultaneous_transient_bytes
            || preparation.original_fresh_query_current_storage_data(source)?
                > current_validation_bytes
            || observe(&scope, scratch, policy.maximum_requested_bytes)? > preparation_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        ticket.origin()?;
        Ok(ticket)
    }
}

fn observe(
    scope: &OriginalFreshRestoreHostScope<'_>,
    scratch: &CnpPreparationStorageScratch,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    scope
        .preparation
        .authenticate_original_fresh_query_preparation_data(scope.source)?;
    scope
        .preparation
        .retained_requested_storage_precredit_data(
            scratch,
            scope.registry,
            scope.supervisor,
            maximum,
        )?
        .complete_requested_bytes_precredit_data()
}

fn checked_sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    terms.into_iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

/// Borrows raw original holder identities while the preparation is mutably held.
///
/// This scope carries no preparation bank loan or requested byte setter.
pub struct OriginalFreshRestoreHostMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a Rc<PacketCompleteSemanticSource>,
}

impl OriginalFreshRestoreHostMemberScope<'_> {
    /// Borrows the genuine installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }
    /// Borrows the same original Source allocation.
    pub fn source(&self) -> &Rc<PacketCompleteSemanticSource> {
        self.source
    }
    /// Compares the actual plan allocation without a callback.
    pub fn is_original_plan(&self, other: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &other.0)
    }
    /// Compares the actual installed authority without invoking it.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

impl CompleteOriginalFreshRestoreHostWindow {
    pub(crate) fn original_source_data(
        &self,
    ) -> Result<Rc<PacketCompleteSemanticSource>, RuntimeError> {
        self.origin()?;
        self.source.upgrade().ok_or(RuntimeError::ForeignAuthority)
    }
    pub(crate) fn authenticate_holder_data(
        &self,
        plan: &InstalledConformancePlan,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let scope = OriginalFreshRestoreHostMemberScope { plan, source };
        plan.0
            .authority
            .authenticate_original_fresh_restore_host_member(plan.evidence(), &scope)
    }
}

impl CompleteOriginalFreshRestoreHostWindow {
    pub(crate) fn quote_data(&self) -> &OriginalFreshRestoreQueryStorageData {
        &self.quote
    }
}

#[path = "fresh_restore_host/initial_node.rs"]
mod initial_node;
