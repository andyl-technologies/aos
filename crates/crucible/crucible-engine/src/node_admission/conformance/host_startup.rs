//! Admits original host SDK constructors under the same installed resource policy.
//!
//! This action is distinct from native birth, publication and post-Admit HOST
//! queries. It charges actual existing input owners and independently compiled
//! host constructors before Source consumes a private member. A returned data
//! quote cannot issue a member or authorize an unrelated controller.

use std::{
    collections::BTreeMap,
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

use crucible_node_format::ContentRef;
use crucible_node_transport::{
    client::PacketNativeHostStartupStorageData,
    reference_packet::service::PacketNative5SourceLaunch,
};

use super::{InstalledConformancePlan, WeakInstalledConformancePlan};
use crate::{node_adapters::cnp::PacketCompleteSemanticSource, node_contract::RuntimeError};

type ContentBank = BTreeMap<ContentRef, Vec<u8>>;

/// Borrows the actual registered Source roster and immutable constructor inputs.
pub struct OriginalNativeHostStartupScope<'a> {
    plan: &'a InstalledConformancePlan,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    launches: &'a [PacketNative5SourceLaunch; 3],
    content: &'a [Rc<ContentBank>; 3],
}

impl OriginalNativeHostStartupScope<'_> {
    /// Borrows the same installed original plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows its fixed original Source allocations.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows the exact typed launches retained by the installed holder.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }

    /// Borrows actual immutable promised-content owners without copying bodies.
    pub fn content(&self) -> &[Rc<ContentBank>; 3] {
        self.content
    }

    /// Compares the same immutable typed launch bank before any owner walk.
    pub fn is_original_launches(&self, actual: &[PacketNative5SourceLaunch; 3]) -> bool {
        std::ptr::eq(self.launches, actual)
    }

    /// Compares each actual Source allocation in the fixed original roster.
    pub fn is_original_sources(&self, actual: &[Rc<PacketCompleteSemanticSource>; 3]) -> bool {
        self.sources
            .iter()
            .zip(actual)
            .all(|(source, original)| Rc::ptr_eq(source, original))
    }

    /// Compares the retained immutable content allocations without encoding.
    pub fn is_original_content(&self, actual: &[Rc<ContentBank>; 3]) -> bool {
        self.content
            .iter()
            .zip(actual)
            .all(|(bank, original)| Rc::ptr_eq(bank, original))
    }

    /// Compares the actual plan allocation without renewing its authority.
    pub fn is_original_plan(&self, actual: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &actual.0)
    }

    /// Compares the exact installed authority before its raw data callback.
    pub fn is_original_authority(&self, actual: &dyn super::ConformanceAdmissionAuthority) -> bool {
        self.plan.has_authority(actual)
    }
}

/// Carries the actual installed policy and precredited observer window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalNativeHostStartupPolicy {
    /// Bounds the entire retained holder, Sources and new host SDK owners.
    pub maximum_requested_bytes: usize,
    /// Admits compiled observer/result headers before the first owner walk.
    pub declared_observer_scratch_bytes: usize,
}

/// Separates existing registered holder storage from independently walked Sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalNativeHostStartupStorage {
    /// Counts actual policy, launch custody, code, content and existing SDK roots.
    pub retained_holder_bytes: usize,
    /// Bounds the holder's simultaneous observation and source-guard phase.
    pub maximum_simultaneous_transient_bytes: usize,
}

/// Borrows one same-source private member for a bank-free currency callback.
pub struct OriginalNativeHostStartupMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a PacketCompleteSemanticSource,
    content: &'a Rc<ContentBank>,
    require_completed: bool,
}

impl OriginalNativeHostStartupMemberScope<'_> {
    /// Borrows the actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the original Source allocation.
    pub fn source(&self) -> &PacketCompleteSemanticSource {
        self.source
    }

    /// Borrows the same immutable promised-content bank.
    pub fn content(&self) -> &Rc<ContentBank> {
        self.content
    }

    /// Requires the same holder's complete constructor action before transport.
    pub fn requires_completed_construction(&self) -> bool {
        self.require_completed
    }

    /// Compares the actual plan without invoking live currentness callbacks.
    pub fn is_original_plan(&self, actual: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &actual.0)
    }

    /// Compares the actual installed authority.
    pub fn is_original_authority(&self, actual: &dyn super::ConformanceAdmissionAuthority) -> bool {
        self.plan.has_authority(actual)
    }
}

/// Owns Core's once-consumed action for the three original host SDK births.
///
/// It has no public constructor, clone or serializer. Each Source retains its
/// private member before an SDK allocation. Errors leave that member spent;
/// dropping this admission cannot replace an already attempted constructor.
pub struct CompleteOriginalNativeHostStartupAdmission<'a> {
    scope: OriginalNativeHostStartupScope<'a>,
    policy: OriginalNativeHostStartupPolicy,
    storage: OriginalNativeHostStartupStorage,
    quotes: [OriginalNativeHostStartupQuote; 3],
    source_bytes: [usize; 3],
    spent: [bool; 3],
    creator: u32,
    thread: ThreadId,
    requested_peak: usize,
}

impl InstalledConformancePlan {
    /// Counts compiled Core, Source and SDK host-constructor observer headers.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn original_native_host_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        sum(
            &[
                size_of::<CompleteOriginalNativeHostStartupAdmission<'_>>(),
                size_of::<OriginalNativeHostStartupScope<'_>>(),
                size_of::<OriginalNativeHostStartupMemberScope<'_>>(),
                size_of::<[Option<OriginalNativeHostStartupQuote>; 3]>(),
                PacketCompleteSemanticSource::original_native_host_startup_counter_scratch_data()?,
            ],
            usize::MAX,
        )
    }

    /// Admits the original host SDK constructors before their first allocation.
    ///
    /// All inputs belong to the same registered holder. Source checks its actual
    /// private birth and previously finalized native action independently. This
    /// grant ends at an unused SDK controller; initial control methods, native
    /// completion, preparation, activation and capture rights remain separate.
    ///
    /// # Errors
    /// Refuses unknown policy/owners, foreign or spent Sources, incomplete
    /// constructor counters, conflicting loans or any requested-storage overrun.
    pub fn reserve_original_native_host_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        content: &'a [Rc<ContentBank>; 3],
    ) -> Result<CompleteOriginalNativeHostStartupAdmission<'a>, RuntimeError> {
        let scope = OriginalNativeHostStartupScope {
            plan: self,
            sources,
            launches,
            content,
        };
        let policy = self
            .0
            .authority
            .original_native_host_startup_policy(&self.evidence(), &scope)?;
        let fixed = Self::original_native_host_startup_counter_scratch_data()?;
        if policy.maximum_requested_bytes == 0
            || fixed > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = self.0.authority.authenticate_original_native_host_startup(
            &self.evidence(),
            &scope,
            &policy,
        )?;
        let mut observed = sum(
            &[
                storage.retained_holder_bytes,
                storage.maximum_simultaneous_transient_bytes,
                policy.declared_observer_scratch_bytes,
            ],
            policy.maximum_requested_bytes,
        )?;
        let mut pending = [None, None, None];
        let mut source_bytes = [0; 3];
        for index in 0..3 {
            if (0..index).any(|earlier| Rc::ptr_eq(&sources[earlier], &sources[index])) {
                return Err(RuntimeError::ForeignAuthority);
            }
            source_bytes[index] = sources[index]
                .original_complete_report_startup_retained_storage_precredit_data(
                    policy.maximum_requested_bytes,
                )?;
            let quote = sources[index].original_native_host_startup_quote_data(
                &launches[index],
                &content[index],
                policy.maximum_requested_bytes,
            )?;
            observed = sum(
                &[observed, source_bytes[index], quote.requested_peak_data()?],
                policy.maximum_requested_bytes,
            )?;
            pending[index] = Some(quote);
        }
        let [a, b, c] = pending;
        let result = CompleteOriginalNativeHostStartupAdmission {
            scope,
            policy,
            storage,
            quotes: [
                a.ok_or(RuntimeError::OwnerUnavailable)?,
                b.ok_or(RuntimeError::OwnerUnavailable)?,
                c.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            source_bytes,
            spent: [false; 3],
            creator: std::process::id(),
            thread: std::thread::current().id(),
            requested_peak: observed,
        };
        result.recheck()?;
        Ok(result)
    }
}

impl CompleteOriginalNativeHostStartupAdmission<'_> {
    /// Returns the actual admitted conjunction as data.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Installs one private Source member before constructing any SDK owner.
    ///
    /// # Errors
    /// Refuses a repeated/foreign member, changed owners, widening or SDK
    /// construction failure. The original Source and partial output stay held.
    pub fn prepare_original_source_into(
        &mut self,
        index: usize,
        completed: &mut Option<crate::node_adapters::cnp::PacketCompleteOriginalHostSdk>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if index >= 3 || self.spent[index] || completed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        // The caller owns the output slot mutably here. Whole holder data
        // callbacks run before that loan and after it is dropped, never while
        // the registered constructor bank is mutably borrowed.
        self.spent[index] = true;
        let member = OriginalNativeHostStartupMember {
            source: Rc::downgrade(&self.scope.sources[index]),
            plan: self.scope.plan.downgrade(),
            content: Rc::downgrade(&self.scope.content[index]),
            quote: self.quotes[index],
            creator: self.creator,
            thread: self.thread,
        };
        self.scope.sources[index].prepare_original_native_host_sdk_into(
            &self.scope.launches[index],
            &self.scope.content[index],
            member,
            completed,
        )?;
        self.origin()
    }

    /// Rechecks the actual complete holder after ending every mutable output loan.
    ///
    /// # Errors
    /// Refuses changed policy/owners, incomplete data or a widened actual row.
    pub fn recheck_original_inputs_data(&self) -> Result<(), RuntimeError> {
        self.recheck()
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    fn recheck(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        let actual = self
            .scope
            .plan
            .0
            .authority
            .authenticate_original_native_host_startup(
                &self.scope.plan.evidence(),
                &self.scope,
                &self.policy,
            )?;
        let spent_retained = self
            .spent
            .iter()
            .zip(&self.quotes)
            .filter(|(spent, _)| **spent)
            .try_fold(0usize, |total, (_, quote)| {
                total
                    .checked_add(quote.retained_requested_bytes())
                    .ok_or(RuntimeError::ResourceLimit)
            })?;
        if actual.retained_holder_bytes
            > self
                .storage
                .retained_holder_bytes
                .checked_add(spent_retained)
                .ok_or(RuntimeError::ResourceLimit)?
            || actual.maximum_simultaneous_transient_bytes
                > self.storage.maximum_simultaneous_transient_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        for index in 0..3 {
            let source = &self.scope.sources[index];
            let allowed_source = self.source_bytes[index]
                .checked_add(if self.spent[index] {
                    self.quotes[index].source_retained_bytes
                } else {
                    0
                })
                .ok_or(RuntimeError::ResourceLimit)?;
            if source.original_complete_report_startup_retained_storage_precredit_data(
                self.policy.maximum_requested_bytes,
            )? > allowed_source
            {
                return Err(RuntimeError::ResourceLimit);
            }
            if !self.spent[index] {
                let quote = source.original_native_host_startup_quote_data(
                    &self.scope.launches[index],
                    &self.scope.content[index],
                    self.policy.maximum_requested_bytes,
                )?;
                if quote.retained_requested_bytes() > self.quotes[index].retained_requested_bytes()
                    || quote.maximum_simultaneous_transient_bytes()
                        > self.quotes[index].maximum_simultaneous_transient_bytes()
                    || quote.declared_counter_scratch_bytes()
                        > self.quotes[index].declared_counter_scratch_bytes()
                    || quote.prior_commitment_peak > self.quotes[index].prior_commitment_peak
                {
                    return Err(RuntimeError::ResourceLimit);
                }
            }
        }
        self.origin()
    }
}

pub(crate) struct OriginalNativeHostStartupMember {
    source: Weak<PacketCompleteSemanticSource>,
    plan: WeakInstalledConformancePlan,
    content: Weak<ContentBank>,
    pub(crate) quote: OriginalNativeHostStartupQuote,
    creator: u32,
    thread: ThreadId,
}

impl OriginalNativeHostStartupMember {
    pub(crate) fn authenticate(
        &self,
        source: &PacketCompleteSemanticSource,
        content: &Rc<ContentBank>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_phase(source, content, false)
    }

    pub(crate) fn authenticate_for_connection(
        &self,
        source: &PacketCompleteSemanticSource,
        content: &Rc<ContentBank>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_phase(source, content, true)
    }

    fn authenticate_phase(
        &self,
        source: &PacketCompleteSemanticSource,
        content: &Rc<ContentBank>,
        require_completed: bool,
    ) -> Result<(), RuntimeError> {
        if self.creator != std::process::id()
            || !std::ptr::eq(self.source.as_ptr(), source)
            || !Weak::ptr_eq(&self.content, &Rc::downgrade(content))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let scope = OriginalNativeHostStartupMemberScope {
            plan: &plan,
            source,
            content,
            require_completed,
        };
        plan.0
            .authority
            .authenticate_original_native_host_startup_member(&plan.evidence(), &scope)
    }
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(*value)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

#[derive(Clone, Copy)]
pub(crate) struct OriginalNativeHostStartupQuote {
    pub(crate) sdk: PacketNativeHostStartupStorageData,
    pub(crate) source_retained_bytes: usize,
    retained_requested_bytes: usize,
    source_guard_window: usize,
    pub(crate) prior_commitment_peak: usize,
}

impl OriginalNativeHostStartupQuote {
    pub(crate) fn new(
        sdk: PacketNativeHostStartupStorageData,
        source_retained_bytes: usize,
        source_guard_window: usize,
        prior_commitment_peak: usize,
    ) -> Result<Self, RuntimeError> {
        let retained_requested_bytes = sdk
            .retained_requested_bytes()
            .checked_add(source_retained_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        sdk.requested_peak_data()
            .map_err(|_| RuntimeError::ResourceLimit)?
            .checked_add(source_retained_bytes)
            .and_then(|bytes| bytes.checked_add(source_guard_window))
            .and_then(|bytes| bytes.checked_add(prior_commitment_peak))
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(Self {
            sdk,
            source_retained_bytes,
            retained_requested_bytes,
            source_guard_window,
            prior_commitment_peak,
        })
    }

    fn retained_requested_bytes(&self) -> usize {
        self.retained_requested_bytes
    }

    fn maximum_simultaneous_transient_bytes(&self) -> usize {
        // The selected Source guard runs around SDK transport. Its complete
        // fixed/link window is conservatively conjoined with the SDK phase.
        self.sdk
            .maximum_simultaneous_transient_bytes()
            .max(self.source_guard_window)
    }

    fn declared_counter_scratch_bytes(&self) -> usize {
        self.sdk.declared_counter_scratch_bytes()
    }

    pub(crate) fn requested_peak_data(&self) -> Result<usize, RuntimeError> {
        self.sdk
            .requested_peak_data()
            .map_err(|_| RuntimeError::ResourceLimit)?
            .checked_add(self.source_retained_bytes)
            .and_then(|bytes| bytes.checked_add(self.source_guard_window))
            .and_then(|bytes| bytes.checked_add(self.prior_commitment_peak))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl OriginalNativeHostStartupMember {
    pub(crate) fn original_source_data(
        &self,
    ) -> Result<Rc<PacketCompleteSemanticSource>, RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        self.source.upgrade().ok_or(RuntimeError::ForeignAuthority)
    }

    pub(crate) fn original_content_data(&self) -> Result<Rc<ContentBank>, RuntimeError> {
        self.content.upgrade().ok_or(RuntimeError::ForeignAuthority)
    }
}

impl OriginalNativeHostStartupMember {
    pub(crate) fn authenticate_original_plan_data(
        &self,
        actual: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let original = self
            .plan
            .0
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(&original, &actual.0) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn original_initial_guard_window_data(&self) -> usize {
        self.quote.source_guard_window
    }

    pub(crate) fn remaining_initial_lifecycle_commitments_data(
        &self,
        include_pending_host: bool,
    ) -> Result<usize, RuntimeError> {
        // The actual holder counts current SDK backing independently. Retain
        // the full remaining constructor/Hello row conservatively while it is
        // pending; do not relabel future Controller backing as current usage.
        // The selected new lifecycle row includes this same future window, so
        // its private caller excludes this term once, never the other peers'.
        let remaining_hello = if !include_pending_host {
            0
        } else {
            sum(
                &[
                    self.quote.sdk.retained_requested_bytes(),
                    self.quote.sdk.maximum_simultaneous_transient_bytes(),
                    self.quote.sdk.declared_counter_scratch_bytes(),
                    self.quote.source_guard_window,
                ],
                usize::MAX,
            )?
        };
        sum(
            &[self.quote.prior_commitment_peak, remaining_hello],
            usize::MAX,
        )
    }
}
