//! Admits the same original native baseline before private parsing or Child birth.
//!
//! The installed resource action observes its actual holder and fixed Source
//! roster, then admits separately compiled private-bootstrap, native-birth and
//! optional pre-MAC Prepare phases. Report and HOST query actions remain separate.
//! No row, serialized body or numeric limit can construct a member.

use std::{
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

use crucible_node_provider::reference_packet::service::{
    PacketNative5SourceLaunch, native_startup::PacketNativeStartupAllocationRow,
};

use super::{InstalledConformancePlan, WeakInstalledConformancePlan};
use crate::{node_adapters::cnp::PacketCompleteSemanticSource, node_contract::RuntimeError};

/// Borrows the actual original policy roster and both retained launch views.
///
/// Core constructs this scope. The policy compares each reference against its
/// registered holder; byte equality cannot replace the original association.
pub struct OriginalNativeStartupScope<'a> {
    plan: &'a InstalledConformancePlan,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    launches: &'a [PacketNative5SourceLaunch; 3],
    encoded_launches: &'a [Vec<u8>; 3],
}

impl OriginalNativeStartupScope<'_> {
    /// Borrows the same actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the fixed actual producer, relay and sink Sources.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows their typed launches without constructing or serializing a DTO.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }

    /// Borrows the independent encodings retained from the same installation.
    pub fn encoded_launches(&self) -> &[Vec<u8>; 3] {
        self.encoded_launches
    }

    /// Compares the exact plan allocation without a live callback.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the retained policy object without reauthentication work.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Carries the installed baseline resource action and its observer allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalNativeStartupPolicy {
    /// Bounds the complete actual holder, Sources and all new native owners.
    pub maximum_requested_bytes: usize,
    /// Precredits actual concrete holder and source/compiled-producer observers.
    pub declared_observer_scratch_bytes: usize,
}

/// Separates actual registered host owners from the independently observed Sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalNativeStartupStorage {
    /// Counts all actual holder, code, policy, plan, Host and receiver roots.
    pub retained_holder_bytes: usize,
    /// Bounds its entire simultaneous additional observation/construction phase.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Precharges each original launch's full retained, transient and scratch row.
    pub prospective_host_launch_requested_bytes: [usize; 3],
}

/// Borrows the same private member's policy and Source without a live callback.
pub struct OriginalNativeStartupMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a PacketCompleteSemanticSource,
}

impl OriginalNativeStartupMemberScope<'_> {
    /// Borrows the actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the original Source allocation.
    pub fn source(&self) -> &PacketCompleteSemanticSource {
        self.source
    }

    /// Compares the exact plan without renewing it.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the actual authority before its raw same-holder callback.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

// This fixed primitive projection owns no schema String or body before credit.
// The actual Binding14 allocation object is constructed only after consumption.
#[derive(Clone, Copy)]
pub(crate) struct NativeStartupRows {
    pub(crate) private_bootstrap: PacketNativeStartupAllocationRow,
    pub(crate) native_birth: PacketNativeStartupAllocationRow,
    pub(crate) restore_prepare: Option<PacketNativeStartupAllocationRow>,
}

impl NativeStartupRows {
    fn peak(self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut retained = 0;
        let mut phase = 0;
        for row in [
            Some(self.private_bootstrap),
            Some(self.native_birth),
            self.restore_prepare,
        ]
        .into_iter()
        .flatten()
        {
            row.requested_peak_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            retained = add(
                retained,
                extent(row.retained_requested_bytes.get())?,
                maximum,
            )?;
            phase = phase.max(add(
                extent(row.maximum_simultaneous_transient_bytes.get())?,
                extent(row.declared_counter_scratch_bytes.get())?,
                maximum,
            )?);
        }
        add(retained, phase, maximum)
    }
}

pub(crate) struct OriginalNativeStartupQuote {
    pub(crate) rows: NativeStartupRows,
    pub(crate) finalization_bytes: usize,
    pub(crate) wire_requested_bytes: usize,
    pub(crate) publication_bytes: usize,
    pub(crate) launch_digest: [u8; 32],
    pub(crate) maximum_boot_bytes: usize,
}

/// Retains Core's original once-consumed baseline allocation admission.
///
/// No constructor, Clone or serialization exists. It authorizes only the
/// separately named allocation phases; post-Hello MAC, semantic, activation,
/// Capture and whole restoration rights remain independent.
pub struct CompleteOriginalNativeStartupAdmission<'a> {
    scope: OriginalNativeStartupScope<'a>,
    process: u32,
    thread: ThreadId,
    policy: OriginalNativeStartupPolicy,
    storage: OriginalNativeStartupStorage,
    quotes: [OriginalNativeStartupQuote; 3],
    source_bytes: [usize; 3],
    spent: [bool; 3],
    requested_peak: usize,
}

impl InstalledConformancePlan {
    /// Quotes the actual fixed Core and Source baseline-observation layouts.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn original_native_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        sum(&[size_of::<CompleteOriginalNativeStartupAdmission<'_>>(),
            size_of::<OriginalNativeStartupScope<'_>>(),
            size_of::<OriginalNativeStartupMemberScope<'_>>(),
            size_of::<[OriginalNativeStartupQuote; 3]>(),
            size_of::<[Option<OriginalNativeStartupQuote>; 3]>(),
            crate::node_adapters::cnp::CnpSemanticLaunchReservation::unlaunched_storage_counter_scratch_data(),
            PacketCompleteSemanticSource::original_native_startup_counter_scratch_data()?], usize::MAX)
    }

    /// Admits native baseline allocations on the same actual pre-Child roster.
    ///
    /// All three real compiled quotes must be complete. Missing private-parser,
    /// native-birth or selected Prepare phases refuse before a member exists.
    /// The holder retains the returned admission throughout finalization.
    ///
    /// # Errors
    /// Refuses unsupported policy, foreign/spent owners, unknown actual backing,
    /// incomplete compiled phases or any checked aggregate storage overrun.
    pub fn reserve_original_native_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalNativeStartupAdmission<'a>, RuntimeError> {
        let scope = OriginalNativeStartupScope {
            plan: self,
            sources,
            launches,
            encoded_launches,
        };
        let policy = self
            .0
            .authority
            .original_native_startup_policy(&self.evidence(), &scope)?;
        let fixed = Self::original_native_startup_counter_scratch_data()?;
        if fixed > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
            || policy.maximum_requested_bytes == 0
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = self.0.authority.authenticate_original_native_startup(
            &self.evidence(),
            &scope,
            &policy,
        )?;
        let mut source_bytes = [0; 3];
        if storage.prospective_host_launch_requested_bytes.contains(&0) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let mut observed = sum(
            &storage.prospective_host_launch_requested_bytes,
            policy.maximum_requested_bytes,
        )?;
        observed = add(
            observed,
            storage.retained_holder_bytes,
            policy.maximum_requested_bytes,
        )?;
        let mut pending = [None, None, None];
        for index in 0..3 {
            if (0..index).any(|previous| Rc::ptr_eq(&sources[previous], &sources[index])) {
                return Err(RuntimeError::ForeignAuthority);
            }
            source_bytes[index] = sources[index]
                .original_complete_report_startup_retained_storage_precredit_data(
                    policy.maximum_requested_bytes,
                )?;
            observed = add(
                observed,
                source_bytes[index],
                policy.maximum_requested_bytes,
            )?;
            let quote = sources[index].original_native_startup_quote_data(
                &launches[index],
                &encoded_launches[index],
                policy.maximum_requested_bytes,
            )?;
            observed = add(
                observed,
                quote.rows.peak(policy.maximum_requested_bytes)?,
                policy.maximum_requested_bytes,
            )?;
            observed = add(
                observed,
                quote.finalization_bytes,
                policy.maximum_requested_bytes,
            )?;
            observed = add(
                observed,
                quote.publication_bytes,
                policy.maximum_requested_bytes,
            )?;
            pending[index] = Some(quote);
        }
        observed = add(
            observed,
            add(
                policy.declared_observer_scratch_bytes,
                storage.maximum_simultaneous_transient_bytes,
                policy.maximum_requested_bytes,
            )?,
            policy.maximum_requested_bytes,
        )?;
        let [a, b, c] = pending;
        let admission = CompleteOriginalNativeStartupAdmission {
            scope,
            process: std::process::id(),
            thread: std::thread::current().id(),
            policy,
            storage,
            quotes: [
                a.ok_or(RuntimeError::OwnerUnavailable)?,
                b.ok_or(RuntimeError::OwnerUnavailable)?,
                c.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            source_bytes,
            spent: [false; 3],
            requested_peak: observed,
        };
        admission.recheck()?;
        Ok(admission)
    }
}

impl CompleteOriginalNativeStartupAdmission<'_> {
    /// Returns the actual admitted requested-storage conjunction as data.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Consumes one original member before Source changes its private birth.
    ///
    /// # Errors
    /// Refuses a foreign/repeated member, changed holder or widened owner. A
    /// failed finalization stays spent and retains its same partial Source owner.
    pub fn finalize_original_source(&mut self, index: usize) -> Result<(), RuntimeError> {
        self.origin()?;
        if index >= 3 || self.spent[index] {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.recheck()?;
        let source = &self.scope.sources[index];
        let quote = &self.quotes[index];
        let actual = source.original_native_startup_quote_data(
            &self.scope.launches[index],
            &self.scope.encoded_launches[index],
            self.policy.maximum_requested_bytes,
        )?;
        for (allowed, observed) in [
            (
                Some(quote.rows.private_bootstrap),
                Some(actual.rows.private_bootstrap),
            ),
            (
                Some(quote.rows.native_birth),
                Some(actual.rows.native_birth),
            ),
            (quote.rows.restore_prepare, actual.rows.restore_prepare),
        ] {
            match (allowed, observed) {
                (Some(allowed), Some(observed)) => allowed
                    .authenticate_actual_data(&observed)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                (None, None) => {}
                _ => return Err(RuntimeError::ForeignAuthority),
            }
        }
        if actual.launch_digest != quote.launch_digest
            || actual.maximum_boot_bytes > quote.maximum_boot_bytes
            || actual.finalization_bytes > quote.finalization_bytes
            || actual.wire_requested_bytes > quote.wire_requested_bytes
            || actual.publication_bytes > quote.publication_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.spent[index] = true;
        let member = OriginalNativeStartupMember {
            process: self.process,
            thread: self.thread,
            source: Rc::downgrade(source),
            plan: self.scope.plan.downgrade(),
            rows: quote.rows,
            finalization_bytes: quote.finalization_bytes,
            wire_requested_bytes: quote.wire_requested_bytes,
            host_launch_requested_bytes: self.storage.prospective_host_launch_requested_bytes
                [index],
            launch_digest: quote.launch_digest,
            maximum_boot_bytes: quote.maximum_boot_bytes,
        };
        source.finalize_original_native_startup_birth(member, &self.scope.launches[index])?;
        self.recheck()?;
        source.complete_original_native_startup_birth()?;
        self.origin()
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

    fn recheck(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        let authority = &self.scope.plan.0.authority;
        if authority.original_native_startup_policy(&self.scope.plan.evidence(), &self.scope)?
            != self.policy
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let actual = authority.authenticate_original_native_startup(
            &self.scope.plan.evidence(),
            &self.scope,
            &self.policy,
        )?;
        if actual.retained_holder_bytes > self.storage.retained_holder_bytes
            || actual.maximum_simultaneous_transient_bytes
                > self.storage.maximum_simultaneous_transient_bytes
            || actual.prospective_host_launch_requested_bytes
                != self.storage.prospective_host_launch_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        for index in 0..3 {
            let actual = self.scope.sources[index]
                .original_complete_report_startup_retained_storage_precredit_data(
                    self.policy.maximum_requested_bytes,
                )?;
            let allowed = add(
                self.source_bytes[index],
                if self.spent[index] {
                    self.quotes[index].finalization_bytes
                } else {
                    0
                },
                self.policy.maximum_requested_bytes,
            )?;
            if actual > allowed {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        self.origin()
    }
}

pub(crate) struct OriginalNativeStartupMember {
    process: u32,
    thread: ThreadId,
    source: Weak<PacketCompleteSemanticSource>,
    plan: WeakInstalledConformancePlan,
    pub(crate) rows: NativeStartupRows,
    pub(crate) finalization_bytes: usize,
    pub(crate) wire_requested_bytes: usize,
    pub(crate) host_launch_requested_bytes: usize,
    pub(crate) launch_digest: [u8; 32],
    pub(crate) maximum_boot_bytes: usize,
}

impl OriginalNativeStartupMember {
    pub(crate) fn retained_shared_storage_data(&self) -> Result<usize, RuntimeError> {
        self.plan
            .retained_allocation_bytes()
            .checked_add(
                crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                    PacketCompleteSemanticSource,
                >(),
            )
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(crate) fn authenticate(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source.as_ptr(), source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let scope = OriginalNativeStartupMemberScope {
            plan: &plan,
            source,
        };
        plan.0
            .authority
            .authenticate_original_native_startup_member(&plan.evidence(), &scope)
    }
}

fn extent(value: u64) -> Result<usize, RuntimeError> {
    usize::try_from(value).map_err(|_| RuntimeError::ResourceLimit)
}

fn add(a: usize, b: usize, maximum: usize) -> Result<usize, RuntimeError> {
    a.checked_add(b)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values
        .iter()
        .try_fold(0, |total, value| add(total, *value, maximum))
}
