//! Admits original report publication before a selected private boot can start.
//!
//! The actual installed policy authenticates its original pre-Child holder and
//! immutable launch roster. Core counts those owners and the three real Sources,
//! then admits the closed compiled publication projections. Only this path can
//! issue the once-spent member consumed by Source's private-birth finalizer.
//! Report data, archive tickets and numeric codec limits cannot construct one.

use std::{
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

use crucible_node_format::U64;
use crucible_node_transport::reference_packet::service::{
    PacketNative5SourceLaunch,
    report_startup::{
        PacketNativeReportStartupAllocationRow, PacketNativeReportStartupPurpose,
        original_report_startup_counter_scratch_data, original_report_startup_storage_data,
    },
};

use super::{EvidenceError, InstalledConformancePlan, WeakInstalledConformancePlan, failure};
use crate::node_adapters::cnp::PacketCompleteSemanticSource;

/// Borrows the same installed plan and original fixed producer/relay/sink roster.
///
/// Only Core constructs this scope. Its borrowed values must be compared with
/// the actual registered holder; equivalent serialized data is insufficient.
pub struct OriginalReportStartupScope<'a> {
    plan: &'a InstalledConformancePlan,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    launches: &'a [PacketNative5SourceLaunch; 3],
}

impl OriginalReportStartupScope<'_> {
    /// Borrows the actual installed original plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Checks the exact installed plan allocation without invoking its callbacks.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Checks the actual installed policy object before any observer is entered.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }

    /// Borrows the original fixed Source roster without cloning an owner.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows the immutable original typed launches without encoding them.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }
}

/// Borrows a privately issued startup member's actual plan and Source.
///
/// Core constructs this scope only after checking the member's original creator
/// and weak Source identity. The installed authority checks its same registered
/// holder and revision using borrowed identity data; ordinary live-plan callbacks
/// and their hashing, kernel or serialization work do not belong to this phase.
pub struct OriginalReportStartupMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a PacketCompleteSemanticSource,
}

impl OriginalReportStartupMemberScope<'_> {
    /// Borrows the actual retained plan without invoking its callbacks.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the exact original member Source without cloning an owner.
    pub fn source(&self) -> &PacketCompleteSemanticSource {
        self.source
    }

    /// Checks the exact installed plan allocation without invoking its callbacks.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Checks the installed policy object without invoking its callbacks.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Carries the installed action's resource policy and its observer scratch.
///
/// This callback result is data. A caller cannot turn it into a startup member;
/// Core invokes the actual retained authority and checks all owning terms first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalReportStartupPolicy {
    /// Bounds the complete admitted holder, Sources and prospective publication.
    pub maximum_requested_bytes: usize,
    /// Includes the actual declared holder/counter observation scratch.
    pub declared_observer_scratch_bytes: usize,
}

/// Observes the actual registered pre-Child holder separately from its Sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalReportStartupStorage {
    /// Includes the plan/authority/code graph/factory/Host/capsule owning roots.
    pub retained_holder_bytes: usize,
    /// Includes its complete simultaneous non-Source observation/construction phase.
    pub maximum_simultaneous_transient_bytes: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct StartupRows {
    pub(crate) original_observe12: Option<PacketNativeReportStartupAllocationRow>,
    pub(crate) fresh_completed_admit13: Option<PacketNativeReportStartupAllocationRow>,
}

impl StartupRows {
    fn peak(self) -> Result<usize, EvidenceError> {
        let mut retained = 0usize;
        let mut phase = 0usize;
        let mut present = false;
        for row in [self.original_observe12, self.fresh_completed_admit13]
            .into_iter()
            .flatten()
        {
            row.requested_peak_data()
                .map_err(|_| failure("invalid compiled startup row"))?;
            present = true;
            retained = add(retained, extent(row.retained_growth_bytes.get())?)?;
            phase = phase.max(add(
                extent(row.maximum_simultaneous_transient_bytes.get())?,
                extent(row.declared_counter_scratch_bytes.get())?,
            )?);
        }
        if !present {
            return Err(failure("original startup has no selected report purpose"));
        }
        add(retained, phase)
    }
}

/// Retains Core's actual once-only pre-Child publication admission.
///
/// There is no constructor, Clone or serialization implementation. Each member
/// is spent before Source allocates its replacement birth bank. A failed member
/// stays spent and the Source retains its failed construction owners.
/// This admits report publication only; it grants no activation, Prepare MAC,
/// semantic execution, complete Capture or whole-restoration authority.
pub struct CompleteOriginalReportStartupAdmission<'a> {
    scope: OriginalReportStartupScope<'a>,
    process: u32,
    thread: ThreadId,
    policy: OriginalReportStartupPolicy,
    storage: OriginalReportStartupStorage,
    rows: [StartupRows; 3],
    finalization_bytes: [usize; 3],
    source_bytes: [usize; 3],
    spent: [bool; 3],
    requested_peak: usize,
}

impl InstalledConformancePlan {
    pub(crate) fn original_report_startup_plan_header_storage_data() -> usize {
        crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<super::Plan>()
    }

    /// Admits original publication against the actual installed pre-Child policy.
    ///
    /// The installed action must authenticate the original holder and immutable
    /// launches before any owning walk. Sources retain ready, unstarted private
    /// births; no Child, graph, controller, report or future report is needed.
    ///
    /// # Errors
    /// Refuses missing policy, foreign/borrowed/spent Source phases, unknown
    /// holder backing, unavailable compiled projections or any aggregate excess.
    pub fn reserve_original_report_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
    ) -> Result<CompleteOriginalReportStartupAdmission<'a>, EvidenceError> {
        let scope = OriginalReportStartupScope {
            plan: self,
            sources,
            launches,
        };
        let policy = self
            .0
            .authority
            .original_report_startup_policy(self.evidence(), &scope)?;
        let fixed = fixed_scratch(&policy)?;
        let mut budget = Budget::new(policy.maximum_requested_bytes, fixed)?;
        let storage = self.0.authority.authenticate_original_report_startup(
            self.evidence(),
            &scope,
            &policy,
        )?;
        budget.insert(storage.retained_holder_bytes)?;
        budget.insert(storage.maximum_simultaneous_transient_bytes)?;
        let mut rows = [StartupRows::default(); 3];
        let mut finalization_bytes = [0usize; 3];
        let mut source_bytes = [0usize; 3];
        for index in 0..3 {
            for earlier in 0..index {
                if Rc::ptr_eq(&sources[index], &sources[earlier]) {
                    return Err(failure("startup Source roster aliases a different member"));
                }
            }
            let source = &sources[index];
            source
                .authenticate_original_report_startup_launch_data(&launches[index])
                .map_err(|_| failure("original startup Source launch differs"))?;
            source_bytes[index] = source
                .original_complete_report_startup_retained_storage_data(
                    policy.maximum_requested_bytes,
                )
                .map_err(|_| failure("original startup Source owners are unavailable"))?;
            budget.insert(source_bytes[index])?;
            rows[index] = compiled_rows(&launches[index])?;
            budget.insert(rows[index].peak()?)?;
            finalization_bytes[index] = source
                .original_report_startup_finalization_storage_data(
                    &launches[index],
                    rows[index],
                    policy.maximum_requested_bytes,
                )
                .map_err(|_| failure("original birth finalization demand is unavailable"))?;
            // Summing all members is deliberately conservative: successful new
            // birth banks can coexist while a later member is being finalized.
            budget.insert(finalization_bytes[index])?;
        }
        recheck(&scope, &policy, &storage)?;
        Ok(CompleteOriginalReportStartupAdmission {
            scope,
            process: std::process::id(),
            thread: std::thread::current().id(),
            policy,
            storage,
            rows,
            finalization_bytes,
            source_bytes,
            spent: [false; 3],
            requested_peak: budget.used,
        })
    }
}

impl CompleteOriginalReportStartupAdmission<'_> {
    /// Observes the admitted original requested-layout conjunction.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Finalizes one actual Source's same private birth before launch.
    ///
    /// # Errors
    /// Refuses foreign creator/roster, repeated consumption, changed policy or
    /// owner growth. A construction failure remains spent and retained by Source.
    pub fn finalize_original_source(&mut self, index: usize) -> Result<(), EvidenceError> {
        self.ensure_origin()?;
        if index >= 3 || self.spent[index] {
            return Err(failure("original report startup member is absent or spent"));
        }
        self.recheck_sources()?;
        recheck(&self.scope, &self.policy, &self.storage)?;
        let source = &self.scope.sources[index];
        source
            .authenticate_original_report_startup_launch_data(&self.scope.launches[index])
            .map_err(|_| failure("original startup Source changed before consumption"))?;
        let actual = source
            .original_report_startup_finalization_storage_data(
                &self.scope.launches[index],
                self.rows[index],
                self.policy.maximum_requested_bytes,
            )
            .map_err(|_| failure("original birth finalization demand changed"))?;
        if actual > self.finalization_bytes[index] {
            return Err(failure("original birth finalization demand widened"));
        }
        self.spent[index] = true;
        let member = OriginalReportStartupMember {
            plan: self.scope.plan.downgrade(),
            source: Rc::downgrade(source),
            process: self.process,
            thread: self.thread,
            rows: self.rows[index],
            finalization_bytes: self.finalization_bytes[index],
        };
        source
            .finalize_original_report_startup_birth(member, &self.scope.launches[index])
            .map_err(|_| failure("original startup birth finalization failed"))?;
        self.recheck_sources()?;
        recheck(&self.scope, &self.policy, &self.storage)?;
        source
            .complete_original_report_startup_birth(add(
                self.source_bytes[index],
                add(
                    InstalledConformancePlan::original_report_startup_plan_header_storage_data(),
                    crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                        PacketCompleteSemanticSource,
                    >(),
                )?,
            )?)
            .map_err(|_| failure("original startup final custody check refused"))?;
        self.ensure_origin()
    }

    fn recheck_sources(&self) -> Result<(), EvidenceError> {
        for index in 0..3 {
            let observed = self.scope.sources[index]
                .original_complete_report_startup_retained_storage_data(
                    self.policy.maximum_requested_bytes,
                )
                .map_err(|_| failure("original startup Source backing changed"))?;
            let permitted = add(
                self.source_bytes[index],
                if self.spent[index] {
                    add(
                        InstalledConformancePlan::original_report_startup_plan_header_storage_data(
                        ),
                        crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                            PacketCompleteSemanticSource,
                        >(),
                    )?
                } else {
                    0
                },
            )?;
            if observed > permitted {
                return Err(failure("original startup Source backing widened"));
            }
        }
        Ok(())
    }

    fn ensure_origin(&self) -> Result<(), EvidenceError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(failure("foreign original report startup admission"));
        }
        Ok(())
    }
}

pub(crate) struct OriginalReportStartupMember {
    plan: WeakInstalledConformancePlan,
    source: Weak<PacketCompleteSemanticSource>,
    process: u32,
    thread: ThreadId,
    pub(crate) rows: StartupRows,
    pub(crate) finalization_bytes: usize,
}

impl OriginalReportStartupMember {
    pub(crate) fn authenticate(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), EvidenceError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source.as_ptr(), source)
        {
            return Err(failure("foreign original report startup Source member"));
        }
        let plan = self.plan.upgrade()?;
        let scope = OriginalReportStartupMemberScope {
            plan: &plan,
            source,
        };
        plan.0
            .authority
            .authenticate_original_report_startup_member(plan.evidence(), &scope)
    }

    pub(crate) fn retained_shared_storage_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        self.plan
            .retained_allocation_bytes()
            .checked_add(
                crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                    PacketCompleteSemanticSource,
                >(),
            )
            .ok_or(crate::node_contract::RuntimeError::ResourceLimit)
    }

    pub(crate) fn retained_shared_storage_data(&self) -> Result<usize, EvidenceError> {
        // Both weak owners retain their real allocation after the strong owner
        // drops. Live strong-row conjunction may conservatively count it again.
        add(
            self.plan.retained_allocation_bytes(),
            crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                PacketCompleteSemanticSource,
            >(),
        )
    }
}

fn compiled_rows(launch: &PacketNative5SourceLaunch) -> Result<StartupRows, EvidenceError> {
    let mut rows = StartupRows::default();
    for (selected, purpose, slot) in [
        (
            launch.capture_allocation_selection.is_some(),
            PacketNativeReportStartupPurpose::OriginalObserve12,
            &mut rows.original_observe12,
        ),
        (
            launch.fresh_restore_allocation_selection.is_some(),
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            &mut rows.fresh_completed_admit13,
        ),
    ] {
        if selected {
            let data = original_report_startup_storage_data(launch, purpose)
                .map_err(|_| failure("compiled original startup projection refused"))?;
            if data.declared_counter_scratch_bytes()
                > original_report_startup_counter_scratch_data()
            {
                return Err(failure(
                    "compiled startup counter exceeded preadmitted scratch",
                ));
            }
            *slot = Some(PacketNativeReportStartupAllocationRow {
                raw_report_capacity: U64::new(data.raw_report_capacity() as u64),
                retained_growth_bytes: U64::new(data.retained_growth_bytes() as u64),
                maximum_simultaneous_transient_bytes: U64::new(
                    data.maximum_simultaneous_transient_bytes() as u64,
                ),
                declared_counter_scratch_bytes: U64::new(
                    data.declared_counter_scratch_bytes() as u64
                ),
            });
        }
    }
    rows.peak()?;
    Ok(rows)
}

fn recheck(
    scope: &OriginalReportStartupScope<'_>,
    policy: &OriginalReportStartupPolicy,
    storage: &OriginalReportStartupStorage,
) -> Result<(), EvidenceError> {
    let observed_policy = scope
        .plan
        .0
        .authority
        .original_report_startup_policy(scope.plan.evidence(), scope)?;
    if &observed_policy != policy {
        return Err(failure("original startup resource policy changed"));
    }
    let observed = scope
        .plan
        .0
        .authority
        .authenticate_original_report_startup(scope.plan.evidence(), scope, policy)?;
    if observed.retained_holder_bytes > storage.retained_holder_bytes
        || observed.maximum_simultaneous_transient_bytes
            > storage.maximum_simultaneous_transient_bytes
    {
        return Err(failure("original startup holder demand widened"));
    }
    Ok(())
}

fn fixed_scratch(policy: &OriginalReportStartupPolicy) -> Result<usize, EvidenceError> {
    if policy.maximum_requested_bytes == 0 || policy.declared_observer_scratch_bytes == 0 {
        return Err(failure("original startup resource action is unavailable"));
    }
    [
        size_of::<CompleteOriginalReportStartupAdmission<'_>>(),
        size_of::<OriginalReportStartupScope<'_>>(),
        size_of::<OriginalReportStartupMemberScope<'_>>(),
        size_of::<[StartupRows; 3]>(),
        2 * size_of::<[usize; 3]>(),
        policy.declared_observer_scratch_bytes,
        PacketCompleteSemanticSource::original_report_startup_observer_scratch_data(),
        original_report_startup_counter_scratch_data(),
    ]
    .into_iter()
    .try_fold(0, add)
}

struct Budget {
    maximum: usize,
    used: usize,
}
impl Budget {
    fn new(maximum: usize, fixed: usize) -> Result<Self, EvidenceError> {
        let mut value = Self { maximum, used: 0 };
        value.insert(fixed)?;
        Ok(value)
    }
    fn insert(&mut self, bytes: usize) -> Result<(), EvidenceError> {
        let next = add(self.used, bytes)?;
        if next > self.maximum {
            return Err(failure(
                "original startup requested allocation exceeds installed resource policy",
            ));
        }
        self.used = next;
        Ok(())
    }
}
fn extent(value: u64) -> Result<usize, EvidenceError> {
    usize::try_from(value)
        .map_err(|_| failure("original startup requested layout is not addressable"))
}
fn add(left: usize, right: usize) -> Result<usize, EvidenceError> {
    left.checked_add(right)
        .ok_or_else(|| failure("original startup requested allocation overflow"))
}

mod invocation;

mod settled17;

impl OriginalReportStartupMember {
    /// Records the original plan and Source weak shells as capacity-only DATA.
    ///
    /// # Errors
    /// Refuses exhausted rows, invalid layout or unready physical backing. No
    /// authority is upgraded and no spent member or publication is renewed.
    pub(crate) fn record_retained_capacity_data(
        &self,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        let Self {
            plan,
            source,
            process,
            thread,
            rows,
            finalization_bytes,
        } = self;
        census.observe_inline_data(process);
        census.observe_inline_data(thread);
        census.observe_inline_data(rows);
        census.observe_inline_data(finalization_bytes);
        plan.record_retained_capacity_data(census)?;
        census.observe_weak_allocation_data(source)
    }
}
