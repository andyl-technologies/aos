//! Admits fixed inactive construction on the same original installed owner roster.
//!
//! Each member belongs to one nonrenewing holder phase. Data and callbacks price
//! actual owners before allocation; they issue no Ready, Begin, Capture, restore
//! or Accepted permission. The caller stores the spent member before constructor
//! effects and retains every partial original through post-growth requery.

use super::*;
use crate::{
    node_adapters::cnp::{
        CnpSemanticLaunchGuard, PacketCompleteOriginalHostSdk, PacketCompleteSemanticSource,
    },
    node_contract::{ActivationRecord, RuntimeError, RuntimeLimits},
};
use crucible_node_provider::reference_packet::service::{
    PacketNative5SourceLaunch, complete_restore::PacketNative5CompleteRestoreSelection,
};
use std::{
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

/// Identifies one exact inactive construction step on its original holder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalRuntimeConstructionPhase {
    /// Retains original programme/schedule inputs and shares the same linear owners.
    InputOwners,
    /// Installs the original Oracle/factory/actor/graph and converts actual nodes.
    CollectingGraph,
    /// Consumes the original reserved slot into its inactive four-node runtime.
    InactiveRuntime,
}

/// Borrows the same original scene policy and concrete owner roster.
pub struct OriginalRuntimeConstructionScope<'a> {
    plan: &'a InstalledConformancePlan,
    phase: OriginalRuntimeConstructionPhase,
    after: bool,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    launches: &'a [PacketNative5SourceLaunch; 3],
    sdks: [&'a PacketCompleteOriginalHostSdk; 3],
    activation: &'a ActivationRecord,
    limits: RuntimeLimits,
}

impl OriginalRuntimeConstructionScope<'_> {
    /// Borrows this same installed plan allocation.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Returns the original fixed constructor phase.
    pub fn phase(&self) -> OriginalRuntimeConstructionPhase {
        self.phase
    }

    /// Distinguishes a terminal whole-owner observation from a prospective issue.
    pub fn is_post_construction(&self) -> bool {
        self.after
    }

    /// Borrows the actual Source roster in producer/relay/sink order.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows the same retained immutable typed private launches.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }

    /// Borrows the same opaque completed initial SDK owners.
    pub fn sdks(&self) -> [&PacketCompleteOriginalHostSdk; 3] {
        self.sdks
    }

    /// Borrows the exact proposal already associated with the original runtime slot.
    pub fn activation(&self) -> &ActivationRecord {
        self.activation
    }

    /// Returns the exact fixed limits passed to that original reservation.
    pub fn limits(&self) -> RuntimeLimits {
        self.limits
    }

    /// Compares the actual retained plan allocation without currentness work.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the installed authority's actual allocation.
    pub fn is_original_authority(&self, authority: &dyn ConformanceAdmissionAuthority) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Carries independently installed memory/descriptor ceilings and observer credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRuntimeConstructionPolicy {
    /// Bounds the complete simultaneous owning construction phase.
    pub maximum_requested_bytes: usize,
    /// Bounds actual retained and temporary descriptor views independently.
    pub maximum_owned_descriptors: usize,
    /// Admits all actual fixed Core/Source/holder observation views before walking.
    pub declared_observer_scratch_bytes: usize,
}

/// Reports exact owner and prospective-constructor DATA from the trusted holder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRuntimeConstructionStorage {
    /// Includes the actual holder, Host, graph policy, SDK, preparation and owner banks.
    pub retained_holder_bytes: usize,
    /// Bounds additional concrete callback work while existing owners remain.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Bounds only new owners constructed by this exact step.
    pub construction_retained_requested_bytes: usize,
    /// Bounds additional constructor work while all retained owners coexist.
    pub construction_transient_requested_bytes: usize,
    /// Names this exact constructor's explicit fixed views and counters.
    pub construction_counter_scratch_bytes: usize,
    /// Counts actual retained external holder descriptor views.
    pub retained_descriptors: usize,
    /// Bounds concrete callback temporary descriptors before any constructor work.
    pub maximum_simultaneous_transient_descriptors: usize,
}

/// Retains a spent same-plan/same-Source allocation action through partial construction.
///
/// No constructor or deserializer exists. The same registered holder keeps this
/// member and all partial objects; successful requery grants no execution right.
#[must_use = "retain the spent member with every original partial constructor owner"]
pub struct CompleteOriginalRuntimeConstructionMember {
    process: u32,
    thread: ThreadId,
    plan: WeakInstalledConformancePlan,
    sources: [Weak<PacketCompleteSemanticSource>; 3],
    phase: OriginalRuntimeConstructionPhase,
    policy: OriginalRuntimeConstructionPolicy,
    requested_peak: usize,
}

impl InstalledConformancePlan {
    /// Names fixed original-resource issuer/member and simultaneous row views.
    ///
    /// # Errors
    /// Refuses checked layout overflow before calling any observer.
    pub fn original_runtime_construction_counter_scratch_data() -> Result<usize, RuntimeError> {
        let fixed = [
            size_of::<OriginalRuntimeConstructionScope<'_>>(),
            size_of::<CompleteOriginalRuntimeConstructionMember>(),
            size_of::<OriginalRuntimeConstructionPolicy>(),
            2 * size_of::<OriginalRuntimeConstructionStorage>(),
            2 * size_of::<[usize; 3]>(),
            size_of::<[&PacketCompleteOriginalHostSdk; 3]>(),
            size_of::<[Weak<PacketCompleteSemanticSource>; 3]>(),
            PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(),
        ];
        sum(&[sum(&fixed,usize::MAX)?,size_of::<CompleteOriginalRuntimeConstructionDiagnostics>(),
            crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::counter_scratch_bytes(),
            crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::requested_bytes(),
            crate::node_admission::error::original_construction_diagnostic_requested_bytes()],usize::MAX)
    }

    /// Issues the same installed holder's once-only inactive-construction action.
    ///
    /// The authority must consume its fixed phase flag during policy selection;
    /// retries cannot obtain a second member. The caller immediately stores this
    /// member before allocating, then performs a whole post-growth requery.
    ///
    /// # Errors
    /// Refuses missing same-holder policy, foreign or unfinished originals,
    /// unknown storage/descriptor views or a simultaneous resource excess.
    pub fn reserve_original_runtime_construction(
        &self,
        phase: OriginalRuntimeConstructionPhase,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<CompleteOriginalRuntimeConstructionMember, RuntimeError> {
        let scope = OriginalRuntimeConstructionScope {
            plan: self,
            phase,
            after: false,
            sources,
            launches,
            sdks,
            activation,
            limits,
        };
        if activation.owners.len() != 4 || limits.maximum_nodes != 4 || limits.maximum_owners != 4 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let authority = &self.0.authority;
        let policy = authority.original_runtime_construction_policy(&self.evidence(), &scope)?;
        let fixed = Self::original_runtime_construction_counter_scratch_data()?;
        if policy.maximum_requested_bytes == 0
            || policy.maximum_owned_descriptors == 0
            || fixed > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = authority.authenticate_original_runtime_construction(
            &self.evidence(),
            &scope,
            &policy,
        )?;
        let (requested_peak, _) = observe(&scope, policy, storage, false)?;
        let after = authority.authenticate_original_runtime_construction(
            &self.evidence(),
            &scope,
            &policy,
        )?;
        if after != storage {
            return Err(RuntimeError::ForeignAuthority);
        }
        authority.authenticate_original_runtime_construction_member(&self.evidence(), &scope)?;
        let member = CompleteOriginalRuntimeConstructionMember {
            process: std::process::id(),
            thread: std::thread::current().id(),
            plan: self.downgrade(),
            sources: std::array::from_fn(|i| Rc::downgrade(&sources[i])),
            phase,
            policy,
            requested_peak,
        };
        member.origin()?;
        Ok(member)
    }
}

impl CompleteOriginalRuntimeConstructionMember {
    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Returns the complete originally admitted peak without renewing it.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Rechecks exact original identity before a constructor consumes its owners.
    ///
    /// # Errors
    /// Refuses foreign creator, phase, Source/plan or revoked registered holder.
    pub fn authenticate_original_data(
        &self,
        plan: &InstalledConformancePlan,
        phase: OriginalRuntimeConstructionPhase,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if phase != self.phase
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .same_original(plan)
            || (0..3).any(|i| self.sources[i].as_ptr() != Rc::as_ptr(&sources[i]))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let scope = OriginalRuntimeConstructionScope {
            plan,
            phase,
            after: true,
            sources,
            launches,
            sdks,
            activation,
            limits,
        };
        plan.0
            .authority
            .authenticate_original_runtime_construction_member(&plan.evidence(), &scope)?;
        self.origin()
    }

    /// Requeries all actual owners after constructor loans end against the same grant.
    ///
    /// # Errors
    /// Refuses changed originals/policy, unknown partial owners, revoked holder,
    /// overflow or actual growth beyond the original simultaneous allowance.
    pub fn recheck_original_data(
        &self,
        plan: &InstalledConformancePlan,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_data(
            plan, self.phase, sources, launches, sdks, activation, limits,
        )?;
        let scope = OriginalRuntimeConstructionScope {
            plan,
            phase: self.phase,
            after: true,
            sources,
            launches,
            sdks,
            activation,
            limits,
        };
        if plan
            .0
            .authority
            .original_runtime_construction_policy(&plan.evidence(), &scope)?
            != self.policy
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let actual = plan
            .0
            .authority
            .authenticate_original_runtime_construction(&plan.evidence(), &scope, &self.policy)
            .inspect_err(|error| {
                if cfg!(feature = "test-support") && matches!(error, RuntimeError::ResourceLimit) {
                    use std::io::Write;

                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "native control: runtime {:?} holder resource recheck refused",
                        self.phase,
                    );
                }
            })?;
        let (peak, descriptors) =
            observe(&scope, self.policy, actual, true).inspect_err(|error| {
                if cfg!(feature = "test-support") && matches!(error, RuntimeError::ResourceLimit) {
                    use std::io::Write;

                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "native control: runtime {:?} resource observation refused: policy={:?} storage={actual:?}",
                        self.phase, self.policy,
                    );
                }
            })?;
        if peak > self.requested_peak {
            if cfg!(feature = "test-support") {
                use std::io::Write;

                let _ = writeln!(
                    std::io::stderr().lock(),
                    "native control: runtime {:?} exceeds original peak: actual={peak} admitted={} descriptors={descriptors} policy={:?} storage={actual:?}",
                    self.phase,
                    self.requested_peak,
                    self.policy,
                );
            }
            return Err(RuntimeError::ResourceLimit);
        }
        // No arbitrary callback follows this terminal original-identity fence.
        self.authenticate_original_data(
            plan, self.phase, sources, launches, sdks, activation, limits,
        )?;
        Ok(peak)
    }
}

fn observe(
    scope: &OriginalRuntimeConstructionScope<'_>,
    policy: OriginalRuntimeConstructionPolicy,
    storage: OriginalRuntimeConstructionStorage,
    after: bool,
) -> Result<(usize, usize), RuntimeError> {
    let max = policy.maximum_requested_bytes;
    let mut peak = sum(
        &[
            storage.retained_holder_bytes,
            storage.maximum_simultaneous_transient_bytes,
            policy.declared_observer_scratch_bytes,
        ],
        max,
    )?;
    if !after {
        peak = sum(
            &[
                peak,
                storage.construction_retained_requested_bytes,
                storage.construction_transient_requested_bytes,
                storage.construction_counter_scratch_bytes,
            ],
            max,
        )?;
    } else if storage.construction_retained_requested_bytes != 0
        || storage.construction_transient_requested_bytes != 0
        || storage.construction_counter_scratch_bytes != 0
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let mut descriptors = sum(
        &[
            storage.retained_descriptors,
            storage.maximum_simultaneous_transient_descriptors,
            CnpSemanticLaunchGuard::original_initial_lifecycle_transient_descriptor_data(),
        ],
        policy.maximum_owned_descriptors,
    )?;
    for i in 0..3 {
        if scope.launches[i].complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || (0..i).any(|j| Rc::ptr_eq(&scope.sources[i], &scope.sources[j]))
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        peak = sum(
            &[
                peak,
                scope.sources[i].original_initial_lifecycle_source_storage_data(max)?,
                scope.sdks[i].original_completed_initial_commitments_storage_data(
                    &scope.sources[i],
                    &scope.launches[i],
                    scope.plan,
                )?,
            ],
            max,
        )?;
        descriptors = sum(
            &[
                descriptors,
                scope.sources[i].original_initial_lifecycle_descriptor_views_precredit_data()?,
            ],
            policy.maximum_owned_descriptors,
        )?;
    }
    Ok((peak, descriptors))
}

fn sum(terms: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    terms.iter().try_fold(0usize, |sum, n| {
        sum.checked_add(*n)
            .filter(|sum| *sum <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

thread_local! {static SELECTED_RUNTIME_DIAGNOSTICS:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}

pub(crate) fn original_runtime_construction_failure_reason<E: std::fmt::Display>(
    error: E,
) -> String {
    if SELECTED_RUNTIME_DIAGNOSTICS.get() {
        crate::node_adapters::cnp::original_construction_failure_reason(error)
    } else {
        error.to_string()
    }
}

/// Restores the private selected diagnostic state on return or unwind.
///
/// This owner grants no allocation, execution or callback permission. Only the
/// genuine issued member can create it after reauthenticating the same holder.
pub struct CompleteOriginalRuntimeConstructionDiagnostics {
    previous_runtime: bool,
    _source: crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics,
    _graph: crate::node_admission::error::OriginalConstructionDiagnosticScope,
}

impl CompleteOriginalRuntimeConstructionMember {
    /// Bounds delegated diagnostics during this same original constructor phase.
    ///
    /// Ordinary diagnostic behavior is unchanged outside this non-Send scope.
    /// The operation/effect classifications remain in the original error types.
    ///
    /// # Errors
    /// Refuses a foreign, stale or revoked issued member before changing state.
    pub fn begin_original_constructor_diagnostics(
        &self,
        plan: &InstalledConformancePlan,
        phase: OriginalRuntimeConstructionPhase,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<CompleteOriginalRuntimeConstructionDiagnostics, RuntimeError> {
        self.authenticate_original_data(plan, phase, sources, launches, sdks, activation, limits)?;
        Ok(CompleteOriginalRuntimeConstructionDiagnostics {
            previous_runtime: SELECTED_RUNTIME_DIAGNOSTICS.replace(true),
            _source: crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::begin(),
            _graph: crate::node_admission::error::OriginalConstructionDiagnosticScope::enter(),
        })
    }
}

impl InstalledConformancePlan {
    /// Quotes the actual compiled constructor DTO's serialization DATA.
    ///
    /// This is a counter, not allocation authority. The selected trusted caller
    /// supplies only the fixed World, programme, schedule and WitnessPlan DTOs;
    /// arbitrary serializers are not part of that installed action's contract.
    /// Delegated serializer work must be independently admitted by any caller.
    ///
    /// # Errors
    /// Refuses unsupported serialization or checked requested-layout excess.
    pub fn original_runtime_constructor_serialization_storage_data(
        value: &impl serde::Serialize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        crate::node_contract::NodeRuntime::original_runtime_constructor_serialization_storage_data(
            value, maximum,
        )
    }

    /// Quotes typed requirements, parser and canonical DATA from actual raw bytes.
    ///
    /// The genuine graph constructor independently validates the same immutable
    /// scenario content. The byte loan and these numeric rows issue no grant.
    ///
    /// # Errors
    /// Refuses malformed raw JSON, overflow or the requested ceiling.
    pub fn original_runtime_requirements_decode_storage_data(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        use crate::node_contract::NodeRuntime;
        NodeRuntime::capture_selected_json_decode_axes_data(
            bytes,
            size_of::<crate::node_admission::ScenarioRequirements>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            maximum,
        )
    }

    /// Names the actual closed serializer and raw requirements counter views.
    pub fn original_runtime_constructor_data_counter_scratch_data() -> usize {
        crate::node_contract::NodeRuntime::capture_serialization_counter_scratch_data()
            + crate::node_contract::NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + size_of::<(usize, usize, usize)>()
    }
}

impl Drop for CompleteOriginalRuntimeConstructionDiagnostics {
    fn drop(&mut self) {
        SELECTED_RUNTIME_DIAGNOSTICS.set(self.previous_runtime);
    }
}
