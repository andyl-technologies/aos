//! Reconciles exact protected Stop history with a fresh complete native census.
//!
//! A wholly absent target yields observation-only recovery DATA. A currently
//! owned pending target yields a distinct passive cleanup candidate, never
//! adoption or effect permission. Unknown/residual identities stay quarantined.
//! The same original Control pays a finite raw discovery window selected
//! against its actual residual before any allocation/IO. Residuals stay on this
//! owner as quarantine; independent Host, kernel and clock posts remain owed.

use super::*;
use crate::state::HistoricalNamespaceCandidateV7;
use aos_sandbox_broker::paired_clock::{PairedClockBaselineV1, PairedClockSamplesV1};
use aos_sandbox_model::{
    RawClockProvenance, RawPairedClockSample, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_linux::cgroup::HostRuntimeCgroupAbsenceOriginalV5;
use aos_sandbox_protocol::host_recovered_namespace::HostRecoveredNamespaceDataV7;
use aos_sandbox_protocol::host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1;
use aos_sandbox_protocol::host_cleanup_lineage::HostCleanupLineageDataV1;
use aos_sandbox_protocol::{ValidatedHeader, host_inventory_absence::HostInventoryAbsenceDataV5};
use aos_systemd_client::HostRuntimeDiscoveryOriginalV5;

#[derive(Clone, Copy)]
pub(super) struct Shape {
    message: usize,
    materialized: usize,
    demand: ResourceVector,
}

impl Shape {
    fn for_message(message: usize, maximum_response: u32, population: PopulationV6) -> Option<Self> {
        let owned = population.owned_incarnation_v8();
        let materialized = match owned {
            Some(incarnation) => HostRuntimeDiscoveryOriginalV5::materialization_extent_for_owned_cleanup_v8(incarnation, message)?,
            None => message.checked_mul(12)?,
        };
        let sdk = match owned {
            Some(incarnation) => HostRuntimeDiscoveryOriginalV5::receiving_footprint_for_owned_cleanup_v8(incarnation, message, materialized)?,
            None => HostRuntimeDiscoveryOriginalV5::receiving_footprint_v5(message, materialized)?,
        };
        let (kernel_bytes, kernel_files, kernel_names) = if owned.is_some() {
            HostRuntimeCgroupAbsenceOriginalV5::receiving_obligations_for_owned_cleanup_v8()?
        } else { HostRuntimeCgroupAbsenceOriginalV5::receiving_obligations_v5()? };
        let bytes = sdk
            .memory_bytes
            .checked_add(kernel_bytes)?
            .checked_add(3 * std::mem::size_of::<InventoryRuntimeResponse>())?
            .checked_add(
                3 * aos_sandbox_protocol::host_inventory_absence::HOST_INVENTORY_ABSENCE_BYTES_V5,
            )?
            .checked_add(
                3 * aos_sandbox_protocol::host_recovered_namespace::HOST_RECOVERED_NAMESPACE_BYTES_V7,
            )?
            .checked_add(if population.historical_v8() {
                3 * aos_sandbox_protocol::host_cleanup_lineage::HOST_CLEANUP_LINEAGE_BYTES_V1
            } else { 0 })?
            .checked_add(if owned.is_some() {
                3 * aos_sandbox_protocol::host_stop_cleanup_candidate::HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1
            } else { 0 })?
            .checked_add(3 * std::mem::size_of::<Vec<u8>>())?
            .checked_add(usize::try_from(maximum_response).ok()?.checked_mul(3)?)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(
                D::OpenFiles,
                u64::try_from(sdk.open_files.checked_add(kernel_files)?).ok()?,
            )
            .with(
                D::MetadataEntries,
                u64::try_from(sdk.metadata_entries.checked_add(kernel_names)?).ok()?,
            )
            .with(D::NetworkBytes, u64::try_from(sdk.network_bytes).ok()?)
            .with(D::LogBytes, u64::try_from(sdk.maximum_log_bytes).ok()?)
            .with(D::OutputBytes, u64::from(maximum_response));
        if owned.is_some() {
            demand = demand.checked_add(crate::worker::HostOwnedRuntimeProofOriginalV8::receiving_demand_v8()?).ok()?;
        }
        Some(Self {
            message,
            materialized,
            demand,
        })
    }

    fn select(available: ResourceVector, maximum_response: u32, population: PopulationV6) -> Option<Self> {
        // The upper bound is D-Bus's existing wire maximum. Every smaller
        // success is solely the actual same Control's restrictive cost check;
        // no inventory row limit, capacity increase or truncated reply exists.
        let (mut low, mut high) = HostRuntimeDiscoveryOriginalV5::message_extent_range_v5();
        let mut selected = None;
        while low <= high {
            let candidate = low.checked_add((high - low) / 2)?;
            match Self::for_message(candidate, maximum_response, population)
                .filter(|shape| available.checked_sub(shape.demand).is_ok())
            {
                Some(shape) => {
                    selected = Some(shape);
                    low = candidate.checked_add(1)?;
                }
                None => {
                    high = candidate.checked_sub(1)?;
                }
            }
        }
        selected
    }
}

#[derive(Clone, Copy)]
enum First {
    Before,
    Header,
    Context,
    Extension,
    Clock(usize),
    Deadline,
    DiscoveryBegin,
    Listing(usize),
    OwnedRole(usize),
    CleanupRoles,
    Kernel(usize),
    History(usize),
    DiscoveryAfter,
    DiscoveryClose,
    After,
    DiscoveryDispose,
    ClockDispose,
    Dispose,
    Body,
}

// Selects comparison geometry only. Neither variant supplies native absence.
#[derive(Clone, Copy, Eq, PartialEq)]
enum PopulationV6 {
    ColdEmpty,
    HistoricalStopped,
    HistoricalOwned([u8; 16]),
}

impl PopulationV6 {
    fn historical_v8(self) -> bool { self != Self::ColdEmpty }

    fn owned_incarnation_v8(self) -> Option<[u8; 16]> {
        match self { Self::HistoricalOwned(incarnation) => Some(incarnation), _ => None }
    }
}

pub(super) struct HostNativeInventoryOriginalV5 {
    header:
        Option<std::result::Result<ValidatedHeader, aos_sandbox_protocol::ProtocolValidationError>>,
    context: Option<Result<()>>,
    extension: Option<Result<()>>,
    discovery: HostRuntimeDiscoveryOriginalV5,
    kernel: HostRuntimeCgroupAbsenceOriginalV5,
    owned_roles: Option<Box<crate::worker::HostOwnedRuntimeProofOriginalV8>>,
    owned_results: [Option<Result<()>>; 2],
    baseline: Option<PairedClockBaselineV1>,
    samples: Option<PairedClockSamplesV1>,
    before: Option<Result<()>>,
    clocks: [Option<Result<RawPairedClockSample>>; 2],
    deadline: Option<Result<tokio::time::Instant>>,
    discovery_begin: Option<std::result::Result<(), aos_systemd_client::HostRuntimeDiscoveryRefusalV5>>,
    listings: [Option<std::result::Result<(), aos_systemd_client::HostRuntimeDiscoveryRefusalV5>>; 2],
    kernel_results: [Option<
        std::result::Result<(), aos_sandbox_linux::cgroup::HostRuntimeCgroupAbsenceRefusalV5>,
    >; 2],
    population: PopulationV6,
    history_reads: [Option<crate::state::HostStateReadAttemptV2>; 2],
    history: [Option<Result<HistoricalNamespaceCandidateV7>>; 2],
    recovery: Option<HostRecoveredNamespaceDataV7>,
    present: Option<HostStopCleanupCandidateDataV1>,
    launch_candidate: Option<
        aos_sandbox_protocol::host_launch_cleanup_candidate::HostLaunchCleanupCandidateDataV1,
    >,
    resident_scope: Option<aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1>,
    lineage: Option<HostCleanupLineageDataV1>,
    discovery_after: Option<std::result::Result<(), aos_systemd_client::HostRuntimeDiscoveryRefusalV5>>,
    after: Option<Result<()>>,
    discovery_close: Option<std::result::Result<(), aos_systemd_client::HostRuntimeDiscoveryRefusalV5>>,
    discovery_dispose: Option<std::result::Result<(), aos_systemd_client::HostRuntimeDiscoveryRefusalV5>>,
    clock_dispose: Option<Result<()>>,
    dispose: Option<Result<()>>,
    body: Option<Result<Vec<u8>>>,
    first: Option<First>,
    complete: bool,
    original_selected: bool,
    cleanup_request: Option<([u8; 16], [u8; 32], [u8; 32])>,
    cleanup_shape: Option<Shape>,
    cleanup_subject: Option<aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1>,
    cleanup_roles_post: Option<Result<()>>,
}

/// Borrows the real before-effect census; passive candidate DATA cannot create it.
pub(crate) struct HostCleanupNativeOwnershipV1<'native> {
    original: &'native HostNativeInventoryOriginalV5,
}

impl HostCleanupNativeOwnershipV1<'_> {
    pub(crate) fn require_current_target_v1(&self,
        candidate: &HistoricalNamespaceCandidateV7,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        let original = self.original;
        if original.cleanup_request != Some((request.request_id(),request.session_binding(),request.signed_request_digest()))
            || original.first.is_some() || !matches!(original.before, Some(Ok(())))
            || !original.kernel_completed_v8()
            || original.history[0].as_ref().and_then(|result| result.as_ref().ok()) != Some(candidate)
            || original.history[1].as_ref().and_then(|result| result.as_ref().ok()) != Some(candidate)
        { return Err(HostError::Fence("fresh cleanup target differs from its actual protected/native census")); }
        let rounds = original.discovery.closed_owned_observations_v1()
            .map_err(|_| HostError::Fence("fresh cleanup native ownership rounds are not closed"))?;
        if rounds[0] != rounds[1] {
            return Err(HostError::Fence("fresh cleanup native target changed across rounds"));
        }
        if rounds[1].0 != &aos_systemd_client::PostUnrefUnitObservation::Absent
            || rounds[1].1 != &aos_systemd_client::PostUnrefUnitObservation::Absent
        {
            candidate.require_present_target_v1(rounds[1].0, rounds[1].1)?;
        }
        Ok(())
    }
}

impl HostNativeInventoryOriginalV5 {
    fn new(population: PopulationV6) -> Self {
        Self {
            header: None,
            context: None,
            extension: None,
            discovery: match population.owned_incarnation_v8() {
                Some(incarnation) => HostRuntimeDiscoveryOriginalV5::new_for_owned_cleanup_v8(incarnation),
                None => HostRuntimeDiscoveryOriginalV5::new(),
            },
            kernel: HostRuntimeCgroupAbsenceOriginalV5::new(),
            owned_roles: None,
            owned_results: std::array::from_fn(|_| None),
            baseline: None,
            samples: None,
            before: None,
            clocks: [None, None],
            deadline: None,
            discovery_begin: None,
            listings: std::array::from_fn(|_| None),
            kernel_results: std::array::from_fn(|_| None),
            population,
            history_reads: std::array::from_fn(|_| None),
            history: std::array::from_fn(|_| None),
            recovery: None,
            present: None,
            launch_candidate: None,
            resident_scope: None,
            lineage: None,
            discovery_after: None,
            after: None,
            discovery_close: None,
            discovery_dispose: None,
            clock_dispose: None,
            dispose: None,
            body: None,
            first: None,
            complete: false,
            original_selected: false,
            cleanup_request: None,
            cleanup_shape: None,
            cleanup_subject: None,
            cleanup_roles_post: None,
        }
    }

    pub(super) fn cleanup_entry_demand_v1(
        state: &crate::state::HostState,
        actual_body_bytes: usize,
    ) -> Result<ResourceVector> {
        entry_demand_v5(actual_body_bytes)?
            .checked_add(
                state
                    .native_inventory_history_receiving_demand_v6()
                    .ok_or(HostError::ResourceExhausted)?,
            )
            .map_err(|_| HostError::ResourceExhausted)
    }

    pub(super) fn cleanup_before_entered_v1(&self) -> bool {
        self.before.is_some()
    }

    pub(super) fn new_cleanup_before_native_v1(
        receiving: &mut crate::plan::HostControlPreparationReceivingV5<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        runtime: &ValidatedRuntimeRequest,
        complete: &mut ResourceVector,
    ) -> Result<Self> {
        Self::new_cleanup_census_v1(
            receiving,
            request,
            runtime,
            complete,
            PopulationV6::HistoricalOwned(*runtime.fence().incarnation_id()),
        )
    }

    pub(super) fn new_cleanup_terminal_before_native_v1(
        receiving: &mut crate::plan::HostControlPreparationReceivingV5<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        runtime: &ValidatedRuntimeRequest,
        complete: &mut ResourceVector,
    ) -> Result<Self> {
        Self::new_cleanup_census_v1(
            receiving,
            request,
            runtime,
            complete,
            PopulationV6::HistoricalStopped,
        )
    }

    fn new_cleanup_census_v1(
        receiving: &mut crate::plan::HostControlPreparationReceivingV5<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        runtime: &ValidatedRuntimeRequest,
        complete: &mut ResourceVector,
        population: PopulationV6,
    ) -> Result<Self> {
        receiving.require_cleanup_request_v1(request)?;
        let subject = runtime
            .host_stop_cleanup_v1()
            .ok_or(HostError::Fence("fresh cleanup subject is absent"))?;
        subject.require_request_data_v1(
            &request.request_id(),
            runtime.fence(),
            request.deadline_boottime_nanoseconds(),
        )?;
        let shape = Shape::select(
            receiving.remaining_cleanup_capacity_v1()?,
            runtime.header().maximum_response_bytes(),
            population,
        )
        .ok_or(HostError::ResourceExhausted)?;
        *complete = complete
            .checked_add(shape.demand)
            .map_err(|_| HostError::ResourceExhausted)?;
        receiving.raise_complete_v1(*complete)?;
        let mut original = Self::new(population);
        original.cleanup_request = Some((
            request.request_id(),
            request.session_binding(),
            request.signed_request_digest(),
        ));
        original.cleanup_shape = Some(shape);
        original.cleanup_subject = Some(*subject);
        Ok(original)
    }

    pub(super) async fn capture_cleanup_native_once_v1(
        &mut self,
        receiving: &mut crate::plan::HostControlPreparationReceivingV5<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        effect: &aos_sandbox_broker::BrokerEffectIntentV1,
        store: &impl HostStateStore,
        expected: &crate::state::HostState,
        authority: &crate::authorization::HostAuthorityV1,
        worker: &crate::worker::RetainedPayloadWorkerV1<'_>,
    ) -> Result<()> {
        receiving.require_cleanup_request_v1(request)?;
        if self.before.is_some()
            || self.baseline.is_some()
            || self.first.is_some()
            || self.cleanup_request
                != Some((
                    request.request_id(),
                    request.session_binding(),
                    request.signed_request_digest(),
                ))
        {
            return Err(HostError::Fence(
                "fresh cleanup census reentry differs from its actual request",
            ));
        }
        if self.population.owned_incarnation_v8().is_some() {
            self.before = Some(receiving.observe_before_once_v5().await);
            if !matches!(self.before, Some(Ok(()))) {
                self.original_selected = receiving.original_failure_entered_v5();
                self.first.get_or_insert(First::Before);
            }
        }
        if self.first.is_none() {
            self.baseline = Some(PairedClockBaselineV1::capture(
                RawClockProvenance::new_untrusted(crate::KERNEL_CLOCK_PROVENANCE),
            ));
            self.samples = Some(PairedClockSamplesV1::new());
            self.sample(
                0,
                Some(request.deadline_boottime_nanoseconds()),
                *effect.host_boot_id(),
            );
        }
        if self.first.is_none() {
            self.deadline = Some((|| {
                let clock = self.clocks[0]
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(HostError::ResourceExhausted)?;
                aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(effect)
                    .require_fresh(clock)?;
                let remaining = request
                    .deadline_boottime_nanoseconds()
                    .checked_sub(clock.boottime_nanoseconds())
                    .ok_or(HostError::ResourceExhausted)?;
                tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_nanos(remaining))
                    .ok_or(HostError::ResourceExhausted)
            })());
            if !matches!(self.deadline, Some(Ok(_))) {
                self.first.get_or_insert(First::Deadline);
            }
        }
        if self.first.is_none() {
            if self.population.owned_incarnation_v8().is_some() {
                self.owned_roles = Some(Box::new(
                    crate::worker::HostOwnedRuntimeProofOriginalV8::new(),
                ));
            }
            let shape = self.cleanup_shape.ok_or(HostError::ResourceExhausted)?;
            let deadline = *self
                .deadline
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(HostError::ResourceExhausted)?;
            self.discovery_begin = Some(
                self.discovery
                    .begin_once_v5(
                        shape.message,
                        shape.materialized,
                        deadline,
                        request.deadline_boottime_nanoseconds(),
                    )
                    .await,
            );
            if !matches!(self.discovery_begin, Some(Ok(()))) {
                self.first.get_or_insert(First::DiscoveryBegin);
            }
            self.capture_history_census_once_v1(store, expected, authority, worker)
                .await?;
        }
        if self.discovery_begin.is_some() {
            self.discovery_after = Some(self.discovery.observe_after_once_v5().await);
            if !matches!(self.discovery_after, Some(Ok(()))) {
                self.first.get_or_insert(First::DiscoveryAfter);
            }
        }
        if self.first.is_none() && self.kernel_completed_v8() {
            self.discovery_close = Some(self.discovery.close_positive_body_once_v5().await);
            if !matches!(self.discovery_close, Some(Ok(()))) {
                self.first.get_or_insert(First::DiscoveryClose);
            }
        }
        if self.samples.is_some() {
            self.sample(
                1,
                Some(request.deadline_boottime_nanoseconds()),
                *effect.host_boot_id(),
            );
        }
        if self.first.is_some() {
            return Err(HostError::Fence(
                "fresh cleanup census refused; actual originals retained",
            ));
        }
        let clock = self.clocks[1]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(HostError::ResourceExhausted)?;
        self.context = Some(
            aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(effect)
                .require_fresh(clock)
                .map_err(Into::into),
        );
        if !matches!(self.context, Some(Ok(()))) {
            self.first.get_or_insert(First::Context);
            return Err(HostError::Fence(
                "cleanup final native clock comparison refused; typed cause retained",
            ));
        }
        Ok(())
    }

    pub(super) fn borrow_cleanup_ownership_v1(&self) -> Result<HostCleanupNativeOwnershipV1<'_>> {
        if self.cleanup_request.is_none()
            || self.first.is_some()
            || !self.kernel_completed_v8()
            || !matches!(self.before, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "fresh cleanup has no actual before-effect ownership",
            ));
        }
        self.discovery
            .closed_owned_observations_v1()
            .map_err(|_| HostError::Fence("fresh cleanup native rounds are not closed"))?;
        Ok(HostCleanupNativeOwnershipV1 { original: self })
    }

    pub(super) fn cleanup_initial_owner_posts_entered_v1(&self) -> bool {
        self.cleanup_roles_post.is_some()
    }

    pub(super) fn finish_cleanup_initial_owners_once_v1(
        &mut self,
        worker: &crate::worker::RetainedPayloadWorkerV1<'_>,
    ) -> Result<()> {
        if self.cleanup_roles_post.is_some() {
            return Err(HostError::Fence(
                "cleanup initial-owner posts already entered",
            ));
        }
        self.cleanup_roles_post = Some(
            worker.finish_inventory_owned_roles_after_cleanup_v1(
                self.owned_roles
                    .as_mut()
                    .ok_or(HostError::ResourceExhausted)?,
            ),
        );
        if !matches!(self.cleanup_roles_post, Some(Ok(()))) {
            self.first.get_or_insert(First::CleanupRoles);
            return Err(HostError::Fence(
                "cleanup initial owner death/population refused; actual results retained",
            ));
        }
        Ok(())
    }

    pub(super) fn require_cleanup_native_completed_v1(&self, terminal: &Self) -> Result<()> {
        if self.first.is_some()
            || terminal.first.is_some()
            || self.cleanup_request.is_none()
            || self.cleanup_request != terminal.cleanup_request
            || self.cleanup_subject != terminal.cleanup_subject
            || !matches!(self.before, Some(Ok(())))
            || !self
                .owned_roles
                .as_ref()
                .is_some_and(|roles| roles.cleanup_posts_completed_v1())
            || !terminal.kernel_completed_v8()
            || terminal.population != PopulationV6::HistoricalStopped
        {
            return Err(HostError::Fence(
                "cleanup whole native terminal conjunction is incomplete",
            ));
        }
        terminal
            .discovery
            .require_closed_absence_v1()
            .map_err(|_| HostError::Fence("cleanup terminal native census is not closed/absent"))?;
        let before = terminal.history[0]
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let after = terminal.history[1]
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let (Some(before), Some(after)) = (before, after) else {
            return Err(HostError::Fence(
                "cleanup terminal protected snapshots are absent",
            ));
        };
        if before != after {
            return Err(HostError::Fence(
                "cleanup terminal protected snapshots changed",
            ));
        }
        after.require_cleanup_child_data_v1(
            self.cleanup_subject
                .as_ref()
                .ok_or(HostError::ResourceExhausted)?,
            self.cleanup_request.ok_or(HostError::ResourceExhausted)?,
        )
    }

    pub(super) fn require_cleanup_posts_completed_v1(&self, terminal: &Self) -> Result<()> {
        self.require_cleanup_native_completed_v1(terminal)?;
        if !matches!(self.after, Some(Ok(())))
            || !self.census_completed_v8()
            || !terminal.census_completed_v8()
            || !matches!(self.clock_dispose, Some(Ok(())))
            || !matches!(terminal.clock_dispose, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "cleanup independently owed posts/disposals are incomplete",
            ));
        }
        Ok(())
    }

    pub(super) async fn finish_cleanup_native_post_once_v1(
        &mut self,
        after: Result<()>,
        original_selected: bool,
    ) -> Result<()> {
        if self.after.is_some() {
            return Err(HostError::Fence("fresh cleanup post was already entered"));
        }
        self.after = Some(after);
        if !matches!(self.after, Some(Ok(()))) {
            if self.first.is_none() {
                self.original_selected = original_selected;
            }
            self.first.get_or_insert(First::After);
        }
        self.dispose_cleanup_native_leaves_once_v1().await
    }

    pub(super) async fn dispose_cleanup_terminal_after_posts_v1(
        &mut self,
        initial: &Self,
    ) -> Result<()> {
        if self.population != PopulationV6::HistoricalStopped
            || self.cleanup_request != initial.cleanup_request
            || !matches!(initial.before, Some(Ok(())))
            || !matches!(initial.after, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "terminal cleanup native leaves lack the SAME actual Source posts",
            ));
        }
        self.dispose_cleanup_native_leaves_once_v1().await
    }

    async fn dispose_cleanup_native_leaves_once_v1(&mut self) -> Result<()> {
        if self.first.is_none() {
            self.discovery_dispose = Some(self.discovery.dispose_positive_once_v5().await);
            if !matches!(self.discovery_dispose, Some(Ok(()))) {
                self.first.get_or_insert(First::DiscoveryDispose);
            }
        }
        // Every actually entered clock remains owned on a failed flight. On a
        // positive census the same native leaf disposer runs after Source-after.
        if self.first.is_none() {
            self.clock_dispose = Some((|| {
                self.baseline
                    .as_mut()
                    .ok_or(HostError::ResourceExhausted)?
                    .retire_positive_native_file_v2()
                    .map_err(|_| HostError::Fence("cleanup baseline disposal refused"))?;
                self.samples
                    .as_mut()
                    .ok_or(HostError::ResourceExhausted)?
                    .retire_positive_native_files_v2()
                    .map_err(|_| HostError::Fence("cleanup clock disposal refused"))
            })());
            if !matches!(self.clock_dispose, Some(Ok(()))) {
                self.first.get_or_insert(First::ClockDispose);
            }
        }
        if self.first.is_some() {
            return Err(HostError::Fence(
                "cleanup native/Source post refused; originals retained",
            ));
        }
        Ok(())
    }

    // Both authenticated Host3 and fresh Host1 cleanup use this one concrete
    // protected-history/native two-round programme. Its callers independently
    // prepay and retain their actual request-bound Control loan and posts.
    pub(super) async fn capture_history_census_once_v1(
        &mut self,
        store: &impl HostStateStore,
        expected: &crate::state::HostState,
        authority: &crate::authorization::HostAuthorityV1,
        worker: &crate::worker::RetainedPayloadWorkerV1<'_>,
    ) -> Result<()> {
        if matches!(self.discovery_begin, Some(Ok(()))) {
            if self.population.historical_v8() {
                self.history_reads[0] = Some(crate::state::HostStateReadAttemptV2::new());
                self.history[0] = Some(read_history_v6(
                    store,
                    expected,
                    authority,
                    self.history_reads[0]
                        .as_mut()
                        .ok_or(HostError::ResourceExhausted)?,
                ));
                if !matches!(self.history[0], Some(Ok(_))) {
                    self.first.get_or_insert(First::History(0));
                }
            }
            for index in 0..2 {
                self.listings[index] = Some(self.discovery.observe_next_once_v5().await);
                if !matches!(self.listings[index], Some(Ok(()))) {
                    self.first.get_or_insert(First::Listing(index));
                }
                // Both complete kernel rounds remain reached after a
                // residual/failed listing; they create no positive effect.
                if let (Some(roles), Some(incarnation)) = (
                    self.owned_roles.as_mut(),
                    self.population.owned_incarnation_v8(),
                ) {
                    self.owned_results[index] = Some(worker.capture_inventory_owned_roles_v8(
                        roles,
                        &self.discovery,
                        incarnation,
                    ));
                    if !matches!(self.owned_results[index], Some(Ok(()))) {
                        self.first.get_or_insert(First::OwnedRole(index));
                    }
                    self.kernel_results[index] =
                        Some(worker.capture_inventory_owned_cgroup_v8(roles, &mut self.kernel));
                } else {
                    self.kernel_results[index] =
                        Some(worker.capture_inventory_cgroup_v5(&mut self.kernel));
                }
                if !matches!(self.kernel_results[index], Some(Ok(()))) {
                    self.first.get_or_insert(First::Kernel(index));
                }
            }
            if self.population.historical_v8() {
                // This paid after destination remains reached even if
                // the first read, listing or kernel census refused.
                self.history_reads[1] = Some(crate::state::HostStateReadAttemptV2::new());
                self.history[1] = Some(read_history_v6(
                    store,
                    expected,
                    authority,
                    self.history_reads[1]
                        .as_mut()
                        .ok_or(HostError::ResourceExhausted)?,
                ));
                if !matches!(self.history[1], Some(Ok(_))) {
                    self.first.get_or_insert(First::History(1));
                }
            }
        }
        Ok(())
    }

    fn sample(&mut self, index: usize, deadline: Option<u64>, boot: [u8; 16]) {
        self.clocks[index] = Some((|| {
            let sample = self
                .samples
                .as_mut()
                .ok_or(HostError::ResourceExhausted)?
                .sample(self.baseline.as_mut().ok_or(HostError::ResourceExhausted)?)
                .map_err(|_| HostError::Fence("Host native inventory paired clock failed"))?;
            if sample.host_boot_id() != boot
                || deadline.is_some_and(|deadline| sample.boottime_nanoseconds() >= deadline)
            {
                return Err(HostError::Fence(
                    "Host native inventory fresh read horizon expired",
                ));
            }
            Ok(sample)
        })());
        if !matches!(self.clocks[index], Some(Ok(_))) {
            self.first.get_or_insert(First::Clock(index));
        }
    }

    fn kernel_completed_v8(&self) -> bool {
        match self.owned_roles.as_ref() {
            Some(roles) => roles.completed_v8() && self.kernel.completed_owned_cleanup_v8(),
            None => self.population.owned_incarnation_v8().is_none() && self.kernel.completed_v5(),
        }
    }

    fn census_completed_v8(&self) -> bool {
        self.kernel_completed_v8()
            && if self.population.owned_incarnation_v8().is_some() {
                self.discovery.completed_owned_cleanup_v8()
            } else {
                self.discovery.completed_v5()
            }
    }

    fn present_roles_v8(
        &self,
    ) -> Option<(
        &aos_systemd_client::PostUnrefUnitObservation,
        &aos_systemd_client::PostUnrefUnitObservation,
    )> {
        use aos_systemd_client::{ExactUnitRole, PostUnrefUnitObservation};
        let payload = self
            .discovery
            .owned_unit_observation_v8(1, ExactUnitRole::Payload)?;
        let guardian = self
            .discovery
            .owned_unit_observation_v8(1, ExactUnitRole::Guardian)?;
        (matches!(payload, PostUnrefUnitObservation::Present(_))
            || matches!(guardian, PostUnrefUnitObservation::Present(_)))
        .then_some((payload, guardian))
    }

    fn require_launch_absent_rounds_v1(&self) -> Result<()> {
        let rounds = self
            .discovery
            .closed_owned_observations_v1()
            .map_err(|_| HostError::Fence("Launch-only native ownership rounds are not closed"))?;
        if !rounds.into_iter().all(|(payload, guardian)| {
            payload == &aos_systemd_client::PostUnrefUnitObservation::Absent
                && guardian == &aos_systemd_client::PostUnrefUnitObservation::Absent
        }) {
            return Err(HostError::Fence(
                "Launch-only total absence differs across native rounds",
            ));
        }
        Ok(())
    }

    fn reconciled_history_v8(&self) -> Result<()> {
        if let Some(candidate) = self.launch_candidate.as_ref() {
            if !self.complete
                || self.first.is_some()
                || !self.census_completed_v8()
                || !matches!(self.before, Some(Ok(())))
                || !matches!(self.after, Some(Ok(())))
                || !matches!(self.dispose, Some(Ok(())))
            {
                return Err(HostError::Fence(
                    "Launch-only comparison lacks its completed native/Source posts",
                ));
            }
            let before = self.history[0]
                .as_ref()
                .and_then(|result| result.as_ref().ok());
            let after = self.history[1]
                .as_ref()
                .and_then(|result| result.as_ref().ok());
            let (Some(before), Some(after)) = (before, after) else {
                return Err(HostError::Fence("Launch-only protected history is absent"));
            };
            if before != after
                || after.dispatched_observation_scope_v1().as_ref()
                    != Some(candidate.launch_scope_v1())
            {
                return Err(HostError::Fence(
                    "Launch-only history changed across native rounds",
                ));
            }
            use aos_sandbox_protocol::host_launch_cleanup_candidate::HostLaunchCleanupPopulationDataV1 as Population;
            return match (candidate.population_v1(), self.present_roles_v8()) {
                (Population::PresentOwned, Some((payload, guardian))) => {
                    after.require_present_target_v1(payload, guardian)
                }
                (Population::Absent, None) => self.require_launch_absent_rounds_v1(),
                _ => Err(HostError::Fence(
                    "Launch-only population differs from actual native census",
                )),
            };
        }
        if let Some(lineage) = self.lineage.as_ref() {
            if !self.complete
                || self.first.is_some()
                || !self.census_completed_v8()
                || self.present_roles_v8().is_some()
                || !matches!(self.before, Some(Ok(()))) || !matches!(self.after, Some(Ok(())))
                || !matches!(self.dispose, Some(Ok(())))
            { return Err(HostError::Fence("cleanup lineage lacks its actual complete absence census")); }
            let before = self.history[0].as_ref().and_then(|result| result.as_ref().ok());
            let after = self.history[1].as_ref().and_then(|result| result.as_ref().ok());
            return match (before, after) {
                (Some(before), Some(after)) if before == after
                    && after.cleanup_lineage_data_v1(*lineage.observation_v1())? == Some(*lineage) => Ok(()),
                _ => Err(HostError::Fence("cleanup lineage changed across protected/native rounds")),
            };
        }
        if self.present.is_none() {
            return self.reconciled_namespace_v7().map(|_| ());
        }
        if !self.complete
            || self.first.is_some()
            || !self.census_completed_v8()
            || !matches!(self.before, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || !matches!(self.dispose, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "Host owned candidate lacks its actual completed native posts",
            ));
        }
        let before = self.history[0]
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let after = self.history[1]
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        match (
            before,
            after,
            self.present.as_ref(),
            self.present_roles_v8(),
        ) {
            (Some(before), Some(after), Some(candidate), Some((payload, guardian)))
                if before == after
                    && candidate.historical_scope_v1() == after.stopped_scope_v1()?
                    && after.present_phase_v8(payload, guardian)? == candidate.saved_phase_v1() =>
            {
                Ok(())
            }
            _ => Err(HostError::Fence(
                "Host owned candidate differs from its exact protected/native history",
            )),
        }
    }

    pub(super) fn completed_v5(&self) -> bool {
        self.complete
    }

    /// Borrows the exact scope only after the actual census and native disposals.
    ///
    /// # Errors
    /// Refuses any unfinished native/financial post or differing history reads.
    pub(super) fn reconciled_namespace_v7(&self) -> Result<&HostRecoveredNamespaceDataV7> {
        if !self.complete
            || self.first.is_some()
            || !self.population.historical_v8()
            || !self.census_completed_v8()
            || !matches!(self.before, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || !matches!(self.dispose, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "Host historical namespace has no completed native census",
            ));
        }
        let before = self.history[0]
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let after = self.history[1]
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        match (before, after) {
            (Some(before), Some(after)) if before == after => {
                let recovery = self
                    .recovery
                    .as_ref()
                    .ok_or(HostError::Fence("Host recovered observation is absent"))?;
                if recovery.historical_scope_v7() != after.stopped_scope_v1()? {
                    return Err(HostError::Fence("Host recovered scope changed"));
                }
                Ok(recovery)
            }
            _ => Err(HostError::Fence(
                "Host historical namespace changed across native census",
            )),
        }
    }

    pub(super) fn failed_v5(&self) -> bool {
        self.first.is_some()
    }

    pub(super) fn cleanup_body_failed_v1(&self) -> bool {
        self.first.is_some() && !matches!(self.first,Some(First::After | First::DiscoveryDispose | First::ClockDispose))
    }

    pub(super) fn original_failure_selected_v5(&self) -> bool {
        self.original_selected
    }

    pub(super) fn format_failure_v5(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        if matches!(
            self.first,
            Some(
                First::DiscoveryBegin
                    | First::Listing(_)
                    | First::DiscoveryAfter
                    | First::DiscoveryClose
                    | First::DiscoveryDispose
            )
        ) {
            if let Ok(Some(native)) = self.discovery.native_failure_v5() {
                return match native.cause() {
                    aos_systemd_client::HostSystemdNativeFailureRefV2::Native(cause) => {
                        std::fmt::Display::fmt(cause, formatter)
                    }
                    aos_systemd_client::HostSystemdNativeFailureRefV2::Protocol(cause) => {
                        std::fmt::Display::fmt(cause, formatter)
                    }
                    aos_systemd_client::HostSystemdNativeFailureRefV2::Ended => {
                        formatter.write_str("Host discovery native receiver ended")
                    }
                };
            }
        }
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first {
            Some(First::Header) => self
                .header
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Context) => self
                .context
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Extension) => self
                .extension
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Clock(index)) => self
                .baseline
                .as_ref()
                .and_then(PairedClockBaselineV1::failure)
                .or_else(|| self.samples.as_ref()?.observation_failure(index))
                .or_else(|| {
                    self.clocks[index]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            Some(
                First::DiscoveryBegin
                | First::Listing(_)
                | First::DiscoveryAfter
                | First::DiscoveryClose
                | First::DiscoveryDispose,
            ) => self.discovery.failure_v5(),
            Some(First::Kernel(_)) => self.kernel.failure_v5(),
            Some(First::CleanupRoles) => self.owned_roles.as_ref().and_then(|roles|roles.failure_v8())
                .or_else(||self.cleanup_roles_post.as_ref()?.as_ref().err().map(|cause|cause as _)),
            Some(First::OwnedRole(index)) => self.owned_roles.as_ref()
                .and_then(|roles| roles.failure_v8())
                .or_else(|| self.owned_results[index].as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(First::History(index)) => self.history_reads[index]
                .as_ref()
                .and_then(crate::state::HostStateReadAttemptV2::failure)
                .or_else(|| {
                    self.history[index]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            Some(First::Before) => self
                .before
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|cause| cause as _),
            Some(First::After) => self
                .after
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Dispose) => self
                .dispose
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|cause| cause as _),
            Some(First::ClockDispose) => self
                .clock_dispose
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Deadline) => self
                .deadline
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Body) => self
                .body
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            _ => None,
        };
        match cause {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Host native inventory retains an incomplete original"),
        }
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(crate) fn requires_native_inventory_entry_v5(&self) -> bool {
        self.stopped_namespace_v4.is_none()
    }

    pub(crate) async fn inventory_runtime_received_native_v5(
        &mut self,
        body: &[u8],
        request_id: [u8; 16],
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot: [u8; 16],
        last_boottime: &mut Option<u64>,
    ) -> Result<Vec<u8>> {
        self.ensure_healthy()?;
        let live_source = self.live_cleanup_source_v1()?;
        // Every retained native owner must be absent, including failed/pending
        // owners. History selects a paid reconciliation candidate below; a
        // terminal State receipt is never substituted for native absence.
        if self.active_accepted_authorization.is_some()
            || (self.launch_original.is_some() && live_source.is_none())
            || self.argument_stages.iter().any(Option::is_some)
            || self.active_argument_writes.is_some()
            || self.active_launch_writes.is_some()
            || self.live_agent.is_some()
            || (live_source.is_none() && !self.runtime_pins.is_empty())
            || (live_source.is_none() && !self.observed_leaders.is_empty())
            || !self.live_limit_attempts.is_empty()
            || !self.fuse_workers.is_empty()
            || self
                .native_inventory_v5
                .as_ref()
                .is_some_and(|read| !read.complete)
        {
            return Err(HostError::Fence(
                "Host native inventory has occupied runtime custody",
            ));
        }
        let worker = self
            .worker
            .retained_payload_worker()
            .ok_or(HostError::Fence(
                "Host total inventory requires the actual installed worker",
            ))?;
        let control = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence("Host native inventory original is absent"))?;
        let mut control = control
            .lock()
            .map_err(|_| HostError::Fence("Host native inventory original is poisoned"))?;
        let (boot, recipient) = control.native_inventory_coordinates_v5()?;
        // This only selects geometry. Protected history is authenticated below
        // after the same original has paid both real snapshot readers.
        let mut population = if self.state.native_inventory_state_empty_v5() {
            PopulationV6::ColdEmpty
        } else {
            PopulationV6::HistoricalStopped
        };
        let historical = population.historical_v8();
        self.native_inventory_entry_v5 = Some((|| {
            let history = if historical {
                self.state
                    .native_inventory_history_receiving_demand_v6()
                    .ok_or(HostError::ResourceExhausted)?
            } else {
                ResourceVector::ZERO
            };
            entry_demand_v5(body.len())?
                .checked_add(history)
                .map_err(|_| HostError::ResourceExhausted)
        })());
        let entry = *self
            .native_inventory_entry_v5
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or(HostError::ResourceExhausted)?;
        let entered = match live_source.as_ref() {
            Some(source) => {
                let held = source
                    .lock()
                    .map_err(|_| HostError::AgentLaunchQuarantined)?;
                control.begin_live_native_inventory_entry_v1(
                    entry,
                    &mut self.native_inventory_original_selected_v5,
                    &held.borrow_live_cleanup_parent_v1()?,
                )
            }
            None => control.begin_native_inventory_entry_v5(
                entry,
                &mut self.native_inventory_original_selected_v5,
            ),
        };
        let mut loan = match entered {
            Ok(loan) => {
                self.native_inventory_funding_v5 = Some(Ok(()));
                loan
            }
            Err(cause) => {
                self.native_inventory_funding_v5 = Some(Err(cause));
                return Err(HostError::Fence(
                    "Host native inventory funding failed; original retained",
                ));
            }
        };
        if historical {
            // The admitted entry already includes the whole protected-history
            // invoice. This untrusted projection selects only a restrictive
            // readonly shape; both paid snapshots authenticate it below.
            if let Some(incarnation) = self.state.native_inventory_pending_incarnation_data_v8() {
                population = PopulationV6::HistoricalOwned(incarnation);
            }
        }
        self.native_inventory_v5 = Some(Box::new(HostNativeInventoryOriginalV5::new(population)));
        let read = self
            .native_inventory_v5
            .as_mut()
            .ok_or(HostError::ResourceExhausted)?;
        read.resident_scope = match live_source.as_ref() {
            Some(source) => Some(
                source
                    .lock()
                    .map_err(|_| HostError::AgentLaunchQuarantined)?
                    .borrow_live_cleanup_parent_v1()?
                    .namespace_scope_v1()?,
            ),
            None => None,
        };
        read.baseline = Some(PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::KERNEL_CLOCK_PROVENANCE),
        ));
        read.samples = Some(PairedClockSamplesV1::new());
        read.sample(0, None, boot);
        if let Some(Ok(sample)) = read.clocks[0].as_ref() {
            read.context = Some(
                if protected_boot != boot
                    || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                {
                    Err(HostError::Fence(
                        "Host native inventory authenticated boot/clock context changed",
                    ))
                } else {
                    Ok(())
                },
            );
            if matches!(read.context, Some(Ok(()))) {
                *last_boottime = Some(sample.boottime_nanoseconds());
                read.header = Some(crate::observation::decode_inventory_runtime_request(
                    body,
                    peer,
                    policy,
                    sample.boottime_nanoseconds(),
                ));
                if !matches!(read.header, Some(Ok(_))) {
                    read.first.get_or_insert(First::Header);
                }
                if let Some(Ok(header)) = read.header.as_ref() {
                    read.context = Some(
                        if header.request_id() == &request_id
                            && header.protocol_version() == protocol_version
                        {
                            Ok(())
                        } else {
                            Err(HostError::Fence(
                                "Host native inventory authenticated request context changed",
                            ))
                        },
                    );
                    if !matches!(read.context, Some(Ok(()))) {
                        read.first.get_or_insert(First::Context);
                    }
                }
            } else {
                read.first.get_or_insert(First::Context);
            }
        }
        if read.first.is_none() {
            read.extension = Some((|| {
                let header = read
                    .header
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(HostError::ResourceExhausted)?;
                self.native_inventory_shape_v5 = Some(
                    Shape::select(
                        loan.native_inventory_extension_available_v5()?,
                        header.maximum_response_bytes(),
                        population,
                    )
                    .ok_or(HostError::ResourceExhausted),
                );
                let shape = self
                    .native_inventory_shape_v5
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(HostError::ResourceExhausted)?;
                loan.extend_native_inventory_once_v5(shape.demand)
            })());
            if !matches!(read.extension, Some(Ok(()))) {
                read.original_selected = loan.original_failure_entered_v5();
                read.first.get_or_insert(First::Extension);
            }
        }
        // Even malformed/expired Header and extension refusal retain the
        // already-paid native-before and independently owed after destinations.
        read.before = Some(loan.observe_before_once_v5().await);
        if !matches!(read.before, Some(Ok(()))) && read.first.is_none() {
            read.original_selected = loan.original_failure_entered_v5();
            read.first = Some(First::Before);
        }
        let header = read.header.as_ref().and_then(|r| r.as_ref().ok()).copied();
        let shape = self
            .native_inventory_shape_v5
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .copied();
        if let (Some(header), Some(shape)) = (header.as_ref(), shape) {
            if read.first.is_none() {
                if population.owned_incarnation_v8().is_some() {
                    // The extended complete invoice includes every actual role
                    // probe and its constructor before this owning allocation.
                    read.owned_roles = Some(Box::new(crate::worker::HostOwnedRuntimeProofOriginalV8::new()));
                }
                // Convert only the already sampled remaining original horizon;
                // this timer does not create a new now+TTL permission window.
                read.deadline = Some((|| {
                    let sample = read.clocks[0]
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(HostError::ResourceExhausted)?;
                    let remaining = header
                        .deadline_boottime_nanoseconds()
                        .checked_sub(sample.boottime_nanoseconds())
                        .ok_or(HostError::ResourceExhausted)?;
                    tokio::time::Instant::now()
                        .checked_add(std::time::Duration::from_nanos(remaining))
                        .ok_or(HostError::ResourceExhausted)
                })());
                if let Some(Ok(deadline)) = read.deadline.as_ref() {
                    read.discovery_begin = Some(
                        read.discovery
                            .begin_once_v5(
                                shape.message,
                                shape.materialized,
                                *deadline,
                                header.deadline_boottime_nanoseconds(),
                            )
                            .await,
                    );
                    if !matches!(read.discovery_begin, Some(Ok(()))) {
                        read.first.get_or_insert(First::DiscoveryBegin);
                    }
                } else {
                    read.first.get_or_insert(First::Deadline);
                }
                read.capture_history_census_once_v1(&self.store, &self.state, &self.authority, &worker).await?;
                if read.discovery_begin.is_some() {
                    read.discovery_after = Some(read.discovery.observe_after_once_v5().await);
                    if !matches!(read.discovery_after, Some(Ok(()))) {
                        read.first.get_or_insert(First::DiscoveryAfter);
                    }
                }
            }
        }
        if read.first.is_none() && read.kernel_completed_v8() {
            read.discovery_close = Some(read.discovery.close_positive_body_once_v5().await);
            if !matches!(read.discovery_close, Some(Ok(()))) {
                read.first.get_or_insert(First::DiscoveryClose);
            }
        }
        // These are separate paid destinations even after earlier native,
        // clock, decoded residual or financial refusal. No healthy reentry.
        read.after = Some(loan.observe_after_once_v5().await);
        if !matches!(read.after, Some(Ok(()))) && read.first.is_none() {
            read.original_selected = loan.original_failure_entered_v5();
            read.first = Some(First::After);
        }
        read.sample(
            1,
            header
                .as_ref()
                .map(|header| header.deadline_boottime_nanoseconds()),
            boot,
        );
        if matches!(read.context, Some(Ok(()))) {
            if let Some(Ok(sample)) = read.clocks[1].as_ref() {
                *last_boottime = Some(sample.boottime_nanoseconds());
            }
        }
        if read.first.is_none() && read.kernel_completed_v8() {
            read.discovery_dispose = Some(read.discovery.dispose_positive_once_v5().await);
            if !matches!(read.discovery_dispose, Some(Ok(()))) {
                read.first.get_or_insert(First::DiscoveryDispose);
            }
        }
        if read.first.is_none() {
            read.clock_dispose = Some((|| {
                read.baseline
                    .as_mut()
                    .ok_or(HostError::ResourceExhausted)?
                    .retire_positive_native_file_v2()
                    .map_err(|_| {
                        HostError::Fence("Host native inventory baseline disposal failed")
                    })?;
                read.samples
                    .as_mut()
                    .ok_or(HostError::ResourceExhausted)?
                    .retire_positive_native_files_v2()
                    .map_err(|_| HostError::Fence("Host native inventory clock disposal failed"))
            })());
            if !matches!(read.clock_dispose, Some(Ok(()))) {
                read.first.get_or_insert(First::ClockDispose);
            }
        }
        if read.first.is_none() {
            read.body = Some((|| {
                let header = read
                    .header
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or(HostError::ResourceExhausted)?;
                if !read.census_completed_v8() {
                    return Err(HostError::Fence(
                        "Host native inventory complete census is absent",
                    ));
                }
                if let Some(expected) = read.resident_scope.as_ref() {
                    let candidate = read.history[1]
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(HostError::AgentLaunchQuarantined)?;
                    if candidate.launch_only_scope_v1() != Some(expected) {
                        return Err(HostError::Fence(
                            "live native Launch differs from protected Launch-only history",
                        ));
                    }
                }
                let before = read.clocks[0]
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(HostError::ResourceExhausted)?
                    .boottime_nanoseconds();
                let after = read.clocks[1]
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(HostError::ResourceExhausted)?
                    .boottime_nanoseconds();
                let native_absence_v5 = if historical {
                    Vec::new()
                } else {
                    HostInventoryAbsenceDataV5::from_data_v5(
                        *header.request_id(),
                        boot,
                        recipient,
                        before,
                        after,
                    )?
                    .encode_v5()
                    .to_vec()
                };
                let mut present_candidates = Vec::new();
                if let Some(candidate) = read.history[1]
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .filter(|candidate| candidate.dispatched_observation_scope_v1().is_some())
                {
                    if read.history[0]
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        != Some(candidate)
                    {
                        return Err(HostError::Fence(
                            "Launch-only history changed across native rounds",
                        ));
                    }
                    use aos_sandbox_protocol::host_launch_cleanup_candidate::{
                        HostLaunchCleanupCandidateDataV1, HostLaunchCleanupPopulationDataV1,
                    };
                    let population = match read.present_roles_v8() {
                        Some((payload, guardian)) => {
                            candidate.require_present_target_v1(payload, guardian)?;
                            HostLaunchCleanupPopulationDataV1::PresentOwned
                        }
                        None => {
                            read.require_launch_absent_rounds_v1()?;
                            HostLaunchCleanupPopulationDataV1::Absent
                        }
                    };
                    let launch = HostLaunchCleanupCandidateDataV1::from_data_v1(
                        candidate
                            .dispatched_observation_scope_v1()
                            .ok_or(HostError::ResourceExhausted)?,
                        *header.request_id(),
                        boot,
                        recipient,
                        before,
                        after,
                        population,
                    )?;
                    present_candidates.push(launch.encode_v1().to_vec());
                    read.launch_candidate = Some(launch);
                } else if let Some((payload, guardian)) = read.present_roles_v8() {
                    let candidate = read.history[1]
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(HostError::Fence(
                            "Host owned candidate lacks protected history",
                        ))?;
                    if read.history[0]
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        != Some(candidate)
                    {
                        return Err(HostError::Fence(
                            "Host owned candidate history changed across census",
                        ));
                    }
                    let phase = candidate.present_phase_v8(payload, guardian)?;
                    let present = HostStopCleanupCandidateDataV1::from_data_v1(
                        *candidate.stopped_scope_v1()?,
                        *header.request_id(),
                        boot,
                        recipient,
                        before,
                        after,
                        phase,
                    )?;
                    present_candidates.push(present.encode_v1().to_vec());
                    read.present = Some(present);
                }
                let mut cleanup_lineages = Vec::new();
                let bytes = InventoryRuntimeResponse {
                    native_absence_v5,
                    recovered_namespaces_v7: if historical
                        && read.present.is_none()
                        && read.launch_candidate.is_none()
                    {
                        let candidate = read.history[1]
                            .as_ref()
                            .and_then(|result| result.as_ref().ok())
                            .ok_or(HostError::Fence(
                                "Host historical namespace association is absent",
                            ))?;
                        if read.history[0]
                            .as_ref()
                            .and_then(|result| result.as_ref().ok())
                            != Some(candidate)
                        {
                            return Err(HostError::Fence(
                                "Host historical namespace changed across census",
                            ));
                        }
                        let observation = HostInventoryAbsenceDataV5::from_data_v5(
                            *header.request_id(),
                            boot,
                            recipient,
                            before,
                            after,
                        )?;
                        if let Some(lineage) = candidate.cleanup_lineage_data_v1(observation)? {
                            cleanup_lineages.push(lineage.encode_v1().to_vec());
                            read.lineage = Some(lineage);
                            Vec::new()
                        } else {
                            let phase = candidate.absent_phase_v7(after)?;
                            let recovery = HostRecoveredNamespaceDataV7::from_data_v7(
                                *candidate.stopped_scope_v1()?,
                                observation,
                                phase,
                            );
                            read.recovery = Some(recovery);
                            vec![recovery.encode_v7().to_vec()]
                        }
                    } else {
                        Vec::new()
                    },
                    present_stop_cleanup_candidates_v1: present_candidates,
                    cleanup_lineages_v1: cleanup_lineages,
                    ..Default::default()
                }
                .encode_to_vec();
                ensure_response_bound(&bytes, header.maximum_response_bytes())?;
                Ok(bytes)
            })());
            if !matches!(read.body, Some(Ok(_))) {
                read.first.get_or_insert(First::Body);
            }
        }
        if read.first.is_none() {
            read.dispose = Some(loan.dispose_positive_once_v5());
            if !matches!(read.dispose, Some(Ok(()))) {
                read.original_selected = loan.original_failure_entered_v5();
                read.first.get_or_insert(First::Dispose);
            }
        }
        if read.first.is_some() {
            return Err(HostError::Fence(
                "Host native inventory refused; full original retained",
            ));
        }
        read.complete = true;
        if historical {
            if let Err(cause) = read.reconciled_history_v8() {
                read.history[1] = Some(Err(cause));
                read.first.get_or_insert(First::History(1));
                read.complete = false;
                return Err(HostError::Fence(
                    "Host recovered native census completion refused; original retained",
                ));
            }
            // Only fully positive readers retire here after all native posts;
            // a failed read stays on this exact original with its first cause.
            read.history_reads = std::array::from_fn(|_| None);
        }
        read.body
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned()
            .ok_or(HostError::Fence("Host native inventory response is absent"))
    }
}

fn read_history_v6(
    store: &impl HostStateStore,
    expected: &crate::state::HostState,
    authority: &crate::authorization::HostAuthorityV1,
    original: &mut crate::state::HostStateReadAttemptV2,
) -> Result<HistoricalNamespaceCandidateV7> {
    let snapshot = store.load_retaining_v2(original)?;
    if snapshot != *expected {
        return Err(HostError::Fence(
            "Host historical namespace protected snapshot changed",
        ));
    }
    // The actual resident shape paid the authentication traversal. A changed
    // but valid larger snapshot cannot select unquoted historical work.
    snapshot.historical_namespace_candidate_v7(authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_profile_uses_actual_native_reply_extent_and_cannot_manufacture_completion() {
        let population = PopulationV6::HistoricalOwned([1; 16]);
        let message = HostRuntimeDiscoveryOriginalV5::message_extent_range_v5().0 * 16;
        let invoice = Shape::for_message(message, 4096, population).unwrap();
        assert_eq!(invoice.materialized,
            HostRuntimeDiscoveryOriginalV5::materialization_extent_for_owned_cleanup_v8([1; 16], message).unwrap());
        let selected = Shape::select(invoice.demand, 4096, population).unwrap();
        assert!(invoice.demand.checked_sub(selected.demand).is_ok());
        assert!(Shape::select(ResourceVector::ZERO, 4096, population).is_none());

        let mut original = HostNativeInventoryOriginalV5::new(population);
        original.complete = true;
        original.before = Some(Ok(()));
        original.after = Some(Ok(()));
        original.dispose = Some(Ok(()));
        assert!(!original.census_completed_v8());
        assert!(original.reconciled_history_v8().is_err());
        assert!(original.present_roles_v8().is_none());
    }

    #[test]
    fn historical_data_without_the_actual_completed_native_census_cannot_construct_a_terminal_owner()
     {
        let mut original = HostNativeInventoryOriginalV5::new(PopulationV6::HistoricalStopped);

        assert!(original.reconciled_namespace_v7().is_err());
        original.complete = true;
        original.before = Some(Ok(()));
        original.after = Some(Ok(()));
        original.dispose = Some(Ok(()));

        assert!(original.reconciled_namespace_v7().is_err());
        assert!(original.reconciled_namespace_v7().is_err());
    }

    #[test]
    fn actual_native_invoice_selects_only_inside_the_same_residual() {
        let minimum = HostRuntimeDiscoveryOriginalV5::message_extent_range_v5().0;
        let invoice = Shape::for_message(minimum * 16, 4096, PopulationV6::ColdEmpty).unwrap();
        let selected = Shape::select(invoice.demand, 4096, PopulationV6::ColdEmpty).unwrap();
        assert!(selected.message >= invoice.message);
        assert!(invoice.demand.checked_sub(selected.demand).is_ok());
        assert!(Shape::select(ResourceVector::ZERO, 4096, PopulationV6::ColdEmpty).is_none());
        let refused = invoice.demand.with(D::OpenFiles, 0);
        assert!(Shape::select(refused, 4096, PopulationV6::ColdEmpty).is_none());
    }
}

fn entry_demand_v5(actual_body_bytes: usize) -> Result<ResourceVector> {
    let model = HostInventoryAbsenceDataV5::request_decoding_memory_bytes_v5(actual_body_bytes)
        .ok_or(HostError::ResourceExhausted)?;
    let boot =
        aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
            .ok_or(HostError::ResourceExhausted)?;
    let bytes = std::mem::size_of::<HostNativeInventoryOriginalV5>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(5_usize.checked_mul(boot)?))
        .and_then(|bytes| bytes.checked_add(model))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(HostError::ResourceExhausted)?;
    PairedClockSamplesV1::receiving_demand_v1()
        .ok_or(HostError::ResourceExhausted)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        .map_err(|_| HostError::ResourceExhausted)
}
