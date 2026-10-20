//! Same-original Storage service receiving and protected Session replay.
//!
//! The sole constructor is entered by the first inherited Storage table. The
//! actual component pair, PID1 image, own process and fixed cgroup stay on its
//! enclosing worker owner. No decoded vector, caller file, row or timestamp can
//! reconstruct that owner. Charges are monotone; native resident bytes provide
//! no credit. Dominant capacities are conservative RFC-0006 obligations, with
//! the same actual cgroup and existing strict decoders backing residual costs.

// The existing initial recipe pays the actual main and one synchronously
// joined PID1 property observer. Physical workers cannot spend these slots.
const RESIDENT_PROCESS_SLOTS_V1: u64 = 2;

pub(super) mod aggregate;
mod launch_association;
mod currentness;
mod observer_operation;
mod initial_post;
mod initial_mode;
mod session;
mod lifecycle;
mod initial_pin_quiescence;
pub use initial_pin_quiescence::StorageInitialPinQuiescenceLoanV1;
use initial_pin_quiescence::InitialPinQuiescenceOriginalV1;

mod root_launch_export;
pub use root_launch_export::{StorageRootLaunchExportReceivingLoanV2, StorageRootLaunchExportDisposalV2};
use root_launch_export::RootLaunchExportReceivingOriginalV2;

mod floor_physical;
pub use floor_physical::StorageFloorPhysicalProgramReceivingV2;
use floor_physical::StorageFloorPhysicalReceivingOriginalV2;

mod floor_capture;
use floor_capture::StorageFloorCaptureReceivingOriginalV2;

mod physical_worker;
pub use physical_worker::{
    StoragePhysicalWorkerLoanV1, StorageBoundPhysicalWorkerLoanV1,
    StoragePhysicalWorkerDisposalV1,
    StorageResidentCaptureWorkerV2, StorageCaptureWorkerBorrowV2, StorageCaptureWorkerDisposalV2,
    StorageCaptureStopQuiescenceV4,
};
mod session_wire;
pub use session_wire::{StorageInitialSessionHelloDisposalV1, StorageSessionHelloDisposalErrorV1};
pub use lifecycle::{
    StorageOutputOwedAfterOriginalV1,
    StorageLifecycleSessionLoanV1, StorageLifecyclePositiveDisposalV1,
    StorageLifecycleDisposalErrorV1,
};
mod startup;
mod state_recovery;
pub use state_recovery::StorageStateRecoveryEncodingLoanV1;
use state_recovery::StateRecoveryEncodingOriginalV1;
mod native_opening_peak;
mod template;
pub use template::StorageGuestRootTemplateReceivingLoanV1;
use template::GuestRootTemplateReceivingV1;
use native_opening_peak::{NativeOpeningPeakV1, NativeOpeningKindV1};
pub use startup::StoragePrepareStartupJournalLoanV1;
use startup::StartupJournalStagesV1;
pub use session::StoragePrepareSessionReplayLoanV1;
use session::{OutcomeReservationV1, SessionJournalObservationV1};
use observer_operation::StorageObserverOperationOriginalV1;
use crate::journal::storage_native_commit::StorageNativeCommitOriginalV1;

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use crate::controller_resource_reservation::{
    StorageComponentEnvelopeOriginalV1, StorageComponentPairPostV1,
    component_receiving::ComponentServiceReceivingLedgerV1,
    service_interval::ObserverLifetime,
};
use crate::journal::StorageBrokerCapturedJournalOpenV1;
use crate::normal_root::{
    NormalRootStartupErrorV1, StorageWorkerParentDataV3,
    observe_fixed_storage_resource_parent_with_archive_v1, service,
};

use super::{StartupCustody, StorageResourceRecipientCustodyV1,
            StorageWorkerOriginCauseV3, StorageWorkerOriginV3};

type ParentResult = Result<(StorageWorkerParentDataV3, [u8; 16]), NormalRootStartupErrorV1>;
type NativeResult = Result<(), StorageWorkerOriginCauseV3>;

// These are selected PID1-property materialization obligations, not smaller
// transport limits. Existing decoders require 12 arguments of at most4096,
// plus at most one fixed <=64-byte git/Nix selector for resource Main,
// one executable <=4096, one fragment <=1024, empty drop-ins, fixed roles and
// contexts. Each of the existing 33 messages has a conservative 1024-byte
// header/path allowance; fixed tuples, identifiers and strings have 16 cells.
// A shape exceeding its paid materialization interval is refused by the shared
// raw-frame gate before decoding, under the unchanged 64KiB per-frame limit.
const PROPERTY_BYTES: usize = 33 * 1024 + 12 * (4096 + 16) + (64 + 16)
    + 4096 + 1024 + 16 * 256 + 2048;

/// Reports a closed receiving interval without replacing its original cause.
///
/// The actual worker retains accounting, property, native and replay Results;
/// this small status is never the authority or a substitute for those causes.
#[derive(Debug, thiserror::Error)]
#[error("the original Storage receiving interval is unavailable or closed")]
pub struct StorageReceivingClosedV1;

#[derive(Clone, Copy)]
enum Failure {
    Accounting,
    Arithmetic,
    Prefix,
    Containment,
    Aggregate,
    Archive,
    Before,
    Fields,
    NativeBefore,
    After,
    NativeAfter,
    Pair,
    Binding,
    Settlement,
    Current,
    SessionJournal,
    Lifecycle,
    PhysicalWorker,
    FloorCapture,
    FloorPhysical,
    RootLaunchExport,
    InitialPinQuiescence,
    LaunchAssociation,
    SessionWire,
    InitialPost,
    OutputAfter,
    Catalog,
    StartupProfile,
    StateRecovery,
    Template,
    StartupBootstrap,
    StartupResolverFloor,
    PrepareResolverFloor,
    Shape,
    Closed,
}

pub(super) struct StorageReceivingOriginalV1 {
    ceiling: ResourceVector,
    ledger: ComponentServiceReceivingLedgerV1,
    lifetime: ObserverLifetime,
    archive: service::FirstGlobalPropertyArchive,
    containment: ReceivingContainmentReadbackV1,
    prefix: Option<NativeResult>,
    archive_preparation: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<ParentResult>,
    fields: Option<NativeResult>,
    native_before: Option<NativeResult>,
    after: Option<ParentResult>,
    native_after: Option<NativeResult>,
    pair: Option<StorageComponentPairPostV1>,
    binding: Option<Result<(), StorageReceivingClosedV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    initial_transports_disposed: bool,
    current: StorageObserverOperationOriginalV1,
    initial_post: StorageObserverOperationOriginalV1,
    output_after: StorageObserverOperationOriginalV1,
    output_after_local_demand: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    output_after_local_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    initial_post_pending: bool,
    initial_mode_payment: Option<Result<(), StorageReceivingClosedV1>>,
    initial_post_local_demand: Option<Result<ResourceVector, aos_sandbox_core::AccountingError>>,
    initial_post_local_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    initial_post_result: Option<Result<(), StorageReceivingClosedV1>>,
    shape: Option<crate::JournalError>,
    arithmetic: Option<aos_sandbox_core::AccountingError>,
    first: Option<Failure>,
    attempted: bool,
    startup: StartupJournalStagesV1,
    state_recovery: StateRecoveryEncodingOriginalV1,
    lifecycle: lifecycle::LifecycleReceivingV1,
    physical_worker: physical_worker::PhysicalWorkerReceivingV1,
    floor_capture: StorageFloorCaptureReceivingOriginalV2,
    floor_physical: StorageFloorPhysicalReceivingOriginalV2,
    guest_root_serialization_name_paid: bool,
    guest_root_health_entered: bool,
    guest_root_health_models_paid: bool,
    guest_root_health_worker_entered: bool,
    root_launch_export: RootLaunchExportReceivingOriginalV2,
    initial_pin_quiescence: Option<InitialPinQuiescenceOriginalV1>,
    initial_pin_demand: Option<Result<ResourceVector, initial_pin_quiescence::DemandError>>,
    initial_pin_payment: Option<Result<(), StorageReceivingClosedV1>>,
    initial_pin_post: Option<NativeResult>,
    initial_pin_entered: bool,
    launch_association: launch_association::LaunchAssociationOriginalV1,
    session_wire: session_wire::SessionWireOriginalV1,
    session_identity: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
    session_journal: SessionJournalObservationV1,
    session_fixed: bool,
    session_prefix: bool,
    session_schema: bool,
    session_replayed: bool,
    session_initialization: bool,
    prepare_wire: bool,
    native_opening_peak: NativeOpeningPeakV1,
    template: GuestRootTemplateReceivingV1,
    catalog_observer_peak_paid: bool,
    inventory_paid: bool,
    inventory_outcome: OutcomeReservationV1,
    prepare_outcome: OutcomeReservationV1,
    replay_lane_paid: bool,
    catalog_paid: bool,
    catalog_append_paid: bool,
    preparation_append_high_water: ResourceVector,
    prepare_policy_append_paid: bool,
    catalog: StorageNativeCommitOriginalV1,
    startup_bootstrap: StorageNativeCommitOriginalV1,
    startup_resolver_floor: StorageNativeCommitOriginalV1,
    prepare_resolver_floor: StorageNativeCommitOriginalV1,
}

impl StorageReceivingOriginalV1 {
    pub(super) fn new(ceiling: ResourceVector, lifetime: ObserverLifetime) -> Self {
        Self {
            ceiling,
            ledger: ComponentServiceReceivingLedgerV1::new(ceiling),
            archive: service::FirstGlobalPropertyArchive::with_materialization_limit(
                2, lifetime.clone(), PROPERTY_BYTES,
            ),
            lifetime,
            containment: ReceivingContainmentReadbackV1::default(),
            prefix: None,
            archive_preparation: None,
            before: None,
            fields: None,
            native_before: None,
            after: None,
            native_after: None,
            pair: None,
            binding: None,
            settlement: None,
            initial_transports_disposed: false,
            current: StorageObserverOperationOriginalV1::new(),
            initial_post: StorageObserverOperationOriginalV1::new(),
            output_after: StorageObserverOperationOriginalV1::with_repeated_fixed_names_v1(),
            output_after_local_demand: None,
            output_after_local_reservation: None,
            initial_post_pending: false,
            initial_mode_payment: None,
            initial_post_local_demand: None,
            initial_post_local_reservation: None,
            initial_post_result: None,
            shape: None,
            arithmetic: None,
            first: None,
            attempted: false,
            startup: StartupJournalStagesV1::new(),
            state_recovery: StateRecoveryEncodingOriginalV1::new(),
            lifecycle: lifecycle::LifecycleReceivingV1::new(),
            physical_worker: physical_worker::PhysicalWorkerReceivingV1::new(),
            floor_capture: StorageFloorCaptureReceivingOriginalV2::new(),
            floor_physical: StorageFloorPhysicalReceivingOriginalV2::new(),
            guest_root_serialization_name_paid: false,
            guest_root_health_entered: false,
            guest_root_health_models_paid: false,
            guest_root_health_worker_entered: false,
            root_launch_export: RootLaunchExportReceivingOriginalV2::new(),
            initial_pin_quiescence: None,
            initial_pin_demand: None,
            initial_pin_payment: None,
            initial_pin_post: None,
            initial_pin_entered: false,
            launch_association: launch_association::LaunchAssociationOriginalV1::new(),
            session_wire: session_wire::SessionWireOriginalV1::new(),
            session_identity: None,
            session_journal: SessionJournalObservationV1::new(),
            session_fixed: false,
            session_prefix: false,
            session_schema: false,
            session_replayed: false,
            session_initialization: false,
            prepare_wire: false,
            native_opening_peak: NativeOpeningPeakV1::new(),
            template: GuestRootTemplateReceivingV1::new(),
            catalog_observer_peak_paid: false,
            inventory_paid: false,
            inventory_outcome: OutcomeReservationV1::new(),
            prepare_outcome: OutcomeReservationV1::new(),
            replay_lane_paid: false,
            catalog_paid: false,
            catalog_append_paid: false,
            preparation_append_high_water: ResourceVector::ZERO,
            prepare_policy_append_paid: false,
            catalog: StorageNativeCommitOriginalV1::new(),
            startup_bootstrap: StorageNativeCommitOriginalV1::new(),
            startup_resolver_floor: StorageNativeCommitOriginalV1::new(),
            prepare_resolver_floor: StorageNativeCommitOriginalV1::new(),
        }
    }

    fn reserve(&mut self, demand: ResourceVector) -> Result<(), StorageReceivingClosedV1> {
        if self.first.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        if self.ledger.reserve(demand).is_err() {
            self.first = Some(Failure::Accounting);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    fn startup_demand() -> Result<ResourceVector, StorageReceivingClosedV1> {
        let observer = service::fixed_property_observer_demand_v1(PROPERTY_BYTES)
            .map_err(|_| StorageReceivingClosedV1)?;
        // Fixed process/cgroup/image owners, immutable-image streaming hashes,
        // proc/argument scratch (Linux ARG_MAX), fixed native errors and paths.
        // Executables are streamed under their existing 16MiB limit, not read
        // into another executable-sized buffer. The six actual listeners and
        // original pair/image are retained throughout the whole service.
        ResourceVector::ZERO
            .with(D::MemoryBytes, std::mem::size_of::<Self>() as u64 + 4 * 1024 * 1024
                // Initial cleanup arithmetic/payment errors precede its native body.
                + 2 * 256)
            // stdio3 + inherited9 + retained duplicates9 + original/image/
            // own-pidfd6 + actual initial cgroup6 =33 retained slots. Fifteen
            // fixed Native path/proc/image verification slots cover transient
            // acquisitions; containment24 and observer7/row are added below.
            .with(D::OpenFiles, 48)
            .with(D::Pids, RESIDENT_PROCESS_SLOTS_V1)
            // Five empty admission headers and three actual Runtime borrow/scan/
            // disposal receipts precede any possible cleanup admission refusal.
            .with(D::MetadataEntries, 64 + 8)
            .checked_add(ReceivingContainmentReadbackV1::fixed_demand())
            .and_then(|demand| demand.checked_add(aggregate::StorageAggregateOriginalV1::fixed_demand()
                .map_err(|_| aos_sandbox_core::AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?))
            .and_then(|demand| demand.checked_add(observer))
            .and_then(|demand| demand.checked_add(observer))
            .map_err(|_| StorageReceivingClosedV1)
    }

    pub(super) fn capture_once(
        &mut self,
        custody: &mut StartupCustody,
        component: &StorageComponentEnvelopeOriginalV1,
        image: &OwnedFd,
    ) -> Result<(), StorageWorkerOriginCauseV3> {
        if self.attempted {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageWorkerOriginCauseV3::Closed);
        }
        self.attempted = true;
        let demand = match Self::startup_demand() {
            Ok(demand) => demand,
            Err(_) => {
                self.first = Some(Failure::Shape);
                return Err(StorageWorkerOriginCauseV3::Binding);
            }
        };
        if self.reserve(demand).is_err() {
            return Err(StorageWorkerOriginCauseV3::Binding);
        }

        self.prefix = Some(custody.capture_native_receiving_prefix(image, self.ceiling));
        if matches!(self.prefix, Some(Err(_))) {
            self.first = Some(Failure::Prefix);
            return Err(StorageWorkerOriginCauseV3::Binding);
        }
        match custody.cgroup.as_ref() {
            Some(anchor) => self.containment.capture(anchor, self.ceiling),
            None => {
                self.first = Some(Failure::Closed);
                return Err(StorageWorkerOriginCauseV3::Binding);
            }
        }
        if self.containment.require_initial().is_err() {
            self.first = Some(Failure::Containment);
            return Err(StorageWorkerOriginCauseV3::Binding);
        }
        self.archive_preparation = Some(self.archive.prepare());
        if matches!(self.archive_preparation, Some(Err(_))) {
            self.first = Some(Failure::Archive);
            return Err(StorageWorkerOriginCauseV3::Binding);
        }

        self.before = Some(observe_fixed_storage_resource_parent_with_archive_v1(&mut self.archive));
        if matches!(self.before, Some(Err(_))) {
            self.first = Some(Failure::Before);
        }
        if let Some(Ok((before, _))) = &self.before {
            self.fields = Some(custody.capture_observed_fields(before));
            if matches!(self.fields, Some(Err(_))) {
                self.first.get_or_insert(Failure::Fields);
            }
        }
        self.native_before = Some(custody.recheck_native_before());
        if matches!(self.native_before, Some(Err(_))) {
            self.first.get_or_insert(Failure::NativeBefore);
        }

        // Both fresh enclosing property flights and all independent posts run
        // even after an earlier refusal. None is reconstructed from the first.
        self.after = Some(observe_fixed_storage_resource_parent_with_archive_v1(&mut self.archive));
        if matches!(self.after, Some(Err(_))) {
            self.first.get_or_insert(Failure::After);
        }
        self.native_after = Some(custody.recheck_native_after());
        if matches!(self.native_after, Some(Err(_))) {
            self.first.get_or_insert(Failure::NativeAfter);
        }
        self.pair = Some(component.storage_receiving_pair_post());
        if self.pair.as_ref().is_some_and(|post| post.failure().is_some()) {
            self.first.get_or_insert(Failure::Pair);
        }
        if let Some(anchor) = custody.cgroup.as_ref() {
            self.containment.recheck(anchor);
        }
        if self.containment.require_current().is_err() {
            self.first.get_or_insert(Failure::Containment);
        }
        custody.aggregate.recheck_once();
        if custody.aggregate.failure().is_some() {
            self.first.get_or_insert(Failure::Aggregate);
        }
        self.binding = Some((|| {
            let (before, before_producer) = self.before.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(StorageReceivingClosedV1)?;
            let (after, after_producer) = self.after.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(StorageReceivingClosedV1)?;
            if before != after {
                return Err(StorageReceivingClosedV1);
            }
            component.require_storage_receiving_binding(
                (before.invocation(), *before_producer), (after.invocation(), *after_producer),
            ).map_err(|_| StorageReceivingClosedV1)
        })());
        if matches!(self.binding, Some(Err(_))) {
            self.first.get_or_insert(Failure::Binding);
        }
        if self.first.is_none() {
            self.settlement = Some(self.archive.settle_positive_once());
            if matches!(self.settlement, Some(Err(_))) {
                self.first = Some(Failure::Settlement);
            }
        }
        if self.first.is_none() {
            self.containment.settle_positive_named_verifications_once_v1();
            custody.aggregate.settle_initial_once();
            if !custody.aggregate.is_current() {
                self.first.get_or_insert(Failure::Aggregate);
            }
            if !self.containment.named_verifications_settled_v1() {
                self.first = Some(Failure::Containment);
            } else {
                // The actual initial two-flight transport archive is positively
                // settled and all joins/posts completed. Dispose it now; keep
                // both actual Parent Results plus the genuine component pair,
                // process, images and eight readable native control originals.
                let empty = service::FirstGlobalPropertyArchive::with_materialization_limit(
                    0, self.lifetime.clone(), 0);
                drop(std::mem::replace(&mut self.archive, empty));
                self.initial_transports_disposed = true;
            }
        }
        self.require_initial().map_err(|_| StorageWorkerOriginCauseV3::Binding)
    }

    pub(super) fn require_service_handoff_v1(&self) -> Result<(), StorageReceivingClosedV1> {
        self.require_initial()?;
        if !self.lifecycle.is_parked_v1() || !self.session_wire.is_between_flights_v1()
            || self.initial_post_pending || !self.root_launch_export.is_idle_v2()
        {
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn require_initial(&self) -> Result<(), StorageReceivingClosedV1> {
        if self.first.is_some() || !matches!(self.binding, Some(Ok(())))
            || !matches!(self.settlement, Some(Ok(()))) {
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn observe_current(
        &mut self,
        custody: &StartupCustody,
        component: &StorageComponentEnvelopeOriginalV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_initial()?;
        if !self.initial_transports_disposed || !self.containment.named_verifications_settled_v1() {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let Some(initial) = self.before.as_ref().and_then(|result| result.as_ref().ok()) else {
            self.first = Some(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        };
        let observed = self.current.observe(
            &mut self.ledger,
            &self.lifetime,
            custody,
            component,
            initial,
            &self.containment,
        );
        if observed.is_err() {
            self.first = Some(if self.ledger.failure().is_some() {
                Failure::Accounting
            } else {
                Failure::Current
            });
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn failed_aggregate_v1(&self) -> bool {
        matches!(self.first, Some(Failure::Aggregate))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            Failure::Accounting => self.ledger.failure().map(|e| e as &dyn Error),
            Failure::Arithmetic => self.arithmetic.as_ref().map(|e| e as &dyn Error),
            Failure::Prefix => native_failure(&self.prefix),
            Failure::Containment => self.containment.failure(),
            // Actual aggregate originals stay on the enclosing startup owner.
            // Its initial-capture/currentness failure resolver borrows them.
            Failure::Aggregate => Some(&StorageReceivingClosedV1),
            Failure::Archive => self.archive_preparation.as_ref().and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn Error),
            Failure::Before => self.before.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            Failure::Fields => native_failure(&self.fields),
            Failure::NativeBefore => native_failure(&self.native_before),
            Failure::After => self.after.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            Failure::NativeAfter => native_failure(&self.native_after),
            Failure::Pair => self.pair.as_ref().and_then(StorageComponentPairPostV1::failure),
            Failure::Binding => self.binding.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            Failure::Settlement => self.settlement.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            Failure::Current => self.current.failure(),
            Failure::Lifecycle => self.lifecycle.failure(),
            Failure::PhysicalWorker => self.physical_worker.failure(),
            Failure::FloorPhysical => self.floor_physical.failure().or_else(|| self.ledger.failure().map(|cause| cause as _)),
            Failure::FloorCapture => self.floor_capture.failure().or_else(|| self.ledger.failure().map(|cause| cause as _)),
            Failure::RootLaunchExport => self.root_launch_export.failure(&self.ledger, &self.current),
            Failure::InitialPinQuiescence => self.initial_pin_demand.as_ref()
                .and_then(|value| value.as_ref().err()).map(|cause| cause as &dyn Error)
                .or_else(|| self.initial_pin_quiescence.as_ref().and_then(InitialPinQuiescenceOriginalV1::failure))
                .or_else(|| native_failure(&self.initial_pin_post)),
            Failure::LaunchAssociation => self.launch_association.failure(),
            Failure::SessionWire => self.session_wire.failure(),
            Failure::InitialPost => self.initial_post_local_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
                .or_else(|| self.initial_post.failure()),
            Failure::OutputAfter => self.output_after_local_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
                .or_else(|| self.output_after.failure()),
            Failure::SessionJournal => self.session_journal.failure(),
            Failure::Catalog => self.catalog.failure(),
            Failure::Template => self.template.failure(),
            Failure::StateRecovery => self.lifecycle.state_recovery.failure()
                .or_else(|| self.state_recovery.failure()),
            Failure::StartupProfile => self.startup.failure().map(|cause| cause as &dyn Error),
            Failure::StartupBootstrap => self.startup_bootstrap.failure(),
            Failure::StartupResolverFloor => self.startup_resolver_floor.failure(),
            Failure::PrepareResolverFloor => self.prepare_resolver_floor.failure(),
            Failure::Shape => self.shape.as_ref().map(|e| e as &dyn Error),
            Failure::Closed => None,
        };
        cause.or(Some(&StorageReceivingClosedV1))
    }
}


fn native_failure(result: &Option<NativeResult>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error)
}

/// Borrows one genuine Storage receiver through protected Prepare work.
///
/// Construction requires the actual retained worker owner. It exposes no file,
/// decoded grant or independent resource account, and cannot be cloned.
#[must_use]
pub struct StoragePrepareReceivingLoanV1<'original> {
    original: &'original mut StorageWorkerOriginV3,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    pub(super) fn new(original: &'original mut StorageWorkerOriginV3) -> Self {
        Self { original }
    }

    /// Retains a compiled native-geometry refusal in this same receiving owner.
    pub(crate) fn retain_native_geometry_refusal_v1(
        &mut self,
        error: aos_sandbox_core::AccountingError,
    ) -> StorageReceivingClosedV1 {
        if let Ok(receiving) = self.receiving() {
            if receiving.arithmetic.is_none() {
                receiving.arithmetic = Some(error);
            }
            receiving.first.get_or_insert(Failure::Arithmetic);
        }
        StorageReceivingClosedV1
    }

    fn receiving(&mut self) -> Result<&mut StorageReceivingOriginalV1, StorageReceivingClosedV1> {
        if !self.original.open {
            return Err(StorageReceivingClosedV1);
        }
        match self.original.recipient.as_mut() {
            Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) => {
                receiving.require_initial()?;
                if !receiving.root_launch_export.is_idle_v2() {
                    return Err(StorageReceivingClosedV1);
                }
                Ok(receiving)
            }
            _ => Err(StorageReceivingClosedV1),
        }
    }

}

use aos_sandbox_broker::receiving::receiving_limits::{ReceivingContainmentReadbackV1, ReceivingContainmentCurrentnessV1};
