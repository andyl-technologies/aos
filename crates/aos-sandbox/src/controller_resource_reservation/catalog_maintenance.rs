//! Owns one genuine finite maintenance interval on the current Controller B.
//!
//! This purpose pays observation and catalog DATA publication. It supplies no
//! ownership or effect grant. Optional Storage guest-root work must separately
//! derive its exact protected assignment, reservation, signed plan and lease.
//! Every entered Source/C/clock destination remains independently owed.

mod append;
mod append_recipe;
mod cold;
pub use cold::CatalogMaintenanceColdCompletedNativeBorrowV2;
mod warm;
mod guest_root;
pub(crate) use guest_root::ControllerCatalogMaintenanceRootLoanV3;
pub use guest_root::ControllerCatalogMaintenanceSigningBorrowV3;
pub use guest_root::ControllerMaintenanceStorageRequestOriginalV3;
pub use guest_root::ControllerMaintenanceStorageIoLoanV3;
pub use guest_root::ControllerMaintenanceStorageSdkDisposalV3;
pub use warm::CatalogMaintenanceRefreshCompletedNativeBorrowV2;
mod bridge;
mod catalog_io;
mod clock;
pub(crate) use append::CatalogMaintenanceAppendContextV2;
pub use bridge::CatalogMaintenanceSourceBorrowV2;
pub use catalog_io::{
    ControllerCatalogMaintenanceCatalogDisposalV2, ControllerCatalogMaintenanceCompletionRefusalV2,
    ControllerCatalogMaintenanceIoLoanV2, ControllerCatalogMaintenanceSessionCurrentnessErrorV2,
};
mod inventory_evidence;
mod queries;
mod snapshots;
mod source_projection;
mod completed_start;
pub(super) mod closed_family;
mod recover_family;
pub(crate) use completed_start::{
    CatalogMaintenanceCompletedStartDataV1, CatalogMaintenanceCompletedStartOriginalV1,
};
pub(crate) use queries::CatalogMaintenanceSourceReceivingV2;
pub use queries::ControllerCatalogMaintenanceLoanV2;

use std::error::Error;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use super::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::{Journal, JournalError};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2;
use aos_sandbox_broker::source_receiving::SourceCatalogMaintenanceCurrentnessOriginalV2;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use clock::CatalogMaintenanceClockV2;
use source_projection::CatalogMaintenanceSourceProjectionV2;

/// Refuses incomplete maintenance while its actual originals remain resident.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the current catalog maintenance interval is incomplete or refused")]
#[doc(hidden)]
pub struct CatalogMaintenanceClosedV2;

#[derive(Clone, Copy, Eq, PartialEq)]
enum MaintenancePurposeV2 {
    ColdPopulation,
    CatalogRefresh,
}

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Append(usize),
    Geometry,
    Native,
    ClockBefore,
    ClockFrontier,
    SourceGeometry,
    SourceBefore,
    SourceProjection,
    Current,
    CurrentNative,
    CurrentSource,
    Funding,
    Body,
    Sdk,
    Inventory(usize),
    InventoryEvidence(usize),
    Snapshot(usize),
    CatalogIo,
    SourceAfter,
    ControllerAfter,
    SourceDisposal,
    ClockAfter,
    Cold,
    Warm,
    GuestRoot,
}

/// Describes concrete SDK inline construction DATA before native maintenance entry.
///
/// It selects no account, purpose, Session or authority. The actual SDK's
/// compiled supplier is the installed caller; native and Source suppliers are
/// added independently by their owning engines.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct CatalogMaintenanceSdkShapeDataV2 {
    /// Memory of the actual enclosing SDK owner and its construction destination.
    pub inline_and_construction_bytes: u64,
}

/// Retains the original payment, Source, mechanical horizon and all owed posts.
///
/// Empty construction performs no IO or allocation. This owner cannot be
/// cloned, rearmed after a refusal or built from a numeric resource vector.
#[doc(hidden)]
#[must_use = "retain all originals through every independently owed post"]
pub struct CatalogMaintenanceOriginalV2 {
    purpose: Option<MaintenancePurposeV2>,
    cold: cold::CatalogMaintenanceColdOriginalV2,
    warm: warm::CatalogMaintenanceWarmOriginalV2,
    guest_root: guest_root::CatalogMaintenanceGuestRootOriginalV3,
    bank: Option<Arc<Mutex<ControllerResourceBankOpeningV1>>>,
    profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    native: Option<Result<ControllerCatalogMaintenanceReceivingV2, ResourceReservationErrorV1>>,
    clock: CatalogMaintenanceClockV2,
    clock_before: Option<Result<(), JournalError>>,
    source_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    source_projection: CatalogMaintenanceSourceProjectionV2,
    source:
        Option<Result<SourceCatalogMaintenanceCurrentnessOriginalV2, ResourceReservationErrorV1>>,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    inventory: [super::operator_create_recovery::storage::inventory::InventoryOriginalsV1; 4],
    inventory_evidence: inventory_evidence::CatalogMaintenanceInventoryEvidenceV2,
    snapshots: snapshots::CatalogMaintenanceSnapshotsOriginalV2,
    appends: append::CatalogMaintenanceAppendOriginalsV2,
    catalog_source_entered: bool,
    catalog_io_entered: bool,
    catalog_io: catalog_io::CatalogMaintenanceIoOriginalV2,
    sdk_refusal: Option<JournalError>,
    reached: ResourceVector,
    body: Option<Result<(), CatalogMaintenanceClosedV2>>,
    source_after: Option<Result<(), JournalError>>,
    controller_after: Option<Result<(), ResourceReservationErrorV1>>,
    source_disposal: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
    reentry: CatalogMaintenanceClosedV2,
}

impl CatalogMaintenanceOriginalV2 {
    /// Creates only the inert retained destinations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            purpose: None,
            cold: cold::CatalogMaintenanceColdOriginalV2::new(),
            warm: warm::CatalogMaintenanceWarmOriginalV2::new(),
            guest_root: guest_root::CatalogMaintenanceGuestRootOriginalV3::new(),
            bank: None,
            profile: None,
            runtime: None,
            geometry: None,
            native: None,
            clock: Default::default(),
            clock_before: None,
            source_geometry: None,
            source_projection: CatalogMaintenanceSourceProjectionV2::new(),
            source: None,
            current: None,
            funding: None,
            inventory: std::array::from_fn(|_| Default::default()),
            inventory_evidence: inventory_evidence::CatalogMaintenanceInventoryEvidenceV2::new(),
            snapshots: snapshots::CatalogMaintenanceSnapshotsOriginalV2::new(),
            appends: append::CatalogMaintenanceAppendOriginalsV2::new(),
            catalog_source_entered: false,
            catalog_io_entered: false,
            catalog_io: catalog_io::CatalogMaintenanceIoOriginalV2::new(),
            sdk_refusal: None,
            reached: ResourceVector::ZERO,
            body: None,
            source_after: None,
            controller_after: None,
            source_disposal: None,
            first: None,
            reentry: CatalogMaintenanceClosedV2,
        }
    }

    // The actual Runtime must already retain this complete inline header.
    // These newly reached construction/native/control costs exclude permanent
    // Session/context residents, which the same B sums intrinsically.
    fn fixed_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .checked_add(CatalogMaintenanceClockV2::receiving_demand_v2()?)
            .map_err(Into::into)
    }

    /// Enters only the actual new finite maintenance purpose on the same B.
    ///
    /// The native constructor pays its complete eight-append roster before
    /// entry. A fresh paired-before then establishes the mechanical transport
    /// cutoff, followed by the same actual Source pair. Initial HELLO payment
    /// and acquisition time are never reused for this work.
    ///
    /// # Errors
    /// Retains reentry, compiled geometry, original/native payment, clock or
    /// Source refusal. The caller must always invoke `finish_native_once_v2`.
    pub fn begin_once_v2(
        &mut self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
        runtime: &Arc<tokio::runtime::Runtime>,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), CatalogMaintenanceClosedV2> {
        self.begin_selected_once_v2(
            MaintenancePurposeV2::ColdPopulation,
            bank,
            profile,
            runtime,
            controller,
            source,
            0,
        )
    }

    /// Enters a recurring catalog refresh without claiming cold population absence.
    ///
    /// This closed schedule uses fresh Mount16, Storage18 and Network19. It
    /// does not require a Host absence certificate while runtimes are live.
    /// The same current B, Source and independent native posts remain mandatory.
    ///
    /// # Errors
    /// Retains reentry, native admission, Source replay, clock or geometry
    /// refusal. Every entered destination still requires its native finish.
    pub fn begin_refresh_once_v2(
        &mut self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
        runtime: &Arc<tokio::runtime::Runtime>,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), CatalogMaintenanceClosedV2> {
        self.begin_selected_once_v2(
            MaintenancePurposeV2::CatalogRefresh,
            bank,
            profile,
            runtime,
            controller,
            source,
            0,
        )
    }

    /// Enters cold maintenance with the actual SDK owner's compiled shape prepaid.
    ///
    /// # Errors
    /// Retains the same geometry, payment, clock and Source failures as ordinary entry.
    #[doc(hidden)]
    pub fn begin_cold_with_sdk_shape_once_v2(
        &mut self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
        runtime: &Arc<tokio::runtime::Runtime>,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        shape: CatalogMaintenanceSdkShapeDataV2,
    ) -> Result<(), CatalogMaintenanceClosedV2> {
        self.begin_selected_once_v2(
            MaintenancePurposeV2::ColdPopulation,
            bank,
            profile,
            runtime,
            controller,
            source,
            shape.inline_and_construction_bytes,
        )
    }

    /// Enters recurring maintenance with its actual enclosing SDK shape prepaid.
    ///
    /// # Errors
    /// Retains changed scope, geometry, native payment, clock and Source failure.
    #[doc(hidden)]
    pub fn begin_refresh_with_sdk_shape_once_v2(
        &mut self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
        runtime: &Arc<tokio::runtime::Runtime>,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        shape: CatalogMaintenanceSdkShapeDataV2,
    ) -> Result<(), CatalogMaintenanceClosedV2> {
        self.begin_selected_once_v2(
            MaintenancePurposeV2::CatalogRefresh,
            bank,
            profile,
            runtime,
            controller,
            source,
            shape.inline_and_construction_bytes,
        )
    }

    fn begin_selected_once_v2(
        &mut self,
        purpose: MaintenancePurposeV2,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
        runtime: &Arc<tokio::runtime::Runtime>,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        sdk_bytes: u64,
    ) -> Result<(), CatalogMaintenanceClosedV2> {
        if self.geometry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CatalogMaintenanceClosedV2);
        }
        self.purpose = Some(purpose);
        self.bank = Some(Arc::clone(bank));
        self.profile = Some(Arc::clone(profile));
        self.runtime = Some(Arc::clone(runtime));
        self.geometry = Some(Self::fixed_demand_v2().and_then(|fixed| {
            fixed
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, sdk_bytes))
                .map_err(Into::into)
        }));
        let Some(fixed) = self
            .geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            self.first = Some(First::Geometry);
            return Err(CatalogMaintenanceClosedV2);
        };
        self.reached = fixed;
        self.native = Some(
            bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                .and_then(|bank| {
                    bank.begin_catalog_maintenance_native_v2(controller, profile, fixed)
                }),
        );
        if !self.native.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .is_ok_and(|native| native.require_prepaid_owed_observation_v2().is_ok())
        }) {
            self.first = Some(First::Native);
            return Err(CatalogMaintenanceClosedV2);
        }
        // The negative-capable native return may already own a failed before
        // or profile observation. Select it before entering any later sampler.
        if self.native.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .is_ok_and(|native| native.failure_v2().is_some())
        }) {
            self.first = Some(First::Native);
            return Err(CatalogMaintenanceClosedV2);
        }
        self.clock_before = Some(
            self.clock.begin_once_v2(
                self.native
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(CatalogMaintenanceClosedV2)?,
            ),
        );
        if !matches!(self.clock_before, Some(Ok(()))) {
            self.first = Some(First::ClockBefore);
            return Err(CatalogMaintenanceClosedV2);
        }
        self.source_geometry = Some(
            SourceCatalogMaintenanceCurrentnessOriginalV2::receiving_demand_v2()
                .map_err(ResourceReservationErrorV1::from)
                .and_then(|demand| fixed.checked_add(demand).map_err(Into::into)),
        );
        if !matches!(self.source_geometry, Some(Ok(_))) {
            self.first = Some(First::SourceGeometry);
            return Err(CatalogMaintenanceClosedV2);
        }
        self.source = Some(
            bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                .and_then(|bank| {
                    bank.begin_source_catalog_maintenance_v2(
                        self.native
                            .as_mut()
                            .and_then(|result| result.as_mut().ok())
                            .ok_or(ResourceReservationErrorV1::Conflict)?,
                        controller,
                        source,
                        profile,
                        fixed,
                    )
                }),
        );
        if !self.source.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .is_ok_and(|source| source.failure_v2().is_none())
        }) {
            self.first = Some(First::SourceBefore);
            return Err(CatalogMaintenanceClosedV2);
        }
        self.reached = self
            .source_geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(CatalogMaintenanceClosedV2)?;
        self.observe_source_projection_once_v2(controller, source)
            .map_err(|_| CatalogMaintenanceClosedV2)?;
        if purpose == MaintenancePurposeV2::ColdPopulation {
            self.cold.baseline =
                Some((|| {
                    if let Some((_, starts)) = self.source_projection.stopped_history_v2(
                        controller, source.journal_ref_v1())? {
                        let bank = self.bank.as_ref().ok_or(JournalError::ProtectedBoundary)?
                            .lock().map_err(|_| JournalError::ProtectedBoundary)?;
                        starts.require_enrolled_nodes_v1(&bank)
                            .map_err(|_| JournalError::ProtectedBoundary)
                    } else {
                        controller.require_cold_controller_family_for_maintenance_data_v2()
                    }
                })());
            if !matches!(self.cold.baseline, Some(Ok(()))) {
                self.first.get_or_insert(First::Cold);
                return Err(CatalogMaintenanceClosedV2);
            }

            if self
                .source_projection
                .observe_cold_scope_once_v2(source.journal_ref_v1())
                .is_err()
            {
                self.first.get_or_insert(First::SourceProjection);
                return Err(CatalogMaintenanceClosedV2);
            }
        }
        Ok(())
    }

    pub(super) fn require_current_v2(
        &mut self,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some() || self.body.is_some() || self.controller_after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut current_native_selected = false;
        let mut current_source_selected = false;
        self.current = Some((|| {
            let bank = self
                .bank
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let profile = self
                .profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let native = self
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let current = bank.require_catalog_maintenance_current_v2(native, controller, profile);
            if current.is_err() {
                current_native_selected = native.failure_v2().is_some();
                return current;
            }
            let original = self
                .source
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let current = bank.require_source_catalog_maintenance_current_v2(
                original, native, controller, source, profile,
            );
            if current.is_err() {
                current_source_selected = original.failure_v2().is_some();
            }
            current
        })());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(if current_native_selected {
                First::CurrentNative
            } else if current_source_selected {
                First::CurrentSource
            } else {
                First::Current
            });
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn reserve_additional_v2(
        &mut self,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        contribution: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller, source)?;
        // Failed contributions remain selected; nothing replaces the earlier
        // same-operation requirement with a smaller highwater or refunds traffic.
        self.funding = Some((|| {
            let complete = self.reached.checked_add(contribution)?;
            let native = self
                .native
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.bank
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_catalog_maintenance_complete_v2(
                    native,
                    controller,
                    self.profile
                        .as_ref()
                        .ok_or(ResourceReservationErrorV1::Conflict)?,
                    complete,
                )?;
            self.reached = complete;
            Ok(())
        })());
        if !matches!(self.funding, Some(Ok(()))) {
            self.first.get_or_insert(First::Funding);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn observe_source_projection_once_v2(
        &mut self,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller, source)?;
        self.source_projection
            .prepare_geometry_once_v2(source.journal_ref_v1(), controller,
                self.purpose == Some(MaintenancePurposeV2::ColdPopulation));
        let geometry = match self.source_projection.receiving_demand_v2() {
            Ok(geometry) => geometry,
            Err(_) => {
                self.first.get_or_insert(First::SourceProjection);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        self.reserve_additional_v2(controller, source, geometry)?;
        self.check_frontier_v2()?;
        let returned = self
            .source_projection
            .observe_once_v2(source.journal_ref_v1(), controller);
        if returned.is_err() {
            self.first.get_or_insert(First::SourceProjection);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }

    pub(super) fn check_frontier_v2(&mut self) -> Result<RawPairedClockSample, JournalError> {
        let returned = self.clock.check_frontier_v2();
        if returned.is_err() {
            self.first.get_or_insert(First::ClockFrontier);
        }
        returned
    }

    /// Parks the actual body's negative result before independent native posts.
    ///
    /// This marker cannot prove a completed query or catalog publication.
    pub fn retain_body_result_v2(&mut self, result: Result<(), CatalogMaintenanceClosedV2>) {
        if self.body.is_some() {
            self.first.get_or_insert(First::Reentry);
            return;
        }
        if result.is_ok() && self.guest_root.reject_unfinished_root_body_v3() {
            self.first.get_or_insert(First::GuestRoot);
            self.body = Some(Err(CatalogMaintenanceClosedV2));
            return;
        }
        if result.is_err() {
            self.first.get_or_insert(First::Body);
        }
        self.body = Some(result);
    }

    /// Runs every entered Source, C and final-clock destination independently.
    ///
    /// Missing body completion is retained as refusal. No failed primary may
    /// suppress the paid after samplers or replace its earlier selected cause.
    pub fn finish_native_once_v2(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) {
        if self.body.is_none() {
            self.retain_body_result_v2(Err(CatalogMaintenanceClosedV2));
        }
        if self.source_after.is_none() {
            if let Some(Ok(original)) = self.source.as_mut() {
                self.source_after = Some(
                    source
                        .journal_ref_v1()
                        .finish_source_catalog_maintenance_native_v2(original),
                );
                if !matches!(self.source_after, Some(Ok(()))) {
                    self.first.get_or_insert(First::SourceAfter);
                }
            }
        }
        if self.controller_after.is_none() {
            self.controller_after = Some((|| {
                let native = self
                    .native
                    .as_mut()
                    .and_then(|result| result.as_mut().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                self.bank
                    .as_ref()
                    .ok_or(ResourceReservationErrorV1::Conflict)?
                    .lock()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .finish_catalog_maintenance_native_once_v2(
                        native,
                        controller,
                        self.profile
                            .as_ref()
                            .ok_or(ResourceReservationErrorV1::Conflict)?,
                    )
            })());
            if !matches!(self.controller_after, Some(Ok(()))) {
                self.first.get_or_insert(First::ControllerAfter);
            }
        }
        if self.source_disposal.is_none() {
            if let Some(Ok(original)) = self.source.as_mut() {
                self.source_disposal = Some((|| {
                    self.bank
                        .as_ref()
                        .ok_or(ResourceReservationErrorV1::Conflict)?
                        .lock()
                        .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                        .dispose_source_catalog_maintenance_v2(
                            original,
                            self.native
                                .as_ref()
                                .and_then(|result| result.as_ref().ok())
                                .ok_or(ResourceReservationErrorV1::Conflict)?,
                            controller,
                            source,
                            self.profile
                                .as_ref()
                                .ok_or(ResourceReservationErrorV1::Conflict)?,
                        )
                })());
                if !matches!(self.source_disposal, Some(Ok(()))) {
                    self.first.get_or_insert(First::SourceDisposal);
                }
            }
        }
        if let Some(Ok(native)) = self.native.as_ref() {
            self.clock.finish_once_v2(native);
            if self.clock.failure_v2().is_some() {
                self.first.get_or_insert(First::ClockAfter);
            }
        }
        if self.first.is_none() {
            self.finish_append_disposals_v2(controller);
        }
    }

    // This private post gate does not reopen the finished native turn or allow
    // another request. Actual SDK disposal and cold completion add their own
    // concrete retained source/query/Session conjunctions afterwards.
    pub(super) fn require_completed_posts_v2(
        &self,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.source_after, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !matches!(self.source_disposal, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.clock.require_completed_v2()?;
        self.appends.require_disposed_v2()?;
        let bank = self
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.require_catalog_maintenance_completed_v2(
            self.native
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            controller,
            self.profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        )
    }

    /// Selects only the actual Domain/native cause before an enclosing SDK error.
    ///
    /// This readonly diagnostic never promotes completion or reorders an
    /// earlier Source/SDK body failure behind a later independent post.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        match self.first {
            None | Some(First::Sdk | First::Body) => false,
            Some(First::Inventory(index)) => !self.inventory[index].sdk_failure_is_selected_v2(),
            Some(_) => true,
        }
    }

    /// Borrows the original selected cause without retrying or reading native state.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => Some(&self.reentry),
            First::Append(index) => self.appends.failure_v2(index),
            First::Geometry => self
                .geometry
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Native => match self.native.as_ref()? {
                Err(cause) => Some(cause),
                Ok(native) => native.failure_v2(),
            },
            First::ClockBefore | First::ClockFrontier | First::ClockAfter => {
                self.clock.failure_v2()
            }
            First::SourceGeometry => self
                .source_geometry
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::SourceBefore => match self.source.as_ref()? {
                Err(cause) => Some(cause),
                Ok(source) => source.failure_v2(),
            },
            First::SourceProjection => self.source_projection.failure_v2(),
            First::CurrentNative => self
                .native
                .as_ref()
                .and_then(|native| native.as_ref().ok())
                .and_then(|native| native.failure_v2()),
            First::CurrentSource => self
                .source
                .as_ref()
                .and_then(|source| source.as_ref().ok())
                .and_then(|source| source.failure_v2()),
            First::Current => self
                .current
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Funding => self
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(|native| native.failure_v2())
                .or_else(|| {
                    self.funding
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Inventory(index) => self.inventory[index].failure_v1(),
            First::InventoryEvidence(index) => self.inventory_evidence.failure_v2(index),
            First::Snapshot(index) => self.snapshots.failure_v2(index),
            First::CatalogIo => self.catalog_io.failure_v2(),
            First::Cold => self.cold.failure_v2(),
            First::Warm => self.warm.failure_v2(),
            First::GuestRoot => self.guest_root.failure_v3(),
            First::Sdk => self.sdk_refusal.as_ref().map(|cause| cause as _),
            First::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SourceAfter => self
                .source
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(|source| source.failure_v2())
                .or_else(|| {
                    self.source_after
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::ControllerAfter => self
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(|native| native.failure_v2())
                .or_else(|| {
                    self.controller_after
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::SourceDisposal => self
                .source_disposal
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
        }
    }
}

impl Default for CatalogMaintenanceOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}
