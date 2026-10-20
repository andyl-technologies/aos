//! Runs the shared Root five-view and physical Cache engine on the actual D flight.
//!
//! This owner borrows only genuine same-flight native/financial destinations.
//! It retains the complete Cache reducers, physical pair and actionable rows
//! through independent Root service/clock posts, and supplies comparison DATA.
//! It cannot accept initial six, send their ACK or publish a lifecycle floor.

use super::*;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1, provisioning_current::RootProvisioningNativeViewsV1,
};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::{
    CacheJournalDataV1, CachePhysicalDataV1,
};

type Rows = Vec<crate::lifecycle::LifecycleBootDomainEntryV1>;

#[derive(Debug, thiserror::Error)]
pub(super) enum RowsError {
    #[error(transparent)]
    Lifecycle(#[from] aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError),
    #[error(transparent)]
    Original(#[from] RootDeleteErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Cache(#[from] crate::cache_residency::CacheResidencyProtectedJournalErrorV1),
}

#[derive(Clone, Copy)]
enum CacheFirst {
    Preparation,
    Arm,
    ClockBefore,
    Before,
    Body,
    NativePosts,
    RowsDemand,
    RowsFunding,
    Rows,
    After,
    ClockAfter,
    Retirement,
    ResidentRetirement,
    Reentry,
}

pub(crate) struct RootDeleteCacheCurrentOriginalV2 {
    views: RootProvisioningNativeViewsV1,
    final_pass: bool,
    prepared: Option<Result<(), JournalError>>,
    body: Option<Result<(), JournalError>>,
    native_after: Option<Result<(), JournalError>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    rows_demand: Option<Result<ResourceVector, JournalError>>,
    rows_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    rows: Option<Result<Rows, RowsError>>,
    retirement: Option<Result<(), JournalError>>,
    resident_retirement: Option<Result<(), NormalRootStartupErrorV1>>,
    entered: bool,
    complete: bool,
    first: Option<CacheFirst>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteCacheCurrentOriginalV2 {
    fn default() -> Self {
        Self {
            views: RootProvisioningNativeViewsV1::new(),
            final_pass: false,
            prepared: None,
            body: None,
            native_after: None,
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            before_original: Default::default(),
            before_clock: None,
            before_binding: None,
            after_original: Default::default(),
            after_clock: None,
            after_binding: None,
            rows_demand: None,
            rows_funding: None,
            rows: None,
            retirement: None,
            resident_retirement: None,
            entered: false,
            complete: false,
            first: None,
            closed: None,
        }
    }
}

impl RootDeleteCacheCurrentOriginalV2 {
    // The selected ordinary constructor remains false. Only the separate
    // genuine final Source consumer may later select the second disposal slot.
    pub(crate) fn is_final_read_v2(&self) -> bool { self.final_pass }

    // The SAME shared native-view constructor adds this actual enclosing D
    // overlay before any Box, service archive or clock acquisition is built.
    pub(crate) fn fixed_overlay_demand_v2() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    3 * std::mem::size_of::<
                        crate::normal_root::RootDeleteCacheStageReceivingV2<'_, '_>,
                    >(),
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    3 * std::mem::size_of::<
                        crate::controller_resource_reservation::RootContinuationDemandV1,
                    >(),
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        RootDeleteChunkPostsV1::fixed_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
                D::OpenFiles,
                2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
            ))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn observe_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        floor: &RootDeleteFloorOriginalV1,
        transfer: &RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(CacheFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.final_pass = source.is_final_read_v2();
        let horizon = challenge
            .continuation_horizon_v2()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        let query = challenge
            .source_query_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        let project = aos_sandbox_core::ProjectId::from_bytes(query.project);
        self.prepared = Some((|| {
            let receiving = flight
                .delete_cache_stage_receiving_v2(challenge, controller, source, floor, transfer)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.views
                .prepare_delete_cache_once_v2(receiving, source, project, horizon)
        })());
        if !matches!(self.prepared, Some(Ok(()))) {
            self.first = Some(CacheFirst::Preparation);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(CacheFirst::Arm);
        } else {
            self.before_clock = Some(self.before_original.observe_once(None));
            self.before_binding = Some(
                positive(&self.before_clock)
                    .and_then(|sample| challenge.require_current_clock_v1(*sample)),
            );
            self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
            if !matches!(self.before_binding, Some(Ok(()))) {
                self.first = Some(CacheFirst::ClockBefore);
            }
            if !matches!(self.before, Some(Ok(()))) {
                self.first.get_or_insert(CacheFirst::Before);
            }
            if self.first.is_none() {
                self.body = Some((|| {
                    let receiving = flight
                        .delete_cache_stage_receiving_v2(
                            challenge, controller, source, floor, transfer,
                        )
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    self.views
                        .observe_delete_cache_body_once_v2(receiving, source, project)
                })());
                if !matches!(self.body, Some(Ok(()))) {
                    self.first = Some(CacheFirst::Body);
                }
            }
        }
        // This drives the sole five-view/ObjectPair after engine even when
        // primary decoding or a reached incremental admission failed.
        self.native_after = Some(self.views.finish_delete_cache_after_once_v2());
        if !matches!(self.native_after, Some(Ok(()))) {
            self.first.get_or_insert(CacheFirst::NativePosts);
        }
        if self.first.is_none() {
            self.rows_demand = Some(self.views.cache_inventory_v1().and_then(|models| {
                crate::cache_residency::actionable_rows_receiving_demand_v2(
                    models.historical_inventories_data_v2(),
                )
                .ok_or(JournalError::JournalTooLarge)
            }));
            if !matches!(self.rows_demand, Some(Ok(_))) {
                self.first = Some(CacheFirst::RowsDemand);
            } else {
                self.rows_funding = Some((|| {
                    let mut receiving = flight.delete_cache_stage_receiving_v2(
                        challenge, controller, source, floor, transfer,
                    )?;
                    receiving.admit_delete_cache_actionable_once_v2(crate::controller_resource_reservation::RootContinuationDemandV1::
                        from_demand_v1(*positive(&self.rows_demand).map_err(|_| NormalRootStartupErrorV1::Service)?))
                })());
                if !matches!(self.rows_funding, Some(Ok(()))) {
                    self.first = Some(CacheFirst::RowsFunding);
                } else {
                    self.rows = Some((|| {
                        let models = self.views.cache_inventory_v1()?;
                        Ok(crate::cache_residency::actionable_rows_data_v2(
                            models.historical_inventories_data_v2(),
                        )?)
                    })());
                    if !matches!(self.rows, Some(Ok(_))) {
                        self.first = Some(CacheFirst::Rows);
                    }
                }
            }
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(CacheFirst::After);
        }
        self.after_clock = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            positive(&self.before_clock)?
                .validate_later_sample(*positive(&self.after_clock)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if let Ok(inner) = self.views.clock_v1() {
                inner
                    .validate_later_sample(*positive(&self.after_clock)?)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            }
            challenge.require_current_clock_v1(*positive(&self.after_clock)?)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(CacheFirst::ClockAfter);
        }
        if self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.retirement = Some(self.views.retire_delete_cache_prefixes_once_v2());
        if !matches!(self.retirement, Some(Ok(()))) {
            self.first = Some(CacheFirst::Retirement);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        self.resident_retirement = Some(flight.retire_delete_cache_resident_once_v2(self));
        if !matches!(self.resident_retirement, Some(Ok(()))) {
            self.first = Some(CacheFirst::ResidentRetirement);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }


    pub(crate) fn retired_cache_files_v2(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.require_complete().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if !matches!(self.retirement, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.views.retired_delete_cache_files_v2().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    fn require_complete(&self) -> Result<(), RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.views
            .require_complete_v1()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn native_coordinates_v2(
        &self,
    ) -> Result<[CacheJournalDataV1; 5], RootDeleteErrorV1> {
        self.require_complete()?;
        self.views
            .delete_cache_coordinates_v2()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn graph_physical_limits_v2(&self) -> Result<
        aos_sandbox_protocol::cache_state::physical_manifest::view_data::PhysicalManifestLimitsDataV1,
        RootDeleteErrorV1>
    {
        self.require_complete()?;
        self.views.delete_cache_limits_v2().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn physical_v2(&self) -> Result<CachePhysicalDataV1, RootDeleteErrorV1> {
        self.require_complete()?;
        self.views
            .delete_cache_physical_v2()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn initial_cut_v2(
        &self, nonce: [u8; 16], cutoff: u64,
    ) -> Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        RowsError> {
        self.require_complete()?;
        let models = self.views.cache_inventory_v1()?;
        let rows = positive(&self.rows)?;
        Ok(aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::
            cache_inventory_cut_data_v2(&self.native_coordinates_v2()?, self.physical_v2()?,
                nonce, cutoff, *models.projection_root_data_v2().as_bytes(),
                rows.iter().map(|row| (row.resource(), *row.identity().as_bytes())))?)
    }

    pub(super) fn resident_retirement_failed_v2(&self) -> bool {
        matches!(self.first, Some(CacheFirst::ResidentRetirement))
    }

    pub(super) fn funding_failed(&self) -> bool {
        matches!(
            self.first,
            Some(CacheFirst::Preparation | CacheFirst::RowsFunding)
        ) || matches!(self.first, Some(CacheFirst::Body))
            && self.views.funding_failure_is_selected_v1()
            || matches!(self.first, Some(CacheFirst::Arm)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            CacheFirst::Before | CacheFirst::After => {
                self.posts.property_failure_view_v1(self.failure()?)
            }
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            CacheFirst::Retirement => self.views.failure().or_else(|| cause(&self.retirement)),
            CacheFirst::ResidentRetirement => cause(&self.resident_retirement),
            CacheFirst::Preparation => self.views.failure().or_else(|| cause(&self.prepared)),
            CacheFirst::Arm => self.posts.before_failure_v1().or_else(|| cause(&self.arm)),
            CacheFirst::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.before)),
            CacheFirst::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            CacheFirst::ClockBefore => self
                .before_original
                .failure()
                .or_else(|| cause(&self.before_clock))
                .or_else(|| cause(&self.before_binding)),
            CacheFirst::ClockAfter => self
                .after_original
                .failure()
                .or_else(|| cause(&self.after_clock))
                .or_else(|| cause(&self.after_binding)),
            CacheFirst::Body => self.views.failure().or_else(|| cause(&self.body)),
            CacheFirst::NativePosts => self.views.failure().or_else(|| cause(&self.native_after)),
            CacheFirst::RowsDemand => cause(&self.rows_demand),
            CacheFirst::RowsFunding => cause(&self.rows_funding),
            CacheFirst::Rows => self.rows.as_ref()?.as_ref().err().map(|cause| cause as _),
            CacheFirst::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
