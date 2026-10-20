//! Keeps the actual object view across the private current-purpose interval.
//!
//! The actual service owns both observations and the F debit. A preparation
//! reaches only bounded native metadata; its actual byte extent is admitted
//! before either manifest read. The independently owed after observation may
//! reach its fixed native prefix on failure, but cannot allocate an unpaid or
//! changed byte extent. Historical quotas remain comparison DATA until the
//! enclosing five-journal replay and every purpose post have succeeded.

use aos_sandbox_broker::receiving::RepresentationDemandDebitV1 as _;

use std::error::Error;

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::cache_state::NodeCacheQuotaV1;

use super::object_view::CacheObjectViewOriginalV1;
use super::physical_manifest::{
    PhysicalManifestDataErrorV1, PhysicalManifestLimitsDataV1, dynamic_receiving_demand_v1,
    quota_derivation_receiving_demand_v1,
};
use super::{
    CachePurposeReceivingV1, CacheSignerReceivingClosedV1 as Closed, Common, First, StageOriginals,
    admit_stage, cause, observe_original, sample_pair_demand,
};

#[derive(Clone, Copy)]
enum ObjectFailure {
    Entry,
    FixedFunding,
    Before,
    Limits,
    Prepare,
    Extent,
    DynamicFunding,
    Read,
    LocalBeforePost,
    BeforeDeadline,
    PrepareAfter,
    ExtentAfter,
    ReadAfter,
    LocalAfterPost,
    Comparison,
    After,
    AfterDeadline,
}

pub(super) struct CacheCurrentObjectsOriginalV1 {
    stage: StageOriginals,
    limits: Option<Result<PhysicalManifestLimitsDataV1, PhysicalManifestDataErrorV1>>,
    before: Option<CacheObjectViewOriginalV1>,
    after: Option<CacheObjectViewOriginalV1>,
    extent: Option<Result<usize, Closed>>,
    dynamic_demand: Option<Result<ResourceVector, AccountingError>>,
    dynamic_debit: Option<Result<(), Closed>>,
    before_prepare: Option<Result<(), Closed>>,
    before_read: Option<Result<(), Closed>>,
    before_post: Option<Result<(), Closed>>,
    after_prepare: Option<Result<(), Closed>>,
    after_read: Option<Result<(), Closed>>,
    after_post: Option<Result<(), Closed>>,
    comparison: Option<Result<(), Closed>>,
    before_clock: Option<rustix::time::Timespec>,
    before_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    after_clock: Option<rustix::time::Timespec>,
    after_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    after_entered: bool,
    first: Option<ObjectFailure>,
}

impl CacheCurrentObjectsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: Default::default(),
            limits: None,
            before: None,
            after: None,
            extent: None,
            dynamic_demand: None,
            dynamic_debit: None,
            before_prepare: None,
            before_read: None,
            before_post: None,
            after_prepare: None,
            after_read: None,
            after_post: None,
            comparison: None,
            before_clock: None,
            before_deadline: None,
            after_clock: None,
            after_deadline: None,
            after_entered: false,
            first: None,
        }
    }

    fn begin_once(
        &mut self,
        common: &mut Common,
        controller_uid: u32,
        maximum_memory_bytes: u64,
        quotas: &[NodeCacheQuotaV1],
        resident_files: u64,
        _cutoff: u64,
    ) -> Result<(), Closed> {
        if self.stage.demand.is_some() {
            return self.refuse(ObjectFailure::Entry);
        }
        self.stage.demand = Some((|| {
            let missing = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            CacheObjectViewOriginalV1::fixed_receiving_demand_v1()
                .ok_or(missing)?
                .checked_add(
                    CacheObjectViewOriginalV1::fixed_receiving_demand_v1().ok_or(missing)?,
                )?
                .checked_add(sample_pair_demand()?)?
                .checked_add(quota_derivation_receiving_demand_v1(quotas.len()).ok_or(missing)?)?
                .checked_add(ResourceVector::ZERO.with(
                    D::MemoryBytes,
                    u64::try_from(std::mem::size_of::<Self>()).map_err(|_| missing)?,
                ))
        })());
        if admit_stage(common, &mut self.stage, resident_files).is_err() {
            return self.refuse(ObjectFailure::FixedFunding);
        }
        // Both fixed native prefixes are funded before the first observation.
        self.before = Some(CacheObjectViewOriginalV1::new());
        self.after = Some(CacheObjectViewOriginalV1::new());
        self.stage.before_result = Some(observe_original(common, &mut self.stage.before));
        if !matches!(self.stage.before_result, Some(Ok(()))) {
            return self.refuse(ObjectFailure::Before);
        }
        self.limits = Some(PhysicalManifestLimitsDataV1::from_node_quotas(
            maximum_memory_bytes,
            quotas.iter().copied(),
        ));
        let limits = match self.limits.as_ref() {
            Some(Ok(limits)) => *limits,
            _ => return self.refuse(ObjectFailure::Limits),
        };
        self.before_prepare = Some(
            self.before
                .as_mut()
                .ok_or(Closed)?
                .prepare_once(controller_uid),
        );
        if !matches!(self.before_prepare, Some(Ok(()))) {
            return self.refuse(ObjectFailure::Prepare);
        }
        self.extent = Some(self.before.as_ref().ok_or(Closed)?.prepared_length_v1());
        let length = match self.extent {
            Some(Ok(length)) => length,
            _ => return self.refuse(ObjectFailure::Extent),
        };
        self.dynamic_demand = Some(dynamic_receiving_demand_v1(length).ok_or(
            AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            },
        ));
        let demand = match self.dynamic_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return self.refuse(ObjectFailure::DynamicFunding),
        };
        self.dynamic_debit = Some(
            common
                .representation
                .as_mut()
                .ok_or(Closed)?
                .reserve(demand)
                .map_err(|_| Closed),
        );
        if !matches!(self.dynamic_debit, Some(Ok(()))) {
            return self.refuse(ObjectFailure::DynamicFunding);
        }
        self.before_read = Some(self.before.as_mut().ok_or(Closed)?.read_once(limits));
        if !matches!(self.before_read, Some(Ok(()))) {
            self.refuse(ObjectFailure::Read)?;
        }
        Ok(())
    }

    fn finish_once(
        &mut self,
        common: &mut Common,
        controller_uid: u32,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if !self.stage.admitted() || self.after_entered {
            return self.refuse(ObjectFailure::Entry);
        }
        self.after_entered = true;
        // Preparation/read failures still owe all reached local native posts.
        if let Some(before) = self.before.as_mut() {
            self.before_post = Some(before.finish_native_once());
            if !matches!(self.before_post, Some(Ok(()))) {
                self.first.get_or_insert(ObjectFailure::LocalBeforePost);
            }
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.before_clock = Some(now);
        self.before_deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.before_deadline, Some(Ok(_))) {
            self.first.get_or_insert(ObjectFailure::BeforeDeadline);
        }
        if let Some(after) = self.after.as_mut() {
            self.after_prepare = Some(after.prepare_once(controller_uid));
            if !matches!(self.after_prepare, Some(Ok(()))) {
                self.first.get_or_insert(ObjectFailure::PrepareAfter);
            } else if matches!(self.dynamic_debit, Some(Ok(()))) {
                let same_extent = match (self.extent, after.prepared_length_v1()) {
                    (Some(Ok(before)), Ok(current)) => before == current,
                    _ => false,
                };
                if !same_extent {
                    self.first.get_or_insert(ObjectFailure::ExtentAfter);
                } else if let Some(Ok(limits)) = self.limits.as_ref() {
                    self.after_read = Some(after.read_once(*limits));
                    if !matches!(self.after_read, Some(Ok(()))) {
                        self.first.get_or_insert(ObjectFailure::ReadAfter);
                    }
                }
            }
            self.after_post = Some(after.finish_native_once());
            if !matches!(self.after_post, Some(Ok(()))) {
                self.first.get_or_insert(ObjectFailure::LocalAfterPost);
            }
        }
        self.comparison = Some((|| {
            let before = self.before.as_ref().ok_or(Closed)?;
            let after = self.after.as_ref().ok_or(Closed)?;
            before.require_same_completed_v1(after)?;
            Ok(())
        })());
        if !matches!(self.comparison, Some(Ok(()))) {
            self.first.get_or_insert(ObjectFailure::Comparison);
        }
        self.stage.after_result = Some(observe_original(common, &mut self.stage.after));
        if !matches!(self.stage.after_result, Some(Ok(()))) {
            self.first.get_or_insert(ObjectFailure::After);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.after_clock = Some(now);
        self.after_deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.after_deadline, Some(Ok(_))) {
            self.first.get_or_insert(ObjectFailure::AfterDeadline);
        }
        // Both observations and actual F samples remain through the complete
        // signed exchange and final purpose posts. No projected DATA retires them.
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn resident_file_bound_v1(&self) -> Result<u64, Closed> {
        if !self.stage.admitted() {
            return Err(Closed);
        }
        self.stage
            .demand
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|demand| demand.get(D::OpenFiles))
            .ok_or(Closed)
    }

    /// Returns only the fully checked same actual before/after physical cut.
    pub(super) fn completed_snapshot_v1(
        &self,
    ) -> Result<(
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1,
        super::physical_manifest::PhysicalManifestSnapshotDataV1,
    ), Closed>{
        if self.first.is_some()
            || !self.after_entered
            || !self.stage.complete()
            || !matches!(self.comparison, Some(Ok(())))
            || !matches!(self.after_deadline, Some(Ok(_)))
        {
            return Err(Closed);
        }
        let observed = self.after.as_ref().ok_or(Closed)?;
        let snapshot = observed.completed_data_v1()?;
        let (root, lock, manifest) = observed.observed_identities_v1()?;
        let limits = self
            .limits
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Closed)?;
        let physical = aos_sandbox_broker::physical_cache_observation::current_view::CacheObjectViewOriginalV1::
            comparison_from_observations_data_v2(root, lock, manifest,
                observed.observed_source_uid_v1()?, snapshot, limits.digest_v1().map_err(|_| Closed)?);
        Ok((physical, snapshot))
    }

    pub(super) fn owes_after_v1(&self) -> bool {
        self.stage.admitted() && !self.after_entered
    }

    fn refuse(&mut self, first: ObjectFailure) -> Result<(), Closed> {
        self.first.get_or_insert(first);
        Err(Closed)
    }

    pub(super) fn failure<'a>(&'a self, common: &'a Common) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            ObjectFailure::Entry => Some(&Closed),
            ObjectFailure::FixedFunding => self.stage.funding_failure(common),
            ObjectFailure::Before => self
                .stage
                .before
                .failure()
                .or_else(|| cause(&self.stage.before_result)),
            ObjectFailure::Limits => cause(&self.limits),
            ObjectFailure::Prepare | ObjectFailure::Read | ObjectFailure::LocalBeforePost => self
                .before
                .as_ref()
                .and_then(CacheObjectViewOriginalV1::failure)
                .or_else(|| cause(&self.before_prepare))
                .or_else(|| cause(&self.before_read))
                .or_else(|| cause(&self.before_post)),
            ObjectFailure::Extent => cause(&self.extent),
            ObjectFailure::DynamicFunding => cause(&self.dynamic_demand)
                .or_else(|| {
                    common
                        .representation
                        .as_ref()
                        .and_then(|ledger| ledger.failure())
                        .map(|cause| cause as _)
                })
                .or_else(|| cause(&self.dynamic_debit)),
            ObjectFailure::BeforeDeadline => cause(&self.before_deadline),
            ObjectFailure::PrepareAfter
            | ObjectFailure::ReadAfter
            | ObjectFailure::LocalAfterPost => self
                .after
                .as_ref()
                .and_then(CacheObjectViewOriginalV1::failure)
                .or_else(|| cause(&self.after_prepare))
                .or_else(|| cause(&self.after_read))
                .or_else(|| cause(&self.after_post)),
            ObjectFailure::ExtentAfter => Some(&Closed),
            ObjectFailure::Comparison => cause(&self.comparison),
            ObjectFailure::After => self
                .stage
                .after
                .failure()
                .or_else(|| cause(&self.stage.after_result)),
            ObjectFailure::AfterDeadline => cause(&self.after_deadline),
        }
    }
}

impl CachePurposeReceivingV1<'_> {
    // Called only from this service's actual five-view historical reducer.
    // Quotas alone never complete or authorize the enclosing signer purpose.
    pub(super) fn begin_current_objects_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_some()
            || !matches!(self.original.current_clock_before, Some(Ok(())))
            || self.original.current_objects.is_some()
            || !self
                .original
                .current_journals
                .as_ref()
                .is_some_and(|journals| journals.native_leaves_are_retired_v1())
        {
            return Err(self.fail(First::Closed));
        }
        let maximum_memory_bytes = self.credential()?.maximum_memory_bytes();
        let controller_uid = self.startup.profile.profile().ok_or(Closed)?.identities[0];
        let cutoff = self.original.root_challenge.data()?.cutoff;
        let clock = self
            .original
            .current_clock_stage
            .demand
            .as_ref()
            .and_then(|d| d.as_ref().ok())
            .ok_or(Closed)?;
        let resident = self
            .current_purpose_resident_files_v1()?
            .checked_add(clock.get(D::OpenFiles))
            // The completed journal native leaves are physically gone. Its
            // whole-purpose F samples remain until their independently owed post.
            .and_then(|files| files.checked_add(sample_pair_demand().ok()?.get(D::OpenFiles)))
            .ok_or(Closed)?;
        let quotas = self
            .original
            .current_models
            .as_ref()
            .ok_or(Closed)?
            .data_v1()?
            .quotas_v1();
        self.original.current_objects = Some(CacheCurrentObjectsOriginalV1::new());
        let result = self
            .original
            .current_objects
            .as_mut()
            .ok_or(Closed)?
            .begin_once(
                &mut self.startup.common,
                controller_uid,
                maximum_memory_bytes,
                quotas,
                resident,
                cutoff,
            );
        if result.is_err() {
            self.fail(First::CurrentObjects);
        }
        result
    }

    pub(super) fn finish_current_objects_once(&mut self) -> Result<(), Closed> {
        let controller_uid = self.startup.profile.profile().ok_or(Closed)?.identities[0];
        let cutoff = self.original.root_challenge.data()?.cutoff;
        let result = self
            .original
            .current_objects
            .as_mut()
            .ok_or(Closed)?
            .finish_once(&mut self.startup.common, controller_uid, cutoff);
        if result.is_err() {
            self.fail(First::CurrentObjects);
        }
        result
    }
}
