//! Reads fresh Source, all five Cache journals and physical objects under R.
//!
//! Both explicit provisioning purposes lend the same actual financial stage
//! engine. This native owner supplies comparison DATA only; it cannot normalize
//! a method, sign, admit a public request or replace Controller/Session/compiler
//! checks. Every entered reader retains and performs its independently owed
//! rooted-name/metadata post on either body outcome.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_core::{ProjectId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::{physical_cache_observation::current_view::{
    CacheObjectViewOriginalV1, CacheObjectViewClosedV1,
}, systemd_credentials::RootCurrentCacheMemoryCustodyV1};
use aos_sandbox_protocol::{cache_state::{fixed_journals::CacheJournalRecipeRoleV1 as Role,
    physical_manifest::view_data::{self, PhysicalManifestLimitsDataV1, PhysicalManifestSnapshotDataV1}},
    domain_ledger::{DomainLedgerDataError, ProtectedHistoryDataErrorV1}};
use aos_sandbox_ledger_replay::cache_current::{
    self, CacheCurrentRawViewsDataV1, CacheCurrentInventoryDataV1, CacheCurrentModelErrorV1,
};
use crate::journal::{JournalError, Journal, RootReadonlyJournalModelOriginalsV1 as Model};
use crate::normal_root::{RootMaintenanceStorageStageReceivingV2, RootDeleteCacheStageReceivingV2, RootApplyStageReceivingV1, RootHostLaunchStageReceivingV1,
    RootEnvironmentStageReceivingV1, NormalRootStartupErrorV1};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    create_storage_current::controller_readonly::native_read::{RootFixedNativeReadOriginalsV1 as Reader, RootFixedCompletedReadDataV2 as CompletedReader}};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use super::receiving::ReceivingV1;
use super::RootEnvironmentReadonlyContextV1;
use super::horizon::{RootContinuationHorizonDataV1, RootContinuationClockGateV1};

const ROLES: [Role; 5] = [Role::Bootstrap, Role::Hold, Role::State, Role::Authority, Role::Clock];

#[derive(Debug, thiserror::Error)]
enum StopV1 {
    #[error(transparent)] Native(#[from] JournalError),
    #[error(transparent)] Funding(#[from] NormalRootStartupErrorV1),
    #[error(transparent)] Models(#[from] CacheCurrentModelErrorV1),
    #[error(transparent)] Rows(#[from] DomainLedgerDataError),
    #[error(transparent)] Hold(#[from] ProtectedHistoryDataErrorV1),
    #[error(transparent)] Tree(#[from] aos_sandbox_ledger_replay::hierarchy::codec::HierarchyCodecError),
    #[error(transparent)] Memory(#[from] aos_sandbox_protocol::role_credential::cache_signer_inputs::CacheSignerInputDataErrorV1),
    #[error(transparent)] Limits(#[from] view_data::PhysicalManifestDataErrorV1),
    #[error(transparent)] Objects(#[from] CacheObjectViewClosedV1),
    #[error("the fresh Source/Cache native observation is incomplete")] Incomplete,
}

pub(crate) struct TreeDataV1 {
    pub(super) tree: aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1,
    pub(crate) generation: u64,
    pub(crate) commitment: aos_sandbox_core::ObjectDigest,
    pub(crate) head: aos_sandbox_core::ObjectDigest,
    pub(crate) lineage: aos_sandbox_core::ObjectDigest,
}

impl TreeDataV1 {
    /// Borrows the same fully replayed tree as mechanical comparison DATA.
    pub(in crate::policy_compiler) fn tree_v2(&self)
        -> &aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1
    {
        &self.tree
    }
}


// Lazy backing is constructed only after the genuine SourceFixed stage pays
// its complete size/construction, clocks and first fixed native acquisition.
struct NativeViewsV1 {
    frontier_clock: RootContinuationClockGateV1,
    source: Reader,
    host_source_model: Option<Box<Model>>,
    source_entered: bool,
    cache: [Option<Reader>; 5],
    completed_cache: [Option<CompletedReader>; 5],
    before_clock: RetainedKernelPairedClockAttemptV1,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    source_tree: Option<Result<TreeDataV1, StopV1>>,
    cache_models: Option<Result<CacheCurrentInventoryDataV1, CacheCurrentModelErrorV1>>,
    objects: Option<Box<ObjectPairV1>>,
    primary: Option<Result<(), StopV1>>,
    posts: Option<Result<(), StopV1>>,
}

impl NativeViewsV1 {
    fn new(horizon: RootContinuationHorizonDataV1) -> Self {
        Self {
            frontier_clock: RootContinuationClockGateV1::new(horizon),
            source: Reader::source_current_v1(), host_source_model: None, source_entered: false,
            cache: ROLES.map(|role| Some(Reader::cache_current_v1(role))),
            completed_cache: std::array::from_fn(|_| None),
            before_clock: Default::default(), before: None,
            after_clock: Default::default(), after: None,
            source_tree: None, cache_models: None, objects: None, primary: None, posts: None,
        }
    }

    fn fixed_demand_v1(source: SourceInputV1<'_>, project: ProjectId) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootProvisioningNativeViewsV1>()))
            .and_then(|bytes| bytes.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let first = match source {
            SourceInputV1::Captured => Reader::source_current_fixed_demand_v1()?,
            SourceInputV1::Delete(source) => {
                source.verified_fields_v1().map_err(|_| JournalError::ProtectedBoundary)?;
                crate::policy_compiler::delete_root::RootDeleteCacheCurrentOriginalV2::fixed_overlay_demand_v2()?
            },
            SourceInputV1::Environment(original) => source_tree_demand_v1(original.source_state_v1()?, project)?,
            SourceInputV1::Maintenance(source) => source_tree_demand_v1(source.state_data_v2()?, project)?,
        };
        let clocks = first.checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
            .map_err(|_| invalid())?;
        clocks.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, u64::try_from(2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
                .map_err(|_| invalid())?)).map_err(|_| invalid())
    }

    fn raw_cache_v1(&self) -> Result<CacheCurrentRawViewsDataV1<'_>, JournalError> {
        Self::raw_cache_parts_v2(&self.cache, &self.completed_cache)
    }

    fn raw_cache_parts_v2<'view>(
        cache: &'view [Option<Reader>; 5],
        completed_cache: &'view [Option<CompletedReader>; 5],
    ) -> Result<CacheCurrentRawViewsDataV1<'view>, JournalError> {
        let raw = |index: usize| match &completed_cache[index] {
            Some(data) => data.cache_raw_view_v2(),
            None => cache[index].as_ref().ok_or(JournalError::ProtectedBoundary)?.cache_raw_view_v1(),
        };
        Ok(CacheCurrentRawViewsDataV1 {
            bootstrap: raw(0)?, hold: raw(1)?, state: raw(2)?,
            authority: raw(3)?, clock: raw(4)?,
        })
    }

    fn observe_inner(
        &mut self,
        receiving: &mut ReceivingV1<'_, '_>,
        project: ProjectId,
        source_input: SourceInputV1<'_>,
    ) -> Result<(), StopV1> {
        self.before = Some(self.before_clock.observe_once(None));
        let sample = *positive(&self.before)?;
        self.frontier_clock.check_next_once_v1()?;
        let uid = receiving.controller_identity_v1().0;
        match source_input {
            SourceInputV1::Delete(source) => {
                // The same D owner already verified complete signed/native
                // Source pending semantics. Cache comparison needs no second
                // Source parser or ordinary non-pending provisioning Tree.
                source
                    .verified_source_predecessor_v2()
                    .map_err(|_| StopV1::Incomplete)?;
            }
            SourceInputV1::Captured => {
                self.source_entered = true;
                self.source.capture_once(uid);
                self.source.require_captured_v1()?;
                receiving.admit_source_native_once_v1(self.source.replay_demand_v1()?)?;
                self.frontier_clock.check_next_once_v1()?;
                self.source.audit_once();
                let semantic = self.source.additional_semantic_demand_v1()?;
                let semantic = if matches!(receiving, ReceivingV1::HostLaunch(_) | ReceivingV1::MaintenanceStorage(_)) {
                    semantic.checked_add(Model::receiving_demand_v1(&self.source)?)
                        .map_err(JournalError::ReceivingAccounting)?
                } else { semantic };
                receiving.admit_source_semantic_once_v1(semantic)?;
                self.frontier_clock.check_next_once_v1()?;
                self.source.replay_once();
                self.source.replay_native_v1()?;
                let source = self.source.replay_native_v1()?;
                receiving.admit_source_tree_models_once_v1(source_tree_demand_v1(
                    source.state,
                    project
                )?)?;
                self.frontier_clock.check_next_once_v1()?;
                self.source_tree = Some(fold_source_tree_v1(source.state, project));
                if matches!(receiving, ReceivingV1::HostLaunch(_) | ReceivingV1::MaintenanceStorage(_)) {
                    // Move the SAME completed Source reader into the readonly
                    // model only after its native post. No second open/replay
                    // or cloned map supplies Host's lifecycle history.
                    self.source.finish_post_once();
                    self.source.terminal_native_v1()?;
                    self.host_source_model = Some(Box::new(Model::new()));
                    let model = self.host_source_model.as_mut().ok_or(StopV1::Incomplete)?;
                    model.adopt_once(&mut self.source);
                    model.require_complete_v1()?;
                }
            }
            SourceInputV1::Environment(original) => {
                // This purpose already paid/captured/audited the actual Source
                // model. Borrow it; never rearm Source or repeat cold IO.
                let earlier = original.clock_v1()?;
                if earlier.host_boot_id() != sample.host_boot_id()
                    || earlier.boottime_nanoseconds() > sample.boottime_nanoseconds()
                {
                    return Err(StopV1::Incomplete);
                }
                self.frontier_clock.check_next_once_v1()?;
                self.source_tree = Some(fold_source_tree_v1(original.source_state_v1()?, project));
            }
            SourceInputV1::Maintenance(source) => {
                // The same actual Maintenance Root readonly owner already
                // captured/audited/replayed this Source under stages6..8 and
                // retains its independent late post. No second Source reader
                // or copied map substitutes for that held native model.
                self.frontier_clock.check_next_once_v1()?;
                self.source_tree = Some(fold_source_tree_v1(source.state_data_v2()?, project));
            }
        }
        if !matches!(source_input, SourceInputV1::Delete(_)) {
            positive(&self.source_tree)?;
        }

        for (index, role) in ROLES.into_iter().enumerate() {
            receiving
                .admit_cache_fixed_once_v1(role, Reader::cache_current_fixed_demand_v1(role)?)?;
            let reader = self.cache[index].as_mut().ok_or(StopV1::Incomplete)?;
            self.frontier_clock.check_next_once_v1()?;
            reader.capture_once(uid);
            reader.require_captured_v1()?;
            receiving.admit_cache_native_once_v1(role, reader.replay_demand_v1()?)?;
            self.frontier_clock.check_next_once_v1()?;
            reader.audit_once();
            receiving
                .admit_cache_semantic_once_v1(role, reader.additional_semantic_demand_v1()?)?;
            self.frontier_clock.check_next_once_v1()?;
            reader.replay_once();
            reader.replay_native_v1()?;
        }
        // Borrow only the Cache fields while the independent frontier clock
        // is sampled; the model still observes the same retained native rows.
        let raw = Self::raw_cache_parts_v2(&self.cache, &self.completed_cache)?;
        receiving.admit_cache_models_once_v1(
            cache_current::model_geometry_v1(&raw).map_err(CacheCurrentModelErrorV1::from)?
        )?;
        self.frontier_clock.check_next_once_v1()?;
        self.cache_models = Some((|| {
            let clock = cache_current::decode_clock_v1(raw.clock)?;
            let hold = cache_current::decode_hold_v1(raw.hold)?;
            if hold.legacy.hold.is_some_and(|hold| hold.is_held())
                || hold.legacy.v8_pending.is_some()
                || hold.q04_pending.is_some()
            {
                return Err(CacheCurrentModelErrorV1::Changed);
            }
            let now = u64::try_from(sample.wall_seconds())
                .map_err(|_| CacheCurrentModelErrorV1::Changed)?
                .max(clock.observed_unix_seconds);
            cache_current::reconstruct_inventory_v1(&raw, now, project)
        })());
        let models = positive(&self.cache_models)?;
        receiving.admit_cache_objects_fixed_once_v1(ObjectPairV1::fixed_demand_v1(
            models.quotas_v1().len()
        )?)?;
        self.objects = Some(Box::new(ObjectPairV1::new()));
        self.objects
            .as_mut()
            .ok_or(StopV1::Incomplete)?
            .observe_before(receiving, models.quotas_v1(), &mut self.frontier_clock)
    }

    fn finish_posts(&mut self, uid: u32) {
        if let Some(objects) = self.objects.as_mut() { objects.finish_once(uid); }
        self.source.finish_post_once();
        if let Some(model) = self.host_source_model.as_mut() {
            model.finish_parent_post_once_v1();
        }
        for reader in self.cache.iter_mut().flatten() { reader.finish_post_once(); }
        self.after = Some(self.after_clock.observe_once(self.before.as_ref().and_then(|sample| sample.as_ref().ok()).copied()));
        self.posts = Some((|| {
            if let Some(model) = self.host_source_model.as_ref() {
                model.require_parent_post_v1()?;
            } else if self.source_entered {
                self.source.terminal_native_v1()?;
            }
            for reader in self.cache.iter().flatten() { reader.terminal_native_v1()?; }
            let sample = *positive(&self.after)?;
            self.frontier_clock.require_final_sample_v1(sample)?;
            let clock = cache_current::decode_clock_v1(self.raw_cache_v1()?.clock)?;
            let now = u64::try_from(sample.wall_seconds()).map_err(|_| StopV1::Incomplete)?.max(clock.observed_unix_seconds);
            positive(&self.cache_models)?.require_live_at_v1(now)?;
            self.objects.as_ref().ok_or(StopV1::Incomplete)?.require_complete()?;
            Ok(())
        })());
    }
}

// This role-private pair keeps the actual unchanged manifest limits artifact,
// both native views, and their every partial Result through the outer R posts.
struct ObjectPairV1 {
    memory: RootCurrentCacheMemoryCustodyV1,
    memory_capture: Option<Result<(), ()>>,
    memory_decode: Option<Result<u64, aos_sandbox_protocol::role_credential::cache_signer_inputs::CacheSignerInputDataErrorV1>>,
    memory_post: Option<Result<(), ()>>,
    limits: Option<Result<PhysicalManifestLimitsDataV1, view_data::PhysicalManifestDataErrorV1>>,
    before: CacheObjectViewOriginalV1,
    after: CacheObjectViewOriginalV1,
    before_prepare: Option<Result<(), CacheObjectViewClosedV1>>,
    extent: Option<Result<usize, CacheObjectViewClosedV1>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    before_read: Option<Result<(), CacheObjectViewClosedV1>>,
    before_post: Option<Result<(), CacheObjectViewClosedV1>>,
    after_prepare: Option<Result<(), CacheObjectViewClosedV1>>,
    after_read: Option<Result<(), CacheObjectViewClosedV1>>,
    after_post: Option<Result<(), CacheObjectViewClosedV1>>,
    comparison: Option<Result<(), CacheObjectViewClosedV1>>,
    first: Option<ObjectFirstV1>,
}

#[derive(Clone, Copy)]
enum ObjectFirstV1 { MemoryCapture, MemoryDecode, Limits, BeforePrepare, Extent, Funding, BeforeRead,
    BeforePost, AfterPrepare, AfterRead, AfterPost, Comparison, MemoryPost }

impl ObjectPairV1 {
    fn new() -> Self {
        Self { memory: RootCurrentCacheMemoryCustodyV1::new(), memory_capture: None, memory_decode: None,
            memory_post: None, limits: None, before: CacheObjectViewOriginalV1::root_current_v1(),
            after: CacheObjectViewOriginalV1::root_current_v1(), before_prepare: None, extent: None,
            funding: None, before_read: None, before_post: None, after_prepare: None, after_read: None,
            after_post: None, comparison: None, first: None }
    }

    fn fixed_demand_v1(quotas: usize) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let bytes = size_of::<Self>().checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let mut demand = ResourceVector::ZERO.with(D::MemoryBytes, bytes);
        for part in [RootCurrentCacheMemoryCustodyV1::dominant_demand(),
            CacheObjectViewOriginalV1::fixed_receiving_demand_v1(), CacheObjectViewOriginalV1::fixed_receiving_demand_v1(),
            view_data::quota_derivation_receiving_demand_v1(quotas)] {
            demand = demand.checked_add(part.ok_or_else(invalid)?).map_err(|_| invalid())?;
        }
        Ok(demand)
    }

    fn observe_before(&mut self, receiving: &mut ReceivingV1<'_, '_>, quotas: &[aos_sandbox_protocol::cache_state::NodeCacheQuotaV1],
        clock: &mut RootContinuationClockGateV1)
        -> Result<(), StopV1> {
        let uid = receiving.controller_identity_v1().0;
        clock.check_next_once_v1()?;
        self.memory_capture = Some(self.memory.capture_once());
        if !matches!(self.memory_capture, Some(Ok(()))) { self.first = Some(ObjectFirstV1::MemoryCapture); return Err(StopV1::Incomplete); }
        self.memory_decode = Some(aos_sandbox_protocol::role_credential::cache_signer_inputs::decode_memory_ceiling_data_v1(
            self.memory.bytes().ok_or(StopV1::Incomplete)?));
        let memory = match self.memory_decode.as_ref() { Some(Ok(value)) => *value,
            _ => { self.first = Some(ObjectFirstV1::MemoryDecode); return Err(StopV1::Incomplete); } };
        self.limits = Some(PhysicalManifestLimitsDataV1::from_node_quotas(memory, quotas.iter().copied()));
        if !matches!(self.limits, Some(Ok(_))) { self.first = Some(ObjectFirstV1::Limits); return Err(StopV1::Incomplete); }
        clock.check_next_once_v1()?;
        self.before_prepare = Some(self.before.prepare_once(uid));
        if !matches!(self.before_prepare, Some(Ok(()))) { self.first = Some(ObjectFirstV1::BeforePrepare); return Err(StopV1::Incomplete); }
        self.extent = Some(self.before.prepared_length_v1());
        let length = match self.extent { Some(Ok(value)) => value,
            _ => { self.first = Some(ObjectFirstV1::Extent); return Err(StopV1::Incomplete); } };
        let demand = view_data::dynamic_receiving_demand_v1(length).ok_or(JournalError::JournalTooLarge)?;
        self.funding = Some(receiving.admit_cache_objects_native_once_v1(demand));
        if !matches!(self.funding, Some(Ok(()))) { self.first = Some(ObjectFirstV1::Funding); return Err(StopV1::Incomplete); }
        clock.check_next_once_v1()?;
        self.before_read = Some(self.before.read_once(*positive(&self.limits)?));
        if !matches!(self.before_read, Some(Ok(()))) { self.first = Some(ObjectFirstV1::BeforeRead); return Err(StopV1::Incomplete); }
        Ok(())
    }

    fn finish_before_once(&mut self) {
        if self.before_prepare.is_some() && self.before_post.is_none() {
            self.before_post = Some(self.before.finish_native_once());
            if !matches!(self.before_post, Some(Ok(()))) { self.first.get_or_insert(ObjectFirstV1::BeforePost); }
        }
    }

    fn finish_once(&mut self, uid: u32) {
        self.finish_before_once();
        self.after_prepare = Some(self.after.prepare_once(uid));
        if !matches!(self.after_prepare, Some(Ok(()))) { self.first.get_or_insert(ObjectFirstV1::AfterPrepare); }
        else if matches!(self.funding, Some(Ok(()))) {
            if self.extent.as_ref().and_then(|value| value.as_ref().ok()).copied() == self.after.prepared_length_v1().ok() {
                if let Some(Ok(limits)) = self.limits.as_ref() {
                    self.after_read = Some(self.after.read_once(*limits));
                    if !matches!(self.after_read, Some(Ok(()))) { self.first.get_or_insert(ObjectFirstV1::AfterRead); }
                }
            } else { self.first.get_or_insert(ObjectFirstV1::AfterRead); }
        }
        self.after_post = Some(self.after.finish_native_once());
        if !matches!(self.after_post, Some(Ok(()))) { self.first.get_or_insert(ObjectFirstV1::AfterPost); }
        self.comparison = Some(self.before.require_same_completed_v1(&self.after));
        if !matches!(self.comparison, Some(Ok(()))) { self.first.get_or_insert(ObjectFirstV1::Comparison); }
        self.memory_post = Some(self.memory.recheck_once());
        if !matches!(self.memory_post, Some(Ok(()))) { self.first.get_or_insert(ObjectFirstV1::MemoryPost); }
    }

    fn require_complete(&self) -> Result<(), StopV1> {
        if self.first.is_some() || !matches!(self.comparison, Some(Ok(()))) || !matches!(self.memory_post, Some(Ok(()))) {
            return Err(StopV1::Incomplete);
        }
        self.after.completed_data_v1()?;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ObjectFirstV1::MemoryCapture => self.memory.capture_failure().map(|cause| cause as _),
            ObjectFirstV1::MemoryDecode => cause(&self.memory_decode),
            ObjectFirstV1::Limits => cause(&self.limits),
            ObjectFirstV1::BeforePrepare | ObjectFirstV1::Extent | ObjectFirstV1::BeforeRead | ObjectFirstV1::BeforePost => self.before.failure(),
            ObjectFirstV1::Funding => cause(&self.funding),
            ObjectFirstV1::AfterPrepare | ObjectFirstV1::AfterRead | ObjectFirstV1::AfterPost | ObjectFirstV1::Comparison => self.after.failure().or_else(|| cause(&self.comparison)),
            ObjectFirstV1::MemoryPost => self.memory.post_failure().map(|cause| cause as _),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PurposeV1 { Delete, Environment, Apply, HostLaunch, MaintenanceStorage }

/// Retains one actual fresh R-native Source/Cache observation, never an issuer.
pub(crate) struct RootProvisioningNativeViewsV1 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    fixed: Option<Result<(), NormalRootStartupErrorV1>>,
    backing: Option<Box<NativeViewsV1>>,
    entered: bool,
    body_pending: bool,
    purpose: Option<PurposeV1>,
    original_uid: Option<u32>,
    closed: Option<JournalError>,
}

impl RootProvisioningNativeViewsV1 {
    pub(crate) fn new() -> Self { Self { geometry: None, fixed: None, backing: None, entered: false, body_pending: false, purpose: None, original_uid: None, closed: None } }

    pub(crate) fn prepare_delete_cache_once_v2(&mut self, receiving: RootDeleteCacheStageReceivingV2<'_, '_>,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        project: ProjectId, horizon: RootContinuationHorizonDataV1) -> Result<(), JournalError> {
        self.prepare_once(&mut ReceivingV1::Delete(receiving), project, SourceInputV1::Delete(source), horizon)
    }

    pub(crate) fn observe_delete_cache_body_once_v2(&mut self, receiving: RootDeleteCacheStageReceivingV2<'_, '_>,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        project: ProjectId) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.observe_prepared_once(&mut ReceivingV1::Delete(receiving), project, SourceInputV1::Delete(source))
    }

    pub(crate) fn finish_delete_cache_after_once_v2(&mut self) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.finish_body_after_once_v1()
    }

    /// Reuses this genuine Environment flight's completed Source model.
    /// The issuer retains that context through its independently owed late
    /// model posts. This method leaves the Cache/object afterposts owed until
    /// finish_environment_after_once_v1 on either compiler/artifact outcome.
    /// Prepared getters lend comparison DATA only, never admission.
    pub(crate) fn observe_environment_once(&mut self,
        receiving: RootEnvironmentStageReceivingV1<'_, '_>,
        source: &RootEnvironmentReadonlyContextV1, project: ProjectId,
        horizon: RootContinuationHorizonDataV1,
    ) -> Result<(), JournalError> {
        self.observe_once(ReceivingV1::Environment(receiving), project, SourceInputV1::Environment(source), horizon)
    }

    pub(crate) fn observe_apply_once(&mut self, receiving: RootApplyStageReceivingV1<'_, '_>, project: ProjectId, horizon: RootContinuationHorizonDataV1)
        -> Result<(), JournalError> { self.observe_once(ReceivingV1::Apply(receiving), project, SourceInputV1::Captured, horizon) }

    pub(crate) fn observe_host_launch_once(&mut self, receiving: RootHostLaunchStageReceivingV1<'_, '_>, project: ProjectId, horizon: RootContinuationHorizonDataV1)
        -> Result<(), JournalError> { self.observe_once(ReceivingV1::HostLaunch(receiving), project, SourceInputV1::Captured, horizon) }

    /// Uses the same rooted Source/Cache recipe for the distinct current31 purpose.
    pub(crate) fn observe_maintenance_storage_once_v2(&mut self,
        receiving: RootMaintenanceStorageStageReceivingV2<'_, '_>,
        readonly: &super::finality_readonly::RootCreateFinalityReadonlyOriginalV1,
        project: ProjectId,
        horizon: RootContinuationHorizonDataV1,
    ) -> Result<(), JournalError> {
        let source = readonly.maintenance_source_data_v2()?;
        self.observe_once(ReceivingV1::MaintenanceStorage(receiving), project,
            SourceInputV1::Maintenance(source), horizon)
    }

    fn observe_once(&mut self, mut receiving: ReceivingV1<'_, '_>, project: ProjectId,
        source: SourceInputV1<'_>, horizon: RootContinuationHorizonDataV1) -> Result<(), JournalError> {
        self.prepare_once(&mut receiving, project, source, horizon)?;
        self.observe_prepared_once(&mut receiving, project, source)
    }

    fn prepare_once(&mut self, receiving: &mut ReceivingV1<'_, '_>, project: ProjectId,
        source: SourceInputV1<'_>, horizon: RootContinuationHorizonDataV1) -> Result<(), JournalError> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.body_pending = true;
        self.purpose = Some(match &*receiving {
            ReceivingV1::Delete(_) => PurposeV1::Delete,
            ReceivingV1::Environment(_) => PurposeV1::Environment,
            ReceivingV1::Apply(_) => PurposeV1::Apply,
            ReceivingV1::HostLaunch(_) => PurposeV1::HostLaunch,
            ReceivingV1::MaintenanceStorage(_) => PurposeV1::MaintenanceStorage,
        });
        self.geometry = Some(NativeViewsV1::fixed_demand_v1(source, project));
        let demand = self.geometry.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.fixed = Some(match source {
            SourceInputV1::Captured | SourceInputV1::Delete(_) => receiving.admit_source_fixed_once_v1(demand),
            SourceInputV1::Environment(_) | SourceInputV1::Maintenance(_) => receiving.admit_source_tree_models_once_v1(demand),
        });
        if !matches!(self.fixed, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.backing = Some(Box::new(NativeViewsV1::new(horizon)));
        self.original_uid = Some(receiving.controller_identity_v1().0);
        Ok(())
    }

    fn observe_prepared_once(&mut self, receiving: &mut ReceivingV1<'_, '_>, project: ProjectId,
        source: SourceInputV1<'_>) -> Result<(), JournalError> {
        let actual = self.backing.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if actual.primary.is_some() || !matches!(self.fixed, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        actual.primary = Some(actual.observe_inner(receiving, project, source));
        if self.body_pending {
            // Complete the first physical sample's own native post before
            // lending its DATA. The distinct physical after sample and all
            // five journal afterposts still bracket the full compiler body.
            if matches!(actual.primary, Some(Ok(()))) {
                if let Some(objects) = actual.objects.as_mut() {
                    objects.finish_before_once();
                    if objects.before.completed_data_v1().is_err() {
                        actual.primary = Some(Err(StopV1::Incomplete));
                    }
                }
            }
            self.require_pending_body_v1()
        } else {
            actual.finish_posts(receiving.controller_identity_v1().0);
            self.require_complete_v1()
        }
    }

    // These lend only the selected genuine purpose's current before DATA.
    // No caller bytes, status flag, decoded row or old Create grant enters.
    fn require_pending_body_v1(&self) -> Result<(), JournalError> {
        if !self.body_pending || self.closed.is_some() { return Err(JournalError::ProtectedBoundary); }
        let actual = self.backing.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(actual.primary, Some(Ok(()))) || actual.posts.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn prepared_tree_v1(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_pending_body_v1()?;
        self.backing.as_ref().and_then(|actual| actual.source_tree.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
    }

    fn prepared_cache_v1(&self) -> Result<&CacheCurrentInventoryDataV1, JournalError> {
        self.require_pending_body_v1()?;
        self.backing.as_ref().and_then(|actual| actual.cache_models.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
    }

    fn prepared_physical_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, JournalError> {
        self.require_pending_body_v1()?;
        self.backing.as_ref().and_then(|actual| actual.objects.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?.before.completed_data_v1()
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    fn prepared_limits_digest_v1(&self)
        -> Result<aos_sandbox_core::ObjectDigest, JournalError>
    {
        self.require_pending_body_v1()?;
        self.backing.as_ref().and_then(|actual| actual.objects.as_ref())
            .and_then(|objects| objects.limits.as_ref()).and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.digest_v1()
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    fn prepared_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_pending_body_v1()?;
        self.backing.as_ref().and_then(|actual| actual.before.as_ref())
            .and_then(|sample| sample.as_ref().ok()).copied().ok_or(JournalError::ProtectedBoundary)
    }

    /// Runs every independently owed Cache/object/clock afterpost without a
    /// healthy financial reentry or allocation after an earlier body failure.
    fn finish_body_after_once_v1(&mut self) -> Result<(), JournalError> {
        if !self.body_pending || !self.entered {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let actual = self.backing.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if actual.posts.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let uid = self.original_uid.ok_or(JournalError::ProtectedBoundary)?;
        actual.finish_posts(uid);
        self.require_complete_v1()
    }

    fn require_purpose_v1(&self, expected: PurposeV1) -> Result<(), JournalError> {
        if self.purpose == Some(expected) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn prepared_environment_tree_v1(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Environment)?;
        self.prepared_tree_v1()
    }

    pub(crate) fn prepared_environment_cache_v1(&self) -> Result<&CacheCurrentInventoryDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Environment)?;
        self.prepared_cache_v1()
    }

    pub(crate) fn prepared_environment_physical_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Environment)?;
        self.prepared_physical_v1()
    }

    pub(crate) fn prepared_environment_limits_digest_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.require_purpose_v1(PurposeV1::Environment)?;
        self.prepared_limits_digest_v1()
    }

    pub(crate) fn prepared_environment_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_purpose_v1(PurposeV1::Environment)?;
        self.prepared_clock_v1()
    }

    pub(crate) fn finish_environment_after_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::Environment)?;
        self.finish_body_after_once_v1()
    }

    pub(crate) fn prepared_apply_tree_v1(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.prepared_tree_v1()
    }

    pub(crate) fn prepared_apply_cache_v1(&self) -> Result<&CacheCurrentInventoryDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.prepared_cache_v1()
    }

    pub(crate) fn prepared_apply_physical_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.prepared_physical_v1()
    }

    pub(crate) fn prepared_apply_limits_digest_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.prepared_limits_digest_v1()
    }

    pub(crate) fn prepared_apply_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.prepared_clock_v1()
    }

    pub(crate) fn finish_apply_after_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.finish_body_after_once_v1()
    }

    pub(crate) fn prepared_host_launch_tree_v1(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.prepared_tree_v1()
    }

    pub(crate) fn prepared_host_launch_cache_v1(&self) -> Result<&CacheCurrentInventoryDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.prepared_cache_v1()
    }

    pub(crate) fn prepared_host_launch_physical_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.prepared_physical_v1()
    }

    pub(crate) fn prepared_host_launch_limits_digest_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.prepared_limits_digest_v1()
    }

    pub(crate) fn prepared_host_launch_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.prepared_clock_v1()
    }

    /// Borrows the same Host Source model while its independent parent post is owed.
    pub(crate) fn prepared_host_launch_source_v2(&self) -> Result<&Journal, JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.require_pending_body_v1()?;
        self.backing.as_ref().and_then(|actual| actual.host_source_model.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?.journal_v1()
    }

    pub(crate) fn finish_host_launch_after_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::HostLaunch)?;
        self.finish_body_after_once_v1()
    }

    pub(crate) fn prepared_maintenance_storage_tree_v1(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.prepared_tree_v1()
    }

    pub(crate) fn prepared_maintenance_storage_cache_v1(&self) -> Result<&CacheCurrentInventoryDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.prepared_cache_v1()
    }

    pub(crate) fn prepared_maintenance_storage_physical_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.prepared_physical_v1()
    }

    pub(crate) fn prepared_maintenance_storage_limits_digest_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.prepared_limits_digest_v1()
    }

    pub(crate) fn prepared_maintenance_storage_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.prepared_clock_v1()
    }

    pub(crate) fn finish_maintenance_storage_after_once_v2(&mut self) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.finish_body_after_once_v1()
    }

    pub(crate) fn completed_maintenance_storage_tree_v3(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::MaintenanceStorage)?;
        self.tree_data_v1()
    }

    pub(crate) fn apply_source_input_bytes_v1(&self) -> Result<u64, JournalError> {
        self.require_purpose_v1(PurposeV1::Apply)?;
        self.require_pending_body_v1()?;
        let source = self.backing.as_ref().ok_or(JournalError::ProtectedBoundary)?.source.replay_native_v1()?;
        source.state.iter().try_fold(0_u64, |sum, ((_, key), value)| {
            let row = key.len().checked_add(value.len()).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            sum.checked_add(row).ok_or(JournalError::JournalTooLarge)
        })
    }

    pub(crate) fn delete_cache_coordinates_v2(&self) -> Result<[
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1; 5], JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.require_complete_v1()?;
        let actual = self.backing.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let one = |index: usize| -> Result<_, JournalError> {
            let native = match &actual.completed_cache[index] {
                Some(data) => data.readback_v2()?,
                None => actual.cache[index].as_ref().ok_or(JournalError::ProtectedBoundary)?.terminal_native_v1()?,
            };
            Ok(aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1 {
                names: native.names, next: native.next, end: native.end })
        };
        Ok([one(0)?,one(1)?,one(2)?,one(3)?,one(4)?])
    }

    // Only the completed actual D Cache owner lends its own canonical limits.
    pub(crate) fn delete_cache_limits_v2(&self) -> Result<PhysicalManifestLimitsDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.require_complete_v1()?;
        self.backing.as_ref().and_then(|actual| actual.objects.as_ref())
            .and_then(|objects| objects.limits.as_ref()).and_then(|value| value.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn delete_cache_physical_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1, JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.require_complete_v1()?;
        let objects = self.backing.as_ref().and_then(|actual| actual.objects.as_ref()).ok_or(JournalError::ProtectedBoundary)?;
        let limits = objects.limits.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        objects.after.completed_comparison_data_v2(limits.digest_v1().map_err(|_| JournalError::ProtectedBoundary)?)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    // The actual D owner calls only after its separate Root/service/clock
    // afters. All five native predicates are checked before any file is dropped.
    pub(crate) fn retire_delete_cache_prefixes_once_v2(&mut self) -> Result<(), JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.require_complete_v1()?;
        let actual = self.backing.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let ready = actual.completed_cache.iter().all(Option::is_none)
            && actual.cache.iter().all(|reader| reader.as_ref()
                .is_some_and(|reader| reader.require_completed_data_v2().is_ok()));
        if !ready {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        for index in 0..5 {
            let reader = actual.cache[index].take().ok_or(JournalError::ProtectedBoundary)?;
            match reader.into_completed_data_v2() {
                Ok(data) => actual.completed_cache[index] = Some(data),
                Err(reader) => {
                    actual.cache[index] = Some(reader);
                    self.closed.get_or_insert(JournalError::ProtectedBoundary);
                    return Err(JournalError::ProtectedBoundary);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn retired_delete_cache_files_v2(&self) -> Result<u64, JournalError> {
        self.require_purpose_v1(PurposeV1::Delete)?;
        self.require_complete_v1()?;
        let actual = self.backing.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if actual.cache.iter().any(Option::is_some) { return Err(JournalError::ProtectedBoundary); }
        ROLES.into_iter().enumerate().try_fold(0u64, |total, (index, role)| {
            let fixed = actual.completed_cache[index].as_ref().ok_or(JournalError::ProtectedBoundary)?
                .cache_fixed_demand_v2(role)?;
            total.checked_add(fixed.get(D::OpenFiles)).ok_or(JournalError::JournalTooLarge)
        })
    }

    pub(crate) fn funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.fixed, Some(Err(_))) || self.backing.as_ref().is_some_and(|actual|
            matches!(actual.primary, Some(Err(StopV1::Funding(_))))
                || actual.objects.as_ref().is_some_and(|objects| matches!(objects.first, Some(ObjectFirstV1::Funding))))
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        let actual = self.backing.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.closed.is_none() && matches!(actual.primary, Some(Ok(()))) && matches!(actual.posts, Some(Ok(()))) {
            Ok(())
        } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_complete_v1()?;
        self.backing.as_ref().and_then(|actual| actual.after.as_ref()).and_then(|sample| sample.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn tree_data_v1(&self) -> Result<&TreeDataV1, JournalError> {
        self.require_complete_v1()?;
        self.backing.as_ref().and_then(|actual| actual.source_tree.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn cache_inventory_v1(&self) -> Result<&CacheCurrentInventoryDataV1, JournalError> {
        self.require_complete_v1()?;
        self.backing.as_ref().and_then(|actual| actual.cache_models.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn physical_snapshot_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, JournalError> {
        self.require_complete_v1()?;
        self.backing.as_ref().and_then(|actual| actual.objects.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?.after.completed_data_v1()
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn physical_limits_digest_v1(&self) -> Result<aos_sandbox_core::ObjectDigest, JournalError> {
        self.require_complete_v1()?;
        self.backing.as_ref().and_then(|actual| actual.objects.as_ref())
            .and_then(|objects| objects.limits.as_ref()).and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.digest_v1()
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let actual = self.backing.as_ref();
        cause(&self.geometry).or_else(|| cause(&self.fixed)).or_else(|| {
            let actual = actual?;
            cause(&actual.before).or_else(|| actual.frontier_clock.failure()).or_else(|| actual.source.failure())
                .or_else(|| actual.host_source_model.as_ref().and_then(|model| model.failure()))
                .or_else(|| cause(&actual.source_tree))
                .or_else(|| actual.cache.iter().flatten().find_map(Reader::failure))
                .or_else(|| cause(&actual.cache_models))
                .or_else(|| actual.objects.as_ref().and_then(|objects| objects.failure()))
                .or_else(|| cause(&actual.primary))
                .or_else(|| actual.source.post_failure())
                .or_else(|| actual.host_source_model.as_ref().and_then(|model| model.parent_post_failure_v1()))
                .or_else(|| actual.cache.iter().flatten().find_map(Reader::post_failure))
                .or_else(|| cause(&actual.after)).or_else(|| cause(&actual.posts))
        }).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, StopV1> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(StopV1::Incomplete)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

// Only the actual Environment constructor can select the completed-model arm.
// No raw map, successful flag or caller-selected role constructs this input.
#[derive(Clone, Copy)]
enum SourceInputV1<'source> {
    Captured,
    Delete(&'source crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1),
    Environment(&'source RootEnvironmentReadonlyContextV1),
    Maintenance(super::finality_readonly::RootMaintenanceSourceDataV2<'source>),
}

/// Prices the same canonical Source tree replay on an actual Maintenance cut.
pub(crate) fn maintenance_tree_model_receiving_demand_v3(
    source: super::finality_readonly::RootMaintenanceSourceDataV2<'_>, project: ProjectId,
) -> Result<ResourceVector, JournalError> {
    source_tree_demand_v1(source.state_data_v2()?, project)
}

/// Replays the current Maintenance Source tree through the sole lineage engine.
pub(crate) fn maintenance_tree_model_data_v3(
    source: super::finality_readonly::RootMaintenanceSourceDataV2<'_>, project: ProjectId,
) -> Result<TreeDataV1, Box<dyn Error>> {
    fold_source_tree_v1(source.state_data_v2()?, project).map_err(|cause| Box::new(cause) as _)
}

fn source_tree_demand_v1(state: &cache_current::State, project: ProjectId)
    -> Result<ResourceVector, JournalError>
{
    type Tree = aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1<DomainLedgerDataError>;
    let rows = state.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()));
    let dynamic = Tree::receiving_dynamic_demand_v1(rows, project).map_err(JournalError::from)?;
    let fixed = Tree::receiving_fixed_bytes_v1().and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    dynamic.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
        .map_err(|_| JournalError::JournalTooLarge)
}

fn fold_source_tree_v1(state: &cache_current::State, project: ProjectId)
    -> Result<TreeDataV1, StopV1>
{
    let hold = aos_sandbox_ledger_replay::source_policy_hold::current_state(state)?;
    if hold.delete_pending.is_some() || hold.q04_pending.is_some() || hold.v8_pending.is_some()
        || hold.hold.is_some_and(|hold| hold.is_held()) { return Err(StopV1::Incomplete); }
    let rows = state.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()))
        .filter(|(namespace, key, _)| aos_sandbox_ledger_replay::replay::tree_lineage::retained::matching_project_tree_row(*namespace, key, project));
    let mut heads = aos_sandbox_ledger_replay::replay::tree_lineage::replay_closed_tree_lineage_records_v2(rows)?;
    let head = heads.remove(&project).ok_or(StopV1::Incomplete)?;
    Ok(TreeDataV1 { generation: head.tree.tree_generation().get(),
        commitment: aos_sandbox_ledger_replay::hierarchy::codec::tree_commitment_v1(&head.tree)?,
        head: head.tree_head, lineage: head.lineage_head, tree: head.tree })
}

#[cfg(test)]
mod environment_currentness_tests {
    use super::*;

    #[test]
    fn unentered_actual_source_context_cannot_price_or_supply_an_environment_cut() {
        let source = RootEnvironmentReadonlyContextV1::new();
        let project = ProjectId::from_bytes([7; 16]);

        assert!(NativeViewsV1::fixed_demand_v1(SourceInputV1::Environment(&source), project).is_err());
        assert!(source.source_state_v1().is_err());
    }

    #[test]
    fn dormant_environment_finalizer_cannot_allocate_or_complete_a_native_owner() {
        let mut actual = RootProvisioningNativeViewsV1::new();

        assert!(actual.finish_environment_after_once_v1().is_err());
        assert!(actual.backing.is_none());
        assert!(actual.require_complete_v1().is_err());
        assert!(actual.prepared_environment_cache_v1().is_err());
        assert!(actual.prepared_environment_physical_v1().is_err());
        assert!(actual.clock_v1().is_err());
    }
}
