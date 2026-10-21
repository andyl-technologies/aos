//! Keeps main and physical workers inside the same original Storage envelope.
//!
//! The original sealed Storage F supplies comparison coordinates once, before
//! native capture. One installed aggregate cgroup enforces its CPU, memory and
//! task ceilings across main and every fixed helper. This creates no child
//! account and charges no second CPU rate. Native workers still need their own
//! exclusive flight, actual representation/FD/task/traffic admission and exact
//! membership beneath this continuously held aggregate before any effect.

use super::*;
use aos_sandbox_linux::cgroup::{
    CgroupV2Root, RetainedCgroupAnchor, StorageReceivingAggregateCgroupReadbackV1,
    WorkerCgroupOpeningV1, WorkerCgroupOpeningRefusalV1,
};

pub(in crate::normal_root::storage_worker_origin) struct StorageAggregateOriginalV1 {
    opening: StorageReceivingAggregateCgroupReadbackV1,
    opened: Option<Result<(), aos_linux_descriptors::Error>>,
    root: Option<CgroupV2Root>,
    anchor: Option<RetainedCgroupAnchor>,
    main: WorkerCgroupOpeningV1,
    main_result: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    limits: ReceivingContainmentReadbackV1,
    first: Option<AggregateFailure>,
    taken: bool,
    initial_complete: bool,
}

#[derive(Clone, Copy)]
enum AggregateFailure { Opening, Main, Limits, Closed }

impl Default for StorageAggregateOriginalV1 {
    fn default() -> Self {
        Self {
            opening: StorageReceivingAggregateCgroupReadbackV1::new(),
            opened: None, root: None, anchor: None, main: WorkerCgroupOpeningV1::new(),
            main_result: None, limits: ReceivingContainmentReadbackV1::default(),
            first: None, taken: false, initial_complete: false,
        }
    }
}

impl StorageAggregateOriginalV1 {
    pub(in crate::normal_root::storage_worker_origin) fn fixed_demand() -> Result<ResourceVector, StorageReceivingClosedV1> {
        ReceivingContainmentReadbackV1::fixed_demand().checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, (std::mem::size_of::<Self>() + 4 * 4097 + 24 * 256) as u64)
                .with(D::OpenFiles, 12)
                .with(D::MetadataEntries, 32),
        ).map_err(|_| StorageReceivingClosedV1)
    }

    // Only the continuously owned original receiver calls this after paying
    // fixed_demand on that same ledger. The vector cannot construct this owner
    // or authorize any worker; it is the original F's immutable control recipe.
    pub(in crate::normal_root::storage_worker_origin) fn capture_once(&mut self, original_f: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        if self.opened.is_some() || self.first.is_some() || self.taken {
            self.first.get_or_insert(AggregateFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.opened = Some(self.opening.capture_once());
        if !matches!(self.opened, Some(Ok(()))) {
            self.first = Some(AggregateFailure::Opening);
            return Err(StorageReceivingClosedV1);
        }
        let Some((root, anchor)) = self.opening.take_validated_pair() else { std::process::abort() };
        self.root = Some(root);
        self.anchor = Some(anchor);
        let Some(anchor) = self.anchor.as_ref() else { std::process::abort() };
        self.main_result = Some(self.main.capture_descendant_once(anchor, std::path::Path::new("aos-storaged.service")));
        if !matches!(self.main_result, Some(Ok(()))) {
            self.first = Some(AggregateFailure::Main);
            return Err(StorageReceivingClosedV1);
        }
        self.limits.capture(anchor, original_f);
        if self.limits.require_initial().is_err() {
            self.first = Some(AggregateFailure::Limits);
            return Err(StorageReceivingClosedV1);
        }
        self.initial_complete = true;
        Ok(())
    }

    pub(in crate::normal_root::storage_worker_origin) fn take_main_once(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        if self.first.is_some() || self.taken || self.limits.require_initial().is_err()
            || self.root.is_none() || self.main.anchor().is_none()
        { return None; }
        self.taken = true;
        match (self.root.take(), self.main.take_anchor_once()) {
            (Some(root), Some(main)) => Some((root, main)),
            _ => std::process::abort(),
        }
    }

    pub(in crate::normal_root::storage_worker_origin) fn recheck_once(&mut self) {
        if let Some(anchor) = self.anchor.as_ref() {
            self.limits.recheck(anchor);
        }
        if self.limits.require_current().is_err() {
            self.first.get_or_insert(AggregateFailure::Limits);
        }
    }

    pub(in crate::normal_root::storage_worker_origin) fn settle_initial_once(&mut self) {
        if self.first.is_some() { return; }
        self.limits.settle_positive_named_verifications_once_v1();
        if !self.limits.named_verifications_settled_v1() {
            self.first.get_or_insert(AggregateFailure::Limits);
        }
    }

    pub(in crate::normal_root::storage_worker_origin) fn is_current(&self) -> bool {
        self.first.is_none() && self.taken && self.anchor.is_some()
            && self.limits.require_current().is_ok()
            && self.limits.named_verifications_settled_v1()
    }

    pub(in crate::normal_root::storage_worker_origin) fn observe_current_into(&self, sample: &mut ReceivingContainmentCurrentnessV1) {
        if let Some(anchor) = self.anchor.as_ref() {
            self.limits.observe_current_into(anchor, sample);
        }
    }

    pub(in crate::normal_root::storage_worker_origin) fn anchor(&self) -> Result<&RetainedCgroupAnchor, StorageReceivingClosedV1> {
        if !self.is_current() { return Err(StorageReceivingClosedV1); }
        self.anchor.as_ref().ok_or(StorageReceivingClosedV1)
    }

    pub(in crate::normal_root::storage_worker_origin) fn initial_failure(&self)
        -> Option<&(dyn Error + 'static)>
    {
        if self.initial_complete { return None; }
        self.failure()
    }

    pub(in crate::normal_root::storage_worker_origin) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            AggregateFailure::Opening => self.opening.failure()
                .or_else(|| self.opened.as_ref()?.as_ref().err().map(|error| error as _)),
            AggregateFailure::Main => self.main.failure(),
            AggregateFailure::Limits => self.limits.failure(),
            AggregateFailure::Closed => Some(&StorageReceivingClosedV1),
        }
    }
}
