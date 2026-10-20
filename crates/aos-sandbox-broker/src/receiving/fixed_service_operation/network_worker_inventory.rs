//! Joins the real Network19 loan, fixed SDK census and private native forest.
//!
//! Preparation pays the entire retained destination before FDStore or worker
//! native work. The same operation/recipient and continuously held anchors
//! remain mandatory on independently owed observations after body refusal.

use super::*;
use aos_sandbox_linux::cgroup::{NetworkWorkerCgroupAbsenceOriginalV4 as Forest,
    NetworkWorkerCgroupAbsenceRefusalV4};
use aos_systemd::{NetworkWorkerCensusOriginalV4 as Sdk, NetworkWorkerCensusRefusalV4};
use aos_systemd::fd_store::NetworkFdStoreFailureViewV4;

#[derive(Clone, Copy)]
enum First { Current, Shape, Funding, Anchors, Association, Begin, ListingBefore, ForestBefore,
    ListingAfter, SdkAfter, ForestAfter, Close, Disposal, Order }

/// Retains both full worker listings and both native aggregate forest rounds.
///
/// This owner supplies no worker, namespace, cleanup or capacity authority.
/// Its actual Network19 loan prepays the whole supplier before native entry.
#[must_use = "retain every worker census original through the enclosing F posts"]
pub struct NetworkWorkerInventoryObservationOriginalV4 {
    current: Option<Result<(), FixedServiceOperationClosedV4>>,
    shape: Option<Result<ResourceVector, AccountingError>>,
    extents: Option<(usize, usize)>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    ordinal: Option<u64>,
    invocation: Option<[u8; 16]>,
    anchors: Option<(u64, u64)>,
    association: Option<FixedServiceOperationClosedV4>,
    sdk: Sdk,
    sdk_begin: Option<Result<(), NetworkWorkerCensusRefusalV4>>,
    listing_before: Option<Result<(), NetworkWorkerCensusRefusalV4>>,
    forest: Forest,
    forest_before: Option<Result<(), NetworkWorkerCgroupAbsenceRefusalV4>>,
    listing_after: Option<Result<(), NetworkWorkerCensusRefusalV4>>,
    sdk_after: Option<Result<(), NetworkWorkerCensusRefusalV4>>,
    forest_after: Option<Result<(), NetworkWorkerCgroupAbsenceRefusalV4>>,
    close: Option<Result<(), NetworkWorkerCensusRefusalV4>>,
    disposal: Option<Result<(), NetworkWorkerCensusRefusalV4>>,
    after_entered: bool,
    first: Option<First>,
    closed: FixedServiceOperationClosedV4,
}

impl Default for NetworkWorkerInventoryObservationOriginalV4 {
    fn default() -> Self {
        Self { current: None, shape: None, extents: None, funding: None, ordinal: None,
            invocation: None, anchors: None, association: None, sdk: Sdk::new(),
            sdk_begin: None, listing_before: None, forest: Forest::new(), forest_before: None,
            listing_after: None, sdk_after: None, forest_after: None, close: None,
            disposal: None, after_entered: false, first: None, closed: FixedServiceOperationClosedV4 }
    }
}

impl NetworkWorkerInventoryObservationOriginalV4 {
    /// Constructs inert destinations without native work or dynamic allocation.
    pub fn new() -> Self { Self::default() }

    fn demand_v4(extents: (usize, usize)) -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let sdk = Sdk::receiving_footprint_v4(extents.0, extents.1).ok_or(overflow)?;
        let forest = Forest::receiving_obligations_v4().ok_or(overflow)?;
        let header = std::mem::size_of::<Self>().checked_mul(2).ok_or(overflow)?;
        let memory = sdk.memory_bytes.checked_add(forest.0)
            .and_then(|bytes| bytes.checked_add(header)).ok_or(overflow)?;
        let files = sdk.open_files.checked_add(forest.1).ok_or(overflow)?;
        let names = sdk.metadata_entries.checked_add(forest.2).ok_or(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| overflow)?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow)?)
            .with(D::NetworkBytes, u64::try_from(sdk.network_bytes).map_err(|_| overflow)?)
            .with(D::LogBytes, u64::try_from(sdk.maximum_log_bytes).map_err(|_| overflow)?))
    }

    /// Requires both complete listings, native forest rounds and SDK disposal.
    ///
    /// # Errors
    /// Refuses failed, missing, foreign or repeated original observations.
    pub fn require_complete_v4(&self) -> Result<(), FixedServiceOperationClosedV4> {
        if self.first.is_none() && self.after_entered && self.sdk.completed_v4()
            && self.forest.completed_v4() && matches!(self.funding, Some(Ok(())))
            && matches!(self.listing_before, Some(Ok(())))
            && matches!(self.listing_after, Some(Ok(())))
            && matches!(self.sdk_after, Some(Ok(()))) && matches!(self.close, Some(Ok(())))
            && matches!(self.disposal, Some(Ok(()))) { Ok(()) } else { Err(self.closed) }
    }

    /// Reports that the same enclosing receiving owner holds the selected cause.
    pub fn original_failure_selected_v4(&self) -> bool {
        matches!(self.first, Some(First::Current | First::Funding | First::Anchors))
    }

    /// Borrows the chronological native, SDK or receiving refusal.
    pub fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ForestBefore | First::ForestAfter => self.forest.failure_v4(),
            First::Begin | First::ListingBefore | First::ListingAfter | First::SdkAfter
                | First::Close | First::Disposal => self.sdk.failure_v4().or(Some(&self.closed)),
            First::Anchors | First::Association | First::Order => Some(&self.closed),
        }
    }

    /// Borrows the selected raw archive guard without replacing earlier causes.
    pub fn failure_view_v4(&self) -> Option<NetworkFdStoreFailureViewV4<'_>> {
        if matches!(self.first, Some(First::Begin | First::ListingBefore | First::ListingAfter
            | First::SdkAfter | First::Close | First::Disposal)) {
            if let Ok(Some(native)) = self.sdk.native_failure_v4() {
                return Some(NetworkFdStoreFailureViewV4::Native(native));
            }
        }
        self.failure_v4().map(NetworkFdStoreFailureViewV4::Cause)
    }
}

impl FixedServiceOperationLoanV4<'_> {
    fn require_worker_inventory_association_v4(&self, original: &NetworkWorkerInventoryObservationOriginalV4)
        -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkInventory))
            || !self.operation.armed || !matches!(original.funding, Some(Ok(())))
            || original.ordinal != self.operation.operation_ordinal
            || original.invocation != self.operation.invocation {
            return Err(original.closed);
        }
        let aggregate = self.common.network_aggregate.as_ref()
            .and_then(|aggregate| aggregate.retained_inventory_anchor_v4()).ok_or(original.closed)?;
        let main = self.common.cgroup.as_ref().ok_or(original.closed)?;
        if original.anchors != Some((aggregate.kernel_id(), main.kernel_id())) {
            return Err(original.closed);
        }
        Ok(())
    }

    /// Pays all worker SDK and forest destinations before the FDStore begins.
    ///
    /// # Errors
    /// Retains actual Network19 currentness, geometry or same-F debit refusal.
    pub fn prepare_network_worker_inventory_once_v4(&mut self,
        original: &mut NetworkWorkerInventoryObservationOriginalV4,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if original.current.is_some() { original.first.get_or_insert(First::Order); return Err(original.closed); }
        original.current = Some(self.require_network_inventory_current_v4());
        if !matches!(original.current, Some(Ok(()))) { original.first = Some(First::Current); return Err(original.closed); }
        original.ordinal = self.operation.operation_ordinal;
        original.invocation = self.operation.invocation;
        original.extents = Sdk::fixed_empty_census_shape_v4();
        original.shape = Some(original.extents.ok_or(AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes }).and_then(NetworkWorkerInventoryObservationOriginalV4::demand_v4));
        let Some(Ok(demand)) = original.shape.as_ref().copied() else {
            original.first = Some(First::Shape); return Err(original.closed);
        };
        original.funding = Some(self.require_additional_representation_v4(demand));
        if !matches!(original.funding, Some(Ok(()))) { original.first = Some(First::Funding); return Err(original.closed); }
        original.anchors = self.common.network_aggregate.as_ref().and_then(|owner| owner.anchor_v4().ok())
            .zip(self.common.cgroup.as_ref()).map(|(aggregate, main)| (aggregate.kernel_id(), main.kernel_id()));
        if original.anchors.is_none() { original.first = Some(First::Anchors); return Err(original.closed); }
        Ok(())
    }

    /// Observes the first listing and forest on the prepaid same original.
    ///
    /// # Errors
    /// Retains SDK/FDStore association or native worker residuals. A failed SDK
    /// opening still reaches the separately paid native forest observation.
    pub fn observe_network_worker_inventory_before_v4(&mut self,
        original: &mut NetworkWorkerInventoryObservationOriginalV4,
        fd_store: &FixedServiceInventoryFdStoreEmptyOriginalV2,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if self.require_worker_inventory_association_v4(original).is_err()
            || original.forest_before.is_some() || original.after_entered {
            original.first.get_or_insert(First::Order); return Err(original.closed);
        }
        let context = fd_store.network_worker_context_v4(original.ordinal, original.invocation);
        match (context, original.extents) {
            (Ok((sdk, deadline, cutoff, wall)), Some((message, materialized))) => {
                original.sdk_begin = Some(original.sdk.begin_on_inventory_runtime_once_v4(
                    sdk, message, materialized, deadline, cutoff, wall));
                if !matches!(original.sdk_begin, Some(Ok(()))) { original.first.get_or_insert(First::Begin); }
                original.listing_before = Some(original.sdk.observe_next_once_v4());
                if !matches!(original.listing_before, Some(Ok(()))) { original.first.get_or_insert(First::ListingBefore); }
            }
            _ => { original.association = Some(original.closed); original.first.get_or_insert(First::Association); }
        }
        let aggregate = self.common.network_aggregate.as_ref()
            .and_then(|owner| owner.retained_inventory_anchor_v4()).ok_or(original.closed)?;
        let main = self.common.cgroup.as_ref().ok_or(original.closed)?;
        original.forest_before = Some(original.forest.capture_next_once_v4(aggregate, main));
        if !matches!(original.forest_before, Some(Ok(()))) { original.first.get_or_insert(First::ForestBefore); }
        if original.first.is_none() { Ok(()) } else { Err(original.closed) }
    }

    /// Attempts all independently prepaid worker afters despite prior refusal.
    ///
    /// # Errors
    /// Keeps earlier SDK/native failure, changed association, missing first
    /// observation, disposal or repeated-entry refusal without another debit.
    pub fn observe_network_worker_inventory_after_owed_v4(&mut self,
        original: &mut NetworkWorkerInventoryObservationOriginalV4,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if self.require_worker_inventory_association_v4(original).is_err() || original.after_entered {
            original.first.get_or_insert(First::Order); return Err(original.closed);
        }
        original.after_entered = true;
        original.listing_after = Some(original.sdk.observe_next_once_v4());
        if !matches!(original.listing_after, Some(Ok(()))) { original.first.get_or_insert(First::ListingAfter); }
        original.sdk_after = Some(original.sdk.observe_after_once_v4());
        if !matches!(original.sdk_after, Some(Ok(()))) { original.first.get_or_insert(First::SdkAfter); }
        let aggregate = self.common.network_aggregate.as_ref()
            .and_then(|owner| owner.retained_inventory_anchor_v4()).ok_or(original.closed)?;
        let main = self.common.cgroup.as_ref().ok_or(original.closed)?;
        if original.forest_before.is_none() {
            // The primary path may have stopped before reaching its native
            // round. Both paid destinations remain physically observable here.
            original.first.get_or_insert(First::Order);
            original.forest_before = Some(original.forest.capture_next_once_v4(aggregate, main));
        }
        original.forest_after = Some(original.forest.capture_next_once_v4(aggregate, main));
        if !matches!(original.forest_after, Some(Ok(()))) { original.first.get_or_insert(First::ForestAfter); }
        if original.first.is_none() {
            original.close = Some(original.sdk.close_positive_body_once_v4());
            if !matches!(original.close, Some(Ok(()))) { original.first.get_or_insert(First::Close); }
        }
        if original.first.is_none() {
            original.disposal = Some(original.sdk.dispose_positive_once_v4());
            if !matches!(original.disposal, Some(Ok(()))) { original.first.get_or_insert(First::Disposal); }
        }
        original.require_complete_v4()
    }
}
