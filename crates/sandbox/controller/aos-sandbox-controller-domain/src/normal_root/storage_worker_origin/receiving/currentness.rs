//! Fresh Storage observations under one exclusive original operation loan.
//!
//! Same original native controls, process, images and component stay held. Only
//! a fully positive flight whose property transport settled may be disposed
//! before a new operation is admitted. Resident peak and per-operation traffic
//! are distinct obligations. Failed or ambiguous observations stay resident.

use super::*;
use crate::controller_resource_reservation::component_receiving::ComponentReceivingOperationLoanV1;

#[derive(Clone, Copy)]
enum CurrentFailure { Operation, Preparation, Before, InitialLimits, AggregateBefore, Parent, After, Pair, FinalLimits, AggregateAfter, Binding, Settlement }

pub(super) struct CurrentObservation {
    archive: service::FirstGlobalPropertyArchive,
    operation: Option<Result<(), StorageReceivingClosedV1>>,
    preparation: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<NativeResult>,
    initial_limits: ReceivingContainmentCurrentnessV1,
    aggregate_before: ReceivingContainmentCurrentnessV1,
    parent: Option<ParentResult>,
    after: Option<NativeResult>,
    pair: Option<StorageComponentPairPostV1>,
    final_limits: ReceivingContainmentCurrentnessV1,
    aggregate_after: ReceivingContainmentCurrentnessV1,
    binding: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<CurrentFailure>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl CurrentObservation {
    pub(super) fn new(lifetime: ObserverLifetime) -> Self {
        Self {
            archive: service::FirstGlobalPropertyArchive::with_materialization_limit(1, lifetime, PROPERTY_BYTES),
            operation: None, preparation: None, before: None, initial_limits: ReceivingContainmentCurrentnessV1::default(),
            aggregate_before: ReceivingContainmentCurrentnessV1::default(),
            parent: None, after: None, pair: None,
            final_limits: ReceivingContainmentCurrentnessV1::default(),
            aggregate_after: ReceivingContainmentCurrentnessV1::default(), binding: None, first: None, settlement: None,
        }
    }

    pub(super) fn demand() -> Result<ResourceVector, StorageReceivingClosedV1> {
        // Native/control observations and retained Parent/status owners are
        // separate from the operation's shared observer transport/model recipe.
        // Earlier startup obligations remain charged; this additional finite
        // operation capacity is never inferred from that archive's disposal.
        let observer = service::fixed_property_observer_demand_v1(PROPERTY_BYTES)
            .map_err(|_| StorageReceivingClosedV1)?;
        if observer.get(D::MemoryBytes) < (6 * PROPERTY_BYTES) as u64 {
            return Err(StorageReceivingClosedV1);
        }
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, std::mem::size_of::<Self>() as u64 + 64 * 1024 + 2 * 8 * 2 * 256)
            .with(D::MetadataEntries, 8 + 2 * 8))
    }

    pub(super) fn observe(&mut self, custody: &StartupCustody, component: &StorageComponentEnvelopeOriginalV1,
               initial: &(StorageWorkerParentDataV3, [u8; 16]),
               limits: &ReceivingContainmentReadbackV1,
               operation: &mut ComponentReceivingOperationLoanV1<'_>) {
        self.before = Some(custody.recheck_native_before());
        if matches!(self.before, Some(Err(_))) { self.first.get_or_insert(CurrentFailure::Before); }
        if let Some(anchor) = custody.cgroup.as_ref() {
            limits.observe_current_into(anchor, &mut self.initial_limits);
        }
        if self.initial_limits.require_current().is_err() {
            self.first.get_or_insert(CurrentFailure::InitialLimits);
        }
        custody.aggregate.observe_current_into(&mut self.aggregate_before);
        if self.aggregate_before.require_current().is_err() {
            self.first.get_or_insert(CurrentFailure::AggregateBefore);
        }
        // The genuine original and all local controls are checked before the
        // exclusive operation spends its one flight. No AUTH, frame, runtime or
        // archive allocation starts before the full operation shape is admitted.
        if self.first.is_none() {
            self.operation = Some(operation.consume_flight_once()
                .map_err(|_| StorageReceivingClosedV1));
            if matches!(self.operation, Some(Err(_))) {
                self.first = Some(CurrentFailure::Operation);
            }
        }
        if self.first.is_none() {
            self.preparation = Some(self.archive.prepare());
            if matches!(self.preparation, Some(Err(_))) {
                self.first = Some(CurrentFailure::Preparation);
            }
        }
        if self.first.is_none() {
            self.parent = Some(observe_fixed_storage_resource_parent_with_archive_v1(&mut self.archive));
            if matches!(self.parent, Some(Err(_))) { self.first = Some(CurrentFailure::Parent); }
        }
        self.after = Some(custody.recheck_native_after());
        if matches!(self.after, Some(Err(_))) { self.first.get_or_insert(CurrentFailure::After); }
        self.pair = Some(component.storage_receiving_pair_post());
        if self.pair.as_ref().is_some_and(|post| post.failure().is_some()) {
            self.first.get_or_insert(CurrentFailure::Pair);
        }
        if let Some(anchor) = custody.cgroup.as_ref() {
            limits.observe_current_into(anchor, &mut self.final_limits);
        }
        if self.final_limits.require_current().is_err() {
            self.first.get_or_insert(CurrentFailure::FinalLimits);
        }
        custody.aggregate.observe_current_into(&mut self.aggregate_after);
        if self.aggregate_after.require_current().is_err() {
            self.first.get_or_insert(CurrentFailure::AggregateAfter);
        }
        self.binding = Some((|| {
            let current = self.parent.as_ref().and_then(|r| r.as_ref().ok()).ok_or(StorageReceivingClosedV1)?;
            if current != initial { return Err(StorageReceivingClosedV1); }
            component.require_storage_receiving_binding(
                (initial.0.invocation(), initial.1), (current.0.invocation(), current.1),
            ).map_err(|_| StorageReceivingClosedV1)
        })());
        if matches!(self.binding, Some(Err(_))) { self.first.get_or_insert(CurrentFailure::Binding); }
        if self.first.is_none() {
            self.settlement = Some(self.archive.settle_positive_once());
            if matches!(self.settlement, Some(Err(_))) { self.first = Some(CurrentFailure::Settlement); }
        }
    }

    pub(super) fn can_dispose(&self) -> bool {
        self.first.is_none()
            && matches!(self.operation, Some(Ok(())))
            && matches!(self.binding, Some(Ok(())))
            && matches!(self.settlement, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            CurrentFailure::Operation => self.operation.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn Error),
            CurrentFailure::Preparation => self.preparation.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            CurrentFailure::Before => native_failure(&self.before),
            CurrentFailure::InitialLimits => self.initial_limits.failure(),
            CurrentFailure::AggregateBefore => self.aggregate_before.failure(),
            CurrentFailure::AggregateAfter => self.aggregate_after.failure(),
            CurrentFailure::Parent => self.parent.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            CurrentFailure::After => native_failure(&self.after),
            CurrentFailure::Pair => self.pair.as_ref().and_then(StorageComponentPairPostV1::failure),
            CurrentFailure::FinalLimits => self.final_limits.failure(),
            CurrentFailure::Settlement => self.settlement.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
            CurrentFailure::Binding => self.binding.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &dyn Error),
        };
        cause.or(Some(&StorageReceivingClosedV1))
    }
}
