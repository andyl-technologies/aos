//! Continuous root-export financing on the same admitted Storage original.
//!
//! This owner pays receiving and retained models before Host input/native work.
//! Its independently armed post remains callable after ordinary health closes.
//! It creates neither a signed Host grant nor a physical worker; those require
//! the separate verified original request and same catalog/native producer.

use super::*;
use crate::controller_resource_reservation::component_receiving::{
    ComponentReceivingOwnedOperationV1, complete_bound_delta_v1,
};
use aos_sandbox_broker::{BrokerAuthority, VerifiedStorageHostLaunchExportV2};
use aos_sandbox_model::AccountingError;
use aos_sandbox_model::component_receiving::{
    operation_traffic_demand_v1, without_operation_traffic_v1,
};

#[derive(Clone, Copy)]
enum RootExportFailure {
    Shape,
    Growth,
    Reservation,
    Operation,
    ModelShape,
    ModelGrowth,
    ModelReservation,
    ReadbackGrowth,
    ReadbackReservation,
    Preparation,
    Before,
    Binding,
    After,
    Closed,
}

pub(super) struct RootLaunchExportReceivingOriginalV2 {
    capacity: ResourceVector,
    shape: Option<Result<ResourceVector, StorageReceivingClosedV1>>,
    growth: Option<Result<(ResourceVector, ResourceVector), AccountingError>>,
    reservation: Option<Result<(), StorageReceivingClosedV1>>,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    flight_reservation: Option<Result<ResourceVector, AccountingError>>,
    model_shape: Option<Result<ResourceVector, StorageReceivingClosedV1>>,
    model_growth: Option<Result<(ResourceVector, ResourceVector), AccountingError>>,
    model_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    readback_capacity: ResourceVector,
    readback_bound: ResourceVector,
    readback_growth: Option<Result<(ResourceVector, ResourceVector, ResourceVector), AccountingError>>,
    readback_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    owed_post: StorageObserverOperationOriginalV1,
    preparation: Option<Result<(), StorageReceivingClosedV1>>,
    before: Option<NativeResult>,
    after: Option<NativeResult>,
    post_result: Option<Result<(), StorageReceivingClosedV1>>,
    binding: Option<Result<[u8; 32], StorageReceivingClosedV1>>,
    first: Option<RootExportFailure>,
    post_entered: bool,
    disposal_entered: bool,
}

impl RootLaunchExportReceivingOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            capacity: ResourceVector::ZERO,
            shape: None,
            growth: None,
            reservation: None,
            operation: None,
            flight_reservation: None,
            model_shape: None,
            model_growth: None,
            model_reservation: None,
            readback_capacity: ResourceVector::ZERO,
            readback_bound: ResourceVector::ZERO,
            readback_growth: None,
            readback_reservation: None,
            owed_post: StorageObserverOperationOriginalV1::new(),
            preparation: None,
            before: None,
            after: None,
            post_result: None,
            binding: None,
            first: None,
            post_entered: false,
            disposal_entered: false,
        }
    }

    pub(super) fn is_idle_v2(&self) -> bool {
        self.first.is_none() && self.operation.is_none()
    }

    fn is_current_v2(&self) -> bool {
        self.first.is_none() && !self.post_entered && !self.disposal_entered
            && self.operation.as_ref().is_some_and(
                ComponentReceivingOwnedOperationV1::is_consumed_current,
            )
    }

    pub(super) fn require_catalog_v2(&self) -> Result<(), StorageReceivingClosedV1> {
        // This is only the actual paid catalog-observation flight. The upper
        // closed launch owner independently establishes its signed authority;
        // neither a model debit nor this financial check can supply a grant.
        if !self.is_current_v2()
            || !matches!(self.model_reservation, Some(Ok(())))
        {
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    pub(super) fn failure<'owner>(&'owner self,
        ledger: &'owner ComponentServiceReceivingLedgerV1,
        current: &'owner StorageObserverOperationOriginalV1,
    ) -> Option<&'owner (dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>)
            -> Option<&(dyn Error + 'static)>
        {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            RootExportFailure::Shape => error(&self.shape),
            RootExportFailure::Growth => error(&self.growth).or_else(|| error(&self.flight_reservation)),
            RootExportFailure::Reservation => ledger.failure().map(|cause| cause as _),
            RootExportFailure::ModelShape => error(&self.model_shape),
            RootExportFailure::ModelGrowth => error(&self.model_growth),
            RootExportFailure::ModelReservation | RootExportFailure::ReadbackReservation => ledger.failure().map(|cause| cause as _),
            RootExportFailure::ReadbackGrowth => error(&self.readback_growth),
            RootExportFailure::Operation => self.operation.as_ref()?.failure().map(|cause| cause as _),
            RootExportFailure::Preparation | RootExportFailure::After => {
                ledger.failure().map(|cause| cause as &dyn Error)
                    .or_else(|| self.owed_post.failure()).or_else(|| error(&self.preparation))
                    .or_else(|| error(&self.after)).or(Some(&StorageReceivingClosedV1))
            }
            RootExportFailure::Before => ledger.failure().map(|cause| cause as &dyn Error)
                .or_else(|| current.failure()).or_else(|| error(&self.before)),
            RootExportFailure::Binding => error(&self.binding),
            RootExportFailure::Closed => Some(&StorageReceivingClosedV1),
        }
    }
}

/// Holds receiving/model debt on the same Storage F through export and posts.
///
/// Construction is available only through the genuine admitted original. Its
/// Rust borrow excludes other fresh Session/physical work throughout the turn.
/// This loan is financial custody, not Host admission or a descriptor grant.
#[must_use]
pub struct StorageRootLaunchExportReceivingLoanV2<'flight, 'original> {
    pub(super) receiving: &'flight mut StoragePrepareReceivingLoanV1<'original>,
    completed: bool,
}

/// Holds the checked original until the actual upper native owners dispose.
#[must_use]
pub struct StorageRootLaunchExportDisposalV2<'flight, 'original> {
    loan: StorageRootLaunchExportReceivingLoanV2<'flight, 'original>,
}

impl<'flight, 'original> StorageRootLaunchExportReceivingLoanV2<'flight, 'original> {
    fn state(&mut self) -> &mut RootLaunchExportReceivingOriginalV2 {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        &mut receiving.root_launch_export
    }

    /// Pays actual launch payload and bounded models after the native preview.
    ///
    /// The native preview and all hostile ancillary slots were already prepaid
    /// before receive. This named stage reserves the actual announced payload
    /// and the sole Broker trust/Protocol model bound on the SAME original
    /// ledger before the shared receiver allocates or decodes that payload.
    ///
    /// # Errors
    /// Retains arithmetic or ledger refusal and closes this same flight. The
    /// caller must retain/refuse its actual native preview and attempt the
    /// already armed independent post even after this stage refuses.
    pub fn require_launch_model_receiving_v2(
        &mut self,
        authority: &BrokerAuthority,
        actual_extent: usize,
    ) -> Result<(), StorageReceivingClosedV1> {
        let bytes = authority.storage_host_launch_export_receiving_bytes_v2(actual_extent)
            .and_then(|bytes| bytes.checked_add(actual_extent));
        self.require_model_bytes_once_v2(bytes)
    }

    fn require_model_bytes_once_v2(&mut self, bytes: Option<usize>) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        let scope = &mut receiving.root_launch_export;
        if !scope.is_current_v2() || scope.model_shape.is_some() {
            scope.first.get_or_insert(RootExportFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        scope.model_shape = Some((|| {
            let original = scope.shape.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(StorageReceivingClosedV1)?;
            let additional = u64::try_from(bytes.ok_or(StorageReceivingClosedV1)?)
                .map_err(|_| StorageReceivingClosedV1)?;
            let memory = original.get(D::MemoryBytes).checked_add(additional)
                .ok_or(StorageReceivingClosedV1)?;
            Ok(original.with(D::MemoryBytes, memory))
        })());
        let Some(required) = scope.model_shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            scope.first.get_or_insert(RootExportFailure::ModelShape);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        scope.model_growth = Some(complete_bound_delta_v1(
            scope.capacity, without_operation_traffic_v1(required),
        ));
        let Some(Ok((capacity, delta))) = scope.model_growth.as_ref().copied() else {
            scope.first.get_or_insert(RootExportFailure::ModelGrowth);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        scope.model_reservation = Some(receiving.ledger.reserve(delta).map_err(|_| StorageReceivingClosedV1));
        if !matches!(scope.model_reservation, Some(Ok(()))) {
            scope.first.get_or_insert(RootExportFailure::ModelReservation);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        scope.capacity = capacity;
        Ok(())
    }

    /// Pays one reached guest-root readback delta on this verified export.
    ///
    /// The actual signed Host original is already associated. The upper fixed
    /// reader derives only additional retained model/native/name planes; this
    /// method creates neither a new export, grant nor financial account.
    ///
    /// # Errors
    /// Refuses a foreign State, missing verified binding, post/disposal phase,
    /// unsupported dimensions, arithmetic or the same original ledger's debt.
    pub fn reserve_guest_root_readback_delta_v2(
        &mut self,
        state: &crate::Journal,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        let scope = &mut receiving.root_launch_export;
        let representation = ResourceVector::ZERO
            .with(D::MemoryBytes, demand.get(D::MemoryBytes))
            .with(D::OpenFiles, demand.get(D::OpenFiles))
            .with(D::MetadataEntries, demand.get(D::MetadataEntries));
        if !scope.is_current_v2() || !matches!(scope.binding, Some(Ok(_)))
            || !receiving.startup.state_recovery_ready_v1(state)
            || representation != demand
        {
            scope.first.get_or_insert(RootExportFailure::Closed);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        scope.readback_growth = Some((|| {
            let bound = scope.readback_bound.checked_add(demand)?;
            let (capacity, delta) = complete_bound_delta_v1(scope.readback_capacity, bound)?;
            Ok((bound, capacity, delta))
        })());
        let Some(Ok((bound, capacity, delta))) = scope.readback_growth.as_ref().copied() else {
            scope.first.get_or_insert(RootExportFailure::ReadbackGrowth);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        scope.readback_reservation = Some(receiving.ledger.reserve(delta).map_err(|_| StorageReceivingClosedV1));
        if !matches!(scope.readback_reservation, Some(Ok(()))) {
            scope.first.get_or_insert(RootExportFailure::ReadbackReservation);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        scope.readback_bound = bound;
        scope.readback_capacity = capacity;
        Ok(())
    }

    /// Associates the checked original frame without issuing or reserving work.
    ///
    /// # Errors
    /// Refuses reentry, closed financing, another original boot, or an absent
    /// native startup association. The original crypto comparison remains upper.
    pub fn bind_verified_original_once_v2(
        &mut self,
        verified: &VerifiedStorageHostLaunchExportV2,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        let state = &mut receiving.root_launch_export;
        if !state.is_current_v2() || state.binding.is_some()
            || !matches!(state.model_reservation, Some(Ok(()))) {
            state.first.get_or_insert(RootExportFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let boot = receiving.before.as_ref().and_then(|result| result.as_ref().ok())
            .map(|(_, boot)| *boot);
        state.binding = Some(if boot == Some(verified.host_boot_id_v2()) {
            Ok(verified.request_digest_v2())
        } else {
            Err(StorageReceivingClosedV1)
        });
        if !matches!(state.binding, Some(Ok(_))) {
            state.first.get_or_insert(RootExportFailure::Binding);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Runs the already-prepaid independent post after every entered body result.
    ///
    /// # Errors
    /// Retains an original post refusal or rejects reentry. This path bypasses
    /// fresh health/ledger entry, but cannot create a receiver, worker or retry.
    pub fn finish_native_once_v2(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if self.state().post_entered {
            self.state().first.get_or_insert(RootExportFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.state().post_entered = true;
        let Some(StorageResourceRecipientCustodyV1::Receiving { component, receiving }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        let initial = receiving.before.as_ref().and_then(|result| result.as_ref().ok());
        let state = &mut receiving.root_launch_export;
        let result = if let Some(initial) = initial {
            state.owed_post.observe_prepared_once_v1(
                &receiving.lifetime, &self.receiving.original.custody, component,
                initial, &receiving.containment,
            )
        } else {
            Err(StorageReceivingClosedV1)
        };
        let positive = result.is_ok();
        state.post_result = Some(result);
        state.after = Some(if positive { Ok(()) } else { Err(StorageWorkerOriginCauseV3::Binding) });
        if !positive {
            state.first.get_or_insert(RootExportFailure::After);
            receiving.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Borrows an already selected catalog-worker refusal from this same F.
    ///
    /// This performs no observation, retries no failed profile and lends no
    /// worker. Callers use it only when their actual primary error selected
    /// the existing physical-native refusal marker; later posts cannot replace
    /// an earlier IO or protocol failure through this diagnostic method.
    #[must_use]
    pub fn catalog_worker_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.receiving.root_export_catalog_failure_v2()
    }

    /// Borrows the original financial/native cause without observing again.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.receiving.root_export_receiving_failure_v2()
    }

    /// Checks completed native posts before upper positive carrier disposal.
    ///
    /// The sole private upper owner must first require its actual typed body,
    /// signed/native transfer and all peer/name/clock posts. No bool or callback
    /// supplies those facts here. An upper failure stays resident and never
    /// invokes this positive-disposition continuation.
    ///
    /// # Errors
    /// Refuses any financial/native failure, absent verified original, pending
    /// worker, missing post, or reentry.
    pub fn prepare_positive_disposal_v2(mut self)
        -> Result<StorageRootLaunchExportDisposalV2<'flight, 'original>, StorageReceivingClosedV1>
    {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else { std::process::abort() };
        let worker_idle = receiving.physical_worker.is_between_flights_v2();
        let state = &mut receiving.root_launch_export;
        if state.first.is_some() || state.disposal_entered || !state.post_entered
            || !matches!(state.binding, Some(Ok(_)))
            || !matches!(state.after, Some(Ok(()))) || !worker_idle
            || !state.operation.as_ref().is_some_and(
                ComponentReceivingOwnedOperationV1::is_consumed_current,
            )
        {
            state.first.get_or_insert(RootExportFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        state.disposal_entered = true;
        Ok(StorageRootLaunchExportDisposalV2 { loan: self })
    }
}

impl StorageRootLaunchExportDisposalV2<'_, '_> {
    /// Completes financial arithmetic only after actual upper native disposal.
    pub fn complete_after_disposal_v2(mut self) {
        let state = self.loan.state();
        if state.first.is_some() || !state.disposal_entered {
            std::process::abort();
        }
        let Some(operation) = state.operation.take() else { std::process::abort() };
        operation.complete_after_disposal();
        // The observer owns only its successfully completed sample here. Its
        // permanent reservoir stays charged and the next entry disposes that
        // positive sample through the same existing observer engine.
        state.shape = None;
        state.flight_reservation = None;
        state.model_shape = None;
        state.model_growth = None;
        state.model_reservation = None;
        state.growth = None;
        state.reservation = None;
        state.preparation = None;
        state.before = None;
        state.after = None;
        state.post_result = None;
        state.binding = None;
        state.readback_bound = ResourceVector::ZERO;
        state.readback_growth = None;
        state.readback_reservation = None;
        state.post_entered = false;
        state.disposal_entered = false;
        self.loan.completed = true;
    }
}

impl Drop for StorageRootLaunchExportReceivingLoanV2<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.state().first.get_or_insert(RootExportFailure::Closed);
            let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            else { return };
            receiving.first.get_or_insert(Failure::RootLaunchExport);
        }
    }
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Borrows this same original's root-export financial/native refusal.
    ///
    /// This negative diagnostic remains available after its short root-export
    /// borrower returns. It performs no native work and lends no new flight.
    #[must_use]
    pub fn root_export_receiving_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_ref()
        else { return Some(&StorageReceivingClosedV1); };
        receiving.root_launch_export.failure(&receiving.ledger, &receiving.current)
    }

    /// Borrows the same already-entered root-export catalog worker cause.
    ///
    /// Upper callers select this only for an actual physical-native refusal
    /// marker. It cannot override an earlier protocol, IO or semantic error.
    #[must_use]
    pub fn root_export_catalog_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_ref()
        else { return None; };
        receiving.physical_worker.failure()
            .or_else(|| receiving.ledger.failure().map(|cause| cause as _))
    }

    /// Enters only root-export receiving on the actual serving Storage original.
    ///
    /// The private fixed upper coordinator supplies compiled native-carrier and
    /// complete saved-catalog BYTE bounds plus actual namespace-index entries and
    /// the same compiled native marker/clock descriptor reservoirs. These representation amounts cannot
    /// select a worker, purpose, account, grant or resource capacity. The real
    /// authority supplies its own pinned-policy/model bound, while this method
    /// derives the closed transport, namespace and full-vector operation terms.
    ///
    /// # Errors
    /// Refuses foreign State, another outstanding service/worker, a previous
    /// refusal, arithmetic/budget exhaustion or original native currentness.
    /// Entered primary currentness always consumes its independently armed post
    /// on failure; receiving and verified-body refusal owe that post later.
    pub fn borrow_root_launch_export_receiving_v2<'flight>(
        &'flight mut self,
        state_journal: &crate::Journal,
        upper_carrier_bytes: usize,
        saved_catalog_model_bytes: usize,
        catalog_namespace_entries: usize,
        catalog_native_files: usize,
    ) -> Result<StorageRootLaunchExportReceivingLoanV2<'flight, 'original>, StorageReceivingClosedV1> {
        let original = self.receiving()?;
        if !original.startup.state_recovery_ready_v1(state_journal)
            || !original.lifecycle.is_parked_v1()
            || !original.session_wire.is_between_flights_v1()
            || !original.physical_worker.is_between_flights_v2()
            || !original.root_launch_export.is_idle_v2()
        {
            original.first.get_or_insert(Failure::RootLaunchExport);
            original.root_launch_export.first.get_or_insert(RootExportFailure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let required = root_export_demand_v2(
            state_journal, upper_carrier_bytes, saved_catalog_model_bytes,
            catalog_namespace_entries, catalog_native_files,
        );
        let scope = &mut original.root_launch_export;
        scope.shape = Some(required);
        let Some(required) = scope.shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            scope.first.get_or_insert(RootExportFailure::Shape);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        let reusable = without_operation_traffic_v1(required);
        let traffic = operation_traffic_demand_v1(required);
        scope.growth = Some(complete_bound_delta_v1(scope.capacity, reusable));
        let Some(Ok((capacity, delta))) = scope.growth.as_ref().copied() else {
            scope.first.get_or_insert(RootExportFailure::Growth);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        scope.flight_reservation = Some(delta.checked_add(traffic));
        let Some(Ok(reservation)) = scope.flight_reservation.as_ref().copied() else {
            scope.first.get_or_insert(RootExportFailure::Growth);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        scope.reservation = Some(original.ledger.reserve(reservation).map_err(|_| StorageReceivingClosedV1));
        if !matches!(scope.reservation, Some(Ok(()))) {
            scope.first.get_or_insert(RootExportFailure::Reservation);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        scope.capacity = capacity;
        // The complete current-flight operation sees its already charged
        // traffic alongside reusable capacity; no old flight lends new bytes.
        scope.flight_reservation = Some(capacity.checked_add(traffic));
        let Some(Ok(paid_flight)) = scope.flight_reservation.as_ref().copied() else {
            scope.first.get_or_insert(RootExportFailure::Growth);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        };
        scope.operation = Some(ComponentReceivingOwnedOperationV1::preflight(paid_flight, required));
        let Some(operation) = scope.operation.as_mut() else { std::process::abort() };
        if operation.consume_once().is_err() {
            scope.first.get_or_insert(RootExportFailure::Operation);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        scope.preparation = Some(scope.owed_post.prepare_once_v1(
            &mut original.ledger, &original.lifetime,
        ));
        if !matches!(scope.preparation, Some(Ok(()))) {
            scope.first.get_or_insert(RootExportFailure::Preparation);
            original.first.get_or_insert(Failure::RootLaunchExport);
            return Err(StorageReceivingClosedV1);
        }
        let before = self.original.recheck();
        let positive = before.is_ok();
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else { std::process::abort() };
        receiving.root_launch_export.before = Some(before);
        let mut loan = StorageRootLaunchExportReceivingLoanV2 { receiving: self, completed: false };
        if !positive {
            loan.state().first.get_or_insert(RootExportFailure::Before);
            let _ = loan.finish_native_once_v2();
            return Err(StorageReceivingClosedV1);
        }
        Ok(loan)
    }
}

fn root_export_demand_v2(
    journal: &crate::Journal,
    upper_carrier_bytes: usize,
    saved_catalog_model_bytes: usize,
    catalog_namespace_entries: usize,
    catalog_native_files: usize,
) -> Result<ResourceVector, StorageReceivingClosedV1> {
    use aos_sandbox_protocol::storage_root_export::launch::
        STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2 as FRAME;
    use aos_sandbox_protocol::storage_root_export::STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1 as REPLY;
    use aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1 as Membership;
    let overflow = || StorageReceivingClosedV1;
    let (wire, control_files) = aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket::
        storage_root_export_preview_obligations_v2().ok_or_else(overflow)?;
    let (admission_bytes, admission_files) = aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket::
        retaining_raw_admission_obligations_v2().ok_or_else(overflow)?;
    // Eight actual membership samples: accepted peer; connection/record/
    // connection sandwich; pre-export peer; pre-send peer; independent peer and record-subject posts.
    // The fixed cgroup capture retains six originals. The accepted endpoint,
    // its peer pidfd and returned mount each have one additional owned slot.
    let (membership_bytes, membership_files, _) = Membership::exact_receiving_demand_v1().ok_or_else(overflow)?;
    let membership_bytes = membership_bytes.checked_mul(8).ok_or_else(overflow)?;
    let files = control_files.checked_add(membership_files.checked_mul(8).ok_or_else(overflow)?)
        .and_then(|files| files.checked_add(6 + 1))
        .and_then(|files| files.checked_add(admission_files))
        .and_then(|files| files.checked_add(catalog_native_files)).ok_or_else(overflow)?;
    let bytes = wire.checked_add(admission_bytes)
        .and_then(|bytes| bytes.checked_add(membership_bytes))
        .and_then(|bytes| bytes.checked_add(upper_carrier_bytes))
        .and_then(|bytes| bytes.checked_add(saved_catalog_model_bytes))
        .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<
            StorageRootLaunchExportReceivingLoanV2<'_, '_>,
        >())).ok_or_else(overflow)?;
    // Only actual resident dataset/child/State key-index entries supplied by
    // the sole fixed catalog caller belong here. Encoded bytes, JSON field
    // keys, Rust fields and parser/Vec controls never become namespace fees.
    // The five additional fixed filesystem names are the cgroup hierarchy,
    // system.slice, Host leaf, and the two actual cgroup.procs names.
    let entries = catalog_namespace_entries.checked_add(5).ok_or_else(overflow)?;
    let _same_paid_state = journal;
    let to_u64 = |value| u64::try_from(value).map_err(|_| StorageReceivingClosedV1);
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, to_u64(bytes)?)
        .with(D::MetadataEntries, to_u64(entries)?)
        .with(D::OpenFiles, to_u64(files)?)
        .with(D::NetworkBytes, to_u64(FRAME.checked_add(REPLY).ok_or_else(overflow)?)?)
        .with(D::OutputBytes, to_u64(REPLY)?)
        .with(D::LogBytes, to_u64(FRAME)?)
        .with(D::Mounts, 1)
        .with(D::ConcurrentOperations, 1))
}
