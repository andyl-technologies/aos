//! Owns one finite paid catalog cycle over the four actual ordinary Sessions.
//!
//! The same inventory driver, canonical Source builder and Catalog17 shared
//! flight own all work. This owner remains resident through native Source/C/
//! clock posts; its completion borrower exists only after physical SDK disposal.

use super::*;
use crate::handshake::output_registration_continuation::OutputPreparationClosedV1;
use crate::controller_composition::ControllerCatalogMaintenanceSessionIoOriginalV2;
use aos_sandbox::host_catalog_reconciliation::{
    CatalogMaintenancePublicationStatusV2, StartHostCatalogPublicationOriginalV2,
};
use aos_sandbox::{CatalogMaintenanceOriginalV2, Journal, ResourceReservationErrorV1};
use std::error::Error;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Query(usize),
    GuestRoot,
    Cold,
    Warm,
    Source,
    Catalog,
    Confirmation,
    Disposal,
}

/// Retains every actual query, canonical source and signed Catalog17 flight.
#[doc(hidden)]
#[must_use = "retain the whole cycle until every outer post and physical disposition"]
pub struct ControllerCatalogMaintenanceCycleOriginalV2 {
    queries: [ControllerCatalogMaintenanceInventoryOriginalV2; 4],
    source: StartHostCatalogPublicationOriginalV2,
    catalog: ControllerCatalogMaintenanceSessionIoOriginalV2,
    cold: Option<Result<(), ResourceReservationErrorV1>>,
    warm: Option<Result<(), ResourceReservationErrorV1>>,
    guest_root: Option<Result<bool, ResourceReservationErrorV1>>,
    prepared_guest_root: Option<Result<aos_sandbox::ControllerMaintenanceStorageRequestOriginalV3, ResourceReservationErrorV1>>,
    storage: crate::handshake::output_registration_continuation::MaintenanceStorageSessionIoOriginalV3,
    storage_continuation: Option<Result<(), ResourceReservationErrorV1>>,
    storage_disposal: Option<Result<(), ResourceReservationErrorV1>>,
    publication: Option<
        Result<
            CatalogMaintenancePublicationStatusV2,
            aos_sandbox::host_catalog_reconciliation::StartHostCatalogPublicationClosedV2,
        >,
    >,
    confirmation: Option<
        Result<(), aos_sandbox::host_catalog_reconciliation::StartHostCatalogPublicationClosedV2>,
    >,
    disposal: Option<Result<(), OutputPreparationClosedV1>>,
    first: Option<First>,
    entered: bool,
    is_cold: bool,
}

impl ControllerCatalogMaintenanceCycleOriginalV2 {
    /// Borrows the retained continuation cause without exposing a Session owner.
    #[doc(hidden)]
    #[must_use]
    pub fn continuation_failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::GuestRoot => self.storage.failure_v3(),
            First::Source | First::Confirmation => self.source.failure_v2(),
            First::Catalog | First::Disposal => self.catalog.failure_v2(),
            _ => None,
        }
    }

    /// Constructs only empty inline destinations, without allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queries: std::array::from_fn(|_| Default::default()),
            source: StartHostCatalogPublicationOriginalV2::new(),
            catalog: ControllerCatalogMaintenanceSessionIoOriginalV2::new(),
            cold: None,
            warm: None,
            guest_root: None,
            prepared_guest_root: None,
            storage: crate::handshake::output_registration_continuation::MaintenanceStorageSessionIoOriginalV3::new(),
            storage_continuation: None,
            storage_disposal: None,
            publication: None,
            confirmation: None,
            disposal: None,
            first: None,
            entered: false,
            is_cold: false,
        }
    }

    /// Returns the actual compiled enclosing construction/header shape before entry.
    ///
    /// # Errors
    /// Refuses unrepresentable concrete layout arithmetic.
    #[doc(hidden)]
    pub fn receiving_shape_v2()
    -> Result<aos_sandbox::CatalogMaintenanceSdkShapeDataV2, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(aos_sandbox::CatalogMaintenanceSdkShapeDataV2 {
            inline_and_construction_bytes: bytes,
        })
    }

    /// Runs fresh whole-population comparison and canonical publication under one loan.
    ///
    /// # Errors
    /// Retains any query, same-model/native, Source, append, transport or
    /// confirmation refusal. The caller must always finish the native owner.
    #[doc(hidden)]
    pub fn observe_cold_once_v2<'session>(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        mount: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        storage: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        network: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.run_cycle_once_v2(loan, host, mount, storage, network, true, None)
    }

    /// Runs the genuine no-effect refresh on the same four completed Sessions.
    ///
    /// Real Mount16, Storage18 and Network19 queries feed the same canonical
    /// catalog. The exact Storage result must pass the native no31 selector;
    /// a required or retained effect remains refused with its whole prefix.
    ///
    /// # Errors
    /// Retains query, native/no31, Source, publication or confirmation refusal.
    #[doc(hidden)]
    pub fn observe_refresh_once_v2<'session>(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        mount: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        storage: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        network: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.run_cycle_once_v2(loan, host, mount, storage, network, false, pins)
    }

    /// Runs the shared real refresh queries and opens a required Root31 child.
    ///
    /// `true` means that this exact signed Storage18/current-C selection needs
    /// the actual method31 continuation. It is scheduling DATA, never a grant.
    /// The four opaque completed Session borrowers remain held by the caller.
    ///
    /// # Errors
    /// Retains query, current assignment/reservation, same-F append, Root
    /// native/transport/model or unchanged-cutoff refusal.
    #[doc(hidden)]
    pub fn begin_refresh_once_v3<'session>(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        mount: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        storage: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        network: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    ) -> Result<bool, OutputPreparationClosedV1> {
        self.observe_queries_once_v3(loan, host, mount, storage, network, false)?;
        self.guest_root = Some((|| {
            let (receiving, session) = storage.reborrow_v1();
            let journal = session.operator_reconciliation_inventory_journal_v2(
                aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            ).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if loan
                .reserve_refresh_guest_root_once_v3(receiving, journal, pins)?
                .is_none()
            {
                self.warm = Some(
                    loan.require_refresh_no_guest_root_effect_once_v2(receiving, journal, pins),
                );
                return self
                    .warm
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map(|()| false)
                    .ok_or(ResourceReservationErrorV1::Conflict);
            }
            loan.open_refresh_guest_root_root_once_v3(
                receiving,
                journal,
                self.queries[2]
                    .maintenance_outcome_data_v2()
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
            )?;
            Ok(true)
        })());
        match self.guest_root {
            Some(Ok(required)) => Ok(required),
            _ => {
                self.first.get_or_insert(First::Warm);
                loan.retain_sdk_refusal_once_v2();
                Err(OutputPreparationClosedV1)
            }
        }
    }

    /// Borrows the required Root child's signer beside its actual initial18.
    ///
    /// # Errors
    /// Refuses a no-effect schedule, a failed earlier query, changed completed
    /// Session, substituted signed18, missing Root opening or financial refusal.
    #[doc(hidden)]
    pub fn borrow_refresh_signer_once_v3<'borrow>(
        &'borrow mut self,
        loan: &'borrow mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        storage: &'borrow mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<
        aos_sandbox::ControllerCatalogMaintenanceSigningBorrowV3<'borrow, 'borrow>,
        OutputPreparationClosedV1,
    > {
        if self.first.is_some() || !matches!(self.guest_root, Some(Ok(true))) {
            return Err(OutputPreparationClosedV1);
        }
        let (receiving, session) = storage.reborrow_v1();
        let journal = session.operator_reconciliation_inventory_journal_v2(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        ).map_err(|_| OutputPreparationClosedV1)?;
        loan.begin_refresh_guest_root_signing_once_v3(
            receiving,
            journal,
            self.queries[2]
                .maintenance_outcome_data_v2()
                .ok_or(OutputPreparationClosedV1)?,
            verifier,
        )
        .map_err(|_| OutputPreparationClosedV1)
    }

    /// Runs required31, fresh18, final Root ACK and canonical17 on the same M.
    ///
    /// The worker first completes the concrete fixed signer borrower. This
    /// continuation transfers only its actual completed request, prepays the
    /// fresh snapshot fence, runs the two shared flights on the same Storage
    /// Session and persists the exact fresh terminal through the common reducer.
    /// Root's final current proof/ACK/EOF and posts precede the actual no-effect
    /// inspection of that new physical snapshot and Source/Catalog17 sequence.
    ///
    /// # Errors
    /// Retains every signing, request, shared IO, fresh snapshot, Root finality,
    /// physical proof, Source/catalog or confirmation prefix on refusal.
    #[doc(hidden)]
    pub fn finish_refresh_once_v3(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
        storage: &mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
        pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.first.is_some() || !matches!(self.guest_root, Some(Ok(_))) {
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        }
        if matches!(self.guest_root, Some(Ok(true))) {
            if self.prepared_guest_root.is_some() {
                self.first = Some(First::GuestRoot);
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
            self.prepared_guest_root = Some(loan.take_refresh_guest_root_request_once_v3());
            let prepared = self
                .prepared_guest_root
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(OutputPreparationClosedV1)?;
            if loan
                .begin_refresh_storage_snapshot_once_v3(prepared)
                .is_err()
                || self
                    .storage
                    .observe_once_v3(loan, storage, prepared)
                    .is_err()
            {
                self.first = Some(First::GuestRoot);
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
            self.storage_continuation = Some((|| {
                let (resource, inventory, native) = self
                    .storage
                    .outcomes_v3()
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                loan.persist_refresh_storage_snapshot_once_v3(resource, inventory, native)?;
                let (receiving, session) = storage.reborrow_v1();
                let journal = session.operator_reconciliation_inventory_journal_v2(
                    aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                loan.complete_refresh_guest_root_root_once_v3(
                    receiving,
                    journal,
                    self.queries[2]
                        .maintenance_outcome_data_v2()
                        .ok_or(ResourceReservationErrorV1::Conflict)?,
                    prepared,
                    resource,
                    inventory,
                    native,
                )?;
                self.warm = Some(
                    loan.require_refresh_no_guest_root_effect_once_v2(receiving, journal, pins),
                );
                if !matches!(self.warm, Some(Ok(()))) {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                Ok(())
            })());
            if !matches!(self.storage_continuation, Some(Ok(()))) {
                self.first = Some(First::GuestRoot);
                return Err(OutputPreparationClosedV1);
            }
        }
        self.publish_catalog_once_v3(loan, host)
    }

    fn observe_queries_once_v3<'session>(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        mount: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        storage: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        network: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        cold: bool,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.entered {
            self.first.get_or_insert(First::Entry);
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        }
        self.entered = true;
        self.is_cold = cold;
        let mut sessions = [host, mount, storage, network];
        for index in if cold { 0..4 } else { 1..4 } {
            if self.queries[index]
                .observe_maintenance_once_v2(loan, sessions[index], index)
                .is_err()
            {
                self.first = Some(First::Query(index));
                return Err(OutputPreparationClosedV1);
            }
        }
        Ok(())
    }

    // These finite schedules share one owning source/17/confirmation sequence.
    // The warm arm proves no effect is required from its actual signed model;
    // it cannot adopt an old unpriced exchange or a genuine Start/Root scope.
    fn run_cycle_once_v2<'session>(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        mount: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        storage: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        network: &mut DormantControllerInitialSessionCompletedBorrowV1<'session>,
        cold: bool,
        pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.observe_queries_once_v3(loan, host, mount, storage, network, cold)?;
        let mut sessions = [host, mount, storage, network];
        if cold {
            self.cold = Some((|| {
                let data = |index: usize| -> Result<_, ResourceReservationErrorV1> {
                    Ok((
                        self.queries[index]
                            .maintenance_outcome_data_v2()
                            .ok_or(ResourceReservationErrorV1::Conflict)?,
                        self.queries[index]
                            .maintenance_model_data_v2()
                            .ok_or(ResourceReservationErrorV1::Conflict)?,
                    ))
                };
                loan.observe_cold_population_once_v2(data(0)?, data(1)?, data(2)?, data(3)?)
            })());
            if !matches!(self.cold, Some(Ok(()))) {
                self.first = Some(First::Cold);
                return Err(OutputPreparationClosedV1);
            }
        } else {
            self.warm = Some((|| {
                let (receiving, session) = sessions[2].reborrow_v1();
                let journal = session.operator_reconciliation_inventory_journal_v2(
                    aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
                ).map_err(|_| ResourceReservationErrorV1::Conflict)?;
                loan.require_refresh_no_guest_root_effect_once_v2(receiving, journal, pins)
            })());
            if !matches!(self.warm, Some(Ok(()))) {
                self.first = Some(First::Warm);
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        }
        self.publish_catalog_once_v3(loan, sessions[0])
    }

    fn publish_catalog_once_v3(
        &mut self,
        loan: &mut aos_sandbox::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.publication = Some(loan.prepare_catalog_publication_once_v2(&mut self.source));
        match self.publication {
            Some(Ok(CatalogMaintenancePublicationStatusV2::Unchanged)) => return Ok(()),
            Some(Ok(CatalogMaintenancePublicationStatusV2::PublicationPending)) => {}
            _ => {
                self.first = Some(First::Source);
                return Err(OutputPreparationClosedV1);
            }
        }
        if self
            .catalog
            .publish_once_v2(loan, host, &self.source)
            .is_err()
        {
            self.first = Some(First::Catalog);
            return Err(OutputPreparationClosedV1);
        }
        let Some(outcome) = self.catalog.completed_outcome_v2() else {
            self.first = Some(First::Catalog);
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        };
        self.confirmation =
            Some(loan.confirm_catalog_publication_once_v2(&mut self.source, outcome));
        if !matches!(self.confirmation, Some(Ok(()))) {
            self.first = Some(First::Confirmation);
            return Err(OutputPreparationClosedV1);
        }
        Ok(())
    }

    /// Physically retires successful Catalog17 prefixes after real outer native posts.
    ///
    /// # Errors
    /// Refuses earlier body failure, incomplete source/native posts, changed
    /// Host Session or duplicate disposition. Failed owners remain retained.
    #[doc(hidden)]
    pub fn dispose_after_native_posts_once_v2(
        &mut self,
        native: &mut CatalogMaintenanceOriginalV2,
        controller: &Journal,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.first.is_some() || self.disposal.is_some() {
            self.first.get_or_insert(First::Disposal);
            return Err(OutputPreparationClosedV1);
        }
        if matches!(self.guest_root, Some(Ok(true))) {
            self.storage_disposal = Some((|| {
                let prepared = self.prepared_guest_root.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let (resource, inventory, position) = self.storage.outcomes_v3()
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let token = native.prepare_storage_sdk_disposal_once_v3(controller, prepared, resource, inventory, position)?;
                self.storage.dispose_after_all_posts_v3(token)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)
            })());
            if !matches!(self.storage_disposal, Some(Ok(()))) {
                self.first = Some(First::Disposal);
                return Err(OutputPreparationClosedV1);
            }
        }
        self.disposal = Some(match self.publication {
            Some(Ok(CatalogMaintenancePublicationStatusV2::Unchanged)) => Ok(()),
            Some(Ok(CatalogMaintenancePublicationStatusV2::PublicationPending)) => self
                .catalog
                .dispose_positive_once_v2(native, controller, &self.source, host),
            _ => Err(OutputPreparationClosedV1),
        });
        if !matches!(self.disposal, Some(Ok(()))) {
            self.first = Some(First::Disposal);
            return Err(OutputPreparationClosedV1);
        }
        Ok(())
    }

    /// Disposes through the same Node's private C after every actual native post.
    ///
    /// # Errors
    /// Refuses changed native/source/Session affinity, incomplete posts or reentry.
    #[doc(hidden)]
    pub fn dispose_after_node_posts_once_v2<C, E>(
        &mut self,
        node: &aos_sandbox::NodeController<C, E>,
        native: &mut CatalogMaintenanceOriginalV2,
        host: &mut DormantControllerInitialSessionCompletedBorrowV1<'_>,
    ) -> Result<(), OutputPreparationClosedV1>
    where
        C: aos_sandbox::ActivatedOperationCompiler,
        E: aos_sandbox::SingleNodeEffectExecutor,
    {
        if self.first.is_some() || self.disposal.is_some() {
            self.first.get_or_insert(First::Disposal);
            return Err(OutputPreparationClosedV1);
        }
        if matches!(self.guest_root, Some(Ok(true))) {
            self.storage_disposal = Some((|| {
                let prepared = self.prepared_guest_root.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let (resource, inventory, position) = self.storage.outcomes_v3()
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let token = node.prepare_catalog_maintenance_storage_sdk_disposal_v3(native, prepared, resource, inventory, position)?;
                self.storage.dispose_after_all_posts_v3(token)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)
            })());
            if !matches!(self.storage_disposal, Some(Ok(()))) {
                self.first = Some(First::Disposal);
                return Err(OutputPreparationClosedV1);
            }
        }
        self.disposal = Some(match self.publication {
            Some(Ok(CatalogMaintenancePublicationStatusV2::Unchanged)) => Ok(()),
            Some(Ok(CatalogMaintenancePublicationStatusV2::PublicationPending)) => self
                .catalog
                .dispose_positive_with_node_once_v2(node, native, &self.source, host),
            _ => Err(OutputPreparationClosedV1),
        });
        if !matches!(self.disposal, Some(Ok(()))) {
            self.first = Some(First::Disposal);
            return Err(OutputPreparationClosedV1);
        }
        Ok(())
    }

    /// Borrows actual SDK/native cold completion through the Node's same C.
    ///
    /// # Errors
    /// Refuses any incomplete query, Source, native post or physical disposal.
    #[doc(hidden)]
    pub fn completed_cold_with_node_v2<'completed, C, E>(
        &'completed self,
        node: &aos_sandbox::NodeController<C, E>,
        native: &'completed CatalogMaintenanceOriginalV2,
    ) -> Result<ControllerCatalogMaintenanceColdCompletedV2<'completed>, ResourceReservationErrorV1>
    where
        C: aos_sandbox::ActivatedOperationCompiler,
        E: aos_sandbox::SingleNodeEffectExecutor,
    {
        if !self.is_cold
            || self.first.is_some()
            || !matches!(self.cold, Some(Ok(())))
            || !matches!(self.disposal, Some(Ok(())))
            || self
                .queries
                .iter()
                .any(|query| query.maintenance_model_data_v2().is_none())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = node.completed_catalog_maintenance_cold_native_v2(native, &self.source)?;
        Ok(ControllerCatalogMaintenanceColdCompletedV2 {
            _sdk: self,
            _native: native,
        })
    }

    /// Borrows genuine completed cold custody after all native and SDK dispositions.
    ///
    /// # Errors
    /// Refuses missing actual signed query/models, canonical publication,
    /// physical disposal or the new maintenance's independent native posts.
    #[doc(hidden)]
    pub fn completed_cold_v2<'completed>(
        &'completed self,
        native: &'completed CatalogMaintenanceOriginalV2,
        controller: &Journal,
    ) -> Result<ControllerCatalogMaintenanceColdCompletedV2<'completed>, ResourceReservationErrorV1>
    {
        if !self.is_cold
            || self.first.is_some()
            || !matches!(self.cold, Some(Ok(())))
            || !matches!(self.disposal, Some(Ok(())))
            || self
                .queries
                .iter()
                .any(|query| query.maintenance_model_data_v2().is_none())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = native.completed_cold_native_v2(controller, &self.source)?;
        Ok(ControllerCatalogMaintenanceColdCompletedV2 {
            _sdk: self,
            _native: native,
        })
    }

    /// Borrows actual refresh completion through the Node's same C.
    ///
    /// # Errors
    /// Refuses cold mode, unfinished31, incomplete signed models, canonical
    /// source, any independent post or unfinished physical disposal.
    #[doc(hidden)]
    pub fn completed_refresh_with_node_v2<'completed, C, E>(
        &'completed self,
        node: &aos_sandbox::NodeController<C, E>,
        native: &'completed CatalogMaintenanceOriginalV2,
    ) -> Result<ControllerCatalogMaintenanceRefreshCompletedV2<'completed>, ResourceReservationErrorV1>
    where
        C: aos_sandbox::ActivatedOperationCompiler,
        E: aos_sandbox::SingleNodeEffectExecutor,
    {
        if !self.entered || self.is_cold || self.first.is_some()
            || !matches!(self.warm, Some(Ok(())))
            || !matches!(self.disposal, Some(Ok(())))
            || (matches!(self.guest_root, Some(Ok(true))) && !matches!(self.storage_disposal, Some(Ok(()))))
            || self.queries[1..].iter().any(|query| query.maintenance_model_data_v2().is_none())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = node.completed_catalog_maintenance_refresh_native_v2(native, &self.source)?;
        Ok(ControllerCatalogMaintenanceRefreshCompletedV2 { _sdk: self, _native: native })
    }

    /// Retires the complete positive refresh after its actual all-post join.
    ///
    /// The same B keeps all highwaters and spent traffic. The returned receipt
    /// is historical status and carries neither cold completion nor31 authority.
    ///
    /// # Errors
    /// Returns both whole owners on any completion/status refusal. Failed
    /// prefixes are never dropped, replaced, rearmed or charged to another B.
    #[doc(hidden)]
    pub fn retire_completed_refresh_with_node_v2<C, E>(
        self,
        node: &aos_sandbox::NodeController<C, E>,
        native: CatalogMaintenanceOriginalV2,
    ) -> Result<ControllerCatalogMaintenanceRefreshReceiptV2, (Self, CatalogMaintenanceOriginalV2)>
    where
        C: aos_sandbox::ActivatedOperationCompiler,
        E: aos_sandbox::SingleNodeEffectExecutor,
    {
        if self.completed_refresh_with_node_v2(node, &native).is_err() {
            return Err((self, native));
        }
        let Some((generation, digest)) = self.completed_catalog_status_data_v2() else {
            return Err((self, native));
        };
        drop(self);
        drop(native);
        Ok(ControllerCatalogMaintenanceRefreshReceiptV2 { generation, digest })
    }

    /// Borrows canonical completed catalog coordinates as historical DATA.
    #[must_use]
    pub fn completed_catalog_status_data_v2(
        &self,
    ) -> Option<(u64, aos_sandbox_core::ObjectDigest)> {
        if self.first.is_some() || !matches!(self.disposal, Some(Ok(()))) {
            return None;
        }
        self.source.completed_maintenance_catalog_status_data_v2()
    }

    /// Physically retires the complete positive cold SDK/native owner graph.
    ///
    /// The actual all-post/native/query comparison precedes these moves. The
    /// nonclone receipt is constructed only after the canonical Source sealer,
    /// query/model owners, all samplers and enclosing native original drop.
    /// Financial highwater and spent traffic remain on the same B.
    ///
    /// # Errors
    /// Returns both whole owning prefixes if completion or status comparison
    /// refuses. No failed owner is dropped or replaced.
    #[doc(hidden)]
    pub fn retire_completed_cold_with_node_v2<C, E>(
        self,
        node: &aos_sandbox::NodeController<C, E>,
        native: CatalogMaintenanceOriginalV2,
    ) -> Result<ControllerCatalogMaintenanceColdReceiptV2, (Self, CatalogMaintenanceOriginalV2)>
    where
        C: aos_sandbox::ActivatedOperationCompiler,
        E: aos_sandbox::SingleNodeEffectExecutor,
    {
        if self.completed_cold_with_node_v2(node, &native).is_err() {
            return Err((self, native));
        }
        let Some((generation, digest)) = self.completed_catalog_status_data_v2() else {
            return Err((self, native));
        };
        drop(self);
        drop(native);
        Ok(ControllerCatalogMaintenanceColdReceiptV2 { generation, digest })
    }

    /// Borrows only this cycle's first actual SDK/source failure.
    #[must_use]
    pub fn failure_v2<'cause>(
        &'cause self,
        sessions: [&'cause DormantAuthenticatedBrokerSessionV1; 4],
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            First::Entry | First::Cold | First::Warm =>
                Some(&OutputPreparationClosedV1 as &(dyn Error + 'static)),
            First::Query(index) => self.queries[index].failure_v1(sessions[index]),
            First::GuestRoot => self.storage.failure_v3(),
            First::Source | First::Confirmation => self.source.failure_v2(),
            First::Catalog => self.catalog.failure_v2(),
            First::Disposal => self.storage_disposal.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)).or_else(|| self.catalog.failure_v2()),
        }
        .or(Some(&OutputPreparationClosedV1))
    }
}

impl Default for ControllerCatalogMaintenanceCycleOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps both actual SDK custody and genuine new-B native cold completion borrowed.
///
/// It has no public constructor, replacement deadline, effect permission or
/// Boolean adoption port. Dropping it releases only the comparison borrow.
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceColdCompletedV2<'completed> {
    _sdk: &'completed ControllerCatalogMaintenanceCycleOriginalV2,
    _native: aos_sandbox::CatalogMaintenanceColdCompletedNativeBorrowV2<'completed>,
}

/// Retains the actual completed-cold result after the whole positive graph retired.
///
/// No public constructor, clone, lease, account or effect permission is exposed.
/// It is historical completion of the same worker's first cold cycle, not a
/// replacement for any later current maintenance or authorized effect interval.
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceColdReceiptV2 {
    generation: u64,
    digest: aos_sandbox_core::ObjectDigest,
}

/// Keeps the SDK and actual refresh native completion continuously borrowed.
///
/// Its private construction proves this cycle's comparisons and disposal;
/// it cannot replace the original cold receipt or authorize another effect.
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceRefreshCompletedV2<'completed> {
    _sdk: &'completed ControllerCatalogMaintenanceCycleOriginalV2,
    _native: aos_sandbox::CatalogMaintenanceRefreshCompletedNativeBorrowV2<'completed>,
}

/// Retains refresh status only after the whole positive SDK/native graph dropped.
///
/// No public constructor, clone, account, deadline or effect grant is exposed.
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceRefreshReceiptV2 {
    generation: u64,
    digest: aos_sandbox_core::ObjectDigest,
}

impl ControllerCatalogMaintenanceRefreshReceiptV2 {
    /// Borrows canonical catalog coordinates as historical comparison DATA.
    #[must_use]
    pub fn catalog_status_data_v2(&self) -> (u64, aos_sandbox_core::ObjectDigest) {
        (self.generation, self.digest)
    }
}

impl ControllerCatalogMaintenanceColdReceiptV2 {
    /// Borrows the canonical catalog coordinates from this actual completion.
    #[must_use]
    pub fn catalog_status_data_v2(&self) -> (u64, aos_sandbox_core::ObjectDigest) {
        (self.generation, self.digest)
    }
}
