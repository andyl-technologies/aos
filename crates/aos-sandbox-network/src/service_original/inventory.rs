//! Retains the complete fresh Network19 census under its own genuine interval.
//!
//! A native absence companion requires every protected history, held writer,
//! current root, worker population, descriptor store and paired-clock bookend.
//! Ordinary inventories continue through the same catalog encoder without it.

use super::callsite::NetworkServiceMethodV4;
use super::inventory_history::HistoryOriginal;
use super::*;
use crate::namespace_catalog::{NetworkNamespaceCatalogError, NetworkPinObservationOriginalV4,
    NetworkPinRootAbsenceOriginalV2};
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use crate::journal::{JournalError, FixedServiceInventoryJournalCurrentnessOriginalV2 as Writer};
use aos_sandbox_broker::receiving::{NetworkServiceReceivingLoanV4,
    FixedServiceInventoryFdStoreEmptyOriginalV2 as FdStore,
    NetworkWorkerInventoryObservationOriginalV4 as Workers};
use aos_sandbox_protocol::{ProtocolValidationError,
    fixed_service_inventory_absence::FixedServiceInventoryAbsenceDataV2 as Absence,
    authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1};
use aos_systemd::fd_store::NetworkFdStoreFailureViewV4;

#[derive(Debug, thiserror::Error)]
enum GeometryError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[derive(Clone, Copy)]
enum Failure {
    Order, Binding, Geometry, Funding, Writer(usize), History(usize), Workers,
    FdStore, RootBefore, RootAfter, Population, Census, Bound,
}

/// Retains all protected/native observations and the response through owed posts.
///
/// Construction is inert. The real service callsite pays each complete supplier
/// before its first growth or native entry. Failed prefixes remain owned until
/// the enclosing Session and F intervals have independently finished.
#[must_use = "retain all inventory originals through the enclosing Session/F posts"]
pub struct NetworkServiceInventoryOriginalV4 {
    pins: Vec<NetworkPinObservationOriginalV4>,
    empty_roots: [NetworkPinRootAbsenceOriginalV2; 2],
    writers: [Writer; 4],
    writer_before: [Option<std::result::Result<(), JournalError>>; 4],
    writer_after: [Option<std::result::Result<(), JournalError>>; 4],
    histories: [HistoryOriginal; 2],
    fd_store: FdStore,
    workers: Workers,
    worker_prepare: Option<std::result::Result<(), Closed>>,
    worker_before: Option<std::result::Result<(), Closed>>,
    worker_after: Option<std::result::Result<(), Closed>>,
    fd_before: Option<std::result::Result<(), Closed>>,
    fd_after: Option<std::result::Result<(), Closed>>,
    clock_before: Option<std::result::Result<aos_sandbox_core::RawPairedClockSample, Closed>>,
    clock_after: Option<std::result::Result<aos_sandbox_core::RawPairedClockSample, Closed>>,
    population: Option<std::result::Result<bool, crate::NetworkNamespaceStoreError>>,
    companion: Option<std::result::Result<Absence, ProtocolValidationError>>,
    geometry: Option<std::result::Result<ResourceVector, GeometryError>>,
    funding: Option<std::result::Result<(), Closed>>,
    response: Option<std::result::Result<Vec<u8>, NetworkNamespaceCatalogError>>,
    first: Option<Failure>,
    original_selected: bool,
    entered: bool,
    identity: Option<([u8; 16], [u8; 32])>,
}

impl NetworkServiceInventoryOriginalV4 {
    /// Creates inert destinations without touching a catalog or native source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pins: Vec::new(), empty_roots: std::array::from_fn(|_| Default::default()),
            writers: std::array::from_fn(|_| Default::default()),
            writer_before: std::array::from_fn(|_| None),
            writer_after: std::array::from_fn(|_| None),
            histories: std::array::from_fn(|_| Default::default()),
            fd_store: Default::default(), workers: Default::default(),
            worker_prepare: None, worker_before: None, worker_after: None,
            fd_before: None, fd_after: None, clock_before: None, clock_after: None,
            population: None, companion: None, geometry: None, funding: None,
            response: None, first: None, original_selected: false, entered: false, identity: None,
        }
    }

    /// Physically retires only a successful census after its actual F posts.
    ///
    /// # Errors
    /// Refuses a failed body, another request or unfinished native interval.
    pub fn dispose_completed_inventory_once_v5(&mut self,
        loan: &NetworkServiceReceivingLoanV4<'_>, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        loan.require_completed_inventory_interval_v5(19).map_err(|_| NetworkServiceClosedV4)?;
        if !self.entered || self.first.is_some()
            || self.identity != Some((request.request_id(), request.signed_request_digest()))
            || request.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
            || !matches!(self.response, Some(Ok(_))) {
            return Err(NetworkServiceClosedV4);
        }
        // Every native after and response was positive. Drop actual physical
        // census owners before another F interval; accepted charges persist.
        drop(std::mem::replace(self, Self::new()));
        Ok(())
    }

    fn select_fd_store(&mut self) {
        if self.first.is_none() {
            self.original_selected = self.fd_store.original_failure_selected_v2();
            self.first = Some(Failure::FdStore);
        }
    }

    fn select_workers(&mut self) {
        if self.first.is_none() {
            self.original_selected = self.workers.original_failure_selected_v4();
            self.first = Some(Failure::Workers);
        }
    }

    /// Reports whether the first refusing frontier belongs to the genuine loan.
    #[must_use]
    pub const fn original_failure_selected_v4(&self) -> bool { self.original_selected }

    /// Borrows the selected SDK archive guard without changing attribution.
    #[must_use]
    pub fn fd_store_failure_view_v2(&self) -> Option<NetworkFdStoreFailureViewV4<'_>> {
        match self.first? {
            Failure::FdStore => self.fd_store.failure_view_v2(),
            Failure::Workers => self.workers.failure_view_v4(),
            _ => None,
        }
    }

    /// Borrows the exact reached geometry, protected history or native cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Writer(index) => self.writers[index].failure_v2(),
            Failure::History(index) => self.histories[index].failure(),
            Failure::FdStore => self.fd_store.failure_v2(),
            Failure::Workers => self.workers.failure_v4(),
            Failure::RootBefore => self.empty_roots[0].failure_v2(),
            Failure::RootAfter => self.empty_roots[1].failure_v2(),
            Failure::Population => self.population.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.companion.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or(Some(&NetworkServiceClosedV4)),
            Failure::Census => self.pins.iter().find_map(NetworkPinObservationOriginalV4::failure)
                .or_else(|| self.response.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Failure::Order | Failure::Binding | Failure::Funding | Failure::Bound => Some(&NetworkServiceClosedV4),
        }
    }
}

impl Default for NetworkServiceInventoryOriginalV4 {
    fn default() -> Self { Self::new() }
}

impl NetworkServiceDomainCallsiteV4<'_> {
    /// Observes the same service's whole protected and native Network19 state.
    ///
    /// # Errors
    /// Retains purpose, request, funding, currentness, complete history, worker,
    /// descriptor-store, root, horizon and authenticated response-bound refusal.
    pub fn inventory_once_v4<'held>(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &'held mut NetworkServiceInventoryOriginalV4,
    ) -> Result<NetworkServiceObservationV4<'held>> {
        if original.entered {
            original.first.get_or_insert(Failure::Order);
            return Err(NetworkServiceClosedV4);
        }
        original.entered = true;
        original.identity = Some((request.request_id(), request.signed_request_digest()));
        if !matches!(self.method, NetworkServiceMethodV4::Inventory)
            || request.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES {
            original.first = Some(Failure::Binding);
            return Err(NetworkServiceClosedV4);
        }
        if loan.require_network_inventory_current_v4().is_err() {
            original.original_selected = true;
            original.first = Some(Failure::Funding);
            return Err(NetworkServiceClosedV4);
        }
        original.geometry = Some((|| {
            let header = std::mem::size_of::<NetworkServiceInventoryOriginalV4>()
                .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            Ok(self.namespaces.inventory_receiving_demand_v4()?
                .checked_add(self.inventory_history_receiving_demand_v2()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, header))?)
        })());
        let Some(Ok(demand)) = original.geometry.as_ref() else {
            original.first = Some(Failure::Geometry);
            return Err(NetworkServiceClosedV4);
        };
        original.funding = Some(loan.require_additional_representation_v4(*demand));
        if !matches!(original.funding, Some(Ok(()))) {
            original.original_selected = true;
            original.first = Some(Failure::Funding);
            return Err(NetworkServiceClosedV4);
        }

        // Each actual captured writer owns its independently prepaid post even
        // when another writer or a later domain/source observation refuses.
        self.inventory_native_before_v2(&mut original.writers, &mut original.writer_before);
        for (index, result) in original.writer_before.iter().enumerate() {
            if !matches!(result, Some(Ok(()))) {
                original.first.get_or_insert(Failure::Writer(index));
            }
        }
        let empty_history = if original.first.is_none() {
            match original.histories[0].observe_once(self) {
                Ok(empty) => empty,
                Err(_) => { original.first = Some(Failure::History(0)); false }
            }
        } else { false };
        let empty_root = self.namespaces.has_no_namespace_history_v2();

        if empty_history && original.first.is_none() {
            // This complete worker invoice precedes FDStore runtime creation,
            // any listing and every native aggregate forest observation.
            original.worker_prepare = Some(loan.prepare_network_worker_inventory_once_v4(&mut original.workers));
            if !matches!(original.worker_prepare, Some(Ok(()))) { original.select_workers(); }
            if original.first.is_none() {
                original.fd_before = Some(loan.observe_inventory_fd_store_empty_before_v2(&mut original.fd_store));
                if !matches!(original.fd_before, Some(Ok(()))) { original.select_fd_store(); }
            }
            if original.first.is_none() {
                original.clock_before = Some(loan.observe_inventory_population_clock_before_v2(&mut original.fd_store));
                if !matches!(original.clock_before, Some(Ok(_))) { original.select_fd_store(); }
            }
            if original.first.is_none() {
                original.worker_before = Some(loan.observe_network_worker_inventory_before_v4(
                    &mut original.workers, &original.fd_store));
                if !matches!(original.worker_before, Some(Ok(()))) { original.select_workers(); }
            }
        }
        if empty_root && original.first.is_none()
            && self.namespaces.observe_empty_pin_root_v2(&mut original.empty_roots[0]).is_err() {
            original.first = Some(Failure::RootBefore);
        }

        // Ordinary pin validation stays inside the same native writer/root
        // interval. A certified empty response has no per-resource native pins;
        // it is encoded only after every independently owed post succeeds.
        if !empty_history && original.first.is_none() {
            original.response = Some(self.namespaces.inventory_resources_retaining_v4(&mut original.pins));
            if !matches!(original.response, Some(Ok(_))) {
                original.first = Some(Failure::Census);
            }
        }

        // Read every private history again inside the population interval. A
        // retained old row simply omits the companion; an unhealthy fold fails.
        if original.first.is_none() {
            match original.histories[1].observe_once(self) {
                Ok(after_empty) if after_empty == empty_history => {}
                Ok(_) => { original.first = Some(Failure::Population); }
                Err(_) => { original.first = Some(Failure::History(1)); }
            }
        }
        if empty_root && self.namespaces.observe_empty_pin_root_v2(&mut original.empty_roots[1]).is_err() {
            original.first.get_or_insert(Failure::RootAfter);
        }
        self.inventory_native_after_owed_v2(&mut original.writers, &mut original.writer_after);
        for (index, result) in original.writer_after.iter().enumerate() {
            if !matches!(result, Some(Ok(()))) {
                original.first.get_or_insert(Failure::Writer(index));
            }
        }
        if empty_history {
            original.worker_after = Some(loan.observe_network_worker_inventory_after_owed_v4(&mut original.workers));
            if !matches!(original.worker_after, Some(Ok(()))) { original.select_workers(); }
            original.fd_after = Some(loan.observe_inventory_fd_store_empty_after_owed_v2(&mut original.fd_store));
            if !matches!(original.fd_after, Some(Ok(()))) { original.select_fd_store(); }
            if original.first.is_none() {
                if let Some(capacity) = original.fd_store.maximum_entries_data_v2() {
                    original.population = Some(self.namespace_store.inventory_is_empty_at_capacity_v2(capacity));
                }
                if !matches!(original.population, Some(Ok(true)))
                    || !self.prepare_executor.inventory_local_custody_clear_v2()
                    || !self.observation_executor.inventory_local_custody_clear_v2()
                    || original.workers.require_complete_v4().is_err()
                    || original.writers.iter().any(|writer| writer.require_complete_v2().is_err()) {
                    original.first = Some(Failure::Population);
                }
            }
            // The second real paired destination is independent of every body
            // result above. It is not a repeat of a poisoned primary sampler.
            original.clock_after = Some(loan.observe_inventory_population_clock_after_owed_v2(&mut original.fd_store));
            if !matches!(original.clock_after, Some(Ok(_))) { original.select_fd_store(); }
        }
        if original.first.is_some() { return Err(NetworkServiceClosedV4); }

        if empty_history {
            original.companion = Some(self.complete_absence_data_v2(request, original));
            if !matches!(original.companion, Some(Ok(_))) {
                original.first = Some(Failure::Population);
                return Err(NetworkServiceClosedV4);
            }
        }
        if let Some(Ok(absence)) = original.companion.as_ref() {
            original.response = Some(self.namespaces.inventory_resources_with_absence_retaining_v2(
                &mut original.pins, absence));
        }
        let Some(Ok(body)) = original.response.as_ref() else {
            original.first = Some(Failure::Census);
            return Err(NetworkServiceClosedV4);
        };
        if body.len() > request.maximum_response_bytes() as usize {
            original.first = Some(Failure::Bound);
            return Err(NetworkServiceClosedV4);
        }
        Ok(NetworkServiceObservationV4 { body, request_id: request.request_id(), method: 19,
            signed_request_digest: request.signed_request_digest() })
    }

    fn complete_absence_data_v2(&self, request: &AuthenticatedBrokerMethodRequestV1,
        original: &NetworkServiceInventoryOriginalV4,
    ) -> std::result::Result<Absence, ProtocolValidationError> {
        let invalid = || ProtocolValidationError::InvalidField("complete Network native absence");
        let (before, after) = original.fd_store.population_interval_data_v2().ok_or_else(invalid)?;
        let invocation = original.fd_store.recipient_invocation_data_v2().ok_or_else(invalid)?;
        let root = original.empty_roots[0].complete_identity_v2().ok_or_else(invalid)?;
        let (boot, catalog_invocation) = self.namespaces.inventory_native_identity_v2();
        if before.host_boot_id() != boot || after.host_boot_id() != boot
            || invocation != catalog_invocation
            || original.empty_roots[1].complete_identity_v2() != Some(root) {
            return Err(invalid());
        }
        Absence::from_network_native_data_v2(request.request_id(), boot, invocation,
            before.boottime_nanoseconds(), after.boottime_nanoseconds(), root)
    }
}
