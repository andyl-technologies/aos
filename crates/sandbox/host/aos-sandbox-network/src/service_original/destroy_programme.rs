//! Joins signed Destroy9 to the sole P/O programme and durable retirement.
//!
//! A prospective protobuf body is only prepaid response DATA. The actual
//! observation requires the same signed source, retained target OFD, complete
//! P/O originals, fresh pin absence, whole FDStore removal and both guarded
//! canonical commits. Failed prefixes remain owned through enclosing posts.

use super::callsite::{NetworkServiceMethodV4, NetworkServiceObservationV4};
use super::destroy_selected::NetworkServiceDestroyOriginalV4;
use super::receiving::{NetworkPrepareEffectReceivingV4, NetworkReceivingOriginalV4};
use super::worker_programme::NetworkServiceWorkersOriginalV2;
use super::worker_programme::response::PreparationResponseOriginalV2;
use super::*;
use crate::namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceLifecycleObservationV1,
    NetworkNamespaceLifecycleTransitionV1, NetworkNamespaceObservedStateKindV1,
    NetworkPinObservationOriginalV4,
};
use crate::namespace_store::{
    NetworkNamespaceStoreError, NetworkNamespaceStoreMutationOriginalV4, NetworkNamespaceStoreName,
    NetworkNamespaceStoreOutcome, NetworkNamespaceStoreRefusalV4,
};
use aos_sandbox_broker::receiving::NetworkServiceReceivingLoanV4;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy)]
enum Failure {
    Order,
    Entry,
    Geometry,
    Sources,
    Target,
    StoreIdentity,
    Response,
    Workers,
    Pin,
    Store,
    Transition,
    Commit,
}

/// Retains one actual signed Destroy's complete physical and durable suffix.
///
/// Construction is inert. No identity, prospective response, supplied proof,
/// scalar fee or caller callback can replace the private completed owners.
#[must_use]
pub struct NetworkServiceDestroyProgrammeOriginalV2 {
    entered: bool,
    execution_entered: bool,
    prepared: bool,
    first: Option<Failure>,
    binding: Option<([u8; 16], [u8; 32])>,
    geometry: Option<std::result::Result<ResourceVector, AccountingError>>,
    entry: Option<std::result::Result<(), Closed>>,
    receiving: NetworkReceivingOriginalV4,
    sources: NetworkServiceDestroyOriginalV4,
    source_result: Option<Result<()>>,
    target: NetworkPinObservationOriginalV4,
    target_result: Option<std::result::Result<(), NetworkNamespaceCatalogError>>,
    store_name: Option<std::result::Result<NetworkNamespaceStoreName, NetworkNamespaceStoreError>>,
    store_identity: Option<
        std::result::Result<
            Option<aos_sandbox_linux::pidfd::NamespaceIdentity>,
            NetworkNamespaceStoreError,
        >,
    >,
    response: PreparationResponseOriginalV2,
    response_result: Option<Result<()>>,
    workers: NetworkServiceWorkersOriginalV2,
    worker_result: Option<Result<()>>,
    pin_before_store: NetworkPinObservationOriginalV4,
    pin_result: Option<std::result::Result<(), NetworkNamespaceCatalogError>>,
    store: NetworkNamespaceStoreMutationOriginalV4,
    store_result:
        Option<std::result::Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreRefusalV4>>,
    transition: Option<
        std::result::Result<NetworkNamespaceLifecycleTransitionV1, NetworkNamespaceCatalogError>,
    >,
    pin_catalog: NetworkPinObservationOriginalV4,
    committed: Option<
        std::result::Result<crate::CommittedNetworkLifecycleResultV1, crate::NetworkBrokerError>,
    >,
    original_selected: bool,
}

impl NetworkServiceDestroyProgrammeOriginalV2 {
    /// Creates empty destinations without native work or permission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false,
            execution_entered: false,
            prepared: false,
            first: None,
            binding: None,
            geometry: None,
            entry: None,
            receiving: NetworkReceivingOriginalV4::new(),
            sources: NetworkServiceDestroyOriginalV4::new(),
            source_result: None,
            target: NetworkPinObservationOriginalV4::new(),
            target_result: None,
            store_name: None,
            store_identity: None,
            response: PreparationResponseOriginalV2::new(),
            response_result: None,
            workers: NetworkServiceWorkersOriginalV2::new(),
            worker_result: None,
            pin_before_store: NetworkPinObservationOriginalV4::new(),
            pin_result: None,
            store: NetworkNamespaceStoreMutationOriginalV4::new(),
            store_result: None,
            transition: None,
            pin_catalog: NetworkPinObservationOriginalV4::new(),
            committed: None,
            original_selected: false,
        }
    }

    /// Borrows unsigned canonical DATA solely for before-P SDK pricing.
    ///
    /// # Errors
    /// Refuses incomplete or failed preparation; this never supplies a result.
    pub fn prospective_response_body_v2(&self) -> Result<&[u8]> {
        if !self.prepared || self.first.is_some() {
            return Err(NetworkServiceClosedV4);
        }
        self.response
            .prospective_body_data_v2()
            .ok_or(NetworkServiceClosedV4)
    }

    /// Identifies an actual selected original payer or Source failure.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        match self.first {
            Some(Failure::Entry) => self.original_selected,
            Some(Failure::Geometry | Failure::Commit) => {
                self.receiving.original_failure_selected_v4()
            }
            Some(Failure::Sources) => self.sources.original_failure_selected_v4(),
            Some(Failure::Response) => self.response.original_failure_selected(),
            Some(Failure::Workers) => self.workers.original_failure_selected_v2(),
            Some(Failure::Store) => self.store.original_failure_selected_v4(),
            _ => false,
        }
    }

    /// Borrows the actual retained FDStore diagnostic without erasing custody.
    #[must_use]
    pub fn store_failure_view_v2(&self) -> Option<NetworkNamespaceStoreFailureV4<'_>> {
        if matches!(self.first, Some(Failure::Workers)) {
            self.workers.store_failure_view_v2()
        } else if matches!(self.first, Some(Failure::Store)) {
            self.store.failure_view_v4()
        } else {
            None
        }
    }

    /// Borrows the first native, decoder, State or financial cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(
            slot: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|error| error as _)
        }
        let cause = match self.first? {
            Failure::Order => None,
            Failure::Entry => cause(&self.entry),
            Failure::Geometry => cause(&self.geometry).or_else(|| self.receiving.failure()),
            Failure::Sources => self
                .sources
                .failure()
                .or_else(|| cause(&self.source_result)),
            Failure::Target => self.target.failure().or_else(|| cause(&self.target_result)),
            Failure::StoreIdentity => {
                cause(&self.store_name).or_else(|| cause(&self.store_identity))
            }
            Failure::Response => self
                .response
                .failure()
                .or_else(|| cause(&self.response_result)),
            Failure::Workers => self
                .workers
                .failure()
                .or_else(|| cause(&self.worker_result)),
            Failure::Pin => self
                .pin_before_store
                .failure()
                .or_else(|| cause(&self.pin_result)),
            Failure::Store => cause(&self.store_result),
            Failure::Transition => cause(&self.transition),
            Failure::Commit => self
                .pin_catalog
                .failure()
                .or_else(|| self.receiving.failure())
                .or_else(|| cause(&self.committed)),
        };
        cause.or(Some(&NetworkServiceClosedV4))
    }

    /// Drops only the whole positive suffix after its actual completed interval.
    ///
    /// Every accepted F charge remains retained by the same source ledger.
    ///
    /// # Errors
    /// Refuses unfinished native/Session posts, wrong requests or any failed suffix.
    pub fn dispose_completed_destroy_once_v2(
        &mut self,
        loan: &NetworkServiceReceivingLoanV4<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        loan.require_completed_network_destroy_interval_v5()
            .map_err(|_| NetworkServiceClosedV4)?;
        self.completed_response_v2(request)?;
        drop(std::mem::replace(self, Self::new()));
        Ok(())
    }

    fn completed_response_v2<'held>(
        &'held self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<NetworkServiceObservationV4<'held>> {
        let committed = self
            .committed
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NetworkServiceClosedV4)?;
        if self.first.is_some()
            || !self.execution_entered
            || !self.prepared
            || self.binding != Some((request.request_id(), request.signed_request_digest()))
            || request.method() as u32 != 9
            || committed.request_id() != request.request_id()
            || committed.action() != crate::NetworkNamespaceLifecycleActionV1::Destroy
            || !self
                .response
                .matches_binding_v2(request, committed.network_handle())
        {
            return Err(NetworkServiceClosedV4);
        }
        Ok(NetworkServiceObservationV4 {
            body: self
                .response
                .prospective_body_data_v2()
                .ok_or(NetworkServiceClosedV4)?,
            request_id: request.request_id(),
            method: 9,
            signed_request_digest: request.signed_request_digest(),
        })
    }

    fn close<T>(&mut self, failure: Failure) -> Result<T> {
        self.first.get_or_insert(failure);
        Err(NetworkServiceClosedV4)
    }
}

impl Default for NetworkServiceDestroyProgrammeOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkServiceDomainCallsiteV4<'_> {
    /// Prepares the genuine signed source and held target before SDK prepayment.
    ///
    /// # Errors
    /// Retains original purpose/currentness, geometry, signed source, native pin,
    /// existing Store identity or canonical response preparation refusal.
    pub fn prepare_destroy_programme_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceDestroyProgrammeOriginalV2,
    ) -> Result<()> {
        if original.entered {
            return original.close(Failure::Order);
        }
        original.entered = true;
        original.binding = Some((request.request_id(), request.signed_request_digest()));
        if !matches!(self.method, NetworkServiceMethodV4::Destroy)
            || request.network_destroy_data_v4().is_none()
        {
            original.entry = Some(Err(Closed));
            return original.close(Failure::Entry);
        }
        original.entry = Some(loan.require_network_destroy_current_v4());
        if !matches!(original.entry, Some(Ok(()))) {
            original.original_selected = true;
            return original.close(Failure::Entry);
        }
        original.geometry = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            let bytes = std::mem::size_of::<NetworkServiceDestroyProgrammeOriginalV2>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(NetworkNamespaceStoreName::maximum_bytes_v4()))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(overflow)?;
            // Target, pre-Store absence and catalog absence are distinct native
            // frontiers. Canonical codec/index planes remain charged too.
            let pins = NetworkPinObservationOriginalV4::receiving_demand_v4(3).ok_or(overflow)?;
            ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                .checked_add(pins)?
                .checked_add(crate::lifecycle_state::lifecycle_record_receiving_demand_v4()?)?
                .checked_add(NetworkNamespaceCatalogV1::publication_receiving_demand_v4()?)
        })());
        let demand = original
            .geometry
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied();
        let Some(demand) = demand else {
            return original.close(Failure::Geometry);
        };
        if original
            .receiving
            .admit_additional_v4(loan, Ok(demand))
            .is_err()
        {
            return original.close(Failure::Geometry);
        }
        original.source_result =
            Some(self.destroy_sources_once_v4(request, loan, &mut original.sources));
        if !matches!(original.source_result, Some(Ok(()))) {
            return original.close(Failure::Sources);
        }
        let (dispatch, _) = original
            .sources
            .dispatch_v4()
            .ok_or(NetworkServiceClosedV4)?;
        let identity = dispatch.target_identity();
        original.target_result = Some(
            self.namespaces
                .retain_destroy_target_once_v2(identity, &mut original.target),
        );
        if !matches!(original.target_result, Some(Ok(()))) {
            return original.close(Failure::Target);
        }
        original.store_name = Some(NetworkNamespaceStoreName::from_network_handle(
            identity.network_handle(),
        ));
        let Some(Ok(name)) = original.store_name.as_ref() else {
            return original.close(Failure::StoreIdentity);
        };
        original.store_identity = Some(self.namespace_store.retained_identity(name));
        let expected = aos_sandbox_linux::pidfd::NamespaceIdentity {
            device: identity.namespace_device(),
            inode: identity.namespace_inode(),
        };
        if !matches!(original.store_identity, Some(Ok(Some(observed))) if observed == expected) {
            return original.close(Failure::StoreIdentity);
        }
        original.response_result = Some(original.response.prepare_destroy_once_v2(
            request,
            identity.network_handle(),
            loan,
        ));
        if !matches!(original.response_result, Some(Ok(()))) {
            return original.close(Failure::Response);
        }
        original.prepared = true;
        Ok(())
    }

    /// Executes the sole P/O programme and actual guarded Destroy retirement.
    ///
    /// The SDK caller has already prepaid the prospective canonical response.
    /// The whole P/O and suffix fit runs on the latest same ledger before P.
    ///
    /// # Errors
    /// Retains failure without selecting an observation or dropping its owners.
    pub fn execute_destroy_programme_once_v2<'held>(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &'held mut NetworkServiceDestroyProgrammeOriginalV2,
    ) -> Result<NetworkServiceObservationV4<'held>> {
        let result = self.execute_destroy_programme_inner_v2(request, loan, original);
        if result.is_err() {
            original.first.get_or_insert(Failure::Order);
            return Err(NetworkServiceClosedV4);
        }
        original.completed_response_v2(request)
    }

    fn execute_destroy_programme_inner_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceDestroyProgrammeOriginalV2,
    ) -> Result<()> {
        if original.execution_entered
            || !original.prepared
            || original.first.is_some()
            || original.binding != Some((request.request_id(), request.signed_request_digest()))
            || !matches!(self.method, NetworkServiceMethodV4::Destroy)
        {
            return original.close(Failure::Order);
        }
        original.execution_entered = true;
        let target = original
            .target
            .completed_namespace_v2()
            .ok_or(NetworkServiceClosedV4)?;
        original.worker_result = Some(self.destroy_workers_once_v2(
            request,
            &original.sources,
            target,
            loan,
            &mut original.workers,
        ));
        if !matches!(original.worker_result, Some(Ok(()))) {
            return original.close(Failure::Workers);
        }
        let proof = original
            .workers
            .completed_destroy_observation_v2()
            .ok_or(NetworkServiceClosedV4)?;
        let (dispatch, _) = original
            .sources
            .dispatch_v4()
            .ok_or(NetworkServiceClosedV4)?;
        let identity = dispatch.target_identity();
        original.pin_result = Some(
            self.namespaces
                .observe_destroy_absence_once_v2(identity, &mut original.pin_before_store),
        );
        if !matches!(original.pin_result, Some(Ok(()))) {
            return original.close(Failure::Pin);
        }
        let name = original
            .store_name
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NetworkServiceClosedV4)?;
        original.store_result = Some(self.namespace_store.remove_retaining_once_v2(
            name,
            loan,
            &mut original.store,
        ));
        if !matches!(
            original.store_result,
            Some(Ok(NetworkNamespaceStoreOutcome::Removed))
        ) {
            return original.close(Failure::Store);
        }
        original.transition = Some((|| {
            if proof.request_id() != dispatch.request_id()
                || proof.effect_digest() != dispatch.effect_digest()
                || proof.kernel_plan_digest() != dispatch.kernel_plan().digest()
                || proof.kernel_boot_id() != identity.kernel_boot_id()
                || proof.namespace().device != identity.namespace_device()
                || proof.namespace().inode != identity.namespace_inode()
                || proof.observed_state().kind() != NetworkNamespaceObservedStateKindV1::Absent
            {
                return Err(NetworkNamespaceCatalogError::IdentityConflict);
            }
            let mut digest = Sha256::new();
            digest.update(b"aos.sandbox.network.source-destroyed-custody.v2\0");
            digest.update(dispatch.request_id());
            digest.update(dispatch.effect_digest().as_bytes());
            digest.update(proof.observation_digest().as_bytes());
            digest.update(identity.network_handle());
            digest.update(identity.kernel_boot_id());
            digest.update(identity.namespace_device().to_be_bytes());
            digest.update(identity.namespace_inode().to_be_bytes());
            digest.update(b"same-P-pin-absent+whole-systemd-store-absent\0");
            let observation = NetworkNamespaceLifecycleObservationV1::new(
                dispatch.request_id(),
                dispatch.prior_resource_digest(),
                identity,
                proof.observed_state(),
                ObjectDigest::from_bytes(digest.finalize().into()),
            )?;
            NetworkNamespaceLifecycleTransitionV1::destroy(observation)
        })());
        let Some(transition) = original
            .transition
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return original.close(Failure::Transition);
        };
        let verified = original
            .sources
            .observer_verified_original_v2()
            .ok_or(NetworkServiceClosedV4)?;
        let mut receiving = NetworkPrepareEffectReceivingV4 {
            original: &mut original.receiving,
            loan,
        };
        original.committed = Some(self.coordinator.commit_destroy_transition_guarded_v2(
            dispatch.request_id(),
            dispatch.effect_digest(),
            transition,
            self.namespaces,
            &mut original.pin_catalog,
            &mut receiving,
            &verified.effect,
        ));
        if !matches!(original.committed, Some(Ok(_))) {
            return original.close(Failure::Commit);
        }
        Ok(())
    }
}
