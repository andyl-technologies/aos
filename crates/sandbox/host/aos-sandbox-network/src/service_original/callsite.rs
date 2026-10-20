//! Lends only the real enrolled Network catalogs to their closed operations.

use super::*;
use aos_sandbox_broker::receiving::{
    FixedServiceOperationOriginalV4, NetworkServiceReceivingLoanV4,
};

#[derive(Clone, Copy)]
pub(super) enum NetworkServiceMethodV4 {
    Receiving,
    Inventory,
    Prepare,
    Destroy,
}

/// Names the finite branch selected from the actual authenticated SDK request.
///
/// This scheduling value grants no effect and cannot construct a service loan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkServiceRequestMethodV5 {
    /// Queries complete current Network inventory.
    Inventory,
    /// Prepares the exact admitted Network63 sources and native workers.
    Prepare,
    /// Destroys only the exact signed Network9 target.
    Destroy,
}

/// Borrows a domain response bound to the original authenticated request.
///
/// Session commit, native send and independent Session/F afters remain owed.
/// Only the actual protected service callsite can construct this observation.
pub struct NetworkServiceObservationV4<'held> {
    pub(super) body: &'held [u8],
    pub(super) request_id: [u8; 16],
    pub(super) method: u32,
    pub(super) signed_request_digest: [u8; 32],
}

impl NetworkServiceObservationV4<'_> {
    /// Borrows the exact successful domain response held by its original.
    #[must_use]
    pub const fn body_v4(&self) -> &[u8] {
        self.body
    }

    /// Returns that same authenticated request's identifier.
    #[must_use]
    pub const fn request_id_v4(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the exact closed method that produced the response.
    #[must_use]
    pub const fn method_v4(&self) -> u32 {
        self.method
    }

    /// Returns the same signed request's packet commitment.
    #[must_use]
    pub const fn signed_request_digest_v4(&self) -> [u8; 32] {
        self.signed_request_digest
    }
}

/// Borrows the actual held complete Network namespace catalog.
///
/// Construction remains private to the enrolled service. It exposes no raw
/// Journal, authority, descriptor, financial account or substitute grant.
pub struct NetworkServiceDomainCallsiteV4<'held> {
    pub(super) public_credentials: &'held ProtectedBrokerPublicCredentials,
    pub(super) namespaces: &'held mut NetworkNamespaceCatalogV1,
    pub(super) method: NetworkServiceMethodV4,
    pub(super) coordinator: &'held mut NetworkLifecycleAdmissionCoordinator,
    pub(super) preparations: &'held mut NetworkPreparationCatalogV1,
    pub(super) namespace_store: &'held SystemdNetworkNamespaceStore,
    pub(super) prepare_executor: &'held mut SystemdNetworkPrepareExecutor,
    pub(super) observation_executor: &'held mut SystemdNetworkObservationExecutor,
    pub(super) creation_original: &'held NetworkCreationStateOpeningOriginalV4,
    pub(super) lifecycle_original: &'held NetworkLifecycleOpeningOriginalV4,
    pub(super) preparation_original: &'held NetworkPreparationOpeningOriginalV4,
    pub(super) namespace_original: &'held NetworkNamespaceCatalogOpeningOriginalV4,
}

impl NetworkServiceDomainCallsiteV4<'_> {
    /// Selects a domain branch after the same SDK request consumed receiving.
    ///
    /// # Errors
    /// Refuses reentry, a substituted request or failed original currentness.
    pub fn select_received_request_once_v5(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
    ) -> Result<NetworkServiceRequestMethodV5> {
        if !matches!(self.method, NetworkServiceMethodV4::Receiving) {
            // Reentry must fence the same original rather than leave an
            // earlier selected effect usable after a refused second choice.
            let _ = loan.select_authenticated_network_request_once_v5(request);
            return Err(NetworkServiceClosedV4);
        }
        loan.require_selected_network_request_v5(request).map_err(|_| NetworkServiceClosedV4)?;
        let (method, branch) = match request.method() as u32 {
            19 => (NetworkServiceMethodV4::Inventory, NetworkServiceRequestMethodV5::Inventory),
            63 => (NetworkServiceMethodV4::Prepare, NetworkServiceRequestMethodV5::Prepare),
            9 => (NetworkServiceMethodV4::Destroy, NetworkServiceRequestMethodV5::Destroy),
            _ => return Err(NetworkServiceClosedV4),
        };
        self.method = method;
        Ok(branch)
    }

    /// Borrows the six actual protected public originals from this same service.
    ///
    /// The caller retains its genuine operation loan and performs the existing
    /// per-original native revalidation before any O handoff. This lends no
    /// secret, journal authenticator, replacement credential or signing path.
    pub(crate) fn public_credentials_v2(&self) -> &ProtectedBrokerPublicCredentials {
        self.public_credentials
    }
}

impl NetworkServiceOriginalV4 {
    /// Borrows the real catalogs and F for neutral authenticated receiving.
    ///
    /// The SDK must authenticate and select the same request before any domain
    /// operation. No Inventory loan is converted into effect authority.
    ///
    /// # Errors
    /// Refuses incomplete startup, missing originals, prior debt or geometry.
    pub fn begin_request_receiving_once_v5<'held>(
        &'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(NetworkServiceReceivingLoanV4<'held>, NetworkServiceDomainCallsiteV4<'held>)> {
        self.borrow_domain_once_v4(operation, fixed, NetworkServiceMethodV4::Receiving)
    }

    /// Borrows only Destroy9 on the actual enrolled owner and protected catalogs.
    ///
    /// Signed admission and the same native worker programme remain required.
    /// This lender creates no dispatch, namespace, receipt or substitute payer.
    ///
    /// # Errors
    /// Refuses incomplete startup, missing owners, geometry or original F failure.
    pub fn begin_destroy_once_v4<'held>(
        &'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(
        NetworkServiceReceivingLoanV4<'held>,
        NetworkServiceDomainCallsiteV4<'held>,
    )> {
        self.borrow_domain_once_v4(operation, fixed, NetworkServiceMethodV4::Destroy)
    }

    /// Borrows the actual enrolled Prepare63 payer and protected source owners.
    ///
    /// This lender grants no worker, preparation result or publication. Its
    /// caller must retain the same original through all native and Session posts.
    ///
    /// # Errors
    /// Refuses incomplete startup, absent protected owners, checked geometry
    /// failure or the original once-only same-F Prepare63 admission.
    pub fn begin_prepare_once_v4<'held>(
        &'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(
        NetworkServiceReceivingLoanV4<'held>,
        NetworkServiceDomainCallsiteV4<'held>,
    )> {
        self.borrow_domain_once_v4(operation, fixed, NetworkServiceMethodV4::Prepare)
    }

    /// Borrows the separate fresh Inventory19 loan and actual complete catalog.
    ///
    /// # Errors
    /// Refuses incomplete startup, absent retained owners, geometry overflow or
    /// the original same-F financial/native admission.
    pub fn begin_inventory_once_v4<'held>(
        &'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(
        NetworkServiceReceivingLoanV4<'held>,
        NetworkServiceDomainCallsiteV4<'held>,
    )> {
        self.borrow_domain_once_v4(operation, fixed, NetworkServiceMethodV4::Inventory)
    }

    fn borrow_domain_once_v4<'held>(
        &'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
        method: NetworkServiceMethodV4,
    ) -> Result<(
        NetworkServiceReceivingLoanV4<'held>,
        NetworkServiceDomainCallsiteV4<'held>,
    )> {
        self.require_ready_v4()?;
        self.geometry = Some((|| {
            let bytes = std::mem::size_of::<NetworkServiceDomainCallsiteV4<'_>>()
                .checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                })?;
            fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let fixed = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(NetworkServiceClosedV4)?;
        let namespaces = self.namespaces.as_mut().ok_or(NetworkServiceClosedV4)?;
        let coordinator = self.coordinator.as_mut().ok_or(NetworkServiceClosedV4)?;
        let preparations = self.preparations.as_mut().ok_or(NetworkServiceClosedV4)?;
        let namespace_store = self.namespace_store.as_ref().ok_or(NetworkServiceClosedV4)?;
        let prepare_executor = self.prepare_executor.as_mut().ok_or(NetworkServiceClosedV4)?;
        let observation_executor = self.observation_executor.as_mut().ok_or(NetworkServiceClosedV4)?;
        let public_credentials = self.credentials.as_ref().ok_or(NetworkServiceClosedV4)?;

        let loan = match method {
            NetworkServiceMethodV4::Receiving => self
                .common
                .begin_network_request_receiving_once_v5(operation, fixed),
            NetworkServiceMethodV4::Destroy => self
                .common
                .begin_network_destroy_once_v4(operation, fixed),
            NetworkServiceMethodV4::Prepare => self
                .common
                .begin_network_prepare_once_v4(operation, fixed),
            NetworkServiceMethodV4::Inventory => self
                .common
                .begin_network_inventory_once_v4(operation, fixed),
        }
        .map_err(|_| NetworkServiceClosedV4)?;
        Ok((loan, NetworkServiceDomainCallsiteV4 {
            public_credentials,
            namespaces, method, coordinator, preparations, namespace_store,
            prepare_executor, observation_executor,
            creation_original: &self.creation_opening,
            lifecycle_original: &self.lifecycle_opening,
            preparation_original: &self.preparation_opening,
            namespace_original: &self.namespace_opening,
        }))
    }
}
