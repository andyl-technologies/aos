//! Closed production dispatch for every authenticated broker method.
//!
//! The dispatcher derives its branch solely from the signed request method.
//! Callers supply concrete sealed domain owners, never a method selector or a
//! response body. Pre-effect failures retain request custody, while failures
//! after dispatch retain the existing opaque outcome-recovery custody.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorCommitResultV1,
    DormantBrokerDescriptorExecutionFailureV1, DormantBrokerExecutionErrorV1,
    DormantBrokerExecutionFailureV1, DormantBrokerPublicationExecutionFailureV1,
    DormantHostBrokerEffectAdapterV1, DormantHostBrokerObservationAdapterV1,
    DormantMountBrokerEffectAdapterV1, DormantMountBrokerInventoryAdapterV1,
    DormantMountCatalogPreparationAdapterV1, DormantNetworkBrokerEffectAdapterV1,
    DormantReceivedBrokerDescriptorRequestV1, DormantReceivedBrokerRequestV1,
    DormantStorageBrokerEffectAdapterV1, ProtectedBrokerOutcomeCommitResultV1,
};

/// Retains the exact commit shape produced by one Host method.
#[must_use = "send or recover the exact committed Host response"]
pub enum ProductionHostBrokerDispatchCommitV1 {
    /// The Host response contains no ancillary descriptors.
    Ordinary(ProtectedBrokerOutcomeCommitResultV1),
    /// The Host response carries a protected descriptor table.
    Descriptor(DormantBrokerDescriptorCommitResultV1),
}

/// Retains Host request or recovery custody across a dispatch failure.
#[must_use = "retain or explicitly recover the failed Host dispatch"]
pub enum ProductionHostBrokerDispatchFailureV1 {
    /// A descriptor was supplied for a method whose exact table is empty.
    RequestShape(DormantReceivedBrokerDescriptorRequestV1),
    /// An ordinary Host operation failed before or after effect dispatch.
    Ordinary(DormantBrokerExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>),
    /// A descriptor-producing scope operation failed with its custody retained.
    Descriptor(
        DormantBrokerDescriptorExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    ),
    /// Catalog publication failed with its request descriptor retained.
    Publication(
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    ),
}

/// Classifies a failed Storage domain operation without erasing recovery custody.
#[derive(Debug, thiserror::Error)]
pub enum ProductionStorageBrokerDispatchErrorV1 {
    /// Apply, catalog preparation, or workspace-pin repair failed.
    #[error("authenticated Storage operation failed: {0}")]
    Operation(#[from] aos_sandbox_storage::DormantStorageBrokerCallErrorV1),
    /// Authoritative Storage inventory could not complete.
    #[error("authenticated Storage inventory failed: {0}")]
    Inventory(#[from] aos_sandbox_storage::StorageRuntimeError),
}

/// Classifies a failed Network domain operation without erasing recovery custody.
#[derive(Debug, thiserror::Error)]
pub enum ProductionNetworkBrokerDispatchErrorV1 {
    /// Apply admission or its protected physical observation failed.
    #[error("authenticated Network operation failed: {0}")]
    Operation(#[from] aos_sandbox_network::DormantNetworkBrokerCallErrorV1),
    /// Authoritative Network inventory could not complete.
    #[error("authenticated Network inventory failed: {0}")]
    Inventory(#[from] aos_sandbox_network::NetworkNamespaceCatalogError),
}

/// Classifies a failed Mount domain operation without erasing recovery custody.
#[derive(Debug, thiserror::Error)]
pub enum ProductionMountBrokerDispatchErrorV1 {
    /// Apply, inventory, destination-slot, or catalog preparation failed.
    #[error("authenticated Mount operation failed: {0}")]
    Operation(#[from] aos_sandbox_mount::DormantMountBrokerCallErrorV1),
    /// Source acquisition, release, inventory, or recovery failed.
    #[error("authenticated Mount source operation failed: {0}")]
    Source(#[from] aos_sandbox_mount::MountError),
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Dispatches every Host protocol method through sealed production owners.
    ///
    /// The request arrives through the mixed zero-or-one descriptor receive
    /// path. `PublishCatalog` alone retains its incoming descriptor; every
    /// other method must convert to descriptor-free custody before dispatch.
    /// Scope observations preserve their exact outgoing descriptor table.
    ///
    /// # Errors
    ///
    /// Returns move-only request, effect, publication, or descriptor custody
    /// whenever the method shape, protected currentness, domain operation, or
    /// terminal commit cannot be completed exactly.
    pub async fn dispatch_host_request_and_commit(
        &mut self,
        request: DormantReceivedBrokerDescriptorRequestV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<ProductionHostBrokerDispatchCommitV1, ProductionHostBrokerDispatchFailureV1> {
        if request.method() == BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG {
            return self
                .execute_host_catalog_publication_and_commit(request, publisher)
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Publication);
        }

        let request = request
            .into_descriptor_free_request()
            .map_err(ProductionHostBrokerDispatchFailureV1::RequestShape)?;
        match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
                let Some(artifacts) = request.authorization_artifacts().cloned() else {
                    return Err(ProductionHostBrokerDispatchFailureV1::Ordinary(
                        before_effect_currentness(request),
                    ));
                };
                self.execute_host_apply_and_commit(
                    request,
                    DormantHostBrokerEffectAdapterV1::new(host, &artifacts),
                )
                .await
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Ordinary)
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
            | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => self
                .execute_host_observation_and_commit(
                    request,
                    DormantHostBrokerObservationAdapterV1::new(host),
                )
                .await
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Ordinary),
            BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
                let Some(artifacts) = request.authorization_artifacts().cloned() else {
                    return Err(ProductionHostBrokerDispatchFailureV1::Ordinary(
                        before_effect_currentness(request),
                    ));
                };
                self.execute_host_observation_and_commit(
                    request,
                    DormantHostBrokerObservationAdapterV1::new_authorized(host, &artifacts),
                )
                .await
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Ordinary)
            }
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
                let Some(artifacts) = request.authorization_artifacts().cloned() else {
                    return Err(ProductionHostBrokerDispatchFailureV1::Ordinary(
                        before_effect_currentness(request),
                    ));
                };
                self.execute_host_scope_and_commit(
                    request,
                    DormantHostBrokerEffectAdapterV1::new(host, &artifacts),
                )
                .await
                .map(ProductionHostBrokerDispatchCommitV1::Descriptor)
                .map_err(ProductionHostBrokerDispatchFailureV1::Descriptor)
            }
            _ => Err(ProductionHostBrokerDispatchFailureV1::Ordinary(
                before_effect_currentness(request),
            )),
        }
    }

    /// Dispatches every Storage protocol method through its sealed production owner.
    ///
    /// The signed method selects Apply, catalog preparation, workspace-pin
    /// repair, or authoritative inventory. Mutation artifacts are copied from
    /// the already authenticated request only long enough to satisfy Rust's
    /// move discipline; the Storage adapter independently binds their exact
    /// commitment before entering the domain owner.
    ///
    /// # Errors
    ///
    /// Returns move-only request or outcome custody when method selection,
    /// protected currentness, domain execution, or terminal commit cannot be
    /// completed exactly. A caller must retain or explicitly recover it.
    pub fn dispatch_storage_request_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>,
    > {
        match request.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
                let Some(artifacts) = request.authorization_artifacts().cloned() else {
                    return Err(before_effect_currentness(request));
                };
                let adapter = DormantStorageBrokerEffectAdapterV1::new(storage, &artifacts);
                let result = if request.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY {
                    self.execute_storage_apply_and_commit(request, adapter)
                } else {
                    self.execute_storage_operation_and_commit(request, adapter)
                };
                result.map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => self
                .execute_storage_inventory_and_commit(request, storage)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            _ => Err(before_effect_currentness(request)),
        }
    }

    /// Dispatches every Mount protocol method through its sealed production owners.
    ///
    /// The optional Host scope is consumed only by `PrepareCatalog`. Source
    /// methods use the retained RootMount/provider graph and canonical catalog
    /// publication; no caller-selected method can redirect those authorities.
    ///
    /// # Errors
    ///
    /// Returns move-only request or outcome custody when a required Host scope
    /// is absent, authorization artifacts do not match, protected currentness
    /// fails, a domain effect is ambiguous, or terminal commit is incomplete.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_mount_request_and_commit<Transport>(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
        source_owner: &mut aos_sandbox_mount::source_acquisition::FixedMountSourceAcquisitionOwnerV2,
        root_session: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        provider: &mut aos_sandbox_source_provider::FixedProviderOwnerV1,
        backend: &mut Transport,
        canonical_catalog_publication: &[u8],
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionMountBrokerDispatchErrorV1>,
    >
    where
        Transport: aos_sandbox_source_provider::SourceProviderBackendTransportV1 + ?Sized,
    {
        match request.method() {
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
                let Some(artifacts) = request.authorization_artifacts().cloned() else {
                    return Err(before_effect_currentness(request));
                };
                let adapter = DormantMountBrokerEffectAdapterV1::new(mount, &artifacts);
                let result = if request.method() == BrokerMethod::BROKER_METHOD_MOUNT_APPLY {
                    self.execute_mount_apply_and_commit(request, adapter)
                } else {
                    self.execute_mount_destination_slot_and_commit(request, adapter)
                };
                result.map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => self
                .execute_mount_inventory_and_commit(
                    request,
                    DormantMountBrokerInventoryAdapterV1::new(mount),
                )
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => {
                let Some(scope) = catalog_scope else {
                    return Err(before_effect_currentness(request));
                };
                self.execute_mount_catalog_preparation_and_commit(
                    request,
                    DormantMountCatalogPreparationAdapterV1::new(mount, scope),
                )
                .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => self
                .execute_mount_source_operation_and_commit(
                    request,
                    source_owner,
                    root_session,
                    provider,
                    backend,
                    canonical_catalog_publication,
                )
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => self
                .execute_mount_source_inventory_and_commit(
                    request,
                    source_owner,
                    root_session,
                    provider,
                    backend,
                )
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            _ => Err(before_effect_currentness(request)),
        }
    }

    /// Dispatches every Network protocol method through its sealed production owner.
    ///
    /// Apply uses the sealed admission composition and signed artifacts;
    /// inventory methods read the authoritative namespace catalog directly.
    /// The caller cannot substitute a response body or route one Network method
    /// through another adapter.
    ///
    /// # Errors
    ///
    /// Returns move-only request or outcome custody when method selection,
    /// protected currentness, domain execution, or terminal commit cannot be
    /// completed exactly. A caller must retain or explicitly recover it.
    pub fn dispatch_network_request_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        network: &mut dyn aos_sandbox_network::DormantNetworkBrokerCallsiteV1,
        catalog: &aos_sandbox_network::NetworkNamespaceCatalogV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionNetworkBrokerDispatchErrorV1>,
    > {
        match request.method() {
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
                let Some(artifacts) = request.authorization_artifacts().cloned() else {
                    return Err(before_effect_currentness(request));
                };
                self.execute_network_apply_and_commit(
                    request,
                    DormantNetworkBrokerEffectAdapterV1::new(network, &artifacts),
                )
                .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => self
                .execute_network_inventory_and_commit(request, catalog)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            _ => Err(before_effect_currentness(request)),
        }
    }
}

fn before_effect_currentness<Domain>(
    request: DormantReceivedBrokerRequestV1,
) -> DormantBrokerExecutionFailureV1<Domain> {
    DormantBrokerExecutionFailureV1::BeforeEffect {
        error: crate::BrokerSessionSecurityError::Currentness,
        request,
    }
}

fn map_execution_failure<Source, Target>(
    failure: DormantBrokerExecutionFailureV1<Source>,
    map_domain: impl FnOnce(Source) -> Target,
) -> DormantBrokerExecutionFailureV1<Target> {
    match failure {
        DormantBrokerExecutionFailureV1::BeforeEffect { error, request } => {
            DormantBrokerExecutionFailureV1::BeforeEffect { error, request }
        }
        DormantBrokerExecutionFailureV1::OutcomeUnknown { error, custody } => {
            let error = match error {
                DormantBrokerExecutionErrorV1::Currentness(error) => {
                    DormantBrokerExecutionErrorV1::Currentness(error)
                }
                DormantBrokerExecutionErrorV1::Domain(error) => {
                    DormantBrokerExecutionErrorV1::Domain(map_domain(error))
                }
            };
            DormantBrokerExecutionFailureV1::OutcomeUnknown { error, custody }
        }
    }
}
