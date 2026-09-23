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
    DormantBrokerExecutionFailureV1, DormantBrokerFailureV1,
    DormantBrokerPublicationExecutionFailureV1, DormantHostBrokerEffectAdapterV1,
    DormantHostBrokerObservationAdapterV1, DormantHostCatalogPublicationRecoveryProgressV1,
    DormantMountBrokerEffectAdapterV1, DormantMountBrokerInventoryAdapterV1,
    DormantMountCatalogPreparationAdapterV1, DormantNetworkBrokerEffectAdapterV1,
    DormantReceivedBrokerDescriptorRequestV1, DormantReceivedBrokerRequestV1,
    DormantStorageBrokerEffectAdapterV1, ProductionBrokerRequestEventV1,
    ProductionBrokerResponseErrorV1, ProductionHostBrokerRequestEventV1,
    ProtectedBrokerOutcomeCommitResultV1,
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
    /// A Host execution intent failed with its protected replay custody.
    Execution(DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>),
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
    /// Completes one normalized Host request or replay event.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when durable domain
    /// recovery, descriptor reopening, protected commit, or bounded response
    /// transport cannot complete exactly.
    pub async fn complete_host_request_event(
        self,
        event: ProductionHostBrokerRequestEventV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        match event {
            ProductionHostBrokerRequestEventV1::Request(request) => {
                self.dispatch_host_request_to_completion(
                    request,
                    host,
                    publisher,
                    agent,
                    deadline_boottime_nanoseconds,
                )
                .await
            }
            ProductionHostBrokerRequestEventV1::InFlightReplay(replay) => {
                self.dispatch_host_request_to_completion(
                    replay.into_recovery_request(),
                    host,
                    publisher,
                    agent,
                    deadline_boottime_nanoseconds,
                )
                .await
            }
            ProductionHostBrokerRequestEventV1::TerminalReplay(replay) => {
                self.finish_authenticated_terminal_replay(replay, deadline_boottime_nanoseconds)
            }
            ProductionHostBrokerRequestEventV1::DescriptorTerminalReplay(replay) => {
                let artifacts = replay
                    .authorization_artifacts()
                    .cloned()
                    .ok_or(ProductionBrokerResponseErrorV1::DescriptorReplay)?;
                self.finish_host_descriptor_terminal_replay(
                    replay,
                    host,
                    &artifacts,
                    deadline_boottime_nanoseconds,
                )
                .await
            }
        }
    }

    /// Completes one normalized Storage request or replay event.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when durable Storage
    /// recovery, protected commit, or bounded response transport cannot finish.
    pub fn complete_storage_request_event(
        self,
        event: ProductionBrokerRequestEventV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        match event {
            ProductionBrokerRequestEventV1::Request(request) => self
                .dispatch_storage_request_to_completion(
                    request,
                    storage,
                    deadline_boottime_nanoseconds,
                ),
            ProductionBrokerRequestEventV1::InFlightReplay(replay) => {
                let request = replay
                    .into_unobserved_request()
                    .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?;
                self.dispatch_storage_request_to_completion(
                    request,
                    storage,
                    deadline_boottime_nanoseconds,
                )
            }
            ProductionBrokerRequestEventV1::TerminalReplay(replay) => {
                self.finish_authenticated_terminal_replay(replay, deadline_boottime_nanoseconds)
            }
            ProductionBrokerRequestEventV1::DescriptorTerminalReplay(_) => {
                Err(ProductionBrokerResponseErrorV1::DescriptorReplay)
            }
        }
    }

    /// Completes one normalized Network request or replay event.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when durable Network
    /// recovery, protected commit, or bounded response transport cannot finish.
    pub fn complete_network_request_event(
        self,
        event: ProductionBrokerRequestEventV1,
        network: &mut dyn aos_sandbox_network::DormantNetworkBrokerCallsiteV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        match event {
            ProductionBrokerRequestEventV1::Request(request) => self
                .dispatch_network_request_to_completion(
                    request,
                    network,
                    deadline_boottime_nanoseconds,
                ),
            ProductionBrokerRequestEventV1::InFlightReplay(replay) => {
                let request = replay
                    .into_unobserved_request()
                    .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?;
                self.dispatch_network_request_to_completion(
                    request,
                    network,
                    deadline_boottime_nanoseconds,
                )
            }
            ProductionBrokerRequestEventV1::TerminalReplay(replay) => {
                self.finish_authenticated_terminal_replay(replay, deadline_boottime_nanoseconds)
            }
            ProductionBrokerRequestEventV1::DescriptorTerminalReplay(_) => {
                Err(ProductionBrokerResponseErrorV1::DescriptorReplay)
            }
        }
    }

    /// Completes one normalized Mount request or replay event.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when durable Mount/source
    /// recovery, protected commit, or bounded response transport cannot finish.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_mount_request_event(
        self,
        event: ProductionBrokerRequestEventV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
        source: Option<crate::ProductionMountSourceOwnersV1<'_>>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let request = match event {
            ProductionBrokerRequestEventV1::Request(request) => request,
            ProductionBrokerRequestEventV1::InFlightReplay(replay) => replay
                .into_unobserved_request()
                .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?,
            ProductionBrokerRequestEventV1::TerminalReplay(replay) => {
                return self
                    .finish_authenticated_terminal_replay(replay, deadline_boottime_nanoseconds);
            }
            ProductionBrokerRequestEventV1::DescriptorTerminalReplay(_) => {
                return Err(ProductionBrokerResponseErrorV1::DescriptorReplay);
            }
        };
        self.dispatch_mount_request_to_completion(
            request,
            mount,
            catalog_scope,
            source,
            deadline_boottime_nanoseconds,
        )
    }

    /// Dispatches and completes one Host request through all recovery branches.
    ///
    /// This is the consuming production path from durably admitted Host
    /// custody to an exact sent terminal response. It keeps catalog descriptor
    /// readback, scope descriptor commit/finalization, ordinary observation,
    /// and transport retry under the same authenticated session owner.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when an effect remains
    /// unknown, exact protected recovery cannot complete, or response transport
    /// exceeds the boot-time deadline. Such errors require reconnect and exact
    /// replay; they never authorize generic redispatch.
    pub async fn dispatch_host_request_to_completion(
        mut self,
        request: DormantReceivedBrokerDescriptorRequestV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let artifacts = request.authorization_artifacts().cloned();
        let dispatched = self
            .dispatch_host_request_and_commit(
                request,
                host,
                publisher,
                agent,
                deadline_boottime_nanoseconds,
            )
            .await;

        match dispatched {
            Ok(ProductionHostBrokerDispatchCommitV1::Ordinary(committed)) => {
                self.finish_authenticated_response(committed, deadline_boottime_nanoseconds)
            }
            Ok(ProductionHostBrokerDispatchCommitV1::Descriptor(committed)) => {
                let artifacts = artifacts
                    .as_ref()
                    .ok_or(ProductionBrokerResponseErrorV1::OutcomeRecovery)?;
                self.finish_host_descriptor_response(
                    committed,
                    host,
                    artifacts,
                    deadline_boottime_nanoseconds,
                )
            }
            Err(ProductionHostBrokerDispatchFailureV1::RequestShape(_)) => {
                Err(ProductionBrokerResponseErrorV1::OutcomeRecovery)
            }
            Err(ProductionHostBrokerDispatchFailureV1::Ordinary(failure)) => {
                self.finish_ordinary_dispatch(Err(failure), deadline_boottime_nanoseconds)
            }
            Err(ProductionHostBrokerDispatchFailureV1::Execution(failure)) => {
                self.finish_ordinary_dispatch(Err(failure), deadline_boottime_nanoseconds)
            }
            Err(ProductionHostBrokerDispatchFailureV1::Descriptor(failure)) => match failure {
                DormantBrokerDescriptorExecutionFailureV1::BeforeEffect { error, request } => self
                    .finish_ordinary_dispatch(
                        Err::<ProtectedBrokerOutcomeCommitResultV1, _>(
                            DormantBrokerExecutionFailureV1::<
                                aos_sandbox_host::DormantHostBrokerCallErrorV1,
                            >::BeforeEffect {
                                error,
                                request,
                            },
                        ),
                        deadline_boottime_nanoseconds,
                    ),
                DormantBrokerDescriptorExecutionFailureV1::OutcomeUnknown { custody, .. } => {
                    let artifacts = artifacts
                        .as_ref()
                        .ok_or(ProductionBrokerResponseErrorV1::OutcomeRecovery)?;
                    let committed = self
                        .retry_observed_host_scope_and_commit(
                            custody,
                            DormantHostBrokerEffectAdapterV1::new(host, artifacts),
                        )
                        .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?;
                    self.finish_host_descriptor_response(
                        committed,
                        host,
                        artifacts,
                        deadline_boottime_nanoseconds,
                    )
                }
            },
            Err(ProductionHostBrokerDispatchFailureV1::Publication(failure)) => {
                let committed = match failure {
                    DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                        request, ..
                    } => self.commit_authenticated_publication_error_response(
                        request,
                        DormantBrokerFailureV1::InvalidRequest,
                    )?,
                    DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                        recovery, ..
                    } => match self.recover_host_catalog_publication(recovery, publisher) {
                        Ok(DormantHostCatalogPublicationRecoveryProgressV1::ResponseCommit(
                            committed,
                        )) => committed,
                        Ok(DormantHostCatalogPublicationRecoveryProgressV1::RetrySafe(retry)) => {
                            self.retry_absent_host_catalog_publication(retry, publisher)
                                .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?
                        }
                        Err(_) => return Err(ProductionBrokerResponseErrorV1::OutcomeRecovery),
                    },
                };
                self.finish_authenticated_response(committed, deadline_boottime_nanoseconds)
            }
        }
    }

    /// Dispatches and completes one Storage request on the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when domain outcome
    /// recovery, protected commit, or bounded response transport cannot finish
    /// exactly. Reconnect and exact replay are then required.
    pub fn dispatch_storage_request_to_completion(
        mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let dispatched = self.dispatch_storage_request_and_commit(request, storage);
        self.finish_ordinary_dispatch(dispatched, deadline_boottime_nanoseconds)
    }

    /// Dispatches and completes one Network request on the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when domain outcome
    /// recovery, protected commit, or bounded response transport cannot finish
    /// exactly. Reconnect and exact replay are then required.
    pub fn dispatch_network_request_to_completion(
        mut self,
        request: DormantReceivedBrokerRequestV1,
        network: &mut dyn aos_sandbox_network::DormantNetworkBrokerCallsiteV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let dispatched = self.dispatch_network_request_and_commit(request, network);
        self.finish_ordinary_dispatch(dispatched, deadline_boottime_nanoseconds)
    }

    /// Dispatches and completes one Mount request on the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when domain or source
    /// recovery, protected commit, or bounded response transport cannot finish
    /// exactly. Reconnect and exact replay are then required.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_mount_request_to_completion(
        mut self,
        request: DormantReceivedBrokerRequestV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
        source: Option<crate::ProductionMountSourceOwnersV1<'_>>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let dispatched =
            self.dispatch_mount_request_and_commit(request, mount, catalog_scope, source);
        self.finish_ordinary_dispatch(dispatched, deadline_boottime_nanoseconds)
    }

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
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
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
            BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE => self
                .execute_host_execution_and_commit(
                    request,
                    host,
                    agent,
                    deadline_boottime_nanoseconds,
                )
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
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
    /// repair, grouped snapshot, or authoritative inventory. Mutation artifacts
    /// are copied from the already authenticated request only long enough to
    /// satisfy Rust's move discipline; the Storage adapter binds their exact
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
            | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
            | BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
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
    pub fn dispatch_mount_request_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
        source: Option<crate::ProductionMountSourceOwnersV1<'_>>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionMountBrokerDispatchErrorV1>,
    > {
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
            | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
                let Some(source) = source else {
                    return Err(before_effect_currentness(request));
                };
                self.execute_mount_source_operation_and_commit(
                    request,
                    source.source_owner,
                    source.root_session,
                    source.provider,
                    source.backend,
                    source.canonical_catalog_publication,
                )
                .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
                let Some(source) = source else {
                    return Err(before_effect_currentness(request));
                };
                self.execute_mount_source_inventory_and_commit(
                    request,
                    source.source_owner,
                    source.root_session,
                    source.provider,
                    source.backend,
                )
                .map_err(|failure| map_execution_failure(failure, Into::into))
            }
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
                .execute_network_inventory_and_commit(request, network.namespace_catalog())
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
