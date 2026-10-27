//! Closed production dispatch for every authenticated broker method.
//!
//! The dispatcher derives its branch solely from the signed request method.
//! Callers supply concrete sealed domain owners, never a method selector or a
//! response body. Pre-effect failures retain request custody, while failures
//! after dispatch retain the existing opaque outcome-recovery custody.

use std::os::fd::OwnedFd;

use aos_sandbox_api::aos::sandbox::local::v1::{ApplyHostExecutionRequestV1, BrokerMethod};
use aos_linux_descriptors::boot::KernelBootId;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use buffa::Message as _;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorCommitResultV1,
    DormantBrokerDescriptorExecutionFailureV1, DormantBrokerExecutionErrorV1,
    DormantBrokerExecutionFailureV1, DormantBrokerFailureV1,
    DormantBrokerPublicationExecutionFailureV1, DormantHostBrokerEffectAdapterV1,
    DormantHostBrokerObservationAdapterV1, DormantHostCatalogPublicationRecoveryProgressV1,
    DormantMountBrokerEffectAdapterV1, DormantMountBrokerInventoryAdapterV1,
    DormantMountCatalogPreparationAdapterV1,
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
    /// A paid Host argument interval stays pending through real response Sent.
    HostArgument(ProtectedBrokerOutcomeCommitResultV1, DormantReceivedBrokerRequestV1),
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
    /// Host ApplyExecution failed while its exact content descriptor remained owned.
    ExecutionDescriptor {
        failure: DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>,
        request: DormantReceivedBrokerDescriptorRequestV1,
    },
    /// The sealed argument source was checked but has no accepted-Create issuer.
    ArgumentSourceDescriptor {
        failure: DormantBrokerExecutionFailureV1<()>,
        request: DormantReceivedBrokerDescriptorRequestV1,
        /// Distinguishes valid transport from malformed sealed content.
        transport_validated: bool,
    },
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
    /// The actual same-Session execution availability interval refused entry.
    #[error("authenticated Storage execution availability failed: {0}")]
    Availability(crate::BrokerSessionSecurityError),
    /// Apply, catalog preparation, or workspace-pin repair failed.
    #[error("authenticated Storage operation failed: {0}")]
    Operation(#[from] aos_sandbox_storage::DormantStorageBrokerCallErrorV1),
    /// Authoritative Storage inventory could not complete.
    #[error("authenticated Storage inventory failed: {0}")]
    Inventory(#[from] aos_sandbox_storage::StorageRuntimeError),
    /// The exact original signed inventory or protected abandonment is unavailable.
    #[error("authenticated Storage inventory recovery failed: {0}")]
    Recovery(#[from] crate::BrokerSessionSecurityError),
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
    /// Receives one selected Storage cycle with the daemon's original output loan.
    ///
    /// Receipt, replay, dispatch, commit and response remain the same engines as
    /// ordinary Storage. The concrete output loan only enables the four closed
    /// coverage routes; it grants neither an output reservation nor allocation.
    ///
    /// # Errors
    /// Returns the existing consuming request-cycle error on receive, owner
    /// comparison, protected commit or transport failure. The selected daemon
    /// must park that whole result before its own final owner bookend.
    #[doc(hidden)]
    pub fn serve_production_storage_request_with_git_coverage_v1(
        self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, crate::ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session.complete_storage_request_event_with_git_coverage_v1(
            event, storage, output, deadline_boottime_nanoseconds,
        ).map_err(Into::into)
    }

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
        self.complete_storage_event_with_coverage_v1(
            event, storage, deadline_boottime_nanoseconds, None,
        )
    }

    /// Completes a selected Storage event while its real output owner stays held.
    ///
    /// # Errors
    /// Preserves the ordinary disposition for old methods. Coverage refuses
    /// missing/changed original domains and rechecks them before every send.
    pub fn complete_storage_request_event_with_git_coverage_v1(
        self,
        event: ProductionBrokerRequestEventV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        self.complete_storage_event_with_coverage_v1(
            event, storage, deadline_boottime_nanoseconds, Some(output),
        )
    }

    fn complete_storage_event_with_coverage_v1(
        self,
        event: ProductionBrokerRequestEventV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
        output: Option<&aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        match event {
            ProductionBrokerRequestEventV1::Request(request) => self
                .complete_storage_dispatch_with_coverage_v1(
                    request,
                    storage,
                    deadline_boottime_nanoseconds,
                    output,
                ),
            ProductionBrokerRequestEventV1::InFlightReplay(replay) => {
                let request = replay
                    .into_unobserved_request()
                    .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?;
                self.complete_storage_dispatch_with_coverage_v1(
                    request,
                    storage,
                    deadline_boottime_nanoseconds,
                    output,
                )
            }
            ProductionBrokerRequestEventV1::TerminalReplay(replay) => {
                if crate::dormant_handshake::git_coverage::is_storage(replay.method()) {
                    let output = output.ok_or(ProductionBrokerResponseErrorV1::CoverageOwnerMissing)?;
                    return self.finish_replay_with_coverage_v1(
                        replay, deadline_boottime_nanoseconds,
                        Some(crate::production_response::GitCoverageResponseOwnerV1::Storage {
                            storage, output,
                        }),
                    );
                }
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
    /// Returns an error after consuming the session when durable Mount
    /// recovery, protected commit, or bounded response transport cannot finish.
    pub fn complete_mount_request_event(
        self,
        event: ProductionBrokerRequestEventV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let request = match event {
            ProductionBrokerRequestEventV1::Request(request) => request,
            ProductionBrokerRequestEventV1::InFlightReplay(replay) => replay
                .into_unobserved_request()
                .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?,
            ProductionBrokerRequestEventV1::TerminalReplay(replay) => {
                if crate::dormant_handshake::git_coverage::is_mount(replay.method()) {
                    return self.finish_replay_with_coverage_v1(
                        replay, deadline_boottime_nanoseconds,
                        Some(crate::production_response::GitCoverageResponseOwnerV1::Mount(mount)),
                    );
                }
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
            Ok(ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request)) => {
                self.finish_host_argument_response_v2(committed, request, host,
                    deadline_boottime_nanoseconds)
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
            Err(ProductionHostBrokerDispatchFailureV1::ExecutionDescriptor {
                failure,
                request: _,
            }) => self.finish_ordinary_dispatch(Err(failure), deadline_boottime_nanoseconds),
            Err(ProductionHostBrokerDispatchFailureV1::ArgumentSourceDescriptor {
                failure,
                request: _,
                transport_validated: _,
            }) => self.finish_ordinary_dispatch(Err(failure), deadline_boottime_nanoseconds),
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
                    DormantBrokerPublicationExecutionFailureV1::NativeRefused { error, .. } => {
                        eprintln!("Host catalog native publication refused: {error}; original: {}",
                            host.catalog_publication_failure_view_v2());
                        return Err(ProductionBrokerResponseErrorV1::OutcomeRecovery);
                    }
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
        self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        self.complete_storage_dispatch_with_coverage_v1(
            request, storage, deadline_boottime_nanoseconds, None,
        )
    }

    fn complete_storage_dispatch_with_coverage_v1(
        mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
        output: Option<&aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let coverage = crate::dormant_handshake::git_coverage::is_storage(request.method());
        let dispatched = self.dispatch_storage_with_coverage_v1(request, storage, output);
        if coverage {
            let output = output.ok_or(ProductionBrokerResponseErrorV1::CoverageOwnerMissing)?;
            return self.finish_storage_dispatch_with_coverage_v1(
                dispatched, deadline_boottime_nanoseconds,
                Some(crate::production_response::GitCoverageResponseOwnerV1::Storage {
                    storage, output,
                }),
            );
        }
        self.finish_storage_dispatch_with_coverage_v1(dispatched, deadline_boottime_nanoseconds, None)
    }

    /// Dispatches and completes one Mount request on the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when domain recovery,
    /// protected commit, or bounded response transport cannot finish
    /// exactly. Reconnect and exact replay are then required.
    pub fn dispatch_mount_request_to_completion(
        mut self,
        request: DormantReceivedBrokerRequestV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let coverage = crate::dormant_handshake::git_coverage::is_mount(request.method());
        let dispatched = self.dispatch_mount_request_and_commit(request, mount, catalog_scope);
        if coverage {
            return self.finish_dispatch_with_coverage_v1(
                dispatched, deadline_boottime_nanoseconds,
                Some(crate::production_response::GitCoverageResponseOwnerV1::Mount(mount)),
            );
        }
        self.finish_ordinary_dispatch(dispatched, deadline_boottime_nanoseconds)
    }

    /// Dispatches every Host protocol method through sealed production owners.
    ///
    /// The request arrives through the mixed zero-or-one descriptor receive
    /// path. `PublishCatalog` and `ApplyExecution` retain their sole incoming
    /// descriptors; every other method uses descriptor-free custody.
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
                .execute_original_host_catalog_publication_and_commit_v2(request, host, publisher)
                .await
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Publication);
        }

        if request.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION {
            let Some((execution_request, descriptor)) = request.clone_host_execution_spec_request()
            else {
                return Err(ProductionHostBrokerDispatchFailureV1::RequestShape(request));
            };
            let Some(content_bytes) = host_execution_spec_content_bytes(execution_request.body())
            else {
                return Err(ProductionHostBrokerDispatchFailureV1::RequestShape(request));
            };
            let selected = ApplyHostExecutionRequestV1::decode_from_slice(execution_request.body()).ok()
                .is_some_and(|request| request.spec_transfer_version == 5
                    || (host.has_accepted_execution(execution_request.authenticated_original_v2()) && request.action.as_known() == Some(
                        aos_sandbox_api::aos::sandbox::local::v1::HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE)));
            if selected {
                // Host owns the precharged real59 capsule and performs its
                // bounded mapping before awaiting the existing native posts.
                // No borrowed memfd slice crosses an await or escapes custody.
                return self.execute_host_accepted_execution_and_commit_v2(execution_request,
                    descriptor, host, agent, deadline_boottime_nanoseconds).await
                    .map(|(committed, original)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, original))
                    .map_err(|failure| ProductionHostBrokerDispatchFailureV1::ExecutionDescriptor { failure, request });
            }
            let dispatched =
                with_sealed_host_execution_content(content_bytes, descriptor, |content| {
                    self.execute_host_execution_and_commit(
                        execution_request,
                        Some(content),
                        host,
                        agent,
                        deadline_boottime_nanoseconds,
                    )
                });
            return match dispatched {
                Some(Ok(committed)) => {
                    Ok(ProductionHostBrokerDispatchCommitV1::Ordinary(committed))
                }
                Some(Err(failure)) => {
                    Err(ProductionHostBrokerDispatchFailureV1::ExecutionDescriptor {
                        failure,
                        request,
                    })
                }
                None => Err(ProductionHostBrokerDispatchFailureV1::RequestShape(request)),
            };
        }

        if request.method() == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT {
            let Some((argument_request, descriptor)) = request.clone_host_argument_source_request()
            else {
                return Err(ProductionHostBrokerDispatchFailureV1::RequestShape(request));
            };
            let transport_validated =
                verify_argument_source_descriptor(&argument_request, descriptor);

            // The signed accepted-Create issuer and Host one-shot owner bridge
            // are not installed. Valid transport cannot authorize Guest send.
            return Err(
                ProductionHostBrokerDispatchFailureV1::ArgumentSourceDescriptor {
                    failure: before_effect_currentness(argument_request),
                    request,
                    transport_validated,
                },
            );
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
                self.execute_host_apply_and_commit_retaining_v2(
                    request,
                    DormantHostBrokerEffectAdapterV1::new(host, &artifacts),
                    agent.as_deref(),
                )
                .await
                .map(|(committed, original)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, original))
                .map_err(ProductionHostBrokerDispatchFailureV1::Ordinary)
            }
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => self
                .execute_host_argument_and_commit_v2(request, host, agent, deadline_boottime_nanoseconds)
                .await
                .map(|(committed, request)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request))
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => self
                .execute_host_execution_availability_and_commit_v2(request, host, deadline_boottime_nanoseconds)
                .await
                .map(|(committed, request)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request))
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
                if host.has_execution_availability() => self
                .execute_host_execution_availability_and_commit_v2(request, host, deadline_boottime_nanoseconds)
                .await
                .map(|(committed, request)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request))
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
                if request.authenticated_original_v2().host_execution_query_data_v3()
                    .and_then(|query| query.monitor_v3()).is_some() => self
                .execute_host_resident_query_and_commit_v3(request, host, deadline_boottime_nanoseconds)
                .await
                .map(|(committed, request)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request))
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                if request.authenticated_original_v2().host_before_argument_no_apply_data_v2().is_some()
                    && host.has_execution_availability() => self
                .execute_host_execution_availability_and_commit_v2(request, host, deadline_boottime_nanoseconds)
                .await
                .map(|(committed, request)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request))
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
                if (host.has_execution_availability()
                    || matches!(request.authenticated_original_v2().host_held_no_apply_settlement_data_v2()
                        .map(|value| value.command_v2()),
                        Some(aos_sandbox_protocol::host_execution_no_apply::held_settlement_transport::HostNoApplyHeldCommandV2::RecoveryPreliminary { .. })))
                    && (request.authenticated_original_v2().host_held_no_apply_settlement_data_v2().is_some()
                        || request.authenticated_original_v2().host_no_apply_current_lease_query_data_v2().is_some()) => self
                .execute_host_execution_availability_and_commit_v2(request, host, deadline_boottime_nanoseconds)
                .await
                .map(|(committed, request)| ProductionHostBrokerDispatchCommitV1::HostArgument(committed, request))
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            | BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT
            | BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE
            | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => self
                .execute_host_execution_and_commit(
                    request,
                    None,
                    host,
                    agent,
                    deadline_boottime_nanoseconds,
                )
                .map(ProductionHostBrokerDispatchCommitV1::Ordinary)
                .map_err(ProductionHostBrokerDispatchFailureV1::Execution),
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
                // Controller cannot yet settle the matching Create operation and
                // execution projection. Keep both recovery verbs off production.
                Err(ProductionHostBrokerDispatchFailureV1::Ordinary(
                    before_effect_currentness(request),
                ))
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
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
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

    pub(crate) fn dispatch_storage_lifecycle_request_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        logical: &mut crate::production_service::StorageOutputLifecycleOriginalV1,
        availability: &mut crate::production_service::ProductionStorageExecutionAvailabilityOriginalV2,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox_controller_domain::StorageReceivingClosedV1>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>,
    > {
        match request.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 => self
                .execute_storage_execution_availability_receiving_and_commit_v2(
                    request, availability, receiving, native_admission)
                .map_err(|failure| map_execution_failure(failure, ProductionStorageBrokerDispatchErrorV1::Availability)),
            BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
                let Some(output) = output else { return Err(before_effect_currentness(request)); };
                self.execute_storage_capture_candidate_lifecycle_and_commit_v1(request, storage, output, receiving, native_admission)
                    .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1 => {
                let Some(output) = output else { return Err(before_effect_currentness(request)); };
                self.execute_storage_logical_output_lifecycle_and_commit_v1(request, storage, output, logical, receiving, native_admission)
                    .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1 => {
                let Some(output) = output else { return Err(before_effect_currentness(request)); };
                self.execute_storage_capture_query_lifecycle_and_commit_v3(request, storage, output, receiving, native_admission)
                    .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY => self
                .execute_storage_apply_receiving_and_commit_v1(request, storage, receiving, native_admission)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => self
                .execute_storage_inventory_lifecycle_and_commit_v1(request, storage, receiving, native_admission)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
            | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => self
                .execute_storage_operation_lifecycle_and_commit_v1(request, storage, receiving, native_admission)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            _ => Err(before_effect_currentness(request)),
        }
    }

    /// Dispatches only the selected original candidate with the actual output loan.
    pub(crate) fn dispatch_storage_capture_candidate_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>,
    > {
        self.execute_storage_capture_candidate_and_commit_v1(request, storage, output)
            .map_err(|failure| map_execution_failure(failure, Into::into))
    }

    pub(crate) fn dispatch_storage_prepare_request_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>,
    > {
        match request.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => self
                .execute_storage_prepare_receiving_and_commit_v1(request, storage, receiving)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => self
                .execute_storage_inventory_with_storage_receiving_v1(request, storage, Some(receiving))
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            _ => Err(before_effect_currentness(request)),
        }
    }

    /// Dispatches every Storage protocol method through its sealed production owner.
    ///
    /// The signed method selects Apply, catalog preparation, workspace-pin
    /// repair, grouped snapshot, guest-root publication, or authoritative
    /// inventory. Mutation artifacts
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
        self.dispatch_storage_with_coverage_v1(request, storage, None)
    }

    fn dispatch_storage_with_coverage_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>,
    > {
        match request.method() {
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => {
                let Some(output) = output else {
                    return Err(before_effect_currentness(request));
                };
                self.execute_storage_git_coverage_and_commit_v1(request, storage, output)
                    .map_err(|failure| map_execution_failure(failure, Into::into))
            }
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
            | BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
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
            BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY => self
                .execute_storage_inventory_recovery_and_commit(request)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
            _ => Err(before_effect_currentness(request)),
        }
    }

    /// Dispatches every Mount protocol method through its sealed production owners.
    ///
    /// The optional Host scope is consumed only by `PrepareCatalog`. Source
    /// methods remain closed until the separate provider service and Mount
    /// journal owner can exchange authenticated protocol evidence.
    ///
    /// # Errors
    ///
    /// Returns move-only request or outcome custody when a required Host scope
    /// is absent, authorization artifacts do not match, protected currentness
    /// fails, a domain effect is ambiguous, or terminal commit is incomplete.
    pub fn dispatch_mount_request_and_commit(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mount: &mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
        catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<ProductionMountBrokerDispatchErrorV1>,
    > {
        match request.method() {
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1 => self
                .execute_mount_git_coverage_and_commit_v1(request, mount)
                .map_err(|failure| map_execution_failure(failure, Into::into)),
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
            | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
                // The remote provider has no attested physical class or
                // cross-process catalog authority yet.
                Err(before_effect_currentness(request))
            }
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

fn current_boottime_nanoseconds() -> Option<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanoseconds = u64::try_from(now.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

fn host_execution_spec_content_bytes(body: &[u8]) -> Option<u64> {
    let request = ApplyHostExecutionRequestV1::decode_from_slice(body).ok()?;
    let maximum = match request.spec_transfer_version {
        1 => aos_sandbox_protocol::host_execution::MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
        5 if request.action.as_known() == Some(
            aos_sandbox_api::aos::sandbox::local::v1::HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE,
        ) => aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5,
        _ => return None,
    } as u64;
    (request.canonical_execution_spec.is_empty()
        && request.spec_content_bytes != 0
        && request.spec_content_bytes <= maximum)
        .then_some(request.spec_content_bytes)
}

fn with_sealed_host_execution_content<R>(
    content_bytes: u64,
    descriptor: &OwnedFd,
    use_content: impl for<'content> FnOnce(&'content [u8]) -> R,
) -> Option<R> {
    let maximum = aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5 as u64;
    if content_bytes == 0 || content_bytes > maximum {
        return None;
    }

    // The broker validates the signed digest and attempt inside this mapping
    // before effect. No borrowed content can escape the descriptor's custody.
    let duplicate = rustix::io::dup(descriptor).ok()?;
    SealedMemfdMapping::run(duplicate, content_bytes, maximum, |content, _identity| {
        use_content(content)
    })
    .ok()
}

fn verify_argument_source_descriptor(
    request: &DormantReceivedBrokerRequestV1,
    descriptor: &std::os::fd::OwnedFd,
) -> bool {
    let Some(now) = current_boottime_nanoseconds() else {
        return false;
    };
    let Ok(decoded) = request.decode_host_runtime_argument_request(now) else {
        return false;
    };
    let Ok(boot) = KernelBootId::current() else {
        return false;
    };
    let Ok(duplicate) = rustix::io::dup(descriptor) else {
        return false;
    };

    matches!(
        SealedMemfdMapping::run(
            duplicate,
            decoded.content_fields().bytes(),
            aos_sandbox_protocol::host_argument_source::MAXIMUM_CONTROLLER_EXECUTION_ARGUMENT_SOURCE_BYTES_V1 as u64,
            |content, _identity| decoded.verify_source(content, boot.into_bytes(), now),
        ),
        Ok(Ok(_))
    )
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

#[cfg(test)]
mod execution_spec_content_tests {
    use std::time::{Duration, Instant};

    use aos_sandbox_api::aos::sandbox::local::v1::{
        Audience, BrokerDescriptorEntry, BrokerDescriptorRole, BrokerRequestEnvelope,
        QueryHostExecutionRequestV1, RequestHeader,
    };
    use aos_sandbox_model::runtime_backend::EffectOperationV1;
    use aos_sandbox_model::{ExecutionId, ObjectDigest};
    use aos_linux_descriptors::credential::SealedReadOnlyCredential;
    use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};
    use aos_sandbox_protocol::host_execution::{
        HOST_EXECUTION_CONTROL_CONTENT_V1, HostExecutionSpecContentFieldsV1,
        MAXIMUM_HOST_EXECUTION_SPEC_BYTES, decode_host_execution_apply_v1,
        decode_host_execution_query_v1, host_execution_spec_content_fields_v1,
    };
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn peer() -> (PeerCredentials, PeerPolicy) {
        (
            PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        )
    }

    fn header(request_id: [u8; 16]) -> RequestHeader {
        RequestHeader {
            protocol_major: 1,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 10,
            maximum_response_bytes: 4_096,
            ..Default::default()
        }
    }

    #[test]
    fn full_content_ceiling_crosses_one_small_host_frame_and_sealed_fd() {
        let content = vec![0xa5; MAXIMUM_HOST_EXECUTION_SPEC_BYTES];
        let fields = host_execution_spec_content_fields_v1(
            [1; 16],
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            EffectOperationV1::AuthorizeExecution,
            &content,
        )
        .unwrap();
        let body = ApplyHostExecutionRequestV1 {
            header: Some(header([1; 16])).into(),
            operation_id: vec![2; 16],
            execution_id: vec![3; 16],
            action: aos_sandbox_api::aos::sandbox::local::v1::HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE.into(),
            source_operation_commitment: vec![4; 32],
            spec_transfer_version: 1,
            spec_content_bytes: fields.bytes(),
            spec_content_digest: fields.digest().to_vec(),
            spec_attempt_commitment: fields.attempt_commitment().to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let frame = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION.into(),
            body,
            descriptors: vec![BrokerDescriptorEntry {
                index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_EXECUTION_SPEC.into(),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        assert!(frame.len() < 64 * 1024);

        let credential = SealedReadOnlyCredential::create(
            "host-execution-spec-maximum-test",
            &content,
            MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
        )
        .unwrap();
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender
            .send_with_descriptors(&frame, &[credential.as_fd()])
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let record = loop {
            match receiver.receive_with_optional_descriptor(64 * 1024) {
                Ok(record) => break record,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    assert!(
                        Instant::now() < deadline,
                        "Host descriptor receive timed out"
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("Host descriptor receive failed: {error}"),
            }
        };
        let (received, _, mut descriptors) = record.into_parts();
        let received = BrokerRequestEnvelope::decode_from_slice(&received).unwrap();
        assert_eq!(
            received.method.as_known(),
            Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION)
        );
        let (credentials, policy) = peer();
        let decoded =
            decode_host_execution_apply_v1(&received.body, credentials, policy, 1).unwrap();
        assert_eq!(decoded.content_bytes(), Some(fields.bytes()));
        assert_eq!(descriptors.len(), 1);
        let descriptor = descriptors.pop().unwrap();
        let content_bytes = host_execution_spec_content_bytes(&received.body).unwrap();
        let digest = with_sealed_host_execution_content(content_bytes, &descriptor, |bytes| {
            assert_eq!(bytes.len(), MAXIMUM_HOST_EXECUTION_SPEC_BYTES);
            <[u8; 32]>::from(Sha256::digest(bytes))
        })
        .unwrap();
        assert_eq!(digest, fields.digest());

        let mut changed_size =
            ApplyHostExecutionRequestV1::decode_from_slice(&received.body).unwrap();
        changed_size.spec_content_bytes -= 1;
        assert!(
            with_sealed_host_execution_content(
                changed_size.spec_content_bytes,
                &descriptor,
                |_| ()
            )
            .is_none()
        );
        changed_size.spec_content_bytes = MAXIMUM_HOST_EXECUTION_SPEC_BYTES as u64 + 1;
        assert!(host_execution_spec_content_bytes(&changed_size.encode_to_vec()).is_none());
        changed_size.spec_content_bytes = fields.bytes();
        changed_size.spec_transfer_version = 4;
        assert!(host_execution_spec_content_bytes(&changed_size.encode_to_vec()).is_none());
        changed_size.spec_transfer_version = 1;
        changed_size.canonical_execution_spec = vec![0];
        assert!(host_execution_spec_content_bytes(&changed_size.encode_to_vec()).is_none());
    }

    #[test]
    fn lifetime_descriptor_requires_authorize_and_its_complete_width() {
        use aos_sandbox_api::aos::sandbox::local::v1::HostExecutionActionV1;
        let maximum = aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5;
        let mut request = ApplyHostExecutionRequestV1 {
            action: HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE.into(),
            spec_transfer_version: 5,
            spec_content_bytes: maximum as u64,
            ..Default::default()
        };

        assert_eq!(host_execution_spec_content_bytes(&request.encode_to_vec()), Some(maximum as u64));
        request.spec_content_bytes += 1;
        assert!(host_execution_spec_content_bytes(&request.encode_to_vec()).is_none());
        request.spec_content_bytes = maximum as u64;
        request.action = HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE.into();
        assert!(host_execution_spec_content_bytes(&request.encode_to_vec()).is_none());
        request.action = HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE.into();
        request.spec_transfer_version = 3;
        assert!(host_execution_spec_content_bytes(&request.encode_to_vec()).is_none());
        for version in [2, 4, 6] {
            request.spec_transfer_version = version;
            assert!(host_execution_spec_content_bytes(&request.encode_to_vec()).is_none());
        }
    }

    #[test]
    fn control_descriptor_and_query_reject_changed_attempt_or_content() {
        let content = HOST_EXECUTION_CONTROL_CONTENT_V1;
        let execution = ExecutionId::from_bytes([3; 16]);
        let source = ObjectDigest::from_bytes([4; 32]);
        let fields = host_execution_spec_content_fields_v1(
            [1; 16],
            [2; 16],
            execution,
            source,
            EffectOperationV1::Cancel,
            content,
        )
        .unwrap();
        let body = ApplyHostExecutionRequestV1 {
            header: Some(header([1; 16])).into(),
            operation_id: vec![2; 16],
            execution_id: vec![3; 16],
            action: aos_sandbox_api::aos::sandbox::local::v1::HostExecutionActionV1::HOST_EXECUTION_ACTION_CANCEL.into(),
            source_operation_commitment: vec![4; 32],
            spec_transfer_version: 1,
            spec_content_bytes: fields.bytes(),
            spec_content_digest: fields.digest().to_vec(),
            spec_attempt_commitment: fields.attempt_commitment().to_vec(),
            ..Default::default()
        };
        let credential =
            SealedReadOnlyCredential::create("host-execution-control-test", content, 1).unwrap();
        let descriptor = rustix::io::dup(credential.as_fd()).unwrap();
        let (credentials, policy) = peer();
        let mut request =
            decode_host_execution_apply_v1(&body.encode_to_vec(), credentials, policy, 1).unwrap();

        assert_eq!(
            with_sealed_host_execution_content(fields.bytes(), &descriptor, |bytes| {
                request.verify_content(bytes)
            }),
            Some(Ok(()))
        );
        let mut changed_attempt = body.clone();
        changed_attempt.header = Some(header([9; 16])).into();
        assert!(
            decode_host_execution_apply_v1(
                &changed_attempt.encode_to_vec(),
                credentials,
                policy,
                1
            )
            .is_err()
        );

        let changed =
            SealedReadOnlyCredential::create("host-execution-control-changed", &[1], 1).unwrap();
        let changed_descriptor = rustix::io::dup(changed.as_fd()).unwrap();
        let mut same_request =
            decode_host_execution_apply_v1(&body.encode_to_vec(), credentials, policy, 1).unwrap();
        assert!(
            with_sealed_host_execution_content(fields.bytes(), &changed_descriptor, |bytes| {
                same_request.verify_content(bytes)
            })
            .unwrap()
            .is_err()
        );

        let query_fields = HostExecutionSpecContentFieldsV1::for_grant(content)
            .bind_query_attempt_v2(
                [5; 16],
                [2; 16],
                execution,
                source,
                ObjectDigest::from_bytes([6; 32]),
            );
        let query = QueryHostExecutionRequestV1 {
            header: Some(header([5; 16])).into(),
            operation_id: vec![2; 16],
            execution_id: vec![3; 16],
            source_operation_commitment: vec![4; 32],
            spec_transfer_version: 1,
            query_binding_version: 2,
            execution_spec_digest: vec![6; 32],
            spec_content_bytes: query_fields.bytes(),
            spec_content_digest: query_fields.digest().to_vec(),
            spec_attempt_commitment: query_fields.attempt_commitment().to_vec(),
            ..Default::default()
        };
        let decoded =
            decode_host_execution_query_v1(&query.encode_to_vec(), credentials, policy, 1).unwrap();
        assert_eq!(decoded.content_fields().digest(), fields.digest());
        let mut replayed_query = query;
        replayed_query.header = Some(header([6; 16])).into();
        assert!(
            decode_host_execution_query_v1(&replayed_query.encode_to_vec(), credentials, policy, 1)
                .is_err()
        );
    }
}
