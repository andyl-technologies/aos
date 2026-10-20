//! Protected Host catalog publication and exact ambiguous-effect custody.
//!
//! This owner keeps the received catalog descriptor, intended snapshot, and
//! publication result together across execution, locked physical readback,
//! proven-absent retry, and protected response commit. Only the existing
//! authenticated session recipes can mint its opaque recovery and retry states.
//! Shared session admission, signing, transport, and replay stay in the parent.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorDisposition, BrokerDescriptorDispositionEntry, BrokerDescriptorRole,
    BrokerMethod, BrokerResponseEnvelope, HostCatalogPublicationStatus, PublishHostCatalogResponse,
};
use aos_sandbox_core::ProtocolVersion;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_BYTES;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerExecutionErrorV1, DormantBrokerFailureV1,
    DormantReceivedBrokerDescriptorRequestV1, DormantReceivedBrokerRequestV1,
    current_publication_boottime,
};
use crate::{BrokerSessionSecurityError, ProtectedBrokerOutcomeCommitResultV1};

/// Retains the catalog descriptor request across publication execution failure.
#[must_use = "retain or explicitly resolve the exact publication custody"]
pub enum DormantBrokerPublicationExecutionFailureV1<Domain> {
    /// No publisher was invoked; the exact request and descriptor remain owned.
    BeforeEffect {
        error: BrokerSessionSecurityError,
        request: DormantReceivedBrokerDescriptorRequestV1,
    },
    /// The genuine native callee refused; its whole owner remains on Host.
    NativeRefused {
        /// Preserves the coarse call boundary while Host keeps the exact cause.
        error: DormantBrokerExecutionErrorV1<Domain>,
        /// Keeps the actual authenticated request and received descriptor.
        request: DormantReceivedBrokerDescriptorRequestV1,
    },
    /// Publication dispatch began; only protected readback may resolve the request.
    OutcomeUnknown {
        error: DormantBrokerExecutionErrorV1<Domain>,
        recovery: DormantHostCatalogPublicationUnknownV1,
    },
}

/// Retains exact Host catalog effect custody until physical readback resolves it.
#[must_use = "resolve the exact physical publication or retain its custody"]
pub struct DormantHostCatalogPublicationUnknownV1 {
    request: DormantReceivedBrokerRequestV1,
    descriptor: Option<OwnedFd>,
    native_completed: Option<aos_sandbox_host::catalog::HostCatalogPublicationCompletedV2>,
    snapshot: aos_sandbox_protocol::HostCatalogSnapshot,
    intended_bytes: u64,
    intended_generation: u64,
    intended_digest: aos_sandbox_core::ObjectDigest,
    known_status: Option<HostCatalogPublicationStatus>,
}

/// Authorizes one retry only after protected readback proved the effect absent.
#[must_use = "retry the exact proven-absent publication or retain its custody"]
pub struct DormantHostCatalogPublicationRetryV1(DormantHostCatalogPublicationUnknownV1);

/// Reports physical resolution of one ambiguous Host catalog publication.
#[must_use = "commit the response, retry the exact absent effect, or retain recovery custody"]
pub enum DormantHostCatalogPublicationRecoveryProgressV1 {
    /// Physical readback proved the intended catalog committed; response commit advanced.
    ResponseCommit(ProtectedBrokerOutcomeCommitResultV1),
    /// Physical readback proved the intended effect absent and retry-safe.
    RetrySafe(DormantHostCatalogPublicationRetryV1),
}

fn validated_publication_snapshot(
    descriptor: &OwnedFd,
    expected_bytes: u64,
    expected_generation: u64,
    expected_digest: aos_sandbox_core::ObjectDigest,
) -> Result<aos_sandbox_protocol::HostCatalogSnapshot, aos_sandbox_host::DormantHostBrokerCallErrorV1>
{
    let duplicate = rustix::io::dup(descriptor)
        .map_err(|error| aos_sandbox_host::HostError::Catalog(error.to_string()))?;
    SealedMemfdMapping::run(
        duplicate,
        expected_bytes,
        u64::try_from(MAXIMUM_HOST_CATALOG_BYTES)
            .map_err(|_| aos_sandbox_host::DormantHostBrokerCallErrorV1::StaleKernel)?,
        |catalog, _identity| {
            let digest = aos_sandbox_core::ObjectDigest::from_bytes(Sha256::digest(catalog).into());
            if digest != expected_digest {
                return Err(aos_sandbox_host::HostError::Catalog(
                    "sealed host catalog digest does not match request".to_owned(),
                ));
            }
            let snapshot = aos_sandbox_protocol::HostCatalogSnapshot::decode_canonical(catalog)?;
            if snapshot.generation() != expected_generation {
                return Err(aos_sandbox_host::HostError::Catalog(
                    "sealed host catalog generation does not match request".to_owned(),
                ));
            }
            Ok(snapshot)
        },
    )
    .map_err(|error| aos_sandbox_host::HostError::Catalog(error.to_string()))?
    .map_err(Into::into)
}

fn publication_response_body(
    generation: u64,
    digest: aos_sandbox_core::ObjectDigest,
    status: HostCatalogPublicationStatus,
) -> Vec<u8> {
    PublishHostCatalogResponse {
        status: status.into(),
        generation,
        catalog_sha256: digest.as_bytes().to_vec(),
        ..Default::default()
    }
    .encode_to_vec()
}

impl DormantAuthenticatedBrokerSessionV1 {

    /// Executes the installed publication through the real consumed Host owner.
    ///
    /// # Errors
    /// Keeps the exact request on native refusal and the actual completed
    /// publication on response-commit refusal. It never invokes ordinary
    /// unpriced ambiguity readback after an entered Host native failure.
    pub async fn execute_original_host_catalog_publication_and_commit_v2(
        &mut self, request: DormantReceivedBrokerDescriptorRequestV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>>
    {
        if request.request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || request.request.authorization().is_some() || request.descriptors.len() != 1
            || request.request.host_catalog_publication_data_v2().is_none()
        {
            return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness, request,
            });
        }
        let mut currentness: Option<Result<(), BrokerSessionSecurityError>> = None;
        let mut pending_guard = || {
            currentness = Some((|| {
                let (gate, context) = self.0.reopen_broker_outcome(&request.request)?;
                drop(gate);
                let publication = request.request.host_catalog_publication_data_v2()
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                if publication.header().request_id() != &request.request.request_id()
                    || publication.header().protocol_version() !=
                        ProtocolVersion::new(context.protocol_major(), context.protocol_minor())
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                // The callee's retained paired samples enforce the same
                // absolute Header deadline before write/rename and after posts.
                Ok(())
            })());
            if matches!(currentness, Some(Ok(()))) { Ok(()) }
            else { Err(aos_sandbox_host::HostError::Fence(
                "Host catalog pending Session refused; exact Security cause retained")) }
        };
        let outcome = match host.borrow_catalog_publication_v2() {
            Ok(mut original) => original.publish_once_v2(
                &request.request, publisher, &request.descriptors[0], &mut pending_guard).await,
            Err(cause) => {
                drop(pending_guard);
                return Err(DormantBrokerPublicationExecutionFailureV1::NativeRefused {
                    error: DormantBrokerExecutionErrorV1::Domain(cause), request,
                });
            }
        };
        drop(pending_guard);
        let mut completed = match outcome {
            Ok(completed) => completed,
            Err(cause) => return Err(DormantBrokerPublicationExecutionFailureV1::NativeRefused {
                error: match currentness {
                    Some(Err(cause)) => DormantBrokerExecutionErrorV1::Currentness(cause),
                    _ => DormantBrokerExecutionErrorV1::Domain(cause.into()),
                },
                request,
            }),
        };
        let publication = match request.request.host_catalog_publication_data_v2() {
            Some(publication) => publication,
            None => return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness, request,
            }),
        };
        let intended_bytes = publication.catalog_bytes();
        let intended_generation = publication.catalog_generation();
        let intended_digest = publication.catalog_digest();
        let status = match completed.outcome_v2() {
            aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Published =>
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED,
            aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Replay =>
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY,
        };
        let snapshot = match completed.take_snapshot_v2() {
            Some(snapshot) => snapshot,
            None => return Err(DormantBrokerPublicationExecutionFailureV1::NativeRefused {
                error: DormantBrokerExecutionErrorV1::Domain(
                    aos_sandbox_host::HostError::Fence("Host catalog completion was already consumed").into()),
                request,
            }),
        };
        let DormantReceivedBrokerDescriptorRequestV1 { request, descriptors } = request;
        // All local copies of this sole received role are physically closed
        // before signing its CLOSED disposition. The native owner already
        // unmapped and closed its own positively validated input duplicate.
        drop(descriptors);
        let custody = DormantHostCatalogPublicationUnknownV1 {
            request: DormantReceivedBrokerRequestV1(request),
            descriptor: None, native_completed: Some(completed), snapshot,
            intended_bytes, intended_generation, intended_digest, known_status: Some(status),
        };
        self.commit_host_catalog_publication(&custody, status)
            .map_err(|error| DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error), recovery: custody,
            })
    }

    /// Publishes one sealed Host catalog before signing its exact result.
    ///
    /// # Errors
    ///
    /// Returns a domain or protected-currentness error without signing success
    /// unless the exact request descriptor is consumed by the fixed publisher.
    pub fn execute_host_catalog_publication_and_commit(
        &mut self,
        request: DormantReceivedBrokerDescriptorRequestV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        if request.request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || request.request.authorization().is_some()
            || request.descriptors.len() != 1
        {
            return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                error: BrokerSessionSecurityError::Currentness,
                request,
            });
        }
        let context = match self.0.reopen_broker_outcome(&request.request) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let now = match current_publication_boottime(&request.request, &context) {
            Ok(now) => now,
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error,
                    request,
                });
            }
        };
        let publication =
            match aos_sandbox_protocol::host_catalog::decode_host_catalog_publication_request(
                request.request.exact_body(),
                request.request.peer(),
                request.request.peer_policy(),
                now,
            ) {
                Ok(publication)
                    if publication.header().request_id() == &request.request.request_id()
                        && publication.header().protocol_version() == version =>
                {
                    publication
                }
                _ => {
                    return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                        error: BrokerSessionSecurityError::Currentness,
                        request,
                    });
                }
            };
        let descriptor = &request.descriptors[0];
        let snapshot = match validated_publication_snapshot(
            descriptor,
            publication.catalog_bytes(),
            publication.catalog_generation(),
            publication.catalog_digest(),
        ) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error: BrokerSessionSecurityError::Currentness,
                    request,
                });
            }
        };
        let outcome = publisher.publish(&snapshot);
        let DormantReceivedBrokerDescriptorRequestV1 {
            request: authenticated_request,
            mut descriptors,
        } = request;
        let descriptor = descriptors.remove(0);
        let mut custody = DormantHostCatalogPublicationUnknownV1 {
            request: DormantReceivedBrokerRequestV1(authenticated_request),
            descriptor: Some(descriptor),
            native_completed: None,
            snapshot,
            intended_bytes: publication.catalog_bytes(),
            intended_generation: publication.catalog_generation(),
            intended_digest: publication.catalog_digest(),
            known_status: None,
        };
        let status = match outcome {
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Published) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
            }
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Replay) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error.into()),
                    recovery: custody,
                });
            }
        };
        custody.known_status = Some(status);
        match self.commit_host_catalog_publication(&custody, status) {
            Ok(committed) => Ok(committed),
            Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                recovery: custody,
            }),
        }
    }

    /// Resolves an ambiguous Host catalog effect without redispatching it.
    ///
    /// # Errors
    ///
    /// Returns the unchanged recovery custody when descriptor, session,
    /// deadline, fixed-root readback, or visible catalog state is indeterminate.
    pub fn recover_host_catalog_publication(
        &mut self,
        recovery: DormantHostCatalogPublicationUnknownV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<
        DormantHostCatalogPublicationRecoveryProgressV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        if recovery.native_completed.is_some() {
            // Only this private completed native owner can omit the already
            // closed input descriptor. It authorizes response recovery only.
            let Some(status) = recovery.known_status else {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(BrokerSessionSecurityError::Currentness),
                    recovery,
                });
            };
            return self.commit_host_catalog_publication(&recovery, status)
                .map(DormantHostCatalogPublicationRecoveryProgressV1::ResponseCommit)
                .map_err(|error| DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(error), recovery,
                });
        }
        if recovery.descriptor.as_ref().is_none_or(|descriptor| validated_publication_snapshot(
            descriptor, recovery.intended_bytes, recovery.intended_generation, recovery.intended_digest,
        ).is_err())
        {
            return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(
                    BrokerSessionSecurityError::Currentness,
                ),
                recovery,
            });
        }
        if let Some(status) = recovery.known_status {
            return match self.commit_host_catalog_publication(&recovery, status) {
                Ok(committed) => {
                    Ok(DormantHostCatalogPublicationRecoveryProgressV1::ResponseCommit(committed))
                }
                Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(error),
                    recovery,
                }),
            };
        }
        let readback = match publisher.resolve_ambiguous_publication(&recovery.snapshot) {
            Ok(readback) => readback,
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error.into()),
                    recovery,
                });
            }
        };
        match readback {
            aos_sandbox_host::catalog::HostCatalogPublicationReadback::Committed => {
                match self.commit_host_catalog_publication(
                    &recovery,
                    HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED,
                ) {
                    Ok(committed) => Ok(
                        DormantHostCatalogPublicationRecoveryProgressV1::ResponseCommit(committed),
                    ),
                    Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                        error: DormantBrokerExecutionErrorV1::Currentness(error),
                        recovery,
                    }),
                }
            }
            aos_sandbox_host::catalog::HostCatalogPublicationReadback::Absent => {
                let context = match self.0.reopen_broker_outcome(&recovery.request.0) {
                    Ok((gate, context)) => {
                        drop(gate);
                        context
                    }
                    Err(error) => {
                        return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                            error: DormantBrokerExecutionErrorV1::Currentness(error),
                            recovery,
                        });
                    }
                };
                if let Err(error) = current_publication_boottime(&recovery.request.0, &context) {
                    return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                        error: DormantBrokerExecutionErrorV1::Currentness(error),
                        recovery,
                    });
                }
                Ok(DormantHostCatalogPublicationRecoveryProgressV1::RetrySafe(
                    DormantHostCatalogPublicationRetryV1(recovery),
                ))
            }
            aos_sandbox_host::catalog::HostCatalogPublicationReadback::Conflicting => {
                Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Currentness(
                        BrokerSessionSecurityError::Currentness,
                    ),
                    recovery,
                })
            }
        }
    }

    /// Retries only a publication whose protected readback proved it absent.
    ///
    /// # Errors
    ///
    /// Returns pre-effect custody after lost currentness, or exact ambiguity
    /// custody if the fixed publisher begins the retry without a durable result.
    pub fn retry_absent_host_catalog_publication(
        &mut self,
        retry: DormantHostCatalogPublicationRetryV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerPublicationExecutionFailureV1<aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    > {
        let custody = retry.0;
        let context = match self.0.reopen_broker_outcome(&custody.request.0) {
            Ok((gate, context)) => {
                drop(gate);
                context
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                    error,
                    request: DormantReceivedBrokerDescriptorRequestV1 {
                        request: custody.request.0,
                        descriptors: custody.descriptor.into_iter().collect(),
                    },
                });
            }
        };
        if let Err(error) = current_publication_boottime(&custody.request.0, &context) {
            return Err(DormantBrokerPublicationExecutionFailureV1::BeforeEffect {
                error,
                request: DormantReceivedBrokerDescriptorRequestV1 {
                    request: custody.request.0,
                    descriptors: custody.descriptor.into_iter().collect(),
                },
            });
        }
        let status = match publisher.publish(&custody.snapshot) {
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Published) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
            }
            Ok(aos_sandbox_host::catalog::HostCatalogPublicationOutcome::Replay) => {
                HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY
            }
            Err(error) => {
                return Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                    error: DormantBrokerExecutionErrorV1::Domain(error.into()),
                    recovery: custody,
                });
            }
        };
        let mut custody = custody;
        custody.known_status = Some(status);
        match self.commit_host_catalog_publication(&custody, status) {
            Ok(committed) => Ok(committed),
            Err(error) => Err(DormantBrokerPublicationExecutionFailureV1::OutcomeUnknown {
                error: DormantBrokerExecutionErrorV1::Currentness(error),
                recovery: custody,
            }),
        }
    }

    fn commit_host_catalog_publication(
        &mut self,
        custody: &DormantHostCatalogPublicationUnknownV1,
        status: HostCatalogPublicationStatus,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        let (gate, context) = self.0.reopen_broker_outcome(&custody.request.0)?;
        drop(gate);
        current_publication_boottime(&custody.request.0, &context)?;
        let body =
            publication_response_body(custody.intended_generation, custody.intended_digest, status);
        let message = BrokerResponseEnvelope {
            request_id: custody.request.0.request_id().to_vec(),
            method: custody.request.0.method().into(),
            body,
            request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
                request_index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG.into(),
                disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                    .into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pending = self.0.prepare_broker_outcome(&custody.request.0, message)?;
        Ok(self.0.commit_broker_outcome(pending))
    }

    /// Commits a terminal error for a rejected Host catalog descriptor request.
    ///
    /// The sole received descriptor is closed before terminal preparation, and
    /// the signed response records its exact Host-catalog role and closed
    /// disposition. This method cannot terminalize a request after publication
    /// dispatch has begun.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request is exactly `Host.PublishCatalog`
    /// with one descriptor and the protected terminal error can be prepared.
    pub fn commit_authenticated_publication_error_response(
        &mut self,
        request: DormantReceivedBrokerDescriptorRequestV1,
        failure: DormantBrokerFailureV1,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, BrokerSessionSecurityError> {
        if request.request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || request.descriptors.len() != 1
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let DormantReceivedBrokerDescriptorRequestV1 {
            request,
            descriptors,
        } = request;
        drop(descriptors);
        let message = BrokerResponseEnvelope {
            request_id: request.request_id().to_vec(),
            method: request.method().into(),
            error: Some(failure.error()?).into(),
            request_descriptor_dispositions: vec![BrokerDescriptorDispositionEntry {
                request_index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG.into(),
                disposition: BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
                    .into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pending = self.0.prepare_broker_outcome(&request, message)?;
        Ok(self.0.commit_broker_outcome(pending))
    }
}
