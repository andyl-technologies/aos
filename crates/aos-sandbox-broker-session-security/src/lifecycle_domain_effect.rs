//! Protected Storage, Mount, and Network lifecycle effect exchanges.
//!
//! This dormant adapter owns the authenticated client session from the exact
//! effect request through its immediately adjacent complete inventory query.
//! Durable outcome ambiguity retains a move-only continuation and never
//! repeats the lower-domain effect.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerMethod, BrokerRequestEnvelope, InventoryMountsRequest,
    InventoryNetworksRequest, InventoryStorageRequest, RequestHeader,
};
use aos_sandbox::lifecycle::{
    CurrentLifecycleEffectV1, LifecycleBootBootstrapEndpointV1,
    LifecycleBootInventoryBootstrapChallengeV1, LifecycleEffectObservationV1,
    LifecyclePhase6ErrorV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use buffa::Message as _;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestCoordinatesV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1, DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerRequestV1, DormantUnconfirmedBrokerRequestV1,
    ProtectedBrokerOutcomeCommitRecoveryV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerSessionInitializationRecoveryV1,
};

/// Reports a completed observation or retained exact durable recovery custody.
#[must_use = "consume the observation or retain and recover the exact exchange"]
pub enum DormantLifecycleDomainEffectProgressV1<'lifecycle> {
    /// The fixed endpoint authenticated the complete effect and readback pair.
    Observed(LifecycleEffectObservationV1),
    /// Exact preparation, transport, or commit custody must be resumed.
    RecoveryRequired(DormantLifecycleDomainEffectRecoveryV1<'lifecycle>),
}

/// Retains one exact Storage, Mount, or Network exchange across every boundary.
#[must_use = "resume recovery through the same protected session owner"]
pub struct DormantLifecycleDomainEffectRecoveryV1<'lifecycle> {
    stage: RecoveryStageV1<'lifecycle>,
}

enum ExchangeStageV1<'lifecycle> {
    Effect {
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
    },
    Inventory {
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
    },
}

impl ExchangeStageV1<'_> {
    const fn is_effect(&self) -> bool {
        matches!(self, Self::Effect { .. })
    }

    fn effect(&self) -> &CurrentLifecycleEffectV1<'_> {
        match self {
            Self::Effect { effect, .. } | Self::Inventory { effect, .. } => effect,
        }
    }
}

enum RecoveryStageV1<'lifecycle> {
    Initialization {
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Successor {
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Send {
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        prepared: DormantPreparedBrokerRequestV1,
    },
    Receive {
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        outstanding: DormantOutstandingBrokerRequestV1,
    },
    Commit {
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    },
}

/// Owns one fixed protected broker session for dormant lifecycle effects.
#[must_use = "retain the protected session through effect readback and recovery"]
pub struct DormantLifecycleDomainEffectOwnerV1 {
    session: DormantAuthenticatedBrokerSessionV1,
}

impl DormantLifecycleDomainEffectOwnerV1 {
    /// Couples a completed fixed-custody session to lifecycle effect exchange.
    #[must_use]
    pub fn from_protected_session(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self { session }
    }

    /// Sends one exact Mount Apply and immediately queries complete Mount state.
    ///
    /// # Errors
    ///
    /// Returns an error before observation minting for malformed request,
    /// transport backpressure, a stale endpoint, or a noncanonical response.
    pub fn observe_mount<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        self.begin(
            challenge,
            LifecycleBootBootstrapEndpointV1::Mount,
            effect,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            build,
        )
    }

    /// Sends one exact Mount destination-slot Apply and queries complete Mount state.
    ///
    /// # Errors
    ///
    /// Returns an error before observation minting for malformed request,
    /// transport backpressure, a stale endpoint, or a noncanonical response.
    pub fn observe_mount_destination_slot<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        self.begin(
            challenge,
            LifecycleBootBootstrapEndpointV1::Mount,
            effect,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
            build,
        )
    }

    /// Sends one exact Network Apply and immediately queries complete Network state.
    ///
    /// # Errors
    ///
    /// Returns an error before observation minting for malformed request,
    /// transport backpressure, a stale endpoint, or a noncanonical response.
    pub fn observe_network<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        self.begin(
            challenge,
            LifecycleBootBootstrapEndpointV1::Network,
            effect,
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            build,
        )
    }

    /// Sends one exact Storage Apply and queries the complete five-family state.
    ///
    /// # Errors
    ///
    /// Returns an error before dispatch for a request that differs from the
    /// lifecycle compiler, or later for protected recovery or bad readback.
    pub fn observe_storage<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        self.begin(
            challenge,
            LifecycleBootBootstrapEndpointV1::Storage,
            effect,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            build,
        )
    }

    /// Resumes any retained protected-session stage without rebuilding a request.
    ///
    /// # Errors
    ///
    /// Returns an error if the protected session can no longer recover the
    /// retained exact stage or the following inventory exchange fails.
    pub fn recover<'lifecycle>(
        &mut self,
        retained: DormantLifecycleDomainEffectRecoveryV1<'lifecycle>,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        match retained.stage {
            RecoveryStageV1::Initialization {
                exchange,
                method,
                recovery,
                request,
            } => match self
                .session
                .recover_prepared_initialization(recovery, request)
            {
                DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                    self.send_query(exchange, method, prepared)
                }
                DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => Ok(recovery_required(RecoveryStageV1::Initialization {
                    exchange,
                    method,
                    recovery,
                    request,
                })),
                DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { .. } => {
                    Err(LifecyclePhase6ErrorV1::StaleAuthority)
                }
            },
            RecoveryStageV1::Successor {
                exchange,
                method,
                recovery,
                request,
            } => match self.session.recover_prepared_successor(recovery, request) {
                DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                    self.send_query(exchange, method, prepared)
                }
                DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => Ok(recovery_required(RecoveryStageV1::Successor {
                    exchange,
                    method,
                    recovery,
                    request,
                })),
                DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { .. } => {
                    Err(LifecyclePhase6ErrorV1::StaleAuthority)
                }
            },
            RecoveryStageV1::Send {
                exchange,
                method,
                prepared,
            } => self.send_query(exchange, method, prepared),
            RecoveryStageV1::Receive {
                exchange,
                method,
                outstanding,
            } => self.receive_query(exchange, method, outstanding),
            RecoveryStageV1::Commit {
                exchange,
                method,
                recovery,
            } => match self.session.recover_broker_outcome_commit(recovery) {
                ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                    let (outcome, currentness) = committed.into_outcome_and_currentness();
                    if outcome.method() != method {
                        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
                    }
                    self.complete_query(exchange, outcome, currentness)
                }
                ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                    Ok(recovery_required(RecoveryStageV1::Commit {
                        exchange,
                        method,
                        recovery,
                    }))
                }
            },
        }
    }

    fn begin<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        method: BrokerMethod,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        let exchange = ExchangeStageV1::Effect {
            challenge,
            endpoint,
            effect,
        };
        self.prepare_query(exchange, method, build)
    }

    fn finish_effect<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        let method = match endpoint {
            LifecycleBootBootstrapEndpointV1::Storage => {
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            }
            LifecycleBootBootstrapEndpointV1::Mount => {
                BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
            }
            LifecycleBootBootstrapEndpointV1::Network => {
                BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
            }
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        let exchange = ExchangeStageV1::Inventory {
            challenge,
            endpoint,
            effect,
            outcome,
        };
        self.prepare_query(exchange, method, move |coordinates| {
            inventory_envelope(endpoint, coordinates)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_inventory<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        inventory: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        let mut current = self
            .session
            .revalidate_broker_outcome(currentness)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        current
            .revalidate()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        drop(current);
        let message =
            challenge.broker_effect_signing_message(endpoint, &effect, &outcome, &inventory)?;
        let signature = self
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        effect
            .observe_fixed_broker_effect(&challenge, endpoint, &outcome, &inventory, signature)
            .map(DormantLifecycleDomainEffectProgressV1::Observed)
    }

    fn prepare_query<'lifecycle>(
        &mut self,
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        build: impl FnOnce(DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        let prepared = self
            .session
            .prepare_authenticated_request_checked(method, build, |request| {
                !exchange.is_effect()
                    || exchange
                        .effect()
                        .validate_authenticated_broker_request(request)
                        .is_ok()
            })
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        match prepared {
            DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                self.send_query(exchange, method, prepared)
            }
            DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                recovery,
                request,
                ..
            } => Ok(recovery_required(RecoveryStageV1::Initialization {
                exchange,
                method,
                recovery,
                request,
            })),
            DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                recovery,
                request,
                ..
            } => Ok(recovery_required(RecoveryStageV1::Successor {
                exchange,
                method,
                recovery,
                request,
            })),
        }
    }

    fn send_query<'lifecycle>(
        &mut self,
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        prepared: DormantPreparedBrokerRequestV1,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        match self
            .session
            .send_authenticated_request(prepared)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        {
            DormantBrokerRequestSendProgressV1::Pending(prepared) => {
                Ok(recovery_required(RecoveryStageV1::Send {
                    exchange,
                    method,
                    prepared,
                }))
            }
            DormantBrokerRequestSendProgressV1::Sent(outstanding) => {
                self.receive_query(exchange, method, outstanding)
            }
        }
    }

    fn receive_query<'lifecycle>(
        &mut self,
        exchange: ExchangeStageV1<'lifecycle>,
        method: BrokerMethod,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        match self
            .session
            .receive_authenticated_response(outstanding)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        {
            DormantBrokerResponseProgressV1::Pending(outstanding) => {
                Ok(recovery_required(RecoveryStageV1::Receive {
                    exchange,
                    method,
                    outstanding,
                }))
            }
            DormantBrokerResponseProgressV1::Committed(
                ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
            ) => {
                let (outcome, currentness) = committed.into_outcome_and_currentness();
                self.complete_query(exchange, outcome, currentness)
            }
            DormantBrokerResponseProgressV1::Committed(
                ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. },
            ) => Ok(recovery_required(RecoveryStageV1::Commit {
                exchange,
                method,
                recovery,
            })),
        }
    }

    fn complete_query<'lifecycle>(
        &mut self,
        exchange: ExchangeStageV1<'lifecycle>,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<DormantLifecycleDomainEffectProgressV1<'lifecycle>, LifecyclePhase6ErrorV1> {
        match exchange {
            ExchangeStageV1::Effect {
                challenge,
                endpoint,
                effect,
            } => {
                let mut current = self
                    .session
                    .revalidate_broker_outcome(currentness)
                    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
                current
                    .revalidate()
                    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
                drop(current);
                self.finish_effect(challenge, endpoint, effect, outcome)
            }
            ExchangeStageV1::Inventory {
                challenge,
                endpoint,
                effect,
                outcome: effect_outcome,
            } => self.finish_inventory(
                challenge,
                endpoint,
                effect,
                effect_outcome,
                outcome,
                currentness,
            ),
        }
    }
}

fn recovery_required<'lifecycle>(
    stage: RecoveryStageV1<'lifecycle>,
) -> DormantLifecycleDomainEffectProgressV1<'lifecycle> {
    DormantLifecycleDomainEffectProgressV1::RecoveryRequired(
        DormantLifecycleDomainEffectRecoveryV1 { stage },
    )
}

fn inventory_envelope(
    endpoint: LifecycleBootBootstrapEndpointV1,
    coordinates: DormantBrokerRequestCoordinatesV1,
) -> BrokerRequestEnvelope {
    let version = coordinates.protocol_version();
    let header = Some(RequestHeader {
        protocol_major: version.major().into(),
        protocol_minor: version.minor().into(),
        request_id: coordinates.request_id().to_vec(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
        maximum_response_bytes: coordinates.maximum_response_bytes(),
        ..Default::default()
    })
    .into();
    let (method, body) = match endpoint {
        LifecycleBootBootstrapEndpointV1::Storage => (
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            InventoryStorageRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        LifecycleBootBootstrapEndpointV1::Mount => (
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
            InventoryMountsRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        LifecycleBootBootstrapEndpointV1::Network => (
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            InventoryNetworksRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        _ => (BrokerMethod::BROKER_METHOD_UNSPECIFIED, Vec::new()),
    };
    BrokerRequestEnvelope {
        method: method.into(),
        body,
        ..Default::default()
    }
}
