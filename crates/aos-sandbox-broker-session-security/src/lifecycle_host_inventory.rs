//! Protected lifecycle inventory queries over live broker sessions.
//!
//! The concrete owners issue fresh Host, Storage, Mount, or Network inventory requests through
//! the repository-owned authenticated post-handshake exchange. No callback,
//! request identifier, sequence, packet, signer, or trust policy is supplied
//! by the caller.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerMethod, BrokerRequestEnvelope, InventoryDestinationSlotsRequest,
    InventoryMountSourceAcquisitionsRequest, InventoryMountsRequest, InventoryNetworksRequest,
    InventoryRuntimeRequest, InventoryStorageRequest, RequestHeader,
};
use aos_sandbox::attachment_source::{
    AttachmentSourceAttemptKindV1, DurableCurrentAttachmentSourceDispatchV1,
};
use aos_sandbox::lifecycle::{
    CurrentLifecycleBootInventoryV1, CurrentLifecycleEffectV1, CurrentLifecycleOperationV1,
    LifecycleAtomicDatasetSnapshotPlanV1, LifecycleAuthenticatedAtomicStorageSuccessorV1,
    LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
    LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecycleAuthenticatedBrokerEffectV1,
    LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
    LifecycleAuthenticatedRuntimeInventorySuccessorV1,
    LifecycleAuthenticatedStorageInventoryBootstrapV1,
    LifecycleAuthenticatedStorageInventorySuccessorV1, LifecycleAuthenticatedStorageInventoryV1,
    LifecycleAuthenticatedStorageReadbackV1, LifecycleBootBootstrapEndpointV1,
    LifecycleBootInventoryBootstrapChallengeV1, LifecyclePhase6ErrorV1, LiveRuntimeFenceV1,
};
use aos_sandbox::mount_attempt::DurableCurrentMountAttemptV1;
use aos_sandbox::mount_preparation::PreparedCurrentMountCatalogQueryV1;
use aos_sandbox::{
    DurableCurrentDestinationSlotAttemptV1, EffectFailure, PreparedAuthorityEffectV1,
    ValidatedAuthorityEffectReceiptV1,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1;
use buffa::Message as _;

use crate::controller_authority_effect::ControllerAuthorityEffectExchangeV1;
use crate::recovery::{
    ProtectedPriorAtomicStorageHistoryV1, ProtectedVerifiedAtomicStorageHistoryV1,
};
use crate::{
    AuthenticatedStorageCreatePreparationV1, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1, DormantBrokerRequestPreparationV1,
    DormantBrokerRequestSendProgressV1, DormantBrokerResponseProgressV1,
    DormantOutstandingBrokerRequestV1, DormantPreparedBrokerRequestV1,
    DormantUnconfirmedBrokerRequestV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerSessionInitializationRecoveryV1,
};

#[derive(Clone, Copy)]
enum LifecycleInventoryMethodV1 {
    Host,
    Mount,
    MountSources,
    DestinationSlots,
    Network,
    Storage,
}

impl LifecycleInventoryMethodV1 {
    const fn method(self) -> BrokerMethod {
        match self {
            Self::Host => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            Self::Mount => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
            Self::MountSources => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS,
            Self::DestinationSlots => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            Self::Network => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            Self::Storage => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        }
    }

    fn envelope(self, coordinates: DormantBrokerRequestCoordinatesV1) -> BrokerRequestEnvelope {
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
        let body = match self {
            Self::Host => InventoryRuntimeRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
            Self::Mount => InventoryMountsRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
            Self::MountSources => InventoryMountSourceAcquisitionsRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
            Self::DestinationSlots => InventoryDestinationSlotsRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
            Self::Network => InventoryNetworksRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
            Self::Storage => InventoryStorageRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
        };
        BrokerRequestEnvelope {
            method: self.method().into(),
            body,
            ..Default::default()
        }
    }
}

fn endpoint_for_inventory_method(
    method: LifecycleInventoryMethodV1,
) -> Result<LifecycleBootBootstrapEndpointV1, LifecyclePhase6ErrorV1> {
    match method {
        LifecycleInventoryMethodV1::Mount => Ok(LifecycleBootBootstrapEndpointV1::Mount),
        LifecycleInventoryMethodV1::Network => Ok(LifecycleBootBootstrapEndpointV1::Network),
        LifecycleInventoryMethodV1::Host
        | LifecycleInventoryMethodV1::MountSources
        | LifecycleInventoryMethodV1::Storage
        | LifecycleInventoryMethodV1::DestinationSlots => Err(LifecyclePhase6ErrorV1::InvalidInput),
    }
}

fn current_domain_inventory_pair(
    inventory: &mut DormantLifecycleInventorySessionV1,
    method: LifecycleInventoryMethodV1,
    challenge: &LifecycleBootInventoryBootstrapChallengeV1,
    boot: &CurrentLifecycleBootInventoryV1<'_>,
) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1> {
    let endpoint = endpoint_for_inventory_method(method)?;
    let boot_before = KernelBootId::current()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .into_bytes();
    let (initial, _) = inventory.query_complete(method)?;
    let (current, currentness) = inventory.query_complete(method)?;
    inventory.recheck(currentness)?;
    let message = challenge.endpoint_signing_message(endpoint, &initial, &current)?;
    let signature = inventory
        .session
        .sign_lifecycle_bootstrap_attestation(&message)
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let boot_after = KernelBootId::current()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .into_bytes();
    if boot_before != boot_after {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    LifecycleAuthenticatedBrokerDomainInventorySuccessorV1::from_fixed_endpoint_attestation(
        challenge, boot, endpoint, &initial, &current, signature,
    )
}

fn bootstrap_domain_inventory_pair(
    inventory: &mut DormantLifecycleInventorySessionV1,
    method: LifecycleInventoryMethodV1,
    challenge: &LifecycleBootInventoryBootstrapChallengeV1,
) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
    let endpoint = endpoint_for_inventory_method(method)?;
    let boot_before = KernelBootId::current()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .into_bytes();
    if boot_before != challenge.host_boot() {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    let (initial, _) = inventory.query_complete(method)?;
    let (current, currentness) = inventory.query_complete(method)?;
    inventory.recheck(currentness)?;
    let message = challenge.endpoint_signing_message(endpoint, &initial, &current)?;
    let signature = inventory
        .session
        .sign_lifecycle_bootstrap_attestation(&message)
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let boot_after = KernelBootId::current()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .into_bytes();
    if boot_before != boot_after {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1::from_fixed_endpoint_attestation(
        challenge, endpoint, &initial, &current, signature,
    )
}

macro_rules! domain_inventory_owner {
    ($name:ident, $method:expr, $label:literal) => {
        #[doc = concat!("Owns a live authenticated ", $label, " inventory endpoint.")]
        #[must_use = "retain the protected endpoint through lifecycle currentness joins"]
        pub struct $name(DormantLifecycleInventorySessionV1);

        impl $name {
            /// Couples a completed fixed-custody session to lifecycle queries.
            #[must_use]
            pub fn from_protected_session(session: DormantAuthenticatedBrokerSessionV1) -> Self {
                Self(DormantLifecycleInventorySessionV1 {
                    session,
                    pending: None,
                    authority_effects: ControllerAuthorityEffectExchangeV1::default(),
                })
            }

            /// Applies or resumes one exact authority effect on this session.
            pub(crate) fn apply_authority_effect(
                &mut self,
                effect: &PreparedAuthorityEffectV1,
            ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
                self.0.apply_authority_effect(effect)
            }

            /// Resumes matching retained effect custody without issuing a new Apply.
            pub(crate) fn resume_authority_effect(
                &mut self,
                effect: &PreparedAuthorityEffectV1,
            ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
                self.0.resume_authority_effect(effect)
            }

            /// Recovers this exact Apply from prior-process terminal history.
            pub(crate) fn recover_terminal_authority_effect(
                &mut self,
                effect: &PreparedAuthorityEffectV1,
            ) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
                self.0.recover_terminal_authority_effect(effect)
            }

            /// Resumes retained inventory transport or durable commit custody.
            ///
            /// # Errors
            ///
            /// Returns an error for fatal transport or changed protected authority.
            pub fn resume_pending_inventory_query(
                &mut self,
            ) -> Result<Option<DormantLifecycleInventoryQueryProgressV1>, LifecyclePhase6ErrorV1>
            {
                self.0.resume_pending()
            }

            /// Issues and authenticates an adjacent inventory pair for a live boot root.
            ///
            /// # Errors
            ///
            /// Returns an error unless both queries and the fixed endpoint remain current.
            pub fn current_inventory_pair(
                &mut self,
                challenge: &LifecycleBootInventoryBootstrapChallengeV1,
                boot: &CurrentLifecycleBootInventoryV1<'_>,
            ) -> Result<
                LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
                LifecyclePhase6ErrorV1,
            > {
                current_domain_inventory_pair(&mut self.0, $method, challenge, boot)
            }

            /// Issues and authenticates an adjacent inventory pair for boot genesis.
            ///
            /// # Errors
            ///
            /// Returns an error unless both queries and the fixed endpoint remain current.
            pub fn bootstrap_inventory_pair(
                &mut self,
                challenge: &LifecycleBootInventoryBootstrapChallengeV1,
            ) -> Result<
                LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
                LifecyclePhase6ErrorV1,
            > {
                bootstrap_domain_inventory_pair(&mut self.0, $method, challenge)
            }
        }
    };
}

domain_inventory_owner!(
    DormantMountLifecycleInventoryOwnerV1,
    LifecycleInventoryMethodV1::Mount,
    "Mount"
);
domain_inventory_owner!(
    DormantNetworkLifecycleInventoryOwnerV1,
    LifecycleInventoryMethodV1::Network,
    "Network"
);

impl DormantMountLifecycleInventoryOwnerV1 {
    /// Supplies fresh session coordinates before the protected Host scope query.
    pub(crate) fn mount_request_coordinates(
        &mut self,
    ) -> Result<DormantBrokerRequestCoordinatesV1, LifecyclePhase6ErrorV1> {
        if self.0.pending.is_some() || self.0.authority_effects.has_pending() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        self.0
            .session
            .mount_request_coordinates()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)
    }

    /// Issues a fresh Mount query under protected terminal currentness.
    pub(crate) fn current_inventory_observation(
        &mut self,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Mount)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Issues a fresh signed source-acquisition inventory query on retained Mount.
    pub(crate) fn current_source_inventory_observation(
        &mut self,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self
            .0
            .query_complete(LifecycleInventoryMethodV1::MountSources)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Queries destination slots on the same retained Mount session.
    pub(crate) fn current_destination_slot_observation(
        &mut self,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self
            .0
            .query_complete(LifecycleInventoryMethodV1::DestinationSlots)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Sends or resumes one exact durable slot attempt on the retained Mount session.
    ///
    /// The returned outcome has passed terminal session-currentness recheck.
    /// The controller must still compare it with the durable attempt and commit
    /// its validated completion before querying fresh physical slot inventory.
    pub(crate) fn authenticated_destination_slot_effect(
        &mut self,
        attempt: &DurableCurrentDestinationSlotAttemptV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.slot_effect_complete(attempt)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Sends or drains an exact Host-authorized catalog query on retained Mount.
    ///
    /// A retained prior catalog request is drained first; its outcome may not
    /// match the caller's newly prepared query and must fail the core binding.
    pub(crate) fn authenticated_mount_catalog_preparation(
        &mut self,
        query: &PreparedCurrentMountCatalogQueryV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.catalog_query_complete(query)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Sends or drains one exact durable Mount Apply on the retained session.
    pub(crate) fn authenticated_mount_apply(
        &mut self,
        attempt: &DurableCurrentMountAttemptV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.mount_apply_complete(attempt)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Sends or drains one exact protected Mount source effect on retained AOSAGE.
    pub(crate) fn authenticated_mount_source_effect(
        &mut self,
        attempt: &DurableCurrentAttachmentSourceDispatchV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.source_effect_complete(attempt)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Drains only retained Acquire custody without preparing a successor request.
    pub(crate) fn drain_pending_mount_acquire(
        &mut self,
        attempt: &DurableCurrentAttachmentSourceDispatchV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        if attempt.kind() != AttachmentSourceAttemptKindV1::Acquire {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let method = BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE;
        let Some(pending) = self.0.pending.as_ref() else {
            return Ok(());
        };
        if pending.method != method {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let (outcome, currentness) = self.0.exact_request_complete(method, |_| {
            Err(crate::BrokerSessionSecurityError::Currentness)
        })?;
        self.0.recheck(currentness)?;
        if outcome.method() != method
            || outcome.request().exact_body() != attempt.dispatch_attempt().body()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

impl DormantNetworkLifecycleInventoryOwnerV1 {
    /// Issues a fresh query and rechecks its protected terminal currentness.
    pub(crate) fn current_inventory_observation(
        &mut self,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Network)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }
}

/// Retains an exact lifecycle inventory exchange at its resumable boundary.
#[must_use = "resume the exact exchange or retain its protected custody"]
pub struct DormantLifecycleInventoryQueryRecoveryV1 {
    method: BrokerMethod,
    stage: DormantLifecycleInventoryQueryStageV1,
}

enum DormantLifecycleInventoryQueryStageV1 {
    Initialization {
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Successor {
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Send(DormantPreparedBrokerRequestV1),
    Receive(DormantOutstandingBrokerRequestV1),
    Commit(ProtectedBrokerOutcomeCommitRecoveryV1),
}

/// Reports completion or exact resumable custody for one inventory exchange.
#[must_use = "consume the complete observation or resume protected custody"]
pub enum DormantLifecycleInventoryQueryProgressV1 {
    /// The signed inventory and move-only terminal currentness are available.
    Complete {
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    },
    /// Transport backpressure or durable ambiguity retained the exact exchange.
    RecoveryRequired(DormantLifecycleInventoryQueryRecoveryV1),
}

struct DormantLifecycleInventorySessionV1 {
    session: DormantAuthenticatedBrokerSessionV1,
    pending: Option<DormantLifecycleInventoryQueryRecoveryV1>,
    authority_effects: ControllerAuthorityEffectExchangeV1,
}

impl DormantLifecycleInventorySessionV1 {
    fn query(
        &mut self,
        method: LifecycleInventoryMethodV1,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        if self.authority_effects.has_pending() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let prepared = self
            .session
            .prepare_authenticated_request(method.method(), |coordinates| {
                method.envelope(coordinates)
            })
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let method = method.method();
        let prepared = match prepared {
            DormantBrokerRequestPreparationV1::Prepared(prepared) => prepared,
            DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                recovery,
                request,
                ..
            } => {
                return Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Initialization {
                            recovery,
                            request,
                        },
                    },
                ));
            }
            DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                recovery,
                request,
                ..
            } => {
                return Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Successor {
                            recovery,
                            request,
                        },
                    },
                ));
            }
        };
        self.send_query(method, prepared)
    }

    fn apply_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        if self.pending.is_some() {
            return Err(EffectFailure::Retryable(
                "broker session has retained inventory work".to_owned(),
            ));
        }
        self.authority_effects.apply(&mut self.session, effect)
    }

    fn resume_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        self.authority_effects.resume(&mut self.session, effect)
    }

    fn recover_terminal_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
        if self.pending.is_some() || self.authority_effects.has_pending() {
            return Err(EffectFailure::Retryable(
                "broker session has retained recovery work".to_owned(),
            ));
        }
        self.session.recover_terminal_authority_effect(effect)
    }

    fn send_query(
        &mut self,
        method: BrokerMethod,
        prepared: DormantPreparedBrokerRequestV1,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        match self
            .session
            .send_authenticated_request(prepared)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        {
            DormantBrokerRequestSendProgressV1::Pending(prepared) => {
                Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Send(prepared),
                    },
                ))
            }
            DormantBrokerRequestSendProgressV1::Sent(outstanding) => {
                self.receive_query(method, outstanding)
            }
        }
    }

    fn receive_query(
        &mut self,
        method: BrokerMethod,
        outstanding: DormantOutstandingBrokerRequestV1,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        match self
            .session
            .receive_authenticated_response(outstanding)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        {
            DormantBrokerResponseProgressV1::Pending(outstanding) => {
                Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Receive(outstanding),
                    },
                ))
            }
            DormantBrokerResponseProgressV1::Committed(
                ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
            ) => {
                let (outcome, currentness) = committed.into_outcome_and_currentness();
                Ok(DormantLifecycleInventoryQueryProgressV1::Complete {
                    outcome,
                    currentness,
                })
            }
            DormantBrokerResponseProgressV1::Committed(
                ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. },
            ) => Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                DormantLifecycleInventoryQueryRecoveryV1 {
                    method,
                    stage: DormantLifecycleInventoryQueryStageV1::Commit(recovery),
                },
            )),
        }
    }

    fn resume_query(
        &mut self,
        recovery: DormantLifecycleInventoryQueryRecoveryV1,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        let method = recovery.method;
        match recovery.stage {
            DormantLifecycleInventoryQueryStageV1::Initialization { recovery, request } => {
                match self
                    .session
                    .recover_prepared_initialization(recovery, request)
                {
                    DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                        self.send_query(method, prepared)
                    }
                    DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                        recovery,
                        request,
                        ..
                    } => Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                        DormantLifecycleInventoryQueryRecoveryV1 {
                            method,
                            stage: DormantLifecycleInventoryQueryStageV1::Initialization {
                                recovery,
                                request,
                            },
                        },
                    )),
                    DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { .. } => {
                        Err(LifecyclePhase6ErrorV1::StaleAuthority)
                    }
                }
            }
            DormantLifecycleInventoryQueryStageV1::Successor { recovery, request } => {
                match self.session.recover_prepared_successor(recovery, request) {
                    DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                        self.send_query(method, prepared)
                    }
                    DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                        recovery,
                        request,
                        ..
                    } => Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                        DormantLifecycleInventoryQueryRecoveryV1 {
                            method,
                            stage: DormantLifecycleInventoryQueryStageV1::Successor {
                                recovery,
                                request,
                            },
                        },
                    )),
                    DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                        ..
                    } => Err(LifecyclePhase6ErrorV1::StaleAuthority),
                }
            }
            DormantLifecycleInventoryQueryStageV1::Send(prepared) => {
                self.send_query(method, prepared)
            }
            DormantLifecycleInventoryQueryStageV1::Receive(outstanding) => {
                self.receive_query(method, outstanding)
            }
            DormantLifecycleInventoryQueryStageV1::Commit(recovery) => {
                match self.session.recover_broker_outcome_commit(recovery) {
                    ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                        let (outcome, currentness) = committed.into_outcome_and_currentness();
                        Ok(DormantLifecycleInventoryQueryProgressV1::Complete {
                            outcome,
                            currentness,
                        })
                    }
                    ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                        Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                            DormantLifecycleInventoryQueryRecoveryV1 {
                                method,
                                stage: DormantLifecycleInventoryQueryStageV1::Commit(recovery),
                            },
                        ))
                    }
                }
            }
        }
    }

    fn recheck(
        &mut self,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.recheck_retained(currentness).map(|_| ())
    }

    fn recheck_retained(
        &mut self,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<ProtectedBrokerOutcomeCurrentnessOwnerV1, LifecyclePhase6ErrorV1> {
        let mut current = self
            .session
            .revalidate_broker_outcome(currentness)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        current
            .revalidate()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        Ok(current.into_currentness_owner())
    }

    fn query_complete(
        &mut self,
        method: LifecycleInventoryMethodV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        if self.pending.is_some() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let progress = self.query(method)?;
        self.drive_complete(progress)
    }

    fn query_complete_or_resume_retained(
        &mut self,
        method: LifecycleInventoryMethodV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        let Some(recovery) = self.pending.take() else {
            return self.query_complete(method);
        };
        if recovery.method != method.method() {
            self.pending = Some(recovery);
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }

        let progress = self.resume_query(recovery)?;
        self.drive_complete(progress)
    }

    fn slot_effect_complete(
        &mut self,
        attempt: &DurableCurrentDestinationSlotAttemptV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        self.exact_request_complete(
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
            |session| session.prepare_authenticated_destination_slot_effect(attempt),
        )
    }

    fn catalog_query_complete(
        &mut self,
        query: &PreparedCurrentMountCatalogQueryV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        self.exact_request_complete(
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG,
            |session| session.prepare_authenticated_mount_catalog_query(query),
        )
    }

    fn mount_apply_complete(
        &mut self,
        attempt: &DurableCurrentMountAttemptV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        self.exact_request_complete(BrokerMethod::BROKER_METHOD_MOUNT_APPLY, |session| {
            session.prepare_authenticated_mount_apply(attempt)
        })
    }

    fn source_effect_complete(
        &mut self,
        attempt: &DurableCurrentAttachmentSourceDispatchV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        let method = match attempt.kind() {
            AttachmentSourceAttemptKindV1::Acquire => {
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            }
            AttachmentSourceAttemptKindV1::Release => {
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            }
            AttachmentSourceAttemptKindV1::Consume => {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
        };
        self.exact_request_complete(method, |session| {
            session.prepare_authenticated_mount_source_effect(attempt)
        })
    }

    fn exact_request_complete(
        &mut self,
        method: BrokerMethod,
        prepare: impl FnOnce(
            &mut DormantAuthenticatedBrokerSessionV1,
        ) -> Result<
            DormantBrokerRequestPreparationV1,
            crate::BrokerSessionSecurityError,
        >,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        if self.authority_effects.has_pending() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        if let Some(recovery) = self.pending.take() {
            if recovery.method != method {
                self.pending = Some(recovery);
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
            let progress = self.resume_query(recovery)?;
            return self.drive_complete(progress);
        }
        let prepared =
            prepare(&mut self.session).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let progress = match prepared {
            DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                self.send_query(method, prepared)?
            }
            DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                recovery,
                request,
                ..
            } => DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                DormantLifecycleInventoryQueryRecoveryV1 {
                    method,
                    stage: DormantLifecycleInventoryQueryStageV1::Initialization {
                        recovery,
                        request,
                    },
                },
            ),
            DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                recovery,
                request,
                ..
            } => DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                DormantLifecycleInventoryQueryRecoveryV1 {
                    method,
                    stage: DormantLifecycleInventoryQueryStageV1::Successor { recovery, request },
                },
            ),
        };
        self.drive_complete(progress)
    }

    fn drive_complete(
        &mut self,
        mut progress: DormantLifecycleInventoryQueryProgressV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        loop {
            match progress {
                DormantLifecycleInventoryQueryProgressV1::Complete {
                    outcome,
                    currentness,
                } => {
                    crate::dormant_handshake::check_production_deadline(
                        outcome.request().deadline_boottime_nanoseconds(),
                    )
                    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
                    return Ok((outcome, currentness));
                }
                DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(recovery) => {
                    // Socket backpressure is not durable ambiguity. Wait on the
                    // retained session using the original signed deadline, never
                    // a fresh timeout that could extend the request's lifetime.
                    let readiness = match &recovery.stage {
                        DormantLifecycleInventoryQueryStageV1::Send(request) => {
                            Some((true, request.deadline_boottime_nanoseconds()))
                        }
                        DormantLifecycleInventoryQueryStageV1::Receive(request) => {
                            Some((false, request.deadline_boottime_nanoseconds()))
                        }
                        _ => None,
                    };
                    let Some((wants_write, deadline)) = readiness else {
                        self.pending = Some(recovery);
                        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
                    };
                    let wait = self.session.as_fd().and_then(|fd| {
                        crate::dormant_handshake::wait_for_handshake_readiness(
                            fd,
                            wants_write,
                            deadline,
                        )
                        .and_then(|()| {
                            crate::dormant_handshake::check_production_deadline(deadline)
                        })
                    });
                    if wait.is_err() {
                        // Preserve exact custody on expiry or transport failure;
                        // no later inventory may overtake this request.
                        self.pending = Some(recovery);
                        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
                    }
                    progress = self.resume_query(recovery)?;
                }
            }
        }
    }

    fn resume_pending(
        &mut self,
    ) -> Result<Option<DormantLifecycleInventoryQueryProgressV1>, LifecyclePhase6ErrorV1> {
        let Some(recovery) = self.pending.take() else {
            return Ok(None);
        };
        let progress = self.resume_query(recovery)?;
        if let DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(recovery) = progress {
            self.pending = Some(recovery);
            return Ok(None);
        }
        Ok(Some(progress))
    }
}

/// Owns a live authenticated Host inventory endpoint.
#[must_use = "retain the protected Host endpoint through the final boot recheck"]
pub struct DormantHostRuntimeInventoryOwnerV1(DormantLifecycleInventorySessionV1);

impl DormantHostRuntimeInventoryOwnerV1 {
    /// Couples a completed fixed-custody session to Host lifecycle queries.
    #[must_use]
    pub fn from_protected_session(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self(DormantLifecycleInventorySessionV1 {
            session,
            pending: None,
            authority_effects: ControllerAuthorityEffectExchangeV1::default(),
        })
    }

    /// Returns the protected session after no inventory query remains pending.
    #[must_use]
    pub(crate) fn into_protected_session(self) -> DormantAuthenticatedBrokerSessionV1 {
        self.0.session
    }

    /// Applies or resumes one exact Host authority effect on this session.
    pub(crate) fn apply_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        self.0.apply_authority_effect(effect)
    }

    /// Resumes matching retained Host effect custody without issuing a new Apply.
    pub(crate) fn resume_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        self.0.resume_authority_effect(effect)
    }

    /// Resumes a retained Host inventory exchange without rebuilding its request.
    ///
    /// # Errors
    ///
    /// Returns an error for fatal transport or changed protected authority.
    pub fn resume_pending_inventory_query(
        &mut self,
    ) -> Result<Option<DormantLifecycleInventoryQueryProgressV1>, LifecyclePhase6ErrorV1> {
        self.0.resume_pending()
    }

    /// Issues two exact adjacent Host inventory exchanges under one kernel boot.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for transport backpressure, protected
    /// recovery, boot rollover, or any non-adjacent or changed inventory.
    pub fn current_inventory_pair(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
    ) -> Result<LifecycleAuthenticatedRuntimeInventorySuccessorV1, LifecyclePhase6ErrorV1> {
        let boot_before = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        let (initial, _) = self.0.query_complete(LifecycleInventoryMethodV1::Host)?;
        let (current, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Host)?;
        let boot_after = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        self.0.recheck(currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            &initial,
            &current,
        )?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedRuntimeInventorySuccessorV1::from_fixed_endpoint_attestation(
            challenge, boot, &initial, &current, boot_after, signature,
        )
    }

    /// Issues and challenge-authenticates the Host pair for first-root publication.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless both exchanges and the exact
    /// terminal head remain current while the fixed client-record key signs
    /// the lifecycle owner's one-shot challenge.
    pub fn bootstrap_inventory_pair(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
    ) -> Result<LifecycleAuthenticatedRuntimeInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        let boot_before = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != challenge.host_boot() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let (initial, _) = self.0.query_complete(LifecycleInventoryMethodV1::Host)?;
        let (current, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Host)?;
        self.0.recheck(currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            &initial,
            &current,
        )?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        LifecycleAuthenticatedRuntimeInventoryBootstrapV1::from_fixed_endpoint_attestation(
            challenge, &initial, &current, signature,
        )
    }
}

/// Owns a live authenticated Storage inventory endpoint.
#[must_use = "retain the protected Storage endpoint through lifecycle currentness joins"]
pub struct DormantStorageLifecycleInventoryOwnerV1(DormantLifecycleInventorySessionV1);

/// Retains the exact protected Storage inventory immediately before a group effect.
#[must_use = "the predecessor must be consumed by the matching post-effect query"]
pub struct DormantAtomicStorageInventoryPredecessorV1 {
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    inventory: LifecycleAuthenticatedStorageInventoryV1,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
}

impl DormantAtomicStorageInventoryPredecessorV1 {
    /// Borrows the exact authenticated inventory used to derive the group plan.
    #[must_use]
    pub const fn inventory(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.inventory
    }

    /// Borrows the signed predecessor exchange retained for the adjacent join.
    #[must_use]
    pub const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.outcome
    }
}

/// Retains both sides of a post-atomic Storage inventory ambiguity.
#[must_use = "resume the exact post-effect query with its protected predecessor"]
pub struct DormantAtomicStorageInventoryFinishRecoveryV1 {
    previous: DormantAtomicStorageInventoryPredecessorV1,
    group: AuthenticatedBrokerMethodOutcomeV1,
    query: DormantLifecycleInventoryQueryRecoveryV1,
}

impl DormantAtomicStorageInventoryFinishRecoveryV1 {
    /// Borrows the retained exact grouped response while its successor query resolves.
    #[must_use]
    pub const fn group_outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.group
    }
}

/// Reports a completed atomic Storage join or its exact resumable custody.
#[must_use = "consume the successor or retain and resume protected custody"]
pub enum DormantAtomicStorageInventoryFinishProgressV1 {
    /// The authenticated predecessor/successor join completed.
    Complete(DormantAtomicStorageInventoryCompletionV1),
    /// The post-effect query remains ambiguous without losing its predecessor.
    RecoveryRequired(DormantAtomicStorageInventoryFinishRecoveryV1),
}

/// Retains the verified successor with all three exact signed exchanges.
///
/// The successor is either adjacent to the group or a fresh signed status
/// whose protected catalog head equals the exact original group post-head.
/// A lifecycle source record then commits their exact packet hashes.
#[must_use = "retain the verified successor and signed packet evidence"]
#[derive(Clone)]
pub struct DormantAtomicStorageInventoryCompletionV1 {
    successor: LifecycleAuthenticatedAtomicStorageSuccessorV1,
    predecessor: AuthenticatedBrokerMethodOutcomeV1,
    group: AuthenticatedBrokerMethodOutcomeV1,
    current: AuthenticatedBrokerMethodOutcomeV1,
}

impl DormantAtomicStorageInventoryCompletionV1 {
    /// Borrows the verified complete Storage successor.
    #[must_use]
    pub const fn successor(&self) -> &LifecycleAuthenticatedAtomicStorageSuccessorV1 {
        &self.successor
    }

    /// Borrows the exact signed pre-effect inventory exchange.
    #[must_use]
    pub const fn predecessor_outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.predecessor
    }

    /// Borrows the exact signed grouped-effect exchange.
    #[must_use]
    pub const fn group_outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.group
    }

    /// Borrows the exact signed post-effect inventory exchange.
    #[must_use]
    pub const fn successor_outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.current
    }

    /// Moves the verified successor and all three signed exchanges together.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LifecycleAuthenticatedAtomicStorageSuccessorV1,
        AuthenticatedBrokerMethodOutcomeV1,
        AuthenticatedBrokerMethodOutcomeV1,
        AuthenticatedBrokerMethodOutcomeV1,
    ) {
        (self.successor, self.predecessor, self.group, self.current)
    }
}

impl DormantStorageLifecycleInventoryOwnerV1 {
    /// Retains one exact signed Create Prepare and its authenticated catalog.
    ///
    /// A returned catalog is not Apply authority. The separate signed Apply
    /// must name it and pass the Create-specific lifecycle handoff check.
    ///
    /// # Errors
    ///
    /// Returns an error for another pending Storage query, stale protected
    /// Create inputs, transport ambiguity, or a contradictory signed result.
    pub fn prepare_storage_create(
        &mut self,
        protected: &ProtectedStorageCreatePreparationV1,
        authority: &PreparedAuthorityEffectV1,
    ) -> Result<AuthenticatedStorageCreatePreparationV1, EffectFailure> {
        if self.0.pending.is_some() {
            return Err(EffectFailure::Retryable(
                "Storage inventory query retains exact session custody".to_owned(),
            ));
        }
        let outcome = self.0.authority_effects.storage_create_prepare(
            &mut self.0.session,
            protected,
            authority,
        )?;
        AuthenticatedStorageCreatePreparationV1::from_outcome(protected, authority, outcome)
    }

    /// Borrows the retained Storage session for one separate guest-root effect.
    ///
    /// # Errors
    ///
    /// Rejects an unresolved inventory or authority-effect exchange, preserving
    /// sole session custody and exact packet ordering.
    pub(crate) fn guest_root_session(
        &mut self,
    ) -> Result<&mut DormantAuthenticatedBrokerSessionV1, EffectFailure> {
        if self.0.pending.is_some() || self.0.authority_effects.has_pending() {
            return Err(EffectFailure::Retryable(
                "Storage session retains another exact exchange".to_owned(),
            ));
        }
        Ok(&mut self.0.session)
    }

    /// Returns the signed-hello/context checkpoint bound to this Storage session.
    pub(crate) fn historical_checkpoint_digest(
        &self,
    ) -> Result<aos_sandbox_core::ObjectDigest, EffectFailure> {
        self.0
            .session
            .historical_checkpoint_digest()
            .map(aos_sandbox_core::ObjectDigest::from_bytes)
            .map_err(|_| {
                EffectFailure::Retryable("Storage historical checkpoint is unavailable".to_owned())
            })
    }

    /// Reauthenticates a complete old trio without issuing a Storage request.
    pub(crate) fn recover_verified_atomic_snapshot_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: aos_sandbox_core::ObjectDigest,
        predecessor_packet: aos_sandbox_core::ObjectDigest,
        session_binding: aos_sandbox_core::ObjectDigest,
        checkpoint: aos_sandbox_core::ObjectDigest,
    ) -> Result<ProtectedVerifiedAtomicStorageHistoryV1, EffectFailure> {
        self.0
            .session
            .prior_verified_atomic_storage_history(
                request_id,
                *request_packet.as_bytes(),
                *predecessor_packet.as_bytes(),
                *session_binding.as_bytes(),
                *checkpoint.as_bytes(),
            )
            .map_err(|_| {
                EffectFailure::Retryable(
                    "protected historical Storage trio is unavailable".to_owned(),
                )
            })
    }

    /// Preserves the verified original signed session before a status query.
    ///
    /// The immutable archive is keyed by the original request ID and checked
    /// against the source reservation's packet, session, and hello checkpoint.
    /// A fresh inventory may roll the live session history only after this
    /// write is durably committed and reread.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn archive_verified_atomic_snapshot_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: aos_sandbox_core::ObjectDigest,
        predecessor_packet: aos_sandbox_core::ObjectDigest,
        session_binding: aos_sandbox_core::ObjectDigest,
        checkpoint: aos_sandbox_core::ObjectDigest,
    ) -> Result<(), EffectFailure> {
        self.0
            .session
            .archive_verified_atomic_storage_history(
                request_id,
                *request_packet.as_bytes(),
                *predecessor_packet.as_bytes(),
                *session_binding.as_bytes(),
                *checkpoint.as_bytes(),
            )
            .map_err(|_| {
                EffectFailure::Retryable("original Storage group archive is unavailable".to_owned())
            })
    }

    /// Removes temporary old-session bytes after protected source completion.
    pub(crate) fn retire_atomic_snapshot_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<(), EffectFailure> {
        self.0
            .session
            .retire_atomic_storage_archive(request_id)
            .map_err(|_| {
                EffectFailure::Retryable("Storage group archive retirement failed".to_owned())
            })
    }

    /// Reattests a fully verified old trio with the current fixed Storage key.
    ///
    /// This issues no broker request. The fresh signature binds the current
    /// protected lifecycle challenge to the exact historical packets after
    /// read-only session verification; absent successors remain unresolved.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_verified_atomic_snapshot_completion(
        &mut self,
        request_id: [u8; 16],
        request_packet: aos_sandbox_core::ObjectDigest,
        predecessor_packet: aos_sandbox_core::ObjectDigest,
        session_binding: aos_sandbox_core::ObjectDigest,
        checkpoint: aos_sandbox_core::ObjectDigest,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<Option<DormantAtomicStorageInventoryCompletionV1>, EffectFailure> {
        let history = self.recover_verified_atomic_snapshot_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint,
        )?;
        let ProtectedVerifiedAtomicStorageHistoryV1::Complete {
            predecessor,
            group,
            successor: current,
        } = history
        else {
            return Ok(None);
        };
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
            return Err(EffectFailure::Permanent(
                "historical Storage group was not successful".to_owned(),
            ));
        };
        let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage receipt is invalid".to_owned())
            })?;
        let program = aos_sandbox_core::ObjectDigest::from_bytes(receipt.program());
        let observation = aos_sandbox_core::ObjectDigest::from_bytes(receipt.observation());
        let message = challenge
            .storage_atomic_snapshot_signing_message(&predecessor, &group, &current)
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage trio is not adjacent".to_owned())
            })?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| {
                EffectFailure::Retryable(
                    "Storage fixed endpoint attestation is unavailable".to_owned(),
                )
            })?;
        let successor =
            LifecycleAuthenticatedAtomicStorageSuccessorV1::from_fixed_endpoint_attestation(
                challenge,
                operation,
                plan,
                program,
                observation,
                &predecessor,
                &group,
                &current,
                signature,
            )
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage successor is invalid".to_owned())
            })?;
        Ok(Some(DormantAtomicStorageInventoryCompletionV1 {
            successor,
            predecessor,
            group,
            current,
        }))
    }

    /// Attests a successful historical group with a fresh read-only status.
    ///
    /// The protected history has already reconstructed the original signed
    /// predecessor and group. The only new broker exchange is an inventory
    /// query; its checkpoint must still name the exact post-group catalog head.
    pub(crate) fn recover_verified_atomic_snapshot_status(
        &mut self,
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<DormantAtomicStorageInventoryCompletionV1, EffectFailure> {
        let (current, currentness) = self
            .0
            .query_complete_or_resume_retained(LifecycleInventoryMethodV1::Storage)
            .map_err(|_| {
                EffectFailure::Retryable("Storage status inventory is unavailable".to_owned())
            })?;
        self.0.recheck(currentness).map_err(|_| {
            EffectFailure::Retryable("Storage status inventory is no longer current".to_owned())
        })?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
            return Err(EffectFailure::Permanent(
                "historical Storage group was not successful".to_owned(),
            ));
        };
        let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage receipt is invalid".to_owned())
            })?;
        let program = aos_sandbox_core::ObjectDigest::from_bytes(receipt.program());
        let observation = aos_sandbox_core::ObjectDigest::from_bytes(receipt.observation());
        let message = challenge
            .storage_atomic_snapshot_status_signing_message(&predecessor, &group, &current)
            .map_err(|_| {
                EffectFailure::Permanent("Storage status cannot attest the group".to_owned())
            })?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| {
                EffectFailure::Retryable(
                    "Storage fixed endpoint status attestation is unavailable".to_owned(),
                )
            })?;
        let successor =
            LifecycleAuthenticatedAtomicStorageSuccessorV1::from_fixed_endpoint_status_attestation(
                challenge,
                operation,
                plan,
                program,
                observation,
                &predecessor,
                &group,
                &current,
                signature,
            )
            .map_err(|_| {
                EffectFailure::Permanent("Storage status does not prove the group".to_owned())
            })?;
        Ok(DormantAtomicStorageInventoryCompletionV1 {
            successor,
            predecessor,
            group,
            current,
        })
    }

    /// Inspects the exact old Storage session before a new request rolls it over.
    pub(crate) fn recover_prior_atomic_snapshot_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: aos_sandbox_core::ObjectDigest,
        predecessor_packet: aos_sandbox_core::ObjectDigest,
        session_binding: aos_sandbox_core::ObjectDigest,
    ) -> Result<ProtectedPriorAtomicStorageHistoryV1, EffectFailure> {
        if self.0.pending.is_some() || self.0.authority_effects.has_pending() {
            return Err(EffectFailure::Retryable(
                "Storage session has retained recovery work".to_owned(),
            ));
        }
        self.0
            .session
            .prior_atomic_storage_history(
                request_id,
                *request_packet.as_bytes(),
                *predecessor_packet.as_bytes(),
                *session_binding.as_bytes(),
            )
            .map_err(|_| {
                EffectFailure::Retryable(
                    "protected Storage session history is unavailable".to_owned(),
                )
            })
    }

    /// Sends one lifecycle-bound atomic Storage group through retained session custody.
    ///
    /// The caller must retain the predecessor until the authenticated group
    /// outcome and immediate successor inventory have both joined. A retry
    /// resumes this exact effect; it never selects a replacement request.
    ///
    /// # Errors
    ///
    /// Returns [`EffectFailure`] if pre-send binding, protected custody,
    /// transport, or the terminal signed response is invalid or ambiguous.
    pub(crate) fn apply_atomic_snapshot_group(
        &mut self,
        lifecycle: &CurrentLifecycleEffectV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        previous: &mut DormantAtomicStorageInventoryPredecessorV1,
        fence: LiveRuntimeFenceV1,
        authority: &PreparedAuthorityEffectV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if self.0.pending.is_some() {
            return Err(EffectFailure::Retryable(
                "Storage inventory recovery must settle before group dispatch".to_owned(),
            ));
        }
        if plan.inventory() != previous.inventory.commitment()
            || plan.inventory_generation() != previous.inventory.generation()
            || plan.inventory_source() != previous.inventory.source()
        {
            return Err(EffectFailure::Permanent(
                "Storage group plan differs from its retained predecessor inventory".to_owned(),
            ));
        }
        if !self.0.authority_effects.has_pending() {
            let currentness = previous.currentness.take().ok_or_else(|| {
                EffectFailure::Permanent("Storage predecessor currentness was lost".to_owned())
            })?;
            previous.currentness = Some(self.0.recheck_retained(currentness).map_err(|_| {
                EffectFailure::Permanent("Storage predecessor is no longer current".to_owned())
            })?);
        }
        self.0.authority_effects.atomic_storage(
            &mut self.0.session,
            lifecycle,
            plan,
            fence,
            authority,
        )
    }

    /// Issues a fresh query and rechecks its protected terminal currentness.
    pub(crate) fn current_inventory_observation(
        &mut self,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
    }

    /// Applies or resumes one exact Storage authority effect on this session.
    pub(crate) fn apply_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        self.0.apply_authority_effect(effect)
    }

    /// Resumes matching retained Storage effect custody without issuing a new Apply.
    pub(crate) fn resume_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        self.0.resume_authority_effect(effect)
    }

    /// Recovers this exact Apply from prior-process terminal history.
    pub(crate) fn recover_terminal_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
        self.0.recover_terminal_authority_effect(effect)
    }

    /// Couples a completed fixed-custody session to Storage lifecycle queries.
    #[must_use]
    pub fn from_protected_session(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self(DormantLifecycleInventorySessionV1 {
            session,
            pending: None,
            authority_effects: ControllerAuthorityEffectExchangeV1::default(),
        })
    }

    /// Resumes a retained Storage inventory exchange without rebuilding its request.
    ///
    /// # Errors
    ///
    /// Returns an error for fatal transport or changed protected authority.
    pub fn resume_pending_inventory_query(
        &mut self,
    ) -> Result<Option<DormantLifecycleInventoryQueryProgressV1>, LifecyclePhase6ErrorV1> {
        self.0.resume_pending()
    }

    /// Issues two exact adjacent complete Storage inventory exchanges.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for transport backpressure, protected
    /// recovery, or any non-adjacent or changed five-family inventory.
    pub fn current_inventory_pair(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
    ) -> Result<LifecycleAuthenticatedStorageInventorySuccessorV1, LifecyclePhase6ErrorV1> {
        let (initial, _) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        let (current, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        self.0.recheck(currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            &initial,
            &current,
        )?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedStorageInventorySuccessorV1::from_fixed_endpoint_attestation(
            challenge, boot, &initial, &current, signature,
        )
    }

    /// Issues and challenge-authenticates the Storage pair for first-root publication.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless both complete inventory
    /// exchanges and the terminal head remain current through fixed-key signing.
    pub fn bootstrap_inventory_pair(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
    ) -> Result<LifecycleAuthenticatedStorageInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        let (initial, _) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        let (current, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        self.0.recheck(currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            &initial,
            &current,
        )?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedStorageInventoryBootstrapV1::from_fixed_endpoint_attestation(
            challenge, &initial, &current, signature,
        )
    }

    /// Issues one immediate complete Storage readback after an Apply exchange.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the protected session commits
    /// a canonical complete five-family Storage inventory outcome.
    pub fn current_post_effect_readback(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        effect: &LifecycleAuthenticatedBrokerEffectV1,
        apply: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedStorageReadbackV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        self.0.recheck(currentness)?;
        let message = challenge.storage_effect_signing_message(apply, &outcome)?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedStorageReadbackV1::from_fixed_endpoint_attestation(
            challenge, effect, apply, &outcome, signature,
        )
    }

    /// Captures the protected complete Storage predecessor before an atomic group.
    ///
    /// The group plan must be derived from the returned predecessor's inventory;
    /// another query has a different authenticated request commitment.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless a fresh complete inventory is
    /// committed and remains the live session head.
    pub fn begin_atomic_snapshot_inventory(
        &mut self,
    ) -> Result<DormantAtomicStorageInventoryPredecessorV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Storage)?;
        let currentness = self.0.recheck_retained(currentness)?;
        let inventory =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(&outcome)?;
        Ok(DormantAtomicStorageInventoryPredecessorV1 {
            outcome,
            inventory,
            currentness: Some(currentness),
        })
    }

    /// Captures the immediate inventory after one authenticated group outcome.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the predecessor belongs to
    /// this live session and the successor proves every committed plan member.
    pub fn finish_atomic_snapshot_inventory(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        program: aos_sandbox_core::ObjectDigest,
        observation: aos_sandbox_core::ObjectDigest,
        previous: DormantAtomicStorageInventoryPredecessorV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<DormantAtomicStorageInventoryFinishProgressV1, LifecyclePhase6ErrorV1> {
        if self.0.pending.is_some() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        match self.0.query(LifecycleInventoryMethodV1::Storage)? {
            DormantLifecycleInventoryQueryProgressV1::Complete {
                outcome,
                currentness,
            } => self.complete_atomic_snapshot_inventory(
                challenge,
                operation,
                plan,
                program,
                observation,
                previous,
                group,
                outcome,
                currentness,
            ),
            DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(query) => Ok(
                DormantAtomicStorageInventoryFinishProgressV1::RecoveryRequired(
                    DormantAtomicStorageInventoryFinishRecoveryV1 {
                        previous,
                        group,
                        query,
                    },
                ),
            ),
        }
    }

    /// Resumes an ambiguous post-atomic Storage query without rebuilding either side.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for fatal transport, changed protected
    /// authority, or an invalid predecessor/successor transition.
    pub fn resume_atomic_snapshot_inventory(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        program: aos_sandbox_core::ObjectDigest,
        observation: aos_sandbox_core::ObjectDigest,
        recovery: DormantAtomicStorageInventoryFinishRecoveryV1,
    ) -> Result<DormantAtomicStorageInventoryFinishProgressV1, LifecyclePhase6ErrorV1> {
        let DormantAtomicStorageInventoryFinishRecoveryV1 {
            previous,
            group,
            query,
        } = recovery;
        match self.0.resume_query(query)? {
            DormantLifecycleInventoryQueryProgressV1::Complete {
                outcome,
                currentness,
            } => self.complete_atomic_snapshot_inventory(
                challenge,
                operation,
                plan,
                program,
                observation,
                previous,
                group,
                outcome,
                currentness,
            ),
            DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(query) => Ok(
                DormantAtomicStorageInventoryFinishProgressV1::RecoveryRequired(
                    DormantAtomicStorageInventoryFinishRecoveryV1 {
                        previous,
                        group,
                        query,
                    },
                ),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_atomic_snapshot_inventory(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        program: aos_sandbox_core::ObjectDigest,
        observation: aos_sandbox_core::ObjectDigest,
        previous: DormantAtomicStorageInventoryPredecessorV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
        current: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<DormantAtomicStorageInventoryFinishProgressV1, LifecyclePhase6ErrorV1> {
        self.0.recheck(currentness)?;
        let message = challenge.storage_atomic_snapshot_signing_message(
            &previous.outcome,
            &group,
            &current,
        )?;
        let signature = self
            .0
            .session
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let successor =
            LifecycleAuthenticatedAtomicStorageSuccessorV1::from_fixed_endpoint_attestation(
                challenge,
                operation,
                plan,
                program,
                observation,
                &previous.outcome,
                &group,
                &current,
                signature,
            )?;
        Ok(DormantAtomicStorageInventoryFinishProgressV1::Complete(
            DormantAtomicStorageInventoryCompletionV1 {
                successor,
                predecessor: previous.outcome,
                group,
                current,
            },
        ))
    }
}
