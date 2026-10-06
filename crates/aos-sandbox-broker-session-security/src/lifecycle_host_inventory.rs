//! Protected lifecycle inventory queries over live broker sessions.
//!
//! The concrete owners issue fresh Host, Storage, Mount, or Network inventory requests through
//! the repository-owned authenticated post-handshake exchange. Ordinary
//! callers supply no request identifier, sequence, packet, signer, or trust
//! policy. The closed operator Repair path may durably reserve the session's
//! own selected request identifier before that exact query is prepared.

mod operator_repair;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerMethod, BrokerRequestEnvelope, InventoryDestinationSlotsRequest,
    InventoryMountSourceAcquisitionsRequest, InventoryMountsRequest, InventoryNetworksRequest,
    InventoryRuntimeRequest, InventoryStorageRequest, RecoverStorageInventoryRequestV1,
    RequestHeader,
};
use aos_sandbox::attachment_source::{
    AttachmentSourceAttemptKindV1, DurableCurrentAttachmentSourceDispatchV1,
};
use aos_sandbox::controller::{ActivatedOperationCompiler, NodeController};
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
    SingleNodeEffectExecutor, ValidatedAuthorityEffectReceiptV1,
};
use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1;
use aos_sandbox_protocol::{
    ValidatedStorageInventoryRecoveryResponseV1, decode_storage_inventory_recovery_response_v1,
};
use buffa::Message as _;

use crate::controller_authority_effect::ControllerAuthorityEffectExchangeV1;
use crate::recovery::{
    ProtectedPriorAtomicStorageHistoryV1, ProtectedVerifiedAtomicStorageHistoryV1,
};
use crate::{
    AuthenticatedStorageCreatePreparationV1, BrokerSessionSecurityError,
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestCoordinatesV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1, DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerRequestV1, DormantUnconfirmedBrokerRequestV1,
    ProtectedBrokerOutcomeCommitRecoveryV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerSessionInitializationRecoveryV1,
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
                    output_registration: None,
                    capture_candidate: None,
                    #[cfg(feature = "online-nix")]
                    nix_generation: None,
                    git_coverage: None,
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
        self.drain_pending_mount(BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE, || {
            attempt.dispatch_attempt().body()
        })
    }

    /// Drains only a retained Mount Apply receive/commit without issuing it.
    ///
    /// This cannot promote an expired source Host scope. Fresh inventory must
    /// classify the result before any attachment completion is recorded.
    pub(crate) fn drain_pending_mount_apply(
        &mut self,
        attempt: &DurableCurrentMountAttemptV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.drain_pending_mount(BrokerMethod::BROKER_METHOD_MOUNT_APPLY, || {
            attempt.dispatch_attempt().body()
        })
    }

    /// Drains a retained catalog response without using stale source authority.
    pub(crate) fn drain_pending_mount_catalog(
        &mut self,
        query: &PreparedCurrentMountCatalogQueryV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.drain_pending_mount(BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG, || {
            query.body()
        })
    }

    fn drain_pending_mount<'a>(
        &mut self,
        method: BrokerMethod,
        exact_body: impl FnOnce() -> &'a [u8],
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let Some(pending) = self.0.pending.as_ref() else {
            return Ok(());
        };
        if pending.method != method {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let (outcome, currentness) = self.0.drain_retained_request_complete(method)?;
        self.0.recheck(currentness)?;
        // Inspect the expected body only after the retained response is current.
        if outcome.method() != method || outcome.request().exact_body() != exact_body() {
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
    // The selected original's fence must run before the actual Session drops.
    capture_candidate: Option<crate::controller_capture_candidate_exchange::ControllerStorageCaptureCandidateExchangeV1>,
    session: DormantAuthenticatedBrokerSessionV1,
    pending: Option<DormantLifecycleInventoryQueryRecoveryV1>,
    authority_effects: ControllerAuthorityEffectExchangeV1,
    output_registration: Option<crate::controller_service::execution_output_storage_registration::OriginalControllerOutputRegistrationV1>,
    #[cfg(feature = "online-nix")]
    nix_generation: Option<crate::controller_service::nix_generation::NixGenerationAttemptV1>,
    git_coverage: Option<GitCoverageQueryCustodyV1>,
}

type GitCoverageReplyV1 = (
    AuthenticatedBrokerMethodOutcomeV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1,
);
type GitCoverageProofResultV1 = Result<
    Vec<u8>,
    aos_sandbox_core::format::git_upload_enrollment::GitCoverageDataErrorV1,
>;

#[derive(Debug)]
pub(crate) enum GitCoverageQueryFailureV1 {
    Protected(BrokerSessionSecurityError),
    Readiness(crate::DormantBrokerSessionHandshakeErrorV1),
    Refused,
}

impl std::fmt::Display for GitCoverageQueryFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protected(cause) => std::fmt::Display::fmt(cause, formatter),
            Self::Readiness(cause) => std::fmt::Display::fmt(cause, formatter),
            Self::Refused => formatter.write_str("Git coverage exchange is permanently refused"),
        }
    }
}

impl std::error::Error for GitCoverageQueryFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protected(cause) => Some(cause),
            Self::Readiness(cause) => Some(cause),
            Self::Refused => None,
        }
    }
}

struct GitCoverageQueryCustodyV1 {
    original_cut: u64,
    first_failure: Option<GitCoverageQueryFailureV1>,
    postcheck_debt: Option<GitCoverageQueryFailureV1>,
    completed: Option<GitCoverageReplyV1>,
}

/// Owns one selected original Session and its two whole coverage replies.
///
/// This is private transport custody, not an enrollment or currentness factory.
/// Its containing Controller attempt remains prearmed through all field drops.
pub(crate) struct DormantGitCoverageQueryOwnerV1 {
    inner: DormantLifecycleInventorySessionV1,
    replies: [Option<GitCoverageReplyV1>; 2],
    checkpoint: Option<Result<Vec<u8>, BrokerSessionSecurityError>>,
    proof: Option<GitCoverageProofResultV1>,
}

impl DormantGitCoverageQueryOwnerV1 {
    // Called only after the returned original Session is parked here. A
    // mismatch keeps its actual cause and entire transport in this owner.
    pub(crate) fn require_original_node(
        &mut self,
        node: [u8; 16],
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        match self.inner.session.require_current_node(node) {
            Ok(()) => Ok(()),
            Err(cause) => Err(self.inner.query_protected_failure(cause)),
        }
    }

    pub(crate) fn from_original_mount(
        original: DormantMountLifecycleInventoryOwnerV1,
        original_cut: u64,
    ) -> Self {
        Self::from_original_inner(original.0, original_cut)
    }

    pub(crate) fn from_original_storage(
        original: DormantStorageLifecycleInventoryOwnerV1,
        original_cut: u64,
    ) -> Self {
        Self::from_original_inner(original.0, original_cut)
    }

    fn from_original_inner(
        mut inner: DormantLifecycleInventorySessionV1,
        original_cut: u64,
    ) -> Self {
        let refused = inner.pending.is_some()
            || inner.authority_effects.has_pending()
            || inner.has_pending_output_registration();
        if let Some(custody) = inner.git_coverage.as_mut() {
            custody.first_failure.get_or_insert(GitCoverageQueryFailureV1::Refused);
        } else {
            inner.git_coverage = Some(GitCoverageQueryCustodyV1 {
                original_cut,
                first_failure: refused.then_some(GitCoverageQueryFailureV1::Refused),
                postcheck_debt: None,
                completed: None,
            });
        }
        Self {
            inner,
            replies: [None, None],
            checkpoint: None,
            proof: None,
        }
    }

    // The selected containing owner calls these only after the actual account
    // CAS and local Root completion. Failure returns this WHOLE owning capsule;
    // it cannot strip an IO owner or recreate a Session from proof DATA.
    pub(crate) fn restore_original_mount(
        mut self,
    ) -> Result<DormantMountLifecycleInventoryOwnerV1, Self> {
        if self.recheck(1).is_err() || self.proof().is_none()
            || self.reply(0).map(|reply| reply.0.method())
                != Some(BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1)
            || self.inner.pending.is_some()
        {
            return Err(self);
        }
        self.inner.git_coverage = None;
        Ok(DormantMountLifecycleInventoryOwnerV1(self.inner))
    }

    pub(crate) fn restore_original_storage(
        mut self,
    ) -> Result<DormantStorageLifecycleInventoryOwnerV1, Self> {
        if self.recheck(1).is_err() || self.proof().is_none()
            || self.reply(0).map(|reply| reply.0.method())
                != Some(BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1)
            || self.inner.pending.is_some()
        {
            return Err(self);
        }
        self.inner.git_coverage = None;
        Ok(DormantStorageLifecycleInventoryOwnerV1(self.inner))
    }

    pub(crate) fn exchange(
        &mut self,
        method: BrokerMethod,
        body: &[u8],
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let slot = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1 => 0,
            BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
            | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => 1,
            _ => return Err(self.inner.refuse_git_coverage()),
        };
        let Some(custody) = self.inner.git_coverage.as_ref() else {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        };
        if custody.first_failure.is_some()
            || self.replies[slot].is_some()
            || self.checkpoint.as_ref().is_some_and(Result::is_err)
            || (slot == 1 && !matches!(self.checkpoint.as_ref(), Some(Ok(_))))
        {
            return Err(self.inner.refuse_git_coverage());
        }
        let cut = custody.original_cut;
        let result = self.inner.exact_request_complete(method, |session| {
            session.prepare_git_coverage_request_v1(method, body, cut)
        });
        match result {
            Ok(reply) => self.replies[slot] = Some(reply),
            Err(cause) => {
                self.inner.refuse_git_coverage();
                return Err(cause);
            }
        }
        let Some((outcome, _)) = self.replies[slot].as_ref() else {
            return Err(self.inner.refuse_git_coverage());
        };
        let original_sequence = if slot == 0 { 1 } else { 2 };
        if outcome.method() != method
            || outcome.request().client_sequence() != original_sequence
            || outcome.broker_sequence() != original_sequence
        {
            return Err(self.inner.refuse_git_coverage());
        }

        // The complete response/currentness is already resident before this
        // independent live peer, full protected head and original-cut check.
        self.recheck(slot)?;
        if slot == 0 {
            self.capture_prepare_checkpoint()?;
        }
        Ok(())
    }

    fn capture_prepare_checkpoint(&mut self) -> Result<(), LifecyclePhase6ErrorV1> {
        use aos_sandbox_core::format::git_upload_enrollment::{
            COVERAGE_BROKER_PROOF_HEADER_BYTES_V1,
            MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1,
        };

        if self.checkpoint.is_some() {
            return Err(self.inner.refuse_git_coverage());
        }
        let Some((prepare, currentness)) = self.replies[0].as_ref() else {
            return Err(self.inner.refuse_git_coverage());
        };
        let maximum = MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1
            .checked_sub(COVERAGE_BROKER_PROOF_HEADER_BYTES_V1)
            .and_then(|remaining| remaining.checked_sub(prepare.request().canonical_packet().len()))
            .and_then(|remaining| remaining.checked_sub(prepare.canonical_packet().len()))
            .filter(|remaining| *remaining != 0);
        let Some(maximum) = maximum else {
            return Err(self.inner.refuse_git_coverage());
        };

        // Prepare is still the actual current outcome here. Later Read cannot
        // regenerate this capture or pretend that Prepare's old head is live.
        self.checkpoint = Some(self.inner.session.capture_git_coverage_checkpoint_v1(
            currentness, maximum,
        ));
        let postcheck = self.recheck_original_outcome(0);
        if self.checkpoint.as_ref().is_some_and(Result::is_err) {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        postcheck
    }

    pub(crate) fn recheck(&mut self, slot: usize) -> Result<(), LifecyclePhase6ErrorV1> {
        if self.checkpoint.as_ref().is_some_and(Result::is_err)
            || self.proof.as_ref().is_some_and(Result::is_err)
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        if slot == 0 && self.replies[1].is_some() {
            // Read already advanced the actual protected head. Prepare's
            // historical pair must never be presented as current again.
            return Err(self.inner.refuse_git_coverage());
        }
        self.recheck_original_outcome(slot)
    }

    // Used directly only for the independent postcheck after an encoding
    // Result is parked. It preserves that first error and records later debt.
    fn recheck_original_outcome(&mut self, slot: usize) -> Result<(), LifecyclePhase6ErrorV1> {
        let Some(custody) = self.inner.git_coverage.as_ref() else {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        };
        if custody.first_failure.is_some() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let cut = custody.original_cut;
        let Some((outcome, currentness)) = self.replies.get(slot).and_then(Option::as_ref) else {
            return Err(self.inner.refuse_git_coverage());
        };
        let deadline = cut.min(outcome.request().deadline_boottime_nanoseconds());
        let before = crate::dormant_handshake::check_production_deadline(deadline);
        if let Err(cause) = before {
            return Err(self.retain_recheck_failure(GitCoverageQueryFailureV1::Readiness(cause)));
        }
        let comparison = self.inner.session.compare_git_coverage_outcome_v1(currentness);
        if let Err(cause) = comparison {
            return Err(self.retain_recheck_failure(GitCoverageQueryFailureV1::Protected(cause)));
        }
        if let Err(cause) = crate::dormant_handshake::check_production_deadline(deadline) {
            return Err(self.retain_recheck_failure(GitCoverageQueryFailureV1::Readiness(cause)));
        }
        Ok(())
    }

    fn retain_recheck_failure(
        &mut self,
        cause: GitCoverageQueryFailureV1,
    ) -> LifecyclePhase6ErrorV1 {
        let encoding_failed = self.checkpoint.as_ref().is_some_and(Result::is_err)
            || self.proof.as_ref().is_some_and(Result::is_err);
        if let Some(custody) = self.inner.git_coverage.as_mut() {
            if encoding_failed || custody.first_failure.is_some() {
                custody.postcheck_debt.get_or_insert(cause);
            } else {
                custody.first_failure = Some(cause);
            }
        }
        LifecyclePhase6ErrorV1::StaleAuthority
    }

    pub(crate) fn reply(&self, slot: usize) -> Option<&GitCoverageReplyV1> {
        self.replies.get(slot).and_then(Option::as_ref)
    }

    pub(crate) fn assemble_proof(&mut self) -> Result<(), LifecyclePhase6ErrorV1> {
        use aos_sandbox_core::format::git_upload_enrollment::{
            GitCoverageBrokerProofV1, GitCoverageBrokerRoleV1,
        };

        if self.proof.is_some() {
            return Err(self.inner.refuse_git_coverage());
        }
        self.recheck(1)?;
        let Some((prepare, prepare_owner)) = self.replies[0].as_ref() else {
            return Err(self.inner.refuse_git_coverage());
        };
        let Some((read, read_owner)) = self.replies[1].as_ref() else {
            return Err(self.inner.refuse_git_coverage());
        };
        let role = match (prepare.method(), read.method()) {
            (
                BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1,
                BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1,
            ) => GitCoverageBrokerRoleV1::Mount,
            (
                BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1,
                BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1,
            ) => GitCoverageBrokerRoleV1::Storage,
            _ => return Err(self.inner.refuse_git_coverage()),
        };
        if prepare_owner.context != read_owner.context
            || prepare_owner.transcript != read_owner.transcript
        {
            return Err(self.inner.refuse_git_coverage());
        }
        let Some(Ok(checkpoint)) = self.checkpoint.as_ref() else {
            return Err(self.inner.refuse_git_coverage());
        };

        // The sole framing codec checks all five actual lengths before copying.
        // Both original pairs and the earlier checkpoint remain resident.
        self.proof = Some(GitCoverageBrokerProofV1::encode(role, [
            checkpoint,
            prepare.request().canonical_packet(),
            prepare.canonical_packet(),
            read.request().canonical_packet(),
            read.canonical_packet(),
        ]));
        let postcheck = self.recheck_original_outcome(1);
        if self.proof.as_ref().is_some_and(Result::is_err) {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        postcheck
    }

    pub(crate) fn proof(&self) -> Option<&[u8]> {
        if self.first_failure().is_some() {
            return None;
        }
        self.proof.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    // A missing observation is not success; the whole selected attempt and its
    // independent postcheck result remain with the containing Controller owner.
    pub(crate) fn first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // An encoding error precedes its later independent postcheck debt.
        // Those owning Results are never taken, cloned or formatted into a cause.
        if let Some(Err(cause)) = &self.checkpoint {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.proof {
            return Some(cause);
        }
        self.inner.git_coverage.as_ref()?.first_failure.as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&GitCoverageQueryFailureV1> {
        self.inner.git_coverage.as_ref()?.postcheck_debt.as_ref()
    }
}

impl DormantLifecycleInventorySessionV1 {
    fn query_protected_failure(&mut self, cause: BrokerSessionSecurityError) -> LifecyclePhase6ErrorV1 {
        if let Some(custody) = self.git_coverage.as_mut() {
            if custody.first_failure.is_none() {
                custody.first_failure = Some(GitCoverageQueryFailureV1::Protected(cause));
            }
        }
        LifecyclePhase6ErrorV1::StaleAuthority
    }

    fn query_readiness_failure(
        &mut self,
        cause: crate::DormantBrokerSessionHandshakeErrorV1,
    ) -> LifecyclePhase6ErrorV1 {
        if let Some(custody) = self.git_coverage.as_mut() {
            if custody.first_failure.is_none() {
                custody.first_failure = Some(GitCoverageQueryFailureV1::Readiness(cause));
            }
        }
        LifecyclePhase6ErrorV1::StaleAuthority
    }

    fn refuse_git_coverage(&mut self) -> LifecyclePhase6ErrorV1 {
        if let Some(custody) = self.git_coverage.as_mut() {
            if custody.first_failure.is_none() {
                custody.first_failure = Some(GitCoverageQueryFailureV1::Refused);
            }
        }
        LifecyclePhase6ErrorV1::StaleAuthority
    }

    // Only the Storage-specific named loan can populate this slot. Keeping it
    // beside the original session prevents another exchange from replacing a
    // failed output attempt after a durable local terminal or postcheck debt.
    fn has_pending_output_registration(&self) -> bool {
        if self.capture_candidate.is_some() { return true; }
        #[cfg(feature = "online-nix")]
        if self.nix_generation.is_some() { return true; }
        self.output_registration.as_ref().is_some_and(|attempt| attempt.has_pending())
    }

    fn query(
        &mut self,
        method: LifecycleInventoryMethodV1,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        self.query_with_preparation(method, |session| {
            session.prepare_authenticated_request(method.method(), |coordinates| {
                method.envelope(coordinates)
            })
        })
    }

    fn query_with_preparation(
        &mut self,
        method: LifecycleInventoryMethodV1,
        prepare: impl FnOnce(
            &mut DormantAuthenticatedBrokerSessionV1,
        )
            -> Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        if self.has_pending_output_registration() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        if self.authority_effects.has_pending() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let prepared =
            prepare(&mut self.session).map_err(|cause| self.query_protected_failure(cause))?;
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
        if self.has_pending_output_registration() {
            return Err(output_registration_pending());
        }
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
        if self.has_pending_output_registration() {
            return Some(Err(output_registration_pending()));
        }
        self.authority_effects.resume(&mut self.session, effect)
    }

    fn recover_terminal_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
        if self.has_pending_output_registration() {
            return Err(output_registration_pending());
        }
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
            .map_err(|cause| self.query_protected_failure(cause))?
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
            .map_err(|cause| self.query_protected_failure(cause))?
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
                ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery },
            ) => {
                self.query_protected_failure(error);
                Ok(DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Commit(recovery),
                    },
                ))
            }
        }
    }

    fn resume_query(
        &mut self,
        recovery: DormantLifecycleInventoryQueryRecoveryV1,
    ) -> Result<DormantLifecycleInventoryQueryProgressV1, LifecyclePhase6ErrorV1> {
        // The existing API consumes recovery on refusal. It must not enter a
        // Session recovery frontier while original output custody is resident.
        if self.has_pending_output_registration() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
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

    fn query_complete_with_challenge(
        &mut self,
        method: LifecycleInventoryMethodV1,
        reserve: impl FnOnce([u8; 16]) -> Result<(), BrokerSessionSecurityError>,
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
        let mut selected_request_id = None;
        let progress = self.query_with_preparation(method, |session| {
            session.prepare_authenticated_request_checked_fallible(
                method.method(),
                |coordinates| {
                    let request_id = coordinates.request_id();
                    reserve(request_id)?;
                    selected_request_id = Some(request_id);
                    Ok(method.envelope(coordinates))
                },
                |_| true,
            )
        })?;
        let (outcome, currentness) = self.drive_complete(progress)?;
        if selected_request_id != Some(outcome.request().request_id()) {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok((outcome, currentness))
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
        if self.has_pending_output_registration() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
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
            prepare(&mut self.session).map_err(|cause| self.query_protected_failure(cause))?;
        let progress = match prepared {
            DormantBrokerRequestPreparationV1::Prepared(prepared) => {
                self.send_query(method, prepared)?
            }
            DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
                error,
                recovery,
                request,
            } => {
                self.query_protected_failure(error);
                DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Initialization {
                            recovery,
                            request,
                        },
                    },
                )
            }
            DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
                error,
                recovery,
                request,
            } => {
                self.query_protected_failure(error);
                DormantLifecycleInventoryQueryProgressV1::RecoveryRequired(
                    DormantLifecycleInventoryQueryRecoveryV1 {
                        method,
                        stage: DormantLifecycleInventoryQueryStageV1::Successor { recovery, request },
                    },
                )
            }
        };
        self.drive_complete(progress)
    }

    fn drain_retained_request_complete(
        &mut self,
        method: BrokerMethod,
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
        let recovery = self
            .pending
            .take()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if recovery.method != method {
            self.pending = Some(recovery);
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        if !matches!(
            &recovery.stage,
            DormantLifecycleInventoryQueryStageV1::Receive(_)
                | DormantLifecycleInventoryQueryStageV1::Commit(_)
        ) {
            self.pending = Some(recovery);
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }

        // A late terminal response can clear the retained session slot, but
        // cannot authorize source completion. The caller requires fresh Mount
        // inventory after this exact authenticated response is drained.
        let progress = self.resume_query(recovery)?;
        self.drive_complete_inner(progress, false)
    }

    fn drive_complete(
        &mut self,
        progress: DormantLifecycleInventoryQueryProgressV1,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        self.drive_complete_inner(progress, true)
    }

    fn drive_complete_inner(
        &mut self,
        mut progress: DormantLifecycleInventoryQueryProgressV1,
        require_live_deadline: bool,
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
                    if let Some(custody) = self.git_coverage.as_mut() {
                        let deadline = custody.original_cut
                            .min(outcome.request().deadline_boottime_nanoseconds());
                        custody.completed = Some((outcome, currentness));
                        if let Err(cause) = crate::dormant_handshake::check_production_deadline(deadline) {
                            return Err(self.query_readiness_failure(cause));
                        }
                        return self.git_coverage.as_mut()
                            .and_then(|custody| custody.completed.take())
                            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority);
                    }
                    if require_live_deadline {
                        crate::dormant_handshake::check_production_deadline(
                            outcome.request().deadline_boottime_nanoseconds(),
                        )
                        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
                    }
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
                        if self.git_coverage.is_some() {
                            self.refuse_git_coverage();
                        }
                        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
                    };
                    // Selected custody is parked before the fallible readiness
                    // loan. Ordinary callers keep their original local interval.
                    let selected = self.git_coverage.is_some();
                    let deadline = match self.git_coverage.as_ref() {
                        Some(custody) => custody.original_cut.min(deadline),
                        None => deadline,
                    };
                    let mut local_recovery = Some(recovery);
                    if selected {
                        self.pending = local_recovery.take();
                    }
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
                    if let Err(cause) = wait {
                        // Preserve exact custody on expiry or transport failure;
                        // no later inventory may overtake this request.
                        if !selected {
                            self.pending = local_recovery;
                        }
                        return Err(self.query_readiness_failure(cause));
                    }
                    let recovery = if selected { self.pending.take() } else { local_recovery };
                    let Some(recovery) = recovery else {
                        return Err(self.refuse_git_coverage());
                    };
                    progress = self.resume_query(recovery)?;
                }
            }
        }
    }

    fn resume_pending(
        &mut self,
    ) -> Result<Option<DormantLifecycleInventoryQueryProgressV1>, LifecyclePhase6ErrorV1> {
        if self.has_pending_output_registration() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
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

fn output_registration_pending() -> EffectFailure {
    EffectFailure::Permanent("Storage session retains original output registration".to_owned())
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
            output_registration: None,
            capture_candidate: None,
            #[cfg(feature = "online-nix")]
            nix_generation: None,
            git_coverage: None,
        })
    }

    #[cfg(all(test, feature = "kernel-tests"))]
    pub(crate) fn qualification_current_inventory_observation(
        &mut self,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        let (outcome, currentness) = self.0.query_complete(LifecycleInventoryMethodV1::Host)?;
        self.0.recheck(currentness)?;
        Ok(outcome)
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

/// Classifies the exact post-group inventory after protected cold recovery.
pub(crate) enum DormantAtomicStorageInventoryColdRecoveryV1 {
    /// No original post-group inventory was sent; a fresh status may be read.
    NoOriginalRequest,
    /// Both endpoints durably abandoned the original read-only request.
    AbandonedReadOnly,
    /// The broker returned the original signed terminal, reauthenticated here.
    OriginalTerminal(AuthenticatedBrokerMethodOutcomeV1),
}

impl DormantStorageLifecycleInventoryOwnerV1 {
    /// Resolves a pending original post-group inventory through Method32.
    ///
    /// # Errors
    ///
    /// Returns an error if original history, the signed control result, or
    /// either endpoint's protected abandonment cannot be verified.
    pub(crate) fn recover_atomic_snapshot_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<DormantAtomicStorageInventoryColdRecoveryV1, EffectFailure> {
        self.require_no_capture_candidate()?;
        let original = self
            .0
            .session
            .original_storage_inventory_coordinates(group_request_id, group_request_digest)
            .map_err(|_| {
                EffectFailure::Retryable("original Storage inventory is unavailable".to_owned())
            })?;
        let Some(original) = original else {
            return Ok(DormantAtomicStorageInventoryColdRecoveryV1::NoOriginalRequest);
        };
        self.recover_atomic_snapshot_inventory_head(
            group_request_id,
            group_request_digest,
            original,
        )
    }

    /// Resolves a fresh status through its exact signed history or Method32.
    pub(crate) fn recover_fresh_atomic_snapshot_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<DormantAtomicStorageInventoryColdRecoveryV1, EffectFailure> {
        self.require_no_capture_candidate()?;
        let fresh = self
            .0
            .session
            .fresh_storage_inventory_coordinates(group_request_id, group_request_digest)
            .map_err(|_| {
                EffectFailure::Retryable("fresh Storage status history is unavailable".to_owned())
            })?;
        let Some(fresh) = fresh else {
            return Ok(DormantAtomicStorageInventoryColdRecoveryV1::NoOriginalRequest);
        };
        self.recover_atomic_snapshot_inventory_head(group_request_id, group_request_digest, fresh)
    }

    fn recover_atomic_snapshot_inventory_head(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        original: crate::recovery::ArchivedStorageInventoryHeadV1,
    ) -> Result<DormantAtomicStorageInventoryColdRecoveryV1, EffectFailure> {
        let retained = self
            .0
            .session
            .archive_original_storage_inventory(
                group_request_id,
                group_request_digest,
                original.inventory_request_id,
                original.inventory_request_digest,
            )
            .map_err(|_| {
                EffectFailure::Retryable(
                    "Storage inventory history could not be retained".to_owned(),
                )
            })?;
        if retained.original_head != original.original_head
            || retained.archive_digest != original.archive_digest
        {
            return Err(EffectFailure::Permanent(
                "Storage inventory history changed during recovery".to_owned(),
            ));
        }
        if let Some(packet) = original.terminal_packet.as_deref() {
            let terminal = self
                .0
                .session
                .verify_original_storage_inventory_terminal(
                    group_request_id,
                    group_request_digest,
                    original.inventory_request_id,
                    original.inventory_request_digest,
                    packet,
                )
                .map_err(|_| {
                    EffectFailure::Permanent(
                        "original Storage inventory terminal did not reauthenticate".to_owned(),
                    )
                })?;
            return Ok(DormantAtomicStorageInventoryColdRecoveryV1::OriginalTerminal(terminal));
        }
        if self
            .0
            .session
            .client_storage_inventory_abandonment_committed(
                group_request_id,
                group_request_digest,
                original.inventory_request_id,
                original.inventory_request_digest,
                original.original_head,
            )
            .map_err(|_| {
                EffectFailure::Retryable("Storage inventory abandonment is unavailable".to_owned())
            })?
        {
            return Ok(DormantAtomicStorageInventoryColdRecoveryV1::AbandonedReadOnly);
        }

        let inventory_id = original.inventory_request_id;
        let inventory_digest = original.inventory_request_digest;
        let client_head = original.original_head;
        let (outcome, currentness) = self
            .0
            .exact_request_complete(
                BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY,
                |session| {
                    session.prepare_authenticated_request(
                        BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY,
                        |coordinates| {
                            let version = coordinates.protocol_version();
                            let body = RecoverStorageInventoryRequestV1 {
                                header: Some(RequestHeader {
                                    protocol_major: version.major().into(),
                                    protocol_minor: version.minor().into(),
                                    request_id: coordinates.request_id().to_vec(),
                                    audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                                    deadline_boottime_nanoseconds: coordinates
                                        .deadline_boottime_nanoseconds(),
                                    maximum_response_bytes: coordinates.maximum_response_bytes(),
                                    ..Default::default()
                                })
                                .into(),
                                group_request_id: group_request_id.to_vec(),
                                group_request_digest: group_request_digest.to_vec(),
                                inventory_request_id: inventory_id.to_vec(),
                                inventory_request_digest: inventory_digest.to_vec(),
                                client_original_head: client_head.to_vec(),
                                ..Default::default()
                            };
                            BrokerRequestEnvelope {
                                method: BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
                                    .into(),
                                body: body.encode_to_vec(),
                                ..Default::default()
                            }
                        },
                    )
                },
            )
            .map_err(|_| {
                EffectFailure::Retryable(
                    "Storage inventory control exchange is unavailable".to_owned(),
                )
            })?;
        self.0.recheck(currentness).map_err(|_| {
            EffectFailure::Retryable("Storage inventory control is no longer current".to_owned())
        })?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(EffectFailure::Permanent(
                "Storage inventory control was rejected".to_owned(),
            ));
        };
        let decision = decode_storage_inventory_recovery_response_v1(
            exact_body,
            outcome.request().maximum_response_bytes(),
        )
        .map_err(|_| {
            EffectFailure::Permanent("Storage inventory control result is invalid".to_owned())
        })?;
        match decision {
            ValidatedStorageInventoryRecoveryResponseV1::OriginalTerminal { packet, .. } => {
                let original = self
                    .0
                    .session
                    .verify_original_storage_inventory_terminal(
                        group_request_id,
                        group_request_digest,
                        inventory_id,
                        inventory_digest,
                        &packet,
                    )
                    .map_err(|_| {
                        EffectFailure::Permanent(
                            "original Storage terminal did not reauthenticate".to_owned(),
                        )
                    })?;
                Ok(DormantAtomicStorageInventoryColdRecoveryV1::OriginalTerminal(original))
            }
            ValidatedStorageInventoryRecoveryResponseV1::AbandonedReadOnly { .. } => {
                self.0
                    .session
                    .client_confirm_storage_inventory_abandonment(
                        group_request_id,
                        group_request_digest,
                        inventory_id,
                        inventory_digest,
                    )
                    .map_err(|_| {
                        EffectFailure::Retryable(
                            "client Storage abandonment was not durable".to_owned(),
                        )
                    })?;
                Ok(DormantAtomicStorageInventoryColdRecoveryV1::AbandonedReadOnly)
            }
        }
    }

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
        if self.0.has_pending_output_registration() {
            return Err(output_registration_pending());
        }
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
        self.exclusive_effect_session()
    }

    /// Lends disjoint request custody and the same original Storage session.
    ///
    /// This excludes inventory and other authority effects but grants no
    /// registration permission and extracts no transport or owner.
    pub(crate) fn output_registration_loan(
        &mut self,
    ) -> Result<(
        &mut Option<crate::controller_service::execution_output_storage_registration::OriginalControllerOutputRegistrationV1>,
        &mut DormantAuthenticatedBrokerSessionV1,
    ), EffectFailure> {
        if self.0.pending.is_some() || self.0.authority_effects.has_pending()
            || self.0.git_coverage.is_some()
            || self.has_pending_nix_generation()
            || self.0.capture_candidate.is_some()
        {
            return Err(EffectFailure::Retryable(
                "Storage session retains another exact exchange".to_owned(),
            ));
        }
        Ok((&mut self.0.output_registration, &mut self.0.session))
    }

    /// Lends only completed registration custody, its original candidate slot
    /// and the same authenticated Storage Session. No owner can be extracted.
    ///
    /// # Errors
    /// Refuses unfinished registration, another exchange or absent custody.
    pub(crate) fn capture_candidate_loan(
        &mut self,
    ) -> Result<(
        &crate::controller_service::execution_output_storage_registration::OriginalControllerOutputRegistrationV1,
        &mut Option<crate::controller_capture_candidate_exchange::ControllerStorageCaptureCandidateExchangeV1>,
        &mut DormantAuthenticatedBrokerSessionV1,
    ), EffectFailure> {
        if self.0.pending.is_some() || self.0.authority_effects.has_pending()
            || self.0.git_coverage.is_some() || self.has_pending_nix_generation()
        {
            return Err(output_registration_pending());
        }
        let registration = self.0.output_registration.as_ref().ok_or_else(output_registration_pending)?;
        if registration.has_pending() { return Err(output_registration_pending()); }
        Ok((registration, &mut self.0.capture_candidate, &mut self.0.session))
    }

    pub(crate) fn capture_candidate_profile_selected(&self) -> bool {
        self.0.session.has_selected_capture_candidate_profile()
    }

    pub(crate) fn has_capture_candidate(&self) -> bool {
        self.0.capture_candidate.is_some()
    }

    pub(crate) fn has_pending_capture_candidate(&self) -> bool {
        self.0.capture_candidate.as_ref().is_some_and(|attempt| attempt.has_pending())
    }

    pub(crate) fn capture_candidate_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.capture_candidate.as_ref()?.failure(&self.0.session)
    }

    pub(crate) fn capture_candidate_postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.capture_candidate.as_ref()?.postcheck_debt(&self.0.session)
    }

    fn require_no_capture_candidate(&self) -> Result<(), EffectFailure> {
        if self.0.capture_candidate.is_some() {
            return Err(EffectFailure::Permanent("Storage retains its original capture query".to_owned()));
        }
        Ok(())
    }

    pub(crate) fn output_registration_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.output_registration.as_ref()?.failure(&self.0.session)
    }

    pub(crate) fn has_pending_output_registration(&self) -> bool {
        // The shared inner gate also blocks unrelated work after a completed
        // candidate. The reconnect coordinator distinguishes that retained
        // success from an unfinished/failed registration or candidate.
        self.has_pending_nix_generation()
            || self.0.output_registration.as_ref().is_some_and(|attempt| attempt.has_pending())
    }

    pub(crate) fn has_pending_nix_generation(&self) -> bool {
        #[cfg(feature = "online-nix")]
        { self.0.nix_generation.is_some() }
        #[cfg(not(feature = "online-nix"))]
        { false }
    }

    /// Lends only this actual Storage Session and its selected resident subslot.
    #[cfg(feature = "online-nix")]
    pub(crate) fn nix_generation_loan(
        &mut self,
    ) -> Result<(
        &mut Option<crate::controller_service::nix_generation::NixGenerationAttemptV1>,
        &mut DormantAuthenticatedBrokerSessionV1,
    ), EffectFailure> {
        if self.0.pending.is_some() || self.0.authority_effects.has_pending()
            || self.0.output_registration.is_some() || self.0.git_coverage.is_some()
            || self.0.capture_candidate.is_some()
        {
            return Err(EffectFailure::Permanent("Storage original Session is occupied".to_owned()));
        }
        Ok((&mut self.0.nix_generation, &mut self.0.session))
    }

    pub(crate) fn output_registration_postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.output_registration.as_ref()?.postcheck_debt(&self.0.session)
    }

    fn exclusive_effect_session(
        &mut self,
    ) -> Result<&mut DormantAuthenticatedBrokerSessionV1, EffectFailure> {
        if self.0.has_pending_output_registration() {
            return Err(output_registration_pending());
        }
        if self.0.pending.is_some() || self.0.authority_effects.has_pending() {
            return Err(EffectFailure::Retryable(
                "Storage session retains another exact exchange".to_owned(),
            ));
        }
        Ok(&mut self.0.session)
    }

    /// Compares the borrowed Snapshot predecessor with this exact live Session.
    ///
    /// This retains the original terminal owner on failure and grants no group
    /// dispatch or physical dataset-currentness permission.
    ///
    /// # Errors
    ///
    /// Refuses another resident exchange, missing predecessor custody, or any
    /// changed protected terminal, endpoint or live peer binding.
    pub(crate) fn compare_atomic_snapshot_predecessor_v3(
        &mut self,
        predecessor: &DormantAtomicStorageInventoryPredecessorV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.0.pending.is_some()
            || self.0.authority_effects.has_pending()
            || self.0.output_registration.is_some()
            || self.0.git_coverage.is_some()
            || self.has_pending_nix_generation()
            || self.0.capture_candidate.is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let currentness = predecessor.currentness.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if currentness.outcome != predecessor.outcome {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        self.0.session.compare_atomic_snapshot_predecessor_v3(currentness)
    }

    /// Returns the signed-hello/context checkpoint bound to this Storage session.
    pub(crate) fn historical_checkpoint_digest(
        &self,
    ) -> Result<aos_sandbox_core::ObjectDigest, EffectFailure> {
        self.require_no_capture_candidate()?;
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
        self.require_no_capture_candidate()?;
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
        self.require_no_capture_candidate()?;
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
        self.require_no_capture_candidate()?;
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
        self.attest_original_atomic_snapshot_terminal(
            predecessor,
            group,
            current,
            challenge,
            operation,
            plan,
        )
        .map(Some)
    }

    /// Attests a Method32-recovered original terminal against the original trio.
    pub(crate) fn attest_original_atomic_snapshot_terminal(
        &mut self,
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
        current: AuthenticatedBrokerMethodOutcomeV1,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<DormantAtomicStorageInventoryCompletionV1, EffectFailure> {
        self.require_no_capture_candidate()?;
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
        Ok(DormantAtomicStorageInventoryCompletionV1 {
            successor,
            predecessor,
            group,
            current,
        })
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
        self.attest_fresh_atomic_snapshot_terminal(
            predecessor,
            group,
            current,
            challenge,
            operation,
            plan,
        )
    }

    /// Attests a recovered fresh terminal as status evidence for the group.
    pub(crate) fn attest_fresh_atomic_snapshot_terminal(
        &mut self,
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
        current: AuthenticatedBrokerMethodOutcomeV1,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<DormantAtomicStorageInventoryCompletionV1, EffectFailure> {
        self.require_no_capture_candidate()?;
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
        self.require_no_capture_candidate()?;
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
        if self.0.has_pending_output_registration() {
            return Err(output_registration_pending());
        }
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

    /// Issues a signed physical Inventory query under a precommitted Repair challenge.
    ///
    /// The trusted Controller callback must durably reserve the authenticated
    /// session's own request identifier before the broker request is written
    /// or sent. A different
    /// independently generated ID cannot satisfy the returned outcome. A
    /// retained ambiguous exchange must be recovered before another challenge.
    ///
    /// # Errors
    ///
    /// Rejects a failed reservation callback, stale broker outcome, pending
    /// exchange, or incomplete Storage inventory. This crate-private helper
    /// is not an operator admission route by itself.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn challenged_operator_repair_inventory_observation(
        &mut self,
        reserve: impl FnOnce([u8; 16]) -> Result<(), BrokerSessionSecurityError>,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            LifecycleAuthenticatedStorageInventoryV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        let (outcome, currentness) = self
            .0
            .query_complete_with_challenge(LifecycleInventoryMethodV1::Storage, reserve)?;
        let inventory =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(&outcome)?;
        self.0.recheck(currentness)?;
        self.operator_repair_inventory_history(
            outcome.request().request_id(),
            Some(outcome.canonical_packet()),
        )?;
        Ok((outcome, inventory))
    }

    /// Reserves Controller AOSORQ01 custody before the signed pre-effect query.
    ///
    /// The callback is deliberately closed over the actual Controller journal;
    /// no caller-provided request ID can diverge from session coordinates.
    ///
    /// # Errors
    ///
    /// Rejects stale issuance or current head before send, or an incomplete or
    /// noncurrent authenticated physical Inventory outcome afterward.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn current_operator_repair_before_inventory<C, E>(
        &mut self,
        controller: &mut NodeController<C, E>,
        operation_id: OperationId,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            LifecycleAuthenticatedStorageInventoryV1,
        ),
        LifecyclePhase6ErrorV1,
    >
    where
        C: ActivatedOperationCompiler,
        E: SingleNodeEffectExecutor,
    {
        self.challenged_operator_repair_inventory_observation(|request_id| {
            controller
                .reserve_operator_storage_repair_before_inventory_challenge_v1(
                    operation_id,
                    request_id,
                )
                .map_err(|_| {
                    BrokerSessionSecurityError::manifest("operator Repair before challenge")
                })
        })
    }

    /// Reserves Controller AOSORQ01 custody before the signed post-effect query.
    ///
    /// The exact owner-signed evidence and receipt are checked under the
    /// unchanged issuance and current head before any Inventory request send.
    ///
    /// # Errors
    ///
    /// Rejects a changed head, invalid owner pair, pending broker exchange, or
    /// stale or incomplete authenticated physical Inventory outcome.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn current_operator_repair_after_inventory<C, E>(
        &mut self,
        controller: &mut NodeController<C, E>,
        operation_id: OperationId,
        signed_evidence: &[u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        signed_receipt: &[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            LifecycleAuthenticatedStorageInventoryV1,
        ),
        LifecyclePhase6ErrorV1,
    >
    where
        C: ActivatedOperationCompiler,
        E: SingleNodeEffectExecutor,
    {
        self.challenged_operator_repair_inventory_observation(|request_id| {
            controller
                .reserve_operator_storage_repair_after_inventory_challenge_v1(
                    operation_id,
                    signed_evidence,
                    signed_receipt,
                    request_id,
                )
                .map_err(|_| {
                    BrokerSessionSecurityError::manifest("operator Repair after challenge")
                })
        })
    }

    /// Issues a fresh signed Storage Inventory after the Repair proof is sealed.
    ///
    /// The Controller reserves the authenticated session's actual request ID
    /// before send. This query remains nonterminal until its exact packet,
    /// latest physical state, and public-ledger CAS are checked together.
    ///
    /// # Errors
    ///
    /// Rejects an unsealed or stale proof, owner rotation, an ambiguous broker
    /// exchange, or an incomplete/noncurrent signed Inventory response.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn current_operator_repair_terminal_inventory<C, E>(
        &mut self,
        controller: &mut NodeController<C, E>,
        operation_id: OperationId,
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            LifecycleAuthenticatedStorageInventoryV1,
        ),
        LifecyclePhase6ErrorV1,
    >
    where
        C: ActivatedOperationCompiler,
        E: SingleNodeEffectExecutor,
    {
        self.challenged_operator_repair_inventory_observation(|request_id| {
            controller
                .reserve_operator_storage_repair_terminal_inventory_challenge_v1(
                    operation_id,
                    request_id,
                )
                .map_err(|_| {
                    BrokerSessionSecurityError::manifest("operator Repair terminal challenge")
                })
        })
    }

    /// Recovers only the pending signed Inventory exchange for one retained challenge.
    ///
    /// Cold process restart has no in-memory exchange to resume: the caller
    /// must durably replace its prior challenge before starting a new query.
    /// A historical signed outcome with another ID never becomes current.
    ///
    /// # Errors
    ///
    /// Rejects absent or different pending work, a mismatched request ID,
    /// stale terminal currentness, or incomplete physical inventory.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn recover_challenged_operator_repair_inventory_observation(
        &mut self,
        expected_request_id: [u8; 16],
    ) -> Result<
        (
            AuthenticatedBrokerMethodOutcomeV1,
            LifecycleAuthenticatedStorageInventoryV1,
        ),
        LifecyclePhase6ErrorV1,
    > {
        if expected_request_id == [0; 16] || self.0.pending.is_none() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let (outcome, currentness) = self
            .0
            .query_complete_or_resume_retained(LifecycleInventoryMethodV1::Storage)?;
        if outcome.request().request_id() != expected_request_id {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let inventory =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(&outcome)?;
        self.0.recheck(currentness)?;
        self.operator_repair_inventory_history(
            expected_request_id,
            Some(outcome.canonical_packet()),
        )?;
        Ok((outcome, inventory))
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
            output_registration: None,
            capture_candidate: None,
            #[cfg(feature = "online-nix")]
            nix_generation: None,
            git_coverage: None,
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
