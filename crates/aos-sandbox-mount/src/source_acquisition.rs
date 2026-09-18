//! Durable Mount source acquisition storage and recovery.
//!
//! Namespace 40 is hard-cut to five exact `AOSMSA02` record kinds. Recovery
//! materializes acquisition, holder-sequence, provider-head, provider-session,
//! and provider-query-attempt maps, then validates their complete object graph.
//! No `AOSMSA01` value, v1 key, migration alias, or partial graph is accepted.
//!
//! ```text
//! acquisition = "aos.mount.source-acquisition.v2\0" || acquisition-id[32]
//! head        = "aos.mount.source-provider-head.v2\0" || holder[16] || provider[16]
//! holder-seq  = "aos.mount.source-holder-sequence.v2\0" || holder[16]
//! session     = "aos.mount.source-provider-session.v2\0" || session-id[32]
//! attempt     = "aos.mount.source-provider-query-attempt.v2\0" || attempt-id[32]
//! ```
//!
//! Shared typed records are nonauthorizing data. This table keeps its maps and
//! transitions private; mutations consume purpose-specific provider-security
//! capabilities and protected journal authority. The fixed dormant owner
//! reserves and sends Acquire/Release, retains exact send and response custody,
//! resumes replay-derived pending attempts, and resolves postcommit readback.
//! No listener, service registration, readiness path, or feature advertisement
//! activates those transitions in production.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceResponse, BrokerMethod, InventoryMountSourceAcquisitionsResponse,
    ReleaseMountSourceAcquisitionResponse,
};
use aos_sandbox::journal::{Journal, RecordNamespace};
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceAcquisitionStateV2, validate_mount_source_state_graph_v2,
};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, decode_acquire_mount_source_request,
    decode_release_mount_source_acquisition_request,
};
use buffa::Message as _;

use crate::Result;

mod checkpoint;
mod format;
mod history;
mod inventory;
mod lifecycle;
mod model;
mod outcome;
mod projection;
mod release;
mod release_authority;
mod replacement;
mod reservation;
mod retry;
mod security;
mod transition;
mod validation;
mod wire;

pub(crate) use lifecycle::{CommittedSourceConsumptionV2, SourceConsumptionCommitV2};
pub(crate) use outcome::{ConsumedProviderOutcomeV2, RecoveredProviderOutcomeConsumptionV2};
pub(crate) use release::{ReservedReleaseProviderQueryV2, RetainedReleasePreparationFailureV2};
pub(crate) use reservation::{
    ProviderQuerySendRecoveryV2, ReservedProviderQueryV2, SentProviderQueryV2,
};

use format::{
    MAXIMUM_SOURCE_ACQUISITIONS, MAXIMUM_SOURCE_HOLDER_SEQUENCES, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
    MAXIMUM_SOURCE_PROVIDER_HEADS, MAXIMUM_SOURCE_PROVIDER_SESSIONS, state_error,
};
use lifecycle::SourceAcquisitionPostcommitOutcomeV2;
use model::{
    HolderSequenceV2, ProviderAttemptStateV2, ProviderMethodV2, ProviderStatusV2, RecordRefV2,
    SourceAcquisitionRowV2, SourceProviderHeadV2, SourceProviderQueryAttemptV2,
    SourceProviderSessionV2,
};
pub(crate) use model::{SourceAcquisitionPhaseV2, SourceAcquisitionProofClassV2};
use wire::source_acquisition_record;

/// Maximum retained acquisition rows in one Mount journal.
pub const MAXIMUM_SOURCE_ACQUISITION_ROWS: usize = MAXIMUM_SOURCE_ACQUISITIONS;
/// Maximum stable holder/provider heads in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_HEAD_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_HEADS;
/// Maximum stable holder-wide sequence floors in one Mount journal.
pub const MAXIMUM_SOURCE_HOLDER_SEQUENCE_ROWS: usize = MAXIMUM_SOURCE_HOLDER_SEQUENCES;
/// Maximum immutable authenticated provider sessions in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_SESSION_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_SESSIONS;
/// Maximum immutable provider query attempts in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_ATTEMPT_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_ATTEMPTS;

/// Materializes the complete validated `AOSMSA02` object graph.
#[derive(Clone, Debug)]
pub struct SourceAcquisitionTableV2 {
    acquisitions: BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    holder_sequences: BTreeMap<[u8; 16], HolderSequenceV2>,
    provider_heads: BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV2>,
    provider_sessions: BTreeMap<[u8; 32], SourceProviderSessionV2>,
    provider_attempts: BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
}

/// Owns fixed Mount source state and its sole protected journal root.
///
/// This dormant integration wraps the existing Mount-manager startup owner;
/// it does not open a second trust root. Consumption access is lent only with
/// the purpose-limited opaque journal authority and cannot outlive this owner.
pub struct FixedMountSourceAcquisitionOwnerV2 {
    protected: aos_sandbox::MountManagerStartupProtectedOwnerV1,
    table: SourceAcquisitionTableV2,
    broker_instance_id: [u8; 16],
    last_boottime_nanoseconds: Option<u64>,
    pending_provider: Option<SentProviderQueryV2>,
    pending_provider_send: Option<ProviderQuerySendRecoveryV2>,
    pending_backend_recovery_replacement: Option<BackendRecoveryReplacementV2>,
    pending_inventory_recovery_replacement:
        Option<([u8; 16], [u8; 16], Option<[u8; 32]>, [u8; 32])>,
    pending_release_preparation: Option<RetainedFreshReleasePreparationV2>,
    pending_manager_custody: Vec<RetainedManagerSourceCustodyV2>,
    manager_control: Option<aos_sandbox::mount_manager_startup::ManagerSourceControlAuthorityV1>,
    startup_activation_descriptors:
        Option<aos_sandbox::mount_manager_startup::MountManagerActivationDescriptorsV1>,
    startup_manager_sources:
        Vec<aos_sandbox::mount_manager_startup::StartupManagerSourcePresenceV1>,
    startup_manager_losses: Vec<aos_sandbox::mount_manager_startup::LostMountSourceCustodyV1>,
    startup_lost_release_preparations:
        BTreeMap<[u8; 32], aos_sandbox_source_provider_security::PreparedMountSourceReleaseV2>,
    startup_manager_absences: Vec<aos_sandbox::mount_manager_startup::TerminalMountSourceAbsenceV1>,
    manager_handoffs: Vec<ManagerHandoffStateV1>,
    cold_pending_attempts: Vec<[u8; 32]>,
    retained_source_roots:
        BTreeMap<[u8; 32], aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2>,
    retained_postcommit_recovery: Vec<RetainedSourcePostcommitRecoveryV2>,
    retained_release_authorities:
        Vec<aos_sandbox_source_provider_security::MountSourceReleaseAuthorityV2>,
    retained_terminal_release_outcomes:
        BTreeMap<[u8; 32], aos_sandbox_source_provider_security::VerifiedMountProviderOutcomeV2>,
    retained_terminal_release_response_evidence: BTreeMap<[u8; 32], RecordRefV2>,
    retained_noncomplete_dispositions: BTreeMap<
        ([u8; 32], u8),
        aos_sandbox_source_provider_security::VerifiedMountProviderOutcomeV2,
    >,
    pending_manager_removals: Vec<PendingManagerReleaseV2>,
    retained_negative_custody_recovery: Vec<RetainedNegativeCustodyRecoveryV2>,
    cold_released_rows: Vec<[u8; 32]>,
    retained_released_roots:
        BTreeMap<[u8; 32], aos_sandbox_source_provider_security::ReleasedMountSourceRootV2>,
}

struct ManagerHandoffStateV1 {
    acquisition_id: [u8; 32],
    request: aos_sandbox_protocol::mount_manager_startup::ManagerSourceControlRequestV1,
    accepted:
        Option<aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1>,
    present:
        Option<aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1>,
}

struct PendingManagerReleaseV2 {
    acquisition_id: [u8; 32],
    expected_revision: u64,
    expected_digest: [u8; 32],
    retained: Option<aos_sandbox_source_provider_security::RetainedMountSourceReleaseForRemovalV2>,
    terminal_outcome: Option<aos_sandbox_source_provider_security::VerifiedMountProviderOutcomeV2>,
    stage: Option<ManagerReleaseStageV2>,
}

enum ManagerReleaseStageV2 {
    BeforeRemoval(aos_sandbox::mount_manager_startup::FreshManagerSourcePresenceProjectionV1),
    AwaitingRemoval {
        prior_presence: aos_sandbox::mount_manager_startup::FreshManagerSourcePresenceProjectionV1,
        request: aos_sandbox_protocol::mount_manager_startup::ManagerSourceControlRequestV1,
        removed: Option<
            aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1,
        >,
        absent: Option<
            aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1,
        >,
    },
    Ready(aos_sandbox::mount_manager_startup::FreshManagerSourceRemovalProjectionV1),
    Prepared(lifecycle::ReleaseFinishPreparationV2),
}

/// Retains exact move-only SourceRoot custody until Release reservation commits.
struct RetainedFreshReleasePreparationV2 {
    acquisition_id: [u8; 32],
    mount_request: Vec<u8>,
    prepared_release: aos_sandbox_source_provider_security::PreparedMountSourceReleaseV2,
}

#[derive(Clone, Copy)]
struct BackendRecoveryReplacementV2 {
    acquisition_id: [u8; 32],
    expected_revision: u64,
    expected_digest: [u8; 32],
    method: ProviderMethodV2,
    predecessor_signed_request_digest: [u8; 32],
}

struct RetainedSourcePostcommitRecoveryV2 {
    acquisition_id: [u8; 32],
    recovery: lifecycle::SourceAcquisitionPostcommitRecoveryV2,
    startup_acquire_terminal: Option<RecordRefV2>,
}

struct RetainedNegativeCustodyRecoveryV2 {
    acquisition_id: [u8; 32],
    recovery: lifecycle::SourceAcquisitionNegativeCustodyRecoveryV2,
    startup_terminals: Option<StartupTerminalAttemptsV2>,
}

#[derive(Clone, Copy)]
struct StartupTerminalAttemptsV2 {
    acquire: RecordRefV2,
    release: Option<RecordRefV2>,
}

/// Retains exact manager proof and SourceRoot through descriptor precommit.
enum RetainedManagerSourceCustodyV2 {
    Unpaired {
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        manager_presence: aos_sandbox::mount_manager_startup::FreshManagerSourcePresenceV1,
    },
    Paired {
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        preparation: lifecycle::ManagerSourceCustodyPreparationV2,
    },
}

impl RetainedManagerSourceCustodyV2 {
    const fn acquisition_id(&self) -> [u8; 32] {
        match self {
            Self::Unpaired { acquisition_id, .. } | Self::Paired { acquisition_id, .. } => {
                *acquisition_id
            }
        }
    }
}

impl core::fmt::Debug for FixedMountSourceAcquisitionOwnerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedMountSourceAcquisitionOwnerV2([protected owner])")
    }
}

impl FixedMountSourceAcquisitionOwnerV2 {
    /// Reports whether replay recovered an unsatisfied durable provider attempt.
    #[must_use]
    #[doc(hidden)]
    pub fn has_cold_provider_recovery(&self) -> bool {
        !self.cold_pending_attempts.is_empty()
    }

    /// Reports whether a pre-send carrier boundary retains exact reservation custody.
    #[must_use]
    #[doc(hidden)]
    pub fn has_pending_provider_send(&self) -> bool {
        self.pending_provider_send.is_some()
    }

    /// Reports whether a live sent verifier awaits its exact provider response.
    #[must_use]
    #[doc(hidden)]
    pub fn has_pending_provider_response(&self) -> bool {
        self.pending_provider.is_some()
    }

    /// Reports whether exact SourceRoot custody awaits a Release reservation.
    #[must_use]
    #[doc(hidden)]
    pub fn has_pending_release_preparation(&self) -> bool {
        self.pending_release_preparation.is_some()
    }

    /// Reports whether a committed SourceRoot transition awaits protected resealing.
    #[must_use]
    #[doc(hidden)]
    pub fn has_postcommit_recovery(&self) -> bool {
        !self.retained_postcommit_recovery.is_empty()
    }

    /// Reports whether a manager handoff/removal must advance before response signing.
    #[must_use]
    #[doc(hidden)]
    pub fn has_pending_manager_operation(&self) -> bool {
        !self.manager_handoffs.is_empty()
            || !self.pending_manager_custody.is_empty()
            || !self.pending_manager_removals.is_empty()
            || !self.retained_terminal_release_outcomes.is_empty()
            || !self.startup_manager_sources.is_empty()
            || !self.startup_manager_losses.is_empty()
            || !self.startup_manager_absences.is_empty()
            || self
                .retained_source_roots
                .values()
                .any(|source_root| retained_source_root_phase(source_root).is_none())
    }

    /// Reports whether protected startup physical custody remains unconsumed.
    #[must_use]
    #[doc(hidden)]
    pub fn has_startup_manager_recovery(&self) -> bool {
        !self.startup_manager_sources.is_empty()
            || !self.startup_manager_losses.is_empty()
            || !self.startup_manager_absences.is_empty()
    }

    /// Reports whether manager-negative custody awaits exact protected resealing.
    #[must_use]
    #[doc(hidden)]
    pub fn has_negative_custody_recovery(&self) -> bool {
        !self.retained_negative_custody_recovery.is_empty() || !self.cold_released_rows.is_empty()
    }

    /// Reports whether cold recovery starts after durable outcome consumption.
    #[must_use]
    #[doc(hidden)]
    pub fn cold_provider_recovery_has_consumed_disposition(&self) -> bool {
        self.cold_pending_attempts
            .first()
            .is_some_and(|attempt_id| {
                self.table
                    .provider_attempts
                    .get(attempt_id)
                    .is_some_and(|attempt| {
                        matches!(
                            attempt.state,
                            ProviderAttemptStateV2::DispositionConsumed { .. }
                        )
                    })
            })
    }

    /// Reports whether cold recovery starts from an exact Reserved request.
    #[must_use]
    #[doc(hidden)]
    pub fn cold_provider_recovery_has_reserved_request(&self) -> bool {
        self.cold_pending_attempts
            .first()
            .and_then(|attempt_id| self.table.provider_attempts.get(attempt_id))
            .is_some_and(|attempt| matches!(attempt.state, ProviderAttemptStateV2::Reserved))
    }

    /// Returns the exact signed cold Reserved request for protected Provider readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the oldest cold barrier is an acquisition-owned
    /// Reserved Acquire or Release request whose retained canonical bytes and
    /// digest still match the durable attempt.
    #[doc(hidden)]
    pub fn cold_reserved_provider_request(
        &self,
    ) -> Result<aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1> {
        let attempt_id = self
            .cold_pending_attempts
            .first()
            .ok_or_else(|| state_error("cold provider recovery is absent"))?;
        let attempt = self
            .table
            .provider_attempts
            .get(attempt_id)
            .filter(|attempt| matches!(attempt.state, ProviderAttemptStateV2::Reserved))
            .ok_or_else(|| state_error("cold provider recovery is not Reserved"))?;
        let expected_method = match attempt.method {
            ProviderMethodV2::Acquire => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            }
            ProviderMethodV2::Release => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            }
            ProviderMethodV2::Inventory => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            }
        };
        let signed = aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &attempt.signed_request,
        )
        .map_err(|_| state_error("cold provider request envelope is invalid"))?;
        if signed.method() != expected_method
            || *aos_sandbox_source_provider_protocol::digest_signed_request(&signed).as_bytes()
                != attempt.signed_request_digest
        {
            return Err(state_error(
                "cold provider request differs from its durable identity",
            ));
        }
        Ok(signed)
    }

    /// Returns the exact signed request for the oldest cold provider barrier.
    ///
    /// Unlike [`Self::cold_reserved_provider_request`], this projection also
    /// admits an already-consumed disposition so Provider can reopen a
    /// completed Acquire or return a persisted descriptor-free response.
    ///
    /// # Errors
    ///
    /// Returns an error unless canonical request bytes, method, and durable
    /// signed-request digest all match the oldest protected attempt.
    #[doc(hidden)]
    pub fn cold_provider_request(
        &self,
    ) -> Result<aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1> {
        let attempt_id = self
            .cold_pending_attempts
            .first()
            .ok_or_else(|| state_error("cold provider recovery is absent"))?;
        let attempt = self
            .table
            .provider_attempts
            .get(attempt_id)
            .filter(|attempt| {
                matches!(
                    attempt.state,
                    ProviderAttemptStateV2::Reserved
                        | ProviderAttemptStateV2::DispositionConsumed { .. }
                )
            })
            .ok_or_else(|| state_error("cold provider recovery is not recoverable"))?;
        let expected_method = match attempt.method {
            ProviderMethodV2::Acquire => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            }
            ProviderMethodV2::Release => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            }
            ProviderMethodV2::Inventory => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            }
        };
        let signed = aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &attempt.signed_request,
        )
        .map_err(|_| state_error("cold provider request envelope is invalid"))?;
        if signed.method() != expected_method
            || *aos_sandbox_source_provider_protocol::digest_signed_request(&signed).as_bytes()
                != attempt.signed_request_digest
        {
            return Err(state_error(
                "cold provider request differs from its durable identity",
            ));
        }
        Ok(signed)
    }

    /// Returns the exact signed request retained by live send/response custody.
    ///
    /// # Errors
    ///
    /// Returns an error unless one live stage names a canonical durable
    /// provider attempt with the same signed-request digest.
    #[doc(hidden)]
    pub fn pending_provider_request(
        &self,
    ) -> Result<aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1> {
        let attempt_id = self
            .pending_provider
            .as_ref()
            .map(SentProviderQueryV2::attempt_id)
            .or_else(|| {
                self.pending_provider_send
                    .as_ref()
                    .map(ProviderQuerySendRecoveryV2::attempt_id)
            })
            .ok_or_else(|| state_error("live provider request custody is absent"))?;
        let attempt = self
            .table
            .provider_attempts
            .get(&attempt_id)
            .ok_or_else(|| state_error("live provider request attempt is absent"))?;
        let signed = aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &attempt.signed_request,
        )
        .map_err(|_| state_error("live provider request envelope is invalid"))?;
        if *aos_sandbox_source_provider_protocol::digest_signed_request(&signed).as_bytes()
            != attempt.signed_request_digest
        {
            return Err(state_error(
                "live provider request differs from its durable identity",
            ));
        }
        Ok(signed)
    }

    /// Reports whether a committed Inventory replacement still needs sending.
    #[must_use]
    #[doc(hidden)]
    pub fn has_inventory_recovery_replacement(&self) -> bool {
        self.pending_inventory_recovery_replacement.is_some()
    }

    /// Returns the exact predecessor request for a committed Inventory replacement.
    ///
    /// # Errors
    ///
    /// Returns an error unless replay reconstructed one unambiguous replacement
    /// and its superseded Inventory request still matches the retained digest.
    #[doc(hidden)]
    pub fn inventory_replaced_provider_request(
        &self,
    ) -> Result<aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1> {
        let (_, _, _, signed_request_digest) = self
            .pending_inventory_recovery_replacement
            .ok_or_else(|| state_error("Inventory recovery replacement is absent"))?;
        let mut attempts = self.table.provider_attempts.values().filter(|attempt| {
            attempt.method == ProviderMethodV2::Inventory
                && matches!(
                    attempt.state,
                    ProviderAttemptStateV2::SupersededIndeterminate { .. }
                )
                && attempt.signed_request_digest == signed_request_digest
        });
        let attempt = attempts
            .next()
            .ok_or_else(|| state_error("Inventory recovery predecessor is absent"))?;
        if attempts.next().is_some() {
            return Err(state_error("Inventory recovery predecessor is aliased"));
        }
        let signed = aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1::from_canonical_bytes(
            &attempt.signed_request,
        )
        .map_err(|_| state_error("Inventory recovery predecessor is invalid"))?;
        if signed.method() != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            || *aos_sandbox_source_provider_protocol::digest_signed_request(&signed).as_bytes()
                != signed_request_digest
        {
            return Err(state_error(
                "Inventory recovery predecessor differs from durable identity",
            ));
        }
        Ok(signed)
    }

    /// Reports whether an exact authenticated broker request owns pending I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the request or protected clock is invalid.
    #[doc(hidden)]
    pub fn pending_provider_request_matches(
        &mut self,
        method: BrokerMethod,
        authenticated_request_id: [u8; 16],
        request_body: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
    ) -> Result<bool> {
        let attempt_id = self
            .pending_provider
            .as_ref()
            .map(SentProviderQueryV2::attempt_id)
            .or_else(|| {
                self.pending_provider_send
                    .as_ref()
                    .map(ProviderQuerySendRecoveryV2::attempt_id)
            })
            .or_else(|| self.cold_pending_attempts.first().copied());
        if let Some(pending) = &self.pending_release_preparation {
            if method != BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
                || pending.mount_request != request_body
            {
                return Ok(false);
            }
            let now = self.current_boottime(protected_boot_id)?;
            let live =
                decode_release_mount_source_acquisition_request(request_body, peer, policy, now)?;
            return Ok(live.header().request_id() == &authenticated_request_id);
        }
        let Some(attempt_id) = attempt_id else {
            return Ok(false);
        };
        let (attempt_owner, attempt_method) = self
            .table
            .provider_attempts
            .get(&attempt_id)
            .map(|attempt| (attempt.owner.owner_id(), attempt.method))
            .ok_or_else(|| state_error("outstanding SourceProvider attempt is absent"))?;
        let now = self.current_boottime(protected_boot_id)?;
        let acquisition_id = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
                let live = decode_acquire_mount_source_request(request_body, peer, policy, now)?;
                if live.header().request_id() != &authenticated_request_id {
                    return Ok(false);
                }
                live.acquisition_id().as_bytes().to_owned()
            }
            BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
                let live = decode_release_mount_source_acquisition_request(
                    request_body,
                    peer,
                    policy,
                    now,
                )?;
                if live.header().request_id() != &authenticated_request_id {
                    return Ok(false);
                }
                live.acquisition_id().as_bytes().to_owned()
            }
            _ => return Ok(false),
        };
        let provider_method = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => ProviderMethodV2::Acquire,
            BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
                ProviderMethodV2::Release
            }
            _ => return Ok(false),
        };
        if attempt_owner != acquisition_id || attempt_method != provider_method {
            return Ok(false);
        }
        let row = self
            .table
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("outstanding provider request owner row is absent"))?;
        let exact_request_matches = match provider_method {
            ProviderMethodV2::Acquire => {
                row.acquire.operation_id == authenticated_request_id
                    && row.mount_acquire_request == request_body
                    && row.acquire.request_digest
                        == *aos_sandbox_protocol::mount_source_acquisition_request_digest_v1(
                            request_body,
                        )
                        .as_bytes()
            }
            ProviderMethodV2::Release => {
                row.release.is_some_and(|operation| {
                    operation.operation_id == authenticated_request_id
                        && operation.request_digest
                            == *aos_sandbox_protocol::mount_source_acquisition_request_digest_v1(
                                request_body,
                            )
                            .as_bytes()
                }) && row.mount_release_request.as_deref() == Some(request_body)
            }
            ProviderMethodV2::Inventory => false,
        };
        Ok(exact_request_matches)
    }

    /// Opens the existing fixed Mount journal owner and fully replays AOSMSA02.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed root, lock, startup policy, consumption
    /// scope, or complete canonical source-acquisition graph is invalid.
    #[doc(hidden)]
    pub fn open_fixed() -> Result<(Self, aos_sandbox::MountManagerStartupProtectedOpenReportV1)> {
        let (mut protected, report) =
            aos_sandbox::MountManagerStartupProtectedOwnerV1::open_fixed_protected()
                .map_err(|error| crate::MountError::State(error.to_string()))?;
        let table = {
            let authority = protected
                .source_consumption_authority()
                .map_err(|error| crate::MountError::State(error.to_string()))?;
            SourceAcquisitionTableV2::recover_from_consumption_authority(&authority)?
        };
        let mut broker_instance_id = [0_u8; 16];
        fill_random(&mut broker_instance_id)?;
        if broker_instance_id == [0; 16] {
            return Err(crate::MountError::State(
                "kernel returned a sentinel broker instance ID".to_owned(),
            ));
        }
        let mut cold_pending_attempts: Vec<_> = table
            .provider_attempts
            .values()
            .filter(|attempt| {
                matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    || (matches!(
                        attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed { .. }
                    ) && table
                        .acquisitions
                        .get(&attempt.owner.owner_id())
                        .is_some_and(|row| {
                            let terminal_attempt_matches = match attempt.method {
                                ProviderMethodV2::Acquire => {
                                    row.acquire_lineage.tail.id == attempt.attempt_id
                                }
                                ProviderMethodV2::Release => row
                                    .release_lineage
                                    .as_ref()
                                    .is_some_and(|lineage| lineage.tail.id == attempt.attempt_id),
                                ProviderMethodV2::Inventory => false,
                            };
                            terminal_attempt_matches
                                && matches!(
                                    row.phase,
                                    SourceAcquisitionPhaseV2::PendingQuery
                                        | SourceAcquisitionPhaseV2::DescriptorCustodied
                                        | SourceAcquisitionPhaseV2::Active
                                        | SourceAcquisitionPhaseV2::Consumed
                                        | SourceAcquisitionPhaseV2::Releasing
                                        | SourceAcquisitionPhaseV2::Faulted
                                )
                        }))
            })
            .map(|attempt| attempt.attempt_id)
            .collect();
        // Restore the retained Acquire descriptor before resolving its Release.
        cold_pending_attempts.sort_by_key(|attempt_id| {
            table
                .provider_attempts
                .get(attempt_id)
                .map_or(3, |attempt| match (&attempt.method, &attempt.state) {
                    (ProviderMethodV2::Acquire, _) => 0,
                    (ProviderMethodV2::Release, ProviderAttemptStateV2::Reserved) => 1,
                    (
                        ProviderMethodV2::Release,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: ProviderStatusV2::Complete,
                            ..
                        },
                    ) => 2,
                    _ => 3,
                })
        });
        let cold_released_rows = table
            .acquisitions
            .values()
            .filter(|row| row.phase == SourceAcquisitionPhaseV2::Released)
            .map(|row| row.acquisition_id)
            .collect();
        let mut backend_recovery_replacements = table
            .provider_attempts
            .values()
            .filter_map(|attempt| {
                if !matches!(
                    attempt.state,
                    ProviderAttemptStateV2::SupersededIndeterminate { .. }
                ) {
                    return None;
                }
                let acquisition_id = attempt.owner.owner_id();
                let row = table.acquisitions.get(&acquisition_id)?;
                let tail = match attempt.method {
                    ProviderMethodV2::Acquire => Some(row.acquire_lineage.tail),
                    ProviderMethodV2::Release => {
                        row.release_lineage.as_ref().map(|lineage| lineage.tail)
                    }
                    ProviderMethodV2::Inventory => None,
                }?;
                (tail.id == attempt.attempt_id
                    && tail.revision == attempt.revision
                    && tail.record_digest == attempt.record_digest)
                    .then_some(BackendRecoveryReplacementV2 {
                        acquisition_id,
                        expected_revision: row.revision,
                        expected_digest: row.record_digest,
                        method: attempt.method,
                        predecessor_signed_request_digest: attempt.signed_request_digest,
                    })
            })
            .collect::<Vec<_>>();
        if backend_recovery_replacements.len() > 1 {
            return Err(state_error(
                "multiple backend recovery replacement stages are unresolved",
            ));
        }
        let pending_backend_recovery_replacement = backend_recovery_replacements.pop();
        let mut inventory_replacements = table
            .provider_heads
            .values()
            .filter_map(|head| {
                if head.pending_attempt.is_some() {
                    return None;
                }
                let tail = head
                    .recovery_barrier
                    .as_ref()
                    .and_then(|barrier| barrier.recovery_inventory_tail)
                    .or(head.last_inventory_attempt)?;
                let attempt = table.provider_attempts.get(&tail.id).filter(|attempt| {
                    attempt.revision == tail.revision
                        && attempt.record_digest == tail.record_digest
                        && attempt.method == ProviderMethodV2::Inventory
                        && matches!(
                            attempt.state,
                            ProviderAttemptStateV2::SupersededIndeterminate { .. }
                        )
                })?;
                Some((
                    head.scope.holder_authority_id,
                    head.scope.provider_authority_id,
                    head.recovery_barrier
                        .as_ref()
                        .map(|barrier| barrier.root_attempt.id),
                    attempt.signed_request_digest,
                ))
            })
            .collect::<Vec<_>>();
        if inventory_replacements.len() > 1 {
            return Err(state_error(
                "multiple Inventory recovery replacement stages are unresolved",
            ));
        }
        let pending_inventory_recovery_replacement = inventory_replacements.pop();
        Ok((
            Self {
                protected,
                table,
                broker_instance_id,
                last_boottime_nanoseconds: None,
                pending_provider: None,
                pending_provider_send: None,
                pending_backend_recovery_replacement,
                pending_inventory_recovery_replacement,
                pending_release_preparation: None,
                pending_manager_custody: Vec::new(),
                manager_control: None,
                startup_activation_descriptors: None,
                startup_manager_sources: Vec::new(),
                startup_manager_losses: Vec::new(),
                startup_lost_release_preparations: BTreeMap::new(),
                startup_manager_absences: Vec::new(),
                manager_handoffs: Vec::new(),
                cold_pending_attempts,
                retained_source_roots: BTreeMap::new(),
                retained_postcommit_recovery: Vec::new(),
                retained_release_authorities: Vec::new(),
                retained_terminal_release_outcomes: BTreeMap::new(),
                retained_terminal_release_response_evidence: BTreeMap::new(),
                retained_noncomplete_dispositions: BTreeMap::new(),
                pending_manager_removals: Vec::new(),
                retained_negative_custody_recovery: Vec::new(),
                cold_released_rows,
                retained_released_roots: BTreeMap::new(),
            },
            report,
        ))
    }

    /// Runs one operation under the existing fixed consumption authority.
    ///
    /// The closure receives only the validated table and purpose-specific
    /// journal handoff. It cannot retain either borrow or obtain the raw
    /// journal, startup authority, or another protected namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed owner cannot re-establish its protected
    /// consumption scope or when `operation` rejects current state.
    #[doc(hidden)]
    pub fn with_consumption_authority<R>(
        &mut self,
        operation: impl for<'authority> FnOnce(
            &mut SourceAcquisitionTableV2,
            &mut aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'authority>,
        ) -> Result<R>,
    ) -> Result<R> {
        let mut authority = self
            .protected
            .source_consumption_authority()
            .map_err(|error| crate::MountError::State(error.to_string()))?;
        operation(&mut self.table, &mut authority)
    }

    /// Runs one operation under the exact fixed namespace-40 owner claim.
    ///
    /// The purpose wrapper may lend the raw claim only through its
    /// higher-ranked nonescaping borrow. This permits nesting a fixed
    /// Root-Mount session operation without making caller-selected journal
    /// authority usable by any public SourceProvider transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed owner cannot establish its exact
    /// namespace-40 scope or when `operation` rejects current state.
    #[doc(hidden)]
    pub fn with_source_acquisition_authority<R>(
        &mut self,
        operation: impl for<'authority> FnOnce(
            &mut SourceAcquisitionTableV2,
            &mut aos_sandbox::MountSourceAcquisitionJournalAuthorityV2<'authority>,
        ) -> Result<R>,
    ) -> Result<R> {
        let mut authority = self
            .protected
            .source_acquisition_authority()
            .map_err(|error| crate::MountError::State(error.to_string()))?;
        operation(&mut self.table, &mut authority)
    }

    /// Installs the move-only manager control authority produced by startup capture.
    ///
    /// # Errors
    ///
    /// Returns an error if a control authority is already installed.
    #[doc(hidden)]
    pub fn install_manager_control_authority(
        &mut self,
        control: aos_sandbox::mount_manager_startup::ManagerSourceControlAuthorityV1,
    ) -> Result<()> {
        if self.manager_control.is_some() {
            return Err(state_error(
                "manager control authority is already installed",
            ));
        }
        self.manager_control = Some(control);
        Ok(())
    }

    /// Installs one complete protected physical startup capture for cold recovery.
    ///
    /// The fixed owner retains all descriptor, presence, absence, and control
    /// capabilities until their exact namespace-40 transitions are consumed.
    ///
    /// # Errors
    ///
    /// Returns the unchanged authority if another startup capture or control
    /// authority is already installed.
    #[doc(hidden)]
    pub fn install_manager_startup_authority(
        &mut self,
        authority: aos_sandbox::mount_manager_startup::MountManagerStartupAuthorityV1,
    ) -> std::result::Result<
        (),
        (
            crate::MountError,
            aos_sandbox::mount_manager_startup::MountManagerStartupAuthorityV1,
        ),
    > {
        if self.manager_control.is_some()
            || self.startup_activation_descriptors.is_some()
            || !self.startup_manager_sources.is_empty()
            || !self.startup_manager_losses.is_empty()
            || !self.startup_manager_absences.is_empty()
        {
            return Err((
                state_error("manager startup authority is already installed"),
                authority,
            ));
        }
        let (descriptors, sources, losses, absences, control) = authority.into_parts();
        self.startup_activation_descriptors = Some(descriptors);
        self.startup_manager_sources = sources;
        self.startup_manager_losses = losses;
        self.startup_manager_absences = absences.into_absences();
        self.manager_control = Some(control);
        Ok(())
    }

    fn exact_complete_terminal_attempt(
        &self,
        acquisition_id: [u8; 32],
        method: ProviderMethodV2,
    ) -> Result<Option<RecordRefV2>> {
        let row = self
            .table
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("startup manager source row is absent"))?;
        let terminal = match method {
            ProviderMethodV2::Acquire => Some(
                row.acquire_terminal_attempt
                    .ok_or_else(|| state_error("startup source has no terminal Acquire"))?,
            ),
            ProviderMethodV2::Release => row.release_terminal_attempt,
            ProviderMethodV2::Inventory => {
                return Err(state_error(
                    "startup source cannot supersede an Inventory attempt",
                ));
            }
        };
        let Some(terminal) = terminal else {
            return Ok(None);
        };
        let lineage_tail = match method {
            ProviderMethodV2::Acquire => row.acquire_lineage.tail,
            ProviderMethodV2::Release => {
                row.release_lineage
                    .as_ref()
                    .map(|lineage| lineage.tail)
                    .ok_or_else(|| state_error("startup source has no Release lineage"))?
            }
            ProviderMethodV2::Inventory => {
                return Err(state_error(
                    "startup source cannot supersede an Inventory attempt",
                ));
            }
        };
        let attempt = self
            .table
            .provider_attempts
            .get(&terminal.id)
            .filter(|attempt| {
                terminal == lineage_tail
                    && attempt.revision == terminal.revision
                    && attempt.record_digest == terminal.record_digest
                    && attempt.method == method
                    && attempt.owner.owner_id() == acquisition_id
                    && matches!(
                        attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: ProviderStatusV2::Complete,
                            ..
                        }
                    )
            })
            .ok_or_else(|| state_error("startup source terminal attempt lineage differs"))?;
        if self.cold_pending_attempts.iter().any(|attempt_id| {
            self.table
                .provider_attempts
                .get(attempt_id)
                .is_some_and(|queued| {
                    queued.owner.owner_id() == acquisition_id
                        && queued.method == method
                        && matches!(
                            queued.state,
                            ProviderAttemptStateV2::DispositionConsumed {
                                status: ProviderStatusV2::Complete,
                                ..
                            }
                        )
                        && queued.attempt_id != attempt.attempt_id
                })
        }) {
            return Err(state_error(
                "startup source has conflicting cold terminal attempt custody",
            ));
        }
        Ok(Some(terminal))
    }

    fn resolve_superseded_cold_attempt(&mut self, terminal: RecordRefV2) {
        self.cold_pending_attempts
            .retain(|attempt_id| *attempt_id != terminal.id);
    }

    /// Consumes one protected startup presence or absence into exact Mount custody.
    ///
    /// # Errors
    ///
    /// Returns an error unless the current Root-Mount session and protected
    /// startup capture name the same durable acquisition state.
    #[doc(hidden)]
    pub fn resume_next_startup_manager_custody(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        if let Some(acquisition_id) = self
            .startup_manager_sources
            .last()
            .map(|presence| presence.custody_evidence().acquisition_id)
        {
            let terminal = self
                .exact_complete_terminal_attempt(acquisition_id, ProviderMethodV2::Acquire)?
                .ok_or_else(|| state_error("startup source has no terminal Acquire"))?;
            let presence = self
                .startup_manager_sources
                .pop()
                .ok_or_else(|| state_error("startup manager source custody disappeared"))?;
            let phase = self
                .table
                .acquisitions
                .get(&acquisition_id)
                .map(|row| row.phase)
                .ok_or_else(|| state_error("startup manager source row is absent"))?;
            let mut retained_presence = Some(presence);
            let outcome = root
                .with_current_session(|session| {
                    self.with_source_acquisition_authority(|table, authority| {
                        authority.with_authority(|journal| {
                            let presence = retained_presence.take().ok_or_else(|| {
                                state_error("startup manager presence was already consumed")
                            })?;
                            if phase == SourceAcquisitionPhaseV2::PendingQuery {
                                table.record_startup_descriptor_custody_v2(
                                    journal, session, presence,
                                )
                            } else {
                                table.adopt_startup_retained_source_v2(journal, session, presence)
                            }
                        })
                    })
                })
                .map_err(|_| state_error("Root-Mount provider session is not current"))
                .and_then(|value| {
                    value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
                })
                .and_then(core::convert::identity);
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    if let Some(presence) = retained_presence {
                        self.startup_manager_sources.push(presence);
                    }
                    return Err(error);
                }
            };
            return match outcome {
                lifecycle::SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                    match source_root {
                        aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::StartupAdopted(
                            aos_sandbox_source_provider_security::RecoveredRetainedMountSourceRootV2::Releasing(authority),
                        ) => self.retained_release_authorities.push(authority),
                        source_root => {
                            self.retained_source_roots.insert(acquisition_id, source_root);
                        }
                    }
                    self.resolve_superseded_cold_attempt(terminal);
                    Ok(())
                }
                lifecycle::SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                    self.retained_postcommit_recovery
                        .push(RetainedSourcePostcommitRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_acquire_terminal: Some(terminal),
                        });
                    Err(state_error("startup manager custody recovery is required"))
                }
            };
        }
        if let Some(acquisition_id) = self
            .startup_manager_losses
            .last()
            .map(|loss| loss.projection().subject.acquisition_id)
        {
            let terminal = self
                .exact_complete_terminal_attempt(acquisition_id, ProviderMethodV2::Acquire)?
                .ok_or_else(|| state_error("lost startup source has no terminal Acquire"))?;
            let loss = self
                .startup_manager_losses
                .pop()
                .ok_or_else(|| state_error("startup manager loss custody disappeared"))?;
            let mut retained_loss = Some(loss);
            let prepared = root
                .with_current_session(|session| {
                    self.with_source_acquisition_authority(|table, authority| {
                        authority.with_authority(|journal| {
                            let loss = retained_loss.take().ok_or_else(|| {
                                state_error("startup manager loss was already consumed")
                            })?;
                            table.prepare_lost_source_cleanup_v2(journal, session, loss)
                        })
                    })
                })
                .map_err(|_| state_error("Root-Mount provider session is not current"))
                .and_then(|value| {
                    value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
                })
                .and_then(core::convert::identity);
            match prepared {
                Ok(prepared) => {
                    self.startup_lost_release_preparations
                        .insert(acquisition_id, prepared);
                    self.resolve_superseded_cold_attempt(terminal);
                    return Ok(());
                }
                Err(error) => {
                    if let Some(loss) = retained_loss {
                        self.startup_manager_losses.push(loss);
                    }
                    return Err(error);
                }
            }
        }
        if let Some(acquisition_id) = self
            .startup_manager_absences
            .last()
            .map(|absence| absence.projection().subject.acquisition_id)
        {
            let acquire_terminal = self
                .exact_complete_terminal_attempt(acquisition_id, ProviderMethodV2::Acquire)?
                .ok_or_else(|| state_error("terminal startup absence has no terminal Acquire"))?;
            let terminal =
                self.exact_complete_terminal_attempt(acquisition_id, ProviderMethodV2::Release)?;
            if let Some(outcome) = self.retained_terminal_release_outcomes.get(&acquisition_id)
                && (terminal.is_none()
                    || !self.table.retained_disposition_matches_v2(
                        acquisition_id,
                        ProviderMethodV2::Release,
                        outcome,
                    )?)
            {
                return Err(state_error(
                    "startup absence terminal Release evidence differs",
                ));
            }
            let absence = self
                .startup_manager_absences
                .pop()
                .ok_or_else(|| state_error("startup manager absence custody disappeared"))?;
            let mut retained_absence = Some(absence);
            let outcome = root
                .with_current_session(|session| {
                    self.with_source_acquisition_authority(|table, authority| {
                        authority.with_authority(|journal| {
                            let absence = retained_absence.take().ok_or_else(|| {
                                state_error("startup manager absence was already consumed")
                            })?;
                            table.recover_and_finish_release_absence_v2(journal, session, absence)
                        })
                    })
                })
                .map_err(|_| state_error("Root-Mount provider session is not current"))
                .and_then(|value| {
                    value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
                })
                .and_then(core::convert::identity);
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    if let Some(absence) = retained_absence {
                        self.startup_manager_absences.push(absence);
                    }
                    return Err(error);
                }
            };
            return match outcome {
                lifecycle::SourceAcquisitionNegativeCustodyOutcomeV2::Success(released) => {
                    self.retained_released_roots
                        .insert(acquisition_id, released);
                    self.resolve_superseded_cold_attempt(acquire_terminal);
                    if let Some(terminal) = terminal {
                        self.resolve_superseded_cold_attempt(terminal);
                        self.retained_terminal_release_outcomes
                            .remove(&acquisition_id);
                        self.retained_terminal_release_response_evidence
                            .insert(acquisition_id, terminal);
                    }
                    Ok(())
                }
                lifecycle::SourceAcquisitionNegativeCustodyOutcomeV2::RecoveryRequired(
                    recovery,
                ) => {
                    self.retained_negative_custody_recovery.push(
                        RetainedNegativeCustodyRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_terminals: Some(StartupTerminalAttemptsV2 {
                                acquire: acquire_terminal,
                                release: terminal,
                            }),
                        },
                    );
                    Err(state_error("startup manager absence recovery is required"))
                }
            };
        }
        Err(state_error("no startup manager custody awaits recovery"))
    }

    /// Begins one exact manager descriptor handoff from the current source row.
    ///
    /// The returned bytes are nonauthorizing transport material. All authority
    /// and retry state remains inside this fixed owner.
    ///
    /// # Errors
    ///
    /// Returns an error for missing source/control authority or stale protected state.
    #[doc(hidden)]
    pub fn begin_manager_source_handoff(&mut self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        if self
            .manager_handoffs
            .iter()
            .any(|pending| pending.acquisition_id == acquisition_id)
        {
            return Err(state_error("manager handoff is already pending"));
        }
        if !matches!(
            self.retained_source_roots.get(&acquisition_id),
            Some(
                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Received(_)
                    | aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Reopened(
                        _
                    )
            )
        ) {
            return Err(state_error(
                "manager handoff lacks exact received SourceRoot custody",
            ));
        }
        let row = self
            .table
            .acquisitions
            .get(&acquisition_id)
            .cloned()
            .ok_or_else(|| state_error("manager handoff acquisition is absent"))?;
        let mut control = self
            .manager_control
            .take()
            .ok_or_else(|| state_error("manager control authority is absent"))?;
        let pending = self
            .protected
            .control_session()
            .map_err(|error| state_error(error.to_string()))
            .and_then(|mut session| {
                session
                    .begin_handoff(&mut control, &row)
                    .map_err(|error| state_error(error.to_string()))
            });
        self.manager_control = Some(control);
        let pending = pending?;
        let request = pending.request().clone();
        self.manager_handoffs.push(ManagerHandoffStateV1 {
            acquisition_id,
            request: request.clone(),
            accepted: None,
            present: None,
        });
        let bytes =
            aos_sandbox_protocol::mount_manager_startup::encode_manager_source_control_request_v1(
                &request,
            )
            .map_err(|error| state_error(error.to_string()))?;
        Ok(bytes)
    }

    /// Authenticates descriptor acceptance while retaining positive-readback custody.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the retained request when the signed
    /// outcome or protected history is inconsistent.
    #[doc(hidden)]
    pub fn accept_manager_source_handoff(
        &mut self,
        acquisition_id: [u8; 32],
        accepted: aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1,
    ) -> Result<Vec<u8>> {
        let index = self
            .manager_handoffs
            .iter()
            .position(|pending| pending.acquisition_id == acquisition_id)
            .ok_or_else(|| state_error("manager handoff is absent"))?;
        if self.manager_handoffs[index].accepted.is_none() {
            self.manager_handoffs[index].accepted = Some(accepted);
        }
        let request = self.manager_handoffs[index].request.clone();
        let accepted = self.manager_handoffs[index]
            .accepted
            .clone()
            .ok_or_else(|| state_error("manager handoff acceptance is absent"))?;
        {
            let mut session = self
                .protected
                .control_session()
                .map_err(|error| state_error(error.to_string()))?;
            let recovered = session
                .recover_handoff(request.clone(), Some(accepted))
                .map_err(|error| state_error(error.to_string()))?;
            let aos_sandbox::mount_manager_startup::FreshManagerSourceHandoffRecoveryV1::AwaitingPresence(
                _,
            ) = recovered
            else {
                return Err(state_error("manager handoff recovery phase differs"));
            };
        }
        aos_sandbox_protocol::mount_manager_startup::encode_manager_source_control_request_v1(
            &request,
        )
        .map_err(|error| state_error(error.to_string()))
    }

    /// Authenticates positive readback and commits exact manager SourceRoot custody.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining recoverable handoff or SourceRoot
    /// custody when the outcome, protected session, or descriptor commit fails.
    #[doc(hidden)]
    pub fn confirm_manager_source_present(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        acquisition_id: [u8; 32],
        present: aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1,
    ) -> Result<()> {
        let index = self
            .manager_handoffs
            .iter()
            .position(|pending| pending.acquisition_id == acquisition_id)
            .ok_or_else(|| state_error("manager handoff is absent"))?;
        let request = self.manager_handoffs[index].request.clone();
        let accepted = self.manager_handoffs[index]
            .accepted
            .clone()
            .ok_or_else(|| state_error("manager handoff acceptance is absent"))?;
        if self.manager_handoffs[index].present.is_none() {
            self.manager_handoffs[index].present = Some(present);
        }
        let present = self.manager_handoffs[index]
            .present
            .clone()
            .ok_or_else(|| state_error("manager presence outcome is absent"))?;
        let presence = {
            let mut session = self
                .protected
                .control_session()
                .map_err(|error| state_error(error.to_string()))?;
            let recovered = session
                .recover_handoff(request, Some(accepted))
                .map_err(|error| state_error(error.to_string()))?;
            let aos_sandbox::mount_manager_startup::FreshManagerSourceHandoffRecoveryV1::AwaitingPresence(
                awaiting,
            ) = recovered
            else {
                return Err(state_error("manager presence recovery phase differs"));
            };
            session
                .confirm_present(awaiting, present)
                .map_err(|error| state_error(error.to_string()))?
        };
        self.manager_handoffs.remove(index);
        self.record_manager_source_presence(root, acquisition_id, presence)
    }

    /// Begins manager removal for one provider-terminal Release.
    ///
    /// # Errors
    ///
    /// Returns an error unless exact Release authority, terminal provider
    /// outcome, fresh manager presence, control authority, and row CAS agree.
    #[doc(hidden)]
    pub fn begin_manager_source_removal(&mut self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        if self
            .pending_manager_removals
            .iter()
            .any(|pending| pending.acquisition_id == acquisition_id)
        {
            return Err(state_error("manager source removal is already pending"));
        }
        let row = self
            .table
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("manager source removal row is absent"))?;
        let expected_revision = row.revision;
        let expected_digest = row.record_digest;
        let terminal_outcome = self
            .retained_terminal_release_outcomes
            .remove(&acquisition_id)
            .ok_or_else(|| state_error("terminal provider Release outcome is absent"))?;
        let authority_index = self
            .retained_release_authorities
            .iter()
            .position(|authority| {
                authority.projection().mount_acquisition_id() == Some(acquisition_id)
            });
        let Some(authority_index) = authority_index else {
            self.retained_terminal_release_outcomes
                .insert(acquisition_id, terminal_outcome);
            return Err(state_error("SourceRoot Release authority is absent"));
        };
        let authority = self.retained_release_authorities.remove(authority_index);
        match authority.prepare_manager_removal() {
            aos_sandbox_source_provider_security::MountSourceRemovalPreparationV2::Fresh {
                retained,
                presence,
            } => {
                let presence_projection = presence.projection().clone();
                drop(presence);
                self.pending_manager_removals.push(PendingManagerReleaseV2 {
                    acquisition_id,
                    expected_revision,
                    expected_digest,
                    retained: Some(retained),
                    terminal_outcome: Some(terminal_outcome),
                    stage: Some(ManagerReleaseStageV2::BeforeRemoval(presence_projection)),
                });
                self.resume_manager_source_removal(acquisition_id)
            }
            aos_sandbox_source_provider_security::MountSourceRemovalPreparationV2::StartupRecoveryRequired(
                authority,
            )
            | aos_sandbox_source_provider_security::MountSourceRemovalPreparationV2::StartupLost(
                authority,
            ) => {
                self.retained_release_authorities.push(authority);
                self.retained_terminal_release_outcomes
                    .insert(acquisition_id, terminal_outcome);
                Err(state_error(
                    "manager source removal requires startup recovery",
                ))
            }
        }
    }

    /// Resumes or reads the exact pending manager-removal request.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining all Release, SourceRoot, presence, and
    /// provider-outcome custody when protected recovery or request issue fails.
    #[doc(hidden)]
    pub fn resume_manager_source_removal(&mut self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        let index = self
            .pending_manager_removals
            .iter()
            .position(|pending| pending.acquisition_id == acquisition_id)
            .ok_or_else(|| state_error("manager source removal is absent"))?;
        let mut pending = self.pending_manager_removals.remove(index);
        let stage = match pending.stage.take() {
            Some(stage) => stage,
            None => {
                self.pending_manager_removals.push(pending);
                return Err(state_error("manager removal stage is unavailable"));
            }
        };
        match stage {
            ManagerReleaseStageV2::BeforeRemoval(presence_projection) => {
                let mut control = match self.manager_control.take() {
                    Some(control) => control,
                    None => {
                        pending.stage =
                            Some(ManagerReleaseStageV2::BeforeRemoval(presence_projection));
                        self.pending_manager_removals.push(pending);
                        return Err(state_error("manager control authority is absent"));
                    }
                };
                let result = self
                    .protected
                    .control_session()
                    .map_err(|error| state_error(error.to_string()))
                    .and_then(|mut session| {
                        let presence = session
                            .recover_presence(presence_projection.clone())
                            .map_err(|error| state_error(error.to_string()))?;
                        session
                            .begin_removal(&mut control, presence)
                            .map_err(|error| state_error(error.to_string()))
                    });
                self.manager_control = Some(control);
                match result {
                    Ok(removal) => {
                        let request = removal.request().clone();
                        pending.stage = Some(ManagerReleaseStageV2::AwaitingRemoval {
                            prior_presence: presence_projection,
                            request: request.clone(),
                            removed: None,
                            absent: None,
                        });
                        self.pending_manager_removals.push(pending);
                        aos_sandbox_protocol::mount_manager_startup::encode_manager_source_control_request_v1(&request)
                            .map_err(|error| state_error(error.to_string()))
                    }
                    Err(error) => {
                        pending.stage =
                            Some(ManagerReleaseStageV2::BeforeRemoval(presence_projection));
                        self.pending_manager_removals.push(pending);
                        Err(error)
                    }
                }
            }
            ManagerReleaseStageV2::AwaitingRemoval {
                prior_presence,
                request,
                removed,
                absent,
            } => {
                let bytes = aos_sandbox_protocol::mount_manager_startup::encode_manager_source_control_request_v1(&request)
                    .map_err(|error| state_error(error.to_string()));
                pending.stage = Some(ManagerReleaseStageV2::AwaitingRemoval {
                    prior_presence,
                    request,
                    removed,
                    absent,
                });
                self.pending_manager_removals.push(pending);
                bytes
            }
            stage => {
                pending.stage = Some(stage);
                self.pending_manager_removals.push(pending);
                Err(state_error("manager removal no longer awaits request I/O"))
            }
        }
    }

    /// Authenticates the manager's descriptor-removed outcome.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining the exact request and supplied outcome
    /// for protected recovery and exact retry.
    #[doc(hidden)]
    pub fn accept_manager_source_removal(
        &mut self,
        acquisition_id: [u8; 32],
        removed: aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1,
    ) -> Result<()> {
        let index = self
            .pending_manager_removals
            .iter()
            .position(|pending| pending.acquisition_id == acquisition_id)
            .ok_or_else(|| state_error("manager source removal is absent"))?;
        let pending = &mut self.pending_manager_removals[index];
        let Some(ManagerReleaseStageV2::AwaitingRemoval {
            prior_presence,
            request,
            removed: retained_removed,
            ..
        }) = pending.stage.as_mut()
        else {
            return Err(state_error("manager source removal phase differs"));
        };
        if retained_removed.is_none() {
            *retained_removed = Some(removed);
        }
        let retained_removed = retained_removed
            .clone()
            .ok_or_else(|| state_error("manager removed outcome is absent"))?;
        let mut session = self
            .protected
            .control_session()
            .map_err(|error| state_error(error.to_string()))?;
        let recovered = session
            .recover_removal(
                prior_presence.clone(),
                request.clone(),
                Some(retained_removed),
            )
            .map_err(|error| state_error(error.to_string()))?;
        if !matches!(
            recovered,
            aos_sandbox::mount_manager_startup::FreshManagerSourceRemovalRecoveryV1::AwaitingAbsence(_)
        ) {
            return Err(state_error("manager removal recovery phase differs"));
        }
        Ok(())
    }

    /// Authenticates negative readback and finishes exact Released state.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining the removal chain and all terminal
    /// SourceRoot/provider custody for exact recovery.
    #[doc(hidden)]
    pub fn confirm_manager_source_absent(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        acquisition_id: [u8; 32],
        absent: aos_sandbox_protocol::mount_manager_startup::SignedManagerSourceControlOutcomeV1,
    ) -> Result<()> {
        let index = self
            .pending_manager_removals
            .iter()
            .position(|pending| pending.acquisition_id == acquisition_id)
            .ok_or_else(|| state_error("manager source removal is absent"))?;
        let receipt_projection = {
            let pending = &mut self.pending_manager_removals[index];
            let Some(ManagerReleaseStageV2::AwaitingRemoval {
                prior_presence,
                request,
                removed,
                absent: retained_absent,
            }) = pending.stage.as_mut()
            else {
                return Err(state_error("manager source removal phase differs"));
            };
            if retained_absent.is_none() {
                *retained_absent = Some(absent);
            }
            let removed = removed
                .clone()
                .ok_or_else(|| state_error("manager removed outcome is absent"))?;
            let retained_absent = retained_absent
                .clone()
                .ok_or_else(|| state_error("manager absent outcome is absent"))?;
            let mut session = self
                .protected
                .control_session()
                .map_err(|error| state_error(error.to_string()))?;
            let recovered = session
                .recover_removal(prior_presence.clone(), request.clone(), Some(removed))
                .map_err(|error| state_error(error.to_string()))?;
            let aos_sandbox::mount_manager_startup::FreshManagerSourceRemovalRecoveryV1::AwaitingAbsence(
                awaiting,
            ) = recovered
            else {
                return Err(state_error("manager absence recovery phase differs"));
            };
            session
                .confirm_absent(awaiting, retained_absent)
                .map_err(|error| state_error(error.to_string()))?
                .into_projection()
        };
        self.pending_manager_removals[index].stage =
            Some(ManagerReleaseStageV2::Ready(receipt_projection));
        self.finish_pending_manager_release(root, acquisition_id)
    }

    /// Finishes a retained manager-negative Release without redispatching effects.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining the exact receipt or prepared
    /// negative-custody transition when protected completion remains uncertain.
    #[doc(hidden)]
    pub fn finish_pending_manager_release(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        acquisition_id: [u8; 32],
    ) -> Result<()> {
        let index = self
            .pending_manager_removals
            .iter()
            .position(|pending| pending.acquisition_id == acquisition_id)
            .ok_or_else(|| state_error("manager source removal is absent"))?;
        let mut pending = self.pending_manager_removals.remove(index);
        let expected_revision = pending.expected_revision;
        let expected_digest = pending.expected_digest;
        let stage = match pending.stage.take() {
            Some(stage) => stage,
            None => {
                self.pending_manager_removals.push(pending);
                return Err(state_error("manager release stage is absent"));
            }
        };
        let preparation = match stage {
            ManagerReleaseStageV2::Ready(projection) => {
                let receipt = match self
                    .protected
                    .control_session()
                    .map_err(|error| state_error(error.to_string()))
                    .and_then(|mut session| {
                        session
                            .recover_removal_receipt(projection.clone())
                            .map_err(|error| state_error(error.to_string()))
                    }) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        pending.stage = Some(ManagerReleaseStageV2::Ready(projection));
                        self.pending_manager_removals.push(pending);
                        return Err(error);
                    }
                };
                let retained = match pending.retained.take() {
                    Some(retained) => retained,
                    None => {
                        pending.stage = Some(ManagerReleaseStageV2::Ready(projection));
                        self.pending_manager_removals.push(pending);
                        return Err(state_error("retained SourceRoot Release is absent"));
                    }
                };
                let terminal_outcome = match pending.terminal_outcome.take() {
                    Some(terminal_outcome) => terminal_outcome,
                    None => {
                        pending.retained = Some(retained);
                        pending.stage = Some(ManagerReleaseStageV2::Ready(projection));
                        self.pending_manager_removals.push(pending);
                        return Err(state_error("terminal provider Release outcome is absent"));
                    }
                };
                lifecycle::ReleaseFinishPreparationV2::Pending(
                    retained.retain_negative_custody(terminal_outcome, receipt),
                )
            }
            ManagerReleaseStageV2::Prepared(prepared) => prepared,
            stage => {
                pending.stage = Some(stage);
                self.pending_manager_removals.push(pending);
                return Err(state_error("manager release is not ready to finish"));
            }
        };
        let mut retained_preparation = Some(preparation);
        let outcome = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let preparation = retained_preparation.take().ok_or_else(|| {
                            state_error("manager Release finish was already consumed")
                        })?;
                        match table.finish_release_v2(
                            journal,
                            session,
                            acquisition_id,
                            expected_revision,
                            expected_digest,
                            preparation,
                        ) {
                            Ok(outcome) => Ok(outcome),
                            Err(failure) => {
                                let (error, preparation) = failure.into_parts();
                                retained_preparation = Some(preparation);
                                Err(error)
                            }
                        }
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(preparation) = retained_preparation {
                    pending.stage = Some(ManagerReleaseStageV2::Prepared(preparation));
                    self.pending_manager_removals.push(pending);
                }
                return Err(error);
            }
        };
        match outcome {
            lifecycle::SourceAcquisitionNegativeCustodyOutcomeV2::Success(released) => {
                self.retained_released_roots
                    .insert(acquisition_id, released);
                Ok(())
            }
            lifecycle::SourceAcquisitionNegativeCustodyOutcomeV2::RecoveryRequired(recovery) => {
                self.retained_negative_custody_recovery
                    .push(RetainedNegativeCustodyRecoveryV2 {
                        acquisition_id,
                        recovery,
                        startup_terminals: None,
                    });
                Err(state_error("Released postcommit recovery is required"))
            }
        }
    }

    /// Resolves one ambiguous Released seal without repeating manager removal.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining the exact negative-custody proof when
    /// the fixed provider session, journal readback, or reseal remains unavailable.
    #[doc(hidden)]
    pub fn resolve_next_negative_custody_recovery(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        if self.retained_negative_custody_recovery.is_empty() {
            return self.recover_next_cold_released_row(root);
        }
        if let Some(retained) = self.retained_negative_custody_recovery.last()
            && let Some(terminals) = retained.startup_terminals
        {
            if self.exact_complete_terminal_attempt(
                retained.acquisition_id,
                ProviderMethodV2::Acquire,
            )? != Some(terminals.acquire)
                || self.exact_complete_terminal_attempt(
                    retained.acquisition_id,
                    ProviderMethodV2::Release,
                )? != terminals.release
            {
                return Err(state_error(
                    "startup absence recovery terminal lineage differs",
                ));
            }
        }
        let retained_recovery = self
            .retained_negative_custody_recovery
            .pop()
            .ok_or_else(|| state_error("no Released postcommit recovery is retained"))?;
        let acquisition_id = retained_recovery.acquisition_id;
        let startup_terminals = retained_recovery.startup_terminals;
        let recovery = retained_recovery.recovery;
        let mut retained = Some(recovery);
        let outcome = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let recovery = retained.take().ok_or_else(|| {
                            state_error("Released postcommit recovery was already consumed")
                        })?;
                        Ok(table.reseal_negative_custody_postcommit_v2(journal, session, recovery))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(recovery) = retained {
                    self.retained_negative_custody_recovery.push(
                        RetainedNegativeCustodyRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_terminals,
                        },
                    );
                }
                return Err(error);
            }
        };
        match outcome {
            lifecycle::SourceAcquisitionNegativeCustodyOutcomeV2::Success(released) => {
                self.retained_released_roots
                    .insert(acquisition_id, released);
                if let Some(terminals) = startup_terminals {
                    self.resolve_superseded_cold_attempt(terminals.acquire);
                    if let Some(release) = terminals.release {
                        self.resolve_superseded_cold_attempt(release);
                        self.retained_terminal_release_outcomes
                            .remove(&acquisition_id);
                        self.retained_terminal_release_response_evidence
                            .insert(acquisition_id, release);
                    }
                }
                Ok(())
            }
            lifecycle::SourceAcquisitionNegativeCustodyOutcomeV2::RecoveryRequired(recovery) => {
                self.retained_negative_custody_recovery
                    .push(RetainedNegativeCustodyRecoveryV2 {
                        acquisition_id,
                        recovery,
                        startup_terminals,
                    });
                Err(state_error("Released postcommit recovery remains required"))
            }
        }
    }

    fn recover_next_cold_released_row(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        let acquisition_id = self
            .cold_released_rows
            .pop()
            .ok_or_else(|| state_error("no Released recovery is retained"))?;
        let row = match self.table.acquisitions.get(&acquisition_id).cloned() {
            Some(row) => row,
            None => {
                self.cold_released_rows.push(acquisition_id);
                return Err(state_error("cold Released row is absent"));
            }
        };
        let acquisition_key = format::acquisition_key(acquisition_id);
        let acquisition_record = match format::put_record(
            &aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition {
                value: row,
            },
        ) {
            Ok(record) => match record.value().map(ToOwned::to_owned) {
                Some(value) => value,
                None => {
                    self.cold_released_rows.push(acquisition_id);
                    return Err(state_error("cold Released row materialized as a delete"));
                }
            },
            Err(error) => {
                self.cold_released_rows.push(acquisition_id);
                return Err(error);
            }
        };
        let mut retained_inputs = Some((acquisition_key, acquisition_record));
        let released = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|_table, authority| {
                    authority.with_authority(|journal| {
                        let (key, record) = retained_inputs
                            .take()
                            .ok_or_else(|| state_error("cold Released row was already consumed"))?;
                        session
                            .recover_released_mount_source_root_v2(
                                journal,
                                journal.snapshot()?,
                                key,
                                record,
                            )
                            .map_err(|_| state_error("cold Released evidence recovery failed"))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        match released {
            Ok(released) => {
                self.retained_released_roots
                    .insert(acquisition_id, released);
                Ok(())
            }
            Err(error) => {
                self.cold_released_rows.push(acquisition_id);
                Err(error)
            }
        }
    }

    /// Encodes a protected, current-boot source-acquisition inventory.
    ///
    /// # Errors
    ///
    /// Returns an error unless the fixed journal claim remains current and the
    /// complete recovered table forms one canonical bounded response.
    #[doc(hidden)]
    pub fn encode_current_inventory(&mut self) -> Result<Vec<u8>> {
        let broker_instance_id = self.broker_instance_id;
        let kernel_boot_id = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|error| crate::MountError::State(error.to_string()))?
            .into_bytes();
        self.with_source_acquisition_authority(|table, authority| {
            let snapshot = authority.with_authority(|claim| claim.snapshot())?;
            let response = table.encode_inventory_response(
                kernel_boot_id,
                snapshot.sequence(),
                broker_instance_id,
            )?;
            authority.with_authority(|claim| claim.validate_snapshot_for_effect(&snapshot))?;
            Ok(response)
        })
    }

    /// Reads a terminal Acquire or Release result from the fixed source graph.
    ///
    /// This path never executes provider I/O. A fresh or incomplete operation
    /// fails closed until the existing protected provider-session owner has
    /// completed and retained its exact result.
    ///
    /// # Errors
    ///
    /// Returns an error for another method, stale wire semantics, or absence of
    /// the exact terminal acquisition row.
    #[doc(hidden)]
    pub fn encode_current_operation_response(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>> {
        let current_boot_id = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|error| crate::MountError::State(error.to_string()))?
            .into_bytes();
        let sample = crate::service::trusted_paired_clock_sample()?;
        if current_boot_id != protected_boot_id
            || sample.host_boot_id() != protected_boot_id
            || self
                .last_boottime_nanoseconds
                .is_some_and(|floor| sample.boottime_nanoseconds() < floor)
        {
            return Err(crate::MountError::State(
                "source operation readback crossed the protected kernel clock".to_owned(),
            ));
        }
        self.last_boottime_nanoseconds = Some(sample.boottime_nanoseconds());

        let (acquisition_id, request_digest) = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
                let request = decode_acquire_mount_source_request(
                    request_body,
                    peer,
                    policy,
                    sample.boottime_nanoseconds(),
                )?;
                (
                    *request.acquisition_id().as_bytes(),
                    *request.request_digest().as_bytes(),
                )
            }
            BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
                let request = decode_release_mount_source_acquisition_request(
                    request_body,
                    peer,
                    policy,
                    sample.boottime_nanoseconds(),
                )?;
                (
                    *request.acquisition_id().as_bytes(),
                    *request.request_digest().as_bytes(),
                )
            }
            _ => {
                return Err(crate::MountError::State(
                    "unsupported source method".to_owned(),
                ));
            }
        };
        let retained_acquire_phase = self
            .retained_source_roots
            .get(&acquisition_id)
            .and_then(retained_source_root_phase);
        let row_request_matches = self
            .table
            .acquisitions
            .get(&acquisition_id)
            .is_some_and(|row| match method {
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
                    row.acquire.request_digest == request_digest
                }
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => row
                    .release
                    .is_some_and(|release| release.request_digest == request_digest),
                _ => false,
            });
        if !row_request_matches {
            return Err(state_error(
                "source operation request differs from retained disposition",
            ));
        }
        let provider_method = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => ProviderMethodV2::Acquire,
            BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
                ProviderMethodV2::Release
            }
            _ => {
                return Err(state_error("unsupported source method"));
            }
        };
        let retained_noncomplete = match self
            .retained_noncomplete_dispositions
            .get(&(acquisition_id, provider_method.tag()))
        {
            Some(outcome) => {
                if !self.table.retained_disposition_matches_v2(
                    acquisition_id,
                    provider_method,
                    outcome,
                )? {
                    return Err(state_error(
                        "retained provider disposition differs from durable state",
                    ));
                }
                true
            }
            None => false,
        };
        if method == BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE && !retained_noncomplete {
            let cold_recovery_is_pending = self.cold_pending_attempts.iter().any(|attempt_id| {
                self.table
                    .provider_attempts
                    .get(attempt_id)
                    .is_some_and(|attempt| attempt.owner.owner_id() == acquisition_id)
            });
            let postcommit_recovery_is_pending = self
                .retained_postcommit_recovery
                .iter()
                .any(|retained| retained.acquisition_id == acquisition_id);
            let manager_custody_is_pending = self
                .pending_manager_custody
                .iter()
                .any(|pending| pending.acquisition_id() == acquisition_id);
            if retained_acquire_phase.is_none()
                || cold_recovery_is_pending
                || postcommit_recovery_is_pending
                || manager_custody_is_pending
            {
                return Err(state_error(
                    "Acquire terminal response requires exact recovered SourceRoot custody",
                ));
            }
        }
        if method == BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
            && !retained_noncomplete
        {
            if let Some(terminal) = self
                .retained_terminal_release_response_evidence
                .get(&acquisition_id)
                .copied()
                && self
                    .exact_complete_terminal_attempt(acquisition_id, ProviderMethodV2::Release)?
                    != Some(terminal)
            {
                return Err(state_error(
                    "terminal Release response evidence differs from durable lineage",
                ));
            }
            let release_recovery_is_pending = self
                .retained_negative_custody_recovery
                .iter()
                .any(|retained| retained.acquisition_id == acquisition_id);
            let manager_removal_is_pending = self
                .pending_manager_removals
                .iter()
                .any(|pending| pending.acquisition_id == acquisition_id);
            let provider_recovery_is_pending =
                self.cold_pending_attempts.iter().any(|attempt_id| {
                    self.table
                        .provider_attempts
                        .get(attempt_id)
                        .is_some_and(|attempt| attempt.owner.owner_id() == acquisition_id)
                });
            let terminal_provider_custody_is_pending = self
                .retained_terminal_release_outcomes
                .contains_key(&acquisition_id)
                || self.retained_release_authorities.iter().any(|authority| {
                    authority.projection().mount_acquisition_id() == Some(acquisition_id)
                });
            if !self.retained_released_roots.contains_key(&acquisition_id)
                || release_recovery_is_pending
                || manager_removal_is_pending
                || provider_recovery_is_pending
                || terminal_provider_custody_is_pending
            {
                return Err(state_error(
                    "Release terminal response requires exact recovered negative custody",
                ));
            }
        }
        self.with_source_acquisition_authority(|table, authority| {
            let snapshot = authority.with_authority(|claim| claim.snapshot())?;
            let response = match method {
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => table
                    .acquisitions
                    .get(&acquisition_id)
                    .filter(|row| {
                        retained_noncomplete
                            || (row.evidence.is_some() && Some(row.phase) == retained_acquire_phase)
                    })
                    .ok_or_else(|| state_error("Acquire has no terminal protected provider result"))
                    .and_then(|_| table.encode_acquire_response(acquisition_id)),
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => table
                    .acquisitions
                    .get(&acquisition_id)
                    .filter(|row| {
                        retained_noncomplete || row.phase == SourceAcquisitionPhaseV2::Released
                    })
                    .ok_or_else(|| state_error("Release has no terminal protected provider result"))
                    .and_then(|_| table.encode_release_response(acquisition_id)),
                _ => Err(crate::MountError::State(
                    "unsupported source method".to_owned(),
                )),
            }?;
            authority.with_authority(|claim| claim.validate_snapshot_for_effect(&snapshot))?;
            Ok(response)
        })
    }

    /// Durably reserves and sends one fresh Acquire through fixed Root-Mount custody.
    ///
    /// The protected catalog capability and namespace-40 authority are checked
    /// in the same closure that signs and reserves the exact request. The sent
    /// outcome verifier remains inside this fixed owner until consumption.
    ///
    /// # Errors
    ///
    /// Returns an error for another outstanding provider request, stale fixed
    /// custody or catalog state, invalid admission, or reservation/send failure.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_and_send_fresh_acquire(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_catalog: aos_sandbox_source_provider_security::ProtectedCurrentCatalogPublicationV1,
        mount_request: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
        mount_plan_digest: [u8; 32],
        ownership_lease_digest: [u8; 32],
    ) -> Result<()> {
        if self.pending_provider.is_some()
            || self.pending_provider_send.is_some()
            || self.pending_release_preparation.is_some()
            || !self.cold_pending_attempts.is_empty()
        {
            return Err(state_error("another SourceProvider request is outstanding"));
        }
        let now = self.current_boottime(protected_boot_id)?;
        let live_request = decode_acquire_mount_source_request(mount_request, peer, policy, now)?;
        let result = root
            .with_current_session(|session| {
                let (holder_id, provider_id, deadline) = session
                    .current_authority_scope_v2()
                    .map_err(|_| state_error("Root-Mount provider session is not current"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let floor = session
                            .authorize_mount_acquire_verification_floor_v2(
                                journal,
                                journal.snapshot()?,
                                catalog_journal,
                                current_catalog,
                                None,
                            )
                            .map_err(|_| state_error("provider catalog floor is not current"))?;
                        let reserved = table.prepare_and_admit_acquire_v2(
                            journal,
                            catalog_journal,
                            session,
                            holder_id,
                            provider_id,
                            &live_request,
                            mount_request.to_vec(),
                            mount_plan_digest,
                            ownership_lease_digest,
                            floor,
                            deadline,
                        )?;
                        Ok(reserved.send(journal, session))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        match result {
            Ok(sent) => {
                self.pending_provider = Some(sent);
                Ok(())
            }
            Err(recovery) => {
                self.pending_provider_send = Some(recovery);
                Err(state_error(
                    "SourceProvider request send requires exact retry",
                ))
            }
        }
    }

    /// Replaces one backend-recovery predecessor and sends its durable retry.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining the exact committed replacement or
    /// send-retry stage unless provider identity, successor currentness,
    /// catalog verification, reservation, and carrier send all agree.
    #[doc(hidden)]
    pub fn replace_and_send_backend_recovery(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        retry_authority: aos_sandbox_source_provider::ProtectedProviderMountRetryAuthorityV1,
        current_catalog: Option<
            aos_sandbox_source_provider_security::ProtectedCurrentCatalogPublicationV1,
        >,
    ) -> Result<()> {
        if self.pending_provider_send.is_some() {
            return self.retry_pending_provider_send(root);
        }

        let (recovery_method, provider_acquisition_id, signed_request_digest) =
            retry_authority.into_identity();
        let provider_acquisition_id = provider_acquisition_id
            .ok_or_else(|| state_error("backend recovery is not acquisition-owned"))?;
        let expected_method = match recovery_method {
            aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire => {
                ProviderMethodV2::Acquire
            }
            aos_sandbox_source_provider_protocol::SourceProviderMethod::Release => {
                ProviderMethodV2::Release
            }
            _ => {
                return Err(state_error(
                    "backend recovery is not a Mount source operation",
                ));
            }
        };
        if self.pending_backend_recovery_replacement.is_none() {
            let live_attempt_id = self
                .pending_provider
                .as_ref()
                .map(SentProviderQueryV2::attempt_id);
            let cold_attempt_id =
                self.cold_pending_attempts
                    .first()
                    .copied()
                    .filter(|attempt_id| {
                        self.table
                            .provider_attempts
                            .get(attempt_id)
                            .is_some_and(|attempt| {
                                matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                                    && attempt.method == expected_method
                                    && attempt.provider_acquisition.is_some_and(|identity| {
                                        identity.acquisition_id == provider_acquisition_id
                                    })
                            })
                    });
            if live_attempt_id.is_none()
                && !self.cold_pending_attempts.is_empty()
                && cold_attempt_id.is_none()
            {
                return Err(state_error(
                    "Provider recovery work differs from the oldest Mount cold attempt",
                ));
            }
            let replacement = if let Some(attempt_id) = live_attempt_id.or(cold_attempt_id) {
                let attempt = self
                    .table
                    .provider_attempts
                    .get(&attempt_id)
                    .ok_or_else(|| state_error("backend recovery attempt is absent"))?;
                if attempt.method != expected_method
                    || attempt
                        .provider_acquisition
                        .is_none_or(|identity| identity.acquisition_id != provider_acquisition_id)
                {
                    return Err(state_error(
                        "backend recovery differs from the pending Mount attempt",
                    ));
                }
                if signed_request_digest != attempt.signed_request_digest {
                    return Err(state_error(
                        "protected absence names a different signed Mount request",
                    ));
                }
                let replacement = root
                    .with_current_session(|session| {
                        self.with_source_acquisition_authority(|table, authority| {
                            authority.with_authority(|journal| {
                                table.replace_backend_recovery_session_v2(
                                    journal, session, attempt_id,
                                )
                            })
                        })
                    })
                    .map_err(|_| state_error("Root-Mount successor session is not current"))?
                    .ok_or_else(|| state_error("Root-Mount successor handshake is pending"))??;
                if live_attempt_id == Some(attempt_id) {
                    self.pending_provider = None;
                }
                if cold_attempt_id == Some(attempt_id) {
                    if self.cold_pending_attempts.first() != Some(&attempt_id) {
                        return Err(state_error(
                            "Mount cold recovery order changed during replacement",
                        ));
                    }
                    self.cold_pending_attempts.remove(0);
                }
                replacement
            } else {
                let matching_rows = self
                    .table
                    .acquisitions
                    .values()
                    .filter(|row| {
                        row.provider_acquisition.acquisition_id == provider_acquisition_id
                    })
                    .filter_map(|row| {
                        let tail = match expected_method {
                            ProviderMethodV2::Acquire => Some(row.acquire_lineage.tail),
                            ProviderMethodV2::Release => {
                                row.release_lineage.as_ref().map(|lineage| lineage.tail)
                            }
                            ProviderMethodV2::Inventory => None,
                        }?;
                        let attempt = self.table.provider_attempts.get(&tail.id)?;
                        if attempt.signed_request_digest != signed_request_digest {
                            return None;
                        }
                        matches!(
                            attempt.state,
                            ProviderAttemptStateV2::DispositionConsumed {
                                status: ProviderStatusV2::Pending
                                    | ProviderStatusV2::Rejected
                                    | ProviderStatusV2::Unavailable,
                                ..
                            }
                        )
                        .then_some((
                            row.acquisition_id,
                            row.revision,
                            row.record_digest,
                        ))
                    })
                    .collect::<Vec<_>>();
                let [(acquisition_id, expected_revision, expected_digest)] =
                    matching_rows.as_slice()
                else {
                    return Err(state_error(
                        "backend recovery does not select one consumed Mount lineage",
                    ));
                };
                let scope = self
                    .table
                    .acquisitions
                    .get(acquisition_id)
                    .ok_or_else(|| state_error("backend recovery row is absent"))?
                    .scope;
                root.with_current_session(|session| {
                    self.with_source_acquisition_authority(|table, authority| {
                        authority.with_authority(|journal| {
                            let live_session_id = *session
                                .current_session_id_v2()
                                .map_err(|_| state_error("successor session is stale"))?
                                .as_bytes();
                            let installed_session_id = table
                                .provider_heads
                                .get(&(scope.holder_authority_id, scope.provider_authority_id))
                                .ok_or_else(|| state_error("backend recovery head is absent"))?
                                .current_session_id;
                            if live_session_id == installed_session_id {
                                Ok(())
                            } else {
                                table.replace_idle_provider_session_v2(
                                    journal,
                                    session,
                                    scope.holder_authority_id,
                                    scope.provider_authority_id,
                                )
                            }
                        })
                    })
                })
                .map_err(|_| state_error("Root-Mount successor session is not current"))?
                .ok_or_else(|| state_error("Root-Mount successor handshake is pending"))??;
                (
                    *acquisition_id,
                    *expected_revision,
                    *expected_digest,
                    expected_method,
                )
            };
            self.pending_backend_recovery_replacement = Some(BackendRecoveryReplacementV2 {
                acquisition_id: replacement.0,
                expected_revision: replacement.1,
                expected_digest: replacement.2,
                method: replacement.3,
                predecessor_signed_request_digest: signed_request_digest,
            });
        }

        let replacement = self
            .pending_backend_recovery_replacement
            .take()
            .ok_or_else(|| state_error("backend recovery replacement stage is absent"))?;
        let replacement_matches = self
            .table
            .acquisitions
            .get(&replacement.acquisition_id)
            .is_some_and(|row| {
                row.provider_acquisition.acquisition_id == provider_acquisition_id
                    && replacement.method == expected_method
                    && replacement.predecessor_signed_request_digest == signed_request_digest
            });
        if !replacement_matches {
            self.pending_backend_recovery_replacement = Some(replacement);
            return Err(state_error(
                "backend recovery differs from the retained replacement stage",
            ));
        }
        let retained_replacement = Some(replacement);
        let result = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let replacement = retained_replacement.ok_or_else(|| {
                            state_error("backend recovery replacement stage was already consumed")
                        })?;
                        let provider_deadline_seconds = session
                            .current_authority_scope_v2()
                            .map_err(|_| state_error("successor session is stale"))?
                            .2;
                        let reserved = match replacement.method {
                            ProviderMethodV2::Acquire => {
                                let catalog = current_catalog.ok_or_else(|| {
                                    state_error("backend recovery Acquire lacks catalog authority")
                                })?;
                                let floor = session
                                    .authorize_mount_acquire_verification_floor_v2(
                                        journal,
                                        journal.snapshot()?,
                                        catalog_journal,
                                        catalog,
                                        Some(format::acquisition_key(replacement.acquisition_id)),
                                    )
                                    .map_err(|_| {
                                        state_error("backend recovery catalog floor is stale")
                                    })?;
                                table.prepare_and_reserve_acquire_retry_v2(
                                    journal,
                                    catalog_journal,
                                    session,
                                    replacement.acquisition_id,
                                    replacement.expected_revision,
                                    replacement.expected_digest,
                                    floor,
                                    provider_deadline_seconds,
                                )?
                            }
                            ProviderMethodV2::Release => table
                                .prepare_and_reserve_release_retry_v2(
                                    journal,
                                    session,
                                    replacement.acquisition_id,
                                    replacement.expected_revision,
                                    replacement.expected_digest,
                                    provider_deadline_seconds,
                                )?,
                            ProviderMethodV2::Inventory => {
                                return Err(state_error(
                                    "backend recovery retry is not acquisition-owned",
                                ));
                            }
                        };
                        Ok(reserved.send(journal, session))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount successor session is not current"))?
            .ok_or_else(|| state_error("Root-Mount successor handshake is pending"))?;
        match result {
            Ok(Ok(sent)) => {
                self.pending_provider = Some(sent);
                Ok(())
            }
            Ok(Err(recovery)) => {
                self.pending_provider_send = Some(recovery);
                Err(state_error("backend recovery retry send remains pending"))
            }
            Err(error) => {
                if let Some(replacement) = retained_replacement {
                    self.pending_backend_recovery_replacement = Some(replacement);
                }
                Err(error)
            }
        }
    }

    /// Replaces and sends one exact cold or live Inventory recovery request.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining a durable replacement or send-retry
    /// stage unless Provider recovery names the exact Inventory request and the
    /// successor Root-Mount session remains current.
    #[doc(hidden)]
    pub fn replace_and_send_inventory_backend_recovery(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        retry_authority: aos_sandbox_source_provider::ProtectedProviderMountRetryAuthorityV1,
    ) -> Result<()> {
        if self.pending_provider_send.is_some() {
            return self.retry_pending_provider_send(root);
        }
        let (method, acquisition_id, signed_request_digest) = retry_authority.into_identity();
        if method != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            || acquisition_id.is_some()
        {
            return Err(state_error(
                "Inventory recovery authority has another method",
            ));
        }
        if self
            .pending_inventory_recovery_replacement
            .is_some_and(|replacement| replacement.3 != signed_request_digest)
        {
            return Err(state_error(
                "Inventory recovery authority differs from committed replacement",
            ));
        }

        if self.pending_inventory_recovery_replacement.is_none() {
            let live_attempt_id = self
                .pending_provider
                .as_ref()
                .map(SentProviderQueryV2::attempt_id);
            let cold_attempt_id =
                self.cold_pending_attempts
                    .first()
                    .copied()
                    .filter(|attempt_id| {
                        self.table
                            .provider_attempts
                            .get(attempt_id)
                            .is_some_and(|attempt| {
                                attempt.method == ProviderMethodV2::Inventory
                                    && matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                                    && attempt.signed_request_digest == signed_request_digest
                            })
                    });
            if live_attempt_id.is_none()
                && !self.cold_pending_attempts.is_empty()
                && cold_attempt_id.is_none()
            {
                return Err(state_error(
                    "Provider Inventory recovery differs from the oldest Mount cold attempt",
                ));
            }
            let attempt_id = live_attempt_id
                .or(cold_attempt_id)
                .ok_or_else(|| state_error("Inventory recovery request is absent"))?;
            let attempt = self
                .table
                .provider_attempts
                .get(&attempt_id)
                .ok_or_else(|| state_error("Inventory recovery attempt is absent"))?;
            if attempt.method != ProviderMethodV2::Inventory
                || attempt.signed_request_digest != signed_request_digest
            {
                return Err(state_error(
                    "Inventory recovery differs from the retained request",
                ));
            }
            let replacement = root
                .with_current_session(|session| {
                    self.with_source_acquisition_authority(|table, authority| {
                        authority.with_authority(|journal| {
                            table
                                .replace_inventory_recovery_session_v2(journal, session, attempt_id)
                        })
                    })
                })
                .map_err(|_| state_error("Root-Mount successor session is not current"))?
                .ok_or_else(|| state_error("Root-Mount successor handshake is pending"))??;
            self.pending_provider = None;
            if cold_attempt_id == Some(attempt_id) {
                if self.cold_pending_attempts.first() != Some(&attempt_id) {
                    return Err(state_error(
                        "Inventory recovery differs from the oldest Mount cold attempt",
                    ));
                }
                self.cold_pending_attempts.remove(0);
            }
            self.pending_inventory_recovery_replacement = Some(replacement);
        }

        let replacement = self
            .pending_inventory_recovery_replacement
            .ok_or_else(|| state_error("Inventory recovery replacement stage is absent"))?;
        let result = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let deadline = session
                            .current_authority_scope_v2()
                            .map_err(|_| state_error("successor session is stale"))?
                            .2;
                        Ok(table
                            .prepare_and_reserve_inventory_v2(
                                journal,
                                session,
                                replacement.0,
                                replacement.1,
                                replacement.2,
                                deadline,
                            )?
                            .send(journal, session))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount successor session is not current"))?
            .ok_or_else(|| state_error("Root-Mount successor handshake is pending"))??;
        match result {
            Ok(sent) => {
                self.pending_inventory_recovery_replacement = None;
                self.pending_provider = Some(sent);
                Ok(())
            }
            Err(recovery) => {
                self.pending_inventory_recovery_replacement = None;
                self.pending_provider_send = Some(recovery);
                Err(state_error("Inventory recovery send requires exact retry"))
            }
        }
    }

    /// Durably fences and sends one fresh Release using exact SourceRoot custody.
    ///
    /// `prepared_release` has no public scalar constructor: it is minted only
    /// from retained descriptor or protected startup-loss custody. The release
    /// authority remains in this fixed owner after the provider request is sent.
    ///
    /// # Errors
    ///
    /// Returns an error for another outstanding provider request, stale fixed
    /// custody, invalid release CAS, ambiguous postcommit, or carrier failure.
    #[doc(hidden)]
    pub fn prepare_and_send_fresh_release(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        mount_request: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
    ) -> Result<()> {
        if self.pending_provider.is_some()
            || self.pending_provider_send.is_some()
            || !self.cold_pending_attempts.is_empty()
        {
            return Err(state_error("another SourceProvider request is outstanding"));
        }
        let now = self.current_boottime(protected_boot_id)?;
        let live_request =
            decode_release_mount_source_acquisition_request(mount_request, peer, policy, now)?;
        let acquisition_id = *live_request.request().acquisition_id().as_bytes();
        let retained_preparation = if let Some(pending) = self.pending_release_preparation.take() {
            if pending.acquisition_id != acquisition_id || pending.mount_request != mount_request {
                self.pending_release_preparation = Some(pending);
                return Err(state_error(
                    "another SourceProvider Release preparation is outstanding",
                ));
            }
            pending
        } else if let Some(prepared_release) = self
            .startup_lost_release_preparations
            .remove(&acquisition_id)
        {
            RetainedFreshReleasePreparationV2 {
                acquisition_id,
                mount_request: mount_request.to_vec(),
                prepared_release,
            }
        } else {
            let retained = self
                .retained_source_roots
                .remove(&acquisition_id)
                .ok_or_else(|| state_error("fresh Release lacks retained SourceRoot custody"))?;
            let prepared_release = match retained {
                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::DescriptorCustodied(
                    custody,
                ) => custody.prepare_release(),
                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Active(custody) => {
                    custody.prepare_release()
                }
                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Consumed(
                    custody,
                ) => custody.prepare_release(),
                retained => {
                    self.retained_source_roots.insert(acquisition_id, retained);
                    return Err(state_error("retained SourceRoot is not releasable"));
                }
            };
            RetainedFreshReleasePreparationV2 {
                acquisition_id,
                mount_request: mount_request.to_vec(),
                prepared_release,
            }
        };
        let mut retained_preparation = Some(retained_preparation);
        let prepared = root
            .with_current_session(|session| {
                let (_, _, deadline) = session
                    .current_authority_scope_v2()
                    .map_err(|_| state_error("Root-Mount provider session is not current"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let pending = retained_preparation.take().ok_or_else(|| {
                            state_error("SourceRoot Release preparation was already consumed")
                        })?;
                        let reserved = match table.prepare_and_begin_release_v2(
                            journal,
                            session,
                            &live_request,
                            pending.mount_request.clone(),
                            deadline,
                            pending.prepared_release,
                        ) {
                            Ok(reserved) => reserved,
                            Err(failure) => {
                                let (error, prepared_release) = failure.into_parts();
                                retained_preparation = Some(RetainedFreshReleasePreparationV2 {
                                    acquisition_id,
                                    mount_request: pending.mount_request,
                                    prepared_release,
                                });
                                return Err(error);
                            }
                        };
                        let postcommit = reserved.into_postcommit();
                        let committed = match postcommit {
                            SourceAcquisitionPostcommitOutcomeV2::Success(
                                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Releasing(
                                    committed,
                                ),
                            ) => committed,
                            retained => return Ok(Err(retained)),
                        };
                        let (release_authority, reservation) = committed.into_parts();
                        let attempt_id = table
                            .provider_attempts
                            .values()
                            .find(|attempt| {
                                attempt.owner.owner_id() == acquisition_id
                                    && attempt.method == ProviderMethodV2::Release
                                    && matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                            })
                            .map(|attempt| attempt.attempt_id)
                            .ok_or_else(|| {
                                state_error("committed provider Release attempt is absent")
                            })?;
                        let send = ReservedProviderQueryV2::from_reserved(attempt_id, reservation)
                            .send(journal, session);
                        Ok(Ok((send, release_authority)))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.pending_release_preparation = retained_preparation;
                return Err(error);
            }
        };
        let (send, release_authority) = match prepared {
            Ok(prepared) => prepared,
            Err(SourceAcquisitionPostcommitOutcomeV2::Success(source_root)) => {
                self.retained_source_roots
                    .insert(acquisition_id, source_root);
                return Err(state_error(
                    "provider Release produced the wrong custody phase",
                ));
            }
            Err(SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery)) => {
                self.retained_postcommit_recovery
                    .push(RetainedSourcePostcommitRecoveryV2 {
                        acquisition_id,
                        recovery,
                        startup_acquire_terminal: None,
                    });
                return Err(state_error(
                    "provider Release postcommit recovery is required",
                ));
            }
        };
        self.retained_release_authorities.push(release_authority);
        match send {
            Ok(sent) => {
                self.pending_provider = Some(sent);
                Ok(())
            }
            Err(recovery) => {
                self.pending_provider_send = Some(recovery);
                Err(state_error("provider Release send requires exact retry"))
            }
        }
    }

    /// Commits normal Mount-manager custody for one retained Complete Acquire.
    ///
    /// The presence capability is minted only after the protected manager
    /// control session authenticates descriptor handoff and positive readback.
    /// On success, this owner retains the DescriptorCustodied source from which
    /// a subsequent fresh Release derives its move-only release capability.
    ///
    /// # Errors
    ///
    /// Returns an error unless the manager proof, retained SourceRoot, exact
    /// acquisition row, provider session, and namespace-40 commit all agree.
    #[doc(hidden)]
    pub fn record_manager_source_presence(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        acquisition_id: [u8; 32],
        manager_presence: aos_sandbox::mount_manager_startup::FreshManagerSourcePresenceV1,
    ) -> Result<()> {
        let manager_evidence = manager_presence.custody_evidence();
        let manager_acquisition_id = manager_evidence.acquisition_id;
        let expected_revision = manager_evidence.acquisition_revision;
        let expected_digest = manager_evidence.acquisition_record_digest;
        self.pending_manager_custody
            .push(RetainedManagerSourceCustodyV2::Unpaired {
                acquisition_id: manager_acquisition_id,
                expected_revision,
                expected_digest,
                manager_presence,
            });
        if manager_acquisition_id != acquisition_id {
            return Err(state_error(
                "manager presence names a different source acquisition",
            ));
        }
        self.resume_manager_source_presence(root)
    }

    /// Resumes exact manager/SourceRoot custody without accepting replacement evidence.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining the same move-only preparation when
    /// session, journal, CAS, evidence, descriptor, or preparation validation
    /// is unavailable before postcommit recovery takes ownership.
    #[doc(hidden)]
    pub fn resume_manager_source_presence(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        let mut retained = self.pending_manager_custody.pop();
        let acquisition_id = retained
            .as_ref()
            .map(RetainedManagerSourceCustodyV2::acquisition_id)
            .ok_or_else(|| state_error("no manager SourceRoot preparation is retained"))?;
        if matches!(
            &retained,
            Some(RetainedManagerSourceCustodyV2::Unpaired { .. })
        ) {
            let pending = retained.take().ok_or_else(|| {
                state_error("manager SourceRoot preparation was already consumed")
            })?;
            let RetainedManagerSourceCustodyV2::Unpaired {
                acquisition_id,
                expected_revision,
                expected_digest,
                manager_presence,
            } = pending
            else {
                return Err(state_error("manager SourceRoot preparation phase changed"));
            };
            let Some(source_root) = self.retained_source_roots.remove(&acquisition_id) else {
                self.pending_manager_custody
                    .push(RetainedManagerSourceCustodyV2::Unpaired {
                        acquisition_id,
                        expected_revision,
                        expected_digest,
                        manager_presence,
                    });
                return Err(state_error("manager presence lacks retained SourceRoot"));
            };
            let pending = match source_root {
                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Received(
                    committed,
                ) => committed.retain_manager_presence(manager_presence),
                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Reopened(
                    committed,
                ) => committed.retain_manager_presence(manager_presence),
                source_root => {
                    self.retained_source_roots
                        .insert(acquisition_id, source_root);
                    self.pending_manager_custody
                        .push(RetainedManagerSourceCustodyV2::Unpaired {
                            acquisition_id,
                            expected_revision,
                            expected_digest,
                            manager_presence,
                        });
                    return Err(state_error("SourceRoot is not awaiting manager custody"));
                }
            };
            retained = Some(RetainedManagerSourceCustodyV2::Paired {
                acquisition_id,
                expected_revision,
                expected_digest,
                preparation: lifecycle::ManagerSourceCustodyPreparationV2::Pending(pending),
            });
        }
        let postcommit = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let pending = retained.take().ok_or_else(|| {
                            state_error("manager SourceRoot preparation was already consumed")
                        })?;
                        let RetainedManagerSourceCustodyV2::Paired {
                            acquisition_id,
                            expected_revision,
                            expected_digest,
                            preparation,
                        } = pending
                        else {
                            return Err(state_error(
                                "manager SourceRoot preparation is not paired",
                            ));
                        };
                        match table.record_descriptor_custody_v2(
                            journal,
                            session,
                            acquisition_id,
                            expected_revision,
                            expected_digest,
                            preparation,
                        ) {
                            Ok(postcommit) => Ok(postcommit),
                            Err(failure) => {
                                let (error, preparation) = failure.into_parts();
                                retained = Some(RetainedManagerSourceCustodyV2::Paired {
                                    acquisition_id,
                                    expected_revision,
                                    expected_digest,
                                    preparation,
                                });
                                Err(error)
                            }
                        }
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let postcommit = match postcommit {
            Ok(postcommit) => postcommit,
            Err(error) => {
                if let Some(retained) = retained {
                    self.pending_manager_custody.push(retained);
                }
                return Err(error);
            }
        };
        match postcommit {
            SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                self.retained_source_roots
                    .insert(acquisition_id, source_root);
                Ok(())
            }
            SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                self.retained_postcommit_recovery
                    .push(RetainedSourcePostcommitRecoveryV2 {
                        acquisition_id,
                        recovery,
                        startup_acquire_terminal: None,
                    });
                Err(state_error(
                    "manager SourceRoot custody recovery is required",
                ))
            }
        }
    }

    fn current_boottime(&mut self, protected_boot_id: [u8; 16]) -> Result<u64> {
        let current_boot_id = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|error| crate::MountError::State(error.to_string()))?
            .into_bytes();
        let sample = crate::service::trusted_paired_clock_sample()?;
        if current_boot_id != protected_boot_id
            || sample.host_boot_id() != protected_boot_id
            || self
                .last_boottime_nanoseconds
                .is_some_and(|floor| sample.boottime_nanoseconds() < floor)
        {
            return Err(state_error(
                "source operation crossed the protected kernel clock",
            ));
        }
        self.last_boottime_nanoseconds = Some(sample.boottime_nanoseconds());
        Ok(sample.boottime_nanoseconds())
    }

    /// Retries the exact request whose first carrier send did not complete.
    ///
    /// # Errors
    ///
    /// Returns an error and restores the same move-only reservation when the
    /// current protected session, journal readback, or carrier remains unavailable.
    #[doc(hidden)]
    pub fn retry_pending_provider_send(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        let recovery = self
            .pending_provider_send
            .take()
            .ok_or_else(|| state_error("no SourceProvider send recovery is retained"))?;
        let mut retained = Some(recovery);
        let sent = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|_table, authority| {
                    authority.with_authority(|journal| {
                        let recovery = retained.take().ok_or_else(|| {
                            state_error("SourceProvider send recovery was already consumed")
                        })?;
                        Ok(recovery.retry(journal, session))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        match sent {
            Ok(Ok(sent)) => {
                self.pending_provider = Some(sent);
                Ok(())
            }
            Ok(Err(recovery)) => {
                self.pending_provider_send = Some(recovery);
                Err(state_error("SourceProvider request send remains pending"))
            }
            Err(error) => {
                if let Some(recovery) = retained {
                    self.pending_provider_send = Some(recovery);
                }
                Err(error)
            }
        }
    }

    /// Consumes the exact response for the owner-retained sent request.
    ///
    /// Any Complete Acquire SourceRoot stays in this fixed owner rather than
    /// being returned as a raw descriptor or dropped after broker success.
    ///
    /// # Errors
    ///
    /// Returns an error when no request is outstanding or protected response,
    /// catalog, journal, descriptor, or session validation fails.
    #[doc(hidden)]
    pub fn consume_sent_provider_outcome(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<()> {
        let sent = self
            .pending_provider
            .take()
            .ok_or_else(|| state_error("no SourceProvider request is outstanding"))?;
        let (acquisition_id, provider_method) = self
            .table
            .provider_attempts
            .get(&sent.attempt_id())
            .map(|attempt| (attempt.owner.owner_id(), attempt.method))
            .ok_or_else(|| state_error("outstanding SourceProvider attempt is absent"))?;
        let consumed = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.consume_provider_outcome_v2(journal, catalog_journal, session, &sent)
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) => {
                self.pending_provider = Some(sent);
                return Err(error);
            }
        };
        match consumed {
            ConsumedProviderOutcomeV2::WithoutSourceRoot { outcome } => {
                if provider_method == ProviderMethodV2::Release
                    && outcome.status()
                        == aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.retained_terminal_release_outcomes
                        .insert(acquisition_id, outcome);
                } else if outcome.status()
                    != aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.retained_noncomplete_dispositions
                        .insert((acquisition_id, provider_method.tag()), outcome);
                }
            }
            ConsumedProviderOutcomeV2::CompleteAcquire { postcommit } => match postcommit {
                SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                    self.retained_source_roots
                        .insert(acquisition_id, source_root);
                }
                SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                    self.retained_postcommit_recovery
                        .push(RetainedSourcePostcommitRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_acquire_terminal: None,
                        });
                    return Err(state_error("SourceRoot postcommit recovery is required"));
                }
            },
        }
        Ok(())
    }

    /// Receives and resumes the next durable provider attempt after cold reopen.
    ///
    /// The attempt and historical session are selected exclusively from the
    /// recovered namespace-40 graph. No request is rebuilt or redispatched;
    /// the current protected Root-Mount carrier captures the provider's exact
    /// response and the historical recovery verifier binds it to that attempt.
    ///
    /// # Errors
    ///
    /// Returns an error unless a queued durable attempt awaits an outcome, the
    /// protected carrier supplies its canonical response, and historical trust,
    /// journal, catalog, and descriptor recovery all agree.
    #[doc(hidden)]
    pub fn recover_cold_provider_outcome(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<()> {
        if self.pending_provider.is_some() {
            return Err(state_error(
                "live SourceProvider response custody must be resumed directly",
            ));
        }
        let attempt_id = self
            .cold_pending_attempts
            .first()
            .copied()
            .ok_or_else(|| state_error("no durable SourceProvider attempt awaits recovery"))?;
        let attempt = self
            .table
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| {
                matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    || (matches!(
                        attempt.method,
                        ProviderMethodV2::Acquire | ProviderMethodV2::Release
                    ) && matches!(
                        attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed { .. }
                    ))
            })
            .ok_or_else(|| state_error("cold recovery barrier differs from durable state"))?;
        let acquisition_id = attempt.owner.owner_id();
        let provider_method = attempt.method;
        let complete_acquire_requires_startup_manager = provider_method
            == ProviderMethodV2::Acquire
            && matches!(
                attempt.state,
                ProviderAttemptStateV2::DispositionConsumed {
                    status: ProviderStatusV2::Complete,
                    ..
                }
            )
            && self
                .table
                .acquisitions
                .get(&acquisition_id)
                .is_some_and(|row| row.phase != SourceAcquisitionPhaseV2::PendingQuery);
        if complete_acquire_requires_startup_manager {
            return Err(state_error(
                "cold held SourceRoot requires protected manager startup custody",
            ));
        }
        let method = match provider_method {
            ProviderMethodV2::Acquire => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            }
            ProviderMethodV2::Release => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            }
            ProviderMethodV2::Inventory => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            }
        };
        let recovered = root
            .with_current_session(|session| {
                let captured = session
                    .capture_mount_provider_recovery_outcome_v2(method)
                    .map_err(|_| state_error("protected recovery receive failed"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.recover_and_consume_provider_outcome_v2(
                            journal,
                            catalog_journal,
                            session,
                            attempt_id,
                            captured,
                        )
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        self.cold_pending_attempts.remove(0);
        match recovered {
            RecoveredProviderOutcomeConsumptionV2::WithoutSourceRoot { outcome } => {
                if provider_method == ProviderMethodV2::Release
                    && outcome.status()
                        == aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.retained_terminal_release_outcomes
                        .insert(acquisition_id, outcome);
                } else if outcome.status()
                    != aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.retained_noncomplete_dispositions
                        .insert((acquisition_id, provider_method.tag()), outcome);
                }
            }
            RecoveredProviderOutcomeConsumptionV2::CompleteAcquire { postcommit } => {
                match postcommit {
                    SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                        self.retained_source_roots
                            .insert(acquisition_id, source_root);
                    }
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                        self.retained_postcommit_recovery
                            .push(RetainedSourcePostcommitRecoveryV2 {
                                acquisition_id,
                                recovery,
                                startup_acquire_terminal: None,
                            });
                        return Err(state_error(
                            "cold-recovered SourceRoot postcommit recovery is required",
                        ));
                    }
                }
            }
            RecoveredProviderOutcomeConsumptionV2::RetainedSourceRoot { source_root } => {
                match source_root {
                    aos_sandbox_source_provider_security::RecoveredRetainedMountSourceRootV2::Releasing(
                        authority,
                    ) => self.retained_release_authorities.push(authority),
                    source_root => {
                        self.retained_source_roots.insert(
                            acquisition_id,
                            aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::StartupAdopted(
                                source_root,
                            ),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Reauthenticates a replay-validated persisted Provider outcome.
    ///
    /// Provider bytes and any reopened SourceRoot remain nonauthorizing until
    /// the current Root-Mount owner binds them to the exact oldest protected
    /// attempt and historical session. This path performs no carrier receive
    /// and never sends a historical response on a successor session.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical Provider evidence, cold-order drift,
    /// failed historical authentication, or ambiguous SourceRoot postcommit.
    #[doc(hidden)]
    pub fn recover_persisted_cold_provider_outcome(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        historical: aos_sandbox_source_provider::FixedProviderHistoricalOutcomeV1,
    ) -> Result<()> {
        if self.pending_provider.is_some() {
            return Err(state_error(
                "live SourceProvider response custody must be resumed directly",
            ));
        }
        let attempt_id = self
            .cold_pending_attempts
            .first()
            .copied()
            .ok_or_else(|| state_error("no durable SourceProvider attempt awaits recovery"))?;
        let attempt = self
            .table
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| {
                matches!(
                    attempt.state,
                    ProviderAttemptStateV2::Reserved
                        | ProviderAttemptStateV2::DispositionConsumed { .. }
                )
            })
            .ok_or_else(|| state_error("cold recovery barrier differs from durable state"))?;
        let acquisition_id = attempt.owner.owner_id();
        let provider_method = attempt.method;
        let method = match provider_method {
            ProviderMethodV2::Acquire => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            }
            ProviderMethodV2::Release => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            }
            ProviderMethodV2::Inventory => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            }
        };
        let (response, source_root, persisted) = historical
            .into_security_parts()
            .map_err(|_| state_error("persisted Provider SourceRoot revalidation failed"))?;
        let recovered = root
            .with_current_session(|session| {
                let captured = session
                    .capture_persisted_mount_provider_outcome_v2(
                        method,
                        response,
                        source_root,
                        persisted,
                    )
                    .map_err(|_| state_error("persisted Provider outcome capture failed"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.recover_and_consume_provider_outcome_v2(
                            journal,
                            catalog_journal,
                            session,
                            attempt_id,
                            captured,
                        )
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        self.cold_pending_attempts.remove(0);
        match recovered {
            RecoveredProviderOutcomeConsumptionV2::WithoutSourceRoot { outcome } => {
                if provider_method == ProviderMethodV2::Release
                    && outcome.status()
                        == aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.retained_terminal_release_outcomes
                        .insert(acquisition_id, outcome);
                } else if outcome.status()
                    != aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.retained_noncomplete_dispositions
                        .insert((acquisition_id, provider_method.tag()), outcome);
                }
            }
            RecoveredProviderOutcomeConsumptionV2::CompleteAcquire { postcommit } => {
                match postcommit {
                    SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                        self.retained_source_roots
                            .insert(acquisition_id, source_root);
                    }
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                        self.retained_postcommit_recovery
                            .push(RetainedSourcePostcommitRecoveryV2 {
                                acquisition_id,
                                recovery,
                                startup_acquire_terminal: None,
                            });
                        return Err(state_error(
                            "persisted SourceRoot postcommit recovery is required",
                        ));
                    }
                }
            }
            RecoveredProviderOutcomeConsumptionV2::RetainedSourceRoot { source_root } => {
                match source_root {
                    aos_sandbox_source_provider_security::RecoveredRetainedMountSourceRootV2::Releasing(
                        authority,
                    ) => self.retained_release_authorities.push(authority),
                    source_root => {
                        self.retained_source_roots.insert(
                            acquisition_id,
                            aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::StartupAdopted(
                                source_root,
                            ),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolves one retained SourceRoot postcommit ambiguity by readback.
    ///
    /// A successful retained source is restored to this owner. A successful
    /// Release reservation is sent through the same current Root-Mount session
    /// and its response verifier and release authority remain here. Any still
    /// ambiguous seal is reinserted without re-executing the provider effect.
    ///
    /// # Errors
    ///
    /// Returns an error when no recovery exists, the fixed session or journal
    /// is stale, resealing remains ambiguous, or a recovered Release cannot be
    /// correlated and sent through its exact reservation.
    #[doc(hidden)]
    pub fn resolve_next_postcommit_recovery(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        if let Some(retained) = self.retained_postcommit_recovery.last()
            && let Some(terminal) = retained.startup_acquire_terminal
            && self.exact_complete_terminal_attempt(
                retained.acquisition_id,
                ProviderMethodV2::Acquire,
            )? != Some(terminal)
        {
            return Err(state_error(
                "startup SourceRoot recovery terminal lineage differs",
            ));
        }
        let retained_recovery = self
            .retained_postcommit_recovery
            .pop()
            .ok_or_else(|| state_error("no SourceRoot postcommit recovery is retained"))?;
        let acquisition_id = retained_recovery.acquisition_id;
        let startup_acquire_terminal = retained_recovery.startup_acquire_terminal;
        let recovery = retained_recovery.recovery;
        let mut unentered_recovery = Some(recovery);
        let resolved = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let recovery = unentered_recovery.take().ok_or_else(|| {
                            state_error("SourceRoot postcommit recovery was already consumed")
                        })?;
                        match table.reseal_source_root_postcommit_v2(journal, session, recovery) {
                            SourceAcquisitionPostcommitOutcomeV2::Success(
                                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Releasing(
                                    committed,
                                ),
                            ) => {
                                let (release_authority, reservation) = committed.into_parts();
                                let attempt_id = table
                                    .provider_attempts
                                    .values()
                                    .find(|attempt| {
                                        attempt.owner.owner_id() == acquisition_id
                                            && attempt.method == ProviderMethodV2::Release
                                            && matches!(
                                                attempt.state,
                                                ProviderAttemptStateV2::Reserved
                                            )
                                    })
                                    .map(|attempt| attempt.attempt_id)
                                    .ok_or_else(|| {
                                        state_error(
                                            "recovered provider Release attempt is absent",
                                        )
                                    })?;
                                let send = ReservedProviderQueryV2::from_reserved(
                                    attempt_id,
                                    reservation,
                                )
                                .send(journal, session);
                                Ok(Ok((None, Some((send, release_authority)))))
                            }
                            SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                                Ok(Ok((Some(source_root), None)))
                            }
                            SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                                Ok(Err(recovery))
                            }
                        }
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let resolved = match resolved {
            Ok(resolved) => resolved,
            Err(error) => {
                if let Some(recovery) = unentered_recovery {
                    self.retained_postcommit_recovery
                        .push(RetainedSourcePostcommitRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_acquire_terminal,
                        });
                }
                return Err(error);
            }
        };
        match resolved {
            Ok((source_root, sent_release)) => {
                if let Some(source_root) = source_root {
                    self.retained_source_roots
                        .insert(acquisition_id, source_root);
                    if let Some(terminal) = startup_acquire_terminal {
                        self.resolve_superseded_cold_attempt(terminal);
                    }
                }
                if let Some((send, release_authority)) = sent_release {
                    self.retained_release_authorities.push(release_authority);
                    match send {
                        Ok(sent) => self.pending_provider = Some(sent),
                        Err(recovery) => self.pending_provider_send = Some(recovery),
                    }
                }
                Ok(())
            }
            Err(recovery) => {
                self.retained_postcommit_recovery
                    .push(RetainedSourcePostcommitRecoveryV2 {
                        acquisition_id,
                        recovery,
                        startup_acquire_terminal,
                    });
                Err(state_error(
                    "SourceRoot postcommit recovery remains ambiguous",
                ))
            }
        }
    }
}

fn retained_source_root_phase(
    retained: &aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2,
) -> Option<SourceAcquisitionPhaseV2> {
    use aos_sandbox_source_provider_security::{
        RecoveredRetainedMountSourceRootV2, SourceRootPostcommitSuccessV2,
    };

    match retained {
        SourceRootPostcommitSuccessV2::DescriptorCustodied(_) => {
            Some(SourceAcquisitionPhaseV2::DescriptorCustodied)
        }
        SourceRootPostcommitSuccessV2::Active(_) => Some(SourceAcquisitionPhaseV2::Active),
        SourceRootPostcommitSuccessV2::Consumed(_) => Some(SourceAcquisitionPhaseV2::Consumed),
        SourceRootPostcommitSuccessV2::Releasing(_) => Some(SourceAcquisitionPhaseV2::Releasing),
        SourceRootPostcommitSuccessV2::StartupAdopted(recovered) => match recovered {
            RecoveredRetainedMountSourceRootV2::DescriptorCustodied(_) => {
                Some(SourceAcquisitionPhaseV2::DescriptorCustodied)
            }
            RecoveredRetainedMountSourceRootV2::Active(_) => Some(SourceAcquisitionPhaseV2::Active),
            RecoveredRetainedMountSourceRootV2::Consumed(_) => {
                Some(SourceAcquisitionPhaseV2::Consumed)
            }
            RecoveredRetainedMountSourceRootV2::Releasing(_) => {
                Some(SourceAcquisitionPhaseV2::Releasing)
            }
            RecoveredRetainedMountSourceRootV2::CleanupOnly(_) => None,
        },
        SourceRootPostcommitSuccessV2::Received(_) | SourceRootPostcommitSuccessV2::Reopened(_) => {
            None
        }
    }
}

fn fill_random(output: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        match rustix::rand::getrandom(&mut output[offset..], rustix::rand::GetRandomFlags::empty())
        {
            Ok(0) => {
                return Err(crate::MountError::State(
                    "kernel randomness returned an empty read".to_owned(),
                ));
            }
            Ok(count) => offset += count,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => {
                return Err(crate::MountError::State(format!(
                    "kernel randomness failed: {error}"
                )));
            }
        }
    }
    Ok(())
}

impl SourceAcquisitionTableV2 {
    /// Reconstructs the complete canonical `AOSMSA02` namespace-40 graph.
    ///
    /// # Errors
    ///
    /// Returns an error for a v1 or otherwise unsupported envelope, unknown or
    /// noncanonical JSON, a key or record-digest mismatch, a count/value limit,
    /// or any invalid, aliased, dangling, cyclic, or contradictory graph edge.
    pub fn recover(journal: &Journal) -> Result<Self> {
        let state = validate_mount_source_state_graph_v2(
            journal.records(RecordNamespace::MountSourceAcquisition),
        )?;
        Ok(Self {
            acquisitions: state.acquisitions,
            holder_sequences: state.holder_sequences,
            provider_heads: state.provider_heads,
            provider_sessions: state.provider_sessions,
            provider_attempts: state.provider_attempts,
        })
    }

    /// Reconstructs state through the fixed-owner source-consumption authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the complete current namespace-40 graph is
    /// canonical, bounded, and valid under the retained fixed journal lock.
    #[doc(hidden)]
    pub fn recover_from_consumption_authority(
        authority: &aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
    ) -> Result<Self> {
        let state = validate_mount_source_state_graph_v2(authority.records()?)?;
        Ok(Self {
            acquisitions: state.acquisitions,
            holder_sequences: state.holder_sequences,
            provider_heads: state.provider_heads,
            provider_sessions: state.provider_sessions,
            provider_attempts: state.provider_attempts,
        })
    }

    pub(super) fn state(&self) -> MountSourceAcquisitionStateV2 {
        MountSourceAcquisitionStateV2 {
            acquisitions: self.acquisitions.clone(),
            holder_sequences: self.holder_sequences.clone(),
            provider_heads: self.provider_heads.clone(),
            provider_sessions: self.provider_sessions.clone(),
            provider_attempts: self.provider_attempts.clone(),
        }
    }

    /// Returns acquisition views in canonical acquisition-ID order.
    pub fn acquisitions(&self) -> impl Iterator<Item = SourceAcquisitionViewV2<'_>> {
        self.acquisitions
            .values()
            .map(|row| SourceAcquisitionViewV2 { row })
    }

    /// Returns one recovered acquisition view.
    #[must_use]
    pub fn acquisition(&self, acquisition_id: &[u8; 32]) -> Option<SourceAcquisitionViewV2<'_>> {
        self.acquisitions
            .get(acquisition_id)
            .map(|row| SourceAcquisitionViewV2 { row })
    }

    /// Returns provider-head views in stable holder/provider order.
    pub fn provider_heads(&self) -> impl Iterator<Item = SourceProviderHeadViewV2<'_>> {
        self.provider_heads
            .values()
            .map(|head| SourceProviderHeadViewV2 { head })
    }

    /// Returns holder-wide acquisition sequence floors in stable-holder order.
    pub fn holder_sequences(&self) -> impl Iterator<Item = HolderSequenceViewV2<'_>> {
        self.holder_sequences
            .values()
            .map(|sequence| HolderSequenceViewV2 { sequence })
    }

    /// Returns immutable provider-session views in session-ID order.
    pub fn provider_sessions(&self) -> impl Iterator<Item = SourceProviderSessionViewV2<'_>> {
        self.provider_sessions
            .values()
            .map(|session| SourceProviderSessionViewV2 { session })
    }

    /// Returns immutable provider-attempt views in attempt-ID order.
    pub fn provider_attempts(&self) -> impl Iterator<Item = SourceProviderQueryAttemptViewV2<'_>> {
        self.provider_attempts
            .values()
            .map(|attempt| SourceProviderQueryAttemptViewV2 { attempt })
    }

    /// Encodes one canonical bounded source-acquisition inventory response.
    ///
    /// The response is a broker-returned observation, not independent proof of
    /// the syscall writer. Broker-session authentication and deployment
    /// confinement remain required before a controller treats it as current.
    ///
    /// # Errors
    ///
    /// Returns an error for sentinel snapshot identities, a zero journal
    /// sequence, a failed private-to-wire projection, or a response over the
    /// global protocol maximum.
    pub fn encode_inventory_response(
        &self,
        kernel_boot_id: [u8; 16],
        journal_sequence: u64,
        broker_instance_id: [u8; 16],
    ) -> Result<Vec<u8>> {
        if kernel_boot_id == [0; 16] || journal_sequence == 0 || broker_instance_id == [0; 16] {
            return Err(state_error(
                "source acquisition inventory header is invalid",
            ));
        }
        let acquisitions = self
            .acquisitions
            .values()
            .map(|row| source_acquisition_record(self, row))
            .collect::<Result<Vec<_>>>()?;
        let bytes = InventoryMountSourceAcquisitionsResponse {
            kernel_boot_id: kernel_boot_id.to_vec(),
            journal_sequence,
            acquisitions,
            broker_instance_id: broker_instance_id.to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition inventory exceeds the global protocol maximum",
            ));
        }
        Ok(bytes)
    }

    /// Encodes one canonical Acquire response selected by acquisition ID.
    ///
    /// The row, terminal attempt, and immutable session are joined through
    /// exact private record references owned by this recovered table.
    ///
    /// # Errors
    ///
    /// Returns an error when the acquisition is absent or its private evidence
    /// graph cannot be projected to the unchanged Mount 2.0 response.
    pub fn encode_acquire_response(&self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition response row is missing"))?;
        let bytes = AcquireMountSourceResponse {
            record: Some(source_acquisition_record(self, row)?).into(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition response exceeds the global protocol maximum",
            ));
        }
        Ok(bytes)
    }

    /// Encodes one canonical Release response selected by acquisition ID.
    ///
    /// The row, terminal attempt, and immutable session are joined through
    /// exact private record references owned by this recovered table.
    ///
    /// # Errors
    ///
    /// Returns an error when the acquisition is absent or its private evidence
    /// graph cannot be projected to the unchanged Mount 2.0 response.
    pub fn encode_release_response(&self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition response row is missing"))?;
        let bytes = ReleaseMountSourceAcquisitionResponse {
            record: Some(source_acquisition_record(self, row)?).into(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition response exceeds the global protocol maximum",
            ));
        }
        Ok(bytes)
    }
}

/// Is a read-only view of one stable holder's non-reuse sequence floor.
#[derive(Clone, Copy, Debug)]
pub struct HolderSequenceViewV2<'a> {
    sequence: &'a HolderSequenceV2,
}

impl HolderSequenceViewV2<'_> {
    /// Returns the stable holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(self) -> [u8; 16] {
        self.sequence.holder_authority_id
    }

    /// Returns the only sequence eligible for a fresh provider acquisition.
    #[must_use]
    pub const fn next_acquisition_sequence(self) -> u64 {
        self.sequence.next_acquisition_sequence
    }

    /// Returns the greatest sequence that can never be allocated again.
    #[must_use]
    pub const fn non_reuse_floor(self) -> u64 {
        self.sequence.last_allocated_acquisition_sequence
    }
}

/// Is a read-only view of one recovered acquisition row.
#[derive(Clone, Copy, Debug)]
pub struct SourceAcquisitionViewV2<'a> {
    row: &'a SourceAcquisitionRowV2,
}

impl SourceAcquisitionViewV2<'_> {
    /// Returns the Mount-minted stable acquisition ID.
    #[must_use]
    pub const fn acquisition_id(self) -> [u8; 32] {
        self.row.acquisition_id
    }

    /// Returns the holder-authority-scoped SourceProvider acquisition ID.
    #[must_use]
    pub const fn provider_acquisition_id(self) -> [u8; 32] {
        self.row.provider_acquisition.acquisition_id
    }

    /// Returns the monotone sequence committed into the SourceProvider ID.
    #[must_use]
    pub const fn provider_acquisition_sequence(self) -> u64 {
        self.row.provider_acquisition.acquisition_sequence
    }

    /// Returns the holder authority tuple that scopes the provider identity.
    #[must_use]
    pub const fn provider_acquisition_holder(self) -> ([u8; 16], u64, [u8; 32]) {
        (
            self.row.provider_acquisition.holder_authority_id,
            self.row.provider_acquisition.holder_authority_generation,
            self.row.provider_acquisition.holder_authority_digest,
        )
    }

    /// Returns the monotonic row revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.row.revision
    }

    /// Returns the exact lifecycle phase.
    #[must_use]
    pub const fn phase(self) -> SourceAcquisitionPhaseV2 {
        self.row.phase
    }

    /// Returns the corruption-protected canonical record digest.
    #[must_use]
    pub const fn record_digest(self) -> [u8; 32] {
        self.row.record_digest
    }
}

/// Is a read-only view of one stable provider head.
#[derive(Clone, Copy, Debug)]
pub struct SourceProviderHeadViewV2<'a> {
    head: &'a SourceProviderHeadV2,
}

impl SourceProviderHeadViewV2<'_> {
    /// Returns the stable holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(self) -> [u8; 16] {
        self.head.scope.holder_authority_id
    }

    /// Returns the stable provider authority ID.
    #[must_use]
    pub const fn provider_authority_id(self) -> [u8; 16] {
        self.head.scope.provider_authority_id
    }

    /// Returns the current immutable session ID.
    #[must_use]
    pub const fn current_session_id(self) -> [u8; 32] {
        self.head.current_session_id
    }

    /// Returns the current projection epoch and digest.
    #[must_use]
    pub const fn projection(self) -> (u64, [u8; 32]) {
        (
            self.head.current_projection_epoch,
            self.head.current_projection_digest,
        )
    }

    /// Reports whether crash recovery blocks normal provider work.
    #[must_use]
    pub const fn recovery_required(self) -> bool {
        self.head.recovery_barrier.is_some()
    }
}

/// Is a read-only view of one immutable authenticated session record.
#[derive(Clone, Copy, Debug)]
pub struct SourceProviderSessionViewV2<'a> {
    session: &'a SourceProviderSessionV2,
}

impl SourceProviderSessionViewV2<'_> {
    /// Returns the content-derived session ID.
    #[must_use]
    pub const fn session_id(self) -> [u8; 32] {
        self.session.session_id
    }

    /// Returns the kernel boot observed for the provider execution.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.session.kernel_boot_id
    }

    /// Returns the ordered four-signer commitment.
    #[must_use]
    pub const fn signer_set_commitment(self) -> [u8; 32] {
        self.session.signer_set_commitment
    }
}

/// Is a read-only view of one immutable provider query attempt.
#[derive(Clone, Copy, Debug)]
pub struct SourceProviderQueryAttemptViewV2<'a> {
    attempt: &'a SourceProviderQueryAttemptV2,
}

impl SourceProviderQueryAttemptViewV2<'_> {
    /// Returns the content-derived attempt ID.
    #[must_use]
    pub const fn attempt_id(self) -> [u8; 32] {
        self.attempt.attempt_id
    }

    /// Returns the exact request sequence reserved by this attempt.
    #[must_use]
    pub const fn request_sequence(self) -> u64 {
        self.attempt.request_sequence
    }

    /// Returns the SourceProvider acquisition ID for Acquire or Release.
    #[must_use]
    pub const fn provider_acquisition_id(self) -> Option<[u8; 32]> {
        match self.attempt.provider_acquisition {
            Some(value) => Some(value.acquisition_id),
            None => None,
        }
    }

    /// Returns the holder-scoped acquisition sequence for Acquire or Release.
    #[must_use]
    pub const fn provider_acquisition_sequence(self) -> Option<u64> {
        match self.attempt.provider_acquisition {
            Some(value) => Some(value.acquisition_sequence),
            None => None,
        }
    }

    /// Returns whether the attempt remains reserved and unresolved.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(&self.attempt.state, ProviderAttemptStateV2::Reserved)
    }

    /// Returns the closed SourceProvider method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self.attempt.method {
            ProviderMethodV2::Acquire => "acquire",
            ProviderMethodV2::Release => "release",
            ProviderMethodV2::Inventory => "inventory",
        }
    }
}
