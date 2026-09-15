//! Concrete protected storage for authenticated broker-session histories.
//!
//! Each namespace-47 value is one canonical, bounded full history. The owner
//! consumes the protected endpoint that defines its local role and publication
//! identity, so opening or replaying bytes cannot mint recovery authority
//! without revalidating the same protected endpoint before and after the read.

use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES, BrokerSessionDurableEndpointV1,
    BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use sha2::{Digest as _, Sha256};

use crate::{
    BrokerSessionSecurityError, ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1,
};

use super::{
    ObservedBrokerPeerExecutionV1, ProtectedBrokerOutcomeCommitReadbackV1,
    ProtectedBrokerOutcomeCommittedAdvancementV1, ProtectedBrokerOutcomeCurrentV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, ProtectedBrokerOutcomeGateRecoveryV1,
    ProtectedBrokerOutcomePendingAdvancementV1, ProtectedBrokerRequestWriteV1,
    ProtectedBrokerSessionJournalAuthorityV1, ProtectedBrokerSessionJournalSnapshotV1,
    reconstruct_terminal_semantics, reopen_current, request_matches_head,
};

const KEY_MAGIC: &[u8; 8] = b"AOSBSJ01";
const VALUE_MAGIC: &[u8; 8] = b"AOSBSJ01";
const VALUE_VERSION: u16 = 1;
const VALUE_FIXED_BYTES: usize = 152;
const VALUE_DIGEST_BYTES: usize = 32;
const VALUE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.protected-history.v1\0";
const ENDPOINT_PUBLICATION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.endpoint-publication.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.journal-transaction.v1\0";
const MAXIMUM_PROTOCOL_RECORDS: usize = 4;
const PROTECTED_MOUNT_CLIENT_ROOT: &str = "/var/lib/aos/sandboxd/broker-session/mount";
const PROTECTED_MOUNT_BROKER_ROOT: &str = "/var/lib/aos/sandbox-mount/broker-session";
const PROTECTED_MOUNT_SESSION_JOURNAL: &str = "session.journal";

fn protected_mount_session_journal_limits() -> JournalLimits {
    let maximum_record_bytes =
        BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES + VALUE_FIXED_BYTES + 1024;
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes,
        maximum_key_bytes: KEY_MAGIC.len() + 1,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: maximum_record_bytes + 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_PROTOCOL_RECORDS * maximum_record_bytes,
        maximum_materialized_records: MAXIMUM_PROTOCOL_RECORDS,
    }
}

/// Seals the recovery reader implementation to this module.
pub(super) trait SealedJournalAuthority {}

enum ProtectedEndpointV1 {
    Client(ProtectedBrokerSessionClientV1),
    Broker(ProtectedBrokerSessionBrokerV1),
}

impl ProtectedEndpointV1 {
    fn role(&self) -> BrokerSessionDurableEndpointV1 {
        match self {
            Self::Client(_) => BrokerSessionDurableEndpointV1::Client,
            Self::Broker(_) => BrokerSessionDurableEndpointV1::Broker,
        }
    }

    fn revalidate(&mut self) -> Result<(), BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.revalidate_handshake_custody(),
            Self::Broker(endpoint) => endpoint.revalidate_handshake_custody(),
        }
    }

    fn process_execution_id(&self) -> [u8; 16] {
        match self {
            Self::Client(endpoint) => endpoint.process_execution_id_bytes(),
            Self::Broker(endpoint) => endpoint.process_execution_id_bytes(),
        }
    }

    fn manifest_binding(&mut self) -> Result<[u8; 32], BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.manifest_binding().map(|value| *value.as_bytes()),
            Self::Broker(endpoint) => endpoint.manifest_binding().map(|value| *value.as_bytes()),
        }
    }

    fn context(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.context_for_handshake(transcript.broker_process()),
            Self::Broker(endpoint) => endpoint.context_for_handshake(transcript.client_process()),
        }
    }
}

/// Owns one protected broker-session journal and its exact local endpoint.
///
/// Construction is dormant: it opens storage and retains authority, but starts
/// no listener, route, dispatcher, or background task.
#[must_use = "dropping the owner releases the sole protected journal lock"]
pub(crate) struct ProtectedBrokerSessionJournalV1 {
    journal: Journal,
    endpoint: ProtectedEndpointV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionJournalV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionJournalV1([redacted])")
    }
}

/// Selects one fixed Mount broker-session endpoint role.
///
/// Each variant maps to a compile-time endpoint directory. It cannot select a
/// path, journal basename, ownership policy, or replay bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedMountBrokerSessionRoleV1 {
    /// Uses the controller-side Mount client custody root.
    ControllerClient,
    /// Uses the Mount-service broker custody root.
    MountBroker,
}

/// Owns one fixed-root protected Mount broker-session endpoint and journal.
///
/// Opening this dormant owner retains endpoint custody and the sole journal
/// lock. It creates no socket, listener, route, dispatcher, or background task;
/// all peer checks use an already-connected socket supplied to an operation.
#[must_use = "dropping the owner releases fixed endpoint custody and its journal lock"]
pub struct ProtectedMountBrokerSessionOwnerV1 {
    journal: ProtectedBrokerSessionJournalV1,
}

impl core::fmt::Debug for ProtectedMountBrokerSessionOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedMountBrokerSessionOwnerV1([redacted])")
    }
}

impl ProtectedMountBrokerSessionOwnerV1 {
    /// Opens the fixed protected endpoint and journal selected by `role`.
    ///
    /// The controller client root is
    /// `/var/lib/aos/sandboxd/broker-session/mount`; the Mount broker root is
    /// `/var/lib/aos/sandbox-mount/broker-session`. Both use the fixed basename
    /// `session.journal` and the closed limits in this module.
    ///
    /// # Errors
    ///
    /// Returns an error unless endpoint custody and complete bounded journal
    /// replay satisfy the protected profile at the selected fixed root.
    pub fn open_fixed_protected(
        role: ProtectedMountBrokerSessionRoleV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let root = Path::new(match role {
            ProtectedMountBrokerSessionRoleV1::ControllerClient => PROTECTED_MOUNT_CLIENT_ROOT,
            ProtectedMountBrokerSessionRoleV1::MountBroker => PROTECTED_MOUNT_BROKER_ROOT,
        });
        let journal = match role {
            ProtectedMountBrokerSessionRoleV1::ControllerClient => {
                ProtectedBrokerSessionJournalV1::open_client(
                    ProtectedBrokerSessionClientV1::load(root)?,
                    root,
                    PROTECTED_MOUNT_SESSION_JOURNAL,
                    protected_mount_session_journal_limits(),
                )?
            }
            ProtectedMountBrokerSessionRoleV1::MountBroker => {
                ProtectedBrokerSessionJournalV1::open_broker(
                    ProtectedBrokerSessionBrokerV1::load(root)?,
                    root,
                    PROTECTED_MOUNT_SESSION_JOURNAL,
                    protected_mount_session_journal_limits(),
                )?
            }
        };
        Ok(Self { journal })
    }

    /// Installs the first authenticated request under an exact absence CAS.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request, transcript, adopted peer, endpoint,
    /// and empty fixed journal are mutually current.
    pub fn initialize_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        self.journal
            .initialize_authenticated_request(request, transcript, connection_peer)
    }

    /// Reopens the exact protected broker-side Mount outcome gate.
    ///
    /// # Errors
    ///
    /// Returns an error unless complete replay and current endpoint, peer,
    /// transcript, request, and journal-head evidence agree.
    pub fn reopen_mount_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError> {
        self.journal
            .reopen_mount_outcome(request, transcript, connection_peer)
    }

    /// Appends one successor request after a protected terminal head.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request is the exact current successor and
    /// the fixed owner remains current before mutation.
    pub fn append_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.journal
            .append_authenticated_request(request, transcript, connection_peer)
    }

    /// Commits one pending Mount outcome with ambiguity-safe exact readback.
    #[must_use]
    pub fn commit_mount_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.journal.commit_mount_outcome(pending, connection_peer)
    }

    /// Recovers an interrupted Mount outcome commit against the fixed owner.
    #[must_use]
    pub fn recover_mount_outcome_commit(
        &mut self,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.journal
            .recover_mount_outcome_commit(recovery, connection_peer)
    }

    /// Recovers an interrupted initial request installation.
    #[must_use]
    pub fn recover_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        self.journal
            .recover_initialization(recovery, connection_peer)
    }

    /// Recovers an interrupted successor-request append.
    #[must_use]
    pub fn recover_request_commit(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        self.journal
            .recover_request_commit(recovery, connection_peer)
    }

    /// Revalidates an exact terminal Mount head for immediate effect handoff.
    ///
    /// The returned token retains this fixed owner's unique mutable borrow.
    ///
    /// # Errors
    ///
    /// Returns an error unless every protected terminal binding remains exact.
    pub fn revalidate_mount_outcome<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>, BrokerSessionSecurityError> {
        self.journal
            .revalidate_mount_outcome(owner, connection_peer)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    /// Opens a root-owned journal for one protected client endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error unless the journal has protected-open provenance, its
    /// complete namespace-47 materialized state is canonical and bounded, and
    /// every retained record matches the current protected client endpoint.
    pub(crate) fn open_client(
        endpoint: ProtectedBrokerSessionClientV1,
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<Self, BrokerSessionSecurityError> {
        Self::open(
            ProtectedEndpointV1::Client(endpoint),
            directory,
            name,
            limits,
        )
    }

    /// Opens a root-owned journal for one protected broker endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error unless the journal has protected-open provenance, its
    /// complete namespace-47 materialized state is canonical and bounded, and
    /// every retained record matches the current protected broker endpoint.
    pub(crate) fn open_broker(
        endpoint: ProtectedBrokerSessionBrokerV1,
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<Self, BrokerSessionSecurityError> {
        Self::open(
            ProtectedEndpointV1::Broker(endpoint),
            directory,
            name,
            limits,
        )
    }

    fn open(
        endpoint: ProtectedEndpointV1,
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let (journal, _) = Journal::open_protected_at(directory, name, limits)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = Self { journal, endpoint };
        authority.validate_all()?;
        Ok(authority)
    }

    /// Installs the first authenticated request under an exact absence CAS.
    ///
    /// The initial request must carry a nonzero catalog binding. That signed
    /// binding becomes the protected catalog head for this protocol; no scalar
    /// catalog constructor is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation for a wrong endpoint, stale peer,
    /// mismatched transcript, absent catalog binding, or nonempty protocol
    /// history. A durability or readback failure is returned as a retained
    /// recovery token rather than an ordinary error.
    pub fn initialize_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        if super::endpoint_for_request(request) != self.endpoint.role() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let before = self.read_optional(transcript.protocol())?;
        if before.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let current_catalog = request
            .catalog_binding()
            .filter(|value| value.iter().any(|byte| *byte != 0))
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let endpoint_publication = self.endpoint_publication(transcript.protocol())?;
        let empty = ProtectedBrokerSessionJournalSnapshotV1::new(
            0,
            endpoint_publication,
            current_catalog,
            [0; 32],
            None,
        )?;
        let write = ProtectedBrokerRequestWriteV1::prepare_initial_from_snapshot(
            request, &context, transcript, &peer, &empty,
        )?;
        let target = StoredProtocolHistoryV1::from_request_write(
            transcript.protocol(),
            self.endpoint.role(),
            endpoint_publication,
            current_catalog,
            write,
        )?;
        let recovery = ProtectedBrokerSessionInitializationRecoveryV1 {
            target,
            transcript: transcript.clone(),
        };
        Ok(self.install_initial(recovery, connection_peer))
    }

    /// Reopens the exact protected broker-side Mount outcome gate.
    ///
    /// # Errors
    ///
    /// Returns an error unless full canonical replay, endpoint custody, peer
    /// identity, catalog binding, transcript, request, and current head agree.
    pub fn reopen_mount_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        let recovery = ProtectedBrokerOutcomeGateRecoveryV1::reopen_mount_outcome(
            self, request, transcript, &context, &peer,
        )?;
        let after_peer = self.observe_peer(transcript, connection_peer)?;
        if recovery.gate.currentness.peer_binding
            != after_peer.binding(self.endpoint.role(), transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(recovery.into_gate())
    }

    /// Revalidates one exact protected terminal Mount outcome for immediate use.
    ///
    /// The returned token holds this journal's unique mutable borrow, preventing
    /// another in-process recovery or advancement from superseding the checked
    /// head during the associated effect-authority handoff.
    ///
    /// # Errors
    ///
    /// Returns an error unless endpoint custody, peer identity, transcript,
    /// protected bindings, generation, head, request, and outcome packet still
    /// match the authority captured by protected admission.
    pub fn revalidate_mount_outcome<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>, BrokerSessionSecurityError> {
        let context = self.current_context(&owner.transcript)?;
        if context.protected_context_digest() != owner.context.protected_context_digest() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let peer = self.observe_peer(&owner.transcript, connection_peer)?;
        let peer_binding = peer.binding(self.endpoint.role(), &owner.transcript, &owner.context)?;
        let (history, traffic, current) =
            reopen_current(self, &owner.transcript, &owner.context, &peer)?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if current.generation != owner.protected_generation
            || current.current_head != owner.protected_head
            || current.protected_bindings(&owner.context)? != owner.protected_bindings
            || peer_binding != owner.peer_binding
            || head.endpoint() != BrokerSessionDurableEndpointV1::Broker
            || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || !request_matches_head(
                &owner.request,
                head,
                aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive,
            )
            || traffic.has_outstanding_request()
            || head.outcome_packet() != Some(owner.outcome_packet.as_slice())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let reconstructed = reconstruct_terminal_semantics(
            &history,
            &owner.request,
            &owner.transcript,
            &owner.context,
            &traffic,
        )?;
        if reconstructed.canonical_packet() != owner.outcome_packet
            || reconstructed.filesystem_worker_qualification_commitment()
                != owner.qualification_record_commitment
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let after_peer = self.observe_peer(&owner.transcript, connection_peer)?;
        if after_peer.binding(self.endpoint.role(), &owner.transcript, &owner.context)?
            != owner.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(ProtectedBrokerOutcomeCurrentV1 { _authority: self })
    }

    /// Appends one authenticated successor request after a terminal head.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation unless canonical full replay selects
    /// the exact terminal predecessor and the protected endpoint, peer,
    /// transcript, catalog, generation, head, and revision all remain current.
    pub fn append_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        let write = ProtectedBrokerRequestWriteV1::prepare_successor(
            self, request, &context, transcript, &peer,
        )?;
        let current = self
            .read_optional(transcript.protocol())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if current.generation != write.expected_generation()
            || current.current_head != write.expected_head()
            || current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .revision()
                != write.expected_revision()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let recovery = ProtectedBrokerRequestCommitRecoveryV1 {
            expected_generation: write.expected_generation(),
            expected_head: write.expected_head(),
            expected_revision: write.expected_revision(),
            target: StoredProtocolHistoryV1::from_request_write(
                transcript.protocol(),
                current.endpoint,
                current.endpoint_publication,
                current.current_catalog,
                write,
            )?,
            transcript: transcript.clone(),
        };
        Ok(self.install_successor(recovery, connection_peer))
    }

    /// Commits one exact pending outcome and confirms canonical readback.
    ///
    /// Every post-preflight failure retains the pending advancement inside an
    /// explicit recovery token. A freshly reopened owner can consume that token
    /// to classify the exact predecessor or replacement state.
    #[must_use]
    pub fn commit_mount_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        match self.try_commit_outcome(&pending, connection_peer) {
            Ok(readback) => match pending.confirm_committed_preserving(readback) {
                Ok(committed) => ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                Err((error, pending)) => ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                    error,
                    recovery: ProtectedBrokerOutcomeCommitRecoveryV1 { pending },
                },
            },
            Err(error) => ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                error,
                recovery: ProtectedBrokerOutcomeCommitRecoveryV1 { pending },
            },
        }
    }

    /// Resolves an interrupted outcome commit against a freshly opened owner.
    #[must_use]
    pub fn recover_mount_outcome_commit(
        &mut self,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.commit_mount_outcome(recovery.pending, connection_peer)
    }

    /// Resolves an interrupted initial install by exact target or absence.
    #[must_use]
    pub fn recover_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        self.install_initial(recovery, connection_peer)
    }

    /// Resolves an interrupted successor-request append.
    #[must_use]
    pub fn recover_request_commit(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        self.install_successor(recovery, connection_peer)
    }

    fn install_initial(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        let target = &recovery.target;
        let result = (|| {
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            match self.read_optional(target.protocol)? {
                Some(current) if current == *target => return Ok(()),
                Some(_) => return Err(BrokerSessionSecurityError::Currentness),
                None => {}
            }
            self.commit_stored(target)?;
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            if !matches!(self.read_optional(target.protocol)?, Some(current) if current == *target)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        match result {
            Ok(()) => ProtectedBrokerSessionInitializationResultV1::Initialized,
            Err(error) => {
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery }
            }
        }
    }

    fn install_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        let target = &recovery.target;
        let result = (|| {
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            let current = self
                .read_optional(target.protocol)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            if current == *target {
                return Ok(());
            }
            let head = current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .clone();
            if current.generation != recovery.expected_generation
                || current.current_head != recovery.expected_head
                || head.revision() != recovery.expected_revision
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            self.commit_stored(target)?;
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            if !matches!(self.read_optional(target.protocol)?, Some(current) if current == *target)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        match result {
            Ok(()) => ProtectedBrokerRequestCommitResultV1::Committed,
            Err(error) => {
                ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery }
            }
        }
    }

    fn try_commit_outcome(
        &mut self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCommitReadbackV1, BrokerSessionSecurityError> {
        let context = self.current_context(&pending.transcript)?;
        let before_peer = self.observe_peer(&pending.transcript, connection_peer)?;
        if before_peer.binding(self.endpoint.role(), &pending.transcript, &context)?
            != pending.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let protocol = pending.transcript.protocol();
        let current = self
            .read_optional(protocol)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let replacement = StoredProtocolHistoryV1::from_pending_outcome(&current, pending)?;
        if current.generation == replacement.generation
            && current.current_head == replacement.current_head
            && current.history == replacement.history
        {
            return self.confirm_pending(pending, connection_peer);
        }
        if current.generation != pending.durable_cas.expected_generation
            || current.current_head != pending.durable_cas.expected_head
            || current.endpoint_publication != pending.protected_bindings.endpoint_publication()
            || current.current_catalog != pending.protected_bindings.current_catalog()
            || current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .revision()
                != pending.durable_cas.expected_revision
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.commit_stored(&replacement)?;
        self.confirm_pending(pending, connection_peer)
    }

    fn confirm_pending(
        &mut self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCommitReadbackV1, BrokerSessionSecurityError> {
        let peer = self.observe_peer(&pending.transcript, connection_peer)?;
        let readback =
            ProtectedBrokerOutcomeCommitReadbackV1::confirm_after_cas(self, pending, &peer)?;
        let context = self.current_context(&pending.transcript)?;
        let after_peer = self.observe_peer(&pending.transcript, connection_peer)?;
        if after_peer.binding(self.endpoint.role(), &pending.transcript, &context)?
            != pending.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(readback)
    }

    fn current_context(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let context = self.endpoint.context(transcript)?;
        self.endpoint.revalidate()?;
        if context.protected_context_digest() != transcript.protected_context_digest()
            || context.protocol() != transcript.protocol()
            || context.client_process() != transcript.client_process()
            || context.broker_process() != transcript.broker_process()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(context)
    }

    fn validate_recovery_peer(
        &mut self,
        target: &StoredProtocolHistoryV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        let head = target
            .history_model()?
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .clone();
        if target.protocol != transcript.protocol()
            || target.endpoint != self.endpoint.role()
            || head.session_binding() != transcript.session_binding()
            || head.peer_binding() != peer.binding(target.endpoint, transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn observe_peer(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ObservedBrokerPeerExecutionV1, BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let process_execution_id = match self.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => transcript.broker_process(),
            BrokerSessionDurableEndpointV1::Broker => transcript.client_process(),
        };
        let peer =
            ObservedBrokerPeerExecutionV1::from_connection(connection_peer, process_execution_id)?;
        self.endpoint.revalidate()?;
        Ok(peer)
    }

    fn endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let manifest = self.endpoint.manifest_binding()?;
        let process = self.endpoint.process_execution_id();
        let role = endpoint_code(self.endpoint.role());
        self.endpoint.revalidate()?;

        let mut digest = Sha256::new();
        digest.update(ENDPOINT_PUBLICATION_DOMAIN);
        digest.update([protocol_code(protocol), role]);
        digest.update(manifest);
        digest.update(process);
        Ok(digest.finalize().into())
    }

    fn read_optional(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let before_publication = self.endpoint_publication(protocol)?;
        let records = {
            let authority = self
                .journal
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut decoded = Vec::new();
            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                if decoded.len() == MAXIMUM_PROTOCOL_RECORDS {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                decoded.push(StoredProtocolHistoryV1::decode(key, value)?);
            }
            decoded
        };
        let after_publication = self.endpoint_publication(protocol)?;
        if before_publication != after_publication
            || records
                .iter()
                .any(|record| record.endpoint != self.endpoint.role())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut selected = None;
        for record in records {
            if record.endpoint_publication != self.endpoint_publication(record.protocol)? {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            if record.protocol == protocol {
                if selected.replace(record).is_some() {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            }
        }
        Ok(selected)
    }

    fn validate_all(&mut self) -> Result<(), BrokerSessionSecurityError> {
        for protocol in [
            BrokerSessionProtocolV1::Host,
            BrokerSessionProtocolV1::Storage,
            BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network,
        ] {
            let _ = self.read_optional(protocol)?;
        }
        Ok(())
    }

    fn commit_stored(
        &mut self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let key = protocol_key(stored.protocol);
        let value = stored.encode()?;
        let transaction = JournalTransaction::new(
            transaction_id(stored)?,
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                key,
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .commit(&transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(())
    }
}

impl SealedJournalAuthority for ProtectedBrokerSessionJournalV1 {}

impl ProtectedBrokerSessionJournalAuthorityV1 for ProtectedBrokerSessionJournalV1 {
    fn read_current(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
        let current = self
            .read_optional(protocol)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        current.snapshot()
    }
}

/// Classifies an initial protected-history install.
#[must_use = "an interrupted install must retain its recovery token"]
pub enum ProtectedBrokerSessionInitializationResultV1 {
    /// The exact first history is current and durably readable.
    Initialized,
    /// Durable state may contain the target and must be reopened explicitly.
    RecoveryRequired {
        /// Redacted reason that the install could not be confirmed.
        error: BrokerSessionSecurityError,
        /// Move-only exact target used for reopen classification.
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
    },
}

/// Retains the exact canonical initial target across an ambiguous commit.
#[must_use = "the initialization target must be resolved against a reopened journal"]
pub struct ProtectedBrokerSessionInitializationRecoveryV1 {
    target: StoredProtocolHistoryV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
}

/// Classifies a successor-request commit without discarding its exact target.
#[must_use = "an interrupted request commit must retain its recovery token"]
pub enum ProtectedBrokerRequestCommitResultV1 {
    /// The exact successor history is current and durably readable.
    Committed,
    /// Durable state may contain the target and must be reopened explicitly.
    RecoveryRequired {
        /// Redacted reason that exact readback did not complete.
        error: BrokerSessionSecurityError,
        /// Move-only predecessor and target retained for exact classification.
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
    },
}

/// Retains one exact predecessor CAS and successor target across interruption.
#[must_use = "the successor target must be resolved against a reopened journal"]
pub struct ProtectedBrokerRequestCommitRecoveryV1 {
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_revision: u64,
    target: StoredProtocolHistoryV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
}

/// Classifies an outcome commit without discarding authenticated progress.
#[must_use = "an interrupted outcome commit must retain its recovery token"]
pub enum ProtectedBrokerOutcomeCommitResultV1 {
    /// The replacement was committed, fully replayed, and read back exactly.
    Committed(ProtectedBrokerOutcomeCommittedAdvancementV1),
    /// Durable state is unconfirmed and requires an explicit reopen.
    RecoveryRequired {
        /// Redacted reason that exact readback did not complete.
        error: BrokerSessionSecurityError,
        /// Move-only pending advancement retained for exact classification.
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    },
}

/// Retains an exact pending outcome across ambiguous durable mutation.
#[must_use = "the pending outcome must be resolved against a reopened journal"]
pub struct ProtectedBrokerOutcomeCommitRecoveryV1 {
    pending: ProtectedBrokerOutcomePendingAdvancementV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredProtocolHistoryV1 {
    protocol: BrokerSessionProtocolV1,
    endpoint: BrokerSessionDurableEndpointV1,
    generation: u64,
    endpoint_publication: [u8; 32],
    current_catalog: [u8; 32],
    current_head: [u8; 32],
    history: Vec<u8>,
}

impl StoredProtocolHistoryV1 {
    fn from_request_write(
        protocol: BrokerSessionProtocolV1,
        endpoint: BrokerSessionDurableEndpointV1,
        endpoint_publication: [u8; 32],
        current_catalog: [u8; 32],
        write: ProtectedBrokerRequestWriteV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let history = write.encode()?;
        let model = BrokerSessionDurableHistoryV1::decode(&history)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(Self {
            protocol,
            endpoint,
            generation: write
                .expected_generation()
                .checked_add(1)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
            endpoint_publication,
            current_catalog,
            current_head: model.head_commitment(),
            history,
        })
    }

    fn from_pending_outcome(
        current: &Self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let history = pending.replacement_history.clone();
        let model = BrokerSessionDurableHistoryV1::decode(&history)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if model.head_commitment() != pending.durable_cas.replacement_head {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            protocol: current.protocol,
            endpoint: current.endpoint,
            generation: pending
                .durable_cas
                .expected_generation
                .checked_add(1)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
            endpoint_publication: current.endpoint_publication,
            current_catalog: pending.protected_bindings.current_catalog(),
            current_head: pending.durable_cas.replacement_head,
            history,
        })
    }

    fn history_model(&self) -> Result<BrokerSessionDurableHistoryV1, BrokerSessionSecurityError> {
        BrokerSessionDurableHistoryV1::decode(&self.history)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    fn snapshot(
        &self,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
        ProtectedBrokerSessionJournalSnapshotV1::new(
            self.generation,
            self.endpoint_publication,
            self.current_catalog,
            self.current_head,
            Some(self.history.clone()),
        )
    }

    fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        let model = self.history_model()?;
        let head = model
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.generation == 0
            || self.endpoint_publication.iter().all(|byte| *byte == 0)
            || self.current_catalog.iter().all(|byte| *byte == 0)
            || model.head_commitment() != self.current_head
            || head.protocol() != self.protocol
            || head.endpoint() != self.endpoint
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history_length = u32::try_from(self.history.len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let capacity = VALUE_FIXED_BYTES
            .checked_add(self.history.len())
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if self.history.len() > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut value = Vec::with_capacity(capacity);
        value.extend_from_slice(VALUE_MAGIC);
        value.extend_from_slice(&VALUE_VERSION.to_be_bytes());
        value.push(protocol_code(self.protocol));
        value.push(endpoint_code(self.endpoint));
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&self.endpoint_publication);
        value.extend_from_slice(&self.current_catalog);
        value.extend_from_slice(&self.current_head);
        value.extend_from_slice(&history_length.to_be_bytes());
        value.extend_from_slice(&self.history);
        let digest = value_digest(&value);
        value.extend_from_slice(&digest);
        Ok(value)
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        if value.len() < VALUE_FIXED_BYTES
            || value.len()
                > VALUE_FIXED_BYTES
                    .checked_add(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)
                    .ok_or(BrokerSessionSecurityError::Currentness)?
            || value.get(..8) != Some(VALUE_MAGIC.as_slice())
            || read_u16(value, 8)? != VALUE_VERSION
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let protocol = decode_protocol(read_u8(value, 10)?)?;
        let endpoint = decode_endpoint(read_u8(value, 11)?)?;
        if key != protocol_key(protocol) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let generation = read_u64(value, 12)?;
        let endpoint_publication = read_array(value, 20)?;
        let current_catalog = read_array(value, 52)?;
        let current_head = read_array(value, 84)?;
        let history_length = usize::try_from(read_u32(value, 116)?)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let history_end = 120usize
            .checked_add(history_length)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let digest_end = history_end
            .checked_add(VALUE_DIGEST_BYTES)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if history_length == 0
            || history_length > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
            || digest_end != value.len()
            || read_array::<32>(value, history_end)? != value_digest(&value[..history_end])
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history = value
            .get(120..history_end)
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .to_vec();
        let stored = Self {
            protocol,
            endpoint,
            generation,
            endpoint_publication,
            current_catalog,
            current_head,
            history,
        };
        if stored.encode()? != value {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(stored)
    }
}

fn protocol_key(protocol: BrokerSessionProtocolV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(9);
    key.extend_from_slice(KEY_MAGIC);
    key.push(protocol_code(protocol));
    key
}

fn protocol_code(protocol: BrokerSessionProtocolV1) -> u8 {
    match protocol {
        BrokerSessionProtocolV1::Host => 1,
        BrokerSessionProtocolV1::Storage => 2,
        BrokerSessionProtocolV1::Mount => 3,
        BrokerSessionProtocolV1::Network => 4,
    }
}

fn decode_protocol(code: u8) -> Result<BrokerSessionProtocolV1, BrokerSessionSecurityError> {
    match code {
        1 => Ok(BrokerSessionProtocolV1::Host),
        2 => Ok(BrokerSessionProtocolV1::Storage),
        3 => Ok(BrokerSessionProtocolV1::Mount),
        4 => Ok(BrokerSessionProtocolV1::Network),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn endpoint_code(endpoint: BrokerSessionDurableEndpointV1) -> u8 {
    match endpoint {
        BrokerSessionDurableEndpointV1::Client => 1,
        BrokerSessionDurableEndpointV1::Broker => 2,
    }
}

fn decode_endpoint(code: u8) -> Result<BrokerSessionDurableEndpointV1, BrokerSessionSecurityError> {
    match code {
        1 => Ok(BrokerSessionDurableEndpointV1::Client),
        2 => Ok(BrokerSessionDurableEndpointV1::Broker),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn value_digest(value_without_digest: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(VALUE_DOMAIN);
    digest.update(value_without_digest);
    digest.finalize().into()
}

fn transaction_id(
    stored: &StoredProtocolHistoryV1,
) -> Result<[u8; 16], BrokerSessionSecurityError> {
    let value = stored.encode()?;
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update([
        protocol_code(stored.protocol),
        endpoint_code(stored.endpoint),
    ]);
    digest.update(stored.generation.to_be_bytes());
    digest.update(stored.current_head);
    digest.update(value_digest(&value));
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[..16]);
    if id == [0; 16] {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(id)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, BrokerSessionSecurityError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(BrokerSessionSecurityError::Currentness)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BrokerSessionSecurityError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BrokerSessionSecurityError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, BrokerSessionSecurityError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], BrokerSessionSecurityError> {
    bytes
        .get(offset..offset + N)
        .ok_or(BrokerSessionSecurityError::Currentness)?
        .try_into()
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}
