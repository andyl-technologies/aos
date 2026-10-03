//! Fixed-root ownership for dormant runtime execution durability.
//!
//! This module is the only public entry to the execution and agent journals.
//! It resolves exact Host peer and backend-currentness records from the fixed
//! protected Host root, derives all journal bindings from those records, and
//! retains the protected claim while admission, recovery, and agent CAS are
//! possible. It performs no backend, guest, route, or service effect.
//!
//! ```text
//! AOSREC01 || backend_build[32] || probe_epoch:u64be
//! || probe_protected_context[32] || resource_ledger[32]
//! || output_reservation[32] || record_digest[32]
//! ```
//!
//! ```text
//! AOSRPC01 || count:u8 || ordered_capability_codes[11] || zero_padding
//! || record_digest[32]
//! ```
//!
//! ```text
//! AOSRHE01 || host_evidence_key[32] || trust_context[32]
//! || evidence_channel[32] || host_boot_id[16] || record_digest[32]
//!
//! AOSRPL01 || required_count:u8 || ordered_required_codes_and_zero_padding[15]
//! || storage_root[32] || attachment_set[32] || network[32]
//! || runtime_profile[32] || plan_commitment[32] || record_digest[32]
//!
//! AOSRLH01 || next_lifecycle_sequence:u64be
//! || next_observation_sequence:u64be || initial_observation_sequence:u64be
//! || store_binding[32] || record_digest[32]
//!
//! AOSRLT01 || operation[16] || operation_sequence:u64be
//! || action:u8 || result_phase:u8 || zero_padding[6] || plan[32]
//! || handle[32] || request[32] || observation_sequence:u64be
//! || observation_commitment[32] || currentness[32] || authority[32]
//! || record_digest[32]
//! ```
//!
//! ```text
//! AOSRBM01 || peer[296] || currentness[176] || capabilities[52]
//! || host_evidence[152] || plan_catalog[216] || manifest_digest[32]
//! ```

use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentFeatureV1, AgentHandshakeRequestV1,
    AgentHandshakeResponseV1, AgentOperationRequestV1, AgentRuntimeBindingV1,
    AgentSessionBindingV1, GuestRuntimeArgumentObservationErrorV1,
    GuestRuntimeArgumentObserveRequestV1, verify_guest_runtime_argument_readback_v1,
};
use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, AdmissionCurrentnessV1, AdmissionStoreCommitV1, AdmittedExecutionV1,
    BackendCapabilitiesV1, BackendCapabilityV1, BackendExecutionInspectionRequestV1,
    BackendExecutionInspectionV1, BackendExecutionInventoryV1, BackendLifecycleOperationV1,
    BackendOperationIdV1, BackendOperationSequenceV1, BackendProbeCurrentnessV1,
    BackendRuntimeInspectionV1, BackendRuntimePhaseV1, BackendStopDeadlineV1,
    DurableExecutionEffectV1, EffectCommitError, EffectCompletionV1, EffectIssueV1,
    EffectOperationV1, EffectPhaseV1, EffectStoreTransitionV1, ExecutionAdmissionDraftV1,
    ExecutionAdmissionStore, ExecutionEffectStore, RequiredBackendCapabilitiesV1,
    ResolvedRuntimePlanV1, RuntimeCurrentnessV1, RuntimeHandleCommitmentV1,
    backend_evidence_authority_binding_v1, backend_execution_inspection_binding_v1,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DecodeLimits, DesiredGeneration, ExecutionId,
    ExecutionRuntimeArgumentLimitV1, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    ObservationSequence, OperationId, PayloadBootId, Revision, SandboxId, decode_execution_spec_v1,
    execution_spec_digest_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV1, HostNoApplySettlementPhaseV2,
};
use aos_sandbox_protocol::host_storage_output_readback::ValidatedHostStorageOutputReadbackRequestV1;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use super::agent_checkpoint::{AgentCheckpointCandidateV1, AgentCheckpointError};
use super::agent_reducer::{
    AgentOperationCas, AgentOperationCasError, AgentOperationRecoveryCas,
    AgentOperationReservationV1, AgentOutcomeRecoveryTokenV1, AgentOutcomeStoreTransitionV1,
    AgentRecoveredOperationV1, AgentRecoveredOutcomeCommitV1, AgentRecoveredReservationV1,
    AgentReservationRecoveryTokenV1, AgentReservationStoreTransitionV1,
    AuthenticatedRecoveredAgentOutcomeV1, PreparedAgentOperationV1,
    agent_handshake_signing_message_v1, agent_outcome_signing_message_v1,
};

use crate::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use crate::execution_output_reservation::{
    DurableExecutionOutputReservationV1, ExecutionOutputReservationCommitV1,
    ExecutionOutputReservationRecoveryResultV1, ExecutionOutputReservationRecoveryV1,
    RetainedClaim, accepted_claim,
};
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::journal::{
    GlobalCapacityReservationPurposeV1, HostCurrentnessFenceV1, HostExecutionFenceV1, Journal,
    JournalError, JournalLimits, JournalRecord, JournalTransaction, ProtectedJournalAuthority,
    RecordNamespace,
};
use crate::sandbox_spec_state;

use super::agent_store::{
    AuthenticatedJournalAgentCheckpointV1, DormantJournalAgentStoreV1, JournalAgentStoreError,
};
use super::argument_observation::ArgumentObservationRecordV1;
use super::evidence::JournalExecutionCompletionV1;
use super::host_output_source::VerifiedHostOutputReserveSourceV1;
use super::no_apply_settlement::{
    ControllerAssertedSettlementArchivesV1, HostObservedSettlementIdentityV1,
    HostSettlementRecordV1, RECORD_BYTES as HOST_SETTLEMENT_RECORD_BYTES,
};
use super::recovery::{AppliedExecutionRecoveryV1, apply_execution_recovery_v1};
use super::route_record::{
    ProtectedAgentRoutePeerV1, ProtectedAgentRouteRecordV1,
    route_binding as protected_agent_route_binding,
};
use super::store::{
    AuthenticatedJournalExecutionRecoveryV1 as JournalRecoveryV1, ExecutionJournalRecoveryTokenV1,
    HostNoApplyIdentityV1, JournalRuntimeExecutionError, JournalRuntimeExecutionStoreV1,
    ProtectedExecutionAdmissionStateV1, ProtectedHostOutputReadbackV1,
    ProtectedHostOutputReservationV1,
};

#[cfg(all(test, target_os = "linux"))]
mod bootstrap_closed_tests;
pub mod bootstrap_proof;
pub(crate) mod host_currentness_fence;
mod settlement_admission;
#[cfg(all(
    target_os = "linux",
    any(test, all(feature = "test-fixtures", debug_assertions))
))]
mod test_fixture;

pub use host_currentness_fence::HostEffectFenceRecoveryClaimV1;
use host_currentness_fence::{load_host_currentness_fence_v1, validate_host_currentness_pair_v1};

const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const BOOTSTRAP_MANIFEST_MAGIC: &[u8; 8] = b"AOSRBM01";
const PEER_JOURNAL_NAME: &str = "runtime-agent-peer.journal";
const EXECUTION_JOURNAL_NAME: &str = "runtime-execution.journal";
const AGENT_JOURNAL_NAME: &str = "runtime-agent-state.journal";
const LIFECYCLE_JOURNAL_NAME: &str = "runtime-lifecycle.journal";
const PEER_CURRENT_KEY: &[u8] = crate::journal::host_currentness_fence::PEER_CURRENT_KEY;
const CURRENTNESS_KEY: &[u8] = crate::journal::host_currentness_fence::CURRENTNESS_KEY;
const CAPABILITIES_KEY: &[u8] = crate::journal::host_currentness_fence::CAPABILITIES_KEY;
const HOST_EVIDENCE_KEY: &[u8] = crate::journal::host_currentness_fence::HOST_EVIDENCE_KEY;
const PLAN_CATALOG_KEY: &[u8] = crate::journal::host_currentness_fence::PLAN_CATALOG_KEY;
const HOST_CURRENTNESS_FENCE_KEY: &[u8] = crate::journal::host_currentness_fence::KEY;
const PEER_MAGIC: &[u8; 8] = b"AOSHPE01";
const CURRENTNESS_MAGIC: &[u8; 8] = b"AOSREC01";
const PEER_BYTES: usize = 296;
const CURRENTNESS_BYTES: usize = 176;
const CAPABILITIES_MAGIC: &[u8; 8] = b"AOSRPC01";
const CAPABILITIES_BYTES: usize = 52;
const HOST_EVIDENCE_MAGIC: &[u8; 8] = b"AOSRHE01";
const HOST_EVIDENCE_BYTES: usize = 152;
const PLAN_CATALOG_MAGIC: &[u8; 8] = b"AOSRPL01";
const PLAN_CATALOG_BYTES: usize = 216;
const BOOTSTRAP_RECORD_BYTES: usize =
    PEER_BYTES + CURRENTNESS_BYTES + CAPABILITIES_BYTES + HOST_EVIDENCE_BYTES + PLAN_CATALOG_BYTES;
const BOOTSTRAP_MANIFEST_BYTES: usize = 8 + BOOTSTRAP_RECORD_BYTES + 32;
// Begin, five records, and Commit advance the protected snapshot by seven.
const PEER_PROVISION_TRANSACTION_FRAME_COUNT: u64 = 7;
const LIFECYCLE_HEAD_KEY: &[u8] = b"runtime-lifecycle-head-v1";
const LIFECYCLE_ISSUE_KEY: &[u8] = b"runtime-lifecycle-issued-v1";
const LIFECYCLE_HEAD_MAGIC: &[u8; 8] = b"AOSRLH01";
const LIFECYCLE_ISSUE_MAGIC: &[u8; 8] = b"AOSRLI01";
const LIFECYCLE_HEAD_BYTES: usize = 96;
const LIFECYCLE_ISSUE_BYTES: usize = 200;
const LIFECYCLE_TERMINAL_PREFIX: &[u8] = b"runtime-lifecycle-terminal-v1/";
const LIFECYCLE_TERMINAL_MAGIC: &[u8; 8] = b"AOSRLT01";
const LIFECYCLE_TERMINAL_BYTES: usize = 272;

/// Supplies the complete typed input for the fixed runtime-owner record set.
///
/// This value is nonauthorizing configuration. [`DormantRuntimeExecutionProvisionerV1`]
/// must atomically commit and cold-recover it before [`DormantRuntimeExecutionOwnerV1`]
/// can mint a live claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DormantRuntimeExecutionProvisioningV1 {
    agent_public_key: [u8; 32],
    agent_channel_binding: ObjectDigest,
    next_observation_sequence: ObservationSequence,
    runtime: RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
    backend_probe: BackendProbeCurrentnessV1,
    backend_capabilities: BackendCapabilitiesV1,
    resource_ledger: ObjectDigest,
    output_reservation: ObjectDigest,
    host_public_key: [u8; 32],
    host_trust_context: ObjectDigest,
    host_channel_binding: ObjectDigest,
    host_boot_id: [u8; 16],
    protected_plan: ResolvedRuntimePlanV1,
}

impl DormantRuntimeExecutionProvisioningV1 {
    /// Validates one complete fixed-root runtime-owner record set.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness`]
    /// for an invalid verification key, sentinel or colliding authority input,
    /// mismatched runtime/probe/plan currentness, or unsatisfied plan feature.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        agent_public_key: [u8; 32],
        agent_channel_binding: ObjectDigest,
        next_observation_sequence: ObservationSequence,
        runtime: RuntimeHandleCommitmentV1,
        payload_boot_id: PayloadBootId,
        backend_probe: BackendProbeCurrentnessV1,
        backend_capabilities: BackendCapabilitiesV1,
        resource_ledger: ObjectDigest,
        output_reservation: ObjectDigest,
        host_public_key: [u8; 32],
        host_trust_context: ObjectDigest,
        host_channel_binding: ObjectDigest,
        host_boot_id: [u8; 16],
        protected_plan: ResolvedRuntimePlanV1,
    ) -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        VerifyingKey::from_bytes(&agent_public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        VerifyingKey::from_bytes(&host_public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if agent_public_key == [0; 32]
            || host_public_key == [0; 32]
            || agent_public_key == host_public_key
            || agent_channel_binding.as_bytes() == &[0; 32]
            || host_trust_context.as_bytes() == &[0; 32]
            || host_channel_binding.as_bytes() == &[0; 32]
            || agent_channel_binding == host_channel_binding
            || host_boot_id == [0; 16]
            || next_observation_sequence.get() == 0
            || next_observation_sequence.get() == u64::MAX
            || resource_ledger.as_bytes() == &[0; 32]
            || output_reservation.as_bytes() == &[0; 32]
            || runtime.currentness().node() != backend_probe.node()
            || protected_plan.currentness() != runtime.currentness()
            || protected_plan.plan_commitment() != runtime.plan_commitment()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        backend_capabilities
            .satisfies(protected_plan.required_capabilities())
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;

        Ok(Self {
            agent_public_key,
            agent_channel_binding,
            next_observation_sequence,
            runtime,
            payload_boot_id,
            backend_probe,
            backend_capabilities,
            resource_ledger,
            output_reservation,
            host_public_key,
            host_trust_context,
            host_channel_binding,
            host_boot_id,
            protected_plan,
        })
    }
}

/// Owns the fixed peer journal while atomically provisioning all five records.
pub(crate) struct DormantRuntimeExecutionProvisionerV1 {
    journal: Journal,
}

/// Reports an exact provision write or commit ambiguity requiring cold reopen.
#[must_use = "ambiguous runtime-owner provisioning must be cold-recovered"]
pub(crate) enum DormantRuntimeExecutionProvisioningTransitionV1 {
    /// The complete record set is durably present.
    Committed(DormantRuntimeExecutionProvisioningReceiptV1),
    /// The atomic append may have committed and must be resolved by reopening.
    RecoveryRequired(DormantRuntimeExecutionProvisioningRecoveryV1),
}

/// Authenticates the complete fixed-root provisioning record set after replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DormantRuntimeExecutionProvisioningReceiptV1 {
    journal_sequence: u64,
    record_set_commitment: ObjectDigest,
}

impl DormantRuntimeExecutionProvisioningReceiptV1 {
    /// Returns the protected journal sequence that authenticated the records.
    #[must_use]
    pub(crate) const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }

    /// Returns the commitment to the ordered five-record set.
    #[must_use]
    pub(crate) const fn record_set_commitment(self) -> ObjectDigest {
        self.record_set_commitment
    }
}

/// Retains the exact expected record set across an ambiguous provision append.
#[must_use = "provisioning ambiguity must be resolved before runtime claim"]
pub(crate) struct DormantRuntimeExecutionProvisioningRecoveryV1 {
    records: RuntimeOwnerPeerRecordsV1,
}

/// Reports the result of cold-reopening an ambiguous atomic provision append.
#[must_use]
pub(crate) enum DormantRuntimeExecutionProvisioningRecoveryOutcomeV1 {
    /// Replay found the exact complete committed record set.
    Committed(DormantRuntimeExecutionProvisioningReceiptV1),
    /// Replay found no record from the transaction, so the intact write may retry.
    Absent(DormantRuntimeExecutionProvisioningRetryV1),
}

/// Proves cold recovery found no part of the atomic provision transaction.
#[must_use = "an absent provision write may be retried or explicitly abandoned"]
pub(crate) struct DormantRuntimeExecutionProvisioningRetryV1 {
    records: RuntimeOwnerPeerRecordsV1,
}

#[derive(Clone)]
struct RuntimeOwnerPeerRecordsV1 {
    peer: Vec<u8>,
    currentness: Vec<u8>,
    capabilities: Vec<u8>,
    host_evidence: Vec<u8>,
    plan_catalog: Vec<u8>,
}

#[derive(Clone, Copy)]
struct LifecycleHeadV1 {
    next_lifecycle_sequence: u64,
    next_observation_sequence: u64,
    initial_observation_sequence: u64,
    store_binding: ObjectDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleTerminalV1 {
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    action: BackendLifecycleOperationV1,
    result_phase: u8,
    plan: ObjectDigest,
    handle: ObjectDigest,
    request: ObjectDigest,
    observation_sequence: u64,
    observation_commitment: ObjectDigest,
    currentness: ObjectDigest,
    authority: ObjectDigest,
}

impl DormantRuntimeExecutionProvisionerV1 {
    /// Opens the fixed root-owned runtime peer journal for provisioning only.
    ///
    /// This dormant entry point accepts no caller-selected path and does not
    /// construct a backend, listener, or readiness advertisement.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when fixed-root
    /// protected resolution, exclusive ownership, or journal replay fails.
    pub(crate) fn open() -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        let (journal, _) = Journal::open_protected_at(
            HOST_STATE_ROOT,
            PEER_JOURNAL_NAME,
            JournalLimits::default(),
        )?;
        Ok(Self { journal })
    }

    /// Atomically writes or exactly replays all five runtime-owner peer records.
    ///
    /// A journal append failure is never classified as absence. The returned
    /// recovery token owns the exact expected bytes and can only be resolved by
    /// a cold fixed-root reopen.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for conflicting or
    /// malformed existing state, preflight failure, or invalid configuration.
    pub(crate) fn provision(
        self,
        provisioning: DormantRuntimeExecutionProvisioningV1,
    ) -> Result<DormantRuntimeExecutionProvisioningTransitionV1, DormantRuntimeExecutionOwnerErrorV1>
    {
        let records = encode_runtime_owner_peer_records(&provisioning)?;
        self.provision_records(records, true)
    }
}

impl DormantRuntimeExecutionProvisioningRecoveryV1 {
    /// Cold-reopens the fixed journal and resolves the atomic provision append.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when replay is
    /// unavailable or finds a partial, substituted, or foreign record set.
    pub(crate) fn recover(
        self,
    ) -> Result<
        DormantRuntimeExecutionProvisioningRecoveryOutcomeV1,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        let (mut journal, _) = Journal::open_protected_at(
            HOST_STATE_ROOT,
            PEER_JOURNAL_NAME,
            JournalLimits::default(),
        )?;
        let authority = journal.claim_protected_authority(RecordNamespace::HostExecution)?;
        if authority.is_materialized_empty()? {
            return Ok(
                DormantRuntimeExecutionProvisioningRecoveryOutcomeV1::Absent(
                    DormantRuntimeExecutionProvisioningRetryV1 {
                        records: self.records,
                    },
                ),
            );
        }

        authenticate_runtime_owner_peer_records(&authority, &self.records)
            .map(DormantRuntimeExecutionProvisioningRecoveryOutcomeV1::Committed)
    }
}

impl DormantRuntimeExecutionProvisioningRetryV1 {
    /// Retries a provision append after cold recovery proved exact absence.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for fixed-root reopen,
    /// preflight, conflict, or malformed retained-record failure.
    pub(crate) fn retry(
        self,
    ) -> Result<DormantRuntimeExecutionProvisioningTransitionV1, DormantRuntimeExecutionOwnerErrorV1>
    {
        let provisioner = DormantRuntimeExecutionProvisionerV1::open()?;
        provisioner.provision_records(self.records, true)
    }
}

impl DormantRuntimeExecutionProvisionerV1 {
    fn provision_records(
        mut self,
        records: RuntimeOwnerPeerRecordsV1,
        allow_exact_existing: bool,
    ) -> Result<DormantRuntimeExecutionProvisioningTransitionV1, DormantRuntimeExecutionOwnerErrorV1>
    {
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        if !authority.is_materialized_empty()? {
            if !allow_exact_existing {
                return Err(DormantRuntimeExecutionOwnerErrorV1::BootstrapAlreadyConsumed);
            }
            let receipt = authenticate_runtime_owner_peer_records(&authority, &records)?;
            return Ok(DormantRuntimeExecutionProvisioningTransitionV1::Committed(
                receipt,
            ));
        }

        let transaction = runtime_owner_peer_transaction(&records)?;
        let protected_sequence = authority
            .snapshot()?
            .sequence()
            .checked_add(PEER_PROVISION_TRANSACTION_FRAME_COUNT)
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        resolve_currentness(
            protected_sequence,
            &records.peer,
            &records.currentness,
            &records.capabilities,
            &records.host_evidence,
            &records.plan_catalog,
        )?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        match authority.commit(&transaction) {
            Ok(_) => Ok(DormantRuntimeExecutionProvisioningTransitionV1::Committed(
                provisioning_receipt(authority.snapshot()?.sequence(), &records),
            )),
            Err(_) => Ok(
                DormantRuntimeExecutionProvisioningTransitionV1::RecoveryRequired(
                    DormantRuntimeExecutionProvisioningRecoveryV1 { records },
                ),
            ),
        }
    }
}

/// Owns the fixed protected Host, execution, and agent journals.
pub struct DormantRuntimeExecutionOwnerV1 {
    peer_journal: Journal,
    execution_journal: Journal,
    agent_journal: Journal,
    lifecycle_journal: Journal,
}

impl DormantRuntimeExecutionOwnerV1 {
    /// Rejects legacy fixed bootstrap until independent currentness is available.
    ///
    /// The old manifest-sidecar path could not authenticate a Controller cut or
    /// an externally monotonic deployment floor. The signed proof codec is
    /// dormant; no production caller may write initial peer records from it
    /// until a protected Controller currentness owner and journal replay join
    /// are implemented.
    ///
    /// # Errors
    ///
    /// Always returns
    /// [`DormantRuntimeExecutionOwnerErrorV1::BootstrapProofRequired`].
    #[cfg(target_os = "linux")]
    pub fn bootstrap_fixed() -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        Err(DormantRuntimeExecutionOwnerErrorV1::BootstrapProofRequired)
    }

    /// Opens the fixed root-owned journals without activating runtime dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when a protected path,
    /// exclusive lock, journal replay, or fixed-root invariant fails.
    pub fn open() -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        let limits = JournalLimits::default();
        let (peer_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, PEER_JOURNAL_NAME, limits)?;
        let (execution_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, EXECUTION_JOURNAL_NAME, limits)?;
        let (agent_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, AGENT_JOURNAL_NAME, limits)?;
        let (lifecycle_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, LIFECYCLE_JOURNAL_NAME, limits)?;

        Ok(Self {
            peer_journal,
            execution_journal,
            agent_journal,
            lifecycle_journal,
        })
    }

    /// Opens all four protected owner journals in a private test directory.
    ///
    /// This opener retains final-directory, file-owner, and journal replay
    /// checks, but omits production root-ancestry validation. It is unavailable
    /// in production builds and never provisions authority or creates a claim.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe directory or journal, a held lock, or corrupt replay.
    #[cfg(all(
        target_os = "linux",
        any(test, all(feature = "test-fixtures", debug_assertions))
    ))]
    #[doc(hidden)]
    pub fn open_protected_at_uid_for_test(
        directory: &Path,
        expected_uid: u32,
    ) -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        let limits = JournalLimits::default();
        let (peer_journal, _) =
            Journal::open_protected_at_uid(directory, PEER_JOURNAL_NAME, limits, expected_uid)?;
        let (execution_journal, _) = Journal::open_protected_at_uid(
            directory,
            EXECUTION_JOURNAL_NAME,
            limits,
            expected_uid,
        )?;
        let (agent_journal, _) =
            Journal::open_protected_at_uid(directory, AGENT_JOURNAL_NAME, limits, expected_uid)?;
        let (lifecycle_journal, _) = Journal::open_protected_at_uid(
            directory,
            LIFECYCLE_JOURNAL_NAME,
            limits,
            expected_uid,
        )?;

        Ok(Self {
            peer_journal,
            execution_journal,
            agent_journal,
            lifecycle_journal,
        })
    }

    /// Claims current runtime execution authority from protected Host state.
    ///
    /// The returned claim keeps the exact peer/currentness journal borrowed,
    /// so those records cannot be superseded through another owner while an
    /// admission, recovery, completion, or agent CAS operation is in flight.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when current protected
    /// records are absent, malformed, inconsistent, stale, or when either
    /// dedicated durable store cannot be initialized or reopened exactly.
    pub fn claim(
        &mut self,
    ) -> Result<DormantRuntimeExecutionClaimV1<'_>, DormantRuntimeExecutionOwnerErrorV1> {
        let Self {
            peer_journal,
            execution_journal,
            agent_journal,
            lifecycle_journal,
        } = self;
        let peer_authority =
            peer_journal.claim_protected_authority(RecordNamespace::HostExecution)?;
        let protected_sequence = peer_authority.snapshot()?.sequence();
        let peer_fence = load_host_currentness_fence_v1(&peer_authority, protected_sequence)?;
        let peer_record = peer_authority
            .get(PEER_CURRENT_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();
        let currentness_record = peer_authority
            .get(CURRENTNESS_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();
        let capability_record = peer_authority
            .get(CAPABILITIES_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();
        let host_evidence_record = peer_authority
            .get(HOST_EVIDENCE_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();
        let plan_record = peer_authority
            .get(PLAN_CATALOG_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();
        if peer_authority.records()?.any(|(key, _)| {
            key != PEER_CURRENT_KEY
                && key != CURRENTNESS_KEY
                && key != CAPABILITIES_KEY
                && key != HOST_EVIDENCE_KEY
                && key != PLAN_CATALOG_KEY
                && key != HOST_CURRENTNESS_FENCE_KEY
        }) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }

        let resolved = resolve_currentness(
            peer_fence.map_or(protected_sequence, |fence| fence.pre_hold_epoch),
            peer_record.as_slice(),
            currentness_record.as_slice(),
            capability_record.as_slice(),
            host_evidence_record.as_slice(),
            plan_record.as_slice(),
        )?;
        if peer_fence.is_some_and(|fence| fence.store_binding != resolved.execution_store_binding) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let admission_state = ProtectedExecutionAdmissionStateV1::new(&resolved.currentness);
        let execution = open_execution_store(
            execution_journal,
            resolved.execution_store_binding,
            admission_state,
            ProtectedAgentRoutePeerV1::new(
                resolved.agent_peer.public_key,
                resolved.agent_peer.channel_binding,
                resolved.agent_peer.authority_binding,
            )?,
            peer_fence.is_some(),
        )?;
        validate_host_currentness_pair_v1(
            peer_fence,
            execution.load_host_execution_fence_v1()?,
            resolved.execution_store_binding,
        )?;
        let agent = open_agent_store(
            agent_journal,
            resolved.agent_store_binding,
            resolved.recovery_authority_binding,
            resolved.agent_peer.public_key,
            resolved.agent_peer.channel_binding,
        )?;
        let (lifecycle_authority, lifecycle_head, lifecycle_issue, lifecycle_terminals) =
            open_lifecycle_store(
                lifecycle_journal,
                resolved.lifecycle_store_binding,
                resolved.agent_peer.next_observation_sequence,
                resolved.host_verifier.authority_binding,
                *resolved.currentness.runtime(),
            )?;

        Ok(DormantRuntimeExecutionClaimV1 {
            peer_authority,
            protected_sequence,
            peer_fence,
            execution_store_binding: resolved.execution_store_binding,
            peer_record,
            currentness_record,
            capability_record,
            host_evidence_record,
            plan_record,
            currentness: resolved.currentness,
            protected_plan: resolved.protected_plan,
            backend_capabilities: resolved.backend_capabilities,
            agent_peer: resolved.agent_peer,
            host_verifier: resolved.host_verifier,
            execution,
            agent,
            lifecycle_authority,
            lifecycle_head,
            lifecycle_issue,
            lifecycle_terminals,
        })
    }
}

/// Retains exact protected Host currentness across dormant durable operations.
pub struct DormantRuntimeExecutionClaimV1<'owner> {
    peer_authority: ProtectedJournalAuthority<'owner>,
    protected_sequence: u64,
    peer_fence: Option<HostCurrentnessFenceV1>,
    execution_store_binding: ObjectDigest,
    peer_record: Vec<u8>,
    currentness_record: Vec<u8>,
    capability_record: Vec<u8>,
    host_evidence_record: Vec<u8>,
    plan_record: Vec<u8>,
    currentness: AdmissionCurrentnessV1,
    protected_plan: ResolvedRuntimePlanV1,
    backend_capabilities: BackendCapabilitiesV1,
    agent_peer: ProtectedRuntimeAgentPeerV1,
    host_verifier: ProtectedRuntimeHostVerifierV1,
    execution: JournalRuntimeExecutionStoreV1<'owner>,
    agent: DormantJournalAgentStoreV1<'owner>,
    lifecycle_authority: ProtectedJournalAuthority<'owner>,
    lifecycle_head: LifecycleHeadV1,
    lifecycle_issue: Option<Vec<u8>>,
    lifecycle_terminals: BTreeMap<[u8; 16], Vec<u8>>,
}

/// Retains a protected historical Host settlement readback without a live lease.
///
/// The marker and ordered stage bytes were joined under one protected Host
/// claim. They can support a signed read-only query, but do not attest that a
/// Controller floor or CAS is current and do not permit another Host effect.
pub struct ProtectedHostNoApplySettlementHistoryV1 {
    marker: HostExecutionNoApplyRecordV1,
    stages: [Option<[u8; HOST_SETTLEMENT_RECORD_BYTES]>; 3],
}

/// Names one digest-bearing protected Host cut while the writer claim is held.
///
/// The sequence and digest are replay coordinates, not a transferable lease.
/// A caller must retain and revalidate the Host owner claim at the effect
/// boundary, and a second owner must compare the signed exact coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHostSettlementCutV1 {
    epoch: u64,
    digest: ObjectDigest,
}

/// Retains an exact preliminary Host record prepared under a held protected cut.
///
/// The H/T fields are Controller assertions. This value is not an append token,
/// a transferable lease, or evidence that the Controller archive is current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedHostSettlementPreliminaryV1 {
    canonical_record: [u8; HOST_SETTLEMENT_RECORD_BYTES],
    cut: ProtectedHostSettlementCutV1,
}

impl PreparedHostSettlementPreliminaryV1 {
    /// Returns the canonical, uncommitted AOSCHL01 preliminary record.
    #[must_use]
    pub const fn canonical_record(&self) -> &[u8; HOST_SETTLEMENT_RECORD_BYTES] {
        &self.canonical_record
    }

    /// Returns the exact protected cut used to prepare the record.
    #[must_use]
    pub const fn cut(&self) -> ProtectedHostSettlementCutV1 {
        self.cut
    }
}

impl ProtectedHostSettlementCutV1 {
    /// Returns the protected journal sequence at which the cut was measured.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the domain-separated digest of the exact protected Effect replay.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

impl ProtectedHostNoApplySettlementHistoryV1 {
    /// Returns the exact protected method-39 no-Apply marker.
    #[must_use]
    pub const fn marker(&self) -> HostExecutionNoApplyRecordV1 {
        self.marker
    }

    /// Borrows the canonical bytes of a retained Host settlement stage, if any.
    #[must_use]
    pub fn stage_bytes(&self, phase: HostNoApplySettlementPhaseV2) -> Option<&[u8]> {
        let index = match phase {
            HostNoApplySettlementPhaseV2::Preliminary => 0,
            HostNoApplySettlementPhaseV2::FloorSealed => 1,
            HostNoApplySettlementPhaseV2::AckRetained => 2,
        };
        self.stages[index].as_ref().map(|bytes| bytes.as_slice())
    }
}

/// Holds a v2-only output claim read back under the protected execution owner.
///
/// The private constructor requires both exact accepted-Create/parent replay
/// and a matching v2 record in the execution journal. This is budget custody,
/// not physical capture backing or permission to dispatch a Host effect.
pub struct ProtectedAcceptedExecutionOutputV2 {
    reservation: DurableExecutionOutputReservationV1,
    currentness: AdmissionCurrentnessV1,
}

impl ProtectedAcceptedExecutionOutputV2 {
    /// Borrows the accepted-Create-derived budget claim.
    #[must_use]
    pub const fn reservation(&self) -> &DurableExecutionOutputReservationV1 {
        &self.reservation
    }

    /// Borrows the per-execution protected admission currentness.
    #[must_use]
    pub const fn currentness(&self) -> &AdmissionCurrentnessV1 {
        &self.currentness
    }

    /// Returns the accepted and durably bound stdout capture ceiling.
    #[must_use]
    pub const fn maximum_stdout_bytes(&self) -> u64 {
        self.reservation.maximum_stdout_bytes()
    }

    /// Returns the accepted and durably bound stderr capture ceiling.
    #[must_use]
    pub const fn maximum_stderr_bytes(&self) -> u64 {
        self.reservation.maximum_stderr_bytes()
    }
}

/// Holds a protected pre-issued one-shot Guest measurement challenge.
///
/// The Host may send its canonical request on the retained signed agent
/// session, but this value is not a verified measurement or exec authority.
pub struct ProtectedRuntimeArgumentChallengeV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    request: GuestRuntimeArgumentObserveRequestV1,
    handshake: AgentHandshakeRequestV1,
    response: AgentHandshakeResponseV1,
    completed: bool,
}

/// Holds a previously issued challenge without granting a live send session.
///
/// Only a packet already signed on the original session can complete this
/// value. A new Host session must not transmit its retained request.
pub struct RecoveredRuntimeArgumentChallengeV1 {
    record: ArgumentObservationRecordV1,
}

impl RecoveredRuntimeArgumentChallengeV1 {
    /// Borrows the original protected request for exact Host-journal lookup.
    #[must_use]
    pub const fn request(&self) -> &GuestRuntimeArgumentObserveRequestV1 {
        &self.record.request
    }

    /// Reports whether the original challenge already consumed a packet.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.record.signed_packet_digest.is_some()
    }
}

impl ProtectedRuntimeArgumentChallengeV1 {
    /// Borrows the exact canonical request committed before Host send.
    #[must_use]
    pub const fn request(&self) -> &GuestRuntimeArgumentObserveRequestV1 {
        &self.request
    }

    /// Borrows the signed session request bound to the protected challenge.
    #[must_use]
    pub const fn handshake(&self) -> &AgentHandshakeRequestV1 {
        &self.handshake
    }

    /// Borrows the signed session response bound to the protected challenge.
    #[must_use]
    pub const fn response(&self) -> &AgentHandshakeResponseV1 {
        &self.response
    }

    /// Reports an exact same-session challenge already consumed by one packet.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.completed
    }
}

/// Holds one independently verified and durably consumed Guest measurement.
///
/// Only the protected runtime owner can construct this proof after checking
/// the fixed agent key, exact live session, assignment, profile, and signed
/// packet against its pre-issued one-shot challenge.
pub struct AuthenticatedRuntimeArgumentReadbackV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    evidence: ExecutionRuntimeArgumentLimitV1,
    request_digest: ObjectDigest,
    packet_digest: ObjectDigest,
    custody_digest: ObjectDigest,
}

impl AuthenticatedRuntimeArgumentReadbackV1 {
    /// Borrows the measured, target-bound argument limit.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionRuntimeArgumentLimitV1 {
        &self.evidence
    }

    /// Returns the exact execution whose pre-issued challenge was consumed.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the accepted Create operation bound to the challenge.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the commitment to the canonical Guest request.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the commitment to the exact signed Guest packet.
    #[must_use]
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the completed protected challenge-record commitment.
    #[must_use]
    pub const fn custody_digest(&self) -> ObjectDigest {
        self.custody_digest
    }
}

/// Proves an execution dispatch is paired with an authenticated AOSAGE session request.
struct ProtectedAgentRouteReservationV1 {
    effect_request: ObjectDigest,
    agent_request: ObjectDigest,
    route_binding: ObjectDigest,
}

/// Retains an exact historical Host-to-agent request for recovery inspection.
///
/// This value grants no fresh dispatch. A caller must obtain a new protected
/// session and resolve the original guest outcome before changing execution
/// state; replaying these bytes is not an authorized new effect.
pub struct RecoveredHostAgentRouteV1 {
    request: AgentOperationRequestV1,
    effect_request: ObjectDigest,
    route_binding: ObjectDigest,
}

/// Owns one guest outcome verified against a cold-recovered Host route.
pub struct AuthenticatedRecoveredHostAgentOutcomeV1 {
    request: AgentOperationRequestV1,
    outcome: AgentExecutionOutcomeV1,
    signature: [u8; 64],
    effect_request: ObjectDigest,
}

/// Owns a Host-committed guest outcome and its original observation identity.
pub struct CommittedHostAgentOutcomeV1 {
    authenticated: AuthenticatedRecoveredHostAgentOutcomeV1,
    observation_sequence: ObservationSequence,
    observation_commitment: ObjectDigest,
}

impl CommittedHostAgentOutcomeV1 {
    /// Borrows the signature-verified guest outcome and original request.
    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedRecoveredHostAgentOutcomeV1 {
        &self.authenticated
    }

    /// Returns the sole Host observation sequence assigned to this packet.
    #[must_use]
    pub const fn observation_sequence(&self) -> ObservationSequence {
        self.observation_sequence
    }

    /// Returns the verified Host observation commitment assigned before crash.
    #[must_use]
    pub const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }
}

impl AuthenticatedRecoveredHostAgentOutcomeV1 {
    /// Borrows the original protected Host-to-agent request.
    #[must_use]
    pub const fn request(&self) -> &AgentOperationRequestV1 {
        &self.request
    }

    /// Borrows the authenticated terminal guest outcome.
    #[must_use]
    pub const fn outcome(&self) -> &AgentExecutionOutcomeV1 {
        &self.outcome
    }

    /// Returns the checked detached signature for Host observation custody.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns the original durable effect-request commitment.
    #[must_use]
    pub const fn effect_request(&self) -> ObjectDigest {
        self.effect_request
    }
}

impl RecoveredHostAgentRouteV1 {
    /// Borrows the exact original agent request for outcome verification.
    #[must_use]
    pub const fn request(&self) -> &AgentOperationRequestV1 {
        &self.request
    }

    /// Returns the original durable effect-request commitment.
    #[must_use]
    pub const fn effect_request(&self) -> ObjectDigest {
        self.effect_request
    }

    /// Returns the protected co-owned route binding.
    #[must_use]
    pub const fn route_binding(&self) -> ObjectDigest {
        self.route_binding
    }
}

/// Describes one protected lifecycle issue recovered under the fixed owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedLifecycleIssueV1 {
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    action: BackendLifecycleOperationV1,
    crossed: bool,
    plan: ObjectDigest,
    handle: Option<ObjectDigest>,
    request: ObjectDigest,
}

impl ProtectedLifecycleIssueV1 {
    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the durable operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> BackendOperationSequenceV1 {
        self.sequence
    }

    /// Returns the exact lifecycle action.
    #[must_use]
    pub const fn action(&self) -> BackendLifecycleOperationV1 {
        self.action
    }

    /// Reports whether the protected effect boundary may already have crossed.
    #[must_use]
    pub const fn crossed(&self) -> bool {
        self.crossed
    }

    /// Returns the immutable runtime-plan commitment.
    #[must_use]
    pub const fn plan(&self) -> ObjectDigest {
        self.plan
    }

    /// Returns the targeted runtime handle, absent only for Prepare.
    #[must_use]
    pub const fn handle(&self) -> Option<ObjectDigest> {
        self.handle
    }

    /// Returns the exact lifecycle request commitment.
    #[must_use]
    pub const fn request(&self) -> ObjectDigest {
        self.request
    }
}

impl DormantRuntimeExecutionClaimV1<'_> {
    pub(super) fn commit_agent_handshake_checkpoint(
        &mut self,
        request: &AgentHandshakeRequestV1,
        response: &AgentHandshakeResponseV1,
        candidate: &AgentCheckpointCandidateV1,
    ) -> Result<AuthenticatedJournalAgentCheckpointV1, AgentCheckpointError> {
        self.validate_current()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        self.agent
            .commit_handshake_checkpoint(request, response, candidate)
    }

    pub(super) fn authenticate_guest_provisioning(
        &self,
        provisioning: &super::AgentProvisioningV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let currentness = self.currentness.runtime().currentness();
        let expected_runtime = AgentRuntimeBindingV1::new(
            currentness.sandbox(),
            currentness.incarnation(),
            currentness.assignment_epoch(),
            currentness.assignment_digest(),
            currentness.desired_generation(),
            currentness.namespace_generation(),
            *self.currentness.payload_boot_id().as_bytes(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if provisioning.runtime() != &expected_runtime
            || provisioning.host_channel_binding() != self.agent_peer.channel_binding
            || provisioning.recovery_authority_binding() != self.agent_peer.authority_binding
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        Ok(())
    }

    /// Revalidates one reducer reservation against the dedicated agent store.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when fixed currentness
    /// changed or the reservation is absent, terminal, substituted, or corrupt.
    pub(super) fn authenticate_guest_reservation(
        &mut self,
        prepared: &PreparedAgentOperationV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        match self
            .agent
            .recover_operation(prepared.reservation(), prepared.request())
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?
        {
            AgentRecoveredOperationV1::Reserved => Ok(()),
            AgentRecoveredOperationV1::Completed(_) | AgentRecoveredOperationV1::Absent => {
                Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)
            }
        }
    }

    pub(super) fn recover_guest_outcome_commit(
        &mut self,
        token: &AgentOutcomeRecoveryTokenV1,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentRecoveredOutcomeCommitV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.agent
            .recover_outcome_commit(token, reservation, outcome)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)
    }

    pub(super) fn load_uncheckpointed_guest_reservation(
        &mut self,
    ) -> Result<
        Option<(AgentOperationRequestV1, AgentOperationReservationV1)>,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        self.validate_current()?;
        self.agent
            .load_uncheckpointed_reservation()
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)
    }

    pub(super) fn commit_signed_guest_outcome_packet(
        &mut self,
        packet: &aos_sandbox_agent::SignedAgentOutcomePacketV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.agent.commit_signed_outcome_packet(packet)?;
        Ok(())
    }

    pub(super) fn load_signed_guest_outcome_packet(
        &mut self,
        session: aos_sandbox_agent::AgentSessionBindingV1,
        sequence: aos_sandbox_agent::AgentOperationSequenceV1,
    ) -> Result<
        Option<aos_sandbox_agent::SignedAgentOutcomePacketV1>,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        self.validate_current()?;
        self.agent
            .load_signed_outcome_packet(session, sequence)
            .map_err(Into::into)
    }

    /// Borrows fixed bootstrap currentness, not a v2 execution reservation.
    ///
    /// New admissions must use [`Self::admission_currentness_for_accepted_output_v2`]
    /// to bind the exact accepted Create and current durable ledger head.
    #[must_use]
    pub const fn currentness(&self) -> &AdmissionCurrentnessV1 {
        &self.currentness
    }

    /// Derives admission currentness from one protected accepted-Create claim.
    ///
    /// The fixed bootstrap output digest is not a per-execution reservation.
    /// This readback uses the v2 claim's complete record digest and the latest
    /// protected resource-ledger head, without accepting either from a caller.
    /// It does not establish physical output storage or Host effect authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner changed, the exact claim is absent or
    /// belongs to another assignment/Create operation, or either protected
    /// journal cannot be read consistently.
    pub fn admission_currentness_for_accepted_output_v2(
        &self,
        execution: ExecutionId,
        create_operation: OperationId,
    ) -> Result<AdmissionCurrentnessV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let claim = self
            .execution
            .load_accepted_output_v2(execution)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingAcceptedOutputClaim)?;
        let state = self.execution.load_admission_state()?;

        derive_accepted_output_currentness_v2(
            &self.currentness,
            &state,
            &claim,
            execution,
            create_operation,
        )
    }

    /// Replays the accepted Create and parent source against one durable v2 claim.
    ///
    /// The result cannot be synthesized from a legacy reservation or a caller
    /// supplied digest. The controller and execution journals must remain under
    /// their protected exclusive owners through the subsequent admission join.
    ///
    /// # Errors
    ///
    /// Returns an error if the accepted request, parent profile, assignment,
    /// or retained v2 claim changed or cannot be authenticated.
    pub fn read_protected_accepted_output_v2(
        &self,
        controller: &mut Journal,
        create_operation: OperationId,
        execution: ExecutionId,
        parent: &ExecutionParentResourceSourceV1,
    ) -> Result<ProtectedAcceptedExecutionOutputV2, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let accepted = accepted_claim(controller, create_operation, execution, parent)
            .map_err(JournalRuntimeExecutionError::from)?;
        let retained = self
            .execution
            .load_accepted_output_v2(execution)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingAcceptedOutputClaim)?;
        if retained.record_digest != accepted.record.record_digest()
            || retained.assignment != accepted.assignment
            || retained.requested_bytes != accepted.requested_bytes
            || retained.parent_bytes != accepted.parent_bytes
            || retained.stream_limits
                != Some((
                    accepted.record.maximum_stdout_bytes(),
                    accepted.record.maximum_stderr_bytes(),
                ))
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::AcceptedOutputClaimMismatch);
        }
        let currentness =
            self.admission_currentness_for_accepted_output_v2(execution, create_operation)?;
        Ok(ProtectedAcceptedExecutionOutputV2 {
            reservation: accepted.record,
            currentness,
        })
    }

    /// Commits one owner-minted Guest argument-limit challenge before Host send.
    ///
    /// The accepted Create/output claim, exact v2 sandbox specification,
    /// protected current session, channel, runtime, and plan profile are
    /// checked under their owners. An old session cannot inherit a retained
    /// challenge; use [`Self::recover_runtime_argument_observation_v1`] to
    /// finish it only from an already signed packet.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or stale source evidence, an unsupported
    /// signed session, entropy failure, or ambiguous protected durability.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_runtime_argument_observation_v1(
        &mut self,
        controller: &mut Journal,
        execution: ExecutionId,
        create_operation: OperationId,
        parent: &ExecutionParentResourceSourceV1,
        handshake: &AgentHandshakeRequestV1,
        response: &AgentHandshakeResponseV1,
    ) -> Result<ProtectedRuntimeArgumentChallengeV1, DormantRuntimeExecutionOwnerErrorV1> {
        let output = self.read_protected_accepted_output_v2(
            controller,
            create_operation,
            execution,
            parent,
        )?;
        if output.reservation().output().assignment_digest()
            != self.currentness.runtime().currentness().assignment_digest()
            || !self.agent.authenticates_session(handshake, response)?
            || !response
                .features()
                .contains(AgentFeatureV1::RuntimeArgumentObservation)
            || handshake.host_channel_binding() != self.agent_peer.channel_binding
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        let current = self.currentness.runtime().currentness();
        let runtime = AgentRuntimeBindingV1::new(
            current.sandbox(),
            current.incarnation(),
            current.assignment_epoch(),
            current.assignment_digest(),
            current.desired_generation(),
            current.namespace_generation(),
            *self.currentness.payload_boot_id().as_bytes(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        if handshake.runtime() != &runtime {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        let retained_spec = sandbox_spec_state::get(controller, parent.specification_descriptor())?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        if retained_spec.record_digest() != parent.specification_record_digest() {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }

        let mut nonce = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::EntropyUnavailable)?;
        let proposed_request = GuestRuntimeArgumentObserveRequestV1::new(
            runtime,
            response.session_binding(),
            self.agent_peer.channel_binding,
            nonce,
            retained_spec.spec().runtime_profile().clone(),
            self.protected_plan.runtime_profile(),
        )?;
        let record = self
            .execution
            .begin_argument_observation_v1(ArgumentObservationRecordV1 {
                execution,
                create_operation,
                request: proposed_request,
                handshake: handshake.clone(),
                response: response.clone(),
                signed_packet_digest: None,
            })?;
        Ok(ProtectedRuntimeArgumentChallengeV1 {
            execution,
            create_operation,
            request: record.request,
            handshake: record.handshake,
            response: record.response,
            completed: record.signed_packet_digest.is_some(),
        })
    }

    /// Recovers an old one-shot challenge without granting a live send path.
    ///
    /// The original signed handshake is reverified against the fixed agent
    /// peer. The Host may only look up a packet already durably captured for
    /// this exact request; an absent packet leaves the challenge quarantined.
    ///
    /// # Errors
    ///
    /// Returns an error if the owner, accepted Create, sandbox policy, old
    /// signed session, or retained challenge no longer matches.
    pub fn recover_runtime_argument_observation_v1(
        &self,
        controller: &mut Journal,
        execution: ExecutionId,
        create_operation: OperationId,
        parent: &ExecutionParentResourceSourceV1,
    ) -> Result<Option<RecoveredRuntimeArgumentChallengeV1>, DormantRuntimeExecutionOwnerErrorV1>
    {
        self.read_protected_accepted_output_v2(controller, create_operation, execution, parent)?;
        let Some(record) = self.execution.load_argument_observation_v1(execution)? else {
            return Ok(None);
        };
        if record.create_operation != create_operation {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        let retained_spec = sandbox_spec_state::get(controller, parent.specification_descriptor())?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        if retained_spec.record_digest() != parent.specification_record_digest()
            || retained_spec.spec().runtime_profile() != record.request.profile()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        self.validate_argument_observation_record_v1(&record)?;
        Ok(Some(RecoveredRuntimeArgumentChallengeV1 { record }))
    }

    /// Verifies and durably consumes one exact signed Guest measurement packet.
    ///
    /// A replay of the same packet is permitted after cold reopen; a different
    /// packet cannot consume the same challenge. The Host must separately
    /// retain its packet bytes for recovery and enforce child-limit/profile
    /// equivalence before any process effect.
    ///
    /// # Errors
    ///
    /// Returns an error for stale owner/session, mismatched challenge or
    /// signature, conflicting packet, or ambiguous protected append.
    pub fn complete_runtime_argument_observation_v1(
        &mut self,
        challenge: &ProtectedRuntimeArgumentChallengeV1,
        signed_packet: &[u8],
    ) -> Result<AuthenticatedRuntimeArgumentReadbackV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if !self
            .agent
            .authenticates_session(&challenge.handshake, &challenge.response)?
            || challenge.request.session() != challenge.response.session_binding()
            || challenge.request.channel() != self.agent_peer.channel_binding
            || challenge.request.profile_commitment() != self.protected_plan.runtime_profile()
            || challenge.request.runtime().assignment_digest()
                != self.currentness.runtime().currentness().assignment_digest()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        let key = VerifyingKey::from_bytes(&self.agent_peer.public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        let readback =
            verify_guest_runtime_argument_readback_v1(signed_packet, &challenge.request, &key)?;
        let custody_digest = self.execution.complete_argument_observation_v1(
            challenge.execution,
            challenge.create_operation,
            &challenge.request,
            readback.packet_digest(),
        )?;
        Ok(AuthenticatedRuntimeArgumentReadbackV1 {
            execution: challenge.execution,
            create_operation: challenge.create_operation,
            evidence: readback.evidence().clone(),
            request_digest: digest(&challenge.request.encode()),
            packet_digest: readback.packet_digest(),
            custody_digest,
        })
    }

    /// Consumes an old challenge only with its exact previously signed packet.
    ///
    /// This method does not restore the old live session. It checks the
    /// original signed handshake and packet against protected custody, then
    /// consumes the one-shot challenge or confirms an identical prior packet.
    /// It returns only a custody digest: a pre-crash measurement is not fresh
    /// runtime evidence for an execution admitted on a new live session.
    ///
    /// # Errors
    ///
    /// Returns an error on stale currentness, forged original session, wrong
    /// packet, conflicting consumption, or ambiguous journal durability.
    pub fn complete_recovered_runtime_argument_observation_v1(
        &mut self,
        challenge: &RecoveredRuntimeArgumentChallengeV1,
        signed_packet: &[u8],
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_argument_observation_record_v1(&challenge.record)?;
        let key = VerifyingKey::from_bytes(&self.agent_peer.public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        let readback = verify_guest_runtime_argument_readback_v1(
            signed_packet,
            &challenge.record.request,
            &key,
        )?;
        self.execution
            .complete_argument_observation_v1(
                challenge.record.execution,
                challenge.record.create_operation,
                &challenge.record.request,
                readback.packet_digest(),
            )
            .map_err(Into::into)
    }

    /// Rechecks a fresh readback against current protected session custody.
    ///
    /// Historical recovery deliberately cannot produce this opaque value.
    /// Even a live proof ceases to qualify when its original agent session is
    /// no longer the protected current session or its owner/record changes.
    ///
    /// # Errors
    ///
    /// Returns an error for stale owner, changed live session, or mismatched
    /// challenge, packet, or current execution target.
    pub fn revalidate_fresh_runtime_argument_readback_v1(
        &self,
        proof: &AuthenticatedRuntimeArgumentReadbackV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        let record = self
            .execution
            .load_argument_observation_v1(proof.execution)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        self.validate_argument_observation_record_v1(&record)?;
        if record.create_operation != proof.create_operation
            || record.signed_packet_digest != Some(proof.packet_digest)
            || digest(&record.request.encode()) != proof.request_digest
            || record
                .digest()
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?
                != proof.custody_digest
            || !self
                .agent
                .authenticates_session(&record.handshake, &record.response)?
            || proof.evidence.target().assignment_digest()
                != self.currentness.runtime().currentness().assignment_digest()
            || proof.evidence.target().payload_boot_id() != self.currentness.payload_boot_id()
            || proof.evidence.runtime_profile_commitment() != self.protected_plan.runtime_profile()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        Ok(())
    }

    fn validate_argument_observation_record_v1(
        &self,
        record: &ArgumentObservationRecordV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let current = self.currentness.runtime().currentness();
        let expected_runtime = AgentRuntimeBindingV1::new(
            current.sandbox(),
            current.incarnation(),
            current.assignment_epoch(),
            current.assignment_digest(),
            current.desired_generation(),
            current.namespace_generation(),
            *self.currentness.payload_boot_id().as_bytes(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        let expected_session =
            AgentSessionBindingV1::derive(&record.handshake, record.response.agent_instance())
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        if record.request.runtime() != &expected_runtime
            || record.handshake.runtime() != &expected_runtime
            || record.handshake.host_channel_binding() != self.agent_peer.channel_binding
            || record.request.channel() != self.agent_peer.channel_binding
            || record.request.profile_commitment() != self.protected_plan.runtime_profile()
            || record.request.session() != expected_session
            || record.response.session_binding() != expected_session
            || !record
                .response
                .features()
                .contains(AgentFeatureV1::RuntimeArgumentObservation)
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch);
        }
        let key = VerifyingKey::from_bytes(&self.agent_peer.public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)?;
        let signing_message = agent_handshake_signing_message_v1(
            &record.handshake,
            expected_session,
            record.response.agent_instance(),
            record.response.features(),
        );
        key.verify_strict(
            &signing_message,
            &Signature::from_bytes(record.response.challenge_signature()),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::ArgumentObservationMismatch)
    }

    fn validate_admission_draft_currentness_v2(
        &self,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<(), AdmissionCommitError> {
        let current = self
            .admission_currentness_for_accepted_output_v2(
                draft.execution(),
                OperationId::from_bytes(*draft.idempotency().operation().as_bytes()),
            )
            .map_err(|_| AdmissionCommitError::StaleAuthority)?;
        // The ledger predecessor may be historical after commit, but the
        // accepted output claim and fixed owner must still be current.
        if !same_owner_and_accepted_output_v2(draft.currentness(), &current) {
            return Err(AdmissionCommitError::CurrentnessMismatch);
        }
        Ok(())
    }

    /// Reserves the exact accepted Create output bytes under this protected owner.
    ///
    /// Zero-byte streams still create an explicit durable record. Ambiguous
    /// commits must be resolved after dropping this claim and cold-reopening
    /// the owner; retrying with a fresh request is not a recovery procedure.
    /// This reservation does not establish physical capture-storage or Host
    /// effect authority.
    ///
    /// # Errors
    ///
    /// Returns an error for stale owner, accepted Create, or parent inputs,
    /// insufficient capacity, or protected journal failure.
    pub fn reserve_accepted_output_v2(
        &mut self,
        controller: &mut Journal,
        create_operation: OperationId,
        execution: ExecutionId,
        parent: &ExecutionParentResourceSourceV1,
    ) -> Result<ExecutionOutputReservationCommitV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .reserve_accepted_output_v2(controller, create_operation, execution, parent)
            .map_err(Into::into)
    }

    /// Commits one signed Controller source under the protected Host ledger.
    ///
    /// The Host broker must first durably admit the exact pending effect. The
    /// accepted parent capacity is Controller-sourced through the signed
    /// carrier; this provisional reservation does not prove physical backing.
    /// An ambiguous append requires cold reopen and query, never redispatch.
    ///
    /// # Errors
    ///
    /// Rejects stale Host ownership, conflicting output custody, exhausted
    /// capacity, or an outcome-unknown protected append.
    pub fn reserve_host_output_v1(
        &mut self,
        verified: &VerifiedHostOutputReserveSourceV1,
    ) -> Result<ProtectedHostOutputReservationV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .reserve_host_output_v1(verified)
            .map_err(Into::into)
    }

    /// Reads one exact prior Host reservation after protected cold reopen.
    ///
    /// This method never appends a claim or renews a Controller preissue. A
    /// foreign claim under the same execution ID conflicts rather than looking
    /// absent, and historical receipts are not fresh execution authority.
    ///
    /// # Errors
    ///
    /// Rejects stale Host ownership, malformed custody, or any mismatched
    /// original request, Create, source, assignment, or Host boot selector.
    #[allow(clippy::too_many_arguments)]
    pub fn query_host_output_v1(
        &self,
        execution: ExecutionId,
        create_operation: OperationId,
        preissue_digest: ObjectDigest,
        claim_digest: ObjectDigest,
        carrier_digest: ObjectDigest,
        original_request_id: [u8; 16],
        assignment_digest: ObjectDigest,
        host_boot_id: [u8; 16],
    ) -> Result<Option<ProtectedHostOutputReservationV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .query_host_output_v1(
                execution,
                create_operation,
                preissue_digest,
                claim_digest,
                carrier_digest,
                original_request_id,
                assignment_digest,
                host_boot_id,
            )
            .map_err(Into::into)
    }

    /// Reads the exact protected Host output pair for a Storage-audience query.
    ///
    /// The parsed Controller records are structural, not an issuance proof.
    /// A future Host responder must separately verify its Controller Host plan
    /// and sign this observation in the Storage-owned authenticated session.
    ///
    /// # Errors
    ///
    /// Rejects stale Host owner, assignment or boot, absent original pair, or
    /// any difference from AOSCIA01/AOSCIS01 plan and correlation fields.
    pub fn read_host_output_for_storage_v1(
        &self,
        request: &ValidatedHostStorageOutputReadbackRequestV1,
    ) -> Result<ProtectedHostOutputReadbackV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let current = self.currentness().runtime().currentness();
        let assignment = BrokerAssignment::new(
            current.sandbox(),
            current.incarnation(),
            current.assignment_epoch(),
            current.desired_generation(),
            current.assignment_digest(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if assignment != request.records().assignment()
            || self.host_verifier().boot_id() != request.records().host_locator().host_boot_id()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::AcceptedOutputClaimMismatch);
        }
        let readback = self.execution.read_host_output_for_storage_v1(request)?;
        self.validate_current()?;
        Ok(readback)
    }

    /// Resolves the exact Host-held AOSEOR02/AOSHOP01 pair for one argument attempt.
    ///
    /// AOSCIA02 is Controller-sourced and nonauthorizing by itself. The caller
    /// must separately match its signed method-37 plan before any Guest send.
    ///
    /// # Errors
    ///
    /// Rejects a stale Host owner, missing correlation, or a source that does
    /// not match every protected output field and the raw AOSHOP01 digest.
    pub fn host_output_for_argument_v1(
        &self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<ProtectedHostOutputReservationV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .host_output_for_argument_v1(source)
            .map_err(Into::into)
    }

    /// Resolves an ambiguous output reservation after protected cold reopen.
    ///
    /// # Errors
    ///
    /// Returns an error if current ownership or the exact durable output
    /// claim cannot be authenticated.
    pub fn recover_accepted_output_v2(
        &self,
        token: ExecutionOutputReservationRecoveryV1,
    ) -> Result<ExecutionOutputReservationRecoveryResultV1, DormantRuntimeExecutionOwnerErrorV1>
    {
        self.validate_current()?;
        self.execution
            .recover_accepted_output_v2(token)
            .map_err(Into::into)
    }

    /// Borrows the authenticated fixed-platform capability evidence.
    #[must_use]
    pub const fn backend_capabilities(&self) -> &BackendCapabilitiesV1 {
        &self.backend_capabilities
    }

    /// Borrows peer-verification inputs authenticated by this same claim.
    #[must_use]
    pub const fn agent_peer(&self) -> &ProtectedRuntimeAgentPeerV1 {
        &self.agent_peer
    }

    /// Returns the runtime-profile commitment authenticated by the fixed plan catalog.
    #[must_use]
    pub const fn runtime_profile_commitment(&self) -> ObjectDigest {
        self.protected_plan.runtime_profile()
    }

    /// Borrows fixed Host lifecycle/deadline verification authority.
    #[must_use]
    pub const fn host_verifier(&self) -> &ProtectedRuntimeHostVerifierV1 {
        &self.host_verifier
    }

    /// Returns the exact persisted next lifecycle operation sequence.
    #[must_use]
    pub const fn next_lifecycle_sequence(&self) -> u64 {
        self.lifecycle_head.next_lifecycle_sequence
    }

    /// Returns the exact persisted next observation sequence.
    #[must_use]
    pub const fn next_observation_sequence(&self) -> aos_sandbox_core::ObservationSequence {
        aos_sandbox_core::ObservationSequence::new(self.lifecycle_head.next_observation_sequence)
    }

    /// Loads the sole protected lifecycle issue retained across reopen.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] if retained bytes are no
    /// longer the canonical issue authenticated when this claim was opened.
    pub fn pending_lifecycle_issue(
        &self,
    ) -> Result<Option<ProtectedLifecycleIssueV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.lifecycle_issue
            .as_deref()
            .map(decode_lifecycle_issue)
            .transpose()
    }

    /// Reports whether an opaque observation is an exact protected terminal replay.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when protected state is
    /// stale or the retained terminal row is malformed.
    pub fn is_exact_terminal_observation(
        &self,
        observation: &BackendRuntimeInspectionV1,
    ) -> Result<bool, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if observation.authority_binding() != self.host_verifier.authority_binding
            || observation.commitment() != self.currentness.runtime()
        {
            return Ok(false);
        }
        let expected = encode_lifecycle_terminal(observation, self.host_verifier.authority_binding);
        Ok(self
            .lifecycle_terminals
            .get(observation.operation().as_bytes())
            == Some(&expected))
    }

    /// Atomically consumes one authenticated agent execution observation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] unless the observation
    /// has the exact protected agent authority, runtime currentness, and next
    /// persisted sequence.
    pub fn consume_execution_observation(
        &mut self,
        observation: &BackendExecutionInspectionV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if observation.authority_binding() != self.agent_peer.authority_binding
            || observation.runtime() != self.currentness.runtime()
            || observation.sequence().get() != self.lifecycle_head.next_observation_sequence
            || observation.sequence().get() == u64::MAX
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.lifecycle_head.next_observation_sequence = observation.sequence().get() + 1;
        self.commit_lifecycle_records(self.lifecycle_issue.clone(), None)?;
        Ok(())
    }

    /// Stages Prepare only for the exact fixed protected plan catalog row.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a lifecycle predecessor or sequence conflict, or durable journal
    /// failure.
    pub fn issue_protected_prepare(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
    ) -> Result<(ResolvedRuntimePlanV1, ObjectDigest), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let plan = self.protected_plan.clone();
        let request = lifecycle_request_commitment(
            BackendLifecycleOperationV1::Prepare,
            operation,
            sequence,
            plan.plan_commitment(),
            None,
        );
        if !self.terminal_issue_is_exact(
            operation,
            sequence,
            BackendLifecycleOperationV1::Prepare,
            plan.plan_commitment(),
            None,
            request,
        )? && !self.lifecycle_terminals.is_empty()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.issue_lifecycle_effect(
            operation.as_bytes(),
            sequence.get(),
            BackendLifecycleOperationV1::Prepare as u8,
            plan.plan_commitment(),
            None,
            request,
        )?;
        Ok((plan, request))
    }

    /// Stages Start for the exact protected plan and predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign handle, invalid predecessor, replay conflict, or durability
    /// failure.
    pub fn issue_protected_start(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.issue_protected_runtime_action(
            BackendLifecycleOperationV1::Start,
            operation,
            sequence,
            runtime,
            None,
        )
    }

    /// Stages Freeze for the exact protected plan and predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign handle, invalid predecessor, replay conflict, or durability
    /// failure.
    pub fn issue_protected_freeze(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.issue_protected_runtime_action(
            BackendLifecycleOperationV1::Freeze,
            operation,
            sequence,
            runtime,
            None,
        )
    }

    /// Stages Thaw for the exact protected plan and predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign handle, invalid predecessor, replay conflict, or durability
    /// failure.
    pub fn issue_protected_thaw(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.issue_protected_runtime_action(
            BackendLifecycleOperationV1::Thaw,
            operation,
            sequence,
            runtime,
            None,
        )
    }

    /// Stages Stop with the exact protected plan, predecessor, and deadline.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign handle, invalid predecessor, replay conflict, or durability
    /// failure.
    pub fn issue_protected_stop(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
        deadline: BackendStopDeadlineV1,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.issue_protected_runtime_action(
            BackendLifecycleOperationV1::Stop,
            operation,
            sequence,
            runtime,
            Some(deadline),
        )
    }

    /// Stages Destroy for the exact protected plan and predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign handle, invalid predecessor, replay conflict, or durability
    /// failure.
    pub fn issue_protected_destroy(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.issue_protected_runtime_action(
            BackendLifecycleOperationV1::Destroy,
            operation,
            sequence,
            runtime,
            None,
        )
    }

    /// Stages Inspect for the exact protected plan and predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign handle, invalid predecessor, replay conflict, or durability
    /// failure.
    pub fn issue_protected_inspect(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.issue_protected_runtime_action(
            BackendLifecycleOperationV1::Inspect,
            operation,
            sequence,
            runtime,
            None,
        )
    }

    /// Stages one exact protected-plan lifecycle action internally.
    ///
    /// Stop requires its protected relative deadline; every other accepted
    /// action rejects a deadline. Prepare and Kill have dedicated flows.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for an action/deadline
    /// shape error, foreign plan/currentness/handle, replay conflict, or
    /// durable journal failure.
    fn issue_protected_runtime_action(
        &mut self,
        action: BackendLifecycleOperationV1,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
        deadline: Option<BackendStopDeadlineV1>,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if runtime != self.currentness.runtime()
            || (action == BackendLifecycleOperationV1::Stop) != deadline.is_some()
            || matches!(
                action,
                BackendLifecycleOperationV1::Prepare | BackendLifecycleOperationV1::Kill
            )
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let request = match deadline {
            Some(deadline) => stop_request_commitment(operation, sequence, *runtime, deadline),
            None => lifecycle_request_commitment(
                action,
                operation,
                sequence,
                runtime.plan_commitment(),
                Some(runtime.handle()),
            ),
        };
        if !self.terminal_issue_is_exact(
            operation,
            sequence,
            action,
            runtime.plan_commitment(),
            Some(runtime.handle()),
            request,
        )? {
            self.validate_runtime_action_predecessor(action, runtime)?;
        }
        self.issue_lifecycle_effect(
            operation.as_bytes(),
            sequence.get(),
            action as u8,
            runtime.plan_commitment(),
            Some(runtime.handle()),
            request,
        )?;
        Ok(request)
    }

    fn terminal_issue_is_exact(
        &self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        action: BackendLifecycleOperationV1,
        plan: ObjectDigest,
        handle: Option<ObjectDigest>,
        request: ObjectDigest,
    ) -> Result<bool, DormantRuntimeExecutionOwnerErrorV1> {
        let Some(bytes) = self.lifecycle_terminals.get(operation.as_bytes()) else {
            return Ok(false);
        };
        let terminal = decode_lifecycle_terminal(bytes)?;
        Ok(terminal.sequence == sequence
            && terminal.action == action
            && terminal.plan == plan
            && terminal.request == request
            && (action == BackendLifecycleOperationV1::Prepare || Some(terminal.handle) == handle))
    }

    fn validate_runtime_action_predecessor(
        &self,
        action: BackendLifecycleOperationV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        let latest = self
            .lifecycle_terminals
            .values()
            .map(|bytes| decode_lifecycle_terminal(bytes))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|terminal| terminal.observation_sequence != 0)
            .max_by_key(|terminal| terminal.sequence.get())
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        let phase = latest.result_phase;
        let predecessor_is_valid = latest.handle == runtime.handle()
            && match action {
                BackendLifecycleOperationV1::Start => {
                    latest.action == BackendLifecycleOperationV1::Prepare && phase == 1
                }
                BackendLifecycleOperationV1::Freeze => phase == 3,
                BackendLifecycleOperationV1::Thaw => phase == 4,
                BackendLifecycleOperationV1::Stop => matches!(phase, 3 | 4),
                BackendLifecycleOperationV1::Destroy => matches!(phase, 1 | 6 | 8),
                BackendLifecycleOperationV1::Inspect => true,
                BackendLifecycleOperationV1::Prepare | BackendLifecycleOperationV1::Kill => false,
            };
        if predecessor_is_valid {
            Ok(())
        } else {
            Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)
        }
    }

    /// Marks the exact currently Issued protected action as crossed.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when `request` is not
    /// the exact fixed-owner issue or its terminal replay.
    pub fn consume_pending_lifecycle(
        &mut self,
        request: ObjectDigest,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let Some(bytes) = self.lifecycle_issue.as_deref() else {
            if self.lifecycle_terminals.values().any(|bytes| {
                decode_lifecycle_terminal(bytes).is_ok_and(|terminal| terminal.request == request)
            }) {
                return Ok(());
            }
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        };
        let issue = decode_lifecycle_issue(bytes)?;
        if issue.request != request || issue.crossed {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.consume_lifecycle_effect(
            issue.operation.as_bytes(),
            issue.sequence.get(),
            issue.action as u8,
            issue.plan,
            issue.handle,
            issue.request,
        )
    }

    /// Durably stages one exact lifecycle effect as Issued.
    #[allow(clippy::too_many_arguments)]
    fn issue_lifecycle_effect(
        &mut self,
        operation: &[u8; 16],
        sequence: u64,
        action_code: u8,
        plan: ObjectDigest,
        handle: Option<ObjectDigest>,
        request: ObjectDigest,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if let Some(terminal) = self.lifecycle_terminals.get(operation) {
            let terminal = decode_lifecycle_terminal(terminal)?;
            if terminal.sequence.get() == sequence
                && terminal.action as u8 == action_code
                && terminal.plan == plan
                && terminal.request == request
                && (action_code == BackendLifecycleOperationV1::Prepare as u8
                    || Some(terminal.handle) == handle)
            {
                return Ok(());
            }
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        if self.lifecycle_issue.is_some()
            || sequence != self.lifecycle_head.next_lifecycle_sequence
            || sequence == u64::MAX
            || !(1..=8).contains(&action_code)
            || (action_code == 1) != handle.is_none()
            || handle.is_some_and(|value| value.as_bytes() == &[0; 32])
            || plan.as_bytes() == &[0; 32]
            || request.as_bytes() == &[0; 32]
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let issue = encode_lifecycle_issue(
            operation,
            sequence,
            action_code,
            1,
            plan,
            handle,
            request,
            self.host_verifier.authority_binding,
        );
        self.lifecycle_head.next_lifecycle_sequence = sequence + 1;
        self.commit_lifecycle_records(Some(issue.clone()), None)?;
        self.lifecycle_issue = Some(issue);
        Ok(())
    }

    /// Marks the exact Issued lifecycle effect as having crossed its boundary.
    #[allow(clippy::too_many_arguments)]
    fn consume_lifecycle_effect(
        &mut self,
        operation: &[u8; 16],
        sequence: u64,
        action_code: u8,
        plan: ObjectDigest,
        handle: Option<ObjectDigest>,
        request: ObjectDigest,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let expected = encode_lifecycle_issue(
            operation,
            sequence,
            action_code,
            1,
            plan,
            handle,
            request,
            self.host_verifier.authority_binding,
        );
        if self.lifecycle_issue.as_deref() != Some(expected.as_slice()) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let consumed = encode_lifecycle_issue(
            operation,
            sequence,
            action_code,
            2,
            plan,
            handle,
            request,
            self.host_verifier.authority_binding,
        );
        self.commit_lifecycle_records(Some(consumed.clone()), None)?;
        self.lifecycle_issue = Some(consumed);
        Ok(())
    }

    /// Atomically closes a consumed lifecycle effect and advances its evidence head.
    ///
    /// Keeping both mutations in one protected transaction prevents a crash
    /// from forgetting either the outstanding effect or its consumed evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_lifecycle_effect_with_observation(
        &mut self,
        observation: &BackendRuntimeInspectionV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let action = observation.lifecycle_operation();
        let handle = (action != BackendLifecycleOperationV1::Prepare)
            .then(|| observation.commitment().handle());
        let expected = encode_lifecycle_issue(
            observation.operation().as_bytes(),
            observation.operation_sequence().get(),
            action as u8,
            2,
            observation.commitment().plan_commitment(),
            handle,
            observation.request_commitment(),
            self.host_verifier.authority_binding,
        );
        if observation.authority_binding() != self.host_verifier.authority_binding
            || observation.commitment() != self.currentness.runtime()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let terminal_key = lifecycle_terminal_key(observation.operation().as_bytes());
        let terminal = encode_lifecycle_terminal(observation, self.host_verifier.authority_binding);
        if let Some(existing) = self
            .lifecycle_terminals
            .get(observation.operation().as_bytes())
        {
            if existing == &terminal && self.lifecycle_issue.is_none() {
                return Ok(());
            }
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        if self.lifecycle_issue.as_deref() != Some(expected.as_slice())
            || observation.sequence().get() != self.lifecycle_head.next_observation_sequence
            || observation.sequence().get() == u64::MAX
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.lifecycle_head.next_observation_sequence = observation.sequence().get() + 1;
        self.commit_lifecycle_records(None, Some((terminal_key, terminal.clone())))?;
        self.lifecycle_issue = None;
        self.lifecycle_terminals
            .insert(*observation.operation().as_bytes(), terminal);
        Ok(())
    }

    /// Supersedes the exact consumed Stop with protected-plan Kill issuance.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] unless the retained
    /// issue is the exact crossed Stop for `runtime` and `stop_request`, or the
    /// Kill sequence/request conflicts with durable history.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_protected_kill(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
        stop_request: ObjectDigest,
        host_boot_id: [u8; 16],
        stop_started_boottime_nanoseconds: u64,
        observed_boottime_nanoseconds: u64,
    ) -> Result<ObjectDigest, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let prior = self
            .lifecycle_issue
            .as_deref()
            .map(decode_lifecycle_issue)
            .transpose()?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        if !prior.crossed
            || prior.action != BackendLifecycleOperationV1::Stop
            || prior.request != stop_request
            || prior.plan != self.protected_plan.plan_commitment()
            || prior.handle != Some(runtime.handle())
            || runtime != self.currentness.runtime()
            || host_boot_id != self.host_verifier.boot_id
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let request = forced_kill_request_commitment(
            operation,
            sequence,
            *runtime,
            stop_request,
            host_boot_id,
            stop_started_boottime_nanoseconds,
            observed_boottime_nanoseconds,
        );
        self.supersede_lifecycle_effect(
            prior.operation.as_bytes(),
            prior.sequence.get(),
            prior.action as u8,
            prior.plan,
            prior.handle,
            prior.request,
            operation.as_bytes(),
            sequence.get(),
            BackendLifecycleOperationV1::Kill as u8,
            runtime.plan_commitment(),
            Some(runtime.handle()),
            request,
        )?;
        Ok(request)
    }

    /// Atomically supersedes one consumed lifecycle ambiguity with a new issue.
    #[allow(clippy::too_many_arguments)]
    fn supersede_lifecycle_effect(
        &mut self,
        prior_operation: &[u8; 16],
        prior_sequence: u64,
        prior_action_code: u8,
        prior_plan: ObjectDigest,
        prior_handle: Option<ObjectDigest>,
        prior_request: ObjectDigest,
        operation: &[u8; 16],
        sequence: u64,
        action_code: u8,
        plan: ObjectDigest,
        handle: Option<ObjectDigest>,
        request: ObjectDigest,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let prior = encode_lifecycle_issue(
            prior_operation,
            prior_sequence,
            prior_action_code,
            2,
            prior_plan,
            prior_handle,
            prior_request,
            self.host_verifier.authority_binding,
        );
        if self.lifecycle_issue.as_deref() != Some(prior.as_slice())
            || sequence != self.lifecycle_head.next_lifecycle_sequence
            || sequence == u64::MAX
            || !(1..=8).contains(&action_code)
            || (action_code == 1) != handle.is_none()
            || handle.is_some_and(|value| value.as_bytes() == &[0; 32])
            || plan.as_bytes() == &[0; 32]
            || request.as_bytes() == &[0; 32]
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let successor = encode_lifecycle_issue(
            operation,
            sequence,
            action_code,
            1,
            plan,
            handle,
            request,
            self.host_verifier.authority_binding,
        );
        let prior_terminal = encode_lifecycle_terminal_row(LifecycleTerminalV1 {
            operation: BackendOperationIdV1::new(*prior_operation)
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
            sequence: BackendOperationSequenceV1::new(prior_sequence)
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
            action: decode_lifecycle_action(prior_action_code)?,
            result_phase: runtime_phase_code(BackendRuntimePhaseV1::Stopping),
            plan: prior_plan,
            handle: prior_handle
                .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
            request: prior_request,
            observation_sequence: 0,
            observation_commitment: request,
            currentness: runtime_currentness_commitment(self.currentness.runtime().currentness()),
            authority: self.host_verifier.authority_binding,
        });
        if self.lifecycle_terminals.contains_key(prior_operation) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.lifecycle_head.next_lifecycle_sequence = sequence + 1;
        self.commit_lifecycle_records(
            Some(successor.clone()),
            Some((
                lifecycle_terminal_key(prior_operation),
                prior_terminal.clone(),
            )),
        )?;
        self.lifecycle_issue = Some(successor);
        self.lifecycle_terminals
            .insert(*prior_operation, prior_terminal);
        Ok(())
    }

    fn commit_lifecycle_records(
        &mut self,
        issue: Option<Vec<u8>>,
        terminal: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        let head = encode_lifecycle_head(self.lifecycle_head);
        let tx_digest = hash_parts(
            b"aos.sandbox.runtime-execution.lifecycle-transition.v1\0",
            &[
                head.as_slice(),
                issue.as_deref().unwrap_or(&[]),
                terminal
                    .as_ref()
                    .map_or(&[][..], |(_, value)| value.as_slice()),
            ],
        );
        let transaction_id = tx_digest.as_bytes()[..16]
            .try_into()
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let mut records = vec![JournalRecord::put(
            RecordNamespace::HostExecution,
            LIFECYCLE_HEAD_KEY.to_vec(),
            head,
        )];
        records.push(match issue {
            Some(value) => JournalRecord::put(
                RecordNamespace::HostExecution,
                LIFECYCLE_ISSUE_KEY.to_vec(),
                value,
            ),
            None => {
                JournalRecord::delete(RecordNamespace::HostExecution, LIFECYCLE_ISSUE_KEY.to_vec())
            }
        });
        if let Some((key, value)) = terminal {
            records.push(JournalRecord::put(
                RecordNamespace::HostExecution,
                key,
                value,
            ));
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        let preflight = self
            .lifecycle_authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.lifecycle_authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        self.lifecycle_authority.commit(&transaction)?;
        Ok(())
    }

    /// Revalidates the exact protected Host peer and runtime-currentness rows.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness`] when
    /// either row or the protected journal sequence changed, or a journal error
    /// when the retained protected authority is unavailable.
    pub fn revalidate(&self) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()
    }

    /// Loads one admitted execution after revalidating protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state or
    /// corrupt/unavailable execution durability.
    pub fn load_admission(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<AdmittedExecutionV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.load_admission(execution).map_err(Into::into)
    }

    /// Loads one durable effect after revalidating protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state or
    /// corrupt/unavailable execution durability.
    pub fn load_effect(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<DurableExecutionEffectV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.load_effect(operation).map_err(Into::into)
    }

    /// Durably closes Host Apply for one original method-37 Create attempt.
    ///
    /// The caller must first match `source` and the original session identities
    /// to the sealed Host method-37 handoff. This transition shares the runtime
    /// execution journal lock with every Host Apply admission and effect CAS.
    /// A failed append is outcome-unknown and requires a new protected read.
    ///
    /// # Errors
    ///
    /// Rejects stale or substituted Host custody, a foreign authenticated
    /// terminal request, an existing admission, or ambiguous durability.
    pub fn commit_host_no_apply_v1(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
        terminal_request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<HostExecutionNoApplyRecordV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if terminal_request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || terminal_request.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            || terminal_request.authorization().is_none()
            || terminal_request.request_id() == source.request_id()
            || source.host_boot_id() != self.host_verifier.boot_id()
            || source.assignment_digest()
                != self.currentness.runtime().currentness().assignment_digest()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let identity = HostNoApplyIdentityV1 {
            source: source.clone(),
            original_session_binding,
            original_signed_request_digest,
            terminal_request_id: terminal_request.request_id(),
            terminal_session_binding: terminal_request.session_binding(),
            terminal_signed_request_digest: terminal_request.signed_request_digest(),
        };
        let record = self
            .execution
            .commit_host_no_apply_v1(&identity, self.currentness.runtime().handle())?;
        self.validate_current()
            .map_err(|_| JournalRuntimeExecutionError::NoApplyOutcomeUnknown)?;
        Ok(record)
    }

    /// Reads the exact protected no-Apply marker without authorizing retry.
    ///
    /// # Errors
    ///
    /// Rejects stale Host currentness, missing source correlation, or a marker
    /// that differs from the original authenticated method-37 identities.
    pub fn query_host_no_apply_v1(
        &self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
    ) -> Result<Option<HostExecutionNoApplyRecordV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.host_output_for_argument_v1(source)?;
        let Some(record) = self.execution.load_host_no_apply_v1(source.execution())? else {
            return Ok(None);
        };
        let fields = record.fields();
        if fields.create_operation_id != *source.create_operation().as_bytes()
            || fields.original_request_id != source.request_id()
            || fields.host_boot_id != source.host_boot_id()
            || fields.assignment_digest != *source.assignment_digest().as_bytes()
            || fields.source_record_digest != *source.record_digest().as_bytes()
            || fields.original_session_binding != original_session_binding
            || fields.original_signed_request_digest != original_signed_request_digest
            || fields.runtime_handle != *self.currentness.runtime().handle().as_bytes()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        Ok(Some(record))
    }

    /// Reads the complete protected Host settlement chain for one original attempt.
    ///
    /// This is historical readback only. The caller must separately verify the
    /// signed method-39 custody, Controller floor/CAS, and current held Host
    /// lease before using any stage as cross-owner settlement evidence.
    ///
    /// # Errors
    ///
    /// Rejects stale Host currentness, a foreign original attempt, or any
    /// malformed, orphaned, or nonconsecutive protected settlement stage.
    pub fn query_host_settlement_history_v1(
        &self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
    ) -> Result<Option<ProtectedHostNoApplySettlementHistoryV1>, DormantRuntimeExecutionOwnerErrorV1>
    {
        let Some(marker) = self.query_host_no_apply_v1(
            source,
            original_session_binding,
            original_signed_request_digest,
        )?
        else {
            if self
                .execution
                .has_host_settlement_stages_v1(source.execution())?
            {
                return Err(JournalRuntimeExecutionError::CorruptRecord.into());
            }
            self.validate_current()?;
            return Ok(None);
        };

        let stages = self
            .execution
            .load_host_settlement_history_v1(source.execution())?;
        self.validate_current()?;

        Ok(Some(ProtectedHostNoApplySettlementHistoryV1 {
            marker,
            stages: stages.map(|record| record.map(HostSettlementRecordV1::encode_canonical)),
        }))
    }

    /// Measures the exact protected Host Effect cut under the current claim.
    ///
    /// This readback can label a future no-Apply lease, but it does not itself
    /// retain a lock or authorize a Controller CAS after the claim is dropped.
    ///
    /// # Errors
    ///
    /// Rejects stale protected currentness, malformed replay, or an unavailable
    /// fixed Host journal.
    pub fn protected_host_settlement_cut_v1(
        &self,
    ) -> Result<ProtectedHostSettlementCutV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let (epoch, digest) = self.execution.protected_host_settlement_cut_v1()?;
        self.validate_current()?;
        Ok(ProtectedHostSettlementCutV1 { epoch, digest })
    }

    /// Runs a bounded action without releasing the protected Host writer claim.
    ///
    /// The action receives only an Effect-cut coordinate. Both the protected
    /// Host currentness and exact Effect cut are checked again before any
    /// successful result is returned. The action must itself bound any socket
    /// wait; a copied coordinate or completed callback is not a transferable
    /// Host lease, Controller floor, or two-owner barrier. If the postcheck
    /// fails, a sent request or durable write remains outcome-unknown and
    /// requires cold exact-request recovery, never a new challenge.
    ///
    /// # Errors
    ///
    /// Rejects stale owner currentness, an Effect-cut change during the
    /// action, an unavailable protected journal, or the action's own error.
    pub fn with_held_host_settlement_cut_v1<T, E>(
        &mut self,
        action: impl FnOnce(ProtectedHostSettlementCutV1) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<DormantRuntimeExecutionOwnerErrorV1>,
    {
        self.validate_current().map_err(E::from)?;
        let result = self
            .execution
            .with_held_host_settlement_cut_v1(|_, (epoch, digest)| {
                Ok(action(ProtectedHostSettlementCutV1 { epoch, digest }))
            })
            .map_err(DormantRuntimeExecutionOwnerErrorV1::from)
            .map_err(E::from)?;
        self.validate_current().map_err(E::from)?;
        result
    }

    /// Prepares, without appending, one preliminary Host no-Apply settlement stage.
    ///
    /// The protected marker and absent stage history are re-read under this
    /// claim. The H/T digests remain Controller assertions until its separate
    /// protected archive owner reauthenticates them and the cross-owner lease
    /// is qualified. The returned bytes cannot be committed by this method.
    ///
    /// # Errors
    ///
    /// Rejects stale custody, a foreign marker, a conflicting prior stage,
    /// malformed asserted coordinates, or a cut that changed during preparation.
    #[allow(
        dead_code,
        reason = "signed cross-owner stage admission remains closed"
    )]
    pub fn prepare_host_settlement_preliminary_v1(
        &self,
        marker: HostExecutionNoApplyRecordV1,
        handoff_digest: ObjectDigest,
        original_h_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
        session_binding: [u8; 32],
        challenge: [u8; 16],
    ) -> Result<PreparedHostSettlementPreliminaryV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let execution = ExecutionId::from_bytes(marker.fields().execution_id);
        if self.execution.load_host_no_apply_v1(execution)? != Some(marker)
            || self
                .execution
                .load_host_settlement_history_v1(execution)?
                .iter()
                .any(Option::is_some)
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }

        let cut = self.protected_host_settlement_cut_v1()?;
        let sequence = self.execution.next_host_settlement_sequence_v1(cut.epoch)?;
        let observed =
            HostObservedSettlementIdentityV1::from_marker_and_handoff(marker, handoff_digest)
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let archives =
            ControllerAssertedSettlementArchivesV1::new(original_h_head, signed_terminal_outcome)
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let record = HostSettlementRecordV1::preliminary(
            observed,
            archives,
            cut.epoch,
            cut.digest,
            session_binding,
            challenge,
            sequence,
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if self.protected_host_settlement_cut_v1()? != cut {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        Ok(PreparedHostSettlementPreliminaryV1 {
            canonical_record: record.encode_canonical(),
            cut,
        })
    }

    /// Commits a prepared preliminary coordinate while its Host writer claim is held.
    ///
    /// This commits no Controller disposition and grants no Host Apply. The
    /// caller must have authenticated the Controller's request and must retain
    /// this claim from preparation through the append. A failed append has an
    /// unknown outcome and requires a cold protected readback of the original
    /// request; the prepared value cannot be retried under a new claim.
    ///
    /// # Errors
    ///
    /// Rejects a changed Host cut, marker, or stage history, a forged prepared
    /// record, stale Host currentness, or uncertain journal durability.
    pub fn commit_host_settlement_preliminary_v1(
        &mut self,
        prepared: PreparedHostSettlementPreliminaryV1,
    ) -> Result<[u8; HOST_SETTLEMENT_RECORD_BYTES], DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let record = HostSettlementRecordV1::decode_canonical(&prepared.canonical_record)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        self.execution.commit_host_settlement_preliminary_v1(
            record,
            prepared.cut.epoch,
            prepared.cut.digest,
        )?;
        self.validate_current()
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if self
            .execution
            .load_host_settlement_history_v1(record.execution)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
            != [Some(record), None, None]
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown.into());
        }
        Ok(record.encode_canonical())
    }

    /// Rejoins a cold-recovered preliminary stage to one exact original request.
    ///
    /// A matching return value is historical custody only. It does not revive
    /// the writer cut that preceded the append or authorize Controller's CAS.
    ///
    /// # Errors
    ///
    /// Rejects a changed marker, handoff, Controller assertion, session, or
    /// challenge, as well as malformed or orphaned protected Host history.
    pub fn match_host_settlement_preliminary_v1(
        &self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
        handoff_digest: ObjectDigest,
        original_h_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
        settlement_session_binding: [u8; 32],
        challenge: [u8; 16],
    ) -> Result<Option<[u8; HOST_SETTLEMENT_RECORD_BYTES]>, DormantRuntimeExecutionOwnerErrorV1>
    {
        let Some(history) = self.query_host_settlement_history_v1(
            source,
            original_session_binding,
            original_signed_request_digest,
        )?
        else {
            return Ok(None);
        };
        let Some(bytes) = history.stage_bytes(HostNoApplySettlementPhaseV2::Preliminary) else {
            return Ok(None);
        };
        let preliminary = HostSettlementRecordV1::decode_canonical(bytes)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;

        if !preliminary.matches_preliminary_source(
            history.marker(),
            handoff_digest,
            original_h_head,
            signed_terminal_outcome,
            settlement_session_binding,
            challenge,
        ) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.validate_current()?;
        Ok(Some(preliminary.encode_canonical()))
    }

    /// Quarantines Host Effect after rejoining one exact preliminary request.
    ///
    /// This retains the HostState and Effect writer claims through the append.
    /// H/T remain Controller assertions until an independently authenticated
    /// two-owner continuation proves their current archive custody. The paired
    /// Effect and HostState holds are permanent in this version and grant no
    /// Floor seal or Apply.
    ///
    /// # Errors
    ///
    /// Rejects foreign original-request or handoff identities, stale Host
    /// currentness or Effect cut, a non-preliminary history, or uncertain
    /// durability. An outcome-unknown append requires cold exact readback.
    #[allow(dead_code, reason = "two-owner continuation remains closed")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn acquire_host_execution_fence_v1(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
        original_session_binding: [u8; 32],
        original_signed_request_digest: [u8; 32],
        handoff_digest: ObjectDigest,
        original_h_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
        settlement_session_binding: [u8; 32],
        challenge: [u8; 16],
    ) -> Result<HostExecutionFenceV1, DormantRuntimeExecutionOwnerErrorV1> {
        let bytes = self
            .match_host_settlement_preliminary_v1(
                source,
                original_session_binding,
                original_signed_request_digest,
                handoff_digest,
                original_h_head,
                signed_terminal_outcome,
                settlement_session_binding,
                challenge,
            )?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        let preliminary = HostSettlementRecordV1::decode_canonical(&bytes)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let cut = self.protected_host_settlement_cut_v1()?;
        let fence =
            self.execution
                .acquire_host_execution_fence_v1(preliminary, cut.epoch, cut.digest)?;
        self.commit_host_currentness_fence_after_effect_v1(fence)?;
        Ok(fence)
    }

    /// Rejects an argument execution with a protected terminal no-Apply marker.
    ///
    /// Absence is not a send grant. Callers must separately validate the exact
    /// signed request and output source while this runtime-owner claim is held.
    ///
    /// # Errors
    ///
    /// Rejects stale currentness or an already committed terminal marker.
    pub fn ensure_host_argument_not_terminal_v1(
        &self,
        execution: ExecutionId,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        if self.execution.load_host_no_apply_v1(execution)?.is_some() {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        Ok(())
    }

    /// Returns the next effect sequence from the protected runtime history.
    ///
    /// A pending or nonterminal predecessor prevents allocation. This value
    /// alone is never a dispatch permit; the effect store rechecks it at CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale currentness, corrupt history, or exhaustion.
    pub fn next_effect_sequence(
        &self,
    ) -> Result<BackendOperationSequenceV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .next_effect_sequence(self.currentness.runtime().handle())
            .map_err(Into::into)
    }

    /// Loads durable recovery evidence before any live inventory is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state or
    /// absent, corrupt, or unavailable protected execution state.
    pub fn load_recovery(
        &self,
        operation: &[u8; 16],
    ) -> Result<JournalRecoveryV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.load_recovery(operation).map_err(Into::into)
    }

    /// Recovers the exact historical agent request without minting dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale peer
    /// currentness, a malformed route, or unavailable protected execution
    /// state. An absent route does not prove that an earlier append failed.
    pub fn recover_agent_route(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<RecoveredHostAgentRouteV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let Some(route) = self.execution.load_agent_route(operation)? else {
            return Ok(None);
        };
        if route.peer_authority() != self.agent_peer.authority_binding
            || route.channel_binding() != self.agent_peer.channel_binding
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let (request, effect_request, route_binding) = route.into_recovery_parts();
        Ok(Some(RecoveredHostAgentRouteV1 {
            request,
            effect_request,
            route_binding,
        }))
    }

    /// Authenticates a cold-recovered outcome against its original route.
    ///
    /// This verifies the fixed protected peer key, channel, exact request,
    /// and durable effect identity. It does not redispatch or complete the
    /// portable effect; the Host must still settle that effect separately.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for absent or stale
    /// route custody, cross-request outcome fields, or signature failure.
    pub fn authenticate_recovered_agent_outcome_packet(
        &self,
        operation: &[u8; 16],
        packet: aos_sandbox_agent::SignedAgentOutcomePacketV1,
    ) -> Result<AuthenticatedRecoveredHostAgentOutcomeV1, DormantRuntimeExecutionOwnerErrorV1> {
        let route = self
            .recover_agent_route(operation)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let (outcome, signature) = packet.into_parts();
        let request = route.request();
        if outcome.session() != request.session()
            || outcome.sequence() != request.sequence()
            || outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let message =
            agent_outcome_signing_message_v1(self.agent_peer.channel_binding, request, &outcome);
        let key = VerifyingKey::from_bytes(&self.agent_peer.public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        key.verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        Ok(AuthenticatedRecoveredHostAgentOutcomeV1 {
            request: route.request,
            outcome,
            signature,
            effect_request: route.effect_request,
        })
    }

    /// Commits a signed guest packet under its original Host request custody.
    ///
    /// This independently verifies the fixed peer signature and exact route
    /// before append. An ambiguous error requires cold protected replay before
    /// the caller may accept another result for this operation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// a foreign packet, conflicting prior outcome, or uncertain durability.
    pub fn commit_signed_host_agent_outcome_packet(
        &mut self,
        operation: &[u8; 16],
        packet: &aos_sandbox_agent::SignedAgentOutcomePacketV1,
        observation_sequence: ObservationSequence,
        observation_commitment: ObjectDigest,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.commit_signed_agent_outcome_packet(
            operation,
            packet,
            observation_sequence,
            observation_commitment,
        )?;
        Ok(())
    }

    /// Recovers a committed signed guest result without contacting the guest.
    ///
    /// A missing record is not evidence that a prior append failed; callers
    /// must first cold-open the protected owner after an ambiguous outcome.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale currentness,
    /// corrupt custody, an invalid signature, or missing route evidence.
    pub fn recover_committed_host_agent_outcome(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<CommittedHostAgentOutcomeV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .load_signed_agent_outcome_packet(operation)?
            .map(|record| {
                let (packet, observation_sequence, observation_commitment) = record.into_parts();
                Ok(CommittedHostAgentOutcomeV1 {
                    authenticated: self
                        .authenticate_recovered_agent_outcome_packet(operation, packet)?,
                    observation_sequence,
                    observation_commitment,
                })
            })
            .transpose()
    }

    /// Reports whether a committed guest reply already owns a Host sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when fixed ownership is
    /// stale or protected outcome custody cannot be read canonically.
    pub fn committed_host_agent_outcome_at_observation_sequence(
        &self,
        sequence: ObservationSequence,
    ) -> Result<bool, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .committed_agent_outcome_at_observation_sequence(sequence)
            .map_err(Into::into)
    }

    /// Reports whether a previous agent route still owns unfinished work.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when fixed ownership is
    /// stale or protected route/effect custody cannot be read canonically.
    pub fn has_unsettled_host_agent_route(
        &self,
    ) -> Result<bool, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution
            .has_unsettled_agent_route()
            .map_err(Into::into)
    }

    /// Verifies a fixed-peer handshake and binds one exact AOSAGE request to an effect.
    ///
    /// Authorization and control requests must match the issued effect's closed
    /// operation and the capabilities signed into this agent session.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale fixed state,
    /// a foreign runtime/channel/session/request, or signature failure.
    fn authorize_coowned_agent_route(
        &self,
        handshake: &AgentHandshakeRequestV1,
        response: &AgentHandshakeResponseV1,
        agent_request: &AgentOperationRequestV1,
        effect: &DurableExecutionEffectV1,
    ) -> Result<ProtectedAgentRouteReservationV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let runtime = self.currentness.runtime().currentness();
        if handshake.runtime().sandbox() != runtime.sandbox()
            || handshake.runtime().incarnation() != runtime.incarnation()
            || handshake.runtime().assignment_epoch() != runtime.assignment_epoch()
            || handshake.runtime().assignment_digest() != runtime.assignment_digest()
            || handshake.runtime().desired_generation() != runtime.desired_generation()
            || handshake.runtime().namespace_generation() != runtime.namespace_generation()
            || handshake.runtime().payload_boot_id()
                != self.currentness.payload_boot_id().as_bytes()
            || handshake.host_channel_binding() != self.agent_peer.channel_binding
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let session =
            aos_sandbox_agent::AgentSessionBindingV1::derive(handshake, response.agent_instance())
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if response.session_binding() != session || agent_request.session() != session {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let message = agent_handshake_signing_message_v1(
            handshake,
            session,
            response.agent_instance(),
            response.features(),
        );
        let verifying_key = VerifyingKey::from_bytes(&self.agent_peer.public_key)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        verifying_key
            .verify_strict(
                &message,
                &Signature::from_bytes(response.challenge_signature()),
            )
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let admission = effect.admission();
        if effect.phase() != EffectPhaseV1::Issued {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let current = self.admission_currentness_for_accepted_output_v2(
            admission.execution(),
            OperationId::from_bytes(*admission.idempotency().operation().as_bytes()),
        )?;
        let admitted = admission.currentness();
        // The admission's ledger predecessor is historical after its commit;
        // replay validates that chain. The assignment and per-execution output
        // claim must still match the live owner before a guest route is issued.
        if !same_owner_and_accepted_output_v2(admitted, &current) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let specification = decode_execution_spec_v1(
            admission.specification_bytes(),
            DecodeLimits {
                maximum_bytes: admission.specification_bytes().len(),
                maximum_collection_items: 65_536,
                maximum_total_items: 262_144,
                maximum_byte_string_bytes: 15 * 1_048_576,
                maximum_text_bytes: 1_048_576,
                maximum_depth: 128,
            },
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        if specification.execution() != admission.execution()
            || execution_spec_digest_v1(&specification) != admission.specification_digest()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let inspection = BackendExecutionInspectionRequestV1::new(
            self.agent_peer.authority_binding,
            effect.issue().idempotency().operation(),
            effect.issue().sequence(),
            effect.issue().idempotency().request_digest(),
            admission.execution(),
            admission.specification_digest(),
            admission.admission_commitment(),
            *self.currentness.runtime(),
            self.currentness.payload_boot_id(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let features = response.features();
        let expected_operation = match effect.issue().operation() {
            EffectOperationV1::AuthorizeExecution
                if features.contains(AgentFeatureV1::ExecutionHandoff) =>
            {
                AgentExecutionOperationV1::Authorize {
                    execution: admission.execution(),
                    specification_bytes: admission.specification_bytes().to_vec(),
                    specification_digest: admission.specification_digest(),
                    admission_commitment: admission.admission_commitment(),
                    principal: specification.principal(),
                    audit: specification.audit(),
                }
            }
            EffectOperationV1::ResizeTerminal { rows, columns }
                if features.contains(AgentFeatureV1::TerminalResize) =>
            {
                AgentExecutionOperationV1::ResizeTerminal {
                    execution: admission.execution(),
                    rows,
                    columns,
                }
            }
            EffectOperationV1::Signal { signal_code }
                if features.contains(AgentFeatureV1::ExecutionSignal) =>
            {
                AgentExecutionOperationV1::Signal {
                    execution: admission.execution(),
                    signal_code,
                }
            }
            EffectOperationV1::Cancel => AgentExecutionOperationV1::Cancel {
                execution: admission.execution(),
            },
            EffectOperationV1::Observe
                if features.contains(AgentFeatureV1::ExecutionObservation) =>
            {
                AgentExecutionOperationV1::Observe {
                    execution: admission.execution(),
                }
            }
            _ => return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness),
        };
        if agent_request.operation_id().as_bytes()
            != effect.issue().idempotency().operation().as_bytes()
            || agent_request.operation() != &expected_operation
            || agent_request.backend_request_binding()
                != backend_execution_inspection_binding_v1(&inspection)
            || agent_request.request_commitment().as_bytes() == &[0; 32]
            || effect.issue().idempotency().request_digest().as_bytes() == &[0; 32]
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let route_binding = protected_agent_route_binding(
            effect.issue().idempotency().request_digest(),
            agent_request,
            self.agent_peer.authority_binding,
        );
        Ok(ProtectedAgentRouteReservationV1 {
            effect_request: effect.issue().idempotency().request_digest(),
            agent_request: agent_request.request_commitment(),
            route_binding,
        })
    }

    /// Consumes the one live-process dispatch permit for an authenticated route.
    ///
    /// No dispatch capability or backend request escapes this call. The
    /// retained fixed owner records consumption before the co-owned Host path
    /// projects the already-bound effect into its authenticated agent route.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// historical/replayed issuance, intervening journal mutation, or a record
    /// that is absent, corrupt, or not exactly Issued.
    fn consume_fresh_execution_for_coowned_route(
        &mut self,
        route: ProtectedAgentRouteReservationV1,
        agent_request: &AgentOperationRequestV1,
        effect: &DurableExecutionEffectV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let expected_route = protected_agent_route_binding(
            effect.issue().idempotency().request_digest(),
            agent_request,
            self.agent_peer.authority_binding,
        );
        if route.effect_request != effect.issue().idempotency().request_digest()
            || route.agent_request != agent_request.request_commitment()
            || route.route_binding != expected_route
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let record = ProtectedAgentRouteRecordV1::new(
            effect,
            agent_request.clone(),
            self.agent_peer.authority_binding,
            self.agent_peer.channel_binding,
        )?;
        if record.route_binding() != route.route_binding {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
        let permit = self.execution.prepare_dispatch(effect)?;
        self.execution.consume_dispatch(permit, record)?;
        Ok(())
    }

    /// Validates an AOSAGE authorization or control route and consumes fresh dispatch.
    ///
    /// The intermediate reservation and store dispatch permit remain private
    /// to this fixed-owner method, so neither can be redirected or consumed by
    /// a second backend/agent path.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale fixed state,
    /// foreign handshake/session/request inputs, historical issuance, or an
    /// intervening protected journal mutation.
    pub fn consume_fresh_execution_for_authenticated_agent_route(
        &mut self,
        handshake: &AgentHandshakeRequestV1,
        response: &AgentHandshakeResponseV1,
        agent_request: &AgentOperationRequestV1,
        effect: &DurableExecutionEffectV1,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        let route =
            self.authorize_coowned_agent_route(handshake, response, agent_request, effect)?;
        self.consume_fresh_execution_for_coowned_route(route, agent_request, effect)
    }

    /// Applies one closed recovery decision without dispatching an effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// invalid inventory/evidence, or durable transition failure.
    pub fn apply_recovery(
        &mut self,
        snapshot: JournalRecoveryV1,
        inventory: Option<BackendExecutionInventoryV1>,
    ) -> Result<AppliedExecutionRecoveryV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        apply_execution_recovery_v1(&mut self.execution, snapshot, inventory).map_err(Into::into)
    }

    /// Commits operation-specific terminal evidence after currentness recheck.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// substituted evidence, phase conflict, or protected durability failure.
    pub fn commit_verified_completion(
        &mut self,
        effect: &DurableExecutionEffectV1,
        evidence: &JournalExecutionCompletionV1,
    ) -> Result<
        aos_sandbox_core::runtime_backend::ExecutionEffectTransitionV1<
            ExecutionJournalRecoveryTokenV1,
        >,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        self.validate_current()?;
        self.execution
            .commit_verified_completion(effect, evidence)
            .map_err(Into::into)
    }

    /// Resolves an ambiguous terminal commit without dispatching another effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// foreign recovery authority, corrupt replay, or receipt mismatch.
    pub fn recover_verified_completion(
        &mut self,
        effect: &DurableExecutionEffectV1,
        evidence: &JournalExecutionCompletionV1,
        token: ExecutionJournalRecoveryTokenV1,
    ) -> Result<
        aos_sandbox_core::runtime_backend::ExecutionEffectTransitionV1<
            ExecutionJournalRecoveryTokenV1,
        >,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        self.validate_current()?;
        self.execution
            .recover_verified_completion(effect, evidence, token)
            .map_err(Into::into)
    }

    /// Persists a checkpoint candidate only after protected full-history replay.
    ///
    /// # Errors
    ///
    /// Returns [`AgentCheckpointError`] for stale currentness, a projection
    /// mismatch, sequence conflict, corrupt state, or unavailable durability.
    pub(super) fn commit_agent_checkpoint(
        &mut self,
        candidate: &AgentCheckpointCandidateV1,
    ) -> Result<AuthenticatedJournalAgentCheckpointV1, AgentCheckpointError> {
        self.validate_current()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        self.agent.commit_checkpoint(candidate)
    }

    /// Loads the authenticated newest agent checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AgentCheckpointError`] for stale currentness or malformed,
    /// unavailable, rolled-back, or unauthenticated protected state.
    pub(super) fn load_agent_checkpoint(
        &mut self,
    ) -> Result<Option<AuthenticatedJournalAgentCheckpointV1>, AgentCheckpointError> {
        self.validate_current()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        self.agent.load_checkpoint()
    }

    pub(super) fn next_agent_checkpoint_sequence(&self) -> Result<u64, JournalAgentStoreError> {
        self.agent.next_checkpoint_sequence()
    }

    pub(super) fn next_agent_handshake_checkpoint_sequence(
        &self,
    ) -> Result<u64, JournalAgentStoreError> {
        self.agent.next_handshake_checkpoint_sequence()
    }

    fn validate_current(&self) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        let peer_fence_bytes = self
            .peer_fence
            .map(HostCurrentnessFenceV1::encode)
            .transpose()?;
        if self.peer_authority.snapshot()?.sequence() != self.protected_sequence
            || self.peer_authority.get(PEER_CURRENT_KEY)? != Some(self.peer_record.as_slice())
            || self.peer_authority.get(CURRENTNESS_KEY)? != Some(self.currentness_record.as_slice())
            || self.peer_authority.get(CAPABILITIES_KEY)? != Some(self.capability_record.as_slice())
            || self.peer_authority.get(HOST_EVIDENCE_KEY)?
                != Some(self.host_evidence_record.as_slice())
            || self.peer_authority.get(PLAN_CATALOG_KEY)? != Some(self.plan_record.as_slice())
            || self.peer_authority.get(HOST_CURRENTNESS_FENCE_KEY)?
                != peer_fence_bytes.as_ref().map(|bytes| bytes.as_slice())
            || self.lifecycle_authority.get(LIFECYCLE_HEAD_KEY)?
                != Some(encode_lifecycle_head(self.lifecycle_head).as_slice())
            || self.lifecycle_authority.get(LIFECYCLE_ISSUE_KEY)? != self.lifecycle_issue.as_deref()
            || !self.lifecycle_terminals_are_current()?
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        validate_host_currentness_pair_v1(
            self.peer_fence,
            self.execution.load_host_execution_fence_v1()?,
            self.execution_store_binding,
        )?;
        Ok(())
    }

    fn lifecycle_terminals_are_current(&self) -> Result<bool, DormantRuntimeExecutionOwnerErrorV1> {
        let mut seen = 0usize;
        for (key, value) in self.lifecycle_authority.records()? {
            if key == LIFECYCLE_HEAD_KEY || key == LIFECYCLE_ISSUE_KEY {
                continue;
            }
            let operation = terminal_operation_from_key(key)?;
            if self.lifecycle_terminals.get(&operation).map(Vec::as_slice) != Some(value) {
                return Ok(false);
            }
            seen = seen
                .checked_add(1)
                .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        }
        Ok(seen == self.lifecycle_terminals.len())
    }
}

impl ExecutionAdmissionStore for DormantRuntimeExecutionClaimV1<'_> {
    type RecoveryToken = ExecutionJournalRecoveryTokenV1;

    fn commit_execution_admission(
        &mut self,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError> {
        self.validate_admission_draft_currentness_v2(draft)?;
        self.execution.commit_execution_admission(draft)
    }

    fn recover_execution_admission(
        &mut self,
        token: Self::RecoveryToken,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError> {
        self.validate_admission_draft_currentness_v2(draft)?;
        self.execution.recover_execution_admission(token, draft)
    }
}

impl ExecutionEffectStore for DormantRuntimeExecutionClaimV1<'_> {
    type RecoveryToken = ExecutionJournalRecoveryTokenV1;

    fn commit_pending_effect(
        &mut self,
        admission: &AdmittedExecutionV1,
        issue: &EffectIssueV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .commit_pending_effect(admission, issue, expected_record)
    }

    fn commit_effect_issued(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution.commit_effect_issued(effect, expected_record)
    }

    fn commit_effect_indeterminate(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .commit_effect_indeterminate(effect, expected_record)
    }

    fn commit_effect_complete(
        &mut self,
        effect: &DurableExecutionEffectV1,
        completion: &EffectCompletionV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .commit_effect_complete(effect, completion, expected_record)
    }

    fn recover_effect_transition(
        &mut self,
        token: Self::RecoveryToken,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .recover_effect_transition(token, expected_record)
    }
}

impl AgentOperationCas for DormantRuntimeExecutionClaimV1<'_> {
    fn reserve_operation(
        &mut self,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentReservationStoreTransitionV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.reserve_operation(request)
    }

    fn commit_operation_outcome(
        &mut self,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.commit_operation_outcome(reservation, outcome)
    }
}

impl AgentOperationRecoveryCas for DormantRuntimeExecutionClaimV1<'_> {
    fn recover_reservation(
        &mut self,
        token: &AgentReservationRecoveryTokenV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredReservationV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.recover_reservation(token, request)
    }

    fn recover_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredOperationV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.recover_operation(reservation, request)
    }

    fn recover_outcome_commit(
        &mut self,
        token: &AgentOutcomeRecoveryTokenV1,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentRecoveredOutcomeCommitV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent
            .recover_outcome_commit(token, reservation, outcome)
    }

    fn resolve_reserved_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
        authenticated: AuthenticatedRecoveredAgentOutcomeV1,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent
            .resolve_reserved_operation(reservation, request, authenticated)
    }
}

struct ResolvedOwnerCurrentnessV1 {
    currentness: AdmissionCurrentnessV1,
    protected_plan: ResolvedRuntimePlanV1,
    backend_capabilities: BackendCapabilitiesV1,
    agent_peer: ProtectedRuntimeAgentPeerV1,
    host_verifier: ProtectedRuntimeHostVerifierV1,
    execution_store_binding: ObjectDigest,
    agent_store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    lifecycle_store_binding: ObjectDigest,
}

fn encode_runtime_owner_peer_records(
    provisioning: &DormantRuntimeExecutionProvisioningV1,
) -> Result<RuntimeOwnerPeerRecordsV1, DormantRuntimeExecutionOwnerErrorV1> {
    let currentness = provisioning.runtime.currentness();
    let mut peer = Vec::with_capacity(PEER_BYTES);
    peer.extend_from_slice(PEER_MAGIC);
    peer.extend_from_slice(&provisioning.agent_public_key);
    peer.extend_from_slice(currentness.sandbox().as_bytes());
    peer.extend_from_slice(currentness.incarnation().as_bytes());
    peer.extend_from_slice(currentness.node().as_bytes());
    peer.extend_from_slice(&currentness.assignment_epoch().get().to_be_bytes());
    peer.extend_from_slice(currentness.assignment_digest().as_bytes());
    peer.extend_from_slice(&currentness.desired_generation().get().to_be_bytes());
    peer.extend_from_slice(&currentness.namespace_generation().get().to_be_bytes());
    peer.extend_from_slice(provisioning.runtime.plan_commitment().as_bytes());
    peer.extend_from_slice(provisioning.runtime.handle().as_bytes());
    peer.extend_from_slice(provisioning.payload_boot_id.as_bytes());
    peer.extend_from_slice(provisioning.agent_channel_binding.as_bytes());
    peer.extend_from_slice(&provisioning.next_observation_sequence.get().to_be_bytes());
    append_record_digest(&mut peer);

    let mut currentness_record = Vec::with_capacity(CURRENTNESS_BYTES);
    currentness_record.extend_from_slice(CURRENTNESS_MAGIC);
    currentness_record.extend_from_slice(provisioning.backend_probe.backend_build().as_bytes());
    currentness_record
        .extend_from_slice(&provisioning.backend_probe.probe_epoch().get().to_be_bytes());
    currentness_record.extend_from_slice(provisioning.backend_probe.protected_context().as_bytes());
    currentness_record.extend_from_slice(provisioning.resource_ledger.as_bytes());
    currentness_record.extend_from_slice(provisioning.output_reservation.as_bytes());
    append_record_digest(&mut currentness_record);

    let capabilities = encode_capability_record(&provisioning.backend_capabilities)?;

    let mut host_evidence = Vec::with_capacity(HOST_EVIDENCE_BYTES);
    host_evidence.extend_from_slice(HOST_EVIDENCE_MAGIC);
    host_evidence.extend_from_slice(&provisioning.host_public_key);
    host_evidence.extend_from_slice(provisioning.host_trust_context.as_bytes());
    host_evidence.extend_from_slice(provisioning.host_channel_binding.as_bytes());
    host_evidence.extend_from_slice(&provisioning.host_boot_id);
    append_record_digest(&mut host_evidence);

    let plan_catalog = encode_plan_catalog_record(&provisioning.protected_plan)?;

    Ok(RuntimeOwnerPeerRecordsV1 {
        peer,
        currentness: currentness_record,
        capabilities,
        host_evidence,
        plan_catalog,
    })
}

fn encode_capability_record(
    capabilities: &BackendCapabilitiesV1,
) -> Result<Vec<u8>, DormantRuntimeExecutionOwnerErrorV1> {
    let count = u8::try_from(capabilities.as_slice().len())
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    if count > 11 {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }

    let mut bytes = Vec::with_capacity(CAPABILITIES_BYTES);
    bytes.extend_from_slice(CAPABILITIES_MAGIC);
    bytes.push(count);
    bytes.extend(
        capabilities
            .as_slice()
            .iter()
            .map(|capability| *capability as u8),
    );
    bytes.resize(20, 0);
    append_record_digest(&mut bytes);
    Ok(bytes)
}

fn encode_plan_catalog_record(
    plan: &ResolvedRuntimePlanV1,
) -> Result<Vec<u8>, DormantRuntimeExecutionOwnerErrorV1> {
    let count = u8::try_from(plan.required_capabilities().as_slice().len())
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    if count > 11 {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }

    let mut bytes = Vec::with_capacity(PLAN_CATALOG_BYTES);
    bytes.extend_from_slice(PLAN_CATALOG_MAGIC);
    bytes.push(count);
    bytes.extend(
        plan.required_capabilities()
            .as_slice()
            .iter()
            .map(|capability| *capability as u8),
    );
    bytes.resize(24, 0);
    bytes.extend_from_slice(plan.storage_root().as_bytes());
    bytes.extend_from_slice(plan.attachment_set().as_bytes());
    bytes.extend_from_slice(plan.network().as_bytes());
    bytes.extend_from_slice(plan.runtime_profile().as_bytes());
    bytes.extend_from_slice(plan.plan_commitment().as_bytes());
    append_record_digest(&mut bytes);
    Ok(bytes)
}

fn append_record_digest(bytes: &mut Vec<u8>) {
    let checksum = digest(bytes);
    bytes.extend_from_slice(checksum.as_bytes());
}

fn runtime_owner_peer_transaction(
    records: &RuntimeOwnerPeerRecordsV1,
) -> Result<JournalTransaction, DormantRuntimeExecutionOwnerErrorV1> {
    let commitment = runtime_owner_peer_record_set_commitment(records);
    let transaction_id = commitment.as_bytes()[..16]
        .try_into()
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    JournalTransaction::new(
        transaction_id,
        vec![
            JournalRecord::put(
                RecordNamespace::HostExecution,
                PEER_CURRENT_KEY.to_vec(),
                records.peer.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::HostExecution,
                CURRENTNESS_KEY.to_vec(),
                records.currentness.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::HostExecution,
                CAPABILITIES_KEY.to_vec(),
                records.capabilities.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::HostExecution,
                HOST_EVIDENCE_KEY.to_vec(),
                records.host_evidence.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::HostExecution,
                PLAN_CATALOG_KEY.to_vec(),
                records.plan_catalog.clone(),
            ),
        ],
    )
    .map_err(Into::into)
}

fn authenticate_runtime_owner_peer_records(
    authority: &ProtectedJournalAuthority<'_>,
    records: &RuntimeOwnerPeerRecordsV1,
) -> Result<DormantRuntimeExecutionProvisioningReceiptV1, DormantRuntimeExecutionOwnerErrorV1> {
    let expected = [
        (PEER_CURRENT_KEY, records.peer.as_slice()),
        (CURRENTNESS_KEY, records.currentness.as_slice()),
        (CAPABILITIES_KEY, records.capabilities.as_slice()),
        (HOST_EVIDENCE_KEY, records.host_evidence.as_slice()),
        (PLAN_CATALOG_KEY, records.plan_catalog.as_slice()),
    ];
    if authority.records()?.count() != expected.len() {
        return Err(DormantRuntimeExecutionOwnerErrorV1::ProvisioningConflict);
    }
    for (key, value) in expected {
        if authority.get(key)? != Some(value) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::ProvisioningConflict);
        }
    }

    let journal_sequence = authority.snapshot()?.sequence();
    resolve_currentness(
        journal_sequence,
        &records.peer,
        &records.currentness,
        &records.capabilities,
        &records.host_evidence,
        &records.plan_catalog,
    )?;
    Ok(provisioning_receipt(journal_sequence, records))
}

fn provisioning_receipt(
    journal_sequence: u64,
    records: &RuntimeOwnerPeerRecordsV1,
) -> DormantRuntimeExecutionProvisioningReceiptV1 {
    DormantRuntimeExecutionProvisioningReceiptV1 {
        journal_sequence,
        record_set_commitment: runtime_owner_peer_record_set_commitment(records),
    }
}

fn runtime_owner_peer_record_set_commitment(records: &RuntimeOwnerPeerRecordsV1) -> ObjectDigest {
    hash_parts(
        b"aos.sandbox.runtime-execution.peer-record-set.v1\0",
        &[
            records.peer.as_slice(),
            records.currentness.as_slice(),
            records.capabilities.as_slice(),
            records.host_evidence.as_slice(),
            records.plan_catalog.as_slice(),
        ],
    )
}

fn resolve_currentness(
    protected_sequence: u64,
    peer: &[u8],
    currentness: &[u8],
    capabilities: &[u8],
    host_evidence: &[u8],
    plan_catalog: &[u8],
) -> Result<ResolvedOwnerCurrentnessV1, DormantRuntimeExecutionOwnerErrorV1> {
    validate_record(peer, PEER_MAGIC, PEER_BYTES)?;
    validate_record(currentness, CURRENTNESS_MAGIC, CURRENTNESS_BYTES)?;
    validate_record(capabilities, CAPABILITIES_MAGIC, CAPABILITIES_BYTES)?;
    validate_record(host_evidence, HOST_EVIDENCE_MAGIC, HOST_EVIDENCE_BYTES)?;
    validate_record(plan_catalog, PLAN_CATALOG_MAGIC, PLAN_CATALOG_BYTES)?;

    let capability_count = usize::from(capabilities[8]);
    if capability_count > 11
        || capabilities[9 + capability_count..20]
            .iter()
            .any(|value| *value != 0)
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let backend_capabilities = BackendCapabilitiesV1::new(
        capabilities[9..9 + capability_count]
            .iter()
            .map(|code| decode_capability(*code))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;

    let public_key = read_array(peer, 8)?;
    if public_key == [0; 32] {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let sandbox = SandboxId::from_bytes(read_array(peer, 40)?);
    let incarnation = IncarnationId::from_bytes(read_array(peer, 56)?);
    let node = NodeId::from_bytes(read_array(peer, 72)?);
    let runtime_currentness = RuntimeCurrentnessV1::new(
        sandbox,
        incarnation,
        node,
        AssignmentEpoch::new(read_u64(peer, 88)?),
        ObjectDigest::from_bytes(read_array(peer, 96)?),
        DesiredGeneration::new(read_u64(peer, 128)?),
        NamespaceGeneration::new(read_u64(peer, 136)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let runtime = RuntimeHandleCommitmentV1::new(
        runtime_currentness,
        ObjectDigest::from_bytes(read_array(peer, 144)?),
        ObjectDigest::from_bytes(read_array(peer, 176)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let payload_boot_id = PayloadBootId::new(read_array(peer, 208)?)
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let channel_binding = ObjectDigest::from_bytes(read_array(peer, 224)?);
    if channel_binding.as_bytes() == &[0; 32] {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let next_observation_sequence =
        aos_sandbox_core::ObservationSequence::new(read_u64(peer, 256)?);
    if next_observation_sequence.get() == 0 || next_observation_sequence.get() == u64::MAX {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }

    let peer_digest = ObjectDigest::from_bytes(read_array(peer, PEER_BYTES - 32)?);
    let protected_peer_binding = hash_parts(
        b"aos.sandbox.host.agent-peer-authority.v1\0",
        &[
            &protected_sequence.to_be_bytes(),
            peer_digest.as_bytes(),
            &public_key,
            runtime.handle().as_bytes(),
            channel_binding.as_bytes(),
        ],
    );
    let trust_context = hash_parts(
        b"aos.sandbox.host.agent-peer-evidence-trust.v1\0",
        &[
            runtime.handle().as_bytes(),
            protected_peer_binding.as_bytes(),
        ],
    );
    let recovery_authority_binding =
        backend_evidence_authority_binding_v1(public_key, trust_context, channel_binding);
    let host_public_key = read_array(host_evidence, 8)?;
    let host_trust_context = ObjectDigest::from_bytes(read_array(host_evidence, 40)?);
    let host_channel_binding = ObjectDigest::from_bytes(read_array(host_evidence, 72)?);
    let host_boot_id = read_array(host_evidence, 104)?;
    if host_public_key == [0; 32]
        || host_trust_context.as_bytes() == &[0; 32]
        || host_channel_binding.as_bytes() == &[0; 32]
        || host_boot_id == [0; 16]
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let host_authority_binding = backend_evidence_authority_binding_v1(
        host_public_key,
        host_trust_context,
        host_channel_binding,
    );
    if host_public_key == public_key
        || host_trust_context == trust_context
        || host_channel_binding == channel_binding
        || host_authority_binding == recovery_authority_binding
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }

    let backend_probe = BackendProbeCurrentnessV1::new(
        node,
        ObjectDigest::from_bytes(read_array(currentness, 8)?),
        Revision::new(read_u64(currentness, 40)?),
        ObjectDigest::from_bytes(read_array(currentness, 48)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let currentness_digest = ObjectDigest::from_bytes(read_array(currentness, 144)?);
    let currentness_value = AdmissionCurrentnessV1::new(
        runtime,
        payload_boot_id,
        backend_probe,
        recovery_authority_binding,
        ObjectDigest::from_bytes(read_array(currentness, 80)?),
        ObjectDigest::from_bytes(read_array(currentness, 112)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let protected_plan = decode_protected_plan(plan_catalog, runtime_currentness)?;
    if protected_plan.currentness() != runtime.currentness()
        || protected_plan.plan_commitment() != runtime.plan_commitment()
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    backend_capabilities
        .satisfies(protected_plan.required_capabilities())
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;

    Ok(ResolvedOwnerCurrentnessV1 {
        currentness: currentness_value,
        protected_plan,
        backend_capabilities,
        agent_peer: ProtectedRuntimeAgentPeerV1 {
            public_key,
            trust_context,
            channel_binding,
            authority_binding: recovery_authority_binding,
            next_observation_sequence,
        },
        host_verifier: ProtectedRuntimeHostVerifierV1 {
            public_key: host_public_key,
            trust_context: host_trust_context,
            channel_binding: host_channel_binding,
            authority_binding: host_authority_binding,
            boot_id: host_boot_id,
        },
        execution_store_binding: hash_parts(
            b"aos.sandbox.runtime-execution.store-owner.v1\0",
            &[
                protected_peer_binding.as_bytes(),
                currentness_digest.as_bytes(),
                recovery_authority_binding.as_bytes(),
            ],
        ),
        agent_store_binding: hash_parts(
            b"aos.sandbox.runtime-execution.agent-store-owner.v1\0",
            &[
                protected_peer_binding.as_bytes(),
                currentness_digest.as_bytes(),
                recovery_authority_binding.as_bytes(),
            ],
        ),
        recovery_authority_binding,
        lifecycle_store_binding: hash_parts(
            b"aos.sandbox.runtime-execution.lifecycle-store-owner.v1\0",
            &[
                protected_peer_binding.as_bytes(),
                currentness_digest.as_bytes(),
                host_authority_binding.as_bytes(),
            ],
        ),
    })
}

/// Carries peer verifier inputs authenticated under one retained fixed-root claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedRuntimeAgentPeerV1 {
    public_key: [u8; 32],
    trust_context: ObjectDigest,
    channel_binding: ObjectDigest,
    authority_binding: ObjectDigest,
    next_observation_sequence: aos_sandbox_core::ObservationSequence,
}

impl ProtectedRuntimeAgentPeerV1 {
    /// Returns the protected peer public key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the protected evidence trust context.
    #[must_use]
    pub const fn trust_context(&self) -> ObjectDigest {
        self.trust_context
    }

    /// Returns the exact protected channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> ObjectDigest {
        self.channel_binding
    }

    /// Returns the derived evidence authority identity.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }
}

/// Carries Host-only verifier inputs authenticated by the fixed owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedRuntimeHostVerifierV1 {
    public_key: [u8; 32],
    trust_context: ObjectDigest,
    channel_binding: ObjectDigest,
    authority_binding: ObjectDigest,
    boot_id: [u8; 16],
}

impl ProtectedRuntimeHostVerifierV1 {
    /// Returns the protected Host evidence public key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the protected Host trust context.
    #[must_use]
    pub const fn trust_context(&self) -> ObjectDigest {
        self.trust_context
    }

    /// Returns the protected Host evidence channel.
    #[must_use]
    pub const fn channel_binding(&self) -> ObjectDigest {
        self.channel_binding
    }

    /// Returns the derived Host evidence authority identity.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Returns the protected Host boot identity fencing boottime evidence.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }
}

fn decode_capability(code: u8) -> Result<BackendCapabilityV1, DormantRuntimeExecutionOwnerErrorV1> {
    match code {
        1 => Ok(BackendCapabilityV1::PrivateUserNamespace),
        2 => Ok(BackendCapabilityV1::LiveMountAttachment),
        3 => Ok(BackendCapabilityV1::PrivateNetworking),
        4 => Ok(BackendCapabilityV1::CgroupFreeze),
        5 => Ok(BackendCapabilityV1::DurableStorageSnapshot),
        6 => Ok(BackendCapabilityV1::CheapFork),
        7 => Ok(BackendCapabilityV1::PortableRestore),
        8 => Ok(BackendCapabilityV1::BackendLocalCheckpoint),
        9 => Ok(BackendCapabilityV1::CrossNodeMigration),
        10 => Ok(BackendCapabilityV1::ExactExecutionEnvelope),
        11 => Ok(BackendCapabilityV1::AuthenticatedGuestAgent),
        _ => Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness),
    }
}

fn decode_protected_plan(
    bytes: &[u8],
    currentness: RuntimeCurrentnessV1,
) -> Result<ResolvedRuntimePlanV1, DormantRuntimeExecutionOwnerErrorV1> {
    let capability_count = usize::from(bytes[8]);
    if capability_count > 11
        || bytes[9 + capability_count..24]
            .iter()
            .any(|value| *value != 0)
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let required = RequiredBackendCapabilitiesV1::new(
        bytes[9..9 + capability_count]
            .iter()
            .map(|code| decode_capability(*code))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let plan = ResolvedRuntimePlanV1::new(
        currentness,
        required,
        ObjectDigest::from_bytes(read_array(bytes, 24)?),
        ObjectDigest::from_bytes(read_array(bytes, 56)?),
        ObjectDigest::from_bytes(read_array(bytes, 88)?),
        ObjectDigest::from_bytes(read_array(bytes, 120)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    if plan.plan_commitment() != ObjectDigest::from_bytes(read_array(bytes, 152)?) {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(plan)
}

fn open_execution_store<'journal>(
    journal: &'journal mut Journal,
    store_binding: ObjectDigest,
    admission_state: ProtectedExecutionAdmissionStateV1,
    agent_peer: ProtectedAgentRoutePeerV1,
    require_existing: bool,
) -> Result<JournalRuntimeExecutionStoreV1<'journal>, JournalRuntimeExecutionError> {
    let empty = {
        let authority = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RuntimeExecution,
        )?;
        authority.is_materialized_empty()?
    };
    if empty {
        // A retained HostState hold must not initialize a rolled-back Effect store.
        if require_existing {
            return Err(JournalRuntimeExecutionError::UninitializedStore);
        }
        JournalRuntimeExecutionStoreV1::initialize(
            journal,
            store_binding,
            admission_state,
            agent_peer,
        )
    } else {
        let store = JournalRuntimeExecutionStoreV1::claim(journal, store_binding, agent_peer)?;
        if store.load_admission_state()? != admission_state {
            return Err(JournalRuntimeExecutionError::InvalidBinding);
        }
        Ok(store)
    }
}

fn open_agent_store<'journal>(
    journal: &'journal mut Journal,
    store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    agent_public_key: [u8; 32],
    agent_channel_binding: ObjectDigest,
) -> Result<DormantJournalAgentStoreV1<'journal>, JournalAgentStoreError> {
    let empty = {
        let authority = journal.claim_protected_authority(RecordNamespace::Effect)?;
        authority.is_materialized_empty()?
    };
    if empty {
        DormantJournalAgentStoreV1::initialize(
            journal,
            store_binding,
            recovery_authority_binding,
            agent_public_key,
            agent_channel_binding,
        )
    } else {
        DormantJournalAgentStoreV1::claim(
            journal,
            store_binding,
            recovery_authority_binding,
            agent_public_key,
            agent_channel_binding,
        )
    }
}

fn open_lifecycle_store<'journal>(
    journal: &'journal mut Journal,
    store_binding: ObjectDigest,
    initial_observation: aos_sandbox_core::ObservationSequence,
    host_authority: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
) -> Result<
    (
        ProtectedJournalAuthority<'journal>,
        LifecycleHeadV1,
        Option<Vec<u8>>,
        BTreeMap<[u8; 16], Vec<u8>>,
    ),
    DormantRuntimeExecutionOwnerErrorV1,
> {
    let mut authority = journal.claim_protected_authority(RecordNamespace::HostExecution)?;
    if authority.is_materialized_empty()? {
        let head = LifecycleHeadV1 {
            next_lifecycle_sequence: 1,
            next_observation_sequence: initial_observation.get(),
            initial_observation_sequence: initial_observation.get(),
            store_binding,
        };
        let encoded = encode_lifecycle_head(head);
        let tx_digest = hash_parts(
            b"aos.sandbox.runtime-execution.lifecycle-genesis.v1\0",
            &[encoded.as_slice()],
        );
        let transaction_id = tx_digest.as_bytes()[..16]
            .try_into()
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::HostExecution,
                LIFECYCLE_HEAD_KEY.to_vec(),
                encoded,
            )],
        )?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        authority.commit(&transaction)?;
    }
    let head_bytes = authority
        .get(LIFECYCLE_HEAD_KEY)?
        .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let head = decode_lifecycle_head(head_bytes, store_binding)?;
    let issue = authority.get(LIFECYCLE_ISSUE_KEY)?.map(ToOwned::to_owned);
    let mut lifecycle_sequences = std::collections::BTreeSet::new();
    if let Some(value) = issue.as_deref() {
        validate_lifecycle_issue(
            value,
            head.next_lifecycle_sequence,
            host_authority,
            runtime.plan_commitment(),
            runtime.handle(),
        )?;
        lifecycle_sequences.insert(read_u64(value, 24)?);
    }
    let mut terminals = BTreeMap::new();
    let mut observation_sequences = std::collections::BTreeSet::new();
    for (key, value) in authority.records()? {
        if key == LIFECYCLE_HEAD_KEY || key == LIFECYCLE_ISSUE_KEY {
            continue;
        }
        let operation = terminal_operation_from_key(key)?;
        let terminal = decode_lifecycle_terminal(value)?;
        if terminal.operation.as_bytes() != &operation
            || terminal.authority != host_authority
            || terminal.currentness != runtime_currentness_commitment(runtime.currentness())
            || terminal.plan != runtime.plan_commitment()
            || terminal.handle != runtime.handle()
            || terminal.sequence.get() >= head.next_lifecycle_sequence
            || terminal.observation_sequence >= head.next_observation_sequence
            || (terminal.observation_sequence != 0
                && terminal.observation_sequence < head.initial_observation_sequence)
            || (terminal.observation_sequence != 0
                && !observation_sequences.insert(terminal.observation_sequence))
            || !lifecycle_sequences.insert(terminal.sequence.get())
            || terminals.insert(operation, value.to_vec()).is_some()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
        }
    }
    let expected_lifecycle_count = usize::try_from(head.next_lifecycle_sequence - 1)
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    if lifecycle_sequences.len() != expected_lifecycle_count
        || lifecycle_sequences
            .iter()
            .copied()
            .ne(1..head.next_lifecycle_sequence)
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    validate_lifecycle_history(&terminals, issue.as_deref())?;
    Ok((authority, head, issue, terminals))
}

fn validate_lifecycle_history(
    terminals: &BTreeMap<[u8; 16], Vec<u8>>,
    issue: Option<&[u8]>,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    let mut ordered = terminals
        .values()
        .map(|bytes| decode_lifecycle_terminal(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    ordered.sort_by_key(|terminal| terminal.sequence.get());

    let mut predecessor: Option<LifecycleTerminalV1> = None;
    for terminal in ordered {
        validate_lifecycle_predecessor(predecessor.as_ref(), terminal.action, terminal.handle)?;
        predecessor = Some(terminal);
    }
    if let Some(bytes) = issue {
        let issue = decode_lifecycle_issue(bytes)?;
        let handle = issue.handle.unwrap_or(ObjectDigest::from_bytes([0; 32]));
        validate_lifecycle_predecessor(predecessor.as_ref(), issue.action, handle)?;
    }
    Ok(())
}

fn validate_lifecycle_predecessor(
    predecessor: Option<&LifecycleTerminalV1>,
    action: BackendLifecycleOperationV1,
    handle: ObjectDigest,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    let Some(predecessor) = predecessor else {
        return if action == BackendLifecycleOperationV1::Prepare {
            Ok(())
        } else {
            Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)
        };
    };
    let same_handle = predecessor.handle == handle;
    let valid = match action {
        BackendLifecycleOperationV1::Prepare => false,
        BackendLifecycleOperationV1::Start => {
            same_handle
                && predecessor.action == BackendLifecycleOperationV1::Prepare
                && predecessor.result_phase == runtime_phase_code(BackendRuntimePhaseV1::Prepared)
        }
        BackendLifecycleOperationV1::Freeze => {
            same_handle
                && predecessor.result_phase == runtime_phase_code(BackendRuntimePhaseV1::Running)
        }
        BackendLifecycleOperationV1::Thaw => {
            same_handle
                && predecessor.result_phase == runtime_phase_code(BackendRuntimePhaseV1::Frozen)
        }
        BackendLifecycleOperationV1::Stop => {
            same_handle
                && matches!(
                    predecessor.result_phase,
                    phase if phase == runtime_phase_code(BackendRuntimePhaseV1::Running)
                        || phase == runtime_phase_code(BackendRuntimePhaseV1::Frozen)
                )
        }
        BackendLifecycleOperationV1::Kill => {
            same_handle
                && predecessor.action == BackendLifecycleOperationV1::Stop
                && predecessor.observation_sequence == 0
                && predecessor.result_phase == runtime_phase_code(BackendRuntimePhaseV1::Stopping)
        }
        BackendLifecycleOperationV1::Destroy => {
            same_handle
                && matches!(
                    predecessor.result_phase,
                    phase if phase == runtime_phase_code(BackendRuntimePhaseV1::Prepared)
                        || phase == runtime_phase_code(BackendRuntimePhaseV1::Stopped)
                        || phase == runtime_phase_code(BackendRuntimePhaseV1::Absent)
                )
        }
        BackendLifecycleOperationV1::Inspect => same_handle,
    };
    if valid {
        Ok(())
    } else {
        Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)
    }
}

fn encode_lifecycle_head(head: LifecycleHeadV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LIFECYCLE_HEAD_BYTES);
    bytes.extend_from_slice(LIFECYCLE_HEAD_MAGIC);
    bytes.extend_from_slice(&head.next_lifecycle_sequence.to_be_bytes());
    bytes.extend_from_slice(&head.next_observation_sequence.to_be_bytes());
    bytes.extend_from_slice(&head.initial_observation_sequence.to_be_bytes());
    bytes.extend_from_slice(head.store_binding.as_bytes());
    let checksum = digest(&bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    bytes
}

fn decode_lifecycle_head(
    bytes: &[u8],
    store_binding: ObjectDigest,
) -> Result<LifecycleHeadV1, DormantRuntimeExecutionOwnerErrorV1> {
    validate_record(bytes, LIFECYCLE_HEAD_MAGIC, LIFECYCLE_HEAD_BYTES)?;
    let head = LifecycleHeadV1 {
        next_lifecycle_sequence: read_u64(bytes, 8)?,
        next_observation_sequence: read_u64(bytes, 16)?,
        initial_observation_sequence: read_u64(bytes, 24)?,
        store_binding: ObjectDigest::from_bytes(read_array(bytes, 32)?),
    };
    if head.next_lifecycle_sequence == 0
        || head.next_lifecycle_sequence == u64::MAX
        || head.next_observation_sequence == 0
        || head.next_observation_sequence == u64::MAX
        || head.initial_observation_sequence == 0
        || head.initial_observation_sequence > head.next_observation_sequence
        || head.store_binding != store_binding
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(head)
}

#[allow(clippy::too_many_arguments)]
fn encode_lifecycle_issue(
    operation: &[u8; 16],
    sequence: u64,
    action_code: u8,
    phase_code: u8,
    plan: ObjectDigest,
    handle: Option<ObjectDigest>,
    request: ObjectDigest,
    authority: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LIFECYCLE_ISSUE_BYTES);
    bytes.extend_from_slice(LIFECYCLE_ISSUE_MAGIC);
    bytes.extend_from_slice(operation);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.push(action_code);
    bytes.push(phase_code);
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(plan.as_bytes());
    bytes.extend_from_slice(
        handle
            .unwrap_or(ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    bytes.extend_from_slice(request.as_bytes());
    bytes.extend_from_slice(authority.as_bytes());
    let checksum = digest(&bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    bytes
}

fn validate_lifecycle_issue(
    bytes: &[u8],
    next_lifecycle_sequence: u64,
    host_authority: ObjectDigest,
    protected_plan: ObjectDigest,
    protected_handle: ObjectDigest,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    validate_record(bytes, LIFECYCLE_ISSUE_MAGIC, LIFECYCLE_ISSUE_BYTES)?;
    let action_code = bytes[32];
    let handle_is_zero = bytes[72..104] == [0; 32];
    if read_array::<16>(bytes, 8)? == [0; 16]
        || read_u64(bytes, 24)? == 0
        || read_u64(bytes, 24)? == u64::MAX
        || read_u64(bytes, 24)?.checked_add(1) != Some(next_lifecycle_sequence)
        || !(1..=8).contains(&action_code)
        || !matches!(bytes[33], 1 | 2)
        || bytes[34..40] != [0; 6]
        || bytes[40..72] == [0; 32]
        || bytes[40..72] != *protected_plan.as_bytes()
        || bytes[104..136] == [0; 32]
        || bytes[136..168] == [0; 32]
        || bytes[136..168] != *host_authority.as_bytes()
        || (action_code == 1) != handle_is_zero
        || (!handle_is_zero && bytes[72..104] != *protected_handle.as_bytes())
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(())
}

fn decode_lifecycle_issue(
    bytes: &[u8],
) -> Result<ProtectedLifecycleIssueV1, DormantRuntimeExecutionOwnerErrorV1> {
    let action = match bytes.get(32).copied() {
        Some(1) => BackendLifecycleOperationV1::Prepare,
        Some(2) => BackendLifecycleOperationV1::Start,
        Some(3) => BackendLifecycleOperationV1::Freeze,
        Some(4) => BackendLifecycleOperationV1::Thaw,
        Some(5) => BackendLifecycleOperationV1::Stop,
        Some(6) => BackendLifecycleOperationV1::Destroy,
        Some(7) => BackendLifecycleOperationV1::Inspect,
        Some(8) => BackendLifecycleOperationV1::Kill,
        _ => return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness),
    };
    let phase = bytes
        .get(33)
        .copied()
        .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let raw_handle = read_array::<32>(bytes, 72)?;
    let handle = (raw_handle != [0; 32]).then(|| ObjectDigest::from_bytes(raw_handle));

    Ok(ProtectedLifecycleIssueV1 {
        operation: BackendOperationIdV1::new(read_array(bytes, 8)?)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
        sequence: BackendOperationSequenceV1::new(read_u64(bytes, 24)?)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
        action,
        crossed: phase == 2,
        plan: ObjectDigest::from_bytes(read_array(bytes, 40)?),
        handle,
        request: ObjectDigest::from_bytes(read_array(bytes, 104)?),
    })
}

fn lifecycle_terminal_key(operation: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(LIFECYCLE_TERMINAL_PREFIX.len() + operation.len());
    key.extend_from_slice(LIFECYCLE_TERMINAL_PREFIX);
    key.extend_from_slice(operation);
    key
}

fn terminal_operation_from_key(
    key: &[u8],
) -> Result<[u8; 16], DormantRuntimeExecutionOwnerErrorV1> {
    if key.len() != LIFECYCLE_TERMINAL_PREFIX.len() + 16
        || !key.starts_with(LIFECYCLE_TERMINAL_PREFIX)
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    key[LIFECYCLE_TERMINAL_PREFIX.len()..]
        .try_into()
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)
}

fn encode_lifecycle_terminal(
    observation: &BackendRuntimeInspectionV1,
    host_authority: ObjectDigest,
) -> Vec<u8> {
    encode_lifecycle_terminal_row(LifecycleTerminalV1 {
        operation: observation.operation(),
        sequence: observation.operation_sequence(),
        action: observation.lifecycle_operation(),
        result_phase: runtime_phase_code(observation.phase()),
        plan: observation.commitment().plan_commitment(),
        handle: observation.commitment().handle(),
        request: observation.request_commitment(),
        observation_sequence: observation.sequence().get(),
        observation_commitment: observation.observation_commitment(),
        currentness: runtime_currentness_commitment(observation.commitment().currentness()),
        authority: host_authority,
    })
}

fn encode_lifecycle_terminal_row(terminal: LifecycleTerminalV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LIFECYCLE_TERMINAL_BYTES);
    bytes.extend_from_slice(LIFECYCLE_TERMINAL_MAGIC);
    bytes.extend_from_slice(terminal.operation.as_bytes());
    bytes.extend_from_slice(&terminal.sequence.get().to_be_bytes());
    bytes.push(terminal.action as u8);
    bytes.push(terminal.result_phase);
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(terminal.plan.as_bytes());
    bytes.extend_from_slice(terminal.handle.as_bytes());
    bytes.extend_from_slice(terminal.request.as_bytes());
    bytes.extend_from_slice(&terminal.observation_sequence.to_be_bytes());
    bytes.extend_from_slice(terminal.observation_commitment.as_bytes());
    bytes.extend_from_slice(terminal.currentness.as_bytes());
    bytes.extend_from_slice(terminal.authority.as_bytes());
    let checksum = digest(&bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    bytes
}

fn decode_lifecycle_terminal(
    bytes: &[u8],
) -> Result<LifecycleTerminalV1, DormantRuntimeExecutionOwnerErrorV1> {
    validate_record(bytes, LIFECYCLE_TERMINAL_MAGIC, LIFECYCLE_TERMINAL_BYTES)?;
    if bytes[34..40] != [0; 6] {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let action = decode_lifecycle_action(bytes[32])?;
    let result_phase = bytes[33];
    validate_terminal_phase(action, result_phase)?;
    let terminal = LifecycleTerminalV1 {
        operation: BackendOperationIdV1::new(read_array(bytes, 8)?)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
        sequence: BackendOperationSequenceV1::new(read_u64(bytes, 24)?)
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
        action,
        result_phase,
        plan: ObjectDigest::from_bytes(read_array(bytes, 40)?),
        handle: ObjectDigest::from_bytes(read_array(bytes, 72)?),
        request: ObjectDigest::from_bytes(read_array(bytes, 104)?),
        observation_sequence: read_u64(bytes, 136)?,
        observation_commitment: ObjectDigest::from_bytes(read_array(bytes, 144)?),
        currentness: ObjectDigest::from_bytes(read_array(bytes, 176)?),
        authority: ObjectDigest::from_bytes(read_array(bytes, 208)?),
    };
    let is_stop_supersession = terminal.action == BackendLifecycleOperationV1::Stop
        && terminal.result_phase == runtime_phase_code(BackendRuntimePhaseV1::Stopping);
    if terminal.handle.as_bytes() == &[0; 32]
        || terminal.request.as_bytes() == &[0; 32]
        || terminal.observation_sequence == u64::MAX
        || (terminal.observation_sequence == 0) != is_stop_supersession
        || terminal.observation_commitment.as_bytes() == &[0; 32]
        || terminal.currentness.as_bytes() == &[0; 32]
        || terminal.authority.as_bytes() == &[0; 32]
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(terminal)
}

fn decode_lifecycle_action(
    code: u8,
) -> Result<BackendLifecycleOperationV1, DormantRuntimeExecutionOwnerErrorV1> {
    match code {
        1 => Ok(BackendLifecycleOperationV1::Prepare),
        2 => Ok(BackendLifecycleOperationV1::Start),
        3 => Ok(BackendLifecycleOperationV1::Freeze),
        4 => Ok(BackendLifecycleOperationV1::Thaw),
        5 => Ok(BackendLifecycleOperationV1::Stop),
        6 => Ok(BackendLifecycleOperationV1::Destroy),
        7 => Ok(BackendLifecycleOperationV1::Inspect),
        8 => Ok(BackendLifecycleOperationV1::Kill),
        _ => Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness),
    }
}

fn runtime_phase_code(phase: BackendRuntimePhaseV1) -> u8 {
    match phase {
        BackendRuntimePhaseV1::Prepared => 1,
        BackendRuntimePhaseV1::Starting => 2,
        BackendRuntimePhaseV1::Running => 3,
        BackendRuntimePhaseV1::Frozen => 4,
        BackendRuntimePhaseV1::Stopping => 5,
        BackendRuntimePhaseV1::Stopped => 6,
        BackendRuntimePhaseV1::Failed => 7,
        BackendRuntimePhaseV1::Absent => 8,
    }
}

fn validate_terminal_phase(
    action: BackendLifecycleOperationV1,
    phase: u8,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    let valid = match action {
        BackendLifecycleOperationV1::Prepare => matches!(phase, 1 | 7 | 8),
        BackendLifecycleOperationV1::Start | BackendLifecycleOperationV1::Thaw => {
            matches!(phase, 3 | 7 | 8)
        }
        BackendLifecycleOperationV1::Freeze => matches!(phase, 4 | 7),
        BackendLifecycleOperationV1::Stop => matches!(phase, 5 | 6 | 8),
        BackendLifecycleOperationV1::Kill | BackendLifecycleOperationV1::Destroy => phase == 8,
        BackendLifecycleOperationV1::Inspect => (1..=8).contains(&phase),
    };
    if valid {
        Ok(())
    } else {
        Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)
    }
}

fn runtime_currentness_commitment(currentness: &RuntimeCurrentnessV1) -> ObjectDigest {
    hash_parts(
        b"aos.sandbox.runtime-execution.currentness.v1\0",
        &[
            currentness.sandbox().as_bytes(),
            currentness.incarnation().as_bytes(),
            currentness.node().as_bytes(),
            &currentness.assignment_epoch().get().to_be_bytes(),
            currentness.assignment_digest().as_bytes(),
            &currentness.desired_generation().get().to_be_bytes(),
            &currentness.namespace_generation().get().to_be_bytes(),
        ],
    )
}

fn lifecycle_request_commitment(
    action: BackendLifecycleOperationV1,
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    plan: ObjectDigest,
    handle: Option<ObjectDigest>,
) -> ObjectDigest {
    hash_parts(
        b"aos.sandbox.host.dormant-lifecycle-request.v1\0",
        &[
            &[action as u8],
            operation.as_bytes(),
            &sequence.get().to_be_bytes(),
            plan.as_bytes(),
            handle
                .unwrap_or(ObjectDigest::from_bytes([0; 32]))
                .as_bytes(),
        ],
    )
}

fn stop_request_commitment(
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    runtime: RuntimeHandleCommitmentV1,
    deadline: BackendStopDeadlineV1,
) -> ObjectDigest {
    hash_parts(
        b"aos.sandbox.host.dormant-stop-request.v1\0",
        &[
            operation.as_bytes(),
            &sequence.get().to_be_bytes(),
            runtime.plan_commitment().as_bytes(),
            runtime.handle().as_bytes(),
            &deadline.after_nanoseconds().to_be_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn forced_kill_request_commitment(
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    runtime: RuntimeHandleCommitmentV1,
    stop_request: ObjectDigest,
    host_boot_id: [u8; 16],
    stop_started_boottime_nanoseconds: u64,
    observed_boottime_nanoseconds: u64,
) -> ObjectDigest {
    hash_parts(
        b"aos.sandbox.host.dormant-forced-kill-request.v1\0",
        &[
            operation.as_bytes(),
            &sequence.get().to_be_bytes(),
            runtime.plan_commitment().as_bytes(),
            runtime.handle().as_bytes(),
            stop_request.as_bytes(),
            &host_boot_id,
            &stop_started_boottime_nanoseconds.to_be_bytes(),
            &observed_boottime_nanoseconds.to_be_bytes(),
        ],
    )
}

fn validate_record(
    bytes: &[u8],
    magic: &[u8; 8],
    length: usize,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    if bytes.len() != length || bytes.get(..8) != Some(magic.as_slice()) {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let expected = digest(
        bytes
            .get(..length - 32)
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
    );
    if bytes.get(length - 32..) != Some(expected.as_bytes().as_slice()) {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(())
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], DormantRuntimeExecutionOwnerErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DormantRuntimeExecutionOwnerErrorV1> {
    read_array(bytes, offset).map(u64::from_be_bytes)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn derive_accepted_output_currentness_v2(
    currentness: &AdmissionCurrentnessV1,
    state: &ProtectedExecutionAdmissionStateV1,
    claim: &RetainedClaim,
    execution: ExecutionId,
    create_operation: OperationId,
) -> Result<AdmissionCurrentnessV1, DormantRuntimeExecutionOwnerErrorV1> {
    if claim.execution != *execution.as_bytes()
        || claim.create_operation != *create_operation.as_bytes()
        || claim.assignment != currentness.runtime().currentness().assignment_digest()
        || state.authority_binding()
            != ProtectedExecutionAdmissionStateV1::new(currentness).authority_binding()
    {
        return Err(DormantRuntimeExecutionOwnerErrorV1::AcceptedOutputClaimMismatch);
    }

    AdmissionCurrentnessV1::new(
        *currentness.runtime(),
        currentness.payload_boot_id(),
        *currentness.backend_probe(),
        currentness.authority_context(),
        state.resource_ledger(),
        claim.record_digest,
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::AcceptedOutputClaimMismatch)
}

fn same_owner_and_accepted_output_v2(
    admitted: &AdmissionCurrentnessV1,
    current: &AdmissionCurrentnessV1,
) -> bool {
    admitted.runtime() == current.runtime()
        && admitted.payload_boot_id() == current.payload_boot_id()
        && admitted.backend_probe() == current.backend_probe()
        && admitted.authority_context() == current.authority_context()
        && admitted.output_reservation() == current.output_reservation()
}

/// Reports fixed-root runtime execution ownership and replay failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantRuntimeExecutionOwnerErrorV1 {
    /// Independent signed proof and Controller currentness are not joined.
    #[error("runtime execution bootstrap requires independent signed proof and currentness")]
    BootstrapProofRequired,
    /// The fixed immutable bootstrap manifest/root is absent or unauthenticated.
    #[cfg(target_os = "linux")]
    #[error("runtime execution bootstrap manifest is invalid")]
    BootstrapManifest,
    /// Protected runtime execution state was already initialized.
    #[error("runtime execution bootstrap authority was already consumed")]
    BootstrapAlreadyConsumed,
    /// Repeated exact recovery could not classify the initial atomic append.
    #[cfg(target_os = "linux")]
    #[error("runtime execution bootstrap outcome remains unknown")]
    BootstrapOutcomeUnknown,
    /// Fixed bootstrap protected-root validation failed.
    #[cfg(target_os = "linux")]
    #[error("runtime execution bootstrap root validation failed: {0}")]
    BootstrapRoot(#[from] aos_sandbox_linux::immutable_file::PublicationRootError),
    /// Fixed bootstrap manifest fs-verity validation failed.
    #[cfg(target_os = "linux")]
    #[error("runtime execution bootstrap immutable manifest failed: {0}")]
    BootstrapImmutable(#[from] aos_sandbox_linux::immutable_file::ImmutableFileError),
    /// Fixed bootstrap beneath-root validation failed.
    #[cfg(target_os = "linux")]
    #[error("runtime execution bootstrap path validation failed: {0}")]
    BootstrapPath(#[from] aos_sandbox_linux::Error),
    /// Fixed bootstrap descriptor operation failed.
    #[cfg(target_os = "linux")]
    #[error("runtime execution bootstrap descriptor failed: {0}")]
    BootstrapDescriptor(#[from] rustix::io::Errno),
    /// The protected Host peer or runtime-currentness record is absent.
    #[error("protected runtime execution currentness is absent")]
    MissingCurrentness,
    /// No durable v2 accepted-Create output claim exists for this execution.
    #[error("protected accepted-Create output claim is absent")]
    MissingAcceptedOutputClaim,
    /// The durable claim or admission authority does not match current inputs.
    #[error("protected accepted-Create output claim is stale or mismatched")]
    AcceptedOutputClaimMismatch,
    /// The protected Guest observation session, target, or runtime profile differs.
    #[error("protected runtime argument observation source is mismatched")]
    ArgumentObservationMismatch,
    /// The one-shot Guest observation nonce could not be generated securely.
    #[error("runtime argument observation entropy is unavailable")]
    EntropyUnavailable,
    /// The signed Guest argument observation is invalid.
    #[error("runtime argument observation is invalid: {0}")]
    ArgumentObservation(#[from] GuestRuntimeArgumentObservationErrorV1),
    /// The selected protected sandbox specification could not be read.
    #[error("runtime argument sandbox specification is unavailable: {0}")]
    SandboxSpec(#[from] crate::sandbox_spec_state::SandboxSpecStateError),
    /// A protected record is noncanonical, invalid, or internally inconsistent.
    #[error("protected runtime execution currentness is malformed")]
    MalformedCurrentness,
    /// The protected peer/currentness record changed while the claim was live.
    #[error("protected runtime execution currentness is stale")]
    StaleCurrentness,
    /// Existing fixed-root provisioning is partial or differs from the input.
    #[error("protected runtime execution provisioning conflicts with current state")]
    ProvisioningConflict,
    /// Fixed-root protected journal access or replay failed.
    #[error("runtime execution owner journal failed: {0}")]
    Journal(#[from] JournalError),
    /// The execution store failed initialization, replay, or mutation.
    #[error("runtime execution durable store failed: {0}")]
    Execution(#[from] JournalRuntimeExecutionError),
    /// The agent store failed initialization or full replay.
    #[error("runtime execution agent store failed: {0}")]
    Agent(#[from] JournalAgentStoreError),
}

#[cfg(test)]
mod accepted_output_currentness_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    fn fixed_currentness(resource_ledger: u8, authority_context: u8) -> AdmissionCurrentnessV1 {
        let runtime = RuntimeCurrentnessV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            NodeId::from_bytes([3; 16]),
            AssignmentEpoch::new(4),
            ObjectDigest::from_bytes([5; 32]),
            DesiredGeneration::new(6),
            NamespaceGeneration::new(7),
        )
        .expect("runtime currentness");
        let handle = RuntimeHandleCommitmentV1::new(
            runtime,
            ObjectDigest::from_bytes([8; 32]),
            ObjectDigest::from_bytes([9; 32]),
        )
        .expect("runtime handle");
        let probe = BackendProbeCurrentnessV1::new(
            NodeId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([10; 32]),
            Revision::new(11),
            ObjectDigest::from_bytes([12; 32]),
        )
        .expect("backend probe");
        AdmissionCurrentnessV1::new(
            handle,
            PayloadBootId::new([13; 16]).expect("payload boot"),
            probe,
            ObjectDigest::from_bytes([authority_context; 32]),
            ObjectDigest::from_bytes([resource_ledger; 32]),
            ObjectDigest::from_bytes([14; 32]),
        )
        .expect("admission currentness")
    }

    fn retained_claim() -> RetainedClaim {
        RetainedClaim {
            execution: [15; 16],
            create_operation: [16; 16],
            assignment: ObjectDigest::from_bytes([5; 32]),
            parent_profile: ObjectDigest::from_bytes([17; 32]),
            claim_commitment: ObjectDigest::from_bytes([18; 32]),
            requested_bytes: 0,
            parent_bytes: 0,
            stream_limits: Some((0, 0)),
            record_digest: ObjectDigest::from_bytes([19; 32]),
        }
    }

    #[test]
    fn retained_hoststate_hold_never_initializes_empty_effect_store() {
        let directory = TempDir::new_in(std::env::current_dir().expect("current directory"))
            .expect("test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = directory.path().metadata().expect("metadata").uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "empty-effect.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("empty Effect journal");
        let peer = ProtectedAgentRoutePeerV1::new(
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
            ObjectDigest::from_bytes([8; 32]),
            ObjectDigest::from_bytes([9; 32]),
        )
        .expect("fixed peer");

        assert!(matches!(
            open_execution_store(
                &mut journal,
                ObjectDigest::from_bytes([1; 32]),
                ProtectedExecutionAdmissionStateV1::new(&fixed_currentness(20, 21)),
                peer,
                true,
            ),
            Err(JournalRuntimeExecutionError::UninitializedStore)
        ));
        assert!(
            journal
                .claim_protected_authority(RecordNamespace::Effect)
                .expect("Effect authority")
                .is_materialized_empty()
                .expect("still empty")
        );
    }

    #[test]
    fn accepted_claim_replaces_fixed_digest_and_uses_latest_durable_ledger_head() {
        let fixed = fixed_currentness(20, 21);
        let advanced = fixed_currentness(22, 21);
        let state = ProtectedExecutionAdmissionStateV1::new(&advanced);
        let claim = retained_claim();

        let derived = derive_accepted_output_currentness_v2(
            &fixed,
            &state,
            &claim,
            ExecutionId::from_bytes([15; 16]),
            OperationId::from_bytes([16; 16]),
        )
        .expect("matching protected claim");

        assert_eq!(derived.output_reservation(), claim.record_digest);
        assert_ne!(derived.output_reservation(), fixed.output_reservation());
        assert_eq!(derived.resource_ledger(), advanced.resource_ledger());

        let historical = AdmissionCurrentnessV1::new(
            *derived.runtime(),
            derived.payload_boot_id(),
            *derived.backend_probe(),
            derived.authority_context(),
            fixed.resource_ledger(),
            claim.record_digest,
        )
        .expect("historical admission predecessor");
        assert_ne!(historical.resource_ledger(), derived.resource_ledger());
        assert!(same_owner_and_accepted_output_v2(&historical, &derived));
        assert!(!same_owner_and_accepted_output_v2(&fixed, &derived));
    }

    #[test]
    fn accepted_claim_rejects_foreign_execution_operation_assignment_and_authority() {
        let fixed = fixed_currentness(20, 21);
        let state = ProtectedExecutionAdmissionStateV1::new(&fixed);
        let execution = ExecutionId::from_bytes([15; 16]);
        let operation = OperationId::from_bytes([16; 16]);
        let claim = retained_claim();

        for (candidate, execution, operation, state) in [
            (
                retained_claim(),
                ExecutionId::from_bytes([23; 16]),
                operation,
                state,
            ),
            (
                retained_claim(),
                execution,
                OperationId::from_bytes([24; 16]),
                state,
            ),
            (
                RetainedClaim {
                    assignment: ObjectDigest::from_bytes([25; 32]),
                    ..retained_claim()
                },
                execution,
                operation,
                state,
            ),
            (
                claim,
                execution,
                operation,
                ProtectedExecutionAdmissionStateV1::new(&fixed_currentness(20, 26)),
            ),
        ] {
            assert!(matches!(
                derive_accepted_output_currentness_v2(
                    &fixed, &state, &candidate, execution, operation
                ),
                Err(DormantRuntimeExecutionOwnerErrorV1::AcceptedOutputClaimMismatch)
            ));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod protected_owner_test_opener_tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn private_owner_opener_replays_four_journals_without_minting_a_claim() {
        let directory = TempDir::new_in(std::env::current_dir().expect("current directory"))
            .expect("test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = directory.path().metadata().expect("metadata").uid();

        let mut owner =
            DormantRuntimeExecutionOwnerV1::open_protected_at_uid_for_test(directory.path(), uid)
                .expect("four protected journals");
        assert!(matches!(
            owner.claim(),
            Err(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)
        ));
        drop(owner);

        let mut cold =
            DormantRuntimeExecutionOwnerV1::open_protected_at_uid_for_test(directory.path(), uid)
                .expect("cold replay of four protected journals");
        assert!(matches!(
            cold.claim(),
            Err(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)
        ));
        drop(cold);

        assert!(
            DormantRuntimeExecutionOwnerV1::open_protected_at_uid_for_test(
                directory.path(),
                uid.wrapping_add(1),
            )
            .is_err()
        );

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make directory unsafe");
        assert!(
            DormantRuntimeExecutionOwnerV1::open_protected_at_uid_for_test(directory.path(), uid)
                .is_err()
        );
    }
}
