//! Authenticated-session callsite for Storage effects.
//!
//! This module deliberately has no service registration. It joins the
//! constructible protected Storage runtime to the existing signed admission and
//! one-shot execution paths only when an external protected-session owner
//! supplies the exact already-authenticated body and kernel identity evidence.

use std::path::{Path, PathBuf};

use aos_sandbox_api::aos::sandbox::local::v1::{
    AtomicStorageSnapshotResponse, BrokerMethod, PopulateStorageGuestRootResponseV1, StorageResult,
};
use aos_sandbox_model::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_protocol::semantics::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::git_project_coverage::{
    decode_git_project_coverage_request_v1, encode_git_project_coverage_response_v1,
};
use aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::guest_root_inventory::{
    ProtectedGuestRootTemplateV1, attach_guest_root_publication_readback_v1,
};
use crate::live_export_clone::StorageLiveExportCloneLedgerV1;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::{
    StorageAdmissionError, StorageAdmissionOutcome, StorageBrokerRuntime, StorageIdentityPoolV1,
    StorageOperation, StorageRuntimeError, StorageRuntimeMutationOutcome, SystemdZfsExecutor,
};

mod apply_clock;

mod sealed {
    pub trait Sealed {}
}

/// Reports rejection at the dormant broker-session-to-Storage boundary.
#[derive(Debug, thiserror::Error)]
pub enum DormantStorageBrokerCallErrorV1 {
    /// A read-only candidate failed with the entire original source retained.
    #[error(transparent)]
    CaptureCandidate(#[from] DormantCaptureCandidateFailureV1),
    /// The protected session and live kernel boot identities differ.
    #[error("authenticated Storage handoff has stale kernel evidence")]
    StaleKernel,
    /// Storage admission or execution rejected the exact request.
    #[error("authenticated Storage Apply failed: {0}")]
    Runtime(#[from] StorageRuntimeError),
}

/// Retains a failed candidate's concrete partial owner and original results.
///
/// This diagnostic custody grants no allocation, source loan or retry. Its
/// destructor fails closed through the original owner rather than discarding
/// a returned native error, opened policy file or authenticated cut.
pub struct DormantCaptureCandidateFailureV1 {
    original: Box<crate::runtime::capture_candidate::OriginalCaptureCandidateV1>,
}

impl std::fmt::Debug for DormantCaptureCandidateFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DormantCaptureCandidateFailureV1")
            .field("cause", &self.original.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for DormantCaptureCandidateFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure().or_else(|| self.original.postcheck_debt()) {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("original capture candidate is permanently closed"),
        }
    }
}

impl std::error::Error for DormantCaptureCandidateFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure().or_else(|| self.original.postcheck_debt())
    }
}

impl DormantCaptureCandidateFailureV1 {
    /// Borrows the exact chronological source cause without moving custody.
    #[must_use]
    pub fn original_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }

    /// Borrows independent later comparison debt without replacing that cause.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.postcheck_debt()
    }
}

/// Seals the result produced by the real Storage admission/execution path.
///
/// Its private fields prevent callers from manufacturing a successful domain
/// observation for the broker-session owner.
pub struct DormantStorageBrokerObservationV1 {
    operation_id: [u8; 16],
    operation: StorageOperation,
    admission: StorageAdmissionOutcome,
    execution: Option<StorageRuntimeMutationOutcome>,
    commitment: ObjectDigest,
}

impl DormantStorageBrokerObservationV1 {
    /// Returns the exact successful Storage result derived from committed state.
    ///
    /// # Errors
    ///
    /// Returns an error while the durable mutation is absent, aborted, or
    /// observation-only and therefore cannot truthfully produce success.
    pub fn response(&self) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        self.response_inner_v1(None)
    }

    fn response_inner_v1(
        &self,
        receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        let committed = self
            .execution
            .and_then(|execution| match execution {
                StorageRuntimeMutationOutcome::Committed(result) => Some(result),
                StorageRuntimeMutationOutcome::Aborted { .. }
                | StorageRuntimeMutationOutcome::ObservationRequired { .. } => None,
            })
            .or_else(|| match self.admission {
                StorageAdmissionOutcome::Replay(result) => Some(result),
                _ => None,
            })
            .ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        if let Some(receiving) = receiving {
            // Two optional32-byte handles and the32-byte result digest, their
            // protobuf tags/lengths, the generated model and Vec backing.
            let bytes = std::mem::size_of::<StorageResult>() + 2 * (32 + 2) + 32 + 2
                + 2 * std::mem::size_of::<Vec<u8>>();
            receiving.reserve_encoded_capacity_v1(bytes, 0)
                .map_err(|_| StorageRuntimeError::Receiving)?;
        }
        Ok(StorageResult {
            storage_handle: committed
                .storage_handle()
                .map_or_else(Vec::new, |handle| handle.to_vec()),
            immutable_version_handle: committed
                .immutable_version_handle()
                .map_or_else(Vec::new, |handle| handle.to_vec()),
            non_secret_receipt: committed.result_digest().as_bytes().to_vec(),
            ..Default::default()
        }
        .encode_to_vec())
    }

    /// Returns the exact Storage operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the closed Storage operation.
    #[must_use]
    pub const fn operation(&self) -> StorageOperation {
        self.operation
    }

    /// Returns the durable admission classification.
    #[must_use]
    pub const fn admission(&self) -> &StorageAdmissionOutcome {
        &self.admission
    }

    /// Returns execution evidence when a newly prepared effect was consumed.
    #[must_use]
    pub const fn execution(&self) -> Option<&StorageRuntimeMutationOutcome> {
        self.execution.as_ref()
    }

    /// Returns the domain-separated observation commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Defines the closed call surface accepted by broker-session security.
///
/// The private supertrait restricts implementations to this crate, so a
/// public caller cannot replace Storage execution with fabricated success.
#[doc(hidden)]
pub trait DormantStorageBrokerCallsiteV1: sealed::Sealed {
    /// Compares or permanently fences the same original unused Storage owners.
    ///
    /// Output custody is the actual independently held daemon owner, not a
    /// caller quantity vector. The response is coverage DATA only.
    ///
    /// # Errors
    /// Rejects foreign methods, stale peer/header/kernel evidence, changed
    /// fixed inputs, nonempty history or physical custody, and failed readback.
    #[cfg(target_os = "linux")]
    fn consume_authenticated_git_coverage_v1(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        output: &crate::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1>;

    /// Admits and, for a fresh Prepared row, executes one exact Apply body.
    ///
    /// # Errors
    ///
    /// Returns an error when request or kernel evidence is stale, or when the
    /// durable Storage admission or execution path rejects the call.
    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantStorageBrokerObservationV1, DormantStorageBrokerCallErrorV1>;

    /// Executes one exact authenticated Storage prepare, repair, or grouped
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for any other method, stale kernel/request evidence,
    /// or a result that still requires authoritative recovery observation.
    fn consume_authenticated_operation(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1>;
}

/// Owns the complete source-only protected Storage Apply composition.
///
/// Construction opens the same protected catalogs and worker custody as the
/// explicit dormant runtime constructor. It does not advertise Apply or
/// install a listener; consumption remains an explicit broker-session call.
pub struct DormantStorageApplyCompositionV1 {
    capture_reserve: Option<Box<crate::runtime::original_capture::OriginalStorageCaptureReserveV3>>,
    capture_reserve_entry: crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1,
    capture_reserve_entered: bool,
    capture_query: Option<crate::runtime::capture_query::OriginalStorageCaptureQueryV3>,
    capture_query_entry: capture_query::QueryEntryOriginalV3,
    runtime: StorageBrokerRuntime,
    apply_clock: Option<Box<apply_clock::ApplyClockOriginalV1>>,
    capture_candidate: Option<Box<crate::runtime::capture_candidate::OriginalCaptureCandidateV1>>,
    capture_candidate_closed: bool,
    capture_candidate_entry: crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1,
    capture_allocation_pin: Option<crate::execution_capture_policy::CaptureAllocationV1>,
    nix_generation: Option<crate::StorageGenerationAttemptV1>,
    nix_generation_clock_error: Option<crate::StorageRuntimeError>,
    guest_root_template: Option<ProtectedGuestRootTemplateV1>,
    _private_live_export_clones: Option<StorageLiveExportCloneLedgerV1>,
}

/// Disposes the same positive Apply clock, Runtime and Native operation owners.
///
/// All fallible Session/State/native/Sent checks precede construction. This
/// exclusive continuation provides no new request/effect admission.
pub struct DormantStorageLifecycleDisposalV1<'runtime, 'phase, 'cut, 'original> {
    runtime: crate::runtime::StorageRuntimeLifecycleDisposalV1<'runtime, 'phase, 'cut, 'original>,
    clocks: &'runtime mut Option<Box<apply_clock::ApplyClockOriginalV1>>,
}

impl DormantStorageLifecycleDisposalV1<'_, '_, '_, '_> {
    /// Drops the actual positive carriers before infallible Native completion.
    pub fn complete_after_disposal_v1(self) {
        drop(self.clocks.take());
        self.runtime.complete_after_disposal_v1();
    }
}

impl Drop for DormantStorageApplyCompositionV1 {
    fn drop(&mut self) {
        if self.capture_candidate.is_some() || self.capture_candidate_closed
            || self.capture_candidate_entry.failure().is_some() || self.apply_clock.is_some()
            || self.capture_reserve_entered || self.capture_reserve.is_some()
            || self.capture_query.is_some() || self.capture_query_entry.is_entered_v3() {
            // Abort before the runtime's original directory and writers drop.
            // Only the real signed-successor path can retire this source.
            std::process::abort();
        }
    }
}

impl DormantStorageApplyCompositionV1 {
    /// Reconciles the actual writers under the active paid Session Domain.
    ///
    /// This uses the same Runtime transaction/pin/catalog engine as startup;
    /// it does not reopen initial stages or substitute for method admission.
    ///
    /// # Errors
    /// Refuses missing genuine Domain/traffic/State identity, unresolved
    /// operator debt, payment failure or any retained native/domain/post cause.
    pub fn reconcile_lifecycle_domain_receiving_v1(
        &mut self,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<crate::StorageRuntimeReadiness, DormantStorageBrokerCallErrorV1> {
        self.runtime.reconcile_lifecycle_domain_receiving_v1(lifecycle, session, socket)
            .map_err(Into::into)
    }

    /// Joins actual terminal-Sent disposition with the held State/helper owners.
    ///
    /// # Errors
    /// Refuses a different/incomplete Native operation token or any unfinished
    /// or negative reconciliation owner, preserving its actual first cause.
    pub fn prepare_lifecycle_reconciliation_disposal_v1<'runtime, 'phase, 'cut, 'original>(
        &'runtime mut self,
        native: aos_sandbox_controller_domain::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
    ) -> Result<DormantStorageLifecycleDisposalV1<'runtime, 'phase, 'cut, 'original>,
        DormantStorageBrokerCallErrorV1>
    {
        if self.apply_clock.as_deref().is_some_and(|clock| clock.failure().is_some()) {
            return Err(StorageRuntimeError::Receiving.into());
        }
        let runtime = self.runtime.prepare_lifecycle_reconciliation_disposal_v1(native)?;
        Ok(DormantStorageLifecycleDisposalV1 { runtime, clocks: &mut self.apply_clock })
    }

    /// Executes the actual authenticated Apply under the current Session Domain.
    ///
    /// The same State subloan spans admission, durable Ambiguous, physical
    /// dispatch, reconciliation, response encoding and independent State posts.
    /// Ordinary and selected calls use the same semantic orchestration.
    ///
    /// # Errors
    /// Refuses an unpaid/currentness-invalid Domain, incomplete State interval,
    /// stale body/kernel binding, authority rejection or real retained native,
    /// effect, capacity or post failure. No initial boot stage is reopened.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_authenticated_apply_receiving_v1(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        let mut receiving = lifecycle.borrow_state_encoding_v1(
            session, socket, self.runtime.lifecycle_state_journal_v1(),
        ).map_err(|_| StorageRuntimeError::Receiving)?;
        let result = (|| {
            self.runtime.prepare_lifecycle_apply_models_v1(&mut receiving)?;
            if self.apply_clock.is_some() {
                return Err(StorageRuntimeError::Receiving.into());
            }
            let bytes = apply_clock::ApplyClockOriginalV1::requested_bytes_v1()
                .ok_or(StorageRuntimeError::Receiving)?;
            receiving.reserve_apply_clock_observations_v1(
                self.runtime.lifecycle_state_journal_v1(), bytes,
            ).map_err(|_| StorageRuntimeError::Receiving)?;
            self.apply_clock = Some(Box::new(apply_clock::ApplyClockOriginalV1::new()));
            let clocks = self.apply_clock.as_deref_mut().ok_or(StorageRuntimeError::Receiving)?;
            let observation = Self::consume_authenticated_apply_inner_v1(
                &mut self.runtime, request_body, request_id, request_body_digest, artifacts, peer, policy,
            protocol_version, protected_boot_id, Some(&mut receiving), Some(clocks),
            )?;
            observation.response_inner_v1(Some(&mut receiving))
        })();
        self.runtime.finish_lifecycle_apply_posts_v1(result, &mut receiving)
    }

    /// Reads complete Inventory under this operation's genuine State Domain.
    ///
    /// # Errors
    /// Preserves ordinary Inventory predicates and refuses unpaid/currentness-
    /// invalid State, native readback or independent post failure. It performs
    /// no transaction retirement or new physical mutation.
    pub fn consume_lifecycle_inventory_receiving_v1(
        &mut self,
        deadline: u64,
        cutoff: u64,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let mut receiving = lifecycle.borrow_state_encoding_v1(
            session, socket, self.runtime.lifecycle_state_journal_v1(),
        ).map_err(|_| StorageRuntimeError::Receiving)?;
        let result = (|| {
            self.runtime.prepare_lifecycle_apply_models_v1(&mut receiving)?;
            self.runtime.complete_lifecycle_inventory_state_receiving_v1(
                deadline, cutoff, self.guest_root_template.as_ref(), &mut receiving,
            ).map_err(Into::into)
        })();
        self.runtime.finish_lifecycle_apply_posts_v1(result, &mut receiving)
            .map_err(|_| StorageRuntimeError::Receiving)
    }

    /// Retains Prepare or Repair under this operation's new same-State Domain.
    ///
    /// # Errors
    /// Refuses a missing genuine Domain, body/boot/request mismatch, policy,
    /// authority, native append or owed post failure. Existing action-specific
    /// admission and replay barriers remain mandatory; no boot stage is reused.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_authenticated_operation_lifecycle_v1(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        let artifacts = request.authorization().ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        let method = request.method();
        let request_body = request.exact_body();
        let request_id = request.request_id();
        let request_body_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
        let peer = request.peer();
        let policy = request.peer_policy();
        let mut receiving = lifecycle.borrow_state_encoding_v1(
            session, socket, self.runtime.lifecycle_state_journal_v1(),
        ).map_err(|_| StorageRuntimeError::Receiving)?;
        let result = (|| {
            self.runtime.prepare_lifecycle_apply_models_v1(&mut receiving)?;
            if ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
                || self.apply_clock.is_some()
            {
                return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
            }
            // Prepare uses two authority callbacks plus the shared boot pair.
            // Repair uses the boot pair, initial/preliminary pair, admission,
            // preeffect and postcommit checks: six total of this fixed eight.
            // The real worker's own final crossing has its separate paid lane.
            let bytes = apply_clock::ApplyClockOriginalV1::requested_bytes_v1()
                .ok_or(StorageRuntimeError::Receiving)?;
            receiving.reserve_apply_clock_observations_v1(
                self.runtime.lifecycle_state_journal_v1(), bytes,
            ).map_err(|_| StorageRuntimeError::Receiving)?;
            self.apply_clock = Some(Box::new(apply_clock::ApplyClockOriginalV1::new()));
            let clocks = self.apply_clock.as_deref_mut().ok_or(StorageRuntimeError::Receiving)?;
            Self::consume_authenticated_operation_inner_v1(
                &mut self.runtime, self.guest_root_template.as_ref(), method,
                request_body, request_id, request_body_digest, artifacts,
                peer, policy, protocol_version, protected_boot_id,
                Some(&mut receiving), Some(clocks), Some(request),
            )
        })();
        self.runtime.finish_lifecycle_apply_posts_v1(result, &mut receiving)
    }

    /// Borrows the actual recurring source/native cause without moving owners.
    #[must_use]
    pub fn lifecycle_apply_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.apply_clock.as_deref().and_then(apply_clock::ApplyClockOriginalV1::failure)
            .or_else(|| self.runtime.lifecycle_apply_failure_v1())
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_authenticated_operation_inner_v1(
        runtime: &mut StorageBrokerRuntime,
        guest_root_template: Option<&ProtectedGuestRootTemplateV1>,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
        mut clocks: Option<&mut apply_clock::ApplyClockOriginalV1>,
        publication_request: Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1>,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        if receiving.is_some() && !matches!(method,
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
                | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT)
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        let current_boot_id = match clocks.as_deref_mut() {
            Some(clocks) => clocks.sample()?.host_boot_id(),
            None => KernelBootId::current()
                .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?.into_bytes(),
        };
        if current_boot_id != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let mut clock = || {
            let sample = match clocks.as_deref_mut() {
                Some(clocks) => clocks.sample(),
                None => super::runtime::trusted_paired_clock_sample(),
            }.map_err(|_| StorageAdmissionError::FenceRejected)?;
            if sample.host_boot_id() != protected_boot_id {
                return Err(StorageAdmissionError::FenceRejected);
            }
            Ok(sample)
        };
        match method {
            BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
                let actual = publication_request.ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
                let receiving = receiving.as_deref_mut().ok_or(StorageRuntimeError::Receiving)?;
                let template = guest_root_template.ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
                let sample = clock().map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?;
                let (proof, current) = runtime.populate_guest_root_receiving_v2(
                    actual, protocol_version, &sample, template, receiving,
                )?;
                Ok(PopulateStorageGuestRootResponseV1 {
                    publication_proof: proof.encode()
                        .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?.to_vec(),
                    current_publication_v2: current.encode_v2().to_vec(),
                    ..Default::default()
                }.encode_to_vec())
            }
            BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
                let request = aos_sandbox_protocol::decode_atomic_storage_snapshot_request(
                    request_body,
                    peer,
                    policy,
                    0,
                )
                .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?;
                if request.header().request_id() != &request_id
                    || request.header().protocol_version() != protocol_version
                {
                    return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
                }
                match runtime.execute_authenticated_atomic_snapshot(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    &mut clock,
                )? {
                    crate::AtomicDatasetSnapshotMutationOutcomeV1::Committed {
                        program,
                        observation,
                    } => Ok(AtomicStorageSnapshotResponse {
                        program_digest: program.as_bytes().to_vec(),
                        observation_digest: observation.as_bytes().to_vec(),
                        observation_required: false,
                        ..Default::default()
                    }
                    .encode_to_vec()),
                    crate::AtomicDatasetSnapshotMutationOutcomeV1::ObservationRequired {
                        ..
                    }
                    | crate::AtomicDatasetSnapshotMutationOutcomeV1::PreparedBeforeEffect {
                        ..
                    } => Err(DormantStorageBrokerCallErrorV1::StaleKernel),
                }
            }
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
                let prepared = match receiving.as_deref_mut() {
                    Some(receiving) => runtime.prepare_catalog_state_receiving_v1(
                        request_body, request_id, artifacts, protocol_version,
                        peer, policy, &mut clock, receiving,
                    ),
                    None => runtime.prepare_catalog(
                        request_body, artifacts, protocol_version, peer, policy, &mut clock,
                    ),
                }?;
                Ok(prepared.response().encode_to_vec())
            }
            BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
                let initial = if receiving.is_some() {
                    clock().map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?
                } else {
                    super::runtime::trusted_paired_clock_sample()?
                };
                let semantics = CanonicalStorageRepairSemanticsV1::decode(
                    request_body,
                    peer,
                    policy,
                    initial.boottime_nanoseconds(),
                )
                .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?;
                if semantics.header().request_id() != &request_id
                    || semantics.header().protocol_version() != protocol_version
                {
                    return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
                }
                let repaired = match receiving.as_deref_mut() {
                    Some(receiving) => {
                        let cutoff = semantics.header().deadline_boottime_nanoseconds()
                            .checked_sub(5_000_000_000)
                            .ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
                        runtime.repair_workspace_pin_state_receiving_v1(
                            request_body, artifacts, protocol_version, peer,
                            policy, &mut clock, cutoff, receiving,
                        )
                    }
                    None => runtime.repair_workspace_pin(
                        request_body, artifacts, protocol_version, peer, policy, &mut clock,
                    ),
                }?;
                match repaired {
                    crate::WorkspacePinRepairExecutionOutcomeV1::Satisfied => Ok(StorageResult {
                        storage_handle: semantics.storage_handle().as_bytes().to_vec(),
                        ..Default::default()
                    }
                    .encode_to_vec()),
                    crate::WorkspacePinRepairExecutionOutcomeV1::ObservationRequired => {
                        Err(DormantStorageBrokerCallErrorV1::StaleKernel)
                    }
                }
            }
            _ => Err(DormantStorageBrokerCallErrorV1::StaleKernel),
        }
    }

    fn consume_authenticated_apply_inner_v1(
        runtime: &mut StorageBrokerRuntime,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        mut receiving: Option<&mut crate::state::encoding::StateEncodingLoanV1<'_, '_>>,
        mut clocks: Option<&mut apply_clock::ApplyClockOriginalV1>,
    ) -> Result<DormantStorageBrokerObservationV1, DormantStorageBrokerCallErrorV1> {
        let current_boot_id = match clocks.as_deref_mut() {
            Some(clocks) => clocks.sample()?.host_boot_id(),
            None => KernelBootId::current()
                .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?.into_bytes(),
        };
        if current_boot_id != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let current_clock = match clocks.as_deref_mut() {
            Some(clocks) => clocks.sample()?,
            None => super::runtime::trusted_paired_clock_sample()?,
        };
        if current_clock.host_boot_id() != protected_boot_id {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        let (admitted_request_id, operation_id, operation, admission) =
            match receiving.as_deref_mut() {
                Some(receiving) => runtime.admit_authenticated_signed_apply_receiving_v1(
                    request_body, &request_id, artifacts, protocol_version, peer, policy,
                    &current_clock, receiving,
                )?,
                None => runtime.admit_authenticated_signed_apply_intent(
                    request_body, &request_id, artifacts, protocol_version, peer, policy, &current_clock,
                )?,
            };
        if admitted_request_id != request_id {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let execution = if matches!(admission, StorageAdmissionOutcome::Prepared { .. }) {
            let mut clock = || {
                let sample = match clocks.as_deref_mut() {
                    Some(clocks) => clocks.sample(),
                    None => super::runtime::trusted_paired_clock_sample(),
                }.map_err(|_| StorageAdmissionError::FenceRejected)?;
                if sample.host_boot_id() != protected_boot_id {
                    return Err(StorageAdmissionError::FenceRejected);
                }
                Ok(sample)
            };
            Some(match receiving.as_deref_mut() {
                Some(receiving) => runtime.execute_admitted_receiving_v1(operation_id, &mut clock, receiving)?,
                None => runtime.execute_admitted(operation_id, &mut clock)?,
            })
        } else {
            None
        };
        let commitment = storage_observation_commitment(
            request_id,
            request_body_digest,
            operation,
            &admission,
            execution.as_ref(),
        );
        Ok(DormantStorageBrokerObservationV1 {
            operation_id,
            operation,
            admission,
            execution,
            commitment,
        })
    }

    /// Consumes an authenticated Prepare through the actual paid Storage receiver.
    ///
    /// The exact body digest/request identity and protected boot remain joined
    /// to the real Runtime/admission and final Native clock path. No Apply or
    /// physical mutation is granted by a preparation receipt.
    ///
    /// # Errors
    /// Refuses stale exact body/kernel joins, absent payment, authority/policy
    /// rejection or Native uncertainty. Whole domain/native causes stay resident.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_authenticated_prepare_catalog_receiving_v1(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        if ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        self.runtime.prepare_catalog_receiving_v1(
            request_body, request_id, protected_boot_id, artifacts, protocol_version,
            peer, policy, receiving,
        ).map(|outcome| outcome.response().encode_to_vec()).map_err(Into::into)
    }

    /// Borrows the actual first paid Prepare cause while this composition is held.
    #[must_use]
    pub fn storage_prepare_receiving_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.runtime.receiving_prepare_failure_v1()
    }

    fn take_capture_candidate_failure(&mut self) -> DormantStorageBrokerCallErrorV1 {
        self.capture_candidate_closed = true;
        match self.capture_candidate.take() {
            Some(original) => DormantCaptureCandidateFailureV1 { original }.into(),
            None => DormantStorageBrokerCallErrorV1::StaleKernel,
        }
    }

    /// Observes one received method-41 request through the original owners.
    ///
    /// The lazy slot is armed before any new read. It uses only the runtime's
    /// retained resolver directory and private configuration binding. This
    /// informational response does not reserve output or authorize mutation.
    ///
    /// # Errors
    /// Rejects reuse, an absent provisioned source or any failed currentness
    /// observation. The error retains the whole original owner; failure
    /// requires process exit rather than replacement or retry.
    pub fn observe_original_capture_candidate_v1(
        &mut self,
        output: &crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        version: ProtocolVersion,
        boot: KernelBootId,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        if self.capture_candidate_closed {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        if let Some(attempt) = &mut self.capture_candidate {
            attempt.close_on_reentry();
            return Err(self.take_capture_candidate_failure());
        }
        self.capture_candidate = Some(Box::new(crate::runtime::capture_candidate::OriginalCaptureCandidateV1::empty(
            request, version, boot,
        )));
        let Some(attempt) = &mut self.capture_candidate else {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        };
        self.runtime.observe_original_capture_candidate(attempt, output, &mut self.capture_allocation_pin);
        match attempt.take_response() {
            Some(body) => Ok(body),
            None => Err(self.take_capture_candidate_failure()),
        }
    }

    /// Rechecks the same retained source immediately before signing or sending.
    ///
    /// # Errors
    /// Rejects an absent or closed recipe, changed policies, expired original
    /// request or changed actual owners, without resetting any failed result.
    pub fn recheck_original_capture_candidate_v1(
        &mut self,
        output: &crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        before_signing: bool,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        let Some(attempt) = &mut self.capture_candidate else {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        };
        self.runtime.recheck_original_capture_candidate(attempt, output, before_signing);
        if attempt.failure().is_some() || attempt.postcheck_debt().is_some() {
            return Err(self.take_capture_candidate_failure());
        }
        Ok(())
    }

    /// Borrows the actual receipt's immutable request DATA for successor comparison.
    #[must_use]
    pub fn original_capture_candidate_request(
        &self,
    ) -> Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1> {
        Some(self.capture_candidate.as_ref()?.original_request())
    }

    /// Retires a successful source only under an actually admitted successor.
    ///
    /// # Errors
    /// Rejects absence, failed custody, replay or another session/sequence.
    /// The same BSA receipt must already have authenticated the predecessor.
    pub fn retire_original_capture_candidate_v1(
        &mut self,
        successor: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        let Some(attempt) = &mut self.capture_candidate else {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        };
        if !attempt.retire_on_successor(successor) {
            attempt.close_on_reentry();
            return Err(self.take_capture_candidate_failure());
        }
        self.capture_candidate = None;
        self.capture_candidate_entry = crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1::new();
        Ok(())
    }

    /// Borrows only the selected original result and its independent clock debt.
    ///
    /// This diagnostic does not admit another request or expose a writer.
    #[must_use]
    pub fn nix_generation_original(&self) -> Option<&crate::StorageGenerationAttemptV1> {
        self.nix_generation.as_ref()
    }

    /// Borrows the selected kernel-clock producer's actual returned error.
    ///
    /// The admission classification and later clock debt remain in the same
    /// attempt. This loan does not sample, renew or reopen its original clock.
    #[must_use]
    pub fn nix_generation_clock_failure(&self) -> Option<&crate::StorageRuntimeError> {
        self.nix_generation_clock_error.as_ref()
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_nix_generation_original_v1(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        use crate::nix_generation::StorageGenerationCauseV1;

        if self.nix_generation.is_some() {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        // The concrete runtime owns this reservoir before kernel, allocation
        // or admission effects. No consuming public adapter owns its lifetime.
        self.nix_generation = Some(crate::StorageGenerationAttemptV1::new());
        let Some(original) = self.nix_generation.as_mut() else {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        };
        original.kernel = Some(KernelBootId::current());
        if original.kernel.as_ref().is_some_and(Result::is_err) {
            original.first = Some(StorageGenerationCauseV1::Kernel);
        }
        original.handoff = Some((|| {
            let boot = original.kernel.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
            if boot.into_bytes() != protected_boot_id
                || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
                || request_body.len() > aos_sandbox_protocol::nix_generation::NIX_GENERATION_REQUEST_MAXIMUM_BYTES_V1
            {
                return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
            }
            Ok(())
        })());
        if original.handoff.as_ref().is_some_and(Result::is_err) {
            original.first.get_or_insert(StorageGenerationCauseV1::Handoff);
        }

        let clock_error = &mut self.nix_generation_clock_error;
        let mut clock = || {
            let sample = match super::runtime::trusted_paired_clock_sample() {
                Ok(sample) => sample,
                Err(error) => {
                    // Keep the real producer error before the existing
                    // authority adapter returns its coarse classification.
                    clock_error.get_or_insert(error);
                    return Err(StorageAdmissionError::FenceRejected);
                }
            };
            if sample.host_boot_id() != protected_boot_id {
                return Err(StorageAdmissionError::FenceRejected);
            }
            Ok(sample)
        };
        if original.first.is_some() {
            if let Err(error) = clock() { original.clock_debt = Some(error); }
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        let mut body = Vec::new();
        if let Err(error) = body.try_reserve_exact(request_body.len()) {
            original.allocation = Some(error);
            original.first = Some(StorageGenerationCauseV1::Allocation);
            if let Err(error) = clock() { original.clock_debt = Some(error); }
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        body.extend_from_slice(request_body);
        original.request = Some(body);
        let result = self.runtime.prepare_nix_generation_into(
            artifacts, request_id, protocol_version, peer, policy, &mut clock, original,
        );
        if result.is_err() {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        let prepared = original.prepared()
            .ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        Ok(prepared.response().encode_to_vec())
    }

    /// Rechecks the original cohort fence and separately held output writer.
    ///
    /// # Errors
    /// Retains changed originals, nonempty domains or negative debt before
    /// response transport. This comparison cannot authorize an allocation.
    #[cfg(target_os = "linux")]
    pub fn recheck_git_coverage_response_v1(
        &mut self,
        output: &crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        deadline: u64,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        self.runtime.compare_git_coverage_v1(output, Some(deadline))?;
        Ok(())
    }

    /// Captures the fixed optional enrollment before this composition is served.
    ///
    /// # Errors
    /// Retains duplicate installation or unsafe/missing original credentials.
    #[cfg(target_os = "linux")]
    pub fn install_git_coverage_v1(&mut self) -> Result<(), StorageRuntimeError> {
        self.runtime.install_git_coverage_v1()
    }

    /// Audits all genuine fixed Storage owners before selected Ready.
    ///
    /// # Errors
    /// Retains nonempty, missing, unclassified or changed originals and actual
    /// negative debt; the borrowed output owner remains with its daemon.
    #[cfg(target_os = "linux")]
    pub fn audit_git_coverage_startup_v1(
        &mut self,
        output: &crate::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<(), StorageRuntimeError> {
        self.runtime.audit_git_coverage_startup_v1(output)
    }

    /// Parks the exact authenticated pending request without observing or permitting it.
    ///
    /// The actual pending Session must retain the returned owner before its
    /// next fallible gate. No scalar constructor or live permission is exposed.
    #[must_use]
    pub fn begin_original_execution_output_registration(
        &mut self,
        request: aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> crate::execution_output_credential::OriginalExecutionOutputRegistrationV1 {
        crate::execution_output_credential::OriginalExecutionOutputRegistrationV1::begin(request)
    }

    /// Registers one original request while the caller retains genuine Host currentness.
    ///
    /// This named operation lends the configured runtime and output writer
    /// exclusively. It parks results in the request-scoped owner, not the
    /// publication custody. Unit return is not success: the caller must inspect
    /// the resident result and finish both original Session bookends before
    /// authenticating a terminal. A failed or abandoned attempt is never reset.
    pub fn register_original_execution_output(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        host_terminal: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) {
        self.runtime.register_original_execution_output(output, attempt, host_terminal);
    }

    /// Reads only an occupied original output marker under configured admission.
    ///
    /// An absent or conflicting marker is not successful registration or a new
    /// reserve permission. The request-scoped owner retains the actual result.
    pub fn query_original_execution_output(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    ) {
        self.runtime.query_original_execution_output(output, attempt);
    }

    /// Opens the complete dormant protected Storage Apply composition.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when protected state, worker custody,
    /// Snapshot metadata, or startup recovery cannot be established.
    #[allow(clippy::too_many_arguments)]
    pub fn open_root_owned(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
    ) -> Result<Self, StorageRuntimeError> {
        let runtime = StorageBrokerRuntime::open_root_owned_dormant_apply_worker(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
        )?;
        Ok(Self {
            runtime,
            capture_reserve: None,
            capture_reserve_entry: crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1::new(),
            capture_reserve_entered: false,
            capture_query: None,
            capture_query_entry: capture_query::QueryEntryOriginalV3::new(),
            apply_clock: None,
            capture_candidate: None,
            capture_candidate_closed: false,
            capture_candidate_entry: crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1::new(),
            capture_allocation_pin: None,
            nix_generation: None,
            nix_generation_clock_error: None,
            guest_root_template: None,
            _private_live_export_clones: None,
        })
    }

    /// Opens provisioned Repair custody before any ordinary startup mutation.
    ///
    /// The same lower writers and actual sidecar owner remain held. An unresolved
    /// token permits only terminal read-only recovery until exact settlement.
    /// This does not activate the unqualified public Repair route.
    ///
    /// # Errors
    ///
    /// Rejects missing or malformed provisioned journals, stale credentials,
    /// unauthenticated cuts, unavailable writer custody, or deferred startup failure.
    #[allow(clippy::too_many_arguments)]
    pub fn open_existing_operator_repair_v4(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        credentials: &crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1,
    ) -> Result<
        (Self, crate::operator_recovery::StorageOperatorRecoveryOwnerV1),
        StorageRuntimeError,
    > {
        let (runtime, owner) = StorageBrokerRuntime::open_existing_operator_repair_v4(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            credentials,
        )?;

        Ok((Self::from_runtime(runtime), owner))
    }

    /// Provisions only the fixed empty operator receipt sidecar, then releases custody.
    ///
    /// All three lower writers must already exist and authenticate. No runtime,
    /// receipt, or effect authority is returned, and ordinary startup never runs.
    /// This does not activate the unqualified public Repair route.
    ///
    /// # Errors
    ///
    /// Rejects missing or changed lower custody, pending lower recovery,
    /// changed role credentials, nonempty or incompatible sidecar history,
    /// unsafe fixed names, or an uncertain creation/synchronization failure.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_empty_operator_repair_v4(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        credentials: &crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1,
    ) -> Result<(), StorageRuntimeError> {
        StorageBrokerRuntime::provision_empty_operator_repair_v4(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            credentials,
        )
    }

    /// Wraps an already-open explicit dormant Apply runtime.
    #[must_use]
    pub const fn from_runtime(runtime: StorageBrokerRuntime) -> Self {
        Self {
            runtime,
            capture_reserve: None,
            capture_reserve_entry: crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1::new(),
            capture_reserve_entered: false,
            capture_query: None,
            capture_query_entry: capture_query::QueryEntryOriginalV3::new(),
            apply_clock: None,
            capture_candidate: None,
            capture_candidate_closed: false,
            capture_candidate_entry: crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1::new(),
            capture_allocation_pin: None,
            nix_generation: None,
            nix_generation_clock_error: None,
            guest_root_template: None,
            _private_live_export_clones: None,
        }
    }

    /// Pins the independently selected AOS package for physical root readback.
    #[must_use]
    pub fn with_guest_root_template(mut self, template: ProtectedGuestRootTemplateV1) -> Self {
        self.guest_root_template = Some(template);
        self
    }

    /// Transfers genuine original Storage startup into this runtime only once.
    ///
    /// This downward loan does not open backend readiness or confer a floor.
    /// Existing constructors leave the original worker slot unavailable.
    ///
    /// # Errors
    ///
    /// Rejects a duplicate, permanently closed, or changed original owner while
    /// preserving incoming startup custody in the typed failure.
    pub fn with_original_worker_startup(
        mut self,
        startup: crate::activation::StorageOriginalWorkerStartupV3,
    ) -> Result<Self, crate::activation::StorageOriginalWorkerStartupErrorV3> {
        self.runtime.install_original_worker_startup(startup)?;
        Ok(self)
    }

    /// Audits private Provider clone history before accepting live-export requests.
    ///
    /// # Errors
    ///
    /// Rejects unsafe journal custody or an interrupted private clone lifecycle.
    pub fn with_private_live_export_cold_audit(
        mut self,
        state_directory: &Path,
    ) -> Result<Self, crate::service::StorageServiceError> {
        self.open_private_live_export_cold_audit(state_directory)
            .map_err(|error| crate::service::StorageServiceError::Activation(error.to_string()))?;
        Ok(self)
    }

    fn open_private_live_export_cold_audit(
        &mut self,
        state_directory: &Path,
    ) -> Result<(), crate::live_export_clone::StorageLiveExportCloneErrorV1> {
        let ledger = StorageLiveExportCloneLedgerV1::open_root_owned(state_directory)?;
        self._private_live_export_clones = Some(ledger);
        Ok(())
    }

    /// Retains the same auxiliary writer in an already parent-owned composition.
    ///
    /// # Errors
    ///
    /// Rejects duplicate admission or unsafe/interrupted private clone history.
    /// The selected caller retains the whole composition on error; the legacy
    /// consuming constructor above keeps its original drop disposition.
    pub fn retain_private_live_export_cold_audit(
        &mut self,
        state_directory: &Path,
    ) -> Result<(), crate::service::StorageServiceError> {
        if self._private_live_export_clones.is_some() {
            return Err(StorageRuntimeError::Recovery.into());
        }
        if let Err(cause) = self.open_private_live_export_cold_audit(state_directory) {
            self.runtime.retain_original_held_startup_failure(
                crate::runtime::original_held_measurement::OriginalHeldMeasurementErrorV3::CloneAudit(cause),
            );
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
        Ok(())
    }

    /// Serves one Controller-signed operator Repair packet on its separate socket.
    ///
    /// # Errors
    ///
    /// Rejects retired activation or protected state requiring process reopen.
    pub fn serve_operator_repair_once(
        &mut self,
        listener: &mut RecordSubjectListener,
        verifier: &crate::peer::ControllerPeerVerifier,
        owner: &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
    ) -> Result<crate::service::StorageConnectionOutcome, crate::service::StorageServiceError> {
        crate::operator_repair_transport::serve_operator_repair_once(
            listener,
            &mut self.runtime,
            verifier,
            owner,
            self.guest_root_template.as_ref(),
        )
    }

    /// Serves one Host-only detached-root request against the retained runtime.
    ///
    /// # Errors
    ///
    /// Rejects changed activation, retired Host cgroup, or protected state requiring reopen.
    pub fn serve_root_export_once(
        &mut self,
        listener: &mut RecordSubjectListener,
        verifier: &crate::peer::HostRootExportPeerVerifier,
    ) -> Result<crate::root_export::RootExportOutcome, crate::service::StorageServiceError> {
        let template = self.guest_root_template.as_ref().ok_or_else(|| {
            crate::service::StorageServiceError::Activation(
                "guest root template is absent".to_owned(),
            )
        })?;
        crate::root_export::serve_root_export_once(listener, &mut self.runtime, verifier, template)
    }

    /// Inspects one authenticated Provider plan without granting an export.
    ///
    /// # Errors
    ///
    /// Rejects changed activation, retired Provider cgroup, or protected state requiring reopen.
    pub fn serve_live_export_request_once(
        &mut self,
        listener: &mut RecordSubjectListener,
        verifier: &crate::peer::ProviderLiveExportPeerVerifier,
        authority_directory: &Path,
        state_directory: &Path,
    ) -> Result<crate::StorageLiveExportTransportOutcomeV1, crate::service::StorageServiceError>
    {
        crate::live_export_transport::serve_live_export_request_once(
            listener,
            &mut self.runtime,
            verifier,
            authority_directory,
            state_directory,
        )
    }

    /// Inspects V1 or delivers a durably accepted V2 original native root.
    ///
    /// # Errors
    ///
    /// Rejects retired activation, Provider identity, or protected state requiring reopen.
    pub fn serve_zfs_hold_request_once(
        &mut self,
        listener: &mut RecordSubjectListener,
        verifier: &crate::peer::ProviderLiveExportPeerVerifier,
        authority_directory: &Path,
        key: Option<&crate::storage_zfs_hold_key::StorageZfsHoldKeyV1>,
    ) -> Result<
        crate::zfs_hold_transport::StorageZfsHoldTransportOutcomeV1,
        crate::service::StorageServiceError,
    > {
        crate::zfs_hold_transport::serve_zfs_hold_request_once(
            listener,
            &mut self.runtime,
            verifier,
            authority_directory,
            key,
        )
    }

    /// Offers the original root, then stores and sends its signed Storage6 once.
    ///
    /// The same child, request, reader and cutoff stay held. Local delivery
    /// establishes neither Source receipt, retirement, public Acquire nor Drain.
    ///
    /// # Errors
    ///
    /// Retains the first concrete native cause and later debt before returning
    /// reopen-required. Failure, interruption and backpressure never resend.
    pub fn serve_original_held_settlement_once(
        &mut self,
        listener: &mut RecordSubjectListener,
        verifier: &crate::peer::ProviderLiveExportPeerVerifier,
        trust: &crate::runtime::StorageOriginalNativeTrustLoanV1<'_>,
        key: &crate::storage_zfs_hold_key::StorageZfsHoldKeyV1,
    ) -> Result<crate::zfs_hold_transport::StorageZfsHoldTransportOutcomeV1,
        crate::service::StorageServiceError> {
        crate::zfs_hold_transport::serve_original_held_settlement_once(
            listener, &mut self.runtime, verifier, trust, key,
        )
    }

    /// Rechecks genuine Output custody through the same moved service original.
    ///
    /// # Errors
    /// Retains the actual Output and original receiving failures on their
    /// owners; refuses absent paid startup, substitution or native/post debt.
    pub fn recheck_execution_output_receiving_v1(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<(), crate::StorageRuntimeError> {
        self.runtime.recheck_execution_output_receiving_v1(output)
    }

    pub(crate) fn runtime_mut_for_service_handoff_v1(&mut self) -> &mut StorageBrokerRuntime {
        &mut self.runtime
    }

    /// Returns the retained runtime for explicit recovery coordination.
    #[must_use]
    pub const fn runtime(&self) -> &StorageBrokerRuntime {
        &self.runtime
    }

    /// Reinstalls exclusion from the actual protected operator owner on reopen.
    ///
    /// # Errors
    ///
    /// Rejects unavailable sidecar custody or conflicting runtime dispatch.
    pub fn retain_operator_terminal_cold_hold(
        &self,
        owner: &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
    ) -> Result<bool, crate::service::StorageServiceError> {
        let unresolved = owner.has_unresolved_terminal_hold_v4()
            .map_err(|_| StorageRuntimeError::ReopenRequired)?;
        if unresolved {
            self.runtime.retain_operator_terminal_exclusion()?;
        }
        Ok(unresolved)
    }

    /// Proves the pinned template and no-effect publisher before accepting sessions.
    ///
    /// # Errors
    ///
    /// Returns an error unless the template is retained and the fixed worker
    /// authenticates through its live socket and exits completely.
    pub fn probe_guest_root_publisher(&self) -> Result<(), StorageRuntimeError> {
        if self.guest_root_template.is_none() {
            return Err(StorageRuntimeError::Recovery);
        }
        self.runtime.probe_guest_root_publisher()
    }

    /// Observes startup health through the same genuine paid Storage original.
    ///
    /// # Errors
    /// Refuses missing template, repeated entry, capacity, native peer/worker
    /// observations, exit or independently owed original posts.
    pub fn probe_guest_root_publisher_receiving_v2(&mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageRuntimeError> {
        if self.guest_root_template.is_none() { return Err(StorageRuntimeError::Recovery); }
        self.runtime.probe_guest_root_publisher_receiving_v2(receiving)
    }

    /// Borrows only the actual retained startup health cause after refusal.
    #[must_use]
    pub fn guest_root_startup_health_failure_v2<'owner>(&'owner self,
        receiving: &'owner aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        self.runtime.guest_root_startup_health_failure_v2(receiving)
    }

    /// Produces Inventory only after paying actual owned domain and worker shapes.
    ///
    /// The same receiving original remains borrowed through the physical pass,
    /// lifecycle/repair construction and later guest-root readback. The actual
    /// response Result is returned directly to the protected resident Session
    /// cycle; it is not cloned into another response owner here.
    ///
    /// # Errors
    /// Refuses unavailable original funding or any ordinary Inventory/readback
    /// error. An independent same-original post also runs after producer error;
    /// the first producer error remains the returned cause.
    pub fn lifecycle_inventory_resources_receiving_v1(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        self.runtime.reserve_inventory_receiving_v1(receiving)?;
        let response = self.runtime.complete_lifecycle_inventory_resources_receiving_v1(
            activation_deadline_boottime_nanoseconds, worker_cutoff_boottime_nanoseconds,
            receiving,
        ).and_then(|body| self.runtime.finish_inventory_body_receiving_v1(
            body, self.guest_root_template.as_ref(), activation_deadline_boottime_nanoseconds,
        ));
        let post = receiving.require_prepare_retention_v1();
        match response {
            Err(error) => Err(error),
            Ok(body) => {
                if post.is_err() {
                    self.runtime.retain_refused_inventory_body_v1(body);
                    return Err(StorageRuntimeError::Receiving);
                }
                Ok(body)
            }
        }
    }

    /// Borrows the actual first domain-shape or worker-observation failure.
    pub fn storage_receiving_inventory_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.runtime.receiving_inventory_demand_failure_v1()
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.runtime.receiving_inventory_worker_failure_v1())
    }

    /// Produces one complete post-observation Storage inventory body.
    ///
    /// The caller must submit these exact bytes through the authenticated
    /// Storage inventory broker-session outcome path. This method performs no
    /// service registration or advertisement.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] when either live workspace observation
    /// or the subsequent protected five-family resolver reread fails.
    pub fn lifecycle_inventory_resources(
        &mut self,
        activation_deadline_boottime_nanoseconds: u64,
        worker_cutoff_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageRuntimeError> {
        let inventory = self.runtime.complete_lifecycle_inventory_resources(
            activation_deadline_boottime_nanoseconds,
            worker_cutoff_boottime_nanoseconds,
        )?;
        self.runtime.finish_inventory_body_ordinary_v1(
            inventory, self.guest_root_template.as_ref(), activation_deadline_boottime_nanoseconds,
        )
    }

    /// Resolves an atomic lifecycle dataset snapshot against protected Storage state.
    ///
    /// This performs no mutation. The returned opaque program includes every
    /// currently owned Dataset row selected by the lifecycle closure, and only
    /// the Storage-owned grouped backend path may consume it.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`](aos_sandbox_controller_domain::lifecycle::LifecyclePhase6ErrorV1)
    /// for a stale inventory head, omitted owned dataset, substituted
    /// SnapshotId, or mismatched protected catalog.
    pub fn prepare_atomic_dataset_snapshot(
        &self,
        plan: &aos_sandbox_controller_domain::lifecycle::LifecycleAtomicDatasetSnapshotPlanV1,
    ) -> Result<crate::DormantAtomicDatasetSnapshotV1, aos_sandbox_controller_domain::lifecycle::LifecyclePhase6ErrorV1>
    {
        self.runtime.prepare_lifecycle_atomic_snapshot(plan)
    }

    /// Recovers one retained coordinated snapshot without redispatching it.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRuntimeError`] for corrupt protected custody or a
    /// worker/projection failure. Ambiguous work is only physically observed.
    pub fn recover_atomic_dataset_snapshot(
        &mut self,
        operation: [u8; 16],
    ) -> Result<crate::AtomicDatasetSnapshotMutationOutcomeV1, StorageRuntimeError> {
        self.runtime.recover_lifecycle_atomic_snapshot(operation)
    }
}

impl sealed::Sealed for DormantStorageApplyCompositionV1 {}

impl DormantStorageBrokerCallsiteV1 for DormantStorageApplyCompositionV1 {
    #[cfg(target_os = "linux")]
    fn consume_authenticated_git_coverage_v1(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        output: &crate::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        if KernelBootId::current()
            .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?
            .into_bytes() != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let sample = super::runtime::trusted_paired_clock_sample()?;
        if sample.host_boot_id() != protected_boot_id {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }
        let original = decode_git_project_coverage_request_v1(
            request_body, method, peer, policy, sample.boottime_nanoseconds(),
        ).map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)?;
        if original.header().request_id() != &request_id
            || original.header().protocol_version() != protocol_version
        {
            return Err(DormantStorageBrokerCallErrorV1::StaleKernel);
        }

        let readback = self.runtime.consume_git_coverage_v1(&original, output)?;
        encode_git_project_coverage_response_v1(&original, readback)
            .map_err(|_| DormantStorageBrokerCallErrorV1::StaleKernel)
    }

    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantStorageBrokerObservationV1, DormantStorageBrokerCallErrorV1> {
        Self::consume_authenticated_apply_inner_v1(
            &mut self.runtime, request_body, request_id, request_body_digest, artifacts, peer, policy,
            protocol_version, protected_boot_id, None, None,
        )
    }

    fn consume_authenticated_operation(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        if method == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1 {
            return self.consume_nix_generation_original_v1(
                request_body, request_id, request_body_digest, artifacts, peer,
                policy, protocol_version, protected_boot_id,
            );
        }
        Self::consume_authenticated_operation_inner_v1(
            &mut self.runtime, self.guest_root_template.as_ref(), method,
            request_body, request_id, request_body_digest, artifacts,
            peer, policy, protocol_version, protected_boot_id, None, None, None,
        )
    }

}

fn storage_observation_commitment(
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    operation: StorageOperation,
    admission: &StorageAdmissionOutcome,
    execution: Option<&StorageRuntimeMutationOutcome>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-storage-broker-observation-v1\0");
    digest.update(request_id);
    digest.update(request_body_digest.as_bytes());
    digest.update([match operation {
        StorageOperation::CreateWorkspace { .. } => 1,
        StorageOperation::Snapshot { .. } => 2,
        StorageOperation::HoldSnapshot { .. } => 3,
        StorageOperation::ReleaseHold { .. } => 4,
        StorageOperation::Clone { .. } => 5,
        StorageOperation::SetQuota { .. } => 6,
        StorageOperation::Destroy { .. } => 7,
    }]);
    match admission {
        StorageAdmissionOutcome::Prepared { mutation_digest } => {
            digest.update([1]);
            digest.update(mutation_digest.as_bytes());
        }
        StorageAdmissionOutcome::ObservationRequired {
            mutation_digest, ..
        } => {
            digest.update([2]);
            digest.update(mutation_digest.as_bytes());
        }
        StorageAdmissionOutcome::Replay(result) => {
            digest.update([3]);
            digest.update(result.result_digest().as_bytes());
        }
        StorageAdmissionOutcome::Aborted { mutation_digest } => {
            digest.update([4]);
            digest.update(mutation_digest.as_bytes());
        }
    }
    match execution {
        Some(StorageRuntimeMutationOutcome::Committed(result)) => {
            digest.update([1]);
            digest.update(result.result_digest().as_bytes());
        }
        Some(StorageRuntimeMutationOutcome::Aborted { mutation_digest }) => {
            digest.update([2]);
            digest.update(mutation_digest.as_bytes());
        }
        Some(StorageRuntimeMutationOutcome::ObservationRequired {
            mutation_digest, ..
        }) => {
            digest.update([3]);
            digest.update(mutation_digest.as_bytes());
        }
        None => digest.update([0]),
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

mod capture_query;
mod capture_reserve;

impl DormantStorageApplyCompositionV1 {
    /// Runs logical46 with the same actual Host outcome and entered Storage F.
    ///
    /// Every native result stays on the supplied original. A response is only
    /// borrowable after all actual action, Output and service posts finish.
    #[doc(hidden)]
    pub fn register_original_execution_output_receiving_v1(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        host: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        self.runtime.register_original_execution_output_receiving_v1(output, attempt, Some(host), lifecycle, session, socket);
    }

    /// Queries historical logical47 under the same actual Storage F.
    ///
    /// This path observes only the existing original marker. It cannot enter
    /// a Host readback, reserve a row or produce a physical Capture lifetime.
    #[doc(hidden)]
    pub fn query_original_execution_output_receiving_v1(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        self.runtime.register_original_execution_output_receiving_v1(output, attempt, None, lifecycle, session, socket);
    }
}

impl DormantStorageApplyCompositionV1 {
    /// Observes the real candidate under the actual paid same-F Session Domain.
    ///
    /// Unit return carries no proof. The caller retains this whole composition
    /// and borrows the response only after every native and independent post.
    pub fn observe_original_capture_candidate_receiving_v1(
        &mut self, output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        version: ProtocolVersion, boot: KernelBootId,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal, socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if self.capture_candidate_closed || self.capture_candidate.is_some() || self.capture_candidate_entry.failure().is_some() { return; }
        let demand = (|| {
            let state = self.runtime.capture_candidate_state_receiving_demand_v1()?;
            crate::runtime::capture_candidate::CandidateNativeOriginalV1::receiving_demand_v1(state, request)
        })();
        if self.capture_candidate_entry.prepare(lifecycle, session, socket, demand) {
            let mut attempt = Box::new(crate::runtime::capture_candidate::OriginalCaptureCandidateV1::empty(request, version, boot));
            attempt.enable_receiving_after_payment_v1();
            self.capture_candidate = Some(attempt);
        }
        self.capture_candidate_entry.finish(lifecycle, session, socket);
        if self.capture_candidate_entry.failure().is_some() { return; }
        let Some(attempt) = self.capture_candidate.as_mut() else { return; };
        self.runtime.observe_original_capture_candidate_receiving_v1(attempt, output,
            &mut self.capture_allocation_pin, lifecycle, session, socket);
    }

    /// Takes only the same real candidate's completely checked response copy.
    #[must_use]
    pub fn take_original_capture_candidate_response_receiving_v1(&mut self) -> Option<Vec<u8>> {
        if self.capture_candidate_entry.failure().is_some() { return None; }
        self.capture_candidate.as_mut()?.take_response()
    }

    /// Borrows the actual first constructor or candidate cause without dropping it.
    #[must_use]
    pub fn original_capture_candidate_receiving_failure_v1<'cause>(&'cause self,
        output: &'cause crate::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.capture_candidate_entry.failure().or_else(||
            self.capture_candidate.as_ref()?.receiving_failure_v1(output))
    }

    /// Rechecks the retained candidate before actual funded signing or delivery.
    ///
    /// # Errors
    /// Refuses missing or failed originals, changed policies/owners, expiry,
    /// native post debt or unaffordable same-F observation. Failure stays held.
    pub fn recheck_original_capture_candidate_receiving_v1(
        &mut self, output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        before_signing: bool, lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal, socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        if self.capture_candidate_entry.failure().is_some() { return Err(DormantStorageBrokerCallErrorV1::StaleKernel); }
        let attempt = self.capture_candidate.as_mut().ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        self.runtime.recheck_original_capture_candidate_receiving_v1(attempt, output, before_signing, lifecycle, session, socket);
        if attempt.failure().is_some() || attempt.postcheck_debt().is_some() { return Err(DormantStorageBrokerCallErrorV1::StaleKernel); }
        Ok(())
    }
}

impl DormantStorageApplyCompositionV1 {
    /// Prearms the exact candidate's independent Output post before actual send.
    ///
    /// # Errors
    /// Refuses a missing/failed candidate, changed current source, expiry or
    /// unavailable actual same-F post capacity. All original causes stay held.
    pub fn prepare_original_capture_candidate_delivery_v1(
        &mut self, output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal, socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        let attempt = self.capture_candidate.as_mut().ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        self.runtime.prepare_capture_candidate_delivery_receiving_v1(attempt, output, lifecycle, session, socket);
        if attempt.failure().is_some() || attempt.postcheck_debt().is_some() { return Err(DormantStorageBrokerCallErrorV1::StaleKernel); }
        Ok(())
    }

    /// Completes the already owed candidate source post after every actual send.
    ///
    /// # Errors
    /// Reports original policy/native/source change or a missing prearmed
    /// destination. This path remains available after the sender poisons F.
    pub fn finish_original_capture_candidate_delivery_v1(
        &mut self, output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal, socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        let attempt = self.capture_candidate.as_mut().ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        self.runtime.finish_capture_candidate_delivery_receiving_v1(attempt, output, lifecycle, session, socket);
        if attempt.failure().is_some() || attempt.postcheck_debt().is_some() { return Err(DormantStorageBrokerCallErrorV1::StaleKernel); }
        Ok(())
    }
}
