//! Durably admits one current Mount dispatch attempt.
//!
//! Catalog preparation and signed-plan binding retain live descriptor authority
//! only in memory for namespace operations. Release instead retains a current
//! catalogless target because it removes broker custody after namespace work is
//! complete. This module consumes either volatile proof, derives one exact
//! lease- and deadline-bound packet, and synchronously records the packet before
//! returning it:
//!
//! ```text
//! live namespace target + prepared operation + signed Mount plan
//!     -> reverify current lease and attenuate deadline
//!     -> commit exact request, packet, and namespace audit reference
//!     -> return a non-cloneable live dispatch token
//! ```
//!
//! The durable record is audit and crash-correlation state, not reconstructed
//! authority. Restart loses the token and any Mount descriptor catalog. After
//! authenticated inventory proves the exact operation remains pending, the
//! controller must reacquire that catalog, reproduce the original signed plan,
//! and obtain a current ownership lease. It may then rebuild an envelope around
//! only the original request body and deadline.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod, MountAction};
use aos_sandbox_core::format::{
    decode_broker_authorization_plan, decode_ownership_lease, decode_signature,
};
use aos_sandbox_core::model::SignaturePurpose;
use aos_sandbox_core::{
    BrokerAudience, DecodeLimits, MediaType, ObjectDigest, PortableMediaType, ProtocolId,
    ProtocolVersion, RawPairedClockSample, descriptor_for_bytes,
};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_protocol::semantics::mount::{MountCatalogBindingV1, canonical_mount_semantics_v1};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, decode_mount_request,
    decode_request_envelope, detached_mount_handle_v1,
};
use sha2::{Digest as _, Sha256};

use crate::dispatch::{
    BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1, semantic_identity_digest,
    template_digest_from_parts, validate_durable_attempt_body, validate_durable_deadline_free_body,
};
use crate::mount_preparation::check_mount_deadline;
use crate::mount_preparation::{
    MountCatalogPreparationError, PreparedCurrentMountDispatchV1,
    PreparedCurrentMountReleaseDispatchV1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{
    CurrentRuntimeScopeError, DurableNamespaceTargetReferenceV1, NamespaceTargetError,
    validate_durable_reference_in_validated_namespace, validate_namespace_target_namespace,
};
use crate::{
    BrokerDispatchTemplateV1, Journal, JournalError, JournalRecord, JournalTransaction,
    RecordNamespace,
};

mod completion;
mod format;
mod inventory;
#[cfg(test)]
mod tests;

pub use completion::{
    CompletedCurrentMountAttemptV1, MountCompletionOutcomeV1, MountDispatchClient,
};
pub(crate) use completion::{
    dispatch_current, validate_namespace as validate_completion_namespace,
};
#[cfg(test)]
pub(crate) use inventory::controller_state_digest as mount_controller_state_digest;
pub use inventory::{
    CurrentMountInventoryReconciliationV1, DurableMountInventorySnapshotV1,
    MountAttemptInventoryObservationV1, MountAttemptInventoryStatusV1, MountInventoryClient,
    MountInventorySnapshotOutcomeV1,
};
pub(crate) use inventory::{
    destination_slot_absent_in_fresh_inventory, reconcile_current as reconcile_current_inventory,
    record_snapshot, source_view_absent_in_fresh_inventory,
    validate_namespace as validate_inventory_namespace,
};

const NAMESPACE: RecordNamespace = RecordNamespace::MountAttempt;
const MOUNT_CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);
const AUTHORITY_VERSION: ProtocolVersion = ProtocolVersion::new(1, 1);
const MAXIMUM_RESPONSE_BYTES: u32 = 16 * 1024;
const MAXIMUM_ATTEMPTS: usize = 4096;
const MAXIMUM_NAMESPACE_BYTES: usize = 256 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 3 * MAXIMUM_REQUEST_BYTES + 1024;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.mount-attempt.transaction.v1\0";

/// Reports stale live authority, conflicting replay, or corrupt durable state.
#[derive(Debug, thiserror::Error)]
pub enum MountAttemptError {
    /// A retained Mount-attempt record or one of its cross-references is inconsistent.
    #[error("mount attempt history is corrupt")]
    CorruptState,
    /// One request identity is already bound to different exact attempt bytes.
    #[error("mount attempt request identity conflicts with durable state")]
    Conflict,
    /// The fixed attempt-count or retained-byte ceiling is exhausted.
    #[error("mount attempt capacity is exhausted")]
    Capacity,
    /// The requested attempt deadline exceeds the prepared operation lifetime.
    #[error("mount attempt deadline exceeds the prepared operation lifetime")]
    Deadline,
    /// The responding process is not the configured live Mount service execution.
    #[error("Mount response does not match the pinned Mount service")]
    MountIdentity,
    /// Mount rejected or could not complete the request.
    #[error("Mount rejected the request with {code:?} (retryable: {retryable})")]
    BrokerRejected {
        /// Closed broker error code.
        code: aos_proto::aos::sandbox::local::v1::BrokerErrorCode,
        /// Whether the same semantics may succeed on a later attempt.
        retryable: bool,
    },
    /// Negotiated envelopes or the Mount result failed validation.
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// Kernel record-subject validation or packet transfer failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Kernel service identity or cgroup validation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Volatile operation preparation is stale, expired, or otherwise invalid.
    #[error(transparent)]
    Preparation(#[from] MountCatalogPreparationError),
    /// Current signed plan, ownership lease, or attempt attenuation failed.
    #[error(transparent)]
    Current(#[from] CurrentRuntimeScopeError),
    /// The referenced namespace-target audit history failed validation.
    #[error(transparent)]
    NamespaceTarget(#[from] NamespaceTargetError),
    /// Protected journal provenance, health, or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Reports whether exact durable admission committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountAttemptAdmissionOutcomeV1 {
    /// The exact attempt became durable in this call.
    Admitted,
    /// The exact attempt was already durable under the same request identity.
    Replay,
}

/// Retains live authority for a Mount request durably admitted before I/O.
///
/// A first issue retains the packet recorded at admission. A pending resume may
/// carry a newer ownership lease with the exact original plan and Apply body;
/// that envelope is intentionally volatile. This token cannot be cloned, and
/// every packet remains non-authorizing until Mount independently verifies the
/// signatures, fence, semantics, protected clock, and durable idempotency state.
///
/// ```compile_fail
/// use aos_sandbox::mount_attempt::DurableCurrentMountAttemptV1;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<DurableCurrentMountAttemptV1>();
/// ```
pub struct DurableCurrentMountAttemptV1 {
    prepared: PreparedMountDispatch,
    attempt: BrokerDispatchAttemptV1,
    record: Record,
    outcome: MountAttemptAdmissionOutcomeV1,
    packet_source: MountAttemptPacketSource,
}

#[derive(Clone, Copy)]
enum MountAttemptPacketSource {
    Recorded,
    Reconstructed,
}

enum PreparedMountDispatch {
    Catalog(PreparedCurrentMountDispatchV1),
    Release(PreparedCurrentMountReleaseDispatchV1),
}

impl PreparedMountDispatch {
    fn target(&self) -> &crate::runtime_scope::CurrentNamespaceTarget {
        match self {
            Self::Catalog(prepared) => prepared.catalog().target(),
            Self::Release(prepared) => prepared.release().target(),
        }
    }

    fn template(&self) -> &crate::BrokerDispatchTemplateV1 {
        match self {
            Self::Catalog(prepared) => prepared.template(),
            Self::Release(prepared) => prepared.template(),
        }
    }

    fn catalog_commitment(&self) -> Option<ObjectDigest> {
        match self {
            Self::Catalog(prepared) => Some(prepared.catalog().catalog_commitment()),
            Self::Release(_) => None,
        }
    }

    fn valid_until_boottime_nanoseconds(&self) -> u64 {
        match self {
            Self::Catalog(prepared) => prepared.catalog().valid_until_boottime_nanoseconds(),
            Self::Release(prepared) => prepared.release().valid_until_boottime_nanoseconds(),
        }
    }

    fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), MountCatalogPreparationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        match self {
            Self::Catalog(prepared) => prepared.recheck(journal, clock),
            Self::Release(prepared) => prepared.recheck(journal, clock),
        }
    }
}

impl DurableCurrentMountAttemptV1 {
    /// Returns whether this call committed or replayed the exact durable record.
    #[must_use]
    pub const fn outcome(&self) -> MountAttemptAdmissionOutcomeV1 {
        self.outcome
    }

    /// Returns the stable request identity used as Mount's idempotency key.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete versioned durable attempt record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns the exact catalog commitment authorized by the signed Mount plan.
    ///
    /// Catalogless release attempts return `None`.
    #[must_use]
    pub fn catalog_commitment(&self) -> Option<ObjectDigest> {
        self.record.catalog_commitment.map(ObjectDigest::from_bytes)
    }

    /// Returns the signed namespace generation retained by the live target.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.record.namespace_target.target_generation()
    }

    /// Borrows the packet carrying the exact durably admitted Apply body.
    #[must_use]
    pub const fn dispatch_attempt(&self) -> &BrokerDispatchAttemptV1 {
        &self.attempt
    }

    pub(crate) fn target(&self) -> &crate::runtime_scope::CurrentNamespaceTarget {
        self.prepared.target()
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), MountAttemptError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.prepared.recheck(journal, clock)?;
        check_mount_deadline(self.attempt.deadline_boottime_nanoseconds())?;

        let history = History::load(journal)?;
        let attempt_matches = match self.packet_source {
            MountAttemptPacketSource::Recorded => {
                self.record.matches_attempt(&self.prepared, &self.attempt)?
            }
            MountAttemptPacketSource::Reconstructed => self
                .record
                .matches_resumed_attempt(&self.prepared, &self.attempt)?,
        };
        if history.records.get(&self.record.request_id) != Some(&self.record) || !attempt_matches {
            return Err(MountAttemptError::Conflict);
        }

        self.prepared.recheck(journal, clock)?;
        check_mount_deadline(self.attempt.deadline_boottime_nanoseconds())?;
        Ok(())
    }
}

pub(crate) fn admit_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentMountDispatchV1,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<DurableCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    admit_prepared(
        journal,
        PreparedMountDispatch::Catalog(prepared),
        deadline_boottime_nanoseconds,
        clock,
    )
}

pub(crate) fn admit_current_release<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentMountReleaseDispatchV1,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<DurableCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    admit_prepared(
        journal,
        PreparedMountDispatch::Release(prepared),
        deadline_boottime_nanoseconds,
        clock,
    )
}

pub(crate) fn resume_current<T>(
    journal: &mut Journal,
    record: Record,
    prepared: PreparedCurrentMountDispatchV1,
    clock: &mut T,
) -> Result<DurableCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    resume_prepared(
        journal,
        record,
        PreparedMountDispatch::Catalog(prepared),
        clock,
    )
}

pub(crate) fn resume_current_release<T>(
    journal: &mut Journal,
    record: Record,
    prepared: PreparedCurrentMountReleaseDispatchV1,
    clock: &mut T,
) -> Result<DurableCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    resume_prepared(
        journal,
        record,
        PreparedMountDispatch::Release(prepared),
        clock,
    )
}

fn admit_prepared<T>(
    journal: &mut Journal,
    prepared: PreparedMountDispatch,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<DurableCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    if deadline_boottime_nanoseconds > prepared.valid_until_boottime_nanoseconds() {
        return Err(MountAttemptError::Deadline);
    }

    let history = History::load(journal)?;
    let target = prepared.target();
    let attempt = target.runtime_generation().scope().prepare_mount_attempt(
        journal,
        prepared.template(),
        deadline_boottime_nanoseconds,
        clock,
    )?;
    check_mount_deadline(attempt.deadline_boottime_nanoseconds())?;
    let record = Record::from_attempt(&prepared, &attempt)?;

    let outcome = match history.admission_outcome(&record)? {
        Some(outcome) => outcome,
        None => {
            history.ensure_capacity(&record)?;
            prepared.recheck(journal, clock)?;
            journal.commit(&record.transaction()?)?;
            MountAttemptAdmissionOutcomeV1::Admitted
        }
    };

    // A successful commit can leave inert audit state if authority changes.
    // Never let the packet escape without checking both durable and live heads.
    let committed = History::load(journal)?;
    if committed.records.get(&record.request_id) != Some(&record) {
        return Err(MountAttemptError::CorruptState);
    }
    prepared.recheck(journal, clock)?;
    check_mount_deadline(attempt.deadline_boottime_nanoseconds())?;

    Ok(DurableCurrentMountAttemptV1 {
        prepared,
        attempt,
        record,
        outcome,
        packet_source: MountAttemptPacketSource::Recorded,
    })
}

fn resume_prepared<T>(
    journal: &mut Journal,
    record: Record,
    prepared: PreparedMountDispatch,
    clock: &mut T,
) -> Result<DurableCurrentMountAttemptV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    if record.namespace_target != prepared.target().durable_reference() {
        return Err(MountAttemptError::Conflict);
    }
    if record.deadline_boottime_nanoseconds > prepared.valid_until_boottime_nanoseconds() {
        return Err(MountAttemptError::Deadline);
    }
    check_mount_deadline(record.deadline_boottime_nanoseconds)?;

    let history = History::load(journal)?;
    if history.records.get(&record.request_id) != Some(&record) {
        return Err(MountAttemptError::Conflict);
    }
    let attempt = prepared
        .target()
        .runtime_generation()
        .scope()
        .prepare_mount_attempt(
            journal,
            prepared.template(),
            record.deadline_boottime_nanoseconds,
            clock,
        )?;
    if !record.matches_resumed_attempt(&prepared, &attempt)? {
        return Err(MountAttemptError::Conflict);
    }

    prepared.recheck(journal, clock)?;
    check_mount_deadline(record.deadline_boottime_nanoseconds)?;
    let resumed = DurableCurrentMountAttemptV1 {
        prepared,
        attempt,
        record,
        outcome: MountAttemptAdmissionOutcomeV1::Replay,
        packet_source: MountAttemptPacketSource::Reconstructed,
    };
    resumed.recheck(journal, clock)?;
    Ok(resumed)
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), MountAttemptError> {
    History::load(journal).map(|_| ())
}

pub(crate) fn replay_record(
    journal: &mut Journal,
    request_id: [u8; 16],
    target: &crate::runtime_scope::CurrentNamespaceTarget,
) -> Result<Record, MountAttemptError> {
    let history = History::load(journal)?;
    let record = history
        .records
        .get(&request_id)
        .cloned()
        .ok_or(MountAttemptError::Conflict)?;
    if record.namespace_target != target.durable_reference() {
        return Err(MountAttemptError::Conflict);
    }
    check_mount_deadline(record.deadline_boottime_nanoseconds)?;
    Ok(record)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Record {
    request_id: [u8; 16],
    namespace_target: DurableNamespaceTargetReferenceV1,
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    catalog_commitment: Option<[u8; 32]>,
    semantic_digest: [u8; 32],
    plan_digest: [u8; 32],
    template_digest: [u8; 32],
    lease_digest: [u8; 32],
    lease_generation: u64,
    deadline_boottime_nanoseconds: u64,
    template_body: Vec<u8>,
    body: Vec<u8>,
    packet: Vec<u8>,
    digest: [u8; 32],
}

impl Record {
    fn from_attempt(
        prepared: &PreparedMountDispatch,
        attempt: &BrokerDispatchAttemptV1,
    ) -> Result<Self, MountAttemptError> {
        let decoded = decode_attempt_body(attempt.body(), attempt.deadline_boottime_nanoseconds())?;
        let assignment = prepared.template().signed_plan().plan().assignment();
        let mut record = Self {
            request_id: *decoded.header().request_id(),
            namespace_target: prepared.target().durable_reference(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: *assignment.digest().as_bytes(),
            catalog_commitment: prepared
                .catalog_commitment()
                .map(|commitment| *commitment.as_bytes()),
            semantic_digest: *semantic_identity_digest(prepared.template().semantics()).as_bytes(),
            plan_digest: *prepared.template().signed_plan().digest().as_bytes(),
            template_digest: *attempt.template_digest().as_bytes(),
            lease_digest: *attempt.lease_digest().as_bytes(),
            lease_generation: attempt.lease_generation(),
            deadline_boottime_nanoseconds: attempt.deadline_boottime_nanoseconds(),
            template_body: prepared.template().body_without_deadline().to_vec(),
            body: attempt.body().to_vec(),
            packet: attempt.packet().to_vec(),
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate_contents()?;
        Ok(record)
    }

    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub(crate) const fn namespace_target(&self) -> DurableNamespaceTargetReferenceV1 {
        self.namespace_target
    }

    pub(crate) fn catalog_commitment(&self) -> Option<ObjectDigest> {
        self.catalog_commitment.map(ObjectDigest::from_bytes)
    }

    pub(crate) const fn plan_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.plan_digest)
    }

    pub(crate) const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    pub(crate) fn body_without_deadline(&self) -> &[u8] {
        &self.template_body
    }

    pub(crate) fn matches_resume_template(&self, template: &BrokerDispatchTemplateV1) -> bool {
        let assignment = template.signed_plan().plan().assignment();

        self.assignment_epoch == assignment.epoch().get()
            && self.desired_generation == assignment.desired_generation().get()
            && self.assignment_digest == *assignment.digest().as_bytes()
            && self.plan_digest == *template.signed_plan().digest().as_bytes()
            && self.template_digest == *template.digest().as_bytes()
            && self.semantic_digest == *semantic_identity_digest(template.semantics()).as_bytes()
            && self.template_body == template.body_without_deadline()
    }

    pub(crate) fn action(&self) -> Result<MountAction, MountAttemptError> {
        Ok(decode_attempt_body(&self.body, self.deadline_boottime_nanoseconds)?.action())
    }

    pub(crate) fn mount_handle(&self) -> Result<[u8; 32], MountAttemptError> {
        let request = decode_attempt_body(&self.body, self.deadline_boottime_nanoseconds)?;
        if request.action() == MountAction::MOUNT_ACTION_CREATE_DETACHED {
            return Ok(detached_mount_handle_v1(Sha256::digest(&self.body).into()));
        }
        request
            .detached_mount_handle()
            .copied()
            .ok_or(MountAttemptError::CorruptState)
    }

    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(17);
        key.push(b'a');
        key.extend_from_slice(&self.request_id);
        key
    }

    fn transaction(&self) -> Result<JournalTransaction, MountAttemptError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| MountAttemptError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, self.key(), self.encode())],
        )?)
    }

    fn encoded_len(&self) -> usize {
        format::FIXED_RECORD_BYTES
            .saturating_add(self.template_body.len())
            .saturating_add(self.body.len())
            .saturating_add(self.packet.len())
    }

    fn matches_attempt(
        &self,
        prepared: &PreparedMountDispatch,
        attempt: &BrokerDispatchAttemptV1,
    ) -> Result<bool, MountAttemptError> {
        Ok(self == &Self::from_attempt(prepared, attempt)?)
    }

    fn matches_resumed_attempt(
        &self,
        prepared: &PreparedMountDispatch,
        attempt: &BrokerDispatchAttemptV1,
    ) -> Result<bool, MountAttemptError> {
        let candidate = Self::from_attempt(prepared, attempt)?;
        Ok(self.matches_resumed_record(&candidate))
    }

    fn matches_resumed_record(&self, candidate: &Self) -> bool {
        // `candidate` was reconstructed through the ordinary live verifier and
        // fully validated by `from_attempt`. Mount's equal-generation fence
        // requires the exact original plan; only its monotonic lease and the
        // resulting envelope may legitimately change.
        self.request_id == candidate.request_id
            && self.namespace_target == candidate.namespace_target
            && self.assignment_epoch == candidate.assignment_epoch
            && self.desired_generation == candidate.desired_generation
            && self.assignment_digest == candidate.assignment_digest
            && self.catalog_commitment == candidate.catalog_commitment
            && self.semantic_digest == candidate.semantic_digest
            && self.plan_digest == candidate.plan_digest
            && self.template_digest == candidate.template_digest
            && self.deadline_boottime_nanoseconds == candidate.deadline_boottime_nanoseconds
            && self.template_body == candidate.template_body
            && self.body == candidate.body
            && (candidate.lease_generation > self.lease_generation
                || (candidate.lease_generation == self.lease_generation
                    && candidate.lease_digest == self.lease_digest))
    }

    fn validate_contents(&self) -> Result<(), MountAttemptError> {
        if self.request_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
            || self.catalog_commitment == Some([0; 32])
            || self.semantic_digest == [0; 32]
            || self.plan_digest == [0; 32]
            || self.template_digest == [0; 32]
            || self.lease_digest == [0; 32]
            || self.lease_generation == 0
            || self.deadline_boottime_nanoseconds == 0
            || self.template_body.is_empty()
            || self.template_body.len() > MAXIMUM_REQUEST_BYTES
            || self.body.is_empty()
            || self.body.len() > MAXIMUM_REQUEST_BYTES
            || self.packet.is_empty()
            || self.packet.len() > MAXIMUM_REQUEST_BYTES
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
            || !validate_durable_deadline_free_body(&self.template_body)
            || !validate_durable_attempt_body(
                &self.template_body,
                self.deadline_boottime_nanoseconds,
                &self.body,
            )
        {
            return Err(MountAttemptError::CorruptState);
        }

        let request = decode_attempt_body(&self.body, self.deadline_boottime_nanoseconds)?;
        self.validate_request(&request)?;

        let envelope = decode_request_envelope(&self.packet, ProtocolId::MountBroker, 0)
            .map_err(|_| MountAttemptError::CorruptState)?;
        if envelope.method() != BrokerMethod::BROKER_METHOD_MOUNT_APPLY
            || !envelope.descriptors().is_empty()
            || envelope.body() != self.body
        {
            return Err(MountAttemptError::CorruptState);
        }
        let artifacts = envelope
            .authorization()
            .ok_or(MountAttemptError::CorruptState)?;
        self.validate_artifacts(artifacts, &request)
    }

    fn validate_request(
        &self,
        request: &aos_sandbox_protocol::ValidatedMountRequest,
    ) -> Result<(), MountAttemptError> {
        let fence = request.fence();
        if request.header().request_id() != &self.request_id
            || request.header().protocol_version() != MOUNT_CARRIER_VERSION
            || request.header().audience() != Audience::AUDIENCE_NODE_CONTROLLER
            || request.header().deadline_boottime_nanoseconds()
                != self.deadline_boottime_nanoseconds
            || request.header().maximum_response_bytes() != MAXIMUM_RESPONSE_BYTES
            || (request.action() == MountAction::MOUNT_ACTION_RELEASE)
                != self.catalog_commitment.is_none()
            || fence.sandbox_id() != self.namespace_target.sandbox().as_bytes()
            || fence.incarnation_id() != self.namespace_target.incarnation().as_bytes()
            || fence.assignment_epoch() != self.assignment_epoch
            || fence.desired_generation() != self.desired_generation
            || fence.assignment_digest() != &self.assignment_digest
            || request.namespace_generation() != self.namespace_target.target_generation()
        {
            return Err(MountAttemptError::CorruptState);
        }

        Ok(())
    }

    fn validate_artifacts(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::ValidatedMountRequest,
    ) -> Result<(), MountAttemptError> {
        let plan =
            decode_broker_authorization_plan(artifacts.broker_plan(), DecodeLimits::default())
                .map_err(|_| MountAttemptError::CorruptState)?;
        let lease = decode_ownership_lease(artifacts.ownership_lease(), DecodeLimits::default())
            .map_err(|_| MountAttemptError::CorruptState)?;
        let plan_signature =
            decode_signature(artifacts.broker_plan_signature(), DecodeLimits::default())
                .map_err(|_| MountAttemptError::CorruptState)?;
        let lease_signature = decode_signature(
            artifacts.ownership_lease_signature(),
            DecodeLimits::default(),
        )
        .map_err(|_| MountAttemptError::CorruptState)?;
        let plan_descriptor = artifact_descriptor(
            PortableMediaType::BrokerAuthorizationPlan,
            artifacts.broker_plan(),
        )?;
        let lease_descriptor = artifact_descriptor(
            PortableMediaType::OwnershipLease,
            artifacts.ownership_lease(),
        )?;
        let assignment = plan.assignment();
        let lease_assignment = lease.assignment();

        if plan.audience() != BrokerAudience::Mount
            || plan.protocol() != ProtocolId::MountBroker
            || plan.protocol_version() != AUTHORITY_VERSION
            || assignment.sandbox() != self.namespace_target.sandbox()
            || assignment.incarnation() != self.namespace_target.incarnation()
            || assignment.epoch().get() != self.assignment_epoch
            || assignment.desired_generation().get() != self.desired_generation
            || assignment.digest().as_bytes() != &self.assignment_digest
            || lease_assignment.sandbox() != assignment.sandbox()
            || lease_assignment.incarnation() != assignment.incarnation()
            || lease_assignment.epoch() != assignment.epoch()
            || lease_assignment.digest() != assignment.digest()
            || lease.node() != plan.node()
            || lease.lease_generation() != self.lease_generation
            || plan_descriptor.digest().as_bytes() != &self.plan_digest
            || lease_descriptor.digest().as_bytes() != &self.lease_digest
            || plan_signature.statement().subject() != &plan_descriptor
            || plan_signature.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || plan_signature.statement().issued_seconds() != plan.issued_seconds()
            || plan_signature.statement().expires_seconds() != Some(plan.expires_seconds())
            || lease_signature.statement().subject() != &lease_descriptor
            || lease_signature.statement().purpose() != SignaturePurpose::OwnershipLease
            || lease_signature.statement().signer() != plan.ownership_authority()
            || lease_signature.statement().issued_seconds() != lease.authority_issued_seconds()
            || lease_signature.statement().expires_seconds()
                != Some(lease.authority_expires_seconds())
        {
            return Err(MountAttemptError::CorruptState);
        }

        let catalog = self
            .catalog_commitment
            .map(ObjectDigest::from_bytes)
            .map(MountCatalogBindingV1::from_verified_digest)
            .transpose()
            .map_err(|_| MountAttemptError::CorruptState)?;
        let canonical = canonical_mount_semantics_v1(request, catalog, &[])
            .map_err(|_| MountAttemptError::CorruptState)?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            canonical.verb(),
            canonical.target(),
            canonical.commitment(),
        );
        let request_bytes =
            u32::try_from(self.body.len()).map_err(|_| MountAttemptError::CorruptState)?;
        let matching_grant = plan.grants().iter().any(|grant| {
            grant.verb() == semantics.verb()
                && grant.target() == semantics.target()
                && grant.argument_commitment() == semantics.argument_commitment()
                && request_bytes <= grant.maximum_request_bytes()
        });
        if !matching_grant
            || semantic_identity_digest(semantics).as_bytes() != &self.semantic_digest
            || template_digest_from_parts(
                plan_descriptor.digest(),
                artifacts.broker_plan_signature(),
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
                &self.template_body,
                &[],
                semantics,
            )
            .as_bytes()
                != &self.template_digest
        {
            return Err(MountAttemptError::CorruptState);
        }

        Ok(())
    }
}

#[derive(Default)]
struct History {
    records: BTreeMap<[u8; 16], Record>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &mut Journal) -> Result<Self, MountAttemptError> {
        journal.ensure_healthy()?;

        let mut decoded = Vec::new();
        let mut retained_bytes = 0_usize;
        for (key, value) in journal.records(NAMESPACE) {
            retained_bytes = retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(MountAttemptError::Capacity)?;
            if decoded.len() >= MAXIMUM_ATTEMPTS
                || retained_bytes > MAXIMUM_NAMESPACE_BYTES
                || value.len() > MAXIMUM_RECORD_BYTES
            {
                return Err(MountAttemptError::Capacity);
            }

            let record = Record::decode(value)?;
            if key != record.key() {
                return Err(MountAttemptError::CorruptState);
            }
            record.validate_contents()?;
            decoded.push(record);
        }

        if !decoded.is_empty() {
            validate_namespace_target_namespace(journal)?;
            for record in &decoded {
                validate_durable_reference_in_validated_namespace(
                    journal,
                    record.namespace_target,
                )?;
            }
        }

        let mut records = BTreeMap::new();
        for record in decoded {
            let request_id = record.request_id;
            if records.insert(request_id, record).is_some() {
                return Err(MountAttemptError::CorruptState);
            }
        }

        Ok(Self {
            records,
            retained_bytes,
        })
    }

    fn ensure_capacity(&self, record: &Record) -> Result<(), MountAttemptError> {
        let next_bytes = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(MountAttemptError::Capacity)?;
        if self.records.len() >= MAXIMUM_ATTEMPTS || next_bytes > MAXIMUM_NAMESPACE_BYTES {
            return Err(MountAttemptError::Capacity);
        }
        Ok(())
    }

    fn admission_outcome(
        &self,
        record: &Record,
    ) -> Result<Option<MountAttemptAdmissionOutcomeV1>, MountAttemptError> {
        match self.records.get(&record.request_id) {
            Some(existing) if existing == record => {
                Ok(Some(MountAttemptAdmissionOutcomeV1::Replay))
            }
            Some(_) => Err(MountAttemptError::Conflict),
            None => Ok(None),
        }
    }
}

fn decode_attempt_body(
    body: &[u8],
    deadline_boottime_nanoseconds: u64,
) -> Result<aos_sandbox_protocol::ValidatedMountRequest, MountAttemptError> {
    let now = deadline_boottime_nanoseconds
        .checked_sub(1)
        .ok_or(MountAttemptError::CorruptState)?;
    decode_mount_request(
        body,
        PeerCredentials {
            uid: 1,
            gid: 1,
            pid: Some(1),
        },
        PeerPolicy {
            uid: 1,
            gid: Some(1),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
    )
    .map_err(|_| MountAttemptError::CorruptState)
}

fn artifact_descriptor(
    media_type: PortableMediaType,
    bytes: &[u8],
) -> Result<aos_sandbox_core::ObjectDescriptor, MountAttemptError> {
    let media_type = MediaType::new(media_type.as_str().to_owned())
        .map_err(|_| MountAttemptError::CorruptState)?;
    Ok(descriptor_for_bytes(media_type, bytes))
}
