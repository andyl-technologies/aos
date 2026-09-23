//! Protected identity reservation for a public execution attachment.
//!
//! A pending record has no operation, idempotency, desired-state, or route
//! effect. Its fixed encoding binds the eventual operation to the request and
//! current execution before a Host installs the matching forced-command gate.
//!
//! ```text
//! AOSAPN01 | request digest | operation | execution | incarnation |
//! epoch | principal | audit | expiry seconds | SHA-256 of preceding bytes
//! ```

use aos_proto::aos::sandbox::v1::ExecutionPhase;
use aos_sandbox_core::public_attach_grant::{
    PUBLIC_ATTACH_GRANT_BYTES, PublicAttachPendingGrantV1, sign_public_attach_pending_grant_v1,
};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, NodeId, OperationId, ProjectId,
    ProtocolId, ProtocolVersion, SandboxId,
};
use aos_sandbox_protocol::semantics::host_attach_gate::canonical_host_attach_gate_semantics_v1;
use aos_sandbox_protocol::HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::publication::AuthorityPublicationStore;
use crate::runtime_authority::{
    RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};
use crate::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};

const MAGIC: &[u8; 8] = b"AOSAPN01";
const VALUE_BYTES: usize = 8 + 32 + 16 + 16 + 16 + 8 + 16 + 16 + 8 + 32;
const MAXIMUM_PENDING_SECONDS: i64 = 300;

/// Binds a Host gate attempt to one durably reserved public attach operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAttachPendingV1 {
    key: IdempotencyKey,
    request_digest: [u8; 32],
    operation: OperationId,
    execution: [u8; 16],
    incarnation: [u8; 16],
    assignment_epoch: u64,
    principal: [u8; 16],
    audit: [u8; 16],
    expires_at: i64,
}

impl PublicAttachPendingV1 {
    /// Returns the operation ID that the Host gate must install and read back.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation
    }

    /// Returns the exact execution served by the Host gate.
    #[must_use]
    pub const fn execution_id(&self) -> [u8; 16] {
        self.execution
    }

    /// Returns the current execution incarnation.
    #[must_use]
    pub const fn sandbox_incarnation_id(&self) -> [u8; 16] {
        self.incarnation
    }

    /// Returns the assignment epoch that the Host gate must verify.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the authenticated public principal bound to the gate.
    #[must_use]
    pub const fn principal_id(&self) -> [u8; 16] {
        self.principal
    }

    /// Returns the execution audit identity bound to the gate.
    #[must_use]
    pub const fn audit_id(&self) -> [u8; 16] {
        self.audit
    }

    /// Returns the exclusive expiry of this reservation in Unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the request digest bound to this reservation.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Returns the digest of the exact protected pending record value.
    ///
    /// A cross-process grant signs this digest after protected readback so the
    /// Host can bind its gate installation to the durable controller CAS.
    #[must_use]
    pub fn record_digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    pub(crate) fn matches_request(&self, key: &IdempotencyKey, digest: [u8; 32]) -> bool {
        &self.key == key && self.request_digest == digest
    }

    pub(crate) fn matches_execution(
        &self,
        execution: &[u8],
        incarnation: &[u8],
        assignment_epoch: u64,
        principal: &[u8],
        audit: &[u8],
    ) -> bool {
        execution == self.execution
            && incarnation == self.incarnation
            && assignment_epoch == self.assignment_epoch
            && principal == self.principal
            && audit == self.audit
    }

    fn encode(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(VALUE_BYTES);
        value.extend_from_slice(MAGIC);
        value.extend_from_slice(&self.request_digest);
        value.extend_from_slice(self.operation.as_bytes());
        value.extend_from_slice(&self.execution);
        value.extend_from_slice(&self.incarnation);
        value.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        value.extend_from_slice(&self.principal);
        value.extend_from_slice(&self.audit);
        value.extend_from_slice(&self.expires_at.to_be_bytes());
        let digest: [u8; 32] = Sha256::digest(&value).into();
        value.extend_from_slice(&digest);
        value
    }

    fn decode(key: IdempotencyKey, value: &[u8]) -> Result<Self, PublicAttachPendingErrorV1> {
        if value.len() != VALUE_BYTES || value.get(..8) != Some(MAGIC.as_slice()) {
            return Err(PublicAttachPendingErrorV1::Corrupt);
        }
        let digest: [u8; 32] = Sha256::digest(&value[..VALUE_BYTES - 32]).into();
        if value[VALUE_BYTES - 32..] != digest {
            return Err(PublicAttachPendingErrorV1::Corrupt);
        }
        let field = |start: usize| -> Result<[u8; 16], PublicAttachPendingErrorV1> {
            value[start..start + 16]
                .try_into()
                .map_err(|_| PublicAttachPendingErrorV1::Corrupt)
        };
        let request_digest = value[8..40]
            .try_into()
            .map_err(|_| PublicAttachPendingErrorV1::Corrupt)?;
        let assignment_epoch = u64::from_be_bytes(
            value[88..96]
                .try_into()
                .map_err(|_| PublicAttachPendingErrorV1::Corrupt)?,
        );
        let expires_at = i64::from_be_bytes(
            value[128..136]
                .try_into()
                .map_err(|_| PublicAttachPendingErrorV1::Corrupt)?,
        );
        let pending = Self {
            key,
            request_digest,
            operation: OperationId::from_bytes(field(40)?),
            execution: field(56)?,
            incarnation: field(72)?,
            assignment_epoch,
            principal: field(96)?,
            audit: field(112)?,
            expires_at,
        };
        if pending.request_digest == [0; 32]
            || pending.operation.as_bytes() == &[0; 16]
            || pending.execution == [0; 16]
            || pending.incarnation == [0; 16]
            || pending.assignment_epoch == 0
            || pending.principal == [0; 16]
            || pending.audit == [0; 16]
            || pending.expires_at <= 0
        {
            return Err(PublicAttachPendingErrorV1::Corrupt);
        }
        Ok(pending)
    }
}

/// Reports a rejected, corrupt, or unavailable protected reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicAttachPendingErrorV1 {
    /// The request conflicts with an existing reservation or admission.
    #[error("public attach reservation conflicts with durable state")]
    Conflict,
    /// The protected reservation is malformed.
    #[error("public attach reservation is corrupt")]
    Corrupt,
    /// The protected journal cannot durably commit or recover the reservation.
    #[error("public attach reservation authority is unavailable")]
    Unavailable,
}

/// Carries one protected grant and its exact current Host-plan inputs.
///
/// The caller signs the plan under the independent broker-plan authority and
/// attaches the returned lease bytes to the authenticated method-28 request.
pub struct PublicAttachHostInstallDraftV1 {
    grant: [u8; PUBLIC_ATTACH_GRANT_BYTES],
    plan: BrokerAuthorizationPlan,
    ownership_lease: Vec<u8>,
    ownership_lease_signature: Vec<u8>,
}

impl PublicAttachHostInstallDraftV1 {
    /// Returns the signed dedicated-key grant sent in the exact request body.
    #[must_use]
    pub const fn grant(&self) -> &[u8; PUBLIC_ATTACH_GRANT_BYTES] {
        &self.grant
    }

    /// Consumes the draft into plan-signing and lease artifact inputs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        [u8; PUBLIC_ATTACH_GRANT_BYTES],
        BrokerAuthorizationPlan,
        Vec<u8>,
        Vec<u8>,
    ) {
        (
            self.grant,
            self.plan,
            self.ownership_lease,
            self.ownership_lease_signature,
        )
    }
}

/// Derives one exact Host-install plan from the protected current publication.
///
/// The caller must first produce `grant` using the same protected pending
/// record and current publication. This function rechecks the current lease,
/// execution, and assignment before committing to the byte-exact packet.
///
/// # Errors
///
/// Rejects changed pending, admitted idempotency, stale execution or lease,
/// missing Host template, or invalid grant-plan semantics.
pub(crate) fn prepare_public_attach_host_install_v1(
    journal: &mut Journal,
    pending: &PublicAttachPendingV1,
    project: ProjectId,
    node: NodeId,
    grant: [u8; PUBLIC_ATTACH_GRANT_BYTES],
    grant_fields: PublicAttachPendingGrantV1,
    now_seconds: i64,
) -> Result<PublicAttachHostInstallDraftV1, PublicAttachPendingErrorV1> {
    let stored = load_public_attach_pending_v1(journal, &pending.key)?
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    if stored != *pending
        || pending.expires_at <= now_seconds
        || journal.check_idempotency(&pending.key, pending.request_digest)
            != IdempotencyOutcome::Vacant
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, pending.execution)
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(PublicAttachPendingErrorV1::Corrupt);
    };
    if projection.project() != project
        || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_RUNNING)
        || !pending.matches_execution(
            &execution.execution_id,
            &execution.sandbox_incarnation_id,
            execution.assignment_epoch,
            &pending.principal,
            &execution.audit_id,
        )
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    let sandbox = SandboxId::from_bytes(
        execution
            .sandbox_id
            .as_slice()
            .try_into()
            .map_err(|_| PublicAttachPendingErrorV1::Corrupt)?,
    );
    let current = AuthorityPublicationStore::new(journal)
        .current(sandbox)
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    let manifest = current.manifest().manifest();
    let assignment = current
        .manifest()
        .broker_assignment()
        .map_err(|_| PublicAttachPendingErrorV1::Conflict)?;
    let lease_assignment = current.lease().lease().assignment();
    if manifest.project() != project
        || manifest.node() != node
        || manifest.incarnation().as_bytes() != &pending.incarnation
        || manifest.epoch().get() != pending.assignment_epoch
        || lease_assignment.sandbox() != assignment.sandbox()
        || lease_assignment.incarnation() != assignment.incarnation()
        || lease_assignment.epoch() != assignment.epoch()
        || lease_assignment.digest() != assignment.digest()
        || current.lease().lease().node() != node
        || current.lease().lease().authority_expires_seconds() < pending.expires_at
        || grant_fields.operation_id != *pending.operation.as_bytes()
        || grant_fields.execution_id != pending.execution
        || grant_fields.sandbox_id != *sandbox.as_bytes()
        || grant_fields.incarnation_id != pending.incarnation
        || grant_fields.node_id != *node.as_bytes()
        || grant_fields.assignment_epoch != pending.assignment_epoch
        || grant_fields.desired_generation != manifest.desired_generation().get()
        || grant_fields.namespace_generation != manifest.namespace_generation().get()
        || grant_fields.assignment_digest != *assignment.digest().as_bytes()
        || grant_fields.lease_generation != current.lease_generation()
        || grant_fields.lease_digest != *current.lease_digest().as_bytes()
        || grant_fields.principal_id != pending.principal
        || grant_fields.audit_id != pending.audit
        || grant_fields.expires_at != pending.expires_at
        || grant_fields.request_digest != pending.request_digest
        || grant_fields.pending_digest != pending.record_digest()
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    let semantics = canonical_host_attach_gate_semantics_v1(assignment, &grant)
        .map_err(|_| PublicAttachPendingErrorV1::Conflict)?;
    let template = current
        .templates()
        .iter()
        .find(|candidate| candidate.audience() == BrokerAudience::Host)
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    let parent = template.plan();
    if parent.assignment() != assignment || parent.node() != node {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    // The recovered template supplies current ownership and policy scope, not
    // attenuation of its exact, unrelated method grant. The independent
    // controller plan signer authorizes this per-operation Host verb.
    let expires = now_seconds
        .checked_add(30)
        .map(|limit| {
            limit
                .min(parent.expires_seconds())
                .min(current.lease().lease().authority_expires_seconds())
                .min(pending.expires_at)
        })
        .filter(|expiry| *expiry > now_seconds && now_seconds >= parent.issued_seconds())
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    let broker_grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        u32::try_from(HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES)
            .map_err(|_| PublicAttachPendingErrorV1::Conflict)?,
        0,
    )
    .map_err(|_| PublicAttachPendingErrorV1::Conflict)?;
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 0),
        assignment,
        node,
        parent.ownership_authority().clone(),
        vec![broker_grant],
        parent.policy_commitment(),
        parent.revocation_scope(),
        now_seconds,
        expires,
        Vec::new(),
    )
    .map_err(|_| PublicAttachPendingErrorV1::Conflict)?;

    Ok(PublicAttachHostInstallDraftV1 {
        grant,
        plan,
        ownership_lease: current.lease().canonical_lease().to_vec(),
        ownership_lease_signature: current.lease().canonical_signature().to_vec(),
    })
}

/// Signs the exact protected reservation for one current Host assignment.
///
/// The caller must provide the dedicated attach-grant signing key and digests
/// of independently provisioned Host trust and generated gate configuration.
/// The Host must pin that key and compare the signed fields with its own live
/// admission and lease before writing a route. This method only signs a
/// reservation that is still pending ordinary operation admission.
///
/// # Errors
///
/// Rejects a missing, expired, or changed pending record; stale execution or
/// runtime authority; an already admitted idempotency key; or invalid grant
/// inputs.
pub fn sign_reserved_public_attach_grant_v1(
    journal: &mut Journal,
    pending: &PublicAttachPendingV1,
    signing_key: &SigningKey,
    trust_digest: [u8; 32],
    gate_config_digest: [u8; 32],
    now_seconds: i64,
) -> Result<[u8; PUBLIC_ATTACH_GRANT_BYTES], PublicAttachPendingErrorV1> {
    let stored = load_public_attach_pending_v1(journal, &pending.key)?
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    if stored != *pending
        || pending.expires_at <= now_seconds
        || now_seconds <= 0
        || journal.check_idempotency(&pending.key, pending.request_digest)
            != IdempotencyOutcome::Vacant
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, pending.execution)
        .map_err(|_| PublicAttachPendingErrorV1::Corrupt)?
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(PublicAttachPendingErrorV1::Corrupt);
    };
    if execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_RUNNING)
        || !pending.matches_execution(
            &execution.execution_id,
            &execution.sandbox_incarnation_id,
            execution.assignment_epoch,
            &pending.principal,
            &execution.audit_id,
        )
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    let sandbox = SandboxId::from_bytes(
        execution
            .sandbox_id
            .as_slice()
            .try_into()
            .map_err(|_| PublicAttachPendingErrorV1::Corrupt)?,
    );
    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
        .and_then(|store| store.current(sandbox))
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    let manifest = binding.manifest().manifest();
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || manifest.incarnation().as_bytes() != &pending.incarnation
        || manifest.epoch().get() != pending.assignment_epoch
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }

    let grant = PublicAttachPendingGrantV1 {
        operation_id: *pending.operation.as_bytes(),
        execution_id: pending.execution,
        sandbox_id: *manifest.sandbox().as_bytes(),
        incarnation_id: pending.incarnation,
        node_id: *manifest.node().as_bytes(),
        assignment_epoch: pending.assignment_epoch,
        desired_generation: manifest.desired_generation().get(),
        namespace_generation: manifest.namespace_generation().get(),
        assignment_digest: *binding.assignment_digest().as_bytes(),
        lease_generation: binding.lease_generation(),
        lease_digest: *binding.lease_digest().as_bytes(),
        principal_id: pending.principal,
        audit_id: pending.audit,
        expires_at: pending.expires_at,
        request_digest: pending.request_digest,
        pending_digest: pending.record_digest(),
        trust_digest,
        gate_config_digest,
    };
    sign_public_attach_pending_grant_v1(&grant, signing_key)
        .map_err(|_| PublicAttachPendingErrorV1::Conflict)
}

/// Loads one protected reservation by its public idempotency key.
///
/// # Errors
///
/// Rejects unavailable protected custody or a corrupt record.
pub fn load_public_attach_pending_v1(
    journal: &Journal,
    key: &IdempotencyKey,
) -> Result<Option<PublicAttachPendingV1>, PublicAttachPendingErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
    journal
        .get(RecordNamespace::PublicAttachPending, key.as_bytes())
        .map(|value| PublicAttachPendingV1::decode(key.clone(), value))
        .transpose()
}

/// Durably reserves the operation ID required by the Host forced-command gate.
///
/// An exact replay returns the same reservation. No ordinary operation or
/// idempotency decision is created until the Host route is authenticated.
///
/// # Errors
///
/// Rejects conflicting identity, invalid expiry, or journal failure.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reserve_public_attach_pending_v1(
    journal: &mut Journal,
    key: &IdempotencyKey,
    request_digest: [u8; 32],
    execution: [u8; 16],
    incarnation: [u8; 16],
    assignment_epoch: u64,
    principal: [u8; 16],
    audit: [u8; 16],
    now_seconds: i64,
    authority_expires_at: i64,
) -> Result<PublicAttachPendingV1, PublicAttachPendingErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
    let expiry = now_seconds
        .checked_add(MAXIMUM_PENDING_SECONDS)
        .map(|value| value.min(authority_expires_at))
        .filter(|value| now_seconds > 0 && *value > now_seconds)
        .ok_or(PublicAttachPendingErrorV1::Conflict)?;
    if request_digest == [0; 32]
        || execution == [0; 16]
        || incarnation == [0; 16]
        || assignment_epoch == 0
        || principal == [0; 16]
        || audit == [0; 16]
    {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    if let Some(existing) = load_public_attach_pending_v1(journal, key)? {
        if !existing.matches_request(key, request_digest)
            || !existing.matches_execution(
                &execution,
                &incarnation,
                assignment_epoch,
                &principal,
                &audit,
            )
        {
            return Err(PublicAttachPendingErrorV1::Conflict);
        }
        match journal.check_idempotency(key, request_digest) {
            IdempotencyOutcome::Vacant if existing.expires_at > now_seconds => {
                return Ok(existing);
            }
            IdempotencyOutcome::Vacant => {
                // The previous grant can no longer authorize a live route.
                // Keep its logical operation ID while advancing only expiry.
                if journal
                    .get(RecordNamespace::Operation, existing.operation.as_bytes())
                    .is_some()
                    || journal
                        .get(
                            RecordNamespace::PublicAttachRoute,
                            existing.operation.as_bytes(),
                        )
                        .is_some()
                {
                    return Err(PublicAttachPendingErrorV1::Conflict);
                }
                let renewed = PublicAttachPendingV1 {
                    expires_at: expiry,
                    ..existing
                };
                let record = JournalRecord::put(
                    RecordNamespace::PublicAttachPending,
                    key.as_bytes().to_vec(),
                    renewed.encode(),
                );
                let transaction =
                    JournalTransaction::new(OperationId::new().into_bytes(), vec![record])
                        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
                journal
                    .commit(&transaction)
                    .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
                return Ok(renewed);
            }
            IdempotencyOutcome::Replay(_) if existing.expires_at > now_seconds => {
                return Ok(existing);
            }
            IdempotencyOutcome::Conflict => return Err(PublicAttachPendingErrorV1::Conflict),
            IdempotencyOutcome::Replay(_) => return Err(PublicAttachPendingErrorV1::Conflict),
        }
    }
    if journal.check_idempotency(key, request_digest) != IdempotencyOutcome::Vacant {
        return Err(PublicAttachPendingErrorV1::Conflict);
    }
    let pending = PublicAttachPendingV1 {
        key: key.clone(),
        request_digest,
        operation: OperationId::new(),
        execution,
        incarnation,
        assignment_epoch,
        principal,
        audit,
        expires_at: expiry,
    };
    let record = JournalRecord::put(
        RecordNamespace::PublicAttachPending,
        key.as_bytes().to_vec(),
        pending.encode(),
    );
    let transaction = JournalTransaction::new(OperationId::new().into_bytes(), vec![record])
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
    journal
        .commit(&transaction)
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
    Ok(pending)
}
