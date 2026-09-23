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

use aos_sandbox_core::OperationId;
use sha2::{Digest as _, Sha256};

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
) -> Result<PublicAttachPendingV1, PublicAttachPendingErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| PublicAttachPendingErrorV1::Unavailable)?;
    let expiry = now_seconds
        .checked_add(MAXIMUM_PENDING_SECONDS)
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
            || existing.expires_at <= now_seconds
        {
            return Err(PublicAttachPendingErrorV1::Conflict);
        }
        match journal.check_idempotency(key, request_digest) {
            IdempotencyOutcome::Vacant | IdempotencyOutcome::Replay(_) => return Ok(existing),
            IdempotencyOutcome::Conflict => return Err(PublicAttachPendingErrorV1::Conflict),
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
