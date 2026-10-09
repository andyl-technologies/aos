//! Historical ownership-chain state and borrow-bound prepared updates.
//!
//! This crate owns canonical entry/current-pointer records, request identity,
//! exact successor/CAS rules, and authenticated historical reconstruction. It
//! does not open storage, issue leases, sample protected clocks, or grant live
//! authority. Callers retain responsibility for protected storage and genuine
//! native commits; prepared updates keep the history exclusively borrowed
//! while those callers commit the returned inert transaction data.
//!
//! `format` owns the V1 record codec, `recovery` reconstructs linear histories,
//! and `transition` supplies the shared admission/replay successor relation.
//! Every recovered lease and replay response still requires fresh verification
//! at its eventual effect boundary.

mod format;
mod recovery;
mod transition;

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::model::KeyReference;
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample, SandboxId};
use aos_sandbox_ownership_protocol::protocol::OwnershipTransactionReferenceV1;
use aos_sandbox_ownership_protocol::{
    CLAIM_BYTES, OwnershipAuthorityVerifier, OwnershipClaimAction, OwnershipClaimV1,
    OwnershipLeaseAcquisitionError, RecoveredOwnershipLease, UnverifiedOwnershipLeaseResponse,
};
use sha2::{Digest as _, Sha256};

use format::*;
use recovery::recover_durable_ownership;

const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
const DURABLE_ENTRY_MAGIC: &[u8; 8] = b"AOSOWNE1";
const DURABLE_CURRENT_MAGIC: &[u8; 8] = b"AOSOWNC1";
const DURABLE_FORMAT_VERSION: u16 = 1;
const DURABLE_ENTRY_PREFIX: &[u8] = b"ownership-entry-v1:";
const DURABLE_CURRENT_PREFIX: &[u8] = b"ownership-current-v1:";
const MAXIMUM_DURABLE_ENTRY_BYTES: usize = 196 * 1024;
const MAXIMUM_DURABLE_ENTRIES: usize = 256;
const MAXIMUM_DURABLE_KEY_BYTES: usize = 64;
// The fixed entry envelope is 330 bytes plus a bounded 255-byte stable key ID.
const MAXIMUM_DURABLE_INTENT_BYTES: usize = 585;
const MAXIMUM_DURABLE_CURRENT_BYTES: usize = 8 + 2 + 16 + 8 + 32;
const BEGIN_TRANSACTION_DOMAIN: &[u8] = b"aos-sandbox-ownership-intent-transaction-v1\0";
const COMPLETION_TRANSACTION_DOMAIN: &[u8] = b"aos-sandbox-ownership-completion-transaction-v1\0";

const MAXIMUM_DURABLE_CURRENT_POINTERS: usize = MAXIMUM_DURABLE_ENTRIES;

/// Reports malformed historical data or a rejected semantic transition.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipHistoryError {
    /// Historical records do not form one authenticated linear lease chain.
    #[error("durable ownership authority state is malformed or inconsistent")]
    CorruptState,
    /// The request identity is already bound to another claim.
    #[error("durable ownership request identity is bound to another claim")]
    IdempotencyConflict,
    /// The claim does not match the exact historical current fence.
    #[error("durable ownership compare-and-swap precondition failed")]
    CompareAndSwapConflict,
    /// No unsigned intent exists for the requested operation.
    #[error("durable ownership intent was not found")]
    IntentNotFound,
    /// Authentication of the issued response failed.
    #[error("ownership lease issuance failed: {0}")]
    Acquisition(#[from] OwnershipLeaseAcquisitionError),
    /// The fixed authority-generation epoch has no capacity for another request.
    #[error("durable ownership authority epoch capacity is exhausted")]
    ResourceExhausted,
}

/// Specifies fixed historical record geometry, not permission or durability.
pub struct OwnershipHistoryBounds;

impl OwnershipHistoryBounds {
    /// Maximum number of admitted request identities in one key-generation epoch.
    pub const MAXIMUM_ENTRIES: usize = MAXIMUM_DURABLE_ENTRIES;

    /// Maximum canonical entry length, including all four response artifacts.
    pub const MAXIMUM_ENTRY_BYTES: usize = MAXIMUM_DURABLE_ENTRY_BYTES;

    /// Maximum canonical unsigned intent length.
    pub const MAXIMUM_INTENT_BYTES: usize = MAXIMUM_DURABLE_INTENT_BYTES;

    /// Maximum canonical current-pointer length.
    pub const MAXIMUM_CURRENT_BYTES: usize = MAXIMUM_DURABLE_CURRENT_BYTES;

    /// Maximum record key length reserved by the protected journal owner.
    pub const MAXIMUM_KEY_BYTES: usize = MAXIMUM_DURABLE_KEY_BYTES;
}

/// Identifies one inert materialized record's semantic namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipHistoryRecordKind {
    /// A request's unsigned intent or authenticated historical completion.
    Entry,
    /// A sandbox's unique authenticated historical head pointer.
    Current,
}

/// Carries canonical record data without storage custody or execution permission.
pub struct OwnershipHistoryRecord {
    kind: OwnershipHistoryRecordKind,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl OwnershipHistoryRecord {
    /// Transfers the inert namespace and canonical byte buffers without copying.
    #[must_use]
    pub fn into_parts(self) -> (OwnershipHistoryRecordKind, Vec<u8>, Vec<u8>) {
        (self.kind, self.key, self.value)
    }
}

/// Carries inert transaction identity and ordered canonical records.
///
/// This value neither proves a commit nor authorizes one. A protected owner
/// must construct and commit its native transaction while the corresponding
/// prepared scope still borrows the history.
pub struct OwnershipHistoryTransaction {
    id: [u8; 16],
    records: Vec<OwnershipHistoryRecord>,
}

impl OwnershipHistoryTransaction {
    /// Transfers the inert transaction identity and ordered records without copying.
    #[must_use]
    pub fn into_parts(self) -> ([u8; 16], Vec<OwnershipHistoryRecord>) {
        (self.id, self.records)
    }
}

/// Describes an inert observation of one exact historical request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnershipHistoryQuery {
    /// No matching request identity is present in the supplied history.
    Absent,
    /// The exact claim has no published completion.
    Pending {
        /// The original immutable action.
        action: OwnershipClaimAction,
    },
    /// The exact historical four-artifact response, without live authority.
    Completed(Box<UnverifiedOwnershipLeaseResponse>),
}

/// Describes semantic admission without claiming that an intent is durable.
pub enum OwnershipHistoryBegin<'a> {
    /// The exact unsigned intent is already present in the history.
    Pending,
    /// The exact request has an authenticated historical completion.
    Replay(Box<UnverifiedOwnershipLeaseResponse>),
    /// A new unsigned intent scope and owned inert transaction data are prepared.
    Prepared(PreparedOwnershipIntent<'a>, OwnershipHistoryTransaction),
}

/// Describes semantic completion lookup without contacting an issuer.
pub enum OwnershipHistoryCompletion<'a> {
    /// The exact authenticated historical response is already present.
    Replay(UnverifiedOwnershipLeaseResponse),
    /// The unsigned intent is exclusively borrowed for completion.
    Pending(PendingOwnershipCompletion<'a>),
}

#[derive(Clone, Debug)]
enum DurableEntryState {
    Intent,
    Completed {
        accepted_wall_seconds: i64,
        lease: Box<RecoveredOwnershipLease>,
    },
}

#[derive(Clone, Debug)]
struct DurableOwnershipEntry {
    claim: OwnershipClaimV1,
    state: DurableEntryState,
}

/// Owns one key-generation-pinned authenticated historical lease chain.
///
/// Construction authenticates supplied record data but makes no claim about
/// its provenance, physical completeness, durability, or current liveness.
/// Protected callers must obtain these bytes from their existing journal.
/// Dropping a prepared scope leaves both maps unchanged.
pub struct OwnershipHistory {
    verifier: OwnershipAuthorityVerifier,
    entries: BTreeMap<[u8; 16], DurableOwnershipEntry>,
    current: BTreeMap<SandboxId, RecoveredOwnershipLease>,
}

impl OwnershipHistory {
    /// Reconstructs a history from materialized namespace record data.
    ///
    /// The four iterators correspond to the original operation, desired-state,
    /// effect, and idempotency namespaces. They are actual borrowed records,
    /// not detached absence flags. Authentication and validation occur in that
    /// order; effect and idempotency records are forbidden. The caller remains
    /// responsible for acquiring the complete protected journal view.
    ///
    /// # Errors
    ///
    /// Returns `CorruptState` for malformed, foreign, unauthenticated, forked,
    /// stale, disconnected, or inconsistent records.
    pub fn from_records<'a>(
        verifier: OwnershipAuthorityVerifier,
        operations: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        currents: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        effects: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        idempotency: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    ) -> Result<Self, OwnershipHistoryError> {
        let (entries, current) =
            recover_durable_ownership(operations, currents, effects, idempotency, &verifier)?;

        Ok(Self {
            verifier,
            entries,
            current,
        })
    }

    /// Returns the exact key generation pinned to this historical owner.
    #[must_use]
    pub const fn authority(&self) -> &KeyReference {
        self.verifier.authority()
    }

    /// Observes an exact request binding without effects or live verification.
    ///
    /// # Errors
    ///
    /// Returns `IdempotencyConflict` for a request bound to another claim digest.
    pub fn query(
        &self,
        reference: OwnershipTransactionReferenceV1,
    ) -> Result<OwnershipHistoryQuery, OwnershipHistoryError> {
        let Some(entry) = self.entries.get(reference.request_id()) else {
            return Ok(OwnershipHistoryQuery::Absent);
        };

        if entry.claim.digest() != reference.claim_digest() {
            return Err(OwnershipHistoryError::IdempotencyConflict);
        }

        Ok(match &entry.state {
            DurableEntryState::Intent => OwnershipHistoryQuery::Pending {
                action: entry.claim.action(),
            },
            DurableEntryState::Completed { lease, .. } => {
                OwnershipHistoryQuery::Completed(Box::new(lease.exact_response()))
            }
        })
    }

    /// Prepares one unsigned intent while exclusively borrowing the history.
    ///
    /// No issuer, clock, or storage operation is performed. The fixed capacity
    /// check reserves worst-case completion space for every admitted request.
    ///
    /// # Errors
    ///
    /// Returns identity, capacity, pending-request, or exact current-fence
    /// conflicts before constructing transaction data.
    pub fn prepare_begin(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<OwnershipHistoryBegin<'_>, OwnershipHistoryError> {
        if let Some(existing) = self.entries.get(claim.request_id()) {
            if existing.claim != *claim {
                return Err(OwnershipHistoryError::IdempotencyConflict);
            }

            return Ok(match &existing.state {
                DurableEntryState::Intent => OwnershipHistoryBegin::Pending,
                DurableEntryState::Completed { lease, .. } => {
                    OwnershipHistoryBegin::Replay(Box::new(lease.exact_response()))
                }
            });
        }

        // Capacity precedes pending and CAS checks, matching protected admission.
        if self.entries.len() >= MAXIMUM_DURABLE_ENTRIES {
            return Err(OwnershipHistoryError::ResourceExhausted);
        }

        let sandbox = claim.assignment().sandbox();
        if self.entries.values().any(|entry| {
            entry.claim.assignment().sandbox() == sandbox
                && matches!(entry.state, DurableEntryState::Intent)
        }) {
            return Err(OwnershipHistoryError::CompareAndSwapConflict);
        }

        validate_claim_against_current(claim, &self.current)?;

        let entry = DurableOwnershipEntry {
            claim: claim.clone(),
            state: DurableEntryState::Intent,
        };
        let record = OwnershipHistoryRecord {
            kind: OwnershipHistoryRecordKind::Entry,
            key: durable_entry_key(claim.request_id()),
            value: encode_durable_entry(&entry, self.verifier.authority()),
        };
        let transaction = OwnershipHistoryTransaction {
            id: begin_transaction_id(*claim.request_id()),
            records: vec![record],
        };

        Ok(OwnershipHistoryBegin::Prepared(
            PreparedOwnershipIntent {
                history: self,
                entry,
            },
            transaction,
        ))
    }

    /// Borrows one unsigned intent before its caller contacts the issuer.
    ///
    /// Exact completed replay bypasses issuer and clock operations.
    ///
    /// # Errors
    ///
    /// Returns `IntentNotFound` or a current-fence conflict before issuance.
    pub fn prepare_completion(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<OwnershipHistoryCompletion<'_>, OwnershipHistoryError> {
        let entry = self
            .entries
            .get(&request_id)
            .cloned()
            .ok_or(OwnershipHistoryError::IntentNotFound)?;

        if let DurableEntryState::Completed { lease, .. } = entry.state {
            return Ok(OwnershipHistoryCompletion::Replay(lease.exact_response()));
        }

        let claim = entry.claim;
        validate_claim_against_current(&claim, &self.current)?;

        Ok(OwnershipHistoryCompletion::Pending(
            PendingOwnershipCompletion {
                history: self,
                claim,
            },
        ))
    }

    /// Returns an authenticated historical head, not present execution permission.
    #[must_use]
    pub fn current(&self, sandbox: SandboxId) -> Option<&RecoveredOwnershipLease> {
        self.current.get(&sandbox)
    }

    /// Returns whether an unsigned intent is present in this historical view.
    #[must_use]
    pub fn is_pending(&self, request_id: &[u8; 16]) -> bool {
        self.entries
            .get(request_id)
            .is_some_and(|entry| matches!(entry.state, DurableEntryState::Intent))
    }
}

/// Retains the semantic owner borrow through a caller's native intent commit.
pub struct PreparedOwnershipIntent<'a> {
    history: &'a mut OwnershipHistory,
    entry: DurableOwnershipEntry,
}

impl PreparedOwnershipIntent<'_> {
    /// Publishes the prepared unsigned intent in memory.
    ///
    /// This operation supplies no durability or authority proof. The protected
    /// journal adapter calls it only after its genuine native commit succeeds;
    /// dropping the scope on any error leaves the historical maps unchanged.
    pub fn publish(self) {
        self.history
            .entries
            .insert(*self.entry.claim.request_id(), self.entry);
    }
}

/// Retains the original semantic owner borrow across issuance and clock sampling.
pub struct PendingOwnershipCompletion<'a> {
    history: &'a mut OwnershipHistory,
    claim: OwnershipClaimV1,
}

impl<'a> PendingOwnershipCompletion<'a> {
    /// Returns the immutable claim already checked against the current fence.
    #[must_use]
    pub const fn claim(&self) -> &OwnershipClaimV1 {
        &self.claim
    }

    /// Authenticates response data and prepares the exact two-record completion.
    ///
    /// The paired clock is advisory verification input, not a protected clock
    /// capability. The protected caller must sample it after issuance returns.
    /// Both the live response authentication and repeated current-fence check
    /// retain their original order.
    /// The returned owned record data can move into the native transaction
    /// without copying; the separate prepared scope retains the history borrow.
    ///
    /// # Errors
    ///
    /// Returns an acquisition error for an invalid response or a current-fence
    /// conflict before constructing completion data.
    pub fn authenticate(
        self,
        response: UnverifiedOwnershipLeaseResponse,
        clock: &RawPairedClockSample,
    ) -> Result<(PreparedOwnershipCompletion<'a>, OwnershipHistoryTransaction), OwnershipHistoryError>
    {
        let lease = self
            .history
            .verifier
            .verify_response(&self.claim, response, clock)?;
        let exact_response = lease.exact_response();

        validate_claim_against_current(&self.claim, &self.history.current)?;

        let request_id = *self.claim.request_id();
        let recovered = lease.into_recovered();
        let completed = DurableOwnershipEntry {
            claim: self.claim,
            state: DurableEntryState::Completed {
                accepted_wall_seconds: clock.wall_seconds(),
                lease: Box::new(recovered.clone()),
            },
        };
        let current_record = encode_current_pointer(request_id, &recovered);
        let records = vec![
            OwnershipHistoryRecord {
                kind: OwnershipHistoryRecordKind::Entry,
                key: durable_entry_key(&request_id),
                value: encode_durable_entry(&completed, self.history.verifier.authority()),
            },
            OwnershipHistoryRecord {
                kind: OwnershipHistoryRecordKind::Current,
                key: durable_current_key(recovered.assignment().sandbox()),
                value: current_record,
            },
        ];
        let transaction = OwnershipHistoryTransaction {
            id: completion_transaction_id(request_id),
            records,
        };

        Ok((
            PreparedOwnershipCompletion {
                history: self.history,
                completed,
                recovered,
                exact_response,
            },
            transaction,
        ))
    }
}

/// Retains the semantic owner borrow through a caller's native completion commit.
pub struct PreparedOwnershipCompletion<'a> {
    history: &'a mut OwnershipHistory,
    completed: DurableOwnershipEntry,
    recovered: RecoveredOwnershipLease,
    exact_response: UnverifiedOwnershipLeaseResponse,
}

impl PreparedOwnershipCompletion<'_> {
    /// Publishes entry then current head and returns historical replay artifacts.
    ///
    /// This operation proves neither persistence nor present authority. The
    /// protected journal adapter invokes it only after genuine native commit
    /// success, with the original owner borrow retained throughout. Dropping
    /// the scope instead leaves both historical maps unchanged.
    #[must_use]
    pub fn publish(self) -> UnverifiedOwnershipLeaseResponse {
        self.history
            .entries
            .insert(*self.completed.claim.request_id(), self.completed);
        self.history
            .current
            .insert(self.recovered.assignment().sandbox(), self.recovered);

        self.exact_response
    }
}

fn validate_claim_against_current(
    claim: &OwnershipClaimV1,
    current: &BTreeMap<SandboxId, RecoveredOwnershipLease>,
) -> Result<(), OwnershipHistoryError> {
    let existing = current.get(&claim.assignment().sandbox());
    match (claim.action(), existing) {
        (OwnershipClaimAction::Acquire, None) => Ok(()),
        (_, Some(lease)) if transition::is_valid_successor(claim, lease) => Ok(()),
        _ => Err(OwnershipHistoryError::CompareAndSwapConflict),
    }
}

#[cfg(test)]
mod tests;
