//! Exclusive ownership-lease acquisition boundary.
//!
//! The controller supplies immutable assignment identity and a bounded maximum
//! duration. Only the authority chooses lease generation, validity interval,
//! clock-skew allowance, and renewal nonce. A response remains explicitly
//! unverified until [`OwnershipAuthorityVerifier`] proves its canonical
//! signature, assignment, node, liveness, duration, and renewal fence.
//!
//! The future remote protocol may carry the fixed claim bytes directly:
//!
//! ```text
//! AOSOCLM1 || version:u16be || action:u8 || reserved:5 || request-id:16 ||
//! sandbox:16 || incarnation:16 || epoch:u64be || assignment-digest:32 ||
//! node:16 || desired-generation:u64be || expected-generation:u64be ||
//! expected-lease-digest:32 || requested-maximum-seconds:u64be
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox_core::model::KeyReference;
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample, SandboxId};
use aos_sandbox_ownership_protocol::protocol::OwnershipTransactionReferenceV1;
pub use aos_sandbox_ownership_protocol::{
    CLAIM_BYTES, ExpectedOwnershipLease, OwnershipAuthority, OwnershipAuthorityError,
    OwnershipAuthorityVerifier, OwnershipClaimAction, OwnershipClaimError, OwnershipClaimV1,
    OwnershipLeaseAcquisitionError, OwnershipTransactionReceiptV1, RecoveredOwnershipLease,
    SignedOwnershipLease, UnverifiedOwnershipLeaseResponse,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
const DURABLE_ENTRY_MAGIC: &[u8; 8] = b"AOSOWNE2";
const DURABLE_CURRENT_MAGIC: &[u8; 8] = b"AOSOWNC2";
const LEGACY_DURABLE_ENTRY_MAGIC: &[u8; 8] = b"AOSOWNE1";
const LEGACY_DURABLE_CURRENT_MAGIC: &[u8; 8] = b"AOSOWNC1";
const DURABLE_FORMAT_VERSION: u16 = 2;
const DURABLE_ENTRY_PREFIX: &[u8] = b"ownership-entry-v2:";
const DURABLE_CURRENT_PREFIX: &[u8] = b"ownership-current-v2:";
const LEGACY_DURABLE_ENTRY_PREFIX: &[u8] = b"ownership-entry-v1:";
const LEGACY_DURABLE_CURRENT_PREFIX: &[u8] = b"ownership-current-v1:";
const MAXIMUM_DURABLE_ENTRY_BYTES: usize = 196 * 1024;
const MAXIMUM_DURABLE_ENTRIES: usize = 256;
const MAXIMUM_DURABLE_CURRENT_POINTERS: usize = MAXIMUM_DURABLE_ENTRIES;
const MAXIMUM_DURABLE_RECORDS: usize = MAXIMUM_DURABLE_ENTRIES + MAXIMUM_DURABLE_CURRENT_POINTERS;
const MAXIMUM_DURABLE_KEY_BYTES: usize = 64;
// The fixed entry envelope is 330 bytes plus a bounded 255-byte stable key ID.
const MAXIMUM_DURABLE_INTENT_BYTES: usize = 585;
const MAXIMUM_DURABLE_INTENT_RECORD_BYTES: usize =
    7 + MAXIMUM_DURABLE_KEY_BYTES + MAXIMUM_DURABLE_INTENT_BYTES;
const MAXIMUM_DURABLE_RECORD_BYTES: usize =
    MAXIMUM_DURABLE_ENTRY_BYTES + MAXIMUM_DURABLE_KEY_BYTES + 7;
const MAXIMUM_DURABLE_CURRENT_BYTES: usize = 8 + 2 + 16 + 8 + 32;
const MAXIMUM_DURABLE_MATERIALIZED_BYTES: usize = MAXIMUM_DURABLE_ENTRIES
    * (MAXIMUM_DURABLE_KEY_BYTES + MAXIMUM_DURABLE_ENTRY_BYTES)
    + MAXIMUM_DURABLE_CURRENT_POINTERS
        * (MAXIMUM_DURABLE_KEY_BYTES + MAXIMUM_DURABLE_CURRENT_BYTES);
// One file header plus, for every admitted request, a worst-case one-record
// intent transaction and worst-case two-record completion transaction. The
// constants include every 72-byte frame header plus begin/commit payloads.
const MAXIMUM_DURABLE_JOURNAL_BYTES: u64 = 72
    + MAXIMUM_DURABLE_ENTRIES as u64
        * (MAXIMUM_DURABLE_INTENT_RECORD_BYTES as u64
            + MAXIMUM_DURABLE_RECORD_BYTES as u64
            + MAXIMUM_DURABLE_KEY_BYTES as u64
            + 657);
const MAXIMUM_DURABLE_TRANSACTIONS: usize = MAXIMUM_DURABLE_ENTRIES * 2;
const BEGIN_TRANSACTION_DOMAIN: &[u8] = b"aos-sandbox-ownership-intent-transaction-v2\0";
const COMPLETION_TRANSACTION_DOMAIN: &[u8] = b"aos-sandbox-ownership-completion-transaction-v2\0";

/// Reports durable ownership-authority state or recovery failure.
#[derive(Debug, thiserror::Error)]
pub enum DurableOwnershipAuthorityError {
    /// Protected journal opening, replay, or commit failed.
    #[error("durable ownership journal failed: {0}")]
    Journal(#[from] JournalError),
    /// Durable records do not form one authenticated linear ownership chain.
    #[error("durable ownership authority state is malformed or inconsistent")]
    CorruptState,
    /// Durable V1 state exists and requires an explicit authenticated migration.
    #[error("durable ownership authority V1 state requires migration")]
    MigrationRequired,
    /// The request identity is already bound to another claim.
    #[error("durable ownership request identity is bound to another claim")]
    IdempotencyConflict,
    /// Acquire or renewal does not match the durable current state.
    #[error("durable ownership compare-and-swap precondition failed")]
    CompareAndSwapConflict,
    /// No unsigned durable intent exists for the requested operation.
    #[error("durable ownership intent was not found")]
    IntentNotFound,
    /// Issuance or cryptographic response verification failed.
    #[error("ownership lease issuance failed: {0}")]
    Acquisition(#[from] OwnershipLeaseAcquisitionError),
    /// The protected paired-clock source could not provide a sample.
    #[error("protected ownership clock is unavailable")]
    ProtectedClockUnavailable(#[from] ProtectedOwnershipClockError),
    /// The fixed authority-generation epoch has no capacity for another request.
    #[error("durable ownership authority epoch capacity is exhausted")]
    ResourceExhausted,
}

/// Reports failure to sample the protected paired clock without backend detail.
///
/// Production adapters should map device, service, and transport failures to
/// this opaque value rather than exposing their implementation through the
/// authority state-machine API.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("protected paired clock is unavailable")]
pub struct ProtectedOwnershipClockError;

/// Describes durable admission of one ownership claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOwnershipBeginOutcome {
    /// An unsigned intent is durable and may be completed explicitly.
    Pending,
    /// The exact completed request was replayed without contacting the issuer.
    Replay(Box<UnverifiedOwnershipLeaseResponse>),
}

/// Describes one exact durable ownership transaction observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOwnershipQueryOutcome {
    /// No request with this identity exists in the protected authority state.
    Absent,
    /// The exact claim is durable but has no committed completion.
    Pending {
        /// The immutable action needed to classify a later CAS conflict.
        action: OwnershipClaimAction,
    },
    /// The exact completed four-artifact response is durable.
    Completed(Box<UnverifiedOwnershipLeaseResponse>),
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

/// Owns one protected, crash-recoverable ownership authority journal.
///
/// The store is an authority state machine, not a broker. Historical proofs
/// rebuild its lease chain but never become current execution permission.
/// Issuance is explicitly split: [`Self::begin`] commits an unsigned intent;
/// [`Self::complete`] contacts an [`OwnershipAuthority`] whose trait contract
/// guarantees exact response replay for the canonical request ID and digest.
/// Recovery never contacts that issuer, so a dangling intent remains durable
/// and non-authorizing until an operator or controller explicitly resumes it.
/// The protected journal is dedicated to this owner; recovery rejects records
/// from other subsystems rather than sharing a writable journal namespace.
///
/// The current trait has no release, expiry retirement, or transfer operation.
/// Consequently a completed assignment remains owned for CAS purposes even
/// after expiry, and cross-assignment transfer is intentionally incomplete.
/// One journal is also pinned to exactly one authority key generation. Key
/// rotation requires an explicit authenticated migration into a new journal;
/// opening old mixed-generation history with a new verifier fails closed.
/// Durable encoding and namespaces are V2; any V1 namespace or magic requires
/// an explicit migration and is never treated as absent state.
pub struct DurableOwnershipAuthority {
    journal: Journal,
    verifier: OwnershipAuthorityVerifier,
    entries: BTreeMap<[u8; 16], DurableOwnershipEntry>,
    current: BTreeMap<SandboxId, RecoveredOwnershipLease>,
}

impl DurableOwnershipAuthority {
    /// Opens root-only protected authority state and authenticates its full history.
    ///
    /// This authority owns fixed, non-configurable replay and materialization
    /// ceilings. In particular, callers cannot expand hostile-input bounds by
    /// supplying permissive generic journal limits.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError`] if protected storage cannot
    /// be opened or if any durable record is malformed, unauthenticated,
    /// forked, stale, equivocal, disconnected, or inconsistent with its unique
    /// current pointer.
    pub fn open_protected(
        directory: impl AsRef<Path>,
        name: &str,
        verifier: OwnershipAuthorityVerifier,
    ) -> Result<(Self, RecoveryReport), DurableOwnershipAuthorityError> {
        let (journal, report) =
            Journal::open_protected_at(directory, name, ownership_journal_limits())?;
        let store = Self::from_journal(journal, verifier)?;
        Ok((store, report))
    }

    fn from_journal(
        journal: Journal,
        verifier: OwnershipAuthorityVerifier,
    ) -> Result<Self, DurableOwnershipAuthorityError> {
        let (entries, current) = recover_durable_ownership(&journal, &verifier)?;
        Ok(Self {
            journal,
            verifier,
            entries,
            current,
        })
    }

    /// Returns the exact protected ownership-authority key generation.
    #[must_use]
    pub const fn authority(&self) -> &KeyReference {
        self.verifier.authority()
    }

    /// Observes one exact durable request and claim binding.
    ///
    /// This method performs no issuer call, clock read, journal write, or live
    /// authority check. A completed response is historical replay material and
    /// remains non-authorizing until independently verified at its use site.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError::IdempotencyConflict`] when
    /// the request identity exists but is bound to another claim digest.
    pub fn query(
        &self,
        reference: OwnershipTransactionReferenceV1,
    ) -> Result<DurableOwnershipQueryOutcome, DurableOwnershipAuthorityError> {
        let Some(entry) = self.entries.get(reference.request_id()) else {
            return Ok(DurableOwnershipQueryOutcome::Absent);
        };
        if entry.claim.digest() != reference.claim_digest() {
            return Err(DurableOwnershipAuthorityError::IdempotencyConflict);
        }
        Ok(match &entry.state {
            DurableEntryState::Intent => DurableOwnershipQueryOutcome::Pending {
                action: entry.claim.action(),
            },
            DurableEntryState::Completed { lease, .. } => {
                DurableOwnershipQueryOutcome::Completed(Box::new(lease.exact_response()))
            }
        })
    }

    /// Durably records one unsigned acquire or renew intent.
    ///
    /// This method never contacts an issuer. Exact completed replay returns
    /// the original unverified four-artifact response; exact pending replay
    /// remains pending.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError::IdempotencyConflict`] when a
    /// request ID is rebound, or
    /// [`DurableOwnershipAuthorityError::CompareAndSwapConflict`] when acquire
    /// is not expected-absence or renew does not name the exact current fence.
    /// Returns [`DurableOwnershipAuthorityError::ResourceExhausted`] before
    /// writing an intent when the fixed epoch request capacity is exhausted.
    pub fn begin(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<DurableOwnershipBeginOutcome, DurableOwnershipAuthorityError> {
        if let Some(existing) = self.entries.get(claim.request_id()) {
            if existing.claim != *claim {
                return Err(DurableOwnershipAuthorityError::IdempotencyConflict);
            }
            return Ok(match &existing.state {
                DurableEntryState::Intent => DurableOwnershipBeginOutcome::Pending,
                DurableEntryState::Completed { lease, .. } => {
                    DurableOwnershipBeginOutcome::Replay(Box::new(lease.exact_response()))
                }
            });
        }
        // The fixed journal limits reserve a worst-case completion transaction
        // for every admitted intent. Refusing the (N + 1)th request before its
        // intent is durable prevents successful external issuance from ever
        // becoming permanently uncommittable due to local capacity.
        if self.entries.len() >= MAXIMUM_DURABLE_ENTRIES {
            return Err(DurableOwnershipAuthorityError::ResourceExhausted);
        }
        let sandbox = claim.assignment().sandbox();
        if self.entries.values().any(|entry| {
            entry.claim.assignment().sandbox() == sandbox
                && matches!(entry.state, DurableEntryState::Intent)
        }) {
            return Err(DurableOwnershipAuthorityError::CompareAndSwapConflict);
        }
        match claim.action() {
            OwnershipClaimAction::Acquire if self.current.contains_key(&sandbox) => {
                return Err(DurableOwnershipAuthorityError::CompareAndSwapConflict);
            }
            OwnershipClaimAction::Acquire => {}
            OwnershipClaimAction::Renew => {
                let current = self
                    .current
                    .get(&sandbox)
                    .ok_or(DurableOwnershipAuthorityError::CompareAndSwapConflict)?;
                if current.assignment() != claim.assignment()
                    || current.node() != claim.node()
                    || Some(current.expected_renewal_fence()) != claim.expected_prior()
                {
                    return Err(DurableOwnershipAuthorityError::CompareAndSwapConflict);
                }
            }
        }
        let entry = DurableOwnershipEntry {
            claim: claim.clone(),
            state: DurableEntryState::Intent,
        };
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            durable_entry_key(claim.request_id()),
            encode_durable_entry(&entry, self.verifier.authority()),
        );
        let transaction =
            JournalTransaction::new(begin_transaction_id(*claim.request_id()), vec![record])?;
        self.journal.commit(&transaction)?;
        self.entries.insert(*claim.request_id(), entry);
        Ok(DurableOwnershipBeginOutcome::Pending)
    }

    /// Completes or explicitly resumes one durable unsigned intent.
    ///
    /// The issuer is called only after the exact intent is durable. Calling
    /// this method after a crash is safe only because [`OwnershipAuthority`]
    /// requires exact idempotent response replay for request ID plus claim
    /// digest. The response is authenticated against the supplied clock sample
    /// before one transaction atomically
    /// commits both completed entry and current pointer. Success returns the
    /// exact unverified artifacts for fresh verification at an effect boundary;
    /// durable replay never manufactures live authority.
    /// `protected_clock` must read a protected paired clock when called. It is
    /// deliberately invoked after the issuer returns, preventing stale
    /// pre-request time from admitting a response that expired in transit.
    ///
    /// # Errors
    ///
    /// Returns [`DurableOwnershipAuthorityError`] for a missing intent,
    /// authority failure, unavailable protected clock, malicious response,
    /// stale post-issuance CAS state, or journal commit failure.
    pub fn complete<A, C>(
        &mut self,
        request_id: [u8; 16],
        issuer: &mut A,
        protected_clock: &mut C,
    ) -> Result<UnverifiedOwnershipLeaseResponse, DurableOwnershipAuthorityError>
    where
        A: OwnershipAuthority,
        C: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let entry = self
            .entries
            .get(&request_id)
            .cloned()
            .ok_or(DurableOwnershipAuthorityError::IntentNotFound)?;
        if let DurableEntryState::Completed { lease, .. } = entry.state {
            return Ok(lease.exact_response());
        }
        let claim = entry.claim;
        validate_claim_against_current(&claim, &self.current)?;
        let response = match claim.action() {
            OwnershipClaimAction::Acquire => issuer.acquire(&claim),
            OwnershipClaimAction::Renew => issuer.renew(&claim),
        };
        let response = response.map_err(OwnershipLeaseAcquisitionError::Authority)?;
        // The protected clock is sampled only after the possibly blocking
        // issuer call, so an already-expired response cannot be recorded using
        // stale pre-call time. This sample is advisory input to live signature
        // verification, not a transferable clock capability.
        let clock = protected_clock()?;
        let lease = self.verifier.verify_response(&claim, response, &clock)?;
        let exact_response = lease.exact_response();
        validate_claim_against_current(&claim, &self.current)?;
        let recovered = lease.into_recovered();
        let completed = DurableOwnershipEntry {
            claim: claim.clone(),
            state: DurableEntryState::Completed {
                accepted_wall_seconds: clock.wall_seconds(),
                lease: Box::new(recovered.clone()),
            },
        };
        let current_record = encode_current_pointer(request_id, &recovered);
        let records = vec![
            JournalRecord::put(
                RecordNamespace::Operation,
                durable_entry_key(&request_id),
                encode_durable_entry(&completed, self.verifier.authority()),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                durable_current_key(recovered.assignment().sandbox()),
                current_record,
            ),
        ];
        let transaction = JournalTransaction::new(completion_transaction_id(request_id), records)?;
        self.journal.commit(&transaction)?;
        self.entries.insert(request_id, completed);
        self.current
            .insert(recovered.assignment().sandbox(), recovered);
        Ok(exact_response)
    }

    /// Returns the unique state-machine head for one sandbox, if completed.
    ///
    /// The returned recovered artifacts carry no present-liveness or broker-effect
    /// proof. In particular, a head reconstructed historically may be expired
    /// and must pass the normal live broker verification path before use.
    #[must_use]
    pub fn current(&self, sandbox: SandboxId) -> Option<&RecoveredOwnershipLease> {
        self.current.get(&sandbox)
    }

    /// Returns whether one request is a durable unsigned intent.
    #[must_use]
    pub fn is_pending(&self, request_id: &[u8; 16]) -> bool {
        self.entries
            .get(request_id)
            .is_some_and(|entry| matches!(entry.state, DurableEntryState::Intent))
    }
}

fn ownership_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: MAXIMUM_DURABLE_JOURNAL_BYTES,
        maximum_record_bytes: MAXIMUM_DURABLE_RECORD_BYTES,
        maximum_key_bytes: MAXIMUM_DURABLE_KEY_BYTES,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: MAXIMUM_DURABLE_RECORD_BYTES * 2,
        maximum_transactions: MAXIMUM_DURABLE_TRANSACTIONS,
        maximum_materialized_bytes: MAXIMUM_DURABLE_MATERIALIZED_BYTES,
        maximum_materialized_records: MAXIMUM_DURABLE_RECORDS,
    }
}

fn validate_claim_against_current(
    claim: &OwnershipClaimV1,
    current: &BTreeMap<SandboxId, RecoveredOwnershipLease>,
) -> Result<(), DurableOwnershipAuthorityError> {
    let existing = current.get(&claim.assignment().sandbox());
    match (claim.action(), existing) {
        (OwnershipClaimAction::Acquire, None) => Ok(()),
        (OwnershipClaimAction::Renew, Some(lease))
            if lease.assignment() == claim.assignment()
                && lease.node() == claim.node()
                && Some(lease.expected_renewal_fence()) == claim.expected_prior() =>
        {
            Ok(())
        }
        _ => Err(DurableOwnershipAuthorityError::CompareAndSwapConflict),
    }
}

fn durable_entry_key(request_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(DURABLE_ENTRY_PREFIX.len() + request_id.len());
    key.extend_from_slice(DURABLE_ENTRY_PREFIX);
    key.extend_from_slice(request_id);
    key
}

fn durable_current_key(sandbox: SandboxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DURABLE_CURRENT_PREFIX.len() + 16);
    key.extend_from_slice(DURABLE_CURRENT_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key
}

fn completion_transaction_id(request_id: [u8; 16]) -> [u8; 16] {
    ownership_transaction_id(COMPLETION_TRANSACTION_DOMAIN, request_id)
}

fn begin_transaction_id(request_id: [u8; 16]) -> [u8; 16] {
    ownership_transaction_id(BEGIN_TRANSACTION_DOMAIN, request_id)
}

fn ownership_transaction_id(domain: &[u8], request_id: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(request_id);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.finalize()[..16]);
    // Journal transaction IDs reserve all-zero. Fixing one bit avoids a
    // probabilistic invalid output without admitting caller-selected bytes.
    id[0] |= 0x80;
    id
}

fn encode_durable_entry(entry: &DurableOwnershipEntry, authority: &KeyReference) -> Vec<u8> {
    let key_id = authority.stable_key_id().as_str().as_bytes();
    let response_bytes = match &entry.state {
        DurableEntryState::Intent => 0,
        DurableEntryState::Completed { lease, .. } => {
            lease.canonical_lease().len()
                + lease.canonical_signature().len()
                + lease.canonical_receipt().len()
                + lease.canonical_receipt_signature().len()
        }
    };
    let mut bytes = Vec::with_capacity(328 + key_id.len() + response_bytes);
    bytes.extend_from_slice(DURABLE_ENTRY_MAGIC);
    bytes.extend_from_slice(&DURABLE_FORMAT_VERSION.to_be_bytes());
    bytes.push(match entry.state {
        DurableEntryState::Intent => 1,
        DurableEntryState::Completed { .. } => 2,
    });
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(&authority.generation().to_be_bytes());
    bytes.extend_from_slice(authority.public_key_sha256().as_bytes());
    bytes.extend_from_slice(entry.claim.canonical_bytes());
    bytes.extend_from_slice(entry.claim.digest().as_bytes());
    match &entry.state {
        DurableEntryState::Intent => {
            bytes.extend_from_slice(&[0; 8 + 8 + 32 + 4 + 4 + 4 + 4]);
        }
        DurableEntryState::Completed {
            accepted_wall_seconds,
            lease,
        } => {
            bytes.extend_from_slice(&accepted_wall_seconds.to_be_bytes());
            bytes.extend_from_slice(&lease.generation().to_be_bytes());
            bytes.extend_from_slice(lease.digest().as_bytes());
            bytes.extend_from_slice(&(lease.canonical_lease().len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(lease.canonical_signature().len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(lease.canonical_receipt().len() as u32).to_be_bytes());
            bytes.extend_from_slice(
                &(lease.canonical_receipt_signature().len() as u32).to_be_bytes(),
            );
            bytes.extend_from_slice(lease.canonical_lease());
            bytes.extend_from_slice(lease.canonical_signature());
            bytes.extend_from_slice(lease.canonical_receipt());
            bytes.extend_from_slice(lease.canonical_receipt_signature());
        }
    }
    debug_assert!(bytes.len() <= MAXIMUM_DURABLE_ENTRY_BYTES);
    bytes
}

fn decode_durable_entry(
    key: &[u8],
    bytes: &[u8],
    verifier: &OwnershipAuthorityVerifier,
) -> Result<DurableOwnershipEntry, DurableOwnershipAuthorityError> {
    if bytes.starts_with(LEGACY_DURABLE_ENTRY_MAGIC) {
        return Err(DurableOwnershipAuthorityError::MigrationRequired);
    }
    if key.len() != DURABLE_ENTRY_PREFIX.len() + 16
        || !key.starts_with(DURABLE_ENTRY_PREFIX)
        || bytes.len() > MAXIMUM_DURABLE_ENTRY_BYTES
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let request_id: [u8; 16] = key[DURABLE_ENTRY_PREFIX.len()..]
        .try_into()
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let mut cursor = 0;
    if durable_take::<8>(bytes, &mut cursor)? != *DURABLE_ENTRY_MAGIC
        || u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?) != DURABLE_FORMAT_VERSION
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let status = durable_take::<1>(bytes, &mut cursor)?[0];
    if durable_take::<5>(bytes, &mut cursor)? != [0; 5] {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let key_id_length = usize::from(u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?));
    if key_id_length == 0 || key_id_length > 255 {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let key_id = durable_slice(bytes, &mut cursor, key_id_length)?;
    let authority_generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let authority_fingerprint = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if key_id != verifier.authority().stable_key_id().as_str().as_bytes()
        || authority_generation != verifier.authority().generation()
        || authority_fingerprint != verifier.authority().public_key_sha256()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let claim_bytes = durable_take::<CLAIM_BYTES>(bytes, &mut cursor)?;
    let claim = OwnershipClaimV1::from_canonical_bytes(&claim_bytes)
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let persisted_claim_digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if claim.request_id() != &request_id || persisted_claim_digest != claim.digest() {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let accepted_wall_seconds = i64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let response_generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let response_digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    let lease_length = usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let signature_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let receipt_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let receipt_signature_length =
        usize::try_from(u32::from_be_bytes(durable_take::<4>(bytes, &mut cursor)?))
            .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    if status == 1 {
        if accepted_wall_seconds != 0
            || response_generation != 0
            || response_digest.as_bytes() != &[0; 32]
            || lease_length != 0
            || signature_length != 0
            || receipt_length != 0
            || receipt_signature_length != 0
            || cursor != bytes.len()
        {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        return Ok(DurableOwnershipEntry {
            claim,
            state: DurableEntryState::Intent,
        });
    }
    if status != 2
        || response_generation == 0
        || response_digest.as_bytes() == &[0; 32]
        || lease_length == 0
        || lease_length > MAXIMUM_LEASE_BYTES
        || signature_length == 0
        || signature_length > MAXIMUM_SIGNATURE_BYTES
        || receipt_length == 0
        || receipt_length > aos_sandbox_ownership_protocol::MAXIMUM_RECEIPT_BYTES
        || receipt_signature_length == 0
        || receipt_signature_length > MAXIMUM_SIGNATURE_BYTES
        || lease_length
            .checked_add(signature_length)
            .and_then(|length| length.checked_add(receipt_length))
            .and_then(|length| length.checked_add(receipt_signature_length))
            .and_then(|length| cursor.checked_add(length))
            != Some(bytes.len())
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let response = UnverifiedOwnershipLeaseResponse::from_transport(
        durable_slice(bytes, &mut cursor, lease_length)?.to_vec(),
        durable_slice(bytes, &mut cursor, signature_length)?.to_vec(),
        durable_slice(bytes, &mut cursor, receipt_length)?.to_vec(),
        durable_slice(bytes, &mut cursor, receipt_signature_length)?.to_vec(),
    )
    .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    let lease = verifier
        .authenticate_historical_response(
            &claim,
            response,
            accepted_wall_seconds,
            response_generation,
            response_digest,
        )
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    Ok(DurableOwnershipEntry {
        claim,
        state: DurableEntryState::Completed {
            accepted_wall_seconds,
            lease: Box::new(lease),
        },
    })
}

fn encode_current_pointer(request_id: [u8; 16], lease: &RecoveredOwnershipLease) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(DURABLE_CURRENT_MAGIC);
    bytes.extend_from_slice(&DURABLE_FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&lease.generation().to_be_bytes());
    bytes.extend_from_slice(lease.digest().as_bytes());
    bytes
}

fn decode_current_pointer(
    key: &[u8],
    bytes: &[u8],
) -> Result<(SandboxId, [u8; 16], u64, ObjectDigest), DurableOwnershipAuthorityError> {
    if bytes.starts_with(LEGACY_DURABLE_CURRENT_MAGIC) {
        return Err(DurableOwnershipAuthorityError::MigrationRequired);
    }
    if key.len() != DURABLE_CURRENT_PREFIX.len() + 16
        || !key.starts_with(DURABLE_CURRENT_PREFIX)
        || bytes.len() != 66
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let sandbox = SandboxId::from_bytes(
        key[DURABLE_CURRENT_PREFIX.len()..]
            .try_into()
            .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?,
    );
    let mut cursor = 0;
    if durable_take::<8>(bytes, &mut cursor)? != *DURABLE_CURRENT_MAGIC
        || u16::from_be_bytes(durable_take::<2>(bytes, &mut cursor)?) != DURABLE_FORMAT_VERSION
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let request_id = durable_take::<16>(bytes, &mut cursor)?;
    let generation = u64::from_be_bytes(durable_take::<8>(bytes, &mut cursor)?);
    let digest = ObjectDigest::from_bytes(durable_take::<32>(bytes, &mut cursor)?);
    if sandbox.as_bytes() == &[0; 16]
        || request_id == [0; 16]
        || generation == 0
        || digest.as_bytes() == &[0; 32]
        || cursor != bytes.len()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    Ok((sandbox, request_id, generation, digest))
}

type RecoveredOwnershipState = (
    BTreeMap<[u8; 16], DurableOwnershipEntry>,
    BTreeMap<SandboxId, RecoveredOwnershipLease>,
);

fn recover_durable_ownership(
    journal: &Journal,
    verifier: &OwnershipAuthorityVerifier,
) -> Result<RecoveredOwnershipState, DurableOwnershipAuthorityError> {
    let mut entries = BTreeMap::new();
    for (key, value) in journal.records(RecordNamespace::Operation) {
        if entries.len() >= MAXIMUM_DURABLE_ENTRIES {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        if key.starts_with(LEGACY_DURABLE_ENTRY_PREFIX) {
            return Err(DurableOwnershipAuthorityError::MigrationRequired);
        }
        if !key.starts_with(DURABLE_ENTRY_PREFIX) {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        let entry = decode_durable_entry(key, value, verifier)?;
        if entries.insert(*entry.claim.request_id(), entry).is_some() {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
    }
    let mut pointers = BTreeMap::new();
    for (key, value) in journal.records(RecordNamespace::DesiredState) {
        if pointers.len() >= MAXIMUM_DURABLE_CURRENT_POINTERS {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        if key.starts_with(LEGACY_DURABLE_CURRENT_PREFIX) {
            return Err(DurableOwnershipAuthorityError::MigrationRequired);
        }
        if !key.starts_with(DURABLE_CURRENT_PREFIX) {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        let (sandbox, request, generation, digest) = decode_current_pointer(key, value)?;
        if pointers
            .insert(sandbox, (request, generation, digest))
            .is_some()
        {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
    }
    if journal.records(RecordNamespace::Effect).next().is_some()
        || journal
            .records(RecordNamespace::Idempotency)
            .next()
            .is_some()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let mut grouped = BTreeMap::<SandboxId, Vec<_>>::new();
    for (request, entry) in &entries {
        grouped
            .entry(entry.claim.assignment().sandbox())
            .or_default()
            .push((request, entry));
    }
    if pointers
        .keys()
        .any(|sandbox| !grouped.contains_key(sandbox))
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let mut current = BTreeMap::new();
    for (sandbox, scoped) in grouped {
        recover_sandbox_chain(sandbox, &scoped, &entries, &pointers, &mut current)?;
    }
    Ok((entries, current))
}

fn recover_sandbox_chain(
    sandbox: SandboxId,
    scoped: &[(&[u8; 16], &DurableOwnershipEntry)],
    entries: &BTreeMap<[u8; 16], DurableOwnershipEntry>,
    pointers: &BTreeMap<SandboxId, ([u8; 16], u64, ObjectDigest)>,
    current: &mut BTreeMap<SandboxId, RecoveredOwnershipLease>,
) -> Result<(), DurableOwnershipAuthorityError> {
    let pending: Vec<_> = scoped
        .iter()
        .filter(|(_, entry)| matches!(entry.state, DurableEntryState::Intent))
        .collect();
    if pending.len() > 1 {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let completed: Vec<_> = scoped
        .iter()
        .filter_map(|(request, entry)| match &entry.state {
            DurableEntryState::Intent => None,
            DurableEntryState::Completed { lease, .. } => Some((*request, entry, lease)),
        })
        .collect();
    if completed.is_empty() {
        if pointers.contains_key(&sandbox)
            || pending
                .first()
                .is_some_and(|(_, entry)| entry.claim.action() != OwnershipClaimAction::Acquire)
        {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        return Ok(());
    }
    let roots: Vec<_> = completed
        .iter()
        .filter(|(_, entry, _)| entry.claim.action() == OwnershipClaimAction::Acquire)
        .collect();
    if roots.len() != 1 {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let mut by_fence = BTreeMap::new();
    for (request, _, lease) in &completed {
        let fence = (lease.generation(), *lease.digest().as_bytes());
        if by_fence.insert(fence, **request).is_some() {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
    }
    let mut children = BTreeMap::new();
    for (request, entry, lease) in &completed {
        if entry.claim.action() == OwnershipClaimAction::Renew {
            let prior = entry
                .claim
                .expected_prior()
                .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
            let predecessor = by_fence
                .get(&(prior.generation(), *prior.digest().as_bytes()))
                .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
            let predecessor_entry = entries
                .get(predecessor)
                .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
            let DurableEntryState::Completed {
                lease: predecessor_lease,
                ..
            } = &predecessor_entry.state
            else {
                return Err(DurableOwnershipAuthorityError::CorruptState);
            };
            if lease.generation() <= predecessor_lease.generation()
                || lease.assignment() != predecessor_lease.assignment()
                || lease.node() != predecessor_lease.node()
                || children.insert(*predecessor, **request).is_some()
            {
                return Err(DurableOwnershipAuthorityError::CorruptState);
            }
        }
    }
    let mut visited = BTreeSet::new();
    let mut head_request = *roots[0].0;
    loop {
        if !visited.insert(head_request) {
            return Err(DurableOwnershipAuthorityError::CorruptState);
        }
        match children.get(&head_request) {
            Some(next) => head_request = *next,
            None => break,
        }
    }
    if visited.len() != completed.len() {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let head = entries
        .get(&head_request)
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    let DurableEntryState::Completed {
        lease: head_lease, ..
    } = &head.state
    else {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    };
    if pointers.get(&sandbox) != Some(&(head_request, head_lease.generation(), head_lease.digest()))
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    if let Some((_, pending_entry)) = pending.first() {
        validate_claim_against_current(
            &pending_entry.claim,
            &BTreeMap::from([(sandbox, head_lease.as_ref().clone())]),
        )
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)?;
    }
    current.insert(sandbox, head_lease.as_ref().clone());
    Ok(())
}

fn durable_take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], DurableOwnershipAuthorityError> {
    durable_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| DurableOwnershipAuthorityError::CorruptState)
}

fn durable_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], DurableOwnershipAuthorityError> {
    let end = cursor
        .checked_add(length)
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(DurableOwnershipAuthorityError::CorruptState)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
    use aos_sandbox_core::model::{
        KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment,
        MediaType, NodeId, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType,
        ProtocolVersion, RawClockProvenance, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_ownership_protocol::protocol::{
        MAXIMUM_OWNERSHIP_RESPONSE_BYTES, NegotiatedOwnershipSessionV1, OwnershipClientHelloV1,
        OwnershipMethodV1, OwnershipProtocolValidationError, OwnershipRequestBodyV1,
        OwnershipResponseOutcomeV1, OwnershipTransactionReferenceV1, OwnershipTransactionStatusV1,
    };
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::journal::IdempotencyKey;
    use crate::publication::tests::{activation_claim, activation_fixture};
    use crate::{
        ActivatedOperationCompiler, EffectDomain, EffectFailure, EffectObservation, EffectPlan,
        EffectReceipt, NodeController, NodeControllerLimits, OperationCompilationError,
        OperationPlan, OwnershipResumeOutcomeV1, Reconciler, SingleNodeEffectExecutor,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-ownership-{label}-{}-{}",
                std::process::id(),
                aos_sandbox_core::OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("authority.journal")
        }

        fn controller_journal(&self) -> PathBuf {
            self.0.join("controller.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestAuthority {
        signing_key: SigningKey,
        authority: KeyReference,
        scope: TrustScopeId,
        policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        requests: BTreeMap<[u8; 16], (ObjectDigest, UnverifiedOwnershipLeaseResponse)>,
        current: Option<(LeaseAssignment, NodeId, u64, ObjectDigest)>,
        now_seconds: i64,
        duration_seconds: i64,
        generation_increment: u64,
        override_assignment: Option<LeaseAssignment>,
        override_node: Option<NodeId>,
        calls: Rc<Cell<usize>>,
    }

    impl TestAuthority {
        fn issue(
            &mut self,
            claim: &OwnershipClaimV1,
            generation: u64,
        ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
            if let Some((digest, response)) = self.requests.get(claim.request_id()) {
                return if *digest == claim.digest() {
                    Ok(response.clone())
                } else {
                    Err(OwnershipAuthorityError::IdempotencyConflict)
                };
            }
            let assignment = self.override_assignment.unwrap_or(claim.assignment());
            let node = self.override_node.unwrap_or(claim.node());
            let nonce_byte = claim.request_id()[0].wrapping_add(generation as u8).max(1);
            let lease = OwnershipLease::new(
                assignment,
                node,
                generation,
                self.now_seconds - 10,
                self.now_seconds - 10 + self.duration_seconds,
                5,
                [nonce_byte; 16],
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            let lease_bytes = encode_ownership_lease(&lease);
            let descriptor = descriptor_for_bytes(
                MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                    .map_err(|_| OwnershipAuthorityError::Internal)?,
                &lease_bytes,
            );
            let statement = SignatureStatement::new(
                descriptor.clone(),
                self.scope,
                self.authority.clone(),
                SignaturePurpose::OwnershipLease,
                lease.authority_issued_seconds(),
                Some(lease.authority_expires_seconds()),
                self.policy_descriptor.clone(),
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            let signature = sign_statement(statement, &self.signing_key)
                .map_err(|_| OwnershipAuthorityError::Internal)?;
            let receipt =
                OwnershipTransactionReceiptV1::new(self.authority.clone(), claim, &lease_bytes)
                    .map_err(|_| OwnershipAuthorityError::Internal)?;
            let receipt_descriptor = descriptor_for_bytes(
                MediaType::new(
                    PortableMediaType::OwnershipTransactionReceipt
                        .as_str()
                        .to_owned(),
                )
                .map_err(|_| OwnershipAuthorityError::Internal)?,
                receipt.canonical_bytes(),
            );
            let receipt_statement = SignatureStatement::new(
                receipt_descriptor,
                self.scope,
                self.authority.clone(),
                SignaturePurpose::OwnershipLease,
                lease.authority_issued_seconds(),
                Some(lease.authority_expires_seconds()),
                self.policy_descriptor.clone(),
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            let receipt_signature = sign_statement(receipt_statement, &self.signing_key)
                .map_err(|_| OwnershipAuthorityError::Internal)?;
            let response = UnverifiedOwnershipLeaseResponse::from_transport(
                lease_bytes,
                encode_signature(&signature),
                receipt.canonical_bytes().to_vec(),
                encode_signature(&receipt_signature),
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?;
            self.requests
                .insert(*claim.request_id(), (claim.digest(), response.clone()));
            self.current = Some((assignment, node, generation, descriptor.digest()));
            Ok(response)
        }
    }

    impl OwnershipAuthority for TestAuthority {
        fn acquire(
            &mut self,
            claim: &OwnershipClaimV1,
        ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
            self.calls.set(self.calls.get() + 1);
            if claim.action() != OwnershipClaimAction::Acquire {
                return Err(OwnershipAuthorityError::Internal);
            }
            if let Some((digest, response)) = self.requests.get(claim.request_id()) {
                return if *digest == claim.digest() {
                    Ok(response.clone())
                } else {
                    Err(OwnershipAuthorityError::IdempotencyConflict)
                };
            }
            if self.current.is_some() {
                return Err(OwnershipAuthorityError::AlreadyOwned);
            }
            self.issue(claim, 7)
        }

        fn renew(
            &mut self,
            claim: &OwnershipClaimV1,
        ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
            self.calls.set(self.calls.get() + 1);
            if claim.action() != OwnershipClaimAction::Renew {
                return Err(OwnershipAuthorityError::Internal);
            }
            if let Some((digest, response)) = self.requests.get(claim.request_id()) {
                return if *digest == claim.digest() {
                    Ok(response.clone())
                } else {
                    Err(OwnershipAuthorityError::IdempotencyConflict)
                };
            }
            let Some((assignment, node, generation, digest)) = self.current else {
                return Err(OwnershipAuthorityError::StaleExpectedPrior);
            };
            if assignment != claim.assignment()
                || node != claim.node()
                || claim.expected_prior()
                    != Some(
                        ExpectedOwnershipLease::new(generation, digest)
                            .map_err(|_| OwnershipAuthorityError::Internal)?,
                    )
            {
                return Err(OwnershipAuthorityError::StaleExpectedPrior);
            }
            let next = generation
                .checked_add(self.generation_increment)
                .ok_or(OwnershipAuthorityError::Internal)?;
            self.issue(claim, next)
        }
    }

    struct Fixture {
        authority: TestAuthority,
        verifier: OwnershipAuthorityVerifier,
        clock: RawPairedClockSample,
    }

    fn fixture(key_byte: u8) -> Fixture {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let authority = KeyReference::new(
            StableKeyId::new(format!("ownership-authority-{key_byte}"))
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            3,
            ObjectDigest::from_bytes(Sha256::digest(public_key).into()),
            KeyUsage::OwnershipLease,
        );
        let scope = TrustScopeId::from_bytes([41; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::OwnershipLease,
            vec![authority.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &policy_bytes,
        );
        let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor.clone(),
            scope,
            authority.clone(),
            public_key,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
        let clock = test_clock(150);
        Fixture {
            authority: TestAuthority {
                signing_key,
                authority: authority.clone(),
                scope,
                policy_descriptor,
                requests: BTreeMap::new(),
                current: None,
                now_seconds: 150,
                duration_seconds: 40,
                generation_increment: 2,
                override_assignment: None,
                override_node: None,
                calls: Rc::new(Cell::new(0)),
            },
            verifier: OwnershipAuthorityVerifier::new(anchor, authority),
            clock,
        }
    }

    fn test_clock(wall_seconds: i64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"test-owner-clock")
                .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
            [42; 16],
            wall_seconds,
            10_000_000_000,
        )
        .unwrap_or_else(|error| panic!("test clock failed: {error}"))
    }

    fn assignment(byte: u8) -> LeaseAssignment {
        LeaseAssignment::new(
            SandboxId::from_bytes([byte; 16]),
            IncarnationId::from_bytes([byte + 1; 16]),
            AssignmentEpoch::new(5),
            ObjectDigest::from_bytes([byte + 2; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"))
    }

    fn indexed_assignment(index: u16) -> LeaseAssignment {
        let mut sandbox = [0; 16];
        sandbox[..2].copy_from_slice(&index.to_be_bytes());
        let mut incarnation = [0; 16];
        incarnation[..2].copy_from_slice(&index.saturating_add(1).to_be_bytes());
        let mut manifest = [0; 32];
        manifest[..2].copy_from_slice(&index.saturating_add(2).to_be_bytes());
        LeaseAssignment::new(
            SandboxId::from_bytes(sandbox),
            IncarnationId::from_bytes(incarnation),
            AssignmentEpoch::new(5),
            ObjectDigest::from_bytes(manifest),
        )
        .unwrap_or_else(|error| panic!("indexed test assignment failed: {error}"))
    }

    fn acquire_claim(request: u8) -> OwnershipClaimV1 {
        OwnershipClaimV1::acquire(
            [request; 16],
            assignment(1),
            DesiredGeneration::new(6),
            NodeId::from_bytes([4; 16]),
            60,
        )
        .unwrap_or_else(|error| panic!("test claim failed: {error}"))
    }

    fn open_test_store(
        path: &Path,
        key_byte: u8,
    ) -> Result<DurableOwnershipAuthority, DurableOwnershipAuthorityError> {
        let (journal, _) = Journal::open(path, JournalLimits::default())?;
        DurableOwnershipAuthority::from_journal(journal, fixture(key_byte).verifier)
    }

    trait LeasePrior {
        fn assignment(&self) -> LeaseAssignment;
        fn node(&self) -> NodeId;
        fn fence(&self) -> ExpectedOwnershipLease;
    }

    impl LeasePrior for SignedOwnershipLease {
        fn assignment(&self) -> LeaseAssignment {
            self.assignment()
        }
        fn node(&self) -> NodeId {
            self.node()
        }
        fn fence(&self) -> ExpectedOwnershipLease {
            self.expected_renewal_fence()
        }
    }

    impl LeasePrior for RecoveredOwnershipLease {
        fn assignment(&self) -> LeaseAssignment {
            self.assignment()
        }
        fn node(&self) -> NodeId {
            self.node()
        }
        fn fence(&self) -> ExpectedOwnershipLease {
            self.expected_renewal_fence()
        }
    }

    fn renewal_claim(request: u8, prior: &impl LeasePrior) -> OwnershipClaimV1 {
        OwnershipClaimV1::renew(
            [request; 16],
            prior.assignment(),
            DesiredGeneration::new(6),
            prior.node(),
            prior.fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test renewal claim failed: {error}"))
    }

    fn completed_entry(
        claim: OwnershipClaimV1,
        lease: SignedOwnershipLease,
        accepted_wall_seconds: i64,
    ) -> DurableOwnershipEntry {
        DurableOwnershipEntry {
            claim,
            state: DurableEntryState::Completed {
                accepted_wall_seconds,
                lease: Box::new(lease.into_recovered()),
            },
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}")
                .unwrap_or_else(|error| panic!("test hex encoding failed: {error}"));
        }
        encoded
    }

    fn flip_embedded_artifact(bytes: &mut [u8], artifact: &[u8]) {
        let offset = bytes
            .windows(artifact.len())
            .position(|candidate| candidate == artifact)
            .unwrap_or_else(|| panic!("test artifact was not embedded"));
        bytes[offset + artifact.len() / 2] ^= 1;
    }

    #[test]
    fn claim_encoding_is_fixed_canonical_and_substitution_bound() {
        let claim = acquire_claim(5);
        assert_eq!(claim.canonical_bytes().len(), CLAIM_BYTES);
        assert_eq!(
            to_hex(claim.canonical_bytes()),
            "414f534f434c4d3100010100000000000505050505050505050505050505050501010101010101010101010101010101020202020202020202020202020202020000000000000005030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c"
        );
        assert_eq!(
            to_hex(claim.digest().as_bytes()),
            "621b3094bf91a148412e2debb10c168318b4375e40a2e7164d3076f222ca25e4"
        );
        assert_eq!(
            OwnershipClaimV1::from_canonical_bytes(claim.canonical_bytes())
                .unwrap_or_else(|error| panic!("test claim decode failed: {error}")),
            claim
        );
        let changed = OwnershipClaimV1::acquire(
            [6; 16],
            claim.assignment(),
            claim.desired_generation(),
            claim.node(),
            claim.requested_maximum_seconds(),
        )
        .unwrap_or_else(|error| panic!("test changed claim failed: {error}"));
        assert_ne!(claim.digest(), changed.digest());

        let mut reserved = *claim.canonical_bytes();
        reserved[11] = 1;
        assert_eq!(
            OwnershipClaimV1::from_canonical_bytes(&reserved),
            Err(OwnershipClaimError::InvalidEncoding)
        );
    }

    #[test]
    fn acquire_is_exclusive_and_exact_request_replay_is_idempotent() {
        let mut fixture = fixture(17);
        let claim = acquire_claim(5);
        let first = fixture
            .verifier
            .acquire(&mut fixture.authority, &claim, &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        let replay = fixture
            .verifier
            .acquire(&mut fixture.authority, &claim, &fixture.clock)
            .unwrap_or_else(|error| panic!("test replay failed: {error}"));
        assert_eq!(first, replay);
        assert_eq!(first.generation(), 7);
        assert_ne!(first.renewal_nonce(), &[0; 16]);
        assert_eq!(first.authority_issued_seconds(), 140);
        assert_eq!(first.authority_expires_seconds(), 180);

        assert_eq!(
            fixture
                .verifier
                .acquire(&mut fixture.authority, &acquire_claim(6), &fixture.clock,),
            Err(OwnershipLeaseAcquisitionError::Authority(
                OwnershipAuthorityError::AlreadyOwned
            ))
        );
    }

    #[test]
    fn renew_is_exact_cas_and_changes_only_lease_facts() {
        let mut fixture = fixture(18);
        let old = fixture
            .verifier
            .acquire(&mut fixture.authority, &acquire_claim(5), &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        fixture.authority.now_seconds = 160;
        let renew = OwnershipClaimV1::renew(
            [7; 16],
            old.assignment(),
            DesiredGeneration::new(6),
            old.node(),
            old.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test renewal claim failed: {error}"));
        let renewal_clock = test_clock(160);
        let renewed = fixture
            .verifier
            .renew(&mut fixture.authority, &renew, &renewal_clock)
            .unwrap_or_else(|error| panic!("test renewal failed: {error}"));

        assert_eq!(renewed.assignment(), old.assignment());
        assert_eq!(renewed.node(), old.node());
        assert!(renewed.generation() > old.generation());
        assert_ne!(renewed.digest(), old.digest());
        assert_ne!(renewed.renewal_nonce(), old.renewal_nonce());

        let stale = OwnershipClaimV1::renew(
            [8; 16],
            old.assignment(),
            DesiredGeneration::new(6),
            old.node(),
            old.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test stale claim failed: {error}"));
        assert_eq!(
            fixture
                .verifier
                .renew(&mut fixture.authority, &stale, &renewal_clock),
            Err(OwnershipLeaseAcquisitionError::Authority(
                OwnershipAuthorityError::StaleExpectedPrior
            ))
        );
    }

    #[test]
    fn verifier_rejects_context_expiry_duration_generation_and_signature_attacks() {
        for attack in 0..5 {
            let mut fixture = fixture(19);
            match attack {
                0 => fixture.authority.override_node = Some(NodeId::from_bytes([99; 16])),
                1 => fixture.authority.override_assignment = Some(assignment(51)),
                2 => fixture.authority.now_seconds = 50,
                3 => fixture.authority.duration_seconds = 100,
                _ => {}
            }
            let claim = acquire_claim(5);
            let response = fixture
                .authority
                .acquire(&claim)
                .unwrap_or_else(|error| panic!("test raw acquire failed: {error}"));
            let response = if attack == 4 {
                let mut signature = response.signature().to_vec();
                let last = signature.len() - 1;
                signature[last] ^= 1;
                UnverifiedOwnershipLeaseResponse::from_transport(
                    response.lease().to_vec(),
                    signature,
                    response.receipt().to_vec(),
                    response.receipt_signature().to_vec(),
                )
                .unwrap_or_else(|error| panic!("test tamper response failed: {error}"))
            } else {
                response
            };
            assert_eq!(
                fixture
                    .verifier
                    .verify_response(&claim, response, &fixture.clock),
                Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
            );
        }

        let mut fixture = fixture(20);
        let old = fixture
            .verifier
            .acquire(&mut fixture.authority, &acquire_claim(5), &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        fixture.authority.generation_increment = 0;
        let claim = OwnershipClaimV1::renew(
            [9; 16],
            old.assignment(),
            DesiredGeneration::new(6),
            old.node(),
            old.expected_renewal_fence(),
            60,
        )
        .unwrap_or_else(|error| panic!("test renew claim failed: {error}"));
        assert_eq!(
            fixture
                .verifier
                .renew(&mut fixture.authority, &claim, &fixture.clock),
            Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
        );
    }

    #[test]
    fn trust_generation_substitution_is_rejected() {
        let mut issuer = fixture(21);
        let verifier = fixture(22).verifier;
        let claim = acquire_claim(5);
        assert_eq!(
            verifier.acquire(&mut issuer.authority, &claim, &issuer.clock),
            Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
        );
    }

    #[test]
    fn receipt_golden_and_verifier_reject_artifact_substitution() {
        let mut fixture = fixture(52);
        let first_claim = acquire_claim(5);
        let second_claim = OwnershipClaimV1::acquire(
            [6; 16],
            first_claim.assignment(),
            DesiredGeneration::new(first_claim.desired_generation().get() + 1),
            first_claim.node(),
            first_claim.requested_maximum_seconds(),
        )
        .unwrap();
        let first = fixture.authority.issue(&first_claim, 7).unwrap();
        assert_eq!(
            to_hex(first.receipt()),
            "414f534f545231000001000100010000010000000000000000166f776e6572736869702d617574686f726974792d353200000000000000030cc42263abfb754678ab60fc3511210608a4b3a64b996170d96b4c21eb3cecbc05050505050505050505050505050505621b3094bf91a148412e2debb10c168318b4375e40a2e7164d3076f222ca25e400000000000000703b245020c73f18fa15642185baf02729622427441736ae998e4e955096fb2fe4"
        );
        assert_eq!(
            descriptor_for_bytes(
                MediaType::new(
                    PortableMediaType::OwnershipTransactionReceipt
                        .as_str()
                        .to_owned()
                )
                .unwrap(),
                first.receipt()
            )
            .digest()
            .to_string(),
            "sha256:10f29616ee1a08f704510c3d6455c6f85a4cd04fca669c164bc3e093e400f539"
        );
        assert_eq!(
            to_hex(first.receipt_signature()),
            "82890184783c6170706c69636174696f6e2f766e642e616f732e73616e64626f782e6f776e6572736869702d7472616e73616374696f6e2d726563656970742e763101582010f29616ee1a08f704510c3d6455c6f85a4cd04fca669c164bc3e093e400f53918b0502929292929292929292929292929292984766f776e6572736869702d617574686f726974792d35320358200cc42263abfb754678ab60fc3511210608a4b3a64b996170d96b4c21eb3cecbc050105188c18b48478306170706c69636174696f6e2f766e642e616f732e73616e64626f782e74727573742d706f6c6963792e76312b63626f72015820d46ce9405fdd0318139e73a8eeb324f5e30755b6487945436416f3068a36c9ef18525840dd311e657898ead235189df060efa80aaa585aa49ee3c9f5051c76faa24b7743ceb6ece33117a62111ab9d4277d389f2c8db00ec122246e5e150d324fd96680b"
        );
        let second = fixture.authority.issue(&second_claim, 8).unwrap();

        let substitutions = [
            UnverifiedOwnershipLeaseResponse::from_transport(
                first.lease().to_vec(),
                first.signature().to_vec(),
                second.receipt().to_vec(),
                second.receipt_signature().to_vec(),
            )
            .unwrap(),
            UnverifiedOwnershipLeaseResponse::from_transport(
                first.lease().to_vec(),
                first.signature().to_vec(),
                first.receipt().to_vec(),
                second.receipt_signature().to_vec(),
            )
            .unwrap(),
            UnverifiedOwnershipLeaseResponse::from_transport(
                second.lease().to_vec(),
                second.signature().to_vec(),
                first.receipt().to_vec(),
                first.receipt_signature().to_vec(),
            )
            .unwrap(),
        ];
        for response in substitutions {
            assert_eq!(
                fixture
                    .verifier
                    .verify_response(&first_claim, response, &fixture.clock),
                Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
            );
        }
    }

    #[test]
    fn request_id_reuse_with_different_claim_is_rejected() {
        let mut fixture = fixture(23);
        let claim = acquire_claim(5);
        fixture
            .verifier
            .acquire(&mut fixture.authority, &claim, &fixture.clock)
            .unwrap_or_else(|error| panic!("test acquire failed: {error}"));
        let changed = OwnershipClaimV1::acquire(
            *claim.request_id(),
            claim.assignment(),
            claim.desired_generation(),
            claim.node(),
            59,
        )
        .unwrap_or_else(|error| panic!("test changed claim failed: {error}"));
        assert_eq!(
            fixture
                .verifier
                .acquire(&mut fixture.authority, &changed, &fixture.clock),
            Err(OwnershipLeaseAcquisitionError::Authority(
                OwnershipAuthorityError::IdempotencyConflict
            ))
        );
    }

    #[test]
    fn durable_intent_restart_and_signed_before_commit_crash_replay_safely() {
        let directory = TestDirectory::new("durable-crash");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(31);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let claim = acquire_claim(5);
        assert_eq!(
            store.begin(&claim).unwrap(),
            DurableOwnershipBeginOutcome::Pending
        );
        assert!(authority.requests.is_empty());
        assert!(store.current(claim.assignment().sandbox()).is_none());
        drop(store);

        let store = open_test_store(&path, 31).unwrap();
        assert!(store.is_pending(claim.request_id()));
        let issued_before_commit = authority.acquire(&claim).unwrap();
        drop(store);

        let mut store = open_test_store(&path, 31).unwrap();
        let completed = store
            .complete(*claim.request_id(), &mut authority, &mut || Ok(clock))
            .unwrap();
        assert_eq!(completed.lease(), issued_before_commit.lease());
        assert_eq!(completed.signature(), issued_before_commit.signature());
        drop(store);

        assert!(matches!(
            open_test_store(&path, 30),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));

        let mut store = open_test_store(&path, 31).unwrap();
        assert_eq!(
            store.begin(&claim).unwrap(),
            DurableOwnershipBeginOutcome::Replay(Box::new(completed.clone()))
        );
        assert_eq!(
            store
                .current(claim.assignment().sandbox())
                .map(RecoveredOwnershipLease::exact_response),
            Some(completed)
        );
        let rebound = OwnershipClaimV1::acquire(
            *claim.request_id(),
            claim.assignment(),
            claim.desired_generation(),
            claim.node(),
            59,
        )
        .unwrap();
        assert!(matches!(
            store.begin(&rebound),
            Err(DurableOwnershipAuthorityError::IdempotencyConflict)
        ));
        assert!(matches!(
            store.begin(&acquire_claim(6)),
            Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
        ));
    }

    #[test]
    fn durable_renewal_chain_recovers_expired_history_and_rejects_stale_cas() {
        let directory = TestDirectory::new("durable-renewal");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(32);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let acquire = acquire_claim(5);
        store.begin(&acquire).unwrap();
        store
            .complete(*acquire.request_id(), &mut authority, &mut || Ok(clock))
            .unwrap();
        let old = store
            .current(acquire.assignment().sandbox())
            .unwrap()
            .clone();
        let renew = renewal_claim(7, &old);
        store.begin(&renew).unwrap();
        authority.now_seconds = 160;
        store
            .complete(*renew.request_id(), &mut authority, &mut || {
                Ok(test_clock(160))
            })
            .unwrap();
        let renewed = store
            .current(acquire.assignment().sandbox())
            .unwrap()
            .clone();
        assert!(renewed.generation() > old.generation());
        let stale = renewal_claim(8, &old);
        assert!(matches!(
            store.begin(&stale),
            Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
        ));
        drop(store);

        // Recovery deliberately has no current wall-clock input; both signed
        // intervals may be expired now, but their durable acceptance instants
        // still authenticate the chain without producing broker authority.
        let store = open_test_store(&path, 32).unwrap();
        assert_eq!(
            store.current(acquire.assignment().sandbox()),
            Some(&renewed)
        );
    }

    #[test]
    fn distinct_sandboxes_recover_independent_acquired_and_renewed_heads() {
        let directory = TestDirectory::new("independent-sandbox-chains");
        let path = directory.journal();
        let verifier = fixture(45).verifier;
        let mut issuer_a = fixture(45).authority;
        let mut issuer_b = fixture(45).authority;
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let acquire_a = OwnershipClaimV1::acquire(
            [10; 16],
            assignment(10),
            DesiredGeneration::new(6),
            NodeId::from_bytes([50; 16]),
            60,
        )
        .unwrap();
        let acquire_b = OwnershipClaimV1::acquire(
            [20; 16],
            assignment(20),
            DesiredGeneration::new(6),
            NodeId::from_bytes([51; 16]),
            60,
        )
        .unwrap();

        store.begin(&acquire_a).unwrap();
        store
            .complete(*acquire_a.request_id(), &mut issuer_a, &mut || {
                Ok(test_clock(150))
            })
            .unwrap();
        let acquired_a = store
            .current(acquire_a.assignment().sandbox())
            .unwrap()
            .clone();
        store.begin(&acquire_b).unwrap();
        store
            .complete(*acquire_b.request_id(), &mut issuer_b, &mut || {
                Ok(test_clock(150))
            })
            .unwrap();
        let acquired_b = store
            .current(acquire_b.assignment().sandbox())
            .unwrap()
            .clone();
        let renew_a = renewal_claim(11, &acquired_a);
        let renew_b = renewal_claim(21, &acquired_b);
        issuer_a.now_seconds = 160;
        issuer_b.now_seconds = 170;
        store.begin(&renew_b).unwrap();
        store
            .complete(*renew_b.request_id(), &mut issuer_b, &mut || {
                Ok(test_clock(170))
            })
            .unwrap();
        let renewed_b = store
            .current(acquire_b.assignment().sandbox())
            .unwrap()
            .clone();
        store.begin(&renew_a).unwrap();
        store
            .complete(*renew_a.request_id(), &mut issuer_a, &mut || {
                Ok(test_clock(160))
            })
            .unwrap();
        let renewed_a = store
            .current(acquire_a.assignment().sandbox())
            .unwrap()
            .clone();
        drop(store);

        let reopened = open_test_store(&path, 45).unwrap();
        assert_eq!(
            reopened.current(acquire_a.assignment().sandbox()),
            Some(&renewed_a)
        );
        assert_eq!(
            reopened.current(acquire_b.assignment().sandbox()),
            Some(&renewed_b)
        );
        assert_ne!(renewed_a.digest(), renewed_b.digest());
    }

    #[test]
    fn cross_sandbox_current_pointer_substitution_fails_recovery_closed() {
        for attack in 0..3_u8 {
            let directory = TestDirectory::new(&format!("pointer-substitution-{attack}"));
            let path = directory.journal();
            let verifier = fixture(46 + attack).verifier;
            let mut issuer_a = fixture(46 + attack).authority;
            let mut issuer_b = fixture(46 + attack).authority;
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
            let claim_a = OwnershipClaimV1::acquire(
                [10; 16],
                assignment(10),
                DesiredGeneration::new(6),
                NodeId::from_bytes([50; 16]),
                60,
            )
            .unwrap();
            let claim_b = OwnershipClaimV1::acquire(
                [20; 16],
                assignment(20),
                DesiredGeneration::new(6),
                NodeId::from_bytes([51; 16]),
                60,
            )
            .unwrap();
            store.begin(&claim_a).unwrap();
            store
                .complete(*claim_a.request_id(), &mut issuer_a, &mut || {
                    Ok(test_clock(150))
                })
                .unwrap();
            let lease_a = store
                .current(claim_a.assignment().sandbox())
                .unwrap()
                .clone();
            store.begin(&claim_b).unwrap();
            store
                .complete(*claim_b.request_id(), &mut issuer_b, &mut || {
                    Ok(test_clock(150))
                })
                .unwrap();
            let lease_b = store
                .current(claim_b.assignment().sandbox())
                .unwrap()
                .clone();
            drop(store);

            let key_a = durable_current_key(claim_a.assignment().sandbox());
            let key_b = durable_current_key(claim_b.assignment().sandbox());
            let records = match attack {
                0 => vec![JournalRecord::delete(RecordNamespace::DesiredState, key_a)],
                1 => vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    key_a,
                    encode_current_pointer(*claim_b.request_id(), &lease_b),
                )],
                _ => vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key_a,
                        encode_current_pointer(*claim_b.request_id(), &lease_b),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key_b,
                        encode_current_pointer(*claim_a.request_id(), &lease_a),
                    ),
                ],
            };
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(&JournalTransaction::new([100 + attack; 16], records).unwrap())
                .unwrap();
            drop(journal);

            assert!(matches!(
                open_test_store(&path, 46 + attack),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ));
        }
    }

    #[test]
    fn durable_recovery_rejects_duplicate_roots_and_forks() {
        let directory = TestDirectory::new("durable-roots");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(33);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let first_claim = acquire_claim(5);
        store.begin(&first_claim).unwrap();
        store
            .complete(*first_claim.request_id(), &mut authority, &mut || Ok(clock))
            .unwrap();
        drop(store);

        let mut second = fixture(33);
        let second_claim = acquire_claim(6);
        let second_lease = second
            .verifier
            .acquire(&mut second.authority, &second_claim, &second.clock)
            .unwrap();
        let entry = completed_entry(second_claim.clone(), second_lease, 150);
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [90; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        durable_entry_key(second_claim.request_id()),
                        encode_durable_entry(&entry, second.verifier.authority()),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(matches!(
            open_test_store(&path, 33),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));

        let directory = TestDirectory::new("durable-fork");
        let path = directory.journal();
        let mut base = fixture(34);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, base.verifier).unwrap();
        let root_claim = acquire_claim(5);
        store.begin(&root_claim).unwrap();
        store
            .complete(*root_claim.request_id(), &mut base.authority, &mut || {
                Ok(base.clock)
            })
            .unwrap();
        let root = store
            .current(root_claim.assignment().sandbox())
            .unwrap()
            .clone();
        drop(store);
        let mut journal = Journal::open(&path, JournalLimits::default()).unwrap().0;
        for (request, transaction) in [(7, 91), (8, 92)] {
            let mut branch = fixture(34);
            branch.authority.current = Some((
                root.assignment(),
                root.node(),
                root.generation(),
                root.digest(),
            ));
            let claim = renewal_claim(request, &root);
            let lease = branch
                .verifier
                .renew(&mut branch.authority, &claim, &branch.clock)
                .unwrap();
            let entry = completed_entry(claim.clone(), lease, 150);
            journal
                .commit(
                    &JournalTransaction::new(
                        [transaction; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            durable_entry_key(claim.request_id()),
                            encode_durable_entry(&entry, branch.verifier.authority()),
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        drop(journal);
        assert!(matches!(
            open_test_store(&path, 34),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));
    }

    #[test]
    fn durable_recovery_rejects_broken_predecessor_rollback_and_tamper() {
        for attack in 0..4 {
            let directory = TestDirectory::new(&format!("durable-chain-attack-{attack}"));
            let path = directory.journal();
            let mut base = fixture(35 + attack);
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut store =
                DurableOwnershipAuthority::from_journal(journal, base.verifier).unwrap();
            let root_claim = acquire_claim(5);
            store.begin(&root_claim).unwrap();
            store
                .complete(*root_claim.request_id(), &mut base.authority, &mut || {
                    Ok(base.clock)
                })
                .unwrap();
            let root = store
                .current(root_claim.assignment().sandbox())
                .unwrap()
                .clone();
            drop(store);

            let mut branch = fixture(35 + attack);
            let claim = renewal_claim(7, &root);
            let raw = branch
                .authority
                .issue(&claim, root.generation() + 2)
                .unwrap();
            let signed = branch
                .verifier
                .verify_response(&claim, raw.clone(), &branch.clock)
                .unwrap();
            let entry = completed_entry(claim.clone(), signed, 150);
            let mut encoded = encode_durable_entry(&entry, &branch.authority.authority);
            match attack {
                0 => flip_embedded_artifact(&mut encoded, claim.canonical_bytes()),
                1 => flip_embedded_artifact(&mut encoded, raw.lease()),
                2 => flip_embedded_artifact(&mut encoded, raw.receipt()),
                _ => flip_embedded_artifact(&mut encoded, raw.receipt_signature()),
            }
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(
                    &JournalTransaction::new(
                        [93; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            durable_entry_key(claim.request_id()),
                            encoded,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);
            assert!(matches!(
                open_test_store(&path, 35 + attack),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ));
        }
    }

    #[test]
    fn durable_recovery_rejects_oversized_record_before_decode() {
        let directory = TestDirectory::new("durable-oversized");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [94; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        durable_entry_key(&[5; 16]),
                        vec![0; MAXIMUM_DURABLE_ENTRY_BYTES + 1],
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(matches!(
            open_test_store(&path, 39),
            Err(DurableOwnershipAuthorityError::CorruptState)
        ));
    }

    #[test]
    fn transaction_domains_prevent_caller_selected_begin_completion_collision() {
        fn exercise(completion_first: bool, key_byte: u8) {
            let directory = TestDirectory::new(if completion_first {
                "transaction-domain-completion-first"
            } else {
                "transaction-domain-begin-first"
            });
            let path = directory.journal();
            let Fixture {
                mut authority,
                verifier,
                clock,
            } = fixture(key_byte);
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
            let claim_a = acquire_claim(5);
            let request_b = completion_transaction_id(*claim_a.request_id());
            let claim_b = OwnershipClaimV1::acquire(
                request_b,
                assignment(20),
                DesiredGeneration::new(6),
                NodeId::from_bytes([44; 16]),
                60,
            )
            .unwrap();

            assert_ne!(
                begin_transaction_id(request_b),
                completion_transaction_id(*claim_a.request_id())
            );
            if !completion_first {
                assert_eq!(
                    store.begin(&claim_b).unwrap(),
                    DurableOwnershipBeginOutcome::Pending
                );
            }
            store.begin(&claim_a).unwrap();
            store
                .complete(*claim_a.request_id(), &mut authority, &mut || Ok(clock))
                .unwrap();
            if completion_first {
                assert_eq!(
                    store.begin(&claim_b).unwrap(),
                    DurableOwnershipBeginOutcome::Pending
                );
            }
        }

        exercise(true, 40);
        exercise(false, 41);
    }

    #[test]
    fn completion_samples_protected_clock_after_issuer_round_trip() {
        struct AdvancingAuthority {
            inner: TestAuthority,
            wall: Rc<Cell<i64>>,
        }

        impl OwnershipAuthority for AdvancingAuthority {
            fn acquire(
                &mut self,
                claim: &OwnershipClaimV1,
            ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
                let response = self.inner.acquire(claim)?;
                self.wall.set(300);
                Ok(response)
            }

            fn renew(
                &mut self,
                claim: &OwnershipClaimV1,
            ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
                self.inner.renew(claim)
            }
        }

        let directory = TestDirectory::new("post-issuer-clock");
        let path = directory.journal();
        let fixture = fixture(42);
        let wall = Rc::new(Cell::new(150));
        let mut authority = AdvancingAuthority {
            inner: fixture.authority,
            wall: Rc::clone(&wall),
        };
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, fixture.verifier).unwrap();
        let claim = acquire_claim(5);
        store.begin(&claim).unwrap();
        let result = store.complete(*claim.request_id(), &mut authority, &mut || {
            Ok(test_clock(wall.get()))
        });

        assert!(matches!(
            result,
            Err(DurableOwnershipAuthorityError::Acquisition(
                OwnershipLeaseAcquisitionError::InvalidIssuerResponse
            ))
        ));
        assert!(store.is_pending(claim.request_id()));
        assert!(store.current(claim.assignment().sandbox()).is_none());
    }

    #[test]
    fn protected_clock_failure_preserves_intent_for_exact_resume() {
        let directory = TestDirectory::new("clock-failure-resume");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            ..
        } = fixture(50);
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let claim = acquire_claim(5);
        store.begin(&claim).unwrap();

        let failed = store.complete(*claim.request_id(), &mut authority, &mut || {
            Err(ProtectedOwnershipClockError)
        });
        assert!(matches!(
            failed,
            Err(DurableOwnershipAuthorityError::ProtectedClockUnavailable(
                ProtectedOwnershipClockError
            ))
        ));
        assert_eq!(authority.requests.len(), 1);
        assert!(store.is_pending(claim.request_id()));
        assert!(store.current(claim.assignment().sandbox()).is_none());
        drop(store);

        let mut store = open_test_store(&path, 50).unwrap();
        assert!(store.is_pending(claim.request_id()));
        assert!(store.current(claim.assignment().sandbox()).is_none());
        let completed = store
            .complete(*claim.request_id(), &mut authority, &mut || {
                Ok(test_clock(160))
            })
            .unwrap();
        assert_eq!(authority.requests.len(), 1);
        assert!(!store.is_pending(claim.request_id()));
        assert_eq!(
            store
                .current(claim.assignment().sandbox())
                .map(RecoveredOwnershipLease::exact_response),
            Some(completed)
        );
    }

    #[test]
    fn fixed_epoch_limits_reserve_every_admitted_intent_completion() {
        let limits = ownership_journal_limits();
        assert_eq!(limits.maximum_transactions, MAXIMUM_DURABLE_ENTRIES * 2);
        assert_eq!(limits.maximum_records_per_transaction, 2);
        assert_eq!(limits.maximum_materialized_records, MAXIMUM_DURABLE_RECORDS);
        assert!(limits.maximum_journal_bytes < JournalLimits::default().maximum_journal_bytes);
        assert!(limits.maximum_journal_bytes < 64 * 1024 * 1024);

        let fixture = fixture(43);
        let claim = acquire_claim(5);
        let response = fixture
            .authority
            .requests
            .get(claim.request_id())
            .map(|(_, response)| response.clone());
        assert!(response.is_none());
        let maximal_entry_bytes = MAXIMUM_DURABLE_ENTRY_BYTES;
        let entry_record_bytes = 7 + durable_entry_key(&[1; 16]).len() + maximal_entry_bytes;
        let current_record_bytes = 7
            + durable_current_key(claim.assignment().sandbox()).len()
            + MAXIMUM_DURABLE_CURRENT_BYTES;
        assert!(entry_record_bytes <= limits.maximum_record_bytes);
        assert!(entry_record_bytes + current_record_bytes <= limits.maximum_transaction_bytes);
        let intent = DurableOwnershipEntry {
            claim: claim.clone(),
            state: DurableEntryState::Intent,
        };
        assert!(
            encode_durable_entry(&intent, fixture.verifier.authority()).len()
                <= MAXIMUM_DURABLE_INTENT_BYTES
        );

        let directory = TestDirectory::new("epoch-capacity");
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, ownership_journal_limits()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, fixture.verifier).unwrap();
        for index in 1..=MAXIMUM_DURABLE_ENTRIES as u16 {
            let mut request = [0; 16];
            request[..2].copy_from_slice(&index.to_be_bytes());
            let claim = OwnershipClaimV1::acquire(
                request,
                indexed_assignment(index),
                DesiredGeneration::new(6),
                NodeId::from_bytes([44; 16]),
                60,
            )
            .unwrap();
            assert_eq!(
                store.begin(&claim).unwrap(),
                DurableOwnershipBeginOutcome::Pending
            );
        }
        let rejected = OwnershipClaimV1::acquire(
            [77; 16],
            assignment(77),
            DesiredGeneration::new(6),
            NodeId::from_bytes([44; 16]),
            60,
        )
        .unwrap();
        assert!(matches!(
            store.begin(&rejected),
            Err(DurableOwnershipAuthorityError::ResourceExhausted)
        ));
        drop(store);
        assert!(open_test_store(&path, 43).is_ok());
    }

    #[test]
    fn recovery_rejects_all_foreign_owned_namespaces() {
        for case in 0..4_u8 {
            let directory = TestDirectory::new(&format!("foreign-namespace-{case}"));
            let path = directory.journal();
            let record = match case {
                0 => JournalRecord::put(
                    RecordNamespace::Operation,
                    b"foreign-operation".to_vec(),
                    vec![1],
                ),
                1 => JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"foreign-desired".to_vec(),
                    vec![1],
                ),
                2 => {
                    JournalRecord::put(RecordNamespace::Effect, b"foreign-effect".to_vec(), vec![1])
                }
                _ => JournalRecord::idempotency(
                    &IdempotencyKey::new(b"foreign-idempotency".to_vec()).unwrap(),
                    [1; 32],
                    aos_sandbox_core::OperationId::from_bytes([2; 16]),
                ),
            };
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(&JournalTransaction::new([case + 1; 16], vec![record]).unwrap())
                .unwrap();
            drop(journal);

            assert!(matches!(
                open_test_store(&path, 44),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ));
        }
    }

    #[test]
    fn v1_durable_namespaces_require_migration_before_open_or_write() {
        for (case, namespace, prefix, value) in [
            (
                1_u8,
                RecordNamespace::Operation,
                LEGACY_DURABLE_ENTRY_PREFIX,
                vec![1],
            ),
            (
                2_u8,
                RecordNamespace::DesiredState,
                LEGACY_DURABLE_CURRENT_PREFIX,
                vec![2],
            ),
            (
                3_u8,
                RecordNamespace::Operation,
                DURABLE_ENTRY_PREFIX,
                LEGACY_DURABLE_ENTRY_MAGIC.to_vec(),
            ),
            (
                4_u8,
                RecordNamespace::DesiredState,
                DURABLE_CURRENT_PREFIX,
                LEGACY_DURABLE_CURRENT_MAGIC.to_vec(),
            ),
        ] {
            let directory = TestDirectory::new(&format!("legacy-v1-{case}"));
            let path = directory.journal();
            let mut key = prefix.to_vec();
            key.extend_from_slice(&[case; 16]);
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            journal
                .commit(
                    &JournalTransaction::new(
                        [case; 16],
                        vec![JournalRecord::put(namespace, key, value)],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);

            assert!(matches!(
                open_test_store(&path, 44),
                Err(DurableOwnershipAuthorityError::MigrationRequired)
            ));
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            assert!(matches!(
                DurableOwnershipAuthority::from_journal(journal, fixture(44).verifier),
                Err(DurableOwnershipAuthorityError::MigrationRequired)
            ));
        }
    }

    #[test]
    fn malformed_signature_response_is_rejected_before_verification() {
        assert_eq!(
            UnverifiedOwnershipLeaseResponse::from_transport(
                vec![1],
                vec![0; MAXIMUM_SIGNATURE_BYTES + 1],
                vec![1],
                vec![1],
            ),
            Err(OwnershipLeaseAcquisitionError::InvalidIssuerResponse)
        );
    }

    #[test]
    fn exact_query_and_protocol_service_never_issue_outside_pending_completion() {
        let directory = TestDirectory::new("protocol-service");
        let path = directory.journal();
        let Fixture {
            mut authority,
            verifier,
            clock,
        } = fixture(61);
        let authority_calls = authority.calls.clone();
        let authority_reference = verifier.authority().clone();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut store = DurableOwnershipAuthority::from_journal(journal, verifier).unwrap();
        let claim = acquire_claim(5);
        let reference = OwnershipTransactionReferenceV1::from_claim(&claim);
        let absent =
            OwnershipTransactionReferenceV1::new([99; 16], ObjectDigest::from_bytes([98; 32]))
                .unwrap();
        assert_eq!(
            store.query(absent).unwrap(),
            DurableOwnershipQueryOutcome::Absent
        );

        let methods = vec![
            OwnershipMethodV1::Begin,
            OwnershipMethodV1::CompleteOrResume,
            OwnershipMethodV1::Query,
        ];
        let hello = OwnershipClientHelloV1::new(
            [71; 32],
            ProtocolVersion::new(1, 0),
            authority_reference.clone(),
            methods.clone(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        let session =
            NegotiatedOwnershipSessionV1::negotiate(&hello, [72; 32], authority_reference, methods)
                .unwrap();
        let clock_calls = Rc::new(Cell::new(0));
        let counted_clock_calls = clock_calls.clone();
        let mut protected_clock = move || {
            counted_clock_calls.set(counted_clock_calls.get() + 1);
            Ok(clock)
        };
        let bounded_hello = OwnershipClientHelloV1::new(
            [73; 32],
            ProtocolVersion::new(1, 0),
            session.authority().clone(),
            session.methods().to_vec(),
            aos_sandbox_ownership_protocol::protocol::MINIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        let bounded_session = NegotiatedOwnershipSessionV1::negotiate(
            &bounded_hello,
            [74; 32],
            session.authority().clone(),
            session.methods().to_vec(),
        )
        .unwrap();
        assert!(
            crate::DurableOwnershipProtocolService::new(
                bounded_session,
                &mut store,
                &mut authority,
                &mut protected_clock,
            )
            .is_ok()
        );
        assert_eq!(authority_calls.get(), 0);
        assert_eq!(clock_calls.get(), 0);
        let wrong_authority = KeyReference::new(
            StableKeyId::new("wrong-service-authority".to_owned()).unwrap(),
            1,
            ObjectDigest::from_bytes([75; 32]),
            KeyUsage::OwnershipLease,
        );
        let wrong_hello = OwnershipClientHelloV1::new(
            [76; 32],
            ProtocolVersion::new(1, 0),
            wrong_authority.clone(),
            session.methods().to_vec(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        let wrong_session = NegotiatedOwnershipSessionV1::negotiate(
            &wrong_hello,
            [77; 32],
            wrong_authority,
            session.methods().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            crate::DurableOwnershipProtocolService::new(
                wrong_session,
                &mut store,
                &mut authority,
                &mut protected_clock,
            ),
            Err(crate::OwnershipProtocolServiceError::InvalidSession)
        ));
        assert_eq!(authority_calls.get(), 0);
        assert_eq!(clock_calls.get(), 0);
        let foreign_hello = OwnershipClientHelloV1::new(
            [78; 32],
            ProtocolVersion::new(1, 0),
            session.authority().clone(),
            session.methods().to_vec(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        let foreign_session = NegotiatedOwnershipSessionV1::negotiate(
            &foreign_hello,
            [79; 32],
            session.authority().clone(),
            session.methods().to_vec(),
        )
        .unwrap();
        {
            let mut service = crate::DurableOwnershipProtocolService::new(
                session.clone(),
                &mut store,
                &mut authority,
                &mut protected_clock,
            )
            .unwrap();
            let query = session
                .request(OwnershipRequestBodyV1::Query(reference))
                .unwrap();
            let foreign_query = foreign_session
                .request(OwnershipRequestBodyV1::Query(reference))
                .unwrap();
            assert!(matches!(
                service.handle(&foreign_query),
                Err(crate::OwnershipProtocolServiceError::Protocol(
                    OwnershipProtocolValidationError::SessionBindingMismatch
                ))
            ));
            assert_eq!(authority_calls.get(), 0);
            assert_eq!(clock_calls.get(), 0);
            assert!(matches!(
                service.handle(&query).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent)
            ));
            assert_eq!(authority_calls.get(), 0);
            assert_eq!(clock_calls.get(), 0);

            let begin = session
                .request(OwnershipRequestBodyV1::Begin(Box::new(claim.clone())))
                .unwrap();
            assert!(matches!(
                service.handle(&begin).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending)
            ));
            assert_eq!(authority_calls.get(), 0);
            assert_eq!(clock_calls.get(), 0);

            assert!(matches!(
                service.handle(&query).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending)
            ));
            assert_eq!(authority_calls.get(), 0);
            assert_eq!(clock_calls.get(), 0);

            let complete = session
                .request(OwnershipRequestBodyV1::CompleteOrResume(reference))
                .unwrap();
            assert!(matches!(
                service.handle(&complete).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(_))
            ));
            assert_eq!(authority_calls.get(), 1);
            assert_eq!(clock_calls.get(), 1);

            assert!(matches!(
                service.handle(&query).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(_))
            ));
            assert_eq!(authority_calls.get(), 1);
            assert_eq!(clock_calls.get(), 1);

            assert!(matches!(
                service.handle(&begin).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(_))
            ));
            assert_eq!(authority_calls.get(), 1);
            assert_eq!(clock_calls.get(), 1);
        }

        let rebound = OwnershipTransactionReferenceV1::new(
            *claim.request_id(),
            ObjectDigest::from_bytes([97; 32]),
        )
        .unwrap();
        assert!(matches!(
            store.query(rebound),
            Err(DurableOwnershipAuthorityError::IdempotencyConflict)
        ));
        drop(store);

        let mut reopened = open_test_store(&path, 61).unwrap();
        assert!(matches!(
            reopened.query(reference).unwrap(),
            DurableOwnershipQueryOutcome::Completed(_)
        ));
        let mut client = crate::InProcessOwnershipSessionClient::new(
            session.clone(),
            &mut reopened,
            &mut authority,
            &mut protected_clock,
        )
        .unwrap();
        let query = session
            .request(OwnershipRequestBodyV1::Query(reference))
            .unwrap();
        crate::OwnershipAuthoritySessionClient::exchange(&mut client, &query).unwrap();
        assert_eq!(authority_calls.get(), 1);
        assert_eq!(clock_calls.get(), 1);
    }

    #[test]
    fn node_controller_composes_with_in_process_service_across_both_journals() {
        #[derive(Default)]
        struct CompositionExecutor;

        impl SingleNodeEffectExecutor for CompositionExecutor {
            fn observe(
                &mut self,
                _operation_id: aos_sandbox_core::OperationId,
                _step: u32,
                _plan: &EffectPlan,
            ) -> Result<EffectObservation, EffectFailure> {
                Ok(EffectObservation::Absent)
            }

            fn apply(
                &mut self,
                _operation_id: aos_sandbox_core::OperationId,
                _step: u32,
                _plan: &EffectPlan,
            ) -> Result<EffectReceipt, EffectFailure> {
                Ok(EffectReceipt::new(vec![1]).unwrap())
            }
        }

        struct CompositionCompiler;

        impl ActivatedOperationCompiler for CompositionCompiler {
            fn compile(
                &mut self,
                _canonical_request: &[u8],
                _request_digest: [u8; 32],
            ) -> Result<OperationPlan, OperationCompilationError> {
                Err(OperationCompilationError::Rejected)
            }
        }

        let directory = TestDirectory::new("controller-service-composition");
        let (draft, _) = activation_fixture(1);
        let claim = activation_claim(&draft, 1);
        let transaction = OwnershipTransactionReferenceV1::from_claim(&claim);
        let signing_key = SigningKey::from_bytes(&[41; 32]);
        let authority_reference = draft.ownership_authority().clone();
        assert_eq!(
            authority_reference.public_key_sha256(),
            ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into())
        );
        let make_verifier = || {
            let scope = TrustScopeId::from_bytes([61; 16]);
            let policy = TrustPolicy::new(
                scope,
                SignaturePurpose::OwnershipLease,
                vec![authority_reference.clone()],
                Vec::new(),
            )
            .unwrap();
            let policy_bytes = encode_trust_policy(&policy);
            let policy_descriptor = descriptor_for_bytes(
                MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
                &policy_bytes,
            );
            let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                policy_bytes,
                policy_descriptor.clone(),
                scope,
                authority_reference.clone(),
                signing_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            (
                OwnershipAuthorityVerifier::new(anchor, authority_reference.clone()),
                scope,
                policy_descriptor,
            )
        };
        let (authority_verifier, authority_scope, authority_policy) = make_verifier();
        let (controller_verifier, _, _) = make_verifier();
        let (reopen_verifier, _, _) = make_verifier();
        let issuer_calls = Rc::new(Cell::new(0));
        let mut issuer = TestAuthority {
            signing_key,
            authority: authority_reference.clone(),
            scope: authority_scope,
            policy_descriptor: authority_policy,
            requests: BTreeMap::new(),
            current: None,
            now_seconds: 150,
            duration_seconds: 40,
            generation_increment: 1,
            override_assignment: None,
            override_node: None,
            calls: issuer_calls.clone(),
        };

        let operation_id = aos_sandbox_core::OperationId::from_bytes([0x81; 16]);
        let plan = OperationPlan::ownership_gated(
            operation_id,
            IdempotencyKey::new(b"controller-service-composition".to_vec()).unwrap(),
            [0x82; 32],
            b"sandbox".to_vec(),
            b"ownership-pending".to_vec(),
            vec![EffectPlan::new(EffectDomain::Guardian, b"arm".to_vec()).unwrap()],
            claim,
            draft,
        )
        .unwrap();
        let (controller_journal, _) =
            Journal::open(directory.controller_journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(controller_journal, CompositionExecutor);
        reconciler.accept(&plan).unwrap();
        let mut controller = NodeController::new(
            crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x83; 32])).unwrap(),
            NodeControllerLimits::default(),
            CompositionCompiler,
            reconciler,
        );
        let (authority_journal, _) =
            Journal::open(directory.journal(), ownership_journal_limits()).unwrap();
        let mut authority_store =
            DurableOwnershipAuthority::from_journal(authority_journal, authority_verifier).unwrap();
        let hello = OwnershipClientHelloV1::new(
            [0x84; 32],
            ProtocolVersion::new(1, 0),
            authority_reference.clone(),
            vec![
                OwnershipMethodV1::Begin,
                OwnershipMethodV1::CompleteOrResume,
                OwnershipMethodV1::Query,
            ],
            aos_sandbox_ownership_protocol::protocol::MINIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        let session = NegotiatedOwnershipSessionV1::negotiate(
            &hello,
            [0x85; 32],
            authority_reference,
            vec![
                OwnershipMethodV1::Begin,
                OwnershipMethodV1::CompleteOrResume,
                OwnershipMethodV1::Query,
            ],
        )
        .unwrap();
        let protected_clock_calls = Rc::new(Cell::new(0));
        let counted_clock_calls = protected_clock_calls.clone();
        let mut protected_clock = move || {
            counted_clock_calls.set(counted_clock_calls.get() + 1);
            Ok(test_clock(150))
        };
        {
            let mut client = crate::InProcessOwnershipSessionClient::new(
                session.clone(),
                &mut authority_store,
                &mut issuer,
                &mut protected_clock,
            )
            .unwrap();
            assert_eq!(
                controller
                    .resume_ownership(operation_id, &mut client, &controller_verifier, &mut || Ok(
                        test_clock(150)
                    ),)
                    .unwrap(),
                OwnershipResumeOutcomeV1::Activated
            );
        }
        assert_eq!(issuer_calls.get(), 1);
        assert_eq!(protected_clock_calls.get(), 1);

        drop(authority_store);
        drop(controller);
        let (authority_journal, _) =
            Journal::open(directory.journal(), ownership_journal_limits()).unwrap();
        let mut authority_store =
            DurableOwnershipAuthority::from_journal(authority_journal, reopen_verifier).unwrap();
        assert!(matches!(
            authority_store.query(transaction).unwrap(),
            DurableOwnershipQueryOutcome::Completed(_)
        ));
        let (controller_journal, _) =
            Journal::open(directory.controller_journal(), JournalLimits::default()).unwrap();
        let mut controller = NodeController::new(
            crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x83; 32])).unwrap(),
            NodeControllerLimits::default(),
            CompositionCompiler,
            Reconciler::new(controller_journal, CompositionExecutor),
        );
        let mut replay_client = crate::InProcessOwnershipSessionClient::new(
            session,
            &mut authority_store,
            &mut issuer,
            &mut protected_clock,
        )
        .unwrap();
        assert_eq!(
            controller
                .resume_ownership(
                    operation_id,
                    &mut replay_client,
                    &controller_verifier,
                    &mut || panic!("activated replay sampled the controller clock"),
                )
                .unwrap(),
            OwnershipResumeOutcomeV1::Replay
        );
        assert_eq!(issuer_calls.get(), 1);
        assert_eq!(protected_clock_calls.get(), 1);
    }
}
