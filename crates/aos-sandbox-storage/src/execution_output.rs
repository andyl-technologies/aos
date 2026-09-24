//! Protected logical custody of retained execution-output reservations.
//!
//! This is a closed Storage-side producer. It binds an exact accepted-Create
//! output claim to a bounded, replayed ledger, including zero-byte streams.
//! No capture file, ZFS dataset, or Host effect is authorized by this ledger.
//! Physical capture requires a separate verified ZFS quota/reservation owner
//! and a cross-owner barrier before this producer can be used for admission.
//!
//! ```text
//! configuration = AOSEOC01 || capacity:u64be || key-id[16] || hmac[32]
//! reservation   = AOSEOR03 || execution[16] || create[16]
//!                 || assignment[32] || v2-claim-digest[32] || bytes:u64be
//!                 || maximum-stdout:u64be || maximum-stderr:u64be
//!                 || state:u8 || delete-operation[16] || hmac[32]
//! physical      = AOSPOB02 || dataset-binding[32] || v2-claim-digest[32]
//!                 || bytes:u64be || creation-generation:u64be || guid:u64be
//!                 || name-length:u16be || dataset-name[bounded] || hmac[32]
//! deletion      = AOSPOD02 || dataset-binding[32] || catalog-generation:u64be
//!                 || catalog-digest[32] || execution-delete-operation[16]
//!                 || storage-destroy-operation[16] || hmac[32]
//! deletion-grant = AOSEOD01 || execution[16] || create[16]
//!                 || v2-claim-digest[32] || delete-operation[16] || hmac[32]
//! observation   = AOSPOV01 || AOSEOR03/AOSCOA01/catalog/ZFS digest tuple
//!                 || measured available/headroom || observation boot/time
//!                 || hmac[32]
//! ```

use std::path::Path;

use aos_sandbox::runtime_execution::ProtectedAcceptedExecutionOutputV2;
use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::{ObjectDigest, OperationId};
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::catalog_transition::VerifiedPhysicalCatalogSnapshotV1;
use crate::catalog_transition::execution_capture::{
    MAX_CAPTURE_DATASET_NAME_BYTES, VerifiedCaptureDatasetV1, VerifiedCaptureDeletionV1,
    verify_deleted_persisted,
};

mod capture_attempt;
#[allow(
    dead_code,
    reason = "method-41 candidate awaits pinned Storage BSA verification and signed response"
)]
mod capture_candidate;
mod physical_observation;

type HmacSha256 = Hmac<Sha256>;

const NAMESPACE: RecordNamespace = RecordNamespace::StorageExecutionOutput;
const CONFIG_KEY: &[u8] = b"configuration";
const CONFIG_MAGIC: &[u8; 8] = b"AOSEOC01";
const RECORD_MAGIC: &[u8; 8] = b"AOSEOR03";
const GRANT_MAGIC: &[u8; 8] = b"AOSEOD01";
const MAC_DOMAIN: &[u8] = b"aos.sandbox.storage.execution-output.v1\0";
const CONFIG_BYTES: usize = 64;
const RECORD_BYTES: usize = 177;
const GRANT_BYTES: usize = 120;
const STATE_RETAINED: u8 = 1;
const STATE_DELETED: u8 = 2;
const PHYSICAL_MAGIC: &[u8; 8] = b"AOSPOB02";
const PHYSICAL_MIN_BYTES: usize = 131;
const DELETION_MAGIC: &[u8; 8] = b"AOSPOD02";
const DELETION_BYTES: usize = 144;

/// Rejects a corrupt ledger, exhausted budget, conflicting replay, or unsafe deletion.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionOutputLedgerErrorV1 {
    /// The protected journal failed to open, replay, or commit.
    #[error(transparent)]
    Journal(#[from] aos_sandbox::JournalError),
    /// The configured capacity or authentication key is invalid.
    #[error("invalid execution-output ledger configuration")]
    InvalidConfiguration,
    /// A retained record failed schema, location, or MAC validation.
    #[error("execution-output ledger is corrupt")]
    Corrupt,
    /// The exact accepted output claim conflicts with retained history.
    #[error("execution-output reservation conflicts with retained history")]
    Conflict,
    /// The supplied admission witness differs from the exact accepted claim.
    #[error("execution-output admission currentness differs from the accepted claim")]
    NotCurrent,
    /// The bounded logical output budget is exhausted.
    #[error("execution-output logical capacity is exhausted")]
    Capacity,
    /// The deletion grant is absent, malformed, or bound to another reservation.
    #[error("execution-output deletion is unauthorized")]
    UnauthorizedDeletion,
    /// The exact ZFS capture dataset has not been verified and durably bound.
    #[error("execution-output physical capture backing is absent or mismatched")]
    MissingPhysicalBacking,
}

/// Authenticates Storage-owned records and deletion grants under a protected key.
pub struct ExecutionOutputLedgerKeyV1 {
    key_id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
}

impl ExecutionOutputLedgerKeyV1 {
    /// Constructs a nonzero protected key and stable key identity.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero key identity or secret.
    pub fn new(key_id: [u8; 16], secret: [u8; 32]) -> Result<Self, ExecutionOutputLedgerErrorV1> {
        if key_id == [0; 16] || secret == [0; 32] {
            return Err(ExecutionOutputLedgerErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            key_id,
            secret: Zeroizing::new(secret),
        })
    }

    fn mac(&self, location: &[u8], body: &[u8]) -> Result<[u8; 32], ExecutionOutputLedgerErrorV1> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_ref())
            .map_err(|_| ExecutionOutputLedgerErrorV1::InvalidConfiguration)?;
        mac.update(MAC_DOMAIN);
        mac.update(&(location.len() as u64).to_be_bytes());
        mac.update(location);
        mac.update(body);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_mac(
        &self,
        location: &[u8],
        body: &[u8],
        tag: &[u8],
    ) -> Result<bool, ExecutionOutputLedgerErrorV1> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_ref())
            .map_err(|_| ExecutionOutputLedgerErrorV1::InvalidConfiguration)?;
        mac.update(MAC_DOMAIN);
        mac.update(&(location.len() as u64).to_be_bytes());
        mac.update(location);
        mac.update(body);
        Ok(mac.verify_slice(tag).is_ok())
    }
}

/// Carries an externally issued, MAC-authenticated exact deletion request.
///
/// The issuing service must first authenticate the public Delete operation and
/// retain its own controller authorization. Possession of these bytes alone
/// cannot produce a grant without the protected Storage key.
pub struct ExecutionOutputDeletionGrantV1([u8; GRANT_BYTES]);

impl ExecutionOutputDeletionGrantV1 {
    /// Copies one exact bounded grant received over an authenticated channel.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid length or version marker. The ledger
    /// verifies the MAC and reservation binding before settling deletion.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ExecutionOutputLedgerErrorV1> {
        let bytes: [u8; GRANT_BYTES] = bytes
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        if &bytes[..8] != GRANT_MAGIC {
            return Err(ExecutionOutputLedgerErrorV1::UnauthorizedDeletion);
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedOutputRecord {
    execution: [u8; 16],
    create: [u8; 16],
    assignment: [u8; 32],
    claim_digest: [u8; 32],
    bytes: u64,
    maximum_stdout_bytes: u64,
    maximum_stderr_bytes: u64,
    state: u8,
    delete_operation: [u8; 16],
}

/// Carries a cold-replayed AOSEOR03 record, not caller-supplied claim fields.
///
/// This is a Storage-local readback witness. It is not a Controller grant or a
/// permission to create a dataset, mount it, or dispatch Host execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedRetainedCaptureV1 {
    execution: [u8; 16],
    create: [u8; 16],
    claim_digest: ObjectDigest,
    record_digest: ObjectDigest,
    admitted_bytes: u64,
    maximum_stdout_bytes: u64,
    maximum_stderr_bytes: u64,
}

impl ProtectedRetainedCaptureV1 {
    pub(crate) const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    pub(crate) const fn admitted_bytes(&self) -> u64 {
        self.admitted_bytes
    }

    pub(crate) const fn maximum_stdout_bytes(&self) -> u64 {
        self.maximum_stdout_bytes
    }

    pub(crate) const fn maximum_stderr_bytes(&self) -> u64 {
        self.maximum_stderr_bytes
    }

    pub(crate) fn matches_capture_requirement(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        claim_digest: ObjectDigest,
        admitted_bytes: u64,
    ) -> bool {
        self.execution == execution
            && self.create == create
            && self.claim_digest == claim_digest
            && self.admitted_bytes == admitted_bytes
    }
}

struct PhysicalBindingRecord {
    binding: ObjectDigest,
    claim_digest: [u8; 32],
    bytes: u64,
    creation_generation: u64,
    guid: u64,
    dataset_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhysicalDeletionRecord {
    binding: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    execution_delete_operation: [u8; 16],
    storage_destroy_operation: [u8; 16],
}

/// Owns one exclusively locked, bounded Storage output-reservation journal.
pub struct ExecutionOutputLedgerV1 {
    journal: Journal,
    key: ExecutionOutputLedgerKeyV1,
    capacity_bytes: u64,
    retained_bytes: u64,
}

impl ExecutionOutputLedgerV1 {
    /// Opens and replays the root-owned protected ledger.
    ///
    /// The directory must already exist with protected journal ownership and
    /// mode. A changed capacity or key identity fails closed on replay.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, invalid durable bytes, a changed
    /// configuration, or a retained sum above the capacity.
    pub fn open_root_owned(
        directory: impl AsRef<Path>,
        name: &str,
        capacity_bytes: u64,
        key: ExecutionOutputLedgerKeyV1,
    ) -> Result<Self, ExecutionOutputLedgerErrorV1> {
        let (journal, _) = Journal::open_protected_at(directory, name, JournalLimits::default())?;
        Self::from_journal(journal, capacity_bytes, key)
    }

    fn from_journal(
        mut journal: Journal,
        capacity_bytes: u64,
        key: ExecutionOutputLedgerKeyV1,
    ) -> Result<Self, ExecutionOutputLedgerErrorV1> {
        let expected_config = configuration_bytes(capacity_bytes, &key)?;
        match journal.get(NAMESPACE, CONFIG_KEY) {
            Some(existing) if existing == expected_config => {}
            Some(_) => return Err(ExecutionOutputLedgerErrorV1::Corrupt),
            None => {
                if journal.all_records().next().is_some() {
                    return Err(ExecutionOutputLedgerErrorV1::Corrupt);
                }
                journal.commit(&JournalTransaction::new(
                    *b"AOSOUTPUTCONFIG1",
                    vec![JournalRecord::put(
                        NAMESPACE,
                        CONFIG_KEY.to_vec(),
                        expected_config.to_vec(),
                    )],
                )?)?;
            }
        }

        let mut retained_bytes = 0_u64;
        for (namespace, location, value) in journal.all_records() {
            if namespace != NAMESPACE {
                return Err(ExecutionOutputLedgerErrorV1::Corrupt);
            }
            if location == CONFIG_KEY {
                continue;
            }
            match location.first() {
                Some(b'r') => {
                    let record = decode_record(location, value, &key)?;
                    if record.state == STATE_RETAINED {
                        retained_bytes = retained_bytes
                            .checked_add(record.bytes)
                            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
                    } else if record.bytes > 0
                        && (journal
                            .get(NAMESPACE, &physical_key(record.execution))
                            .is_none()
                            || journal
                                .get(NAMESPACE, &deletion_key(record.execution))
                                .is_none())
                    {
                        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
                    }
                }
                Some(b'p') => {
                    let physical = decode_physical(location, value, &key)?;
                    let logical_key = reservation_key(
                        location[1..]
                            .try_into()
                            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
                    );
                    let logical = journal
                        .get(NAMESPACE, &logical_key)
                        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
                    let logical = decode_record(&logical_key, logical, &key)?;
                    if physical.claim_digest != logical.claim_digest
                        || physical.bytes != logical.bytes
                    {
                        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
                    }
                    if logical.state == STATE_DELETED {
                        let deletion_key = deletion_key(logical.execution);
                        let deletion = journal
                            .get(NAMESPACE, &deletion_key)
                            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
                        let deletion = decode_deletion(&deletion_key, deletion, &key)?;
                        if deletion.binding != physical.binding
                            || deletion.execution_delete_operation != logical.delete_operation
                        {
                            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
                        }
                    }
                }
                Some(b'd') => {
                    let deletion = decode_deletion(location, value, &key)?;
                    let execution: [u8; 16] = location[1..]
                        .try_into()
                        .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?;
                    let physical_key = physical_key(execution);
                    let physical = journal
                        .get(NAMESPACE, &physical_key)
                        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
                    if decode_physical(&physical_key, physical, &key)?.binding != deletion.binding {
                        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
                    }
                    let logical_key = reservation_key(execution);
                    let logical = journal
                        .get(NAMESPACE, &logical_key)
                        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
                    let logical = decode_record(&logical_key, logical, &key)?;
                    if logical.state != STATE_DELETED
                        || logical.delete_operation != deletion.execution_delete_operation
                    {
                        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
                    }
                }
                Some(b'a') => {
                    capture_attempt::verify_replayed_capture_attempt(
                        &journal, location, value, &key,
                    )?;
                }
                Some(b'o') => {
                    physical_observation::verify_replayed_capture_observation(
                        &journal, location, value, &key,
                    )?;
                }
                _ => return Err(ExecutionOutputLedgerErrorV1::Corrupt),
            }
        }
        if retained_bytes > capacity_bytes {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        Ok(Self {
            journal,
            key,
            capacity_bytes,
            retained_bytes,
        })
    }

    /// Returns the currently retained logical byte total.
    #[must_use]
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Replays one exact retained capture record under the Storage MAC key.
    ///
    /// The requested digest must be the AOSEOR03 record digest returned at
    /// logical reservation. A zero-byte Stream or PTY record cannot be used as
    /// physical capture authority.
    pub(crate) fn read_protected_retained_capture(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        record_digest: ObjectDigest,
    ) -> Result<ProtectedRetainedCaptureV1, ExecutionOutputLedgerErrorV1> {
        let location = reservation_key(execution);
        let bytes = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let record = decode_record(&location, bytes, &self.key)?;
        let observed_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        if record.state != STATE_RETAINED
            || record.create != create
            || record.bytes == 0
            || observed_digest != record_digest
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        Ok(ProtectedRetainedCaptureV1 {
            execution: record.execution,
            create: record.create,
            claim_digest: ObjectDigest::from_bytes(record.claim_digest),
            record_digest: observed_digest,
            admitted_bytes: record.bytes,
            maximum_stdout_bytes: record.maximum_stdout_bytes,
            maximum_stderr_bytes: record.maximum_stderr_bytes,
        })
    }

    /// Resolves the current retained row from exact accepted-Create identities.
    ///
    /// This read-only lookup is for an authenticated candidate query whose
    /// caller does not yet know Storage's AOSEOR03 digest. The resulting row
    /// and journal sequence must be checked again before reserve effects.
    fn read_current_capture_for_candidate(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        claim_digest: ObjectDigest,
        assignment_digest: ObjectDigest,
    ) -> Result<(ProtectedRetainedCaptureV1, u64), ExecutionOutputLedgerErrorV1> {
        self.journal.ensure_healthy()?;
        let location = reservation_key(execution);
        let bytes = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let record = decode_record(&location, bytes, &self.key)?;
        if record.state != STATE_RETAINED
            || record.create != create
            || record.claim_digest != *claim_digest.as_bytes()
            || record.assignment != *assignment_digest.as_bytes()
            || record.bytes == 0
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        let record_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        let protected = self.read_protected_retained_capture(execution, create, record_digest)?;
        self.journal.ensure_healthy()?;
        Ok((protected, self.journal.snapshot_sequence()))
    }

    /// Rechecks the protected output owner head after candidate readback.
    pub(crate) fn candidate_head_sequence(&self) -> Result<u64, ExecutionOutputLedgerErrorV1> {
        self.journal.ensure_healthy()?;
        Ok(self.journal.snapshot_sequence())
    }

    /// Reserves the exact v2 accepted-Create output claim read under its owner.
    ///
    /// Only the runtime execution owner's protected accepted-Create replay can
    /// mint this witness. Its output digest and assignment must match the
    /// retained claim. This remains logical Storage custody, not permission to
    /// capture or dispatch Host Apply without verified physical backing and a
    /// cross-owner currentness barrier.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched witness, capacity exhaustion,
    /// conflicting execution reuse, or an ambiguous journal commit. Reopen
    /// after ambiguity before retry.
    pub fn reserve_protected_accepted_output_v2(
        &mut self,
        accepted: &ProtectedAcceptedExecutionOutputV2,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        let claim = accepted.reservation();
        let currentness = accepted.currentness();
        if currentness.output_reservation() != claim.record_digest()
            || currentness.runtime().currentness().assignment_digest()
                != claim.output().assignment().digest()
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let record = RetainedOutputRecord {
            execution: *claim.execution().as_bytes(),
            create: *claim.create_operation().as_bytes(),
            assignment: *claim.output().assignment().digest().as_bytes(),
            claim_digest: *claim.record_digest().as_bytes(),
            bytes: claim.output().admitted_bytes(),
            maximum_stdout_bytes: accepted.maximum_stdout_bytes(),
            maximum_stderr_bytes: accepted.maximum_stderr_bytes(),
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        };
        self.reserve_record(record)
    }

    fn reserve_record(
        &mut self,
        record: RetainedOutputRecord,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
        if record
            .maximum_stdout_bytes
            .checked_add(record.maximum_stderr_bytes)
            != Some(record.bytes)
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let location = reservation_key(record.execution);
        let bytes = encode_record(&record, &location, &self.key)?;
        if let Some(existing) = self.journal.get(NAMESPACE, &location) {
            if existing == bytes {
                return Ok(ObjectDigest::from_bytes(Sha256::digest(bytes).into()));
            }
            return Err(ExecutionOutputLedgerErrorV1::Conflict);
        }
        let next = self
            .retained_bytes
            .checked_add(record.bytes)
            .filter(|total| *total <= self.capacity_bytes)
            .ok_or(ExecutionOutputLedgerErrorV1::Capacity)?;
        let transaction_id = transaction_id(b"reserve", &location, &record.claim_digest);
        self.journal.commit(&JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, location, bytes.to_vec())],
        )?)?;
        self.retained_bytes = next;
        Ok(ObjectDigest::from_bytes(Sha256::digest(bytes).into()))
    }

    /// Retains the exact authenticated dedicated ZFS dataset observation.
    ///
    /// The dataset witness must join the current accepted claim under an
    /// external cross-owner barrier before capture effects may be enabled.
    /// This record alone is not that barrier or a Host grant.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or mismatched logical reservation,
    /// conflicting physical reuse, or an ambiguous journal commit.
    pub(crate) fn bind_verified_capture_dataset(
        &mut self,
        verified: &VerifiedCaptureDatasetV1,
        execution: [u8; 16],
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let logical_key = reservation_key(execution);
        let logical = self
            .journal
            .get(NAMESPACE, &logical_key)
            .ok_or(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)?;
        let logical = decode_record(&logical_key, logical, &self.key)?;
        if logical.state != STATE_RETAINED
            || !verified.matches_logical(
                logical.execution,
                logical.create,
                logical.claim_digest,
                logical.bytes,
            )
        {
            return Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking);
        }
        let physical_key = physical_key(execution);
        let physical = PhysicalBindingRecord {
            binding: verified.binding(),
            claim_digest: logical.claim_digest,
            bytes: logical.bytes,
            creation_generation: verified.catalog_generation(),
            guid: verified.guid(),
            dataset_name: verified.dataset_name().to_owned(),
        };
        let bytes = encode_physical(&physical_key, &physical, &self.key)?;
        if let Some(existing) = self.journal.get(NAMESPACE, &physical_key) {
            return if existing == bytes {
                Ok(())
            } else {
                Err(ExecutionOutputLedgerErrorV1::Conflict)
            };
        }
        self.journal.commit(&JournalTransaction::new(
            transaction_id(b"physical", &physical_key, verified.binding().as_bytes()),
            vec![JournalRecord::put(NAMESPACE, physical_key, bytes)],
        )?)?;
        Ok(())
    }

    /// Releases logical custody only after exact authenticated ZFS deletion.
    ///
    /// The physical binding remains in the journal beside the logical
    /// tombstone. This method still requires a cross-owner barrier before a
    /// production service can treat the observations as one current cut.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent or substituted physical binding, a
    /// missing catalog tombstone, or any authenticated deletion failure.
    pub(crate) fn settle_verified_capture_deletion(
        &mut self,
        grant: &ExecutionOutputDeletionGrantV1,
        catalog: &VerifiedPhysicalCatalogSnapshotV1,
        storage_delete_operation: OperationId,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let execution: [u8; 16] = grant.0[8..24]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        let key = physical_key(execution);
        let bytes = self
            .journal
            .get(NAMESPACE, &key)
            .ok_or(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)?;
        let physical = decode_physical(&key, bytes, &self.key)?;
        let deletion = verify_deleted_persisted(
            physical.binding,
            &physical.dataset_name,
            physical.guid,
            physical.creation_generation,
            catalog,
            storage_delete_operation,
        )
        .map_err(|_| ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)?;
        self.settle_authenticated_deletion(grant, Some(&deletion))
    }

    /// Settles a stream or PTY claim that retained no physical capture bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a nonzero reservation, a physical binding, or an
    /// invalid authenticated deletion grant.
    pub(crate) fn settle_zero_output_deletion(
        &mut self,
        grant: &ExecutionOutputDeletionGrantV1,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let execution: [u8; 16] = grant.0[8..24]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        let location = reservation_key(execution);
        let bytes = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        let record = decode_record(&location, bytes, &self.key)?;
        if record.bytes != 0
            || self
                .journal
                .get(NAMESPACE, &physical_key(execution))
                .is_some()
        {
            return Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking);
        }
        self.settle_authenticated_deletion(grant, None)
    }

    /// Settles one exact retained reservation after authenticated deletion.
    ///
    /// The tombstone remains permanently so replay or a reused execution ID
    /// cannot reintroduce a deleted capture. A real physical capture owner
    /// must attest deletion before this method is connected to production.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid grant, missing reservation, conflicting
    /// replay, or an ambiguous journal commit.
    fn settle_authenticated_deletion(
        &mut self,
        grant: &ExecutionOutputDeletionGrantV1,
        physical_deletion: Option<&VerifiedCaptureDeletionV1>,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let execution: [u8; 16] = grant.0[8..24]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        let location = reservation_key(execution);
        let value = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        let mut record = decode_record(&location, value, &self.key)?;
        if record.create != grant.0[24..40]
            || record.claim_digest != grant.0[40..72]
            || grant.0[72..88] == [0; 16]
            || !self
                .key
                .verify_mac(&location, &grant.0[..88], &grant.0[88..])?
        {
            return Err(ExecutionOutputLedgerErrorV1::UnauthorizedDeletion);
        }
        let delete_operation: [u8; 16] = grant.0[72..88]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)?;
        if record.bytes > 0 && physical_deletion.is_none() {
            return Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking);
        }
        let deletion_record = physical_deletion.map(|deletion| PhysicalDeletionRecord {
            binding: deletion.dataset_binding(),
            catalog_generation: deletion.catalog().generation(),
            catalog_digest: deletion.catalog().digest(),
            execution_delete_operation: delete_operation,
            storage_destroy_operation: *deletion.storage_delete_operation().as_bytes(),
        });
        if record.state == STATE_DELETED {
            if record.delete_operation != delete_operation {
                return Err(ExecutionOutputLedgerErrorV1::Conflict);
            }
            if let Some(expected) = deletion_record {
                let deletion_key = deletion_key(execution);
                let bytes = self
                    .journal
                    .get(NAMESPACE, &deletion_key)
                    .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
                if decode_deletion(&deletion_key, bytes, &self.key)? != expected {
                    return Err(ExecutionOutputLedgerErrorV1::Conflict);
                }
            }
            return Ok(());
        }
        let next = self
            .retained_bytes
            .checked_sub(record.bytes)
            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
        record.state = STATE_DELETED;
        record.delete_operation = delete_operation;
        let bytes = encode_record(&record, &location, &self.key)?;
        let transaction_id = transaction_id(b"delete", &location, &delete_operation);
        let mut records = vec![JournalRecord::put(NAMESPACE, location, bytes.to_vec())];
        if let Some(deletion) = deletion_record {
            let key = deletion_key(execution);
            let value = encode_deletion(&key, deletion, &self.key)?;
            records.push(JournalRecord::put(NAMESPACE, key, value.to_vec()));
        }
        self.journal
            .commit(&JournalTransaction::new(transaction_id, records)?)?;
        self.retained_bytes = next;
        Ok(())
    }
}

fn configuration_bytes(
    capacity_bytes: u64,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; CONFIG_BYTES], ExecutionOutputLedgerErrorV1> {
    let mut bytes = [0; CONFIG_BYTES];
    bytes[..8].copy_from_slice(CONFIG_MAGIC);
    bytes[8..16].copy_from_slice(&capacity_bytes.to_be_bytes());
    bytes[16..32].copy_from_slice(&key.key_id);
    let mac = key.mac(CONFIG_KEY, &bytes[..32])?;
    bytes[32..].copy_from_slice(&mac);
    Ok(bytes)
}

fn reservation_key(execution: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'r');
    key.extend_from_slice(&execution);
    key
}

fn physical_key(execution: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'p');
    key.extend_from_slice(&execution);
    key
}

fn deletion_key(execution: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'd');
    key.extend_from_slice(&execution);
    key
}

fn encode_deletion(
    location: &[u8],
    record: PhysicalDeletionRecord,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; DELETION_BYTES], ExecutionOutputLedgerErrorV1> {
    let mut bytes = [0; DELETION_BYTES];
    bytes[..8].copy_from_slice(DELETION_MAGIC);
    bytes[8..40].copy_from_slice(record.binding.as_bytes());
    bytes[40..48].copy_from_slice(&record.catalog_generation.to_be_bytes());
    bytes[48..80].copy_from_slice(record.catalog_digest.as_bytes());
    bytes[80..96].copy_from_slice(&record.execution_delete_operation);
    bytes[96..112].copy_from_slice(&record.storage_destroy_operation);
    let mac = key.mac(location, &bytes[..112])?;
    bytes[112..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_deletion(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<PhysicalDeletionRecord, ExecutionOutputLedgerErrorV1> {
    if location.len() != 17
        || location[0] != b'd'
        || bytes.len() != DELETION_BYTES
        || &bytes[..8] != DELETION_MAGIC
        || bytes[8..40] == [0; 32]
        || bytes[40..48] == [0; 8]
        || bytes[48..80] == [0; 32]
        || bytes[80..96] == [0; 16]
        || bytes[96..112] == [0; 16]
        || !key.verify_mac(location, &bytes[..112], &bytes[112..])?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(PhysicalDeletionRecord {
        binding: ObjectDigest::from_bytes(
            bytes[8..40]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        catalog_generation: u64::from_be_bytes(
            bytes[40..48]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        catalog_digest: ObjectDigest::from_bytes(
            bytes[48..80]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        execution_delete_operation: bytes[80..96]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        storage_destroy_operation: bytes[96..112]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
    })
}

fn encode_physical(
    location: &[u8],
    record: &PhysicalBindingRecord,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<Vec<u8>, ExecutionOutputLedgerErrorV1> {
    let name = record.dataset_name.as_bytes();
    let name_length: u16 = name
        .len()
        .try_into()
        .map_err(|_| ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)?;
    if name.is_empty() || name.len() > MAX_CAPTURE_DATASET_NAME_BYTES {
        return Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking);
    }
    let mut bytes = vec![0; 98 + name.len() + 32];
    bytes[..8].copy_from_slice(PHYSICAL_MAGIC);
    bytes[8..40].copy_from_slice(record.binding.as_bytes());
    bytes[40..72].copy_from_slice(&record.claim_digest);
    bytes[72..80].copy_from_slice(&record.bytes.to_be_bytes());
    bytes[80..88].copy_from_slice(&record.creation_generation.to_be_bytes());
    bytes[88..96].copy_from_slice(&record.guid.to_be_bytes());
    bytes[96..98].copy_from_slice(&name_length.to_be_bytes());
    bytes[98..98 + name.len()].copy_from_slice(name);
    let mac = key.mac(location, &bytes[..98 + name.len()])?;
    bytes[98 + name.len()..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_physical(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<PhysicalBindingRecord, ExecutionOutputLedgerErrorV1> {
    let name_length = bytes
        .get(96..98)
        .and_then(|length| <[u8; 2]>::try_from(length).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
    if location.len() != 17
        || location[0] != b'p'
        || !(1..=MAX_CAPTURE_DATASET_NAME_BYTES).contains(&name_length)
        || bytes.len() != 98 + name_length + 32
        || bytes.len() < PHYSICAL_MIN_BYTES
        || &bytes[..8] != PHYSICAL_MAGIC
        || bytes[8..40] == [0; 32]
        || bytes[40..72] == [0; 32]
        || bytes[80..88] == [0; 8]
        || bytes[88..96] == [0; 8]
        || !key.verify_mac(
            location,
            &bytes[..98 + name_length],
            &bytes[98 + name_length..],
        )?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    let dataset_name = std::str::from_utf8(&bytes[98..98 + name_length])
        .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?
        .to_owned();
    Ok(PhysicalBindingRecord {
        binding: ObjectDigest::from_bytes(
            bytes[8..40]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        claim_digest: bytes[40..72]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        bytes: u64::from_be_bytes(
            bytes[72..80]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        creation_generation: u64::from_be_bytes(
            bytes[80..88]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        guid: u64::from_be_bytes(
            bytes[88..96]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
        dataset_name,
    })
}

fn encode_record(
    record: &RetainedOutputRecord,
    location: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; RECORD_BYTES], ExecutionOutputLedgerErrorV1> {
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(RECORD_MAGIC);
    bytes[8..24].copy_from_slice(&record.execution);
    bytes[24..40].copy_from_slice(&record.create);
    bytes[40..72].copy_from_slice(&record.assignment);
    bytes[72..104].copy_from_slice(&record.claim_digest);
    bytes[104..112].copy_from_slice(&record.bytes.to_be_bytes());
    bytes[112..120].copy_from_slice(&record.maximum_stdout_bytes.to_be_bytes());
    bytes[120..128].copy_from_slice(&record.maximum_stderr_bytes.to_be_bytes());
    bytes[128] = record.state;
    bytes[129..145].copy_from_slice(&record.delete_operation);
    let mac = key.mac(location, &bytes[..145])?;
    bytes[145..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_record(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<RetainedOutputRecord, ExecutionOutputLedgerErrorV1> {
    if location.len() != 17
        || location[0] != b'r'
        || bytes.len() != RECORD_BYTES
        || &bytes[..8] != RECORD_MAGIC
        || bytes[8..24] != location[1..]
        || !key.verify_mac(location, &bytes[..145], &bytes[145..])?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    let field = |range: std::ops::Range<usize>| -> Result<[u8; 16], ExecutionOutputLedgerErrorV1> {
        bytes[range]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)
    };
    let digest = |range: std::ops::Range<usize>| -> Result<[u8; 32], ExecutionOutputLedgerErrorV1> {
        bytes[range]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)
    };
    let admitted_bytes = u64::from_be_bytes(
        bytes[104..112]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
    );
    let maximum_stdout_bytes = u64::from_be_bytes(
        bytes[112..120]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
    );
    let maximum_stderr_bytes = u64::from_be_bytes(
        bytes[120..128]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
    );
    let state = bytes[128];
    let delete_operation = field(129..145)?;
    if !matches!(state, STATE_RETAINED | STATE_DELETED)
        || bytes[8..24] == [0; 16]
        || bytes[24..40] == [0; 16]
        || bytes[40..72] == [0; 32]
        || bytes[72..104] == [0; 32]
        || maximum_stdout_bytes.checked_add(maximum_stderr_bytes) != Some(admitted_bytes)
        || (state == STATE_RETAINED && delete_operation != [0; 16])
        || (state == STATE_DELETED && delete_operation == [0; 16])
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(RetainedOutputRecord {
        execution: field(8..24)?,
        create: field(24..40)?,
        assignment: digest(40..72)?,
        claim_digest: digest(72..104)?,
        bytes: admitted_bytes,
        maximum_stdout_bytes,
        maximum_stderr_bytes,
        state,
        delete_operation,
    })
}

fn transaction_id(purpose: &[u8], location: &[u8], commitment: &[u8]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(MAC_DOMAIN);
    digest.update(purpose);
    digest.update(location);
    digest.update(commitment);
    let digest = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id[0] |= 1;
    id
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::capture_attempt::VerifiedCaptureAttemptSourcesV1;
    use super::*;
    use crate::catalog_transition::execution_capture::readback::{
        CaptureZfsCreateCommandV1, CaptureZfsPreflightPlanV1, CaptureZfsReadbackErrorV1,
        CaptureZfsReadbackPlanV1, CaptureZfsToolV1,
    };
    use crate::catalog_transition::execution_capture::tests::{
        deleted_fixture, fixture as capture_fixture,
    };
    use crate::execution_capture_files::{CaptureFileCustodyErrorV1, PinnedCaptureDirectoryV1};
    use crate::execution_capture_writer::{
        CaptureStreamV1, CaptureWriteErrorV1, DetachedCaptureWriterV1,
    };
    use crate::execution_capture_zfs_worker::{
        AuthorizedCaptureCreateAttemptV1, AuthorizedCaptureWriterAttemptV1, CaptureCreateBackendV1,
        CaptureCreateWorkerErrorV1, CaptureWriterWorkerErrorV1,
    };
    use crate::process::ZfsWorkerError;
    use aos_sandbox_core::OperationId;

    fn key() -> ExecutionOutputLedgerKeyV1 {
        ExecutionOutputLedgerKeyV1::new([7; 16], [9; 32]).unwrap()
    }

    fn record(execution: u8, bytes: u64) -> RetainedOutputRecord {
        RetainedOutputRecord {
            execution: [execution; 16],
            create: [2; 16],
            assignment: [3; 32],
            claim_digest: [4; 32],
            bytes,
            maximum_stdout_bytes: bytes,
            maximum_stderr_bytes: 0,
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        }
    }

    fn open(
        path: &Path,
        capacity: u64,
    ) -> Result<ExecutionOutputLedgerV1, ExecutionOutputLedgerErrorV1> {
        let (journal, _) = Journal::open(path, JournalLimits::default())?;
        ExecutionOutputLedgerV1::from_journal(journal, capacity, key())
    }

    fn private_output_file(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
    }

    fn grant(
        ledger: &ExecutionOutputLedgerV1,
        record: &RetainedOutputRecord,
        operation: u8,
    ) -> ExecutionOutputDeletionGrantV1 {
        let mut bytes = [0; GRANT_BYTES];
        bytes[..8].copy_from_slice(GRANT_MAGIC);
        bytes[8..24].copy_from_slice(&record.execution);
        bytes[24..40].copy_from_slice(&record.create);
        bytes[40..72].copy_from_slice(&record.claim_digest);
        bytes[72..88].copy_from_slice(&[operation; 16]);
        let mac = ledger
            .key
            .mac(&reservation_key(record.execution), &bytes[..88])
            .unwrap();
        bytes[88..].copy_from_slice(&mac);
        ExecutionOutputDeletionGrantV1::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn bounded_replay_and_authenticated_deletion_preserve_tombstone() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 12).unwrap();
        let first = record(1, 12);
        let zero = record(2, 0);
        let receipt = ledger.reserve_record(first.clone()).unwrap();
        assert_eq!(ledger.reserve_record(first.clone()).unwrap(), receipt);
        ledger.reserve_record(zero.clone()).unwrap();
        assert!(matches!(
            ledger.reserve_record(record(3, 1)),
            Err(ExecutionOutputLedgerErrorV1::Capacity)
        ));
        assert_eq!(ledger.retained_bytes(), 12);
        drop(ledger);

        let mut reopened = open(&path, 12).unwrap();
        assert_eq!(reopened.retained_bytes(), 12);
        let deletion = grant(&reopened, &zero, 8);
        reopened
            .settle_authenticated_deletion(&deletion, None)
            .unwrap();
        reopened
            .settle_authenticated_deletion(&deletion, None)
            .unwrap();
        assert_eq!(reopened.retained_bytes(), 12);
        assert!(matches!(
            reopened.reserve_record(zero),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));
        drop(reopened);

        let reopened = open(&path, 12).unwrap();
        assert_eq!(reopened.retained_bytes(), 12);
        assert!(matches!(
            open(&path, 13),
            Err(ExecutionOutputLedgerErrorV1::Journal(
                aos_sandbox::JournalError::AlreadyLocked
            ))
        ));
        drop(reopened);
        assert!(matches!(
            open(&path, 13),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let rotated_key = ExecutionOutputLedgerKeyV1::new([8; 16], [9; 32]).unwrap();
        assert!(matches!(
            ExecutionOutputLedgerV1::from_journal(journal, 12, rotated_key),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    #[test]
    fn deletion_rejects_substitution_and_corrupt_replay() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 10).unwrap();
        let retained = record(1, 5);
        ledger.reserve_record(retained.clone()).unwrap();
        let mut substituted = grant(&ledger, &retained, 8);
        substituted.0[40] ^= 1;
        assert!(matches!(
            ledger.settle_authenticated_deletion(&substituted, None),
            Err(ExecutionOutputLedgerErrorV1::UnauthorizedDeletion)
        ));
        assert_eq!(ledger.retained_bytes(), 5);

        let location = reservation_key(retained.execution);
        let mut malformed = ledger.journal.get(NAMESPACE, &location).unwrap().to_vec();
        malformed[104] ^= 1;
        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [44; 16],
                    vec![JournalRecord::put(NAMESPACE, location, malformed)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(ledger);
        assert!(matches!(
            open(&path, 10),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    #[test]
    fn zero_capacity_still_records_stream_claim() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 0).unwrap();
        let stream = record(1, 0);
        let digest = ledger.reserve_record(stream.clone()).unwrap();
        assert!(matches!(
            ledger.read_protected_retained_capture(stream.execution, stream.create, digest),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(matches!(
            ledger.reserve_record(record(2, 1)),
            Err(ExecutionOutputLedgerErrorV1::Capacity)
        ));
        let deletion = grant(&ledger, &stream, 8);
        ledger.settle_zero_output_deletion(&deletion).unwrap();
        drop(ledger);
        assert_eq!(open(&path, 0).unwrap().retained_bytes(), 0);
    }

    #[test]
    fn exact_stream_ceilings_survive_replay_and_invalid_sum_is_rejected() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 20).unwrap();
        let mut retained = record(1, 12);
        retained.maximum_stdout_bytes = 7;
        retained.maximum_stderr_bytes = 5;
        ledger.reserve_record(retained.clone()).unwrap();

        let mut invalid = record(2, 8);
        invalid.maximum_stdout_bytes = 7;
        invalid.maximum_stderr_bytes = 2;
        assert!(matches!(
            ledger.reserve_record(invalid),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        let mut overflowing = record(3, u64::MAX);
        overflowing.maximum_stderr_bytes = 1;
        assert!(matches!(
            ledger.reserve_record(overflowing),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        drop(ledger);

        let mut reopened = open(&path, 20).unwrap();
        let key = reservation_key(retained.execution);
        let record = decode_record(
            &key,
            reopened.journal.get(NAMESPACE, &key).unwrap(),
            &reopened.key,
        )
        .unwrap();
        assert_eq!(record.maximum_stdout_bytes, 7);
        assert_eq!(record.maximum_stderr_bytes, 5);
        assert_eq!(reopened.retained_bytes(), 12);

        let mut tampered = reopened.journal.get(NAMESPACE, &key).unwrap().to_vec();
        tampered[112] ^= 1;
        reopened
            .journal
            .commit(
                &JournalTransaction::new(
                    [46; 16],
                    vec![JournalRecord::put(NAMESPACE, key, tampered)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(reopened);
        assert!(matches!(
            open(&path, 20),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    #[test]
    fn readback_plan_requires_cold_replayed_aoseor03_and_exact_live_properties() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 200).unwrap();
        let (requirement, catalog) = capture_fixture();
        let verified = requirement.verify_present(&catalog).unwrap();
        let mut retained = record(1, 100);
        retained.claim_digest = [3; 32];
        retained.maximum_stdout_bytes = 60;
        retained.maximum_stderr_bytes = 40;
        let digest = ledger.reserve_record(retained).unwrap();
        drop(ledger);

        let ledger = open(&path, 200).unwrap();
        let protected = ledger
            .read_protected_retained_capture([1; 16], [2; 16], digest)
            .unwrap();
        assert_eq!(protected.maximum_stdout_bytes(), 60);
        assert_eq!(protected.maximum_stderr_bytes(), 40);
        assert_eq!(protected.admitted_bytes(), 100);
        assert!(matches!(
            ledger.read_protected_retained_capture([1; 16], [9; 16], digest),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(matches!(
            ledger.read_protected_retained_capture(
                [1; 16],
                [2; 16],
                ObjectDigest::from_bytes([9; 32]),
            ),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));

        let preflight = CaptureZfsPreflightPlanV1::new(&requirement, &protected, 20, 100).unwrap();
        assert_eq!(preflight.commands()[0].tool, CaptureZfsToolV1::Zpool);
        assert_eq!(preflight.commands()[1].tool, CaptureZfsToolV1::Zfs);
        let pool = b"pool\t17\t-\t1000\tONLINE\n".as_slice();
        let root = b"pool/aos\tfilesystem\t11\t900\n".as_slice();
        let observed_preflight = preflight.evaluate([pool, root]).unwrap();
        assert_eq!(observed_preflight.record_digest, digest);
        assert_eq!(observed_preflight.allocation_bytes, 200);
        assert_eq!(observed_preflight.pool_guid, 17);
        assert_eq!(observed_preflight.root_guid, 11);
        assert_eq!(observed_preflight.pool_available_bytes, 1000);
        assert_eq!(observed_preflight.root_available_bytes, 900);
        assert_eq!(observed_preflight.dataset_name, verified.dataset_name());
        assert_ne!(observed_preflight.observation_digest.as_bytes(), &[0; 32]);
        assert_eq!(
            preflight
                .evaluate([b"pool\t17\t1\t1000\tONLINE\n", root])
                .err(),
            Some(CaptureZfsReadbackErrorV1::PoolUnavailable)
        );
        assert_eq!(
            preflight
                .evaluate([b"pool\t0\t-\t1000\tONLINE\n", root])
                .err(),
            Some(CaptureZfsReadbackErrorV1::PoolUnavailable)
        );
        assert_eq!(
            preflight
                .evaluate([b"pool\t17\t-\t299\tONLINE\n", root])
                .err(),
            Some(CaptureZfsReadbackErrorV1::PoolUnavailable)
        );
        assert_eq!(
            preflight
                .evaluate([pool, b"pool/aos\tfilesystem\t11\t299\n"])
                .err(),
            Some(CaptureZfsReadbackErrorV1::DatasetMismatch)
        );
        let create =
            CaptureZfsCreateCommandV1::new(&requirement, &protected, &observed_preflight).unwrap();
        assert_eq!(create.record_digest, digest);
        assert_eq!(
            create.preflight_digest,
            observed_preflight.observation_digest
        );
        assert_eq!(
            create.storage_create_operation,
            observed_preflight.storage_create_operation
        );
        assert_eq!(
            create.arguments,
            [
                "create",
                "-o",
                "mountpoint=none",
                "-o",
                "canmount=off",
                "-o",
                "refquota=200",
                "-o",
                "reservation=200",
                verified.dataset_name(),
            ]
        );
        assert_ne!(create.command_digest.as_bytes(), &[0; 32]);

        let plan = CaptureZfsReadbackPlanV1::new(&verified, &protected, 20, 100).unwrap();
        assert_eq!(plan.commands()[0].tool, CaptureZfsToolV1::Zpool);
        assert_eq!(plan.commands()[1].tool, CaptureZfsToolV1::Zfs);
        assert_eq!(plan.commands()[2].tool, CaptureZfsToolV1::Zfs);
        assert_eq!(plan.commands()[0].arguments[5], "pool");
        assert_eq!(plan.commands()[2].arguments[8], verified.dataset_name());
        assert!(matches!(
            CaptureZfsReadbackPlanV1::new(&verified, &protected, 101, 100),
            Err(CaptureZfsReadbackErrorV1::InvalidRequirement)
        ));

        let dataset = format!(
            "{}\tfilesystem\t17\t-\t200\t200\tnone\toff\tno\t130\n",
            verified.dataset_name()
        );
        let post_pool = b"pool\t-\t1000\tONLINE\n".as_slice();
        let readback = plan
            .evaluate([post_pool, root, dataset.as_bytes()])
            .unwrap();
        assert_eq!(readback.record_digest, digest);
        assert_eq!(readback.catalog_binding, verified.binding());
        assert_ne!(readback.observation_digest.as_bytes(), &[0; 32]);
        assert_eq!(readback.dataset_available_bytes, 130);
        assert_eq!(readback.observed_headroom_bytes, 30);

        for substituted_pool in [
            b"pool\t0\t1000\tONLINE\n".as_slice(),
            b"pool\t1\t1000\tONLINE\n",
            b"pool\t-\t99\tONLINE\n",
            b"pool\t-\t1000\tDEGRADED\n",
        ] {
            assert_eq!(
                plan.evaluate([substituted_pool, root, dataset.as_bytes()])
                    .err(),
                Some(CaptureZfsReadbackErrorV1::PoolUnavailable)
            );
        }
        for substituted_dataset in [
            dataset.replace("\t200\t200\t", "\t199\t200\t"),
            dataset.replace("\tnone\toff\tno\t", "\tlegacy\ton\tyes\t"),
            dataset.replace("\tno\t130\n", "\tno\t119\n"),
            format!(
                "{dataset}{}@snapshot\tsnapshot\t18\n",
                verified.dataset_name()
            ),
        ] {
            assert!(
                plan.evaluate([post_pool, root, substituted_dataset.as_bytes()])
                    .is_err()
            );
        }
        assert_eq!(
            plan.evaluate([
                post_pool,
                b"pool/aos\tfilesystem\t12\t900\n",
                dataset.as_bytes()
            ])
            .err(),
            Some(CaptureZfsReadbackErrorV1::DatasetMismatch)
        );

        let stdout = private_output_file(&directory.path().join("post-stdout"));
        let stderr = private_output_file(&directory.path().join("post-stderr"));
        let mut writer = DetachedCaptureWriterV1::new(&protected, stdout, stderr).unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stdout, &[b'a'; 50])
            .unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stderr, &[b'b'; 20])
            .unwrap();
        writer.finish_stream(CaptureStreamV1::Stdout).unwrap();
        writer.finish_stream(CaptureStreamV1::Stderr).unwrap();
        let mut written = writer.finish().unwrap();
        written.stdout.captured_bytes = 61;
        written.stderr.captured_bytes = 0;
        assert!(matches!(
            CaptureZfsReadbackPlanV1::after_write(&verified, &protected, &written, 20, 100),
            Err(CaptureZfsReadbackErrorV1::InvalidRequirement)
        ));
        written.stdout.captured_bytes = 50;
        written.stderr.captured_bytes = 20;
        let postwrite =
            CaptureZfsReadbackPlanV1::after_write(&verified, &protected, &written, 20, 100)
                .unwrap();
        let remaining = format!(
            "{}\tfilesystem\t17\t-\t200\t200\tnone\toff\tno\t50\n",
            verified.dataset_name()
        );
        let postwrite_readback = postwrite
            .evaluate([post_pool, root, remaining.as_bytes()])
            .unwrap();
        assert_eq!(postwrite_readback.observed_headroom_bytes, 20);
        assert_ne!(
            postwrite_readback.observation_digest,
            readback.observation_digest
        );
        let insufficient = remaining.replace("\tno\t50\n", "\tno\t49\n");
        assert_eq!(
            postwrite
                .evaluate([post_pool, root, insufficient.as_bytes()])
                .err(),
            Some(CaptureZfsReadbackErrorV1::DatasetMismatch)
        );

        let mut writer_attempt = AuthorizedCaptureWriterAttemptV1::for_test(protected, verified);
        let binding = writer_attempt.file_custody_binding();
        assert_eq!(binding.3, digest);
        writer_attempt.expire_for_test();
        let fixed_zfs =
            crate::ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        assert!(matches!(
            writer_attempt.prepare_detached(&fixed_zfs),
            Err(CaptureWriterWorkerErrorV1::InvalidAttempt)
        ));
    }

    #[test]
    fn closed_capture_create_attempt_requires_preflight_and_never_reports_physical_success() {
        struct ScriptedBackend {
            pool: Vec<u8>,
            root: Vec<u8>,
            create_calls: usize,
            create_fails: bool,
        }

        impl CaptureCreateBackendV1 for ScriptedBackend {
            fn observe_preflight(
                &mut self,
                _authorized: &AuthorizedCaptureCreateAttemptV1,
                _plan: &CaptureZfsPreflightPlanV1,
            ) -> Result<[Vec<u8>; 2], ZfsWorkerError> {
                Ok([self.pool.clone(), self.root.clone()])
            }

            fn create(
                &mut self,
                _authorized: &AuthorizedCaptureCreateAttemptV1,
                command: &CaptureZfsCreateCommandV1,
            ) -> Result<bool, ZfsWorkerError> {
                self.create_calls += 1;
                assert_eq!(command.arguments[2], "mountpoint=none");
                assert_eq!(command.arguments[8], "reservation=200");
                if self.create_fails {
                    Err(ZfsWorkerError::Protocol("scripted effect uncertainty"))
                } else {
                    Ok(true)
                }
            }
        }

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 200).unwrap();
        let (requirement, _) = capture_fixture();
        let mut retained = record(1, 100);
        retained.claim_digest = [3; 32];
        retained.maximum_stdout_bytes = 60;
        retained.maximum_stderr_bytes = 40;
        let digest = ledger.reserve_record(retained).unwrap();
        drop(ledger);

        let ledger = open(&path, 200).unwrap();
        let protected = ledger
            .read_protected_retained_capture([1; 16], [2; 16], digest)
            .unwrap();
        let mut backend = ScriptedBackend {
            pool: b"pool\t17\t1\t1000\tONLINE\n".to_vec(),
            root: b"pool/aos\tfilesystem\t11\t900\n".to_vec(),
            create_calls: 0,
            create_fails: false,
        };
        let attempt = AuthorizedCaptureCreateAttemptV1::for_test(
            protected,
            requirement.clone(),
            CaptureZfsPreflightPlanV1::new(&requirement, &protected, 20, 100).unwrap(),
        );
        assert!(matches!(
            attempt.execute_with(&mut backend),
            Err(CaptureCreateWorkerErrorV1::Readback(
                CaptureZfsReadbackErrorV1::PoolUnavailable
            ))
        ));
        assert_eq!(backend.create_calls, 0);

        backend.pool = b"pool\t17\t-\t1000\tONLINE\n".to_vec();
        backend.create_fails = true;
        let attempt = AuthorizedCaptureCreateAttemptV1::for_test(
            protected,
            requirement.clone(),
            CaptureZfsPreflightPlanV1::new(&requirement, &protected, 20, 100).unwrap(),
        );
        let uncertain = attempt.execute_with(&mut backend).unwrap();
        assert_eq!(backend.create_calls, 1);
        assert!(!uncertain.reported_zero_exit);
        assert_eq!(uncertain.record_digest, digest);
        assert_ne!(uncertain.attempt_digest.as_bytes(), &[0; 32]);

        backend.create_fails = false;
        let attempt = AuthorizedCaptureCreateAttemptV1::for_test(
            protected,
            requirement.clone(),
            CaptureZfsPreflightPlanV1::new(&requirement, &protected, 20, 100).unwrap(),
        );
        let zero_exit = attempt.execute_with(&mut backend).unwrap();
        assert_eq!(backend.create_calls, 2);
        assert!(zero_exit.reported_zero_exit);
        assert_ne!(zero_exit.attempt_digest, uncertain.attempt_digest);
    }

    #[test]
    fn capture_writer_records_exact_synced_prefixes_and_eofs() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 10).unwrap();
        let mut claim = record(1, 10);
        claim.maximum_stdout_bytes = 6;
        claim.maximum_stderr_bytes = 4;
        let digest = ledger.reserve_record(claim).unwrap();
        drop(ledger);

        let ledger = open(&path, 10).unwrap();
        let retained = ledger
            .read_protected_retained_capture([1; 16], [2; 16], digest)
            .unwrap();
        let stdout_path = directory.path().join("stdout");
        let stderr_path = directory.path().join("stderr");
        let stdout = private_output_file(&stdout_path);
        let stderr = private_output_file(&stderr_path);
        let mut writer = DetachedCaptureWriterV1::new(&retained, stdout, stderr).unwrap();

        writer.write_chunk(CaptureStreamV1::Stdout, b"abc").unwrap();
        writer.write_chunk(CaptureStreamV1::Stderr, b"xy").unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stdout, b"defgh")
            .unwrap();
        writer.write_chunk(CaptureStreamV1::Stderr, b"z").unwrap();
        writer.finish_stream(CaptureStreamV1::Stdout).unwrap();
        writer.finish_stream(CaptureStreamV1::Stderr).unwrap();
        let result = writer.finish().unwrap();

        assert_eq!(std::fs::read(stdout_path).unwrap(), b"abcdef");
        assert_eq!(std::fs::read(stderr_path).unwrap(), b"xyz");
        assert_eq!(result.record_digest, digest);
        assert_eq!(result.stdout.maximum_bytes, 6);
        assert_eq!(result.stdout.captured_bytes, 6);
        assert!(result.stdout.truncated);
        assert_eq!(result.stderr.maximum_bytes, 4);
        assert_eq!(result.stderr.captured_bytes, 3);
        assert!(!result.stderr.truncated);
        assert_eq!(
            &result.stdout.content_digest.as_bytes()[..],
            &Sha256::digest(b"abcdef")[..]
        );
        assert_eq!(
            &result.stderr.content_digest.as_bytes()[..],
            &Sha256::digest(b"xyz")[..]
        );
        assert!(result.stdout_eof && result.stderr_eof && result.synced_readback);
        assert_ne!(result.result_digest.as_bytes(), &[0; 32]);
    }

    #[test]
    fn pinned_namespace_transfers_only_exact_aoseor03_files_to_writer() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let capture_directory = TempDir::new().unwrap();
        std::fs::set_permissions(
            capture_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let mut ledger = open(&path, 6).unwrap();
        let mut claim = record(1, 6);
        claim.maximum_stdout_bytes = 4;
        claim.maximum_stderr_bytes = 2;
        let digest = ledger.reserve_record(claim).unwrap();
        drop(ledger);

        let ledger = open(&path, 6).unwrap();
        let retained = ledger
            .read_protected_retained_capture([1; 16], [2; 16], digest)
            .unwrap();
        let pin = PinnedCaptureDirectoryV1::for_test(capture_directory.path(), &retained).unwrap();
        let (mut writer, guard) = pin.claim_files().unwrap().into_writer(&retained).unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stdout, b"abcdef")
            .unwrap();
        writer.write_chunk(CaptureStreamV1::Stderr, b"xyz").unwrap();
        writer.finish_stream(CaptureStreamV1::Stdout).unwrap();
        writer.finish_stream(CaptureStreamV1::Stderr).unwrap();
        let written = writer.finish().unwrap();
        guard.sync_after_write().unwrap();

        assert_eq!(written.record_digest, digest);
        assert_eq!(written.stdout.captured_bytes, 4);
        assert_eq!(written.stderr.captured_bytes, 2);
        assert!(written.stdout.truncated && written.stderr.truncated);
        assert_eq!(
            std::fs::read(capture_directory.path().join("stdout")).unwrap(),
            b"abcd"
        );
        assert_eq!(
            std::fs::read(capture_directory.path().join("stderr")).unwrap(),
            b"xy"
        );
        drop(guard);
        assert!(matches!(
            PinnedCaptureDirectoryV1::for_test(capture_directory.path(), &retained)
                .unwrap()
                .claim_files(),
            Err(CaptureFileCustodyErrorV1::AlreadyClaimed)
        ));
    }

    #[test]
    fn capture_writer_rejects_missing_eof_aliasing_and_changed_content() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 4).unwrap();
        let mut claim = record(1, 4);
        claim.maximum_stdout_bytes = 4;
        claim.maximum_stderr_bytes = 0;
        let digest = ledger.reserve_record(claim).unwrap();
        let retained = ledger
            .read_protected_retained_capture([1; 16], [2; 16], digest)
            .unwrap();

        let same_path = directory.path().join("same");
        let same = private_output_file(&same_path);
        assert!(matches!(
            DetachedCaptureWriterV1::new(&retained, same.try_clone().unwrap(), same),
            Err(CaptureWriteErrorV1::InvalidBacking)
        ));

        let stdout_path = directory.path().join("stdout");
        let stderr_path = directory.path().join("stderr");
        let stdout = private_output_file(&stdout_path);
        let stderr = private_output_file(&stderr_path);
        let mut writer = DetachedCaptureWriterV1::new(&retained, stdout, stderr).unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stdout, b"abcd")
            .unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stderr, b"discard")
            .unwrap();
        writer.finish_stream(CaptureStreamV1::Stdout).unwrap();
        assert!(matches!(
            writer.finish(),
            Err(CaptureWriteErrorV1::Incomplete)
        ));

        let stdout = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(&stdout_path)
            .unwrap();
        let stderr = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(&stderr_path)
            .unwrap();
        let mut writer = DetachedCaptureWriterV1::new(&retained, stdout, stderr).unwrap();
        writer
            .write_chunk(CaptureStreamV1::Stdout, b"abcd")
            .unwrap();
        writer.finish_stream(CaptureStreamV1::Stdout).unwrap();
        writer.finish_stream(CaptureStreamV1::Stderr).unwrap();
        std::fs::write(&stdout_path, b"abXd").unwrap();
        assert!(matches!(
            writer.finish(),
            Err(CaptureWriteErrorV1::BackingMismatch)
        ));
    }

    #[test]
    fn physical_binding_and_exact_zfs_tombstone_survive_replay() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 200).unwrap();
        let (requirement, catalog) = capture_fixture();
        let present = requirement.verify_present(&catalog).unwrap();
        let mut retained = record(1, 100);
        retained.claim_digest = [3; 32];
        ledger.reserve_record(retained.clone()).unwrap();
        ledger
            .bind_verified_capture_dataset(&present, [1; 16])
            .unwrap();
        drop(ledger);

        let mut ledger = open(&path, 200).unwrap();

        let grant = grant(&ledger, &retained, 6);
        assert!(matches!(
            ledger.settle_zero_output_deletion(&grant),
            Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)
        ));
        let wrong_catalog = deleted_fixture(&requirement, catalog.clone(), 8);
        let catalog = deleted_fixture(&requirement, catalog, 7);
        drop(ledger);

        let mut ledger = open(&path, 200).unwrap();
        assert_eq!(ledger.retained_bytes(), 100);
        assert!(matches!(
            ledger.settle_verified_capture_deletion(
                &grant,
                &wrong_catalog,
                OperationId::from_bytes([7; 16]),
            ),
            Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)
        ));
        assert_eq!(ledger.retained_bytes(), 100);
        ledger
            .settle_verified_capture_deletion(&grant, &catalog, OperationId::from_bytes([7; 16]))
            .unwrap();
        drop(ledger);

        let mut reopened = open(&path, 200).unwrap();
        assert_eq!(reopened.retained_bytes(), 0);
        let deletion_key = deletion_key([1; 16]);
        let record = decode_deletion(
            &deletion_key,
            reopened.journal.get(NAMESPACE, &deletion_key).unwrap(),
            &reopened.key,
        )
        .unwrap();
        assert_eq!(record.execution_delete_operation, [6; 16]);
        assert_eq!(record.storage_destroy_operation, [7; 16]);
        reopened
            .settle_verified_capture_deletion(&grant, &catalog, OperationId::from_bytes([7; 16]))
            .unwrap();
    }

    #[test]
    fn tampered_physical_identity_fails_cold_replay() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 200).unwrap();
        let (requirement, catalog) = capture_fixture();
        let present = requirement.verify_present(&catalog).unwrap();
        let mut retained = record(1, 100);
        retained.claim_digest = [3; 32];
        ledger.reserve_record(retained).unwrap();
        ledger
            .bind_verified_capture_dataset(&present, [1; 16])
            .unwrap();

        let key = physical_key([1; 16]);
        let mut tampered = ledger.journal.get(NAMESPACE, &key).unwrap().to_vec();
        tampered[88] ^= 1;
        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [45; 16],
                    vec![JournalRecord::put(NAMESPACE, key, tampered)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(ledger);

        assert!(matches!(
            open(&path, 200),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }

    #[test]
    fn capture_physical_observation_is_exact_and_cold_replayable() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path, 200).unwrap();
        let (requirement, catalog) = capture_fixture();
        let mut retained = record(1, 100);
        retained.claim_digest = [3; 32];
        retained.maximum_stdout_bytes = 60;
        retained.maximum_stderr_bytes = 40;
        let output_digest = ledger.reserve_record(retained).unwrap();
        let protected = ledger
            .read_protected_retained_capture([1; 16], [2; 16], output_digest)
            .unwrap();
        let sources = VerifiedCaptureAttemptSourcesV1::for_test(&protected, &requirement, 20, 100);
        let attempt = ledger
            .issue_capture_create_attempt(&sources, &protected, &requirement, 20, 100)
            .unwrap();

        let verified = requirement.verify_present(&catalog).unwrap();
        let plan = CaptureZfsReadbackPlanV1::new(&verified, &protected, 20, 100).unwrap();
        let dataset = format!(
            "{}\tfilesystem\t17\t-\t200\t200\tnone\toff\tno\t130\n",
            verified.dataset_name()
        );
        let observed = plan
            .evaluate([
                b"pool\t-\t1000\tONLINE\n",
                b"pool/aos\tfilesystem\t11\t900\n",
                dataset.as_bytes(),
            ])
            .unwrap();
        assert!(matches!(
            ledger.record_capture_observation_for_test(
                &sources,
                &requirement,
                &catalog,
                20,
                100,
                &observed,
            ),
            Err(ExecutionOutputLedgerErrorV1::MissingPhysicalBacking)
        ));

        ledger
            .bind_verified_capture_dataset(&verified, [1; 16])
            .unwrap();
        let receipt = ledger
            .record_capture_observation_for_test(
                &sources,
                &requirement,
                &catalog,
                20,
                100,
                &observed,
            )
            .unwrap();
        assert_eq!(receipt.output_record_digest, output_digest);
        assert_eq!(
            receipt.durable_attempt_digest,
            attempt.durable_attempt_digest
        );
        assert_eq!(receipt.dataset_binding, verified.binding());
        assert_eq!(receipt.catalog_guid, 17);
        assert_eq!(receipt.zfs_observation_digest, observed.observation_digest);
        assert_eq!(receipt.dataset_available_bytes, 130);
        assert_eq!(receipt.observed_headroom_bytes, 30);
        assert_ne!(receipt.durable_observation_digest.as_bytes(), &[0; 32]);
        drop(ledger);

        let mut reopened = open(&path, 200).unwrap();
        assert_eq!(
            reopened
                .query_capture_physical_observation(&sources)
                .unwrap(),
            Some(receipt)
        );
        assert!(matches!(
            reopened.record_capture_observation_for_test(
                &sources,
                &requirement,
                &catalog,
                20,
                100,
                &observed,
            ),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));
        let changed_policy =
            VerifiedCaptureAttemptSourcesV1::for_test(&protected, &requirement, 21, 100);
        assert!(matches!(
            reopened.query_capture_physical_observation(&changed_policy),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));

        let mut location = [0; 17];
        location[0] = b'o';
        location[1..].fill(1);
        let mut tampered = reopened.journal.get(NAMESPACE, &location).unwrap().to_vec();
        tampered[208] ^= 1;
        reopened
            .journal
            .commit(
                &JournalTransaction::new(
                    [54; 16],
                    vec![JournalRecord::put(NAMESPACE, location.to_vec(), tampered)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(reopened);
        assert!(matches!(
            open(&path, 200),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }
}
