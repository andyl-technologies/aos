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
//! reservation   = AOSEOR02 || execution[16] || create[16]
//!                 || assignment[32] || v2-claim-digest[32] || bytes:u64be
//!                 || state:u8 || delete-operation[16] || hmac[32]
//! deletion-grant = AOSEOD01 || execution[16] || create[16]
//!                 || v2-claim-digest[32] || delete-operation[16] || hmac[32]
//! ```

use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::runtime_backend::AdmissionCurrentnessV1;
use aos_sandbox_core::ObjectDigest;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use aos_sandbox::execution_output_reservation::DurableExecutionOutputReservationV1;

type HmacSha256 = Hmac<Sha256>;

const NAMESPACE: RecordNamespace = RecordNamespace::StorageExecutionOutput;
const CONFIG_KEY: &[u8] = b"configuration";
const CONFIG_MAGIC: &[u8; 8] = b"AOSEOC01";
const RECORD_MAGIC: &[u8; 8] = b"AOSEOR02";
const GRANT_MAGIC: &[u8; 8] = b"AOSEOD01";
const MAC_DOMAIN: &[u8] = b"aos.sandbox.storage.execution-output.v1\0";
const CONFIG_BYTES: usize = 64;
const RECORD_BYTES: usize = 161;
const GRANT_BYTES: usize = 120;
const STATE_RETAINED: u8 = 1;
const STATE_DELETED: u8 = 2;

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
    state: u8,
    delete_operation: [u8; 16],
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
            let record = decode_record(location, value, &key)?;
            if record.state == STATE_RETAINED {
                retained_bytes = retained_bytes
                    .checked_add(record.bytes)
                    .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
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

    /// Reserves the exact durable accepted-Create output claim.
    ///
    /// The witness must be read from the v2 runtime owner; its output digest
    /// and assignment must match the retained claim. The pair is still only
    /// logical Storage custody. The caller must not use the result to authorize
    /// capture or Host Apply without verified physical backing and a cross-owner
    /// currentness barrier.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched witness, capacity exhaustion,
    /// conflicting execution reuse, or an ambiguous journal commit. Reopen
    /// after ambiguity before retry.
    pub fn reserve_accepted_claim(
        &mut self,
        claim: &DurableExecutionOutputReservationV1,
        currentness: &AdmissionCurrentnessV1,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
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
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        };
        self.reserve_record(record)
    }

    fn reserve_record(
        &mut self,
        record: RetainedOutputRecord,
    ) -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
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
    pub fn settle_authenticated_deletion(
        &mut self,
        grant: &ExecutionOutputDeletionGrantV1,
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
        if record.state == STATE_DELETED {
            return if record.delete_operation == delete_operation {
                Ok(())
            } else {
                Err(ExecutionOutputLedgerErrorV1::Conflict)
            };
        }
        let next = self
            .retained_bytes
            .checked_sub(record.bytes)
            .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
        record.state = STATE_DELETED;
        record.delete_operation = delete_operation;
        let bytes = encode_record(&record, &location, &self.key)?;
        let transaction_id = transaction_id(b"delete", &location, &delete_operation);
        self.journal.commit(&JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, location, bytes.to_vec())],
        )?)?;
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
    bytes[112] = record.state;
    bytes[113..129].copy_from_slice(&record.delete_operation);
    let mac = key.mac(location, &bytes[..129])?;
    bytes[129..].copy_from_slice(&mac);
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
        || !key.verify_mac(location, &bytes[..129], &bytes[129..])?
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
    let state = bytes[112];
    let delete_operation = field(113..129)?;
    if !matches!(state, STATE_RETAINED | STATE_DELETED)
        || bytes[8..24] == [0; 16]
        || bytes[24..40] == [0; 16]
        || bytes[40..72] == [0; 32]
        || bytes[72..104] == [0; 32]
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
        bytes: u64::from_be_bytes(
            bytes[104..112]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
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
    use tempfile::TempDir;

    use super::*;

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
        let deletion = grant(&reopened, &first, 8);
        reopened.settle_authenticated_deletion(&deletion).unwrap();
        reopened.settle_authenticated_deletion(&deletion).unwrap();
        assert_eq!(reopened.retained_bytes(), 0);
        assert!(matches!(
            reopened.reserve_record(first),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));
        drop(reopened);

        let reopened = open(&path, 12).unwrap();
        assert_eq!(reopened.retained_bytes(), 0);
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
            ledger.settle_authenticated_deletion(&substituted),
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
        ledger.reserve_record(record(1, 0)).unwrap();
        assert!(matches!(
            ledger.reserve_record(record(2, 1)),
            Err(ExecutionOutputLedgerErrorV1::Capacity)
        ));
        drop(ledger);
        assert_eq!(open(&path, 0).unwrap().retained_bytes(), 0);
    }
}
