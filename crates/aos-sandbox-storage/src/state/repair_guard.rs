//! Closed, durable Storage ownership of an operator Repair commit window.
//!
//! A held row blocks every ordinary Storage state-journal write and survives
//! process restart. It has no deadline or Drop release. Acquisition and
//! resolution require opaque proofs that production cannot construct yet:
//! worker quiescence, live physical readback, a long-lived broker session, and
//! authenticated Controller terminal readback must be connected first.
//!
//! ```text
//! key = "storage-repair-held-v1/" | repair-operation[16]
//! AOSRHG01 | version:u16be=1 | phase:u8 | reserved:u8 | key-id[16]
//! repair-operation[16] | effect-id[16] | sandbox-id[16] | workspace-handle[32]
//! assignment-digest[32] | catalog-generation:u64be | catalog-digest[32]
//! physical-version[32] | owner-id[16] | owner-key-generation:u64be
//! controller-transaction-digest[32] | hmac-sha256[32]
//! ```

use std::collections::BTreeMap;

use aos_sandbox::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use hmac::Mac as _;
use sha2::{Digest as _, Sha256};

use super::{
    CatalogBindingV1, HmacSha256, MAXIMUM_OPERATIONS, StorageStateError, StorageStateKey,
    StorageTransactionStore,
};

const MAGIC: &[u8; 8] = b"AOSRHG01";
const VERSION: u16 = 1;
const KEY_PREFIX: &[u8] = b"storage-repair-held-v1/";
const MAC_DOMAIN: &[u8] = b"aos.sandbox.storage.repair-held-guard.v1\0";
const TX_DOMAIN: &[u8] = b"aos.sandbox.storage.repair-held-guard-transaction.v1\0";
const BODY_BYTES: usize = 8 + 2 + 1 + 1 + 16 + 16 + 16 + 16 + 32 + 32 + 8 + 32 + 32 + 16 + 8 + 32;
pub(super) const RECORD_BYTES: usize = BODY_BYTES + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RepairGuardBindingV1 {
    operation_id: [u8; 16],
    effect_id: [u8; 16],
    sandbox_id: [u8; 16],
    workspace_handle: [u8; 32],
    assignment_digest: [u8; 32],
    catalog: CatalogBindingV1,
    physical_version: [u8; 32],
    owner_id: [u8; 16],
    owner_key_generation: u64,
    controller_transaction_digest: [u8; 32],
}

impl RepairGuardBindingV1 {
    fn validate(self) -> Result<(), StorageStateError> {
        if self.operation_id == [0; 16]
            || self.effect_id == [0; 16]
            || self.sandbox_id == [0; 16]
            || self.workspace_handle == [0; 32]
            || self.assignment_digest == [0; 32]
            || self.physical_version == [0; 32]
            || self.owner_id == [0; 16]
            || self.owner_key_generation == 0
            || self.controller_transaction_digest == [0; 32]
        {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardPhaseV1 {
    Held = 1,
    ControllerCommitted = 2,
    ControllerAbsent = 3,
}

impl GuardPhaseV1 {
    fn decode(value: u8) -> Result<Self, StorageStateError> {
        match value {
            1 => Ok(Self::Held),
            2 => Ok(Self::ControllerCommitted),
            3 => Ok(Self::ControllerAbsent),
            _ => Err(StorageStateError::CorruptRecord),
        }
    }
}

/// Retains the exact Storage-owned guard decision after protected reopen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StorageRepairGuardRecordV1 {
    binding: RepairGuardBindingV1,
    phase: GuardPhaseV1,
}

impl StorageRepairGuardRecordV1 {
    pub(super) const fn is_held(&self) -> bool {
        matches!(self.phase, GuardPhaseV1::Held)
    }

    fn encode(self, key: &StorageStateKey) -> Result<Vec<u8>, StorageStateError> {
        self.binding.validate()?;
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[self.phase as u8, 0]);
        bytes.extend_from_slice(&key.key_id);
        bytes.extend_from_slice(&self.binding.operation_id);
        bytes.extend_from_slice(&self.binding.effect_id);
        bytes.extend_from_slice(&self.binding.sandbox_id);
        bytes.extend_from_slice(&self.binding.workspace_handle);
        bytes.extend_from_slice(&self.binding.assignment_digest);
        bytes.extend_from_slice(&self.binding.catalog.generation().to_be_bytes());
        bytes.extend_from_slice(self.binding.catalog.digest().as_bytes());
        bytes.extend_from_slice(&self.binding.physical_version);
        bytes.extend_from_slice(&self.binding.owner_id);
        bytes.extend_from_slice(&self.binding.owner_key_generation.to_be_bytes());
        bytes.extend_from_slice(&self.binding.controller_transaction_digest);
        let tag = mac(key, self.binding.operation_id, &bytes)?;
        bytes.extend_from_slice(&tag);
        Ok(bytes)
    }

    fn decode(
        operation_id: [u8; 16],
        bytes: &[u8],
        key: &StorageStateKey,
    ) -> Result<Self, StorageStateError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(11) != Some(&0)
            || bytes.get(12..28) != Some(key.key_id.as_slice())
        {
            return Err(StorageStateError::CorruptRecord);
        }
        let body = bytes
            .get(..BODY_BYTES)
            .ok_or(StorageStateError::CorruptRecord)?;
        let tag = bytes
            .get(BODY_BYTES..)
            .ok_or(StorageStateError::CorruptRecord)?;
        let verifier = mac_state(key, operation_id, body)?;
        verifier
            .verify_slice(tag)
            .map_err(|_| StorageStateError::CorruptRecord)?;

        let mut cursor = 28;
        let mut take = |length: usize| {
            let start = cursor;
            cursor += length;
            body.get(start..cursor)
                .ok_or(StorageStateError::CorruptRecord)
        };
        let stored_operation: [u8; 16] = take(16)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let effect_id = take(16)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let sandbox_id = take(16)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let workspace_handle = take(32)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let assignment_digest = take(32)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let generation = u64::from_be_bytes(
            take(8)?
                .try_into()
                .map_err(|_| StorageStateError::CorruptRecord)?,
        );
        let catalog_digest: [u8; 32] = take(32)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let physical_version = take(32)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let owner_id = take(16)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let owner_key_generation = u64::from_be_bytes(
            take(8)?
                .try_into()
                .map_err(|_| StorageStateError::CorruptRecord)?,
        );
        let controller_transaction_digest = take(32)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let catalog =
            CatalogBindingV1::from_publisher(generation, ObjectDigest::from_bytes(catalog_digest))
                .map_err(|_| StorageStateError::CorruptRecord)?;
        let binding = RepairGuardBindingV1 {
            operation_id: stored_operation,
            effect_id,
            sandbox_id,
            workspace_handle,
            assignment_digest,
            catalog,
            physical_version,
            owner_id,
            owner_key_generation,
            controller_transaction_digest,
        };
        binding
            .validate()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        if stored_operation != operation_id || cursor != BODY_BYTES {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(Self {
            binding,
            phase: GuardPhaseV1::decode(bytes[10])?,
        })
    }

    fn transaction(self, key: &StorageStateKey) -> Result<JournalTransaction, StorageStateError> {
        let record_key = record_key(self.binding.operation_id);
        let value = self.encode(key)?;
        let digest = Sha256::digest([TX_DOMAIN, record_key.as_slice(), value.as_slice()].concat());
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| StorageStateError::InvalidValue)?;
        JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                record_key,
                value,
            )],
        )
        .map_err(Into::into)
    }
}

fn record_key(operation_id: [u8; 16]) -> Vec<u8> {
    [KEY_PREFIX, operation_id.as_slice()].concat()
}

fn mac_state(
    key: &StorageStateKey,
    operation_id: [u8; 16],
    body: &[u8],
) -> Result<HmacSha256, StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(MAC_DOMAIN);
    mac.update(&[RecordNamespace::OperatorRecovery as u8]);
    mac.update(&record_key(operation_id));
    mac.update(body);
    Ok(mac)
}

fn mac(
    key: &StorageStateKey,
    operation_id: [u8; 16],
    body: &[u8],
) -> Result<[u8; 32], StorageStateError> {
    Ok(mac_state(key, operation_id, body)?
        .finalize()
        .into_bytes()
        .into())
}

pub(super) fn load(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<BTreeMap<[u8; 16], StorageRepairGuardRecordV1>, StorageStateError> {
    let mut guards = BTreeMap::new();
    let mut held = false;
    // The operator sidecar uses a different journal; this namespace is
    // reserved entirely for guards inside the Storage state journal.
    for (record_key, bytes) in journal.records(RecordNamespace::OperatorRecovery) {
        let operation = record_key
            .strip_prefix(KEY_PREFIX)
            .ok_or(StorageStateError::CorruptRecord)?;
        let operation_id: [u8; 16] = operation
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let record = StorageRepairGuardRecordV1::decode(operation_id, bytes, key)?;
        if record.is_held() {
            if held {
                return Err(StorageStateError::CorruptRecord);
            }
            held = true;
        }
        if guards.insert(operation_id, record).is_some() {
            return Err(StorageStateError::CorruptRecord);
        }
        if guards.len() > MAXIMUM_OPERATIONS {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(guards)
}

// These proof types have no production constructor. An authenticated Storage
// readback and Controller terminal readback must supply them in a later slice.
struct VerifiedStorageRepairGuardSourceV1(RepairGuardBindingV1);

struct VerifiedControllerRepairTerminalOutcomeV1 {
    binding: RepairGuardBindingV1,
    phase: GuardPhaseV1,
}

impl StorageTransactionStore {
    fn hold_repair_guard(
        &mut self,
        source: VerifiedStorageRepairGuardSourceV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let binding = source.0;
        binding.validate()?;
        if self.repair_guards.len() >= MAXIMUM_OPERATIONS
            || self.repair_guards.contains_key(&binding.operation_id)
            || self
                .repair_guards
                .values()
                .any(StorageRepairGuardRecordV1::is_held)
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let held = StorageRepairGuardRecordV1 {
            binding,
            phase: GuardPhaseV1::Held,
        };
        self.commit_journal(&held.transaction(&self.key)?)?;
        self.repair_guards.insert(binding.operation_id, held);
        Ok(())
    }

    fn retain_repair_guard_after_ambiguous_controller_outcome(
        &self,
        binding: RepairGuardBindingV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        match self.repair_guards.get(&binding.operation_id) {
            Some(record) if record.binding == binding && record.is_held() => Ok(()),
            _ => Err(StorageStateError::InvalidTransition),
        }
    }

    fn resolve_repair_guard(
        &mut self,
        outcome: VerifiedControllerRepairTerminalOutcomeV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let Some(current) = self.repair_guards.get(&outcome.binding.operation_id) else {
            return Err(StorageStateError::InvalidTransition);
        };
        if !current.is_held()
            || current.binding != outcome.binding
            || outcome.phase == GuardPhaseV1::Held
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let resolved = StorageRepairGuardRecordV1 {
            binding: outcome.binding,
            phase: outcome.phase,
        };
        self.commit_journal_unfenced(&resolved.transaction(&self.key)?)?;
        self.repair_guards
            .insert(outcome.binding.operation_id, resolved);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_key() -> StorageStateKey {
        StorageStateKey::new([1; 16], [2; 32]).unwrap()
    }

    fn binding(operation_id: [u8; 16]) -> RepairGuardBindingV1 {
        RepairGuardBindingV1 {
            operation_id,
            effect_id: [3; 16],
            sandbox_id: [20; 16],
            workspace_handle: [4; 32],
            assignment_digest: [5; 32],
            catalog: CatalogBindingV1::from_publisher(7, ObjectDigest::from_bytes([6; 32]))
                .unwrap(),
            physical_version: [7; 32],
            owner_id: [8; 16],
            owner_key_generation: 9,
            controller_transaction_digest: [10; 32],
        }
    }

    fn ordinary_transaction() -> JournalTransaction {
        JournalTransaction::new(
            [11; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                [12; 16].to_vec(),
                vec![13],
            )],
        )
        .unwrap()
    }

    #[test]
    fn held_guard_rejects_replay_and_ordinary_writes_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let first = binding([14; 16]);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        store
            .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
            .unwrap();
        assert!(
            store
                .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
                .is_err()
        );
        assert!(
            store
                .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(binding([15; 16])))
                .is_err()
        );
        assert!(store.commit_journal(&ordinary_transaction()).is_err());
        drop(store);

        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        assert!(
            reopened
                .repair_guards
                .get(&first.operation_id)
                .unwrap()
                .is_held()
        );
        reopened
            .retain_repair_guard_after_ambiguous_controller_outcome(first)
            .unwrap();
        assert!(reopened.commit_journal(&ordinary_transaction()).is_err());
        assert!(
            reopened
                .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
                .is_err()
        );
    }

    #[test]
    fn only_exact_verified_resolution_releases_the_write_gate() {
        let directory = tempfile::tempdir().unwrap();
        let first = binding([16; 16]);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        store
            .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
            .unwrap();
        let mut changed = first;
        changed.physical_version = [17; 32];
        assert!(
            store
                .resolve_repair_guard(VerifiedControllerRepairTerminalOutcomeV1 {
                    binding: changed,
                    phase: GuardPhaseV1::ControllerCommitted,
                })
                .is_err()
        );
        assert!(store.commit_journal(&ordinary_transaction()).is_err());
        store
            .resolve_repair_guard(VerifiedControllerRepairTerminalOutcomeV1 {
                binding: first,
                phase: GuardPhaseV1::ControllerCommitted,
            })
            .unwrap();
        store.commit_journal(&ordinary_transaction()).unwrap();
        drop(store);

        let reopened =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        assert!(
            !reopened
                .repair_guards
                .get(&first.operation_id)
                .unwrap()
                .is_held()
        );
    }

    #[test]
    fn tampered_guard_fails_closed_on_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let first = binding([18; 16]);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        store
            .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
            .unwrap();
        let mut altered = store
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &record_key(first.operation_id),
            )
            .unwrap()
            .to_vec();
        altered[100] ^= 1;
        store
            .journal
            .commit(
                &JournalTransaction::new(
                    [19; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::OperatorRecovery,
                        record_key(first.operation_id),
                        altered,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(store);

        assert!(StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).is_err());
    }

    #[test]
    fn lost_acquisition_response_reopens_as_held_without_redispatch() {
        let directory = tempfile::tempdir().unwrap();
        let first = binding([21; 16]);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        store.fail_after_next_journal_commit = true;

        assert!(
            store
                .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
                .is_err()
        );
        assert!(store.requires_reopen());
        drop(store);

        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        assert!(
            reopened
                .repair_guards
                .get(&first.operation_id)
                .unwrap()
                .is_held()
        );
        assert!(reopened.commit_journal(&ordinary_transaction()).is_err());
        assert!(
            reopened
                .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
                .is_err()
        );
    }

    #[test]
    fn two_authenticated_held_rows_fail_closed_on_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let first = binding([22; 16]);
        let second = binding([23; 16]);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).unwrap();
        store
            .hold_repair_guard(VerifiedStorageRepairGuardSourceV1(first))
            .unwrap();
        let injected = StorageRepairGuardRecordV1 {
            binding: second,
            phase: GuardPhaseV1::Held,
        };
        store
            .journal
            .commit(&injected.transaction(&store.key).unwrap())
            .unwrap();
        drop(store);

        assert!(StorageTransactionStore::open_for_test(directory.path(), state_key(), 0).is_err());
    }
}
