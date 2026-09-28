//! Exact sidecar state, fixed append geometry, and capacity preflight.
//!
//! Runtime accepts an already seeded checkpoint only. The opaque Journal is
//! never exposed for another append or compaction. A pending preparation keeps
//! its exact final suffix available through the only permitted state change.

use std::path::{Path, PathBuf};

use aos_sandbox::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, ProtectedJournalLockCustodyV1,
    ProtectedJournalPreflight, RecordNamespace,
};

use super::super::format::{CHECKPOINT_BYTES, INTENT_BYTES};
use super::super::{FloorCheckpointV1, FloorErrorV1, FloorIntentV1, FloorProfileV1, hash_parts};
use crate::recovery::journal::owner::JournalOwnerV1;

pub(super) const NAME: &str = "session-floor.journal";
pub(super) const CHECKPOINT_KEY: &[u8] = b"checkpoint";
const INTENT_KEY: &[u8] = b"intent";
const TRANSACTION_KEY: &[u8] = b"transaction";
const PREPARE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.prepare.v1\0";
const FINALIZE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.finalize.v1\0";

pub(super) struct FloorStoreV1 {
    journal: Journal,
    main_limits: JournalLimits,
    custody: StoreCustodyV1,
}

enum StoreCustodyV1 {
    Production {
        owner: JournalOwnerV1,
        directory: PathBuf,
    },
    #[cfg(test)]
    Fixture { uid: u32, directory: PathBuf },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredFloorV1 {
    pub(super) checkpoint: FloorCheckpointV1,
    pub(super) prepared: Option<(FloorIntentV1, JournalTransaction)>,
    sequence: u64,
}

/// Retains the exact remaining suffix at one actual sidecar instance/sequence.
pub(super) struct FinalSuffixPreflightV1 {
    token: ProtectedJournalPreflight,
    transaction: JournalTransaction,
}

impl FloorStoreV1 {
    pub(super) fn loan_lock_custody(&self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1> {
        self.validate_held()?;
        self.journal
            .loan_protected_lock_custody()
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(super) fn open(
        owner: JournalOwnerV1,
        directory: &Path,
        main_limits: JournalLimits,
    ) -> Result<Self, FloorErrorV1> {
        let limits = sidecar_limits(main_limits)?;
        let (journal, _) = owner
            .open_existing(directory, NAME, limits)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        owner
            .validate_held(&journal, directory, NAME)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(Self {
            journal,
            main_limits,
            custody: StoreCustodyV1::Production {
                owner,
                directory: directory.to_path_buf(),
            },
        })
    }

    #[cfg(test)]
    pub(super) fn open_fixture(
        directory: &Path,
        main_limits: JournalLimits,
        uid: u32,
    ) -> Result<Self, FloorErrorV1> {
        let (journal, _) = Journal::open_existing_protected_at_uid(
            directory,
            NAME,
            sidecar_limits(main_limits)?,
            uid,
        )
        .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(Self {
            journal,
            main_limits,
            custody: StoreCustodyV1::Fixture {
                uid,
                directory: directory.to_path_buf(),
            },
        })
    }

    #[cfg(test)]
    pub(super) fn fixture_limits(
        main_limits: JournalLimits,
    ) -> Result<JournalLimits, FloorErrorV1> {
        sidecar_limits(main_limits)
    }

    #[cfg(test)]
    pub(super) fn fixture_preparation(
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> JournalTransaction {
        prepare_transaction(intent, transaction, limits).unwrap()
    }

    #[cfg(test)]
    pub(super) fn fixture_finalization(intent: FloorIntentV1) -> JournalTransaction {
        finalize_transaction(intent).unwrap()
    }

    #[cfg(test)]
    pub(super) fn fixture_preflight(
        &mut self,
        transactions: &[JournalTransaction],
    ) -> Result<(), FloorErrorV1> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let token = authority
            .preflight_transactions(transactions)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .validate_preflight_for_effect(&token, transactions)
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(super) fn validate_held(&self) -> Result<(), FloorErrorV1> {
        let result = match &self.custody {
            StoreCustodyV1::Production { owner, directory } => {
                owner.validate_held(&self.journal, directory, NAME)
            }
            #[cfg(test)]
            StoreCustodyV1::Fixture { uid, directory } => self
                .journal
                .validate_held_protected_at_uid_for_test(directory, NAME, *uid),
        };
        result.map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(super) fn read(&mut self, profile: FloorProfileV1) -> Result<StoredFloorV1, FloorErrorV1> {
        self.validate_held()?;
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let mut checkpoint = None;
        let mut intent = None;
        let mut transaction = None;
        for (key, value) in authority.records().map_err(|_| FloorErrorV1::Unavailable)? {
            match key {
                CHECKPOINT_KEY => {
                    checkpoint = Some(FloorCheckpointV1::decode(value)?);
                }
                INTENT_KEY => {
                    intent = Some(FloorIntentV1::decode(profile, value)?);
                }
                TRANSACTION_KEY => {
                    transaction = Some(
                        JournalTransaction::decode_prepared_v1(value, self.main_limits)
                            .map_err(|_| FloorErrorV1::Encoding)?,
                    );
                }
                _ => return Err(FloorErrorV1::Encoding),
            }
        }
        let checkpoint = checkpoint.ok_or(FloorErrorV1::Unavailable)?;
        checkpoint.require_profile(profile)?;
        let prepared = match (intent, transaction) {
            (None, None) => None,
            (Some(intent), Some(transaction)) => {
                intent.require_predecessor(profile, checkpoint)?;
                intent.require_transaction(&transaction)?;
                Some((intent, transaction))
            }
            _ => return Err(FloorErrorV1::Encoding),
        };
        let expected_sequence = sidecar_sequence(checkpoint.ordinal(), prepared.is_some())?;
        if snapshot.sequence() != expected_sequence {
            return Err(FloorErrorV1::Diverged);
        }
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let stored = StoredFloorV1 {
            checkpoint,
            prepared,
            sequence: snapshot.sequence(),
        };
        self.validate_held()?;
        Ok(stored)
    }

    pub(super) fn require_same(
        &mut self,
        stored: &StoredFloorV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        if &self.read(profile)? == stored {
            Ok(())
        } else {
            Err(FloorErrorV1::Diverged)
        }
    }

    pub(super) fn prepare(
        &mut self,
        profile: FloorProfileV1,
        old: &StoredFloorV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.require_same(old, profile)?;
        if old.prepared.is_some() {
            return Err(FloorErrorV1::Diverged);
        }
        intent.require_predecessor(profile, old.checkpoint)?;
        intent.require_transaction(transaction)?;
        let prepare = prepare_transaction(intent, transaction, self.main_limits)?;
        let finalize = finalize_transaction(intent)?;
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let transactions = [prepare, finalize];
        let preflight = authority
            .preflight_transactions(&transactions)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .validate_preflight_for_effect(&preflight, &transactions)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .commit(&transactions[0])
            .map_err(|_| FloorErrorV1::Unavailable)?;
        drop(authority);
        let retained = self.read(profile)?;
        if retained.checkpoint != old.checkpoint
            || !retained
                .prepared
                .as_ref()
                .is_some_and(|(retained_intent, retained_transaction)| {
                    *retained_intent == intent && retained_transaction == transaction
                })
        {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    pub(super) fn preflight_final(
        &mut self,
        stored: &StoredFloorV1,
        profile: FloorProfileV1,
    ) -> Result<FinalSuffixPreflightV1, FloorErrorV1> {
        self.require_same(stored, profile)?;
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        let transaction = finalize_transaction(*intent)?;
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let token = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(FinalSuffixPreflightV1 { token, transaction })
    }

    /// Checks the retained suffix immediately before its dependent NV/main effect.
    pub(super) fn validate_final_preflight(
        &mut self,
        suffix: &FinalSuffixPreflightV1,
        stored: &StoredFloorV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        self.require_same(stored, profile)?;
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if suffix.transaction != finalize_transaction(*intent)? {
            return Err(FloorErrorV1::Diverged);
        }
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .validate_preflight_for_effect(
                &suffix.token,
                core::slice::from_ref(&suffix.transaction),
            )
            .map_err(|_| FloorErrorV1::Unavailable)?;
        drop(authority);
        self.validate_held()
    }

    pub(super) fn finalize(
        &mut self,
        profile: FloorProfileV1,
        stored: &StoredFloorV1,
    ) -> Result<(), FloorErrorV1> {
        self.require_same(stored, profile)?;
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        let transaction = finalize_transaction(*intent)?;
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .commit(&transaction)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        drop(authority);
        let retained = self.read(profile)?;
        if retained.checkpoint != intent.target() || retained.prepared.is_some() {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }
}

fn prepare_transaction(
    intent: FloorIntentV1,
    transaction: &JournalTransaction,
    main_limits: JournalLimits,
) -> Result<JournalTransaction, FloorErrorV1> {
    let id = transaction_id(PREPARE_DOMAIN, intent)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                INTENT_KEY.to_vec(),
                intent.encode().to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                TRANSACTION_KEY.to_vec(),
                transaction
                    .encode_prepared_v1(main_limits)
                    .map_err(|_| FloorErrorV1::Encoding)?,
            ),
        ],
    )
    .map_err(|_| FloorErrorV1::Encoding)
}

fn finalize_transaction(intent: FloorIntentV1) -> Result<JournalTransaction, FloorErrorV1> {
    JournalTransaction::new(
        transaction_id(FINALIZE_DOMAIN, intent)?,
        vec![
            JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                CHECKPOINT_KEY.to_vec(),
                intent.target().encode().to_vec(),
            ),
            JournalRecord::delete(RecordNamespace::BrokerSessionTraffic, INTENT_KEY.to_vec()),
            JournalRecord::delete(
                RecordNamespace::BrokerSessionTraffic,
                TRANSACTION_KEY.to_vec(),
            ),
        ],
    )
    .map_err(|_| FloorErrorV1::Encoding)
}

fn transaction_id(domain: &[u8], intent: FloorIntentV1) -> Result<[u8; 16], FloorErrorV1> {
    let digest = hash_parts(domain, &[&intent.encode()]);
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| FloorErrorV1::Encoding)?;
    if id == [0; 16] {
        return Err(FloorErrorV1::Encoding);
    }
    Ok(id)
}

/// An ordinal is NV-bound, so fixed sidecar geometry cannot be reset by compaction.
fn sidecar_sequence(ordinal: u64, pending: bool) -> Result<u64, FloorErrorV1> {
    ordinal
        .checked_sub(1)
        .and_then(|count| count.checked_mul(9))
        .and_then(|frames| frames.checked_add(if pending { 8 } else { 4 }))
        .filter(|sequence| *sequence != u64::MAX)
        .ok_or(FloorErrorV1::Encoding)
}

fn sidecar_limits(main: JournalLimits) -> Result<JournalLimits, FloorErrorV1> {
    let encoded =
        JournalTransaction::maximum_prepared_bytes_v1(main).map_err(|_| FloorErrorV1::Encoding)?;
    let prepared_record_bytes = encoded
        .checked_add(TRANSACTION_KEY.len() + 7)
        .ok_or(FloorErrorV1::Encoding)?;
    let record_bytes = prepared_record_bytes
        .max(INTENT_BYTES + INTENT_KEY.len() + 7)
        .max(CHECKPOINT_BYTES + CHECKPOINT_KEY.len() + 7);
    let transaction_bytes = prepared_record_bytes
        .checked_add(INTENT_BYTES + INTENT_KEY.len() + 7)
        .ok_or(FloorErrorV1::Encoding)?
        .max(
            CHECKPOINT_BYTES + CHECKPOINT_KEY.len() + INTENT_KEY.len() + TRANSACTION_KEY.len() + 21,
        );
    let materialized_bytes = encoded
        .checked_add(
            CHECKPOINT_BYTES
                + INTENT_BYTES
                + CHECKPOINT_KEY.len()
                + INTENT_KEY.len()
                + TRANSACTION_KEY.len(),
        )
        .ok_or(FloorErrorV1::Encoding)?;
    let maximum_transactions = main
        .maximum_transactions
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or(FloorErrorV1::Encoding)?;
    Ok(JournalLimits {
        maximum_journal_bytes: main.maximum_journal_bytes,
        maximum_record_bytes: record_bytes,
        maximum_key_bytes: TRANSACTION_KEY.len(),
        maximum_records_per_transaction: 3,
        maximum_transaction_bytes: transaction_bytes,
        maximum_transactions,
        maximum_materialized_bytes: materialized_bytes,
        maximum_materialized_records: 3,
    })
}
