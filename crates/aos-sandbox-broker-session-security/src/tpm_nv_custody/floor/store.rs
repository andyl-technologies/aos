//! One private sidecar mechanics engine with closed Broker and Host adapters.
//!
//! Broker effects retain their original facade, captured custody and ordering.
//! Host construction accepts genuine Origins only and performs comparison and
//! native funding DATA work, never initialization, preparation writes or NV.
//! Canonical claims, signed main history and actual Journal codecs stay in
//! their existing owners. No injected parser, policy, transport or callback exists.

use aos_sandbox::{
    Journal, JournalLimits, JournalRecord, JournalTransaction,
    ProtectedJournalLockCustodyV1, ProtectedJournalPreflight, RecordNamespace,
};

use super::{
    CHECKPOINT_BYTES, INTENT_BYTES, FloorCheckpointV1, FloorErrorV1, FloorIntentV1,
    FloorProfileV1, HostFloorCheckpointDataV1, HostFloorIntentDataV1, hash_parts,
};
use crate::recovery::BrokerSidecarCustodyV1;
use crate::tpm_nv_custody::host::{HostOwnedJournalErrorV1, HostSidecarCustodyV1};

pub(crate) const CHECKPOINT_KEY: &[u8] = b"checkpoint";
pub(crate) const INTENT_KEY: &[u8] = b"intent";
pub(crate) const TRANSACTION_KEY: &[u8] = b"transaction";
const BROKER_PREPARE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.prepare.v1\0";
const BROKER_FINALIZE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.finalize.v1\0";
const HOST_PREPARE_DOMAIN: &[u8] = b"aos.runtime-deployment.tpm-floor.prepare.v1\0";
const HOST_FINALIZE_DOMAIN: &[u8] = b"aos.runtime-deployment.tpm-floor.finalize.v1\0";
const HOST_INITIAL_DOMAIN: &[u8] = b"aos.runtime-deployment.tpm-floor.initial-sidecar.v1\0";

/// Holds only the original Broker constructor's opaque captured custody.
pub(crate) struct BrokerSidecarStoreV1 {
    custody: BrokerSidecarCustodyV1,
    main_limits: JournalLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredBrokerFloorV1 {
    pub(crate) checkpoint: FloorCheckpointV1,
    pub(crate) prepared: Option<(FloorIntentV1, JournalTransaction)>,
    sequence: u64,
}

/// Retains the original Broker final suffix; it cannot be substituted for Host.
pub(crate) struct FinalSuffixPreflightV1 {
    token: ProtectedJournalPreflight,
    transaction: JournalTransaction,
}

/// Selects only typed canonical DATA; it grants no construction or custody.
#[derive(Clone, Copy)]
enum SidecarIntentDataV1 {
    Broker(FloorIntentV1),
    Host(HostFloorIntentDataV1),
}

impl SidecarIntentDataV1 {
    fn namespace(self) -> RecordNamespace {
        match self {
            Self::Broker(_) => RecordNamespace::BrokerSessionTraffic,
            Self::Host(_) => RecordNamespace::HostCatalogReconciliation,
        }
    }

    fn prepare_domain(self) -> &'static [u8] {
        match self {
            Self::Broker(_) => BROKER_PREPARE_DOMAIN,
            Self::Host(_) => HOST_PREPARE_DOMAIN,
        }
    }

    fn finalize_domain(self) -> &'static [u8] {
        match self {
            Self::Broker(_) => BROKER_FINALIZE_DOMAIN,
            Self::Host(_) => HOST_FINALIZE_DOMAIN,
        }
    }

    fn encode(self) -> [u8; INTENT_BYTES] {
        match self {
            Self::Broker(intent) => intent.encode(),
            Self::Host(intent) => intent.encode(),
        }
    }

    fn target_bytes(self) -> [u8; CHECKPOINT_BYTES] {
        match self {
            Self::Broker(intent) => intent.target().encode(),
            Self::Host(intent) => intent.target().encode(),
        }
    }
}

impl BrokerSidecarStoreV1 {
    pub(crate) fn from_broker(custody: BrokerSidecarCustodyV1) -> Self {
        let main_limits = custody.main_limits();
        Self { custody, main_limits }
    }

    pub(crate) fn loan_lock_custody(&self) -> Result<ProtectedJournalLockCustodyV1, FloorErrorV1> {
        self.validate_held()?;
        self.custody.journal()
            .loan_protected_lock_custody()
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn fixture_limits(
        main_limits: JournalLimits,
    ) -> Result<JournalLimits, FloorErrorV1> {
        sidecar_limits(main_limits)
    }

    #[cfg(test)]
    pub(crate) fn fixture_preparation(
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> JournalTransaction {
        prepare_transaction(SidecarIntentDataV1::Broker(intent), transaction, limits).unwrap()
    }

    #[cfg(test)]
    pub(crate) fn fixture_finalization(intent: FloorIntentV1) -> JournalTransaction {
        finalize_transaction(SidecarIntentDataV1::Broker(intent)).unwrap()
    }

    #[cfg(test)]
    pub(crate) fn fixture_preflight(
        &mut self,
        transactions: &[JournalTransaction],
    ) -> Result<(), FloorErrorV1> {
        let authority = self.custody.journal_mut()
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let token = authority
            .preflight_transactions(transactions)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        authority
            .validate_preflight_for_effect(&token, transactions)
            .map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(crate) fn validate_held(&self) -> Result<(), FloorErrorV1> {
        self.custody.validate_held()
    }

    pub(crate) fn read(&mut self, profile: FloorProfileV1) -> Result<StoredBrokerFloorV1, FloorErrorV1> {
        self.validate_held()?;
        let authority = self.custody.journal_mut()
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
        let stored = StoredBrokerFloorV1 {
            checkpoint,
            prepared,
            sequence: snapshot.sequence(),
        };
        self.validate_held()?;
        Ok(stored)
    }

    pub(crate) fn require_same(
        &mut self,
        stored: &StoredBrokerFloorV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        if &self.read(profile)? == stored {
            Ok(())
        } else {
            Err(FloorErrorV1::Diverged)
        }
    }

    pub(crate) fn prepare(
        &mut self,
        profile: FloorProfileV1,
        old: &StoredBrokerFloorV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.require_same(old, profile)?;
        if old.prepared.is_some() {
            return Err(FloorErrorV1::Diverged);
        }
        intent.require_predecessor(profile, old.checkpoint)?;
        intent.require_transaction(transaction)?;
        let prepare = prepare_transaction(
            SidecarIntentDataV1::Broker(intent), transaction, self.main_limits,
        )?;
        let finalize = finalize_transaction(SidecarIntentDataV1::Broker(intent))?;
        let mut authority = self.custody.journal_mut()
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

    pub(crate) fn preflight_final(
        &mut self,
        stored: &StoredBrokerFloorV1,
        profile: FloorProfileV1,
    ) -> Result<FinalSuffixPreflightV1, FloorErrorV1> {
        self.require_same(stored, profile)?;
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        let transaction = finalize_transaction(SidecarIntentDataV1::Broker(*intent))?;
        let authority = self.custody.journal_mut()
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let token = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(FinalSuffixPreflightV1 { token, transaction })
    }

    /// Checks the retained suffix immediately before its dependent NV/main effect.
    pub(crate) fn validate_final_preflight(
        &mut self,
        suffix: &FinalSuffixPreflightV1,
        stored: &StoredBrokerFloorV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        self.require_same(stored, profile)?;
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if suffix.transaction != finalize_transaction(SidecarIntentDataV1::Broker(*intent))? {
            return Err(FloorErrorV1::Diverged);
        }
        let authority = self.custody.journal_mut()
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

    pub(crate) fn finalize(
        &mut self,
        profile: FloorProfileV1,
        stored: &StoredBrokerFloorV1,
    ) -> Result<(), FloorErrorV1> {
        self.require_same(stored, profile)?;
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        let transaction = finalize_transaction(SidecarIntentDataV1::Broker(*intent))?;
        let mut authority = self.custody.journal_mut()
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
    intent: SidecarIntentDataV1,
    transaction: &JournalTransaction,
    main_limits: JournalLimits,
) -> Result<JournalTransaction, FloorErrorV1> {
    let id = transaction_id(intent.prepare_domain(), intent)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                intent.namespace(),
                INTENT_KEY.to_vec(),
                intent.encode().to_vec(),
            ),
            JournalRecord::put(
                intent.namespace(),
                TRANSACTION_KEY.to_vec(),
                transaction
                    .encode_prepared_v1(main_limits)
                    .map_err(|_| FloorErrorV1::Encoding)?,
            ),
        ],
    )
    .map_err(|_| FloorErrorV1::Encoding)
}

fn finalize_transaction(intent: SidecarIntentDataV1) -> Result<JournalTransaction, FloorErrorV1> {
    JournalTransaction::new(
        transaction_id(intent.finalize_domain(), intent)?,
        vec![
            JournalRecord::put(
                intent.namespace(),
                CHECKPOINT_KEY.to_vec(),
                intent.target_bytes().to_vec(),
            ),
            JournalRecord::delete(intent.namespace(), INTENT_KEY.to_vec()),
            JournalRecord::delete(
                intent.namespace(),
                TRANSACTION_KEY.to_vec(),
            ),
        ],
    )
    .map_err(|_| FloorErrorV1::Encoding)
}

fn transaction_id(domain: &[u8], intent: SidecarIntentDataV1) -> Result<[u8; 16], FloorErrorV1> {
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
    crate::tpm_nv_custody::sidecar_sequence_v1(ordinal, pending)
}

pub(crate) fn sidecar_limits(main: JournalLimits) -> Result<JournalLimits, FloorErrorV1> {
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

/// Owns only the actual Host constructor's original sidecar capsule.
///
/// Its private construction takes no Journal, path, UID or limit DATA factory.
/// Only a genuine admitted Host owner can construct the closed capsule.
pub(in crate::tpm_nv_custody) struct HostSidecarStoreV1<'origin, 'startup> {
    custody: HostSidecarCustodyV1<'origin, 'startup>,
    main_limits: JournalLimits,
}

/// Holds exact original sidecar suffix funding DATA, not append permission.
pub(in crate::tpm_nv_custody) struct HostSuffixPreflightV1 {
    token: ProtectedJournalPreflight,
    transactions: Vec<JournalTransaction>,
}

impl<'origin, 'startup> HostSidecarStoreV1<'origin, 'startup> {
    pub(in crate::tpm_nv_custody) fn from_host(
        custody: HostSidecarCustodyV1<'origin, 'startup>,
    ) -> Self {
        let main_limits = custody.main_limits();
        Self { custody, main_limits }
    }

    pub(in crate::tpm_nv_custody) fn validate_held(
        &self,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        self.custody.validate_held()
    }

    // Only the enclosing private Host owner reborrows this same original
    // into Core's genuine pair guard; no raw writer escapes that owner.
    pub(in crate::tpm_nv_custody) fn original_mut(&mut self) -> &mut Journal {
        self.custody.journal_mut()
    }

    pub(in crate::tpm_nv_custody) fn loan_host_lock(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, HostOwnedJournalErrorV1> {
        self.validate_held()?;
        let loan = self.custody.journal_mut().loan_protected_lock_custody()?;
        self.validate_held()?;
        Ok(loan)
    }

    pub(in crate::tpm_nv_custody) fn require_projection(
        &mut self,
        checkpoint: HostFloorCheckpointDataV1,
        prepared: Option<(HostFloorIntentDataV1, &JournalTransaction)>,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        self.validate_held()?;
        let checkpoint_bytes = checkpoint.encode();
        let pending = prepared.map(|(intent, transaction)| {
            transaction.encode_prepared_v1(self.main_limits)
                .map(|bytes| (intent.encode(), bytes))
        }).transpose()?;
        let authority = self.custody.journal_mut()
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
        let snapshot = authority.snapshot()?;
        let expected_rows = if pending.is_some() { 3 } else { 1 };
        let mut rows = 0_usize;
        for (key, value) in authority.records()? {
            let matches = match key {
                CHECKPOINT_KEY => value == checkpoint_bytes.as_slice(),
                INTENT_KEY => pending.as_ref().is_some_and(|(intent, _)| value == intent.as_slice()),
                TRANSACTION_KEY => pending.as_ref().is_some_and(|(_, bytes)| value == bytes.as_slice()),
                _ => false,
            };
            if !matches {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            rows = rows.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
        }
        if rows != expected_rows
            || snapshot.sequence() != sidecar_sequence(checkpoint.ordinal(), pending.is_some())?
        {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        authority.validate_snapshot_for_effect(&snapshot)?;
        drop(authority);
        self.validate_held()
    }

    /// Funds both prepare/finalize, or the fresh remaining final suffix only.
    ///
    /// No transaction is committed. A later prepare makes a two-TX token
    /// stale: actual pending state must be reread and this final-only path
    /// reacquired at the new original sidecar sequence before any NV/main work.
    pub(in crate::tpm_nv_custody) fn fund_suffix(
        &mut self,
        intent: HostFloorIntentDataV1,
        transaction: &JournalTransaction,
        already_prepared: bool,
    ) -> Result<HostSuffixPreflightV1, HostOwnedJournalErrorV1> {
        self.validate_held()?;
        intent.require_transaction(transaction)?;
        let finalize = finalize_transaction(SidecarIntentDataV1::Host(intent))?;
        let transactions = if already_prepared {
            vec![finalize]
        } else {
            vec![
                prepare_transaction(SidecarIntentDataV1::Host(intent), transaction, self.main_limits)?,
                finalize,
            ]
        };
        let authority = self.custody.journal_mut()
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
        let token = authority.preflight_transactions(&transactions)?;
        authority.validate_preflight_for_effect(&token, &transactions)?;
        drop(authority);
        self.validate_held()?;
        Ok(HostSuffixPreflightV1 { token, transactions })
    }

    pub(in crate::tpm_nv_custody) fn validate_suffix(
        &mut self,
        suffix: &HostSuffixPreflightV1,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        self.validate_held()?;
        let authority = self.custody.journal_mut()
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
        authority.validate_preflight_for_effect(&suffix.token, &suffix.transactions)?;
        drop(authority);
        self.validate_held()
    }
}

/// Builds canonical expected initialization DATA; it writes or seeds nothing.
pub(in crate::tpm_nv_custody) fn host_initial_transaction(
    checkpoint: HostFloorCheckpointDataV1,
) -> Result<JournalTransaction, FloorErrorV1> {
    let bytes = checkpoint.encode();
    let digest = hash_parts(HOST_INITIAL_DOMAIN, &[&bytes]);
    let id: [u8; 16] = digest[..16].try_into().map_err(|_| FloorErrorV1::Encoding)?;
    JournalTransaction::new(id, vec![JournalRecord::put(
        RecordNamespace::HostCatalogReconciliation, CHECKPOINT_KEY.to_vec(), bytes.to_vec(),
    )]).map_err(|_| FloorErrorV1::Encoding)
}

pub(in crate::tpm_nv_custody) fn host_prepare_transaction(
    intent: HostFloorIntentDataV1,
    transaction: &JournalTransaction,
    main_limits: JournalLimits,
) -> Result<JournalTransaction, FloorErrorV1> {
    prepare_transaction(SidecarIntentDataV1::Host(intent), transaction, main_limits)
}

pub(in crate::tpm_nv_custody) fn host_finalize_transaction(
    intent: HostFloorIntentDataV1,
) -> Result<JournalTransaction, FloorErrorV1> {
    finalize_transaction(SidecarIntentDataV1::Host(intent))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inert_main_limits() -> JournalLimits {
        // Shape-only DATA; no genuine Origins or protected owner is created.
        JournalLimits {
            maximum_journal_bytes: 1048576,
            maximum_record_bytes: 1024,
            maximum_key_bytes: 32,
            maximum_records_per_transaction: 1,
            maximum_transaction_bytes: 1024,
            maximum_transactions: 321,
            maximum_materialized_bytes: 262144,
            maximum_materialized_records: 321,
        }
    }

    #[test]
    fn unrun_shared_sidecar_limits_derive_all_eight_host_geometry_fields_once() {
        let main = inert_main_limits();

        let limits = sidecar_limits(main).unwrap();

        assert_eq!(JournalTransaction::maximum_prepared_bytes_v1(main).unwrap(), 1060);
        assert_eq!(limits, JournalLimits {
            maximum_journal_bytes: 1048576,
            maximum_record_bytes: 1078,
            maximum_key_bytes: 11,
            maximum_records_per_transaction: 3,
            maximum_transaction_bytes: 1415,
            maximum_transactions: 643,
            maximum_materialized_bytes: 1567,
            maximum_materialized_records: 3,
        });
    }

    #[test]
    fn unrun_host_initial_data_uuid_is_exact_domain_prefix_without_bit_rewrite() {
        let checkpoint = HostFloorCheckpointDataV1::initial(
            [7; 32], super::super::FloorCutV1::new(4, [8; 32]).unwrap(),
        ).unwrap();
        let expected = hash_parts(HOST_INITIAL_DOMAIN, &[&checkpoint.encode()]);

        let initial = host_initial_transaction(checkpoint).unwrap();

        assert_eq!(initial.id().as_slice(), &expected[..16]);
        assert_eq!(initial.records().len(), 1);
        assert_eq!(initial.records()[0].namespace(), RecordNamespace::HostCatalogReconciliation);
        assert_eq!(initial.records()[0].key(), CHECKPOINT_KEY);
        assert_eq!(initial.records()[0].value(), Some(checkpoint.encode().as_slice()));
    }

    #[test]
    fn unrun_shared_sidecar_limit_derivation_preserves_overflow_refusal() {
        let mut main = inert_main_limits();
        main.maximum_transactions = usize::MAX;

        let result = sidecar_limits(main);

        assert_eq!(result, Err(FloorErrorV1::Encoding));
    }
}
