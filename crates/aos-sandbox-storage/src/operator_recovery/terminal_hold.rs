//! Protected sidecar custody for the existing Repair terminal continuation.
//!
//! A reserved row closes ordinary dispatch before physical reobservation. A
//! held row retains the complete signed claims and both the original witness
//! and any current-process reacquisition. Historical signatures never reopen
//! dispatch. Only the exact Controller ACK, durably read back by this owner,
//! produces the move-only settlement token consumed by the runtime frame.
//!
//! ```text
//! AOSOSH04 | phase:u8 | zero[7] | state-cut[32] | original-header[652]
//!          | reconnect(mode/request/deadline/signature)[89]
//!          | original-witness[208] | current-witness[208]
//!          | settlement[208] | owner-release-signature[64]
//! key = sha256(hold-key-domain | original-effect-id | original-request-cut)
//! ```

use aos_sandbox_protocol::operator_storage_repair_terminal_v4::{
    RepairTerminalModeV4, RepairTerminalRequestV4, RepairTerminalSettlementV4,
    RepairTerminalWitnessV4,
};
use ed25519_dalek::{Signature, Signer as _};

use super::*;

pub(super) const HOLD_MAGIC: &[u8; 8] = b"AOSOSH04";
const BYTES: usize = 1477;
const RESERVED: u8 = 1;
const HELD: u8 = 2;
const SETTLED: u8 = 3;
const KEY_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-owner-hold-key.v4\0";
const TX_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-owner-hold-transaction.v4\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-owner-live-cut.v4\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-owner-release.v4\0";

/// Can be constructed only after actual owner settlement and exact readback.
pub(crate) struct DurableRepairSettlementV4 {
    state_cut: [u8; 32],
    release: Vec<u8>,
    key: [u8; 32],
    request_cut: [u8; 32],
    owner_instance: std::sync::Arc<()>,
}

impl DurableRepairSettlementV4 {
    /// Returns the actual settled Runtime state cut.
    pub(crate) fn state_cut(&self) -> [u8; 32] {
        self.state_cut
    }

    /// Returns the complete signed ACK and owner release.
    pub(crate) fn release(&self) -> &[u8] {
        &self.release
    }

    /// Joins an actual durable owner release to the original deferred debt.
    pub(crate) fn matches_debt(&self, debt: &OperatorRepairStartupDebtV4) -> bool {
        std::sync::Arc::ptr_eq(&self.owner_instance, &debt.owner_instance)
            && self.key == debt.key
            && self.request_cut == debt.request_cut
            && (debt.state_cut == [0; 32] || self.state_cut == debt.state_cut)
    }
}

/// Retains the actual existing writer's authenticated startup classification.
pub(crate) enum OperatorRepairStartupCustodyV4 {
    /// The exact existing writer has no unresolved terminal hold.
    Clear(OperatorRepairStartupClearV4),
    /// One validated original hold excludes ordinary startup mutation.
    Unresolved(OperatorRepairStartupDebtV4),
}

/// Contains an existing-owner snapshot with no unresolved terminal debt.
pub(crate) struct OperatorRepairStartupClearV4 {
    snapshot: aos_sandbox::ProtectedJournalSnapshot,
    owner_instance: std::sync::Arc<()>,
}

/// Contains one fully validated original hold, never caller-supplied gate state.
pub(crate) struct OperatorRepairStartupDebtV4 {
    snapshot: aos_sandbox::ProtectedJournalSnapshot,
    owner_instance: std::sync::Arc<()>,
    key: [u8; 32],
    request_cut: [u8; 32],
    original_header: [u8; 652],
    state_cut: [u8; 32],
}

struct HeldRecordV4([u8; BYTES]);

impl HeldRecordV4 {
    fn reserved(request: &RepairTerminalRequestV4) -> Self {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(HOLD_MAGIC);
        bytes[8] = RESERVED;
        bytes[48..700].copy_from_slice(request.signed_header());
        Self(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageOperatorRecoveryErrorV1> {
        let bytes: [u8; BYTES] = bytes.try_into().map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        if &bytes[..8] != HOLD_MAGIC || bytes[9..16] != [0; 7]
            || !matches!(bytes[8], RESERVED | HELD | SETTLED)
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        Ok(Self(bytes))
    }

    fn original(&self, owner: &StorageOperatorRecoveryOwnerV1) -> Result<RepairTerminalRequestV4, StorageOperatorRecoveryErrorV1> {
        RepairTerminalRequestV4::verify_retained_signed_header(&self.0[48..700], &owner.controller_key, owner.controller_key_generation)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)
    }

    fn current(&self, owner: &StorageOperatorRecoveryOwnerV1) -> Result<RepairTerminalRequestV4, StorageOperatorRecoveryErrorV1> {
        let mut header = self.0[48..700].to_vec();
        header[8] = self.0[700];
        header[16..40].copy_from_slice(&self.0[701..725]);
        header[588..652].copy_from_slice(&self.0[725..789]);
        RepairTerminalRequestV4::verify_retained_signed_header(&header, &owner.controller_key, owner.controller_key_generation)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)
    }

    fn state_cut(&self) -> [u8; 32] {
        let mut cut = [0; 32];
        cut.copy_from_slice(&self.0[16..48]);
        cut
    }
}

impl StorageOperatorRecoveryOwnerV1 {
    /// Classifies actual retained hold state without seeding or mutating it.
    ///
    /// # Errors
    ///
    /// Requires reopen for corrupt, uncertain, foreign, or multiply unresolved custody.
    pub(crate) fn operator_repair_startup_custody_v4(
        &mut self,
    ) -> Result<OperatorRepairStartupCustodyV4, crate::StorageRuntimeError> {
        self.startup_custody().map_err(|_| crate::StorageRuntimeError::ReopenRequired)
    }

    /// Rechecks the exact same protected owner and unchanged journal snapshot.
    ///
    /// # Errors
    ///
    /// Requires reopen after another writer, any journal mutation, or lost protection.
    pub(crate) fn recheck_operator_repair_startup_custody_v4(
        &mut self,
        custody: &OperatorRepairStartupCustodyV4,
    ) -> Result<(), crate::StorageRuntimeError> {
        let (snapshot, instance) = match custody {
            OperatorRepairStartupCustodyV4::Clear(clear) => (&clear.snapshot, &clear.owner_instance),
            OperatorRepairStartupCustodyV4::Unresolved(debt) => (&debt.snapshot, &debt.owner_instance),
        };
        if !std::sync::Arc::ptr_eq(instance, &self.startup_instance) {
            return Err(crate::StorageRuntimeError::ReopenRequired);
        }
        self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)
            .and_then(|authority| authority.validate_snapshot_for_effect(snapshot))
            .map_err(|_| crate::StorageRuntimeError::ReopenRequired)
    }

    /// Refreshes only a known unresolved lineage through actual owner transitions.
    ///
    /// A new hold, another owner, a changed original proposal, or a settled row
    /// cannot masquerade as the same deferred startup debt. Exact snapshots
    /// remain mandatory around each mutation-free physical reobservation.
    ///
    /// # Errors
    ///
    /// Requires reopen for foreign owner, changed lineage/state cut or settled debt.
    pub(crate) fn refresh_operator_repair_startup_custody_v4(
        &mut self,
        previous: &OperatorRepairStartupCustodyV4,
    ) -> Result<OperatorRepairStartupCustodyV4, crate::StorageRuntimeError> {
        let OperatorRepairStartupCustodyV4::Unresolved(previous) = previous else {
            self.recheck_operator_repair_startup_custody_v4(previous)?;
            return self.operator_repair_startup_custody_v4();
        };
        if !std::sync::Arc::ptr_eq(&previous.owner_instance, &self.startup_instance) {
            return Err(crate::StorageRuntimeError::ReopenRequired);
        }
        let current = self.operator_repair_startup_custody_v4()?;
        let OperatorRepairStartupCustodyV4::Unresolved(debt) = &current else {
            return Err(crate::StorageRuntimeError::ReopenRequired);
        };
        if debt.key != previous.key
            || debt.request_cut != previous.request_cut
            || debt.original_header != previous.original_header
            || debt.snapshot.sequence() < previous.snapshot.sequence()
            || (previous.state_cut != [0; 32] && debt.state_cut != previous.state_cut)
        {
            return Err(crate::StorageRuntimeError::ReopenRequired);
        }

        Ok(current)
    }

    fn startup_custody(&mut self) -> Result<OperatorRepairStartupCustodyV4, StorageOperatorRecoveryErrorV1> {
        let rows: Vec<_> = self.journal
            .claim_protected_authority(RecordNamespace::OperatorRecovery)?
            .records()?
            .filter(|(_, value)| value.starts_with(HOLD_MAGIC))
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let mut unresolved = None;
        for (key, value) in rows {
            self.validate_terminal_row_v4(&key, &value)?;
            let record = HeldRecordV4::decode(&value)?;
            if record.0[8] == SETTLED {
                continue;
            }
            if unresolved.is_some() {
                return Err(StorageOperatorRecoveryErrorV1::Binding);
            }
            let original = record.original(self)?;
            let key = key.try_into().map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
            let original_header = original.signed_header().try_into()
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
            unresolved = Some((key, original.cut_digest(), original_header, record.state_cut()));
        }
        let snapshot = self.journal
            .claim_protected_authority(RecordNamespace::OperatorRecovery)?.snapshot()?;
        let owner_instance = std::sync::Arc::clone(&self.startup_instance);
        Ok(match unresolved {
            None => OperatorRepairStartupCustodyV4::Clear(OperatorRepairStartupClearV4 {
                snapshot, owner_instance,
            }),
            Some((key, request_cut, original_header, state_cut)) => {
                OperatorRepairStartupCustodyV4::Unresolved(OperatorRepairStartupDebtV4 {
                    snapshot, owner_instance, key, request_cut, original_header, state_cut,
                })
            }
        })
    }

    pub(crate) fn recover_terminal_settlement_v4(&mut self, request: &RepairTerminalRequestV4) -> Result<Option<Vec<u8>>, StorageOperatorRecoveryErrorV1> {
        if request.mode() != RepairTerminalModeV4::Recover {
            return Ok(None);
        }
        let key = hold_key(self.require_completed_terminal_pair_v4(request)?, request.cut_digest());
        let bytes = self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.get(&key)?.map(ToOwned::to_owned);
        let Some(bytes) = bytes else { return Ok(None); };
        let record = HeldRecordV4::decode(&bytes)?;
        if record.original(self)?.cut_digest() != request.cut_digest() {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        if record.0[8] != SETTLED { return Ok(None); }
        self.validate_terminal_row_v4(&key, &bytes)?;
        let mut readback = b"AOSORZ04".to_vec();
        readback.extend_from_slice(record.current(self)?.signed_header());
        readback.extend_from_slice(&record.0[997..1477]);
        Ok(Some(readback))
    }

    pub(crate) fn verify_terminal_request_v4(&self, bytes: &[u8]) -> Result<RepairTerminalRequestV4, StorageOperatorRecoveryErrorV1> {
        RepairTerminalRequestV4::verify(bytes, &self.controller_key, self.controller_key_generation)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)
    }

    /// Reserves original custody before the runtime can enter TerminalHeld.
    pub(crate) fn reserve_terminal_hold_v4(&mut self, request: &RepairTerminalRequestV4) -> Result<(), StorageOperatorRecoveryErrorV1> {
        let effect = self.require_completed_terminal_pair_v4(request)?;
        let key = hold_key(effect, request.cut_digest());
        let existing = self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.get(&key)?.map(ToOwned::to_owned);
        if let Some(existing) = existing {
            let record = HeldRecordV4::decode(&existing)?;
            let original = record.original(self)?;
            if original.cut_digest() != request.cut_digest() || record.0[8] == SETTLED
                || request.mode() != RepairTerminalModeV4::Recover
            {
                return Err(StorageOperatorRecoveryErrorV1::Binding);
            }
            return Ok(());
        }
        if request.mode() != RepairTerminalModeV4::Hold || self.has_unresolved_terminal_hold_v4()? {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        self.commit_terminal_row_v4(key, HeldRecordV4::reserved(request).0.to_vec())
    }

    pub(crate) fn has_unresolved_terminal_hold_v4(&mut self) -> Result<bool, StorageOperatorRecoveryErrorV1> {
        let authority = self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?;
        for (_, value) in authority.records()? {
            if value.starts_with(HOLD_MAGIC) && HeldRecordV4::decode(value)?.0[8] != SETTLED {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn finish_terminal_hold_v4(&mut self, request: &RepairTerminalRequestV4, state_cut: [u8; 32], live_cut: [u8; 32]) -> Result<RepairTerminalWitnessV4, StorageOperatorRecoveryErrorV1> {
        let effect = self.require_completed_terminal_pair_v4(request)?;
        let key = hold_key(effect, request.cut_digest());
        let bytes = self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.get(&key)?.ok_or(StorageOperatorRecoveryErrorV1::Pending)?.to_vec();
        let mut record = HeldRecordV4::decode(&bytes)?;
        let original = record.original(self)?;
        if original.cut_digest() != request.cut_digest() || record.0[8] == SETTLED
            || (record.0[8] == HELD && record.state_cut() != state_cut)
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        let epoch = if record.0[8] == RESERVED {
            self.journal.snapshot_sequence().checked_add(1).ok_or(StorageOperatorRecoveryErrorV1::Binding)?
        } else {
            RepairTerminalWitnessV4::verify(&record.0[789..997], &original, self.owner_id, self.owner_key_generation, &self.owner_key.verifying_key())
                .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?.epoch()
        };
        let actual_owner_cut = hash(CUT_DOMAIN, &[&live_cut, &epoch.to_be_bytes(), &request.owner_pair_digest(), &self.journal.snapshot_sequence().to_be_bytes()]);
        let witness = RepairTerminalWitnessV4::sign(request, self.owner_id, self.owner_key_generation, epoch, actual_owner_cut, &self.owner_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        record.0[16..48].copy_from_slice(&state_cut);
        if record.0[8] == RESERVED {
            record.0[789..997].copy_from_slice(witness.as_bytes());
        }
        record.0[8] = HELD;
        record.0[700] = request.signed_header()[8];
        record.0[701..725].copy_from_slice(&request.signed_header()[16..40]);
        record.0[725..789].copy_from_slice(&request.signed_header()[588..652]);
        record.0[997..1205].copy_from_slice(witness.as_bytes());
        self.commit_terminal_row_v4(key, record.0.to_vec())?;
        Ok(witness)
    }

    pub(crate) fn settle_terminal_hold_v4(&mut self, request: &RepairTerminalRequestV4, witness: &RepairTerminalWitnessV4, ack: &[u8], now: u64) -> Result<DurableRepairSettlementV4, StorageOperatorRecoveryErrorV1> {
        let settlement = RepairTerminalSettlementV4::verify(ack, request, witness, &self.controller_key)
            .map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        if settlement.deadline() <= now || settlement.deadline() > request.deadline() {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        let key = hold_key(self.require_completed_terminal_pair_v4(request)?, request.cut_digest());
        let mut record = HeldRecordV4::decode(self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.get(&key)?.ok_or(StorageOperatorRecoveryErrorV1::Pending)?)?;
        if record.0[8] != HELD || record.current(self)?.signed_header() != request.signed_header()
            || &record.0[997..1205] != witness.as_bytes()
        {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        let signature = self.owner_key.sign(&release_message(ack));
        record.0[8] = SETTLED;
        record.0[1205..1413].copy_from_slice(ack);
        record.0[1413..].copy_from_slice(&signature.to_bytes());
        let state_cut = record.state_cut();
        self.commit_terminal_row_v4(key, record.0.to_vec())?;
        let mut release = ack.to_vec();
        release.extend_from_slice(&signature.to_bytes());
        Ok(DurableRepairSettlementV4 {
            state_cut, release, key, request_cut: request.cut_digest(),
            owner_instance: std::sync::Arc::clone(&self.startup_instance),
        })
    }

    fn require_completed_terminal_pair_v4(&mut self, request: &RepairTerminalRequestV4) -> Result<[u8; 32], StorageOperatorRecoveryErrorV1> {
        let effect = self.require_reserved_intent(&request.signed_intent())?;
        let stored = StoredRepairV2::decode(self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.get(&effect)?.ok_or(StorageOperatorRecoveryErrorV1::Pending)?)?;
        if stored.phase != COMPLETE || hash(b"aos.sandbox.operator-storage-repair-signed-pair.v2\0", &[&stored.signed_evidence, &stored.signed_receipt]) != request.owner_pair_digest() {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        Ok(effect)
    }

    fn commit_terminal_row_v4(&mut self, key: [u8; 32], bytes: Vec<u8>) -> Result<(), StorageOperatorRecoveryErrorV1> {
        let digest = hash(TX_DOMAIN, &[&key, &bytes]);
        let transaction = JournalTransaction::new(digest[..16].try_into().map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?, vec![JournalRecord::put(RecordNamespace::OperatorRecovery, key.to_vec(), bytes.clone())])?;
        self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.commit(&transaction)?;
        if self.journal.claim_protected_authority(RecordNamespace::OperatorRecovery)?.get(&key)? != Some(bytes.as_slice()) {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        Ok(())
    }

    pub(super) fn validate_terminal_row_v4(&mut self, key: &[u8], bytes: &[u8]) -> Result<(), StorageOperatorRecoveryErrorV1> {
        let record = HeldRecordV4::decode(bytes)?;
        let original = record.original(self)?;
        if original.mode() != RepairTerminalModeV4::Hold || key != hold_key(self.require_completed_terminal_pair_v4(&original)?, original.cut_digest()) {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        if record.0[8] == RESERVED {
            if record.0[16..48] != [0; 32] || record.0[700..] != [0; BYTES - 700] {
                return Err(StorageOperatorRecoveryErrorV1::Binding);
            }
            return Ok(());
        }
        let current = record.current(self)?;
        if current.cut_digest() != original.cut_digest() || record.state_cut() == [0; 32] {
            return Err(StorageOperatorRecoveryErrorV1::Binding);
        }
        let original_witness = RepairTerminalWitnessV4::verify(&record.0[789..997], &original, self.owner_id, self.owner_key_generation, &self.owner_key.verifying_key()).map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        let witness = RepairTerminalWitnessV4::verify(&record.0[997..1205], &current, self.owner_id, self.owner_key_generation, &self.owner_key.verifying_key()).map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        if witness.epoch() != original_witness.epoch() { return Err(StorageOperatorRecoveryErrorV1::Binding); }
        if record.0[8] == HELD {
            if record.0[1205..] != [0; BYTES - 1205] { return Err(StorageOperatorRecoveryErrorV1::Binding); }
        } else {
            RepairTerminalSettlementV4::verify(&record.0[1205..1413], &current, &witness, &self.controller_key).map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
            self.owner_key.verifying_key().verify_strict(&release_message(&record.0[1205..1413]), &Signature::from_bytes(&record.0[1413..].try_into().map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?)).map_err(|_| StorageOperatorRecoveryErrorV1::Binding)?;
        }
        Ok(())
    }
}

fn hold_key(effect: [u8; 32], cut: [u8; 32]) -> [u8; 32] { hash(KEY_DOMAIN, &[&effect, &cut]) }

fn release_message(ack: &[u8]) -> Vec<u8> {
    let mut message = RELEASE_DOMAIN.to_vec();
    message.extend_from_slice(ack);
    message
}
