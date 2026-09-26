//! Protected admission-time witness for one Host preliminary settlement.
//!
//! ```text
//! Effect['w' | execution:16] =
//! AOSCHA01 | version:u16be | reserved[6]=0 | execution:16 |
//! store-binding:32 | preliminary-digest:32 | signed-request-digest:32 |
//! original-session:32 | source-digest:32 | handoff-digest:32 |
//! Host-boot:16 | admitted-boottime:u64be | original-deadline:u64be |
//! commit-sequence:u64be | HostState-cut:32 | SHA256(domain || preceding):32
//! ```
//!
//! The row is appended only after AOSCHL01. An AOSCHL01 without this row is
//! never eligible for historical recovery. Neither row grants a Host lease,
//! Controller disposition, or permission to ignore a changed HostState cut.
//! Storage can verify the Effect sequence and retained stage, but not the
//! caller-supplied trusted clock sample, signed method-42 packet, or HostState
//! cut. No production issuer is wired to this dormant append in this version.

use super::*;

pub(crate) const KEY_PREFIX: u8 = b'w';
const MAGIC: &[u8; 8] = b"AOSCHA01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.host-settlement-admission.v1\0";
const RECORD_BYTES: usize = 328;

/// Encodes an owner's original admission coordinates for one signed stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostSettlementAdmissionWitnessV1 {
    pub(crate) execution: ExecutionId,
    pub(crate) store_binding: ObjectDigest,
    pub(crate) preliminary_digest: ObjectDigest,
    pub(crate) signed_request_digest: ObjectDigest,
    pub(crate) settlement_session_binding: [u8; 32],
    pub(crate) source_digest: ObjectDigest,
    pub(crate) handoff_digest: ObjectDigest,
    pub(crate) host_boot_id: [u8; 16],
    pub(crate) admitted_boottime_nanoseconds: u64,
    pub(crate) original_deadline_boottime_nanoseconds: u64,
    pub(crate) commit_sequence: u64,
    pub(crate) hoststate_cut: ObjectDigest,
}

impl HostSettlementAdmissionWitnessV1 {
    pub(crate) fn encode(self) -> Result<[u8; RECORD_BYTES], JournalRuntimeExecutionError> {
        if self.execution.as_bytes() == &[0; 16]
            || [
                self.store_binding,
                self.preliminary_digest,
                self.signed_request_digest,
                self.source_digest,
                self.handoff_digest,
                self.hoststate_cut,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
            || self.settlement_session_binding == [0; 32]
            || self.host_boot_id == [0; 16]
            || self.admitted_boottime_nanoseconds == 0
            || self.admitted_boottime_nanoseconds >= self.original_deadline_boottime_nanoseconds
            || self.commit_sequence == 0
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(self.execution.as_bytes());
        bytes[32..64].copy_from_slice(self.store_binding.as_bytes());
        bytes[64..96].copy_from_slice(self.preliminary_digest.as_bytes());
        bytes[96..128].copy_from_slice(self.signed_request_digest.as_bytes());
        bytes[128..160].copy_from_slice(&self.settlement_session_binding);
        bytes[160..192].copy_from_slice(self.source_digest.as_bytes());
        bytes[192..224].copy_from_slice(self.handoff_digest.as_bytes());
        bytes[224..240].copy_from_slice(&self.host_boot_id);
        bytes[240..248].copy_from_slice(&self.admitted_boottime_nanoseconds.to_be_bytes());
        bytes[248..256].copy_from_slice(&self.original_deadline_boottime_nanoseconds.to_be_bytes());
        bytes[256..264].copy_from_slice(&self.commit_sequence.to_be_bytes());
        bytes[264..296].copy_from_slice(self.hoststate_cut.as_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..296])
            .finalize();
        bytes[296..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, JournalRuntimeExecutionError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let digest = |start| {
            bytes[start..start + 32]
                .try_into()
                .map(ObjectDigest::from_bytes)
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
        };
        let witness = Self {
            execution: ExecutionId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            ),
            store_binding: digest(32)?,
            preliminary_digest: digest(64)?,
            signed_request_digest: digest(96)?,
            settlement_session_binding: bytes[128..160]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            source_digest: digest(160)?,
            handoff_digest: digest(192)?,
            host_boot_id: bytes[224..240]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            admitted_boottime_nanoseconds: u64::from_be_bytes(
                bytes[240..248]
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            ),
            original_deadline_boottime_nanoseconds: u64::from_be_bytes(
                bytes[248..256]
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            ),
            commit_sequence: u64::from_be_bytes(
                bytes[256..264]
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            ),
            hoststate_cut: digest(264)?,
        };
        if witness.encode()?.as_slice() != bytes {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(witness)
    }

    pub(crate) fn key(self) -> Vec<u8> {
        let mut key = Vec::with_capacity(17);
        key.push(KEY_PREFIX);
        key.extend_from_slice(self.execution.as_bytes());
        key
    }

    pub(crate) fn matches_stage(
        self,
        marker: HostExecutionNoApplyRecordV1,
        preliminary: HostSettlementRecordV1,
        store_binding: ObjectDigest,
    ) -> bool {
        let fields = marker.fields();
        self.execution == preliminary.execution
            && self.execution.as_bytes() == &fields.execution_id
            && self.store_binding == store_binding
            && self.store_binding.as_bytes() == &fields.execution_store_binding
            && self.preliminary_digest == preliminary.digest()
            && self.settlement_session_binding == preliminary.session_binding
            && self.source_digest.as_bytes() == &fields.source_record_digest
            && self.handoff_digest == preliminary.handoff_digest
            && self.host_boot_id == fields.host_boot_id
            // A witness is an immediate second append, never a later attempt
            // to recreate a missed admission-time sample.
            && preliminary.commit_sequence.checked_add(3) == Some(self.commit_sequence)
    }
}

impl JournalRuntimeExecutionStoreV1<'_> {
    /// Reads a witness only when its exact original marker and stage survive.
    pub(crate) fn load_host_settlement_admission_witness_v1(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<HostSettlementAdmissionWitnessV1>, JournalRuntimeExecutionError> {
        let mut key = Vec::with_capacity(17);
        key.push(KEY_PREFIX);
        key.extend_from_slice(execution.as_bytes());
        let Some(bytes) = self.authority.get(&key)? else {
            return Ok(None);
        };
        let witness = HostSettlementAdmissionWitnessV1::decode(bytes)?;
        let marker = self
            .load_host_no_apply_v1(execution)?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let preliminary = self.load_host_settlement_history_v1(execution)?[0]
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if witness.key() != key
            || !witness.matches_stage(marker, preliminary, self.store_binding)
            || witness.commit_sequence >= self.authority.snapshot()?.sequence()
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(Some(witness))
    }

    /// Appends a separate nonauthorizing witness after exact preliminary replay.
    ///
    /// An interrupted stage-to-witness gap remains ineligible for historical
    /// recovery. The caller must supply the trusted original admission sample
    /// and verify the current HostState cut while retaining the Host owner.
    #[allow(dead_code, reason = "historical recovery transport remains closed")]
    pub(crate) fn append_host_settlement_admission_witness_v1(
        &mut self,
        witness: HostSettlementAdmissionWitnessV1,
    ) -> Result<(), JournalRuntimeExecutionError> {
        let snapshot = self.authority.snapshot()?;
        let marker = self
            .load_host_no_apply_v1(witness.execution)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let [Some(preliminary), None, None] =
            self.load_host_settlement_history_v1(witness.execution)?
        else {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        };
        if self.authority.get(HOST_FENCE_KEY)?.is_some()
            || self
                .load_host_settlement_admission_witness_v1(witness.execution)?
                .is_some()
            || !witness.matches_stage(marker, preliminary, self.store_binding)
            || witness.commit_sequence != predicted_commit_sequence(snapshot.sequence(), 1)?
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        self.authority.validate_snapshot_for_effect(&snapshot)?;

        let bytes = witness.encode()?;
        let key = witness.key();
        let transaction = JournalTransaction::new(
            transaction_id(
                b"host-settlement-admission-witness",
                ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
            ),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                key.clone(),
                bytes.to_vec(),
            )],
        )?;
        let committed = self
            .authority
            .append_host_settlement_admission_witness_v1(witness, &transaction)
            .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?;
        if committed.commit_sequence != witness.commit_sequence
            || self
                .authority
                .get(&key)
                .map_err(|_| JournalRuntimeExecutionError::SettlementOutcomeUnknown)?
                != Some(bytes.as_slice())
        {
            return Err(JournalRuntimeExecutionError::SettlementOutcomeUnknown);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_witness_rejects_corrupt_or_expired_coordinates() {
        let witness = HostSettlementAdmissionWitnessV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            store_binding: ObjectDigest::from_bytes([2; 32]),
            preliminary_digest: ObjectDigest::from_bytes([3; 32]),
            signed_request_digest: ObjectDigest::from_bytes([4; 32]),
            settlement_session_binding: [5; 32],
            source_digest: ObjectDigest::from_bytes([6; 32]),
            handoff_digest: ObjectDigest::from_bytes([7; 32]),
            host_boot_id: [8; 16],
            admitted_boottime_nanoseconds: 9,
            original_deadline_boottime_nanoseconds: 10,
            commit_sequence: 11,
            hoststate_cut: ObjectDigest::from_bytes([12; 32]),
        };
        let bytes = witness.encode().expect("canonical witness");
        assert_eq!(
            HostSettlementAdmissionWitnessV1::decode(&bytes).expect("round trip"),
            witness
        );
        for offset in [
            0, 8, 10, 16, 32, 64, 96, 128, 160, 192, 224, 240, 248, 256, 264, 296,
        ] {
            let mut corrupt = bytes;
            corrupt[offset] ^= 1;
            assert!(HostSettlementAdmissionWitnessV1::decode(&corrupt).is_err());
        }
        assert!(
            HostSettlementAdmissionWitnessV1 {
                admitted_boottime_nanoseconds: 10,
                ..witness
            }
            .encode()
            .is_err()
        );
        assert!(
            HostSettlementAdmissionWitnessV1 {
                hoststate_cut: ObjectDigest::from_bytes([0; 32]),
                ..witness
            }
            .encode()
            .is_err()
        );
    }
}
