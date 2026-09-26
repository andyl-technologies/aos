//! Protected pre-effect custody for an authenticated Storage inventory.
//!
//! The owner commits this record before the operator socket may dispatch a
//! Repair. A later client-received inventory can be compared with its exact
//! authenticated packet and session sequence; an owner receipt cannot invent
//! the earlier physical dataset-present/pin-absent observation.
//!
//! ```text
//! storage-repair-before-v1/<operation-id[16]>:
//! AOSORB01 | operation-id[16] | effect-id[32] | current-head-digest[32]
//!          | signed-inventory-packet-digest[32] | session-binding[32]
//!          | client-sequence:u64be | broker-sequence:u64be
//!          | physical-catalog-generation:u64be
//! ```

use aos_proto::aos::sandbox::local::v1::RepairStorageWorkspacePinRequest;
use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect::verify_operator_recovery_effect_intent_v1;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, decode_storage_resource_inventory_response};
use buffa::Message as _;

use super::probe_challenge::{self, ProbeStageV1};
use super::{
    CURRENT_HEAD_DOMAIN_V2, FENCE_DOMAIN, OperatorRecoveryIssuanceErrorV1,
    ProtectedOperatorRecoverySignerV1, REQUEST_DOMAIN, StorageRepairIssuanceV2, hash,
    issuance_key_v2,
};
use crate::controller::{
    ActivatedOperationCompiler, NodeController, SingleNodeEffectExecutor, recovery_current_key,
};
use crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSORB01";
const PREFIX: &[u8] = b"storage-repair-before-v1/";
const RECORD_BYTES: usize = 176;
const PACKET_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-before-packet.v1\0";
const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-before-commit.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StoredBeforeV1 {
    operation_id: [u8; 16],
    effect_id: [u8; 32],
    current_head_digest: [u8; 32],
    packet_digest: [u8; 32],
    session_binding: [u8; 32],
    client_sequence: u64,
    broker_sequence: u64,
    catalog_generation: u64,
}

impl StoredBeforeV1 {
    fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        let mut cursor = 0;
        for field in [
            MAGIC.as_slice(),
            self.operation_id.as_slice(),
            self.effect_id.as_slice(),
            self.current_head_digest.as_slice(),
            self.packet_digest.as_slice(),
            self.session_binding.as_slice(),
            self.client_sequence.to_be_bytes().as_slice(),
            self.broker_sequence.to_be_bytes().as_slice(),
            self.catalog_generation.to_be_bytes().as_slice(),
        ] {
            bytes[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let record = Self {
            operation_id: array(bytes, 8)?,
            effect_id: array(bytes, 24)?,
            current_head_digest: array(bytes, 56)?,
            packet_digest: array(bytes, 88)?,
            session_binding: array(bytes, 120)?,
            client_sequence: u64::from_be_bytes(array(bytes, 152)?),
            broker_sequence: u64::from_be_bytes(array(bytes, 160)?),
            catalog_generation: u64::from_be_bytes(array(bytes, 168)?),
        };
        if record.operation_id == [0; 16]
            || [
                record.effect_id,
                record.current_head_digest,
                record.packet_digest,
                record.session_binding,
            ]
            .contains(&[0; 32])
            || record.client_sequence == 0
            || record.broker_sequence == 0
            || record.catalog_generation == 0
            || record.encode().as_slice() != bytes
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(record)
    }

    pub(super) fn matches_outcome(
        &self,
        before: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        if self.packet_digest != hash(PACKET_DOMAIN, &[before.canonical_packet()])
            || self.session_binding != before.request().session_binding()
            || self.client_sequence != before.request().client_sequence()
            || self.broker_sequence != before.broker_sequence()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(())
    }

    pub(super) const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    pub(super) const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    pub(super) const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    pub(super) const fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    pub(super) const fn packet_digest(&self) -> [u8; 32] {
        self.packet_digest
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Commits a signed dataset-present/pin-absent inventory before dispatch.
    ///
    /// # Errors
    ///
    /// Rejects stale issuance, nonphysical or replayed inventory, prior
    /// Repair commit, changed protected head, or uncertain journal custody.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn reserve_storage_repair_before_v1(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        operation_id: OperationId,
        storage_request_body: &[u8],
        before: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        let journal = self.reconciler.journal_mut();
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let issuance_key = issuance_key_v2(*operation_id.as_bytes());
        let issued = StorageRepairIssuanceV2::decode(
            &issuance_key,
            journal
                .get(RecordNamespace::OperatorRecovery, &issuance_key)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
            signer.verifier(),
            signer.key_id(),
            signer.generation(),
        )?;
        let intent =
            verify_operator_recovery_effect_intent_v1(&issued.signed_intent, signer.verifier())
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let current = journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(intent.target_id),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != issued.current_head_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        probe_challenge::read(
            journal,
            &issued,
            intent.effect_id,
            ProbeStageV1::Before,
            [0; 32],
        )?
        .matches_outcome(before)?;
        let request = RepairStorageWorkspacePinRequest::decode_from_slice(storage_request_body)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let fence = request
            .fence
            .as_option()
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let fence_digest = hash(
            FENCE_DOMAIN,
            &[
                &fence.sandbox_id,
                &fence.incarnation_id,
                &fence.assignment_epoch.to_be_bytes(),
                &fence.desired_generation.to_be_bytes(),
                &fence.assignment_digest,
            ],
        );
        if request.encode_to_vec() != storage_request_body
            || hash(REQUEST_DOMAIN, &[storage_request_body]) != intent.effect_id
            || request.operation_id.as_slice() != intent.recovery_operation_id
            || fence.sandbox_id.as_slice() != intent.target_id
            || fence.desired_generation != intent.current_generation
            || fence_digest != intent.current_fence_digest
            || request.storage_handle.len() != 32
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let inventory = authenticated_before_inventory(before)?;
        let physical = decode_storage_resource_inventory_response(
            authenticated_body(before)?,
            MAXIMUM_RESPONSE_BYTES,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if inventory.commitment().as_bytes() != &issued.inventory_commitment
            || inventory.head().as_bytes() != &issued.inventory_head
            || inventory.generation() != issued.inventory_generation
            || physical
                .workspaces()
                .iter()
                .any(|workspace| workspace.workspace_handle().as_slice() == request.storage_handle)
            || physical
                .operator_repair_commits()
                .iter()
                .any(|commit| commit.operation_id() == &intent.recovery_operation_id)
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let record = StoredBeforeV1 {
            operation_id: intent.recovery_operation_id,
            effect_id: intent.effect_id,
            current_head_digest: issued.current_head_digest,
            packet_digest: hash(PACKET_DOMAIN, &[before.canonical_packet()]),
            session_binding: before.request().session_binding(),
            client_sequence: before.request().client_sequence(),
            broker_sequence: before.broker_sequence(),
            catalog_generation: inventory.generation(),
        };
        reserve(journal, &record)?;
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)
    }
}

pub(super) fn read(
    journal: &mut Journal,
    issued: &StorageRepairIssuanceV2,
    effect_id: [u8; 32],
) -> Result<StoredBeforeV1, OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = key(issued.operation_id);
    let record = StoredBeforeV1::decode(
        journal
            .get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
    )?;
    if record.operation_id != issued.operation_id
        || record.effect_id != effect_id
        || record.current_head_digest != issued.current_head_digest
        || record.catalog_generation != issued.inventory_generation
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(record)
}

pub(super) fn authenticated_before_inventory(
    before: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<LifecycleAuthenticatedStorageInventoryV1, OperatorRecoveryIssuanceErrorV1> {
    let inventory = LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(before)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if inventory.source_version() != 3 {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(inventory)
}

fn authenticated_body(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<&[u8], OperatorRecoveryIssuanceErrorV1> {
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    };
    Ok(exact_body)
}

fn reserve(
    journal: &mut Journal,
    record: &StoredBeforeV1,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let key = key(record.operation_id);
    let encoded = record.encode();
    StoredBeforeV1::decode(&encoded)?;
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &key) {
        StoredBeforeV1::decode(existing)?;
        return if existing == encoded {
            Ok(())
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        };
    }
    let digest = hash(COMMIT_DOMAIN, &[&record.operation_id]);
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::OperatorRecovery,
            key.clone(),
            encoded.to_vec(),
        )],
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let _ = journal.commit(&transaction);
    if journal.get(RecordNamespace::OperatorRecovery, &key) != Some(encoded.as_slice()) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

fn key(operation_id: [u8; 16]) -> Vec<u8> {
    [PREFIX, operation_id.as_slice()].concat()
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OperatorRecoveryIssuanceErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::JournalLimits;

    fn sample() -> StoredBeforeV1 {
        StoredBeforeV1 {
            operation_id: [1; 16],
            effect_id: [2; 32],
            current_head_digest: [3; 32],
            packet_digest: [4; 32],
            session_binding: [5; 32],
            client_sequence: 6,
            broker_sequence: 7,
            catalog_generation: 8,
        }
    }

    #[test]
    fn before_record_rejects_changed_generation_and_legacy_version() {
        let record = sample();
        let bytes = record.encode();
        assert_eq!(StoredBeforeV1::decode(&bytes), Ok(record));
        let mut legacy = bytes;
        legacy[..8].copy_from_slice(b"AOSORB00");
        assert!(StoredBeforeV1::decode(&legacy).is_err());
        let mut absent = bytes;
        absent[168..176].fill(0);
        assert!(StoredBeforeV1::decode(&absent).is_err());
    }

    #[test]
    fn before_custody_replays_exact_packet_after_cold_reopen() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-before.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let record = sample();
        assert_eq!(reserve(&mut journal, &record), Ok(()));
        assert_eq!(reserve(&mut journal, &record), Ok(()));
        let mut changed = record;
        changed.packet_digest = [9; 32];
        assert_eq!(
            reserve(&mut journal, &changed),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );

        drop(journal);
        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-before.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_eq!(reserve(&mut reopened, &record), Ok(()));
        assert_eq!(
            reopened.get(RecordNamespace::OperatorRecovery, &key(record.operation_id)),
            Some(record.encode().as_slice())
        );
    }
}
