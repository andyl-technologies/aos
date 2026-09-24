//! Protected two-endpoint abandonment for one read-only Storage inventory.
//!
//! ```text
//! AOSBSAB1 | version:u16be | endpoint:u8 | group-id:16 | inventory-id:16 |
//! group-request-digest:32 | inventory-request-digest:32 |
//! client-original-head:32 | broker-original-head:32 |
//! client-archive-digest:32 | broker-archive-digest:32 |
//! broker-marker-digest:32 | signed-control-history-length:u32be |
//! signed-control-history | sha256:32
//! ```
//!
//! The broker marker can only be committed while its exact old Method18 head
//! is nonterminal. The client marker retains the signed broker response and
//! its V3 hello/transcript. Neither marker is an old terminal response.

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, RecoverStorageInventoryRequestV1};
use aos_sandbox::{JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use aos_sandbox_protocol::{
    ValidatedStorageInventoryRecoveryResponseV1, decode_storage_inventory_recovery_response_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    BrokerSessionSecurityError, ProtectedBrokerSessionJournalV1, StoredProtocolHistoryV1,
    historical_terminal_outcome, protocol_key, read_array, read_u16, read_u32, reconstruct_traffic,
};

const MAGIC: &[u8; 8] = b"AOSBSAB1";
const DOMAIN: &[u8] = b"aos.sandbox.broker-session.storage-inventory-abandonment.v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-inventory-abandonment-transaction.v1\0";
const HEADER_BYTES: usize = 8 + 2 + 1 + 16 + 16 + 7 * 32 + 4;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StorageInventoryAbandonmentV1 {
    pub(super) endpoint: BrokerSessionDurableEndpointV1,
    pub(super) group_request_id: [u8; 16],
    inventory_request_id: [u8; 16],
    pub(super) group_request_digest: [u8; 32],
    pub(super) inventory_request_digest: [u8; 32],
    pub(super) client_original_head: [u8; 32],
    broker_original_head: [u8; 32],
    client_archive_digest: [u8; 32],
    broker_archive_digest: [u8; 32],
    broker_marker_digest: [u8; 32],
    signed_control_history: Option<StoredProtocolHistoryV1>,
}

impl StorageInventoryAbandonmentV1 {
    fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        let role = match self.endpoint {
            BrokerSessionDurableEndpointV1::Client => 1,
            BrokerSessionDurableEndpointV1::Broker => 2,
        };
        let history = self
            .signed_control_history
            .as_ref()
            .map(StoredProtocolHistoryV1::encode)
            .transpose()?
            .unwrap_or_default();
        let length =
            u32::try_from(history.len()).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.group_request_id == [0; 16]
            || self.inventory_request_id == [0; 16]
            || self.group_request_digest == [0; 32]
            || self.inventory_request_digest == [0; 32]
            || self.client_original_head == [0; 32]
            || self.broker_original_head == [0; 32]
            || self.broker_archive_digest == [0; 32]
            || (role == 1
                && (self.client_archive_digest == [0; 32]
                    || self.broker_marker_digest == [0; 32]
                    || history.is_empty()))
            || (role == 2
                && (self.client_archive_digest != [0; 32]
                    || self.broker_marker_digest != [0; 32]
                    || !history.is_empty()))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut value = Vec::with_capacity(HEADER_BYTES + history.len() + DIGEST_BYTES);
        value.extend_from_slice(MAGIC);
        value.extend_from_slice(&1_u16.to_be_bytes());
        value.push(role);
        value.extend_from_slice(&self.group_request_id);
        value.extend_from_slice(&self.inventory_request_id);
        value.extend_from_slice(&self.group_request_digest);
        value.extend_from_slice(&self.inventory_request_digest);
        value.extend_from_slice(&self.client_original_head);
        value.extend_from_slice(&self.broker_original_head);
        value.extend_from_slice(&self.client_archive_digest);
        value.extend_from_slice(&self.broker_archive_digest);
        value.extend_from_slice(&self.broker_marker_digest);
        value.extend_from_slice(&length.to_be_bytes());
        value.extend_from_slice(&history);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&value)
            .finalize()
            .into();
        value.extend_from_slice(&digest);
        Ok(value)
    }

    fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || read_u16(bytes, 8)? != 1
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let endpoint = match bytes.get(10).copied() {
            Some(1) => BrokerSessionDurableEndpointV1::Client,
            Some(2) => BrokerSessionDurableEndpointV1::Broker,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let group_request_id = read_array(bytes, 11)?;
        let inventory_request_id = read_array(bytes, 27)?;
        let group_request_digest = read_array(bytes, 43)?;
        let inventory_request_digest = read_array(bytes, 75)?;
        let client_original_head = read_array(bytes, 107)?;
        let broker_original_head = read_array(bytes, 139)?;
        let client_archive_digest = read_array(bytes, 171)?;
        let broker_archive_digest = read_array(bytes, 203)?;
        let broker_marker_digest = read_array(bytes, 235)?;
        let length = usize::try_from(read_u32(bytes, 267)?)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let end = HEADER_BYTES
            .checked_add(length)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if key != inventory_request_id || end.checked_add(DIGEST_BYTES) != Some(bytes.len()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let expected: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes[..end])
            .finalize()
            .into();
        if read_array::<32>(bytes, end)? != expected {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let signed_control_history = if length == 0 {
            None
        } else {
            Some(StoredProtocolHistoryV1::decode(
                &protocol_key(BrokerSessionProtocolV1::Storage),
                bytes
                    .get(HEADER_BYTES..end)
                    .ok_or(BrokerSessionSecurityError::Currentness)?,
            )?)
        };
        let record = Self {
            endpoint,
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            client_original_head,
            broker_original_head,
            client_archive_digest,
            broker_archive_digest,
            broker_marker_digest,
            signed_control_history,
        };
        if record.encode()? != bytes {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(record)
    }

    fn digest(&self) -> Result<[u8; 32], BrokerSessionSecurityError> {
        let encoded = self.encode()?;
        read_array(&encoded, encoded.len() - DIGEST_BYTES)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    fn verify_client_storage_inventory_abandonment(
        &mut self,
        record: &StorageInventoryAbandonmentV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let stored = record
            .signed_control_history
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        if stored.endpoint != BrokerSessionDurableEndpointV1::Client
            || stored.stable_endpoint_identity
                != self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || stored.endpoint_publication
                != self.historical_endpoint_publication(
                    BrokerSessionProtocolV1::Storage,
                    &transcript,
                )?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history = stored.history_model()?;
        reconstruct_traffic(&history, &transcript, checkpoint.context())?;
        let records = history.records();
        if records.len() != 2
            || records[0].phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || records[0].method() != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            || records[1].phase() != BrokerSessionDurablePhaseV1::Terminal
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let outcome = historical_terminal_outcome(records, 1, checkpoint, &transcript)?;
        let coordinates =
            RecoverStorageInventoryRequestV1::decode_from_slice(outcome.request().exact_body())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let decision = decode_storage_inventory_recovery_response_v1(
            exact_body,
            outcome.request().maximum_response_bytes(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let ValidatedStorageInventoryRecoveryResponseV1::AbandonedReadOnly {
            broker_head,
            archive_digest,
            abandonment_digest,
        } = decision
        else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        if coordinates.group_request_id.as_slice() != record.group_request_id
            || coordinates.group_request_digest.as_slice() != record.group_request_digest
            || coordinates.inventory_request_id.as_slice() != record.inventory_request_id
            || coordinates.inventory_request_digest.as_slice() != record.inventory_request_digest
            || coordinates.client_original_head.as_slice() != record.client_original_head
            || broker_head != record.broker_original_head
            || archive_digest != record.broker_archive_digest
            || abandonment_digest != record.broker_marker_digest
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    pub(super) fn validate_storage_inventory_abandonments(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        let entries = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(
                    RecordNamespace::BrokerSessionStorageInventoryAbandonment,
                )
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut entries = Vec::new();
            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                if entries.len() == super::MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                entries.push((key.to_vec(), value.to_vec()));
            }
            entries
        };
        for (key, value) in entries {
            let record = StorageInventoryAbandonmentV1::decode(&key, &value)?;
            if record.endpoint != self.endpoint.role() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let original = self.archived_storage_inventory_head(
                record.group_request_id,
                record.group_request_digest,
                record.inventory_request_id,
                record.inventory_request_digest,
            )?;
            if original.terminal_packet.is_some() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            match record.endpoint {
                BrokerSessionDurableEndpointV1::Broker
                    if record.broker_archive_digest == original.archive_digest
                        && record.broker_original_head == original.original_head => {}
                BrokerSessionDurableEndpointV1::Client
                    if record.client_archive_digest == original.archive_digest
                        && record.client_original_head == original.original_head =>
                {
                    self.verify_client_storage_inventory_abandonment(&record)?;
                }
                _ => return Err(BrokerSessionSecurityError::Currentness),
            }
        }
        Ok(())
    }

    pub(super) fn read_storage_inventory_abandonment(
        &mut self,
        inventory_request_id: [u8; 16],
    ) -> Result<Option<StorageInventoryAbandonmentV1>, BrokerSessionSecurityError> {
        let value = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(
                    RecordNamespace::BrokerSessionStorageInventoryAbandonment,
                )
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .get(&inventory_request_id)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        value
            .map(|value| StorageInventoryAbandonmentV1::decode(&inventory_request_id, &value))
            .transpose()
    }

    fn commit_storage_inventory_abandonment(
        &mut self,
        record: &StorageInventoryAbandonmentV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        let value = record.encode()?;
        if let Some(current) =
            self.read_storage_inventory_abandonment(record.inventory_request_id)?
        {
            return if current == *record {
                current.digest()
            } else {
                Err(BrokerSessionSecurityError::Currentness)
            };
        }
        let digest: [u8; 32] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(record.inventory_request_id)
            .chain_update(Sha256::digest(&value))
            .finalize()
            .into();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if transaction_id == [0; 16] {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionStorageInventoryAbandonment,
                record.inventory_request_id.to_vec(),
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionStorageInventoryAbandonment)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&record.inventory_request_id)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .commit(&transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let retained = self
            .read_storage_inventory_abandonment(record.inventory_request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if retained != *record {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        retained.digest()
    }

    pub(super) fn broker_abandon_original_storage_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        client_original_head: [u8; 32],
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), BrokerSessionSecurityError> {
        if self.endpoint.role() != BrokerSessionDurableEndpointV1::Broker {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let original = self.archived_storage_inventory_head(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
        )?;
        if original.terminal_packet.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let record = StorageInventoryAbandonmentV1 {
            endpoint: BrokerSessionDurableEndpointV1::Broker,
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            client_original_head,
            broker_original_head: original.original_head,
            client_archive_digest: [0; 32],
            broker_archive_digest: original.archive_digest,
            broker_marker_digest: [0; 32],
            signed_control_history: None,
        };
        let digest = self.commit_storage_inventory_abandonment(&record)?;
        Ok((original.original_head, original.archive_digest, digest))
    }

    pub(super) fn client_confirm_storage_inventory_abandonment(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.endpoint.role() != BrokerSessionDurableEndpointV1::Client {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let original = self.archived_storage_inventory_head(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
        )?;
        if original.terminal_packet.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let control = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = control
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let history = control.history_model()?;
        if history.records().len() != 2 {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let outcome = historical_terminal_outcome(history.records(), 1, checkpoint, &transcript)?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let decision = decode_storage_inventory_recovery_response_v1(
            exact_body,
            outcome.request().maximum_response_bytes(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let ValidatedStorageInventoryRecoveryResponseV1::AbandonedReadOnly {
            broker_head,
            archive_digest,
            abandonment_digest,
        } = decision
        else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let record = StorageInventoryAbandonmentV1 {
            endpoint: BrokerSessionDurableEndpointV1::Client,
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            client_original_head: original.original_head,
            broker_original_head: broker_head,
            client_archive_digest: original.archive_digest,
            broker_archive_digest: archive_digest,
            broker_marker_digest: abandonment_digest,
            signed_control_history: Some(control),
        };
        self.verify_client_storage_inventory_abandonment(&record)?;
        self.commit_storage_inventory_abandonment(&record)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_marker_binds_both_old_heads_and_rejects_tampering() {
        let record = StorageInventoryAbandonmentV1 {
            endpoint: BrokerSessionDurableEndpointV1::Broker,
            group_request_id: [3; 16],
            inventory_request_id: [5; 16],
            group_request_digest: [7; 32],
            inventory_request_digest: [9; 32],
            client_original_head: [11; 32],
            broker_original_head: [13; 32],
            client_archive_digest: [0; 32],
            broker_archive_digest: [15; 32],
            broker_marker_digest: [0; 32],
            signed_control_history: None,
        };
        let encoded = record.encode().unwrap();
        assert_eq!(
            StorageInventoryAbandonmentV1::decode(&[5; 16], &encoded).unwrap(),
            record
        );
        assert!(StorageInventoryAbandonmentV1::decode(&[6; 16], &encoded).is_err());
        for offset in [11, 27, 43, 75, 107, 139, 203, encoded.len() - 1] {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 1;
            assert!(StorageInventoryAbandonmentV1::decode(&[5; 16], &tampered).is_err());
        }
    }

    #[test]
    fn fresh_inventory_after_control_requires_exact_abandonment_marker() {
        let marker = StorageInventoryAbandonmentV1 {
            endpoint: BrokerSessionDurableEndpointV1::Broker,
            group_request_id: [3; 16],
            inventory_request_id: [5; 16],
            group_request_digest: [7; 32],
            inventory_request_digest: [9; 32],
            client_original_head: [11; 32],
            broker_original_head: [13; 32],
            client_archive_digest: [0; 32],
            broker_archive_digest: [15; 32],
            broker_marker_digest: [0; 32],
            signed_control_history: None,
        };
        let allowed = |record| {
            super::super::exact_storage_inventory_abandonment_marker(
                record,
                BrokerSessionDurableEndpointV1::Broker,
                [3; 16],
                [7; 32],
                [9; 32],
                [11; 32],
            )
        };
        assert!(!allowed(None));
        assert!(allowed(Some(&marker)));
        assert!(!super::super::exact_storage_inventory_abandonment_marker(
            Some(&marker),
            BrokerSessionDurableEndpointV1::Client,
            [3; 16],
            [7; 32],
            [9; 32],
            [11; 32],
        ));
        assert!(!super::super::exact_storage_inventory_abandonment_marker(
            Some(&marker),
            BrokerSessionDurableEndpointV1::Broker,
            [3; 16],
            [7; 32],
            [10; 32],
            [11; 32],
        ));
    }
}
