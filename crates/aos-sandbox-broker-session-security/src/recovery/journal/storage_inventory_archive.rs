//! Immutable protected history for a post-snapshot Storage inventory request.
//!
//! ```text
//! AOSBSIA1 | version:u16be | group-id:16 | inventory-id:16 |
//! group-request-digest:32 | inventory-request-digest:32 |
//! history-length:u32be | canonical-protected-history | sha256:32
//! ```
//!
//! This archive only preserves old signed evidence. It neither abandons an
//! outstanding request nor grants a new session permission to roll over it.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::{JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1, decode_canonical_request_v1,
    decode_canonical_response_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerRequestDirectionV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    prepare_client_sent_authenticated_broker_method_request_v1,
};
use sha2::{Digest as _, Sha256};

use super::{
    BrokerSessionSecurityError, ProtectedBrokerSessionJournalV1, StoredProtocolHistoryV1,
    authenticated_semantic_bindings_from_envelope_v1, authority_envelope_digest,
    historical_terminal_outcome, protocol_key, read_array, read_u16, read_u32, reconstruct_traffic,
    reconstruct_traffic_records, request_matches_head, successful_terminal,
};

const MAGIC: &[u8; 8] = b"AOSBSIA1";
const DOMAIN: &[u8] = b"aos.sandbox.broker-session.storage-inventory-archive.v1\0";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-inventory-archive-transaction.v1\0";
const HEADER_BYTES: usize = 8 + 2 + 16 + 16 + 32 + 32 + 4;
const DIGEST_BYTES: usize = 32;

/// Classifies only the exact signed inventory immediately after a terminal group.
pub(crate) struct ArchivedStorageInventoryHeadV1 {
    pub(crate) inventory_request_id: [u8; 16],
    pub(crate) inventory_request_digest: [u8; 32],
    pub(crate) inventory_request_packet: Vec<u8>,
    pub(crate) original_head: [u8; 32],
    pub(crate) archive_digest: [u8; 32],
    pub(crate) terminal_packet: Option<Vec<u8>>,
}

struct StorageInventoryArchiveV1 {
    group_request_id: [u8; 16],
    inventory_request_id: [u8; 16],
    group_request_digest: [u8; 32],
    inventory_request_digest: [u8; 32],
    history: StoredProtocolHistoryV1,
}

impl StorageInventoryArchiveV1 {
    fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        let history = self.history.encode()?;
        encode_frame(
            self.group_request_id,
            self.inventory_request_id,
            self.group_request_digest,
            self.inventory_request_digest,
            &history,
        )
    }

    fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        let (
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            history_bytes,
        ) = open_frame(key, bytes)?;
        let history = StoredProtocolHistoryV1::decode(
            &protocol_key(BrokerSessionProtocolV1::Storage),
            history_bytes,
        )?;
        let archive = Self {
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            history,
        };
        if archive.encode()? != bytes {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(archive)
    }
}

fn encode_frame(
    group_request_id: [u8; 16],
    inventory_request_id: [u8; 16],
    group_request_digest: [u8; 32],
    inventory_request_digest: [u8; 32],
    history: &[u8],
) -> Result<Vec<u8>, BrokerSessionSecurityError> {
    let length =
        u32::try_from(history.len()).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    if group_request_id == [0; 16]
        || inventory_request_id == [0; 16]
        || group_request_digest == [0; 32]
        || inventory_request_digest == [0; 32]
        || history.is_empty()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + history.len() + DIGEST_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&group_request_id);
    bytes.extend_from_slice(&inventory_request_id);
    bytes.extend_from_slice(&group_request_digest);
    bytes.extend_from_slice(&inventory_request_digest);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(history);
    bytes.extend_from_slice(
        &Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes)
            .finalize(),
    );
    Ok(bytes)
}

#[allow(clippy::type_complexity)]
fn open_frame<'a>(
    key: &[u8],
    bytes: &'a [u8],
) -> Result<([u8; 16], [u8; 16], [u8; 32], [u8; 32], &'a [u8]), BrokerSessionSecurityError> {
    if bytes.len() <= HEADER_BYTES + DIGEST_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || read_u16(bytes, 8)? != 1
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let group_request_id = read_array(bytes, 10)?;
    let inventory_request_id = read_array(bytes, 26)?;
    let group_request_digest = read_array(bytes, 42)?;
    let inventory_request_digest = read_array(bytes, 74)?;
    let length = usize::try_from(read_u32(bytes, 106)?)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let end = HEADER_BYTES
        .checked_add(length)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    if key != inventory_request_id
        || group_request_id == [0; 16]
        || inventory_request_id == [0; 16]
        || group_request_digest == [0; 32]
        || inventory_request_digest == [0; 32]
        || end.checked_add(DIGEST_BYTES) != Some(bytes.len())
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let expected_digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&bytes[..end])
        .finalize()
        .into();
    if read_array::<32>(bytes, end)? != expected_digest {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let history = bytes
        .get(HEADER_BYTES..end)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    Ok((
        group_request_id,
        inventory_request_id,
        group_request_digest,
        inventory_request_digest,
        history,
    ))
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn validate_storage_inventory_archives(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        let entries = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionStorageInventoryArchive)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut entries = Vec::new();
            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                if entries.len() == super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                entries.push((key.to_vec(), value.to_vec()));
            }
            entries
        };
        for (key, value) in entries {
            let archive = StorageInventoryArchiveV1::decode(&key, &value)?;
            self.classify_storage_inventory_archive(&archive)?;
        }
        Ok(())
    }

    fn classify_storage_inventory_archive(
        &mut self,
        archive: &StorageInventoryArchiveV1,
    ) -> Result<ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError> {
        let stored = &archive.history;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        if stored.protocol != BrokerSessionProtocolV1::Storage
            || stored.endpoint != self.endpoint.role()
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
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let request_index = match head.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => records.len() - 1,
            BrokerSessionDurablePhaseV1::Terminal => records
                .len()
                .checked_sub(2)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
        };
        let prepared = records
            .get(request_index)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let group = request_index
            .checked_sub(1)
            .and_then(|index| records.get(index))
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || prepared.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || prepared.request_id() != archive.inventory_request_id
            || Sha256::digest(prepared.request_packet()).as_slice()
                != archive.inventory_request_digest
            || group.phase() != BrokerSessionDurablePhaseV1::Terminal
            || group.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            || group.request_id() != archive.group_request_id
            || authority_envelope_digest(group.request_packet())? != archive.group_request_digest
            || !successful_terminal(group)?
            || group.client_sequence().checked_add(1) != Some(prepared.client_sequence())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let canonical = decode_canonical_request_v1(prepared.request_packet())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if canonical.signed_artifact().method()
            != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let terminal_packet = if head.phase() == BrokerSessionDurablePhaseV1::Terminal {
            let response = head
                .outcome_packet()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let canonical = decode_canonical_response_v1(response)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if head.request_packet() != prepared.request_packet()
                || head.request_id() != prepared.request_id()
                || canonical.message().request_id.as_slice() != prepared.request_id()
                || canonical.message().method.as_known()
                    != Some(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Some(response.to_vec())
        } else {
            None
        };
        Ok(ArchivedStorageInventoryHeadV1 {
            inventory_request_id: archive.inventory_request_id,
            inventory_request_digest: archive.inventory_request_digest,
            inventory_request_packet: prepared.request_packet().to_vec(),
            original_head: stored.current_head,
            archive_digest: Sha256::digest(archive.encode()?).into(),
            terminal_packet,
        })
    }

    pub(super) fn archived_storage_inventory_head(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError> {
        let archive = self
            .read_storage_inventory_archive(inventory_request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if archive.group_request_id != group_request_id
            || archive.group_request_digest != group_request_digest
            || archive.inventory_request_digest != inventory_request_digest
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.classify_storage_inventory_archive(&archive)
    }

    pub(super) fn verify_original_storage_inventory_terminal(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        packet: &[u8],
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
        let archive = self
            .read_storage_inventory_archive(inventory_request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if archive.group_request_id != group_request_id
            || archive.group_request_digest != group_request_digest
            || archive.inventory_request_digest != inventory_request_digest
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let head = self.classify_storage_inventory_archive(&archive)?;
        let checkpoint = archive
            .history
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let model = archive.history.history_model()?;
        let records = model.records();
        if let Some(retained) = head.terminal_packet {
            if retained != packet {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let terminal_index = records
                .len()
                .checked_sub(1)
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            return historical_terminal_outcome(records, terminal_index, checkpoint, &transcript);
        }
        let prepared = records
            .last()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let prior = reconstruct_traffic_records(
            &records[..records.len() - 1],
            &transcript,
            checkpoint.context(),
        )?;
        let canonical = decode_canonical_request_v1(prepared.request_packet())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let bindings = authenticated_semantic_bindings_from_envelope_v1(
            canonical.message(),
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let peer = checkpoint.peer();
        let policy = aos_sandbox_protocol::PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: checkpoint.context().audience(),
        };
        let retained_time = prepared
            .request_companion()
            .deadline_boottime_nanoseconds()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (request, pending_traffic) =
            match prepare_client_sent_authenticated_broker_method_request_v1(
                &prior,
                prepared.request_packet(),
                None,
                canonical.message().descriptors.len(),
                peer,
                policy,
                retained_time,
                bindings,
                checkpoint.context(),
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                AuthenticatedBrokerMethodRequestAdmissionV1::New {
                    request,
                    next_traffic,
                } => (request, next_traffic),
                AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            };
        if !request_matches_head(
            &request,
            prepared,
            AuthenticatedBrokerRequestDirectionV1::ClientSend,
        ) || request.semantic_commitment() != prepared.request_semantic_binding()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let canonical_response = decode_canonical_response_v1(packet)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(
            &pending_traffic,
            &request,
            packet,
            None,
            canonical_response.message().descriptors.len(),
            checkpoint.context(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?
        {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => outcome,
            AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        if !matches!(
            outcome.result(),
            AuthenticatedBrokerMethodResultV1::Success { .. }
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(outcome)
    }

    pub(super) fn original_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<Option<ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError> {
        let archived = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionStorageInventoryArchive)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut records = Vec::new();
            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                if records.len() == super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                records.push((key.to_vec(), value.to_vec()));
            }
            records
        };
        let mut matching = None;
        for (key, value) in archived {
            let archive = StorageInventoryArchiveV1::decode(&key, &value)?;
            if archive.group_request_id == group_request_id {
                if archive.group_request_digest != group_request_digest || matching.is_some() {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                matching = Some(self.classify_storage_inventory_archive(&archive)?);
            }
        }
        if matching.is_some() {
            return Ok(matching);
        }

        let history = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let model = history.history_model()?;
        let head = model
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if head.phase() == BrokerSessionDurablePhaseV1::Terminal
            && head.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            && head.request_id() == group_request_id
            && authority_envelope_digest(head.request_packet())? == group_request_digest
            && successful_terminal(head)?
        {
            return Ok(None);
        }
        let inventory_request_id = head.request_id();
        let inventory_request_digest = Sha256::digest(head.request_packet()).into();
        let archive = StorageInventoryArchiveV1 {
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            history,
        };
        self.classify_storage_inventory_archive(&archive).map(Some)
    }

    fn read_storage_inventory_archive(
        &mut self,
        inventory_request_id: [u8; 16],
    ) -> Result<Option<StorageInventoryArchiveV1>, BrokerSessionSecurityError> {
        let bytes = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionStorageInventoryArchive)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .get(&inventory_request_id)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        bytes
            .map(|bytes| StorageInventoryArchiveV1::decode(&inventory_request_id, &bytes))
            .transpose()
    }

    pub(super) fn archive_original_storage_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
    ) -> Result<ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError> {
        if let Some(archive) = self.read_storage_inventory_archive(inventory_request_id)? {
            if archive.group_request_id != group_request_id
                || archive.group_request_digest != group_request_digest
                || archive.inventory_request_digest != inventory_request_digest
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            return self.classify_storage_inventory_archive(&archive);
        }
        let history = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let archive = StorageInventoryArchiveV1 {
            group_request_id,
            inventory_request_id,
            group_request_digest,
            inventory_request_digest,
            history,
        };
        let head = self.classify_storage_inventory_archive(&archive)?;
        let value = archive.encode()?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(inventory_request_id)
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
                RecordNamespace::BrokerSessionStorageInventoryArchive,
                inventory_request_id.to_vec(),
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionStorageInventoryArchive)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&inventory_request_id)
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
            .read_storage_inventory_archive(inventory_request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if retained.encode()? != archive.encode()? {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.classify_storage_inventory_archive(&retained)
            .and_then(|readback| {
                if readback.original_head == head.original_head {
                    Ok(readback)
                } else {
                    Err(BrokerSessionSecurityError::Currentness)
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox::{Journal, JournalLimits};

    #[test]
    fn frame_binds_original_group_inventory_and_history() {
        let group_id = [5; 16];
        let inventory_id = [7; 16];
        let group_digest = [11; 32];
        let inventory_digest = [13; 32];
        let frame = encode_frame(
            group_id,
            inventory_id,
            group_digest,
            inventory_digest,
            b"original-protected-history",
        )
        .unwrap();
        let decoded = open_frame(&inventory_id, &frame).unwrap();
        assert_eq!(decoded.0, group_id);
        assert_eq!(decoded.2, group_digest);
        assert_eq!(decoded.3, inventory_digest);
        assert_eq!(decoded.4, b"original-protected-history");
        assert!(open_frame(&[8; 16], &frame).is_err());

        for offset in [10, 26, 42, 74, HEADER_BYTES, frame.len() - 1] {
            let mut tampered = frame.clone();
            tampered[offset] ^= 1;
            assert!(open_frame(&inventory_id, &tampered).is_err());
        }
        assert!(open_frame(&inventory_id, &frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn archived_original_survives_session_rollover_and_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("session.journal");
        let inventory_id = [17; 16];
        let archive = encode_frame(
            [5; 16],
            inventory_id,
            [11; 32],
            [13; 32],
            b"original-protected-history",
        )
        .unwrap();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let current_key = protocol_key(BrokerSessionProtocolV1::Storage);
        for (id, namespace, key, value) in [
            (
                1,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"old".to_vec(),
            ),
            (
                2,
                RecordNamespace::BrokerSessionStorageInventoryArchive,
                inventory_id.to_vec(),
                archive.clone(),
            ),
            (
                3,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"new".to_vec(),
            ),
        ] {
            journal
                .commit(
                    &JournalTransaction::new(
                        [id; 16],
                        vec![JournalRecord::put(namespace, key, value)],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        drop(journal);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::BrokerSessionTraffic, &current_key),
            Some(b"new".as_slice())
        );
        let retained = journal
            .get(
                RecordNamespace::BrokerSessionStorageInventoryArchive,
                &inventory_id,
            )
            .unwrap();
        assert_eq!(
            open_frame(&inventory_id, retained).unwrap().4,
            b"original-protected-history"
        );
    }
}
