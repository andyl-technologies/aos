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
use aos_sandbox::RecordNamespace;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1, decode_canonical_request_v1,
    decode_canonical_response_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodResultV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
};
use aos_sandbox_protocol::{
    ValidatedStorageInventoryRecoveryResponseV1, decode_storage_inventory_recovery_response_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    BrokerSessionSecurityError, ProtectedBrokerSessionJournalV1, StorageArchiveKind,
    StoredProtocolHistoryV1, authority_envelope_digest, historical_client_request,
    historical_terminal_outcome, protocol_key, read_array, read_u16, read_u32, reconstruct_traffic,
    storage_archive_key, successful_terminal,
};

const MAGIC: &[u8; 8] = b"AOSBSIA1";
const DOMAIN: &[u8] = b"aos.sandbox.broker-session.storage-inventory-archive.v1\0";
const HEADER_BYTES: usize = 8 + 2 + 16 + 16 + 32 + 32 + 4;
const DIGEST_BYTES: usize = 32;

fn exact_group_rollover(
    group: &StoredProtocolHistoryV1,
    status: &StoredProtocolHistoryV1,
    status_records: usize,
) -> bool {
    let Ok(status_records) = u64::try_from(status_records) else {
        return false;
    };
    group.stable_endpoint_identity == status.stable_endpoint_identity
        && group.endpoint_publication != status.endpoint_publication
        && (1..=2).contains(&status_records)
        && group.generation.checked_add(status_records) == Some(status.generation)
}

struct RetirementCandidate {
    request_id: [u8; 16],
    predecessor_id: Option<[u8; 16]>,
    value: Vec<u8>,
}

fn retirement_leaf(candidates: &[RetirementCandidate]) -> Option<&RetirementCandidate> {
    candidates.iter().find(|candidate| {
        !candidates
            .iter()
            .any(|other| other.predecessor_id == Some(candidate.request_id))
    })
}

/// Classifies only the exact signed inventory immediately after a terminal group.
pub(crate) struct ArchivedStorageInventoryHeadV1 {
    pub(crate) inventory_request_id: [u8; 16],
    pub(crate) inventory_request_digest: [u8; 32],
    pub(crate) inventory_request_packet: Vec<u8>,
    pub(crate) original_head: [u8; 32],
    pub(crate) archive_digest: [u8; 32],
    pub(crate) terminal_packet: Option<Vec<u8>>,
    pub(crate) fresh: bool,
}

pub(super) struct StorageInventoryArchiveV1 {
    pub(super) group_request_id: [u8; 16],
    inventory_request_id: [u8; 16],
    pub(super) group_request_digest: [u8; 32],
    pub(super) inventory_request_digest: [u8; 32],
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
        let entries = self.bounded_storage_records(
            RecordNamespace::BrokerSessionStorageInventoryArchive,
            super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES,
        )?;
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
        self.classify_storage_inventory_archive_inner(archive, 0)
    }

    pub(super) fn classify_storage_inventory_archive_inner(
        &mut self,
        archive: &StorageInventoryArchiveV1,
        depth: usize,
    ) -> Result<ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError> {
        if depth >= super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES {
            return Err(BrokerSessionSecurityError::Currentness);
        }
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
        let predecessor = request_index
            .checked_sub(1)
            .and_then(|index| records.get(index));
        if prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || prepared.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || prepared.request_id() != archive.inventory_request_id
            || Sha256::digest(prepared.request_packet()).as_slice()
                != archive.inventory_request_digest
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let fresh = match predecessor {
            Some(group)
                if group.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT =>
            {
                if group.phase() != BrokerSessionDurablePhaseV1::Terminal
                    || group.request_id() != archive.group_request_id
                    || authority_envelope_digest(group.request_packet())?
                        != archive.group_request_digest
                    || !successful_terminal(group)?
                    || group.client_sequence().checked_add(1) != Some(prepared.client_sequence())
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                false
            }
            Some(control)
                if control.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY =>
            {
                self.validate_fresh_control_predecessor(archive, records, request_index, depth)?;
                true
            }
            None if request_index == 0 => {
                self.validate_standalone_fresh_group(archive, stored)?;
                true
            }
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
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
            fresh,
        })
    }

    fn validate_fresh_control_predecessor(
        &mut self,
        archive: &StorageInventoryArchiveV1,
        records: &[aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1],
        request_index: usize,
        depth: usize,
    ) -> Result<(), BrokerSessionSecurityError> {
        if request_index != 2 {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let control = records
            .first()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let terminal = records
            .get(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let status = records
            .get(2)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if control.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || control.method() != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            || terminal.phase() != BrokerSessionDurablePhaseV1::Terminal
            || control.request_packet() != terminal.request_packet()
            || control.request_id() != terminal.request_id()
            || !successful_terminal(terminal)?
            || terminal.client_sequence().checked_add(1) != Some(status.client_sequence())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let canonical = decode_canonical_request_v1(control.request_packet())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let coordinates = aos_proto::aos::sandbox::local::v1::RecoverStorageInventoryRequestV1::decode_from_slice(
            &canonical.message().body,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let prior_id: [u8; 16] = coordinates
            .inventory_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let prior_digest: [u8; 32] = coordinates
            .inventory_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let client_head: [u8; 32] = coordinates
            .client_original_head
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if coordinates.group_request_id.as_slice() != archive.group_request_id
            || coordinates.group_request_digest.as_slice() != archive.group_request_digest
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_storage_inventory_abandonment_chain(
            prior_id,
            archive.group_request_id,
            archive.group_request_digest,
            prior_digest,
            client_head,
            depth + 1,
        )?;
        let marker = self
            .read_storage_inventory_abandonment(prior_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let response = decode_canonical_response_v1(
            terminal
                .outcome_packet()
                .ok_or(BrokerSessionSecurityError::Currentness)?,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let decision = decode_storage_inventory_recovery_response_v1(
            &response.message().body,
            control.maximum_response_bytes(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let expected_abandonment_digest = if marker.endpoint
            == aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker
        {
            marker.digest()?
        } else {
            marker.broker_marker_digest
        };
        match decision {
            ValidatedStorageInventoryRecoveryResponseV1::AbandonedReadOnly {
                broker_head,
                archive_digest,
                abandonment_digest,
            } if broker_head == marker.broker_original_head
                && archive_digest == marker.broker_archive_digest
                && abandonment_digest == expected_abandonment_digest =>
            {
                Ok(())
            }
            _ => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn validate_standalone_fresh_group(
        &mut self,
        archive: &StorageInventoryArchiveV1,
        status: &StoredProtocolHistoryV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let group = self
            .read_atomic_storage_archive(archive.group_request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = group.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if !exact_group_rollover(
            &group,
            status,
            archive.history.history_model()?.records().len(),
        ) || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            || head.request_id() != archive.group_request_id
            || authority_envelope_digest(head.request_packet())? != archive.group_request_digest
            || !successful_terminal(head)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
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
        let request_index = records
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (request, pending_traffic) =
            historical_client_request(records, request_index, checkpoint, &transcript)?;
        if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES {
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
        let archived = self.bounded_storage_records(
            RecordNamespace::BrokerSessionStorageInventoryArchive,
            super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES,
        )?;
        let mut matching = None;
        for (key, value) in archived {
            let archive = StorageInventoryArchiveV1::decode(&key, &value)?;
            if archive.group_request_id == group_request_id {
                if archive.group_request_digest != group_request_digest {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                let head = self.classify_storage_inventory_archive(&archive)?;
                if !head.fresh {
                    if matching.is_some() {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    matching = Some(head);
                }
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
        if self
            .fresh_storage_inventory_coordinates(group_request_id, group_request_digest)?
            .is_some()
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

    pub(super) fn fresh_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
    ) -> Result<Option<ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError> {
        let current = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = current.history_model()?;
        let records = history.records();
        let first = records
            .first()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let control = if first.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
            let canonical = decode_canonical_request_v1(first.request_packet())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let coordinates = aos_proto::aos::sandbox::local::v1::RecoverStorageInventoryRequestV1::decode_from_slice(
                &canonical.message().body,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if coordinates.group_request_id.as_slice() != group_request_id
                || coordinates.group_request_digest.as_slice() != group_request_digest
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Some(coordinates)
        } else if first.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES {
            None
        } else {
            return Ok(None);
        };
        let (inventory_request_id, inventory_request_digest) =
            if head.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES {
                (
                    head.request_id(),
                    Sha256::digest(head.request_packet()).into(),
                )
            } else if head.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
                let coordinates = control.ok_or(BrokerSessionSecurityError::Currentness)?;
                (
                    coordinates
                        .inventory_request_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?,
                    coordinates
                        .inventory_request_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?,
                )
            } else {
                return Ok(None);
            };
        let archive = match self.read_storage_inventory_archive(inventory_request_id)? {
            Some(archive) => archive,
            None if head.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
                StorageInventoryArchiveV1 {
                    group_request_id,
                    inventory_request_id,
                    group_request_digest,
                    inventory_request_digest,
                    history: current,
                }
            }
            // A committed recovery control cannot be classified from the
            // current head alone; its exact status archive is mandatory.
            None => return Err(BrokerSessionSecurityError::Currentness),
        };
        if archive.group_request_id != group_request_id
            || archive.group_request_digest != group_request_digest
            || archive.inventory_request_digest != inventory_request_digest
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let classified = self.classify_storage_inventory_archive(&archive)?;
        if classified.fresh {
            Ok(Some(classified))
        } else {
            Ok(None)
        }
    }

    // Retire leaves before their signed control predecessors. Every intermediate
    // state remains reopenable if a crash interrupts cleanup between journals.
    pub(super) fn retire_storage_inventory_for_group(
        &mut self,
        group_request_id: [u8; 16],
    ) -> Result<(), BrokerSessionSecurityError> {
        self.validate_storage_inventory_archives()?;
        self.validate_storage_inventory_abandonments()?;
        for _ in 0..=super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES {
            let entries = self.bounded_storage_records(
                RecordNamespace::BrokerSessionStorageInventoryArchive,
                super::MAXIMUM_STORAGE_INVENTORY_ARCHIVES,
            )?;
            let mut relevant = Vec::new();
            for (key, value) in entries {
                let archive = StorageInventoryArchiveV1::decode(&key, &value)?;
                if archive.group_request_id == group_request_id {
                    let predecessor = archive.predecessor_inventory_id()?;
                    relevant.push(RetirementCandidate {
                        request_id: archive.inventory_request_id,
                        predecessor_id: predecessor,
                        value,
                    });
                }
            }
            if relevant.is_empty() {
                return Ok(());
            }
            let leaf = retirement_leaf(&relevant).ok_or(BrokerSessionSecurityError::Currentness)?;
            let request_id = leaf.request_id;
            let archive_value = leaf.value.clone();
            let marker_key = storage_archive_key(
                RecordNamespace::BrokerSessionStorageInventoryAbandonment,
                request_id,
            )?;
            let marker_value = {
                let authority = self
                    .journal_mut()?
                    .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                authority
                    .get(&marker_key)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?
                    .map(<[u8]>::to_vec)
            };
            if let Some(marker_value) = marker_value {
                self.retire_exact_storage_inventory_record(
                    RecordNamespace::BrokerSessionStorageInventoryAbandonment,
                    request_id,
                    &marker_value,
                )?;
            }
            self.retire_exact_storage_inventory_record(
                RecordNamespace::BrokerSessionStorageInventoryArchive,
                request_id,
                &archive_value,
            )?;
        }
        Err(BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn read_storage_inventory_archive(
        &mut self,
        inventory_request_id: [u8; 16],
    ) -> Result<Option<StorageInventoryArchiveV1>, BrokerSessionSecurityError> {
        let key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageInventoryArchive,
            inventory_request_id,
        )?;
        let bytes = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .get(&key)
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
        self.commit_absent_storage_archive(
            StorageArchiveKind::Inventory,
            inventory_request_id,
            value,
        )?;
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

impl StorageInventoryArchiveV1 {
    fn predecessor_inventory_id(&self) -> Result<Option<[u8; 16]>, BrokerSessionSecurityError> {
        let history = self.history.history_model()?;
        let first = history
            .records()
            .first()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if first.method() != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
            return Ok(None);
        }
        let canonical = decode_canonical_request_v1(first.request_packet())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let coordinates = aos_proto::aos::sandbox::local::v1::RecoverStorageInventoryRequestV1::decode_from_slice(
            &canonical.message().body,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        coordinates
            .inventory_request_id
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction};

    #[test]
    fn fresh_status_requires_the_immediate_archived_group_generation() {
        let group = StoredProtocolHistoryV1 {
            protocol: BrokerSessionProtocolV1::Storage,
            endpoint: aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker,
            generation: 7,
            stable_endpoint_identity: [3; 32],
            endpoint_publication: [5; 32],
            current_catalog: [7; 32],
            current_head: [11; 32],
            history: Vec::new(),
            checkpoint: None,
        };
        let mut status = group.clone();
        status.generation += 1;
        status.endpoint_publication = [13; 32];
        assert!(exact_group_rollover(&group, &status, 1));

        status.generation += 1;
        assert!(exact_group_rollover(&group, &status, 2));
        assert!(!exact_group_rollover(&group, &status, 1));
        status.generation += 1;
        assert!(!exact_group_rollover(&group, &status, 2));
        status.generation -= 1;
        status.stable_endpoint_identity = [17; 32];
        assert!(!exact_group_rollover(&group, &status, 2));
        status.stable_endpoint_identity = group.stable_endpoint_identity;
        status.endpoint_publication = group.endpoint_publication;
        assert!(!exact_group_rollover(&group, &status, 2));
    }

    #[test]
    fn retirement_removes_newest_status_before_its_marker_dependency() {
        let candidates = [
            RetirementCandidate {
                request_id: [1; 16],
                predecessor_id: None,
                value: Vec::new(),
            },
            RetirementCandidate {
                request_id: [2; 16],
                predecessor_id: Some([1; 16]),
                value: Vec::new(),
            },
            RetirementCandidate {
                request_id: [3; 16],
                predecessor_id: Some([2; 16]),
                value: Vec::new(),
            },
        ];
        assert_eq!(retirement_leaf(&candidates).unwrap().request_id, [3; 16]);
        assert_eq!(
            retirement_leaf(&candidates[..2]).unwrap().request_id,
            [2; 16]
        );
        assert_eq!(
            retirement_leaf(&candidates[..1]).unwrap().request_id,
            [1; 16]
        );

        let cycle = [
            RetirementCandidate {
                request_id: [1; 16],
                predecessor_id: Some([2; 16]),
                value: Vec::new(),
            },
            RetirementCandidate {
                request_id: [2; 16],
                predecessor_id: Some([1; 16]),
                value: Vec::new(),
            },
        ];
        assert!(retirement_leaf(&cycle).is_none());
    }

    #[test]
    fn crash_between_leaf_marker_and_archive_deletion_preserves_history() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("retirement.journal");
        let inventory_id = [23; 16];
        let archived = encode_frame(
            [5; 16],
            inventory_id,
            [11; 32],
            [13; 32],
            b"signed-inventory-history",
        )
        .unwrap();
        let archive_key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageInventoryArchive,
            inventory_id,
        )
        .unwrap();
        let marker_key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageInventoryAbandonment,
            inventory_id,
        )
        .unwrap();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        for (id, key, value) in [
            (1, archive_key.clone(), archived.clone()),
            (2, marker_key.clone(), b"signed-marker".to_vec()),
        ] {
            journal
                .commit(
                    &JournalTransaction::new(
                        [id; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::BrokerSessionTraffic,
                            key,
                            value,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        journal
            .commit(
                &JournalTransaction::new(
                    [3; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::BrokerSessionTraffic,
                        marker_key.clone(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(
            journal
                .get(RecordNamespace::BrokerSessionTraffic, &marker_key)
                .is_none()
        );
        let retained = journal
            .get(RecordNamespace::BrokerSessionTraffic, &archive_key)
            .unwrap();
        assert_eq!(
            open_frame(&inventory_id, retained).unwrap().4,
            b"signed-inventory-history"
        );
        journal
            .commit(
                &JournalTransaction::new(
                    [4; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::BrokerSessionTraffic,
                        archive_key.clone(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(
            journal
                .get(RecordNamespace::BrokerSessionTraffic, &archive_key)
                .is_none()
        );
    }

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
        let archive_key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageInventoryArchive,
            inventory_id,
        )
        .unwrap();
        for (id, namespace, key, value) in [
            (
                1,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"old".to_vec(),
            ),
            (
                2,
                RecordNamespace::BrokerSessionTraffic,
                archive_key.clone(),
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
            .get(RecordNamespace::BrokerSessionTraffic, &archive_key)
            .unwrap();
        assert_eq!(
            open_frame(&inventory_id, retained).unwrap().4,
            b"original-protected-history"
        );
    }
}
