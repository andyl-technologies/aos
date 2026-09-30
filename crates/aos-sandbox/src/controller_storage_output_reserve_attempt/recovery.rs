//! Strict cold historical loading for complete immutable Output archives.
//!
//! The loader recognizes only the closed original key shapes. An orphan,
//! duplicate slot or malformed record is never absence. Unsupported complete
//! carrier bytes survive as DATA, not a new request or Storage reserve grant.
//!
//! ```text
//! no related keys -> Absent
//! sole AOSCST01 -> LegacyAttemptOnly
//! AOSCST01 + AOSCSA01 + exact complete chunks -> historical archive
//! absent method46 profile -> UnsupportedHistoricalCarrier (same bytes)
//! ```

use aos_proto::aos::sandbox::local::v1::{
    BrokerRequestEnvelope, ReserveStorageExecutionOutputRequestV1,
};
use aos_sandbox_core::format::decode_broker_authorization_plan;
use aos_sandbox_core::{
    BrokerAudience, DecodeLimits, ExecutionId, MediaType, PortableMediaType,
    ProtocolId, ProtocolVersion, descriptor_for_bytes,
};
use aos_sandbox_protocol::storage_output_reserve::authority_archive::{
    HistoricalStorageOutputArchiveErrorV1, HistoricalStorageOutputAuthorityArchiveV1,
};
use aos_sandbox_protocol::storage_output_reserve::storage_output_reserve_grant_v1;
use buffa::Message as _;

use crate::Journal;

use super::authority::{
    HistoricalStorageOutputRetentionErrorV1, NAMESPACE, require_fixed_controller_writer,
};
use super::publication_chunks::HistoricalOutputPublicationChunkViewV1;
use super::{ControllerStorageOutputReserveAttemptV1, inspect_original};

/// Retains fully loaded historical original bytes without any effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalLoadedStorageOutputArchiveV1 {
    attempt: ControllerStorageOutputReserveAttemptV1,
    companion: HistoricalStorageOutputAuthorityArchiveV1,
    publication: Vec<u8>,
}

impl HistoricalLoadedStorageOutputArchiveV1 {
    /// Borrows the existing immutable historical original attempt.
    #[must_use]
    pub const fn attempt(&self) -> &ControllerStorageOutputReserveAttemptV1 {
        &self.attempt
    }

    /// Borrows every retained companion preimage, never a current source cut.
    #[must_use]
    pub const fn companion(&self) -> &HistoricalStorageOutputAuthorityArchiveV1 {
        &self.companion
    }

    /// Borrows the complete reconstructed historical publication bytes.
    #[must_use]
    pub fn publication_bytes(&self) -> &[u8] {
        &self.publication
    }
}

/// Classifies cold Controller archive DATA, never proven Storage absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoricalStorageOutputArchiveStateV1 {
    /// No original or related Controller archive key exists for the execution.
    Absent,
    /// The sole legacy AOSCST01 remains historical and cannot be upgraded.
    LegacyAttemptOnly(ControllerStorageOutputReserveAttemptV1),
    /// The full historical carrier is supported; no current owner is claimed.
    CompleteHistoricalArchive(HistoricalLoadedStorageOutputArchiveV1),
    /// Every outer byte is retained, but the carrier profile remains closed.
    UnsupportedHistoricalCarrier(HistoricalLoadedStorageOutputArchiveV1),
}

/// Loads complete cold original bytes from the SAME fixed Controller writer.
///
/// This function does not reopen a writer, query Storage, regenerate authority
/// or convert historical data to a floor/currentness/source permit.
///
/// # Errors
///
/// Rejects unhealthy/replaced protected custody, malformed key shapes, target
/// orphan/duplicate slots, changed identities/digests, missing/extra chunks and
/// malformed canonical nested data. Unsupported method46 is a historical state,
/// not success, absence or permission to retry.
/// Validation of other owners' global archive dependencies remains separate.
pub fn load_historical_complete_storage_output_archive_v1(
    controller: &Journal,
    execution: ExecutionId,
) -> Result<HistoricalStorageOutputArchiveStateV1, HistoricalStorageOutputRetentionErrorV1> {
    require_fixed_controller_writer(controller)?;
    if execution.as_bytes() == &[0; 16] {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    let selected = select_records(controller.records(NAMESPACE), execution)?;
    let state = decode_selected(execution, selected)?;
    require_fixed_controller_writer(controller)?;
    Ok(state)
}

#[derive(Default)]
struct SelectedRecords<'records> {
    attempt: Option<&'records [u8]>,
    companion: Option<&'records [u8]>,
    chunks: [Option<&'records [u8]>; 2],
}

enum ArchiveKey {
    Attempt(ExecutionId),
    Companion(ExecutionId),
    Chunk(ExecutionId, usize),
}

fn classify_key(key: &[u8]) -> Result<ArchiveKey, HistoricalStorageOutputRetentionErrorV1> {
    let (bytes, slot) = match key {
        bytes if bytes.len() == 16 => (bytes, 0),
        [b'a', bytes @ ..] if bytes.len() == 16 => (bytes, 1),
        [b'p', index, bytes @ ..] if bytes.len() == 16 && *index < 2 => (bytes, 2 + usize::from(*index)),
        [b'h' | b'q', bytes @ ..] if bytes.len() == 16 => {
            return Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedFutureKind.into());
        }
        _ => return Err(HistoricalStorageOutputRetentionErrorV1::Invalid),
    };
    let identity: [u8; 16] = bytes.try_into().map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    if identity == [0; 16] {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    let execution = ExecutionId::from_bytes(identity);
    Ok(match slot {
        0 => ArchiveKey::Attempt(execution),
        1 => ArchiveKey::Companion(execution),
        index => ArchiveKey::Chunk(execution, index - 2),
    })
}

fn select_records<'records>(
    records: impl IntoIterator<Item = (&'records [u8], &'records [u8])>,
    execution: ExecutionId,
) -> Result<SelectedRecords<'records>, HistoricalStorageOutputRetentionErrorV1> {
    let mut selected = SelectedRecords::default();
    for (key, value) in records {
        let slot = match classify_key(key)? {
            ArchiveKey::Attempt(identity) if identity == execution => &mut selected.attempt,
            ArchiveKey::Companion(identity) if identity == execution => &mut selected.companion,
            ArchiveKey::Chunk(identity, index) if identity == execution => &mut selected.chunks[index],
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
    }
    Ok(selected)
}

fn decode_selected(
    execution: ExecutionId,
    selected: SelectedRecords<'_>,
) -> Result<HistoricalStorageOutputArchiveStateV1, HistoricalStorageOutputRetentionErrorV1> {
    let Some(attempt_bytes) = selected.attempt else {
        if selected.companion.is_some() || selected.chunks.iter().any(Option::is_some) {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        return Ok(HistoricalStorageOutputArchiveStateV1::Absent);
    };
    let attempt = ControllerStorageOutputReserveAttemptV1::decode(attempt_bytes)
        .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    if attempt.execution() != execution {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    let Some(companion_bytes) = selected.companion else {
        if selected.chunks.iter().any(Option::is_some) {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        return Ok(HistoricalStorageOutputArchiveStateV1::LegacyAttemptOnly(attempt));
    };
    let companion = HistoricalStorageOutputAuthorityArchiveV1::decode(companion_bytes)?;
    validate_attempt_companion(&attempt, &companion)?;
    let publication = reconstruct_publication(&attempt, &companion, &selected.chunks)?;
    let loaded = HistoricalLoadedStorageOutputArchiveV1 {
        attempt,
        companion,
        publication,
    };
    match loaded.companion.canonical_carrier() {
        Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedCarrierProfile) => {
            Ok(HistoricalStorageOutputArchiveStateV1::UnsupportedHistoricalCarrier(loaded))
        }
        Err(error) => Err(error.into()),
        Ok(carrier) => {
            validate_carrier_message(&loaded.attempt, &loaded.companion, carrier.message())?;
            let quartet = carrier.message().authorization.as_option()
                .ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?;
            crate::publication::validate_historical_output_publication_v1(
                &loaded.publication, loaded.companion.publication_digest(),
                Some((&quartet.ownership_lease, &quartet.ownership_lease_signature)),
            ).map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
            Ok(HistoricalStorageOutputArchiveStateV1::CompleteHistoricalArchive(loaded))
        }
    }
}

/// Compares historical packet contents with the exact existing attempt once.
pub(super) fn validate_carrier_message(
    attempt: &ControllerStorageOutputReserveAttemptV1,
    companion: &HistoricalStorageOutputAuthorityArchiveV1,
    message: &BrokerRequestEnvelope,
) -> Result<(), HistoricalStorageOutputRetentionErrorV1> {
    if message.body != attempt.canonical_body() || !message.descriptors.is_empty() {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    let quartet = message.authorization.as_option()
        .ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    let limits = DecodeLimits {
        maximum_bytes: 786_432,
        maximum_collection_items: 1_024,
        maximum_total_items: 128 * 1_024,
        maximum_byte_string_bytes: 786_432,
        maximum_text_bytes: 65_536,
        maximum_depth: 32,
    };
    let plan = decode_broker_authorization_plan(&quartet.broker_plan, limits)
        .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::BrokerAuthorizationPlan.as_str().to_owned())
            .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?,
        &quartet.broker_plan,
    );
    let (_, records, _) = inspect_original(attempt.canonical_body())
        .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    let grant = storage_output_reserve_grant_v1(
        records.assignment(), attempt.original_request_id(), attempt.canonical_body(),
    ).map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    let body = ReserveStorageExecutionOutputRequestV1::decode_from_slice(attempt.canonical_body())
        .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    let header = body.header.as_option().ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    if descriptor.digest() != attempt.signed_plan_digest()
        || plan.audience() != BrokerAudience::Storage
        || plan.protocol() != ProtocolId::StorageBroker
        || plan.protocol_version() != ProtocolVersion::new(1, 0)
        || plan.assignment() != records.assignment()
        || plan.grants() != [grant]
        || plan.node().as_bytes() != &companion.controller_manifest().node_id()
        || plan.node().as_bytes() != &records.attempt()[8 + 584..8 + 600]
        || header.deadline_boottime_nanoseconds
            != companion.original_coordinates().deadline_boottime_nanoseconds()
    {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    Ok(())
}

pub(super) fn validate_attempt_companion(
    attempt: &ControllerStorageOutputReserveAttemptV1,
    companion: &HistoricalStorageOutputAuthorityArchiveV1,
) -> Result<(), HistoricalStorageOutputRetentionErrorV1> {
    let coordinates = companion.original_coordinates();
    let (_, records, _) = inspect_original(attempt.canonical_body())
        .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    if attempt.execution != coordinates.execution()
        || attempt.create_operation != coordinates.create_operation()
        || attempt.original_request_id() != coordinates.request_id()
        || attempt.record_digest() != companion.attempt_digest()
        || records.host_locator().host_boot_id() != companion.owner_cut_data().boot_id()
        || records.assignment().digest() != companion.owner_cut_data().assignment_manifest_digest()
        || coordinates.deadline_boottime_nanoseconds() > records.deadline_boottime_nanoseconds()
    {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    Ok(())
}

fn reconstruct_publication(
    attempt: &ControllerStorageOutputReserveAttemptV1,
    companion: &HistoricalStorageOutputAuthorityArchiveV1,
    encoded: &[Option<&[u8]>; 2],
) -> Result<Vec<u8>, HistoricalStorageOutputRetentionErrorV1> {
    let first = HistoricalOutputPublicationChunkViewV1::decode(
        encoded[0].ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?,
    )?;
    let count = usize::from(first.count);
    if encoded[count..].iter().any(Option::is_some) {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    let mut publication = Vec::with_capacity(first.full_length);
    for (index, bytes) in encoded[..count].iter().enumerate() {
        let chunk = if index == 0 {
            first
        } else {
            HistoricalOutputPublicationChunkViewV1::decode(
                bytes.ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?,
            )?
        };
        if usize::from(chunk.index) != index
            || chunk.count != first.count
            || chunk.full_length != first.full_length
            || chunk.execution != attempt.execution
            || chunk.create_operation != attempt.create_operation
            || chunk.publication_digest != companion.publication_digest()
        {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
        publication.extend_from_slice(chunk.payload());
    }
    if publication.len() != first.full_length {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    crate::publication::validate_historical_output_publication_v1(
        &publication, companion.publication_digest(),
        None,
    ).map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    Ok(publication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ObjectDigest;

    #[test]
    fn unknown_key_and_duplicate_original_are_errors_not_absence() {
        let execution = ExecutionId::from_bytes([1; 16]);
        let key = [1; 16];
        let records = [(key.as_slice(), b"one".as_slice()), (key.as_slice(), b"two".as_slice())];
        assert!(select_records(records, execution).is_err());
        assert!(select_records([(b"unknown".as_slice(), b"data".as_slice())], execution).is_err());
    }

    #[test]
    fn companion_or_chunk_without_attempt_is_never_absent() {
        let execution = ExecutionId::from_bytes([1; 16]);
        let mut key = vec![b'a'];
        key.extend_from_slice(execution.as_bytes());
        let selected = select_records([(key.as_slice(), b"orphan".as_slice())], execution).unwrap();
        assert!(decode_selected(execution, selected).is_err());

        let selected = SelectedRecords { chunks: [Some(b"orphan"), None], ..Default::default() };
        assert!(decode_selected(execution, selected).is_err());
    }

    #[test]
    fn legacy_original_is_loaded_verbatim_without_an_archive_upgrade() {
        let attempt = ControllerStorageOutputReserveAttemptV1::from_original(
            &super::super::tests::original_body(), ObjectDigest::from_bytes([20; 32]),
        ).unwrap();
        let bytes = attempt.encode();
        let selected = SelectedRecords { attempt: Some(&bytes), ..Default::default() };
        assert_eq!(decode_selected(attempt.execution(), selected).unwrap(),
            HistoricalStorageOutputArchiveStateV1::LegacyAttemptOnly(attempt));
    }
}
