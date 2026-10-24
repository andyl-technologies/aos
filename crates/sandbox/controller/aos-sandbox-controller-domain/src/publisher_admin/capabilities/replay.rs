//! Shares the complete canonical capability registry comparison and census.
//!
//! Ordinary protected stores retain their real guard and Runtime scan position.
//! Root and C17 consume only historical DATA under their own paid native owners;
//! no record, state marker or census creates current authorization or revocation.

use super::*;
use crate::publisher_admin::PublisherReadDataV2;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2;
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read as runtime;

pub(super) struct CapabilityRegistrySummaryV2 {
    pub(super) entries: usize,
    pub(super) materialized_bytes: usize,
    pub(super) has_runtime_issuance: bool,
    pub(super) handle_index: BTreeMap<[u8; 32], CapabilityId>,
}

pub(super) fn validate_registry_rows_v2(
    rows: PublisherReadDataV2<'_>, limits: PublisherAuthorityLimits,
) -> Result<CapabilityRegistrySummaryV2, PublisherAuthorityError> {
    let mut entries = 0_usize;
    let mut materialized_bytes = 0_usize;
    let mut has_runtime_issuance = false;
    let mut handle_index = BTreeMap::new();
    let mut child_counts = BTreeMap::<CapabilityId, u32>::new();
    for (key, value) in rows.records(RecordNamespace::PublisherAuthority) {
        entries = entries
            .checked_add(1)
            .ok_or(PublisherAuthorityError::LimitExceeded("entry count"))?;
        if entries > limits.maximum_entries {
            return Err(PublisherAuthorityError::LimitExceeded("entry count"));
        }
        capability_id_from_key(key)?;
        if value.len() > limits.maximum_record_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("record bytes"));
        }
        materialized_bytes = materialized_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
        if materialized_bytes > limits.maximum_materialized_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
        }
        let record = decode_record(key, value, limits.maximum_record_bytes)?;
        if let Some(handle) = record.handle {
            if handle_index
                .insert(handle_digest(&handle), record.capability.id())
                .is_some()
            {
                return Err(PublisherAuthorityError::DuplicateHandle);
            }
        }
        has_runtime_issuance |= record.runtime.is_some();
        if let Some(parent) = record.parent {
            let parent_key = capability_key(parent);
            let parent_bytes = rows
                .get(RecordNamespace::PublisherAuthority, &parent_key)
                .ok_or(PublisherAuthorityError::InvalidParentLink)?;
            let parent_record =
                decode_record(&parent_key, parent_bytes, limits.maximum_record_bytes)?;
            validate_parent_link(&parent_record.capability, &record.capability)?;

            let count = child_counts.entry(parent).or_default();
            *count = count
                .checked_add(1)
                .ok_or(PublisherAuthorityError::LimitExceeded("parent fanout"))?;
        }
    }

    for (parent_id, child_count) in child_counts {
        let key = capability_key(parent_id);
        let parent = rows
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::InvalidParentLink)?;
        let parent = decode_record(&key, parent, limits.maximum_record_bytes)?;
        if child_count > parent.capability.claims().delegation.maximum_fanout() {
            return Err(PublisherAuthorityError::FanoutExceeded);
        }
    }

    Ok(CapabilityRegistrySummaryV2 { entries, materialized_bytes,
        has_runtime_issuance, handle_index })
}

/// Retains complete canonical original rows after the sole registry validation.
pub(crate) struct PublisherCapabilityCensusDataV2 {
    pub(crate) records: Vec<aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2>,
}

/// Validates all registry parents, handles, fanout and Runtime historical links.
pub(crate) fn publisher_capability_census_from_rows_v2(
    rows: PublisherReadDataV2<'_>, history: HistoricalLedgerRowsDataV2<'_>,
    limits: PublisherAuthorityLimits,
) -> Result<PublisherCapabilityCensusDataV2, PublisherAuthorityError> {
    let summary = validate_registry_rows_v2(rows, limits)?;
    if summary.has_runtime_issuance {
        runtime::scan_namespace_rows_data_v2(history, limits.runtime_limits.data_v2())
            .map_err(crate::runtime_authority::RuntimeAuthorityError::from)?;
    }
    let mut records = Vec::new();
    records.try_reserve_exact(summary.entries)
        .map_err(|_| PublisherAuthorityError::LimitExceeded("census allocation"))?;
    for (key, value) in rows.records(RecordNamespace::PublisherAuthority) {
        let record = decode_record(key, value, limits.maximum_record_bytes)?;
        if let Some(runtime) = &record.runtime {
            let sandbox = record.capability.claims().sandbox
                .ok_or(PublisherAuthorityError::IssuanceCrosslinkMismatch)?;
            let binding = runtime::binding_rows_data_v2(history, sandbox, runtime.binding_revision())
                .map_err(crate::runtime_authority::RuntimeAuthorityError::from)?;
            runtime.validate_binding_data_v2(&binding, &record.capability)?;
        }
        records.push(aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2 {
            key: key.to_vec(), original: value.to_vec(), capability: record.capability,
            state: match record.state {
                DurableCapabilityStateV1::Active => aos_sandbox_protocol::domain_ledger::delete_batch::
                    capability_retention::CapabilityRegistryStateDataV2::Active,
                DurableCapabilityStateV1::Revoked => aos_sandbox_protocol::domain_ledger::delete_batch::
                    capability_retention::CapabilityRegistryStateDataV2::Revoked,
            },
        });
    }
    Ok(PublisherCapabilityCensusDataV2 { records })
}

/// Prices encoded copies, actual JSON models and the two-parent decode peak.
///
/// The caller separately includes its existing full-prefix Runtime/operation/
/// publication semantic recipe. JSON scalar/collection cardinality is bounded by
/// encoded bytes; these are MemoryBytes, never namespace entries per Rust field.
pub(crate) fn publisher_capability_census_receiving_bytes_v2(
    rows: PublisherReadDataV2<'_>,
) -> Option<usize> {
    use aos_sandbox_model::{Grant, Selector};
    let model = std::mem::size_of::<DurableCapabilityRecordWireV1>()
        .checked_add(std::mem::size_of::<DecodedCapabilityRecordV1>())?
        .checked_add(std::mem::size_of::<CapabilityRecord>())?
        .checked_add(std::mem::size_of::<Grant>())?
        .checked_add(std::mem::size_of::<Selector>())?
        .checked_add(std::mem::size_of::<(CapabilityId, u32)>())?
        .checked_add(std::mem::size_of::<([u8; 32], CapabilityId)>())?;
    let entries = rows.records(RecordNamespace::PublisherAuthority).count();
    let handles = aos_sandbox_journal::geometry::
        conservative_btree_node_bytes_v1::<[u8; 32], CapabilityId>(entries)?;
    let parents = aos_sandbox_journal::geometry::
        conservative_btree_node_bytes_v1::<CapabilityId, u32>(entries)?;
    let mut bytes = 3usize.checked_mul(std::mem::size_of::<PublisherCapabilityCensusDataV2>())?
        .checked_add(handles)?.checked_add(parents)?;
    for (key, value) in rows.records(RecordNamespace::PublisherAuthority) {
        // The complete retained model coexists with up to three transient
        // record/parent decodes and bounded canonical re-encoding buffers.
        bytes = bytes.checked_add(value.len().checked_mul(model.checked_mul(4)?.checked_add(8)?)?)?
            .checked_add(key.len().checked_mul(4)?)?
            .checked_add(3 * std::mem::size_of::<aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2>())?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::delete_batch::capability_retention::{
        capability_delete_retention_data_v2, CapabilityDeleteRetentionDataV2,
        CapabilityRegistryStateDataV2,
    };

    #[test]
    fn complete_project_authority_is_censused_without_inventing_retention() {
        let capability = super::super::tests::capability(CapabilityId::from_bytes([71; 16]), 200);
        assert!(capability.claims().sandbox.is_none());
        let key = capability_key(capability.id()).to_vec();
        let value = encode_record(DurableCapabilityStateV1::Active, &capability,
            None, None, None, None, MAXIMUM_RECORD_BYTES).unwrap();
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::PublisherAuthority, key.clone()), value.clone());
        let index = BTreeMap::new();
        let rows = PublisherReadDataV2::from_state_v2(&state);
        let census = publisher_capability_census_from_rows_v2(rows,
            HistoricalLedgerRowsDataV2::new(&state, &index), PublisherAuthorityLimits::default()).unwrap();

        assert_eq!(census.records.len(), 1);
        assert_eq!(census.records[0].key, key);
        assert_eq!(census.records[0].original, value);
        assert_eq!(census.records[0].capability, capability);
        assert_eq!(census.records[0].state, CapabilityRegistryStateDataV2::Active);
        assert_eq!(capability_delete_retention_data_v2(&capability, CapabilityRegistryStateDataV2::Active),
            CapabilityDeleteRetentionDataV2::NoAdministrativeRetention);
        assert_eq!(capability_delete_retention_data_v2(&capability, CapabilityRegistryStateDataV2::Revoked),
            CapabilityDeleteRetentionDataV2::NoAdministrativeRetention);
    }

    #[test]
    fn census_rejects_unknown_contract_and_dangling_parent_using_the_sole_codec() {
        let capability = super::super::tests::capability(CapabilityId::from_bytes([72; 16]), 200);
        let key = capability_key(capability.id()).to_vec();
        let canonical = encode_record(DurableCapabilityStateV1::Active, &capability,
            None, None, None, None, MAXIMUM_RECORD_BYTES).unwrap();
        let mut unknown = canonical.clone();
        let offset = unknown.windows(b"\"version\":1".len())
            .position(|bytes| bytes == b"\"version\":1").unwrap();
        unknown[offset + b"\"version\":".len()] = b'4';
        let index = BTreeMap::new();
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::PublisherAuthority, key.clone()), unknown);
        assert!(matches!(publisher_capability_census_from_rows_v2(
            PublisherReadDataV2::from_state_v2(&state), HistoricalLedgerRowsDataV2::new(&state, &index),
            PublisherAuthorityLimits::default()), Err(PublisherAuthorityError::UnsupportedVersion(4))));

        let mut unsupported = canonical.clone();
        unsupported.pop();
        unsupported.extend_from_slice(b",\"administrative_retention\":true}");
        state.insert((RecordNamespace::PublisherAuthority, key.clone()), unsupported);
        assert!(matches!(publisher_capability_census_from_rows_v2(
            PublisherReadDataV2::from_state_v2(&state), HistoricalLedgerRowsDataV2::new(&state, &index),
            PublisherAuthorityLimits::default()), Err(PublisherAuthorityError::MalformedRecord)));

        let child = encode_record(DurableCapabilityStateV1::Active, &capability,
            None, None, Some(CapabilityId::from_bytes([73; 16])), None, MAXIMUM_RECORD_BYTES).unwrap();
        state.insert((RecordNamespace::PublisherAuthority, key), child);
        assert!(matches!(publisher_capability_census_from_rows_v2(
            PublisherReadDataV2::from_state_v2(&state), HistoricalLedgerRowsDataV2::new(&state, &index),
            PublisherAuthorityLimits::default()), Err(PublisherAuthorityError::InvalidParentLink)));
    }
}
