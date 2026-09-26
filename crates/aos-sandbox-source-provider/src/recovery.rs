//! Hostile replay validation for the complete AOSSPL01 object graph.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::ProtectedJournalAuthority;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceExportLeaseV1, SignedSourceProviderHelloV1, SignedSourceProviderInventoryV1,
    SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1, SignedSourceProviderStatusV1,
    SignedSourceReleaseReceiptV1, SourceProviderInventoryV1, SourceProviderMethod,
    SourceProviderStatus, decode_acquire_request, decode_acquire_response,
    decode_inventory_request, decode_inventory_response, decode_release_request,
    decode_release_response, digest_acquire_request, digest_inventory_request,
    digest_release_request, digest_signed_release_receipt,
    source_provider_inventory_intent_digest_v1, source_provider_release_intent_digest_v1,
    source_provider_request_attempt_digest_v1, verify_export_lease, verify_hello, verify_inventory,
    verify_provider_receipt_and_lease, verify_release_receipt, verify_request,
    verify_response_status,
};
use sha2::{Digest as _, Sha256};

use crate::ProviderLedgerError;
use crate::format::{decode_record, encode_acquisition, record_digest};
use crate::inventory::global_inventory_state_digest;
use crate::model::{
    AcquisitionKeyV1, AttemptKeyV1, DecodedRecordV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1, ProviderRecoveryWorkV1, ProviderReleaseStateV1,
    RecoveredProviderLedgerV1, ReleaseKeyV1,
};
use crate::state::ProtectedProviderConfigurationV1;

#[path = "recovery/graph.rs"]
mod graph;
#[path = "recovery/history.rs"]
mod history;
#[path = "recovery/sessions.rs"]
mod sessions;
#[path = "recovery/work.rs"]
mod work;

use graph::*;
use history::*;
use sessions::*;
pub(crate) use work::recovery_work;

/// Reports one observation-only recovery classification.
///
/// These values grant no effect, signing, descriptor, replay, or send
/// authority. An operator must present the original request through a fresh
/// authenticated session before any completion can be attempted.
#[derive(Debug)]
pub enum ProviderRecoveryObservationV1 {
    /// The durable acquire effect is not present.
    AcquireNotApplied(RecoveryAcquireNotAppliedV1),
    /// The exact durable acquire effect is present; its transient descriptor was closed.
    AcquireApplied,
    /// The durable release target remains present.
    ReleaseStillPresent(RecoveryReleaseStillPresentV1),
    /// The exact durable release is already observed.
    ReleaseApplied,
    /// The exact active source reopened and its transient descriptor was closed.
    ActiveReopened,
    /// An authenticated request must explicitly complete the reserved Inventory.
    InventoryRequiresAuthenticatedCompletion,
    /// The backend could not currently establish the required source.
    Unavailable,
}

/// Proves an exact recovered acquire effect was observed absent at one snapshot.
pub struct RecoveryAcquireNotAppliedV1 {
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) effect_id: [u8; 16],
    pub(crate) snapshot: aos_sandbox::ProtectedJournalSnapshot,
}

impl core::fmt::Debug for RecoveryAcquireNotAppliedV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RecoveryAcquireNotAppliedV1([redacted])")
    }
}

/// Proves an exact recovered release target remained at one snapshot.
pub struct RecoveryReleaseStillPresentV1 {
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) effect_id: [u8; 16],
    pub(crate) snapshot: aos_sandbox::ProtectedJournalSnapshot,
}

impl core::fmt::Debug for RecoveryReleaseStillPresentV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RecoveryReleaseStillPresentV1([redacted])")
    }
}

pub(crate) fn recover(
    journal: &ProtectedJournalAuthority<'_>,
    configuration: &ProtectedProviderConfigurationV1,
) -> Result<RecoveredProviderLedgerV1, ProviderLedgerError> {
    journal.validate_source_provider_authority()?;
    recover_records(journal.records()?, configuration)
}

pub(crate) fn recover_records<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    configuration: &ProtectedProviderConfigurationV1,
) -> Result<RecoveredProviderLedgerV1, ProviderLedgerError> {
    let mut authorities = Vec::new();
    let mut catalogs = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    let mut session_history = BTreeMap::new();
    let mut attempts = BTreeMap::new();
    let mut acquisitions = BTreeMap::new();
    let mut releases = BTreeMap::new();
    let mut aggregate_bytes = 0_usize;
    let mut record_count = 0_usize;

    for (key, bytes) in records {
        record_count = record_count
            .checked_add(1)
            .ok_or(ProviderLedgerError::LimitExceeded("recovered record count"))?;
        aggregate_bytes = aggregate_bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(key.len()))
            .and_then(|total| total.checked_add(bytes.len()))
            .ok_or(ProviderLedgerError::LimitExceeded(
                "recovered aggregate bytes",
            ))?;
        if record_count > aos_sandbox_source_provider_ledger::limits::MAXIMUM_LEDGER_RECORDS
            || aggregate_bytes
                > aos_sandbox_source_provider_ledger::limits::MAXIMUM_LEDGER_GRAPH_BYTES
        {
            return Err(ProviderLedgerError::LimitExceeded(
                "recovered aggregate bounds",
            ));
        }
        match decode_record(key, bytes)? {
            DecodedRecordV1::Authority(record) => authorities.push(record),
            DecodedRecordV1::Catalog(record) => {
                if catalogs.insert(record.catalog_generation, record).is_some() {
                    return Err(ProviderLedgerError::Corrupt("duplicate catalog generation"));
                }
            }
            DecodedRecordV1::Session(record) => {
                let identity = (record.provider.authority_id(), record.holder.authority_id());
                if sessions.insert(identity, record).is_some() {
                    return Err(ProviderLedgerError::Corrupt("duplicate holder session"));
                }
            }
            DecodedRecordV1::SessionHistory(record) => {
                let identity = (
                    record.provider.authority_id(),
                    record.holder.authority_id(),
                    record.session_binding,
                );
                if session_history.insert(identity, record).is_some() {
                    return Err(ProviderLedgerError::Corrupt(
                        "duplicate immutable session history",
                    ));
                }
            }
            DecodedRecordV1::Attempt(record) => {
                let identity = AttemptKeyV1 {
                    provider_id: record.provider.authority_id(),
                    holder_id: record.holder.authority_id(),
                    root_record_key_id: record.root_record_signer.key_id(),
                    method: record.method as u8,
                    request_id: record.request_id,
                };
                if attempts.insert(identity, record).is_some() {
                    return Err(ProviderLedgerError::Corrupt("duplicate request attempt"));
                }
            }
            DecodedRecordV1::Acquisition(record) => {
                let identity = AcquisitionKeyV1 {
                    provider_id: record.provider.authority_id(),
                    holder_id: record.holder.authority_id(),
                    acquisition_id: record.acquisition_id,
                };
                if acquisitions.insert(identity, record).is_some() {
                    return Err(ProviderLedgerError::Corrupt("duplicate acquisition"));
                }
            }
            DecodedRecordV1::Release(record) => {
                let identity = ReleaseKeyV1 {
                    provider_id: record.provider.authority_id(),
                    holder_id: record.holder.authority_id(),
                    acquisition_id: record.acquisition_id,
                };
                if releases.insert(identity, record).is_some() {
                    return Err(ProviderLedgerError::Corrupt("duplicate release"));
                }
            }
        }
    }

    if authorities.len() != 1 || catalogs.is_empty() {
        return Err(ProviderLedgerError::Corrupt(
            "ledger requires exactly one authority and catalog head",
        ));
    }
    if catalogs.len() > crate::limits::MAXIMUM_RETAINED_CATALOG_HEADS {
        return Err(ProviderLedgerError::LimitExceeded("retained catalog heads"));
    }
    let authority = authorities
        .pop()
        .ok_or(ProviderLedgerError::Corrupt("missing authority head"))?;
    let catalog = catalogs
        .get(&authority.catalog_generation)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing current catalog head"))?;
    validate_catalog_history(configuration, &authority, &catalogs)?;
    configuration.validate_heads(&authority, &catalog)?;

    let provider_id = authority.provider.authority_id();
    if catalog.provider != authority.provider
        || catalog.resource_namespace_digest != authority.resource_namespace_digest
        || catalog.catalog_generation != authority.catalog_generation
        || catalog.catalog_digest != authority.catalog_digest
        || sessions
            .keys()
            .any(|(provider, _)| *provider != provider_id)
        || session_history
            .keys()
            .any(|(provider, _, _)| *provider != provider_id)
        || attempts.keys().any(|key| key.provider_id != provider_id)
        || acquisitions
            .keys()
            .any(|key| key.provider_id != provider_id)
        || releases.keys().any(|key| key.provider_id != provider_id)
    {
        return Err(ProviderLedgerError::Corrupt("provider head cross-link"));
    }

    enforce_count_limits(
        configuration,
        &sessions,
        &session_history,
        &attempts,
        &acquisitions,
        &releases,
    )?;
    validate_sessions(&authority, &sessions, &session_history, &attempts)?;
    validate_graph(
        configuration,
        &authority,
        &catalog,
        &catalogs,
        &sessions,
        &session_history,
        &attempts,
        &acquisitions,
        &releases,
    )?;
    validate_historical_signatures(
        configuration,
        &authority,
        &catalogs,
        &session_history,
        &attempts,
        &acquisitions,
        &releases,
    )?;

    let (inventory_state_digest, active_lease_count) = global_inventory_state_digest(
        authority.provider.authority_id(),
        authority.catalog_generation,
        authority.catalog_digest,
        &acquisitions,
        &releases,
        configuration
            .limits()
            .maximum_inventory_tombstones_per_holder(),
    )?;
    if inventory_state_digest != authority.inventory_state_digest
        || active_lease_count != authority.active_lease_count
    {
        return Err(ProviderLedgerError::Corrupt(
            "global inventory projection mismatch",
        ));
    }

    let recovery_work = recovery_work(&attempts, &acquisitions);
    Ok(RecoveredProviderLedgerV1 {
        authority,
        catalog,
        catalog_history: catalogs,
        sessions,
        session_history,
        attempts,
        acquisitions,
        releases,
        recovery_work,
    })
}
