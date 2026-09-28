//! Derives complete namespace-47 HEADs through the existing protected writer.
//!
//! All traffic and archive keys participate, with no hidden exclusion. The
//! floor sidecar is a separate protected Journal. These digests are
//! observational until matched to authenticated NV under retained custody.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::{Journal, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};
use sha2::{Digest as _, Sha256};

use super::format::{FloorEndpointV1, successor_sequence};
use super::{FloorCutV1, FloorErrorV1, FloorProfileV1};
use crate::BrokerSessionSecurityError;

const HEAD_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.head.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.transaction.v1\0";

impl super::super::ProtectedBrokerSessionJournalV1 {
    /// Derives a current and prospective HEAD without committing or extending.
    ///
    /// Existing owner validation and preflight remain authoritative for record
    /// schemas and limits. The returned cuts are not readiness capabilities.
    pub(super) fn tpm_floor_cuts(
        &mut self,
        profile: FloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), BrokerSessionSecurityError> {
        self.validate_all()?;
        self.endpoint.revalidate()?;
        let owner = self.owner;
        let directory = self.directory.clone();
        let name = self.name.clone();
        owner
            .validate_held(self.journal_mut()?, &directory, &name)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let expected_role = match profile.endpoint() {
            FloorEndpointV1::ControllerStorageClient => BrokerSessionDurableEndpointV1::Client,
            FloorEndpointV1::StorageBroker => BrokerSessionDurableEndpointV1::Broker,
        };
        let fixed = match profile.endpoint() {
            FloorEndpointV1::ControllerStorageClient => {
                super::super::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
            }
            FloorEndpointV1::StorageBroker => {
                super::super::ProtectedBrokerSessionFixedEndpointV1::StorageBroker
            }
        };
        let configuration = super::super::fixed_endpoint(fixed);
        if self.directory != std::path::Path::new(configuration.journal_root)
            || self.name != super::super::PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != expected_role
            || self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?
                != profile.stable_endpoint()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if self
            .journal_mut()?
            .all_records()
            .any(|(namespace, _, _)| namespace != RecordNamespace::BrokerSessionTraffic)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let cuts = journal_floor_cuts_v1(self.journal_mut()?, transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?
            != profile.stable_endpoint()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.endpoint.revalidate()?;
        owner
            .validate_held(self.journal_mut()?, &directory, &name)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(cuts)
    }
}

/// Shares protected snapshot/preflight logic, not the production endpoint admission.
pub(super) fn journal_floor_cuts_v1(
    journal: &mut Journal,
    transaction: Option<&JournalTransaction>,
) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
    journal
        .validate_held_protected_names()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    let authority = journal
        .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
        .map_err(|_| FloorErrorV1::Unavailable)?;
    let snapshot = authority
        .snapshot()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    let mut records = BTreeMap::new();
    for (key, value) in authority.records().map_err(|_| FloorErrorV1::Unavailable)? {
        records.insert(key, value);
    }
    let current = cut_from_records_v1(
        snapshot.sequence(),
        records.iter().map(|(key, value)| (*key, *value)),
    )?;
    let target = if let Some(transaction) = transaction {
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        transaction_digest_v1(transaction)?;
        for record in transaction.records() {
            match record.value() {
                Some(value) => {
                    records.insert(record.key(), value);
                }
                None => {
                    records.remove(record.key());
                }
            }
        }
        let sequence = successor_sequence(snapshot.sequence(), transaction)?;
        let target =
            cut_from_records_v1(sequence, records.iter().map(|(key, value)| (*key, *value)))?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Some(target)
    } else {
        None
    };
    authority
        .validate_snapshot_for_effect(&snapshot)
        .map_err(|_| FloorErrorV1::Unavailable)?;
    drop(authority);
    journal
        .validate_held_protected_names()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    Ok((current, target))
}

/// Hashes exact sorted keys and values without copying their packet payloads.
pub(super) fn cut_from_records_v1<'a>(
    sequence: u64,
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<FloorCutV1, FloorErrorV1> {
    let mut digest = Sha256::new();
    digest.update(HEAD_DOMAIN);
    digest.update([RecordNamespace::BrokerSessionTraffic as u8]);
    digest.update(sequence.to_be_bytes());
    let mut predecessor: Option<&[u8]> = None;
    let mut count = 0_u64;
    for (key, value) in records {
        if key.is_empty() || predecessor.is_some_and(|old| old >= key) {
            return Err(FloorErrorV1::Encoding);
        }
        update_bytes(&mut digest, key)?;
        update_bytes(&mut digest, value)?;
        count = count.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
        predecessor = Some(key);
    }
    digest.update(count.to_be_bytes());
    FloorCutV1::new(sequence, digest.finalize().into())
}

/// Commits ID, record order, namespace, put/delete tag, and length-delimited bytes.
pub(super) fn transaction_digest_v1(
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update(transaction.id());
    digest.update(
        u64::try_from(transaction.records().len())
            .map_err(|_| FloorErrorV1::Encoding)?
            .to_be_bytes(),
    );
    let mut keys = BTreeSet::new();
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::BrokerSessionTraffic
            || record.key().is_empty()
            || !keys.insert(record.key())
        {
            return Err(FloorErrorV1::Encoding);
        }
        digest.update([record.namespace() as u8, u8::from(record.value().is_some())]);
        update_bytes(&mut digest, record.key())?;
        update_bytes(&mut digest, record.value().unwrap_or_default())?;
    }
    Ok(digest.finalize().into())
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) -> Result<(), FloorErrorV1> {
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|_| FloorErrorV1::Encoding)?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}
