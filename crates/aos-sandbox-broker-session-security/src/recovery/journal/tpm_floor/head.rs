//! Derives complete namespace-47 HEADs through the existing protected writer.
//!
//! All traffic and archive keys participate, with no hidden exclusion. The
//! floor sidecar is a separate protected Journal. These digests are
//! observational until matched to authenticated NV under retained custody.

use std::collections::BTreeMap;

use aos_sandbox::{Journal, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};

use super::format::{FloorEndpointV1, successor_sequence};
use super::{FloorCutV1, FloorErrorV1, FloorProfileV1};
use crate::BrokerSessionSecurityError;

impl super::super::ProtectedBrokerSessionJournalV1 {
    #[cfg(feature = "online-nix")]
    pub(super) fn online_floor_cuts(
        &mut self,
        profile: crate::tpm_nv_custody::OnlineFloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), BrokerSessionSecurityError> {
        self.validate_schema_only()?;
        self.endpoint.revalidate()?;
        let owner = self.owner;
        let directory = self.directory.clone();
        let name = self.name.clone();
        owner.validate_held(self.journal_mut()?, &directory, &name)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let role = match profile.role() {
            crate::tpm_nv_custody::OnlineFloorRoleV1::Controller => BrokerSessionDurableEndpointV1::Client,
            crate::tpm_nv_custody::OnlineFloorRoleV1::Owner => BrokerSessionDurableEndpointV1::Broker,
        };
        if directory.as_os_str() != std::path::Path::new(profile.role().directory()).as_os_str()
            || name != super::super::PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != role
            || self.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Nix
            || self.stable_endpoint_identity(BrokerSessionProtocolV1::Nix)? != profile.stable_endpoint()
            || !self.online_schema.as_ref().is_some_and(|schema| schema.profile == profile)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if let Some(transaction) = transaction {
            self.require_online_transaction(transaction)?;
        }
        let cuts = journal_floor_cuts_purpose(
            self.journal_mut()?, transaction, HeadPurposeV1::Online(profile),
        ).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.validate_schema_only()?;
        if self.stable_endpoint_identity(BrokerSessionProtocolV1::Nix)? != profile.stable_endpoint() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.endpoint.revalidate()?;
        owner.validate_held(self.journal_mut()?, &directory, &name)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(cuts)
    }

    /// Derives a current and prospective HEAD without committing or extending.
    ///
    /// Existing owner validation and preflight remain authoritative for record
    /// schemas and limits. The returned cuts are not readiness capabilities.
    pub(super) fn tpm_floor_cuts(
        &mut self,
        profile: FloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), BrokerSessionSecurityError> {
        // This borrow is already under the floor coordinator's held traffic
        // owner; startup takes its first cut before acquiring the sidecar.
        // Re-entering the public floor-gated reader would be circular.
        self.validate_schema_only()?;
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
    journal_floor_cuts_purpose(journal, transaction, HeadPurposeV1::Broker)
}

#[derive(Clone, Copy)]
enum HeadPurposeV1 {
    Broker,
    #[cfg(feature = "online-nix")]
    Online(crate::tpm_nv_custody::OnlineFloorProfileV1),
}

impl HeadPurposeV1 {
    fn cut<'a>(self, sequence: u64, records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>)
        -> Result<FloorCutV1, FloorErrorV1>
    {
        match self {
            Self::Broker => cut_from_records_v1(sequence, records),
            #[cfg(feature = "online-nix")]
            Self::Online(profile) => crate::tpm_nv_custody::online_cut_from_records_v1(profile, sequence, records),
        }
    }

    fn require_transaction(self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
        match self {
            Self::Broker => { transaction_digest_v1(transaction)?; }
            #[cfg(feature = "online-nix")]
            Self::Online(profile) => { crate::tpm_nv_custody::online_transaction_digest_v1(profile, transaction)?; }
        }
        Ok(())
    }
}

fn journal_floor_cuts_purpose(
    journal: &mut Journal,
    transaction: Option<&JournalTransaction>,
    purpose: HeadPurposeV1,
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
    let current = purpose.cut(
        snapshot.sequence(),
        records.iter().map(|(key, value)| (*key, *value)),
    )?;
    let target = if let Some(transaction) = transaction {
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        purpose.require_transaction(transaction)?;
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
            purpose.cut(sequence, records.iter().map(|(key, value)| (*key, *value)))?;
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

/// Hashes the original complete Broker map through the sole canonical engine.
///
/// # Errors
///
/// Preserves original key/order, count and cut-sentinel encoding errors.
pub(super) fn cut_from_records_v1<'a>(
    sequence: u64,
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<FloorCutV1, FloorErrorV1> {
    crate::tpm_nv_custody::broker_cut_from_records_v1(sequence, records)
}

/// Commits the original Broker UUID/order/tags/bytes through the sole walker.
///
/// # Errors
///
/// Preserves original namespace, key and length encoding errors.
pub(super) fn transaction_digest_v1(
    transaction: &JournalTransaction,
) -> Result<[u8; 32], FloorErrorV1> {
    crate::tpm_nv_custody::broker_transaction_digest_v1(transaction)
}
