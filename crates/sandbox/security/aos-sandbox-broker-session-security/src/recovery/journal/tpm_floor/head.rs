//! Derives complete namespace-47 HEADs through the existing protected writer.
//!
//! All traffic and archive keys participate, with no hidden exclusion. The
//! floor sidecar is a separate protected Journal. These digests are
//! observational until matched to authenticated NV under retained custody.

use std::collections::BTreeMap;

use aos_sandbox_controller_domain::{Journal, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};

use super::format::{FloorEndpointV1, successor_sequence};
use super::{FloorCutV1, FloorErrorV1, FloorProfileV1};
use crate::BrokerSessionSecurityError;

mod storage_main;
pub(in crate::recovery::journal) use storage_main::StorageFloorMainArchiveV3;
pub(in crate::recovery::journal::tpm_floor) use storage_main::StorageFloorMainOriginalV3;

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
        let currentness = self.floor_currentness.clone();
        let directory = self.directory.clone();
        let name = self.name.clone();
        super::super::floor_revalidation::validate_rooted(
            currentness.as_ref(), owner, self.journal_mut()?, &directory, &name,
        ).map_err(super::super::floor_revalidation::security_error)?;
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
            self.journal_mut()?, transaction, HeadPurposeV1::Online(profile), currentness.as_ref(),
        ).map_err(super::super::floor_revalidation::security_error)?;
        self.validate_schema_only()?;
        if self.stable_endpoint_identity(BrokerSessionProtocolV1::Nix)? != profile.stable_endpoint() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.endpoint.revalidate()?;
        super::super::floor_revalidation::validate_rooted(
            currentness.as_ref(), owner, self.journal_mut()?, &directory, &name,
        ).map_err(super::super::floor_revalidation::security_error)?;
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
        self.tpm_floor_cuts_engine_v3(profile, transaction, None)
    }

    fn tpm_floor_cuts_engine_retaining_v3(
        &mut self, profile: FloorProfileV1, transaction: Option<&JournalTransaction>,
        original: &mut storage_main::StorageFloorMainOriginalV3,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), BrokerSessionSecurityError> {
        self.tpm_floor_cuts_engine_v3(profile, transaction, Some(original))
    }

    fn tpm_floor_cuts_engine_v3(
        &mut self, profile: FloorProfileV1, transaction: Option<&JournalTransaction>,
        mut original: Option<&mut storage_main::StorageFloorMainOriginalV3>,
    ) -> Result<(FloorCutV1, Option<FloorCutV1>), BrokerSessionSecurityError> {
        // This borrow is already under the floor coordinator's held traffic
        // owner; startup takes its first cut before acquiring the sidecar.
        // Re-entering the public floor-gated reader would be circular.
        match original.as_deref_mut() {
            Some(original) => self.validate_schema_only_retaining_v3(&mut original.schema)?,
            None => self.validate_schema_only()?,
        }
        match original.as_deref_mut() {
            Some(original) => self.endpoint.revalidate_into_v1(&mut original.endpoint[0])?,
            None => self.endpoint.revalidate()?,
        }
        let owner = self.owner;
        let currentness = self.floor_currentness.clone();
        let directory = self.directory.clone();
        let name = self.name.clone();
        match original.as_deref_mut() {
            Some(original) => {
                original.rooted_result[0] = Some(owner.validate_held_retaining(
                    self.journal_mut()?, &directory, &name, &mut original.rooted[0]));
                if !matches!(original.rooted_result[0], Some(Ok(()))) {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            }
            None => super::super::floor_revalidation::validate_rooted(
                currentness.as_ref(), owner, self.journal_mut()?, &directory, &name,
            ).map_err(super::super::floor_revalidation::security_error)?,
        }
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
            || match original.as_deref_mut() {
            Some(original) => {
                original.identities[0] = Some(self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage));
                original.identities[0].as_ref().cloned()
                    .ok_or(BrokerSessionSecurityError::Currentness)??
            }
            None => self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?,
        } != profile.stable_endpoint()
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

        let cuts = match original.as_deref_mut() {
            Some(original) => journal_floor_cuts_retaining_v3(self.journal_mut()?, transaction, original),
            None => journal_floor_cuts_purpose(
                self.journal_mut()?, transaction, HeadPurposeV1::Broker, currentness.as_ref()),
        }.map_err(super::super::floor_revalidation::security_error)?;
        let identity = match original.as_deref_mut() {
            Some(original) => {
                original.identities[1] = Some(self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage));
                original.identities[1].as_ref().cloned()
                    .ok_or(BrokerSessionSecurityError::Currentness)??
            }
            None => self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?,
        };
        if identity != profile.stable_endpoint() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        match original.as_deref_mut() {
            Some(original) => self.endpoint.revalidate_into_v1(&mut original.endpoint[1])?,
            None => self.endpoint.revalidate()?,
        }
        match original {
            Some(original) => {
                original.rooted_result[1] = Some(owner.validate_held_retaining(
                    self.journal_mut()?, &directory, &name, &mut original.rooted[1]));
                if !matches!(original.rooted_result[1], Some(Ok(()))) {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            }
            None => super::super::floor_revalidation::validate_rooted(
                currentness.as_ref(), owner, self.journal_mut()?, &directory, &name,
            ).map_err(super::super::floor_revalidation::security_error)?,
        }
        Ok(cuts)
    }
}

/// Shares protected snapshot/preflight logic, not the production endpoint admission.
pub(super) fn journal_floor_cuts_v1(
    journal: &mut Journal,
    transaction: Option<&JournalTransaction>,
) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
    journal_floor_cuts_purpose(journal, transaction, HeadPurposeV1::Broker, None)
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

// One finite recipe keeps ordinary borrowed locals and selected owning DATA
// at the same claim, preflight, digest and effect boundaries.
macro_rules! head_step_v3 {
    (Ordinary, names $original:ident, $journal:ident, $currentness:ident, $index:expr) => {
        super::super::floor_revalidation::validate_names($currentness, $journal)?
    };
    (Retained, names $original:ident, $journal:ident, $currentness:ident, $index:expr) => {{
        $original.names_result[$index] = Some($journal.validate_held_protected_names_retaining(
            &mut $original.names[$index]));
        if !matches!($original.names_result[$index], Some(Ok(()))) {
            return Err(FloorErrorV1::Unavailable);
        }
    }};
    (Ordinary, claim $original:ident, $journal:ident) => {
        $journal.claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?
    };
    (Retained, claim $original:ident, $journal:ident) => {{
        match $journal.claim_protected_authority_retaining_v1(
            RecordNamespace::BrokerSessionTraffic, &mut $original.capacity) {
            Ok(authority) => { $original.claim = Some(Ok(())); authority }
            Err(cause) => {
                $original.claim = Some(Err(cause));
                return Err(FloorErrorV1::Unavailable);
            }
        }
    }};
    (Ordinary, snapshot $original:ident, $authority:ident, $snapshot:ident) => {
        let $snapshot = $authority.snapshot().map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, snapshot $original:ident, $authority:ident, $snapshot:ident) => {
        $original.snapshot = Some($authority.snapshot());
        let $snapshot = $original.snapshot.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Unavailable)?;
    };
    (Ordinary, records $original:ident, $authority:ident, $records:ident) => {
        let mut $records = BTreeMap::new();
        for (key, value) in $authority.records().map_err(|_| FloorErrorV1::Unavailable)? {
            $records.insert(key, value);
        }
    };
    (Retained, records $original:ident, $authority:ident, $records:ident) => {
        match $authority.records() {
            Ok(rows) => {
                for (key, value) in rows { $original.records.insert(key.to_vec(), value.to_vec()); }
                $original.rows = Some(Ok(()));
            }
            Err(cause) => {
                $original.rows = Some(Err(cause));
                return Err(FloorErrorV1::Unavailable);
            }
        }
    };
    (Ordinary, current $original:ident, $purpose:ident, $snapshot:ident, $records:ident) => {
        $purpose.cut($snapshot.sequence(), $records.iter().map(|(key, value)| (*key, *value)))?
    };
    (Retained, current $original:ident, $purpose:ident, $snapshot:ident, $records:ident) => {
        $original.current_hash.observe_broker_once_v3($snapshot.sequence(),
            $original.records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())))?
    };
    (Ordinary, preflight $original:ident, $authority:ident, $transaction:ident, $preflight:ident) => {
        let $preflight = $authority.preflight_transactions(core::slice::from_ref($transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, preflight $original:ident, $authority:ident, $transaction:ident, $preflight:ident) => {
        $original.token = Some($authority.preflight_transactions_retaining_v2(
            core::slice::from_ref($transaction), &mut $original.preflight));
        let $preflight = $original.token.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Unavailable)?;
    };
    (Ordinary, transaction $original:ident, $purpose:ident, $transaction:ident) => {
        $purpose.require_transaction($transaction)?;
    };
    (Retained, transaction $original:ident, $purpose:ident, $transaction:ident) => {
        $original.transaction_hash.observe_broker_once_v3($transaction)?;
        $original.prospective = Some($original.records.clone());
    };
    (Ordinary, apply $original:ident, $records:ident, $record:ident) => {
        match $record.value() {
            Some(value) => { $records.insert($record.key(), value); }
            None => { $records.remove($record.key()); }
        }
    };
    (Retained, apply $original:ident, $records:ident, $record:ident) => {
        let records = $original.prospective.as_mut().ok_or(FloorErrorV1::Encoding)?;
        match $record.value() {
            Some(value) => { records.insert($record.key().to_vec(), value.to_vec()); }
            None => { records.remove($record.key()); }
        }
    };
    (Ordinary, sequence $original:ident, $snapshot:ident, $transaction:ident) => {
        successor_sequence($snapshot.sequence(), $transaction)?
    };
    (Retained, sequence $original:ident, $snapshot:ident, $transaction:ident) => {{
        $original.sequence = Some(successor_sequence($snapshot.sequence(), $transaction));
        $original.sequence.as_ref().copied().ok_or(FloorErrorV1::Encoding)??
    }};
    (Ordinary, target $original:ident, $purpose:ident, $sequence:ident, $records:ident) => {
        $purpose.cut($sequence, $records.iter().map(|(key, value)| (*key, *value)))?
    };
    (Retained, target $original:ident, $purpose:ident, $sequence:ident, $records:ident) => {
        $original.target_hash.observe_broker_once_v3($sequence,
            $original.prospective.as_ref().ok_or(FloorErrorV1::Encoding)?.iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())))?
    };
    (Ordinary, effect $original:ident, $authority:ident, $preflight:ident, $transaction:ident) => {
        $authority.validate_preflight_for_effect(&$preflight, core::slice::from_ref($transaction))
            .map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, effect $original:ident, $authority:ident, $preflight:ident, $transaction:ident) => {
        $original.effect = Some($authority.validate_preflight_for_effect(
            $preflight, core::slice::from_ref($transaction)));
        if !matches!($original.effect, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
    };
    (Ordinary, snapshot_effect $original:ident, $authority:ident, $snapshot:ident) => {
        $authority.validate_snapshot_for_effect(&$snapshot).map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, snapshot_effect $original:ident, $authority:ident, $snapshot:ident) => {
        $original.snapshot_effect = Some($authority.validate_snapshot_for_effect($snapshot));
        if !matches!($original.snapshot_effect, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
    };
}

macro_rules! head_recipe_v3 {
    ($mode:ident, $original:ident, $journal:ident, $transaction:ident, $purpose:ident, $currentness:ident) => {{
        head_step_v3!($mode, names $original, $journal, $currentness, 0);
        let authority = head_step_v3!($mode, claim $original, $journal);
        head_step_v3!($mode, snapshot $original, authority, snapshot);
        head_step_v3!($mode, records $original, authority, records);
        let current = head_step_v3!($mode, current $original, $purpose, snapshot, records);
        let target = if let Some(transaction) = $transaction {
            head_step_v3!($mode, preflight $original, authority, transaction, preflight);
            head_step_v3!($mode, transaction $original, $purpose, transaction);
            for record in transaction.records() { head_step_v3!($mode, apply $original, records, record); }
            let sequence = head_step_v3!($mode, sequence $original, snapshot, transaction);
            let target = head_step_v3!($mode, target $original, $purpose, sequence, records);
            head_step_v3!($mode, effect $original, authority, preflight, transaction);
            Some(target)
        } else { None };
        head_step_v3!($mode, snapshot_effect $original, authority, snapshot);
        drop(authority);
        head_step_v3!($mode, names $original, $journal, $currentness, 1);
        Ok((current, target))
    }};
}

fn journal_floor_cuts_purpose(
    journal: &mut Journal, transaction: Option<&JournalTransaction>, purpose: HeadPurposeV1,
    currentness: Option<&super::super::floor_revalidation::FloorCurrentnessSharedV1>,
) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
    head_recipe_v3!(Ordinary, unused, journal, transaction, purpose, currentness)
}

fn journal_floor_cuts_retaining_v3(
    journal: &mut Journal, transaction: Option<&JournalTransaction>,
    original: &mut storage_main::StorageFloorMainOriginalV3,
) -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1> {
    if original.inner_entered { return Err(FloorErrorV1::Unavailable); }
    original.inner_entered = true;
    head_recipe_v3!(Retained, original, journal, transaction, purpose, currentness)
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

#[cfg(all(test, target_os = "linux"))]
mod retained_head_native_tests {
    use super::*;
    use aos_sandbox_controller_domain::{JournalLimits, JournalRecord};
    use std::os::unix::fs::PermissionsExt as _;

    fn held_journal() -> (tempfile::TempDir, Journal) {
        let directory = tempfile::Builder::new().prefix("aos-floor-head-original-").tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(), "session.journal", JournalLimits::default(), uid).unwrap();
        let initial = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), b"old".to_vec())]).unwrap();
        journal.commit(&initial).unwrap();
        (directory, journal)
    }

    #[test]
    fn selected_head_uses_the_same_real_snapshot_preflight_and_complete_map() {
        let (_directory, mut journal) = held_journal();
        let transaction = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), b"new".to_vec())]).unwrap();
        let expected = journal_floor_cuts_v1(&mut journal, Some(&transaction)).unwrap();
        let mut original = storage_main::StorageFloorMainOriginalV3::new();

        let actual = journal_floor_cuts_retaining_v3(&mut journal, Some(&transaction), &mut original).unwrap();

        assert_eq!(actual, expected);
        assert!(matches!(original.snapshot, Some(Ok(_))));
        assert!(matches!(original.token, Some(Ok(_))));
        assert_eq!(original.records.get(b"a".as_slice()).map(Vec::as_slice), Some(b"old".as_slice()));
        assert_eq!(original.prospective.as_ref().unwrap().get(b"a".as_slice()).map(Vec::as_slice),
            Some(b"new".as_slice()));
    }

    #[test]
    fn a_later_native_preflight_refusal_keeps_the_actual_current_map_and_snapshot() {
        let (_directory, mut journal) = held_journal();
        let transaction = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, b"a".to_vec(), b"new".to_vec())]).unwrap();
        let mut original = storage_main::StorageFloorMainOriginalV3::new();

        assert!(journal_floor_cuts_retaining_v3(&mut journal, Some(&transaction), &mut original).is_err());

        assert!(matches!(original.snapshot, Some(Ok(_))));
        assert!(matches!(original.token, Some(Err(_))));
        assert!(original.preflight.failure().is_some());
        assert_eq!(original.records.get(b"a".as_slice()).map(Vec::as_slice), Some(b"old".as_slice()));
        let cause = original.preflight.failure().unwrap() as *const dyn std::error::Error;
        assert!(journal_floor_cuts_retaining_v3(&mut journal, None, &mut original).is_err());
        assert!(std::ptr::eq(cause, original.preflight.failure().unwrap() as *const dyn std::error::Error));
    }
}
