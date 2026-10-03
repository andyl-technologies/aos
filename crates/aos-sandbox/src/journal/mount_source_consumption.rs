//! Purpose-limited atomic journal authority for Mount source consumption.
//!
//! The pure protocol layer owns the persisted DTOs, structural decoders, and
//! cross-record correlation. This module owns protected currentness, preflight,
//! commit ordering, and opaque receipts only.

use std::collections::BTreeSet;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

pub use aos_sandbox_protocol::mount_source_consumption_state::MountSourceConsumptionProjectionV2 as MountSourceConsumptionCompanionProjectionV2;
use aos_sandbox_protocol::mount_source_consumption_state::{
    MAXIMUM_MOUNT_SOURCE_CONSUMPTION_TRANSACTION_BYTES_V2, MountSourceConsumptionRecordV2,
    validate_mount_source_consumption_v2,
};

use super::{
    JournalAuthorityInstance, JournalError, JournalTransaction, ProtectedAuthorityScope,
    ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
};

/// Proves preflight of one exact atomic Mount source-consumption transaction.
#[doc(hidden)]
#[must_use = "a consumption preflight must be consumed by its exact commit"]
pub struct MountSourceConsumptionPreflight {
    snapshot: ProtectedJournalSnapshot,
    transaction_digest: [u8; 32],
    predecessor_key: Vec<u8>,
    predecessor_value: Vec<u8>,
    companion_projection: MountSourceConsumptionCompanionProjectionV2,
}

/// Records the exact durable boundary of one Mount source-consumption commit.
#[doc(hidden)]
#[must_use = "a consumption receipt must be validated by the custody owner"]
pub struct MountSourceConsumptionCommitReceipt {
    instance: Arc<JournalAuthorityInstance>,
    before_sequence: u64,
    after_sequence: u64,
    transaction_id: [u8; 16],
    transaction_digest: [u8; 32],
    predecessor_key_digest: [u8; 32],
    predecessor_value_digest: [u8; 32],
    record_digests: [[u8; 32]; 4],
    companion_projection: MountSourceConsumptionCompanionProjectionV2,
}

/// Borrows the fixed Mount journal for one closed source-consumption protocol.
///
/// Only [`crate::mount_manager_startup::MountManagerStartupProtectedOwnerV1`]
/// can construct this value. It exposes namespace-40 replay plus the exact
/// four-record preflight, commit, and ambiguity readback; the underlying raw
/// journal claim never crosses the fixed-owner boundary.
#[doc(hidden)]
#[must_use = "the fixed-owner consumption authority must remain live through readback"]
pub struct MountSourceConsumptionJournalAuthorityV1<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

impl<'journal> MountSourceConsumptionJournalAuthorityV1<'journal> {
    pub(crate) fn claim(journal: &'journal mut super::Journal) -> Result<Self, JournalError> {
        Ok(Self {
            authority: journal.claim_mount_source_consumption_authority()?,
        })
    }

    /// Iterates the current canonical namespace-40 record set.
    ///
    /// # Errors
    ///
    /// Returns an error if fixed protected authority is stale or poisoned.
    pub fn records(&self) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.authority.mount_source_acquisition_records()
    }

    /// Returns one current namespace-40 value.
    ///
    /// # Errors
    ///
    /// Returns an error if fixed protected authority is stale or poisoned.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.authority.mount_source_acquisition_get(key)
    }

    /// Captures current fixed-journal sequence and instance provenance.
    ///
    /// # Errors
    ///
    /// Returns an error if protected authority is stale or poisoned.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.authority.snapshot()
    }

    /// Revalidates an exact snapshot through this fixed owner.
    ///
    /// # Errors
    ///
    /// Returns an error after any intervening commit or owner change.
    pub fn validate_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.authority
            .validate_mount_source_acquisition_snapshot(snapshot)
    }

    /// Preflights the sole exact four-record consumption edge.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, foreign, stale, or uncorrelated input.
    pub fn preflight(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<MountSourceConsumptionPreflight, JournalError> {
        self.authority
            .preflight_mount_source_consumption(transaction)
    }

    /// Commits one exact preflighted consumption edge.
    ///
    /// # Errors
    ///
    /// Returns an error for stale preflight, altered input, or ambiguous I/O.
    pub fn commit(
        &mut self,
        preflight: MountSourceConsumptionPreflight,
        transaction: &JournalTransaction,
    ) -> Result<MountSourceConsumptionCommitReceipt, JournalError> {
        self.authority
            .commit_mount_source_consumption(preflight, transaction)
    }

    /// Revalidates all four current records of a committed edge.
    ///
    /// # Errors
    ///
    /// Returns an error unless transaction provenance and every record remain exact.
    pub fn validate_committed(
        &self,
        transaction: &JournalTransaction,
        predecessor_value: &[u8],
    ) -> Result<MountSourceConsumptionCompanionProjectionV2, JournalError> {
        self.authority
            .validate_committed_mount_source_consumption(transaction, predecessor_value)
    }

    /// Reports whether uncompacted provenance retains the transaction identity.
    ///
    /// # Errors
    ///
    /// Returns an error if protected authority is stale or poisoned.
    pub fn contains_transaction(&self, transaction_id: &[u8; 16]) -> Result<bool, JournalError> {
        self.authority
            .contains_mount_source_consumption_transaction(transaction_id)
    }

    /// Validates an exact commit receipt at the current fixed-owner sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for another owner, scope, or journal sequence.
    pub fn validate_receipt(
        &self,
        receipt: &MountSourceConsumptionCommitReceipt,
    ) -> Result<(), JournalError> {
        receipt.validate_current(&self.authority)
    }
}

impl MountSourceConsumptionPreflight {
    /// Returns the typed companion projection proven by this preflight.
    #[must_use]
    #[doc(hidden)]
    pub const fn companion_projection(&self) -> &MountSourceConsumptionCompanionProjectionV2 {
        &self.companion_projection
    }
}

impl ProtectedJournalAuthority<'_> {
    /// Preflights the sole mixed-namespace Mount source-consumption edge.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless the exact ordered transaction,
    /// predecessor, bounds, and pure correlation all validate.
    #[doc(hidden)]
    pub fn preflight_mount_source_consumption(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<MountSourceConsumptionPreflight, JournalError> {
        self.validate_mount_source_consumption_transaction(transaction)?;
        let predecessor_key = transaction.records()[0].key().to_vec();
        let predecessor_value = self
            .journal
            .get(RecordNamespace::MountSourceAcquisition, &predecessor_key)
            .ok_or(JournalError::AuthorityPreflightMismatch)?
            .to_vec();
        self.journal
            .preflight_transactions(std::slice::from_ref(transaction))?;
        let companion_projection =
            consumption_companion_projection(transaction, &predecessor_value)?;

        Ok(MountSourceConsumptionPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: companion_projection.transaction().1,
            predecessor_key,
            predecessor_value,
            companion_projection,
        })
    }

    /// Commits the exact preflighted Mount source-consumption transaction.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for stale/substituted preflight state, failed
    /// pure correlation, or a failed or ambiguous durable commit.
    #[doc(hidden)]
    pub fn commit_mount_source_consumption(
        &mut self,
        preflight: MountSourceConsumptionPreflight,
        transaction: &JournalTransaction,
    ) -> Result<MountSourceConsumptionCommitReceipt, JournalError> {
        self.validate_mount_source_consumption_transaction(transaction)?;
        self.validate_snapshot(&preflight.snapshot)?;
        let projection =
            consumption_companion_projection(transaction, &preflight.predecessor_value)?;
        let transaction_digest = projection.transaction().1;
        if preflight.transaction_digest != transaction_digest
            || preflight.companion_projection != projection
            || transaction.records()[0].key() != preflight.predecessor_key
            || self.journal.get(
                RecordNamespace::MountSourceAcquisition,
                &preflight.predecessor_key,
            ) != Some(preflight.predecessor_value.as_slice())
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }

        let before_sequence = self.journal.snapshot_sequence();
        let predecessor_key_digest = Sha256::digest(&preflight.predecessor_key).into();
        let predecessor_value_digest = Sha256::digest(&preflight.predecessor_value).into();
        let record_digests = *preflight.companion_projection.record_digests();
        self.journal.commit(transaction)?;

        Ok(MountSourceConsumptionCommitReceipt {
            instance: Arc::clone(&self.journal.authority_instance),
            before_sequence,
            after_sequence: self.journal.snapshot_sequence(),
            transaction_id: *transaction.id(),
            transaction_digest,
            predecessor_key_digest,
            predecessor_value_digest,
            record_digests,
            companion_projection: preflight.companion_projection,
        })
    }

    /// Revalidates an already committed consumption against all four current records.
    ///
    /// This recovery-only check requires the exact transaction identity to
    /// remain in uncompacted journal provenance and every ordered PUT to remain
    /// current. The retained predecessor is decoded together with the
    /// transaction by the same pure correlation owner used during preflight.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless the guard has the consumption scope,
    /// the transaction was committed by this journal generation, all four
    /// records are still exact, and their predecessor correlation validates.
    #[doc(hidden)]
    pub fn validate_committed_mount_source_consumption(
        &self,
        transaction: &JournalTransaction,
        predecessor_value: &[u8],
    ) -> Result<MountSourceConsumptionCompanionProjectionV2, JournalError> {
        self.validate_mount_source_consumption_transaction(transaction)?;
        self.journal.ensure_protected_authority()?;
        if !self.journal.transaction_ids.contains(transaction.id())
            || transaction
                .records()
                .iter()
                .any(|record| self.journal.get(record.namespace(), record.key()) != record.value())
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        consumption_companion_projection(transaction, predecessor_value)
    }

    /// Reports whether this journal generation contains one consumption transaction ID.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless this is the protected consumption scope
    /// and the journal remains healthy.
    #[doc(hidden)]
    pub fn contains_mount_source_consumption_transaction(
        &self,
        transaction_id: &[u8; 16],
    ) -> Result<bool, JournalError> {
        if self.scope != ProtectedAuthorityScope::MountSourceConsumption {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.transaction_ids.contains(transaction_id))
    }

    fn validate_mount_source_consumption_transaction(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self.scope != ProtectedAuthorityScope::MountSourceConsumption {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let records = transaction.records();
        let expected_namespaces = [
            RecordNamespace::MountSourceAcquisition,
            RecordNamespace::MountSourcePin,
            RecordNamespace::Effect,
            RecordNamespace::Operation,
        ];
        if records.len() != expected_namespaces.len()
            || records
                .iter()
                .zip(expected_namespaces)
                .any(|(record, namespace)| {
                    record.namespace() != namespace || record.value().is_none()
                })
        {
            return Err(JournalError::MalformedTransaction(
                "Mount source consumption must be four ordered PUT records",
            ));
        }
        if records
            .iter()
            .map(|record| record.key())
            .collect::<BTreeSet<_>>()
            .len()
            != records.len()
        {
            return Err(JournalError::DuplicateRecordKey);
        }
        let encoded_bytes = records.iter().try_fold(0usize, |total, record| {
            total.checked_add(7 + record.key().len() + record.value().map_or(0, <[u8]>::len))
        });
        if encoded_bytes
            .is_none_or(|bytes| bytes > MAXIMUM_MOUNT_SOURCE_CONSUMPTION_TRANSACTION_BYTES_V2)
        {
            return Err(JournalError::LimitExceeded(
                "Mount source consumption transaction bytes",
            ));
        }
        Ok(())
    }
}

impl MountSourceConsumptionCommitReceipt {
    /// Returns the exact typed companion projection proven before the commit.
    #[must_use]
    #[doc(hidden)]
    pub const fn companion_projection(&self) -> &MountSourceConsumptionCompanionProjectionV2 {
        &self.companion_projection
    }

    /// Returns the committed transaction identity and digest.
    #[must_use]
    #[doc(hidden)]
    pub const fn transaction(&self) -> ([u8; 16], [u8; 32]) {
        (self.transaction_id, self.transaction_digest)
    }

    /// Returns the before and after full-journal sequences.
    #[must_use]
    #[doc(hidden)]
    pub const fn sequences(&self) -> (u64, u64) {
        (self.before_sequence, self.after_sequence)
    }

    /// Returns the predecessor key and value commitments.
    #[must_use]
    #[doc(hidden)]
    pub const fn predecessor_digests(&self) -> ([u8; 32], [u8; 32]) {
        (self.predecessor_key_digest, self.predecessor_value_digest)
    }

    /// Returns the exact four committed record digests in order.
    #[must_use]
    #[doc(hidden)]
    pub const fn record_digests(&self) -> &[[u8; 32]; 4] {
        &self.record_digests
    }

    /// Confirms that this receipt belongs to the current purpose authority.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::StaleAuthoritySnapshot`] for another journal,
    /// scope, or a later full-journal sequence.
    #[doc(hidden)]
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        authority.journal.ensure_protected_authority()?;
        if authority.scope != ProtectedAuthorityScope::MountSourceConsumption
            || !Arc::ptr_eq(&authority.journal.authority_instance, &self.instance)
            || authority.journal.snapshot_sequence() != self.after_sequence
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

fn consumption_companion_projection(
    transaction: &JournalTransaction,
    predecessor_value: &[u8],
) -> Result<MountSourceConsumptionCompanionProjectionV2, JournalError> {
    let records = transaction
        .records()
        .iter()
        .map(|record| MountSourceConsumptionRecordV2 {
            namespace: record.namespace() as u16,
            key: record.key(),
            value: record.value(),
        })
        .collect::<Vec<_>>();
    validate_mount_source_consumption_v2(*transaction.id(), predecessor_value, &records)
        .map_err(|_| JournalError::AuthorityPreflightMismatch)
}
