//! Prices Mount's actual captured native prefix and full semantic replay.
//!
//! These values are passive requirements. The actual CommonSource or existing
//! startup owner admits them before growth; geometry cannot create a writer,
//! provide a grant, select a path or renew a financial deadline.

use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalReplayIndexOriginalsV1;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use super::*;

/// Describes the same physically captured Mount journal prefix.
#[derive(Clone, Copy)]
pub struct MountJournalReplayExtentV1 {
    pub(super) limits: JournalLimits,
    canonical: CanonicalReplayExtentDataV1,
}

impl MountJournalReplayExtentV1 {
    pub(super) fn from_canonical_v1(
        canonical: CanonicalReplayExtentDataV1,
    ) -> Result<Self, JournalError> {
        Ok(Self {
            limits: canonical.limits(),
            canonical,
        })
    }

    /// Prices the actual canonical parser and its same resident index.
    ///
    /// # Errors
    /// Refuses overflow in the existing native or index geometry suppliers.
    pub fn dominant_native_receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let index =
            CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(self.canonical).map_err(|_| {
                JournalError::Mechanical(crate::journal::MechanicalError::JournalTooLarge)
            })?;
        self.canonical
            .dominant_native_receiving_demand_v1()?
            .checked_add(index)
            .map_err(Into::into)
    }

    /// Prices the same complete all-family semantic models and saved history.
    ///
    /// # Errors
    /// Refuses overflow in the canonical validators or encoded-prefix bounds.
    pub fn dominant_semantic_receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let encoded = usize::try_from(self.canonical.native_bytes()).map_err(|_| {
            JournalError::Mechanical(crate::journal::MechanicalError::JournalTooLarge)
        })?;
        let rows = encoded / aos_sandbox_journal::framing::HEADER_BYTES;
        let models =
            aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
                encoded, rows,
            )?;
        let history = aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(
            self.canonical.native_bytes(),
        )?;
        self.canonical
            .dominant_semantic_receiving_demand_v1()?
            .checked_add(models)?
            .checked_add(history)
            .map_err(Into::into)
    }
}

/// Retains the actual Mount native or checked-accounting geometry refusal.
#[derive(Debug, thiserror::Error)]
pub enum MountJournalAppendReceivingDemandErrorV1 {
    /// Preserves this same actual writer's geometry, metadata or native cause.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Preserves checked resource aggregation before representation grows.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

impl MountJournalV1 {
    /// Prices one actual transaction's widths before its encoder or native entry.
    ///
    /// # Errors
    /// Refuses unhealthy custody, invalid native widths or arithmetic overflow.
    pub fn append_receiving_demand_v1(
        &self,
        records: impl ExactSizeIterator<Item = RecordShape>,
    ) -> Result<ResourceVector, MountJournalAppendReceivingDemandErrorV1> {
        self.append_sequence_receiving_demand_v1(std::iter::once(Ok(records)))
    }

    /// Prices the complete prospective history of an ordered actual append set.
    ///
    /// Earlier overwritten and terminal native history remains included. This
    /// supplies DATA only; the real caller debits its own original before any
    /// encoding, model clone or captured append allocation can begin.
    /// # Errors
    /// Preserves typed forecasts, metadata, native bounds and checked arithmetic.
    pub fn append_sequence_receiving_demand_v1<I, T>(
        &self,
        transactions: I,
    ) -> Result<ResourceVector, MountJournalAppendReceivingDemandErrorV1>
    where
        I: IntoIterator<Item = Result<T, JournalError>>,
        T: ExactSizeIterator<Item = RecordShape>,
    {
        self.ensure_healthy()?;
        let mut append = 0_u64;
        for records in transactions {
            let bytes = encoded_transaction_append_bytes(records?).map_err(JournalError::from)?;
            append = append
                .checked_add(bytes)
                .ok_or(MechanicalError::JournalTooLarge)
                .map_err(JournalError::from)?;
        }
        let read = self.native.read_view_v1();
        let mut retained_bytes = 0_usize;
        for ((_, key), value) in read.state() {
            retained_bytes = retained_bytes
                .checked_add(key.capacity())
                .and_then(|bytes| bytes.checked_add(value.capacity()))
                .ok_or(MechanicalError::JournalTooLarge)
                .map_err(JournalError::from)?;
        }
        for key in read.idempotency_index().keys() {
            retained_bytes = retained_bytes
                .checked_add(key.capacity())
                .ok_or(MechanicalError::JournalTooLarge)
                .map_err(JournalError::from)?;
        }
        let cells = read
            .state()
            .len()
            .checked_add(read.idempotency_index().len())
            .and_then(|count| count.checked_add(read.transaction_ids().len()))
            .and_then(|count| count.checked_add(read.committed_namespaces().len()))
            .ok_or(MechanicalError::JournalTooLarge)
            .map_err(JournalError::from)?;
        let future = read
            .metadata()
            .map_err(JournalError::from)?
            .len()
            .checked_add(append)
            .ok_or(MechanicalError::JournalTooLarge)
            .map_err(JournalError::from)?;
        let extent = MountJournalReplayExtentV1::from_canonical_v1(
            CanonicalReplayExtentDataV1::new(read.limits(), future).map_err(JournalError::from)?,
        )?;
        let native = extent.dominant_native_receiving_demand_v1()?;
        let semantic = extent.dominant_semantic_receiving_demand_v1()?;
        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let retained = u64::try_from(retained_bytes)
            .ok()
            .and_then(|value| value.checked_mul(16))
            .ok_or_else(overflow)?;
        let cells = u64::try_from(cells)
            .ok()
            .and_then(|value| value.checked_mul(16))
            .ok_or_else(overflow)?;
        let retained = ResourceVector::ZERO
            .with(D::MemoryBytes, retained)
            .with(D::MetadataEntries, cells)
            .with(D::StorageBytes, future);
        let names = match read.protected_name() {
            Some(name) => MountJournalCurrentnessOriginalsV1::named_demand_v1(name)?,
            None => ResourceVector::ZERO,
        };
        let demand = native
            .checked_add(semantic)?
            .checked_add(retained)?
            .checked_add(names)?;
        match &self.captured {
            Some(owner) => {
                let interval =
                    super::append::MountAppendIntervalOriginalV1::construction_bytes_v1()
                        .ok_or_else(overflow)?;
                Ok(demand.checked_add(owner.append_demand_v1(append, interval)?)?)
            }
            None => Ok(demand),
        }
    }
}
