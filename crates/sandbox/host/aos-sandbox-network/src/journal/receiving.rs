//! Prices actual Network parser, index and native append representations.
//!
//! These are passive requirements. The existing startup/operation/parent loan
//! admits them before growth; no amount returned here funds another owner.

use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalReplayIndexOriginalsV1;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::framing::HEADER_BYTES;
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use super::schema::Schema;
use super::{Journal, JournalAppendReceivingDemandErrorV1, JournalError, JournalLimits};

#[derive(Clone, Copy)]
pub(crate) struct ProtectedJournalPreopenReplayExtentV1 {
    pub(crate) limits: JournalLimits,
    pub(crate) native_bytes: u64,
    pub(crate) source_transactions: usize,
    pub(crate) source_checkpoint_rows: usize,
    canonical: CanonicalReplayExtentDataV1,
    schema: Schema,
}

impl ProtectedJournalPreopenReplayExtentV1 {
    pub(super) fn from_canonical(
        canonical: CanonicalReplayExtentDataV1,
        schema: Schema,
    ) -> Result<Self, JournalError> {
        let limits = canonical.limits();
        let bytes = canonical.native_bytes();
        let frames =
            usize::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)? / HEADER_BYTES;
        let transactions = limits
            .maximum_transactions
            .checked_add(1)
            .ok_or(JournalError::JournalTooLarge)?
            .min(frames);
        // These legacy field names are conservative reached-row DATA used by
        // the unchanged catalog suppliers. They certify no Source history.
        Ok(Self {
            limits,
            native_bytes: bytes,
            source_transactions: transactions,
            source_checkpoint_rows: frames,
            canonical,
            schema,
        })
    }

    pub(crate) fn dominant_native_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, JournalError> {
        let index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(self.canonical)
            .map_err(|_| JournalError::JournalTooLarge)?;
        self.canonical
            .dominant_native_receiving_demand_v1()?
            .checked_add(index)
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn dominant_semantic_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, JournalError> {
        let native = self.canonical.dominant_semantic_receiving_demand_v1()?;
        let source = match self.schema {
            Schema::Lifecycle => {
                let bytes = usize::try_from(self.native_bytes)
                    .map_err(|_| JournalError::JournalTooLarge)?;
                aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
                    bytes, bytes / HEADER_BYTES).map_err(JournalError::from)?
            }
            #[cfg(test)]
            Schema::Fixture => {
                let bytes = usize::try_from(self.native_bytes)
                    .map_err(|_| JournalError::JournalTooLarge)?;
                aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
                    bytes, bytes / HEADER_BYTES).map_err(JournalError::from)?
            }
            _ => ResourceVector::ZERO,
        };
        native
            .checked_add(source)
            .map_err(JournalError::ReceivingAccounting)
    }
}

// The sole external static caller prices fixed Prepare-worker replay. Other
// catalog extents carry their actual closed schema from the held opener.
pub(crate) fn protected_journal_preopen_replay_extent_for_prefix_v1(
    limits: JournalLimits,
    bytes: u64,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    ProtectedJournalPreopenReplayExtentV1::from_canonical(
        CanonicalReplayExtentDataV1::new(limits, bytes)?,
        Schema::Worker,
    )
}

impl Journal {
    pub(crate) fn append_receiving_demand_v1(
        &self,
        records: impl ExactSizeIterator<Item = RecordShape>,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        self.append_sequence_receiving_demand_v1(std::iter::once(Ok(records)))
    }

    pub(crate) fn append_sequence_receiving_demand_v1<I, T>(
        &self,
        transactions: I,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    where
        I: IntoIterator<Item = Result<T, JournalError>>,
        T: ExactSizeIterator<Item = RecordShape>,
    {
        let mut append = 0u64;
        for records in transactions {
            let width = encoded_transaction_append_bytes(records?).map_err(JournalError::from)?;
            append = append
                .checked_add(width)
                .ok_or(JournalError::JournalTooLarge)?;
        }
        self.ensure_healthy()?;
        let future = self
            .read_view()
            .metadata()
            .map_err(JournalError::Io)?
            .len()
            .checked_add(append)
            .ok_or(JournalError::JournalTooLarge)?;
        let extent = ProtectedJournalPreopenReplayExtentV1::from_canonical(
            CanonicalReplayExtentDataV1::new(self.read_view().limits(), future)
                .map_err(JournalError::from)?,
            self.schema,
        )?;
        let mut retained_bytes = 0usize;
        for ((_, key), value) in self.read_view().state() {
            retained_bytes = retained_bytes
                .checked_add(key.capacity())
                .and_then(|bytes| bytes.checked_add(value.capacity()))
                .ok_or(JournalError::JournalTooLarge)?;
        }
        for key in self.read_view().idempotency_index().keys() {
            retained_bytes = retained_bytes
                .checked_add(key.capacity())
                .ok_or(JournalError::JournalTooLarge)?;
        }
        let cells = self
            .read_view()
            .state()
            .len()
            .checked_add(self.read_view().idempotency_index().len())
            .and_then(|cells| cells.checked_add(self.read_view().transaction_ids().len()))
            .and_then(|cells| cells.checked_add(self.read_view().committed_namespaces().len()))
            .ok_or(JournalError::JournalTooLarge)?;
        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let retained = u64::try_from(retained_bytes)
            .map_err(|_| overflow())?
            .checked_mul(16)
            .ok_or_else(overflow)?;
        let cells = u64::try_from(cells)
            .map_err(|_| overflow())?
            .checked_mul(16)
            .ok_or_else(overflow)?;
        let retained = ResourceVector::ZERO
            .with(D::MemoryBytes, retained)
            .with(D::MetadataEntries, cells)
            .with(D::StorageBytes, future);
        let names = match self.read_view().protected_name() {
            Some(name) => aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1::<
                JournalError,
            >::named_demand_v1(name)?,
            None => ResourceVector::ZERO,
        };
        let mut total = extent
            .dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(retained)?
            .checked_add(names)?;
        if let Some(captured) = &self.captured {
            total = total.checked_add(captured.append_demand_v1(append,
                super::append::JournalNativeIntervalOriginalV1::receiving_construction_bytes_v1()
                    .ok_or(JournalError::JournalTooLarge)?)?)?;
        }
        Ok(total)
    }
}

// Fixed worker maximum uses the same actual schema/index/native suppliers as
// the held-writer forecast, at its declared ceilings before child creation.
pub(super) fn maximum_worker_append_demand(
    limits: JournalLimits,
    encoded: u64,
) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
    let invalid = || JournalError::JournalTooLarge;
    let bytes = limits
        .maximum_transactions
        .checked_mul(limits.maximum_key_bytes)
        .and_then(|bytes| bytes.checked_add(limits.maximum_materialized_bytes))
        .ok_or_else(invalid)?;
    let cells = limits
        .maximum_transactions
        .checked_mul(2)
        .and_then(|cells| cells.checked_add(limits.maximum_materialized_records))
        .and_then(|cells| cells.checked_add(usize::from(u8::MAX) + 1))
        .ok_or_else(invalid)?;
    let extent = protected_journal_preopen_replay_extent_for_prefix_v1(
        limits,
        limits.maximum_journal_bytes,
    )?;
    let retained = ResourceVector::ZERO
        .with(
            D::MemoryBytes,
            u64::try_from(bytes)
                .ok()
                .and_then(|bytes| bytes.checked_mul(16))
                .ok_or_else(invalid)?,
        )
        .with(
            D::MetadataEntries,
            u64::try_from(cells)
                .ok()
                .and_then(|cells| cells.checked_mul(16))
                .ok_or_else(invalid)?,
        )
        .with(D::StorageBytes, limits.maximum_journal_bytes);
    let names = aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1::<JournalError>
        ::named_demand_v1("network-worker-replay.journal")?;
    let captured = aos_sandbox_broker::canonical_journal::captured::CapturedAppendDataOwnerV1::<
        JournalError,
    >::append_demand_for_fixed_v1(
        "/var/lib/aos-sandbox-network-worker",
        "network-worker-replay.journal",
        encoded,
        super::append::JournalNativeIntervalOriginalV1::receiving_construction_bytes_v1()
            .ok_or_else(invalid)?,
    )?;
    Ok(extent
        .dominant_native_receiving_demand_v1()?
        .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
        .checked_add(retained)?
        .checked_add(names)?
        .checked_add(captured)?)
}
