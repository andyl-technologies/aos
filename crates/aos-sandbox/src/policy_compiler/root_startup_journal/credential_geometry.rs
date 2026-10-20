//! Bounded fixed startup admissions over the same actually held journal.
//!
//! Known DesiredState rows do not allocate unrelated capacity or sidecar models.
//! Existing materialized state may still be copied/revalidated during append,
//! so its old-prefix demand remains a separate simultaneous overlap.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};

use crate::journal::{JournalError, JournalRecord, ProtectedJournalPreopenReplayExtentV1};

use super::RootPolicyStartupJournalV1;

impl RootPolicyStartupJournalV1 {
    pub(crate) fn fixed_credential_append_peak_v1(
        held: &ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("fixed Root credential append geometry");
        let policy = super::super::deployment_head::fixed_startup_policy_admission_shapes_v1();
        let shapes = [
            policy[0], policy[1],
            RecordShape { key_bytes: super::super::cache_readback_pin::CACHE_PIN_KEY.len(), value_bytes: Some(80) },
            RecordShape { key_bytes: aos_sandbox_policy::journal_keys::CONTROLLER_HOLD_PIN_KEY.len(), value_bytes: Some(80) },
            RecordShape { key_bytes: aos_sandbox_policy::journal_keys::SOURCE_HOLD_PIN_KEY.len(), value_bytes: Some(80) },
        ];
        let mut encoded = 0u64;
        for shape in shapes {
            let append = encoded_transaction_append_bytes(std::iter::once(shape))
                .map_err(|_| invalid())?;
            encoded = encoded.checked_add(append).ok_or_else(invalid)?;
        }
        // Keep every new row, transaction/model/preparation owner, native
        // encoding, protected readback and prospective comparison copy. The
        // old-prefix overlap below is additional; no future drop is credited.
        let cells = 5 * 16u64;
        let cell = std::mem::size_of::<(JournalRecord, [u8; 16], [usize; 3])>() as u64;
        let memory = encoded.checked_mul(16)
            .and_then(|bytes| bytes.checked_add(cells.checked_mul(cell)?))
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .and_then(|bytes| bytes.checked_add(u64::try_from(std::mem::size_of::<
                super::RootStartupCredentialWriterV1<'_>,
            >().checked_mul(2)?).ok()?))
            .and_then(|bytes| bytes.checked_add(u64::try_from(std::mem::size_of::<
                Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
            >().checked_mul(2)?).ok()?)).ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::StorageBytes, encoded)
            .with(D::MetadataEntries, cells)
            .with(D::PublicationStagingBytes, memory)
            .with(D::OutputBytes, memory);
        held.dominant_native_receiving_demand_v1()?
            .checked_add(held.dominant_semantic_receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(fixed))
            .map_err(|_| invalid())
    }
}
