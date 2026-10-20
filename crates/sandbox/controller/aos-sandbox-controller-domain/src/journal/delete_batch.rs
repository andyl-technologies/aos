//! Selected Delete native CAS and same-parser COMMIT comparison DATA.
//!
//! The adapter borrows the native map and canonical batch codec. It does not
//! authenticate the supplied graph, Source reference, independent Root floor,
//! physical retirement or a caller's permission to delete anything.

use super::*;
use aos_sandbox_protocol::domain_ledger::controller_history_relation::validate_delete_batch_admission_records_v1;
use aos_sandbox_protocol::domain_ledger::delete_batch::{self as codec, DeleteBatchViewV1};

aos_sandbox_ledger_replay::define_delete_replay_data_recipe_v1!();

#[cfg(all(test, target_os = "linux"))]
mod companion_tests;

/// Observes metadata only after the sole native parser validates COMMIT.
#[cfg(target_os = "linux")]
pub(super) struct NativeObserverV1 {
    transaction: [u8; 16],
    proof: Option<[u8; 64]>,
}

#[cfg(target_os = "linux")]
impl NativeObserverV1 {
    pub(super) const fn new(transaction: [u8; 16]) -> Self {
        Self { transaction, proof: None }
    }

    pub(super) fn completed_proof_data_v1(&self) -> Option<&[u8; 64]> {
        self.proof.as_ref()
    }

    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        commit_sequence: u64,
        end_offset: u64,
        native_digest: &[u8],
    ) -> Result<(), JournalError> {
        if transaction.id() != &self.transaction {
            return Ok(());
        }
        if self.proof.is_some() || native_digest.len() != 32 || !selected(transaction) {
            return Err(invalid());
        }
        self.proof = Some(native_commit_data_v1(*transaction.id(), commit_sequence, end_offset, native_digest)?);
        Ok(())
    }
}

/// Retains first readback cause separately from a final original-owner debt.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
#[error("Delete native readback refused: {cause}")]
pub(crate) struct NativeReadbackErrorV1 {
    #[source]
    pub(crate) cause: JournalError,
    pub(crate) postcheck: Option<JournalError>,
}

#[cfg(target_os = "linux")]
impl From<JournalError> for NativeReadbackErrorV1 {
    fn from(cause: JournalError) -> Self {
        Self { cause, postcheck: None }
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    /// Returns actual validated native COMMIT DATA while borrowing this writer.
    ///
    /// # Errors
    ///
    /// Refuses foreign fixed names/limits, missing batch/COMMIT, incomplete or
    /// compacted history, replay disagreement or original file/lock drift.
    /// The returned bytes cannot authenticate Source or authorize retirement.
    pub(crate) fn observe_delete_batch_native_proof_v1(
        &self,
        batch_bytes: &[u8],
    ) -> Result<[u8; 64], NativeReadbackErrorV1> {
        use super::runtime_deployment_history::ReadAtCursorV1;

        let batch = DeleteBatchViewV1::decode(batch_bytes).map_err(|_| invalid())?;
        self.require_delete_location()?;
        let witness = self.protected_writer_name_witness()?;
        let result = (|| {
            let key = codec::batch_key(batch.project(), batch.operation());
            if self.native.state().get(&(RecordNamespace::DesiredState, key)).map(Vec::as_slice)
                != Some(batch_bytes)
            {
                return Err(invalid());
            }
            bound_preview(self.native.state(), &[], self.native.limits())?;

            let mut observer = NativeObserverV1::new(batch.transaction());
            let reader = self.native.captured_reader(witness.file().byte_len());
            let replayed = replay_coordinator_observed_v1(
                reader,
                self.native.limits(),
                None,
                Some(DeploymentHistoryObserverV1::Delete(&mut observer)),
            )?;
            require_replay_matches_controller_v1(self, &replayed, witness.file().byte_len())?;
            observer.proof.ok_or_else(invalid)
        })();

        let postcheck = self.require_delete_location()
            .and_then(|()| self.validate_protected_writer_name_witness(&witness));
        match (result, postcheck) {
            (Ok(proof), Ok(())) => Ok(proof),
            (Err(cause), postcheck) => Err(NativeReadbackErrorV1 {
                cause,
                postcheck: postcheck.err(),
            }),
            (Ok(_), Err(cause)) => Err(NativeReadbackErrorV1 { cause, postcheck: None }),
        }
    }

    fn require_delete_location(&self) -> Result<(), JournalError> {
        self.require_protected_named_location(
            Path::new("/var/lib/aos/sandboxd"),
            "controller.journal",
            self.protected_owner_uid()?,
            crate::journal::controller::production_journal_limits(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_pending_batch() -> (BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>, Vec<u8>) {
        let bytes = codec::fixture_batch_v1(b"projection", b"retained before", 1);
        let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
        let key = codec::batch_key(batch.project(), batch.operation());
        let state = BTreeMap::from([((RecordNamespace::DesiredState, key), bytes.clone())]);
        (state, bytes)
    }

    #[test]
    fn pending_batch_fences_exact_operation_and_live_preimage_without_global_freeze() {
        let (state, _) = retained_pending_batch();
        for record in [
            JournalRecord::put(RecordNamespace::Operation, vec![5; 16], b"terminal".to_vec()),
            JournalRecord::delete(RecordNamespace::Operation, vec![5; 16]),
            JournalRecord::put(RecordNamespace::DesiredState, b"projection".to_vec(), b"changed".to_vec()),
        ] {
            let transaction = JournalTransaction::new([20; 16], vec![record]).unwrap();
            assert!(matches!(validate(&state, &transaction, 2, JournalLimits::default()), Err(JournalError::ProtectedBoundary)));
        }

        let unrelated = JournalTransaction::new([21; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![22; 16], b"unrelated".to_vec()),
        ]).unwrap();
        assert!(validate(&state, &unrelated, 2, JournalLimits::default()).is_ok());
    }

    #[test]
    fn batch_native_watermark_and_foreign_marker_refuse_before_admission_decode() {
        let (_, bytes) = retained_pending_batch();
        let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
        let transaction = JournalTransaction::new(batch.transaction(), vec![
            JournalRecord::put(RecordNamespace::DesiredState,
                codec::batch_key(batch.project(), batch.operation()), bytes.clone()),
        ]).unwrap();
        assert!(validate(&BTreeMap::new(), &transaction, 2, JournalLimits::default()).is_err());

        let marker_only = JournalTransaction::new([23; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState,
                codec::handoff_key(batch.project(), batch.operation()).to_vec(), vec![0; 160]),
        ]).unwrap();
        assert!(validate(&BTreeMap::new(), &marker_only, 1, JournalLimits::default()).is_err());
    }

    #[test]
    fn preview_checks_aggregate_payload_before_clone_but_ordinary_path_is_unchanged() {
        let (state, _) = retained_pending_batch();
        let maximum_materialized_bytes = state.iter().map(|((_, key), value)| key.len() + value.len()).sum();
        let limits = JournalLimits {
            maximum_materialized_bytes, maximum_transaction_bytes: 8,
            ..JournalLimits::default()
        };
        let transaction = JournalTransaction::new([24; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![25; 16], vec![26; 16]),
        ]).unwrap();

        assert!(bound_preview(&state, std::slice::from_ref(&transaction), limits).is_err());
        assert!(bound_preview(&BTreeMap::new(), &[transaction], limits).is_ok());
    }
}

// One comparison recipe serves ordinary proof projection and the selected
// retained C17 owner. It certifies neither authorization nor a Root relation.
#[cfg(target_os = "linux")]
pub(super) fn require_replay_matches_controller_v1(
    journal: &Journal,
    replayed: &ObservedReplayStateV1,
    length: u64,
) -> Result<(), JournalError> {
    if replayed.durable_end != length
        || replayed.next_sequence != journal.native.next_sequence()
        || replayed.committed_transactions != journal.native.committed_transactions()
        || replayed.native.transaction_ids_data_v1() != journal.native.transaction_ids()
        || replayed.native.state_data_v1() != journal.native.state()
        || replayed.native.idempotency_data_v1() != journal.native.idempotency()
        || replayed.native.materialized_bytes_data_v1() != journal.native.materialized_bytes()
        || replayed.q04_lower_history_present != journal.q04_lower_history_present
        || replayed.source_history_compacted
    {
        return Err(invalid());
    }
    Ok(())
}

// The parser supplies these exact native coordinates and digest. This helper
// formats DATA only; neither caller can turn supplied bytes into an original.
#[cfg(target_os = "linux")]
pub(super) fn native_commit_data_v1(
    transaction: [u8; 16], commit_sequence: u64, end_offset: u64, native_digest: &[u8],
) -> Result<[u8; 64], JournalError> {
    aos_sandbox_protocol::domain_ledger::delete_batch::encode_native_commit_data_v1(
        transaction, commit_sequence, end_offset, native_digest,
    ).map_err(|_| invalid())
}
