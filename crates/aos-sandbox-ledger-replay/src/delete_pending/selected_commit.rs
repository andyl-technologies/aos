//! Selects exact native COMMIT DATA inside the existing canonical cursor.
//!
//! This owner compares historical DATA only. Current Controller/Session models, complete Source
//! Operation/auxiliary relations, role payment, native posts and effect authority
//! remain with Root's actual enclosing D owner.

use super::{JournalError, PendingErrorV1};
use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_protocol::domain_ledger::delete_batch::encode_native_commit_data_v1;
use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentDataErrorV1;
use std::error::Error;
use aos_sandbox_protocol::domain_ledger::{ProtectedHistoryDataErrorV1,
    protected_names::{ProtectedJournalNamesV1, SessionCompletionPositionDataV4}};

/// Retains exact native-COMMIT comparison DATA without a currentness capability.
pub struct DeleteSelectedCommitReplayDataV3 {
    expected: [u8; 64],
    observed: Option<[u8; 64]>,
    storage_history: bool,
    session_boundary: Option<SessionCompletionPositionDataV4>,
    history_rows: [Vec<u8>; 3],
    history_copies: [Option<Result<(), std::collections::TryReserveError>>; 3],
    result: Option<Result<(), PendingErrorV1>>,
    complete: bool,
}

impl DeleteSelectedCommitReplayDataV3 {
    /// Creates vacant comparison slots; the supplied bytes authenticate nothing.
    pub const fn new(expected: [u8; 64]) -> Self {
        Self {
            expected,
            observed: None,
            storage_history: false,
            session_boundary: None,
            history_rows: [Vec::new(), Vec::new(), Vec::new()],
            history_copies: [None, None, None],
            result: None,
            complete: false,
        }
    }

    /// Selects the actual Storage terminal transaction and its predecessor rows.
    ///
    /// This comparison owner retains DATA only. Its caller prices the complete
    /// captured prefix before replay and independently authenticates these rows.
    pub fn new_storage_v3(expected: [u8; 64]) -> Self {
        Self { storage_history: true, ..Self::new(expected) }
    }

    /// Selects the actual last Session receipt at the SDK's native boundary.
    ///
    /// The established producer emits protected names48, next-sequence8 and
    /// held-file-length8. These bytes are not a transaction ID or COMMIT hash.
    /// The actual Root reader separately supplies its independently retained
    /// native names after full replay and native posts.
    ///
    /// # Errors
    /// Rejects malformed names, a zero next sequence or a zero held length.
    pub fn new_session_boundary_v4(expected: [u8; 64]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let position = SessionCompletionPositionDataV4::decode_v4(&expected)?;
        Ok(Self { storage_history: true, session_boundary: Some(position), ..Self::new(expected) })
    }

    /// Prices the actual selected key and both raw history rows before capture.
    ///
    /// # Errors
    /// Rejects arithmetic overflow converting the actual captured-prefix bound.
    pub fn storage_capture_demand_v3(captured_bytes: u64)
        -> Result<aos_sandbox_core::ResourceVector, JournalError>
    {
        let bytes = captured_bytes.checked_mul(3)
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(aos_sandbox_core::ResourceVector::ZERO.with(
            aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
    }

    /// Compares only the selected real COMMIT from the existing canonical cursor.
    ///
    /// # Errors
    /// Rejects duplicate selection, a changed native proof or completed reentry.
    pub fn observe_commit_v3(
        &mut self,
        commit: &CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        if self.complete || self.failure_v3().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        if let Some(position) = self.session_boundary {
            if commit.commit_sequence().checked_add(1) != Some(position.next_sequence_v4())
                || commit.coordinates().offset != position.held_bytes_v4() { return Ok(()); }
        } else if commit.transaction().id().as_slice() != &self.expected[..16] {
            return Ok(());
        }
        self.result = Some((|| {
            if self.observed.is_some() {
                return Err(SourceDeleteCurrentDataErrorV1::Association.into());
            }
            let actual = encode_native_commit_data_v1(
                *commit.transaction().id(),
                commit.commit_sequence(),
                commit.coordinates().offset,
                commit.commit_digest_data_v4().map_err(JournalError::from_ordinary_native_v1)?,
            )?;
            self.observed = Some(actual);
            if self.session_boundary.is_none() && actual != self.expected {
                return Err(SourceDeleteCurrentDataErrorV1::Native.into());
            }
            if self.storage_history {
                // The actual ordinary Session terminal producer commits exactly
                // one history PUT. An unrelated or replayed PUT is insufficient:
                // the upper shared decoder also proves its exact predecessor.
                let [row] = commit.transaction().records() else {
                    return Err(SourceDeleteCurrentDataErrorV1::Association.into());
                };
                if row.namespace() != aos_sandbox_core::RecordNamespace::BrokerSessionTraffic {
                    return Err(SourceDeleteCurrentDataErrorV1::Association.into());
                }
                let current = row.value().ok_or(SourceDeleteCurrentDataErrorV1::Association)?;
                let prior = commit.prior_state().iter().find_map(|((namespace, key), value)|
                    (*namespace == row.namespace() && key.as_slice() == row.key()).then_some(value.as_slice()))
                    .ok_or(SourceDeleteCurrentDataErrorV1::Association)?;
                for (index, bytes) in [row.key(), prior, current].into_iter().enumerate() {
                    self.history_copies[index] = Some(self.history_rows[index].try_reserve_exact(bytes.len()));
                    if !matches!(self.history_copies[index], Some(Ok(()))) {
                        return Err(SourceDeleteCurrentDataErrorV1::Association.into());
                    }
                    self.history_rows[index].extend_from_slice(bytes);
                }
            }
            Ok(())
        })());
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Requires actual selected COMMIT and complete later native EOF.
    ///
    /// # Errors
    /// Rejects missing selection, changed captured end or incomplete native prefix.
    pub fn finish_prefix_v3(
        &mut self,
        prefix: CanonicalReplayPrefixReadViewV1<'_>,
        captured_end: u64,
    ) -> Result<(), JournalError> {
        if self.complete || self.failure_v3().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some((|| {
            let observed = self
                .observed
                .ok_or(SourceDeleteCurrentDataErrorV1::Native)?;
            let sequence = u64::from_be_bytes(
                observed[48..56]
                    .try_into()
                    .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?,
            );
            let end = u64::from_be_bytes(
                observed[56..]
                    .try_into()
                    .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?,
            );
            let actual = prefix.coordinates();
            if let Some(position) = self.session_boundary {
                let expected_next = position.next_sequence_v4();
                let expected_end = position.held_bytes_v4();
                if sequence.checked_add(1) != Some(expected_next)
                    || actual.durable_next_sequence != expected_next
                    || end != expected_end || captured_end != expected_end {
                    return Err(SourceDeleteCurrentDataErrorV1::Native.into());
                }
            }
            if sequence >= actual.durable_next_sequence
                || end > captured_end
                || actual.durable_end != captured_end
                || actual.offset != captured_end
            {
                return Err(SourceDeleteCurrentDataErrorV1::Native.into());
            }
            Ok(())
        })());
        self.complete = matches!(self.result, Some(Ok(())));
        if self.complete {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Borrows selected historical DATA only after the actual completed prefix.
    ///
    /// # Errors
    /// Rejects an incomplete or failed selection.
    pub fn data_v3(&self) -> Result<[u8; 64], SourceDeleteCurrentDataErrorV1> {
        if !self.complete || self.failure_v3().is_some() {
            return Err(SourceDeleteCurrentDataErrorV1::Native);
        }
        self.observed.ok_or(SourceDeleteCurrentDataErrorV1::Native)
    }

    /// Joins all established native boundary bytes with the real Root read.
    ///
    /// # Errors
    /// Refuses another purpose, changed protected name, sequence or file length,
    /// or an incomplete last-receipt selection/full native prefix.
    pub fn session_boundary_data_v4(&self, names: ProtectedJournalNamesV1, next: u64, end: u64)
        -> Result<[u8; 64], SourceDeleteCurrentDataErrorV1> {
        self.data_v3()?;
        let position = self.session_boundary.ok_or(SourceDeleteCurrentDataErrorV1::Native)?;
        if position.names_v4() != names || position.next_sequence_v4() != next || position.held_bytes_v4() != end {
            return Err(SourceDeleteCurrentDataErrorV1::Native);
        }
        Ok(self.expected)
    }

    /// Borrows the retained original comparison refusal.
    pub fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.history_copies.iter().filter_map(Option::as_ref)
            .find_map(|copy| copy.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Borrows the selected key, exact prior row and exact terminal PUT row.
    ///
    /// # Errors
    /// Rejects another purpose or an incomplete selected native EOF comparison.
    pub fn storage_history_rows_v3(&self)
        -> Result<(&[u8], &[u8], &[u8]), SourceDeleteCurrentDataErrorV1>
    {
        self.data_v3()?;
        if !self.storage_history || !self.history_copies.iter().all(|copy| matches!(copy, Some(Ok(())))) {
            return Err(SourceDeleteCurrentDataErrorV1::Association);
        }
        Ok((&self.history_rows[0], &self.history_rows[1], &self.history_rows[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker::canonical_journal::CanonicalReplayOriginalV1;
    use aos_sandbox_core::RecordNamespace;
    use aos_sandbox_protocol::domain_ledger::transaction::{
        JournalLimits, JournalRecord, JournalTransaction, encode_transaction,
    };
    use std::io::Write as _;

    #[test]
    fn actual_commit_selection_requires_all64_and_completed_eof_while_retaining_first_error() {
        let mut file = tempfile::tempfile().unwrap();
        let mut next = 1;
        for id in [7, 8] {
            let transaction = JournalTransaction::new(
                [id; 16],
                vec![JournalRecord::put(
                    RecordNamespace::Operation,
                    vec![id],
                    vec![id + 1],
                )],
            )
            .unwrap();
            let frames = encode_transaction(&transaction, next).unwrap();
            next += frames.len() as u64;
            for frame in frames {
                file.write_all(&frame).unwrap();
            }
        }
        let end = file.metadata().unwrap().len();
        let mut replay = CanonicalReplayOriginalV1::new();
        let mut cursor = replay
            .begin_semantic_cursor_once(&file, JournalLimits::default(), end)
            .unwrap();
        let mut selected = None;
        let mut wrong = Vec::new();
        let mut missing = DeleteSelectedCommitReplayDataV3::new([19; 64]);
        while cursor.advance_once().unwrap() {
            let actual = cursor.current_commit().unwrap();
            if selected.is_none() {
                let expected = encode_native_commit_data_v1(
                    *actual.transaction().id(),
                    actual.commit_sequence(),
                    actual.coordinates().offset,
                    actual.commit_digest_data_v4().unwrap(),
                )
                .unwrap();
                let mut positive = DeleteSelectedCommitReplayDataV3::new(expected);
                let mut unrelated_storage = DeleteSelectedCommitReplayDataV3::new_storage_v3(expected);
                assert!(unrelated_storage.observe_commit_v3(&actual).is_err());
                assert!(unrelated_storage.storage_history_rows_v3().is_err());
                positive.observe_commit_v3(&actual).unwrap();
                assert!(positive.data_v3().is_err());
                for offset in [16, 47, 48, 55, 56, 63] {
                    let mut changed = expected;
                    changed[offset] ^= 1;
                    let mut negative = DeleteSelectedCommitReplayDataV3::new(changed);
                    assert!(negative.observe_commit_v3(&actual).is_err());
                    let first = negative.failure_v3().unwrap() as *const dyn Error;
                    assert!(negative.observe_commit_v3(&actual).is_err());
                    assert!(std::ptr::eq(
                        first,
                        negative.failure_v3().unwrap() as *const dyn Error
                    ));
                    wrong.push(negative);
                }
                selected = Some(positive);
            } else {
                selected
                    .as_mut()
                    .unwrap()
                    .observe_commit_v3(&actual)
                    .unwrap();
            }
            missing.observe_commit_v3(&actual).unwrap();
            cursor.validate_compaction_once().unwrap();
            cursor.register_transaction_once().unwrap();
            cursor.prepare_change_once().unwrap();
            cursor.apply_commit_once().unwrap();
        }
        let selected = selected.as_mut().unwrap();
        selected
            .finish_prefix_v3(cursor.completed_prefix().unwrap(), end)
            .unwrap();
        assert!(selected.data_v3().is_ok());
        assert!(
            missing
                .finish_prefix_v3(cursor.completed_prefix().unwrap(), end)
                .is_err()
        );
        assert!(missing.data_v3().is_err());
        for negative in wrong {
            assert!(negative.data_v3().is_err());
        }
    }
}
