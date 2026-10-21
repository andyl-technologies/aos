//! Shares the actual Root history-pair preparation, native append and readback.
//!
//! Only fixed Root producers supply the private purpose loan. Body and receipt
//! bytes remain comparison DATA; the same existing native commit engine still
//! invokes the exact role transition and final-crossing gates.

use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;
use std::error::Error as StdError;
use std::fs::Metadata;
use std::io;
use std::os::unix::net::UnixStream;

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, RecordCoordinatesV1,
    RecordEnvelopeV1, PhaseV1,
};
use crate::journal::{CommitResult, Journal, JournalError, JournalTransaction};
use crate::journal::create_storage_history::{
    prepare_history_pair_v1, readback_history_pair_v1};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use super::root_open::{RootCurrentOpenStateV1, RootCurrentOpenAppendLoanV1,
    RootCurrentOpenCrossingV1, RootCurrentHistoryPurposeV1};

pub(super) struct RootCurrentHistoryPairV1<const RECORD: usize> {
    pub(super) record: [u8; RECORD],
    pub(super) checksum: Option<Result<[u8; 32], HistoryErrorV1>>,
    pub(super) head: [u8; HEAD_BYTES],
    head_encoding: Option<Result<[u8; HEAD_BYTES], HistoryErrorV1>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    crossing: RootCurrentOpenCrossingV1,
    pub(super) append: Option<Result<CommitResult, JournalError>>,
    pub(super) readback: Option<Result<HistoryPairReadbackDataV1<RECORD>, JournalError>>,
    pub(super) native_end: Option<io::Result<Metadata>>,
    before_next: Option<u64>,
    policy_next: Option<u64>,
}

impl<const RECORD: usize> RootCurrentHistoryPairV1<RECORD> {
    pub(super) fn new() -> Self {
        Self { record: [0; RECORD], checksum: None, head: [0; HEAD_BYTES],
            head_encoding: None, transaction: None, crossing: Default::default(),
            append: None, readback: None, native_end: None, before_next: None,
            policy_next: None }
    }

    pub(super) fn prepare_once(&mut self, key: KeyV1, phase: PhaseV1,
        predecessor: [u8; 32], correlation: [u8; 32], body: &[u8],
    ) -> Result<(), JournalError> {
        if self.checksum.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.checksum = Some(RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor, correlation,
        }, body, &mut self.record));
        self.head_encoding = Some(LatestHeadV1::new(key.revision(),
            *positive(&self.checksum)?).map(|head| head.encode()));
        self.head = *positive(&self.head_encoding)?;
        self.transaction = Some(prepare_history_pair_v1(key, phase, &self.record, &self.head));
        positive(&self.transaction).map(|_| ())
    }

    pub(super) fn prepare_cut_once(&mut self, root: &RootCurrentOpenStateV1,
        purpose: RootCurrentHistoryPurposeV1<'_>) -> Result<(), JournalError>
    {
        if self.before_next.is_some() { return Err(JournalError::ProtectedBoundary); }
        let body = root.completed_body().map_err(|_| JournalError::ProtectedBoundary)?;
        self.before_next = Some(purpose.expected_authority_next(body)?);
        self.policy_next = Some(body.policy_next);
        Ok(())
    }

    pub(super) fn append_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream, authority: &mut Journal, policy: &Journal,
        root: &RootCurrentOpenStateV1, purpose: RootCurrentHistoryPurposeV1<'_>,
    ) -> Result<(), JournalError> {
        if self.append.is_some() { return Err(JournalError::ProtectedBoundary); }
        let transaction = positive(&self.transaction)?;
        let mut loan = RootCurrentOpenAppendLoanV1::for_history_purpose_v1(flight,
            original, policy, root, purpose, transaction, &mut self.crossing)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.append = Some(authority.commit_create_storage_root_history_v1(transaction, &mut loan));
        if matches!(self.append, Some(Ok(_))) {
            self.readback = Some(self.readback_pair(authority, policy));
            self.native_end = Some(authority.held_native_receiving_metadata_v1().0);
        }
        positive(&self.append)?;
        positive(&self.readback)?;
        self.require_end(&self.native_end)
    }

    pub(super) fn readback_pair(&self, authority: &Journal, policy: &Journal)
        -> Result<HistoryPairReadbackDataV1<RECORD>, JournalError>
    {
        let observed = self.readback_pair_data(authority)?;
        if Some(policy.snapshot_sequence()) != self.policy_next {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(observed)
    }

    fn readback_pair_data(&self, authority: &Journal)
        -> Result<HistoryPairReadbackDataV1<RECORD>, JournalError>
    {
        readback_history_pair_v1(authority, positive(&self.transaction)?,
            &self.record, &self.head, self.before_next.ok_or(JournalError::ProtectedBoundary)?,
            positive(&self.append)?)
    }

    pub(super) fn require_end(&self, metadata: &Option<io::Result<Metadata>>)
        -> Result<(), JournalError>
    {
        if positive(metadata)?.len() != positive(&self.append)?.durable_bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn readback_current_v1(&self, authority: &Journal, policy: &Journal)
        -> Result<HistoryPairReadbackDataV1<RECORD>, JournalError>
    {
        let observed = self.readback_pair_data(authority)?;
        let metadata = authority.held_native_receiving_metadata_v1().0?;
        if metadata.len() != positive(&self.append)?.durable_bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        if Some(policy.snapshot_sequence()) != self.policy_next {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(observed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.checksum).or_else(|| cause(&self.head_encoding))
            .or_else(|| cause(&self.transaction)).or_else(|| self.crossing.failure())
            .or_else(|| cause(&self.append)).or_else(|| cause(&self.readback))
            .or_else(|| cause(&self.native_end))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>)
    -> Option<&(dyn StdError + 'static)>
{
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        OwnerV1, continuation::{UseAdmittedBodyDataV1, USE_ADMITTED_RECORD_BYTES_V1},
    };

    fn body() -> Vec<u8> {
        UseAdmittedBodyDataV1 {
            use_reserved: [1; 32], current_proofs: [2; 32], source_current: [3; 32],
            cache_current: [4; 32], use_claim: [5; 16], unsigned_plan: [6; 32],
            signing_statement: [7; 32],
        }.encode().unwrap().to_vec()
    }

    #[test]
    fn shared_root3_preparation_preserves_the_exact_ordered_record_and_head() {
        // Canonical comparison DATA only, without a Root R, native writer,
        // paid stage, current-cut proof or append-loan constructor.
        let key = KeyV1::new([1; 16], OwnerV1::Root, 3).unwrap();
        let phase = PhaseV1::new(OwnerV1::Root, 3).unwrap();
        let mut pair = RootCurrentHistoryPairV1::<USE_ADMITTED_RECORD_BYTES_V1>::new();
        pair.prepare_once(key, phase, [8; 32], [9; 32], &body()).unwrap();

        let envelope = RecordEnvelopeV1::decode(&pair.record, key, phase).unwrap();
        let transaction = pair.transaction.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(envelope.coordinates().predecessor, [8; 32]);
        assert_eq!(envelope.body(), body());
        assert_eq!(transaction.records().len(), 2);
        assert_eq!(transaction.records()[0].key(), key.encode());
        assert_eq!(transaction.records()[0].value(), Some(pair.record.as_slice()));
        assert_eq!(transaction.records()[1].key(),
            KeyV1::new([1; 16], OwnerV1::Root, 0).unwrap().encode());
        assert_eq!(transaction.records()[1].value(), Some(pair.head.as_slice()));
        assert!(pair.append.is_none());
    }

    #[test]
    fn malformed_body_extent_keeps_the_first_encoder_error_after_refused_reentry() {
        let key = KeyV1::new([1; 16], OwnerV1::Root, 3).unwrap();
        let phase = PhaseV1::new(OwnerV1::Root, 3).unwrap();
        let mut pair = RootCurrentHistoryPairV1::<USE_ADMITTED_RECORD_BYTES_V1>::new();
        let body = body();
        assert!(pair.prepare_once(key, phase, [8; 32], [9; 32], &body[..body.len() - 1]).is_err());
        let original = pair.failure().unwrap().downcast_ref::<HistoryErrorV1>().unwrap();
        let address = original as *const HistoryErrorV1;

        assert!(pair.prepare_once(key, phase, [8; 32], [9; 32], &body).is_err());
        let retained = pair.failure().unwrap().downcast_ref::<HistoryErrorV1>().unwrap();
        assert_eq!(address, retained as *const HistoryErrorV1);
        assert!(pair.transaction.is_none());
        assert!(pair.append.is_none());
    }
}
