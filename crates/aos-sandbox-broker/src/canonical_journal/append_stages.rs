//! Retains the existing native append steps without admitting a role mutation.
//!
//! Genuine owners keep their semantic, currentness, financial and final-crossing
//! checks around these explicit steps. An ordinary caller lends its transaction;
//! a selected caller may move its already paid original into the same generic
//! carrier. No extra transaction clone, metadata probe, parser, File adoption,
//! callback, account, successful-disposal receipt or role permit is introduced.
//!
//! The caller retains this whole carrier on failure or abandonment. In
//! particular, ordinary field destruction is not selected negative custody.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::error::Error;

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::materialized::RecordMutationRef;
use aos_sandbox_journal::owner::NativeJournal;
use aos_sandbox_journal::transaction::NativeRecordRef;
use aos_sandbox_protocol::domain_ledger::readonly::{
    IdempotencyDecisionV1, IdempotencyRecordDataErrorV1, apply_idempotency_record,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord, JournalTransaction};

/// Reports a closed or out-of-order mechanical stage without replacing its cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("canonical native append stage is closed or out of order")]
pub struct CanonicalAppendClosedV1;

/// Preserves an ordinary stage's actual owned native or resident-index error.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalAppendErrorV1 {
    /// A known immutable recovery DATA family refused before projection.
    #[error(transparent)]
    Record(#[from] aos_sandbox_protocol::domain_ledger::JournalTransactionDataError),
    /// A projection, encoder, arithmetic, metadata, write or sync step failed.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The resident decision index rejected the record after native application.
    #[error(transparent)]
    Idempotency(#[from] IdempotencyRecordDataErrorV1),
    /// A caller repeated or reordered a step.
    #[error(transparent)]
    Closed(#[from] CanonicalAppendClosedV1),
}

/// Carries actual published coordinates as DATA, never an admitted role receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalAppendPublishedDataV1 {
    /// Names the transaction actually supplied to the common encoder.
    pub transaction: [u8; 16],
    /// Names the actual head used by that encoder.
    pub head: u64,
    /// Names the sequence following the actual encoded frames.
    pub following: u64,
    /// Records the actual append engine's returned durable byte length.
    pub durable_bytes: u64,
    /// Records the actual native map projection accepted before encoding.
    pub materialized_bytes: usize,
}

#[derive(Clone, Copy)]
struct Coordinates {
    commit: u64,
    following: u64,
}

#[derive(Clone, Copy)]
enum AppendDisposition {
    Ordinary,
    Retaining,
}

/// Owns reached native stage results beside the actual supplied transaction.
///
/// The type parameter changes only DATA ownership: `&JournalTransaction` for
/// an ordinary immediate caller, or its genuine retained owned transaction.
/// Native identity, role purpose and unfinished-drop parking remain private to
/// the real owner. This carrier cannot prove those obligations for its caller.
pub struct CanonicalAppendStagesV1<T: Borrow<JournalTransaction>> {
    transaction: T,
    disposition: AppendDisposition,
    projection_original: aos_sandbox_journal::materialized::NativeMaterializedChangeOriginalsV1<RecordNamespace>,
    encoder_original: aos_sandbox_journal::transaction::NativeTransactionEncodeOriginalsV1,
    expected_metadata: Option<std::fs::Metadata>,
    head: Option<u64>,
    immutable_admission: Option<Result<(), aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    projected: Option<Result<usize, FrameError>>,
    frames: Option<Result<Vec<Vec<u8>>, FrameError>>,
    coordinates: Option<Result<Coordinates, FrameError>>,
    expected: Option<Result<u64, FrameError>>,
    native: Option<Result<u64, FrameError>>,
    index: Option<Result<(), IdempotencyRecordDataErrorV1>>,
    applied: usize,
    publication: Option<CanonicalAppendPublishedDataV1>,
    closed: Option<CanonicalAppendClosedV1>,
}

impl<T: Borrow<JournalTransaction>> CanonicalAppendStagesV1<T> {
    /// Retains supplied transaction DATA without native work or allocation.
    pub const fn new(transaction: T) -> Self {
        Self {
            transaction,
            disposition: AppendDisposition::Ordinary,
            projection_original: aos_sandbox_journal::materialized::NativeMaterializedChangeOriginalsV1::new(),
            encoder_original: aos_sandbox_journal::transaction::NativeTransactionEncodeOriginalsV1::new(),
            expected_metadata: None,
            head: None,
            immutable_admission: None,
            projected: None,
            frames: None,
            coordinates: None,
            expected: None,
            native: None,
            index: None,
            applied: 0,
            publication: None,
            closed: None,
        }
    }

    /// Creates the same inert carrier with retained native-local destinations.
    ///
    /// This selects representation custody only. Actual payment, role, native
    /// original identity and unfinished-drop parking still belong to the caller.
    pub const fn new_retaining_v1(transaction: T) -> Self {
        let mut stages = Self::new(transaction);
        stages.disposition = AppendDisposition::Retaining;
        stages
    }

    /// Borrows the same actual supplied transaction as comparison DATA.
    pub fn transaction(&self) -> &JournalTransaction {
        self.transaction.borrow()
    }

    /// Runs the existing native bounded map projection once, before encoding.
    ///
    /// # Errors
    /// Keeps the original projection error resident, or refuses reentry.
    pub fn project_once(
        &mut self,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
    ) -> Result<usize, CanonicalAppendClosedV1> {
        if self.failure().is_some() || self.projected.is_some() {
            return self.refuse();
        }
        self.head = Some(native.next_sequence());
        self.immutable_admission = Some(super::require_new_finality_admissions_v1(
            native.state(), self.transaction.borrow()));
        if !matches!(self.immutable_admission, Some(Ok(()))) {
            return Err(CanonicalAppendClosedV1);
        }
        let records = self.transaction.borrow().records().iter().map(RecordMutationRef::from);
        self.projected = Some(match self.disposition {
            AppendDisposition::Ordinary => native.projected_change(records),
            AppendDisposition::Retaining => native.projected_change_retaining_v1(
                records, &mut self.projection_original,
            ),
        });
        self.projected.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(CanonicalAppendClosedV1)
    }

    /// Runs the same native frame encoder once after successful projection.
    ///
    /// # Errors
    /// Retains encoder failure or refuses a changed head or repeated step.
    ///
    /// # Panics
    /// Preserves the underlying encoder's allocation/count panic conditions.
    pub fn encode_once(
        &mut self,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
    ) -> Result<(), CanonicalAppendClosedV1> {
        if !self.accepts_head(native) || self.frames.is_some()
            || !matches!(self.projected, Some(Ok(_)))
        {
            return self.refuse();
        }
        let transaction = self.transaction.borrow();
        let records = transaction.records().iter().map(|record| NativeRecordRef {
            namespace_byte: record.namespace() as u8,
            key: record.key(),
            value: record.value(),
        });
        self.frames = Some(match self.disposition {
            AppendDisposition::Ordinary => native.encode_at_head(*transaction.id(), records),
            AppendDisposition::Retaining => native.encode_at_head_retaining_v1(
                *transaction.id(), records, &mut self.encoder_original,
            ),
        });
        match self.frames {
            Some(Ok(_)) => Ok(()),
            _ => Err(CanonicalAppendClosedV1),
        }
    }

    /// Checks the old encoded frame-count/head arithmetic before metadata IO.
    ///
    /// # Errors
    /// Retains the original frame-count or sequence error, or refuses reentry.
    pub fn coordinates_once(&mut self) -> Result<(u64, u64), CanonicalAppendClosedV1> {
        if self.failure().is_some() || self.coordinates.is_some() {
            return self.refuse();
        }
        let Some(Ok(frames)) = self.frames.as_ref() else {
            return self.refuse();
        };
        let Some(head) = self.head else {
            return self.refuse();
        };
        self.coordinates = Some((|| {
            let count = u64::try_from(frames.len())
                .map_err(|_| FrameError::LimitExceeded("transaction frame count"))?;
            let commit = head.checked_add(count.checked_sub(1).ok_or(
                FrameError::SequenceExhausted,
            )?).ok_or(FrameError::SequenceExhausted)?;
            let following = commit.checked_add(1).ok_or(FrameError::SequenceExhausted)?;
            Ok(Coordinates { commit, following })
        })());
        self.coordinates.as_ref().and_then(|value| value.as_ref().ok())
            .map(|value| (value.commit, value.following)).ok_or(CanonicalAppendClosedV1)
    }

    /// Borrows the same actual frame vector for upper preflight checks.
    pub fn encoded_frames(&self) -> Option<&[Vec<u8>]> {
        if self.failure().is_some() {
            return None;
        }
        self.frames.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    /// Borrows retained encoded DATA even after a later failure.
    ///
    /// This diagnostic view cannot authorize append, publication or reuse.
    pub fn retained_encoded_frames(&self) -> Option<&[Vec<u8>]> {
        self.frames.as_ref().and_then(|value| value.as_ref().ok()).map(Vec::as_slice)
            .or_else(|| self.encoder_original.frames())
    }

    /// Borrows the actual failed current encoder payload without issuing authority.
    pub fn retained_encoder_payload(&self) -> Option<&[u8]> {
        self.encoder_original.payload()
    }

    /// Borrows the actual successful metadata retained before a later refusal.
    pub fn retained_expected_metadata(&self) -> Option<&std::fs::Metadata> {
        self.expected_metadata.as_ref()
    }

    /// Reports this actual carrier's inline bytes, including its supplied T.
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Bounds named resident and construction/control cells before growth.
    ///
    /// The census includes 15 fields +6 Results; coordinate DATA2; published
    /// DATA5 +local/returned copies10; seven live borrowed call references and
    /// five publication-iterator cells; lower projection7 and encoder8 controls;
    /// one successful Metadata body; one current lookup-key and one encoder
    /// payload/COMMIT allocation; outer frames1 +actual record/BEGIN/COMMIT Vecs.
    ///
    /// Transaction/index/native payloads and existing lower call scratch remain
    /// separate owner obligations. This DATA census grants no paid capacity.
    pub fn receiving_metadata_cells_v1(&self) -> Option<usize> {
        let fields_and_results = 21_usize;
        let coordinate_and_publication_data = 2_usize.checked_add(5)?.checked_add(10)?;
        let call_and_iterator_controls = 7_usize.checked_add(5)?;
        let lower_controls = aos_sandbox_journal::materialized::NativeMaterializedChangeOriginalsV1::<RecordNamespace>::receiving_metadata_cells_v1()
            .checked_add(aos_sandbox_journal::transaction::NativeTransactionEncodeOriginalsV1::receiving_metadata_cells_v1())?;
        fields_and_results.checked_add(coordinate_and_publication_data)?
            .checked_add(call_and_iterator_controls)?.checked_add(lower_controls)?
            .checked_add(3)?.checked_add(self.transaction.borrow().records().len())?
            .checked_add(3)
    }

    /// Copies the actual native projection, without admitting it as a budget.
    pub fn projected_materialized_bytes(&self) -> Option<usize> {
        if self.failure().is_some() {
            return None;
        }
        self.projected.as_ref()?.as_ref().ok().copied()
    }

    /// Copies the recorded encoder head as nonauthorizing DATA.
    pub const fn head(&self) -> Option<u64> {
        self.head
    }

    /// Runs the existing metadata/expected-length operation exactly once.
    ///
    /// # Errors
    /// Retains its original error or refuses incomplete/reordered preparation.
    pub fn expected_length_once(
        &mut self,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
    ) -> Result<u64, CanonicalAppendClosedV1> {
        if !self.accepts_head(native) || self.expected.is_some()
            || !matches!(self.coordinates, Some(Ok(_)))
        {
            return self.refuse();
        }
        let Some(Ok(frames)) = self.frames.as_ref() else {
            return self.refuse();
        };
        self.expected = Some(match self.disposition {
            AppendDisposition::Ordinary => native.expected_append_length(frames),
            AppendDisposition::Retaining => native.expected_append_length_retaining_v1(
                frames, &mut self.expected_metadata,
            ),
        });
        self.expected.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(CanonicalAppendClosedV1)
    }

    /// Performs only the existing exact append at the caller's final crossing.
    ///
    /// # Errors
    /// Retains native write/flush/sync/length failure and the original frames.
    pub fn append_once(
        &mut self,
        native: &mut NativeJournal<RecordNamespace, JournalLimits>,
    ) -> Result<u64, CanonicalAppendClosedV1> {
        if !self.accepts_head(native) || self.native.is_some() {
            return self.refuse();
        }
        let Some(Ok(expected)) = self.expected.as_ref() else {
            return self.refuse();
        };
        let Some(Ok(frames)) = self.frames.as_ref() else {
            return self.refuse();
        };
        self.native = Some(native.append_exact(frames, *expected));
        self.native.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(CanonicalAppendClosedV1)
    }

    /// Applies one native record, then its same resident index step, before advancing.
    ///
    /// Returns `false` only after every actual record has completed both steps.
    /// The caller can update its own provenance mirror after each `true` result.
    ///
    /// # Errors
    /// Retains the actual index refusal without advancing publication, or refuses
    /// an absent successful append, a changed head, or application after publish.
    pub fn apply_next_record_once(
        &mut self,
        native: &mut NativeJournal<RecordNamespace, JournalLimits>,
        index: &mut BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    ) -> Result<bool, CanonicalAppendClosedV1> {
        if !self.accepts_head(native) || !matches!(self.native, Some(Ok(_)))
            || self.publication.is_some()
        {
            return self.refuse();
        }
        let Some(record) = self.transaction.borrow().records().get(self.applied) else {
            return Ok(false);
        };
        native.apply_mutation(RecordMutationRef::from(record));
        self.index = Some(apply_idempotency_record(index, record));
        if !matches!(self.index, Some(Ok(()))) {
            return Err(CanonicalAppendClosedV1);
        }
        self.applied += 1;
        Ok(true)
    }

    /// Borrows the last record that completed native application and index update.
    pub fn last_applied_record(&self) -> Option<&JournalRecord> {
        self.transaction.borrow().records().get(self.applied.checked_sub(1)?)
    }

    /// Publishes native bookkeeping only after every record/index step succeeded.
    ///
    /// # Errors
    /// Refuses premature or repeated publication and changed original head DATA.
    ///
    /// # Panics
    /// Preserves the native transaction-count overflow panic if an upper caller
    /// omitted its existing count admission before this mechanical operation.
    pub fn publish_once(
        &mut self,
        native: &mut NativeJournal<RecordNamespace, JournalLimits>,
    ) -> Result<CanonicalAppendPublishedDataV1, CanonicalAppendClosedV1> {
        if !self.accepts_head(native) || !matches!(self.native, Some(Ok(_)))
            || self.applied != self.transaction.borrow().records().len()
            || self.publication.is_some()
        {
            return self.refuse();
        }
        let (Some(head), Some(Ok(coordinates)), Some(Ok(materialized)), Some(Ok(durable))) = (
            self.head, self.coordinates.as_ref(), self.projected.as_ref(), self.native.as_ref(),
        ) else {
            return self.refuse();
        };
        let transaction = self.transaction.borrow();
        native.publish_append(
            *materialized, coordinates.following, *transaction.id(),
            transaction.records().iter().map(JournalRecord::namespace),
        );
        let published = CanonicalAppendPublishedDataV1 {
            transaction: *transaction.id(), head, following: coordinates.following,
            durable_bytes: *durable, materialized_bytes: *materialized,
        };
        self.publication = Some(published);
        Ok(published)
    }

    /// Borrows the actual first reached stage error without moving any backing.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.immutable_admission)
            .or_else(|| failure(&self.projected))
            .or_else(|| failure(&self.frames))
            .or_else(|| failure(&self.coordinates))
            .or_else(|| failure(&self.expected))
            .or_else(|| failure(&self.native))
            .or_else(|| failure(&self.index))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }

    /// Reports actual native publication as DATA, without proving upper posts.
    pub const fn is_published(&self) -> bool {
        self.publication.is_some()
    }

    /// Copies actual publication DATA without manufacturing a role receipt.
    pub const fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> {
        self.publication
    }

    /// Moves the ordinary first error after explicitly disposing encoded frames.
    ///
    /// This consuming adapter is forbidden for a selected failed owner. That
    /// caller must retain the complete carrier through its own negative fence.
    pub fn into_ordinary_error(self) -> Option<CanonicalAppendErrorV1> {
        let Self {
            transaction, disposition: _, projection_original, encoder_original,
            expected_metadata, head: _, immutable_admission, projected, frames, coordinates, expected,
            native, index, applied: _, publication: _, closed,
        } = self;
        let (frame_bytes, encoder_error) = match frames {
            Some(Ok(frames)) => (Some(frames), None),
            Some(Err(cause)) => (None, Some(cause)),
            None => (None, None),
        };
        // The old ordinary frame vector is a local of the commit engine and
        // is destroyed before its propagated native/index error reaches upper.
        drop(frame_bytes);
        drop(encoder_original);
        drop(projection_original);
        drop(expected_metadata);
        drop(transaction);
        immutable_admission.and_then(Result::err).map(CanonicalAppendErrorV1::Record)
            .or_else(|| projected.and_then(Result::err).map(CanonicalAppendErrorV1::Frame))
            .or_else(|| encoder_error.map(CanonicalAppendErrorV1::Frame))
            .or_else(|| coordinates.and_then(Result::err).map(CanonicalAppendErrorV1::Frame))
            .or_else(|| expected.and_then(Result::err).map(CanonicalAppendErrorV1::Frame))
            .or_else(|| native.and_then(Result::err).map(CanonicalAppendErrorV1::Frame))
            .or_else(|| index.and_then(Result::err).map(CanonicalAppendErrorV1::Idempotency))
            .or_else(|| closed.map(CanonicalAppendErrorV1::Closed))
    }

    fn accepts_head(&self, native: &NativeJournal<RecordNamespace, JournalLimits>) -> bool {
        self.failure().is_none() && self.head == Some(native.next_sequence())
    }

    pub(crate) fn refuse<U>(&mut self) -> Result<U, CanonicalAppendClosedV1> {
        self.closed.get_or_insert(CanonicalAppendClosedV1);
        Err(CanonicalAppendClosedV1)
    }
}

fn failure<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs::{self, OpenOptions};
    use std::path::PathBuf;

    use aos_sandbox_core::OperationId;
    use aos_sandbox_journal::owner::NativeJournalState;
    use aos_sandbox_protocol::domain_ledger::transaction::IdempotencyKey;

    fn native(file: std::fs::File) -> NativeJournal<RecordNamespace, JournalLimits> {
        NativeJournal::from_owned_parts(
            PathBuf::new(), file, tempfile::tempfile().unwrap(), JournalLimits::default(),
            NativeJournalState::from_owned_parts(
                1, 0, BTreeSet::new(), BTreeSet::new(), BTreeMap::new(), 0,
            ),
        )
    }

    fn transaction() -> JournalTransaction {
        JournalTransaction::new([1; 16], vec![
            JournalRecord::idempotency(
                &IdempotencyKey::new(b"request".to_vec()).unwrap(), [2; 32],
                OperationId::from_bytes([3; 16]),
            ),
            JournalRecord::put(RecordNamespace::DesiredState, b"value".to_vec(), b"body".to_vec()),
        ]).unwrap()
    }

    #[test]
    fn immutable_observation_refuses_before_frames_for_both_append_dispositions() {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::CreateFinalityObservationAdmissionDataV1 as Admission;
        use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
        let mut request = b"AOSPMR01".to_vec();
        request.extend_from_slice(&26_u16.to_be_bytes());
        request.extend_from_slice(&2_u32.to_be_bytes());
        request.extend_from_slice(&[8, 1]);
        let operation = Admission::operation_id_v1(&Admission::key_from_original_v1([3; 16], [8; 32]));
        let row = Admission { operation, request_scope: [10; 32], target: [1; 16], node: [2; 16], holder: [3; 16], project: [4; 16], capability: [5; 16],
            channel: [6; 32], authorization_revision: [7; 32], idempotency_digest: [8; 32],
            original: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(), [9; 16], 100, 10_000_000_000,
            ).unwrap(), cutoff: 40_000_000_000, wall_expiry: 140, canonical_request: &request };
        let mut value = vec![0; row.encoded_bytes_v1().unwrap()];
        row.encode_into_v1(&mut value).unwrap();
        let record = JournalRecord::put(RecordNamespace::OperatorRecovery, row.key_v1().to_vec(), value);
        let mut native = native(tempfile::tempfile().unwrap());
        native.apply_mutation((&record).into());
        let transaction = JournalTransaction::new([11; 16], vec![record]).unwrap();

        let mut ordinary = CanonicalAppendStagesV1::new(&transaction);
        let mut retaining = CanonicalAppendStagesV1::new_retaining_v1(&transaction);
        for stages in [&mut ordinary, &mut retaining] {
            assert!(stages.project_once(&native).is_err());
            assert!(stages.frames.is_none());
            assert!(stages.failure().unwrap().downcast_ref::<
                aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>().is_some());
        }
        assert_eq!(native.next_sequence(), 1);
    }

    fn prepare<T: Borrow<JournalTransaction>>(
        stages: &mut CanonicalAppendStagesV1<T>,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
    ) {
        stages.project_once(native).unwrap();
        stages.encode_once(native).unwrap();
        stages.coordinates_once().unwrap();
        stages.expected_length_once(native).unwrap();
    }

    #[test]
    fn borrowed_transaction_applies_native_then_index_before_next_record_and_publish() {
        let mut native = native(tempfile::tempfile().unwrap());
        let transaction = transaction();
        let mut index = BTreeMap::new();
        let mut stages = CanonicalAppendStagesV1::new(&transaction);
        prepare(&mut stages, &native);
        let expected_bytes = stages.encoded_frames().unwrap().concat();

        stages.append_once(&mut native).unwrap();
        assert!(std::ptr::eq(stages.transaction(), &transaction));
        assert!(native.state().is_empty());
        assert!(index.is_empty());
        assert_eq!(native.next_sequence(), 1);

        assert!(stages.apply_next_record_once(&mut native, &mut index).unwrap());
        assert_eq!(native.state().len(), 1);
        assert_eq!(index.len(), 1);
        assert_eq!(stages.last_applied_record(), transaction.records().first());
        assert_eq!(native.next_sequence(), 1);
        assert!(stages.apply_next_record_once(&mut native, &mut index).unwrap());
        assert_eq!(native.state().len(), 2);
        assert!(!stages.apply_next_record_once(&mut native, &mut index).unwrap());

        let published = stages.publish_once(&mut native).unwrap();
        assert_eq!(published.transaction, *transaction.id());
        assert_eq!(published.head, 1);
        assert_eq!(published.following, 5);
        assert_eq!(native.next_sequence(), 5);
        assert_eq!(native.committed_transactions(), 1);
        assert!(stages.is_published());
        assert_eq!(stages.published_coordinates(), Some(published));
        let mut observed_bytes = vec![0; expected_bytes.len()];
        {
            use std::os::unix::fs::FileExt as _;
            native.file().read_exact_at(&mut observed_bytes, 0).unwrap();
        }
        assert_eq!(observed_bytes, expected_bytes);
    }

    #[test]
    fn real_append_failure_retains_original_frames_and_native_cause_across_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("readonly");
        fs::write(&path, []).unwrap();
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        let mut native = native(file);
        let transaction = transaction();
        let records = transaction.records().as_ptr();
        let mut stages = CanonicalAppendStagesV1::new_retaining_v1(transaction);
        prepare(&mut stages, &native);
        let frames = stages.frames.as_ref().unwrap().as_ref().unwrap().as_ptr();

        assert!(stages.append_once(&mut native).is_err());
        assert!(native.is_poisoned());
        let cause = stages.failure().unwrap() as *const _;
        assert!(stages.failure().unwrap().downcast_ref::<FrameError>().is_some());
        assert!(stages.append_once(&mut native).is_err());
        assert_eq!(stages.failure().unwrap() as *const _, cause);
        assert_eq!(stages.frames.as_ref().unwrap().as_ref().unwrap().as_ptr(), frames);
        assert_eq!(stages.transaction().records().as_ptr(), records);
        assert!(!stages.is_published());
        assert_eq!(native.next_sequence(), 1);
        assert!(matches!(stages.into_ordinary_error(), Some(CanonicalAppendErrorV1::Frame(
            FrameError::Io(_),
        ))));
    }

    #[test]
    fn premature_publish_is_sticky_and_cannot_rearm_or_append() {
        let mut native = native(tempfile::tempfile().unwrap());
        let transaction = transaction();
        let mut stages = CanonicalAppendStagesV1::new(&transaction);
        prepare(&mut stages, &native);
        let frames = stages.frames.as_ref().unwrap().as_ref().unwrap().as_ptr();

        assert!(stages.publish_once(&mut native).is_err());
        assert!(stages.append_once(&mut native).is_err());
        assert!(stages.project_once(&native).is_err());
        assert_eq!(native.file().metadata().unwrap().len(), 0);
        assert_eq!(stages.frames.as_ref().unwrap().as_ref().unwrap().as_ptr(), frames);
        assert!(!stages.is_published());
    }

    #[test]
    fn failed_current_index_step_keeps_partial_native_state_unpublished_and_stage_closed() {
        let mut native = native(tempfile::tempfile().unwrap());
        let transaction = JournalTransaction::from_unvalidated_data([1; 16], vec![
            JournalRecord::put(RecordNamespace::Idempotency, b"request".to_vec(), vec![9]),
        ]);
        let mut stages = CanonicalAppendStagesV1::new(transaction);
        let mut index = BTreeMap::new();
        prepare(&mut stages, &native);
        stages.append_once(&mut native).unwrap();

        assert!(stages.apply_next_record_once(&mut native, &mut index).is_err());
        assert_eq!(native.state().len(), 1);
        assert!(index.is_empty());
        assert!(!native.is_poisoned());
        assert_eq!(native.next_sequence(), 1);
        let cause = stages.failure().unwrap() as *const _;
        assert!(stages.apply_next_record_once(&mut native, &mut index).is_err());
        assert_eq!(stages.failure().unwrap() as *const _, cause);
        assert!(stages.publish_once(&mut native).is_err());
        assert!(!stages.is_published());
    }

    #[test]
    fn retained_stage_keeps_the_actual_lower_encoder_prefix_on_sequence_failure() {
        let native = NativeJournal::from_owned_parts(
            PathBuf::new(), tempfile::tempfile().unwrap(), tempfile::tempfile().unwrap(),
            JournalLimits::default(), NativeJournalState::from_owned_parts(
                u64::MAX - 1, 0, BTreeSet::new(), BTreeSet::new(), BTreeMap::new(), 0,
            ),
        );
        let transaction = transaction();
        let mut stages = CanonicalAppendStagesV1::new_retaining_v1(transaction);
        stages.project_once(&native).unwrap();

        assert!(stages.encode_once(&native).is_err());
        assert_eq!(stages.retained_encoded_frames().unwrap().len(), 2);
        assert!(stages.retained_encoder_payload().is_some());
        let prefix = stages.retained_encoded_frames().unwrap().as_ptr();
        let cause = stages.failure().unwrap() as *const _;
        assert!(stages.encode_once(&native).is_err());
        assert_eq!(stages.failure().unwrap() as *const _, cause);
        assert_eq!(stages.retained_encoded_frames().unwrap().as_ptr(), prefix);
        assert_eq!(native.file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn retained_expected_length_keeps_successful_metadata_before_bound_refusal() {
        let mut limits = JournalLimits::default();
        limits.maximum_journal_bytes = 0;
        let mut native = NativeJournal::from_owned_parts(
            PathBuf::new(), tempfile::tempfile().unwrap(), tempfile::tempfile().unwrap(),
            limits, NativeJournalState::from_owned_parts(
                1, 0, BTreeSet::new(), BTreeSet::new(), BTreeMap::new(), 0,
            ),
        );
        let transaction = transaction();
        let mut stages = CanonicalAppendStagesV1::new_retaining_v1(transaction);
        stages.project_once(&native).unwrap();
        stages.encode_once(&native).unwrap();
        stages.coordinates_once().unwrap();

        assert!(stages.expected_length_once(&native).is_err());
        assert!(matches!(stages.failure().unwrap().downcast_ref::<FrameError>(),
            Some(FrameError::JournalTooLarge)));
        assert_eq!(stages.retained_expected_metadata().unwrap().len(), 0);
        assert!(stages.append_once(&mut native).is_err());
        assert_eq!(native.file().metadata().unwrap().len(), 0);
    }

}
