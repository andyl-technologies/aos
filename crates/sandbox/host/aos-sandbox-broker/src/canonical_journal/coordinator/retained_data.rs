//! Retains owned mechanical append DATA without issuing a writer or role.
//!
//! Fixed recipients pay before constructing this sink and retain their own
//! native owner and semantic gates. Unfinished stages use the same permanent
//! storage as selected C/R/Source append stages; no append algorithm is added.

use std::error::Error;
use std::sync::Arc;
use super::selected_append::{SelectedAppendCustodyV1, SelectedAppendGuardV1};
use crate::canonical_journal::append_stages::CanonicalAppendStagesV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

type Body = CanonicalAppendStagesV1<JournalTransaction>;

/// Owns a sticky mechanical append sink, without native fields or authority.
pub struct RetainedAppendDataCustodyV1 {
    original: Arc<SelectedAppendCustodyV1<Body>>,
}

impl RetainedAppendDataCustodyV1 {
    /// Constructs inert storage; the caller separately pays and gates entry.
    #[must_use]
    pub fn new() -> Self { Self { original: Arc::new(SelectedAppendCustodyV1::new()) } }

    /// Reports whether failed actual work has permanently closed this sink.
    #[must_use]
    pub fn is_closed(&self) -> bool { self.original.is_closed() }

    /// Reports only empty, inactive and unfailed mechanical storage.
    ///
    /// A role's actual positive interval decides whether its sink may retire;
    /// this passive status cannot construct a writer or grant append entry.
    #[must_use]
    pub fn is_idle_v1(&self) -> bool { self.original.is_idle() }

    /// Borrows the actual parked append cause after returned diagnostics drop.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.parked_body().and_then(Body::failure)
    }

    #[cfg(test)]
    pub(crate) fn parked_data_for_test(&self) -> Option<&Body> {
        self.original.parked_body()
    }

    /// Copies a transaction only after its fixed recipient has paid its bound.
    ///
    /// # Errors
    /// Refuses active or closed storage; it never resets an earlier failure.
    pub fn prepare_owned_once(&self, transaction: &JournalTransaction)
        -> Result<RetainedAppendDataStageV1, crate::canonical_journal::append_stages::CanonicalAppendClosedV1>
    {
        if !self.original.enter() { return Err(crate::canonical_journal::append_stages::CanonicalAppendClosedV1); }
        Ok(RetainedAppendDataStageV1 { guard: SelectedAppendGuardV1::new(
            Arc::clone(&self.original), Body::new_retaining_v1(transaction.clone())) })
    }

    /// Prices the actual sink allocation before a fixed native opening.
    #[must_use]
    pub fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<SelectedAppendCustodyV1<Body>>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Self>()))
    }

    /// Bounds owned transaction, frame and encoder backing from encoded widths.
    ///
    /// This conservative byte bound allocates nothing. Every record consumes
    /// at least one encoded byte; counting one full record/vector carrier per
    /// byte therefore also bounds all child allocation headers.
    #[must_use]
    pub fn append_bytes_v1(encoded_bytes: u64) -> Option<u64> {
        let per_byte = 8usize.checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>())?
            .checked_add(std::mem::size_of::<Vec<u8>>())?;
        encoded_bytes.checked_mul(u64::try_from(per_byte).ok()?)?
            .checked_add(u64::try_from(3 * std::mem::size_of::<RetainedAppendDataStageV1>()
                + 3 * std::mem::size_of::<Body>()).ok()?)
    }
}

impl Default for RetainedAppendDataCustodyV1 { fn default() -> Self { Self::new() } }

/// Holds the actual owned canonical stage until checked positive disposal.
pub struct RetainedAppendDataStageV1 { guard: SelectedAppendGuardV1<Body> }

impl RetainedAppendDataStageV1 {
    /// Borrows mechanical transaction/encoder DATA, never a native writer.
    #[must_use]
    pub fn data(&self) -> Option<&Body> { self.guard.body() }

    /// Borrows the same mutable mechanical DATA without granting native entry.
    #[must_use]
    pub fn data_mut(&mut self) -> Option<&mut Body> { self.guard.body_mut() }

    /// Parks this actual failed stage before exposing its owning diagnostic.
    #[must_use]
    pub fn into_failure_original(mut self) -> RetainedAppendDataFailureV1 {
        self.guard.park_unfinished();
        RetainedAppendDataFailureV1 { original: Arc::clone(self.guard.custody()) }
    }

    /// Disposes completed scratch after the caller's independent native posts.
    ///
    /// # Errors
    /// Refuses incomplete or failed canonical publication; no reset occurs.
    pub fn dispose_published_once(&mut self)
        -> Result<(), crate::canonical_journal::append_stages::CanonicalAppendClosedV1>
    {
        if !self.guard.body().is_some_and(|body| body.is_published() && body.failure().is_none()) {
            return Err(crate::canonical_journal::append_stages::CanonicalAppendClosedV1);
        }
        drop(self.guard.take_body());
        self.guard.custody().release_active();
        Ok(())
    }
}

/// Keeps the same failed mechanical body resident behind returned diagnostics.
pub struct RetainedAppendDataFailureV1 { original: Arc<SelectedAppendCustodyV1<Body>> }

impl std::fmt::Debug for RetainedAppendDataFailureV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedAppendDataFailureV1").field("failure", &self.source()).finish_non_exhaustive()
    }
}
impl std::fmt::Display for RetainedAppendDataFailureV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.source() { Some(cause) => std::fmt::Display::fmt(cause, f), None => f.write_str("retained append is closed") }
    }
}
impl Error for RetainedAppendDataFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> { self.original.parked_body().and_then(Body::failure) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_journal::owner::{NativeJournal, NativeJournalState};
    use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord};

    fn native(file: std::fs::File, head: u64) -> NativeJournal<RecordNamespace, JournalLimits> {
        NativeJournal::from_owned_parts(std::path::PathBuf::new(), file,
            tempfile::tempfile().unwrap(), JournalLimits::default(),
            NativeJournalState::from_owned_parts(head, 0, BTreeSet::new(),
                BTreeSet::new(), BTreeMap::new(), 0))
    }

    fn transaction() -> JournalTransaction {
        JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, b"key".to_vec(), b"value".to_vec())]).unwrap()
    }

    #[test]
    fn failed_encoder_parks_the_same_reached_prefix_after_diagnostic_drop() {
        let native = native(tempfile::tempfile().unwrap(), u64::MAX - 1);
        let custody = RetainedAppendDataCustodyV1::new();
        let mut stage = custody.prepare_owned_once(&transaction()).unwrap();
        let data = stage.data_mut().unwrap();
        data.project_once(&native).unwrap();
        assert!(data.encode_once(&native).is_err());
        let prefix = data.retained_encoded_frames().unwrap().as_ptr();
        let count = data.retained_encoded_frames().unwrap().len();
        assert!(count > 0);
        let cause_text = data.failure().unwrap().to_string();

        let diagnostic = stage.into_failure_original();
        assert_eq!(diagnostic.source().unwrap().to_string(), cause_text);
        let permanent_cause = diagnostic.source().unwrap() as *const dyn Error;
        drop(diagnostic);

        let parked = custody.original.parked_body().unwrap();
        assert_eq!(parked.retained_encoded_frames().unwrap().as_ptr(), prefix);
        assert_eq!(parked.retained_encoded_frames().unwrap().len(), count);
        assert_eq!(custody.failure().unwrap() as *const dyn Error, permanent_cause);
        assert!(custody.prepare_owned_once(&transaction()).is_err());
        assert_eq!(native.file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn real_append_failure_retains_native_cause_and_frames_in_same_sink() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("readonly");
        std::fs::write(&path, []).unwrap();
        let file = std::fs::OpenOptions::new().read(true).open(path).unwrap();
        let mut native = native(file, 1);
        let custody = RetainedAppendDataCustodyV1::new();
        let mut stage = custody.prepare_owned_once(&transaction()).unwrap();
        let data = stage.data_mut().unwrap();
        data.project_once(&native).unwrap();
        data.encode_once(&native).unwrap();
        data.coordinates_once().unwrap();
        data.expected_length_once(&native).unwrap();
        let frames = data.encoded_frames().unwrap().as_ptr();
        let frame_backings: Vec<_> = data.encoded_frames().unwrap().iter()
            .map(|frame| (frame.as_ptr(), frame.len())).collect();

        assert!(data.append_once(&mut native).is_err());
        let cause_text = data.failure().unwrap().to_string();
        assert!(native.is_poisoned());
        assert!(stage.dispose_published_once().is_err());
        let diagnostic = stage.into_failure_original();
        assert_eq!(diagnostic.source().unwrap().to_string(), cause_text);
        let permanent_cause = diagnostic.source().unwrap() as *const dyn Error;
        let parked = custody.original.parked_body().unwrap();
        assert!(matches!(parked.failure().unwrap().downcast_ref::<aos_sandbox_journal::framing::FrameError>(),
            Some(aos_sandbox_journal::framing::FrameError::Io(_))));
        drop(diagnostic);

        // The healthy preflight view closes on error; diagnostic DATA remains
        // the same actual frame vector and child allocations after parking.
        let retained = parked.retained_encoded_frames().unwrap();
        assert_eq!(retained.as_ptr(), frames);
        assert_eq!(retained.iter().map(|frame| (frame.as_ptr(), frame.len())).collect::<Vec<_>>(), frame_backings);
        assert_eq!(custody.failure().unwrap() as *const dyn Error, permanent_cause);
        assert!(custody.prepare_owned_once(&transaction()).is_err());
    }

    #[test]
    fn only_published_positive_disposal_releases_the_same_active_sink() {
        let mut native = native(tempfile::tempfile().unwrap(), 1);
        let custody = RetainedAppendDataCustodyV1::new();
        let transaction = transaction();
        let mut stage = custody.prepare_owned_once(&transaction).unwrap();
        assert!(custody.prepare_owned_once(&transaction).is_err());
        assert!(stage.dispose_published_once().is_err());
        let data = stage.data_mut().unwrap();
        data.project_once(&native).unwrap();
        data.encode_once(&native).unwrap();
        data.coordinates_once().unwrap();
        data.expected_length_once(&native).unwrap();
        data.append_once(&mut native).unwrap();
        let mut index = BTreeMap::new();
        while data.apply_next_record_once(&mut native, &mut index).unwrap() {}
        data.publish_once(&mut native).unwrap();

        stage.dispose_published_once().unwrap();
        drop(stage);

        assert!(custody.original.is_idle());
        assert!(custody.original.parked_body().is_none());
        assert!(!custody.is_closed());
    }
}
