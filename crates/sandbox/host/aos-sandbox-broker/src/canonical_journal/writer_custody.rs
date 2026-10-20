//! Keeps one actual native writer, resident index and protected location together.
//!
//! This mechanical carrier moves the original native, index and location in
//! that destruction order. It admits no role, supplies no budget and certifies
//! neither the supplied index nor the uninterpreted compaction selection. Closed
//! C/R owners retain genuine originals, semantic gates, financial debt, healthy
//! entry checks, owed observations and every unfinished append destination.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::Metadata;
use std::io;
use std::sync::Arc;

use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::protected_storage::{
    ProtectedFailure, ProtectedJournalLocation, ProtectedWriterNameWitness, WriterWitnessOriginalsV1,
};
use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;
use aos_sandbox_protocol::domain_ledger::readonly::{
    HistoricalLedgerReadViewV1, IdempotencyDecisionV1,
};
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read::
    HistoricalRuntimeLedgerReadV1;

use super::{CanonicalNativeJournalV1, CanonicalOpenedWriterDataV1, RecoveryReport};
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Retains actual writable native DATA beside its same supplied index/location.
///
/// Construction consumes the existing completed acquisition carrier. It does
/// not authenticate the index, grant an effect or adopt a protected role. No
/// public native journal, raw file, descriptor or writable projection escapes.
/// Crate-private fields let the closed owners invoke the existing canonical
/// stages while retaining their distinct role and financial machinery.
pub struct CanonicalWriterCustodyDataV1<P> {
    pub(crate) native: CanonicalNativeJournalV1,
    pub(crate) index: Index,
    pub(crate) location: Arc<ProtectedJournalLocation<P>>,
    pub(crate) replacement_custody: Arc<super::coordinator::selected_append::SelectedAppendCustodyV1<
        super::coordinator::replacement::SelectedReplacementBodyV1<P>,
    >>,
}

impl<P> CanonicalWriterCustodyDataV1<P> {
    /// Moves the existing completed acquisition and resident index without cloning.
    ///
    /// The supplied compaction selection remains uninterpreted DATA. The returned
    /// report is the actual acquisition report; it grants no successful replay,
    /// currentness, role permission or financial admission.
    #[must_use]
    pub fn from_opened_data_v1(
        opened: CanonicalOpenedWriterDataV1,
        index: Index,
        compaction_selection: P,
    ) -> (Self, RecoveryReport) {
        let (native, location, report) = opened.into_native_parts(compaction_selection);
        (
            Self {
                native, index, location: Arc::new(location),
                replacement_custody: Arc::new(super::coordinator::selected_append::SelectedAppendCustodyV1::new()),
            },
            report,
        )
    }

    /// Bounds this constructor's fixed inline carriers without pricing dynamic owners.
    ///
    /// Existing native maps, index nodes, paths and opaque compaction backing move
    /// unchanged and require their actual supplier before growth. The closed role
    /// must add its own identity, original, budget, sink and borrowed-scope fields.
    /// Returns `None` on representation arithmetic overflow.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<CanonicalOpenedWriterDataV1>())?
            .checked_add(std::mem::size_of::<Index>())?
            .checked_add(std::mem::size_of::<P>())?
            .checked_add(std::mem::size_of::<(Self, RecoveryReport)>())?
            // The actual directory/selection now has one owned allocation so
            // unfinished compaction cleanup can retain SAME physical custody.
            .checked_add(std::mem::size_of::<ProtectedJournalLocation<P>>().checked_mul(2)?)?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<ProtectedJournalLocation<P>>())?
            .checked_add(std::mem::size_of::<super::coordinator::selected_append::SelectedAppendCustodyV1<
                super::coordinator::replacement::SelectedReplacementBodyV1<P>,
            >>())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<super::coordinator::selected_append::SelectedAppendCustodyV1<
                super::coordinator::replacement::SelectedReplacementBodyV1<P>,
            >>())
    }

    /// Adds no resident namespace entry for this representation-only move.
    ///
    /// Actual path and resident index entries have their own suppliers. All
    /// constructor, allocation and control representations are paid as bytes.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        0
    }

    /// Borrows historical DATA directly from the actual native and resident index.
    #[must_use]
    pub fn historical_view(&self) -> HistoricalLedgerReadViewV1<'_> {
        HistoricalLedgerReadViewV1::new(self.native.native(), &self.index)
    }

    /// Borrows Runtime history with this same actual protected-location object.
    #[must_use]
    pub fn runtime_history(&self) -> HistoricalRuntimeLedgerReadV1<'_, ProtectedJournalLocation<P>> {
        HistoricalRuntimeLedgerReadV1::new(self.historical_view(), Some(&self.location))
    }

    /// Returns the actual native configuration as comparison DATA.
    #[must_use]
    pub const fn limits(&self) -> JournalLimits {
        self.native.native().limits()
    }

    /// Returns the actual native next sequence as comparison DATA.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.native.native().next_sequence()
    }

    /// Observes the same actual data file at the caller's original metadata frontier.
    ///
    /// # Errors
    /// Returns the original file metadata error without adding a health gate.
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.native.native().file().metadata()
    }

    /// Lends a bounded read cursor over the same held file without opening another.
    ///
    /// A supplied length is DATA. The caller retains its original funding,
    /// identity, replay and full-prefix comparison obligations.
    #[must_use]
    pub fn captured_reader(&self, length: u64) -> ReadOnlyCapturedFileCursorV1<'_> {
        ReadOnlyCapturedFileCursorV1::new(self.native.native().file(), length)
    }

    /// Borrows the same opaque compaction selection without interpreting it.
    #[must_use]
    pub fn compaction_selection(&self) -> &P {
        self.location.original_compaction_selection()
    }

    /// Observes the original names through the existing retained sampler.
    ///
    /// The role owns one-shot entry, health and funding checks before this call,
    /// and parks the returned result before its next frontier. Already-entered
    /// owed observations use these same held files after native poison; this
    /// method supplies no fresh-entry bypass or positive completion/disposal.
    ///
    /// # Errors
    /// Preserves the sampler's actual partials and original name refusal.
    pub fn observe_names_into<E>(
        &self,
        originals: &mut WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where
        E: ProtectedFailure + From<FrameError> + Error + 'static,
    {
        originals.observe_names(
            &self.location,
            self.location.name(),
            self.location.expected_uid(),
            self.native.native().lock_file(),
            self.native.native().file(),
        )
    }

    /// Samples the original directory, data file and lock witness in that order.
    ///
    /// The role reaches this dependent witness only after its original name
    /// comparison succeeds and retains the whole result through later posts.
    ///
    /// # Errors
    /// Returns the first original witness metadata error.
    pub fn writer_witness<E: ProtectedFailure>(&self) -> Result<ProtectedWriterNameWitness, E> {
        self.location.writer_witness(
            self.native.native().file(), self.native.native().lock_file(),
        )
    }

    /// Compares a retained witness with the same actual native/location objects.
    ///
    /// # Errors
    /// Preserves the original metadata failure or stale-witness refusal.
    pub fn require_writer_witness<E: ProtectedFailure>(
        &self,
        witness: &ProtectedWriterNameWitness,
    ) -> Result<(), E> {
        self.location.require_writer_witness(
            self.native.native().file(), self.native.native().lock_file(), witness,
        )
    }

    /// Retains every reached metadata sample from the same actual writer witness.
    ///
    /// The genuine role prepays and embeds `originals` before this frontier and
    /// retains it through all later independent posts. No entry/health/purpose
    /// success or positive retirement is supplied by this mechanical adapter.
    ///
    /// # Errors
    /// Leaves original Metadata/identity/top results resident on native refusal
    /// or reentry. The detailed first native cause remains in `originals`.
    pub fn writer_witness_retaining_v1<E: ProtectedFailure>(
        &self,
        originals: &mut WriterWitnessOriginalsV1<E>,
    ) -> Result<(), E> {
        self.location.writer_witness_retaining_v1(
            self.native.native().file(), self.native.native().lock_file(), originals,
        )
    }

    /// Retains the original lazy comparison with the same held writer witness.
    ///
    /// Uses a distinct owner from the original witness sample. The role retains
    /// its whole entered interval and alone decides positive metadata retirement.
    ///
    /// # Errors
    /// Preserves every reached original Metadata/identity and top comparison
    /// refusal. Later metadata is not sampled after an earlier lazy mismatch.
    pub fn require_writer_witness_retaining_v1<E: ProtectedFailure>(
        &self,
        witness: &ProtectedWriterNameWitness,
        originals: &mut WriterWitnessOriginalsV1<E>,
    ) -> Result<(), E> {
        self.location.require_writer_witness_retaining_v1(
            self.native.native().file(), self.native.native().lock_file(), witness, originals,
        )
    }
}

impl<P> CanonicalWriterCustodyDataV1<P> {
    pub(crate) fn prepare_replacement_once(&mut self)
        -> Result<super::coordinator::replacement::CanonicalSelectedReplacementV1<P>,
            super::coordinator::replacement::CanonicalReplacementErrorV1>
    {
        use super::coordinator::replacement::{CanonicalReplacementErrorV1, CanonicalSelectedReplacementV1};
        let mut replacement = CanonicalSelectedReplacementV1::new(
            Arc::clone(&self.replacement_custody), self.native.native().limits(),
        ).ok_or(CanonicalReplacementErrorV1::Closed)?;
        if let Some(body) = replacement.body_mut() {
            // Return the whole failed stage, retaining its exact original cause.
            let _prepared = body.prepare_once(&self.location, self.native.native().state());
        }
        Ok(replacement)
    }

    pub(crate) fn install_replacement_once(
        &mut self,
        replacement: &mut super::coordinator::replacement::CanonicalSelectedReplacementV1<P>,
    ) -> Result<(), super::coordinator::replacement::CanonicalReplacementErrorV1> {
        use super::coordinator::replacement::CanonicalReplacementErrorV1;
        if !replacement.has_custody(&self.replacement_custody) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        replacement.body_mut().ok_or(CanonicalReplacementErrorV1::Closed)?
            .install_once(self.native.native_mut(), &mut self.index)
    }

    pub(crate) fn finish_replacement_after_posts_once(
        &mut self,
        replacement: &mut super::coordinator::replacement::CanonicalSelectedReplacementV1<P>,
    ) -> Result<(), super::coordinator::replacement::CanonicalReplacementErrorV1> {
        use super::coordinator::replacement::CanonicalReplacementErrorV1;
        if !replacement.has_custody(&self.replacement_custody) {
            return Err(CanonicalReplacementErrorV1::Closed);
        }
        replacement.release_positive()
    }
}

impl<P> Drop for CanonicalWriterCustodyDataV1<P> {
    fn drop(&mut self) {
        if !self.replacement_custody.is_idle() {
            // A selected replacement's files, actual index and cleanup debt
            // remain resident until real posts settle. Abort BEFORE native,
            // index or location fields can release any of that uncertainty.
            std::process::abort();
        }
    }
}
