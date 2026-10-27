//! Holds the trusted Controller semantic coordinator's sole native stage port.
//!
//! The genuine paired fixed opening alone constructs this owner. Domain must
//! still execute its sole semantic, fence and final-crossing engine in order.
//! Native stages certify none of those semantics. Cache/Publisher/Runtime role
//! borrowers receive separate closed loans and never this coordinator port.

use std::fs::Metadata;
use std::io;

use crate::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read::HistoricalRuntimeLedgerReadV1;

use crate::canonical_journal::{
    CanonicalWriterCustodyDataV1, append_stages::CanonicalAppendPublishedDataV1,
};

use super::append::ControllerPreparedAppendV1;
use super::writer::ControllerFixedWriterOriginalV1;
use super::ControllerBankLaunchErrorV1;

/// Owns the actual C fixed writer at the explicit trusted coordinator boundary.
///
/// It accepts no native journal, File, descriptor, decoded bank, account,
/// successful result or resource vector. Construction stays private to the
/// fixed paired startup. The port lends no raw native or mutable location.
pub struct ControllerCoordinatorWriterV1<P> {
    pub(crate) fixed: ControllerFixedWriterOriginalV1<P>,
}

impl<P> ControllerCoordinatorWriterV1<P> {
    pub(super) fn from_fixed_opening(fixed: ControllerFixedWriterOriginalV1<P>) -> Self {
        Self { fixed }
    }

    // The sealed coordinator facade may derive read-only mechanical views.
    // No mutable physical prefix can escape or be replaced with caller DATA.
    pub(crate) fn physical_data(&self) -> &CanonicalWriterCustodyDataV1<P> {
        &self.fixed.physical
    }

    /// Reports any actual native, parked-stage or active-stage closure.
    ///
    /// This negative health DATA cannot reopen the original or prove a role.
    /// Already-owed native posts use their separately prearmed route instead.
    #[must_use]
    pub fn is_closed_or_poisoned_v1(&self) -> bool {
        self.fixed.require_healthy().is_err()
    }

    /// Reports native ambiguity or permanent closure without rejecting a healthy active stage.
    ///
    /// The trusted semantic engine may run its existing gates between native
    /// preparation and append. Fresh loans still use the stricter idle check.
    #[must_use]
    pub fn has_native_uncertainty_v1(&self) -> bool {
        self.fixed.fenced || self.fixed.physical.native.native().is_poisoned()
            || self.fixed.append_custody.is_closed()
            || self.fixed.physical.replacement_custody.is_closed()
    }

    /// Borrows the permanently retained first append or representation cause.
    #[must_use]
    pub fn retained_append_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.retained_append_failure()
    }

    /// Requires this writer's actual same paired C association.
    ///
    /// # Errors
    /// Refuses a foreign original; this cannot adopt or mint a writer.
    pub fn require_same_original_v1(
        &self,
        original: &std::sync::Arc<crate::controller_receiving::ControllerReceivingOriginalV1>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.fixed.has_original(original) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }


    /// Borrows historical record/index DATA from the SAME actual native owner.
    #[must_use]
    pub fn historical_view(&self) -> HistoricalLedgerReadViewV1<'_> {
        self.fixed.historical_view()
    }

    /// Borrows the existing Runtime historical engine and SAME location object.
    #[must_use]
    pub fn runtime_history(&self) -> HistoricalRuntimeLedgerReadV1<'_, aos_sandbox_journal::protected_storage::ProtectedJournalLocation<P>> {
        self.fixed.runtime_history()
    }

    /// Returns the actual native next sequence as passive comparison DATA.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.fixed.next_sequence()
    }

    /// Returns the existing native limits without creating a grant.
    #[must_use]
    pub const fn limits(&self) -> JournalLimits {
        self.fixed.limits()
    }

    /// Samples the original file at the upper engine's metadata frontier.
    ///
    /// # Errors
    /// Returns the original metadata IO error; this is not a currentness proof.
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.fixed.metadata()
    }

    /// Returns the actual retained durable cut solely as sizing DATA.
    ///
    /// This performs no metadata IO and establishes no currentness, replay or
    /// read permission. The actual closed borrower prepays before sampling and
    /// compares native metadata/readback against this same retained extent.
    #[must_use]
    pub const fn durable_prefix_end_data_v1(&self) -> u64 {
        self.fixed.durable_prefix_end_data_v1()
    }

    /// Lends the SAME bounded positional reader without File or FD access.
    #[must_use]
    pub fn captured_reader(&self, length: u64) -> CanonicalCoordinatorReadCursorV1<'_> {
        self.fixed.captured_reader(length)
    }

    /// Prepays the complete append interval before its native post is armed.
    ///
    /// The trusted upper coordinator supplies only its compiled capsule byte
    /// representation. The same C ledger covers it, the actual native post and
    /// the closed append recipe before any clone, encoder growth or post sample.
    /// This DATA-only debit issues no stage, role, account or semantic success.
    ///
    /// # Errors
    /// Retains the first geometry or capacity refusal on the original writer
    /// and permanently fences fresh reuse without entering a native stage.
    #[doc(hidden)]
    pub fn prepay_append_interval_once(
        &mut self,
        transaction: &JournalTransaction,
        upper_interval_bytes: usize,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.fixed.require_healthy()?;
        if self.fixed.append_debit_failure.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }

        let result = self.fixed.require_append_interval_representation(
            transaction, upper_interval_bytes,
        );
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.fixed.append_debit_failure = Some(cause);
                self.fixed.fence();
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    /// Prepares this trusted coordinator's actual transaction under SAME C.
    ///
    /// The actual private complete representation demand is checked before the
    /// retained copy and shared encoder grow. This certifies no semantic gate.
    ///
    /// # Errors
    /// Retains accounting and reached projection/encoder refusal in the same
    /// writer or returned stage. Failure/abandonment permanently closes reuse.
    pub fn prepare_controller_append_once(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<ControllerPreparedAppendV1, ControllerBankLaunchErrorV1> {
        self.fixed.prepare_coordinator_append(transaction)
    }

    /// Checks the actual encoded frame arithmetic BEFORE expected-length IO.
    ///
    /// # Errors
    /// Retains the shared stage's actual arithmetic or ordering refusal.
    pub fn controller_append_coordinates_once(
        &self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<(u64, u64), ControllerBankLaunchErrorV1> {
        self.fixed.coordinator_coordinates(stage)
    }

    /// Performs the SAME expected-length metadata step at its old frontier.
    ///
    /// # Errors
    /// Retains native metadata/bounds failure and rejects a foreign stage.
    pub fn expected_controller_append_length_once(
        &self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<u64, ControllerBankLaunchErrorV1> {
        self.fixed.expected_coordinator_length(stage)
    }

    /// Executes exact native append after the actual upper final crossings.
    ///
    /// The genuine holder is trusted to sequence those crossings. This
    /// mechanical call cannot enforce or replace Domain's semantic checks.
    ///
    /// # Errors
    /// Retains write/flush/sync/length failure and the whole encoded prefix.
    pub fn append_controller_prepared_once(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<u64, ControllerBankLaunchErrorV1> {
        self.fixed.append_coordinator_prepared(stage)
    }

    /// Applies the next actual native record and its index before advancing.
    ///
    /// # Errors
    /// Retains the shared native/index failure and poisons the selected writer.
    pub fn apply_next_controller_record_once(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<bool, ControllerBankLaunchErrorV1> {
        self.fixed.apply_next_coordinator_record(stage)
    }

    /// Applies ONE actual record then its SAME index step before the next.
    ///
    /// # Errors
    /// Retains actual native/index failure or a different expected record;
    /// selected uncertainty permanently poisons this original writer.
    pub fn apply_controller_record_once(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
        record: &JournalRecord,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.fixed.apply_coordinator_record(stage, record)
    }

    /// Publishes only the SAME actually appended/applied native stage.
    ///
    /// Its private Bank receipt is made inside this exact native publication,
    /// never from caller CommitResult, receipt DATA or a success Boolean.
    ///
    /// # Errors
    /// Refuses unfinished or foreign stages and preserves their actual cause.
    pub fn publish_controller_append_once(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<CanonicalAppendPublishedDataV1, ControllerBankLaunchErrorV1> {
        self.fixed.publish_coordinator_append(stage)
    }

    /// Disposes a complete native stage at the actual upper positive return cut.
    ///
    /// The trusted coordinator calls this AFTER its real final semantic posts,
    /// including cache successor ownership. No call accepts completion DATA.
    /// Native/index prefix and financial debt remain in this actual original.
    ///
    /// # Errors
    /// Refuses foreign, failed, unpublished or already disposed stages.
    pub fn finish_controller_append_after_posts_once(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.fixed.dispose_coordinator_append(stage)
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Advances the same actual startup only after native Bank publication.
    ///
    /// The trusted upper coordinator retains its sole typed mutation/semantic
    /// gate. This independently requires this writer's actual publication,
    /// transaction membership and the exact bank identity; no supplied receipt
    /// or success flag can enter this continuation.
    ///
    /// # Errors
    /// Refuses absent actual publication, foreign identity, failed native state
    /// or unpaid/unretired original construction posts.
    pub fn finish_bank_startup_disposition_once_v1(&self)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.fixed.require_healthy()?;
        let receipt = self.fixed.last_receipt.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let original = self.fixed.original().writer_enrollment()?;
        if !std::sync::Arc::ptr_eq(&receipt.identity, self.fixed.identity())
            || !self.fixed.contains_bank_transaction_v1(&receipt.transaction)?
            || aos_sandbox_protocol::domain_ledger::resource_bank::validate(self.fixed.bank_state_v1()?)?
                != Some(original.identity)
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        Ok(self.fixed.original().enrolled_startup_disposition()?)
    }
}
