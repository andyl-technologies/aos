//! Lends the actual fixed Root and Controller cursors to the sole cold recipe.
//!
//! Only concrete Broker cursor types enter these methods. Their constructors,
//! financial admission, held files and independently owed posts remain with
//! their real owners; this module neither opens nor completes a role.

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchErrorV1, ControllerWriterReplayV1,
};
use aos_sandbox_broker::receiving::{RootWriterErrorV1, RootWriterReplayV1};

use super::semantic::SelectedReplayNativeV1;
use super::{ColdReplayClosedV1, ColdReplayOriginalV1, FileIdentity, JournalLimits};

impl ColdReplayOriginalV1<RootWriterErrorV1> {
    /// Drives the same Root invocation cursor through every full semantic hook.
    ///
    /// The actual Root owner prepays representation before lending its cursor.
    /// Semantic refusal leaves its native invocation window unfinished; the
    /// cursor's existing Drop then refuses that same original invocation.
    ///
    /// # Errors
    /// Retains the exact native or semantic cause on reentry or any refusal.
    pub fn observe_root_once(
        &mut self,
        cursor: &mut RootWriterReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
    ) -> Result<(), ColdReplayClosedV1> {
        self.original
            .observe_native_once(cursor, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }
}

impl ColdReplayOriginalV1<ControllerBankLaunchErrorV1> {
    /// Drives the actual paid Controller cursor through the same full recipe.
    ///
    /// The existing fixed constructor performs its own debit and identity
    /// preparation before lending this concrete cursor. No supplied callback
    /// or DATA completion can replace those original operations.
    ///
    /// # Errors
    /// Retains the exact native or semantic cause on reentry or any refusal.
    pub fn observe_controller_once(
        &mut self,
        cursor: &mut ControllerWriterReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
    ) -> Result<(), ColdReplayClosedV1> {
        self.original
            .observe_native_once(cursor, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }
}

impl SelectedReplayNativeV1 for RootWriterReplayV1<'_, '_> {
    type Error = RootWriterErrorV1;

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.advance_once()
    }

    fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.validate_compaction_once()
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.register_and_compare_index_once()
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        self.prepare_change_once()
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.apply_next_record_once()
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.finish_commit_accounting_once()
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        self.finish_commit_once()
    }

    fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.finish_semantic_window_once()
    }
}

impl SelectedReplayNativeV1 for ControllerWriterReplayV1<'_, '_> {
    type Error = ControllerBankLaunchErrorV1;

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.advance_once()
    }

    fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.validate_compaction_once()
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.register_and_compare_index_once()
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        self.prepare_change_once()
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.apply_next_record_once()
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.finish_commit_accounting_once()
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        self.finish_commit_once()
    }

    fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        if self.completed_prefix().is_none() || self.failure().is_some() {
            Err(ControllerBankLaunchErrorV1::Conflict)
        } else {
            Ok(())
        }
    }
}
