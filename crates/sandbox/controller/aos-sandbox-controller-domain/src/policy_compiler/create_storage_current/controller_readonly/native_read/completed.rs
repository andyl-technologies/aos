//! Moves completed replay DATA while consuming its actual native file prefixes.
//!
//! The sole constructor consumes the complete fixed native reader, including
//! all independent mount/name/file afters. The actual purpose owner additionally
//! withholds this handoff until its own service/model/clock posts complete. This
//! historical DATA retains full semantic/canonical maps and indexes; it cannot
//! open a file, adopt a writer, renew native currentness or authorize an effect.

use super::*;

/// Retains complete historical replay DATA after native prefix disposal.
pub(crate) struct RootFixedCompletedReadDataV2 {
    target: RootFixedNativeTargetV1,
    canonical: CanonicalOrdinaryReadonlyReplayDataV1,
    _cold: ColdReplayOriginalV1,
    _audit: crate::journal::RootControllerReadonlyGeometryAuditV1,
    _stopped_history: Option<RootStoppedHistoryOriginalV2>,
    predecessor:
        Option<aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorReplayDataV2>,
    marked: Option<crate::journal::JournalTransaction>,
    names: ProtectedJournalNamesV1,
    next: u64,
    end: u64,
}

impl RootFixedNativeReadOriginalsV1 {
    // Error returns the whole original, including its exact failed native/raw
    // prefixes. No failure or model-transferred reader can become this DATA.
    /// Consumes a fully completed reader while keeping its historical models.
    ///
    /// # Errors
    /// Returns the whole unchanged original after incomplete native/semantic
    /// posts, an earlier failure or an already transferred readonly model.
    pub(crate) fn into_completed_data_v2(mut self) -> Result<RootFixedCompletedReadDataV2, Self> {
        if self.require_completed_data_v2().is_err() {
            return Err(self);
        }
        let native = match self.terminal_native_v1() {
            Ok(native) => (native.names, native.next, native.end),
            Err(_) => return Err(self),
        };
        let opening = std::mem::replace(&mut self.opening, CanonicalOrdinaryReadonlyOpeningV1::new());
        let canonical = match opening.into_completed_data_v1() {
            Ok(canonical) => canonical,
            Err(opening) => {
                self.opening = opening;
                return Err(self);
            }
        };
        let Self {
            target,
            cold,
            audit,
            delete_predecessor,
            stopped_history,
            marked_transaction,
            ..
        } = self;
        // All remaining fields, including every actual File, mount attempt and
        // rooted-name probe, are physically dropped before this method returns.
        Ok(RootFixedCompletedReadDataV2 {
            target,
            canonical,
            _cold: cold,
            _audit: audit,
            predecessor: delete_predecessor, _stopped_history: stopped_history,
            marked: marked_transaction,
            names: native.0,
            next: native.1,
            end: native.2,
        })
    }
}

impl RootFixedNativeReadOriginalsV1 {
    // The consuming handoff and all-five preflight share this exact predicate.
    pub(crate) fn require_completed_data_v2(&self) -> Result<(), JournalError> {
        if self.model_transferred || !self.target.uses_full_semantics() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.terminal_native_v1().map(|_| ())
    }
}

impl RootFixedCompletedReadDataV2 {
    pub(crate) fn delete_graph_request_receiving_bytes_v2(&self) -> Result<usize, JournalError> {
        self.readback_v2()?;
        self.predecessor.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .graph_request_receiving_bytes_v2().map_err(JournalError::from)
    }

    /// Moves the actual predecessor base after this reader's full native posts.
    ///
    /// # Errors
    /// Refuses incomplete predecessor comparison or a repeated model transfer.
    pub(crate) fn take_delete_graph_base_data_v2(&mut self)
        -> Result<aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2, JournalError>
    {
        self.readback_v2()?;
        self.predecessor.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .take_graph_base_data_v2().map_err(JournalError::from)
    }

    /// Borrows this actual completed prefix's canonical rows and exact index.
    ///
    /// # Errors
    /// Refuses an absent completed state; creates no native owner or admission.
    pub(crate) fn historical_rows_data_v2(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, JournalError>
    {
        let state = self.readback_v2()?.state;
        Ok(aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2::new(
            state, self.canonical.index_data_v1()))
    }

    /// Borrows the same completed canonical state and native coordinates.
    ///
    /// # Errors
    /// Refuses absent completed canonical state; it performs no new IO.
    pub(crate) fn readback_v2(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        Ok(RootFixedNativeReadbackV1 {
            marked_transaction: self.marked.as_ref(),
            state: self.canonical.replay_data_v1().state().ok_or(JournalError::ProtectedBoundary)?,
            names: self.names,
            next: self.next,
            end: self.end,
        })
    }

    /// Borrows the complete same-cursor Cache state after native disposal.
    ///
    /// # Errors
    /// Refuses absent completed state, namespaces or native replay report.
    pub(crate) fn cache_raw_view_v2(
        &self,
    ) -> Result<aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1<'_>, JournalError>
    {
        Ok(
            aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1 {
                state: self.canonical.replay_data_v1().state().ok_or(JournalError::ProtectedBoundary)?,
                namespaces: self.canonical.replay_data_v1()
                    .committed_namespaces()
                    .ok_or(JournalError::ProtectedBoundary)?,
                report: self.canonical.replay_data_v1()
                    .report()
                    .ok_or(JournalError::ProtectedBoundary)?
                    .1,
            },
        )
    }

    /// Derives only this actual disposed Cache target's original fixed bound.
    ///
    /// # Errors
    /// Refuses another fixed role or checked supplier overflow.
    pub(crate) fn cache_fixed_demand_v2(
        &self,
        role: aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1,
    ) -> Result<ResourceVector, JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::CacheCurrent(actual) if actual == role) {
            return Err(JournalError::ProtectedBoundary);
        }
        RootFixedNativeReadOriginalsV1::cache_current_fixed_demand_v1(role)
    }

    /// Borrows the same completed pre-Planned Source comparison.
    ///
    /// # Errors
    /// Refuses an absent or failed predecessor observation.
    pub(crate) fn delete_predecessor_data_v2(
        &self,
    ) -> Result<
        aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorDataV2,
        JournalError,
    > {
        self.predecessor
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .data_v2()
            .map_err(JournalError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    fn acquired_readonly() -> (tempfile::TempDir, CanonicalOrdinaryReadonlyOpeningV1<JournalError>) {
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new().prefix("root-readonly-completed-")
            .tempdir_in(executable.parent().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        for name in ["history", "history.lock"] {
            OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(directory.path().join(name)).unwrap();
        }
        let mut opening = CanonicalOrdinaryReadonlyOpeningV1::new();
        opening.prepare_rooted_once_v1(directory.path(), "history",
            crate::journal::JournalLimits::default(), rustix::process::geteuid().as_raw()).unwrap();
        (directory, opening)
    }

    #[test]
    fn incomplete_native_handoff_returns_the_same_live_file_owner() {
        let (directory, opening) = acquired_readonly();
        let identities = opening.identities_data_v1().unwrap();
        let mut original = RootFixedNativeReadOriginalsV1::controller_current_v1();
        original.opening = opening;
        std::fs::remove_file(directory.path().join("history")).unwrap();

        let retained = original.into_completed_data_v2().err().expect("incomplete native prefix");

        assert!(retained.opening.identities_data_v1() == Some(identities));
        // The name is absent; this succeeds only on the still-held original.
        assert!(retained.opening.observe_metadata_v1().is_ok());
    }

    #[test]
    fn an_already_transferred_model_cannot_also_retire_as_complete_data() {
        let (directory, opening) = acquired_readonly();
        let identities = opening.identities_data_v1().unwrap();
        let mut original = RootFixedNativeReadOriginalsV1::source_current_v1();
        original.opening = opening;
        original.model_transferred = true;
        std::fs::remove_file(directory.path().join("history")).unwrap();

        let retained = original.into_completed_data_v2().err().expect("exclusive model handoff");

        assert!(retained.opening.identities_data_v1() == Some(identities));
        assert!(retained.opening.observe_metadata_v1().is_ok());
    }
}
