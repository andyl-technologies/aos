//! Stages the original readonly opener before consuming its held prefix.
//!
//! This is the same native opening and replay engine used by ordinary readers.
//! Capturing files or borrowing an extent grants no receiving allowance. The
//! selected role owner must pay fixed preparation before entry, then admit
//! Native and typed representations through its genuine receiving loan before
//! continuing the same captured owner.

use super::*;

pub(super) struct CapturedReadOnlyPreparationV1 {
    binding: Option<(String, JournalLimits)>,
    native: Option<Result<(), JournalError>>,
    named_admission: Option<Result<(), JournalError>>,
    names: Option<Result<(), JournalError>>,
    replay_entered: bool,
    closed: bool,
}

impl CapturedReadOnlyPreparationV1 {
    pub(super) const fn new() -> Self {
        Self {
            binding: None,
            native: None,
            named_admission: None,
            names: None,
            replay_entered: false,
            closed: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.named_admission.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.native.as_ref().and_then(|result| result.as_ref().err()))
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.then_some(
                &READ_ONLY_OPEN_CLOSED as &(dyn std::error::Error + 'static),
            ))
    }
}

impl ReadOnlyJournalOpenOriginalsV1 {




    /// Prepares Root's independent fixed Controller reader under its same R.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_captured_root_controller_once<'borrow, 'original: 'borrow, 'data>(
        &mut self,
        _original_uid: u32,
        directory_identity: (u64, u64),
        receiving: &mut crate::journal::RootControllerReadonlyReceivingContextV1<
            'borrow, 'original, 'data,
        >,
    ) {
        self.prepare_captured_receiving_once(
            Path::new(crate::journal::ROOT_CONTROLLER_DIRECTORY_V1),
            crate::journal::ROOT_CONTROLLER_JOURNAL_V1,
            crate::journal::controller::production_journal_limits(),
            0,
            directory_identity,
            crate::journal::ReadonlyReceivingContextV1::RootController(receiving),
        );
    }

    // Both closed typed entries arm the same captured owner only after their
    // own genuine original checks its already paid fixed receiving frontier.
    #[cfg(target_os = "linux")]
    fn prepare_captured_receiving_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        directory_identity: (u64, u64),
        mut receiving: crate::journal::ReadonlyReceivingContextV1<'_, '_, '_, '_>,
    ) {
        use crate::journal::ReadonlyReceivingContextV1 as Receiving;
        use super::super::super::readonly_names::ReadonlyNameArchiveV1;

        if self.attempted || self.closed || self.captured.named_admission.is_some() {
            self.captured.closed = true;
            return;
        }
        self.captured.named_admission = Some(match &mut receiving {
            Receiving::RootController(context) => context.require_fixed_named_preparation(),
        });
        if !matches!(self.captured.named_admission, Some(Ok(()))) {
            self.attempted = true;
            return;
        }
        self.named_receiving = Some(match &receiving {
            Receiving::RootController(_) => ReadonlyNameArchiveV1::root_controller(),
        });
        match &mut receiving {
            Receiving::RootController(context) => self.prepare_captured_inner(
                path, name, limits, uid, directory_identity,
                Some(context.retained_lock_name_destination_v1()),
            ),
        }
    }

    /// Captures fixed files and their original metadata without replay growth.
    ///
    /// The caller has already paid this native recipe. The owned binding fixes
    /// the same basename and limits across replay; no replacement File, path,
    /// limit, callback or receiving account enters the continuation.
    pub(crate) fn prepare_captured_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        directory_identity: (u64, u64),
    ) {
        self.prepare_captured_inner(path, name, limits, uid, directory_identity, None);
    }

    fn prepare_captured_inner(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        directory_identity: (u64, u64),
        retained_lock_name: Option<&mut Option<String>>,
    ) {
        if self.attempted || self.closed || self.captured.native.is_some() {
            self.captured.closed = true;
            return;
        }
        self.attempted = true;
        self.captured.binding = Some((name.to_owned(), limits));
        self.captured.native = Some((|| {
            self.prepare_native_inner(path, name, limits, uid, directory_identity, retained_lock_name)?;
            self.capture_prefix_once(limits)?;
            Ok(())
        })());
        // This post is independent of metadata/capture success whenever the
        // original physical-name witness was reached.
        self.captured.names = self.observe_names();
    }

    /// Borrows only the exact held prefix before its sole continuation.
    #[cfg(target_os = "linux")]
    pub(crate) fn captured_extent(
        &self,
    ) -> Option<&crate::journal::ProtectedJournalPreopenReplayExtentV1> {
        if self.closed || self.captured.replay_entered
            || self.captured.failure().is_some()
            || !matches!(self.captured.native, Some(Ok(())))
            || !matches!(self.captured.names, Some(Ok(())))
        {
            return None;
        }
        self.extent.as_ref()?.as_ref().ok()
    }

    // Mechanical DATA borrow for Root's separately paid canonical geometry
    // audit. It cannot supply a protected writer, role view or receiving grant.
    #[cfg(target_os = "linux")]
    pub(in crate::journal) fn captured_opening_for_geometry_audit_v1(&self)
        -> Option<(&aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<JournalError>, crate::journal::ProtectedJournalPreopenReplayExtentV1)>
    {
        Some((&self.native, *self.captured_extent()?))
    }

    /// Replays the same fixed original once after its outer receiving debit.
    ///
    /// Whole native errors, retained scratch and the independent final name
    /// observation stay resident even when replay fails. A failed first stage
    /// cannot be retried or replaced by an ordinary complete opening.
    pub(crate) fn replay_captured_once(&mut self) {
        self.replay_captured_inner(
            #[cfg(target_os = "linux")]
            None,
        );
    }




    /// Replays the same held Controller prefix using its actual Root R context.
    #[cfg(target_os = "linux")]
    pub(crate) fn replay_captured_root_controller_once<'borrow, 'original: 'borrow, 'data>(
        &mut self,
        receiving: &mut crate::journal::RootControllerReadonlyReceivingContextV1<
            'borrow, 'original, 'data,
        >,
    ) {
        self.replay_captured_inner(Some(
            crate::journal::ReadonlyReceivingContextV1::RootController(receiving),
        ));
    }

    fn replay_captured_inner(
        &mut self,
        #[cfg(target_os = "linux")]
        receiving: Option<crate::journal::ReadonlyReceivingContextV1<'_, '_, '_, '_>>,
    ) {
        if self.closed || self.captured.replay_entered
            || self.captured.failure().is_some()
            || !matches!(self.captured.native, Some(Ok(())))
            || !matches!(self.captured.names, Some(Ok(())))
            || self.returned.is_some()
        {
            self.captured.closed = true;
            return;
        }
        self.captured.replay_entered = true;
        let Some((name, limits)) = self.captured.binding.take() else {
            self.captured.closed = true;
            return;
        };
        self.returned = Some(self.finish_read_only_inner(limits, true,
            #[cfg(target_os = "linux")]
            receiving,
        ));
        self.captured.binding = Some((name, limits));
        self.initial_name = self.observe_names();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
