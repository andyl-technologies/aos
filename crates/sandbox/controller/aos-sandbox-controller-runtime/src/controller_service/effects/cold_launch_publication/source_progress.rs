//! Drives one canonical Source phase per genuine C23 and Root native turn.
//!
//! Source itself selects and validates the next phase. This fixed Runtime
//! roster preserves each whole Result and its owed disposition; it cannot
//! manufacture a phase, semantic fact, workspace or terminal record.

use super::*;

pub(super) struct SourceProgressOriginalsV1 {
    phases: [Option<Result<(), ResourceReservationErrorV1>>; 5],
    disposals: [Option<Result<(), ResourceReservationErrorV1>>; 5],
    workspace: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    completed: usize,
}

impl SourceProgressOriginalsV1 {
    pub(super) const fn new() -> Self {
        Self { phases: [None, None, None, None, None],
            disposals: [None, None, None, None, None], workspace: [None, None], completed: 0 }
    }

    pub(super) fn completed_v1(&self) -> bool { self.completed == self.phases.len() }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        for index in 0..self.phases.len() {
            if index >= 3 {
                if let Some(Err(cause)) = &self.workspace[index - 3] { return Some(cause); }
            }
            if let Some(Err(cause)) = &self.phases[index] { return Some(cause); }
            if let Some(Err(cause)) = &self.disposals[index] { return Some(cause); }
        }
        None
    }
}

impl OriginalCreateProvisioningIssuerV1 {
    pub(super) fn advance_source_progress_once_v1(&mut self,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        self.require_healthy()?;
        let index = self.source_progress.completed;
        if index >= self.source_progress.phases.len()
            || self.source_progress.phases[index].is_some() {
            return self.close();
        }
        let entered = self.begin_publication_v1(intake, controller, source);
        if entered.is_err() { return Err(OriginalCreateProvisioningClosedV1); }
        self.source_progress.phases[index] = Some((|| {
            let action = self.action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let root = self.root.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let original = self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            let turn = root.borrow_publication_turn_v1(action, original, controller)?;
            let mut loan = original.borrow_root_v1(intake,
                self.parent.ok_or(ResourceReservationErrorV1::Conflict)?, controller)?;
            if index < 3 {
                loan.advance_original_create_lifecycle_source_once_v1(
                    action, &turn, controller, source)
            } else {
                let workspace = {
                    let mut context = loan.borrow_storage_workspace_source_context_v1(
                        action, &turn, controller)?;
                    let borrowed = match sessions.storage.as_ref() {
                        Some(storage) => storage.borrow_source_workspace_original_v1(
                            &self.storage_io.flights, &mut context),
                        None => Err(ResourceReservationErrorV1::Conflict),
                    };
                    match borrowed {
                        Ok(workspace) => {
                            self.source_progress.workspace[index - 3] = Some(Ok(()));
                            workspace
                        }
                        Err(cause) => {
                            self.source_progress.workspace[index - 3] = Some(Err(cause));
                            return Err(ResourceReservationErrorV1::Conflict);
                        }
                    }
                };
                loan.advance_original_create_workspace_source_once_v1(
                    action, &turn, controller, source, &workspace)
            }
        })());
        if !matches!(self.source_progress.phases[index], Some(Ok(()))) {
            self.first.get_or_insert(First::Source);
        }
        // Every entered Source phase already ran Source-after. The same C23
        // original returns first, then Root-after runs despite any body error.
        self.finish_native_v1(controller);
        if let (Some(root), Some(action)) = (self.root.as_mut(), self.action.as_ref()) {
            self.root_after = Some(root.finish_publication_turn_once_v1(
                action, self.native.as_ref(), controller));
            if !matches!(self.root_after, Some(Ok(()))) {
                self.first.get_or_insert(First::RootAfter);
            }
        }
        if let (Some(original), Some(root), Some(action)) =
            (self.native.as_mut(), self.root.as_ref(), self.action.as_ref()) {
            self.source_progress.disposals[index] = Some(
                original.finish_original_create_lifecycle_progress_after_posts_once_v1(
                    action, root, controller, source));
            if !matches!(self.source_progress.disposals[index], Some(Ok(()))) {
                self.first.get_or_insert(First::Source);
            }
        }
        self.require_healthy()?;
        self.source_progress.completed += 1;
        Ok(())
    }
}
