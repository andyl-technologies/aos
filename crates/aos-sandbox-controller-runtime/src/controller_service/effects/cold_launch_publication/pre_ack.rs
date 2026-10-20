//! Records actual Applied516 while the accepted parent remains Applying.
//!
//! The same native attempt stays inline through every Source/C/Root post. Its
//! genuine completed borrower is retained for the later prearmed final exchange;
//! neither receipt DATA nor this pending parent can authorize public success.

use super::*;

pub(super) struct PreAckOriginalsV1 {
    pub(super) attempt: aos_sandbox::CreateStoppedCompletionAttemptV1,
    entered: bool,
    workspace: Option<Result<(), ResourceReservationErrorV1>>,
    append: Option<Result<aos_sandbox::CommitResult, ResourceReservationErrorV1>>,
    source_after: Option<Result<(), ResourceReservationErrorV1>>,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
}

impl PreAckOriginalsV1 {
    pub(super) fn new() -> Self {
        Self { attempt: Default::default(), entered: false, workspace: None,
            append: None, source_after: None, disposal: None }
    }

    pub(super) fn completed_v1(&self) -> bool {
        matches!(self.disposal, Some(Ok(()))) && self.attempt.failure().is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = self.attempt.failure() { return Some(cause); }
        if let Some(Err(cause)) = &self.workspace { return Some(cause); }
        if let Some(Err(cause)) = &self.append { return Some(cause); }
        if let Some(Err(cause)) = &self.source_after { return Some(cause); }
        self.disposal.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
    }
}

impl OriginalCreateProvisioningIssuerV1 {
    pub(super) fn record_pre_ack_once_v1(&mut self,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        sessions: &mut ControllerBrokerSessions,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        self.require_healthy()?;
        if self.pre_ack.entered || !self.source_progress.completed_v1() {
            return self.close();
        }
        self.pre_ack.entered = true;
        self.begin_publication_v1(intake, controller, source)?;

        self.pre_ack.append = Some((|| {
            let action = self.action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let root = self.root.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let original = self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            let turn = root.borrow_publication_turn_v1(action, original, controller)?;
            let mut loan = original.borrow_root_v1(intake,
                self.parent.ok_or(ResourceReservationErrorV1::Conflict)?, controller)?;
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
                        self.pre_ack.workspace = Some(Ok(()));
                        workspace
                    }
                    Err(cause) => {
                        self.pre_ack.workspace = Some(Err(cause));
                        return Err(ResourceReservationErrorV1::Conflict);
                    }
                }
            };
            let mut context = loan.prepare_create_stopped_pre_ack_context_once_v1(
                &mut self.pre_ack.attempt, action, &turn, controller, source, &workspace)?;
            context.record_controller_pre_ack_once_v1(controller)
        })());
        if !matches!(self.pre_ack.append, Some(Ok(_))) {
            self.first.get_or_insert(First::PreAck);
        }

        // The context constructor may itself fail after arming Source. None of
        // these independently owed posts depends on primary or append success.
        self.pre_ack.source_after = Some(self.pre_ack.attempt
            .finish_pre_ack_source_after_append_once_v1(controller, source));
        if !matches!(self.pre_ack.source_after, Some(Ok(()))) {
            self.first.get_or_insert(First::PreAck);
        }
        self.finish_native_v1(controller);
        if let (Some(root), Some(action)) = (self.root.as_mut(), self.action.as_ref()) {
            self.root_after = Some(root.finish_publication_turn_once_v1(
                action, self.native.as_ref(), controller));
            if !matches!(self.root_after, Some(Ok(()))) {
                self.first.get_or_insert(First::RootAfter);
            }
        }
        if let (Some(action), Some(root), Some(original)) =
            (self.action.as_ref(), self.root.as_ref(), self.native.as_ref()) {
            self.pre_ack.disposal = Some(self.pre_ack.attempt
                .finish_pre_ack_after_original_posts_once_v1(
                    action, root, original, controller, source));
            if !matches!(self.pre_ack.disposal, Some(Ok(()))) {
                self.first.get_or_insert(First::PreAck);
            }
        }
        self.require_healthy()
    }
}
