//! Drives the one prearmed final Create exchange and its actual terminal CAS.
//!
//! Applied516 stays pending until strict Root160/EOF and all original posts.
//! The borrowed pre-ACK context never enters a self-referential Runtime field;
//! the same inline Attempt, C23 and Root client retain every negative prefix.

use super::*;

pub(super) struct FinalOriginalsV1 {
    entered: bool,
    prearm: Option<Result<(), ResourceReservationErrorV1>>,
    wire: Option<Result<(), RootStorageApplyClientClosedV1>>,
    root_after: Option<Result<(), RootStorageApplyClientClosedV1>>,
    token: Option<Result<(), RootStorageApplyClientClosedV1>>,
    terminal: Option<Result<(), ResourceReservationErrorV1>>,
    negative_native: Option<Result<(), ResourceReservationErrorV1>>,
    client_closed: Option<Result<(), RootStorageApplyClientClosedV1>>,
}

impl FinalOriginalsV1 {
    pub(super) const fn new() -> Self {
        Self {
            entered: false,
            prearm: None,
            wire: None,
            root_after: None,
            token: None,
            terminal: None,
            negative_native: None,
            client_closed: None,
        }
    }

    pub(super) fn completed_v1(&self) -> bool {
        matches!(self.terminal, Some(Ok(()))) && matches!(self.client_closed, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.prearm {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.wire {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.root_after {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.token {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.terminal {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.negative_native {
            return Some(cause);
        }
        self.client_closed.as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
    }
}

impl OriginalCreateProvisioningIssuerV1 {
    pub(super) fn finish_create_stopped_once_v1(&mut self,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OriginalCreateProvisioningClosedV1> {
        self.require_healthy()?;
        if self.final_exchange.entered || !self.pre_ack.completed_v1() {
            return self.close();
        }
        let parent = match self.parent {
            Some(parent) => parent,
            None => return self.close(),
        };
        self.final_exchange.entered = true;
        let next = self.next_native_v1(intake, controller, source);
        let mut root_invoked = false;
        // The proof's exclusive Attempt loan ends with this lexical block.
        // Only the actual Root token, which owns its association and borrows
        // Root independently, can cross into the terminal mutation below.
        let completion = {
            let mut pre_ack = None;

            if next.is_ok() {
                let prepared = match
                    (self.action.as_ref(), self.root.as_ref(), self.native.as_mut()) {
                    (Some(action), Some(root), Some(original)) => {
                        match original.borrow_root_v1(intake, parent, controller) {
                            Ok(mut loan) => loan.prearm_create_stopped_completion_once_v1(
                                &mut self.pre_ack.attempt, action, root, controller, source),
                            Err(cause) => Err(cause),
                        }
                    }
                    _ => Err(ResourceReservationErrorV1::Conflict),
                };
                match prepared {
                    Ok(actual) => {
                        self.final_exchange.prearm = Some(Ok(()));
                        pre_ack = Some(actual);
                    }
                    Err(cause) => {
                        self.final_exchange.prearm = Some(Err(cause));
                        self.first.get_or_insert(First::FinalNative);
                    }
                }
                if let Some(actual) = pre_ack.as_ref() {
                    self.final_exchange.wire = Some(match
                        (self.action.as_ref(), self.root.as_mut(), self.native.as_mut()) {
                        (Some(action), Some(root), Some(original)) => {
                            match original.borrow_root_v1(intake,
                                parent, controller) {
                                Ok(mut loan) => {
                                    root_invoked = true;
                                    root.begin_create_stopped_final_once_v1(&mut loan, controller, actual, action)
                                }
                                Err(cause) => {
                                    self.entry = Some(Err(cause));
                                    self.first.get_or_insert(First::Entry);
                                    Err(RootStorageApplyClientClosedV1)
                                }
                            }
                        }
                        _ => Err(RootStorageApplyClientClosedV1),
                    });
                    if !matches!(self.final_exchange.wire, Some(Ok(()))) {
                        self.first.get_or_insert(First::FinalRoot);
                    }
                }
            }

            // Field-split the same actual receiver: pre_ack borrows only the inline
            // Attempt while C23 and the Root client must finish independently.
            if self.after.is_none() {
                if let Some(original) = self.native.as_mut() {
                    self.after = Some(original.finish_native_once_v1(controller));
                    if !matches!(self.after, Some(Ok(()))) {
                        self.first.get_or_insert(First::NativeAfter);
                    }
                }
            }
            if let Some(root) = self.root.as_mut().filter(|_| root_invoked) {
                self.final_exchange.root_after = Some(
                    root.finish_create_stopped_final_after_original_once_v1(self.native.as_ref(), controller));
                if !matches!(self.final_exchange.root_after, Some(Ok(()))) {
                    self.first.get_or_insert(First::FinalRoot);
                }
            }

            if !root_invoked {
                // A refused entry lends no proof. End the whole temporary
                // container before its negative port borrows the actual Attempt.
                drop(pre_ack);
                if let Some(root) = self.root.as_mut() {
                    self.final_exchange.root_after = Some(root
                        .observe_create_stopped_final_entry_refusal_after_original_once_v1(
                            &self.pre_ack.attempt, self.native.as_ref(), controller));
                    if !matches!(self.final_exchange.root_after, Some(Ok(()))) {
                        self.first.get_or_insert(First::FinalRoot);
                    }
                }
                None
            } else {
                let completion = if self.first.is_none() {
                    if let (Some(actual), Some(root), Some(original), Some(_action)) =
                        (pre_ack.as_ref(), self.root.as_mut(), self.native.as_ref(), self.action.as_ref()) {
                        let borrowed = root.borrow_create_stopped_completion_v1(actual, original, controller);
                        match borrowed {
                            Err(cause) => {
                                self.final_exchange.token = Some(Err(cause));
                                self.first.get_or_insert(First::FinalRoot);
                                None
                            }
                            Ok(completion) => {
                                self.final_exchange.token = Some(Ok(()));
                                Some(completion)
                            }
                        }
                    } else { None }
                } else { None };
                drop(pre_ack);
                completion
            }
        };

        let mut terminal_invoked = false;
        if let (Some(completion), Some(original), Some(action)) =
            (completion, self.native.as_ref(), self.action.as_ref()) {
            terminal_invoked = true;
            match self.pre_ack.attempt.finish_create_stopped_after_root_once_v1(
                action, &completion, original, controller, source) {
                Err(cause) => {
                    self.final_exchange.terminal = Some(Err(cause));
                    self.first.get_or_insert(First::FinalNative);
                }
                Ok(terminal) => {
                    self.final_exchange.terminal = Some(Ok(()));
                    self.final_exchange.client_closed = Some(
                        completion.finish_create_stopped_once_v1(&terminal, original, controller));
                    if !matches!(self.final_exchange.client_closed, Some(Ok(()))) {
                        self.first.get_or_insert(First::FinalRoot);
                    }
                }
            }
        }
        if !terminal_invoked {
            if let Some(original) = self.native.as_ref() {
                self.final_exchange.negative_native = Some(self.pre_ack.attempt
                    .finish_create_stopped_completion_native_once_v1(original, controller, source));
                if !matches!(self.final_exchange.negative_native, Some(Ok(()))) {
                    self.first.get_or_insert(First::FinalNative);
                }
            }
        }
        if !self.final_exchange.completed_v1() && self.first.is_none() {
            self.closed.get_or_insert(OriginalCreateProvisioningClosedV1);
            self.first = Some(First::Closed);
        }
        self.require_healthy()
    }
}
