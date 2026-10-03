//! Connects the fixed Git inspection channel to the existing Controller worker.
//!
//! The parent's two slots retain accepted originals, returned commands and
//! completion receivers. The worker's two slots retain the SAME moved owners
//! before evaluation. No second runner, runtime, parser, authority factory or
//! independent terminal exists. The existing parent's terminal exits with
//! failed originals resident; local completion never means admission or Drain.

use std::sync::{Arc, mpsc};

use aos_sandbox::git::delegated_read::{
    GitReadInspectionUnavailableV1, GitReadListenerAttemptV1, GitReadRequestOwnerV1,
};
use aos_sandbox::public_api_session::PublicApiSessionAcceptor;

use super::{ControllerCommand, ControllerResidentCauseV1, ControllerWorkerCustodyV1, ProductionController};
use super::publisher_policy_source::PublisherPolicyBootstrapAttemptV1;

#[derive(Default)]
struct ParentSlotV1 {
    original: Option<GitReadRequestOwnerV1>,
    boxed: Option<Box<Option<GitReadRequestOwnerV1>>>,
    command: Option<ControllerCommand>,
    submitted: Option<Result<(), mpsc::TrySendError<ControllerCommand>>>,
    completion: Option<tokio::sync::oneshot::Receiver<()>>,
    completed: Option<Result<(), tokio::sync::oneshot::error::RecvError>>,
}

pub(super) struct GitReadIngressV1 {
    listener: GitReadListenerAttemptV1,
    first: ParentSlotV1,
    second: ParentSlotV1,
    selected: bool,
}

impl GitReadIngressV1 {
    pub(super) fn new() -> Self {
        Self { listener: GitReadListenerAttemptV1::new(), first: ParentSlotV1::default(),
            second: ParentSlotV1::default(), selected: false }
    }

    pub(super) fn bind(
        &mut self,
        uid: u32,
        gid: u32,
        gateway: (u32, u32),
        terminal: &ControllerWorkerCustodyV1,
    ) {
        if self.selected { terminal.terminate(ControllerResidentCauseV1::GitRead); }
        self.selected = true;
        if self.listener.bind_controller_once(uid, gid, gateway.0, gateway.1).is_err() {
            terminal.terminate(ControllerResidentCauseV1::GitRead);
        }
    }

    pub(super) async fn serve(
        &mut self,
        commands: Option<&mpsc::SyncSender<ControllerCommand>>,
        terminal: &ControllerWorkerCustodyV1,
    ) {
        if !self.selected { std::future::pending::<()>().await; }
        let Some(commands) = commands else {
            terminal.terminate(ControllerResidentCauseV1::GitRead);
        };
        loop {
            let index = if self.first.completion.is_none() { 0 }
                else if self.second.completion.is_none() { 1 }
                else {
                    let (first, second) = (&mut self.first, &mut self.second);
                    let Some(first_receiver) = first.completion.as_mut() else {
                        terminal.terminate(ControllerResidentCauseV1::GitRead);
                    };
                    let Some(second_receiver) = second.completion.as_mut() else {
                        terminal.terminate(ControllerResidentCauseV1::GitRead);
                    };
                    tokio::select! {
                        returned = first_receiver => {
                            first.completed = Some(returned);
                            if !matches!(first.completed, Some(Ok(()))) {
                                terminal.terminate(ControllerResidentCauseV1::GitRead);
                            }
                            first.completion = None;
                            0
                        }
                        returned = second_receiver => {
                            second.completed = Some(returned);
                            if !matches!(second.completed, Some(Ok(()))) {
                                terminal.terminate(ControllerResidentCauseV1::GitRead);
                            }
                            second.completion = None;
                            1
                        }
                    }
                };
            let slot = if index == 0 { &mut self.first } else { &mut self.second };
            if slot.original.is_some() || slot.boxed.is_some() || slot.command.is_some()
                || slot.submitted.as_ref().is_some_and(|result| result.is_err())
            { terminal.terminate(ControllerResidentCauseV1::GitRead); }
            slot.submitted = None;
            slot.completed = None;
            if self.listener.accept_original(&mut slot.original).await.is_err() {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            }
            let Some(original) = slot.original.as_mut() else {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            };
            if original.receive_original().await.is_err() {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            }
            let (reply, received) = tokio::sync::oneshot::channel();
            slot.completion = Some(received);
            // Allocate the empty selected channel cell BEFORE moving custody.
            // An allocator/provider refusal still has the original in its slot.
            slot.boxed = Some(Box::new(None));
            let Some(boxed) = slot.boxed.as_mut() else {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            };
            if boxed.is_some() || slot.original.is_none() {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            }
            **boxed = slot.original.take();
            let Some(original) = slot.boxed.take() else {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            };
            // Only this selected command boxes the SAME owner. The old command
            // channel's element layout/envelope does not grow with proc buffers.
            slot.command = Some(ControllerCommand::InspectGitRead {
                original, index, reply,
            });
            let Some(command) = slot.command.take() else {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            };
            // try_send's whole failed command is parked before classification.
            // Its successful queue move has no second owner or copied request.
            slot.submitted = Some(commands.try_send(command));
            if !matches!(slot.submitted, Some(Ok(()))) {
                terminal.terminate(ControllerResidentCauseV1::GitRead);
            }
        }
    }
}

pub(super) struct GitReadWorkerInputsV1 {
    acceptor: Arc<PublicApiSessionAcceptor>,
    runtime: tokio::runtime::Handle,
    first: Option<Box<Option<GitReadRequestOwnerV1>>>,
    second: Option<Box<Option<GitReadRequestOwnerV1>>>,
    first_reply: Option<tokio::sync::oneshot::Sender<()>>,
    second_reply: Option<tokio::sync::oneshot::Sender<()>>,
    returned: Option<Result<(), GitReadInspectionUnavailableV1>>,
}

impl GitReadWorkerInputsV1 {
    pub(super) fn new(acceptor: Arc<PublicApiSessionAcceptor>, runtime: tokio::runtime::Handle) -> Self {
        Self { acceptor, runtime, first: None, second: None, first_reply: None,
            second_reply: None, returned: None }
    }

    pub(super) fn inspect(
        &mut self,
        controller: &mut ProductionController,
        bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
        original: Box<Option<GitReadRequestOwnerV1>>,
        index: usize,
        reply: tokio::sync::oneshot::Sender<()>,
        terminal: &ControllerWorkerCustodyV1,
    ) {
        let (slot, reply_slot) = match index {
            0 if self.first.is_none() && self.first_reply.is_none() => (&mut self.first, &mut self.first_reply),
            1 if self.second.is_none() && self.second_reply.is_none() => (&mut self.second, &mut self.second_reply),
            _ => {
                // The argument is still genuinely owned in this frame. Abort
                // rather than dropping a foreign/reentered original on refusal.
                std::process::abort();
            }
        };
        *slot = Some(original);
        *reply_slot = Some(reply);
        if terminal.ended.load(std::sync::atomic::Ordering::Acquire) {
            terminal.terminate(ControllerResidentCauseV1::GitRead);
        }
        let Some(original) = slot.as_mut().and_then(|cell| cell.as_mut().as_mut()) else {
            terminal.terminate(ControllerResidentCauseV1::GitRead);
        };
        self.returned = Some(self.runtime.block_on(async {
            original.recheck().await?;
            original.recheck_registration(&self.acceptor)?;
            let (project, resource) = original.route()?;
            // Mandatory ExistingResident Cache and its genuine signed bootstrap
            // remain separate owners; seven quantities are not a total account.
            if super::cache_usage::selected_bookend(controller, bootstrap).is_err()
                || bootstrap.check_git_read_route(controller, project, resource).is_err()
            { return Err(GitReadInspectionUnavailableV1); }
            controller.inspect_original_gateway_git_read_v1(original, &self.acceptor);
            original.recheck().await?;
            original.recheck_registration(&self.acceptor)?;
            if bootstrap.check_git_read_route(controller, project, resource).is_err()
                || super::cache_usage::selected_bookend(controller, bootstrap).is_err()
            { return Err(GitReadInspectionUnavailableV1); }
            original.complete_local_inspection().await?;
            original.recheck().await?;
            original.recheck_registration(&self.acceptor)?;
            if super::cache_usage::selected_bookend(controller, bootstrap).is_err()
                || bootstrap.check_git_read_route(controller, project, resource).is_err()
            { return Err(GitReadInspectionUnavailableV1); }
            original.retire_completed_local()
        }));
        if !matches!(self.returned, Some(Ok(()))) || original.terminal_failure_observed() {
            terminal.terminate(ControllerResidentCauseV1::GitRead);
        }
        // Complete local checks and closure precede deliberate graph retirement.
        // No remote effect permission, restart, final peer ACK or Drain follows.
        drop(slot.take());
        let Some(reply) = reply_slot.take() else { terminal.terminate(ControllerResidentCauseV1::GitRead); };
        if reply.send(()).is_err() { terminal.terminate(ControllerResidentCauseV1::GitRead); }
    }
}
