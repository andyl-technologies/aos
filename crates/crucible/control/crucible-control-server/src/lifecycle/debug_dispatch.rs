//! Actor dispatch implementations for debugger reposition and guest introspection.

use super::*;

impl DebugRepositionDispatch {
    async fn current_configuration(&self) -> Result<Configuration, LifecycleApiError> {
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::Query {
                kind: QueryKind::Snapshot,
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        let result = receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug reposition snapshot reply closed: {error}"),
            })?
            .map_err(session_command_rejection)?;
        match result {
            QueryResult::Snapshot(snapshot) => Ok(snapshot.configuration),
            _ => Err(LifecycleApiError::ActorFailed {
                message: String::from(
                    "debug reposition snapshot query returned an unexpected result",
                ),
            }),
        }
    }

    /// Moves the attached debugger to `target` through actor-owned restore and replay.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when actor communication, target resolution,
    /// replay validation, or live-runtime replacement fails.
    pub async fn goto(
        &self,
        target: crucible_engine::DebugCoordinate,
    ) -> Result<crucible_engine::DebugGotoReport, LifecycleApiError> {
        let current = self.current_configuration().await?;
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugGoto {
                request: crucible_engine::DebugGotoRequest::new(current, target),
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug goto reply closed: {error}"),
            })?
            .map_err(session_command_rejection)
    }

    /// Reverse-steps the attached debugger by one scheduler-defined grain.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when actor communication, reverse-target
    /// resolution, replay validation, or live-runtime replacement fails.
    pub async fn reverse_step(
        &self,
        grain: crucible_engine::DebugReverseStepGrain,
    ) -> Result<crucible_engine::DebugReverseStepReport, LifecycleApiError> {
        let current = self.current_configuration().await?;
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugReverseStep {
                request: crucible_engine::DebugReverseStepRequest::new(current, grain, Vec::new()),
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug reverse-step reply closed: {error}"),
            })?
            .map_err(session_command_rejection)
    }

    /// Reverse-continues to the latest actor-owned event prefix matching `condition`.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when actor communication, condition
    /// evaluation, replay validation, or live-runtime replacement fails.
    pub async fn reverse_continue(
        &self,
        condition: crucible_engine::Condition,
    ) -> Result<crucible_engine::DebugReverseContinueReport, LifecycleApiError> {
        let current = self.current_configuration().await?;
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugReverseContinue {
                request: crucible_engine::DebugReverseContinueRequest::new(
                    current,
                    condition,
                    Vec::new(),
                ),
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug reverse-continue reply closed: {error}"),
            })?
            .map_err(session_command_rejection)
    }
}
impl GuestIntrospectionDispatch {
    async fn current_boundary(&self) -> Result<(Configuration, VirtualTime), LifecycleApiError> {
        let (query_reply, query_receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::Query {
                kind: QueryKind::Snapshot,
                reply: query_reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        let snapshot = query_receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug fork snapshot reply closed: {error}"),
            })?
            .map_err(session_command_rejection)?;
        let QueryResult::Snapshot(snapshot) = snapshot else {
            return Err(LifecycleApiError::ActorFailed {
                message: String::from("debug fork snapshot query returned an unexpected result"),
            });
        };
        Ok((snapshot.configuration.clone(), snapshot.frontier))
    }

    async fn fork_request(
        &self,
        request: crucible_engine::DebugNonCanonicalBranchRequest,
    ) -> Result<crucible_engine::DebugNonCanonicalBranchReport, LifecycleApiError> {
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugForkNonCanonical { request, reply })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("debug fork reply closed: {error}"),
            })?
            .map_err(session_command_rejection)
    }

    /// Exchanges one channel-addressed record with the session actor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the actor is unavailable or rejects
    /// the fork gate, channel envelope, or backend operation.
    pub async fn exchange(
        &self,
        node: NodeId,
        channel_id: u64,
        request: Option<crucible_qemu_protocol::guest_introspection::GuestIntrospectionRecord>,
    ) -> Result<
        Option<crucible_qemu_protocol::guest_introspection::GuestIntrospectionRecord>,
        LifecycleApiError,
    > {
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::GuestIntrospection {
                node,
                channel_id,
                request,
                reply,
            })
            .await
            .map_err(|_| LifecycleApiError::CommandChannelClosed {
                session_id: self.session_id,
            })?;
        receiver
            .await
            .map_err(|error| LifecycleApiError::ActorFailed {
                message: format!("guest-introspection reply closed: {error}"),
            })?
            .map_err(session_command_rejection)
    }

    /// Forks the attached debugger for a guest-introspection action.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when actor communication, attachment, or
    /// non-canonical branch admission fails.
    pub async fn fork(
        &self,
        node: NodeId,
    ) -> Result<crucible_engine::DebugNonCanonicalBranchReport, LifecycleApiError> {
        let (configuration, frontier) = self.current_boundary().await?;
        let request = crucible_engine::DebugNonCanonicalBranchRequest::new(
            configuration,
            frontier,
            crucible_engine::DebugNonCanonicalBranchTrigger::GuestIntrospection,
        )
        .with_action(crucible_engine::DebugNonCanonicalBranchAction::guest_introspection(node));
        self.fork_request(request).await
    }

    /// Records an explicit non-canonical fork for an imminent GDB guest edit.
    ///
    /// The caller must perform the indicated write on this same private
    /// session and verify readback before reporting a successful edit. A failed
    /// write leaves only a disposable non-canonical session, never a canonical
    /// mutation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when actor communication, attachment, or
    /// branch admission fails.
    pub async fn fork_guest_edit(
        &self,
        node: NodeId,
        kind: crucible_engine::DebugGuestEditKind,
        target: String,
        bytes: Vec<u8>,
    ) -> Result<crucible_engine::DebugNonCanonicalBranchReport, LifecycleApiError> {
        let (configuration, frontier) = self.current_boundary().await?;
        let trigger = match kind {
            crucible_engine::DebugGuestEditKind::RegisterWrite => {
                crucible_engine::DebugNonCanonicalBranchTrigger::GuestRegisterWrite
            }
            crucible_engine::DebugGuestEditKind::MemoryWrite => {
                crucible_engine::DebugNonCanonicalBranchTrigger::GuestMemoryWrite
            }
            crucible_engine::DebugGuestEditKind::MemoryPatchBreakpoint => {
                crucible_engine::DebugNonCanonicalBranchTrigger::MemoryPatchBreakpoint
            }
        };
        let edit = crucible_engine::DebugGuestEdit::new(
            node,
            kind,
            crucible_engine::DebugCoordinate::virtual_time(frontier),
            target,
            bytes,
        );
        let request =
            crucible_engine::DebugNonCanonicalBranchRequest::new(configuration, frontier, trigger)
                .with_action(crucible_engine::DebugNonCanonicalBranchAction::guest_edit(
                    edit,
                ));
        self.fork_request(request).await
    }
}

fn session_command_rejection(error: SessionError) -> LifecycleApiError {
    LifecycleApiError::SessionCommandRejected {
        message: error.to_string(),
    }
}
