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
        target: crucible::DebugCoordinate,
    ) -> Result<crucible::DebugGotoReport, LifecycleApiError> {
        let current = self.current_configuration().await?;
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugGoto {
                request: crucible::DebugGotoRequest::new(current, target),
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
        grain: crucible::DebugReverseStepGrain,
    ) -> Result<crucible::DebugReverseStepReport, LifecycleApiError> {
        let current = self.current_configuration().await?;
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugReverseStep {
                request: crucible::DebugReverseStepRequest::new(current, grain, Vec::new()),
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
        condition: crucible::Condition,
    ) -> Result<crucible::DebugReverseContinueReport, LifecycleApiError> {
        let current = self.current_configuration().await?;
        let (reply, receiver) = CommandReply::channel();
        self.sender
            .send(SessionCommand::DebugReverseContinue {
                request: crucible::DebugReverseContinueRequest::new(current, condition, Vec::new()),
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
        request: Option<crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
    ) -> Result<
        Option<crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
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
    ) -> Result<crucible::DebugNonCanonicalBranchReport, LifecycleApiError> {
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
        let request = crucible::DebugNonCanonicalBranchRequest::new(
            snapshot.configuration.clone(),
            snapshot.frontier,
            crucible::DebugNonCanonicalBranchTrigger::GuestIntrospection,
        )
        .with_action(crucible::DebugNonCanonicalBranchAction::guest_introspection(node));
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
                message: format!("debug guest fork reply closed: {error}"),
            })?
            .map_err(session_command_rejection)
    }
}

fn session_command_rejection(error: SessionError) -> LifecycleApiError {
    LifecycleApiError::SessionCommandRejected {
        message: error.to_string(),
    }
}
