//! Guest-introspection response brokering, activation, and channel lifecycle.

use super::*;

impl<L> Engine<L> {
    pub(super) fn handle_guest_introspection_command(
        &mut self,
        node: &NodeId,
        channel_id: u64,
        request: Option<&GuestIntrospectionRecord>,
    ) -> Result<Option<GuestIntrospectionRecord>, SessionError>
    where
        L: QuantumLoop,
    {
        if !matches!(
            self.debug_coordinator.state(),
            DebugCoordinatorState::NonCanonical { .. }
        ) {
            if request.is_none()
                && let Some(record) = self
                    .guest_responses
                    .get_mut(&(node.clone(), channel_id))
                    .and_then(VecDeque::pop_front)
            {
                return Ok(Some(record));
            }
            return Err(SessionError::DebugNonCanonicalBranchRequired {
                operation: "guest-introspection",
            });
        }
        if self.white_box_policies.get(node) != Some(&WhiteBoxPolicy::Enabled) {
            return Err(SessionError::GuestIntrospectionNotAuthorized {
                node: node.name.clone(),
            });
        }
        let Some(record) = request else {
            return self.receive_guest_channel_response(node, channel_id);
        };
        if record.channel_id() != channel_id {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "guest-introspection request channel does not match envelope",
                ),
            }
            .into());
        }
        record
            .validate_host_request()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("invalid guest-introspection request: {error}"),
            })?;
        self.validate_guest_capability(node, record.message())?;
        self.validate_guest_channel_capacity(node, record.message())?;
        let opens_channel = matches!(
            record.message(),
            GuestIntrospectionMessage::Exec { .. }
                | GuestIntrospectionMessage::Pty { .. }
                | GuestIntrospectionMessage::Ssh { .. }
        );
        if opens_channel {
            self.begin_guest_channel_run()?;
        }
        if let Err(error) = self
            .quantum_loop
            .send_guest_introspection(node.clone(), record.clone())
        {
            if opens_channel {
                self.abort_empty_guest_channel_run()?;
            }
            return Err(error.into());
        }
        match record.message() {
            GuestIntrospectionMessage::Exec { .. }
            | GuestIntrospectionMessage::Pty { .. }
            | GuestIntrospectionMessage::Ssh { .. } => {
                self.guest_channels.insert((node.clone(), channel_id));
            }
            GuestIntrospectionMessage::Input(_)
            | GuestIntrospectionMessage::Resize { .. }
            | GuestIntrospectionMessage::Close => {}
            GuestIntrospectionMessage::Features(_)
            | GuestIntrospectionMessage::Output { .. }
            | GuestIntrospectionMessage::Exit { .. }
            | GuestIntrospectionMessage::Error { .. } => {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("guest response message passed host-request validation"),
                }
                .into());
            }
        }
        Ok(None)
    }

    pub(crate) fn receive_guest_channel_response(
        &mut self,
        node: &NodeId,
        channel_id: u64,
    ) -> Result<Option<GuestIntrospectionRecord>, SessionError>
    where
        L: QuantumLoop,
    {
        let key = (node.clone(), channel_id);
        if let Some(record) = self
            .guest_responses
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
        {
            if guest_response_is_terminal(&record)
                && let Err(error) = self.finish_guest_channel_run_if_idle()
            {
                self.guest_responses
                    .entry(key)
                    .or_default()
                    .push_front(record);
                return Err(error);
            }
            return Ok(Some(record));
        }
        for _ in 0..GUEST_RESPONSE_BROKER_CAPACITY {
            let Some(record) = self
                .quantum_loop
                .receive_guest_introspection(node.clone())?
            else {
                return Ok(None);
            };
            record.validate_guest_response().map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("invalid guest-introspection response: {error}"),
                }
            })?;
            let record_key = (node.clone(), record.channel_id());
            let terminal = guest_response_is_terminal(&record);
            if terminal {
                self.guest_channels.remove(&record_key);
                if let Err(error) = self.finish_guest_channel_run_if_idle() {
                    self.guest_responses
                        .entry(record_key)
                        .or_default()
                        .push_back(record);
                    return Err(error);
                }
            }
            if record_key == key {
                return Ok(Some(record));
            }
            let buffered = self
                .guest_responses
                .values()
                .map(VecDeque::len)
                .sum::<usize>();
            if buffered >= GUEST_RESPONSE_BROKER_CAPACITY {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("guest-introspection response broker is full"),
                }
                .into());
            }
            self.guest_responses
                .entry(record_key)
                .or_default()
                .push_back(record);
        }
        Ok(None)
    }

    pub(super) fn begin_debug_guest_activation(
        &mut self,
        node: NodeId,
        mut report: DebugNonCanonicalBranchReport,
        reply: CommandReply<DebugNonCanonicalBranchReport>,
    ) where
        L: QuantumLoop,
    {
        self.guest_features.remove(&node);
        self.guest_responses
            .remove(&(node.clone(), GUEST_INTROSPECTION_FEATURE_CHANNEL_ID));
        if let Err(error) = self.quantum_loop.acquire_internal_debug_run() {
            report.guest_introspection_activation_failure = Some(format!(
                "scheduler ownership acquisition failed before guest activation: {error}"
            ));
            reply.complete(Ok(report));
            if matches!(self.state, EngineState::Running) {
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            return;
        }
        if let Err(error) = self.quantum_loop.activate_debug_guest(node.clone()) {
            let mut reason = error.to_string();
            if let Err(release_error) = self.quantum_loop.release_internal_debug_run() {
                reason.push_str(&format!(
                    "; scheduler ownership release also failed: {release_error}"
                ));
            }
            report.guest_introspection_activation_failure = Some(reason);
            reply.complete(Ok(report));
            if matches!(self.state, EngineState::Running) {
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            return;
        }

        self.active_step = None;
        self.state = EngineState::Running;
        self.pending_guest_activation = Some(PendingGuestActivation {
            node,
            started_quanta: self.quanta,
            report,
            reply,
        });
        if let Err(error) = self.poll_pending_guest_activation() {
            self.fail_pending_guest_activation(format!(
                "guest feature negotiation failed after activation: {error}"
            ));
            self.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }
    }

    pub(crate) fn poll_pending_guest_activation(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        let Some(mut pending) = self.pending_guest_activation.take() else {
            return Ok(());
        };
        let response = self.receive_guest_channel_response(
            &pending.node,
            GUEST_INTROSPECTION_FEATURE_CHANNEL_ID,
        )?;
        if let Some(record) = response {
            match record.message() {
                GuestIntrospectionMessage::Features(features) => {
                    pending.report.guest_introspection_features = Some(*features);
                    self.guest_features.insert(pending.node.clone(), *features);
                }
                _ => {
                    pending.record_guest_activation_failure(String::from(
                        "reserved feature channel returned a non-feature response",
                    ));
                }
            }
            if !matches!(self.state, EngineState::Stopped { .. }) {
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            self.finish_guest_activation(pending);
            return Ok(());
        }

        let elapsed = self.quanta.saturating_sub(pending.started_quanta);
        let stopped = matches!(self.state, EngineState::Stopped { .. });
        if elapsed >= GUEST_ACTIVATION_QUANTUM_LIMIT || stopped {
            pending.record_guest_activation_failure(
                if stopped {
                    String::from("runtime stopped before the guest agent advertised features")
                } else {
                    format!(
                        "no feature advertisement within {GUEST_ACTIVATION_QUANTUM_LIMIT} scheduler quanta"
                    )
                },
            );
            self.finish_guest_activation(pending);
            if !stopped {
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            return Ok(());
        }

        self.pending_guest_activation = Some(pending);
        Ok(())
    }

    pub(crate) fn fail_pending_guest_activation(&mut self, reason: String)
    where
        L: QuantumLoop,
    {
        if let Some(mut pending) = self.pending_guest_activation.take() {
            pending.record_guest_activation_failure(reason);
            self.finish_guest_activation(pending);
        }
    }

    fn finish_guest_activation(&mut self, mut pending: PendingGuestActivation)
    where
        L: QuantumLoop,
    {
        if let Err(error) = self.quantum_loop.release_internal_debug_run() {
            let release_failure = format!("scheduler ownership release failed: {error}");
            let reason = pending
                .report
                .guest_introspection_activation_failure
                .take()
                .map_or(release_failure.clone(), |reason| {
                    format!("{reason}; {release_failure}")
                });
            pending.record_guest_activation_failure(reason);
            self.guest_features.remove(&pending.node);
        }
        pending.reply.complete(Ok(pending.report));
    }

    pub(super) fn validate_guest_capability(
        &self,
        node: &NodeId,
        message: &GuestIntrospectionMessage,
    ) -> Result<(), SessionError> {
        let Some(features) = self.guest_features.get(node).copied() else {
            return Err(SessionError::GuestIntrospectionActivation {
                node: node.name.clone(),
                reason: String::from("fork-time feature negotiation has not completed"),
            });
        };
        let missing = match message {
            GuestIntrospectionMessage::Exec { .. } if !features.argv_exec() => Some("argv-exec"),
            GuestIntrospectionMessage::Pty { .. } if !features.pty() => Some("pty"),
            GuestIntrospectionMessage::Resize { .. } if !features.resize() => Some("resize"),
            GuestIntrospectionMessage::Ssh { .. } if !features.ssh_bridge() => Some("ssh-bridge"),
            _ => None,
        };
        match missing {
            Some(capability) => Err(SessionError::GuestIntrospectionCapabilityUnavailable {
                node: node.name.clone(),
                capability,
            }),
            None => Ok(()),
        }
    }

    pub(super) fn validate_guest_channel_capacity(
        &self,
        node: &NodeId,
        message: &GuestIntrospectionMessage,
    ) -> Result<(), SessionError> {
        if !matches!(
            message,
            GuestIntrospectionMessage::Exec { .. }
                | GuestIntrospectionMessage::Pty { .. }
                | GuestIntrospectionMessage::Ssh { .. }
        ) {
            return Ok(());
        }
        let Some(features) = self.guest_features.get(node).copied() else {
            return Ok(());
        };
        let active = self
            .guest_channels
            .iter()
            .filter(|(active_node, _)| active_node == node)
            .count();
        if active >= usize::from(features.max_channels()) {
            return Err(SessionError::GuestIntrospectionChannelLimit {
                node: node.name.clone(),
                max_channels: features.max_channels(),
            });
        }
        Ok(())
    }

    pub(crate) fn begin_guest_channel_run(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if self.guest_channel_run_active {
            return Ok(());
        }
        self.quantum_loop.acquire_internal_debug_run()?;
        self.guest_channel_run_active = true;
        self.active_step = None;
        self.state = EngineState::Running;
        Ok(())
    }

    pub(super) fn abort_empty_guest_channel_run(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if !self.guest_channels.is_empty() || !self.guest_channel_run_active {
            return Ok(());
        }
        self.quantum_loop.release_internal_debug_run()?;
        self.guest_channel_run_active = false;
        if !matches!(self.state, EngineState::Stopped { .. }) {
            self.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }
        Ok(())
    }

    fn finish_guest_channel_run_if_idle(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        if !self.guest_channels.is_empty() || !self.guest_channel_run_active {
            return Ok(());
        }
        self.quantum_loop.release_internal_debug_run()?;
        self.guest_channel_run_active = false;
        if !matches!(self.state, EngineState::Stopped { .. }) {
            self.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }
        Ok(())
    }

    pub(crate) fn close_guest_channels_for_reposition(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        self.fail_pending_guest_activation(String::from(
            "debug runtime reposition closed pending guest activation",
        ));
        self.guest_responses.clear();
        self.guest_features.clear();
        self.record_guest_channel_closures(String::from(
            "debug runtime reposition closed the guest channel",
        ));
        if self.guest_channel_run_active {
            self.quantum_loop.release_internal_debug_run()?;
            self.guest_channel_run_active = false;
        }
        if !matches!(self.state, EngineState::Stopped { .. }) {
            self.state = EngineState::Paused {
                reason: PauseReason::UserRequested,
            };
        }
        Ok(())
    }

    pub(super) fn resolve_guest_introspection_for_terminal(&mut self)
    where
        L: QuantumLoop,
    {
        self.fail_pending_guest_activation(String::from(
            "session terminated before guest activation completed",
        ));
        self.guest_features.clear();
        self.record_guest_channel_closures(String::from(
            "session terminated before the guest channel completed",
        ));
        if self.guest_channel_run_active && self.quantum_loop.release_internal_debug_run().is_ok() {
            self.guest_channel_run_active = false;
        }
    }

    fn record_guest_channel_closures(&mut self, message: String) {
        for (node, channel_id) in std::mem::take(&mut self.guest_channels) {
            let record = GuestIntrospectionRecord::new(
                channel_id,
                GuestIntrospectionMessage::Error {
                    code: GuestIntrospectionFailureCode::ClosedChannel,
                    message: message.clone(),
                },
            );
            if let Ok(record) = record {
                self.guest_responses
                    .entry((node, channel_id))
                    .or_default()
                    .push_back(record);
            }
        }
    }
}

fn guest_response_is_terminal(record: &GuestIntrospectionRecord) -> bool {
    matches!(
        record.message(),
        GuestIntrospectionMessage::Exit { .. } | GuestIntrospectionMessage::Error { .. }
    )
}
