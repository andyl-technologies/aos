//! Guest-introspection response brokering, activation, and channel lifecycle.

use super::*;

impl<L> Engine<L> {
    pub(super) fn receive_guest_channel_response(
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
            let terminal = matches!(
                record.message(),
                GuestIntrospectionMessage::Exit { .. } | GuestIntrospectionMessage::Error { .. }
            );
            if terminal {
                self.guest_channels.remove(&record_key);
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
        if let Err(error) = self.quantum_loop.activate_debug_guest(node.clone()) {
            report.guest_introspection_activation_failure = Some(error.to_string());
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
                    pending.report.guest_introspection_activation_failure = Some(String::from(
                        "reserved feature channel returned a non-feature response",
                    ));
                }
            }
            if !matches!(self.state, EngineState::Stopped { .. }) {
                self.state = EngineState::Paused {
                    reason: PauseReason::UserRequested,
                };
            }
            pending.reply.complete(Ok(pending.report));
            return Ok(());
        }

        let elapsed = self.quanta.saturating_sub(pending.started_quanta);
        let stopped = matches!(self.state, EngineState::Stopped { .. });
        if elapsed >= GUEST_ACTIVATION_QUANTUM_LIMIT || stopped {
            pending.guest_activation_failure(
                if stopped {
                    String::from("runtime stopped before the guest agent advertised features")
                } else {
                    format!(
                        "no feature advertisement within {GUEST_ACTIVATION_QUANTUM_LIMIT} scheduler quanta"
                    )
                },
            );
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

    pub(crate) fn fail_pending_guest_activation(&mut self, reason: String) {
        if let Some(mut pending) = self.pending_guest_activation.take() {
            pending.guest_activation_failure(reason);
        }
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

    pub(crate) fn close_guest_channels_for_reposition(&mut self) {
        self.guest_responses.clear();
        self.guest_features.clear();
        for (node, channel_id) in std::mem::take(&mut self.guest_channels) {
            let record = GuestIntrospectionRecord::new(
                channel_id,
                GuestIntrospectionMessage::Error {
                    code: GuestIntrospectionFailureCode::ClosedChannel,
                    message: String::from("debug runtime reposition closed the guest channel"),
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
