//! Non-consuming lifecycle publication preflight.

use super::*;

impl ProductionFaultRuntime {
    /// Previews lifecycle actions that can publish host-owned work at one boundary.
    ///
    /// The result includes actions selected by this boundary and active QEMU
    /// rules whose node owns an undrained occurrence. It does not consume the
    /// event transport or mutate the evaluator or action ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when preview evaluation fails,
    /// an active node transport cannot be inspected, an action resolves to a
    /// non-node target, or bounded intent storage cannot be reserved.
    pub fn preview_node_lifecycle_intents(
        &self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<Vec<QemuNodeLifecycleIntent>, ProductionFaultRuntimeError> {
        let mut intents = Vec::new();
        let preview = self
            .runtime
            .as_ref()
            .map(|runtime| runtime.preview_boundary(coordinate, same_coordinate_sequence))
            .transpose()?;
        let preview_actions = preview
            .as_ref()
            .map_or([].as_slice(), |evaluation| evaluation.actions.as_slice());
        let maximum = self
            .qemu_issued_actions
            .len()
            .checked_add(preview_actions.len())
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?;
        intents.try_reserve_exact(maximum).map_err(|_| {
            runtime_collection_reservation("event_records", 0, maximum, self.resource_limits)
        })?;
        for action in self
            .qemu_issued_actions
            .iter()
            .filter_map(|(identity, action)| {
                self.qemu_active_rule_ids
                    .iter()
                    .any(|active| active == identity)
                    .then_some(action)
            })
            .chain(preview_actions.iter())
        {
            let requested_transition = match action.effect.specification() {
                EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                    transition,
                    ..
                }) => Some(*transition),
                EffectSpecification::Node(NodeEffectSpecification::Hang {
                    watchdog_policy: NodeWatchdogPolicy::TransitionAfter { transition, .. },
                    ..
                }) => Some(*transition),
                _ => None,
            };
            let Some(requested_transition) = requested_transition else {
                continue;
            };
            let action_identity = action.id();
            if intents
                .iter()
                .any(|intent: &QemuNodeLifecycleIntent| intent.action == action_identity)
            {
                continue;
            }
            let ResolvedFaultTarget::Node { node } = &action.target else {
                return Err(BackendError::Rejected {
                    message: format!(
                        "lifecycle action `{}` resolved to a non-node target",
                        action.binding
                    ),
                }
                .into());
            };
            let selected_now = preview_actions
                .iter()
                .any(|candidate| candidate.id() == action_identity);
            let retained_event_pending =
                self.pending_qemu_events
                    .iter()
                    .any(|(pending_node, events)| {
                        pending_node.name == node.as_str() && !events.is_empty()
                    });
            if !selected_now
                && !retained_event_pending
                && !nodes.fault_event_pending_by_name(node.as_str())?
            {
                continue;
            }
            self.resource_limits.reserve(
                "nodes",
                u64::try_from(intents.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "nodes",
                        value: u64::MAX,
                    }
                })?,
                1,
            )?;
            intents.push(QemuNodeLifecycleIntent {
                node: NodeId {
                    name: try_clone_string(node.as_str(), || {
                        runtime_collection_reservation(
                            "nodes",
                            intents.len(),
                            1,
                            self.resource_limits,
                        )
                    })?,
                },
                action: action_identity,
                requested_transition,
            });
        }
        intents.sort_unstable_by(|left, right| {
            left.node
                .cmp(&right.node)
                .then_with(|| left.action.bytes.cmp(&right.action.bytes))
        });
        if intents.windows(2).any(|pair| pair[0].node == pair[1].node) {
            return Err(BackendError::Rejected {
                message: String::from(
                    "one boundary retains more than one lifecycle-capable action for one node",
                ),
            }
            .into());
        }
        Ok(intents)
    }
}
