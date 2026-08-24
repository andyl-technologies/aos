//! Non-consuming lifecycle publication preflight.

use super::*;

impl ProductionFaultRuntime {
    /// Previews lifecycle actions that can publish host-owned work at one boundary.
    ///
    /// The result includes direct lifecycle actions selected by this boundary
    /// and exact lifecycle decisions authenticated from an undrained QEMU
    /// occurrence. It does not mutate the evaluator or action ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when preview evaluation fails,
    /// a node event cannot be drained and authenticated, an action resolves to
    /// a non-node target, or bounded intent storage cannot be reserved.
    pub fn preview_node_lifecycle_intents(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<Vec<QemuNodeLifecycleIntent>, ProductionFaultRuntimeError> {
        if self.lifecycle_work_in_flight.is_some() {
            return Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork);
        }
        self.apply_event_staging_capacity(nodes, &[], None)?;
        self.drain_qemu_observations(nodes, coordinate, 0)?;
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
            .pending_node_lifecycle
            .len()
            .checked_add(preview_actions.len())
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?;
        intents.try_reserve_exact(maximum).map_err(|_| {
            runtime_collection_reservation("event_records", 0, maximum, self.resource_limits)
        })?;
        for decision in &self.pending_node_lifecycle {
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
                node: try_clone_ledger_node_id(&decision.node, || {
                    runtime_collection_reservation("nodes", intents.len(), 1, self.resource_limits)
                })?,
                action: decision.action,
                requested_transition: decision.requested_transition,
            });
        }
        for action in preview_actions {
            let EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: requested_transition,
                ..
            }) = action.effect.specification()
            else {
                continue;
            };
            if action.kind != BindingActionKind::Apply {
                continue;
            }
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
                requested_transition: *requested_transition,
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
