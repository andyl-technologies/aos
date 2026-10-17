//! Retains complete private controlled-model histories without release authority.

use super::*;

impl<C: ControlledReference> ControlledReferenceNode<C> {
    pub(super) fn original_retirement_history(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if self.thread != std::thread::current().id()
            || self.role_process != std::process::id()
            || maximum_bytes == 0
        {
            return Err(no_effect(
                "controlled history has foreign original ownership",
            ));
        }
        let native_credit = self
            .child
            .retirement_history_credit()
            .ok_or_else(|| no_effect("controlled native history codec is unsupported"))?;
        let total_credit = native_credit
            .checked_add(64 * 1024 * 1024)
            .filter(|credit| *credit <= maximum_bytes)
            .ok_or_else(|| no_effect("controlled complete history credit is unavailable"))?;
        let windows = self.windows.values().map(|window| {
            serde_json::json!({
                "operation": window.original.token().operation(),
                "request": window.original.request(),
                "activation": SavedRuntimeActivation::from(window.original.activation().record()),
                "input": input(&window.input),
                "grant": window.grant,
                "receipt": window.receipt,
                "outcome": window.outcome,
                "evidence": window.evidence,
                "acknowledged": window.acknowledged,
                "failure": window.failure,
            })
        }).collect::<Vec<_>>();
        let bytes = json_bytes(&serde_json::json!({
            "schema": "crucible.private-controlled-model-history.v1",
            "descriptor": self.descriptor,
            "binding": self.binding,
            "route": {"node": self.route.node, "owners": self.route.owners},
            "world_binding": self.world_hash,
            "quantum_ps": self.quantum_ps.to_string(),
            "host_budget_ns": self.host_budget_ns.to_string(),
            "next_quantum": self.next_quantum,
            "boundary": self.boundary,
            "ready": self.ready.as_ref().map(|(activation, ready)| (
                SavedRuntimeActivation::from(activation), ready,
            )),
            "staged": self.staged.as_ref().map(|stage| serde_json::json!({
                "input": input(&stage.original), "bytes": stage.bytes,
                "acknowledgement": stage.acknowledgement,
                "custody_path": match stage.custody_path {
                    InputCustodyPath::HostOwned => "host_owned",
                    InputCustodyPath::ExternalChild => "external_child",
                },
            })),
            "windows": windows,
            "active": self.active,
            "maximum_operations": self.maximum_operations,
            "reclaimed": self.reclaimed.as_ref().map(|receipt| (
                &receipt.owner, &receipt.receipt,
            )),
            "quarantined": self.quarantined,
            "graceful_retirement": self.graceful_retirement,
            "boundary_evidence": self.boundary_evidence.values().collect::<Vec<_>>(),
            "boundary_evidence_activation": self.boundary_evidence_activation.as_ref()
                .map(|activation| SavedRuntimeActivation::from(activation.record())),
            "observation": self.observation.as_ref().map(|(activation, observation)| (
                SavedRuntimeActivation::from(activation.record()), observation,
            )),
        }))?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(no_effect("controlled model history exceeds source credit"));
        }
        let mut bodies = self.child.retirement_history(native_credit)?;
        let native_bytes = bodies.iter().try_fold(0usize, |total, body| {
            body.reference
                .verify(&body.bytes)
                .map_err(|error| no_effect(&error.to_string()))?;
            total
                .checked_add(body.bytes.len())
                .filter(|total| *total <= native_credit)
                .ok_or_else(|| no_effect("controlled native history exceeded original credit"))
        })?;
        if bodies.is_empty()
            || bodies.len() >= 16
            || native_bytes
                .checked_add(bytes.len())
                .is_none_or(|total| total > total_credit)
        {
            return Err(no_effect("controlled original history inventory changed"));
        }
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| no_effect(&error.to_string()))?;
        bodies.push(InputPayload { reference, bytes });
        Ok(bodies)
    }
}

fn input(batch: &RuntimeInputBatch) -> serde_json::Value {
    serde_json::json!({
        "node": batch.node(), "stage_operation": batch.stage_operation(),
        "batch": batch.batch(), "owners": batch.owners(), "cutoff": batch.cutoff(),
        "inventory": batch.inventory(), "deliveries": batch.deliveries(),
        "payloads": batch.payloads(),
    })
}
