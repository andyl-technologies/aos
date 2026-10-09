//! Complete installed host-model terminal inventory and once-only finalization.

use super::*;

use crate::node_scheduling::InputPayload;

impl HostModelNode {
    pub(super) fn terminal_inventory(
        &self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<NativeTerminalInventory, OperationFailure> {
        if !self.facets.contains(&FacetKind::Introspection)
            || !self.same_world(activation)
            || self.quarantined
            || self
                .completed
                .values()
                .any(|original| !original.acknowledged)
            || self
                .failed
                .values()
                .any(|(_, failure)| failure.effects != EffectKnowledge::None)
            || self
                .staged
                .as_ref()
                .is_some_and(|input| input.consumed != input.original.deliveries().len())
            || !self.pending_causes.is_empty()
        {
            return Err(failure(
                "host complete terminal scope is unsupported or undrained",
            ));
        }
        let disposition = match self.model.as_ref() {
            Some(HostModel::Clock(_)) => NativeTerminalDisposition::Unconditional,
            Some(HostModel::ScriptedSource(source))
                if source.cursor() == source.requests().len() && !source.evaluated() =>
            {
                NativeTerminalDisposition::Unconditional
            }
            Some(HostModel::Io(io)) if io.pending_completion_keys().next().is_none() => {
                NativeTerminalDisposition::InputsDrained
            }
            Some(HostModel::Link(link)) if link.inflight_len() == 0 => {
                NativeTerminalDisposition::InputsDrained
            }
            Some(HostModel::Semantics(model)) if model.next_position().is_none() => {
                NativeTerminalDisposition::InputsDrained
            }
            _ => return Err(failure("host original future native work remains")),
        };
        let native = self.capture_continuation()?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format": "crucible.host-terminal-inventory",
            "version": 1,
            "activation": SavedRuntimeActivation::from(activation.record()),
            "node": self.route.node,
            "owners": self.route.owners,
            "boundary": self.boundary,
            "disposition": disposition,
            "native": crucible_node_contract::Bytes::new(native),
        }))
        .map_err(|error| failure(&error.to_string()))?;
        if bytes.is_empty() || bytes.len() > maximum_bytes {
            return Err(failure(
                "complete host terminal inventory exceeds admitted ceiling",
            ));
        }
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        Ok(NativeTerminalInventory {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            boundary: self.boundary,
            disposition,
            receipt: InputPayload { reference, bytes },
        })
    }

    pub(super) fn begin_finalization(&mut self, admission: &OperationAdmission) -> Submission {
        let run = || -> Result<_, OperationFailure> {
            if !self.facets.contains(&FacetKind::TerminalAssertions)
                || !self.same_world(admission.activation())
                || self.quarantined
                || admission.token().route() != &self.route
                || self.completed.contains_key(admission.token().operation())
                || self.failed.contains_key(admission.token().operation())
                || self.completed.len() >= self.limits.maximum_operations
            {
                return Err(failure(
                    "host finalization lacks original available custody",
                ));
            }
            let Some(HostModel::Semantics(model)) = self.model.as_ref() else {
                return Err(failure("host model has no selected terminal evaluator"));
            };
            let OperationRequest::FinalizeAssertions { barrier, receipt } = admission.request()
            else {
                return Err(failure("host finalization request mismatch"));
            };
            // The installed host terminal codec is qualified only at one
            // authentic common cut. It cannot label an older evaluator boundary
            // with a later Clock position or manufacture an aligning native RUN.
            if self.boundary != barrier.cut
                || barrier
                    .native
                    .iter()
                    .any(|native| native.boundary != barrier.cut)
            {
                return Err(failure(
                    "host terminal codec requires one unchanged native cut",
                ));
            }
            let mut staged = model.clone();
            let report = staged.finalize(admission)?;
            let bytes = canonical::canonical_json(
                &serde_json::to_value(barrier).map_err(|error| failure(&error.to_string()))?,
            )
            .map_err(|error| failure(&error.to_string()))?;
            let evidence = vec![
                InputPayload {
                    reference: receipt.clone(),
                    bytes,
                },
                report.clone(),
            ];
            let retained_bytes = self
                .completed
                .values()
                .flat_map(|completed| &completed.evidence)
                .chain(&evidence)
                .try_fold(0usize, |size, object| size.checked_add(object.bytes.len()));
            if retained_bytes.is_none_or(|bytes| bytes > self.limits.maximum_capture_bytes) {
                return Err(failure(
                    "host original terminal report exceeds custody ceiling",
                ));
            }
            let outcome = OperationOutcome {
                operation: admission.token().operation().clone(),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                progress: ProgressEvidence::AssertionsFinalized {
                    reached: barrier.cut,
                    barrier: receipt.clone(),
                    report: report.reference,
                },
                retained_outputs: Vec::new(),
                scheduling: None,
            };
            Ok((staged, outcome, evidence))
        };
        match run() {
            Err(error) => Submission::Refused(Refusal {
                reason: error.reason,
            }),
            Ok((model, outcome, evidence)) => {
                self.model = Some(HostModel::Semantics(model));
                self.activation_authority = Some(Rc::clone(&admission.activation.authority));
                self.completed.insert(
                    outcome.operation.clone(),
                    Completed {
                        original: admission.clone(),
                        outcome,
                        capture: None,
                        acknowledged: false,
                        evidence,
                    },
                );
                Submission::Accepted
            }
        }
    }
}
