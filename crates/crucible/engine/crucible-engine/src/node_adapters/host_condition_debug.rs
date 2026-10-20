//! Actual stopped host custody and original canonical condition-control effects.

use super::*;
use crate::node_scheduling::InputPayload;

impl HostModelNode {
    fn condition_scope_available(
        &self,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        if self.terminal_inventory.0.as_str() != HOST_CONDITION_INVENTORY_PROFILE
            || !self.facets.contains(&FacetKind::Introspection)
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
        {
            return Err(failure(
                "selected condition inventory lacks settled stopped native custody",
            ));
        }
        match self.model.as_ref() {
            Some(
                HostModel::Clock(_)
                | HostModel::ScriptedSource(_)
                | HostModel::ConditionObserver(_),
            ) => {}
            Some(HostModel::Io(io)) if io.block_device().is_some() => {}
            _ => {
                return Err(failure(
                    "condition stop policy does not qualify this native model",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn condition_hit(
        &self,
        activation: &WorldActivation,
    ) -> Result<Option<super::super::ConditionHitCandidate>, OperationFailure> {
        if !self.facets.contains(&FacetKind::Debugging)
            || !self.same_world(activation)
            || self.quarantined
        {
            return Err(failure(
                "selected condition observer lacks actual native ownership",
            ));
        }
        let Some(HostModel::ConditionObserver(model)) = self.model.as_ref() else {
            return Err(failure("actual condition evaluator is absent"));
        };
        if !model.awaiting_control() {
            return Ok(None);
        }
        Ok(model.candidate().cloned())
    }

    pub(super) fn condition_inventory(
        &self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<NativeConditionStopInventory, OperationFailure> {
        self.condition_scope_available(activation)?;
        if self
            .staged
            .as_ref()
            .is_some_and(|input| input.consumed != input.original.deliveries().len())
        {
            return Err(failure("condition stop still retains current staged input"));
        }
        let native = self.capture_continuation().map_err(|error| {
            failure(&format!(
                "{}; {}",
                error.reason,
                self.condition_storage_summary()
            ))
        })?;
        let (mut store, roots) = super::super::condition_debug_model::dag::EvidenceDag::decode(
            &native,
            condition_state::maximum_objects(self.limits.maximum_operations)?,
            self.limits.maximum_capture_bytes,
        )?;
        if roots.len() != 1 {
            return Err(failure(
                "condition native inventory lacks its single original index",
            ));
        }
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format": "crucible.host-condition-stop-inventory",
            "version": 1,
            "activation": SavedRuntimeActivation::from(activation.record()),
            "node": self.route.node,
            "owners": self.route.owners,
            "boundary": self.boundary,
            "native": roots[0],
        }))
        .map_err(|error| failure(&error.to_string()))?;
        let reference = store.add(&bytes, "application/json", roots)?;
        let complete = store.encode(vec![reference.clone()])?;
        if complete.len() > maximum_bytes {
            return Err(failure(
                "condition native inventory complete DAG credit exhausted",
            ));
        }
        let proof_objects = store
            .objects()
            .filter(|object| object.reference != reference)
            .map(|object| InputPayload {
                reference: object.reference.clone(),
                bytes: object.bytes.as_slice().to_vec(),
            })
            .collect();
        Ok(NativeConditionStopInventory {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            boundary: self.boundary,
            receipt: InputPayload { reference, bytes },
            proof_objects,
        })
    }

    pub(super) fn condition_frontier(
        &self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<NativeConditionEventFrontier, OperationFailure> {
        self.condition_scope_available(activation)?;
        let autonomous = match self.model.as_ref() {
            Some(HostModel::ScriptedSource(source)) => source.next_position(),
            Some(HostModel::Io(io)) => io
                .next_exact_local_event()
                .map(|time| Position::new(time.into(), 0.into(), Phase::Reaction)),
            Some(HostModel::Clock(_) | HostModel::ConditionObserver(_)) => None,
            _ => return Err(failure("condition native frontier policy differs")),
        };
        let staged = match self
            .staged
            .as_ref()
            .and_then(|input| input.original.deliveries().get(input.consumed))
        {
            Some(delivery) => Some(Position::new(
                delivery.delivery.time_ps,
                delivery
                    .delivery
                    .microstep
                    .checked_add(1.into())
                    .map_err(|error| failure(&error.to_string()))?,
                Phase::Reaction,
            )),
            None => None,
        };
        let next = match (autonomous, staged) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if next.is_some_and(|next| next < self.boundary) {
            return Err(failure(
                "condition frontier omits original overdue native work",
            ));
        }
        let native = self.capture_continuation().map_err(|error| {
            failure(&format!(
                "{}; {}",
                error.reason,
                self.condition_storage_summary()
            ))
        })?;
        let native_reference = canonical::content_ref(&native, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format": "crucible.host-condition-event-frontier",
            "version": 1,
            "activation": SavedRuntimeActivation::from(activation.record()),
            "node": self.route.node,
            "owners": self.route.owners,
            "boundary": self.boundary,
            "next": next,
            // The trusted adapter retains the full bounded native ledger and
            // rechecks its exact commitment on validation. A frontier query
            // needs no second opaque-byte encoding of that whole ledger.
            "native": native_reference,
        }))
        .map_err(|error| failure(&error.to_string()))?;
        if bytes.is_empty() || bytes.len() > maximum_bytes {
            return Err(failure("condition native frontier byte credit exhausted"));
        }
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        Ok(NativeConditionEventFrontier {
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            boundary: self.boundary,
            next,
            receipt: InputPayload { reference, bytes },
        })
    }

    fn condition_storage_summary(&self) -> String {
        let mut objects = std::collections::BTreeMap::new();
        let mut entries = 0usize;
        let mut bytes = 0usize;
        for object in self
            .completed
            .values()
            .flat_map(|completed| &completed.evidence)
        {
            entries = entries.saturating_add(1);
            bytes = bytes.saturating_add(object.bytes.len());
            objects
                .entry(&object.reference)
                .or_insert(object.bytes.len());
        }
        let unique = objects
            .values()
            .fold(0usize, |total, bytes| total.saturating_add(*bytes));
        let model = self.capture().map(|bytes| bytes.len());
        format!(
            "node={} original_operations={} evidence_entries={} evidence_bytes={} unique_objects={} unique_bytes={} native_model_bytes={model:?}",
            self.route.node,
            self.completed.len(),
            entries,
            bytes,
            objects.len(),
            unique
        )
    }

    pub(super) fn begin_condition_control(&mut self, admission: &OperationAdmission) -> Submission {
        let run = || -> Result<_, OperationFailure> {
            if !self.facets.contains(&FacetKind::Debugging)
                || !self.same_world(admission.activation())
                || self.quarantined
                || admission.token().route() != &self.route
                || self.completed.contains_key(admission.token().operation())
                || self.failed.contains_key(admission.token().operation())
                || self.completed.len().saturating_add(self.failed.len())
                    >= self.limits.maximum_operations
            {
                return Err(failure(
                    "condition original control lacks native custody credit",
                ));
            }
            let Some(HostModel::ConditionObserver(model)) = self.model.as_ref() else {
                return Err(failure("condition control has no actual native evaluator"));
            };
            let OperationRequest::DebugConditionV1(request) = admission.request() else {
                return Err(failure("condition control grammar differs"));
            };
            let (stop_operation, barrier, report, resumed) = match request.as_ref() {
                ConditionControlRequest::Stop { barrier, receipt } => {
                    (barrier.operation.clone(), receipt.clone(), None, false)
                }
                ConditionControlRequest::Resume {
                    stop_operation,
                    barrier,
                    report,
                } => {
                    let original = self
                        .completed
                        .get(stop_operation)
                        .ok_or_else(|| failure("condition native stop result is absent"))?;
                    if !original.acknowledged
                        || !matches!(&original.outcome.progress,
                        ProgressEvidence::DebugConditionAppliedV1 { resumed: false, barrier: actual, report: body, .. }
                            if actual == barrier && body == report)
                    {
                        return Err(failure(
                            "condition report has not authentically settled original native custody",
                        ));
                    }
                    (
                        stop_operation.clone(),
                        barrier.clone(),
                        Some(report.clone()),
                        true,
                    )
                }
            };
            let mut staged = model.clone();
            let control = staged.native_control(admission)?;
            let report = report.unwrap_or_else(|| control.reference.clone());
            let mut evidence = Vec::new();
            if let ConditionControlRequest::Stop {
                barrier: record,
                receipt,
            } = request.as_ref()
            {
                let bytes = canonical::canonical_json(
                    &serde_json::to_value(record).map_err(|error| failure(&error.to_string()))?,
                )
                .map_err(|error| failure(&error.to_string()))?;
                evidence.push(InputPayload {
                    reference: receipt.clone(),
                    bytes,
                });
            }
            if let ConditionControlRequest::Stop { barrier, .. } = request.as_ref() {
                for inventory in &barrier.native {
                    evidence.push(inventory.receipt.clone());
                    evidence.extend(inventory.proof_objects.iter().cloned());
                }
            }
            evidence.push(control.clone());
            self.check_condition_object_credit(&evidence)?;
            let outcome = OperationOutcome {
                operation: admission.token().operation().clone(),
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                progress: ProgressEvidence::DebugConditionAppliedV1 {
                    reached: self.boundary,
                    stop_operation,
                    barrier,
                    report,
                    control: control.reference,
                    resumed,
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
                let evidence = match self.retain_condition_objects(&outcome.operation, evidence) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        return Submission::Refused(Refusal {
                            reason: error.reason,
                        });
                    }
                };
                self.model = Some(HostModel::ConditionObserver(model));
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
