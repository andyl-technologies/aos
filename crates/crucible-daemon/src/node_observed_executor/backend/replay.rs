//! Original semantic replay dispatch and durable proof publication ordering.
//!
//! The owning backend distinguishes replay selection from fresh physical work.
//! It publishes only runtime-authenticated outcomes from the original semantic
//! plan, and persists their actual proof bytes before scheduler commitment.

use super::*;

impl NodeObservedBackend {
    /// Forms an observation backend from an installed original-source recipe.
    ///
    /// Original signed bodies are copied durably before activation. The actor
    /// then follows original semantic IDs under fresh runtime permissions. This
    /// conditional materialization retains origin nondeterminism and does not
    /// enable unconditional deterministic replay or minimization.
    ///
    /// # Errors
    /// Refuses changed planned context, incomplete prepared custody, nondurable
    /// original source storage or invalid conditional capability admission.
    pub fn from_conditional_replay(
        prepared: InstalledConditionalReplay,
        publisher: StoredWorldActivationPublisher,
        blobs: Arc<dyn ImmutableBlobBackend>,
        inputs: ContentId,
        execution: ExecutionId,
    ) -> Result<Self, NodeObservedError> {
        let InstalledConditionalReplay {
            world,
            configuration,
            plan,
            source_objects,
            original_world,
            source_context,
            activation,
        } = prepared;
        let mut backend = Self::from_prepared_with(
            world,
            configuration,
            blobs,
            inputs,
            execution,
            move |runtime, graph| {
                runtime.arm_all().map_err(native)?;
                let coordinator = runtime
                    .initial_coordinator_snapshot(graph, 1024 * 1024)
                    .map_err(native)?;
                let publisher = publisher.with_prepared_coordinator(
                    activation,
                    runtime.prepared_node_records().map_err(native)?.to_vec(),
                    coordinator,
                )?;
                Ok(Box::new(publisher))
            },
        )?;
        let mut roots = std::collections::BTreeMap::new();
        for (node, source) in source_objects {
            source.reference.verify(&source.bytes)?;
            let id = ContentId::for_bytes(ObjectKind::Trace, 1, &source.bytes);
            let receipt = backend
                .blobs
                .put_if_absent(id, &BlobHandle::from_bytes(source.bytes))?;
            if !receipt.is_durable() {
                return Err(NodeObservedError::Native(
                    "original replay source copy is not durable".into(),
                ));
            }
            backend.evidence_roots.insert(id);
            roots.insert(node.as_str().to_owned(), id);
        }
        backend.admission.capabilities = ExecutorNodeCapabilities::new(
            backend.admission.capabilities.roster().clone(),
            BTreeSet::from([NodeMaterializationStrategy::ConditionalTranscriptReplay]),
        )?;
        backend.admission.conditional = Some(ConditionalReplayScope::new(
            original_world,
            source_context,
            roots,
        )?);
        backend.replay = Some(plan);
        backend.prearmed = true;
        Ok(backend)
    }

    pub(super) fn poll_original_replay(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<(), NodeObservedError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| native("original replay runtime is contained"))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| native("original replay is inactive"))?;
        let plan = self
            .replay
            .as_mut()
            .ok_or_else(|| native("original semantic replay plan is absent"))?;
        match plan.poll(runtime, &self.graph, activation, context)? {
            ReplayStep::Waiting => {}
            ReplayStep::Progress { incoming } => {
                if let Some(incoming) = incoming {
                    retain_event(&mut self.incoming, &mut self.provenance_bytes, incoming)?;
                }
            }
            ReplayStep::Finished => {
                // Exhaustion is completion only if every actually admitted
                // model reached the original configured horizon.
                for node in self.graph.node_ids() {
                    if runtime
                        .scheduler(&self.graph, activation)?
                        .position(node)
                        .map_err(native)?
                        .time_ps
                        != self.configuration.horizon_ps
                    {
                        return Err(native(
                            "original transcript ended before the configured horizon",
                        ));
                    }
                }
                self.begin_completion(ObservedAttemptOutcome::Completed)?;
            }
            ReplayStep::Complete { node, outcome } => {
                let token = runtime.recover(&outcome.operation).map_err(native)?;
                let references = evidence_references(&outcome);
                let objects = runtime
                    .operation_evidence(&token, &references, U64::new(16 * 1024 * 1024))
                    .map_err(native)?;
                let event = serde_json::json!({
                    "operation":token.operation(),"objects":objects.into_iter().map(|object| serde_json::json!({
                        "reference":object.reference,"bytes":crucible_node_contract::Bytes::new(object.bytes)
                    })).collect::<Vec<_>>()
                });
                retain_event(
                    &mut self.native_evidence,
                    &mut self.provenance_bytes,
                    event.clone(),
                )?;
                retain_event(
                    &mut self.outgoing,
                    &mut self.provenance_bytes,
                    serde_json::to_value(outcome)?,
                )?;
                let bytes = canonical::canonical_json(&event)?;
                let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
                if !self
                    .blobs
                    .put_if_absent(id, &BlobHandle::from_bytes(bytes))?
                    .is_durable()
                {
                    return Err(native("original replay receipt copy is not durable"));
                }
                self.evidence_roots.insert(id);
                plan.commit_complete(&node, runtime)?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
type ReplayTestFrontier = Vec<(
    Id,
    crucible_node_contract::Position,
    Vec<crucible::node_scheduling::event::Delivery>,
)>;

#[cfg(test)]
impl NodeObservedBackend {
    pub(crate) fn test_replay_coordinator_frontier(
        &mut self,
    ) -> Result<ReplayTestFrontier, NodeObservedError> {
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| native("inactive replay"))?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| native("missing replay custody"))?;
        let scheduler = runtime.scheduler(&self.graph, activation)?;
        self.graph
            .node_ids()
            .map(|node| {
                Ok((
                    node.clone(),
                    scheduler.position(node)?,
                    scheduler
                        .pending_inputs(node)?
                        .into_iter()
                        .cloned()
                        .collect(),
                ))
            })
            .collect()
    }

    pub(crate) fn test_replay_original_receipt_is_uncommitted(
        &mut self,
        expected_proof: &serde_json::Value,
    ) -> Result<(), NodeObservedError> {
        let outcome: crucible::node_contract::OperationOutcome = serde_json::from_value(
            self.outgoing
                .last()
                .cloned()
                .ok_or_else(|| native("no retained original outcome"))?,
        )?;
        if outcome.retained_outputs.is_empty() {
            return Err(native(
                "fault did not reach a held original producer output",
            ));
        }
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| native("missing original custody"))?;
        let token = runtime.recover(&outcome.operation).map_err(native)?;
        runtime.scheduling_receipt(&token).map_err(native)?;
        if runtime.recover_scheduling_commit(&token).is_ok() {
            return Err(native(
                "uncertain proof write authorized scheduler publication",
            ));
        }
        let mut context = Context::from_waker(Waker::noop());
        let Poll::Ready(Ok(cached)) = runtime.poll(&token, &mut context) else {
            return Err(native(
                "original terminal outcome was lost after storage failure",
            ));
        };
        if cached != outcome {
            return Err(native(
                "original operation/window/outcome inventory changed after failure",
            ));
        }
        let objects = runtime
            .operation_evidence(
                &token,
                &evidence_references(&outcome),
                crucible_node_contract::U64::new(16 * 1024 * 1024),
            )
            .map_err(native)?;
        let retained = serde_json::json!({
            "operation":token.operation(),"objects":objects.iter().map(|object| serde_json::json!({
                "reference":object.reference,"bytes":crucible_node_contract::Bytes::new(object.bytes.clone()),
            })).collect::<Vec<_>>()
        });
        if &retained != expected_proof {
            return Err(native(
                "exact original raw receipt references/body changed after failure",
            ));
        }
        if objects.is_empty() {
            return Err(native(
                "original proof bodies were lost after uncertain placement",
            ));
        }
        Ok(())
    }
}
