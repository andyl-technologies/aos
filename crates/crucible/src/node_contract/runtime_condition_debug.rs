//! Live effect fencing at an authentic condition cut without terminal closure.

use std::collections::BTreeMap;

use crucible_node_contract::{Id, Validate, canonical};

use super::*;
use crate::node_contract::{
    AuthenticatedConditionStop, ConditionStopRecord, NativeConditionStopInventory, PhysicalState,
    SavedConditionStop, condition_debug::ConditionStopState,
};
use crate::node_contract::{ProgressEvidence, PublicationStatus};

impl NodeRuntime {
    /// Authenticates a common actual stopped cut and retains an independent fence.
    ///
    /// Future native and coordinator work remains owned and represented. All
    /// outstanding original operations and staged inputs must already be settled;
    /// physical suspension is separately authenticated by every actual adapter.
    /// Dropping the returned permit never reopens ordinary execution.
    ///
    /// # Errors
    /// Refuses foreign authority, unavailable original condition evidence,
    /// noncommon native cuts, uncertain or outstanding custody, unsupported
    /// external/epoch/fault/terminal combinations and finite resource limits.
    pub fn condition_stop_barrier(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        node: &Id,
        operation: Id,
        maximum_bytes: usize,
    ) -> Result<AuthenticatedConditionStop, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        if self.condition_stop.is_some() || self.terminal.is_some() || self.has_fault_scope() {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::UnsupportedFacet,
            ));
        }
        if maximum_bytes == 0
            || maximum_bytes > 64 * 1024 * 1024
            || self.nodes.len() > 256
            || self
                .operations
                .len()
                .saturating_add(self.input_batches.len())
                .saturating_add(2)
                > self.limits.maximum_operations
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        operation
            .validate()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        if self.operations.contains_key(&operation) || self.input_batches.contains_key(&operation) {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::DuplicateOperation,
            ));
        }
        if self.owners.values().any(|owner| owner.operation.is_some() || owner.lifecycle != Lifecycle::Stopped)
            || self.operations.values().any(|entry| !matches!(entry.result, RetainedResult::Acknowledged(_))
                && !matches!(&entry.result, RetainedResult::Failed(failure) if failure.effects == EffectKnowledge::None))
            || self.input_batches.values().any(|input| !input.committed || input.failure.is_some())
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::OutstandingObligations));
        }
        self.checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        let _ = self
            .facet(node, FacetKind::Debugging)
            .map_err(RuntimePollFailure::Admission)?;
        let hit = self.read_condition_hit(activation, node)?;
        if !self.input_batches.values().any(|input| {
            input.committed
                && input.failure.is_none()
                && input.batch.node() == node
                && input.provenance.is_some()
                && input.batch.deliveries().contains(&hit.input)
        }) {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        // Check identities before any native inventory callback. The fence has
        // its own admission; no terminal EOF permission is reused here.
        if !self
            .scheduler(graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .condition_identity_available(&operation)
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::DuplicateOperation,
            ));
        }
        let inventories = self.read_condition_inventory(activation, maximum_bytes)?;
        let (cut, _) = self
            .scheduler(graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .condition_stop_scope(&inventories, maximum_bytes)
            .map_err(RuntimePollFailure::Admission)?;
        if hit.evaluation > cut || hit.input.consumer != *node {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidTiming));
        }
        self.check_condition_inventory_unchanged(activation, &inventories, maximum_bytes)?;
        if self.read_condition_hit(activation, node)? != hit {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        // This permanently consumes only the original control identity. It
        // grants no run interval and cannot hide an outstanding reservation.
        self.scheduler(graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .retain_condition_identity(operation.clone())
            .map_err(RuntimePollFailure::Admission)?;
        let (_, scheduler) = self
            .scheduler(graph, activation)
            .map_err(RuntimePollFailure::Admission)?
            .condition_stop_scope(&inventories, maximum_bytes)
            .map_err(RuntimePollFailure::Admission)?;
        let record = ConditionStopRecord {
            version: 1,
            operation,
            node: node.clone(),
            source: activation.record().into(),
            cut,
            hit,
            scheduler,
            native: inventories.into_values().collect(),
        };
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&record)
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?,
        )
        .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        if bytes.len() > maximum_bytes {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        self.condition_stop = Some(ConditionStopState {
            saved: SavedConditionStop {
                record: record.clone(),
                reference: reference.clone(),
                submitted: false,
                report: None,
                publication: None,
                acknowledged: false,
                resume_operation: None,
                resume_receipt: None,
                resume_publication: None,
                resumed: false,
            },
            publication_verified_for: None,
        });
        Ok(AuthenticatedConditionStop {
            authority: Rc::clone(&self.authority),
            activation: activation.clone(),
            record,
            reference,
            maximum_bytes,
        })
    }

    /// Returns historical original control facts without minting live authority.
    pub fn condition_stop_checkpoint(&self) -> Option<&SavedConditionStop> {
        self.condition_stop.as_ref().map(|state| &state.saved)
    }

    /// Reads an acknowledged original Stop's complete scheduler at its unchanged cut.
    ///
    /// The returned edition-four snapshot retains future deliveries, exact
    /// payload bodies, producer/native sequences and original input/ACK custody.
    /// It creates no execution or resume permission. Installed native archive
    /// verification remains mandatory before fresh reconstruction.
    ///
    /// # Errors
    /// Refuses foreign activation, an incomplete or resumed Stop, a changed cut,
    /// unsupported pending control, exhausted credit or changed original queues.
    pub fn condition_scheduler_snapshot(
        &self,
        activation: &WorldActivation,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
        maximum_bytes: usize,
    ) -> Result<crate::node_scheduling::SchedulingSnapshot, RuntimeError> {
        self.validate_activation(activation)?;
        let saved = &self
            .condition_stop
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .saved;
        if !saved.submitted
            || !saved.acknowledged
            || saved.resumed
            || saved.resume_operation.is_some()
            || saved.record.cut != cut
            || saved.record.source != SavedRuntimeActivation::from(activation.record())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .condition_capture_snapshot(saved, ordinal, maximum_bytes)
    }

    pub(super) fn condition_fenced(&self) -> bool {
        self.condition_stop
            .as_ref()
            .is_some_and(|state| !state.saved.resumed)
    }

    fn read_condition_hit(
        &self,
        activation: &WorldActivation,
        node: &Id,
    ) -> Result<crate::node_adapters::ConditionHitCandidate, RuntimePollFailure> {
        let snapshot = self
            .snapshots
            .get(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let handle = self
            .nodes
            .get(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        snapshot
            .validate_current(handle.as_ref())
            .map_err(RuntimePollFailure::Admission)?;
        let hit = handle
            .observe_condition_hit(activation)
            .map_err(RuntimePollFailure::Native)?
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::UnsupportedFacet,
            ))?;
        handle
            .validate_condition_hit(activation, &hit)
            .map_err(RuntimePollFailure::Native)?;
        Ok(hit)
    }

    /// Reads actual stopped native custody without issuing a condition fence.
    ///
    /// The record may contain future inputs or local work; it establishes
    /// neither EOF nor terminal closure and cannot authorize report or resume.
    ///
    /// # Errors
    /// Refuses a foreign activation, unqualified node, outstanding custody,
    /// changed native source inventory or exhausted complete byte credit.
    pub fn observe_condition_inventory(
        &mut self,
        activation: &WorldActivation,
        node: &Id,
        maximum_bytes: usize,
    ) -> Result<NativeConditionStopInventory, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        if maximum_bytes == 0 || maximum_bytes > 64 << 20 {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        self.read_condition_inventory(activation, maximum_bytes)?
            .remove(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))
    }

    fn read_condition_inventory(
        &mut self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<BTreeMap<Id, NativeConditionStopInventory>, RuntimePollFailure> {
        let mut remaining = maximum_bytes;
        let mut inventories = BTreeMap::new();
        let nodes: Vec<_> = self.nodes.keys().cloned().collect();
        for id in nodes {
            let route = self
                .checked_route(&id)
                .map_err(RuntimePollFailure::Admission)?;
            let handle = self
                .nodes
                .get_mut(&id)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let snapshot = self
                .snapshots
                .get(&id)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidRoute))?;
            snapshot
                .validate_current(handle.as_ref())
                .map_err(RuntimePollFailure::Admission)?;
            let status = handle.status().map_err(RuntimePollFailure::Native)?;
            let inventory = handle
                .observe_condition_stop(activation, remaining)
                .map_err(RuntimePollFailure::Native)?;
            if status.lifecycle != Lifecycle::Stopped
                || status.physical != PhysicalState::Suspended
                || status.boundary != Some(inventory.boundary)
                || inventory.boundary.validate().is_err()
                || inventory.node != id
                || inventory.owners != route.owners
                || inventory.receipt.bytes.is_empty()
                || inventory.receipt.bytes.len() > remaining
                || inventory
                    .receipt
                    .reference
                    .verify(&inventory.receipt.bytes)
                    .is_err()
            {
                self.contain_roster(&route);
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            handle
                .validate_condition_stop(activation, &inventory)
                .map_err(RuntimePollFailure::Native)?;
            snapshot
                .validate_current(handle.as_ref())
                .map_err(RuntimePollFailure::Admission)?;
            let mut unique = std::collections::BTreeMap::new();
            for object in std::iter::once(&inventory.receipt).chain(&inventory.proof_objects) {
                if object.reference.verify(&object.bytes).is_err() {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                if let Some(previous) = unique.insert(&object.reference, object.bytes.as_slice())
                    && previous != object.bytes.as_slice()
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
            }
            let complete_bytes = unique
                .values()
                .try_fold(0usize, |count, bytes| count.checked_add(bytes.len()))
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            remaining = remaining
                .checked_sub(complete_bytes)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            inventories.insert(id, inventory);
        }
        Ok(inventories)
    }

    fn check_condition_inventory_unchanged(
        &mut self,
        activation: &WorldActivation,
        expected: &BTreeMap<Id, NativeConditionStopInventory>,
        maximum_bytes: usize,
    ) -> Result<(), RuntimePollFailure> {
        let current = self.read_condition_inventory(activation, maximum_bytes)?;
        if current == *expected {
            return Ok(());
        }
        for (id, original) in expected {
            if current.get(id) != Some(original)
                && let Some(route) = self
                    .snapshots
                    .get(id)
                    .map(|snapshot| snapshot.route.clone())
            {
                self.contain_roster(&route);
            }
        }
        Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))
    }
}

impl NodeRuntime {
    pub(super) fn validate_condition_dispatch(
        &self,
        node: &Id,
        operation: &Id,
        request: &OperationRequest,
    ) -> Result<(), RuntimeError> {
        let Some(state) = &self.condition_stop else {
            return if matches!(request, OperationRequest::DebugConditionV1(_)) {
                Err(RuntimeError::ForeignAuthority)
            } else {
                Ok(())
            };
        };
        if state.saved.resumed {
            return if matches!(request, OperationRequest::DebugConditionV1(_)) {
                Err(RuntimeError::ForeignAuthority)
            } else {
                Ok(())
            };
        }
        let OperationRequest::DebugConditionV1(control) = request else {
            return Err(RuntimeError::OutstandingObligations);
        };
        if node != &state.saved.record.node {
            return Err(RuntimeError::ForeignAuthority);
        }
        let valid = match control.as_ref() {
            crate::node_contract::ConditionControlRequest::Stop { barrier, receipt } => {
                state.saved.submitted
                    && operation == &state.saved.record.operation
                    && barrier.as_ref() == &state.saved.record
                    && receipt == &state.saved.reference
            }
            crate::node_contract::ConditionControlRequest::Resume {
                stop_operation,
                barrier,
                report,
            } => {
                state.saved.acknowledged
                    && state.publication_verified_for.as_ref()
                        == Some(&state.saved.record.operation)
                    && state.saved.resume_operation.as_ref() == Some(operation)
                    && stop_operation == &state.saved.record.operation
                    && barrier == &state.saved.reference
                    && state.saved.report.as_ref().map(|body| &body.reference) == Some(report)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(RuntimeError::ForeignAuthority)
        }
    }

    /// Submits the original native stop report under the retained live fence.
    ///
    /// # Errors
    /// Refuses foreign permits, changed current native/coordinator scope,
    /// reused submissions or unavailable actual native condition control.
    pub fn begin_condition_stop(
        &mut self,
        stop: AuthenticatedConditionStop,
    ) -> Result<BeginResult, RuntimePollFailure> {
        self.validate_activation(&stop.activation)
            .map_err(RuntimePollFailure::Admission)?;
        if !Rc::ptr_eq(&self.authority, &stop.authority) {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let saved = &self
            .condition_stop
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved;
        if saved.submitted || saved.record != stop.record || saved.reference != stop.reference {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let inventories = stop
            .record
            .native
            .iter()
            .map(|native| (native.node.clone(), native.clone()))
            .collect();
        let maximum_bytes = stop.maximum_bytes;
        self.check_condition_inventory_unchanged(&stop.activation, &inventories, maximum_bytes)?;
        let (_, scheduler) = self
            .scheduler
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?
            .condition_stop_scope(&inventories, maximum_bytes)
            .map_err(RuntimePollFailure::Admission)?;
        if scheduler != stop.record.scheduler
            || self.read_condition_hit(&stop.activation, &stop.record.node)? != stop.record.hit
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        self.condition_stop
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved
            .submitted = true;
        let node = stop.record.node.clone();
        self.begin_with_inputs(
            &stop.activation,
            &node,
            stop.record.operation.clone(),
            OperationRequest::DebugConditionV1(Box::new(
                crate::node_contract::ConditionControlRequest::Stop {
                    barrier: Box::new(stop.record),
                    receipt: stop.reference,
                },
            )),
            None,
        )
        .map_err(RuntimePollFailure::Admission)
    }

    /// Reads an authentic original candidate without asserting stopped-world authority.
    ///
    /// # Errors
    /// Refuses foreign activation, unavailable native qualification or changed
    /// owner/condition evidence. Absence of a hit does not authorize any progress.
    pub fn condition_hit_candidate(
        &mut self,
        activation: &WorldActivation,
        node: &Id,
    ) -> Result<Option<crate::node_adapters::ConditionHitCandidate>, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        let handle = self
            .nodes
            .get(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let hit = handle
            .observe_condition_hit(activation)
            .map_err(RuntimePollFailure::Native)?;
        if let Some(hit) = &hit {
            handle
                .validate_condition_hit(activation, hit)
                .map_err(RuntimePollFailure::Native)?;
        }
        Ok(hit)
    }

    /// Reads a native frontier without advancing or turning missing events into EOF.
    ///
    /// # Errors
    /// Refuses foreign activation, a live stop fence, busy native owners,
    /// unsupported complete observation, changed scope and finite byte limits.
    pub fn observe_condition_frontier(
        &mut self,
        activation: &WorldActivation,
        node: &Id,
        maximum_bytes: usize,
    ) -> Result<crate::node_contract::NativeConditionEventFrontier, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        if self.condition_fenced()
            || self.terminal.is_some()
            || self.has_fault_scope()
            || maximum_bytes == 0
            || maximum_bytes > 64 * 1024 * 1024
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::UnsupportedFacet,
            ));
        }
        let route = self
            .checked_route(node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        let handle = self
            .nodes
            .get_mut(node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let status = handle.status().map_err(RuntimePollFailure::Native)?;
        let frontier = handle
            .observe_condition_frontier(activation, maximum_bytes)
            .map_err(RuntimePollFailure::Native)?;
        if status.lifecycle != Lifecycle::Stopped
            || status.physical != PhysicalState::Suspended
            || status.boundary != Some(frontier.boundary)
            || frontier.node != *node
            || frontier.owners != route.owners
            || frontier.receipt.bytes.is_empty()
            || frontier.receipt.bytes.len() > maximum_bytes
            || frontier
                .receipt
                .reference
                .verify(&frontier.receipt.bytes)
                .is_err()
            || frontier
                .next
                .is_some_and(|next| next < frontier.boundary || next.validate().is_err())
        {
            self.contain_roster(&route);
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        handle
            .validate_condition_frontier(activation, &frontier)
            .map_err(RuntimePollFailure::Native)?;
        Ok(frontier)
    }

    /// Publishes exact original report or resume roots before native acknowledgement.
    ///
    /// Historical successful publication is always reconciled in the current
    /// trusted store. Failure preserves original ACK/history but returns no new
    /// permit and leaves the world fenced; an unwind retains uncertainty too.
    ///
    /// # Errors
    /// Refuses foreign tokens, unavailable original native results, changed
    /// immutable objects and exhausted complete-result byte credit.
    pub fn publish_condition_result(
        &mut self,
        token: &OperationToken,
        publisher: &mut dyn crate::node_contract::ConditionResultPublisher,
        maximum_bytes: usize,
    ) -> Result<
        (
            PublicationStatus,
            Option<crate::node_contract::ConditionResultCommit>,
        ),
        RuntimePollFailure,
    > {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        let state = self
            .condition_stop
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        let outcome = match &entry.result {
            RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) => {
                outcome.clone()
            }
            _ => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        let ProgressEvidence::DebugConditionAppliedV1 {
            reached,
            stop_operation,
            barrier,
            report,
            control,
            resumed,
        } = &outcome.progress
        else {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        };
        if *reached != state.saved.record.cut
            || stop_operation != &state.saved.record.operation
            || barrier != &state.saved.reference
            || token.route().node != state.saved.record.node
            || !resumed && token.operation() != &state.saved.record.operation
            || *resumed && state.saved.resume_operation.as_ref() != Some(token.operation())
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        let resumed = *resumed;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&state.saved.record)
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?,
        )
        .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let original_barrier = crate::node_scheduling::InputPayload {
            reference: barrier.clone(),
            bytes,
        };
        let mut remaining = maximum_bytes
            .checked_sub(original_barrier.bytes.len())
            .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let original_report = match &state.saved.report {
            Some(body)
                if body.reference == *report
                    && body.reference.verify(&body.bytes).is_ok()
                    && body.bytes.len() <= remaining =>
            {
                body.clone()
            }
            Some(_) => return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt)),
            None if resumed => {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            None => self
                .operation_evidence(
                    token,
                    std::slice::from_ref(report),
                    crucible_node_contract::U64::new(remaining as u64),
                )?
                .pop()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?,
        };
        remaining = remaining
            .checked_sub(original_report.bytes.len())
            .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let resume = if resumed {
            let saved = self
                .condition_stop
                .as_ref()
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ))?;
            Some(match &saved.saved.resume_receipt {
                Some(body)
                    if body.reference == *control
                        && body.reference.verify(&body.bytes).is_ok()
                        && body.bytes.len() <= remaining =>
                {
                    body.clone()
                }
                Some(_) => return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt)),
                None => self
                    .operation_evidence(
                        token,
                        std::slice::from_ref(control),
                        crucible_node_contract::U64::new(remaining as u64),
                    )?
                    .pop()
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?,
            })
        } else {
            None
        };
        let state = self
            .condition_stop
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        state.saved.report = Some(original_report.clone());
        if resume.is_some() {
            state.saved.resume_receipt = resume.clone();
        }
        state.publication_verified_for = None;
        let historical = if resumed {
            state.saved.resume_publication
        } else {
            state.saved.publication
        };
        if historical != Some(crate::node_contract::ConditionPublicationState::Committed) {
            if resumed {
                state.saved.resume_publication =
                    Some(crate::node_contract::ConditionPublicationState::Unknown);
            } else {
                state.saved.publication =
                    Some(crate::node_contract::ConditionPublicationState::Unknown);
            }
        }
        let dependencies: Vec<_> = state.saved.record.dependency_objects().collect();
        let status = match (&resume, historical) {
            (Some(resume), Some(_)) => publisher.reconcile_resume_complete(
                &original_barrier,
                &original_report,
                resume,
                &dependencies,
            ),
            (Some(resume), None) => publisher.publish_resume_complete(
                &original_barrier,
                &original_report,
                resume,
                &dependencies,
            ),
            (None, Some(_)) => {
                publisher.reconcile_complete(&original_barrier, &original_report, &dependencies)
            }
            (None, None) => {
                publisher.publish_complete(&original_barrier, &original_report, &dependencies)
            }
        };
        state.publication_verified_for =
            (status == PublicationStatus::Committed).then(|| token.operation().clone());
        if historical != Some(crate::node_contract::ConditionPublicationState::Committed) {
            let publication = Some(match status {
                PublicationStatus::Committed => {
                    crate::node_contract::ConditionPublicationState::Committed
                }
                PublicationStatus::NotCommitted => {
                    crate::node_contract::ConditionPublicationState::NotCommitted
                }
                PublicationStatus::Unknown => {
                    crate::node_contract::ConditionPublicationState::Unknown
                }
            });
            if resumed {
                state.saved.resume_publication = publication;
            } else {
                state.saved.publication = publication;
            }
        }
        let commit = (status == PublicationStatus::Committed).then(|| {
            crate::node_contract::ConditionResultCommit {
                authority: Rc::clone(&self.authority),
                operation: token.operation().clone(),
                barrier: original_barrier.reference,
                report: original_report.reference,
                resume: resume.map(|body| body.reference),
            }
        });
        Ok((status, commit))
    }

    /// Acknowledges the same durably rooted original stop or resume control.
    ///
    /// # Errors
    /// Refuses foreign or historical-only permits, changed current store proofs,
    /// unavailable original native receipts and uncertain native acknowledgement.
    pub fn acknowledge_condition_result(
        &mut self,
        token: &OperationToken,
        commit: &crate::node_contract::ConditionResultCommit,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        let state = self
            .condition_stop
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        if !Rc::ptr_eq(&self.authority, &commit.authority)
            || commit.operation != *token.operation()
            || commit.barrier != state.saved.reference
            || state.publication_verified_for.as_ref() != Some(&commit.operation)
            || state.saved.report.as_ref().map(|report| &report.reference) != Some(&commit.report)
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let resumed = match &commit.resume {
            None if token.operation() == &state.saved.record.operation => false,
            Some(receipt)
                if state.saved.resume_operation.as_ref() == Some(token.operation())
                    && state
                        .saved
                        .resume_receipt
                        .as_ref()
                        .map(|body| &body.reference)
                        == Some(receipt) =>
            {
                true
            }
            _ => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ));
            }
        };
        self.acknowledge(token, &[])?;
        let state = self
            .condition_stop
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        if resumed {
            state.saved.resumed = true;
        } else {
            state.saved.acknowledged = true;
        }
        Ok(())
    }

    /// Begins one original native resume after current durable roots and stop ACK.
    ///
    /// # Errors
    /// Refuses changed or reused controls, missing current durability, unsettled
    /// stop custody and unsupported native resume; uncertainty keeps the fence.
    pub fn begin_condition_resume(
        &mut self,
        activation: &WorldActivation,
        operation: Id,
    ) -> Result<BeginResult, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        operation
            .validate()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let state = self
            .condition_stop
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        if !state.saved.acknowledged
            || state.publication_verified_for.as_ref() != Some(&state.saved.record.operation)
            || state.saved.resumed
            || state.saved.resume_operation.is_some()
            || self.operations.contains_key(&operation)
            || self.input_batches.contains_key(&operation)
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let node = state.saved.record.node.clone();
        let request = crate::node_contract::ConditionControlRequest::Resume {
            stop_operation: state.saved.record.operation.clone(),
            barrier: state.saved.reference.clone(),
            report: state
                .saved
                .report
                .as_ref()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?
                .reference
                .clone(),
        };
        self.scheduler
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?
            .retain_condition_identity(operation.clone())
            .map_err(RuntimePollFailure::Admission)?;
        self.condition_stop
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved
            .resume_operation = Some(operation.clone());
        self.begin_with_inputs(
            activation,
            &node,
            operation,
            OperationRequest::DebugConditionV1(Box::new(request)),
            None,
        )
        .map_err(RuntimePollFailure::Admission)
    }
}
