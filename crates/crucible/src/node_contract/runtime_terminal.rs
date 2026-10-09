//! Whole-world terminal fencing without horizon-based quiescence or replacement work.

use std::collections::BTreeMap;

use crucible_node_contract::{Id, U64, Validate, canonical};

use super::*;

use crate::node_contract::{
    AuthenticatedWorldTerminal, NativeTerminalInventory, PhysicalState, ProgressEvidence,
    PublicationStatus, SavedWorldTerminal, WorldTerminalRecord, terminal::TerminalState,
};

impl NodeRuntime {
    /// Authenticates complete live terminal scope and retains an effects fence.
    ///
    /// The cut is derived from actual owner positions. Native EOF and drained
    /// input closure must cover the complete admitted world, and all current
    /// operations, publication ACKs and input obligations must be discharged.
    /// A provider must independently authenticate every native inventory.
    ///
    /// # Errors
    /// Refuses unsupported native terminal observation, incomplete closure,
    /// original outstanding custody, changed scope, reused identities or limits.
    pub fn terminal_barrier(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        node: &Id,
        operation: Id,
        maximum_bytes: usize,
    ) -> Result<AuthenticatedWorldTerminal, RuntimeError> {
        self.validate_activation(activation)?;
        if self.terminal.is_some()
            || self.operations.contains_key(&operation)
            || self.input_batches.contains_key(&operation)
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        if maximum_bytes == 0
            || maximum_bytes > 16 * 1024 * 1024
            || self.nodes.len() > 256
            || self
                .operations
                .len()
                .saturating_add(self.input_batches.len())
                >= self.limits.maximum_operations
        {
            return Err(RuntimeError::ResourceLimit);
        }
        if self
            .owners
            .values()
            .any(|owner| owner.operation.is_some() || owner.lifecycle != Lifecycle::Stopped)
            || self.operations.values().any(|operation| {
                !matches!(operation.result, RetainedResult::Acknowledged(_))
                    && !matches!(
                        &operation.result,
                        RetainedResult::Failed(failure) if failure.effects == EffectKnowledge::None
                    )
            })
            || self
                .input_batches
                .values()
                .any(|input| !input.committed || input.failure.is_some())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        operation
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !self
            .scheduler(graph, activation)?
            .terminal_identity_available(&operation)
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.checked_route(node)?;
        let _ = self.facet(node, FacetKind::TerminalAssertions)?;
        self.scheduler(graph, activation)?
            .terminal_preflight(maximum_bytes)?;
        let inventories = self.read_terminal_inventory(activation, maximum_bytes)?;
        let (cut, scheduler) = self
            .scheduler(graph, activation)?
            .terminal_closure(&inventories, maximum_bytes)?;
        self.validate_terminal_inventory_unchanged(activation, &inventories, maximum_bytes)?;
        let record = WorldTerminalRecord {
            version: 1,
            operation,
            node: node.clone(),
            source: activation.record().into(),
            cut,
            scheduler,
            native: inventories.into_values().collect(),
        };
        let value = serde_json::to_value(&record).map_err(|_| RuntimeError::InvalidReceipt)?;
        let bytes = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if bytes.len() > maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // Retain the original coordinator identity only after complete scope
        // and byte preflight succeeds. The historical barrier describes the
        // unchanged pre-submission state; no grant or progress is fabricated.
        self.scheduler(graph, activation)?
            .retain_terminal_identity(record.operation.clone())?;
        self.terminal = Some(TerminalState {
            saved: SavedWorldTerminal {
                record: record.clone(),
                reference: reference.clone(),
                submitted: false,
                report: None,
                publication: None,
                acknowledged: false,
            },
        });
        Ok(AuthenticatedWorldTerminal {
            authority: Rc::clone(&self.authority),
            activation: activation.clone(),
            record,
            reference,
        })
    }

    /// Returns original terminal fence facts without minting restored authority.
    pub fn terminal_checkpoint(&self) -> Option<&SavedWorldTerminal> {
        self.terminal.as_ref().map(|terminal| &terminal.saved)
    }

    /// Reads the fenced original scheduler for explicit terminal-bearing capture.
    ///
    /// This read grants no scheduling permission and never settles work. The
    /// selected archive adapter separately verifies complete native custody.
    ///
    /// # Errors
    /// Refuses foreign activation, absent terminal fence or invalid capture cut.
    pub fn terminal_scheduler_snapshot(
        &self,
        activation: &WorldActivation,
        cut: crucible_node_contract::Position,
        ordinal: U64,
    ) -> Result<crate::node_scheduling::SchedulingSnapshot, RuntimeError> {
        self.validate_activation(activation)?;
        if self
            .terminal
            .as_ref()
            .map(|terminal| terminal.saved.record.cut)
            != Some(cut)
        {
            return Err(RuntimeError::InvalidTiming);
        }
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .snapshot(cut, ordinal)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    /// Submits the original terminal operation under its retained live fence.
    ///
    /// Dropped permits, changed public records and operation retries never
    /// manufacture a replacement admission. Native scope is rechecked before
    /// the original submission. Failure leaves the complete world fenced.
    ///
    /// # Errors
    /// Refuses foreign authority, changed live native state, reused submissions
    /// or an unsupported actual terminal assertion implementation.
    pub fn begin_terminal_assertions(
        &mut self,
        terminal: AuthenticatedWorldTerminal,
    ) -> Result<BeginResult, RuntimeError> {
        self.validate_activation(&terminal.activation)?;
        if !Rc::ptr_eq(&self.authority, &terminal.authority) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let saved = &self
            .terminal
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .saved;
        if saved.submitted
            || saved.record != terminal.record
            || saved.reference != terminal.reference
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let expected: BTreeMap<_, _> = terminal
            .record
            .native
            .iter()
            .map(|inventory| (inventory.node.clone(), inventory.clone()))
            .collect();
        let maximum_bytes = usize::try_from(terminal.reference.length.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.validate_terminal_inventory_unchanged(&terminal.activation, &expected, maximum_bytes)?;
        self.terminal
            .as_mut()
            .ok_or(RuntimeError::ForeignAuthority)?
            .saved
            .submitted = true;
        let node = terminal.record.node.clone();
        self.begin_with_inputs(
            &terminal.activation,
            &node,
            terminal.record.operation.clone(),
            OperationRequest::FinalizeAssertions {
                barrier: Box::new(terminal.record),
                receipt: terminal.reference,
            },
            None,
        )
    }

    fn validate_terminal_inventory_unchanged(
        &mut self,
        activation: &WorldActivation,
        expected: &BTreeMap<Id, NativeTerminalInventory>,
        maximum_bytes: usize,
    ) -> Result<(), RuntimeError> {
        let current = self.read_terminal_inventory(activation, maximum_bytes)?;
        if &current == expected {
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
        Err(RuntimeError::InvalidReceipt)
    }

    fn read_terminal_inventory(
        &mut self,
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<BTreeMap<Id, NativeTerminalInventory>, RuntimeError> {
        let mut inventories = BTreeMap::new();
        let mut remaining = maximum_bytes;
        let ids: Vec<_> = self.nodes.keys().cloned().collect();
        for id in ids {
            let route = self.checked_route(&id)?;
            let observed = {
                let node = self.nodes.get_mut(&id).ok_or(RuntimeError::UnknownNode)?;
                let snapshot = self.snapshots.get(&id).ok_or(RuntimeError::InvalidRoute)?;
                snapshot.validate_current(node.as_ref())?;
                node.status().and_then(|status| {
                    node.observe_terminal(activation, remaining)
                        .map(|inventory| (status, inventory))
                })
            };
            let (status, inventory) = match observed {
                Ok(observed) => observed,
                Err(failure) => {
                    if failure.effects != EffectKnowledge::None {
                        self.contain_roster(&route);
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    return Err(RuntimeError::UnsupportedFacet);
                }
            };
            let valid = status.lifecycle == Lifecycle::Stopped
                && status.physical == PhysicalState::Suspended
                && status.boundary == Some(inventory.boundary)
                && inventory.boundary.validate().is_ok()
                && inventory.node == id
                && inventory.owners == route.owners
                && inventory.receipt.reference.validate().is_ok()
                && inventory.receipt.reference.length.get() != 0
                && inventory
                    .receipt
                    .reference
                    .verify(&inventory.receipt.bytes)
                    .is_ok()
                && self.nodes.get(&id).is_some_and(|node| {
                    node.validate_terminal(activation, &inventory).is_ok()
                        && self.snapshots.get(&id).is_some_and(|snapshot| {
                            snapshot.validate_current(node.as_ref()).is_ok()
                        })
                });
            if !valid {
                self.contain_roster(&route);
                return Err(RuntimeError::InvalidReceipt);
            }
            remaining = remaining
                .checked_sub(inventory.receipt.bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            inventories.insert(id, inventory);
        }
        Ok(inventories)
    }
}

impl NodeRuntime {
    /// Publishes or reconciles the original native terminal report under its fence.
    ///
    /// The first attempt retains uncertainty before calling trusted storage.
    /// Later calls reconcile the same exact report and never resubmit native
    /// finalization. Only a durable committed result produces an ACK permit.
    ///
    /// # Errors
    /// Refuses foreign tokens, incomplete original results, changed receipts,
    /// unsupported authentic native evidence reads and finite byte overruns.
    pub fn publish_terminal_result(
        &mut self,
        token: &OperationToken,
        publisher: &mut dyn crate::node_contract::TerminalResultPublisher,
        maximum_bytes: usize,
    ) -> Result<
        (
            PublicationStatus,
            Option<crate::node_contract::TerminalResultCommit>,
        ),
        RuntimePollFailure,
    > {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        if maximum_bytes == 0 || maximum_bytes > 16 * 1024 * 1024 {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        let saved = &self
            .terminal
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved;
        if saved.record.operation != *token.operation() || saved.record.node != token.route().node {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        let outcome = match &entry.result {
            RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) => outcome,
            _ => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        let ProgressEvidence::AssertionsFinalized {
            barrier, report, ..
        } = &outcome.progress
        else {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        };
        if barrier != &saved.reference {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        let report_reference = report.clone();
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&saved.record)
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?,
        )
        .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let remaining = maximum_bytes
            .checked_sub(bytes.len())
            .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let barrier = crate::node_scheduling::InputPayload {
            reference: saved.reference.clone(),
            bytes,
        };
        let report = if let Some(report) = &saved.report {
            if report.reference != report_reference || report.bytes.len() > remaining {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            report.clone()
        } else {
            let mut objects =
                self.operation_evidence(token, &[report_reference], U64::new(remaining as u64))?;
            objects
                .pop()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?
        };
        let saved = &mut self
            .terminal
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved;
        saved.report = Some(report.clone());
        let original_publication = saved.publication;
        if original_publication != Some(crate::node_contract::TerminalPublicationState::Committed) {
            // An interrupted trusted-storage call must retain uncertainty. A
            // previously authenticated committed marker remains source history,
            // never current-store authority; it is reconciled on every call.
            saved.publication = Some(crate::node_contract::TerminalPublicationState::Unknown);
        }
        let status = match original_publication {
            // A historical committed marker describes the original store. It
            // cannot mint fresh ACK authority when current roots are absent or
            // corrupt; every saved attempt must authenticate actual durability.
            Some(_) => publisher.reconcile(&barrier, &report),
            None => publisher.publish(&barrier, &report),
        };
        // Fresh-store absence cannot erase the authenticated original successful
        // publication or ACK. Returned status and the new opaque permit reflect
        // current durability; the archived marker preserves source history.
        if original_publication != Some(crate::node_contract::TerminalPublicationState::Committed) {
            saved.publication = Some(match status {
                PublicationStatus::Committed => {
                    crate::node_contract::TerminalPublicationState::Committed
                }
                PublicationStatus::NotCommitted => {
                    crate::node_contract::TerminalPublicationState::NotCommitted
                }
                PublicationStatus::Unknown => {
                    crate::node_contract::TerminalPublicationState::Unknown
                }
            });
        }
        let commit = (status == PublicationStatus::Committed).then(|| {
            crate::node_contract::TerminalResultCommit {
                authority: Rc::clone(&self.authority),
                operation: token.operation().clone(),
                node: token.route().node.clone(),
                barrier: barrier.reference,
                report: report.reference,
            }
        });
        Ok((status, commit))
    }

    /// Acknowledges only the original durably published terminal result.
    ///
    /// A failed native ACK retains the report, fence and publication permit for
    /// an idempotent retry. Successful ACK keeps the finalized marker and does
    /// not reopen the world for new effects.
    ///
    /// # Errors
    /// Refuses foreign permits, unmatched original receipts, uncommitted results
    /// or native ACK failure while preserving complete original custody.
    pub fn acknowledge_terminal_result(
        &mut self,
        token: &OperationToken,
        commit: &crate::node_contract::TerminalResultCommit,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        let saved = &self
            .terminal
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved;
        if !Rc::ptr_eq(&self.authority, &commit.authority)
            || commit.operation != *token.operation()
            || commit.node != token.route().node
            || commit.barrier != saved.reference
            || saved.report.as_ref().map(|report| &report.reference) != Some(&commit.report)
            || saved.publication != Some(crate::node_contract::TerminalPublicationState::Committed)
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        self.acknowledge(token, &[])?;
        self.terminal
            .as_mut()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?
            .saved
            .acknowledged = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "runtime_terminal_inventory_tests.rs"]
mod tests;
