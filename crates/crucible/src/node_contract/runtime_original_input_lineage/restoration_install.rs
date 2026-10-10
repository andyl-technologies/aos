//! Rebinds complete original Runtime7 ledgers after authentic target publication.
//!
//! FIRST ancestry remains immutable. Current batches and operation tokens use
//! actual fresh world authority only after both native endpoints authenticated
//! the same source context. No legacy snapshot projection or native replay occurs.

use super::*;
use crate::node_scheduling::{InputCustodyCommit, SchedulingCommit};
use std::collections::BTreeMap;

impl NodeRuntime {
    /// Prepares a paused coordinator from the exact opaque source context before readiness.
    ///
    /// The result owns original queues and reservations but cannot grant work.
    /// Callers retain it beside this same owning runtime through publication.
    ///
    /// # Errors
    /// Refuses changed native context, source scheduler, owner/input/permission
    /// closure or unsupported combined scheduler semantics.
    pub fn prepare_original_lineage_scheduler(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        context: &OriginalLineageRestoration<'_>,
        scheduling: crate::node_scheduling::SchedulingSnapshot,
    ) -> Result<crate::node_scheduling::PreparedSchedulingRestore, RuntimeError> {
        context.validate_current(self)?;
        if self.activated || self.scheduler.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        crate::node_scheduling::PreparedSchedulingRestore::prepare_original_lineage(
            graph, scheduling, context,
        )
        .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    /// Installs complete original runtime and coordinator custody beneath one published target.
    ///
    /// The scheduler is prepared from this same opaque source context before any
    /// model callback. No fresh grant or input is issued during installation.
    /// Any refusal preserves the owning runtime and complete original source.
    ///
    /// # Errors
    /// Refuses another source scheduler or target, widened original permissions,
    /// missing input/ACK custody, populated ledgers or unsupported native adapters.
    pub fn install_complete_original_lineage_restoration(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        context: &OriginalLineageRestoration<'_>,
        activation: &WorldActivation,
        scheduling: crate::node_scheduling::PreparedSchedulingRestore,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(activation)?;
        context.validate_current(self)?;
        if self.scheduler.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        scheduling
            .validate_original_lineage_context(context)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        // Retain the checked coordinator before installing model caches, so an
        // adapter failure cannot discard original queued deliveries/reservations.
        let scheduler = scheduling
            .activate(graph, activation)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        self.install_restored_scheduler(activation, scheduler)?;
        self.install_original_lineage_restoration(context, activation)
    }

    /// Installs complete original lineage beneath the actually published target.
    ///
    /// The source context must belong to this same runtime and remain validated.
    /// All original ledgers are retained before any adapter callback. A refusal
    /// contains the complete owning world; no Begin, Stage, Poll or ACK is resent.
    ///
    /// # Errors
    /// Refuses foreign authority, changed original journals, populated target
    /// ledgers, exhausted copy credit or unsupported native custody rebinding.
    pub fn install_original_lineage_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
        activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        self.validate_activation(activation)?;
        if !Rc::ptr_eq(&self.authority, &context.authority)
            || activation.record() != context.target()
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let result = (|| {
            context.validate_current(self)?;
            preflight_copies(context)?;
            let (inputs, handles) = restore_inputs(self, context, activation)?;
            let operations = restore_operations(self, context, activation, &handles)?;
            let owners = restore_owners(self, context)?;

            // Retain complete original journals before native installation. If
            // a callback fails or unwinds, the owning actor still has every
            // original token, batch, outcome and immutable lineage body.
            self.input_batches = inputs;
            self.operations = operations;
            self.owners = owners;
            for (node_id, native) in &mut self.nodes {
                let selected_operations = self
                    .operations
                    .values()
                    .filter(|operation| &operation.admission.token.route.node == node_id);
                let mut operations = reserve(selected_operations.clone().count())?;
                operations.extend(selected_operations.map(|operation| operation.admission.clone()));
                let selected_inputs = handles.values().filter(|input| input.node() == node_id);
                let mut inputs = reserve(selected_inputs.clone().count())?;
                inputs.extend(selected_inputs.cloned());
                native
                    .install_original_lineage_restored_custody(
                        context,
                        activation,
                        &operations,
                        &inputs,
                    )
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                for operation in self
                    .operations
                    .values()
                    .filter(|operation| &operation.admission.token.route.node == node_id)
                {
                    if let RetainedResult::Complete(outcome)
                    | RetainedResult::Acknowledged(outcome) = &operation.result
                    {
                        native
                            .validate_outcome(&operation.admission, outcome)
                            .map_err(|_| RuntimeError::InvalidReceipt)?;
                    }
                }
                for input in self
                    .input_batches
                    .values()
                    .filter(|input| input.batch.node() == node_id)
                {
                    if let Some(ack) = &input.acknowledgement {
                        native
                            .validate_input_acknowledgement(&input.batch, ack)
                            .map_err(|_| RuntimeError::InvalidReceipt)?;
                    }
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.contain_roster(&NodeRoute {
                node: activation.record().activation_id.clone(),
                owners: activation.record().owners.clone(),
            });
        }
        result
    }
}

fn preflight_copies(context: &OriginalLineageRestoration<'_>) -> Result<(), RuntimeError> {
    context.record.validate_original_bodies(
        context.content,
        context.limits.lineage,
        context.limits.maximum_record_bytes,
    )?;
    let mut remaining = context.limits.lineage.maximum_bytes;
    for input in &context.record.inputs {
        // One payload copy belongs to the current shared batch; the second is
        // retained by the runtime input ledger. All operation and native handle
        // views share the former, including the first-lineage association.
        for reference in input
            .payloads
            .iter()
            .chain(&input.payloads)
            .chain(input.provenance.iter().flat_map(|saved| &saved.objects))
            .chain(
                input
                    .lineage
                    .iter()
                    .flat_map(|saved| &saved.publications)
                    .flat_map(|publication| &publication.objects),
            )
        {
            remaining = remaining
                .checked_sub(
                    usize::try_from(reference.length.get())
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
    }
    Ok(())
}

fn copy_payloads(
    references: &[ContentRef],
    context: &OriginalLineageRestoration<'_>,
) -> Result<Vec<InputPayload>, RuntimeError> {
    let mut objects = reserve(references.len())?;
    for reference in references {
        let original = context
            .original_body(reference)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(original.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        bytes.extend_from_slice(original);
        objects.push(InputPayload {
            reference: reference.clone(),
            bytes,
        });
    }
    Ok(objects)
}

type RestoredInputLedgers = (
    BTreeMap<Id, super::super::super::inputs::RetainedInput>,
    BTreeMap<Id, Rc<RuntimeInputBatch>>,
);

fn restore_inputs(
    runtime: &NodeRuntime,
    context: &OriginalLineageRestoration<'_>,
    activation: &WorldActivation,
) -> Result<RestoredInputLedgers, RuntimeError> {
    let mut inputs = BTreeMap::new();
    let mut handles = BTreeMap::new();
    for saved in &context.record.inputs {
        let route = &runtime
            .snapshots
            .get(&saved.node)
            .ok_or(RuntimeError::UnknownNode)?
            .route;
        let batch = Rc::new(RuntimeInputBatch {
            activation: activation.clone(),
            node: saved.node.clone(),
            stage_operation: saved.stage_operation.clone(),
            batch: saved.batch.clone(),
            owners: route.owners.clone(),
            cutoff: saved.cutoff,
            inventory: saved.inventory.clone(),
            deliveries: saved.deliveries.clone(),
            payloads: copy_payloads(&saved.payloads, context)?,
        });
        let provenance = saved
            .provenance
            .as_ref()
            .map(|proof| -> Result<_, RuntimeError> {
                Ok(InputProvenanceClosure::restore_validated(
                    activation,
                    SavedInputProvenance {
                        schema_version: proof.schema_version,
                        node: proof.node.clone(),
                        stage_operation: proof.stage_operation.clone(),
                        batch: proof.batch.clone(),
                        inventory: proof.inventory.clone(),
                        roots: proof.roots.clone(),
                        objects: copy_payloads(&proof.objects, context)?,
                    },
                ))
            })
            .transpose()?;
        let lineage = saved
            .lineage
            .as_ref()
            .map(|original| -> Result<_, RuntimeError> {
                let mut publications = reserve(original.publications.len())?;
                for publication in &original.publications {
                    let bytes = context
                        .original_body(&publication.published)
                        .ok_or(RuntimeError::InvalidReceipt)?;
                    let event = canonical::decode(bytes, bytes.len())
                        .map_err(|_| RuntimeError::InvalidReceipt)?;
                    publications.push(OriginalPublicationClaim {
                        event,
                        origin: publication.origin.clone(),
                        published: publication.published.clone(),
                        objects: copy_payloads(&publication.objects, context)?,
                        rows: publication.rows.clone(),
                    });
                }
                Ok(OriginalInputLineage {
                    data: Rc::new(OriginalInputLineageData {
                        source_scope: original.source.clone(),
                        original: Rc::clone(&batch),
                        publications,
                    }),
                })
            })
            .transpose()?;
        let acknowledgement = context
            .scope
            .input_acknowledgements
            .iter()
            .find(|ack| ack.stage_operation == saved.stage_operation)
            .cloned();
        if acknowledgement.is_some() != saved.acknowledgement.is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let commit = saved.coordinator_committed.then(|| InputCustodyCommit {
            activation: activation.clone(),
            node: saved.node.clone(),
            stage_operation: saved.stage_operation.clone(),
            batch: saved.batch.clone(),
            inventory: saved.inventory.clone(),
            cutoff: saved.cutoff,
        });
        let owned_batch = RuntimeInputBatch {
            activation: activation.clone(),
            node: saved.node.clone(),
            stage_operation: saved.stage_operation.clone(),
            batch: saved.batch.clone(),
            owners: route.owners.clone(),
            cutoff: saved.cutoff,
            inventory: saved.inventory.clone(),
            deliveries: saved.deliveries.clone(),
            payloads: copy_payloads(&saved.payloads, context)?,
        };
        inputs.insert(
            saved.stage_operation.clone(),
            super::super::super::inputs::RetainedInput {
                batch: owned_batch,
                provenance,
                lineage,
                acknowledgement,
                failure: saved.failure.clone(),
                committed: saved.committed,
                commit,
            },
        );
        handles.insert(saved.batch.clone(), batch);
    }
    Ok((inputs, handles))
}

fn restore_operations(
    runtime: &NodeRuntime,
    context: &OriginalLineageRestoration<'_>,
    activation: &WorldActivation,
    inputs: &BTreeMap<Id, Rc<RuntimeInputBatch>>,
) -> Result<BTreeMap<Id, super::super::super::RetainedOperation>, RuntimeError> {
    let mut operations = BTreeMap::new();
    for saved in &context.record.operations {
        let route = runtime
            .snapshots
            .get(&saved.route.node)
            .ok_or(RuntimeError::UnknownNode)?
            .route
            .clone();
        let input = saved
            .input_batch
            .as_ref()
            .map(|batch| {
                inputs
                    .get(batch)
                    .cloned()
                    .ok_or(RuntimeError::InvalidReceipt)
            })
            .transpose()?;
        let admission = OperationAdmission {
            token: OperationToken {
                authority: Rc::clone(&runtime.authority),
                operation: saved.operation.clone(),
                route: route.clone(),
            },
            request: saved.request.clone(),
            activation: activation.clone(),
            inputs: input,
        };
        let result = match &saved.result {
            SavedRuntimeResult::Pending => RetainedResult::Pending,
            SavedRuntimeResult::Failed(failure) => RetainedResult::Failed(failure.clone()),
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                let mut outcome = outcome.clone();
                outcome.owners = route.owners.clone();
                if let Some(observation) = &mut outcome.scheduling {
                    observation.owners = route.owners.clone();
                }
                if !super::super::super::valid_outcome(&admission, &outcome) {
                    return Err(RuntimeError::InvalidReceipt);
                }
                if matches!(saved.result, SavedRuntimeResult::Acknowledged(_)) {
                    RetainedResult::Acknowledged(outcome)
                } else {
                    RetainedResult::Complete(outcome)
                }
            }
        };
        let scheduling_commit = saved
            .scheduling_commit
            .as_ref()
            .map(|commit| SchedulingCommit {
                activation: activation.clone(),
                node: commit.node.clone(),
                operation: commit.operation.clone(),
                retained_outputs: commit.retained_outputs.clone(),
            });
        operations.insert(
            saved.operation.clone(),
            super::super::super::RetainedOperation {
                admission,
                result,
                close_submission: saved.close_submission.clone(),
                submission_effects: saved.submission_effects.clone(),
                scheduling_commit,
            },
        );
    }
    Ok(operations)
}

fn restore_owners(
    runtime: &NodeRuntime,
    context: &OriginalLineageRestoration<'_>,
) -> Result<BTreeMap<Id, OwnerCustody>, RuntimeError> {
    let mut owners = BTreeMap::new();
    for saved in &context.record.owners {
        let current = runtime
            .owners
            .get(&saved.identity.owner)
            .ok_or(RuntimeError::InvalidRoute)?;
        if !saved.domains.iter().eq(current.domains.iter()) {
            return Err(RuntimeError::InvalidReceipt);
        }
        owners.insert(
            saved.identity.owner.clone(),
            OwnerCustody {
                identity: current.identity.clone(),
                domains: current.domains.clone(),
                operation: saved.operation.clone(),
                lifecycle: saved.lifecycle,
            },
        );
    }
    Ok(owners)
}

fn reserve<T>(count: usize) -> Result<Vec<T>, RuntimeError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(entries)
}
