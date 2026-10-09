//! Actual quantized child transitions and complete retained native stop evidence.

use std::time::Duration;

use crucible_node_contract::*;
use serde_json::json;

use crate::ProviderError;
use crate::bodies::{BudgetOutcome, QuantumBeginArguments, QuantumBeginResult, ShutdownResult};
use crate::envelope::Envelope;
use crate::reference_device::{DeviceGrant, DeviceStatus};

use super::resources::{Resources, Window};

impl Resources {
    pub(super) fn run_quantum(
        &mut self,
        request: &Envelope,
        arguments: &QuantumBeginArguments,
    ) -> Result<QuantumBeginResult, ProviderError> {
        let operation = request
            .operation_id
            .0
            .clone()
            .ok_or(ProviderError::Correlation(
                "quantum has no original operation identity",
            ))?;
        let input = self
            .input
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "quantum input custody disappeared",
            ))?
            .clone();
        let publication = Position::new(arguments.until_ps, U64::new(0), Phase::Publication);
        let grant = DeviceGrant {
            owner_id: self.bootstrap.owner_id.clone(),
            incarnation_id: self.bootstrap.authority.incarnation_id.clone(),
            generation: self.bootstrap.authority.owner_generation,
            window_id: arguments.grant_id.clone(),
            input_batch_id: input.batch_id.clone(),
            quantum: arguments.quantum_index,
            start: Position::new(arguments.from_ps, U64::new(0), Phase::BoundaryControl),
            publication,
            host_budget_ns: arguments.wall_budget_ns,
        };
        let child = self
            .child
            .as_mut()
            .ok_or(ProviderError::Correlation("native child disappeared"))?;
        child.stage(grant.clone(), &self.input_bytes)?;
        child.activate(&grant)?;
        let native = child.close(&grant)?;
        child.validate_receipt(&native)?;
        super::limits::verify_processes(Some(child.child_pid()))?;
        let measurement = self.store_json(&native)?;
        let payload = self.store_json(&native.output)?;
        let sequence = self.next_observation;
        let successor = sequence.checked_add(U64::new(1))?;
        let observation = ObservationBatch {
            schema_version: 1,
            execution_owner_id: self.bootstrap.owner_id.clone(),
            owner_binding_hash: self.owner_binding.identity()?,
            world_binding_hash: self.bootstrap.world_binding_hash.clone(),
            activation_id: self.bootstrap.activation_id.clone(),
            world_generation: self.bootstrap.world_generation,
            owner_generation: self.bootstrap.authority.owner_generation,
            operation_id: operation.clone(),
            grant_id: Some(grant.window_id.clone()),
            first_sequence: sequence,
            last_sequence: sequence,
            events: vec![Event {
                schema_version: 1,
                id: Id::new(format!("checksum-{}", sequence.get()))?,
                source: Endpoint {
                    node_id: self.bootstrap.node_id.clone(),
                    port_id: Id::new("data")?,
                    lane_id: Id::new("output")?,
                },
                destination: Endpoint {
                    node_id: self.bootstrap.node_id.clone(),
                    port_id: Id::new("data")?,
                    lane_id: Id::new("input")?,
                },
                position: publication,
                stage: EventStage::Publication,
                publication_position: publication,
                delivery_position: None,
                source_sequence: sequence,
                causal_parent_ids: Vec::new(),
                payload,
                provenance_ref: measurement.clone(),
                extensions: Extensions::new(),
            }],
            visibility: Visibility::Staged,
            measurement_ref: measurement.clone(),
            extensions: Extensions::new(),
        };
        observation.validate()?;
        let observation_ref = self.store_json(&observation)?;
        let pending = self.pending_for(
            Some(operation.clone()),
            Some(grant.window_id.clone()),
            Some(observation_ref.clone()),
        )?;
        let input_custody = self
            .input_custody
            .clone()
            .ok_or(ProviderError::Correlation(
                "native input receipt disappeared",
            ))?;
        let stop = StopReceipt {
            schema_version: 1,
            session_id: self.bootstrap.authority.session_id.clone(),
            incarnation_id: self.bootstrap.authority.incarnation_id.clone(),
            owner_binding_hash: self.owner_binding.identity()?,
            world_binding_hash: self.bootstrap.world_binding_hash.clone(),
            activation_id: self.bootstrap.activation_id.clone(),
            world_generation: self.bootstrap.world_generation,
            execution_owner_id: self.bootstrap.owner_id.clone(),
            owner_generation: self.bootstrap.authority.owner_generation,
            operation_id: operation.clone(),
            grant_id: Some(grant.window_id.clone()),
            participant_ids: self.profile.owner.participant_ids.clone(),
            mode: OperatingMode::Quantized,
            ordering_profile: "superdense-v1".to_owned(),
            reached: Some(Position::new(
                arguments.until_ps,
                U64::new(0),
                Phase::BoundaryControl,
            )),
            production_prefix: publication,
            prefix_kind: ClosureKind::Through,
            output_lower_bounds: Vec::new(),
            physical_stop: PhysicalStop::ObservationClosed,
            cause: Id::new("application-window-complete")?,
            input_custody,
            pending_inventory: pending.clone(),
            observation_batch: observation_ref.clone(),
            physical_measurement_ref: measurement.clone(),
            evidence_refs: vec![measurement.clone()],
            extensions: Extensions::new(),
        };
        stop.validate()?;
        let stop_ref = self.store_json(stop)?;
        self.window = Some(Window {
            operation,
            grant: grant.clone(),
            native,
            stop: stop_ref.clone(),
            observation,
            observation_ref: observation_ref.clone(),
            pending: pending.clone(),
            measurement: measurement.clone(),
            closed: false,
            committed_ref: None,
            publication_acknowledged: false,
        });
        self.next_observation = successor;
        Ok(QuantumBeginResult {
            grant_id: grant.window_id,
            quantum_index: grant.quantum,
            stop_receipt: stop_ref,
            observation_batch: observation_ref,
            pending_inventory: pending,
            budget_outcome: BudgetOutcome::WithinBudget,
            physical_measurement_ref: measurement,
        })
    }

    pub(super) fn shutdown(&mut self, request: &Envelope) -> Result<ShutdownResult, ProviderError> {
        let child = self
            .child
            .as_mut()
            .ok_or(ProviderError::Correlation("reference child unavailable"))?;
        if !child.quarantine()? || child.status() != DeviceStatus::Reaped {
            return Err(ProviderError::Correlation(
                "native child reclamation is unresolved",
            ));
        }
        let pid = child.child_pid();
        self.active = false;
        let inventory = self.store_json(
            json!({"child_pid":U64::new(u64::from(pid)),"native_status":"reaped",
            "private_socket":"disconnected","publication_pending":false}),
        )?;
        let record = CleanupRecord {
            schema_version: 1,
            owner_ids: vec![self.bootstrap.owner_id.clone()],
            resource_inventory_ref: inventory.clone(),
            disposition: CleanupDisposition::Retained,
            supervisor_receipt: None,
            evidence_refs: vec![inventory],
            extensions: Extensions::new(),
        };
        record.validate()?;
        let record_ref = self.store_json(record)?;
        let request_id = request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "shutdown request identity missing",
            ))?;
        let cleanup = self.control_receipt(
            ControlReceiptKind::Cleanup,
            record_ref,
            request_id,
            request.operation_id.0.clone(),
        )?;
        let pending = self.pending()?;
        let observation = match self.window.as_ref() {
            Some(window) => window.observation_ref.clone(),
            None => self.store_json(ObservationBatch {
                schema_version: 1,
                execution_owner_id: self.bootstrap.owner_id.clone(),
                owner_binding_hash: self.owner_binding.identity()?,
                world_binding_hash: self.bootstrap.world_binding_hash.clone(),
                activation_id: self.bootstrap.activation_id.clone(),
                world_generation: self.bootstrap.world_generation,
                owner_generation: self.bootstrap.authority.owner_generation,
                operation_id: request
                    .operation_id
                    .0
                    .clone()
                    .ok_or(ProviderError::Correlation("shutdown operation missing"))?,
                grant_id: None,
                first_sequence: U64::new(0),
                last_sequence: U64::new(0),
                events: Vec::new(),
                visibility: Visibility::Staged,
                measurement_ref: cleanup.clone(),
                extensions: Extensions::new(),
            })?,
        };
        Ok(ShutdownResult {
            observation_batch: observation,
            pending_inventory: pending,
            stopped: true,
            reaped: true,
            cleanup_receipt: cleanup,
        })
    }

    pub(super) fn pending(&mut self) -> Result<ContentRef, ProviderError> {
        let window = self.window.as_ref();
        self.pending_for(
            window.map(|value| value.operation.clone()),
            window.map(|value| value.grant.window_id.clone()),
            window
                .filter(|value| !value.publication_acknowledged)
                .map(|value| value.observation_ref.clone()),
        )
    }

    fn pending_for(
        &mut self,
        operation: Option<Id>,
        grant: Option<Id>,
        output: Option<ContentRef>,
    ) -> Result<ContentRef, ProviderError> {
        let mut entries = Vec::new();
        if let Some(input) = self.input.clone() {
            let state_ref = self.store_json(input)?;
            entries.push(PendingEntry {
                id: Id::new("accepted-input")?,
                kind: PendingKind::Input,
                owner_id: self.bootstrap.owner_id.clone(),
                deadline: Bound {
                    kind: BoundKind::Unknown,
                    position: None,
                    evidence: None,
                },
                state_ref,
                extensions: Extensions::new(),
            });
        }
        if let Some(output) = output {
            entries.push(PendingEntry {
                id: Id::new("staged-output")?,
                kind: PendingKind::Output,
                owner_id: self.bootstrap.owner_id.clone(),
                deadline: Bound {
                    kind: BoundKind::Unknown,
                    position: None,
                    evidence: None,
                },
                state_ref: output,
                extensions: Extensions::new(),
            });
        }
        let inventory = PendingInventory {
            schema_version: 1,
            execution_owner_id: self.bootstrap.owner_id.clone(),
            owner_binding_hash: self.owner_binding.identity()?,
            world_binding_hash: self.bootstrap.world_binding_hash.clone(),
            activation_id: self.active.then(|| self.bootstrap.activation_id.clone()),
            world_generation: if self.active {
                self.bootstrap.world_generation
            } else {
                U64::new(0)
            },
            operation_id: operation,
            grant_id: grant,
            owner_generation: self.bootstrap.authority.owner_generation,
            revision: self.next_quantum,
            complete: true,
            input_watermark: self
                .input
                .as_ref()
                .map_or(U64::new(0), |input| input.batch_sequence),
            input_epoch: self.bootstrap.authority.input_epoch.clone(),
            entries,
            extensions: Extensions::new(),
        };
        inventory.validate()?;
        self.store_json(inventory)
    }

    pub(super) fn control_receipt(
        &mut self,
        kind: ControlReceiptKind,
        record_ref: ContentRef,
        request_id: &Id,
        operation_id: Option<Id>,
    ) -> Result<ContentRef, ProviderError> {
        let receipt = ControlReceipt {
            schema_version: 1,
            kind,
            session_id: self.bootstrap.authority.session_id.clone(),
            incarnation_id: self.bootstrap.authority.incarnation_id.clone(),
            request_id: request_id.clone(),
            operation_id,
            owner_ids: vec![self.bootstrap.owner_id.clone()],
            world_generation: if self.active {
                self.bootstrap.world_generation
            } else {
                U64::new(0)
            },
            record_ref,
            issuer: ReceiptIssuer::Provider,
            extensions: Extensions::new(),
        };
        receipt.validate()?;
        self.store_json(receipt)
    }

    pub(super) fn timeout(&self) -> Duration {
        Duration::from_nanos(self.bootstrap.host_budget_ns.get())
            .max(Duration::from_secs(1))
            .min(Duration::from_secs(60))
    }
}
