//! Closed-gate realization, activation, close, content, and semantic consumption.

use crucible_node_contract::*;
use serde_json::json;

use crate::ProviderError;
use crate::blob::{BlobSchemaVerifier, TransferKey};
use crate::bodies::*;
use crate::envelope::{Envelope, RequestOrigin};
use crate::reference_device::{DeviceStatus, ReferenceDevice};

use super::completed;
use super::resources::{PublicationConsumption, Resources};

impl Resources {
    pub(super) fn preflight(&self, body: &RequestBody) -> Result<(), ProviderError> {
        let invalid = match body {
            RequestBody::Realize(request) => {
                self.realized
                    || self.child.is_some()
                    || request.realization_id != self.bootstrap.authority.realization_id
                    || request.configuration != self.profile.configuration_ref
                    || request.requested_node_ids != self.profile.owner.participant_ids
                    || request.resource_limits != self.bootstrap.resource_limits
            }
            RequestBody::Admit(request) => {
                !self.realized
                    || self.admitted
                    || request.bindings != [self.binding.clone()]
                    || request.world_binding_hash != self.bootstrap.world_binding_hash
                    || request.admission_receipt != self.bootstrap.admission_receipt
            }
            RequestBody::Activate(request) => {
                !self.admitted
                    || self.staged
                    || self.active
                    || request.admission_id != self.bootstrap.admission_id
                    || request.activation_id != self.bootstrap.activation_id
                    || request.world_generation != self.bootstrap.world_generation
                    || request.prepared_token != self.bootstrap.prepared_token
                    || request.gate_id != self.bootstrap.gate_id
                    || request.world_binding_hash != self.bootstrap.world_binding_hash
                    || self
                        .child
                        .as_ref()
                        .is_none_or(|child| child.status() != DeviceStatus::Parked)
            }
            RequestBody::WorldActivate(request) => {
                !self.staged
                    || self.active
                    || request.transaction_id != self.bootstrap.transaction_id
                    || request.activation_id != self.bootstrap.activation_id
                    || request.world_generation != self.bootstrap.world_generation
                    || request.prepared_token != self.bootstrap.prepared_token
                    || request.gate_id != self.bootstrap.gate_id
                    || request.world_binding_hash != self.bootstrap.world_binding_hash
            }
            RequestBody::Abort(request) => {
                request.transaction_id != self.bootstrap.transaction_id
                    || self.active
                    || self.window.is_some()
            }
            RequestBody::Release(request) => {
                request.realization_id != self.bootstrap.authority.realization_id
                    || self
                        .child
                        .as_ref()
                        .is_none_or(|child| child.status() != DeviceStatus::Reaped)
                    || self
                        .window
                        .as_ref()
                        .is_some_and(|window| !window.publication_acknowledged)
            }
            _ => false,
        };
        if invalid {
            return Err(ProviderError::Conflict(
                "native phase or immutable preparation differs",
            ));
        }
        Ok(())
    }

    pub(super) fn control(
        &mut self,
        envelope: &Envelope,
        body: &RequestBody,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        match body {
            RequestBody::Realize(request) => self.realize(envelope, request),
            RequestBody::Admit(request) => self.admit(request),
            RequestBody::Activate(request) => self.activate(envelope, request),
            RequestBody::WorldActivate(request) => self.world_activate(envelope, request),
            RequestBody::QuantumClose(request) => self.close_round(envelope, request),
            RequestBody::BlobBegin(request) => {
                let key = self.transfer(request.transfer_id.clone());
                let progress = self.blobs.begin(key, request.content.clone())?;
                completed(BlobBeginResult {
                    transfer_id: progress.transfer_id,
                    next_offset: progress.next_offset,
                    maximum_chunk_bytes: progress.maximum_chunk_bytes,
                })
            }
            RequestBody::BlobChunk(request) => {
                let progress = self.blobs.chunk(
                    &self.transfer(request.transfer_id.clone()),
                    request.offset,
                    &request.bytes,
                )?;
                completed(BlobChunkResult {
                    transfer_id: progress.transfer_id,
                    next_offset: progress.next_offset,
                })
            }
            RequestBody::BlobFinish(request) => {
                let verified = self
                    .blobs
                    .finish(&self.transfer(request.transfer_id.clone()))?;
                let reference = verified.content().clone();
                // Ordinary verified blobs are inert. Installed JSON schemas are
                // checked before any control consumer gets access to their bytes.
                let schema = self.profile.content_possession_schema.definition.clone();
                let pin = self.blobs.pin_operation(
                    &verified,
                    request.transfer_id.clone(),
                    schema.clone(),
                    &InertJsonSchema { expected: schema },
                )?;
                let bytes = pin.with_bytes(<[u8]>::to_vec)?;
                self.store(bytes, &reference.media_type)?;
                self.pins.push(pin);
                self.verified
                    .insert(reference.hash.digest.clone(), verified);
                completed(BlobFinishResult {
                    transfer_id: request.transfer_id.clone(),
                    content: reference,
                })
            }
            RequestBody::Release(request) => self.release(envelope, request),
            RequestBody::Abort(request) => self.abort(envelope, request),
            _ => Err(ProviderError::Frame(
                "reference control method requires selected native dispatch",
            )),
        }
    }

    fn realize(
        &mut self,
        envelope: &Envelope,
        request: &RealizeRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        super::limits::verify(&self.bootstrap.resource_limits)?;
        super::limits::verify_processes(None)?;
        if self.realized
            || request.realization_id != self.bootstrap.authority.realization_id
            || request.configuration != self.profile.configuration_ref
            || request.requested_node_ids != self.profile.owner.participant_ids
            || request.resource_limits != self.bootstrap.resource_limits
            || request.resource_limits.processes.get() < 2
            || request.resource_limits.descriptors.get() < 4
            || request.resource_limits.maximum_operations.get() == 0
            || request.resource_limits.pending_events.get() == 0
        {
            return Err(ProviderError::Correlation(
                "realization differs from privately admitted immutable resources",
            ));
        }
        self.child = Some(ReferenceDevice::spawn(
            &self.child_path,
            &self.socket_parent,
            self.bootstrap.owner_id.clone(),
            self.bootstrap.authority.incarnation_id.clone(),
            self.bootstrap.authority.owner_generation,
            self.timeout(),
        )?);
        let child = self.child.as_ref().ok_or(ProviderError::Correlation(
            "actual child failed to establish custody",
        ))?;
        super::limits::verify_processes(Some(child.child_pid()))?;
        let expected = self
            .profile
            .implementation
            .artifacts
            .iter()
            .find(|artifact| artifact.id.as_str() == "device")
            .ok_or(ProviderError::Frame("installed child artifact missing"))?
            .content
            .clone();
        let measured = crate::conformance::measure_executable(std::path::Path::new(&format!(
            "/proc/{}/exe",
            child.child_pid()
        )))?;
        if measured != expected {
            return Err(ProviderError::Correlation(
                "actual child executable differs from installed measurement",
            ));
        }
        let native = self.store_json(
            json!({"child_pid":U64::new(u64::from(child.child_pid())),"application_status":"parked",
            "native_executable":measured,"physical_pause":"unknown"}),
        )?;
        let record = ClosedGateRecord {
            schema_version: 1,
            gate_id: self.bootstrap.gate_id.clone(),
            prepared_token: self.bootstrap.prepared_token.clone(),
            owner_ids: vec![self.bootstrap.owner_id.clone()],
            gate_closed: true,
            physical_status_ref: native.clone(),
            evidence_refs: vec![native],
            extensions: Extensions::new(),
        };
        record.validate()?;
        let record_ref = self.store_json(record)?;
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("realize request ID missing"))?;
        let gate =
            self.control_receipt(ControlReceiptKind::ClosedGate, record_ref, request_id, None)?;
        self.gate_receipt = Some(gate.clone());
        self.realized = true;
        let provider_ref = self.store_json(self.profile.provider_manifest.clone())?;
        completed(RealizeResult {
            realization_manifest: RealizationManifest {
                schema_version: 1,
                realization_id: request.realization_id.clone(),
                provider_manifest: provider_ref,
                descriptors: vec![self.profile.descriptor.clone()],
                bindings: vec![self.binding.clone()],
                owners: vec![self.profile.owner.clone()],
                owner_bindings: vec![self.owner_binding.clone()],
                extensions: Extensions::new(),
            },
            prepared_token: self.bootstrap.prepared_token.clone(),
            closed_gate_receipt: gate,
        })
    }

    fn admit(
        &mut self,
        request: &AdmitRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        if !self.realized
            || self.admitted
            || request.bindings != [self.binding.clone()]
            || request.world_binding_hash != self.bootstrap.world_binding_hash
            || request.admission_receipt != self.bootstrap.admission_receipt
        {
            return Err(ProviderError::Correlation(
                "admission differs from private host record",
            ));
        }
        let receipt: ControlReceipt = self.resolve(&request.admission_receipt)?;
        let record: AdmissionRecord = self.resolve(&receipt.record_ref)?;
        if receipt.issuer != ReceiptIssuer::Host
            || receipt.kind != ControlReceiptKind::Admission
            || receipt.session_id != self.bootstrap.authority.session_id
            || receipt.incarnation_id != self.bootstrap.authority.incarnation_id
            || receipt.owner_ids != [self.bootstrap.owner_id.clone()]
            || record.binding_hashes != [self.binding.identity()?]
            || record.world_binding_hash != self.bootstrap.world_binding_hash
            || record.measured_artifacts != self.profile.implementation.artifacts
            || record.resource_limits != self.bootstrap.resource_limits
            || record.qualification_refs != self.binding.compatibility.qualification_refs
        {
            return Err(ProviderError::Correlation(
                "host admission content differs from actual installed native profile",
            ));
        }
        self.admitted = true;
        completed(AdmitResult {
            accepted_binding_hashes: vec![self.binding.identity()?],
            admission_id: self.bootstrap.admission_id.clone(),
        })
    }

    fn activate(
        &mut self,
        envelope: &Envelope,
        request: &ActivateRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        if !self.admitted
            || self.staged
            || self.active
            || request.admission_id != self.bootstrap.admission_id
            || request.activation_id != self.bootstrap.activation_id
            || request.world_generation != self.bootstrap.world_generation
            || request.prepared_token != self.bootstrap.prepared_token
            || request.gate_id != self.bootstrap.gate_id
            || request.world_binding_hash != self.bootstrap.world_binding_hash
            || self
                .child
                .as_ref()
                .is_none_or(|child| child.status() != DeviceStatus::Parked)
        {
            return Err(ProviderError::Correlation(
                "activation differs from admitted closed native gate",
            ));
        }
        let evidence = self.gate_receipt.clone().ok_or(ProviderError::Correlation(
            "native closed gate evidence missing",
        ))?;
        let record = ActivationReadyRecord {
            schema_version: 1,
            activation_id: request.activation_id.clone(),
            world_generation: request.world_generation,
            gate_id: request.gate_id.clone(),
            prepared_token: request.prepared_token.clone(),
            world_binding_hash: request.world_binding_hash.clone(),
            owner_ids: vec![self.bootstrap.owner_id.clone()],
            gate_closed: true,
            evidence_refs: vec![evidence],
            extensions: Extensions::new(),
        };
        record.validate()?;
        let record_ref = self.store_json(record)?;
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("activation request ID missing"))?;
        let receipt = self.control_receipt(
            ControlReceiptKind::ActivationReady,
            record_ref,
            request_id,
            None,
        )?;
        self.ready_receipt = Some(receipt.clone());
        self.staged = true;
        completed(ActivateResult {
            staged: true,
            gate_id: request.gate_id.clone(),
            staged_owner_ids: vec![self.bootstrap.owner_id.clone()],
            activation_receipt: receipt,
        })
    }

    fn world_activate(
        &mut self,
        envelope: &Envelope,
        request: &WorldActivateRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        if !self.staged
            || self.active
            || request.transaction_id != self.bootstrap.transaction_id
            || request.activation_id != self.bootstrap.activation_id
            || request.world_generation != self.bootstrap.world_generation
            || request.prepared_token != self.bootstrap.prepared_token
            || request.gate_id != self.bootstrap.gate_id
            || request.world_binding_hash != self.bootstrap.world_binding_hash
        {
            return Err(ProviderError::Correlation(
                "world activation differs from private transaction",
            ));
        }
        let manifest: ActivationManifest = self.resolve(&request.activation_manifest)?;
        let expected = PreparedOwner {
            owner_id: self.bootstrap.owner_id.clone(),
            incarnation_id: self.bootstrap.authority.incarnation_id.clone(),
            owner_generation: self.bootstrap.authority.owner_generation,
            prepared_token: self.bootstrap.prepared_token.clone(),
            binding_hashes: vec![self.binding.identity()?],
            ready_receipt: self
                .ready_receipt
                .clone()
                .ok_or(ProviderError::Correlation(
                    "native ready receipt unavailable",
                ))?,
            extensions: Extensions::new(),
        };
        if manifest.transaction_id != request.transaction_id
            || manifest.activation_id != request.activation_id
            || manifest.world_generation != request.world_generation
            || manifest.gate_id != request.gate_id
            || manifest.world_binding_hash != request.world_binding_hash
            || manifest
                .owners
                .iter()
                .find(|owner| owner.owner_id == self.bootstrap.owner_id)
                != Some(&expected)
        {
            return Err(ProviderError::Correlation(
                "world activation manifest omits or changes native prepared custody",
            ));
        }
        self.content(&manifest.coordinator_state_ref)?;
        self.active = true;
        self.binding.authority.activation_id = Some(request.activation_id.clone());
        self.binding.authority.world_generation = request.world_generation;
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "world activation request ID missing",
            ))?;
        let ready = self
            .ready_receipt
            .clone()
            .ok_or(ProviderError::Correlation("native readiness unavailable"))?;
        // Arming records readiness beneath the already proven stopped child;
        // it never stages or executes checksum input without a later grant.
        let readiness: ControlReceipt = self.resolve(&ready)?;
        let receipt = self.control_receipt(
            ControlReceiptKind::ActivationReady,
            readiness.record_ref,
            request_id,
            None,
        )?;
        completed(WorldActivateResult {
            gate_id: request.gate_id.clone(),
            armed_owner_ids: vec![self.bootstrap.owner_id.clone()],
            activation_receipt: receipt,
        })
    }

    fn close_round(
        &mut self,
        envelope: &Envelope,
        request: &QuantumCloseRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        self.check_owner(
            envelope,
            request.owner_generation,
            &self.owner_binding.identity()?,
        )?;
        let window = self.window.as_ref().ok_or(ProviderError::Correlation(
            "native quantum window unavailable",
        ))?;
        let expected_cut = Position::new(
            window.grant.publication.time_ps,
            U64::new(0),
            Phase::BoundaryControl,
        );
        if request.grant_id != window.grant.window_id
            || request.quantum_index != window.grant.quantum
            || request.cut != expected_cut
            || request.activation_id != self.bootstrap.activation_id
            || request.world_generation != self.bootstrap.world_generation
            || request.input_epoch != self.bootstrap.authority.input_epoch
            || request.participant_ids != self.profile.owner.participant_ids
            || request.policy_hash != self.profile.operating_contract.policy_ref.hash
            || request.observation_batch_hash != window.observation.identity()?
            || request.deadline_disposition != BudgetOutcome::WithinBudget
            || self
                .input
                .as_ref()
                .is_none_or(|input| input.batch_sequence != request.input_watermark)
        {
            return Err(ProviderError::Correlation(
                "quantum close changed original native cut or output",
            ));
        }
        self.child
            .as_ref()
            .ok_or(ProviderError::Correlation("native close owner disappeared"))?
            .validate_receipt(&window.native)?;
        let mut committed = window.observation.clone();
        committed.visibility = Visibility::Committed;
        let stop = window.stop.clone();
        let pending = window.pending.clone();
        let committed_ref = self.store_json(committed)?;
        let window = self.window.as_mut().ok_or(ProviderError::Correlation(
            "native close window disappeared",
        ))?;
        window.closed = true;
        window.committed_ref = Some(committed_ref.clone());
        completed(QuantumCloseResult {
            grant_id: request.grant_id.clone(),
            quantum_index: request.quantum_index,
            cut: request.cut,
            policy_hash: request.policy_hash.clone(),
            activation_id: request.activation_id.clone(),
            world_generation: request.world_generation,
            owner_generation: request.owner_generation,
            input_epoch: request.input_epoch.clone(),
            stop_receipt: stop,
            committed_batch: committed_ref,
            pending_inventory: pending,
            next_allowed_quantum: crate::envelope::Nullable(None),
        })
    }

    fn abort(
        &mut self,
        envelope: &Envelope,
        request: &AbortRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        if request.transaction_id != self.bootstrap.transaction_id
            || self.active
            || self.window.is_some()
        {
            return Err(ProviderError::Conflict(
                "activated or unpublished native custody cannot be aborted",
            ));
        }
        if let Some(child) = &mut self.child
            && (!child.quarantine()? || child.status() != DeviceStatus::Reaped)
        {
            return Err(ProviderError::Correlation(
                "native preparation cleanup remains unresolved",
            ));
        }
        self.staged = false;
        let inventory = self.store_json(json!({"child":"reaped-or-never-spawned","execution_gate":"closed","protocol_ledger":"retained"}))?;
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
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("abort request identity missing"))?;
        let receipt =
            self.control_receipt(ControlReceiptKind::Cleanup, record_ref, request_id, None)?;
        completed(AbortResult {
            transaction_id: request.transaction_id.clone(),
            owner_ids: vec![self.bootstrap.owner_id.clone()],
            cleanup_receipt: receipt,
            effect: EffectCertainty::Completed,
        })
    }

    fn release(
        &mut self,
        envelope: &Envelope,
        request: &ReleaseRequest,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        if request.realization_id != self.bootstrap.authority.realization_id
            || self
                .child
                .as_ref()
                .is_none_or(|child| child.status() != DeviceStatus::Reaped)
            || self
                .window
                .as_ref()
                .is_some_and(|window| !window.publication_acknowledged)
        {
            return Err(ProviderError::Conflict(
                "actual native owner has not reclaimed its output and child",
            ));
        }
        let inventory = self.store_json(
            json!({"child":"reaped","external_authority":"revoked","protocol_ledger":"retained"}),
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
        let request_id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("release request ID missing"))?;
        let receipt =
            self.control_receipt(ControlReceiptKind::Cleanup, record_ref, request_id, None)?;
        // Ledger and pins remain supervised; the reply claims only native owner
        // release, not that its retained outcomes vanished from the session.
        self.child = None;
        completed(ReleaseResult {
            realization_id: request.realization_id.clone(),
            owner_ids: vec![self.bootstrap.owner_id.clone()],
            cleanup_receipt: receipt,
            released: true,
        })
    }

    pub(super) fn acknowledge_consumption(
        &mut self,
        reference: &ContentRef,
    ) -> Result<(), ProviderError> {
        if self.consumed.contains(&reference.hash.digest) {
            self.content(reference)?;
            return Ok(());
        }
        let receipt: PublicationConsumption = self.resolve(reference)?;
        let window = self.window.as_ref().ok_or(ProviderError::Correlation(
            "original native output custody unavailable",
        ))?;
        if !window.closed
            || receipt.session_id != self.bootstrap.authority.session_id
            || receipt.incarnation_id != self.bootstrap.authority.incarnation_id
            || receipt.operation_id != window.operation
            || receipt.grant_id != window.grant.window_id
            || receipt.world_binding_hash != self.bootstrap.world_binding_hash
            || receipt.observation_batch_hash != window.observation.identity()?
            || receipt.stop_receipt != window.stop
            || receipt.publication != window.grant.publication
            || !self.transferred.borrow().contains(&window.stop.hash.digest)
            || !self
                .transferred
                .borrow()
                .contains(&window.observation_ref.hash.digest)
            || window.observation.events.iter().any(|event| {
                !self
                    .transferred
                    .borrow()
                    .contains(&event.payload.hash.digest)
            })
        {
            return Err(ProviderError::Correlation(
                "semantic output consumption lacks original native and transferred custody",
            ));
        }
        let grant = window.grant.clone();
        self.child
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "native publication owner unavailable",
            ))?
            .acknowledge_publication(&grant)?;
        self.window
            .as_mut()
            .ok_or(ProviderError::Correlation("native output disappeared"))?
            .publication_acknowledged = true;
        self.consumed.insert(reference.hash.digest.clone());
        self.next_quantum = self.next_quantum.checked_add(U64::new(1))?;
        self.input = None;
        self.input_bytes.clear();
        self.input_custody = None;
        Ok(())
    }

    fn transfer(&self, transfer: Id) -> TransferKey {
        TransferKey {
            origin: RequestOrigin::Controller,
            session: self.bootstrap.authority.session_id.clone(),
            incarnation: self.bootstrap.authority.incarnation_id.clone(),
            transfer,
        }
    }
}

struct InertJsonSchema {
    expected: ContentRef,
}

impl BlobSchemaVerifier for InertJsonSchema {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if schema != &self.expected {
            return Err(ProviderError::Frame("inert content schema differs"));
        }
        // This pin grants only inert local possession. Model/control consumers
        // subsequently decode their specific closed installed schema before use.
        if content.media_type == "application/json" {
            canonical::parse_json(bytes, 16 * 1024 * 1024)?;
        }
        Ok(())
    }
}
