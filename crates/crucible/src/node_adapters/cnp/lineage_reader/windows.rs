//! Original admitted windows, genuine native outputs and separate semantic ACK.

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::*,
    envelope::{Method, Nullable},
    reference_device::{DeviceGrant, DeviceReceipt, DeviceStatus},
    reference_service::PublicationConsumption,
};

use crate::node_contract::OperationRequest;

use super::control::{PublicWindow, ReaderState, canonical_bytes, content, original_id};

impl ReaderState {
    pub(super) fn stage_window(
        &mut self,
        grant: DeviceGrant,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        self.verify_native_custody()?;
        if let Some(original) = self.windows.get(&grant.window_id) {
            if original.grant != grant {
                return Err(ProviderError::Conflict(
                    "public window changed original grant",
                ));
            }
            return Ok(());
        }
        let input = self.input.as_ref().ok_or(ProviderError::Correlation(
            "public original input unavailable",
        ))?;
        let pending = self.pending.as_ref().ok_or(ProviderError::Correlation(
            "public original admission unavailable",
        ))?;
        let OperationRequest::QuantumBegin {
            window,
            start,
            end,
            input_batch,
            host_budget,
        } = pending.request()
        else {
            return Err(ProviderError::Correlation(
                "public admission is not a quantized window",
            ));
        };
        let nanoseconds = u64::try_from(host_budget.as_nanos())
            .map_err(|_| ProviderError::Correlation("public wall budget overflow"))?;
        if input.acknowledgement.is_none()
            || self.status != DeviceStatus::Parked
            || self.windows.len() >= self.maximum_operations
            || window != &grant.window_id
            || *start != grant.start
            || *end != grant.publication
            || input_batch != &grant.input_batch_id
            || nanoseconds != grant.host_budget_ns.get()
            || input.public.batch_id != grant.input_batch_id
            || input.bytes != bytes
            || pending.inputs().is_none_or(|original| {
                original.stage_operation() != input.original.stage_operation()
                    || original.batch() != input.original.batch()
                    || original.inventory() != input.original.inventory()
            })
            || pending.activation().record()
                != self
                    .active
                    .as_ref()
                    .ok_or(ProviderError::Correlation("public world not activated"))?
            || grant.owner_id != self.owner_binding.owner.id
            || grant.incarnation_id != self.binding.authority.incarnation_id
            || grant.generation != self.binding.authority.owner_generation
        {
            return Err(ProviderError::Correlation(
                "public window differs from original opaque host permission",
            ));
        }
        let original = pending.clone();
        self.preflight_window_evidence()?;
        self.windows.insert(
            grant.window_id.clone(),
            PublicWindow {
                original,
                grant,
                receipt: None,
                result: None,
                observations: None,
                closed: false,
                consumed: false,
            },
        );
        self.pending = None;
        self.status = DeviceStatus::Staged;
        Ok(())
    }

    pub(super) fn activate_window(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.verify_native_custody()?;
        let window = self
            .windows
            .get(&grant.window_id)
            .ok_or(ProviderError::Correlation(
                "original public window unavailable",
            ))?;
        if window.grant != *grant {
            return Err(ProviderError::Conflict("public activation changed grant"));
        }
        if window.receipt.is_some() {
            return Ok(());
        }
        let operation = window.original.token().operation().clone();
        let input = self.input.as_ref().ok_or(ProviderError::Correlation(
            "original public input unavailable",
        ))?;
        let watermark = input.public.batch_sequence;
        let input_proof = input
            .acknowledgement
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original public input has no authenticated acknowledgement",
            ))?
            .proof_ref
            .clone();
        let input_reference = input.reference.clone();
        let expected_checksum = input.bytes.iter().fold(self.checksum, |checksum, byte| {
            checksum.wrapping_mul(257).wrapping_add(u64::from(*byte))
        });
        let expected_count = U64::new(
            u64::try_from(input.bytes.len())
                .map_err(|_| ProviderError::ResourceExhausted("public input length"))?,
        );
        let bootstrap = self.controller()?.bootstrap.clone();
        let arguments = QuantumBeginArguments {
            grant_id: grant.window_id.clone(),
            participant_ids: self.controller()?.profile.owner.participant_ids.clone(),
            realization_id: bootstrap.authority.realization_id.clone(),
            activation_id: bootstrap.activation_id.clone(),
            world_generation: bootstrap.world_generation,
            owner_generation: grant.generation,
            input_epoch: bootstrap.authority.input_epoch.clone(),
            mode: OperatingMode::Quantized,
            ordering_profile: "superdense-v1".into(),
            quantum_index: grant.quantum,
            from_ps: grant.start.time_ps,
            until_ps: grant.publication.time_ps,
            input_batch: input.reference.clone(),
            input_watermark: watermark,
            policy_hash: self
                .controller()?
                .profile
                .operating_contract
                .policy_ref
                .hash
                .clone(),
            wall_budget_ns: grant.host_budget_ns,
        };
        let arguments = serde_json::to_value(arguments)
            .map_err(ContractError::from)?
            .as_object()
            .cloned()
            .ok_or(ProviderError::Frame(
                "public quantum arguments are not an object",
            ))?;
        let binding_hash = self.owner_binding.identity()?;
        let request_id = original_id("begin", &operation)?;
        let response = self.controller_mut()?.call(
            request_id.clone(),
            Some(operation.clone()),
            Method::Begin,
            true,
            BeginRequest {
                kind: BeginKind::QuantumBegin,
                binding_hash,
                owner_generation: grant.generation,
                activation_id: Nullable(Some(bootstrap.activation_id.clone())),
                world_generation: bootstrap.world_generation,
                arguments,
                extensions: Extensions::new(),
            },
        )?;
        // The installed reference source completes this bounded operation
        // synchronously. An unexpected accepted/unknown outcome remains under
        // original custody; it never licenses a replacement operation.
        let Some(MethodResult::QuantumBegin(result)) = response.result else {
            return Err(ProviderError::Correlation(
                "original public window has unresolved outcome",
            ));
        };
        let controller = self.controller()?;
        let observations: ObservationBatch = controller.record(&result.observation_batch)?;
        let stop: StopReceipt = controller.record(&result.stop_receipt)?;
        let original = self
            .windows
            .get(&grant.window_id)
            .ok_or(ProviderError::Correlation(
                "original selected window disappeared",
            ))?
            .original
            .clone();
        let input_request = original_id(
            "input",
            original
                .inputs()
                .ok_or(ProviderError::Correlation(
                    "original selected input disappeared",
                ))?
                .stage_operation(),
        )?;
        let native = super::super::lineage::with_original_runtime_lineage(
            &self.guard,
            crucible_node_provider::client::LineageWindowRequests {
                realization: &self.realization,
                input: &input_request,
                begin: &request_id,
            },
            &original,
            |lineage| {
                self.qualification.authenticate_window(&lineage)?;
                Ok(lineage.source().controlled_receipt().clone())
            },
        )?;
        let output = canonical_bytes(&native.output)?;
        let payload = canonical::content_ref(&output, "application/octet-stream")?;
        let native_sequence = grant.quantum.checked_add(U64::new(1))?;
        let native_id = Id::new(format!("checksum-{}", native_sequence.get()))?;
        if result.grant_id != grant.window_id
            || result.quantum_index != grant.quantum
            || result.budget_outcome != BudgetOutcome::WithinBudget
            || native.grant != *grant
            || !native.application_parked
            || native.output.bytes_processed != expected_count
            || native.output.checksum.get() != expected_checksum
            || native.measured_host_ns > grant.host_budget_ns
            || observations.execution_owner_id != bootstrap.owner_id
            || observations.owner_binding_hash != self.owner_binding.identity()?
            || observations.world_binding_hash != bootstrap.world_binding_hash
            || observations.activation_id != bootstrap.activation_id
            || observations.world_generation != bootstrap.world_generation
            || observations.owner_generation != grant.generation
            || observations.operation_id != operation
            || observations.grant_id.as_ref() != Some(&grant.window_id)
            || observations.visibility != Visibility::Staged
            || observations.measurement_ref != result.physical_measurement_ref
            || !observations.extensions.is_empty()
            || observations.events.len() != 1
            || observations.first_sequence != native_sequence
            || observations.last_sequence != native_sequence
            || observations.events[0].id != native_id
            || observations.events[0].source_sequence != native_sequence
            || observations.events[0].delivery_position.is_some()
            || observations.events[0].destination.node_id != bootstrap.node_id
            || observations.events[0].destination.port_id.as_str() != "data"
            || observations.events[0].destination.lane_id.as_str() != "input"
            || observations.events[0].payload != payload
            || observations.events[0].publication_position != grant.publication
            || observations.events[0].position != grant.publication
            || observations.events[0].stage != EventStage::Publication
            || observations.events[0].source.node_id != bootstrap.node_id
            || observations.events[0].source.port_id.as_str() != "data"
            || observations.events[0].source.lane_id.as_str() != "output"
            || observations.events[0].provenance_ref != result.physical_measurement_ref
            || !observations.events[0].causal_parent_ids.is_empty()
            || !observations.events[0].extensions.is_empty()
            || stop.session_id != bootstrap.authority.session_id
            || stop.incarnation_id != bootstrap.authority.incarnation_id
            || stop.owner_binding_hash != self.owner_binding.identity()?
            || stop.world_binding_hash != bootstrap.world_binding_hash
            || stop.activation_id != bootstrap.activation_id
            || stop.world_generation != bootstrap.world_generation
            || stop.execution_owner_id != bootstrap.owner_id
            || stop.owner_generation != grant.generation
            || stop.operation_id != operation
            || stop.grant_id.as_ref() != Some(&grant.window_id)
            || stop.participant_ids != controller.profile.owner.participant_ids
            || stop.mode != OperatingMode::Quantized
            || stop.ordering_profile != "superdense-v1"
            || stop.reached
                != Some(Position::new(
                    grant.publication.time_ps,
                    U64::new(0),
                    Phase::BoundaryControl,
                ))
            || stop.production_prefix != grant.publication
            || stop.prefix_kind != ClosureKind::Through
            || stop.physical_stop != PhysicalStop::ObservationClosed
            || stop.observation_batch != result.observation_batch
            || stop.pending_inventory != result.pending_inventory
            || stop.input_custody != input_proof
            || !stop.output_lower_bounds.is_empty()
            || stop.cause.as_str() != "application-window-complete"
            || stop.evidence_refs != [result.physical_measurement_ref.clone()]
            || stop.physical_measurement_ref != result.physical_measurement_ref
            || !stop.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "public native result changed original scope, output or truthful physical status",
            ));
        }
        payload.verify(controller.content(&payload)?)?;
        self.verify_pending(
            &result.pending_inventory,
            super::pending::ExpectedPending {
                operation: Some(&operation),
                grant: Some(&grant.window_id),
                revision: grant.quantum,
                input: &input_reference,
                output: Some(&result.observation_batch),
                watermark,
            },
        )?;
        self.verify_native_custody()?;
        self.retain_window_evidence(grant)?;
        self.retain_publication_evidence(&result, &observations, &stop)?;
        let window = self
            .windows
            .get_mut(&grant.window_id)
            .ok_or(ProviderError::Correlation("public window custody lost"))?;

        window.receipt = Some(native);
        window.result = Some(result);
        window.observations = Some(observations);
        self.checksum = expected_checksum;
        self.status = DeviceStatus::Active;

        Ok(())
    }

    pub(super) fn close_window(
        &mut self,
        grant: &DeviceGrant,
    ) -> Result<DeviceReceipt, ProviderError> {
        self.verify_native_custody()?;
        let window = self
            .windows
            .get(&grant.window_id)
            .ok_or(ProviderError::Correlation(
                "original public window unavailable",
            ))?;
        if window.grant != *grant {
            return Err(ProviderError::Conflict(
                "public close changed original grant",
            ));
        }
        let receipt = window.receipt.clone().ok_or(ProviderError::Correlation(
            "original public native result unresolved",
        ))?;
        if window.closed {
            return Ok(receipt);
        }
        let operation = window.original.token().operation().clone();
        let result = window.result.clone().ok_or(ProviderError::Correlation(
            "original public stop unavailable",
        ))?;
        let observations = window
            .observations
            .clone()
            .ok_or(ProviderError::Correlation(
                "original public output unavailable",
            ))?;
        let input = self.input.as_ref().ok_or(ProviderError::Correlation(
            "original public input unavailable",
        ))?;
        let bootstrap = self.controller()?.bootstrap.clone();
        let cut = Position::new(
            grant.publication.time_ps,
            U64::new(0),
            Phase::BoundaryControl,
        );
        let request = QuantumCloseRequest {
            grant_id: grant.window_id.clone(),
            activation_id: bootstrap.activation_id.clone(),
            world_generation: bootstrap.world_generation,
            owner_generation: grant.generation,
            input_epoch: bootstrap.authority.input_epoch.clone(),
            quantum_index: grant.quantum,
            participant_ids: self.controller()?.profile.owner.participant_ids.clone(),
            cut,
            policy_hash: self
                .controller()?
                .profile
                .operating_contract
                .policy_ref
                .hash
                .clone(),
            observation_batch_hash: observations.identity()?,
            input_watermark: input.public.batch_sequence,
            deadline_disposition: BudgetOutcome::WithinBudget,
            extensions: Extensions::new(),
        };
        let request_id = original_id("close", &operation)?;
        let response = self.controller_mut()?.call(
            request_id.clone(),
            Some(operation.clone()),
            Method::QuantumClose,
            true,
            &request,
        )?;
        let Some(MethodResult::QuantumClose(closed)) = response.result else {
            return Err(ProviderError::Correlation(
                "original public close unresolved",
            ));
        };
        let committed: ObservationBatch = self.controller()?.record(&closed.committed_batch)?;
        let mut expected = observations;
        expected.visibility = Visibility::Committed;
        if closed.grant_id != grant.window_id
            || closed.quantum_index != grant.quantum
            || closed.cut != cut
            || closed.policy_hash != request.policy_hash
            || closed.activation_id != request.activation_id
            || closed.world_generation != request.world_generation
            || closed.owner_generation != request.owner_generation
            || closed.input_epoch != request.input_epoch
            || closed.stop_receipt != result.stop_receipt
            || closed.pending_inventory != result.pending_inventory
            || committed != expected
        {
            return Err(ProviderError::Correlation(
                "public close changed complete original output custody",
            ));
        }
        let event_refs = committed
            .events
            .iter()
            .map(content)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(reference, _)| reference)
            .chain(std::iter::once(committed.measurement_ref.clone()))
            .collect();
        self.retain_boundary_record(&closed.committed_batch, event_refs)
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.reason)))?;
        self.windows
            .get_mut(&grant.window_id)
            .ok_or(ProviderError::Correlation("public window lost"))?
            .closed = true;
        self.status = DeviceStatus::ClosedPending;

        Ok(receipt)
    }

    pub(super) fn acknowledge_window(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.verify_native_custody()?;
        let window = self
            .windows
            .get(&grant.window_id)
            .ok_or(ProviderError::Correlation(
                "original public window unavailable",
            ))?;
        if window.grant != *grant || !window.closed {
            return Err(ProviderError::Correlation(
                "public publication is not closed",
            ));
        }
        if window.consumed {
            return Ok(());
        }
        let operation = window.original.token().operation().clone();
        let observations = window
            .observations
            .as_ref()
            .ok_or(ProviderError::Correlation("original output unavailable"))?;
        let result = window
            .result
            .as_ref()
            .ok_or(ProviderError::Correlation("original stop unavailable"))?;
        let bootstrap = self.controller()?.bootstrap.clone();
        let consumption = PublicationConsumption {
            schema: "reference-device/publication-consumption-v1".into(),
            session_id: bootstrap.authority.session_id,
            incarnation_id: bootstrap.authority.incarnation_id,
            operation_id: operation.clone(),
            grant_id: grant.window_id.clone(),
            world_binding_hash: bootstrap.world_binding_hash,
            observation_batch_hash: observations.identity()?,
            stop_receipt: result.stop_receipt.clone(),
            publication: grant.publication,
            extensions: Extensions::new(),
        };
        let observation_ref = result.observation_batch.clone();
        let stop_ref = result.stop_receipt.clone();
        let (reference, bytes) = content(&consumption)?;

        self.controller_mut()?.upload(&reference, &bytes)?;
        let request_id = original_id("consume", &operation)?;
        let response = self.controller_mut()?.call(
            request_id.clone(),
            Some(operation.clone()),
            Method::Retire,
            true,
            RetireRequest {
                request_ids: vec![original_id("begin", &operation)?],
                operation_ids: vec![operation.clone()],
                disposition: RetirementDisposition::Consumed,
                custody_receipt: Nullable(Some(reference.clone())),
                extensions: Extensions::new(),
            },
        )?;
        let Some(MethodResult::Retire(retired)) = response.result else {
            return Err(ProviderError::Correlation(
                "public original consumption unresolved",
            ));
        };
        if retired.retired_operation_ids != [operation.clone()]
            || retired.retired_request_ids != [original_id("begin", &operation)?]
        {
            return Err(ProviderError::Correlation(
                "public consumption retired another original",
            ));
        }
        self.retain_boundary_record(&reference, vec![observation_ref, stop_ref])
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.reason)))?;
        self.windows
            .get_mut(&grant.window_id)
            .ok_or(ProviderError::Correlation(
                "original publication custody lost",
            ))?
            .consumed = true;
        self.status = DeviceStatus::Parked;

        // Preserve the accepted input if duplicate observation became ambiguous.
        self.input = None;
        Ok(())
    }
}
