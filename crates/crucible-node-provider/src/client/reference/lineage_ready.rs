//! Borrows original cached realization and initialized native wire before input effects.

use super::*;

/// Borrows genuine received realization, closed gate and initialized native byte custody.
///
/// This view supplies original evidence for an independently installed adopter.
/// It grants no readiness, execution, source class or current kernel authority.
/// Its controller borrow also prevents mutation through that controller.
pub struct OriginalLineageRealization<'a> {
    controller: &'a ReferenceController,
    original: &'a ClientOriginal,
    realization: RealizeResult,
    gate: ControlReceipt,
    closed: ClosedGateRecord,
    pub(super) origin: records::Origin,
}

impl OriginalLineageRealization<'_> {
    /// Returns the exact original sent Realize and its received complete response.
    pub fn original(&self) -> &ClientOriginal {
        self.original
    }

    /// Returns the unchanged realization manifest and original closed-gate reference.
    pub fn realization(&self) -> &RealizeResult {
        &self.realization
    }

    /// Returns the actual original closed-gate control scope.
    pub fn gate(&self) -> &ControlReceipt {
        &self.gate
    }

    /// Returns the actual closed-gate record with its original native evidence reference.
    pub fn closed_gate(&self) -> &ClosedGateRecord {
        &self.closed
    }

    /// Returns the original received native child PID, never a live-process claim.
    pub fn native_pid(&self) -> U64 {
        self.origin.child_pid
    }

    /// Returns the actual original source-retained kernel start counter.
    pub fn native_start_ticks(&self) -> U64 {
        self.origin.original_kernel_start_ticks
    }

    /// Returns the original child artifact reference bound to the selected profile.
    pub fn native_executable(&self) -> &ContentRef {
        &self.origin.native_executable
    }

    /// Borrows exact original Initialize JSON and the complete length-prefixed Ready.
    ///
    /// # Errors
    /// Refuses missing or altered original typed byte custody.
    pub fn native_initialization(&self) -> Result<(&[u8], &[u8]), ProviderError> {
        Ok((
            self.controller.content(&self.origin.initialize_request)?,
            self.controller
                .content(&self.origin.initialize_response_wire)?,
        ))
    }
}

impl ReferenceController {
    /// Borrows a selected original realization from its owning controller request ID.
    ///
    /// A parsed gate or expected reference cannot construct this view. It checks
    /// the actual cached request/response and original native wire agreement,
    /// before inputs are needed. Installed native measurements, two-group kernel
    /// custody and source qualification remain separate mandatory gates.
    ///
    /// # Errors
    /// Refuses legacy profiles, unknown or incomplete originals, changed full
    /// realization, absent gate evidence, altered native scope or malformed wire.
    pub fn original_lineage_realization(
        &self,
        request: &Id,
    ) -> Result<OriginalLineageRealization<'_>, ProviderError> {
        if !self.profile.is_lineage() {
            return Err(invalid());
        }
        let (original, completed) = completed(self, request, Method::Realize)?;
        let Some(MethodResult::Realize(realization)) = completed.result else {
            return Err(invalid());
        };
        let RequestBody::Realize(sent) = decode_request(Method::Realize, &original.request.body)?
        else {
            return Err(invalid());
        };
        let (binding, owner) = self.binding()?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&self.profile.provider_manifest).map_err(ContractError::from)?,
        )?;
        let manifest = &realization.realization_manifest;
        if sent.realization_id != self.bootstrap.authority.realization_id
            || sent.configuration != self.profile.configuration_ref
            || sent.requested_node_ids != [self.bootstrap.node_id.clone()]
            || sent.resource_limits != self.bootstrap.resource_limits
            || !sent.extensions.is_empty()
            || manifest.realization_id != sent.realization_id
            || manifest.provider_manifest != canonical::content_ref(&bytes, "application/json")?
            || manifest.descriptors != [self.profile.descriptor.clone()]
            || manifest.bindings != [binding]
            || manifest.owners != [self.profile.owner.clone()]
            || manifest.owner_bindings != [owner]
            || !manifest.extensions.is_empty()
            || realization.prepared_token != self.bootstrap.prepared_token
        {
            return Err(ProviderError::Correlation(
                "lineage original full realization differs",
            ));
        }
        let gate: ControlReceipt = validated(self, &realization.closed_gate_receipt)?;
        validation::control(self, &gate, request, ControlReceiptKind::ClosedGate)?;
        let closed: ClosedGateRecord = validated(self, &gate.record_ref)?;
        if gate.operation_id.is_some()
            || !gate.extensions.is_empty()
            || closed.owner_ids != [self.bootstrap.owner_id.clone()]
            || closed.gate_id != self.bootstrap.gate_id
            || closed.prepared_token != self.bootstrap.prepared_token
            || !closed.gate_closed
            || !closed.extensions.is_empty()
        {
            return Err(invalid());
        }
        let origin: records::Origin =
            record(self, &closed.physical_status_ref, "application/json")?;
        if origin.schema != "crucible.reference.lineage-origin.v1"
            || origin.dialect != crate::reference_lineage::DIALECT
            || origin.application_status != "parked"
            || origin.physical_pause != "unknown"
            || origin.owner != self.bootstrap.owner_id
            || origin.incarnation != self.bootstrap.authority.incarnation_id
            || origin.owner_generation != self.bootstrap.authority.owner_generation
            || origin.child_pid.get() == 0
            || !self
                .profile
                .implementation
                .artifacts
                .iter()
                .any(|artifact| {
                    artifact.id.as_str() == "device" && artifact.content == origin.native_executable
                })
            || record::<Value>(self, &origin.initialize_request, "application/json")?
                != json!({"command":"initialize","dialect":origin.dialect,"owner":origin.owner,"incarnation":origin.incarnation,"generation":origin.owner_generation})
            || wire(self, &origin.initialize_response_wire)?
                != json!({"result":"ready","dialect":origin.dialect,"owner":origin.owner,"incarnation":origin.incarnation,"generation":origin.owner_generation,"child_pid":origin.child_pid})
        {
            return Err(ProviderError::Correlation(
                "lineage original native initialization differs",
            ));
        }
        Ok(OriginalLineageRealization {
            controller: self,
            original,
            realization,
            gate,
            closed,
            origin,
        })
    }
}
