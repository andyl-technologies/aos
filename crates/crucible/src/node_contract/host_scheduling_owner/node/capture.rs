//! Moves the original common-state producer under its exact administrative ticket.

use super::super::{complete, preservation};
use super::*;
use crate::node_contract::{
    InstalledNativeCapture, InstalledOriginalLineageCapture, NativeCaptureLimits, NativeStateKey,
    OriginalLineageOwnerCaptureTicket, OriginalLineageRuntimeRecord, WorldActivation,
};
use crate::node_scheduling::InputPayload;

impl PreparedHostSchedulingNode {
    pub(super) fn capture_original_common_state(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledOriginalLineageCapture, OperationFailure> {
        self.current()?;
        if self.source.edition != preservation::Edition::CompleteOriginalLineage
            || self.ready.is_none()
            || activation.record() != &self.activation
            || self.capture_preparation.is_some()
            || limits.maximum_objects < 2
            || limits.maximum_record_bytes < 4096
            || limits.maximum_total_record_bytes
                < limits
                    .maximum_record_bytes
                    .checked_add(4096)
                    .ok_or_else(|| failure("host capture credit overflow"))?
        {
            return Err(failure(
                "complete original host capture is unavailable or undercredited",
            ));
        }
        let owner = self
            .route
            .owners
            .first()
            .ok_or_else(|| failure("host capture owner absent"))?;
        ticket
            .authenticate_scope(
                activation,
                source,
                runtime_object,
                owner,
                &self.source.selection.owner.owner.participant_ids,
            )
            .map_err(failure)?;
        let key = NativeStateKey {
            implementation: self
                .source
                .selection
                .binding
                .compatibility
                .implementation
                .implementation_id
                .clone(),
            profile: crucible_node_contract::Id::new(preservation::PROFILE).map_err(failure)?,
            schema: complete::host_scheduling_complete_continuation_schema()?,
        };
        // Retain the once-owned producer before any fallible metadata encoding.
        self.capture_preparation = Some(
            ticket
                .take_prepared_host_continuation(&self.source, activation, source, runtime_object)
                .map_err(failure)?,
        );
        let snapshot = self
            .capture_preparation
            .as_ref()
            .ok_or_else(|| failure("host capture producer missing"))?;
        if snapshot.encoded().bytes.len() > limits.maximum_record_bytes {
            return Err(failure(
                "original host snapshot exceeds reserved record credit",
            ));
        }
        let record = super::super::json!({
            "schema":"source-owned.host-scheduling-capture-journal/2",
            "capture_id":ticket.capture_id(),"operation":ticket.operation_id(),
            "owner":owner,"participants":ticket.participants(),"cut":ticket.cut(),"ordinal":ticket.ordinal(),
            "runtime":ticket.runtime_object(),"snapshot":snapshot.encoded().reference,
            "transition":"one original unchanged-cut common snapshot; no native operation, input or acknowledgement submitted"
        });
        super::super::credit(&record, 4096)?;
        let bytes = canonical::canonical_json(&record).map_err(failure)?;
        let journal = InputPayload {
            reference: canonical::content_ref(
                &bytes,
                "application/vnd.crucible.host-scheduling-capture-journal+json;version=2",
            )
            .map_err(failure)?,
            bytes,
        };
        self.current()?;
        let snapshot = self
            .capture_preparation
            .take()
            .ok_or_else(|| failure("host capture producer transferred twice"))?;
        let state = snapshot.into_encoded();
        Ok(InstalledOriginalLineageCapture {
            native: InstalledNativeCapture {
                owner: owner.owner.clone(),
                participants: self.source.selection.owner.owner.participant_ids.clone(),
                key,
                cut: ticket.cut(),
                state,
                evidence: Vec::new(),
                artifacts: Vec::new(),
            },
            journal,
        })
    }
}
