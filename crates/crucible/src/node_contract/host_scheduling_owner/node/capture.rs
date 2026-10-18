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
        let mut completed = None;
        self.capture_original_common_state_into(
            ticket,
            activation,
            source,
            runtime_object,
            limits,
            &mut completed,
        )?;
        completed.ok_or_else(|| failure("original Host2 capture result absent"))
    }

    pub(super) fn capture_original_common_state_into(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        if ticket.restored_capture_scope17_data().is_some() {
            return self.capture_restored_common_state17_into_data(
                ticket,
                activation,
                source,
                runtime_object,
                limits,
                completed,
            );
        }
        if self
            .source
            .selection
            .binding
            .compatibility
            .implementation
            .formats
            .iter()
            .any(|schema| schema.id.as_str() == "source-owned.host-scheduling-continuation/17")
        {
            return Err(failure(
                "selected Host17 capture requires its genuine current17 scope",
            ));
        }
        self.current()?;
        if completed.is_some() {
            return Err(failure("original Host2 capture destination is occupied"));
        }
        if self.source.edition != preservation::Edition::CompleteOriginalLineage
            || self.ready.is_none()
            || activation.record() != &self.activation
            || self.capture_preparation.is_some()
            || self.capture_preparation17.is_some()
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
        // Allocate metadata while the complete original producer is still
        // retained. Moving its once-owned state into the destination follows
        // only infallible field construction.
        let owner_id = owner.owner.clone();
        let participants = self.source.selection.owner.owner.participant_ids.clone();
        self.source
            .retain_capture_journal_dependencies(
                ticket.runtime_object(),
                &snapshot.encoded().reference,
                &journal.reference,
                limits.maximum_total_record_bytes,
            )
            .map_err(failure)?;
        self.current()?;
        let snapshot = self
            .capture_preparation
            .take()
            .ok_or_else(|| failure("host capture producer transferred twice"))?;
        let state = snapshot.into_encoded();
        *completed = Some(InstalledOriginalLineageCapture {
            native: InstalledNativeCapture {
                owner: owner_id,
                participants,
                key,
                cut: ticket.cut(),
                state,
                evidence: Vec::new(),
                artifacts: Vec::new(),
            },
            journal,
        });
        self.current()
    }
}
