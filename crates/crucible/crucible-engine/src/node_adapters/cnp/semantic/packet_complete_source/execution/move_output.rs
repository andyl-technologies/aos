//! Moves validated complete output without discarding a partially populated slot.

use super::*;

impl PacketCompleteSemanticSource {
    pub(super) fn move_original_complete_output_into(
        &self,
        execution: &mut OriginalCompleteCaptureExecution,
        banks: &mut capture_banks::PacketCompleteCaptureBanks,
        registry: &mut registry_capture::OriginalCompleteRegistryCapture,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        if completed.is_some()
            || !execution.evidence.is_empty()
            || execution.evidence.capacity() < execution.evidence_roles()
            || execution.allocation_selected != execution.allocation.is_some()
        {
            return Err(refused("original complete move destination differs"));
        }
        let original = (
            execution.owner.take(),
            execution.key.take(),
            banks.semantic_snapshot.take(),
            banks.ancestry_record.take(),
            banks.native_objects[0].take(),
            banks.native_objects[1].take(),
            banks.native_objects[2].take(),
            banks.native_after_object.take(),
            execution.host_protocol.take(),
            registry.take_completed_payload(),
            execution.backend.take(),
            banks.journal_record.take(),
        );
        match original {
            (
                Some(owner),
                Some(key),
                Some(semantic),
                Some(ancestry),
                Some(snapshot),
                Some(control),
                Some(anchor),
                Some(after),
                Some(host),
                Some(registry_body),
                Some(backend),
                Some(journal),
            ) => {
                // Eight independently created bodies move into the already
                // reserved Vec. There are no allocations or fallible fences
                // between the first owner move and filling the Core result.
                execution.evidence.push(control);
                execution.evidence.push(anchor);
                execution.evidence.push(after);
                execution.evidence.push(semantic.into_original_payload());
                execution.evidence.push(ancestry);
                execution.evidence.push(host);
                execution.evidence.push(registry_body);
                execution.evidence.push(backend);
                if let Some(report) = execution.allocation.take() {
                    execution.evidence.push(report);
                }
                *completed = Some(InstalledOriginalLineageCapture {
                    native: InstalledNativeCapture {
                        owner,
                        participants: std::mem::take(&mut execution.participants),
                        key,
                        cut: ticket.cut(),
                        state: snapshot,
                        evidence: std::mem::take(&mut execution.evidence),
                        artifacts: Vec::new(),
                    },
                    journal,
                });
                banks.transferred = true;
                execution.transferred = true;
                Ok(())
            }
            (
                owner,
                key,
                semantic,
                ancestry,
                snapshot,
                control,
                anchor,
                after,
                host,
                registry_body,
                backend,
                journal,
            ) => {
                // Even an internal association regression restores every taken
                // resource. A missing result is never permission to drop the
                // other completed native payloads or replace their banks.
                execution.owner = owner;
                execution.key = key;
                banks.semantic_snapshot = semantic;
                banks.ancestry_record = ancestry;
                banks.native_objects = [snapshot, control, anchor];
                banks.native_after_object = after;
                execution.host_protocol = host;
                registry.restore_completed_payload(registry_body);
                execution.backend = backend;
                banks.journal_record = journal;
                Err(refused("original complete output population is incomplete"))
            }
        }
    }
}
