//! Transfers actual Prepare inputs only when their retained destination is empty.
//!
//! An early emitter refusal leaves the caller's input slot intact. After the
//! transfer, the assignment keeps the same typed owners before row/query checks.
//! These inputs and an unverified assignment grant no Source or native rights.

use super::*;
use std::mem::size_of;

/// Retains typed Prepare inputs before the SDK accepts their ownership.
///
/// Callers keep this record in their original retained scope. Early refusal
/// leaves that slot populated; later refusal keeps the same fields in the
/// assignment destination. Preserved inputs do not renew the Source's once
/// scope or authorize retry, signing, upload, model installation or World.
pub struct OriginalNativeImport18PrepareInputs {
    /// Names the predetermined original Prepare request.
    pub request_id: Id,
    /// Retains the exact baseline Begin payload for that assignment.
    pub baseline: BeginRequest,
    /// Retains the complete inert Prepare request before validation.
    pub request: PacketCompleteRestorePrepareRequest,
    /// Retains its full inert import18 binding before validation.
    pub binding: PacketNativeImport18Binding,
    /// Retains the full schema from the independently authenticated cold owner.
    pub expected_backend_schema: SchemaRef,
}

/// Moves the actual inputs before any subsequent fallible assignment work.
///
/// # Errors
/// Refuses an occupied destination or absent inputs without consuming either slot.
pub(super) fn retain_into(
    controller: &Rc<ProtocolCaptureOwner>,
    incoming: &mut Option<OriginalNativeImport18PrepareInputs>,
    output: &mut Option<OriginalNativeImport18Assignment>,
) -> Result<(), ProviderError> {
    if output.is_some() {
        return Err(invalid());
    }

    let OriginalNativeImport18PrepareInputs {
        request_id,
        baseline,
        request,
        binding,
        expected_backend_schema,
    } = incoming.take().ok_or_else(invalid)?;
    // All remaining operations are nonallocating field moves and an Rc handle
    // clone. No fallible validation can strand the consumed input record.
    *output = Some(OriginalNativeImport18Assignment {
        controller: Rc::clone(controller),
        binding,
        expected_backend_schema,
        normalization: Vec::new(),
        prepare: AssignedPhase::new(request_id, baseline, request),
        uploads: input_upload::InputUploadBank::empty(),
    });
    Ok(())
}

/// Names the new owning record and move controls beside earlier constructor terms.
pub(super) fn counter_scratch_data() -> usize {
    2 * size_of::<OriginalNativeImport18PrepareInputs>()
        + 2 * size_of::<Option<OriginalNativeImport18PrepareInputs>>()
        + size_of::<&mut Option<OriginalNativeImport18PrepareInputs>>()
        + size_of::<&Rc<ProtocolCaptureOwner>>()
        + size_of::<&mut Option<OriginalNativeImport18Assignment>>()
        + 2 * size_of::<Result<(), ProviderError>>()
        + 2 * size_of::<bool>()
        // Prepare's outer/inner quote and the prospective upload quote each
        // retain a caller and callee input-record view beside all old controls.
        + 6 * size_of::<&OriginalNativeImport18PrepareInputs>()
}

#[cfg(test)]
#[path = "prepare_inputs/tests.rs"]
mod tests;
