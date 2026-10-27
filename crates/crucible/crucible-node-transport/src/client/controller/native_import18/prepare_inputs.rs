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

impl OriginalNativeImport18PrepareInputs {
    /// Quotes native receiving-bank backing from these exact typed Prepare inputs.
    ///
    /// Borrows every reference and its corresponding ceiling in native receive
    /// order, including the separately bound normalization and semantic spend.
    /// The returned [retained, transient, scratch] row includes this adapter's
    /// controls beside the shared native reservation formula. It creates no bank
    /// and copies no reference or body.
    ///
    /// Admit the fixed counter before this nonallocating walk. The original
    /// Source guards, complete signed Prepare/binding authentication, existing
    /// owners, SDK uploads and whole-phase construction remain independently
    /// funded. Unverified inputs may yield DATA; this quote issues no permission.
    ///
    /// # Errors
    /// Refuses malformed references, empty or over-bound role bodies, width or
    /// arithmetic overflow, or a complete row above the supplied restriction.
    pub fn native_receiving_bank_backing_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let references = PacketNativeImport18InputRole::ALL
            .map(|role| role.reference_data(&self.request, &self.binding));
        let mut maximums = [0usize; 7];
        for role in PacketNativeImport18InputRole::ALL {
            maximums[role.ordinal_data()] =
                usize::try_from(role.maximum_bytes_data(&self.binding).get())
                    .map_err(|_| bank_credit())?;
        }

        let mut row = native_import18_receiving_bank_backing_construction_data(
            references, maximums, maximum,
        )?;
        row[2] = row[2]
            .checked_add(bank_quote_wrapper_counter_scratch_data())
            .ok_or_else(bank_credit)?;
        row.into_iter()
            .try_fold(0usize, |sum, axis| sum.checked_add(axis))
            .filter(|sum| *sum <= maximum)
            .ok_or_else(bank_credit)?;
        Ok(row)
    }

    /// Names the shared native quote and this typed adapter's fixed controls.
    pub fn native_receiving_bank_backing_counter_scratch_data() -> usize {
        native_import18_receiving_bank_backing_counter_scratch_data()
            + bank_quote_wrapper_counter_scratch_data()
    }
}

fn bank_quote_wrapper_counter_scratch_data() -> usize {
    size_of::<&OriginalNativeImport18PrepareInputs>()
        + size_of::<&PacketCompleteRestorePrepareRequest>()
        + size_of::<&PacketNativeImport18Binding>()
        + size_of::<[&ContentRef; 7]>()
        + size_of::<[usize; 7]>()
        + size_of::<PacketNativeImport18InputRole>()
        + size_of::<[PacketNativeImport18InputRole; 7]>() * 2
        + size_of::<std::array::IntoIter<PacketNativeImport18InputRole, 7>>() * 2
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<Option<usize>>() * 2
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<U64>()
        + size_of::<usize>() * 4
}

fn bank_credit() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 typed Prepare bank quote")
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
