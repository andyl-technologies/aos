//! Retains the same Bootstrap assignment and proof across guarded materialization.
//!
//! No SDK original is registered and no bytes are written. The Source separately
//! owns its private signing purpose and independently admits the complete holder.

use super::*;
use crate::client::ClientSession;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapMaterializationRowData,
    PacketNativeImport18BootstrapSealingRowData,
    native_import18_bootstrap_sealing_counter_scratch_data,
    native_import18_bootstrap_sealing_into_data, native_import18_bootstrap_sealing_quote_data,
};

impl CnpController {
    /// Quotes retained materialization under the actual reserved unsigned cut.
    ///
    /// The caller funds the defining static counter before quoting, retains this
    /// row, ends all loans and independently admits its axes beside the whole
    /// Source/Controller/Hello holder before construction. No serializer runs.
    ///
    /// # Errors
    /// Refuses a spent owner, changed original guards, malformed proof, checked
    /// overflow or derived demand exceeding the restriction.
    pub fn quote_original_native_import18_bootstrap_materialization_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        proof: &PacketNativeImport18BootstrapAckProof,
        maximum: usize,
    ) -> Result<PacketNativeImport18BootstrapMaterializationRowData, ProviderError> {
        if owner.materialization_started || owner.sealing.is_some() {
            return Err(invalid());
        }
        self.with_original_native_import18_bootstrap_unsigned_data(hello, owner, |_, _| {
            quote_materialization(
                owner.assignment.as_ref().ok_or_else(invalid)?,
                proof,
                maximum,
            )
        })
    }

    /// Retains the same unsigned original and typed proof before materialization.
    ///
    /// Occupied or absent input refuses before entry. Otherwise the attempt and
    /// exact component row are saved before original guards. Once moved, every
    /// proof, DOM and canonical prefix belongs to the same Controller owner,
    /// including after refusal. No retry, clock renewal, SDK registration or
    /// network publication follows. The defining Source authenticates its own
    /// current private signing purpose separately; this method verifies no MAC.
    ///
    /// # Errors
    /// Refuses repeated entry, changed original identity/cut/slot, changed quote,
    /// serializer failure or actual surviving demand exceeding the saved row.
    pub fn materialize_original_native_import18_bootstrap_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        proof: &mut Option<PacketNativeImport18BootstrapAckProof>,
        row: &PacketNativeImport18BootstrapMaterializationRowData,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        if owner.failed
            || !owner.retained
            || !owner.reserved
            || owner.materialization_started
            || owner.sealing.is_some()
            || proof.is_none()
        {
            return Err(invalid());
        }
        owner.materialization_started = true;
        owner.materialization_row = Some(*row);
        // The attempt is already retained. The readonly preflight still checks
        // the predecessor's healthy state before this construction marks it failed.
        let preflight =
            self.with_original_bootstrap_unsigned_preflight_data(hello, owner, |_, _| Ok(()));
        owner.failed = true;

        let result = (|| {
            preflight?;
            if quote_materialization(
                owner.assignment.as_ref().ok_or_else(invalid)?,
                proof.as_ref().ok_or_else(invalid)?,
                maximum,
            )? != *row
            {
                return Err(invalid());
            }
            native_import18_bootstrap_sealing_into_data(
                &mut owner.assignment,
                proof,
                &row.component,
                maximum,
                &mut owner.sealing,
            )
        })();
        let census = check_retained(owner, row);
        let terminal = authenticate_terminal(self, hello, owner);
        result?;
        census?;
        terminal?;
        owner.failed = false;
        Ok(())
    }

    /// Names defining Controller/SDK guards, construction and actual census work.
    pub fn original_native_import18_bootstrap_materialization_counter_scratch_data() -> usize {
        Self::original_native_import18_bootstrap_unsigned_loan_counter_scratch_data::<
            PacketNativeImport18BootstrapMaterializationRowData,
        >() + native_import18_bootstrap_sealing_counter_scratch_data()
            + ClientSession::original_bootstrap_materialization_counter_scratch_data()
            + size_of::<PacketNativeImport18BootstrapMaterializationRowData>() * 2
            + size_of::<Result<PacketNativeImport18BootstrapMaterializationRowData, ProviderError>>(
            )
            + size_of::<PacketNativeImport18BootstrapSealingRowData>()
            + size_of::<&mut OriginalNativeImport18Bootstrap>()
            + size_of::<&mut Option<PacketNativeImport18BootstrapAckProof>>()
            + size_of::<&PacketNativeImport18BootstrapAckProof>()
            + size_of::<[usize; 4]>()
            + size_of::<[Result<(), ProviderError>; 3]>()
            + size_of::<Result<usize, ProviderError>>()
    }
}

fn quote_materialization(
    assignment: &PacketNativeImport18BootstrapAssignmentData,
    proof: &PacketNativeImport18BootstrapAckProof,
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapMaterializationRowData, ProviderError> {
    let component = native_import18_bootstrap_sealing_quote_data(assignment, proof, maximum)?;
    let mut axes = component.requested_storage_data();
    axes[0] = axes[0]
        .checked_add(size_of::<PacketNativeImport18BootstrapMaterializationRowData>())
        .ok_or_else(credit)?;
    axes[1] = axes[1]
        .checked_add(size_of::<PacketNativeImport18BootstrapMaterializationRowData>() * 2)
        .ok_or_else(credit)?;
    axes[2] = axes[2]
        .checked_add(
            CnpController::original_native_import18_bootstrap_materialization_counter_scratch_data(
            ),
        )
        .ok_or_else(credit)?;
    if storage::checked_sum_data(&axes)? > maximum {
        return Err(credit());
    }
    Ok(PacketNativeImport18BootstrapMaterializationRowData { component, axes })
}

fn authenticate_terminal(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    // Evaluate the original deadline even if construction or identity refused.
    let cut = owner.cut.ok_or_else(invalid)?;
    let deadline = controller
        .session
        .authenticate_original_bootstrap_effect_cut_data(cut, 2);
    let identity = signing::authenticate_original_identity_data(controller, hello, owner);
    let literal = (|| {
        if let Some(sealing) = &owner.sealing {
            let history = sealing.borrowed_history_data();
            let original = history
                .assignment
                .ok_or_else(invalid)?
                .original
                .ok_or_else(invalid)?;
            if history.sealed && !history.failed {
                return controller
                    .session
                    .authenticate_original_bootstrap_materialization_data(
                        original,
                        owner.request.as_ref().ok_or_else(invalid)?,
                        history.proof.ok_or_else(invalid)?,
                        cut,
                        owner.literal_slot,
                    );
            }
            return controller
                .session
                .authenticate_pending_native_import18_data(
                    original,
                    &[],
                    owner.literal_slot,
                    false,
                );
        }
        let original = owner
            .assignment
            .as_ref()
            .ok_or_else(invalid)?
            .borrowed_history_data()
            .original
            .ok_or_else(invalid)?;
        controller
            .session
            .authenticate_pending_native_import18_data(original, &[], owner.literal_slot, false)
    })();
    deadline?;
    identity?;
    literal
}

pub(super) fn check_retained(
    owner: &OriginalNativeImport18Bootstrap,
    row: &PacketNativeImport18BootstrapMaterializationRowData,
) -> Result<(), ProviderError> {
    let facts = owner.retained_metadata_data()?;
    let actual = size_of::<OriginalNativeImport18Bootstrap>()
        .checked_add(requested_metadata_backing_storage_data(&facts)?)
        .ok_or_else(credit)?;
    // The materialization row owns the moved assignment; its earlier separate
    // assignment row is not needed to cover this surviving construction.
    let admitted = owner.row.axes[0]
        .checked_add(row.axes[0])
        .ok_or_else(credit)?;
    if actual > admitted {
        return Err(credit());
    }
    Ok(())
}

#[cfg(test)]
#[path = "materialization/tests.rs"]
mod tests;
