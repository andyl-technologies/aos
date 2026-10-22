//! Retains original SDK registration and publication without renewing the cut.
//!
//! The defining Source separately authenticates its private signing purpose and
//! admits the complete holder, actual SDK, journal banks and supervisor callback.
//! These operations do not receive a response or authenticate a receipt MAC.

use super::*;
use crate::client::{ClientSession, DeadlineStream};
use crate::connection::Connection;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapAckProof;

struct Sealed<'a> {
    original: &'a Envelope,
    proof: &'a PacketNativeImport18BootstrapAckProof,
    literal: &'a [u8],
}

impl CnpController {
    /// Quotes registration of the actual materialized Bootstrap SDK original.
    ///
    /// The caller first funds the static counter, retains the returned row, ends
    /// its loans and independently admits the whole holder before construction.
    ///
    /// # Errors
    /// Refuses spent custody, changed original guards or a short restriction.
    pub fn quote_original_native_import18_bootstrap_sdk_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        maximum: usize,
    ) -> Result<PacketNativeImport18BootstrapSdkRowData, ProviderError> {
        require_entry(owner, false)?;
        authenticate(self, hello, owner, false, false)?;
        quote(false, maximum)
    }

    /// Retains the registration attempt before checking or cloning the original.
    ///
    /// The same materialized Envelope remains in the Controller; the SDK keeps
    /// an independently funded clone. Failed entry preserves every existing bank
    /// and saved row. Private Source proof authority remains with the caller.
    ///
    /// # Errors
    /// Refuses repeated entry, changed row, original identity/cut/slot, failed
    /// registration or actual retained Controller demand exceeding admission.
    pub fn seal_original_native_import18_bootstrap_data(
        &mut self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        row: &PacketNativeImport18BootstrapSdkRowData,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        require_entry(owner, false)?;
        owner.sdk_started = true;
        owner.sdk_row = Some(*row);
        owner.failed = true;

        let result = (|| {
            authenticate(self, hello, owner, false, false)?;
            if quote(false, maximum)? != *row {
                return Err(invalid());
            }
            let sealed = sealed(owner)?;
            self.session.seal_original_bootstrap_data(
                sealed.original,
                owner.request.as_ref().ok_or_else(invalid)?,
                sealed.proof,
                (sealed.literal, owner.literal_slot),
                owner.cut.ok_or_else(invalid)?,
            )
        })();
        let census = census(owner);
        let terminal = authenticate(self, hello, owner, true, false);
        result?;
        census?;
        terminal?;
        owner.sdk_sealed = true;
        owner.failed = false;
        Ok(())
    }

    /// Quotes the unchanged registered original's sole publication attempt.
    ///
    /// SDK and possible incident clones remain independently funded even when
    /// an earlier component already owns them. The row grants no Source credit.
    ///
    /// # Errors
    /// Refuses spent custody, changed original guards or a short restriction.
    pub fn quote_original_native_import18_bootstrap_publication_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        maximum: usize,
    ) -> Result<PacketNativeImport18BootstrapSdkRowData, ProviderError> {
        require_entry(owner, true)?;
        authenticate(self, hello, owner, true, false)?;
        quote(true, maximum)
    }

    /// Publishes the same retained SDK original and literal exactly once.
    ///
    /// The attempt and row survive before any fallible guard. Session sequence
    /// consumption precedes writing; partial writes and later refusals keep the
    /// actual SDK original, journal progress and Controller construction banks.
    /// This method neither receives nor completes the Bootstrap transaction.
    ///
    /// # Errors
    /// Refuses repeated entry, changed row or original guards, uncertain I/O,
    /// expired original cut or retained demand exceeding the saved admission.
    pub fn publish_original_native_import18_bootstrap_data(
        &mut self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        row: &PacketNativeImport18BootstrapSdkRowData,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        require_entry(owner, true)?;
        owner.publication_started = true;
        owner.publication_row = Some(*row);
        owner.failed = true;

        let result = (|| {
            authenticate(self, hello, owner, true, false)?;
            if quote(true, maximum)? != *row {
                return Err(invalid());
            }
            let sealed = sealed(owner)?;
            self.session.publish_original_bootstrap_data(
                sealed.original,
                owner.request.as_ref().ok_or_else(invalid)?,
                sealed.proof,
                (sealed.literal, owner.literal_slot),
                owner.cut.ok_or_else(invalid)?,
            )
        })();
        let census = census(owner);
        let terminal = authenticate(self, hello, owner, true, true);
        result?;
        census?;
        terminal?;
        owner.published = true;
        owner.failed = false;
        Ok(())
    }

    /// Names the actual Controller, SDK, physical journal and census controls.
    pub fn original_native_import18_bootstrap_sdk_counter_scratch_data() -> usize {
        Self::original_native_import18_bootstrap_materialization_counter_scratch_data()
            + ClientSession::original_bootstrap_registered_counter_scratch_data()
            + size_of::<Sealed<'static>>()
            + size_of::<Result<Sealed<'static>, ProviderError>>()
            + size_of::<PacketNativeImport18BootstrapSdkRowData>() * 2
            + size_of::<Result<PacketNativeImport18BootstrapSdkRowData, ProviderError>>()
            + size_of::<&mut Self>()
            + size_of::<&OriginalHelloJournal>()
            + size_of::<&mut OriginalNativeImport18Bootstrap>()
            + size_of::<[usize; 3]>()
            + size_of::<[Result<(), ProviderError>; 3]>()
            + size_of::<bool>() * 2
    }
}

fn require_entry(
    owner: &OriginalNativeImport18Bootstrap,
    publication: bool,
) -> Result<(), ProviderError> {
    if owner.failed
        || !owner.retained
        || !owner.reserved
        || !owner.materialization_started
        || owner.sealing.is_none()
        || if publication {
            !owner.sdk_started || !owner.sdk_sealed || owner.publication_started || owner.published
        } else {
            owner.sdk_started || owner.sdk_sealed || owner.publication_started || owner.published
        }
    {
        return Err(invalid());
    }
    Ok(())
}

fn sealed(owner: &OriginalNativeImport18Bootstrap) -> Result<Sealed<'_>, ProviderError> {
    let history = owner
        .sealing
        .as_ref()
        .ok_or_else(invalid)?
        .borrowed_history_data();
    let assignment = history.assignment.ok_or_else(invalid)?;
    if !history.sealed || history.failed || !assignment.assigned || assignment.failed {
        return Err(invalid());
    }
    Ok(Sealed {
        original: assignment.original.ok_or_else(invalid)?,
        proof: history.proof.ok_or_else(invalid)?,
        literal: history.literal.ok_or_else(invalid)?,
    })
}

fn authenticate(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
    registered: bool,
    published: bool,
) -> Result<(), ProviderError> {
    // Evaluate the real original clock after either effect outcome, even if a
    // later custody/physical guard refuses an already fenced endpoint.
    let cut = owner.cut.ok_or_else(invalid)?;
    let deadline = controller
        .session
        .authenticate_original_bootstrap_effect_cut_data(cut, if published { 3 } else { 2 });
    let identity = signing::authenticate_original_identity_data(controller, hello, owner);
    let physical = (|| {
        let sealed = sealed(owner)?;
        let request = owner.request.as_ref().ok_or_else(invalid)?;
        if registered {
            controller
                .session
                .authenticate_original_bootstrap_registered_data(
                    sealed.original,
                    request,
                    sealed.proof,
                    (sealed.literal, owner.literal_slot),
                    (cut, published),
                )
        } else {
            controller
                .session
                .authenticate_original_bootstrap_materialization_data(
                    sealed.original,
                    request,
                    sealed.proof,
                    cut,
                    owner.literal_slot,
                )
        }
    })();
    deadline?;
    identity?;
    physical
}

fn quote(
    publication: bool,
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapSdkRowData, ProviderError> {
    let mut axes =
        Connection::<DeadlineStream>::original_bootstrap_sealing_construction_data(maximum)?;
    axes[0] = axes[0]
        .checked_add(size_of::<PacketNativeImport18BootstrapSdkRowData>())
        .ok_or_else(credit)?;
    axes[1] = axes[1]
        .checked_add(size_of::<PacketNativeImport18BootstrapSdkRowData>() * 2)
        .ok_or_else(credit)?;
    axes[2] = axes[2]
        .checked_add(CnpController::original_native_import18_bootstrap_sdk_counter_scratch_data())
        .ok_or_else(credit)?;
    if storage::checked_sum_data(&axes)? > maximum {
        return Err(credit());
    }
    Ok(PacketNativeImport18BootstrapSdkRowData { axes, publication })
}

fn census(owner: &OriginalNativeImport18Bootstrap) -> Result<(), ProviderError> {
    // SDK backing is owned by the actual Session and separately admitted by
    // the complete Source holder. This census prices the Controller's banks.
    materialization::check_retained(
        owner,
        owner.materialization_row.as_ref().ok_or_else(invalid)?,
    )
}

#[cfg(test)]
#[path = "publication/tests.rs"]
mod tests;
