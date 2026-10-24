//! Lends actual settled Bootstrap operands under current Controller custody.
//!
//! The defining Source retains its private verification outputs and separately
//! checks birth, purpose, lease, context and receipt MAC before completing once.

use super::*;
use crate::client::ClientSession;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckReceipt,
    PacketNativeImport18BootstrapResponseDecodeHistoryData, PacketNativeImport18BootstrapResult,
    PacketNativeImport18BootstrapSealingHistoryData,
};

impl CnpController {
    /// Lends the original request and settled response to Source verification.
    ///
    /// The callback receives the actual moved SDK request, typed response,
    /// decoded request, result and receipt. The same Controller, Hello, literal,
    /// SDK settlement and original cut bracket the callback after either outcome.
    /// It repeats no read, decode or request clone.
    ///
    /// The Source first admits its whole holder, the endpoint validation
    /// factories, this fixed counter and its callback/output construction. It
    /// retains every initialized output before returning. The Copy result cannot
    /// carry a loaned protocol object out of this scope. This loan supplies no
    /// private MAC verification or Source completion.
    ///
    /// # Errors
    /// Refuses incomplete or failed settlement, foreign custody, changed raw or
    /// typed response, expired/replaced original time, or callback refusal.
    ///
    /// # Panics
    /// Propagates a panic raised by `inspect`.
    pub fn with_original_native_import18_bootstrap_receipt_data<R: Copy>(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        inspect: impl FnOnce(
            &Envelope,
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapResult,
            &PacketNativeImport18BootstrapAckReceipt,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if owner.failed || !owner.retained || !owner.sdk_settled {
            return Err(invalid());
        }
        sdk_settlement::authenticate_terminal(self, hello, owner)?;
        let history = owner
            .sealing
            .as_ref()
            .ok_or_else(invalid)?
            .borrowed_history_data();
        let original = history
            .assignment
            .ok_or_else(invalid)?
            .original
            .ok_or_else(invalid)?;

        let result = self.session.with_original_bootstrap_settled_data(
            original,
            owner.cut.ok_or_else(invalid)?,
            owner.raw_response.as_ref().ok_or_else(invalid)?,
            owner.settled_request.as_ref().ok_or_else(invalid)?,
            owner.decoded_response.as_ref().ok_or_else(invalid)?,
            |moved, decoded| {
                let decoded = decoded.borrowed_history_data();
                inspect(
                    moved,
                    decoded.envelope.ok_or_else(invalid)?,
                    decoded.request.ok_or_else(invalid)?,
                    decoded.result.ok_or_else(invalid)?,
                    decoded.receipt.ok_or_else(invalid)?,
                )
            },
        );
        let terminal = sdk_settlement::authenticate_terminal(self, hello, owner);
        let output = result?;
        terminal?;
        Ok(output)
    }

    /// Names actual settled receipt loans and concrete Copy-result controls.
    ///
    /// Whole-holder backing, endpoint validation factories and callback/output
    /// construction remain separately admitted by the defining Source.
    pub fn original_native_import18_bootstrap_receipt_loan_counter_scratch_data<R: Copy>() -> usize
    {
        Self::original_native_import18_bootstrap_sdk_settlement_counter_scratch_data()
            + ClientSession::original_bootstrap_settled_loan_counter_scratch_data::<R>()
            + size_of::<&Self>()
            + size_of::<&OriginalHelloJournal>()
            + size_of::<&OriginalNativeImport18Bootstrap>()
            + size_of::<PacketNativeImport18BootstrapSealingHistoryData<'static>>()
            + size_of::<PacketNativeImport18BootstrapResponseDecodeHistoryData<'static>>()
            + size_of::<&Envelope>() * 2
            + size_of::<&PacketNativeImport18BootstrapRequest>()
            + size_of::<&PacketNativeImport18BootstrapResult>()
            + size_of::<&PacketNativeImport18BootstrapAckReceipt>()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
            + size_of::<Result<(), ProviderError>>()
    }
}
