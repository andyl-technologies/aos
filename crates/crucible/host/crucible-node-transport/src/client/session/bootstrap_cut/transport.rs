//! Brackets dedicated Bootstrap18 transport with the original Hello deadline.
//!
//! The Source retains every output and independently admits the complete holder,
//! parser, constructors and containment windows before entry. These private
//! Session operations never renew time or authenticate a Source receipt MAC.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapRequest,
    PacketNativeImport18BootstrapResponseDecodeData,
    PacketNativeImport18BootstrapResponseDecodeRowData,
};
use crate::transport::RetainedFrame;

impl ClientSession {
    /// Lends the unchanged reserved unsigned original under its actual SDK cut.
    ///
    /// The caller independently admits this guard and its signing callback,
    /// retaining every callback output before returning either result. The Copy
    /// return carries no request, mutable endpoint or Source completion witness.
    /// No schema factory, serializer, allocation or transport operation runs here.
    ///
    /// # Errors
    /// Refuses an expired/replaced cut, changed original slot, pending traffic,
    /// revoked endpoint, callback refusal or a failed terminal guard.
    pub(in crate::client) fn with_original_bootstrap_unsigned_data<R: Copy>(
        &self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        cut: OperationalDeadline,
        slot: Option<usize>,
        inspect: impl FnOnce(&Envelope) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.authenticate_original_bootstrap_unsigned_data(original, request, cut, slot)?;
        let result = inspect(original);
        let terminal =
            self.authenticate_original_bootstrap_unsigned_data(original, request, cut, slot);
        let output = result?;
        terminal?;
        Ok(output)
    }

    fn authenticate_original_bootstrap_unsigned_data(
        &self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        cut: OperationalDeadline,
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        // Capture both results before propagation: a changed/fenced endpoint
        // still evaluates the original deadline, and a bad cut cannot hide a
        // changed physical literal from the defining terminal observation.
        let deadline = self.authenticate_original_bootstrap_effect_cut_data(cut, 2);
        let literal = self
            .connection
            .authenticate_original_bootstrap_unsigned_data(original, request, slot);
        deadline?;
        literal?;
        Ok(())
    }

    /// Names the concrete readonly callback and actual reserved-slot controls.
    pub(in crate::client) fn original_bootstrap_unsigned_loan_counter_scratch_data<R: Copy>()
    -> usize {
        Self::original_bootstrap_effect_cut_counter_scratch_data()
            + crate::connection::native_import18::pending_assignment_counter_scratch_data()
            + Connection::<DeadlineStream>::original_bootstrap_frontier_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Envelope>() * 2
            + size_of::<&PacketNativeImport18BootstrapRequest>()
            + Connection::<DeadlineStream>::original_bootstrap_reservation_counter_scratch_data()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<usize>>()
            + size_of::<R>()
            + size_of::<Result<R, ProviderError>>()
            + size_of::<[Result<(), ProviderError>; 3]>()
    }

    /// Checks the original deadline after assignment has spent the unused SDK.
    ///
    /// # Errors
    /// Refuses a replaced/expired cut, foreign endpoint, response loss or sequence.
    pub(in crate::client) fn authenticate_original_bootstrap_effect_cut_data(
        &self,
        cut: OperationalDeadline,
        sequence: u64,
    ) -> Result<(), ProviderError> {
        let endpoint = self
            .connection
            .authenticate_original_bootstrap_endpoint_data();
        // A failed I/O may already have fenced the endpoint. Evaluate the same
        // original deadline anyway before propagating either guard's refusal.
        let original_cut = self.bootstrap_hello_cut.authenticate(&self.deadline);
        endpoint?;
        if self.sequence.get() != sequence
            || self.original_response_loss.is_some()
            || self.original_ack_hello.is_none()
            || original_cut? != cut
        {
            return Err(refused());
        }
        Ok(())
    }

    fn require_original_bootstrap_effect_cut_data(
        &mut self,
        cut: OperationalDeadline,
        sequence: u64,
    ) -> Result<(), ProviderError> {
        let result = self.authenticate_original_bootstrap_effect_cut_data(cut, sequence);
        if result.is_err() {
            self.connection.contain_original_bootstrap_data();
        }
        result
    }

    /// Checks the same cut even when the original operation already failed.
    fn finish_original_bootstrap_effect_data(
        &mut self,
        result: Result<(), ProviderError>,
        cut: OperationalDeadline,
        sequence: u64,
    ) -> Result<(), ProviderError> {
        let terminal = self.authenticate_original_bootstrap_effect_cut_data(cut, sequence);
        if result.is_err() || terminal.is_err() {
            self.connection.contain_original_bootstrap_data();
        }
        result.and(terminal)
    }

    /// Reserves the sole bootstrap literal under the initial unrenewed cut.
    ///
    /// # Errors
    /// Refuses occupied output, changed initial scope or exhausted literal bank.
    pub(in crate::client) fn reserve_original_bootstrap_data(
        &mut self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        cut: OperationalDeadline,
        maximum: usize,
        output: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        self.require_original_bootstrap_effect_cut_data(cut, 2)?;
        let result = self
            .connection
            .reserve_original_bootstrap_data(original, request, maximum, output);
        self.finish_original_bootstrap_effect_data(result, cut, 2)
    }

    /// Seals the same original without resetting the initial Hello budget.
    ///
    /// # Errors
    /// Refuses changed cut, proof/body/literal or SDK state; retains all outputs.
    pub(in crate::client) fn seal_original_bootstrap_data(
        &mut self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        proof: &PacketNativeImport18BootstrapAckProof,
        literal: (&[u8], Option<usize>),
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.require_original_bootstrap_effect_cut_data(cut, 2)?;
        let result = self
            .connection
            .seal_original_bootstrap_data(original, request, proof, literal.0, literal.1);
        self.finish_original_bootstrap_effect_data(result, cut, 2)
    }

    /// Spends the Session sequence before attempting the original publication.
    ///
    /// The sequence stays spent after a partial or refused write. The original
    /// SDK and literal bank retain their own independent progress and custody.
    ///
    /// # Errors
    /// Refuses changed cut, repeated publication or uncertain transport effects.
    pub(in crate::client) fn publish_original_bootstrap_data(
        &mut self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        proof: &PacketNativeImport18BootstrapAckProof,
        literal: (&[u8], Option<usize>),
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.require_original_bootstrap_effect_cut_data(cut, 2)?;
        self.sequence = U64::new(3);
        let result = self
            .connection
            .publish_original_bootstrap_data(original, request, proof, literal.0, literal.1);
        self.finish_original_bootstrap_effect_data(result, cut, 3)
    }

    /// Retains the bounded raw response under the same original Hello cut.
    ///
    /// # Errors
    /// Refuses occupied output, changed deadline/sequence or incomplete I/O.
    pub(in crate::client) fn receive_original_bootstrap_raw_into_data(
        &mut self,
        original: &Envelope,
        cut: OperationalDeadline,
        maximum: usize,
        output: &mut Option<RetainedFrame>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        self.require_original_bootstrap_effect_cut_data(cut, 3)?;
        let result = self
            .connection
            .receive_original_bootstrap_raw_into_data(original, maximum, output);
        self.finish_original_bootstrap_effect_data(result, cut, 3)
    }

    /// Retains closed decoding and moves the actual SDK original before return.
    ///
    /// # Errors
    /// Refuses occupied outputs, changed cut or response; preserves every prefix.
    pub(in crate::client) fn decode_original_bootstrap_raw_into_data(
        &mut self,
        original: &Envelope,
        cut: OperationalDeadline,
        raw: &RetainedFrame,
        row: &PacketNativeImport18BootstrapResponseDecodeRowData,
        maximum: usize,
        outputs: (
            &mut Option<PacketNativeImport18BootstrapResponseDecodeData>,
            &mut Option<Envelope>,
        ),
    ) -> Result<(), ProviderError> {
        if outputs.0.is_some() || outputs.1.is_some() {
            return Err(refused());
        }
        self.require_original_bootstrap_effect_cut_data(cut, 3)?;
        let result = self
            .connection
            .decode_original_bootstrap_raw_into_data(original, raw, row, maximum, outputs);
        self.finish_original_bootstrap_effect_data(result, cut, 3)
    }

    /// Names fixed Session guards separately from transport and containment work.
    pub(in crate::client) fn original_bootstrap_effect_cut_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<[OperationalDeadline; 3]>()
            + size_of::<OriginalBootstrapHelloCut>()
            + size_of::<&ExchangeDeadline>()
            + size_of::<Result<OperationalDeadline, ProviderError>>()
            + size_of::<u64>()
            + size_of::<U64>()
            + size_of::<bool>()
            + size_of::<[Result<(), ProviderError>; 3]>()
            + Connection::<DeadlineStream>::original_bootstrap_endpoint_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "transport/tests.rs"]
mod tests;
