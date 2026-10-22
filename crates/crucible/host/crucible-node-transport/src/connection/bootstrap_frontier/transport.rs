//! Dispatches only the original Source Bootstrap18 on the actual retained SDK.
//!
//! Source/Birth purpose, independently admitted whole R/T/S and the unrenewed
//! initial Hello cut remain with the defining Source caller. These private
//! transport operations issue no model, native phase or common Ready witness.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    authenticate_native_import18_immutable_declaration_data,
    bootstrap_ack::{
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
        NATIVE_IMPORT18_BOOTSTRAP_FEATURE, PacketNativeImport18BootstrapAckProof,
        PacketNativeImport18BootstrapRequest, PacketNativeImport18BootstrapResponseDecodeData,
        PacketNativeImport18BootstrapResponseDecodeRowData,
        native_import18_bootstrap_response_decode_into_data,
    },
};
use crate::transport::{RetainedFrame, original_frames::FrameDirection};

#[path = "transport/storage.rs"]
mod storage;
#[path = "transport/wire.rs"]
mod wire;

impl<S: ProviderStream> Connection<S> {
    /// Checks the actual reserved unsigned bootstrap without constructing a DTO.
    ///
    /// # Errors
    /// Refuses a changed endpoint, header/body, SDK frontier or literal slot.
    pub(crate) fn authenticate_original_bootstrap_unsigned_data(
        &self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_bootstrap_frontier_data()?;
        wire::authenticate_data(&self.authority, original, request, None)?;
        self.authenticate_pending_native_import18_data(original, &[], slot, false)
    }

    /// Checks the original endpoint after its unused frontier has been spent.
    ///
    /// This allocation-free guard lends no decoded body or selected phase.
    ///
    /// # Errors
    /// Refuses another actor, revoked registration or fenced/noncontroller SDK.
    pub(crate) fn authenticate_original_bootstrap_endpoint_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authority.ensure_live()?;
        if self.fenced || self.role != EndpointRole::Controller {
            return Err(refused());
        }
        Ok(())
    }

    /// Retains original SDK custody while fencing a refused Session cut.
    pub(crate) fn contain_original_bootstrap_data(&mut self) {
        self.contain(ConnectionFailure::Protocol);
    }

    /// Names the allocation-free endpoint's actual borrowed guard controls.
    pub(crate) fn original_bootstrap_endpoint_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<&ConnectionAuthority>()
            + size_of::<std::sync::atomic::Ordering>()
            + size_of::<u64>()
            + size_of::<bool>()
            + size_of::<[Result<(), ProviderError>; 3]>()
    }

    /// Checks full immutable18 rosters beside the actual installed controller.
    ///
    /// The caller admits all exact schema-factory windows before entry.
    ///
    /// # Errors
    /// Refuses foreign actor/codec/role, incomplete declarations or negotiation.
    fn original_bootstrap_transport_selection_data(&self) -> Result<(), ProviderError> {
        let selection = self.native_import18_selection_data()?;
        let [binding] = selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        authenticate_native_import18_immutable_declaration_data(
            &selection.provider.implementation.formats,
            &binding.compatibility.implementation.formats,
            &selection.provider.extensions_supported,
        )?;
        if self.fenced
            || !self
                .authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == NATIVE_IMPORT18_BOOTSTRAP_FEATURE)
            || !self
                .authority
                .envelope_extensions()
                .contains(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
            || !self
                .authority
                .envelope_extensions()
                .contains(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)
        {
            return Err(refused());
        }
        self.authority.ensure_live()
    }

    /// Reserves the final sequence-two bootstrap literal before Source signing.
    ///
    /// # Errors
    /// Refuses occupied output, another header/body/selection, intervening traffic,
    /// reused original ID or insufficient independently reserved frame capacity.
    pub(crate) fn reserve_original_bootstrap_data(
        &mut self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        maximum: usize,
        output: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        self.original_bootstrap_transport_selection_data()?;
        self.authenticate_original_bootstrap_frontier_data()?;
        wire::authenticate_data(&self.authority, original, request, None)?;
        if maximum == 0 || maximum > allowance(self.authority.limits().frame_bytes.get())? {
            return Err(refused());
        }
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let mut bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        if !bank.complete() || bank.contains_original_id(id.as_str()) {
            return Err(refused());
        }
        let slot = bank.begin(
            FrameDirection::Outgoing,
            maximum.checked_add(4).ok_or_else(refused)?,
        )?;
        *output = Some(slot);
        bank.retain_request(slot, id)
    }

    /// Seals the exact canonical bootstrap proposal and retains its SDK original.
    ///
    /// The caller retains its prepared DOM/literal and Source proof before entry
    /// and separately funds this verification's DOM/JCS/clone windows. Its proof
    /// signer remains the only owner of genuine Source signing permission.
    ///
    /// # Errors
    /// Refuses changed proof/body/bytes or slot. Later failures fence transport
    /// while preserving the actual literal prefix and any registered original.
    pub(crate) fn seal_original_bootstrap_data(
        &mut self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        proof: &PacketNativeImport18BootstrapAckProof,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            self.original_bootstrap_transport_selection_data()?;
            self.authenticate_original_bootstrap_frontier_data()?;
            wire::authenticate_data(&self.authority, original, request, Some(proof))?;
            self.authenticate_pending_native_import18_data(original, &[], slot, false)?;
            let maximum = allowance(self.authority.limits().frame_bytes.get())?;
            if bytes.is_empty() || bytes.len() > maximum {
                return Err(refused());
            }
            let proposal = serde_json::to_value(original)
                .map_err(crucible_node_format::ContractError::from)?;
            if crucible_node_format::canonical::canonical_json(&proposal)? != bytes {
                return Err(refused());
            }
            let length = u32::try_from(bytes.len()).map_err(|_| refused())?;
            let slot = slot.ok_or_else(refused)?;
            let mut bank = self
                .original_frames
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow_mut()
                .map_err(|_| refused())?;
            bank.append(slot, &length.to_be_bytes())?;
            bank.append(slot, bytes)?;
            drop(bank);
            self.authority
                .with_live(|| self.guard.register_outgoing(original.clone()))?;
            self.guard.original_bootstrap_pending_data(original)
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }

    /// Publishes the same sealed bootstrap literal without resetting a deadline.
    ///
    /// # Errors
    /// Refuses changed original/proof/selection or pending literal. Failed writes
    /// retain their transferred prefix and fence the actual original connection.
    pub(crate) fn publish_original_bootstrap_data(
        &mut self,
        original: &Envelope,
        request: &PacketNativeImport18BootstrapRequest,
        proof: &PacketNativeImport18BootstrapAckProof,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            self.original_bootstrap_transport_selection_data()?;
            wire::authenticate_data(&self.authority, original, request, Some(proof))?;
            self.guard.original_bootstrap_pending_data(original)?;
            self.authenticate_pending_native_import18_data(original, bytes, slot, true)?;
            self.check_authority()?;
            self.publish_original_send(bytes, slot)
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        }
        result
    }

    /// Retains the actual bounded raw response before dedicated DTO decoding.
    ///
    /// The Source caller independently derives and admits raw parser/Value and
    /// literal-bank demand. No Prepare-response metadata profile is borrowed.
    ///
    /// # Errors
    /// Refuses occupied output, short/invalid bound, changed SDK or uncertain I/O.
    /// A complete parsed raw frame remains installed after later refusal.
    pub(crate) fn receive_original_bootstrap_raw_into_data(
        &mut self,
        original: &Envelope,
        maximum: usize,
        output: &mut Option<RetainedFrame>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        let result = (|| {
            self.original_bootstrap_transport_selection_data()?;
            self.guard.original_bootstrap_pending_data(original)?;
            if maximum == 0 || maximum > allowance(self.authority.limits().frame_bytes.get())? {
                return Err(refused());
            }
            self.ensure_no_pending_native_restore_response()?;
            self.check_authority()?;
            *output = Some(
                self.reader
                    .read_retained_with_maximum_bytes(maximum)?
                    .ok_or_else(refused)?,
            );
            self.authenticate_native_import18_raw_data(
                original,
                output.as_ref().ok_or_else(refused)?,
            )
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Read);
        }
        result
    }

    /// Decodes the actual current raw response before moving the SDK original.
    ///
    /// Parsed fields and the moved request occupy independently retained slots.
    /// The Source still verifies its independently reconstructed receipt MAC and
    /// original cut before issuing its private completion witness.
    ///
    /// # Errors
    /// Refuses occupied output, changed raw/SDK/policy or closed body grammar.
    /// Every initialized output and the actual original survive later fencing.
    pub(crate) fn decode_original_bootstrap_raw_into_data(
        &mut self,
        original: &Envelope,
        raw: &RetainedFrame,
        row: &PacketNativeImport18BootstrapResponseDecodeRowData,
        maximum: usize,
        outputs: (
            &mut Option<PacketNativeImport18BootstrapResponseDecodeData>,
            &mut Option<Envelope>,
        ),
    ) -> Result<(), ProviderError> {
        let (decoded, retained_request) = outputs;
        if decoded.is_some() || retained_request.is_some() {
            return Err(refused());
        }
        let result = (|| {
            self.original_bootstrap_transport_selection_data()?;
            self.guard.original_bootstrap_pending_data(original)?;
            self.authenticate_native_import18_raw_data(original, raw)?;
            native_import18_bootstrap_response_decode_into_data(
                original, &raw.value, row, maximum, decoded,
            )?;
            let response = decoded
                .as_ref()
                .ok_or_else(refused)?
                .borrowed_history_data()
                .envelope
                .ok_or_else(refused)?;
            self.retain_original_request_id(response, self.reader.original_slot())?;
            self.authority.with_live(|| {
                self.guard.original_bootstrap_receive_into_data(
                    original,
                    response,
                    retained_request,
                )
            })?;
            self.original_bootstrap_transport_selection_data()?;
            self.guard.original_bootstrap_received_data(
                retained_request.as_ref().ok_or_else(refused)?,
                response,
            )
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("dedicated Source bootstrap transport changed")
}

#[cfg(test)]
#[path = "transport/tests.rs"]
mod tests;

#[cfg(test)]
impl<S: ProviderStream> Connection<S> {
    /// Observes model literal custody after fencing without borrowing live policy.
    pub(crate) fn original_bootstrap_model_storage_data(
        &self,
    ) -> crate::protocol_snapshot::OriginalProtocolStorageFacts {
        let maximum = usize::try_from(self.authority.limits().frame_bytes.get()).unwrap();
        self.original_frames
            .as_ref()
            .unwrap()
            .borrow()
            .storage_facts(maximum)
    }

    /// Lends inert model negotiation operands; it creates no Source permission.
    pub(crate) fn original_bootstrap_model_controller_data() -> (
        crate::handshake::Handshake,
        ConnectionAuthority,
        crate::reference_packet::control::PacketControlSelection,
        crate::reference_service::InstalledContent,
    ) {
        tests::scope_inputs(None)
    }
}
