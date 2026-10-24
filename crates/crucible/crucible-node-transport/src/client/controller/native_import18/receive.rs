//! Prices one actual retained raw import reply before any Envelope reparse.
//!
//! Raw reception, quotation and decoding are separate calls. The Source ends
//! its association/capsule loan and admits this row beside all actual owners
//! before decoding; no callback carries its mutable bank through admission.

use super::*;
use crate::protocol_snapshot::raw_value_reparse;
use crate::retained_metadata::serialization_storage::{
    actual_serialization_storage_data, original_serialization_formatter_temporary_storage_data,
};
use crate::retained_metadata::{
    original_native_oracle_expanded_decode_storage_data,
    original_native_oracle_geometry_counter_scratch_data,
    original_native_oracle_value_decode_storage_data, requested_metadata_backing_storage_data,
};
use std::mem::size_of;

#[path = "receive_controls.rs"]
mod controls;

/// Binds actual raw-frame constructor demand without granting admission.
///
/// Fields are private and the real quote alone constructs this row. The Source
/// retains it before independent whole-owner admission under the same original
/// escrow. It cannot renew the native lease, protocol allowance or deadline.
pub struct OriginalNativeImport18ReceiveConstructionData {
    target: ReceiveTarget,
    json_profile: NativeImport18JsonMetadataProfileData,
    controller: Rc<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    raw_value: *const Value,
    raw_bytes: *const u8,
    raw_length: usize,
    original_sequence: U64,
    retained: usize,
    transient: usize,
    scratch: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ReceiveTarget {
    Prepare,
    Upload(usize),
}

impl OriginalNativeImport18ReceiveConstructionData {
    pub(super) const fn metadata_profile_data(&self) -> NativeImport18JsonMetadataProfileData {
        self.json_profile
    }

    pub(super) const fn target_data(&self) -> ReceiveTarget {
        self.target
    }

    /// Returns independently requested additional decoded-owner storage.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns the actual simultaneous decoder/clone/canonical work bound.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns the defining fixed observer/parser controls.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Counts the real original Controller association of the retained row.
    ///
    /// # Errors
    /// Refuses a foreign creator or metadata exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(self.controller.as_ref())?;
        Ok(observer.finish())
    }

    pub(super) fn authenticate(
        &self,
        owner: &OriginalNativeImport18Assignment,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        owner.authenticate_receive_target(controller, emitter, self.target)?;
        let (raw, original) = owner.receive_target_data(self.target)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &owner.controller)
            || !std::ptr::eq(self.raw_value, &raw.value)
            || self.raw_bytes != raw.bytes.as_ptr()
            || self.raw_length != raw.bytes.len()
            || self.original_sequence != original.sequence
            || self.frontier != controller.original_native5_storage_facts()?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl OriginalNativeImport18Assignment {
    /// Names real raw scanner/DTO/serializer controls BEFORE any prewalk.
    pub fn receive_counter_scratch_data() -> usize {
        CnpController::original_native_import18_assignment_counter_scratch_data()
            + raw_value_reparse::value_scanner_counter_scratch_data()
            + controls::counter_scratch_data()
            + original_native_oracle_geometry_counter_scratch_data()
            + size_of::<OriginalNativeImport18ReceiveConstructionData>()
            + size_of::<Result<OriginalNativeImport18ReceiveConstructionData, ProviderError>>()
            + size_of::<&crate::transport::RetainedFrame>()
            + size_of::<Result<&crate::transport::RetainedFrame, ProviderError>>()
            + size_of::<raw_value_reparse::JsonValueReparseConstructionData>()
            + size_of::<Result<raw_value_reparse::JsonValueReparseConstructionData, ProviderError>>(
            )
            + size_of::<(
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
            )>()
            + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData, ProviderError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), ProviderError>>()
            + size_of::<ReceiveTarget>()
            + size_of::<(&crate::transport::RetainedFrame, &Envelope)>()
            + size_of::<Result<(&crate::transport::RetainedFrame, &Envelope), ProviderError>>()
            // The tuple above names all three independently live raw,
            // original and binding serialization facts throughout quotation.
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<&Value>()
            + size_of::<&[u8]>()
            + size_of::<Result<(usize, usize), ProviderError>>()
    }

    /// Quotes the actual selected-contract workspace before full raw quotation.
    ///
    /// This pure origin/Rc check allocates no schema, serializer or parser. The
    /// caller admits static S first, then the returned T/S before the full row.
    ///
    /// # Errors
    /// Refuses another actor, an absent strict raw occurrence, stage or overflow.
    pub fn prepare_receive_prewalk_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(usize, usize), ProviderError> {
        self.authenticate_raw_origin(controller, emitter)?;
        self.receive_quote_workspace_data()
    }

    pub(super) fn receive_quote_workspace_data(&self) -> Result<(usize, usize), ProviderError> {
        let (contract, _) = native_import18_contract_storage_data(usize::MAX)?;
        let facts = metadata::facts(&self.binding)?;
        let formatter = original_serialization_formatter_temporary_storage_data(&facts)?;
        Ok((
            sum(&[contract, formatter, 20])?,
            Self::receive_counter_scratch_data(),
        ))
    }

    /// Quotes this actual strict raw Value's expanded Envelope and body decoders.
    ///
    /// The raw read already passed the strict depth64 transport parser. The
    /// defining RawValue scanner therefore meets its owned-Value depth128 input
    /// precondition without assuming a particular serde feature configuration.
    /// No Envelope, body DTO, raw-value parser or output clone runs here.
    /// The returned row is DATA; Source must end these loans and admit it beside
    /// all actual retained roots before calling decode_prepare_received_data.
    ///
    /// # Errors
    /// Refuses changed raw occurrence/cut/selection, overflow or requested bound.
    pub fn quote_prepare_receive_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        maximum: usize,
    ) -> Result<OriginalNativeImport18ReceiveConstructionData, ProviderError> {
        self.quote_receive_target_data(controller, emitter, maximum, ReceiveTarget::Prepare)
    }

    pub(super) fn quote_receive_target_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        maximum: usize,
        target: ReceiveTarget,
    ) -> Result<OriginalNativeImport18ReceiveConstructionData, ProviderError> {
        self.authenticate_receive_target(controller, emitter, target)?;
        let (raw, original) = self.receive_target_data(target)?;
        let extra = raw_value_reparse::quote_value_data(&raw.value, maximum)?;
        let raw_population = actual_serialization_storage_data(
            &raw.value,
            RetainedProtocolMetadataFacts::default(),
            maximum,
        )?;
        let expanded = original_native_oracle_expanded_decode_storage_data(&extra, maximum)?;
        let baseline = original_native_oracle_value_decode_storage_data(&raw.value, maximum)?;
        let ordinary =
            crate::connection::original_host_initial_raw_receive_storage_data(raw.bytes.len())?;
        let (contract, _) = native_import18_contract_storage_data(maximum)?;

        // Connection::validate_body decodes the retained original request again;
        // Prepare receipt verification repeats it and projects payload/binding
        // and unsigned-original hashes. Those are genuine current operands,
        // independent of the incoming response tree.
        let original_body =
            crate::retained_metadata::original_native_oracle_body_decode_storage_data(
                &original.body,
                maximum,
            )?;
        let original_extra = raw_value_reparse::quote_map_data(&original.body, maximum)?;
        let original_expanded =
            original_native_oracle_expanded_decode_storage_data(&original_extra, maximum)?;
        let original_request_decode =
            sum(&[original_body, original_expanded.0, original_expanded.1])?;
        let original_projection = actual_serialization_storage_data(
            original,
            RetainedProtocolMetadataFacts::default(),
            maximum,
        )?;
        let binding_projection = actual_serialization_storage_data(
            &self.binding,
            metadata::facts(&self.binding)?,
            maximum,
        )?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(self.controller.as_ref())?;
        let association = requested_metadata_backing_storage_data(&observer.finish())?;

        // These are distinct retained outputs in the actual code, not a blanket
        // multiplier: Envelope, ReceivedFrame envelope, controller cached
        // Envelope, ReceivedFrame ResponseBody, and capsule decoded ResponseBody.
        // The defining baseline roster includes precisely the Value/String/u8/Id
        // and pinned serde Content containers used by Begin and Blob responses.
        // Uploads conservatively retain the same independently named capsule
        // decode/receipt allowance even though only Prepare uses those slots.
        // A nonmatching header cannot reach a request-method decoder.
        let envelope = sum(&[baseline, expanded.0])?;
        let received_envelope = envelope;
        let cached_envelope = envelope;
        let received_body = envelope;
        let capsule_decoded_body = envelope;
        let retained = sum(&[
            size_of::<OriginalNativeImport18ReceiveConstructionData>(),
            association,
            envelope,
            received_envelope,
            cached_envelope,
            received_body,
            capsule_decoded_body,
            // ReceivedBody owns the separately allocated ResponseBody box.
            size_of::<ResponseBody>(),
        ])?;

        // Bodies::object independently canonicalizes/clones Shape and Result;
        // decode_response is invoked once by the Connection and once by the
        // owning capsule. Error.details is an alternative to Result, retaining
        // its own canonical validation. Charge all named alternatives rather
        // than assume malformed extension values cannot reach these decoders.
        let envelope_decode = sum(&[baseline, expanded.0, expanded.1])?;
        let connection_shape = sum(&[ordinary, baseline, expanded.0, expanded.1])?;
        let connection_result = connection_shape;
        let capsule_shape = connection_shape;
        let capsule_result = connection_shape;
        let receipt_decode = envelope_decode;
        let transient = sum(&[
            envelope_decode,
            connection_shape,
            connection_result,
            capsule_shape,
            capsule_result,
            receipt_decode,
            original_request_decode, // Connection response classification.
            original_request_decode, // Capsule receipt correspondence.
            original_projection.requested_total()?, // Payload canonical digest.
            original_projection.requested_total()?, // Unsigned original digest.
            binding_projection.requested_total()?, // Full binding digest.
            contract,
            size_of::<Envelope>(),
            size_of::<Result<Envelope, serde_json::Error>>(),
            size_of::<crate::connection::ReceivedFrame>(),
            size_of::<Option<crate::connection::ReceivedFrame>>(),
            size_of::<OriginalNativeImport18ReceiveConstructionData>(),
            size_of::<Result<OriginalNativeImport18ReceiveConstructionData, ProviderError>>(),
        ])?;
        let scratch = sum(&[
            Self::receive_counter_scratch_data(),
            expanded.2,
            original_expanded.2,
            controls::expanded_scratch_data(&extra)?,
            controls::expanded_scratch_data(&original_extra)?,
            original_projection.declared_counter_scratch_bytes,
            binding_projection.declared_counter_scratch_bytes,
        ])?;
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(credit());
        }
        let mut json_profile = NativeImport18JsonMetadataProfileData::from_reparse_population_data(
            &extra,
            raw_population.serialized_value_nodes,
            raw_population.serialized_capacity_records,
        )?
        .covering_data(
            NativeImport18JsonMetadataProfileData::from_reparse_population_data(
                &original_extra,
                original_projection.serialized_value_nodes,
                original_projection.serialized_capacity_records,
            )?,
        );
        json_profile = json_profile.including_data(match target {
            ReceiveTarget::Prepare => self.prepare.json_profile,
            ReceiveTarget::Upload(index) => self.upload_metadata_profile_data(index)?,
        })?;
        json_profile.retain_strict_raw_population_data(raw.bytes.len());
        let row = OriginalNativeImport18ReceiveConstructionData {
            target,
            json_profile,
            controller: Rc::clone(&self.controller),
            frontier: controller.original_native5_storage_facts()?,
            raw_value: &raw.value,
            raw_bytes: raw.bytes.as_ptr(),
            raw_length: raw.bytes.len(),
            original_sequence: original.sequence,
            retained,
            transient,
            scratch,
        };
        self.authenticate_receive_target(controller, emitter, target)?;
        Ok(row)
    }

    /// Spends this raw occurrence and decodes only under its independently paid row.
    ///
    /// Completion means a bounded-input lease, never model/Hold/World readiness.
    /// The Source retains the row and all partial owners on any refusal.
    ///
    /// # Errors
    /// Refuses another row/raw occurrence, cut, actor, malformed body or receipt.
    pub fn decode_prepare_received_data(
        &mut self,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        row: &OriginalNativeImport18ReceiveConstructionData,
    ) -> Result<(), ProviderError> {
        if row.target != ReceiveTarget::Prepare {
            return Err(invalid());
        }
        row.authenticate(self, controller, emitter)?;
        self.prepare.json_profile = row.json_profile;
        self.prepare.stage = Stage::Decoding;
        let result = super::decode_prepare_receipt(controller, &self.binding, &mut self.prepare);
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        result
    }

    fn receive_target_data(
        &self,
        target: ReceiveTarget,
    ) -> Result<(&crate::transport::RetainedFrame, &Envelope), ProviderError> {
        match target {
            ReceiveTarget::Prepare => Ok((
                self.prepare.raw.as_ref().ok_or_else(invalid)?,
                self.prepare.original.as_ref().ok_or_else(invalid)?,
            )),
            ReceiveTarget::Upload(index) => self.upload_raw_data(index),
        }
    }

    fn authenticate_receive_target(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        target: ReceiveTarget,
    ) -> Result<(), ProviderError> {
        match target {
            ReceiveTarget::Prepare => self.authenticate_raw_receive(controller, emitter),
            ReceiveTarget::Upload(index) => {
                self.authenticate_upload_raw_data(controller, emitter, index)
            }
        }
    }

    fn authenticate_raw_origin(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner)
            || self.prepare.stage != Stage::RawReceived
            || self.prepare.raw.is_none()
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn authenticate_raw_receive(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        self.authenticate_raw_origin(controller, emitter)?;
        self.authenticate(controller, emitter)?;
        controller.session.authenticate_native_import18_raw_data(
            self.prepare.original.as_ref().ok_or_else(invalid)?,
            self.prepare.cut.ok_or_else(invalid)?,
            self.prepare.raw.as_ref().ok_or_else(invalid)?,
        )
    }
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(credit)
    })
}
