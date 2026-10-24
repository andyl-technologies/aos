//! Retains distinct Native18 signing assignments in the Source's once owner.
//!
//! The capsule owns one Prepare and its seven input uploads independently of
//! old mapping slots. It issues transport originals only. A Source separately owns
//! its admitted
//! Window/cold/target conjunction and private key; native installation and World
//! publication require the independent native adopter and its original banks.
//! Commit is intentionally not issued here: its actual Held18 producer and
//! defining prefix geometry are separate missing prerequisites.
//!
//! ```text
//! absent -> preparing -> unsigned -> sealing -> sealed -> publishing
//!                                                   -> raw_received -> decoding -> complete
//! ```
//!
//! Every fallible phase follows installation of its actual partial owner. Failed
//! phases never become unused, and resume never renews their operation cut.

use super::*;
use crate::client::session::OriginalAssignedPublicationData;
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::{OriginalProtocolStorageFacts, ProtocolCaptureOwner};
use crate::reference_packet::service::complete_restore::{
    import17::{
        PacketNativeImport17CommitReceipt, PacketNativeImport17PrepareReceipt,
        PacketNativeImport17Proof,
    },
    import18::*,
    transfer::*,
};
use crate::retained_metadata::{
    MetadataObserver, NativeImport18JsonMetadataProfileData, RetainedProtocolMetadataFacts,
};
use crucible_node_format::SchemaRef;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[path = "native_import18/bootstrap.rs"]
mod bootstrap;
pub use bootstrap::{
    OriginalNativeImport18Bootstrap, OriginalNativeImport18BootstrapBirthInputs,
    OriginalNativeImport18BootstrapConstructionData, OriginalNativeImport18BootstrapHistoryData,
    OriginalNativeImport18BootstrapRowHistoryData,
};

#[path = "native_import18/assigned_normalization.rs"]
mod assigned_normalization;
#[path = "native_import18/controller_metadata.rs"]
mod controller_metadata;
#[path = "native_import18/history.rs"]
mod history;
#[path = "native_import18/metadata.rs"]
mod metadata;
#[path = "native_import18/prepare_inputs.rs"]
mod prepare_inputs;
pub use history::OriginalNativeImport18AssignmentHistoryView;
pub use prepare_inputs::OriginalNativeImport18PrepareInputs;
#[path = "native_import18/input_upload.rs"]
mod input_upload;
#[path = "native_import18/receive.rs"]
mod receive;
#[path = "native_import18/registration.rs"]
mod registration;
pub use receive::OriginalNativeImport18ReceiveConstructionData;
#[path = "native_import18/storage.rs"]
mod storage;
pub use input_upload::{
    OriginalNativeImport18InputUploadProspectiveStorageData,
    OriginalNativeImport18InputUploadStorageData,
};
pub use registration::OriginalNativeImport18HostRegistrationView;
pub use storage::OriginalNativeImport18AssignmentStorageData;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Preparing,
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    RawReceived,
    Decoding,
    Complete,
}

struct AssignedPhase<T> {
    stage: Stage,
    request_id: Option<Id>,
    baseline: Option<BeginRequest>,
    request: T,
    body: Option<Value>,
    payload: Option<Value>,
    binding_value: Option<Value>,
    proof: Option<PacketNativeImport17Proof>,
    proof_value: Option<Value>,
    original: Option<Envelope>,
    bytes: Vec<u8>,
    literal_slot: Option<usize>,
    cut: Option<OperationalDeadline>,
    json_profile: NativeImport18JsonMetadataProfileData,
    raw: Option<crate::transport::RetainedFrame>,
    response: Option<Envelope>,
    received: Option<crate::connection::ReceivedFrame>,
    decoded: Option<ResponseBody>,
    prepare_receipt: Option<PacketNativeImport17PrepareReceipt>,
}

impl<T> AssignedPhase<T> {
    fn new(request_id: Id, baseline: BeginRequest, request: T) -> Self {
        Self {
            stage: Stage::Preparing,
            request_id: Some(request_id),
            baseline: Some(baseline),
            request,
            body: None,
            payload: None,
            binding_value: None,
            proof: None,
            proof_value: None,
            original: None,
            bytes: Vec::new(),
            literal_slot: None,
            cut: None,
            json_profile: NativeImport18JsonMetadataProfileData::strict_raw_data(),
            raw: None,
            response: None,
            received: None,
            decoded: None,
            prepare_receipt: None,
        }
    }
}

/// Owns both exact transport assignments without issuing restoration authority.
///
/// The genuine Source retains this noncloneable capsule even after refusal. Its
/// contents cannot construct an old mapping, verified Prepare or native token.
pub struct OriginalNativeImport18Assignment {
    controller: Rc<ProtocolCaptureOwner>,
    binding: PacketNativeImport18Binding,
    expected_backend_schema: SchemaRef,
    normalization: Vec<u8>,
    prepare: AssignedPhase<PacketCompleteRestorePrepareRequest>,
    uploads: input_upload::InputUploadBank,
}

impl CnpController {
    /// Installs the actual Prepare owner before validating or allocating its fields.
    ///
    /// The caller independently admits the row and owns the Source's once slot.
    /// The caller's input slot retains the typed owners through early emitter
    /// and occupied-output refusals. After transfer, the destination retains
    /// them before row/query validation. Constructing and independently funding
    /// those inputs under the original Source once scope remains separate.
    /// The full expected backend schema comes from the actual authenticated cold
    /// owner. It is retained independently rather than inferred from the request.
    /// Source/Window separately prove fresh target definition compatibility; this
    /// transport capsule and its archived definition supply no native authority.
    ///
    /// # Errors
    /// Refuses missing inputs, occupied output, foreign/stale originals or row,
    /// another selected codec, altered normalization/input, exhausted credit or reused ID.
    pub fn prepare_original_native_import18_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        inputs: &mut Option<OriginalNativeImport18PrepareInputs>,
        normalization: &[u8],
        row: &OriginalNativeImport18AssignmentStorageData,
        output: &mut Option<OriginalNativeImport18Assignment>,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self)?;
        prepare_inputs::retain_into(&self.protocol_owner, inputs, output)?;
        let owner = output.as_mut().ok_or_else(invalid)?;
        let result = (|| {
            row.authenticate_prepare_data(self, emitter, query, owner, normalization)?;
            owner.prepare.json_profile = row.json_profile;
            owner.binding.authenticate_prepare_data(
                &owner.prepare.request,
                &owner.expected_backend_schema,
            )?;
            owner.binding.normalization.verify(normalization)?;
            owner
                .normalization
                .try_reserve_exact(normalization.len())
                .map_err(|_| credit())?;
            owner.normalization.extend_from_slice(normalization);
            query.authenticate_current(self, emitter)?;
            self.assign_native_import18_prepare_data(&owner.binding, &mut owner.prepare, row)?;
            Ok(())
        })();
        emitter.authenticate_original(self)?;
        result
    }

    fn assign_native_import18_prepare_data(
        &mut self,
        binding: &PacketNativeImport18Binding,
        owner: &mut AssignedPhase<PacketCompleteRestorePrepareRequest>,
        row: &OriginalNativeImport18AssignmentStorageData,
    ) -> Result<(), ProviderError> {
        let phase = PacketNativeImport18Phase::Prepare;
        self.protocol_owner.ensure_current()?;
        self.session.native_import18_selection_data()?;
        self.ensure_no_pending_original_ack_admit()?;
        self.ensure_no_pending_original_complete_restore()?;
        if self.original_complete_restore.is_some()
            || self.original_complete_restore_prepare.is_some()
            || self.original_complete_restore_commit.is_some()
            || owner.stage != Stage::Preparing
        {
            return Err(invalid());
        }
        let id = owner.request_id.as_ref().ok_or_else(invalid)?;
        let baseline = owner.baseline.as_ref().ok_or_else(invalid)?;
        baseline.validate()?;
        if self.original(id).is_some()
            || !baseline.extensions.is_empty()
            || !matches!(
                baseline.decoded_arguments()?,
                BeginArguments::PrepareRestore(_)
            )
        {
            return Err(invalid());
        }

        owner.body = Some(
            serde_json::to_value(baseline).map_err(crucible_node_format::ContractError::from)?,
        );
        owner.payload = Some(
            serde_json::to_value(&owner.request)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        owner.binding_value =
            Some(serde_json::to_value(binding).map_err(crucible_node_format::ContractError::from)?);
        let (sequence, cut) = self.session.begin_original_ack_admit(self.budget)?;
        owner.cut = Some(cut);
        let mut extensions = Extensions::new();
        extensions.insert(
            phase.request_extension().into(),
            owner.payload.take().ok_or_else(invalid)?,
        );
        extensions.insert(
            NATIVE_IMPORT18_EXTENSION.into(),
            owner.binding_value.take().ok_or_else(invalid)?,
        );
        let Some(Value::Object(body)) = owner.body.take() else {
            return Err(invalid());
        };
        owner.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(owner.request_id.take()),
            operation_id: Nullable(None),
            sequence,
            method: Method::Begin,
            body,
            extensions,
        });
        let original = owner.original.as_ref().ok_or_else(invalid)?;
        self.preflight_source_reply(
            1,
            0,
            row.maximum_frame
                .checked_add(self.maximum_frame()?)
                .ok_or_else(credit)?,
            0,
            0,
        )?;
        owner
            .bytes
            .try_reserve_exact(row.maximum_frame)
            .map_err(|_| credit())?;
        self.session.reserve_native_import18_data(
            original,
            phase,
            row.maximum_frame,
            &mut owner.literal_slot,
        )?;
        owner.stage = Stage::Unsigned;
        Ok(())
    }
}

impl OriginalNativeImport18Assignment {
    fn authenticate(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner) {
            return Err(invalid());
        }
        controller.session.native_import18_selection_data()?;
        Ok(())
    }

    /// Borrows complete input binding DATA without issuing a phase permission.
    ///
    /// # Errors
    /// Refuses a foreign original actor or revoked registration.
    pub fn binding_data(&self) -> Result<&PacketNativeImport18Binding, ProviderError> {
        self.controller.ensure_current()?;
        Ok(&self.binding)
    }

    /// Borrows the independently retained full archived backend definition as DATA.
    ///
    /// This does not authenticate a new cold owner, target definition or phase.
    ///
    /// # Errors
    /// Refuses another process or creator thread.
    pub fn expected_backend_schema_data(&self) -> Result<&SchemaRef, ProviderError> {
        self.controller.ensure_current()?;
        Ok(&self.expected_backend_schema)
    }

    /// Borrows actual retained normalization bytes, including a failed partial copy.
    ///
    /// This inert diagnostic loan does not establish assignment phase, current
    /// protocol frontier, or Source signing permission. Assigned signing uses
    /// assigned_normalization_data with the actual Controller and emitter.
    ///
    /// # Errors
    /// Refuses a foreign original actor or revoked registration.
    pub fn normalization_data(&self) -> Result<&[u8], ProviderError> {
        self.controller.ensure_current()?;
        Ok(&self.normalization)
    }

    /// Borrows the original typed Prepare DATA, including after refusal.
    ///
    /// # Errors
    /// Refuses a foreign original actor or revoked registration.
    pub fn prepare_request_data(
        &self,
    ) -> Result<&PacketCompleteRestorePrepareRequest, ProviderError> {
        self.controller.ensure_current()?;
        Ok(&self.prepare.request)
    }

    /// Borrows this actual pending or completed Prepare original.
    ///
    /// # Errors
    /// Refuses a foreign actor/emitter, absent or failed original, or expired cut.
    pub fn original_prepare_data<'a>(
        &'a self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<&'a Envelope, ProviderError> {
        self.authenticate(controller, emitter)?;
        let p = &self.prepare;
        if !matches!(p.stage, Stage::Unsigned | Stage::Sealed | Stage::Complete) {
            return Err(invalid());
        }
        let original = p.original.as_ref().ok_or_else(invalid)?;
        if p.stage != Stage::Complete {
            controller.session.authenticate_original_ack_admit_cut(
                original.sequence,
                p.cut.ok_or_else(invalid)?,
            )?;
        }
        Ok(original)
    }

    /// Seals proof18 into this same reserved Prepare original.
    ///
    /// The inner proof17 DATA is explicitly selected by Phase18; it supplies no
    /// native mapping or fresh target permission. The Source signs separately.
    ///
    /// # Errors
    /// Refuses a foreign actor/cut, reused phase, proof or insufficient bank.
    pub fn seal_prepare_data(
        &mut self,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        proof: PacketNativeImport17Proof,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner) {
            return Err(invalid());
        }
        begin_seal(&mut self.prepare, proof)?;
        let result = (|| {
            self.authenticate(controller, emitter)?;
            seal(
                controller,
                PacketNativeImport18Phase::Prepare,
                &mut self.prepare,
            )
        })();
        emitter.authenticate_original(controller)?;
        result
    }

    /// Publishes Prepare once and retains its strict raw frame before DTO decode.
    ///
    /// The caller must end this mutable capsule/Source loan, fund the defining
    /// raw prewalk and actual decode row, then call decode_prepare_received_data.
    /// Raw receipt bytes alone establish no lease, model, Hold, Arm or World.
    ///
    /// # Errors
    /// Refuses a foreign actor, attempted phase, wrong receipt or transport loss.
    pub fn publish_prepare_raw_data(
        &mut self,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner) {
            return Err(invalid());
        }
        begin_publication(&mut self.prepare)?;
        let result = (|| {
            self.authenticate(controller, emitter)?;
            let p = &mut self.prepare;
            controller
                .session
                .publish_native_import18_prepare_raw_into_data(
                    &mut controller.custody,
                    OriginalAssignedPublicationData {
                        original: p.original.as_ref().ok_or_else(invalid)?,
                        bytes: &p.bytes,
                        slot: p.literal_slot,
                        cut: p.cut.ok_or_else(invalid)?,
                    },
                    &mut p.raw,
                    &mut p.json_profile,
                )?;
            p.stage = Stage::RawReceived;
            Ok(())
        })();
        emitter.authenticate_original(controller)?;
        result
    }

    /// Borrows the real completed bounded-input Prepare pair as DATA.
    ///
    /// # Errors
    /// Refuses a foreign actor or absent/incomplete/failed Prepare publication.
    pub fn completed_prepare_pair_data<'a>(
        &'a self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(&'a Envelope, &'a Envelope), ProviderError> {
        self.authenticate(controller, emitter)?;
        completed_pair(&self.prepare)
    }
}

fn begin_seal<T>(
    p: &mut AssignedPhase<T>,
    proof: PacketNativeImport17Proof,
) -> Result<(), ProviderError> {
    if p.stage != Stage::Unsigned {
        return Err(invalid());
    }
    p.stage = Stage::Sealing;
    p.proof = Some(proof);
    Ok(())
}

fn begin_publication<T>(p: &mut AssignedPhase<T>) -> Result<(), ProviderError> {
    if p.stage != Stage::Sealed {
        return Err(invalid());
    }
    p.stage = Stage::Publishing;
    Ok(())
}

fn seal<T>(
    controller: &mut CnpController,
    phase: PacketNativeImport18Phase,
    p: &mut AssignedPhase<T>,
) -> Result<(), ProviderError> {
    if p.stage != Stage::Sealing {
        return Err(invalid());
    }
    let original = p.original.as_ref().ok_or_else(invalid)?;
    controller
        .session
        .authenticate_original_ack_admit_cut(original.sequence, p.cut.ok_or_else(invalid)?)?;
    p.proof
        .as_ref()
        .ok_or_else(invalid)?
        .validate_data(phase.payload_phase_data())?;
    p.proof_value = Some(
        serde_json::to_value(p.proof.as_ref().ok_or_else(invalid)?)
            .map_err(crucible_node_format::ContractError::from)?,
    );
    let original = p.original.as_mut().ok_or_else(invalid)?;
    if original.extensions.len() != 2 || original.extensions.contains_key(phase.proof_extension()) {
        return Err(invalid());
    }
    original.extensions.insert(
        phase.proof_extension().into(),
        p.proof_value.take().ok_or_else(invalid)?,
    );
    controller.session.seal_original_ack_admit(
        &mut controller.custody,
        original,
        &mut p.bytes,
        p.literal_slot,
    )?;
    p.stage = Stage::Sealed;
    Ok(())
}

fn decode_prepare_receipt(
    controller: &mut CnpController,
    binding: &PacketNativeImport18Binding,
    p: &mut AssignedPhase<PacketCompleteRestorePrepareRequest>,
) -> Result<(), ProviderError> {
    if p.stage != Stage::Decoding {
        return Err(invalid());
    }
    let phase = PacketNativeImport18Phase::Prepare;
    let original = p.original.as_ref().ok_or_else(invalid)?;
    controller
        .session
        .decode_native_import18_prepare_into_data(
            &mut controller.custody,
            original,
            p.cut.ok_or_else(invalid)?,
            p.raw.as_ref().ok_or_else(invalid)?,
            &mut p.response,
            &mut p.received,
        )?;
    let response = p.response.as_ref().ok_or_else(invalid)?;
    let request = decode_request(original.method, &original.body)?;
    p.decoded = Some(decode_response(&request, &response.body)?);
    if !matches!(
        &p.decoded.as_ref().ok_or_else(invalid)?.shape,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            ..
        }
    ) || response.extensions.len() != 1
    {
        return Err(invalid());
    }
    p.prepare_receipt = Some(
        PacketNativeImport17PrepareReceipt::deserialize(
            response
                .extensions
                .get(phase.receipt_extension())
                .ok_or_else(invalid)?,
        )
        .map_err(crucible_node_format::ContractError::from)?,
    );
    let receipt = p.prepare_receipt.as_ref().ok_or_else(invalid)?;
    receipt.validate_data()?;
    if receipt.input_roster != native_import18_input_roster_digest_data(&p.request, binding)? {
        return Err(invalid());
    }
    let payload = original
        .extensions
        .get(phase.request_extension())
        .ok_or_else(invalid)?;
    let payload_bytes = canonical::canonical_json(payload)?;
    let proof = p.proof.as_ref().ok_or_else(invalid)?;
    let binding_digest = binding.digest_data()?;
    let assigned_response = native_import18_assigned_response_digest(
        original,
        response,
        phase,
        controller.maximum_frame()?,
    )?;
    if receipt.import_binding_digest.as_slice() != binding_digest.as_slice()
        || receipt.context_digest != proof.context_digest
        || receipt.prepare_digest != binding.prepare_digest
        || receipt.prepare_digest.as_slice() != blake3::hash(&payload_bytes).as_bytes()
        || receipt.native_sequence != response.sequence
        || receipt.generation != p.request.generation
        || receipt.assigned_response.as_slice() != assigned_response.as_slice()
    {
        return Err(invalid());
    }
    p.stage = Stage::Complete;
    Ok(())
}

fn completed_pair<T>(p: &AssignedPhase<T>) -> Result<(&Envelope, &Envelope), ProviderError> {
    if p.stage != Stage::Complete {
        return Err(invalid());
    }
    Ok((
        p.original.as_ref().ok_or_else(invalid)?,
        p.response.as_ref().ok_or_else(invalid)?,
    ))
}

fn full_digest(value: &Envelope, maximum: usize) -> Result<[u8; 32], ProviderError> {
    count_serialized(value, maximum)?;
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("Native18 SDK once assignment changed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("Native18 SDK assignment storage")
}

pub use history::partials::{
    OriginalNativeImport18EnvelopePartialData, OriginalNativeImport18PartialHistoryData,
    OriginalNativeImport18PreparePartialData, OriginalNativeImport18RawPartialData,
    OriginalNativeImport18ReceivedPartialData,
};
pub use input_upload::{
    OriginalNativeImport18FrontierPartialData, OriginalNativeImport18UploadBankPartialData,
    OriginalNativeImport18UploadFramePartialData, OriginalNativeImport18UploadOwnerPartialData,
};

pub use storage::OriginalNativeImport18AssignmentRowHistoryData;
