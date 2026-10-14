//! Retains one genuine post-Hello peer association and seals its assigned Admit.
//!
//! The private birth permits preparation only. This association additionally
//! owns the original Hello journal, actual SDK emitter lease and current native
//! read. It signs the SDK-assigned envelope without accepting caller context.
//! The resulting proof enables only the native ACK mechanism; complete graph,
//! Arm, Capture and restoration admission remain independent.

use std::os::unix::fs::MetadataExt;

use super::*;
use crate::node_adapters::cnp::CnpSemanticSourceRead;
use crucible_node_provider::{
    client::{
        CnpController, OriginalCanonicalBlobAckEmitter, OriginalHelloJournal,
        PreparedOriginalCanonicalAckAdmit,
    },
    envelope::{MessageKind, Method},
    reference_packet::service::ack_emitter::{
        PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM, PacketCanonicalAckAdmissionContext,
        canonical_ack_admission_proof_data,
    },
};

// These independent banks are reserved before Rc/Child. They bound encoded
// source-owned copies only; parsed trees, canonical string scratch and SDK/native
// originals remain separately charged at the complete allocation boundary.
const CONTEXT_BANK_LIMITS: [usize; 4] = [512 * 1024, 4 * 1024, 416 * 1024, 16 * 1024];

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalAckPeerAssociation
{
    emitter: Option<OriginalCanonicalBlobAckEmitter>,
    native: Option<CnpSemanticSourceRead>,
    hello: Option<OriginalHelloJournal>,
    banks: [Vec<u8>; 5],
    normalized: [Option<serde_json::Value>; 5],
    context: Option<PacketCanonicalAckAdmissionContext>,
    proof: Option<serde_json::Value>,
    attempted: bool,
    ready: bool,
    failed: bool,
    signing_attempted: bool,
    sealed: bool,
    publication_attempted: bool,
}

impl OriginalAckPeerAssociation {
    pub(super) fn minimum_bank_bytes(frame_bytes: usize) -> Result<usize, OperationFailure> {
        CONTEXT_BANK_LIMITS
            .into_iter()
            .try_fold(frame_bytes, |sum, bytes| {
                sum.checked_add(bytes)
                    .ok_or_else(|| refused("ACK association bank extent overflow"))
            })
    }

    pub(super) fn reserve_into(
        frame_bytes: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), OperationFailure> {
        if completed.is_some() {
            return Err(refused("ACK association bank slot already occupied"));
        }
        *completed = Some(Self {
            emitter: None,
            native: None,
            hello: None,
            banks: std::array::from_fn(|_| Vec::new()),
            normalized: std::array::from_fn(|_| None),
            context: None,
            proof: None,
            attempted: false,
            ready: false,
            failed: false,
            signing_attempted: false,
            sealed: false,
            publication_attempted: false,
        });
        let original = completed
            .as_mut()
            .ok_or_else(|| refused("ACK association slot absent"))?;
        for (bank, maximum) in original.banks.iter_mut().zip(
            CONTEXT_BANK_LIMITS
                .into_iter()
                .chain(std::iter::once(frame_bytes)),
        ) {
            bank.try_reserve_exact(maximum)
                .map_err(|_| refused("ACK association bank reservation unavailable"))?;
        }
        Ok(())
    }

    pub(super) fn allocated_bank_bytes(&self) -> Result<usize, OperationFailure> {
        self.banks.iter().try_fold(0usize, |sum, bank| {
            sum.checked_add(bank.capacity())
                .ok_or_else(|| refused("ACK association capacity overflow"))
        })
    }

    fn emitter(&self) -> Result<&OriginalCanonicalBlobAckEmitter, OperationFailure> {
        self.emitter
            .as_ref()
            .ok_or_else(|| refused("ACK original emitter absent"))
    }

    fn native(&self) -> Result<&CnpSemanticSourceRead, OperationFailure> {
        self.native
            .as_ref()
            .ok_or_else(|| refused("ACK original native read absent"))
    }

    fn hello(&self) -> Result<&OriginalHelloJournal, OperationFailure> {
        self.hello
            .as_ref()
            .ok_or_else(|| refused("ACK original Hello absent"))
    }

    fn authenticate_current(&self) -> Result<(), OperationFailure> {
        if !self.ready || self.failed {
            return Err(refused("ACK peer association is incomplete or refused"));
        }
        self.native()?.ensure_current().map_err(unknown)
    }

    fn encode_normalized(&mut self, index: usize, maximum: usize) -> Result<(), OperationFailure> {
        let value = self.normalized[index]
            .as_ref()
            .ok_or_else(|| refused("ACK normalized original body absent"))?;
        encode_canonical_birth_bank(value, maximum, &mut self.banks[index])
    }
}

impl PacketCompleteSemanticSource {
    /// Retains the original post-Hello journal and actual immutable peer mechanism.
    ///
    /// The genuine realization callback supplies its owning scope and original
    /// negotiation journal slot. No decoded scope, matching declaration or
    /// copied journal can issue this association. A repeated callback rechecks
    /// the same retained association without issuing another one.
    ///
    /// # Errors
    /// Refuses changed origin, unrealized or foreign native/controller custody,
    /// missing birth/preconstruction, changed actual registration or codec,
    /// another Hello bank, repeated issuance or exhausted precharged banks.
    pub fn retain_original_canonical_ack_peer_association(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        hello: &mut Option<OriginalHelloJournal>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("ACK peer association slot is busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("ACK peer association banks absent"))?;
        if original.ready {
            if hello.is_some() {
                return Err(refused(
                    "ACK peer association already owns its Hello journal",
                ));
            }
            self.authenticate_witness_scope(scope)?;
            let birth = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("ACK private birth slot is busy"))?;
            birth
                .as_ref()
                .ok_or_else(|| refused("ACK private birth absent"))?
                .authenticate_original()?;
            original.authenticate_current()?;
            if !original.native()?.same_native_owner(scope.native) {
                return Err(refused("ACK peer association native owner changed"));
            }
            original
                .emitter()?
                .authenticate_original(scope.controller)
                .map_err(unknown)?;
            scope
                .controller
                .original_canonical_ack_hello_frame_digests(original.hello()?)
                .map_err(unknown)?;
            return self.authenticate_witness_scope(scope);
        }
        if original.attempted {
            return Err(refused("ACK peer association attempt is already retained"));
        }
        original.attempted = true;

        let result = (|| {
            self.authenticate_realization(*scope)?;
            self.authenticate_witness_scope(scope)?;
            self.authenticate_original_preconstruction()?;
            let birth_slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("ACK private birth slot is busy"))?;
            let birth = birth_slot
                .as_ref()
                .ok_or_else(|| refused("ACK private birth absent"))?;
            let inputs = birth.original_post_hello_inputs()?;
            let birth_id = inputs.birth_id;
            let host_executable = inputs.host_executable;
            let private_launch = inputs.private_launch;
            let source_bytes = inputs.source_birth;
            let host_bytes = inputs.host_registration;
            let host_value = registration_value(
                scope.controller.authority(),
                "controller",
                scope.controller.authority().connection_id(),
            )?;
            let expected =
                canonical::parse_json(host_bytes, frame::MAXIMUM_ACK_HOST_REGISTRATION_BYTES)
                    .map_err(unknown)?;
            if host_value != expected {
                return Err(refused(
                    "ACK actual host registration differs from original plan",
                ));
            }
            let journal = hello
                .as_ref()
                .ok_or_else(|| refused("ACK original Hello slot absent"))?;
            scope
                .controller
                .original_canonical_ack_hello_frame_digests(journal)
                .map_err(unknown)?;
            original.emitter = Some(
                scope
                    .controller
                    .retain_original_canonical_blob_ack_emitter()
                    .map_err(unknown)?,
            );
            original.native = Some(scope.native.original_source_read().map_err(unknown)?);
            original.hello = hello.take();

            // The owning result now precedes canonical input construction. A
            // failed comparison or final currentness check retains every owner.
            let source_value =
                canonical::parse_json(source_bytes, frame::MAXIMUM_ACK_SOURCE_BIRTH_BYTES)
                    .map_err(unknown)?;
            original.normalized[0] = Some(serde_json::json!({
                "schema": "source-owned.packet-canonical-ack-birth-association/5",
                "birth_id": Bytes::new(birth_id.to_vec()),
                "private_launch": private_launch,
                "host_executable": host_executable,
                "source_binding": source_value,
                "expected_host_registration": expected,
            }));
            original.encode_normalized(0, CONTEXT_BANK_LIMITS[0])?;

            let native_uid = std::fs::metadata(format!("/proc/{}", scope.native.provider_pid()))
                .map_err(|_| refused("ACK actual native UID unavailable"))?
                .uid();
            original.normalized[1] = Some(serde_json::json!({
                "schema": "source-owned.packet-canonical-ack-kernel-binding/5",
                "controller": {"pid": U64::new(u64::from(std::process::id())),
                    "uid": U64::new(u64::from(rustix::process::geteuid().as_raw())),
                    "executable": host_executable},
                "native": {"pid": U64::new(u64::from(scope.native.provider_pid())),
                    "uid": U64::new(u64::from(native_uid)),
                    "executable": scope.controller.peer_executable()},
            }));
            original.encode_normalized(1, CONTEXT_BANK_LIMITS[1])?;
            original.normalized[2] = Some(serde_json::json!({
                "schema": "source-owned.packet-canonical-ack-policy-binding/5",
                "source_binding": original.normalized[0].as_ref()
                    .and_then(|value| value.get("source_binding"))
                    .ok_or_else(|| refused("ACK retained full source binding absent"))?,
                "negotiated": {"limits": scope.controller.authority().limits(),
                    "features": scope.controller.authority().selected_features(),
                    "extensions": scope.controller.authority().selected_extensions()
                        .ok_or_else(|| refused("ACK actual selected extensions absent"))?,
                    "envelope_extensions": scope.controller.authority().envelope_extensions()},
            }));
            original.encode_normalized(2, CONTEXT_BANK_LIMITS[2])?;
            let native_connection =
                Id::new("packet-native5-original-connection").map_err(unknown)?;
            original.normalized[3] = Some(registration_value(
                scope.controller.authority(),
                "native",
                &native_connection,
            )?);
            original.encode_normalized(3, CONTEXT_BANK_LIMITS[3])?;
            original
                .emitter()?
                .authenticate_original(scope.controller)
                .map_err(unknown)?;
            original.native()?.ensure_current().map_err(unknown)?;
            birth.authenticate_original()?;
            self.authenticate_witness_scope(scope)?;
            original.ready = true;
            Ok(())
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    /// Prepares the exact original ACK Admit under the retained post-Hello association.
    ///
    /// The Source supplies the original installation's full body. The SDK owns
    /// the assigned sequence, lifetime ID, literal slot and absolute cut before
    /// returning this unique controller loan.
    ///
    /// # Errors
    /// Refuses changed origin, absent/failed peer association, revoked actual
    /// native/emitter custody, another controller or exhausted SDK credit.
    pub fn prepare_original_canonical_ack_admit<'a>(
        &self,
        controller: &'a mut CnpController,
        request_id: Id,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, OperationFailure> {
        self.ensure_origin()?;
        let slot = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| refused("ACK peer association slot is busy"))?;
        let original = slot
            .as_ref()
            .ok_or_else(|| refused("ACK peer association absent"))?;
        original.authenticate_current()?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("ACK private birth slot is busy"))?;
        birth
            .as_ref()
            .ok_or_else(|| refused("ACK private birth absent"))?
            .authenticate_original()?;
        let installation = self.installation();
        let request = AdmitRequest {
            bindings: vec![installation.binding.clone()],
            world_binding_hash: installation.world_binding_hash.clone(),
            admission_receipt: installation.admission_receipt.clone(),
            extensions: Default::default(),
        };
        controller
            .prepare_original_canonical_ack_admit(original.emitter()?, request_id, request)
            .map_err(unknown)
    }

    /// Seals one source-generated proof into the SDK's exact assigned original Admit.
    ///
    /// Complete context is derived internally from retained original owners and
    /// the actual assigned envelope. A caller cannot supply digests, a key or a
    /// context. Signing attempts are sticky; refusal keeps all original banks.
    ///
    /// # Errors
    /// Refuses a repeated signing attempt, changed native/emitter/Hello/birth,
    /// another assigned request, unsupported body or exhausted canonical banks.
    pub fn seal_original_canonical_ack_admit(
        &self,
        prepared: &mut PreparedOriginalCanonicalAckAdmit<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("ACK peer association slot is busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("ACK peer association absent"))?;
        original.authenticate_current()?;
        if original.signing_attempted {
            return Err(refused("ACK original signing was already attempted"));
        }
        original.signing_attempted = true;
        let result = (|| {
            let birth_slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("ACK private birth slot is busy"))?;
            let birth = birth_slot
                .as_ref()
                .ok_or_else(|| refused("ACK private birth absent"))?;
            let inputs = birth.original_post_hello_inputs()?;
            let key = inputs.key;
            let host_bytes = inputs.host_registration;
            prepared
                .authenticate_original_emitter(original.emitter()?)
                .map_err(unknown)?;
            let envelope = prepared.original().map_err(unknown)?;
            let installation = self.installation();
            let expected = serde_json::to_value(AdmitRequest {
                bindings: vec![installation.binding.clone()],
                world_binding_hash: installation.world_binding_hash.clone(),
                admission_receipt: installation.admission_receipt.clone(),
                extensions: Default::default(),
            })
            .map_err(unknown)?;
            if envelope.message != MessageKind::Request
                || envelope.method != Method::Admit
                || !envelope.extensions.is_empty()
                || envelope.node_id.0.as_ref() != Some(&installation.binding.compatibility.node_id)
                || envelope.execution_owner_id.0.as_ref() != Some(&installation.owner.owner.id)
                || serde_json::Value::Object(envelope.body.clone()) != expected
            {
                return Err(refused("ACK assigned original differs from Source Admit"));
            }
            original.normalized[4] = Some(serde_json::to_value(envelope).map_err(unknown)?);
            let maximum =
                usize::try_from(self.selected_storage_selection()?.limits.frame_bytes.get())
                    .map_err(|_| refused("ACK assigned frame extent overflow"))?;
            original.encode_normalized(4, maximum)?;
            let hello = prepared
                .original_canonical_ack_hello_frame_digests(original.hello()?)
                .map_err(unknown)?;
            original.context = Some(PacketCanonicalAckAdmissionContext {
                schema: "source-owned.packet-canonical-ack-admission-context/5".into(),
                algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.into(),
                source_birth: digest(&original.banks[0]),
                kernel_binding: digest(&original.banks[1]),
                policy_binding: digest(&original.banks[2]),
                host_registration: digest(host_bytes),
                native_registration: digest(&original.banks[3]),
                hello_request: Bytes::new(hello.request_frame_digest.to_vec()),
                hello_response: Bytes::new(hello.response_frame_digest.to_vec()),
                assigned_admit: digest(&original.banks[4]),
            });
            let context = original
                .context
                .as_ref()
                .ok_or_else(|| refused("ACK context slot absent"))?;
            let proof = canonical_ack_admission_proof_data(key, context).map_err(unknown)?;
            original.proof = Some(serde_json::to_value(&proof).map_err(unknown)?);
            original.native()?.ensure_current().map_err(unknown)?;
            birth.authenticate_original()?;
            prepared
                .authenticate_original_emitter(original.emitter()?)
                .map_err(unknown)?;
            prepared.seal(original.emitter()?, proof).map_err(unknown)?;
            original.sealed = true;
            // The sealed SDK slot precedes this final guard. A guard failure
            // leaves the assigned envelope/proof and Source originals held.
            original.native()?.ensure_current().map_err(unknown)
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_completed_world_admission(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        expected: &AdmitRequest,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_witness_scope(scope)?;
        let slot = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| refused("completed ACK association is busy"))?;
        let original = slot
            .as_ref()
            .ok_or_else(|| refused("completed ACK association is absent"))?;
        original.authenticate_current()?;
        if !original.sealed
            || !original.publication_attempted
            || !original.native()?.same_native_owner(scope.native)
        {
            return Err(refused(
                "completed ACK admission has another original occurrence",
            ));
        }
        let birth_slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("completed ACK birth is busy"))?;
        birth_slot
            .as_ref()
            .ok_or_else(|| refused("completed ACK birth is absent"))?
            .authenticate_original()?;
        let completed = scope
            .controller
            .original_completed_canonical_ack_admit(original.emitter()?)
            .map_err(unknown)?;
        let envelope = completed.original();
        envelope
            .matches_response(completed.response())
            .map_err(unknown)?;
        let proof = original
            .proof
            .as_ref()
            .ok_or_else(|| refused("completed ACK original proof is absent"))?;
        let mut base = serde_json::to_value(envelope).map_err(unknown)?;
        let extensions = base
            .get_mut("extensions")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| refused("completed ACK original extensions are malformed"))?;
        let proof_key = crucible_node_provider::reference_packet::service::ack_emitter::
            PACKET_CANONICAL_ACK_ADMISSION_FEATURE;
        if extensions.len() != 1 || extensions.get(proof_key) != Some(proof) {
            return Err(refused("completed ACK original proof changed"));
        }
        extensions.remove(proof_key);
        if original.normalized[4].as_ref() != Some(&base)
            || serde_json::Value::Object(envelope.body.clone())
                != serde_json::to_value(expected).map_err(unknown)?
        {
            return Err(refused(
                "completed ACK original differs from the world request",
            ));
        }
        let response = crucible_node_provider::bodies::decode_response(
            &crucible_node_provider::bodies::decode_request(envelope.method, &envelope.body)
                .map_err(unknown)?,
            &completed.response().body,
        )
        .map_err(unknown)?;
        let Some(MethodResult::Admit(admitted)) = response.result else {
            return Err(refused("completed ACK world admission did not complete"));
        };
        let installation = self.installation();
        let binding = installation.binding.identity().map_err(unknown)?;
        if admitted.admission_id != installation.admission
            || admitted.accepted_binding_hashes.as_slice() != std::slice::from_ref(&binding)
        {
            return Err(refused(
                "completed ACK world admission changed the full binding",
            ));
        }
        original
            .emitter()?
            .authenticate_original(scope.controller)
            .map_err(unknown)?;
        original.native()?.ensure_current().map_err(unknown)?;
        self.authenticate_witness_scope(scope)
    }

    /// Publishes the same sealed original Admit without renewing its cut or sequence.
    ///
    /// The caller's completed slot precedes final Source checks. A refusal keeps
    /// SDK originals, Source owners and any actual received response retained.
    /// This enables only protocol ACK admission, never semantic Arm or Capture.
    ///
    /// # Errors
    /// Refuses failed/repeated publication, changed original peers or transport,
    /// exhausted credit, partial I/O, foreign reply or final currentness failure.
    ///
    /// # Panics
    /// Trusted SDK schema/supervision callbacks may unwind. Both owners retain
    /// the attempted original and its progress outside those callbacks.
    pub fn publish_original_canonical_ack_admit_into(
        &self,
        prepared: &mut PreparedOriginalCanonicalAckAdmit<'_>,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("ACK peer association slot is busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("ACK peer association absent"))?;
        original.authenticate_current()?;
        if !original.sealed || original.publication_attempted || completed.is_some() {
            return Err(refused(
                "ACK original publication is unsealed, repeated or occupied",
            ));
        }
        original.publication_attempted = true;
        let result = (|| {
            let birth = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("ACK private birth slot is busy"))?;
            birth
                .as_ref()
                .ok_or_else(|| refused("ACK private birth absent"))?
                .authenticate_original()?;
            prepared
                .publish_into(original.emitter()?, completed)
                .map_err(unknown)?;
            original.native()?.ensure_current().map_err(unknown)?;
            let birth = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("ACK private birth slot is busy"))?;
            birth
                .as_ref()
                .ok_or_else(|| refused("ACK private birth absent"))?
                .authenticate_original()
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }
}

impl CnpSemanticPreparation {
    /// Publishes the original source-authenticated protocol ACK Admit from this capsule.
    ///
    /// This entry uniquely borrows the controller already owned by the same
    /// realized preparation. It authenticates the exact installed Source Rc,
    /// keeps the assigned SDK request and response in their original slots, and
    /// checks the preparation again after publication. It enables only the
    /// protocol ACK mechanism; graph admission, Arm and Capture remain separate.
    ///
    /// # Errors
    /// Refuses an occupied result, another installed Source allocation, changed
    /// original preparation, absent post-Hello association, signing failure or
    /// uncertain transport effects. The capsule and any completed reply remain
    /// owned when a final currentness or callback check fails.
    ///
    /// # Panics
    /// Trusted preparation and SDK callbacks may unwind. The capsule retains
    /// its controller and the Source retains its signing/publication attempt.
    pub fn call_original_canonical_ack_admit_into(
        &mut self,
        source: &PacketCompleteSemanticSource,
        request_id: Id,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), OperationFailure> {
        source.ensure_origin()?;
        if completed.is_some() {
            return Err(refused("original protocol ACK Admit result is occupied"));
        }
        let scope = self.scope()?;
        let installed = scope
            .native
            .source
            .as_ref()
            .ok_or_else(|| refused("original protocol ACK installed Source absent"))?;
        if !std::ptr::eq(
            std::rc::Rc::as_ptr(installed).cast::<()>(),
            std::ptr::from_ref(source).cast::<()>(),
        ) || !std::ptr::eq(scope.installation, source.installation())
        {
            return Err(refused("original protocol ACK Source allocation differs"));
        }
        self.reauthenticate()?;
        source.authenticate_witness_scope(&self.scope()?)?;
        let read_owner = std::rc::Rc::clone(&self.scope()?.native.read_owner);
        // This guard does not set ReadCall.busy: the Source must authenticate
        // its retained readonly native view while signing. Unique controller
        // borrowing already prevents another request from consuming its slot.
        let mut attempt = OriginalAckProtocolAttempt {
            process: std::process::id(),
            revoke: Some(move || read_owner.revoke()),
        };

        let result = (|| {
            let native = self
                .guard
                .custody
                .as_mut()
                .ok_or_else(|| refused("original protocol ACK native custody absent"))?;
            // The common graph constructor must never send a second Admit
            // after this one-shot assigned mechanism has started.
            native.completed_ack_protocol_started = true;
            let controller = native
                .controller
                .as_mut()
                .ok_or_else(|| refused("original protocol ACK controller absent"))?;
            let mut prepared =
                source.prepare_original_canonical_ack_admit(controller, request_id)?;
            source.seal_original_canonical_ack_admit(&mut prepared)?;
            source.publish_original_canonical_ack_admit_into(&mut prepared, completed)
        })();
        if let Err(error) = result {
            // Assignment, signing or publication may already have retained an
            // original attempt. Its owners are never dropped or reset here.
            return Err(crate::node_adapters::cnp::semantic::after_effect(error));
        }

        // Transport decoding also returns refusals as data. Only the exact
        // completed original binding/admission can close this protocol attempt.
        // The reply stays in the caller's slot even when this check refuses.
        let Some(MethodResult::Admit(admitted)) = completed
            .as_ref()
            .and_then(|response| response.result.as_ref())
        else {
            return Err(crate::node_adapters::cnp::semantic::after_effect(unknown(
                "original protocol ACK admission did not complete",
            )));
        };
        let installation = source.installation();
        let expected = installation
            .binding
            .identity()
            .map_err(unknown)
            .map_err(crate::node_adapters::cnp::semantic::after_effect)?;
        if admitted.admission_id != installation.admission
            || admitted.accepted_binding_hashes.as_slice() != std::slice::from_ref(&expected)
        {
            return Err(crate::node_adapters::cnp::semantic::after_effect(unknown(
                "original protocol ACK admission changed the full Source binding",
            )));
        }

        // The actual reply precedes final callbacks and original-source checks.
        // An error or unwind revokes the same retained native read occurrence.
        self.reauthenticate()
            .and_then(|()| source.authenticate_witness_scope(&self.scope()?))
            .map_err(crate::node_adapters::cnp::semantic::after_effect)?;
        attempt.revoke = None;
        Ok(())
    }
}

struct OriginalAckProtocolAttempt<F: FnOnce()> {
    process: u32,
    revoke: Option<F>,
}

impl<F: FnOnce()> Drop for OriginalAckProtocolAttempt<F> {
    fn drop(&mut self) {
        if self.process != std::process::id() {
            return;
        }
        if let Some(revoke) = self.revoke.take() {
            revoke();
        }
    }
}

fn registration_value(
    authority: &crucible_node_provider::handshake::ConnectionAuthority,
    role: &str,
    connection_id: &Id,
) -> Result<serde_json::Value, OperationFailure> {
    authority.ensure_live().map_err(unknown)?;
    Ok(serde_json::json!({
        "schema": "source-owned.packet-canonical-ack-registration/5",
        "role": role,
        "connection_id": connection_id,
        "session_id": authority.session_id(),
        "incarnation_id": authority.incarnation_id(),
        "limits": authority.limits(),
        "features": authority.selected_features(),
        "extensions": authority.selected_extensions()
            .ok_or_else(|| refused("ACK actual selected extensions absent"))?,
        "envelope_extensions": authority.envelope_extensions(),
    }))
}

fn digest(bytes: &[u8]) -> Bytes {
    Bytes::new(blake3::hash(bytes).as_bytes().to_vec())
}
