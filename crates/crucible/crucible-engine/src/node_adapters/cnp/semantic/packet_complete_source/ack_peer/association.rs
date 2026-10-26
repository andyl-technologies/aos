//! Retains one genuine post-Hello peer association and seals its assigned Admit.
//!
//! The private birth permits preparation only. This association additionally
//! owns the original Hello journal, actual SDK emitter lease and current native
//! read. It signs the SDK-assigned envelope without accepting caller context.
//! The resulting proof enables only the native ACK mechanism; complete graph,
//! Arm, Capture and restoration admission remain independent.

use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use std::os::unix::fs::MetadataExt;

use super::*;
use crate::node_adapters::cnp::CnpSemanticSourceRead;
use crucible_node_transport::{
    client::{
        CnpController, OriginalCanonicalBlobAckEmitter, OriginalCanonicalRestoreInputEmitter,
        OriginalHelloJournal, PreparedOriginalCanonicalAckAdmit,
        PreparedOriginalCompleteRestoreTransfer,
    },
    envelope::{MessageKind, Method},
    reference_packet::service::ack_emitter::{
        PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM, PacketCanonicalAckAdmissionContext,
        canonical_ack_admission_proof_data,
    },
};

#[path = "association/restoration_capacities.rs"]
mod restoration_capacities;

#[path = "association/protocol_capacities.rs"]
mod protocol_capacities;

#[path = "association/typed_decoder_backing.rs"]
mod typed_decoder_backing;

// These independent banks are reserved before Rc/Child. They bound encoded
// source-owned copies only; parsed trees, canonical string scratch and SDK/native
// originals remain separately charged at the complete allocation boundary.
#[path = "association/complete_restore.rs"]
mod complete_restore;
#[path = "association/fresh_restore_host.rs"]
mod fresh_restore_host;
#[path = "association/restoration_activation.rs"]
mod restoration_activation;
#[path = "association/restoration_observation.rs"]
mod restoration_observation;
#[path = "association/restored_checkpoint17.rs"]
mod restored_checkpoint17;
#[path = "association/restored_input_reactive17.rs"]
mod restored_input_reactive17;
#[path = "association/restored_observation17.rs"]
mod restored_observation17;

#[path = "association/restoration_continuation.rs"]
mod restoration_continuation;

#[path = "association/restoration_transfer.rs"]
mod restoration_transfer;
#[path = "association/restore_transfer_banks.rs"]
mod restore_transfer_banks;
pub use complete_restore::PacketCompleteRestorePreparation;

#[path = "association/initial_lifecycle_storage.rs"]
pub(in crate::node_adapters::cnp::semantic) mod initial_lifecycle_storage;

const CONTEXT_BANK_LIMITS: [usize; 4] = [512 * 1024, 4 * 1024, 416 * 1024, 16 * 1024];

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalAckPeerAssociation
{
    restore: Option<complete_restore::OriginalCompleteRestoreAttempt>,
    restore_transfer_banks: Option<restore_transfer_banks::OriginalRestoreTransferBanks>,
    restoration_activation:
        Option<restoration_activation::OriginalSourceRestorationActivationAttempt>,
    restoration_observation:
        Option<restoration_observation::OriginalSourceRestorationObservationAttempt>,
    // Fixed, separate custody: immutable first-Observe owners are never replaced.
    // Every initialized/failed seed remains inside the actual Source sizeof root.
    current_observations: std::cell::RefCell<restoration_observation::CurrentObservationHistory>,
    producer_progress: std::cell::RefCell<producer_progress::ProducerProgressHistory>,
    restored_capture: std::cell::RefCell<producer_progress::capture::CaptureOnceOwner>,
    restored_observations17: restored_observation17::Observation17Owner,
    restored_inputs: std::cell::RefCell<restored_input_reactive17::InputReactive17History>,
    restored_suffix:
        std::cell::RefCell<Option<restoration_continuation::OriginalRestoredSuffixSeed>>,
    emitter: Option<OriginalCanonicalBlobAckEmitter>,
    restore_input_emitter: Option<OriginalCanonicalRestoreInputEmitter>,
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
    // Set only after the actual completed SDK pair and same world binding pass.
    completed_mechanism: std::cell::Cell<bool>,
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
            restore: None,
            restore_transfer_banks: None,
            restoration_activation: None,
            restoration_observation: None,
            restored_suffix: std::cell::RefCell::new(None),
            current_observations: std::cell::RefCell::new(
                restoration_observation::CurrentObservationHistory::new(),
            ),
            producer_progress: std::cell::RefCell::new(
                producer_progress::ProducerProgressHistory::new(),
            ),
            restored_capture: std::cell::RefCell::new(
                producer_progress::capture::CaptureOnceOwner::new_data(),
            ),
            restored_observations17: restored_observation17::Observation17Owner::new_data(),
            restored_inputs: std::cell::RefCell::new(
                restored_input_reactive17::InputReactive17History::new_data(),
            ),
            emitter: None,
            restore_input_emitter: None,
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
            completed_mechanism: std::cell::Cell::new(false),
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
        self.allocated_bank_bytes_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn allocated_bank_bytes_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<usize, E> {
        let existing = self.banks.iter().try_fold(0usize, |sum, bank| {
            sum.checked_add(bank.capacity())
                .ok_or_else(|| E::limit("ACK association capacity overflow"))
        })?;
        let restore = self
            .restore
            .as_ref()
            .map_or(Ok(0), |restore| restore.allocated_bytes_with_error::<E>())?;
        let transfer = self
            .restore_transfer_banks
            .as_ref()
            .map_or(Ok(0), |banks| banks.allocated_bytes_with_error::<E>())?;
        let activation = self
            .restoration_activation
            .as_ref()
            .map_or(Ok(0), |attempt| {
                attempt.allocated_bank_bytes_with_error::<E>()
            })?;
        let observation = self
            .restoration_observation
            .as_ref()
            .map_or(Ok(0), |attempt| {
                attempt.allocated_bank_bytes_with_error::<E>()
            })?;
        existing
            .checked_add(observation)
            .and_then(|bytes| bytes.checked_add(activation))
            .and_then(|bytes| bytes.checked_add(restore))
            .and_then(|bytes| bytes.checked_add(transfer))
            .ok_or_else(|| E::limit("complete restore association capacity overflow"))
    }

    fn emitter(&self) -> Result<&OriginalCanonicalBlobAckEmitter, OperationFailure> {
        self.emitter
            .as_ref()
            .ok_or_else(|| refused("ACK original emitter absent"))
    }

    fn authenticate_restore_input_emitter(
        &self,
        controller: &CnpController,
        expected: Option<crucible_node_transport::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    ) -> Result<(), OperationFailure> {
        if controller
            .original_native5_restore_input_emitter_selection()
            .map_err(unknown)?
            != expected
        {
            return Err(refused(
                "actual restore input emitter selection differs from Source",
            ));
        }
        match (expected, self.restore_input_emitter.as_ref()) {
            (Some(_), Some(emitter)) => emitter.authenticate_original(controller).map_err(unknown),
            (None, None) => Ok(()),
            _ => Err(refused(
                "original restore input emitter custody differs from selection",
            )),
        }
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
        self.authenticate_original_native_host_barrier()?;
        if matches!(
            self.selected_capture_profile()?,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            self.retain_original_extension_registry_metadata_owner(scope)?;
        }
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
            original.authenticate_restore_input_emitter(
                scope.controller,
                self.selected_restore_input_emitter_selection()?,
            )?;
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
            if scope
                .controller
                .original_native5_restore_input_emitter_selection()
                .map_err(unknown)?
                != self.selected_restore_input_emitter_selection()?
            {
                return Err(refused("post-Hello restore input emitter policy differs"));
            }
            if self.selected_restore_input_emitter_selection()?.is_some() {
                // The owning slot precedes every later normalization and guard.
                // Issuance proves a current SDK writer, never a native upload right.
                original.restore_input_emitter = Some(
                    scope
                        .controller
                        .retain_original_canonical_restore_input_emitter()
                        .map_err(unknown)?,
                );
            }
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
            original.authenticate_restore_input_emitter(
                scope.controller,
                self.selected_restore_input_emitter_selection()?,
            )?;
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
        self.prepare_original_canonical_ack_admit_selected(controller, request_id, false)
    }

    pub(in crate::node_adapters::cnp::semantic) fn prepare_original_initial_canonical_ack_admit<
        'a,
    >(
        &self,
        controller: &'a mut CnpController,
        request_id: Id,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, OperationFailure> {
        self.prepare_original_canonical_ack_admit_selected(controller, request_id, true)
    }

    fn prepare_original_canonical_ack_admit_selected<'a>(
        &self,
        controller: &'a mut CnpController,
        request_id: Id,
        initial: bool,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_original_native_host_barrier()?;
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
        original.authenticate_restore_input_emitter(
            controller,
            self.selected_restore_input_emitter_selection()?,
        )?;
        let installation = self.installation();
        let request = AdmitRequest {
            bindings: vec![installation.binding.clone()],
            world_binding_hash: installation.world_binding_hash.clone(),
            admission_receipt: installation.admission_receipt.clone(),
            extensions: Default::default(),
        };
        if initial {
            controller.prepare_original_initial_canonical_ack_admit(
                original.emitter()?,
                request_id,
                request,
            )
        } else {
            controller.prepare_original_canonical_ack_admit(
                original.emitter()?,
                request_id,
                request,
            )
        }
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
        self.authenticate_original_native_host_barrier()?;
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
        self.authenticate_original_native_host_barrier()?;
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
        let proof_key = crucible_node_transport::reference_packet::service::ack_emitter::
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
        let response = crucible_node_transport::bodies::decode_response(
            &crucible_node_transport::bodies::decode_request(envelope.method, &envelope.body)
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
        original.authenticate_restore_input_emitter(
            scope.controller,
            self.selected_restore_input_emitter_selection()?,
        )?;
        original.native()?.ensure_current().map_err(unknown)?;
        self.authenticate_witness_scope(scope)?;
        original.native()?.ensure_current().map_err(unknown)?;
        original.completed_mechanism.set(true);
        Ok(())
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
        self.publish_original_canonical_ack_admit_selected(prepared, completed, false)
    }

    fn publish_original_canonical_ack_admit_selected(
        &self,
        prepared: &mut PreparedOriginalCanonicalAckAdmit<'_>,
        completed: &mut Option<ResponseBody>,
        initial: bool,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_original_native_host_barrier()?;
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
            if initial {
                prepared.publish_initial_into(original.emitter()?, completed)
            } else {
                prepared.publish_into(original.emitter()?, completed)
            }
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
        self.call_original_canonical_ack_admit_selected(source, request_id, completed, false)
    }

    pub(in crate::node_adapters::cnp::semantic) fn call_original_initial_canonical_ack_admit_into(
        &mut self,
        source: &PacketCompleteSemanticSource,
        request_id: Id,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), OperationFailure> {
        self.call_original_canonical_ack_admit_selected(source, request_id, completed, true)
    }

    fn call_original_canonical_ack_admit_selected(
        &mut self,
        source: &PacketCompleteSemanticSource,
        request_id: Id,
        completed: &mut Option<ResponseBody>,
        initial: bool,
    ) -> Result<(), OperationFailure> {
        source.ensure_origin()?;
        source.authenticate_original_native_host_barrier()?;
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
            let mut prepared = if initial {
                source.prepare_original_initial_canonical_ack_admit(controller, request_id)?
            } else {
                source.prepare_original_canonical_ack_admit(controller, request_id)?
            };
            source.seal_original_canonical_ack_admit(&mut prepared)?;
            source.publish_original_canonical_ack_admit_selected(&mut prepared, completed, initial)
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
    authority: &crucible_node_transport::handshake::ConnectionAuthority,
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

impl PacketCompleteSemanticSource {
    /// Authenticates this original source's installed complete capture mechanism.
    ///
    /// This checks availability of the actual measured code/codec and completed
    /// native ACK association. It does not authenticate a graph, scheduler,
    /// stopped frontier, all-owner runtime, preflight geometry or Capture ticket.
    /// The factory must conjoin those original owners before any effects.
    ///
    /// # Errors
    /// Refuses another creator, missing owning profile/physical banks, changed
    /// source/registration/private birth, unfinished original protocol Admit,
    /// revoked native custody or a missing exact installed complete definition.
    pub fn authenticate_original_complete_capture_support(&self) -> Result<(), OperationFailure> {
        self.authenticate_original_complete_capture_mechanism(true)
    }

    /// Authenticates original post-Hello mechanism preparation before assigned Admit.
    ///
    /// The actual native read, preconstruction, opaque emitter/Hello and private
    /// birth must exist already. This predicate permits only mechanism/profile
    /// preparation; active support additionally requires the actual completed
    /// assigned SDK request/proof/reply and original world-binding checks.
    ///
    /// # Errors
    /// Refuses a foreign source, missing original post-Hello capabilities,
    /// incomplete physical banks or changed current native/preconstruction.
    pub fn authenticate_original_complete_capture_preparation_support(
        &self,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_complete_capture_mechanism(false)
    }

    fn authenticate_original_complete_capture_mechanism(
        &self,
        require_completed: bool,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_original_native_host_barrier()?;
        if !matches!(self.selected_capture_profile()?,PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            || self.selected_confirmation_selection()? != Some(crucible_node_transport::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5)
            || self.selected_ack_emitter_selection()? != Some(crucible_node_transport::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || self.selected_complete_restore_selection()?.is_none()
            || self.selected_protocol_metadata_limits()?.is_none()
            || self.selected_native_ack_codec_metadata_extent()? != Some(crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        {
            return Err(refused("complete owning mechanism selection absent"));
        }
        let snapshot_class = self.selected_complete_native_snapshot_class()?;
        if snapshot_class
            == super::super::archive_owner::CompleteNativeSnapshotClass::InvocationCapture15
        {
            self.authenticate_original_capture_invocation_data()
                .map_err(unknown)?;
        }
        let schema = snapshot_class.schema()?;
        let installation = self.installation();
        if !installation
            .provider
            .implementation
            .formats
            .contains(&schema)
            || !installation
                .binding
                .compatibility
                .implementation
                .formats
                .contains(&schema)
        {
            return Err(refused("complete owning implementation definition differs"));
        }
        self.authenticate_current_native()?;
        self.authenticate_original_preconstruction()?;
        let original = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| refused("complete original ACK association busy"))?;
        let original = original
            .as_ref()
            .ok_or_else(|| refused("complete original ACK association absent"))?;
        original.authenticate_current()?;
        if self.selected_restore_input_emitter_selection()?.is_some()
            != original.restore_input_emitter.is_some()
        {
            return Err(refused(
                "complete original restore input writer association absent",
            ));
        }
        if original.emitter.is_none()
            || original.hello.is_none()
            || original.normalized[..4].iter().any(Option::is_none)
            || require_completed
                && (!original.completed_mechanism.get()
                    || !original.sealed
                    || !original.publication_attempted
                    || original.context.is_none()
                    || original.proof.is_none())
        {
            return Err(refused(
                "complete original SDK/native mechanism phase is incomplete",
            ));
        }
        self.authenticate_original_preconstruction_native(original.native()?)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("complete original private birth busy"))?;
        let birth = birth
            .as_ref()
            .ok_or_else(|| refused("complete original private birth absent"))?;
        birth.authenticate_original()?;
        if snapshot_class.has_allocation() {
            birth.authenticate_selected_native_startup(self)?;
        }
        self.original_extension_registry_storage_data(512 * 1024 * 1024)?;
        self.authenticate_original_effect_receiver_source_binding()?;
        self.original_capture_bank_facts()?;
        original.native()?.ensure_current().map_err(unknown)?;
        self.authenticate_current_native()
    }
}

impl PacketCompleteSemanticSource {
    /// Reauthenticates both actual writers in the uniquely owned assigned transfer.
    ///
    /// The prepared SDK wrapper retains its actual original sequence, ID, frame
    /// slot and operation cut. This predicate neither signs a proof nor resets
    /// that cut. A Prepare signer calls it before and after sealing, in addition
    /// to actual Core archive/fresh-context checks and the private fresh key.
    ///
    /// # Errors
    /// Refuses foreign or incomplete Source custody, uncompleted original ACK
    /// Admit, an absent canonical input lease, changed actual controller/codec/
    /// registration or revoked original native read. Mapping and archive context
    /// remain separate mandatory signer checks.
    pub fn authenticate_original_complete_restore_transfer_writers(
        &self,
        prepared: &PreparedOriginalCompleteRestoreTransfer<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_original_native_host_barrier()?;
        self.authenticate_current_native()?;
        self.authenticate_original_preconstruction()?;
        if self.selected_restore_input_emitter_selection()?.is_none() {
            return Err(refused(
                "source-bound restore input writer selection absent",
            ));
        }
        let slot = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| refused("restore input writer Source association busy"))?;
        let original = slot
            .as_ref()
            .ok_or_else(|| refused("restore input writer Source association absent"))?;
        original.authenticate_current()?;
        if !original.completed_mechanism.get() {
            return Err(refused(
                "restore input writer precedes completed original ACK Admit",
            ));
        }
        self.authenticate_original_preconstruction_native(original.native()?)?;
        prepared
            .authenticate_original_emitter(original.emitter()?)
            .map_err(unknown)?;
        prepared
            .authenticate_original_restore_input_emitter(
                original
                    .restore_input_emitter
                    .as_ref()
                    .ok_or_else(|| refused("actual retained restore input emitter absent"))?,
            )
            .map_err(unknown)?;
        prepared
            .original_canonical_ack_hello_frame_digests(original.hello()?)
            .map_err(unknown)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("restore input writer private birth busy"))?;
        birth
            .as_ref()
            .ok_or_else(|| refused("restore input writer private birth absent"))?
            .authenticate_original()?;
        original.native()?.ensure_current().map_err(unknown)?;
        self.authenticate_current_native()
    }
}

#[path = "association/retained.rs"]
mod retained;

impl OriginalAckPeerAssociation {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_reserved_prebirth_data(
        &self,
    ) -> Result<(), OperationFailure> {
        self.authenticate_reserved_prebirth_data_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn authenticate_reserved_prebirth_data_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
    ) -> Result<(), E> {
        let Self {
            restore,
            restore_transfer_banks,
            restoration_activation,
            restoration_observation,
            restored_suffix,
            current_observations,
            producer_progress,
            restored_capture,
            restored_observations17,
            restored_inputs,
            emitter,
            restore_input_emitter,
            native,
            hello,
            banks,
            normalized,
            context,
            proof,
            attempted,
            ready,
            failed,
            signing_attempted,
            sealed,
            publication_attempted,
            completed_mechanism,
        } = self;
        if restored_observations17
            .is_used_data()
            .map_err(|_| E::refused("reserved prebirth signed observation owner is busy"))?
        {
            return Err(E::refused(
                "reserved prebirth signed observation owner is used",
            ));
        }
        let inputs17 = restored_inputs
            .try_borrow()
            .map_err(|_| E::refused("reserved prebirth signed input owner is busy"))?;
        if inputs17.is_used_data() {
            return Err(E::refused("reserved prebirth signed input owner is used"));
        }
        drop(inputs17);
        // A fixed failed seed has no heap to refund, but it still permanently
        // leaves this association outside the never-used prebirth family.
        let seed = restored_suffix
            .try_borrow()
            .map_err(|_| E::refused("reserved prebirth ACK association is already used"))?;
        if seed.is_some() {
            return Err(E::refused(
                "reserved prebirth ACK association is already used",
            ));
        }
        drop(seed);
        let current = current_observations
            .try_borrow()
            .map_err(|_| E::refused("reserved prebirth current observation owner busy"))?;
        if current.is_used_data() {
            return Err(E::refused(
                "reserved prebirth current observation owner already used",
            ));
        }
        drop(current);
        let progress = producer_progress
            .try_borrow()
            .map_err(|_| E::refused("reserved prebirth Producer owner busy"))?;
        if progress.is_used_data() {
            return Err(E::refused("reserved prebirth Producer owner already used"));
        }
        drop(progress);
        let capture = restored_capture
            .try_borrow()
            .map_err(|_| E::refused("reserved prebirth Capture owner busy"))?;
        if capture.is_used_data() {
            return Err(E::refused("reserved prebirth Capture owner already used"));
        }
        drop(capture);

        if restoration_observation.is_some()
            || restoration_activation.is_some()
            || emitter.is_some()
            || restore_input_emitter.is_some()
            || native.is_some()
            || hello.is_some()
            || normalized.iter().any(Option::is_some)
            || context.is_some()
            || proof.is_some()
            || *attempted
            || *ready
            || *failed
            || *signing_attempted
            || *sealed
            || *publication_attempted
            || completed_mechanism.get()
            || banks.iter().any(|bank| !bank.is_empty())
        {
            return Err(E::refused(
                "reserved prebirth ACK association is already used",
            ));
        }
        if let Some(restore) = restore {
            restore.authenticate_reserved_prebirth_data_with_error::<E>()?;
        }
        if let Some(transfer) = restore_transfer_banks {
            transfer.authenticate_reserved_prebirth_data_with_error::<E>()?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "association/prebirth_storage_tests.rs"]
mod prebirth_storage_tests;

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn selected_complete_native_snapshot_class(
        &self,
    ) -> Result<super::super::archive_owner::CompleteNativeSnapshotClass, OperationFailure> {
        use super::super::archive_owner::CompleteNativeSnapshotClass;
        use crucible_node_transport::reference_packet::service::{
            capture_allocation::PacketNative5CaptureAllocationSelection,
            complete_restore::{
                PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            },
        };

        self.ensure_origin()?;
        // The explicit installed edition is DATA only; live original purpose
        // and full cold class ownership are authenticated by their callers.
        if self
            .is_original_invocation_snapshot_declaration_data()
            .map_err(unknown)?
        {
            return Ok(CompleteNativeSnapshotClass::InvocationCapture15);
        }
        match self.selected_capture_allocation_selection()? {
            None => Ok(CompleteNativeSnapshotClass::Legacy11),
            Some(PacketNative5CaptureAllocationSelection::OriginalObserve12) => {
                if self.selected_complete_restore_selection()?
                    != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                    || self.selected_restore_input_emitter_selection()?
                        != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
                    || !matches!(self.selected_capture_profile()?, PacketNative5CaptureProfile::OwnedProtocol11 { .. })
                    || self.selected_protocol_metadata_limits()?.is_none()
                    || self.selected_ack_emitter_selection()?
                        != Some(crucible_node_transport::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                    || self.selected_native_ack_codec_metadata_extent()?
                        != Some(crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                    || self.selected_fresh_restore_allocation_selection()?.is_some()
                {
                    return Err(refused("startup Capture snapshot selection is incomplete or unsupported"));
                }
                Ok(CompleteNativeSnapshotClass::StartupCapture14)
            }
        }
    }
}

#[path = "association/restoration_construction.rs"]
mod restoration_construction;

pub(crate) use restoration_transfer::{
    OriginalSourceRestoreSignerConstructionData, OriginalSourceRestoreVerifiedPhase,
    SourceVerifiedPhase as OriginalSourceRestoreVerifiedPhaseKind,
};

pub use restoration_activation::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestorationActivationVerifiedPhase,
};

pub use restoration_observation::{
    OriginalSourceRestorationObservationConstructionData,
    OriginalSourceRestorationObservationVerifiedPhase,
};

impl OriginalAckPeerAssociation {
    /// Names the seed loan before either prebirth or retained backing walks.
    pub(in crate::node_adapters::cnp::semantic) fn reserved_suffix_counter_scratch_data() -> usize {
        use restoration_continuation::OriginalRestoredSuffixSeed as Seed;
        use std::cell::{BorrowError, Ref, RefCell};
        use std::mem::size_of;

        Seed::retained_counter_scratch_data()
            + size_of::<&RefCell<Option<Seed>>>()
            + size_of::<Ref<'static, Option<Seed>>>()
            + size_of::<Result<Ref<'static, Option<Seed>>, BorrowError>>()
            + size_of::<Result<Ref<'static, Option<Seed>>, OperationFailure>>()
            + size_of::<Result<Ref<'static, Option<Seed>>, crate::node_contract::RuntimeError>>()
            + size_of::<&Option<Seed>>()
            + size_of::<Option<&Seed>>()
            + size_of::<bool>()
            + size_of::<[usize; 2]>()
            + size_of::<std::array::IntoIter<usize, 2>>()
            + size_of::<Option<usize>>()
            + size_of::<&usize>()
            + size_of::<Result<usize, OperationFailure>>()
            + size_of::<Result<usize, crate::node_contract::RuntimeError>>()
    }
}

pub(crate) use restoration_observation::OriginalSourceRestoredObservationCompletion;

#[path = "association/producer_progress.rs"]
mod producer_progress;

pub(crate) use producer_progress::OriginalSourceRestoredProducerPhaseCompletion;

#[path = "association/settled17_once.rs"]
mod settled17_once;
pub(crate) use settled17_once::OriginalSourceRestoredOnce17Read;

pub(crate) use producer_progress::{
    OriginalSourceRestoredFirstObservationHistory17Read, OriginalSourceRestoredInstallation17,
    OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17,
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Prelude, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs,
};

pub(crate) use producer_progress::{
    OriginalSourceRestoredCaptureCompletion, OriginalSourceRestoredCaptureQuoteInputs,
};

pub(crate) use producer_progress::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use producer_progress::OriginalSourceRestoredCaptureCountingBanksData;

pub use producer_progress::OriginalSourceRestoredCaptureConstructionData;
