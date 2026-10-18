//! Signs exact assigned restoration requests only beneath original Core authority.
//!
//! The pre-Child attempt banks and original fresh birth/Hello/emitter association
//! precede signing. Core native tickets and SDK mappings move into this slot
//! before fallible validation. A refused or unwound attempt remains spent and
//! retains every original owner; it cannot be retried with replacement data.

use super::*;

#[path = "complete_restore/history.rs"]
mod history;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crate::{
    node_contract::OriginalLineageRestoration,
    node_state::{CompleteOriginalNativeTicket, CompleteOriginalRestorationSource},
};
use crucible_node_provider::{
    bodies::{BeginKind, BeginRequest, MethodResult, PrepareRestoreArguments, ResponseShape},
    client::PreparedOriginalCompleteRestore,
    envelope::Nullable,
    protocol_snapshot::PreparedArchivedProtocolMapping,
    reference_packet::service::complete_restore::{
        PACKET_COMPLETE_RESTORE_ALGORITHM, PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA,
        PACKET_COMPLETE_RESTORE_FEATURE, PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        PacketCompleteRestoreContext, PacketCompleteRestoreReceipt, PacketCompleteRestoreRequest,
        PacketNative5CompleteRestoreSelection, complete_restore_assigned_request_digest,
        complete_restore_assigned_response_digest, complete_restore_proof_data,
        verify_complete_restore_receipt_data,
    },
};

const BACKEND_BYTES: usize = 512 * 1024;
pub(super) const MAPPING_BYTES: usize = 64 * 1024;
const JOURNAL_BYTES: usize = 64 * 1024;
const RESTORE_FIXED_BANKS: [usize; 5] = [BACKEND_BYTES, MAPPING_BYTES, 8192, 2048, 256];

/// Borrows actual signed source, target and owning inputs for one restoration.
///
/// Constructing this argument bundle grants no authority. Its tickets, runtime
/// context and SDK mapping have independent private issuers; the Source checks
/// their same-original associations before moving any request toward publication.
pub struct PacketCompleteRestorePreparation<'a, 'context> {
    /// Borrows the actual completely verified signed archive source.
    pub source: &'a CompleteOriginalRestorationSource,
    /// Transfers the original single-owner ticket into failure-retaining custody.
    pub ticket: &'a mut Option<CompleteOriginalNativeTicket>,
    /// Borrows the independently issued actual fresh Core runtime context.
    pub context: &'a OriginalLineageRestoration<'context>,
    /// Transfers the actual fresh SDK mapping into the same attempt.
    pub mapping: &'a mut Option<PreparedArchivedProtocolMapping>,
    /// Names the signed owner's exact local settlement journal role.
    pub journal_reference: &'a ContentRef,
    /// Names the one assigned request and baseline preparation transaction.
    pub request_id: Id,
    /// Charges all other retained owners during full Core index serialization.
    pub additional_retained_bytes: usize,
}

pub(super) struct OriginalCompleteRestoreAttempt {
    ticket: Option<CompleteOriginalNativeTicket>,
    mapping: Option<PreparedArchivedProtocolMapping>,
    journal: Option<crate::node_adapters::cnp::PacketCompleteSettledJournal>,
    request: Option<PacketCompleteRestoreRequest>,
    context: Option<PacketCompleteRestoreContext>,
    normalized: [Option<serde_json::Value>; 6],
    banks: [Vec<u8>; 6],
    assigned_digest: Option<[u8; 32]>,
    prepared: bool,
    ready: bool,
    signing_started: bool,
    sealed: bool,
    publishing_started: bool,
    frame_maximum: usize,
}

impl OriginalCompleteRestoreAttempt {
    pub(super) fn allocated_bytes(&self) -> Result<usize, OperationFailure> {
        self.allocated_bytes_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn allocated_bytes_with_error<E: StorageError>(
        &self,
    ) -> Result<usize, E> {
        self.banks.iter().try_fold(0usize, |sum, bank| {
            sum.checked_add(bank.capacity())
                .ok_or_else(|| E::limit("complete restore actual bank extent overflow"))
        })
    }

    fn ticket(&self) -> Result<&CompleteOriginalNativeTicket, OperationFailure> {
        self.ticket
            .as_ref()
            .ok_or_else(|| refused("complete restore original ticket absent"))
    }

    fn mapping(&self) -> Result<&PreparedArchivedProtocolMapping, OperationFailure> {
        self.mapping
            .as_ref()
            .ok_or_else(|| refused("complete restore original mapping absent"))
    }

    fn request(&self) -> Result<&PacketCompleteRestoreRequest, OperationFailure> {
        self.request
            .as_ref()
            .ok_or_else(|| refused("complete restore original request absent"))
    }

    fn encode(&mut self, index: usize, maximum: usize) -> Result<(), OperationFailure> {
        encode_canonical_birth_bank(
            self.normalized[index]
                .as_ref()
                .ok_or_else(|| refused("complete restore normalized owner absent"))?,
            maximum,
            &mut self.banks[index],
        )
    }
}

impl OriginalAckPeerAssociation {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn minimum_complete_restore_bank_bytes(
        frame_bytes: usize,
    ) -> Result<usize, OperationFailure> {
        RESTORE_FIXED_BANKS
            .into_iter()
            .try_fold(frame_bytes, |sum, next| {
                sum.checked_add(next)
                    .ok_or_else(|| refused("complete restore selected bank sum overflow"))
            })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn reserve_complete_restore_banks(
        &mut self,
        frame_bytes: usize,
    ) -> Result<(), OperationFailure> {
        if self.restore.is_some() || self.attempted {
            return Err(refused(
                "complete restore banks are repeated or follow Hello association",
            ));
        }
        self.restore = Some(OriginalCompleteRestoreAttempt {
            ticket: None,
            mapping: None,
            journal: None,
            request: None,
            context: None,
            normalized: std::array::from_fn(|_| None),
            banks: std::array::from_fn(|_| Vec::new()),
            assigned_digest: None,
            prepared: false,
            ready: false,
            signing_started: false,
            sealed: false,
            publishing_started: false,
            frame_maximum: frame_bytes,
        });
        let restore = self
            .restore
            .as_mut()
            .ok_or_else(|| refused("complete restore bank slot absent"))?;
        for (bank, limit) in restore
            .banks
            .iter_mut()
            .zip(RESTORE_FIXED_BANKS.into_iter().chain([frame_bytes]))
        {
            bank.try_reserve_exact(limit)
                .map_err(|_| refused("complete restore bank allocation refused"))?;
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Derives the original fresh mapping nonce without granting installation.
    ///
    /// # Errors
    /// Refuses foreign custody, absent selected restoration or changed private birth.
    pub fn original_complete_restore_mapping_nonce(&self) -> Result<[u8; 32], OperationFailure> {
        self.ensure_origin()?;
        let domain = match self.selected_complete_restore_selection()? {
            Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11) => {
                "source-owned.packet-complete-restore-mapping-nonce/11"
            }
            Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                if self.selected_restore_input_emitter_selection()?.is_some() =>
            {
                "source-owned.packet-complete-restore-mapping-nonce/12"
            }
            _ => return Err(refused("complete restore source selection absent")),
        };
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("complete restore private birth busy"))?;
        let inputs = birth
            .as_ref()
            .ok_or_else(|| refused("complete restore private birth absent"))?
            .original_post_hello_inputs()?;
        Ok(blake3::derive_key(domain, inputs.key))
    }

    /// Prepares one restore under the actual signed source and fresh Core context.
    ///
    /// Both original owning input slots move into the precharged destination
    /// before archive/mapping checks. The SDK subsequently owns the assigned
    /// envelope, original sequence, cut and literal slot before returning.
    /// `additional_retained_bytes` is the factory's independently checked total
    /// of all other coexisting owners for the bounded Core index serialization.
    /// This method enforces its actual Source/content bank floor; the argument
    /// never replaces complete factory/target memory admission.
    ///
    /// # Errors
    /// Refuses occupied/spent ownership, another source/target/backend, wrong
    /// journal roles, changed fresh mapping or exhausted original banks.
    pub fn prepare_original_complete_restoration<'a>(
        &self,
        controller: &'a mut CnpController,
        inputs: PacketCompleteRestorePreparation<'_, '_>,
    ) -> Result<PreparedOriginalCompleteRestore<'a>, OperationFailure> {
        self.ensure_origin()?;
        if self.selected_complete_restore_selection()?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11)
        {
            // Full outer13 decoding does not issue the distinct Prepare/Commit
            // transaction required by Transfer12. Keep this signer edition11.
            return Err(refused(
                "single-request restore requires explicit selected11",
            ));
        }
        let PacketCompleteRestorePreparation {
            source,
            ticket,
            context,
            mapping,
            journal_reference,
            request_id,
            additional_retained_bytes,
        } = inputs;
        let nonce = self.original_complete_restore_mapping_nonce()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("complete restore original association busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("complete restore original association absent"))?;
        original.authenticate_current()?;
        original
            .emitter()?
            .authenticate_original(controller)
            .map_err(unknown)?;
        let association_bytes = original.allocated_bank_bytes()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or_else(|| refused("complete restore original emitter absent"))?;
        let native = original
            .native
            .as_ref()
            .ok_or_else(|| refused("complete restore original native absent"))?;
        let restore = original
            .restore
            .as_mut()
            .ok_or_else(|| refused("complete restore precharged banks absent"))?;
        if restore.prepared || restore.ticket.is_some() || restore.mapping.is_some() {
            return Err(refused(
                "complete restore original preparation already spent",
            ));
        }
        restore.prepared = true;
        restore.ticket = ticket.take();
        restore.mapping = mapping.take();
        let result = (move || {
            restore
                .ticket()?
                .authenticate_source(source)
                .map_err(unknown)?;
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)?;
            controller
                .authenticate_archived_protocol_mapping(restore.mapping()?)
                .map_err(unknown)?;
            if restore.mapping()?.nonce() != &nonce {
                return Err(refused(
                    "complete restore mapping nonce differs from fresh birth",
                ));
            }
            let source_floor = restore
                .ticket()?
                .content()
                .map_err(unknown)?
                .capture_owned_storage()
                .map_err(unknown)?
                .checked_add(self.original_capture_bank_facts()?.total_bytes)
                .and_then(|sum| sum.checked_add(association_bytes))
                .ok_or_else(|| refused("complete restore index retained floor overflow"))?;
            if additional_retained_bytes < source_floor {
                return Err(refused(
                    "complete restore index omitted retained source allocations",
                ));
            }
            let owner = restore.ticket()?.owner().map_err(unknown)?;
            let installation = self.installation();
            let target = context.target();
            let target_owner = target
                .owners
                .iter()
                .find(|one| one.owner == owner.owner)
                .ok_or_else(|| refused("complete restore actual Core target owner absent"))?;
            if owner.owner != installation.owner.owner.id
                || owner.participants != installation.owner.owner.participant_ids
                || target.world_binding_hash != installation.world_binding_hash
                || target_owner.generation != installation.binding.authority.owner_generation
                || owner.cut != context.record().capture_cut
                || !owner.evidence.contains(journal_reference)
                || owner.key.implementation != installation.provider.implementation.implementation_id
                || owner.key.profile.as_str() != "source-owned.packet-complete-original-lineage/5"
                || owner.key.schema != crucible_node_provider::reference_packet::service::native_owned11_snapshot_schema().map_err(unknown)?
            {
                return Err(refused("complete restore signed owner or actual target differs"));
            }
            let content = restore.ticket()?.content().map_err(unknown)?;
            let journal_bytes = content
                .get(journal_reference)
                .ok_or_else(|| refused("complete restore signed local journal absent"))?;
            journal_reference.verify(journal_bytes).map_err(unknown)?;
            restore.journal = Some(
                crate::node_adapters::cnp::PacketCompleteSettledJournal::decode_data(
                    journal_bytes,
                    JOURNAL_BYTES,
                )?,
            );
            let journal = restore
                .journal
                .as_ref()
                .ok_or_else(|| refused("complete restore retained journal absent"))?;
            let ticket = restore.ticket()?;
            let owner = ticket.owner().map_err(unknown)?;
            let content = ticket.content().map_err(unknown)?;
            journal.authenticate_owner_data(
                owner,
                context.record(),
                ticket.runtime_object().map_err(unknown)?,
                content,
            )?;
            journal.authenticate_backend_data(
                &installation.provider.implementation,
                &owner.key,
                content,
            )?;
            if restore.mapping()?.archive_protocol() != &journal.host_protocol
                || restore.mapping()?.native_protocol() != &journal.native_after_protocol
            {
                return Err(refused(
                    "complete restore mapping differs from signed complete protocol roles",
                ));
            }
            restore.normalized[0] = Some(
                crate::node_adapters::cnp::PacketCompleteSettledJournal::backend_identity_data(
                    &installation.provider.implementation,
                    &owner.key,
                ),
            );
            restore.encode(0, BACKEND_BYTES)?;
            restore.normalized[1] = Some(
                serde_json::to_value(restore.mapping()?.normalization_view()).map_err(unknown)?,
            );
            restore.encode(1, MAPPING_BYTES)?;
            let owner = restore.ticket()?.owner().map_err(unknown)?;
            let journal = restore
                .journal
                .as_ref()
                .ok_or_else(|| refused("complete restore journal lost"))?;
            let mapping_reference =
                canonical::content_ref(&restore.banks[1], "application/json").map_err(unknown)?;
            let request = PacketCompleteRestoreRequest {
                schema: PACKET_COMPLETE_RESTORE_FEATURE.into(),
                archive_index: source
                    .archive()
                    .complete_original_index_identity(BACKEND_BYTES, additional_retained_bytes)
                    .map_err(unknown)?,
                capture_manifest: source.archive().artifact().clone(),
                owner_state: owner.state.clone(),
                journal: journal_reference.clone(),
                source_runtime: journal.runtime.clone(),
                backend_implementation: journal.backend_implementation.clone(),
                backend_schema: owner.key.schema.clone(),
                archived_cut: journal.cut,
                archived_ordinal: journal.ordinal,
                target_world: target.world_binding_hash.clone(),
                target_owner: target_owner.owner.clone(),
                target_owner_binding: installation.owner.identity().map_err(unknown)?,
                target_activation: target.activation_id.clone(),
                target_generation: target.generation,
                target_owner_generation: target_owner.generation,
                mapping: mapping_reference,
                nonce: Bytes::new(nonce.to_vec()),
            };
            request.validate_data().map_err(unknown)?;
            restore.request = Some(request);
            restore.normalized[2] =
                Some(serde_json::to_value(restore.request()?).map_err(unknown)?);
            restore.encode(2, 8192)?;
            let request = restore.request()?;
            let arguments = PrepareRestoreArguments {
                transaction_id: request_id.clone(),
                capture_manifest: request.capture_manifest.clone(),
                expected_world_binding_hash: request.target_world.clone(),
                expected_owner_binding_hash: request.target_owner_binding.clone(),
                destination_owner_ids: vec![request.target_owner.clone()],
            };
            let arguments = serde_json::to_value(arguments)
                .map_err(unknown)?
                .as_object()
                .cloned()
                .ok_or_else(|| refused("complete restore baseline arguments are not an object"))?;
            let baseline = BeginRequest {
                kind: BeginKind::PrepareRestore,
                binding_hash: request.target_owner_binding.clone(),
                owner_generation: request.target_owner_generation,
                activation_id: Nullable(Some(request.target_activation.clone())),
                world_generation: request.target_generation,
                arguments,
                extensions: Default::default(),
            };
            let request: PacketCompleteRestoreRequest =
                serde_json::from_slice(&restore.banks[2]).map_err(unknown)?;
            let prepared = controller
                .prepare_original_complete_restore(
                    emitter,
                    request_id,
                    baseline,
                    request,
                    restore.mapping()?,
                )
                .map_err(unknown)?;
            native.ensure_current().map_err(unknown)?;
            restore.ready = true;
            Ok(prepared)
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }
}

impl PacketCompleteSemanticSource {
    /// Signs the exact SDK-assigned restore from retained original owners.
    ///
    /// No context, digest, key, archive role or counter can be supplied by the
    /// caller. The source rechecks its original ticket/target, mapping, literal
    /// Hello and fresh native/emitter before sealing the same assigned frame.
    ///
    /// # Errors
    /// Refuses a repeated/incomplete attempt, changed Core target, another
    /// assigned request, changed original peer or exhausted retained banks.
    pub fn seal_original_complete_restoration(
        &self,
        prepared: &mut PreparedOriginalCompleteRestore<'_>,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("complete restore association busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("complete restore association absent"))?;
        original.authenticate_current()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or_else(|| refused("complete restore emitter absent"))?;
        let journal = original
            .hello
            .as_ref()
            .ok_or_else(|| refused("complete restore original Hello absent"))?;
        let native = original
            .native
            .as_ref()
            .ok_or_else(|| refused("complete restore original native absent"))?;
        let restore = original
            .restore
            .as_mut()
            .ok_or_else(|| refused("complete restore banks absent"))?;
        if !restore.ready || restore.signing_started {
            return Err(refused("complete restore signing is incomplete or spent"));
        }
        restore.signing_started = true;
        let result = (|| {
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)?;
            prepared
                .authenticate_original_emitter(emitter)
                .map_err(unknown)?;
            prepared
                .authenticate_archived_mapping(restore.mapping()?)
                .map_err(unknown)?;
            let envelope = prepared.original().map_err(unknown)?;
            let request = restore.request()?;
            let extension = envelope
                .extensions
                .get(PACKET_COMPLETE_RESTORE_FEATURE)
                .ok_or_else(|| refused("complete restore assigned request extension absent"))?;
            if envelope.extensions.len() != 1
                || serde_json::to_value(request).map_err(unknown)? != *extension
                || envelope.node_id.0.as_ref()
                    != Some(&self.installation().binding.compatibility.node_id)
                || envelope.execution_owner_id.0.as_ref() != Some(&request.target_owner)
            {
                return Err(refused(
                    "complete restore assigned original differs from Source",
                ));
            }
            let baseline: BeginRequest =
                serde_json::from_value(serde_json::Value::Object(envelope.body.clone()))
                    .map_err(unknown)?;
            let crucible_node_provider::bodies::BeginArguments::PrepareRestore(arguments) =
                baseline.decoded_arguments().map_err(unknown)?
            else {
                return Err(refused("complete restore assigned baseline kind differs"));
            };
            if baseline.binding_hash != request.target_owner_binding
                || baseline.owner_generation != request.target_owner_generation
                || baseline.world_generation != request.target_generation
                || baseline.activation_id.0.as_ref() != Some(&request.target_activation)
                || !baseline.extensions.is_empty()
                || envelope.request_id.0.as_ref() != Some(&arguments.transaction_id)
                || arguments.capture_manifest != request.capture_manifest
                || arguments.expected_world_binding_hash != request.target_world
                || arguments.expected_owner_binding_hash != request.target_owner_binding
                || arguments.destination_owner_ids.as_slice()
                    != std::slice::from_ref(&request.target_owner)
            {
                return Err(refused("complete restore assigned baseline scope differs"));
            }
            let maximum = restore.frame_maximum;
            let assigned =
                complete_restore_assigned_request_digest(envelope, maximum).map_err(unknown)?;
            restore.normalized[5] = Some(serde_json::to_value(envelope).map_err(unknown)?);
            restore.encode(5, maximum)?;
            restore.assigned_digest = Some(assigned);
            let projections = restore
                .request()?
                .context_bindings(&restore.banks[1])
                .map_err(unknown)?;
            let hello = prepared
                .original_canonical_ack_hello_frame_digests(journal)
                .map_err(unknown)?;
            let birth_slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("complete restore original birth busy"))?;
            let birth = birth_slot
                .as_ref()
                .ok_or_else(|| refused("complete restore original birth absent"))?;
            let inputs = birth.original_post_hello_inputs()?;
            restore.context = Some(PacketCompleteRestoreContext {
                schema: PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA.into(),
                algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
                source_birth: digest(&original.banks[0]),
                kernel_binding: digest(&original.banks[1]),
                policy_binding: digest(&original.banks[2]),
                host_registration: digest(inputs.host_registration),
                native_registration: digest(&original.banks[3]),
                hello_request: Bytes::new(hello.request_frame_digest.to_vec()),
                hello_response: Bytes::new(hello.response_frame_digest.to_vec()),
                assigned_restore: Bytes::new(assigned.to_vec()),
                archive_binding: projections.archive_binding,
                target_binding: projections.target_binding,
                mapping_binding: projections.mapping_binding,
                request_binding: projections.request_binding,
            });
            restore.normalized[3] = Some(
                serde_json::to_value(
                    restore
                        .context
                        .as_ref()
                        .ok_or_else(|| refused("complete restore context slot absent"))?,
                )
                .map_err(unknown)?,
            );
            restore.encode(3, 2048)?;
            let context_data = restore
                .context
                .as_ref()
                .ok_or_else(|| refused("complete restore context lost"))?;
            context_data
                .authenticate_request_bindings_data(restore.request()?, &restore.banks[1])
                .map_err(unknown)?;
            let proof = complete_restore_proof_data(inputs.key, context_data).map_err(unknown)?;
            restore.normalized[4] = Some(serde_json::to_value(&proof).map_err(unknown)?);
            restore.encode(4, 256)?;
            native.ensure_current().map_err(unknown)?;
            birth.authenticate_original()?;
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)?;
            prepared
                .authenticate_archived_mapping(restore.mapping()?)
                .map_err(unknown)?;
            prepared.seal(emitter, proof).map_err(unknown)?;
            restore.sealed = true;
            native.ensure_current().map_err(unknown)
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    /// Publishes the same sealed original while retaining its response on failure.
    ///
    /// This returns transport data only. The independently authenticated native
    /// receipt and original Core target are rechecked before a fresh association
    /// or mechanical host installation can succeed.
    ///
    /// # Errors
    /// Refuses repeated/unsealed publication, changed owners, uncertain IO or
    /// a final original custody check. The caller result slot is never cleared.
    pub fn publish_original_complete_restoration_into(
        &self,
        prepared: &mut PreparedOriginalCompleteRestore<'_>,
        context: &OriginalLineageRestoration<'_>,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("complete restore association busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("complete restore association absent"))?;
        original.authenticate_current()?;
        let restore = original
            .restore
            .as_mut()
            .ok_or_else(|| refused("complete restore attempt absent"))?;
        if !restore.sealed || restore.publishing_started || completed.is_some() {
            return Err(refused(
                "complete restore publication is unsealed, spent or occupied",
            ));
        }
        restore.publishing_started = true;
        let result = (|| {
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)?;
            prepared
                .authenticate_archived_mapping(restore.mapping()?)
                .map_err(unknown)?;
            prepared
                .publish_into(
                    original
                        .emitter
                        .as_ref()
                        .ok_or_else(|| refused("complete restore emitter lost"))?,
                    completed,
                )
                .map_err(unknown)?;
            original
                .native
                .as_ref()
                .ok_or_else(|| refused("complete restore native lost"))?
                .ensure_current()
                .map_err(unknown)?;
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    /// Checks the actual completed native receipt against its original Core target.
    ///
    /// This read-only predicate issues no provider constructor or portable token.
    /// A host mechanical installer must also consume the SDK's actual completed
    /// original and retained mapping exactly once.
    ///
    /// # Errors
    /// Refuses changed source/target/controller, absent completion, another
    /// mapping or wrong response correlation/MAC. Reauthentication never spends
    /// another native token or performs a mechanical host installation.
    pub fn authenticate_completed_original_complete_restoration(
        &self,
        controller: &CnpController,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        let mut slot = self
            .ack_peer_association
            .try_borrow_mut()
            .map_err(|_| refused("complete restore association busy"))?;
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("complete restore association absent"))?;
        original.authenticate_current()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or_else(|| refused("complete restore emitter absent"))?;
        let restore = original
            .restore
            .as_mut()
            .ok_or_else(|| refused("complete restore attempt absent"))?;
        if !restore.publishing_started {
            return Err(refused("complete restore original publication is absent"));
        }
        let result = (|| {
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)?;
            controller
                .authenticate_archived_protocol_mapping(restore.mapping()?)
                .map_err(unknown)?;
            let completed = controller
                .original_completed_complete_restore(emitter)
                .map_err(unknown)?;
            let request = completed.original();
            let response = completed.response();
            let expected_assigned = restore
                .assigned_digest
                .ok_or_else(|| refused("complete restore assigned digest absent"))?;
            if complete_restore_assigned_request_digest(request, restore.frame_maximum)
                .map_err(unknown)?
                != expected_assigned
                || response.extensions.len() != 1
            {
                return Err(refused("complete restore completed original changed"));
            }
            let context_data = restore
                .context
                .as_ref()
                .ok_or_else(|| refused("complete restore context absent"))?;
            let receipt: PacketCompleteRestoreReceipt = serde::Deserialize::deserialize(
                response
                    .extensions
                    .get(PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION)
                    .ok_or_else(|| refused("complete restore native receipt absent"))?,
            )
            .map_err(unknown)?;
            let response_digest =
                complete_restore_assigned_response_digest(request, response, restore.frame_maximum)
                    .map_err(unknown)?;
            let birth_slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| refused("complete restore private birth busy"))?;
            let birth = birth_slot
                .as_ref()
                .ok_or_else(|| refused("complete restore private birth absent"))?;
            let inputs = birth.original_post_hello_inputs()?;
            verify_complete_restore_receipt_data(
                inputs.key,
                restore.request()?,
                context_data,
                response.sequence,
                &response_digest,
                &receipt,
            )
            .map_err(unknown)?;
            let request_body =
                crucible_node_provider::bodies::decode_request(request.method, &request.body)
                    .map_err(unknown)?;
            let completed_body =
                crucible_node_provider::bodies::decode_response(&request_body, &response.body)
                    .map_err(unknown)?;
            let request_data = restore.request()?;
            if !matches!(completed_body.shape, ResponseShape::Completed { ref extensions, .. } if extensions.is_empty())
            {
                return Err(refused("complete restore response is not closed completed"));
            }
            let Some(MethodResult::PrepareRestore(prepared)) = completed_body.result else {
                return Err(refused("complete restore response result differs"));
            };
            if request.request_id.0.as_ref() != Some(&prepared.transaction_id)
                || prepared.world_binding_hash != request_data.target_world
                || prepared.owner_binding_hash != request_data.target_owner_binding
                || prepared.staged_owner_ids.as_slice()
                    != std::slice::from_ref(&request_data.target_owner)
                || prepared.validated_manifest != request_data.capture_manifest
            {
                return Err(refused("complete restore completed native target differs"));
            }
            birth.authenticate_original()?;
            original
                .native
                .as_ref()
                .ok_or_else(|| refused("complete restore native lost"))?
                .ensure_current()
                .map_err(unknown)?;
            restore
                .ticket()?
                .authenticate_context(context)
                .map_err(unknown)?;
            Ok(())
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod reservation_tests {
    use super::*;

    #[test]
    fn restore_prebirth_banks_are_distinct_and_repeated_reservation_retains_them() {
        let mut slot = None;
        OriginalAckPeerAssociation::reserve_into(8192, &mut slot).unwrap();
        let association = slot.as_mut().unwrap();
        let before = association.allocated_bank_bytes().unwrap();
        let minimum =
            OriginalAckPeerAssociation::minimum_complete_restore_bank_bytes(8192).unwrap();

        association.reserve_complete_restore_banks(8192).unwrap();
        let retained = association.allocated_bank_bytes().unwrap();
        assert!(retained >= before + minimum);
        assert!(association.reserve_complete_restore_banks(8192).is_err());
        assert_eq!(association.allocated_bank_bytes().unwrap(), retained);
    }

    #[test]
    fn hello_association_attempt_cannot_retrofit_restore_banks() {
        let mut slot = None;
        OriginalAckPeerAssociation::reserve_into(8192, &mut slot).unwrap();
        let association = slot.as_mut().unwrap();
        let before = association.allocated_bank_bytes().unwrap();
        association.attempted = true;

        assert!(association.reserve_complete_restore_banks(8192).is_err());
        assert!(association.restore.is_none());
        assert_eq!(association.allocated_bank_bytes().unwrap(), before);
    }
}

impl OriginalCompleteRestoreAttempt {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_unpopulated_capture_metadata_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<(), E> {
        if self.ticket.is_some()
            || self.mapping.is_some()
            || self.journal.is_some()
            || self.request.is_some()
            || self.context.is_some()
            || self.normalized.iter().any(Option::is_some)
        {
            return Err(E::refused(
                "retained restore graph requires post-install owning class coverage",
            ));
        }
        Ok(())
    }
}

impl OriginalCompleteRestoreAttempt {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_reserved_prebirth_data_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
    ) -> Result<(), E> {
        let Self {
            ticket,
            mapping,
            journal,
            request,
            context,
            normalized,
            banks,
            assigned_digest,
            prepared,
            ready,
            signing_started,
            sealed,
            publishing_started,
            frame_maximum,
        } = self;
        if ticket.is_some()
            || mapping.is_some()
            || journal.is_some()
            || request.is_some()
            || context.is_some()
            || normalized.iter().any(Option::is_some)
            || assigned_digest.is_some()
            || *prepared
            || *ready
            || *signing_started
            || *sealed
            || *publishing_started
            || *frame_maximum == 0
            || banks.iter().any(|bank| !bank.is_empty())
        {
            return Err(E::refused(
                "reserved prebirth restore banks are already used",
            ));
        }
        Ok(())
    }
}

impl OriginalCompleteRestoreAttempt {
    pub(super) fn settled17_once_data(
        &self,
    ) -> Result<super::settled17_once::RestoreOnce17, RuntimeError> {
        self.authenticate_unpopulated_capture_metadata_with_error::<RuntimeError>()?;
        Ok(super::settled17_once::RestoreOnce17 {
            prepared: self.prepared,
            ready: self.ready,
            signing_started: self.signing_started,
            sealed: self.sealed,
            publishing_started: self.publishing_started,
        })
    }
}
