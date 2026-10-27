//! Retains a distinct original complete-restore request before signing or I/O.

use super::*;
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::PreparedArchivedProtocolMapping;
use crate::reference_packet::service::complete_restore::*;
use std::rc::Rc;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Phase {
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

pub(super) struct AssignedOriginalCompleteRestore {
    pub(super) original: Envelope,
    pub(super) bytes: Vec<u8>,
    pub(super) literal_slot: Option<usize>,
    pub(super) cut: OperationalDeadline,
    pub(super) phase: Phase,
    pub(super) response: Option<Envelope>,
    pub(super) mapping: ContentRef,
    pub(super) mapping_identity: Rc<crate::protocol_snapshot::ArchivedProtocolMappingIdentity>,
    pub(super) nonce: [u8; 32],
}

impl AssignedOriginalCompleteRestore {
    pub(super) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.validate_owned_snapshot()?;
        let Self {
            original,
            bytes,
            literal_slot: _,
            cut: _,
            phase: _,
            response,
            mapping,
            mapping_identity,
            nonce: _,
        } = self;
        observer.observe(original)?;
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(response)?;
        observer.observe(mapping)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ArchivedMapping,
            mapping_identity.as_ref(),
        )
    }

    pub(super) fn original_cut(&self) -> OperationalDeadline {
        self.cut
    }

    pub(super) fn owned_protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            "complete-restore",
            (
                "complete",
                &self.original,
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(&self.bytes),
                self.bytes.capacity(),
                self.literal_slot,
                &self.response,
                "original-physical-cut-retained-by-opaque-owner-not-portable-time",
            ),
            &self.mapping,
            self.nonce,
            "original-prepared-mapping-retained",
        )
    }

    pub(super) fn validate_owned_snapshot(&self) -> Result<(), ProviderError> {
        if self.phase != Phase::Complete || self.response.is_none() || self.literal_slot.is_none() {
            return Err(ProviderError::Correlation(
                "assigned complete restore unsettled",
            ));
        }
        Ok(())
    }
}

/// Borrows an exact controller-owned assigned restore without moving its owners.
#[must_use = "the original request remains in the controller when this loan ends"]
pub struct PreparedOriginalCompleteRestore<'a> {
    controller: &'a mut CnpController,
}

/// Borrows both exact completed originals without minting restoration permission.
pub struct CompletedOriginalCompleteRestore<'a> {
    original: &'a Envelope,
    response: &'a Envelope,
}

impl CompletedOriginalCompleteRestore<'_> {
    /// Borrows the exact sequence-assigned request, including its sole proof.
    pub fn original(&self) -> &Envelope {
        self.original
    }

    /// Borrows the actual correlated response, including its original receipt.
    pub fn response(&self) -> &Envelope {
        self.response
    }
}

impl CnpController {
    /// Assigns one source-signed restore request before lending it to the signer.
    ///
    /// # Errors
    /// Refuses a stale emitter/mapping, another retained restore, reused ID,
    /// unnegotiated schema, wrong baseline kind or insufficient original credit.
    pub fn prepare_original_complete_restore<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        baseline: BeginRequest,
        request: PacketCompleteRestoreRequest,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<PreparedOriginalCompleteRestore<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        self.ensure_no_pending_original_ack_admit()?;
        self.authenticate_archived_protocol_mapping(mapping)?;
        if self.original_native5_complete_restore_selection()?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11)
        {
            return Err(ProviderError::Correlation(
                "source-signed complete restore codec absent",
            ));
        }
        if self.original_complete_restore.is_some() || self.original(&request_id).is_some() {
            return Err(ProviderError::Conflict(
                "original complete restore already reserved",
            ));
        }
        if !baseline.extensions.is_empty()
            || !matches!(
                baseline.decoded_arguments()?,
                BeginArguments::PrepareRestore(_)
            )
            || request.nonce.as_slice() != mapping.nonce()
        {
            return Err(ProviderError::Correlation(
                "original complete restore baseline/mapping differs",
            ));
        }
        for key in [
            PACKET_COMPLETE_RESTORE_FEATURE,
            PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
            PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        ] {
            if !self.authority().envelope_extensions().contains(key) {
                return Err(ProviderError::Correlation(
                    "original complete restore extension unnegotiated",
                ));
            }
        }
        request.validate_data()?;
        baseline.validate()?;
        let maximum = self.maximum_frame()?;
        count_serialized(&baseline, maximum)?;
        let value =
            serde_json::to_value(baseline).map_err(crucible_node_format::ContractError::from)?;
        let Value::Object(body) = value else {
            return Err(ProviderError::Frame(
                "original complete restore body not object",
            ));
        };
        let request_value =
            serde_json::to_value(&request).map_err(crucible_node_format::ContractError::from)?;
        let mut extensions = Extensions::new();
        extensions.insert(PACKET_COMPLETE_RESTORE_FEATURE.into(), request_value);
        let (sequence, cut) = self.session.current_original_complete_restore_cut()?;
        let original = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(request_id)),
            operation_id: Nullable(None),
            sequence,
            method: Method::Begin,
            body,
            extensions,
        };
        let final_maximum = crate::connection::serialized_credit(&original, maximum)?
            .checked_add(PACKET_COMPLETE_RESTORE_PROOF_EXTENSION.len() + 3)
            .and_then(|n| n.checked_add(MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES))
            .filter(|n| *n <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "original complete restore proof frame credit",
            ))?;
        self.preflight_source_reply(
            1,
            0,
            final_maximum
                .checked_add(maximum)
                .ok_or(ProviderError::ResourceExhausted(
                    "original complete restore journal credit",
                ))?,
            0,
            0,
        )?;
        self.original_complete_restore = Some(AssignedOriginalCompleteRestore {
            original,
            bytes: Vec::new(),
            literal_slot: None,
            cut,
            phase: Phase::Unsigned,
            response: None,
            mapping: request.mapping,
            mapping_identity: mapping.retain_identity(),
            nonce: *mapping.nonce(),
        });
        let state = self
            .original_complete_restore
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "original complete restore owner absent",
            ))?;
        state.bytes.try_reserve_exact(final_maximum).map_err(|_| {
            ProviderError::ResourceExhausted("original complete restore canonical bank")
        })?;
        self.session.reserve_original_complete_restore(
            &state.original,
            final_maximum,
            &mut state.literal_slot,
        )?;
        Ok(PreparedOriginalCompleteRestore { controller: self })
    }

    /// Resumes the same unattempted signing or sealed original without renewing it.
    ///
    /// # Errors
    /// Refuses changed emitter/cut, missing slot or any prior failed attempt.
    pub fn resume_original_complete_restore<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<PreparedOriginalCompleteRestore<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self
            .original_complete_restore
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original complete restore absent",
            ))?;
        if !matches!(state.phase, Phase::Unsigned | Phase::Sealed) || state.literal_slot.is_none() {
            return Err(ProviderError::Conflict(
                "original complete restore cannot resume",
            ));
        }
        self.session
            .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        Ok(PreparedOriginalCompleteRestore { controller: self })
    }

    /// Borrows actual completed originals under this same retained emitter.
    ///
    /// # Errors
    /// Refuses another emitter, incomplete state or an absent actual reply.
    pub fn original_completed_complete_restore(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<CompletedOriginalCompleteRestore<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self
            .original_complete_restore
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "completed original complete restore absent",
            ))?;
        state.validate_owned_snapshot()?;
        Ok(CompletedOriginalCompleteRestore {
            original: &state.original,
            response: state.response.as_ref().ok_or(ProviderError::Correlation(
                "completed restore raw reply absent",
            ))?,
        })
    }

    pub(super) fn ensure_no_pending_original_complete_restore(&self) -> Result<(), ProviderError> {
        self.ensure_no_pending_original_restored_settled_capture()?;
        self.ensure_no_pending_original_installed_restoration_activation()?;
        if [
            self.original_complete_restore.as_ref(),
            self.original_complete_restore_prepare.as_ref(),
            self.original_complete_restore_commit.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|state| state.phase != Phase::Complete)
        {
            return Err(ProviderError::Conflict(
                "assigned original complete restore remains retained",
            ));
        }
        Ok(())
    }
}

impl PreparedOriginalCompleteRestore<'_> {
    fn state(&self) -> Result<&AssignedOriginalCompleteRestore, ProviderError> {
        self.controller
            .original_complete_restore
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "assigned complete restore owner absent",
            ))
    }

    /// Reauthenticates the same actual emitter before signing or publishing.
    ///
    /// # Errors
    /// Refuses another emitter, changed original sequence or expired original cut.
    pub fn authenticate_original_emitter(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        let state = self.state()?;
        if state.phase != Phase::Complete {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        }
        Ok(())
    }

    /// Rechecks this actual fresh mapping and its retained request binding.
    ///
    /// # Errors
    /// Refuses another target/mapping/nonce or a stale original physical cut.
    pub fn authenticate_archived_mapping(
        &self,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_archived_protocol_mapping(mapping)?;
        let state = self.state()?;
        mapping.authenticate_identity(&state.mapping_identity)?;
        if state.nonce != *mapping.nonce() {
            return Err(ProviderError::Correlation(
                "assigned complete restore mapping changed",
            ));
        }
        Ok(())
    }

    /// Borrows the exact assigned envelope before or after proof sealing.
    ///
    /// # Errors
    /// Refuses foreign origin, missing owner or a changed/expired original cut.
    pub fn original(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self.state()?;
        if state.phase != Phase::Complete {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        }
        Ok(&state.original)
    }

    /// Borrows digests from this actual retained original Hello journal.
    ///
    /// # Errors
    /// Refuses another bank/actor, revoked codec or incomplete original literals.
    pub fn original_canonical_ack_hello_frame_digests(
        &self,
        journal: &super::super::OriginalHelloJournal,
    ) -> Result<crate::native_hello::OriginalHelloFrameDigests, ProviderError> {
        self.controller
            .original_canonical_ack_hello_frame_digests(journal)
    }

    /// Seals only the separate proof extension into the same original slot.
    ///
    /// # Errors
    /// Refuses bad syntax, changed emitter/cut, second attempt or encoded credit.
    pub fn seal(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        proof: PacketCompleteRestoreProof,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_emitter(emitter)?;
        proof.validate_data()?;
        let state = self.controller.original_complete_restore.as_mut().ok_or(
            ProviderError::Correlation("assigned complete restore absent"),
        )?;
        if state.phase != Phase::Unsigned
            || state.original.extensions.len() != 1
            || !state
                .original
                .extensions
                .contains_key(PACKET_COMPLETE_RESTORE_FEATURE)
        {
            return Err(ProviderError::Conflict(
                "assigned complete restore seal attempted",
            ));
        }
        state.phase = Phase::Sealing;
        let value =
            serde_json::to_value(proof).map_err(crucible_node_format::ContractError::from)?;
        state
            .original
            .extensions
            .insert(PACKET_COMPLETE_RESTORE_PROOF_EXTENSION.into(), value);
        self.controller.session.seal_original_ack_admit(
            &mut self.controller.custody,
            &state.original,
            &mut state.bytes,
            state.literal_slot,
        )?;
        state.phase = Phase::Sealed;
        Ok(())
    }

    /// Writes the same sealed original and retains its reply before returning.
    ///
    /// # Errors
    /// Refuses an occupied output, changed cut, repeated attempt or transport/body
    /// failure. The controller retains original bytes, phase and raw literal bank.
    pub fn publish_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_emitter(emitter)?;
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "original complete restore result occupied",
            ));
        }
        let state = self.controller.original_complete_restore.as_mut().ok_or(
            ProviderError::Correlation("original complete restore absent"),
        )?;
        if state.phase != Phase::Sealed {
            return Err(ProviderError::Conflict(
                "original complete restore publish attempted",
            ));
        }
        state.phase = Phase::Publishing;
        let reply = self.controller.session.publish_original_complete_restore(
            &mut self.controller.custody,
            &state.original,
            &state.bytes,
            state.literal_slot,
            state.cut,
        )?;
        state.response = Some(reply);
        let response = state.response.as_ref().ok_or(ProviderError::Correlation(
            "original complete restore response absent",
        ))?;
        let request = decode_request(state.original.method, &state.original.body)?;
        *completed = Some(decode_response(&request, &response.body)?);
        state.phase = Phase::Complete;
        Ok(())
    }
}

impl AssignedOriginalCompleteRestore {
    pub(super) fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        let Self {
            original,
            bytes,
            literal_slot,
            cut: _,
            phase,
            response,
            mapping,
            mapping_identity: _,
            nonce,
        } = self;
        (
            "source-private.sdk-assigned-restore-current/17",
            original,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(bytes),
            bytes.capacity(),
            literal_slot,
            match phase {
                Phase::Unsigned => "unsigned",
                Phase::Sealing => "sealing",
                Phase::Sealed => "sealed",
                Phase::Publishing => "publishing",
                Phase::Complete => "complete",
            },
            response,
            "historical-nonrenewable-operational-cut",
            mapping,
            nonce,
            "same-prepared-mapping-identity",
        )
    }

    pub(super) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.original)?;
        observer.vector::<u8>(self.bytes.capacity())?;
        observer.observe(&self.response)?;
        observer.observe(&self.mapping)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ArchivedMapping,
            self.mapping_identity.as_ref(),
        )?;
        Ok(())
    }
}

fn settled_field_views<T>(_: impl FnOnce(&'static AssignedOriginalCompleteRestore) -> T) -> usize {
    std::mem::size_of::<T>()
}

impl AssignedOriginalCompleteRestore {
    pub(super) fn settled_history_counter_scratch_data() -> usize {
        settled_field_views(|value| {
            let projected = value.borrowed_settled_history_data();
            (projected, Some(value.borrowed_settled_history_data()))
        }) + settled_field_views(|value| {
            let AssignedOriginalCompleteRestore {
                original,
                bytes,
                literal_slot,
                cut,
                phase,
                response,
                mapping,
                mapping_identity,
                nonce,
            } = value;
            (
                original,
                bytes,
                literal_slot,
                cut,
                phase,
                response,
                mapping,
                mapping_identity,
                nonce,
            )
        }) + std::mem::size_of::<&Self>()
            + std::mem::size_of::<Option<&Self>>()
            + std::mem::size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}
