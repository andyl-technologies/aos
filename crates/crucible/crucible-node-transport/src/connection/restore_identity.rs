//! Retains actual fresh restoration identity without issuing an install permit.

use super::*;
use crate::reference_packet::Native5Policy;
use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
use std::cell::RefCell;

pub(crate) struct OriginalNativeRestorationConnectionIdentity {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    authority: ConnectionAuthority,
    policy: Rc<Native5Policy>,
    frames: Rc<RefCell<OriginalFrameReservation>>,
    request_id: crucible_node_format::Id,
    sequence: crucible_node_format::U64,
    literal_slot: usize,
    literal_length: usize,
    literal_digest: blake3::Hash,
}

impl OriginalNativeRestorationConnectionIdentity {
    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        let codec = connection
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("fresh restore codec absent"))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "fresh restore native role changed",
            ));
        };
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || !Rc::ptr_eq(policy, &self.policy)
            || !self.authority.same_registration(&connection.authority)
            || connection.role != EndpointRole::Provider
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &self.frames))
        {
            return Err(ProviderError::Correlation(
                "fresh restore original actor changed",
            ));
        }
        let bank = self
            .frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("fresh restore literal bank borrowed"))?;
        let frame = bank
            .frame(self.literal_slot)
            .ok_or(ProviderError::Correlation("fresh restore literal absent"))?;
        if frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() != self.literal_length
            || blake3::hash(frame.bytes) != self.literal_digest
        {
            return Err(ProviderError::Correlation(
                "fresh restore original literal changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_installation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        connection
            .guard
            .authenticate_incoming_complete_restore(original)?;
        if original.request_id.0.as_ref() != Some(&self.request_id)
            || original.sequence != self.sequence
        {
            return Err(ProviderError::Correlation(
                "fresh restore assigned original changed",
            ));
        }
        let bank = self
            .frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("fresh restore literal bank borrowed"))?;
        let frame = bank
            .frame(self.literal_slot)
            .ok_or(ProviderError::Correlation("fresh restore literal absent"))?;
        if frame.bytes.len() < 4 {
            return Err(ProviderError::Correlation("fresh restore header absent"));
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(original, &frame.bytes[4..])
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn retain_original_native_restore_identity(
        &self,
        original: &Envelope,
        policy: &Rc<Native5Policy>,
    ) -> Result<OriginalNativeRestorationConnectionIdentity, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.guard
            .authenticate_incoming_complete_restore(original)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("fresh restore codec absent"))?;
        let Native5CodecOwner::NativePacket(actual) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "fresh restore native role required",
            ));
        };
        if self.role != EndpointRole::Provider || !Rc::ptr_eq(actual, policy) {
            return Err(ProviderError::Correlation(
                "fresh restore policy association changed",
            ));
        }
        use crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection;
        match policy.complete_restore_selection() {
            Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11) => {
                CompleteRestoreProjection::from_envelope(original)?;
            }
            Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) => {
                let projection =
                    self.original_selected_restore_transfer_projection_data(original)?;
                if !matches!(
                    projection,
                    CompleteRestoreTransferProjection::Request { .. }
                ) {
                    return Err(ProviderError::Correlation(
                        "restore transfer incoming request required",
                    ));
                }
            }
            None => {
                return Err(ProviderError::Correlation(
                    "fresh restore source mechanism unselected",
                ));
            }
        }
        let frames = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("fresh restore bank absent"))?;
        let bank = frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("fresh restore bank borrowed"))?;
        let literal_slot = bank
            .frames()
            .count()
            .checked_sub(1)
            .ok_or(ProviderError::Correlation("fresh restore literal absent"))?;
        let frame = bank
            .frame(literal_slot)
            .ok_or(ProviderError::Correlation("fresh restore literal absent"))?;
        if frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() < 4
        {
            return Err(ProviderError::Correlation(
                "fresh restore literal incomplete",
            ));
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(original, &frame.bytes[4..])?;
        Ok(OriginalNativeRestorationConnectionIdentity {
            actor: Rc::clone(&self.protocol_owner),
            authority: self.authority.clone(),
            policy: Rc::clone(policy),
            frames: Rc::clone(frames),
            request_id: original
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("fresh restore ID absent"))?
                .clone(),
            sequence: original.sequence,
            literal_slot,
            literal_length: frame.bytes.len(),
            literal_digest: blake3::hash(frame.bytes),
        })
    }

    pub(crate) fn original_native5_complete_restore_selection(&self) -> Result<Option<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>,ProviderError>{
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native restore source codec absent",
            ))?;
        match (self.role, codec.as_ref()) {
            (EndpointRole::Controller, Native5CodecOwner::ControllerPacket(_))
            | (EndpointRole::Provider, Native5CodecOwner::NativePacket(_)) => {
                Ok(codec.complete_restore_selection())
            }
            _ => Err(ProviderError::Correlation(
                "restore source codec role differs",
            )),
        }
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn authenticate_archived_native_protocol_mapping(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        mapping.authenticate_target(
            &self.authority,
            &self.protocol_owner,
            self.native5_codec.as_ref(),
        )
    }
}

impl OriginalNativeRestorationConnectionIdentity {
    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        let Self {
            actor,
            authority,
            policy,
            frames,
            request_id,
            sequence,
            literal_slot,
            literal_length,
            literal_digest: _,
        } = self;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        authority.observe_retained_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        policy.observe_retained_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::FrameBank, frames.as_ref())?;
        frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("restore identity original bank borrowed"))?
            .observe_owned11_metadata(observer)?;
        observer.observe(request_id)?;
        observer.observe(sequence)?;
        observer.observe(literal_slot)?;
        observer.observe(literal_length)
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Names the actual independently allocated assigned-response owner header.
    pub(crate) fn original_prepare_response_owner_layout_data() -> usize {
        super::restore_response::original_restore_response_owner_layout()
    }

    /// Counts the two independently copied authority backings of real Prepare.
    pub(crate) fn original_prepare_authority_clone_storage_data(
        &self,
        maximum_features: usize,
    ) -> Result<usize, ProviderError> {
        let installed = self.original_native_owned11_admission()?;
        for authority in [&self.authority, &installed.authority] {
            let maximum_keys = authority.selected_features().len().checked_mul(2).ok_or(
                ProviderError::ResourceExhausted("Prepare extension cardinality"),
            )?;
            if authority.selected_features().len() > maximum_features
                || authority.envelope_extensions().len() > maximum_keys
                || authority
                    .envelope_extensions()
                    .iter()
                    .any(|key| key.len() > 128)
            {
                return Err(ProviderError::Correlation("Prepare extension cardinality"));
            }
        }
        let identity = self.authority.independent_clone_backing_storage_data()?;
        let prepare = installed
            .authority
            .independent_clone_backing_storage_data()?;
        identity
            .checked_add(prepare)
            .ok_or(ProviderError::ResourceExhausted(
                "Prepare authority clone backing",
            ))
    }
}

#[path = "prepare_startup_receive.rs"]
mod prepare_startup_receive;
pub(crate) use prepare_startup_receive::authenticate_original_native_prepare_header_data;

#[path = "restore_identity/settled.rs"]
mod settled_history;
