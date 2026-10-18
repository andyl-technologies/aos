//! Retains actual native connection identity for the private keyed Admit issuer.
//!
//! This crate-private correspondence capsule is not a verified admission token.
//! Only the genuine boot/context MAC verifier can issue that separate token;
//! a selected policy or an identity capsule cannot lower receive allowances.

use super::*;
use crate::reference_packet::Native5Policy;
use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
use std::cell::RefCell;

pub(crate) struct OriginalNativeAckConnectionIdentity {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    authority: ConnectionAuthority,
    policy: Rc<Native5Policy>,
    frames: Rc<RefCell<OriginalFrameReservation>>,
    admit_id: crucible_node_contract::Id,
    admit_sequence: crucible_node_contract::U64,
    literal_index: usize,
    literal_length: usize,
    literal_digest: blake3::Hash,
}

impl OriginalNativeAckConnectionIdentity {
    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        // Origin refusal precedes access to any inherited RefCell or socket owner.
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || !self.authority.same_registration(&connection.authority)
            || connection.role != EndpointRole::Provider
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &self.frames))
        {
            return Err(ProviderError::Correlation(
                "native ACK original connection differs",
            ));
        }
        let Some(codec) = &connection.native5_codec else {
            return Err(ProviderError::Correlation(
                "native ACK original codec absent",
            ));
        };
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "native ACK identity is not native policy",
            ));
        };
        if !Rc::ptr_eq(policy, &self.policy) {
            return Err(ProviderError::Correlation(
                "native ACK original policy differs",
            ));
        }
        codec.authenticate_ack_emitter_selection(&connection.authority)?;
        let bank = self
            .frames
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("native ACK original literal bank borrowed"))?;
        let frame = bank
            .frames()
            .nth(self.literal_index)
            .ok_or(ProviderError::Correlation(
                "native ACK original Admit literal absent",
            ))?;
        if frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() != self.literal_length
            || blake3::hash(frame.bytes) != self.literal_digest
        {
            return Err(ProviderError::Correlation(
                "native ACK original Admit literal changed",
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
            .authenticate_incoming_canonical_ack_admit(original)?;
        if original.request_id.0.as_ref() != Some(&self.admit_id)
            || original.sequence != self.admit_sequence
        {
            return Err(ProviderError::Correlation(
                "native ACK assigned original differs",
            ));
        }
        Ok(())
    }
}

impl crate::retained_metadata::ObserveMetadata for OriginalNativeAckConnectionIdentity {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        let Self {
            actor,
            authority,
            policy,
            frames,
            admit_id,
            admit_sequence,
            literal_index,
            literal_length,
            literal_digest: _,
        } = self;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            actor.as_ref(),
        )?;
        authority.observe_retained_metadata(observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )?;
        policy.observe_owned11_metadata(observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::FrameBank,
            frames.as_ref(),
        )?;
        frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native identity original bank borrowed"))?
            .observe_owned11_metadata(observer)?;
        observer.observe(admit_id)?;
        observer.observe(admit_sequence)?;
        observer.observe(literal_index)?;
        observer.observe(literal_length)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn retain_original_native_ack_identity(
        &self,
        original: &Envelope,
        policy: &Rc<Native5Policy>,
    ) -> Result<OriginalNativeAckConnectionIdentity, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.guard
            .authenticate_incoming_canonical_ack_admit(original)?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation(
                "native ACK issuer requires provider actor",
            ));
        }
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("native ACK source codec absent"))?;
        let Native5CodecOwner::NativePacket(actual) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "native ACK issuer requires native policy",
            ));
        };
        if !Rc::ptr_eq(actual, policy) {
            return Err(ProviderError::Correlation(
                "native ACK selected native policy differs",
            ));
        }
        codec.authenticate_ack_emitter_selection(&self.authority)?;
        let admit_id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native ACK assigned Admit ID absent",
            ))?;
        let frames = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native ACK original literal bank absent",
            ))?;
        let bank = frames
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("native ACK original literal bank borrowed"))?;
        let (literal_index, frame) =
            bank.frames()
                .enumerate()
                .last()
                .ok_or(ProviderError::Correlation(
                    "native ACK assigned Admit literal absent",
                ))?;
        if frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
        {
            return Err(ProviderError::Correlation(
                "native ACK assigned Admit literal incomplete",
            ));
        }
        Ok(OriginalNativeAckConnectionIdentity {
            actor: self.protocol_owner.clone(),
            authority: self.authority.clone(),
            policy: policy.clone(),
            frames: frames.clone(),
            admit_id: admit_id.clone(),
            admit_sequence: original.sequence,
            literal_index,
            literal_length: frame.bytes.len(),
            literal_digest: blake3::hash(frame.bytes),
        })
    }
}

impl OriginalNativeAckConnectionIdentity {
    /// Borrows exact historical identity fields without exporting live authority.
    pub(crate) fn borrowed_owned11_protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a OriginalNativeAckConnectionIdentity);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let owner = self.0;
                owner
                    .actor
                    .ensure_current()
                    .map_err(serde::ser::Error::custom)?;
                let bank = owner.frames.try_borrow().map_err(|_| {
                    serde::ser::Error::custom("native identity original bank borrowed")
                })?;
                serde::Serialize::serialize(
                    &(
                        "source-private.native-ack-connection-identity/11",
                        "historical-source-owner",
                        owner.authority.historical_owned_view(),
                        owner.policy.borrowed_owned11_protocol_view(),
                        bank.protocol_view_with_encoding(true),
                        &owner.admit_id,
                        owner.admit_sequence,
                        owner.literal_index,
                        owner.literal_length,
                        owner.literal_digest.as_bytes(),
                    ),
                    serializer,
                )
            }
        }
        View(self)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_native_owned11_admission(
        &self,
    ) -> Result<
        &crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission,
        ProviderError,
    > {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let original =
            self.original_canonical_ack_admission
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original native admission absent",
                ))?;
        original.authenticate_current(self)?;
        Ok(original)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_native5_protocol_metadata_limits(
        &self,
    ) -> Result<
        Option<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>,
        ProviderError,
    > {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation(
                "native metadata selection requires provider",
            ));
        }
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("native original codec absent"))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "native metadata selection requires original policy",
            ));
        };
        Ok(policy.protocol_metadata_limits())
    }
}

impl OriginalNativeAckConnectionIdentity {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        use crate::retained_metadata::aliases::MetadataSharedKind;
        self.actor.ensure_current()?;
        let Self {
            actor,
            authority,
            policy,
            frames,
            admit_id,
            admit_sequence,
            literal_index,
            literal_length,
            literal_digest: _,
        } = self;
        roots.observe_shared(observer, MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        authority.observe_unique_capture_metadata(roots, observer)?;
        if roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())? {
            policy.observe_unique_capture_metadata(roots, observer)?;
        }
        if roots.observe_shared(observer, MetadataSharedKind::FrameBank, frames.as_ref())? {
            frames
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("native identity unique frame bank borrowed"))?
                .observe_owned11_metadata(observer)?;
        }
        observer.observe(admit_id)?;
        observer.observe(admit_sequence)?;
        observer.observe(literal_index)?;
        observer.observe(literal_length)
    }
}

#[path = "native_fresh_frontier.rs"]
mod fresh_frontier;
pub(crate) use fresh_frontier::OriginalNativeFreshFrontierData;

#[path = "ack_admission/settled.rs"]
mod settled_history;
