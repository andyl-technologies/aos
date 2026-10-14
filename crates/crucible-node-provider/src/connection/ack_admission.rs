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
        observer.shared_value(std::mem::size_of_val(actor.as_ref()))?;
        authority.observe_retained_metadata(observer)?;
        observer.shared_value(std::mem::size_of_val(policy.as_ref()))?;
        policy.observe_retained_metadata(observer)?;
        observer.shared_value(std::mem::size_of_val(frames.as_ref()))?;
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
