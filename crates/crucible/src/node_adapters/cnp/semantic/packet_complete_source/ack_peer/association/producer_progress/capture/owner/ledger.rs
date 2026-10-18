//! Preserves Capture's modeled once state and immutable completion evidence.
//!
//! ```text
//! {schema,cut,phase,once_spent,failed,prefix_frontier,frontier,bridge}
//! ```
//!
//! Completed encoder/decoder caches stay in their actual live owning census.
//! They are not modeled memory. A distinct synchronous preencoder witness names
//! the actual Preparing phase; it never certifies future Capture completion.

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::mem::size_of;

const SCHEMA: &str = "source-private.source-capture-housekeeping/17";

/// Borrows one actual synchronous preencoder cut without transferable custody.
///
/// Its constructor is private to the once owner's Preparing transition. No
/// decoder, Clone implementation or state-setting method exists. Raw tokens are
/// compared only against the same retained Source slot and are never encoded.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct CapturePreEncoderCut<'a>
{
    source: &'a PacketCompleteSemanticSource,
    owner: *const CaptureOnceOwner,
    controller: &'a CnpController,
    emitter: &'a OriginalCanonicalBlobAckEmitter,
    prefix_frontier: U64,
}

/// Borrows the actual prefix encoder for one private synchronous callback.
///
/// The callback builds its history with the borrowed cut and calls encode_data
/// before that cut can expire. A no-op callback cannot complete preparation.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct CapturePrefixEncoder<
    'a,
    'claim,
> {
    prefix: &'a mut CapturePrefixOwners,
    source: &'a PacketCompleteSemanticSource,
    controller: *const CnpController,
    claim: &'a OriginalRestoredCaptureClaim<'claim>,
    maximum_checkpoint: usize,
    maximum_prefix: usize,
    recheck_read: &'a mut dyn FnMut() -> Result<(), RuntimeError>,
    completed: bool,
}

impl CapturePreEncoderCut<'_> {
    /// Rechecks the same Source slot, controller and unchanged pre-upload cut.
    ///
    /// # Errors
    /// Refuses foreign owners, a busy Source association, an already retained
    /// SDK Capture, or a changed original emitter/frontier. No owner is opened.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_owner_data(
        &self,
        source: &PacketCompleteSemanticSource,
        owner: *const (),
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(source, self.source)
            || owner != self.owner.cast()
            || !std::ptr::eq(controller, self.controller)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        source.storage_origin_with_error::<RuntimeError>()?;
        let association = source
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        // The actual RefCell is already mutably borrowed by preparation. Its
        // retained address is checked without attempting another content loan.
        if original.restored_capture.as_ptr() != self.owner.cast_mut() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if controller
            .original_restored_settled_capture_is_retained_data(self.emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?
            || controller
                .original_restored_settled_capture_history_next_sequence_precredit_data(self.emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?
                != self.prefix_frontier
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    /// Borrows scalar phase/frontier DATA without certifying a completed Capture.
    ///
    /// # Errors
    /// Refuses changed actual parents or SDK frontier; serialization rechecks.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn state_data(
        &self,
    ) -> Result<impl Serialize + '_, RuntimeError> {
        self.authenticate_owner_data(self.source, self.owner.cast(), self.controller)?;
        Ok(PreEncoderState(self))
    }

    /// Returns the actual sampled SDK prefix coordinate as comparison DATA only.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn prefix_frontier_data(
        &self,
    ) -> U64 {
        self.prefix_frontier
    }
}

struct PreEncoderState<'a, 'source>(&'a CapturePreEncoderCut<'source>);

impl Serialize for PreEncoderState<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_owner_data(self.0.source, self.0.owner.cast(), self.0.controller)
            .map_err(serde::ser::Error::custom)?;
        let result = write_fields(
            serializer,
            "pre_encoder",
            "preparing",
            true,
            false,
            Some(self.0.prefix_frontier),
            None,
            None::<()>,
        );
        self.0
            .authenticate_owner_data(self.0.source, self.0.owner.cast(), self.0.controller)
            .map_err(serde::ser::Error::custom)?;
        result
    }
}

impl CapturePrefixEncoder<'_, '_> {
    /// Encodes this same owner's admitted prefix while its witness is borrowed.
    ///
    /// # Errors
    /// Refuses another attempt, failed claim/read checks or bounded encoding.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn encode_data<
        H: Serialize + ?Sized,
    >(
        &mut self,
        history: &H,
    ) -> Result<(), RuntimeError> {
        if self.completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.prefix.encode_data(
            self.source,
            self.controller,
            self.claim,
            history,
            self.maximum_checkpoint,
            self.maximum_prefix,
            self.recheck_read,
        )?;
        self.prefix.payload_data()?;
        self.completed = true;
        Ok(())
    }
}

impl CaptureOnceOwner {
    /// Encodes history within the real Preparing witness's synchronous lifetime.
    ///
    /// The owning callback may borrow the witness in its complete Source view.
    /// A refusal retains every prefix partial and leaves Preparing spent; no
    /// subsequent callback can restart it. The claim and SDK frontier remain
    /// unchanged across the entire original encoder callback.
    ///
    /// # Errors
    /// Refuses repeated or foreign preparation, changed SDK/claim/read state,
    /// a callback refusal, an unencoded callback or an invalid bounded payload.
    ///
    /// # Panics
    /// A callback panic unwinds with the actual Preparing owner still spent.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn prepare_prefix_with_data(
        &mut self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        claim: &OriginalRestoredCaptureClaim<'_>,
        maximum_checkpoint: usize,
        maximum_prefix: usize,
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
        encode: impl FnOnce(
            &CapturePreEncoderCut<'_>,
            &mut CapturePrefixEncoder<'_, '_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Unused || self.transport.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Spend before the first fallible check. This is the actual owner phase,
        // not a proxy record with a manufactured Complete state.
        self.stage = Stage::Preparing;
        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()?;
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let prefix_frontier = controller
            .original_restored_settled_capture_history_next_sequence_precredit_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let cut = CapturePreEncoderCut {
            source,
            owner: self,
            controller,
            emitter,
            prefix_frontier,
        };
        cut.authenticate_owner_data(source, self as *const Self as *const (), controller)?;
        let mut encoder = CapturePrefixEncoder {
            prefix: &mut self.prefix,
            source,
            controller,
            claim,
            maximum_checkpoint,
            maximum_prefix,
            recheck_read: &mut *recheck_read,
            completed: false,
        };
        encode(&cut, &mut encoder)?;
        if !encoder.completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        encoder.prefix.payload_data()?;
        drop(encoder);
        cut.authenticate_owner_data(source, self as *const Self as *const (), controller)?;
        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()?;
        self.stage = Stage::Prepared;
        Ok(())
    }

    /// Borrows only an unused or genuinely completed administrative ledger.
    ///
    /// The whole caller separately keeps its actual SourceRead and native/world
    /// guards. Completed SDK originals and terminals stay in their independently
    /// bound Controller history; this ledger links the exact existing Bridge.
    /// No prefix bytes, decoder caches or process addresses are serialized.
    ///
    /// # Errors
    /// Refuses an active/refused phase, foreign actual owner, changed SDK custody
    /// or an incomplete/stale native/World/Source Bridge correspondence.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn borrowed_housekeeping_ledger_data<
        'a,
    >(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
        emitter: &'a OriginalCanonicalBlobAckEmitter,
        world: &'a crate::node_contract::WorldActivation,
        key: &'a [u8; 32],
    ) -> Result<impl Serialize + 'a, RuntimeError> {
        let view = Ledger {
            owner: self,
            source,
            controller,
            emitter,
            world,
            key,
        };
        view.authenticate_data()?;
        Ok(view)
    }

    pub(super) fn housekeeping_counter_scratch_data() -> usize {
        CnpController::original_restored_settled_capture_once_query_counter_scratch_data()
            + size_of::<String>()
            + size_of::<CapturePreEncoderCut<'static>>()
            + size_of::<PreEncoderState<'static, 'static>>()
            + size_of::<CapturePrefixEncoder<'static, 'static>>()
            + size_of::<Ledger<'static>>()
            + size_of::<Result<Ledger<'static>, RuntimeError>>()
            + size_of::<
                crucible_node_provider::client::OriginalCompletedRestoredSettledCaptureData<
                    'static,
                >,
            >()
            + size_of::<Option<U64>>() * 2
            + size_of::<(&str, &str, bool, bool, Option<U64>, Option<U64>)>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<bool, crucible_node_provider::ProviderError>>()
            + size_of::<Result<U64, crucible_node_provider::ProviderError>>()
            + size_of::<
                std::cell::Ref<
                    'static,
                    Option<super::super::super::super::OriginalAckPeerAssociation>,
                >,
            >()
            + size_of::<Result<(), crucible_node_provider::ProviderError>>()
    }
}

struct Ledger<'a> {
    owner: &'a CaptureOnceOwner,
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    emitter: &'a OriginalCanonicalBlobAckEmitter,
    world: &'a crate::node_contract::WorldActivation,
    key: &'a [u8; 32],
}

impl Ledger<'_> {
    fn authenticate_data(&self) -> Result<(), RuntimeError> {
        self.source.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .source
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if original.restored_capture.as_ptr() != self.owner as *const _ as *mut _ {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.emitter
            .authenticate_original(self.controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // These are the entire actual fields: prefix and post-confirmation
        // decoder buffers remain live housekeeping, while the post-confirmation
        // Bridge and its completion guard are independently authenticated below.
        let CaptureOnceOwner {
            stage,
            construction,
            prefix: _,
            transport,
            post_confirmation: _,
        } = self.owner;
        match stage {
            Stage::Unused => {
                if construction.is_started_data()
                    || transport.is_some()
                    || self
                        .controller
                        .original_restored_settled_capture_is_retained_data(self.emitter)
                        .map_err(|_| RuntimeError::InvalidReceipt)?
                {
                    return Err(RuntimeError::OutstandingObligations);
                }
                Ok(())
            }
            Stage::Complete => self.owner.current_bridge_data()?.authenticate_current_data(
                self.source,
                self.controller,
                self.emitter,
                self.world,
                self.key,
            ),
            Stage::Preparing | Stage::Prepared | Stage::Capturing | Stage::Confirming => {
                Err(RuntimeError::OutstandingObligations)
            }
        }
    }
}

impl Serialize for Ledger<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.authenticate_data()
            .map_err(serde::ser::Error::custom)?;
        let result = match self.owner.stage {
            Stage::Unused => write_fields(
                serializer, "settled", "unused", false, false, None, None, None::<()>,
            ),
            Stage::Complete => {
                let sdk = self
                    .controller
                    .original_completed_restored_settled_capture_data(self.emitter)
                    .map_err(serde::ser::Error::custom)?;
                let bridge = self
                    .owner
                    .current_bridge_data()
                    .map_err(serde::ser::Error::custom)?;
                let prefix = sdk
                    .prefix_frontier_data()
                    .map_err(serde::ser::Error::custom)?;
                if prefix != bridge.pre_checkpoint_identity_data().2
                    || sdk.frontier_data() != bridge.checkpoint_identity_data().2
                {
                    return Err(serde::ser::Error::custom(RuntimeError::InvalidReceipt));
                }
                write_fields(
                    serializer,
                    "settled",
                    "complete",
                    true,
                    false,
                    Some(prefix),
                    Some(sdk.frontier_data()),
                    Some(
                        bridge
                            .historical_data()
                            .map_err(serde::ser::Error::custom)?,
                    ),
                )
            }
            Stage::Preparing | Stage::Prepared | Stage::Capturing | Stage::Confirming => {
                return Err(serde::ser::Error::custom(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };
        self.authenticate_data()
            .map_err(serde::ser::Error::custom)?;
        result
    }
}

fn write_fields<S: Serializer, B: Serialize>(
    serializer: S,
    cut: &str,
    phase: &str,
    once_spent: bool,
    failed: bool,
    prefix: Option<U64>,
    frontier: Option<U64>,
    bridge: Option<B>,
) -> Result<S::Ok, S::Error> {
    let mut fields = serializer.serialize_struct("SourceCaptureHousekeeping17", 8)?;
    fields.serialize_field("schema", SCHEMA)?;
    fields.serialize_field("cut", cut)?;
    fields.serialize_field("phase", phase)?;
    fields.serialize_field("once_spent", &once_spent)?;
    fields.serialize_field("failed", &failed)?;
    fields.serialize_field("prefix_frontier", &prefix)?;
    fields.serialize_field("frontier", &frontier)?;
    fields.serialize_field("bridge", &bridge)?;
    fields.end()
}
